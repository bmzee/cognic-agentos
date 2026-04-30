# Sprint 3 — LLM Gateway + Provider-Honesty Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every LLM call goes through one auditable chokepoint. Cloud-policy fail-closed enforcement gates external providers. The portal exposes runtime reality (what model actually got hit) per ADR-007, not a static label.

**Architecture:** A single `llm.gateway.LLMGateway` resolves a tier alias → LiteLLM alias → upstream model identifier, fires INPUT guardrails before policy evaluation, denies external upstreams when `allow_external_llm=False`, rate-limits via a per-profile concurrency primitive, dispatches via httpx to the LiteLLM router, classifies SLA on response, fires OUTPUT guardrails, writes one row to a new `gateway_call_ledger` table, and emits per-trip / per-violation / per-breach `audit_event` rows through the Sprint-2 hash-chain substrate. The portal API layer reads from the ledger as the authoritative source for `/api/v1/system/effective-routing`.

**Tech Stack:** Python 3.12, httpx (async), LiteLLM router (already running in compose per Sprint 1C), Pydantic Settings (additive fields), SQLAlchemy 2.0 async (additive `gateway_call_ledger` Alembic migration), FastAPI (two new GET endpoints), Sprint 2 substrate (`AuditStore`, `core/canonical`), Sprint 2.5 substrate (`SLATimer`, `GuardrailPipeline`).

---

## Doctrine alignment

| Source | Constraint | How this plan honours it |
|---|---|---|
| **ADR-007** (Provider-Honesty) | `/system/effective-routing` reads from a local Postgres ledger as **authoritative**; Langfuse is opportunistic enrichment only. The honesty claim never depends on Langfuse availability. | T4 introduces `gateway_call_ledger` (new Alembic migration). T10 endpoint reads ledger first, settings second, Langfuse third with `langfuse_available: false` fallback flag. |
| **ADR-007** | Cloud-policy enforcement classifies based on the **upstream** identity returned by LiteLLM, not the LiteLLM alias name string. | `_is_external(model_string, api_base)` in `preflight.py` is api_base-aware (Round-2 reviewer-P1#2): vLLM/SGLang serving `model: openai/X` against a private api_base classify as self-hosted; cloud OpenAI without api_base classifies as external. The post-response policy recheck (T6 flow step 7) re-runs the enforcer on the actual `ResolvedUpstream` returned by LiteLLM, closing the external→external silent-drift class (Round-2 reviewer-P1#1). Decision-locking §1 + §3. |
| **ADR-013** (Model lifecycle) | Decision-history events tagged with `model_id` so examiners can prove which model handled which case. `model_id` is Sprint 9.5 territory. | Sprint 3 ledger row reserves a nullable `model_id` column for Sprint 9.5 backfill. **No `decision_history` emission in Sprint 3** — gateway calls are operational ledger, not chain-of-custody evidence. Decision-locking section §5. |
| **ADR-015** (Policy-as-code) | Sprint 4 is the first sprint with the OPA seed. Sprint 3 cloud-policy is **not** a Rego query yet. | T3 enforcer is a pure-Python settings-driven check. Refactor to delegate via the OPA engine lands in Sprint 13.5 (per ADR-015 §"Sprint 13.5 (full)"). |
| **ADR-006 / ISO 42001** | Operational logging (A.9.2) + AI system impact assessment (A.7.4). | Cloud-policy denial emits `audit_event` with `iso_controls=("ISO42001.A.9.2",)`. SLA breach emits with `("ISO42001.A.9.2",)`. Guardrail trips already emit with `("ISO42001.A.7.4",)` from Sprint 2.5. |
| **AGENTS.md critical-controls rule** | `llm/gateway.py` is on the cloud-policy enforcer + provider-honesty ledger feed list. ≥95% line / ≥90% branch per-file. | T11 extends `tools/check_critical_coverage.py` with `llm/gateway.py`. All gateway-shape modules ride the same gate. |
| **AGENTS.md production-grade rule** | No mock implementations on the runtime path; stubs raise `NotImplementedError` citing an ADR. | T1 settings extension; T5 `LLMGateway.completion` is a real httpx call to LiteLLM in dev (compose-resident); tests use a recorded-response fixture, not a mock generator. |
| **Sprint-2.5 substrate** | `SLATimer.compute_deadline` + `classify` are pure-functional; caller emits. `GuardrailPipeline.check` returns `PipelineResult`; caller decides what to do with trips. | T6 wraps both: pipeline trip → halt + audit + raise; SLA breach → audit but **does not raise** (caller-escalation-friendly). Decision-locking sections §3 + §4. |
| **Sprint-1C config** | `infra/litellm/config.yaml` already declares the alias matrix (`cognic-tier1-dev`, `cognic-tier1-vllm`, `cognic-tier1-sglang`). Cloud aliases are not yet declared. | T2 adds `cognic-tier1-cloud-openai` / `cognic-tier1-cloud-anthropic` aliases to the LiteLLM config so the cloud-policy denial path is exercised end-to-end. |

---

## The five locked-before-code decisions

The user requested these be pinned explicitly before any code lands. Each is a contract that the rest of the plan honours.

### §1 — Provider alias semantics: three layers + `ResolvedUpstream` + `api_base`-aware classification

There are three names floating around. The plan distinguishes them rigidly to avoid the bug ADR-007 was written against:

| Layer | Example | Source of truth | Owned by |
|---|---|---|---|
| **Tier alias** | `tier1`, `tier2` | AgentOS code | Caller of `LLMGateway.completion(tier=...)` |
| **LiteLLM alias** | `cognic-tier1-dev`, `cognic-tier1-vllm`, `cognic-tier1-cloud-openai` | `infra/litellm/config.yaml` + settings (`tier1_alias`, `tier2_alias`) | Operator |
| **Resolved upstream** | `ResolvedUpstream(model_string="openai/Qwen3-8B-Instruct", api_base="http://vllm:8000/v1", external=False)` | `PreflightResolver.resolve(alias)` — reads YAML + `${VAR}` substitution | LiteLLM config + AgentOS resolver |

#### Why classification can't operate on the model string alone (Round-2 reviewer-P1#2)

The original Round-1 plan classified on the bare model string (`ollama/qwen3:8b` → self-hosted, `openai/gpt-5.4` → external). That fails on the most common production self-hosted shape:

```yaml
- model_name: cognic-tier1-vllm
  litellm_params:
    model: openai/${COGNIC_TIER1_VLLM_MODEL}    # NOTE the openai/ prefix
    api_base: ${VLLM_BASE_URL}                  # ...but pointed at a private vLLM
```

vLLM and SGLang both serve the OpenAI-compatible HTTP shape, so banks declare them as `model: openai/<model-name>` with a private `api_base`. Classifying on the model prefix alone would deny these self-hosted production routes under default policy. The reviewer's framing: *the model prefix is one signal among several; the api_base is the dispositive one.*

#### Classification rule (priority order — first match wins)

```python
def _is_external(model_string: str, api_base: str | None) -> bool:
    """Cloud-policy classification using both signals.

    Priority:
      1. api_base set + host on the known-cloud allow-list  → external
      2. api_base set + host is private/local              → self-hosted
      3. api_base set + host unrecognised                  → external (fail-closed)
      4. api_base unset + model prefix on self-hosted list → self-hosted
      5. else                                              → external (fail-closed)
    """
```

- **Known-cloud hosts** (constant tuple, declared in `llm/gateway.py`): `api.openai.com`, `*.openai.azure.com`, `api.anthropic.com`, `*.bedrock.*.amazonaws.com`, `api.cohere.ai`, `api.cohere.com`, `*.googleapis.com`, `generativelanguage.googleapis.com`. Per-tenant override is Sprint 13.5 OPA territory.
- **Private/local hosts:** RFC1918 (10.0.0.0/8, 172.16/12, 192.168/16), 127.0.0.0/8, `localhost`, `*.local`, `*.internal`, `*.svc`, `*.svc.cluster.local`, container DNS (single-label hostnames like `vllm`, `sglang`, `ollama`, `litellm`).
- **Self-hosted model prefixes** (only consulted when `api_base` is unset): `ollama/`, `vllm/`, `sglang/`, `openai-compat/`, `local/`.

#### `ResolvedUpstream` dataclass

```python
@dataclasses.dataclass(frozen=True, slots=True)
class ResolvedUpstream:
    alias: str                     # the LiteLLM alias that produced this resolution
    model_string: str              # post-${VAR}-substitution model identifier
    api_base: str | None           # post-substitution api_base (if declared)
    external: bool                 # _is_external(model_string, api_base)
    provenance: Literal["resolved", "unresolved", "ambiguous"] = "resolved"
                                   # Round-4 + Round-5 + Round-6 reviewer-P1: provenance
                                   # state. "resolved" = single reverse_lookup match (or
                                   # no reverse-lookup needed in pre-call resolve path).
                                   # "unresolved" = zero reverse_lookup matches OR LiteLLM
                                   # response had a missing/invalid model field.
                                   # "ambiguous" = multiple reverse_lookup matches with
                                   # disagreeing classifications. enforce_cloud_policy
                                   # denies UNCONDITIONALLY whenever provenance !=
                                   # "resolved" — ADR-007 provenance bedrock.
```

`PreflightResolver.resolve(alias) -> ResolvedUpstream` returns the enriched object. `enforce_cloud_policy(resolved, settings) -> PolicyDecision` consumes it. The audit payload on denial carries `alias`, `model_string`, `api_base`, `external`, `provenance`, `policy_mode`, `reason` — full transparency for examiners.

**Why this matters for `/system/effective-routing`:** the endpoint surfaces alias + model_string + api_base + external + **provenance** for every recent call (Round-6 reviewer-P1: provenance is persisted in the ledger row, not derived from current YAML at endpoint-read time, so historical rows stay authoritative). PROFILE chip drift detection per ADR-007 filters to `provenance != "no_dispatch"` (Round-7 reviewer-P1: includes `resolved`, `unresolved`, AND `ambiguous` — all three are post-dispatch states where LiteLLM contacted the upstream and the operator must see the count). Only `no_dispatch` rows are excluded — they reflect intended preflight identity from pre-dispatch failures and don't represent actual upstream contact.

### §2 — Cloud-policy fail-closed behaviour

Three settings drive the enforcer:

```python
allow_external_llm: bool = False                # default closed (self-hosted-first)
policy_mode: Literal["self_hosted", "cloud_openai", "cloud_anthropic", "cloud_mixed"] = "self_hosted"
allowed_providers: list[str] = []              # explicit allow-list of provider prefixes
```

**Decision tree** (in order — first match wins; takes a `ResolvedUpstream`):

1. `resolved.provenance != "resolved"` → DENY UNCONDITIONALLY (Round-4 + Round-5 + Round-6 reviewer-P1: any provenance gap overrides every other gate. `unresolved` and `ambiguous` both fall here. Even `allow_external_llm=True` + provider on `allowed_providers` cannot make this allow).
2. `resolved.external is False` → ALLOW (self-hosted always passes — note: api_base-aware, so vLLM/SGLang on private hosts pass even with `model: openai/...`).
3. `allow_external_llm is False` → DENY (`reason="external upstream blocked: allow_external_llm=False"`).
4. Provider prefix derived from `resolved.model_string` (`openai`, `azure`, `anthropic`, `bedrock`, `cohere`) NOT in `allowed_providers` → DENY (cite the missing provider).
5. `policy_mode == "self_hosted"` AND `resolved.external is True` → DENY (mode + flag inconsistency — operator misconfigured).
6. Otherwise ALLOW.

**Fail-closed posture:** a setting in an ambiguous state (e.g. `allow_external_llm=True` but `allowed_providers=[]`) DENIES, not ALLOWS. Every code path that doesn't reach an explicit ALLOW returns DENY.

**Audit emission on denial:** before raising `CloudPolicyViolationError`, the gateway emits one `audit_event` with `event_type="gateway.cloud_policy_denied"`, `payload={"alias": ..., "model_string": ..., "api_base": ..., "external": ..., "policy_mode": ..., "reason": ..., "post_response": <bool>}`, `iso_controls=("ISO42001.A.9.2",)`. **No PII in payload — alias + model_string + api_base + reason only**, never the prompt or any user-supplied content. Same privacy posture as Sprint 2.5 T7-reviewer-P1 (no `detail` persisted to the chain). The `post_response: true` flag distinguishes a pre-dispatch denial from a post-response policy recheck denial — load-bearing for the Round-2 reviewer-P1#1 fix.

### §3 — Guardrail input/output placement

The gateway flow, with guardrail attach points:

```
caller → LLMGateway.completion(tier, messages, ...)
   ┌─ Pre-dispatch (best-effort ledger regime — see §5 contract) ─────────────────
   │  1. Resolve tier → LiteLLM alias (settings) → preflight ResolvedUpstream
   │     (PreflightResolver.resolve, sourced from infra/litellm/config.yaml,
   │      lazy ${VAR} substitution per-alias)
   │  2. INPUT guardrails fire on `messages` (joined string view)
   │      → trip? best-effort ledger write + raise GuardrailViolationError("input")
   │  3. Cloud-policy check on PREFLIGHT ResolvedUpstream (api_base-aware)
   │      → deny? emit audit(gateway.cloud_policy_denied, post_response=False)
   │              + best-effort ledger write + raise CloudPolicyViolationError
   │  4. try: acquire concurrency slot
   │     except LLMConcurrencyExceeded:
   │         best-effort ledger write outcome="concurrency_exhausted" + re-raise
   │
   ├─ Dispatch ──────────────────────────────────────────────────────────────────
   │  5. SLATimer.compute_deadline(start=now, policy=stored_policy)
   │  6. httpx POST to LiteLLM /chat/completions
   │     (split httpx exception handling: ConnectError/ConnectTimeout/PoolTimeout/
   │      LocalProtocolError → pre-dispatch best-effort; ReadTimeout/ReadError/
   │      WriteError/WriteTimeout/RemoteProtocolError → post-dispatch strict)
   │  7. Parse response — strict-ledger regime engages from here:
   │       - response.model missing/empty/non-string → _build_unresolved_actual
   │           (cause="missing_model_field", provenance="unresolved", api_base=None)
   │       - else → _build_actual_resolved(actual_model_string)
   │
   ├─ Post-dispatch (strict ledger regime — see §5 contract) ────────────────────
   │  8. SLATimer.classify(now=..., deadline=...)
   │      → BREACHED? emit audit(sla.breach); do not raise
   │  9. Build actual_resolved (entire post-dispatch block wrapped in
   │     try/except that strict-ledgers + re-raises on AuditStore failure
   │     or response-shape failure — Round-7 reviewer-P1):
   │       - 0 matches → _build_unresolved_actual(cause="model_not_in_yaml",
   │           provenance="unresolved", api_base=None) + emit upstream_unresolved event
   │       - 1 match → use it (provenance="resolved")
   │       - N matches uniform classification → use first (provenance="resolved")
   │       - N matches mixed classification → fail-closed (provenance="ambiguous",
   │           api_base=None) + emit upstream_classification_ambiguous event
   │ 9a. Validate response content shape; KeyError/IndexError/TypeError on
   │     body['choices'][0]['message']['content'] → strict ledger via outer
   │     except + re-raise (Round-7 reviewer-P1)
   │ 10. Drift check: actual_resolved.model_string != preflight.model_string?
   │      → emit audit(gateway.upstream_drift_detected) with both resolutions
   │        (telemetry only — does NOT raise on its own)
   │ 11. Re-run cloud-policy on actual_resolved
   │      → deny? emit audit(gateway.cloud_policy_denied, post_response=True)
   │              + strict ledger write outcome="denied" upstream=actual
   │              + raise CloudPolicyViolationError (chained from drift event)
   │ 12. OUTPUT guardrails fire on response content
   │      → trip? strict ledger write outcome="guardrail_output"
   │              + raise GuardrailViolationError("output")
   │ 13. Strict ledger write outcome="ok"|"drift" OR raise LedgerWriteFailed
   │     ("drift" when actual != preflight AND actual policy allowed;
   │      "ok" when actual == preflight)
   │ 14. Return GatewayResponse to caller (only reachable after ledger persisted)
   └─────────────────────────────────────────────────────────────────────────────
```

Two ledger-write regimes per reviewer-P1#1:

- **Best-effort** (steps 2-4): LiteLLM never reached; the hash-chained `audit_event` already records the violation; ledger gap costs `/effective-routing` count fidelity but not chain-of-custody. Includes the `LLMConcurrencyExceeded` path — the `try/except` around the concurrency acquire ensures a saturation hit lands a ledger row before propagating (Round-2 reviewer-P2 fix).
- **Strict** (steps 11-13): LiteLLM dispatched; ADR-007's authoritativeness contract requires the ledger row before any successful return OR before any post-dispatch raise propagates with a "this happened" record. The post-response policy recheck (step 11) is the load-bearing fix for Round-2 reviewer-P1#1: pre-call policy ALLOW does not bind LiteLLM's actual dispatch, so we re-classify the actual upstream (using the resolver's `reverse_lookup` to get its api_base) and re-run policy. A divergent classification — e.g. preflight `openai/gpt-5.4` (external + allow-listed) but actual `bedrock/anthropic.claude` (external + NOT allow-listed) — fails loudly with `CloudPolicyViolationError(post_response=True)`.

#### Drift event vs post-response denial — separate concerns

Per Round-2 reviewer-P1#1: any `actual_model_string != preflight.model_string` is a **provider-honesty drift event** — emitted unconditionally as `gateway.upstream_drift_detected`. Whether the actual upstream's policy passes is a *separate* check whose denial fails loudly. Three cases:

| Case | Drift event | Policy on actual | Outcome | Raises |
|---|---|---|---|---|
| `actual == preflight` | none | n/a (already checked pre-call) | `ok` | no |
| `actual != preflight`, actual allowed | yes | allow | `drift` | no — call returns |
| `actual != preflight`, actual denied | yes | deny | `denied` | `CloudPolicyViolationError(post_response=True)` |

**No standalone `UpstreamDriftDetected` exception.** The drift signal is the audit event + the `outcome="drift"` ledger row + the actual `model_string`/`api_base` recorded for `/effective-routing`. The fail-loud channel is `CloudPolicyViolationError`, which is what banks already handle.

**Decisions baked in:**

- **INPUT runs BEFORE cloud-policy check.** Reason: a prompt that trips a PII filter never reaches the policy decision — we never want to log "would have called external LLM with this PII" as a separate evidence trail. Trip first, deny doesn't matter.
- **OUTPUT runs AFTER LLM call returns BEFORE caller sees the response.** Reason: the response could carry a model-leaked secret or a prompt-injection mirror; the gateway is the right place to filter, not the caller.
- **Trip = halt + raise.** Sprint 3 does not implement "redact and continue" or "warn and pass". Sprint 5+ may add modes; for now a trip is a hard-stop. This matches Sprint 2.5's `GuardrailPipeline.check` posture: pipeline returns a result, gateway interprets a non-empty trip list as a halt.
- **GuardrailPipeline is injected at construction, not built per-call.** `LLMGateway.__init__(input_pipeline: GuardrailPipeline | None, output_pipeline: GuardrailPipeline | None)`. None on either side = no guardrails on that direction (safe-by-construction null-object pattern). No global default — every call site declares what it wants. T6 ships `RegexPIIGuardrail` + `InjectionGuardrail` wired in dev compose; banks override the injection in their own deployment.

### §4 — SLA classification behaviour

SLAPolicy is injected at gateway construction, not per-call. Why: tier alias semantics + bank tier differ; the policy is a per-tier construction-time choice, not a per-prompt knob.

**Defaults:**

```python
SLAPolicy(
    total_budget=timedelta(seconds=30),     # tier-1 defaults to 30s end-to-end
    warning_threshold=timedelta(seconds=20),
)
```

**Classification points** (Sprint 2.5 SLATimer is a static-method namespace per reviewer-P2#1):

- `SLATimer.compute_deadline(start=now, policy=self._sla_policy)` runs at flow step 5 — AFTER input guardrails + policy + concurrency-slot acquisition, BEFORE the LLM call.
- `SLATimer.classify(now=now, deadline=deadline)` runs at flow step 8 — RIGHT after httpx returns.
- `BREACHED` → emit `audit_event` with `event_type="sla.breach"`, `payload={"alias": ..., "upstream": ..., "elapsed_ms": ..., "budget_ms": ...}`, `iso_controls=("ISO42001.A.9.2",)`. **Does not raise.** Caller decides whether breach triggers escalation.
- `WARNING` → log via the structured logger at WARNING level, no audit emission. Reason: warning is operational signal, not evidence. Banks who want evidence on warning emit it themselves via the SLA primitive.
- `GREEN` → no-op.

**Why no raise on breach:** Sprint 2.5 SLAPolicy is informational. The caller may have a downstream timeout that's stricter (e.g. an interactive request with a 10s outer budget); raising on breach would crash the caller's path even when the response is usable. ADR-006 A.9.2 wants the *evidence*, not the abort. Caller composes the abort behaviour if it wants one.

### §5 — Audit + decision-history emission contract

| Event | Substrate | When | Why |
|---|---|---|---|
| `gateway.cloud_policy_denied` (`post_response: false`) | `AuditStore.append` (hash-chained) | Flow step 3, before raise | A.9.2 requires proof that the policy enforcer denied a specific upstream pre-dispatch — the chain ensures that proof is tamper-evident. |
| `gateway.cloud_policy_denied` (`post_response: true`) | `AuditStore.append` (hash-chained) | Flow step 11, on actual-upstream re-policy denial | Round-2 reviewer-P1#1: the preflight ALLOW does not bind LiteLLM's actual dispatch. If actual classifies into a non-allow-listed provider (e.g. preflight openai/gpt-5.4 allow-listed, actual bedrock/anthropic.claude not in `allowed_providers`), this row is the evidence that the actual upstream was denied — emitted *in addition to* the drift event row. |
| `guardrail.trip` | `AuditStore.append` (already wired in Sprint 2.5 `GuardrailPipeline._emit_audit`) | Flow steps 2 + 12 | A.7.4 — guardrail evidence. Sprint 3 reuses the Sprint 2.5 emission verbatim; gateway does not re-emit. |
| `sla.breach` | `AuditStore.append` (hash-chained) | Flow step 8, on BREACHED | A.9.2 — operational logging. |
| `gateway.upstream_drift_detected` | `AuditStore.append` (hash-chained) | Flow step 10, on `actual_model_string != preflight.model_string` (string-equality, not classification-equality) | A.9.2 — Round-1 reviewer-P1#2 + Round-2 reviewer-P1#1. Telemetry-only on its own; does NOT raise. The fail-loud channel for unauthorised actual upstreams is the post-response `gateway.cloud_policy_denied` row + `CloudPolicyViolationError`. Drift without policy denial (preflight openai allowed, actual azure also allowed) records the provider-honesty record without aborting the call — banks who want stricter behaviour write a tenant Rego policy in Sprint 13.5 that denies any drift. |
| `gateway.upstream_classification_ambiguous` | `AuditStore.append` (hash-chained) | `_build_actual_resolved`, when reverse_lookup returns multiple matches with mixed external/self-hosted classification | A.9.2 — Round-3 + Round-4 reviewer-P1. The OpenAI-compat self-hosted vs cloud-OpenAI YAML-collision case: an `infra/litellm/config.yaml` that declares both a private-vLLM alias AND a cloud-OpenAI alias for the same `model: openai/gpt-4o` makes the post-response `model` field ambiguous about which alias actually dispatched. The fail-closed `ResolvedUpstream` carries `provenance="ambiguous"`, and `enforce_cloud_policy` denies UNCONDITIONALLY on `provenance != "resolved"` — even with `allow_external_llm=True` + the surface provider on `allowed_providers`. ADR-007's authoritativeness contract requires per-call provenance; an ambiguous match is a provenance gap that no policy permission can paper over. The YAML config issue is surfaced to the operator via this evidence row + the post-response `gateway.cloud_policy_denied` row. |
| `gateway.upstream_unresolved` | `AuditStore.append` (hash-chained) | `_build_unresolved_actual`, when reverse_lookup returns ZERO matches OR LiteLLM's response had a missing/empty/non-string `model` field. Payload carries `cause: "model_not_in_yaml" \| "missing_model_field"` so operators distinguish in evidence. | A.9.2 — Round-5 + Round-6 reviewer-P1. LiteLLM's response either named a model the resolver doesn't know about, or carried no model identifier at all — the gateway cannot truthfully report the actual api_base. Same provenance-gap treatment as the collision case: `ResolvedUpstream` carries `provenance="unresolved"` + `api_base=None`, and `enforce_cloud_policy` denies UNCONDITIONALLY. Single helper (`_build_unresolved_actual`) covers both causes. |
| **Gateway call** (pre-dispatch failure: input trip / cloud-policy denial / concurrency exhausted) | `gateway_call_ledger` (plain INSERT, **not** hash-chained) | Best-effort — log on failure, do not chain | ADR-007 — operational ledger. Hash-chained `audit_event` already records the violation; ledger gap costs `/effective-routing` fidelity, not chain-of-custody. |
| **Gateway call** (post-dispatch: happy path / output trip / drift / post-response policy denial / HTTP status error after `httpx.post` succeeded / JSON parse error on response body / possibly-dispatched httpx errors — `ReadTimeout`, `ReadError`, `WriteError`, `WriteTimeout`, `RemoteProtocolError`, etc. / **AuditStore failure mid-emission** / **malformed response content** — KeyError / IndexError / TypeError extracting `body['choices'][0]['message']['content']` / non-string content) | `gateway_call_ledger` (plain INSERT, **not** hash-chained) | **Strict** — failure raises `LedgerWriteFailed` (chained from any in-flight exception); no successful return without persistence | ADR-007 §"two layers" — the ledger is the **authoritative** source for `/system/effective-routing`. Round-1 + Round-4 + Round-5 + Round-7 reviewer-P1. The narrow pre-dispatch best-effort set is `httpx.ConnectError | ConnectTimeout | PoolTimeout | LocalProtocolError` only. Every other post-dispatch exit path lands a strict ledger row, including failures from emitting `sla.breach` / `gateway.upstream_drift_detected` / post-response `gateway.cloud_policy_denied` / `gateway.upstream_unresolved` / `gateway.upstream_classification_ambiguous` (Round-7 reviewer-P1: an `AuditStore.append` raise mid-emission would otherwise drop the ledger row even though LiteLLM was already contacted). Outer `try/except Exception` wraps the post-dispatch flow; on unexpected failure, strict-ledgers with `actual_resolved` if built or `preflight_resolved` as fallback, then re-raises. Malformed-response-content extraction (`body["choices"][0]["message"]["content"]`) is wrapped with a `_MalformedResponseContent` internal sentinel that propagates to the same outer catch. |
| `decision_history` | **NONE in Sprint 3** | — | ADR-013 `model_id` is Sprint 9.5. Without `model_id`, a `decision_history` row would be incomplete by design. Wave 2 wires this. |

**Ledger row shape:**

```python
class GatewayCallLedgerRow:
    id: uuid.UUID
    timestamp: datetime               # UTC, timezone-aware (Sprint 2 R3 contract)
    request_id: str
    tenant_id: str | None
    tier: Literal["tier1", "tier2"]
    litellm_alias: str                # cognic-tier1-dev / cognic-tier1-cloud-openai / ...
    upstream_model: str               # ollama/qwen3:8b / openai/gpt-5.4 / "<missing>" / ...
    upstream_api_base: str | None     # Round-6 reviewer-P1: post-substitution api_base from the resolved upstream;
                                      # NULL for unresolved/ambiguous post-dispatch rows + best-effort no-dispatch rows
    external: bool                    # _is_external(model_string, api_base) on the resolved upstream
    provenance: Literal["resolved", "unresolved", "ambiguous", "no_dispatch"]
                                      # Round-6 reviewer-P1: persists provenance status so /effective-routing
                                      # can authoritatively classify historical rows without re-resolving the
                                      # current YAML. resolved = single reverse_lookup match (or actual==preflight);
                                      # unresolved = zero reverse_lookup matches OR missing/invalid response model
                                      # field; ambiguous = mixed-classification collision; no_dispatch = pre-
                                      # dispatch failure (best-effort regime — upstream_model + api_base reflect
                                      # the INTENDED preflight target, not actual provenance).
    latency_ms: int                   # end-to-end gateway latency (input-guardrail-start to output-guardrail-done)
    outcome: Literal["ok", "denied", "guardrail_input", "guardrail_output", "concurrency_exhausted", "upstream_error", "drift"]
    model_id: str | None              # RESERVED — Sprint 9.5 backfills via ADR-013 model registry
```

**No prompt / response content ever lands in the ledger.** The ledger is metadata-only. Prompt + response live in Langfuse traces (Sprint 1C adapter) keyed by `request_id`; banks who need full audit replay correlate via `request_id`.

---

## File structure

### Created (~18)

- `src/cognic_agentos/llm/__init__.py` — package marker
- `src/cognic_agentos/llm/gateway.py` — `LLMGateway`, `GatewayResponse`, `resolve_tier_alias`, `Tier`, `UnknownTierError`, `LedgerWriteFailed`. Classification primitives are NOT here — they live with the YAML parser in `preflight.py` (Round-2 reviewer-P1#2 + co-location).
- `src/cognic_agentos/llm/preflight.py` — `PreflightResolver.from_yaml` (lazy `${VAR}` substitution per Round-2 reviewer-P1#3), `PreflightResolver.resolve(alias) -> ResolvedUpstream`, `PreflightResolver.reverse_lookup(model_string) -> tuple[ResolvedUpstream, ...]` (Round-3 reviewer-P1: returns ALL matching aliases so the gateway can fail-closed on collision), `ResolvedUpstream` dataclass (alias / model_string / api_base / external), `_is_external` (api_base-aware classifier per Round-2 reviewer-P1#2), `SELF_HOSTED_MODEL_PREFIXES`, `_KNOWN_CLOUD_HOST_SUFFIXES`, `_is_private_host`, `UnknownAliasError`
- `src/cognic_agentos/llm/concurrency.py` — `ProfileRateLimiter` (queued + fail-fast modes; atomic per-profile lock per reviewer-P2#2), `LLMConcurrencyExceeded`
- `src/cognic_agentos/llm/ledger.py` — `GatewayCallLedger.write_row`, `read_recent_calls(window_minutes)`, ledger row dataclass
- `src/cognic_agentos/llm/policy.py` — `enforce_cloud_policy(upstream, settings)`, `PolicyDecision`, `CloudPolicyViolationError`, `GuardrailViolationError`
- `src/cognic_agentos/db/migrations/versions/0002_gateway_call_ledger.py` — Alembic migration creating `gateway_call_ledger` (PG + Oracle dialect-portable; ledger is un-chained so just `Uuid` PK + `Datetime(timezone=True)` + columns)
- `src/cognic_agentos/portal/api/system_routes.py` — `/api/v1/system/policy` and `/api/v1/system/effective-routing` route handlers (factored out of `app.py` because two new endpoints + the existing `/readyz` shape make `app.py` too dense to test cleanly)
- `tests/unit/llm/__init__.py`
- `tests/unit/llm/test_gateway_alias_resolution.py` — tier → LiteLLM alias → upstream classification (incl. unknown-prefix fail-closed)
- `tests/unit/llm/test_gateway_policy.py` — cloud-policy decision tree + audit emission on denial
- `tests/unit/llm/test_preflight_resolver.py` — lazy `${VAR}` substitution (Round-2 reviewer-P1#3); unknown-alias fail-loud; round-trip against the real `infra/litellm/config.yaml` with dev-only env; api_base-aware classification of vLLM/SGLang OpenAI-compat self-hosted shapes (Round-2 reviewer-P1#2); `reverse_lookup` for post-response policy recheck
- `tests/unit/llm/test_gateway_classification.py` — vLLM/SGLang self-hosted with `model: openai/X` + private api_base classifies as self-hosted; cloud OpenAI without api_base classifies as external; mis-configured unknown api_base host fails closed (external)
- `tests/unit/llm/test_gateway_concurrency_ledger.py` — `LLMConcurrencyExceeded` produces a best-effort ledger row before propagating (Round-2 reviewer-P2)
- `tests/unit/llm/test_gateway_httpx_dispatch_errors.py` — parametrised over httpx exception types: `ConnectError | ConnectTimeout | PoolTimeout | LocalProtocolError` use best-effort regime; `ReadTimeout | ReadError | WriteError | WriteTimeout | RemoteProtocolError` use strict regime with preflight identity (Round-5 reviewer-P1)
- `tests/unit/llm/test_gateway_post_dispatch_strict_discipline.py` — Round-7 reviewer-P1: AuditStore failures mid-emission + malformed response content all hit the post-dispatch outer try/except, which strict-ledgers with the best-available `ResolvedUpstream` before re-raising
- `tests/unit/llm/test_gateway_completion.py` — happy path + denial path
- `tests/unit/llm/test_gateway_guardrails.py` — input + output guardrail attach + halt-and-audit on trip; output trip uses strict ledger regime
- `tests/unit/llm/test_gateway_sla.py` — breach emits audit but does not raise; warning logs but does not emit; green is no-op
- `tests/unit/llm/test_gateway_drift.py` — load-bearing for Round-1 reviewer-P1#2 + Round-2 reviewer-P1#1: drift event emitted on string mismatch (telemetry-only, no raise on its own); post-response policy recheck on actual `ResolvedUpstream` denies external→external provider drift (e.g. preflight openai allow-listed but actual bedrock not in allowed_providers); ledger row outcome="drift" when actual policy allows, outcome="denied" + post_response=True audit when actual policy denies
- `tests/unit/llm/test_gateway_ledger_contract.py` — load-bearing for reviewer-P1#1: strict-regime ledger failure raises `LedgerWriteFailed` not `GatewayResponse`; chains via `__cause__`; pre-dispatch path uses best-effort
- `tests/unit/llm/test_gateway_ledger.py` — ledger row shape + write semantics (no prompt content, model_id NULL on Sprint 3)
- `tests/unit/llm/test_concurrency.py` — fail-fast mode rejects when slot unavailable; queued mode waits; **Round-8 reviewer-P2 rewrite:** load-bearing tests are `test_fail_fast_raises_immediately_when_saturated` (pre-fill via public `acquire()` then nested fail_fast must raise) + `test_fail_fast_no_race_under_concurrent_arrival` (barrier-released contenders → exactly one wins the slot, one raises, neither blocks on slot availability)
- `tests/unit/llm/test_effective_routing.py` — endpoint reflects ledger; Langfuse-down sets `langfuse_available: false`; recent_calls window honoured; **Round-6 reviewer-P1 pin:** endpoint surfaces `upstream_api_base` + `provenance` from the persisted ledger row, NOT re-resolved from current YAML. **Round-7 reviewer-P1 pin:** PROFILE chip drift detection filters to `provenance != "no_dispatch"` (includes resolved+unresolved+ambiguous — all three are post-dispatch states). Negative regression seeded with `provenance="unresolved"` + `external=True` + `allow_external_llm=False` → drift count includes this row, PROFILE chip flips to `self-hosted (DRIFT)`.
- `tests/unit/llm/test_system_policy.py` — endpoint reflects current settings (allow_external_llm, mode, allowed_providers)
- `tests/integration/db/test_gateway_call_ledger.py` — env-gated PG + Oracle integration; round-trip ledger row; recent_calls query

### Modified (~5)

- `pyproject.toml` — no new runtime deps (httpx already pulled by Sprint 1A; LiteLLM is an external service, not a Python dep)
- `src/cognic_agentos/core/config.py` — adds `tier1_alias`, `tier2_alias`, `litellm_base_url`, `litellm_master_key`, `allow_external_llm`, `policy_mode`, `allowed_providers`, `llm_timeout_s`, `llm_concurrency_per_profile`, `llm_concurrency_mode` ("queued" | "fail_fast"), `provider_honesty_ledger_window_minutes` (default 60)
- `src/cognic_agentos/portal/api/app.py` — mounts `system_routes` router; lifespan opens `LLMGateway` (constructs ledger, guardrail pipelines, SLA policy from settings) so `/readyz` can include `llm_gateway: {status: ok | unreachable}`
- `src/cognic_agentos/portal/api/__init__.py` — re-exports new router if any
- `infra/litellm/config.yaml` — adds `cognic-tier1-cloud-openai`, `cognic-tier1-cloud-anthropic`, `cognic-tier2-cloud-openai`, `cognic-tier2-cloud-anthropic` cloud aliases (env-var-driven for keys; no key in source) so the denial path is exercisable end-to-end
- `tools/check_critical_coverage.py` — adds `src/cognic_agentos/llm/gateway.py`, `src/cognic_agentos/llm/policy.py`, and `src/cognic_agentos/llm/preflight.py` at ≥95% line / ≥90% branch (concurrency.py + ledger.py target ≥80% — operational, not critical-controls). Preflight is on the critical list because incorrect alias-to-upstream resolution silently bypasses the cloud-policy enforcer (reviewer-P1#2 reasoning).
- `.env.example` — documents the new settings
- `docs/BUILD_PLAN.md` — flips Sprint 3 status to **CLOSED** at T12 closeout
- `docs/closeouts/2026-04-30-sprint-3-llm-gateway-and-provider-honesty.md` — closeout note (T12)

---

## Tasks

### Task 0: Confirm clean working tree, branch from main

**Files:** none

- [ ] **Step 1: Verify branch + clean state**

```bash
git status --porcelain && git rev-parse --abbrev-ref HEAD
```

Expected: empty working-tree output; branch == `main` after the user authorizes branching.

- [ ] **Step 2: Wait for user `branch` authorization**

Per the per-action rule, branching is a remote-affecting choice (the next push targets a new ref). User says `branch` → create. Do not autonomously branch.

- [ ] **Step 3: After authorization, create branch**

```bash
git switch -c feat/sprint-3-llm-gateway
```

---

### Task 1: Settings extension

**Files:**
- Modify: `src/cognic_agentos/core/config.py`
- Modify: `.env.example`
- Test: `tests/unit/test_config.py` (extend existing — add new fields under their own test class)

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_config.py — add test class
class TestLLMGatewaySettings:
    def test_defaults_are_self_hosted_first(self, monkeypatch):
        monkeypatch.delenv("COGNIC_ALLOW_EXTERNAL_LLM", raising=False)
        get_settings.cache_clear()
        s = get_settings()
        assert s.allow_external_llm is False
        assert s.policy_mode == "self_hosted"
        assert s.allowed_providers == []
        assert s.tier1_alias == "cognic-tier1-dev"
        assert s.llm_timeout_s == 30.0
        assert s.llm_concurrency_per_profile == 4
        assert s.llm_concurrency_mode == "queued"

    def test_allowed_providers_parses_csv(self, monkeypatch):
        monkeypatch.setenv("COGNIC_ALLOWED_PROVIDERS", "openai,azure")
        get_settings.cache_clear()
        s = get_settings()
        assert s.allowed_providers == ["openai", "azure"]

    def test_policy_mode_rejects_unknown(self, monkeypatch):
        monkeypatch.setenv("COGNIC_POLICY_MODE", "no_such_mode")
        get_settings.cache_clear()
        with pytest.raises(ValueError):
            get_settings()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
uv run pytest tests/unit/test_config.py::TestLLMGatewaySettings -v
```

Expected: FAIL with `AttributeError` or pydantic validation error on missing fields.

- [ ] **Step 3: Implement settings extension**

Add to `Settings` in `core/config.py`:

```python
# --- LLM gateway (Sprint 3, per ADR-007) -------------------------
tier1_alias: str = Field(default="cognic-tier1-dev", description="LiteLLM alias resolved when caller asks for tier=tier1.")
tier2_alias: str = Field(default="cognic-tier2-dev", description="LiteLLM alias resolved when caller asks for tier=tier2.")
litellm_base_url: str | None = Field(default=None, description="LiteLLM router base URL (e.g. http://litellm:4000).")
litellm_master_key: str | None = Field(default=None, description="LiteLLM master key. Dev-only when set in source; prod sources via Vault (Sprint 10).")
allow_external_llm: bool = Field(default=False, description="Master cloud-policy gate per ADR-007. Default closed = self-hosted-first.")
policy_mode: Literal["self_hosted", "cloud_openai", "cloud_anthropic", "cloud_mixed"] = Field(default="self_hosted", description="Operator-declared deployment mode. Cross-checked against allow_external_llm.")
allowed_providers: Annotated[list[str], NoDecode] = Field(default_factory=list, description="Allow-list of external provider prefixes (openai, azure, anthropic, bedrock, cohere). Empty = self-hosted-only.")
llm_timeout_s: float = Field(default=30.0, gt=0.0, description="Per-call httpx timeout to LiteLLM.")
llm_concurrency_per_profile: int = Field(default=4, ge=1, description="Max in-flight gateway calls per profile.")
llm_concurrency_mode: Literal["queued", "fail_fast"] = Field(default="queued", description="Queued = block on slot. fail_fast = raise LLMConcurrencyExceeded.")
provider_honesty_ledger_window_minutes: int = Field(default=60, ge=1, le=1440, description="Window /system/effective-routing reads from the ledger.")

@field_validator("allowed_providers", mode="before")
@classmethod
def _split_allowed_providers(cls, value: object) -> list[str]:
    # Same shape as the CORS validator — accept None / [] / JSON array / CSV.
    if value is None:
        return []
    if isinstance(value, list):
        return [str(p).strip().lower() for p in value if str(p).strip()]
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        if stripped.startswith("["):
            import json as _json
            parsed = _json.loads(stripped)
            if not isinstance(parsed, list):
                raise ValueError("allowed_providers JSON value must be a list of strings")
            return [str(p).strip().lower() for p in parsed if str(p).strip()]
        return [p.strip().lower() for p in stripped.split(",") if p.strip()]
    raise ValueError(f"allowed_providers must be list, JSON array, or CSV; got {type(value).__name__}")
```

- [ ] **Step 4: Run test to verify it passes**

```bash
uv run pytest tests/unit/test_config.py::TestLLMGatewaySettings -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cognic_agentos/core/config.py .env.example tests/unit/test_config.py
git commit -m "feat(sprint-3): add LLM gateway settings (T1)

- Six new settings: tier{1,2}_alias, litellm_base_url, litellm_master_key,
  allow_external_llm (default False), policy_mode, allowed_providers,
  llm_timeout_s, llm_concurrency_*, provider_honesty_ledger_window_minutes.
- self-hosted-first defaults — allow_external_llm=False; allowed_providers=[].
- CSV/JSON-array env-var parsing on allowed_providers (mirrors the
  Sprint-1B cors_allowed_origins shape).
- Per ADR-007 (provider-honesty) — these settings drive the cloud-policy
  enforcer in T3 + the /system/policy endpoint in T9.
"
```

---

### Task 2: Tier alias resolver

**Files:**
- Create: `src/cognic_agentos/llm/__init__.py`
- Create: `src/cognic_agentos/llm/gateway.py` (tier resolver only — `LLMGateway` lands in T6)
- Test: `tests/unit/llm/__init__.py`
- Test: `tests/unit/llm/test_gateway_alias_resolution.py`

Note (Round-2 reviewer-P1#2): the api_base-aware `_is_external` classifier + `SELF_HOSTED_MODEL_PREFIXES` constant + `ResolvedUpstream` dataclass live in `src/cognic_agentos/llm/preflight.py` (T6 ships the resolver; this module hands `gateway.py` only the tier→alias-name translation). Keeping classification in the same module as the YAML parser avoids the circular dependency `gateway.py → preflight.py → gateway.py` that the Round-1 shape carried.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/llm/test_gateway_alias_resolution.py
import pytest
from cognic_agentos.llm.gateway import (
    UnknownTierError,
    resolve_tier_alias,
)


class TestResolveTierAlias:
    def test_tier1_resolves_from_settings(self, settings_with_tier1_alias):
        # settings_with_tier1_alias fixture sets tier1_alias = "cognic-tier1-vllm"
        assert resolve_tier_alias("tier1", settings_with_tier1_alias) == "cognic-tier1-vllm"

    def test_tier2_resolves_from_settings(self, settings_with_tier2_alias):
        assert resolve_tier_alias("tier2", settings_with_tier2_alias) == "cognic-tier2-sglang"

    def test_unknown_tier_raises(self, settings_with_tier1_alias):
        with pytest.raises(UnknownTierError, match="unknown tier"):
            resolve_tier_alias("tier99", settings_with_tier1_alias)
```

- [ ] **Step 2: Run test to verify it fails**

Expected: ImportError on `cognic_agentos.llm.gateway`.

- [ ] **Step 3: Implement tier resolver**

```python
# src/cognic_agentos/llm/gateway.py
"""LLM gateway (Sprint 3) — tier alias resolution + completion flow.

Layer classification: **platform primitive** (critical control per
AGENTS.md — cloud-policy enforcer + provider-honesty ledger feed).

This module ships the tier-name → LiteLLM-alias translator. The
LiteLLM-alias → ResolvedUpstream resolver + the api_base-aware
classifier live in ``cognic_agentos.llm.preflight`` (T6) so the
classification primitives and the YAML parser stay co-located.

The full ``LLMGateway.completion`` flow lands in T6.
"""

from __future__ import annotations

from typing import Literal

from cognic_agentos.core.config import Settings

#: Tier vocabulary. Sprint 3 ships two tiers; Sprint 9.5 (model
#: registry per ADR-013) may extend.
Tier = Literal["tier1", "tier2"]


class UnknownTierError(ValueError):
    """Raised when ``resolve_tier_alias`` sees a tier outside ``Tier``."""


def resolve_tier_alias(tier: str, settings: Settings) -> str:
    """Resolve a tier name to the configured LiteLLM alias.

    Reads ``settings.tier1_alias`` / ``settings.tier2_alias``. Sprint 3
    ships only two tiers; an unknown tier raises ``UnknownTierError``.
    """
    if tier == "tier1":
        return settings.tier1_alias
    if tier == "tier2":
        return settings.tier2_alias
    raise UnknownTierError(f"unknown tier {tier!r}; expected one of: tier1, tier2")
```

- [ ] **Step 4: Run test to verify it passes**

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cognic_agentos/llm/ tests/unit/llm/__init__.py tests/unit/llm/test_gateway_alias_resolution.py
git commit -m "feat(sprint-3): tier alias resolver (T2)

- llm/gateway.py: Tier literal + UnknownTierError + resolve_tier_alias.
- Classification primitives intentionally NOT in this module — they
  live with the YAML parser in llm/preflight.py (T6) for co-location
  reasons + to avoid the gateway → preflight → gateway circular
  dependency the Round-1 shape carried.
- Per Decision-Locking §1 + ADR-007 §two layers: classification keys
  off the api_base-aware ResolvedUpstream, not a bare model prefix.
- Full LLMGateway.completion flow lands in T6.
"
```

---

### Task 3: Cloud-policy enforcer

**Files:**
- Create: `src/cognic_agentos/llm/policy.py`
- Test: `tests/unit/llm/test_gateway_policy.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/llm/test_gateway_policy.py
import pytest

from cognic_agentos.llm.policy import (
    CloudPolicyViolationError,
    PolicyDecision,
    enforce_cloud_policy,
)
from cognic_agentos.llm.preflight import ResolvedUpstream


def _ollama() -> ResolvedUpstream:
    return ResolvedUpstream(alias="cognic-tier1-dev", model_string="ollama/qwen3:8b", api_base="http://ollama:11434", external=False)

def _vllm_self_hosted() -> ResolvedUpstream:
    """vLLM serving OpenAI-compat HTTP shape on a private host —
    Round-2 reviewer-P1#2 case: model_string starts with openai/ but
    api_base is private, so external=False."""
    return ResolvedUpstream(alias="cognic-tier1-vllm", model_string="openai/Qwen3-8B-Instruct", api_base="http://vllm:8000/v1", external=False)

def _openai_cloud() -> ResolvedUpstream:
    return ResolvedUpstream(alias="cognic-tier1-cloud-openai", model_string="openai/gpt-5.4", api_base=None, external=True)

def _bedrock_cloud() -> ResolvedUpstream:
    return ResolvedUpstream(alias="cognic-tier1-cloud-bedrock", model_string="bedrock/anthropic.claude-3-5-sonnet", api_base=None, external=True)


class TestEnforceCloudPolicy:
    def test_self_hosted_ollama_passes(self, settings_self_hosted):
        decision = enforce_cloud_policy(resolved=_ollama(), settings=settings_self_hosted, post_response=False)
        assert decision.allowed is True

    def test_self_hosted_vllm_passes_even_with_openai_model_prefix(self, settings_self_hosted):
        """Round-2 reviewer-P1#2: vLLM with private api_base must pass,
        even though model_string is openai/X."""
        decision = enforce_cloud_policy(resolved=_vllm_self_hosted(), settings=settings_self_hosted, post_response=False)
        assert decision.allowed is True
        assert "self-hosted" in decision.reason

    def test_external_with_flag_off_denies(self, settings_self_hosted):
        decision = enforce_cloud_policy(resolved=_openai_cloud(), settings=settings_self_hosted, post_response=False)
        assert decision.allowed is False
        assert "allow_external_llm=False" in decision.reason

    def test_external_with_flag_on_but_provider_not_allowlisted_denies(self, settings_cloud_anthropic_only):
        decision = enforce_cloud_policy(resolved=_openai_cloud(), settings=settings_cloud_anthropic_only, post_response=False)
        assert decision.allowed is False
        assert "openai" in decision.reason

    def test_external_with_flag_on_and_provider_allowlisted_passes(self, settings_cloud_openai_allowed):
        decision = enforce_cloud_policy(resolved=_openai_cloud(), settings=settings_cloud_openai_allowed, post_response=False)
        assert decision.allowed is True

    def test_external_to_external_drift_denied_post_response(self, settings_cloud_openai_allowed):
        """Round-2 reviewer-P1#1: openai allow-listed but actual is bedrock.
        Both classify as external; Round-1 classification-equality drift
        check would have missed this. Post-response policy recheck must deny."""
        decision = enforce_cloud_policy(resolved=_bedrock_cloud(), settings=settings_cloud_openai_allowed, post_response=True)
        assert decision.allowed is False
        assert "bedrock" in decision.reason

    def test_mode_self_hosted_with_flag_on_still_denies_external(self, settings_self_hosted_mode_with_flag_on):
        decision = enforce_cloud_policy(resolved=_openai_cloud(), settings=settings_self_hosted_mode_with_flag_on, post_response=False)
        assert decision.allowed is False
        assert "self_hosted" in decision.reason or "mode" in decision.reason

    def test_decision_carries_audit_payload_shape(self, settings_self_hosted):
        decision = enforce_cloud_policy(resolved=_openai_cloud(), settings=settings_self_hosted, post_response=False)
        assert decision.audit_payload["alias"] == "cognic-tier1-cloud-openai"
        assert decision.audit_payload["model_string"] == "openai/gpt-5.4"
        assert decision.audit_payload["api_base"] is None
        assert decision.audit_payload["external"] is True
        assert decision.audit_payload["policy_mode"] == "self_hosted"
        assert decision.audit_payload["post_response"] is False
        assert "reason" in decision.audit_payload
        # No prompt content / no PII in payload — Decision-Locking §2.
        assert "prompt" not in decision.audit_payload
        assert "messages" not in decision.audit_payload

    def test_post_response_flag_propagates_into_payload(self, settings_self_hosted):
        decision = enforce_cloud_policy(resolved=_openai_cloud(), settings=settings_self_hosted, post_response=True)
        assert decision.audit_payload["post_response"] is True


class TestCloudPolicyViolationError:
    def test_carries_decision(self, settings_self_hosted):
        decision = enforce_cloud_policy(resolved=_openai_cloud(), settings=settings_self_hosted, post_response=False)
        err = CloudPolicyViolationError.from_decision(decision)
        assert err.decision is decision
        assert "openai/gpt-5.4" in str(err)
```

- [ ] **Step 2: Run test to verify it fails**

Expected: ImportError.

- [ ] **Step 3: Implement enforcer**

```python
# src/cognic_agentos/llm/policy.py
"""Cloud-policy enforcer (Sprint 3) — pure function over a ResolvedUpstream + Settings.

Operates on the api_base-aware ``ResolvedUpstream`` rather than a bare
model string (Round-2 reviewer-P1#2). Audit payload carries alias,
model_string, api_base, external, plus the ``post_response`` flag
distinguishing pre-dispatch denials from the post-response policy
recheck (Round-2 reviewer-P1#1).

Per ADR-015 §"Sprint 13.5 (full)": this static enforcer is replaced by
an OPA-Rego query when the policy engine seed lands in Sprint 4 + the
full engine in Sprint 13.5. Sprint 3 ships the static check only.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from cognic_agentos.core.config import Settings
from cognic_agentos.llm.preflight import ResolvedUpstream

_KNOWN_EXTERNAL_PROVIDERS: tuple[str, ...] = (
    "openai", "azure", "anthropic", "bedrock", "cohere",
)


@dataclasses.dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    resolved: ResolvedUpstream
    reason: str
    policy_mode: str
    post_response: bool
    audit_payload: dict[str, Any]


class CloudPolicyViolationError(RuntimeError):
    def __init__(self, message: str, decision: PolicyDecision) -> None:
        super().__init__(message)
        self.decision = decision

    @classmethod
    def from_decision(cls, decision: PolicyDecision) -> "CloudPolicyViolationError":
        suffix = " (post-response recheck)" if decision.post_response else ""
        return cls(
            f"cloud-policy denial: {decision.reason} (upstream={decision.resolved.model_string}){suffix}",
            decision,
        )


class GuardrailViolationError(RuntimeError):
    def __init__(self, direction: str, trip_summary: str) -> None:
        super().__init__(f"guardrail.{direction} trip: {trip_summary}")
        self.direction = direction
        self.trip_summary = trip_summary


def enforce_cloud_policy(
    *,
    resolved: ResolvedUpstream,
    settings: Settings,
    post_response: bool,
) -> PolicyDecision:
    """Decision tree per Decision-Locking §2 (api_base-aware).

    Order matters — first match wins. Every code path that does not
    reach an explicit ALLOW returns DENY (fail-closed).
    """
    payload_base: dict[str, Any] = {
        "alias": resolved.alias,
        "model_string": resolved.model_string,
        "api_base": resolved.api_base,
        "external": resolved.external,
        "provenance": resolved.provenance,
        "policy_mode": settings.policy_mode,
        "allow_external_llm": settings.allow_external_llm,
        "allowed_providers": list(settings.allowed_providers),
        "post_response": post_response,
    }

    # Round-4 + Round-5 + Round-6 reviewer-P1: any provenance gap DENIES
    # unconditionally, before any allow_external_llm / allowed_providers
    # check. Reason: we cannot prove which upstream LiteLLM dispatched
    # against, and ADR-007's authoritativeness contract requires per-call
    # provenance. An operator who legitimately allows cloud OpenAI must
    # NOT silently get the call when the YAML has a colliding self-hosted
    # alias for the same model_string, or when the response model field
    # was missing, or when the actual model isn't declared in any route.
    if resolved.provenance != "resolved":
        reason = (
            f"provenance gap ({resolved.provenance}): cannot truthfully "
            "report which upstream LiteLLM dispatched against"
        )
        return PolicyDecision(
            allowed=False, resolved=resolved, reason=reason,
            policy_mode=settings.policy_mode, post_response=post_response,
            audit_payload={**payload_base, "reason": reason},
        )

    if not resolved.external:
        return PolicyDecision(
            allowed=True,
            resolved=resolved,
            reason="self-hosted upstream (api_base-aware); cloud-policy not applicable",
            policy_mode=settings.policy_mode,
            post_response=post_response,
            audit_payload={**payload_base, "reason": "self-hosted-pass"},
        )

    if not settings.allow_external_llm:
        reason = "external upstream blocked: allow_external_llm=False"
        return PolicyDecision(
            allowed=False, resolved=resolved, reason=reason,
            policy_mode=settings.policy_mode, post_response=post_response,
            audit_payload={**payload_base, "reason": reason},
        )

    provider = resolved.provider()
    if provider not in settings.allowed_providers:
        reason = f"provider {provider!r} not in allowed_providers"
        return PolicyDecision(
            allowed=False, resolved=resolved, reason=reason,
            policy_mode=settings.policy_mode, post_response=post_response,
            audit_payload={**payload_base, "reason": reason},
        )

    if settings.policy_mode == "self_hosted":
        reason = "policy_mode=self_hosted but external upstream attempted (operator misconfiguration)"
        return PolicyDecision(
            allowed=False, resolved=resolved, reason=reason,
            policy_mode=settings.policy_mode, post_response=post_response,
            audit_payload={**payload_base, "reason": reason},
        )

    return PolicyDecision(
        allowed=True, resolved=resolved,
        reason="external upstream allowed by policy",
        policy_mode=settings.policy_mode, post_response=post_response,
        audit_payload={**payload_base, "reason": "external-pass"},
    )
```

- [ ] **Step 4: Run test to verify it passes**

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cognic_agentos/llm/policy.py tests/unit/llm/test_gateway_policy.py
git commit -m "feat(sprint-3): cloud-policy enforcer (T3)

- llm/policy.py: enforce_cloud_policy + PolicyDecision dataclass +
  CloudPolicyViolationError + GuardrailViolationError.
- Decision tree fails closed: self-hosted always passes; external
  passes only when allow_external_llm=True AND provider on
  allowed_providers AND policy_mode != self_hosted.
- Audit payload exposed on the decision so the gateway can emit
  without reconstructing — mode/flag/allowed_providers/upstream/reason
  only; NO prompt content (Decision-Locking §2).
- Static enforcer per ADR-015 §Sprint 13.5: refactor to OPA query
  lands in 13.5; Sprint 3 ships the static shape.
"
```

---

### Task 4: Alembic migration for `gateway_call_ledger`

**Files:**
- Create: `src/cognic_agentos/db/migrations/versions/0002_gateway_call_ledger.py`
- Test: `tests/unit/db/test_migrations.py` — extend with downgrade-then-upgrade round-trip on the new revision (under existing fixture)

- [ ] **Step 1: Write the failing test**

Extend the existing migration round-trip test to drive 0001 → 0002 → 0001 → 0002 against the in-memory SQLite fixture.

- [ ] **Step 2: Run test to verify it fails**

Expected: revision 0002 not found.

- [ ] **Step 3: Implement migration**

```python
# src/cognic_agentos/db/migrations/versions/0002_gateway_call_ledger.py
"""gateway_call_ledger — Sprint 3 operational ledger per ADR-007.

Operational, not chain-of-custody. Plain INSERT semantics; no chain
head, no SELECT FOR UPDATE. ADR-007 §"two layers" — this is the
authoritative source for /api/v1/system/effective-routing because it
is local, transactional, and never lossy. Hash-chained tamper-evidence
for the violation cases lives in audit_event (Sprint 2 substrate);
duplicating tamper-evidence here would impose a write-rate ceiling
that ADR-007 explicitly rejects.

``model_id`` reserved nullable column — Sprint 9.5 backfills via the
ADR-013 model registry. Sprint 3 INSERTs NULL.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None
# NOTE: revision IDs match the existing 0001 migration's bare numeric
# form (revision = "0001"). The plan reviewer-P1#3 fix corrects the
# original "0001_initial_governance_schema" mis-naming that would have
# made Alembic unable to resolve the graph. The descriptive slug lives
# in the migration filename (`0002_gateway_call_ledger.py`), not the
# revision identifier.


def upgrade() -> None:
    op.create_table(
        "gateway_call_ledger",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=True),
        sa.Column("tier", sa.String(length=16), nullable=False),
        sa.Column("litellm_alias", sa.String(length=128), nullable=False),
        sa.Column("upstream_model", sa.String(length=256), nullable=False),
        # Round-6 reviewer-P1: api_base is dispositive for cloud-policy
        # classification, so /effective-routing must be able to read it
        # from the authoritative ledger without re-resolving current YAML.
        sa.Column("upstream_api_base", sa.String(length=512), nullable=True),
        sa.Column("external", sa.Boolean(), nullable=False),
        # Round-6 reviewer-P1: provenance status persisted so historical
        # rows can be classified authoritatively. Values:
        # resolved | unresolved | ambiguous | no_dispatch.
        sa.Column("provenance", sa.String(length=16), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        sa.Column("model_id", sa.String(length=128), nullable=True),
    )
    op.create_index("ix_gateway_ledger_ts", "gateway_call_ledger", ["ts"])
    op.create_index("ix_gateway_ledger_request_id", "gateway_call_ledger", ["request_id"])
    op.create_index("ix_gateway_ledger_provenance", "gateway_call_ledger", ["provenance"])


def downgrade() -> None:
    op.drop_index("ix_gateway_ledger_provenance", table_name="gateway_call_ledger")
    op.drop_index("ix_gateway_ledger_request_id", table_name="gateway_call_ledger")
    op.drop_index("ix_gateway_ledger_ts", table_name="gateway_call_ledger")
    op.drop_table("gateway_call_ledger")
```

- [ ] **Step 4: Run test to verify it passes**

```bash
uv run pytest tests/unit/db/test_migrations.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cognic_agentos/db/migrations/versions/0002_gateway_call_ledger.py tests/unit/db/test_migrations.py
git commit -m "feat(sprint-3): gateway_call_ledger Alembic migration (T4)

- New revision 0002 — gateway_call_ledger table per ADR-007.
- Plain INSERT; no chain head; no FOR UPDATE.
- model_id nullable + reserved for Sprint 9.5 (ADR-013 model registry).
- Indexes on ts + request_id for /system/effective-routing queries.
- Up/down round-trip green on PG + Oracle dialect-portable types.
"
```

---

### Task 5: GatewayCallLedger writer + reader

**Files:**
- Create: `src/cognic_agentos/llm/ledger.py`
- Test: `tests/unit/llm/test_gateway_ledger.py`
- Test: `tests/integration/db/test_gateway_call_ledger.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/llm/test_gateway_ledger.py
import datetime as dt
import uuid

import pytest

from cognic_agentos.llm.ledger import GatewayCallLedger, GatewayCallRow


class TestGatewayCallRowConstruction:
    def test_minimal_construction_succeeds(self):
        row = GatewayCallRow(
            id=uuid.uuid4(),
            ts=dt.datetime.now(dt.UTC),
            request_id="req-1",
            tenant_id=None,
            tier="tier1",
            litellm_alias="cognic-tier1-dev",
            upstream_model="ollama/qwen3:8b",
            external=False,
            latency_ms=523,
            outcome="ok",
            model_id=None,
        )
        assert row.outcome == "ok"

    def test_naive_timestamp_rejected_at_construction(self):
        with pytest.raises(ValueError, match="timezone-aware"):
            GatewayCallRow(
                id=uuid.uuid4(),
                ts=dt.datetime(2026, 4, 30, 12, 0),  # naive
                request_id="req-1",
                tenant_id=None,
                tier="tier1",
                litellm_alias="x",
                upstream_model="x/y",
                external=False,
                latency_ms=1,
                outcome="ok",
                model_id=None,
            )

    @pytest.mark.parametrize("outcome", ["ok", "denied", "drift", "guardrail_input", "guardrail_output", "concurrency_exhausted", "upstream_error"])
    def test_known_outcomes_accepted(self, outcome):
        row = GatewayCallRow(id=uuid.uuid4(), ts=dt.datetime.now(dt.UTC), request_id="r", tenant_id=None, tier="tier1", litellm_alias="x", upstream_model="x/y", external=False, latency_ms=0, outcome=outcome, model_id=None)
        assert row.outcome == outcome

    def test_unknown_outcome_rejected(self):
        with pytest.raises(ValueError, match="outcome"):
            GatewayCallRow(id=uuid.uuid4(), ts=dt.datetime.now(dt.UTC), request_id="r", tenant_id=None, tier="tier1", litellm_alias="x", upstream_model="x/y", external=False, latency_ms=0, outcome="bogus", model_id=None)


class TestLedgerWrite:
    async def test_write_row_persists(self, sqlite_engine_with_ledger):
        ledger = GatewayCallLedger(sqlite_engine_with_ledger)
        row = _make_row(outcome="ok")
        await ledger.write_row(row)

        rows = await ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].request_id == row.request_id

    async def test_read_recent_calls_window_filter(self, sqlite_engine_with_ledger):
        ledger = GatewayCallLedger(sqlite_engine_with_ledger)
        old_row = _make_row(outcome="ok", ts=dt.datetime.now(dt.UTC) - dt.timedelta(hours=2))
        new_row = _make_row(outcome="ok")
        await ledger.write_row(old_row)
        await ledger.write_row(new_row)

        rows = await ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].request_id == new_row.request_id
```

- [ ] **Step 2: Run test to verify it fails**

Expected: ImportError.

- [ ] **Step 3: Implement ledger**

```python
# src/cognic_agentos/llm/ledger.py
"""GatewayCallLedger — operational ledger feeding ADR-007.

Plain INSERT; no chain head. ``write_row`` raises on persistence
failure — it is the gateway's job (see Round-4 reviewer-P2 fix in
``LLMGateway``) to choose between best-effort vs strict regimes per
the ADR-007 success contract. The ledger primitive itself does NOT
swallow write failures; that posture decision belongs at the call
site, where the gateway knows whether LiteLLM dispatched.

Read-side (`read_recent_calls`) serves the provider-honesty endpoint.

Sprint 3 contract — ``model_id`` is always ``None`` on write; Sprint
9.5 (ADR-013 model registry) backfills.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import uuid
from typing import Literal

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

_ALLOWED_OUTCOMES: frozenset[str] = frozenset({
    "ok",
    "denied",                # pre- OR post-dispatch policy denial
    "drift",                 # actual_model_string != preflight; actual policy allowed
    "guardrail_input",
    "guardrail_output",
    "concurrency_exhausted",
    "upstream_error",
})

# Round-6 reviewer-P1: provenance status persisted at write time so
# /effective-routing can authoritatively classify historical rows.
_ALLOWED_PROVENANCES: frozenset[str] = frozenset({
    "resolved",       # actual upstream identified unambiguously
    "unresolved",     # zero reverse_lookup matches OR missing/invalid response model field
    "ambiguous",      # mixed-classification collision (multiple matches disagree)
    "no_dispatch",    # pre-dispatch failure — upstream_model + api_base reflect INTENDED preflight target
})


@dataclasses.dataclass(frozen=True, slots=True)
class GatewayCallRow:
    """A single ledger entry — one LLM call's metadata."""

    id: uuid.UUID
    ts: _dt.datetime
    request_id: str
    tenant_id: str | None
    tier: Literal["tier1", "tier2"]
    litellm_alias: str
    upstream_model: str
    upstream_api_base: str | None              # Round-6 reviewer-P1
    external: bool
    provenance: str                            # Round-6 reviewer-P1 — see _ALLOWED_PROVENANCES
    latency_ms: int
    outcome: str
    model_id: str | None  # reserved — Sprint 9.5 (ADR-013)

    def __post_init__(self) -> None:
        if self.ts.tzinfo is None:
            raise ValueError("ts must be timezone-aware (Sprint 2 R3 canonical-form contract)")
        if self.outcome not in _ALLOWED_OUTCOMES:
            raise ValueError(f"outcome {self.outcome!r} not in {sorted(_ALLOWED_OUTCOMES)}")
        if self.provenance not in _ALLOWED_PROVENANCES:
            raise ValueError(f"provenance {self.provenance!r} not in {sorted(_ALLOWED_PROVENANCES)}")


_ledger_table = sa.Table(
    "gateway_call_ledger",
    sa.MetaData(),
    sa.Column("id", sa.Uuid(), primary_key=True),
    sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
    sa.Column("request_id", sa.String(length=128), nullable=False),
    sa.Column("tenant_id", sa.String(length=128), nullable=True),
    sa.Column("tier", sa.String(length=16), nullable=False),
    sa.Column("litellm_alias", sa.String(length=128), nullable=False),
    sa.Column("upstream_model", sa.String(length=256), nullable=False),
    sa.Column("upstream_api_base", sa.String(length=512), nullable=True),
    sa.Column("external", sa.Boolean(), nullable=False),
    sa.Column("provenance", sa.String(length=16), nullable=False),
    sa.Column("latency_ms", sa.Integer(), nullable=False),
    sa.Column("outcome", sa.String(length=32), nullable=False),
    sa.Column("model_id", sa.String(length=128), nullable=True),
)


class GatewayCallLedger:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def write_row(self, row: GatewayCallRow) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(_ledger_table.insert().values(**dataclasses.asdict(row)))

    async def read_recent_calls(self, *, window_minutes: int) -> list[GatewayCallRow]:
        cutoff = _dt.datetime.now(_dt.UTC) - _dt.timedelta(minutes=window_minutes)
        async with self._engine.connect() as conn:
            result = await conn.execute(
                sa.select(_ledger_table)
                .where(_ledger_table.c.ts >= cutoff)
                .order_by(_ledger_table.c.ts.desc())
            )
            return [GatewayCallRow(**dict(r._mapping)) for r in result.fetchall()]
```

- [ ] **Step 4: Run test to verify it passes**

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cognic_agentos/llm/ledger.py tests/unit/llm/test_gateway_ledger.py tests/integration/db/test_gateway_call_ledger.py
git commit -m "feat(sprint-3): gateway_call_ledger writer + reader (T5)

- llm/ledger.py: GatewayCallRow frozen+slotted dataclass +
  GatewayCallLedger.write_row + read_recent_calls.
- Outcome whitelist enforced at construction.
- Naive timestamp rejected at boundary (Sprint 2 R3 contract).
- model_id reserved + always-None on Sprint 3 writes (ADR-013 / Sprint 9.5).
- Integration tests env-gated on PG + Oracle.
"
```

---

### Task 6: LLMGateway.completion — full flow

**Files:**
- Create: `src/cognic_agentos/llm/preflight.py` — `PreflightResolver` (authoritative alias→upstream map sourced from `infra/litellm/config.yaml`)
- Modify: `src/cognic_agentos/llm/gateway.py` — extend with `LLMGateway`, `GatewayResponse`, `LedgerWriteFailed`
- Modify: `src/cognic_agentos/llm/policy.py` — extend `enforce_cloud_policy` with the post-response variant (same function, different audit event tag on the drift path)
- Test: `tests/unit/llm/test_preflight_resolver.py`
- Test: `tests/unit/llm/test_gateway_guardrails.py`
- Test: `tests/unit/llm/test_gateway_sla.py`
- Test: `tests/unit/llm/test_gateway_completion.py`
- Test: `tests/unit/llm/test_gateway_drift.py` — load-bearing for reviewer-P1#2 (post-response upstream drift detection)
- Test: `tests/unit/llm/test_gateway_ledger_contract.py` — load-bearing for reviewer-P1#1 (success contract: no GatewayResponse without persisted ledger row)

#### Decision-locking restated for this task (after reviewer-P1#1, P1#2, P2#1)

The original T6 sample carried three drift bugs that the reviewer flagged. The fixes are baked into the rewritten flow below; calling them out here so the implementer doesn't re-introduce them:

- **Ledger persistence is part of the success contract** (reviewer-P1#1). A successful `GatewayResponse` cannot return without a persisted ledger row. If the ledger write fails on a dispatched call, the gateway raises `LedgerWriteFailed` (chained from the original cause) and the caller sees a 5xx — never a successful response with no provenance. Per ADR-007 §"two layers" the ledger is *authoritative* for `/system/effective-routing`; opportunistic writes contradict that.
- **Authoritative pre-call resolver + post-response drift check** (reviewer-P1#2). Cloud-policy classification operates on the upstream identifier per Decision-Locking §1, but a static inline map in the gateway can drift from LiteLLM's actual dispatch. The fix is two-part:
  1. `PreflightResolver` reads `infra/litellm/config.yaml` at startup — same source of truth LiteLLM consumes — eliminating the static-map-drift risk.
  2. After LiteLLM responds, the gateway either calls `PreflightResolver.reverse_lookup(actual_model_string)` and runs `_build_actual_resolved` (Round-3 reviewer-P1: 0 matches → unresolved; 1 match → use it; N uniform → use first; N mixed → ambiguous), OR — if the response carried no usable `model` field — calls `_build_unresolved_actual(cause="missing_model_field", ...)` directly (Round-6 reviewer-P1). All four outcomes set `ResolvedUpstream.provenance` accordingly. Then `enforce_cloud_policy(actual_resolved, settings, post_response=True)` runs. The enforcer's highest-priority gate is `if resolved.provenance != "resolved": DENY` — unconditional, applied before any allow-list check, because ADR-007 requires per-call provenance and any provenance gap is unrecoverable. A drift event (`gateway.upstream_drift_detected`) is emitted unconditionally on any `actual_model_string != preflight.model_string` (telemetry-only; no raise on its own). Actual-policy denial fails loudly via `CloudPolicyViolationError(post_response=True)` — closes the external→external silent-drift class flagged in Round-2, the YAML-collision-with-permissive-allow-list class flagged in Round-4, the zero-match-and-missing-model-field provenance gaps flagged in Round-5 + Round-6.
- **Sprint 2.5 API correctness** (reviewer-P2#1). `SLATimer` is a static-method namespace (`compute_deadline(start, policy)`, `classify(now, deadline)` — no instance, no `.policy` field). `GuardrailPipeline.check(content=..., direction=..., request_id=..., tenant_id=...)` returns `PipelineResult(passed: bool, results: tuple[GuardrailResult, ...])`. Trips derive from `[r for r in result.results if not r.passed]`. The plan now uses these exact signatures.

#### Failure-posture contract (per reviewer-P1#1 "define the failure posture explicitly")

Three regimes, decided by where in the flow we are when the ledger write happens:

| Stage when failure surfaces | Was LiteLLM dispatched? | Ledger write posture | Why |
|---|---|---|---|
| Pre-dispatch (input guardrail trip, cloud-policy denial, concurrency exhaustion) | No | **Best-effort** — log on failure, do not chain into the user-visible exception | The hash-chained `audit_event` already carries the evidence (`guardrail.trip` / `gateway.cloud_policy_denied`). A ledger gap on these paths costs us `/effective-routing` count fidelity but does not break chain-of-custody. |
| Dispatched + happy path | Yes | **Strict** — ledger write inline before `return`; failure raises `LedgerWriteFailed` instead of returning | ADR-007's authoritativeness contract: a successful return without a ledger row means `/effective-routing` reports a self-hosted posture that is no longer guaranteed by the ledger. Caller must see a 5xx. |
| Dispatched + post-call failure (output guardrail trip, drift detected, upstream HTTP error after partial response) | Yes | **Strict** — ledger write before raise; failure raises `LedgerWriteFailed` chained from the original | LiteLLM already hit the upstream — the ledger MUST record this happened so PROFILE-chip drift detection works. The original raise is preserved via `raise LedgerWriteFailed(...) from original_exc`. |

The `upstream_model is not None` flag is the runtime cue: non-None ⇒ LiteLLM dispatched ⇒ strict posture; None ⇒ pre-dispatch ⇒ best-effort posture.

- [ ] **Step 1: Implement `PreflightResolver` (TDD-first)**

Test (`tests/unit/llm/test_preflight_resolver.py`):

```python
import pytest
import yaml

from cognic_agentos.llm.preflight import PreflightResolver, UnknownAliasError


def _make_config(model_list):
    return yaml.safe_dump({"model_list": model_list, "litellm_settings": {}, "general_settings": {}})


class TestPreflightResolver:
    def test_resolves_dev_alias_to_ollama_upstream(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text(_make_config([
            {"model_name": "cognic-tier1-dev", "litellm_params": {"model": "ollama/qwen3:8b"}},
        ]))
        resolver = PreflightResolver.from_yaml(cfg)
        assert resolver.resolve("cognic-tier1-dev") == "ollama/qwen3:8b"

    def test_unknown_alias_fails_loudly(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text(_make_config([{"model_name": "cognic-tier1-dev", "litellm_params": {"model": "ollama/qwen3:8b"}}]))
        resolver = PreflightResolver.from_yaml(cfg)
        with pytest.raises(UnknownAliasError, match="not declared in"):
            resolver.resolve("cognic-tier1-cloud-openai")

    def test_substitutes_env_vars_at_resolve_time(self, tmp_path, monkeypatch):
        """LiteLLM uses ${VAR_NAME} substitution. The resolver must do the
        same so the parsed upstream matches what LiteLLM dispatches.

        Round-2 reviewer-P1#3: substitution is **lazy** — happens on
        ``resolve(alias)``, not at ``from_yaml`` load time. This means
        a dev environment with COGNIC_TIER1_VLLM_MODEL unset can still
        load the resolver as long as it never resolves the vllm alias.
        """
        monkeypatch.setenv("COGNIC_TIER1_VLLM_MODEL", "Qwen3-8B-Instruct")
        cfg = tmp_path / "config.yaml"
        cfg.write_text(_make_config([
            {"model_name": "cognic-tier1-vllm", "litellm_params": {"model": "openai/${COGNIC_TIER1_VLLM_MODEL}", "api_base": "http://vllm:8000/v1"}},
        ]))
        resolver = PreflightResolver.from_yaml(cfg)
        resolved = resolver.resolve("cognic-tier1-vllm")
        assert resolved.model_string == "openai/Qwen3-8B-Instruct"
        assert resolved.api_base == "http://vllm:8000/v1"
        assert resolved.external is False  # api_base on private hostname → self-hosted (Round-2 reviewer-P1#2)

    def test_lazy_substitution_does_not_require_unused_aliases(self, tmp_path, monkeypatch):
        """The Round-2 reviewer-P1#3 load-bearing test.

        Real ``infra/litellm/config.yaml`` declares vLLM/SGLang aliases
        whose env vars are normally unset in dev. A naive eager-substitution
        from_yaml() would fail at import time. The lazy resolver must
        construct fine and only fail when the operator tries to ``resolve``
        an alias whose vars are missing.
        """
        monkeypatch.delenv("COGNIC_TIER1_VLLM_MODEL", raising=False)
        cfg = tmp_path / "config.yaml"
        cfg.write_text(_make_config([
            {"model_name": "cognic-tier1-dev", "litellm_params": {"model": "ollama/qwen3:8b", "api_base": "http://ollama:11434"}},
            {"model_name": "cognic-tier1-vllm", "litellm_params": {"model": "openai/${COGNIC_TIER1_VLLM_MODEL}", "api_base": "http://vllm:8000/v1"}},
        ]))
        # MUST NOT raise — the vllm var is unset but we're not using that alias.
        resolver = PreflightResolver.from_yaml(cfg)
        # The dev alias works:
        assert resolver.resolve("cognic-tier1-dev").model_string == "ollama/qwen3:8b"
        # The vllm alias fails ONLY when actually selected:
        with pytest.raises(ValueError, match="COGNIC_TIER1_VLLM_MODEL"):
            resolver.resolve("cognic-tier1-vllm")

    def test_round_trip_against_real_compose_config_dev_env_only(self, monkeypatch):
        """Reads the real ``infra/litellm/config.yaml``.

        Sets ONLY the dev/Ollama env. Round-2 reviewer-P1#3 pin: the
        production vLLM/SGLang aliases must not require their env vars
        to be set just to load the resolver — only to resolve them.
        """
        from pathlib import Path
        # Clear all the production env vars to prove the dev path stands alone.
        for var in ("COGNIC_TIER1_VLLM_MODEL", "COGNIC_TIER2_VLLM_MODEL",
                    "COGNIC_TIER1_SGLANG_MODEL", "COGNIC_TIER2_SGLANG_MODEL",
                    "VLLM_BASE_URL", "VLLM_API_KEY",
                    "SGLANG_BASE_URL", "SGLANG_API_KEY"):
            monkeypatch.delenv(var, raising=False)
        repo_root = Path(__file__).resolve().parents[3]
        resolver = PreflightResolver.from_yaml(repo_root / "infra/litellm/config.yaml")
        # Dev aliases resolve cleanly:
        assert resolver.resolve("cognic-tier1-dev").model_string.startswith("ollama/")
        assert resolver.resolve("cognic-tier2-dev").model_string.startswith("ollama/")
        # Production aliases are KNOWN but not RESOLVED — calling resolve raises.
        assert "cognic-tier1-vllm" in resolver.known_aliases
        with pytest.raises(ValueError):
            resolver.resolve("cognic-tier1-vllm")

    def test_classifies_openai_compat_self_hosted_as_self_hosted(self, tmp_path, monkeypatch):
        """Round-2 reviewer-P1#2 load-bearing test.

        ``model: openai/X`` + ``api_base: http://vllm:8000/v1`` is the
        production self-hosted vLLM shape. The api_base-aware classifier
        must mark this as self-hosted, NOT external.
        """
        monkeypatch.setenv("COGNIC_TIER1_VLLM_MODEL", "Qwen3-8B-Instruct")
        cfg = tmp_path / "config.yaml"
        cfg.write_text(_make_config([
            {"model_name": "cognic-tier1-vllm", "litellm_params": {"model": "openai/${COGNIC_TIER1_VLLM_MODEL}", "api_base": "http://vllm:8000/v1"}},
            {"model_name": "cognic-tier1-cloud-openai", "litellm_params": {"model": "openai/gpt-4o", "api_key": "sk-test"}},  # no api_base → cloud
        ]))
        resolver = PreflightResolver.from_yaml(cfg)
        vllm = resolver.resolve("cognic-tier1-vllm")
        cloud = resolver.resolve("cognic-tier1-cloud-openai")
        assert vllm.external is False, "vLLM with private api_base must classify as self-hosted"
        assert cloud.external is True, "openai/* without api_base must classify as external"

    def test_reverse_lookup_returns_all_matches(self, tmp_path, monkeypatch):
        """Round-3 reviewer-P1: reverse_lookup returns ALL aliases whose
        resolved model_string matches. The gateway disambiguates."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text(_make_config([
            {"model_name": "cognic-tier1-dev", "litellm_params": {"model": "ollama/qwen3:8b", "api_base": "http://ollama:11434"}},
            {"model_name": "cognic-tier1-cloud-openai", "litellm_params": {"model": "openai/gpt-5.4", "api_key": "sk-test"}},
        ]))
        resolver = PreflightResolver.from_yaml(cfg)
        matches = resolver.reverse_lookup("openai/gpt-5.4")
        assert len(matches) == 1
        assert matches[0].alias == "cognic-tier1-cloud-openai"
        assert matches[0].external is True
        assert resolver.reverse_lookup("anthropic/claude-3-5-sonnet") == ()  # unknown — empty tuple

    def test_reverse_lookup_returns_all_matches_on_collision(self, tmp_path, monkeypatch):
        """Round-3 reviewer-P1 load-bearing test: two aliases share the
        same model_string but differ in api_base/classification — exactly
        the OpenAI-compat self-hosted vs cloud OpenAI shape this plan
        supports. ``reverse_lookup`` must return ALL matches so the
        gateway can detect the ambiguity and fail-closed."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text(_make_config([
            # Self-hosted vLLM serving openai/gpt-4o:
            {"model_name": "cognic-tier1-vllm-gpt4o-shape", "litellm_params": {"model": "openai/gpt-4o", "api_base": "http://vllm:8000/v1"}},
            # Real cloud OpenAI gpt-4o:
            {"model_name": "cognic-tier1-cloud-openai", "litellm_params": {"model": "openai/gpt-4o", "api_key": "sk-test"}},
        ]))
        resolver = PreflightResolver.from_yaml(cfg)
        matches = resolver.reverse_lookup("openai/gpt-4o")
        assert len(matches) == 2, "both aliases share the model_string and must both surface"
        externals = {m.external for m in matches}
        assert externals == {True, False}, "matches must reflect the api_base-aware classification disagreement"
        # Caller (gateway) reads len(matches) > 1 + classification disagreement → fail-closed.
```

Implementation (`src/cognic_agentos/llm/preflight.py`):

```python
"""PreflightResolver — authoritative alias → ResolvedUpstream map.

Reads ``infra/litellm/config.yaml`` (the same source of truth LiteLLM
consumes) at startup. Stores RAW model_string + api_base templates;
``${VAR}`` substitution is **lazy** — happens at ``resolve(alias)``
time so the resolver loads cleanly in dev/CI environments where
production-only env vars (e.g. ``COGNIC_TIER1_VLLM_MODEL``) are unset
(Round-2 reviewer-P1#3).

The classification (self-hosted vs external) uses BOTH the model
string prefix AND the api_base host — the api_base is dispositive
because vLLM/SGLang serve the OpenAI-compatible HTTP shape with
``model: openai/<name>`` against a private api_base (Round-2
reviewer-P1#2).
"""

from __future__ import annotations

import dataclasses
import ipaddress
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


class UnknownAliasError(KeyError):
    """Raised when an alias is not declared in the LiteLLM config."""


@dataclasses.dataclass(frozen=True, slots=True)
class ResolvedUpstream:
    """Enriched upstream identity used by the cloud-policy enforcer.

    All fields are post-substitution (resolved at ``resolve()`` call
    time). Round-2 reviewer-P1#2 baked in: ``external`` reflects the
    api_base-aware classification, NOT a bare model-prefix check.

    Round-4 + Round-5 + Round-6 reviewer-P1: ``provenance`` carries the
    provenance state. ``"resolved"`` = single reverse_lookup match (or
    no reverse-lookup needed in the pre-call resolve path).
    ``"unresolved"`` = zero reverse_lookup matches OR LiteLLM response
    had a missing/invalid ``model`` field. ``"ambiguous"`` = multiple
    reverse_lookup matches with disagreeing classifications.
    ``enforce_cloud_policy`` denies UNCONDITIONALLY when
    ``provenance != "resolved"`` — even with ``allow_external_llm=True``
    and the surface provider on ``allowed_providers`` — because we
    genuinely cannot prove which upstream LiteLLM dispatched against,
    and provenance is the bedrock of ADR-007.
    """

    alias: str
    model_string: str
    api_base: str | None
    external: bool
    provenance: Literal["resolved", "unresolved", "ambiguous"] = "resolved"

    def provider(self) -> str | None:
        head, _, _ = self.model_string.partition("/")
        return head or None


#: Self-hosted model-string prefixes. Only consulted when ``api_base``
#: is unset (otherwise the api_base host is dispositive).
SELF_HOSTED_MODEL_PREFIXES: tuple[str, ...] = (
    "ollama/", "vllm/", "sglang/", "openai-compat/", "local/",
)

#: Known external host suffixes. If api_base hostname matches any of
#: these, the upstream is external regardless of model prefix.
_KNOWN_CLOUD_HOST_SUFFIXES: tuple[str, ...] = (
    "api.openai.com",
    ".openai.azure.com",
    "api.anthropic.com",
    ".bedrock.amazonaws.com",         # bedrock-runtime.<region>.amazonaws.com
    ".bedrock-runtime.amazonaws.com",
    "api.cohere.ai",
    "api.cohere.com",
    ".googleapis.com",
    "generativelanguage.googleapis.com",
)

_ENV_VAR_RE = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}")


def _substitute_env(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        var_name = match.group(1)
        default = match.group(2)
        if var_name in os.environ:
            return os.environ[var_name]
        if default is not None:
            return default
        raise ValueError(f"environment variable {var_name!r} required by litellm config but not set")
    return _ENV_VAR_RE.sub(replace, value)


def _is_private_host(host: str) -> bool:
    """Container DNS / RFC1918 / loopback / *.local / *.internal / *.svc."""
    if host in {"localhost"}:
        return True
    if host.endswith((".local", ".internal", ".svc", ".svc.cluster.local")):
        return True
    # No-tld single-label name is a docker-compose-style hostname.
    if "." not in host:
        return True
    # IP literals — RFC1918 / loopback / link-local.
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def _is_known_cloud_host(host: str) -> bool:
    return any(host == sfx.lstrip(".") or host.endswith(sfx) for sfx in _KNOWN_CLOUD_HOST_SUFFIXES)


def _is_external(model_string: str, api_base: str | None) -> bool:
    """Cloud-policy classification per Decision-Locking §1 priority order."""
    if api_base is not None:
        host = (urlparse(api_base).hostname or "").lower()
        if _is_known_cloud_host(host):
            return True
        if _is_private_host(host):
            return False
        return True  # api_base set, host unrecognised → fail-closed
    # api_base unset — fall back to model prefix.
    if any(model_string.startswith(p) for p in SELF_HOSTED_MODEL_PREFIXES):
        return False
    return True  # unknown prefix without api_base → fail-closed


@dataclasses.dataclass(frozen=True, slots=True)
class _RawEntry:
    model_template: str
    api_base_template: str | None


class PreflightResolver:
    """Resolve a LiteLLM alias to its enriched ``ResolvedUpstream``."""

    def __init__(self, raw_entries: dict[str, _RawEntry]) -> None:
        self._raw = dict(raw_entries)

    @classmethod
    def from_yaml(cls, path: Path) -> "PreflightResolver":
        """Parse the YAML and store RAW templates. Substitution is lazy."""
        raw = yaml.safe_load(Path(path).read_text())
        model_list: list[dict[str, Any]] = raw.get("model_list") or []
        entries: dict[str, _RawEntry] = {}
        for entry in model_list:
            alias = entry.get("model_name")
            params = entry.get("litellm_params") or {}
            model_template = params.get("model")
            api_base_template = params.get("api_base")
            if not alias or not model_template:
                continue
            entries[alias] = _RawEntry(model_template=model_template, api_base_template=api_base_template)
        return cls(entries)

    def resolve(self, alias: str) -> ResolvedUpstream:
        """Resolve ``alias`` to a ``ResolvedUpstream``. Substitutes env
        vars NOW; raises ValueError if any required var is unset."""
        if alias not in self._raw:
            raise UnknownAliasError(f"alias {alias!r} not declared in litellm config; known: {sorted(self._raw)}")
        entry = self._raw[alias]
        model_string = _substitute_env(entry.model_template)
        api_base = _substitute_env(entry.api_base_template) if entry.api_base_template else None
        return ResolvedUpstream(
            alias=alias,
            model_string=model_string,
            api_base=api_base,
            external=_is_external(model_string, api_base),
        )

    def reverse_lookup(self, model_string: str) -> tuple[ResolvedUpstream, ...]:
        """Find ALL aliases whose resolved ``model_string`` matches.

        Returns a tuple — empty when nothing matches, single-entry on
        the common case, multi-entry on the load-bearing ambiguity case
        (Round-3 reviewer-P1): two aliases that share the same
        model_string but differ in api_base / classification — e.g. a
        self-hosted vLLM serving ``openai/gpt-4o`` and the real cloud
        ``openai/gpt-4o`` declared as separate aliases for routing.

        Returning all matches keeps this primitive free of policy. The
        gateway is the right place to decide what to do with an
        ambiguous match: if classifications agree, pick first; if they
        disagree, **fail closed** — treat as drift with external=True
        + emit a `gateway.upstream_classification_ambiguous` event so
        the operator sees the YAML-level config issue.
        """
        out: list[ResolvedUpstream] = []
        for alias in self._raw:
            try:
                resolved = self.resolve(alias)
            except ValueError:
                continue  # unresolvable env — skip
            if resolved.model_string == model_string:
                out.append(resolved)
        return tuple(out)

    @property
    def known_aliases(self) -> tuple[str, ...]:
        return tuple(self._raw)
```

- [ ] **Step 2: Write the gateway tests**

Seven test modules, each load-bearing for one contract claim:

1. `test_gateway_completion.py` — happy path: tier1 → cognic-tier1-dev → ollama/qwen3:8b (private api_base). Asserts: ledger row written **before** return, outcome="ok", external=False, no audit_event. Uses httpx-respx for the LiteLLM stub.
2. `test_gateway_guardrails.py`:
   - INPUT trip halts before policy resolution + raises `GuardrailViolationError("input")` + ledger row outcome="guardrail_input" (best-effort regime).
   - OUTPUT trip raises `GuardrailViolationError("output")` + **ledger row outcome="guardrail_output" MUST be present** (post-dispatch strict regime).
3. `test_gateway_sla.py` — breach emits `audit_event(sla.breach)` + iso_controls=("ISO42001.A.9.2",); does NOT raise; ledger outcome="ok"; warning logs no-audit; green is no-op.
4. `test_gateway_completion.py` (denied path) — cloud upstream + flag off → `audit_event(gateway.cloud_policy_denied, post_response=False)` + `CloudPolicyViolationError`; **no LiteLLM HTTP call made** (httpx-respx asserts zero requests); ledger row best-effort outcome="denied".
5. `test_gateway_drift.py` (**load-bearing for Round-1+Round-2 reviewer-P1#1**) — three subtests:
   - **Drift + actual allowed:** resolver has both `cognic-tier1-cloud-openai → openai/gpt-5.4` (api_key, no api_base) and `cognic-tier1-cloud-azure → azure/gpt-4o`. Settings allow both `openai` and `azure`. Caller asks tier1=cloud-openai; httpx-respx makes LiteLLM return `{"model": "azure/gpt-4o", ...}`. Asserts: `audit_event(gateway.upstream_drift_detected)` emitted; **NO `gateway.cloud_policy_denied` event**; ledger row outcome="drift" with upstream="azure/gpt-4o"; **GatewayResponse returned** (no raise — actual policy allowed).
   - **Drift + actual denied:** same setup but settings allow ONLY `openai`. Asserts: `audit_event(gateway.upstream_drift_detected)` AND `audit_event(gateway.cloud_policy_denied, post_response=True)`; ledger row outcome="denied" with upstream="azure/gpt-4o" (post-dispatch strict — call DID happen); raises `CloudPolicyViolationError`.
   - **External-to-external silent drift** (the Round-2 reviewer-P1#1 specific case): preflight `openai/gpt-5.4` allow-listed, actual `bedrock/anthropic.claude-3` NOT allow-listed. Both classify as external — Round-1 check (`_is_external` equality) would have missed this; Round-2 fix runs the policy enforcer on the actual ResolvedUpstream and denies. Asserts: drift event + post_response=True denied event + raise.
6. `test_gateway_classification.py` (**load-bearing for Round-2 reviewer-P1#2**):
   - vLLM self-hosted shape: `model: openai/Qwen3-8B-Instruct` + `api_base: http://vllm:8000/v1`. Resolver returns `external=False`. Default settings (`allow_external_llm=False`) ALLOW the call.
   - SGLang self-hosted shape: same posture. Confirm allow.
   - Cloud OpenAI shape: `model: openai/gpt-5.4`, no api_base. Resolver returns `external=True`. Default settings DENY.
   - Mis-configured api_base = unknown host (not on cloud allow-list, not private): resolver returns `external=True` (fail-closed). Default settings DENY.
7. `test_gateway_concurrency_ledger.py` (**load-bearing for Round-2 reviewer-P2**):
   - Saturate the limiter; next acquire raises `LLMConcurrencyExceeded`. Asserts: a ledger row exists with outcome="concurrency_exhausted" (best-effort) BEFORE the exception propagates to the caller.

7b. `test_gateway_post_dispatch_strict_discipline.py` (**load-bearing for Round-7 reviewer-P1**):
   - **Subtest A — AuditStore raises on `sla.breach` emit:** httpx-respx returns a slow successful response that triggers SLA BREACHED; stub `AuditStore.append` to raise on the `sla.breach` event. Asserts: a strict ledger row was written with `outcome="upstream_error"` + `provenance="resolved"` (actual_resolved was built before the audit failure) BEFORE the AuditStore exception propagates to the caller; the original AuditStore exception is what the caller sees.
   - **Subtest B — AuditStore raises on `gateway.upstream_drift_detected` emit:** drift case (actual != preflight); stub AuditStore to raise on the drift event. Same assertion: strict ledger row with `outcome="upstream_error"` + `actual_resolved` identity; original exception propagates.
   - **Subtest C — AuditStore raises on `gateway.upstream_unresolved` emit (Round-8 reviewer-P1):** missing-model-field case; stub AuditStore to raise on the unresolved event. `_build_unresolved_actual` is sync (Round 8) so `actual_resolved` IS bound to the correct `provenance="unresolved"` ResolvedUpstream BEFORE the audit emission. Strict ledger writes `provenance="unresolved"` + `upstream_model="<missing>"` + `upstream_api_base IS NULL` — NOT preflight identity. Variant: same shape with `cause="model_not_in_yaml"` (zero reverse_lookup matches) — same assertion. Both pin that the round-8 sync-build pattern preserves correct provenance through the outer catch-all even when the audit emission fails.
   - **Subtest C2 — AuditStore raises on `gateway.upstream_classification_ambiguous` emit (Round-8 reviewer-P1):** mixed-classification YAML; stub AuditStore to raise on the ambiguous event. Strict ledger writes `provenance="ambiguous"` + `upstream_api_base IS NULL` — NOT preflight identity. Confirms the same sync-build-then-audit pattern works for the ambiguous path.
   - **Subtest D — Malformed response content (no `choices`):** httpx-respx returns `{"model": "openai/gpt-5.4"}` (no choices key). KeyError fires inside the wrapped extraction. Asserts: strict ledger row written with `outcome="upstream_error"` + `actual_resolved` identity (already built); `KeyError` (or `_MalformedResponseContent` chained from it) propagates.
   - **Subtest E — Malformed response content (non-string):** httpx-respx returns `{"model": "openai/gpt-5.4", "choices": [{"message": {"content": 42}}]}`. Asserts: strict ledger + same shape as Subtest D.
   - **Negative regression:** stub `_ledger.write_row` to ALSO fail in Subtest A. Asserts `LedgerWriteFailed` raised, NOT the bare AuditStore exception; ADR-007 success contract preserved on the outer-catch path.

7a. `test_gateway_httpx_dispatch_errors.py` (**load-bearing for Round-5 reviewer-P1**):
   - Parametrised over `(httpx.ConnectError, "best_effort")`, `(httpx.ConnectTimeout, "best_effort")`, `(httpx.PoolTimeout, "best_effort")`, `(httpx.LocalProtocolError, "best_effort")`, `(httpx.ReadTimeout, "strict")`, `(httpx.ReadError, "strict")`, `(httpx.WriteError, "strict")`, `(httpx.WriteTimeout, "strict")`, `(httpx.RemoteProtocolError, "strict")`. For each:
     - Stub `httpx.AsyncClient.post` to raise the parametrised exception.
     - Assert the ledger row exists with outcome="upstream_error".
     - For `best_effort` cases: assert ledger has `upstream_model="<unresolved>"` + `external=False` (best-effort regime).
     - For `strict` cases: assert ledger has `upstream_model=preflight_resolved.model_string` + `external=preflight_resolved.external` (strict regime — preflight identity preserved).
   - Negative regression: stub `_ledger.write_row` to raise on a `strict` case → asserts `LedgerWriteFailed` raised, NOT the original httpx exception (chained via `__cause__`). The ADR-007 success contract holds even on dispatch-time httpx errors.
8. `test_gateway_classification_ambiguity.py` (**load-bearing for Round-3 + Round-4 + Round-5 reviewer-P1**):
   - YAML declares two aliases sharing `model: openai/gpt-4o`: `cognic-tier1-vllm-gpt4o-shape` (api_base=`http://vllm:8000/v1`, self-hosted) AND `cognic-tier1-cloud-openai` (api_key, no api_base, external).
   - Caller asks for one alias; httpx-respx makes LiteLLM return `{"model": "openai/gpt-4o", ...}` (the shared model string).
   - **Subtest A — collision, default settings:** asserts `gateway.upstream_classification_ambiguous` event emitted with both matching aliases + classifications in payload; `actual_resolved.provenance == "ambiguous"`; post-response policy recheck DENIES; raises `CloudPolicyViolationError` whose decision payload carries `provenance="ambiguous"`; ledger row outcome="denied" + `provenance="ambiguous"` (post-dispatch strict).
   - **Subtest B — collision, `allow_external_llm=True`, `allowed_providers=["openai"]`:** asserts the call STILL DENIES (Round-4 reviewer-P1 — any provenance gap overrides the surface-provider allow-list because ADR-007 authoritativeness depends on per-call provenance). Audit row carries `provenance="ambiguous"` AND `allow_external_llm=true` AND `allowed_providers=["openai"]` so the operator can see the YAML config issue caused the denial, not the policy itself.
   - **Subtest C — collision, `enforce_cloud_policy` direct test:** with `ResolvedUpstream(provenance="ambiguous", external=True)` and the most-permissive settings (`allow_external_llm=True`, `allowed_providers=["openai", "azure", "anthropic", "bedrock", "cohere"]`, `policy_mode="cloud_mixed"`), `decision.allowed is False`. The `provenance != "resolved"` check is the highest-priority policy gate.
   - **Subtest D — UNRESOLVED actual, default settings (Round-5 reviewer-P1):** YAML declares only `cognic-tier1-cloud-openai → openai/gpt-5.4`. httpx-respx makes LiteLLM return `{"model": "openai/gpt-7", ...}` — not declared anywhere. Asserts `gateway.upstream_unresolved` event emitted with `cause="model_not_in_yaml"` in payload; `actual_resolved.provenance == "unresolved"`; `actual_resolved.api_base is None`; post-response policy recheck DENIES; ledger row outcome="denied" + `provenance="unresolved"`.
   - **Subtest E — UNRESOLVED actual, permissive `allowed_providers` (Round-5 reviewer-P1):** same YAML; LiteLLM returns `openai/gpt-7`; settings have `allow_external_llm=True` + `allowed_providers=["openai"]`. Surface provider IS allowed, but the call STILL DENIES because the actual model isn't declared in any YAML route — the gateway cannot truthfully report the api_base. Audit row carries `provenance="unresolved"` so the operator sees provenance, not policy, drove the denial.
   - **Subtest F — MISSING `model` field in response (Round-6 reviewer-P1):** httpx-respx makes LiteLLM return `{"choices": [...], "model": null}` — content present but no model identifier. Asserts `gateway.upstream_unresolved` event emitted with `cause="missing_model_field"` in payload; `actual_resolved.provenance == "unresolved"`; `actual_resolved.model_string == "<missing>"`; post-response policy recheck DENIES; ledger row `outcome="denied"`, `upstream_model="<missing>"`, `upstream_api_base IS NULL`, `provenance="unresolved"`.
   - **Subtest G — MISSING `model` field, permissive `allowed_providers` (Round-6 reviewer-P1):** same setup but `allow_external_llm=True` + `allowed_providers=["openai"]`. Call STILL DENIES because the response model field is missing — provenance gap overrides any policy permission.
8. `test_gateway_ledger_contract.py` (load-bearing for Round-1 reviewer-P1#1):
   - Stub LiteLLM with successful response; stub `ledger.write_row` to raise `RuntimeError("DB down")`.
   - Asserts: `LedgerWriteFailed` raised, NOT `GatewayResponse` returned; original cause chained via `__cause__`; structured-logger captures the failure.
   - Negative regression: a fresh `LLMGateway` without the failure stub returns `GatewayResponse` and the ledger has exactly one row.

- [ ] **Step 3: Run tests to verify they fail**

Expected: ImportError on `LLMGateway`, `LedgerWriteFailed`, `ResolvedUpstream`, `enforce_cloud_policy(... post_response=...)`.

- [ ] **Step 4: Implement `LLMGateway`**

```python
# src/cognic_agentos/llm/gateway.py — extension below the existing classification primitives

import dataclasses
import datetime as _dt
import logging
import time
import uuid

import httpx

from cognic_agentos.core.audit import AuditEvent, AuditStore
from cognic_agentos.core.config import Settings
from cognic_agentos.core.guardrails import GuardrailDirection, GuardrailPipeline, PipelineResult
from cognic_agentos.core.sla import SLAPolicy, SLAStatus, SLATimer
from cognic_agentos.llm.concurrency import LLMConcurrencyExceeded, ProfileRateLimiter
from cognic_agentos.llm.ledger import GatewayCallLedger, GatewayCallRow
from cognic_agentos.llm.policy import (
    CloudPolicyViolationError,
    GuardrailViolationError,
    enforce_cloud_policy,
)
from cognic_agentos.llm.preflight import (
    PreflightResolver,
    ResolvedUpstream,
    _is_external,  # api_base-aware classifier (Round-2 reviewer-P1#2)
)

_LOG = logging.getLogger("cognic_agentos.llm.gateway")


class LedgerWriteFailed(RuntimeError):
    """Raised when a strict-regime ledger write fails.

    Per Round-1 reviewer-P1#1: ADR-007 makes the ledger authoritative
    for /system/effective-routing. Success contract is "no successful
    return without a persisted ledger row".
    """


class _MalformedResponseContent(RuntimeError):
    """Internal sentinel for the post-dispatch outer-catch block.

    Round-7 reviewer-P1: response shape failures (KeyError /
    IndexError / TypeError extracting ``body['choices'][0]['message']
    ['content']``, or a non-string content) raise this so the outer
    ``except Exception`` block strict-ledgers + propagates with full
    context. Not part of the public exception API.
    """


@dataclasses.dataclass(frozen=True, slots=True)
class GatewayResponse:
    content: str
    upstream_model: str          # actual model_string from LiteLLM response
    api_base: str | None         # actual api_base (from reverse_lookup) — may differ from preflight on drift
    external: bool               # _is_external(model_string, api_base) on the actual
    request_id: str
    tier: str
    latency_ms: int


class LLMGateway:
    def __init__(
        self,
        *,
        settings: Settings,
        ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        preflight: PreflightResolver,
        sla_policy: SLAPolicy,
        input_pipeline: GuardrailPipeline | None = None,
        output_pipeline: GuardrailPipeline | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._settings = settings
        self._ledger = ledger
        self._audit = audit_store
        self._rate_limiter = rate_limiter
        self._preflight = preflight
        self._sla_policy = sla_policy
        self._input_pipeline = input_pipeline
        self._output_pipeline = output_pipeline
        self._http = http_client or httpx.AsyncClient(timeout=settings.llm_timeout_s)

    async def completion(
        self,
        *,
        tier: str,
        messages: list[dict[str, str]],
        request_id: str,
        tenant_id: str | None = None,
    ) -> GatewayResponse:
        flow_start = time.monotonic()
        litellm_alias = resolve_tier_alias(tier, self._settings)
        preflight_resolved = self._preflight.resolve(litellm_alias)
        actual_resolved: ResolvedUpstream | None = None  # set after LiteLLM responds
        outcome: str = "ok"

        # --- 1. INPUT guardrails (pre-dispatch — best-effort ledger regime) -----
        if self._input_pipeline is not None:
            joined = "\n".join(m.get("content", "") for m in messages)
            ip_result: PipelineResult = await self._input_pipeline.check(
                joined,
                direction=GuardrailDirection.INPUT,
                request_id=request_id,
                tenant_id=tenant_id,
            )
            input_trips = [r for r in ip_result.results if not r.passed]
            if input_trips:
                outcome = "guardrail_input"
                trip_summary = ",".join(r.guardrail_name for r in input_trips)
                err = GuardrailViolationError("input", trip_summary)
                await self._best_effort_ledger_write(
                    request_id=request_id, tenant_id=tenant_id, tier=tier,
                    litellm_alias=litellm_alias, preflight=preflight_resolved,
                    flow_start=flow_start, outcome=outcome,
                )
                raise err

        # --- 2. Pre-call cloud-policy on preflight ResolvedUpstream -------------
        decision = enforce_cloud_policy(resolved=preflight_resolved, settings=self._settings, post_response=False)
        if not decision.allowed:
            outcome = "denied"
            await self._audit.append(AuditEvent(
                event_type="gateway.cloud_policy_denied",
                request_id=request_id,
                payload=decision.audit_payload,  # carries post_response=False already
                tenant_id=tenant_id,
                iso_controls=("ISO42001.A.9.2",),
            ))
            await self._best_effort_ledger_write(
                request_id=request_id, tenant_id=tenant_id, tier=tier,
                litellm_alias=litellm_alias, preflight=preflight_resolved,
                flow_start=flow_start, outcome=outcome,
            )
            raise CloudPolicyViolationError.from_decision(decision)

        # --- 3-9. Concurrency slot + dispatch + post-dispatch (clean async with)
        # Round-3 reviewer-P2: the natural ``async with`` shape preserves
        # exception context for the limiter's ``__aexit__``. If
        # ``__aenter__`` raises (LLMConcurrencyExceeded in fail_fast),
        # ``__aexit__`` is NOT called per the language spec, and the
        # exception propagates to the outer ``except``. The Round-2
        # manual __aenter__/__aexit__ shape was over-engineered AND
        # broke exception-context propagation by always passing
        # (None, None, None) to __aexit__.
        try:
            async with self._rate_limiter.acquire(profile=tier):
                # --- 4. SLA timer + dispatch ---------------------------
                sla_start = _dt.datetime.now(_dt.UTC)
                deadline = SLATimer.compute_deadline(start=sla_start, policy=self._sla_policy)

                # Round-5 reviewer-P1: ``httpx.RequestError`` is too
                # broad to mean "no dispatch". It includes ReadTimeout,
                # ReadError, RemoteProtocolError, and similar that fire
                # AFTER the request was sent to LiteLLM (and possibly
                # after LiteLLM has contacted the upstream). The Round-4
                # blanket ``except httpx.RequestError`` re-introduced
                # the lossy post-dispatch ledger path. Narrow the pre-
                # dispatch best-effort set to connection-class failures
                # only; everything else under RequestError is treated
                # as possibly dispatched (strict regime).
                try:
                    resp = await self._http.post(
                        f"{self._settings.litellm_base_url}/chat/completions",
                        json={"model": litellm_alias, "messages": messages},
                        headers={"Authorization": f"Bearer {self._settings.litellm_master_key}"},
                    )
                except (
                    httpx.ConnectError,
                    httpx.ConnectTimeout,
                    httpx.PoolTimeout,
                    httpx.LocalProtocolError,
                ):
                    # Definitively pre-dispatch — the connection was
                    # never established or our local request was
                    # malformed before going on the wire. Best-effort
                    # regime.
                    outcome = "upstream_error"
                    await self._best_effort_ledger_write(
                        request_id=request_id, tenant_id=tenant_id, tier=tier,
                        litellm_alias=litellm_alias, preflight=preflight_resolved,
                        flow_start=flow_start, outcome=outcome,
                    )
                    raise
                except httpx.RequestError as exc:
                    # ReadTimeout / ReadError / WriteError / WriteTimeout
                    # / RemoteProtocolError — request was sent (possibly
                    # in full) and the failure happened after LiteLLM
                    # received bytes. Strict regime — ADR-007 demands a
                    # ledger row because LiteLLM may have already
                    # contacted the upstream. Fallback upstream identity
                    # is preflight_resolved since no model field came
                    # back.
                    outcome = "upstream_error"
                    await self._strict_ledger_write_or_raise(
                        request_id=request_id, tenant_id=tenant_id, tier=tier,
                        litellm_alias=litellm_alias, resolved=preflight_resolved,
                        flow_start=flow_start, outcome=outcome,
                        original_exc=exc,
                    )
                    raise

                # We have a response — DISPATCHED. Any failure from here
                # is post-dispatch (HTTP status / JSON parse / response
                # shape) and uses the strict ledger regime.
                try:
                    resp.raise_for_status()
                    body = resp.json()
                except (httpx.HTTPStatusError, ValueError) as exc:
                    outcome = "upstream_error"
                    await self._strict_ledger_write_or_raise(
                        request_id=request_id, tenant_id=tenant_id, tier=tier,
                        litellm_alias=litellm_alias, resolved=preflight_resolved,
                        flow_start=flow_start, outcome=outcome,
                        original_exc=exc,
                    )
                    raise

                # Round-6 reviewer-P1: a missing/empty/non-string
                # ``model`` field in the response is a provenance gap of
                # the same class as zero reverse_lookup matches — we
                # cannot truthfully report which upstream LiteLLM
                # actually dispatched against. Don't fall back to the
                # preflight identity silently. Hand the unrecoverable
                # signal to ``_build_actual_resolved`` which emits
                # ``gateway.upstream_unresolved`` and returns a fail-
                # closed ResolvedUpstream(provenance="unresolved").
                # Round-7 reviewer-P1: every exit path from here on must
                # land a strict ledger row before propagating. Wrap the
                # post-dispatch flow in an outer try/except so unexpected
                # failures (AuditStore.append raising mid-emission, content
                # extraction raising on malformed response shape, etc.)
                # also satisfy the ADR-007 success contract — LiteLLM was
                # already contacted, so the ledger row is required.
                #
                # Expected exception types (CloudPolicyViolationError /
                # GuardrailViolationError / LedgerWriteFailed) handle
                # their own strict ledger writes inline and re-raise as-is.
                # The catch-all path is for AuditStore failures + response-
                # shape failures, which would otherwise drop the ledger row.
                try:
                    # Round-8 reviewer-P1: build is sync + returns
                    # (ResolvedUpstream, AuditEvent | None). actual_resolved
                    # is bound BEFORE the audit emit so an audit failure
                    # leaves the catch-all with the correct provenance
                    # state, not the preflight identity.
                    raw_actual = body.get("model")
                    if not isinstance(raw_actual, str) or not raw_actual.strip():
                        actual_resolved, pending_audit = self._build_unresolved_actual(
                            cause="missing_model_field",
                            preflight_resolved=preflight_resolved,
                            request_id=request_id,
                            tenant_id=tenant_id,
                        )
                    else:
                        actual_resolved, pending_audit = self._build_actual_resolved(
                            actual_model_string=raw_actual,
                            preflight_resolved=preflight_resolved,
                            request_id=request_id,
                            tenant_id=tenant_id,
                        )
                    # Now emit. If this raises, the outer catch-all sees
                    # actual_resolved bound to the correct provenance state.
                    if pending_audit is not None:
                        await self._audit.append(pending_audit)

                    # --- 5. SLA classify (post-dispatch — strict ledger regime) -
                    now = _dt.datetime.now(_dt.UTC)
                    if SLATimer.classify(now=now, deadline=deadline) is SLAStatus.BREACHED:
                        elapsed_ms = int((now - sla_start).total_seconds() * 1000)
                        budget_ms = int(self._sla_policy.total_budget.total_seconds() * 1000)
                        await self._audit.append(AuditEvent(
                            event_type="sla.breach",
                            request_id=request_id,
                            payload={
                                "alias": litellm_alias,
                                "preflight_model": preflight_resolved.model_string,
                                "actual_model": actual_resolved.model_string,
                                "elapsed_ms": elapsed_ms,
                                "budget_ms": budget_ms,
                            },
                            tenant_id=tenant_id,
                            iso_controls=("ISO42001.A.9.2",),
                        ))

                    # --- 6. Provider-honesty drift event ---------------------
                    drift = actual_resolved.model_string != preflight_resolved.model_string
                    if drift:
                        await self._audit.append(AuditEvent(
                            event_type="gateway.upstream_drift_detected",
                            request_id=request_id,
                            payload={
                                "alias": litellm_alias,
                                "preflight_model": preflight_resolved.model_string,
                                "preflight_api_base": preflight_resolved.api_base,
                                "preflight_external": preflight_resolved.external,
                                "actual_model": actual_resolved.model_string,
                                "actual_api_base": actual_resolved.api_base,
                                "actual_external": actual_resolved.external,
                            },
                            tenant_id=tenant_id,
                            iso_controls=("ISO42001.A.9.2",),
                        ))

                    # --- 7. POST-RESPONSE policy recheck ---------------------
                    actual_decision = enforce_cloud_policy(
                        resolved=actual_resolved, settings=self._settings, post_response=True,
                    )
                    if not actual_decision.allowed:
                        outcome = "denied"
                        await self._audit.append(AuditEvent(
                            event_type="gateway.cloud_policy_denied",
                            request_id=request_id,
                            payload=actual_decision.audit_payload,
                            tenant_id=tenant_id,
                            iso_controls=("ISO42001.A.9.2",),
                        ))
                        policy_err = CloudPolicyViolationError.from_decision(actual_decision)
                        await self._strict_ledger_write_or_raise(
                            request_id=request_id, tenant_id=tenant_id, tier=tier,
                            litellm_alias=litellm_alias, resolved=actual_resolved,
                            flow_start=flow_start, outcome=outcome,
                            original_exc=policy_err,
                        )
                        raise policy_err

                    # --- 7a. Extract content (Round-7 reviewer-P1) ----------
                    # Validate the response shape inside the protected block;
                    # KeyError / IndexError / TypeError propagate to the outer
                    # catch which strict-ledgers + re-raises.
                    try:
                        content = body["choices"][0]["message"]["content"]
                    except (KeyError, IndexError, TypeError) as exc:
                        raise _MalformedResponseContent(str(exc)) from exc
                    if not isinstance(content, str):
                        raise _MalformedResponseContent(
                            f"choices[0].message.content is not str: got {type(content).__name__}"
                        )

                    # --- 8. OUTPUT guardrails -------------------------------
                    if self._output_pipeline is not None:
                        op_result: PipelineResult = await self._output_pipeline.check(
                            content,
                            direction=GuardrailDirection.OUTPUT,
                            request_id=request_id,
                            tenant_id=tenant_id,
                        )
                        output_trips = [r for r in op_result.results if not r.passed]
                        if output_trips:
                            outcome = "guardrail_output"
                            trip_summary = ",".join(r.guardrail_name for r in output_trips)
                            err = GuardrailViolationError("output", trip_summary)
                            await self._strict_ledger_write_or_raise(
                                request_id=request_id, tenant_id=tenant_id, tier=tier,
                                litellm_alias=litellm_alias, resolved=actual_resolved,
                                flow_start=flow_start, outcome=outcome,
                                original_exc=err,
                            )
                            raise err

                    # --- 9. Strict ledger write THEN return -------------------
                    outcome = "drift" if drift else "ok"
                    latency_ms = int((time.monotonic() - flow_start) * 1000)
                    await self._strict_ledger_write_or_raise(
                        request_id=request_id, tenant_id=tenant_id, tier=tier,
                        litellm_alias=litellm_alias, resolved=actual_resolved,
                        flow_start=flow_start, outcome=outcome,
                        original_exc=None,
                    )
                    return GatewayResponse(
                        content=content,
                        upstream_model=actual_resolved.model_string,
                        api_base=actual_resolved.api_base,
                        external=actual_resolved.external,
                        request_id=request_id,
                        tier=tier,
                        latency_ms=latency_ms,
                    )
                except (CloudPolicyViolationError, GuardrailViolationError, LedgerWriteFailed):
                    # Already strict-ledgered inline (or LedgerWriteFailed
                    # from a strict-ledger failure). Re-raise as-is.
                    raise
                except Exception as exc:
                    # Round-7 reviewer-P1: AuditStore.append failures + the
                    # malformed-response-content path land here. ADR-007
                    # success contract still binds: LiteLLM was already
                    # contacted on this code path. Use actual_resolved if it
                    # was built before the failure, else fall back to
                    # preflight_resolved (preserves SOME provenance signal
                    # for /effective-routing). Strict-ledger then re-raise.
                    best_resolved = actual_resolved or preflight_resolved
                    await self._strict_ledger_write_or_raise(
                        request_id=request_id, tenant_id=tenant_id, tier=tier,
                        litellm_alias=litellm_alias, resolved=best_resolved,
                        flow_start=flow_start, outcome="upstream_error",
                        original_exc=exc,
                    )
                    raise
        except LLMConcurrencyExceeded:
            # Round-2 reviewer-P2: ledger best-effort then propagate. The
            # ``async with`` __aenter__ raised; __aexit__ was not called.
            outcome = "concurrency_exhausted"
            await self._best_effort_ledger_write(
                request_id=request_id, tenant_id=tenant_id, tier=tier,
                litellm_alias=litellm_alias, preflight=preflight_resolved,
                flow_start=flow_start, outcome=outcome,
            )
            raise

    def _build_actual_resolved(
        self,
        *,
        actual_model_string: str,
        preflight_resolved: ResolvedUpstream,
        request_id: str,
        tenant_id: str | None,
    ) -> tuple[ResolvedUpstream, AuditEvent | None]:
        """Round-3+4+5+6+8 fail-closed disambiguation.

        Round-8 reviewer-P1: this helper is now **synchronous** and
        returns ``(ResolvedUpstream, AuditEvent | None)``. The caller
        ASSIGNS the resolved object BEFORE awaiting the audit emission,
        so a failure inside ``AuditStore.append`` on the unresolved or
        ambiguous paths cannot leave ``actual_resolved`` unbound — the
        outer post-dispatch catch-all then strict-ledgers with the
        correct provenance state, not the preflight identity.

        Four cases:

          * 0 matches: provenance gap → delegate to
            ``_build_unresolved_actual`` (returns the unresolved object
            + a non-None ``gateway.upstream_unresolved`` event).
          * 1 match: unambiguous → return ``(match, None)``.
          * N matches with uniform classification: return
            ``(matches[0], None)``.
          * N matches with MIXED classification: build the ambiguous
            ResolvedUpstream + a ``gateway.upstream_classification_ambiguous``
            event and return both.
        """
        matches = self._preflight.reverse_lookup(actual_model_string)
        if not matches:
            return self._build_unresolved_actual(
                cause="model_not_in_yaml",
                preflight_resolved=preflight_resolved,
                request_id=request_id,
                tenant_id=tenant_id,
                actual_model_string=actual_model_string,
            )
        externals = {m.external for m in matches}
        if len(externals) == 1:
            return matches[0], None  # unambiguous classification — no audit needed
        # Mixed-classification collision: fail-closed with provenance gap.
        constructed = ResolvedUpstream(
            alias=preflight_resolved.alias,
            model_string=actual_model_string,
            api_base=None,                   # ambiguous — don't assume preflight's api_base
            external=True,                   # fail-closed
            provenance="ambiguous",          # Round-4 + Round-6: enforce_cloud_policy denies unconditionally
        )
        event = AuditEvent(
            event_type="gateway.upstream_classification_ambiguous",
            request_id=request_id,
            payload={
                "actual_model_string": actual_model_string,
                "matching_aliases": [m.alias for m in matches],
                "matching_classifications": [
                    {"alias": m.alias, "api_base": m.api_base, "external": m.external}
                    for m in matches
                ],
            },
            tenant_id=tenant_id,
            iso_controls=("ISO42001.A.9.2",),
        )
        return constructed, event

    def _build_unresolved_actual(
        self,
        *,
        cause: str,                                # "model_not_in_yaml" | "missing_model_field"
        preflight_resolved: ResolvedUpstream,
        request_id: str,
        tenant_id: str | None,
        actual_model_string: str | None = None,
    ) -> tuple[ResolvedUpstream, AuditEvent]:
        """Round-5+6+8 reviewer-P1: provenance-gap fail-close, sync.

        Round-8 reviewer-P1: synchronous; returns
        ``(ResolvedUpstream, AuditEvent)`` so the caller can ASSIGN the
        resolved object BEFORE awaiting the audit emission. If the
        subsequent ``await self._audit.append(event)`` raises, the
        caller's ``actual_resolved`` is already bound to the correct
        ``provenance="unresolved"`` object — outer catch-all ledgers with
        the right provenance, not the preflight identity (which would
        be a false historical claim).

        Single helper for both unresolvable causes:

          * ``model_not_in_yaml``: reverse_lookup found zero matches.
          * ``missing_model_field``: LiteLLM response had no/empty/non-
            string ``model`` field.
        """
        constructed = ResolvedUpstream(
            alias=preflight_resolved.alias,
            model_string=actual_model_string or "<missing>",
            api_base=None,
            external=True,
            provenance="unresolved",
        )
        event = AuditEvent(
            event_type="gateway.upstream_unresolved",
            request_id=request_id,
            payload={
                "cause": cause,
                "actual_model_string": actual_model_string,
                "preflight_alias": preflight_resolved.alias,
                "preflight_model_string": preflight_resolved.model_string,
                "known_aliases": list(self._preflight.known_aliases),
            },
            tenant_id=tenant_id,
            iso_controls=("ISO42001.A.9.2",),
        )
        return constructed, event

    async def _strict_ledger_write_or_raise(
        self,
        *,
        request_id: str,
        tenant_id: str | None,
        tier: str,
        litellm_alias: str,
        resolved: ResolvedUpstream,
        flow_start: float,
        outcome: str,
        original_exc: Exception | None,
    ) -> None:
        """Strict-regime ledger write per Round-1 reviewer-P1#1 +
        Round-6 reviewer-P1.

        Persists the full provenance state (api_base + provenance) so
        ``/system/effective-routing`` can authoritatively classify
        historical rows without re-resolving the current YAML.
        """
        try:
            await self._ledger.write_row(GatewayCallRow(
                id=uuid.uuid4(),
                ts=_dt.datetime.now(_dt.UTC),
                request_id=request_id,
                tenant_id=tenant_id,
                tier=tier,  # type: ignore[arg-type]
                litellm_alias=litellm_alias,
                upstream_model=resolved.model_string,
                upstream_api_base=resolved.api_base,
                external=resolved.external,
                provenance=resolved.provenance,  # "resolved" | "unresolved" | "ambiguous"
                latency_ms=int((time.monotonic() - flow_start) * 1000),
                outcome=outcome,
                model_id=None,
            ))
        except Exception as ledger_exc:  # noqa: BLE001
            _LOG.exception("strict ledger write failed; raising LedgerWriteFailed (ADR-007 success contract)")
            raise LedgerWriteFailed(
                f"ledger write failed for request_id={request_id} upstream={resolved.model_string}: {ledger_exc}"
            ) from (original_exc or ledger_exc)

    async def _best_effort_ledger_write(
        self,
        *,
        request_id: str,
        tenant_id: str | None,
        tier: str,
        litellm_alias: str,
        preflight: ResolvedUpstream,
        flow_start: float,
        outcome: str,
    ) -> None:
        """Best-effort ledger write for pre-dispatch failure paths.

        Round-6 + Round-7 reviewer-P1: persists the *intended* preflight
        identity (alias / model_string / api_base / external) with
        ``provenance="no_dispatch"`` so the operator sees what was about
        to be dispatched. ``/system/effective-routing`` filters drift
        detection to ``provenance != "no_dispatch"`` — ``no_dispatch``
        rows are operator-side telemetry of pre-dispatch denials/trips,
        not evidence of actual upstream contact.
        """
        try:
            await self._ledger.write_row(GatewayCallRow(
                id=uuid.uuid4(),
                ts=_dt.datetime.now(_dt.UTC),
                request_id=request_id,
                tenant_id=tenant_id,
                tier=tier,  # type: ignore[arg-type]
                litellm_alias=litellm_alias,
                upstream_model=preflight.model_string,
                upstream_api_base=preflight.api_base,
                external=preflight.external,
                provenance="no_dispatch",
                latency_ms=int((time.monotonic() - flow_start) * 1000),
                outcome=outcome,
                model_id=None,
            ))
        except Exception:  # noqa: BLE001
            _LOG.exception("best-effort ledger write failed; pre-dispatch path — not chaining")
```

Note: the slot uses `async with self._rate_limiter.acquire(profile=tier)` (Round-3 reviewer-P2 + Round-4 reviewer-P2 — the natural shape is required, not the manual `__aenter__/__aexit__` one). When `__aenter__` raises (`LLMConcurrencyExceeded` in fail_fast), `__aexit__` is NOT called per the language spec, so the exception propagates to the outer `try/except LLMConcurrencyExceeded:` for ledger-write + re-raise. Body exceptions trigger the limiter's `__aexit__(type(exc), exc, tb)` correctly, preserving exception context. The earlier manual `__aenter__/__aexit__(None, None, None)` shape was both over-engineered AND broken (always reported success to the limiter regardless of in-flight exception); do NOT regress to it.

- [ ] **Step 5: Run tests to verify they pass**

Expected: PASS on all six modules, including:
- `test_gateway_drift.py::test_post_response_drift_emits_audit_and_raises`
- `test_gateway_drift.py::test_post_response_drift_persists_ledger_row_with_actual_upstream`
- `test_gateway_ledger_contract.py::test_strict_write_failure_raises_LedgerWriteFailed_not_GatewayResponse`
- `test_gateway_ledger_contract.py::test_strict_write_failure_chains_via___cause__`
- `test_gateway_ledger_contract.py::test_pre_dispatch_failure_uses_best_effort_path`

- [ ] **Step 6: Commit**

```bash
git add src/cognic_agentos/llm/gateway.py src/cognic_agentos/llm/preflight.py src/cognic_agentos/llm/policy.py tests/unit/llm/test_gateway_completion.py tests/unit/llm/test_gateway_guardrails.py tests/unit/llm/test_gateway_sla.py tests/unit/llm/test_gateway_drift.py tests/unit/llm/test_gateway_ledger_contract.py tests/unit/llm/test_gateway_classification.py tests/unit/llm/test_gateway_concurrency_ledger.py tests/unit/llm/test_preflight_resolver.py
git commit -m "feat(sprint-3): LLMGateway.completion + preflight resolver + post-response policy recheck (T6)

- llm/preflight.py: PreflightResolver.from_yaml reads
  infra/litellm/config.yaml at startup and stores RAW templates;
  \${VAR} substitution is lazy per resolve(alias) so unused vLLM/SGLang
  aliases don't require their env vars at load time (Round-2 P1#3).
  Resolves to ResolvedUpstream(alias, model_string, api_base, external)
  using api_base-aware classification (Round-2 P1#2): vLLM/SGLang
  serving 'model: openai/X' against a private api_base classify as
  self-hosted. reverse_lookup(model_string) supports the post-response
  policy recheck.
- llm/policy.py: enforce_cloud_policy now takes a ResolvedUpstream +
  post_response: bool. Audit payload carries alias, model_string,
  api_base, external, post_response, policy_mode, allow_external_llm,
  allowed_providers, reason — full transparency.
- llm/gateway.py: LLMGateway.completion runs the post-response policy
  recheck on the actual ResolvedUpstream (Round-2 P1#1) — closes the
  external→external provider drift class (preflight openai allow-listed
  but actual bedrock not in allowed_providers passes Round-1's
  classification-equality check).
  Drift event emitted on any model_string mismatch (telemetry-only;
  no raise on its own). Fail-loud channel is CloudPolicyViolationError
  on post-response denial.
  LLMConcurrencyExceeded is caught by an outer try/except around the
  natural 'async with self._rate_limiter.acquire(profile=tier)' shape
  so saturation hits write a best-effort ledger row before propagating
  (Round-2 P2 + Round-3/Round-4 P2 — the manual __aenter__/__aexit__
  shape from a prior round was over-engineered and broke exception
  context propagation; do NOT regress to it).
- Two posture regimes preserved (Round-1 P1#1):
    * pre-dispatch (input trip / policy denial / concurrency exhausted /
      pre-response upstream_error): best-effort ledger write, log on
      failure, do not chain.
    * post-dispatch (drift / output trip / post-response policy denial /
      happy): strict ledger write — failure raises LedgerWriteFailed
      chained from any in-flight exception.
- SLATimer used as static-method namespace; GuardrailPipeline.check
  called positionally with content + direction kwargs (Round-1 P2#1).
"
```

---

### Task 7: Concurrency primitive

**Files:**
- Create: `src/cognic_agentos/llm/concurrency.py`
- Test: `tests/unit/llm/test_concurrency.py`

- [ ] **Step 1: Write the failing test**

Three test classes:

1. `TestQueuedMode` — saturates the per-profile slot count; the next acquire blocks until a release; release order is FIFO.
2. `TestFailFastMode` — saturates; the next acquire raises `LLMConcurrencyExceeded` immediately (no `await`).
3. `TestPerProfileIsolation` — tier1 saturation does not block tier2.
4. `TestExceptionReleasesSlot` — exception inside the async-context body releases the slot before propagation.
5. `TestFailFastIsAtomic` — **the load-bearing test for the P2#2 fix.** Two complementary tests prove fail_fast never blocks on slot availability:
   - **`test_fail_fast_raises_immediately_when_saturated`**: pre-fill the slot via the public `acquire()` context manager, then assert a nested fail_fast acquire raises `LLMConcurrencyExceeded` immediately. The pytest test timeout catches the buggy "blocks on sem.acquire()" implementation; the correct atomic implementation completes in microseconds.
   - **`test_fail_fast_no_race_under_concurrent_arrival`**: a barrier releases two contenders simultaneously; exactly one wins the per-profile lock + takes the slot, the other waits-then-checks-then-raises. The buggy non-atomic check-then-acquire would let the loser block instead.

```python
async def test_fail_fast_raises_immediately_when_saturated(self):
    """Round-8 reviewer-P2 rewrite: pre-fill the slot via the public
    acquire() context, then prove a nested fail_fast acquire raises
    immediately rather than blocking on the saturated slot.
    """
    limiter = ProfileRateLimiter(per_profile=1, mode="fail_fast")
    # Worker A holds the slot via the context manager.
    async with limiter.acquire(profile="tier1"):
        # Slot saturated. Worker B must raise immediately — NOT block.
        # If the implementation was buggy (check-then-await), this
        # call would block forever and pytest's test-level timeout
        # would catch it. With the atomic shape it raises in
        # microseconds.
        with pytest.raises(LLMConcurrencyExceeded):
            await limiter._take_slot_or_raise("tier1")
    # Slot released; a fresh acquire should now succeed.
    async with limiter.acquire(profile="tier1"):
        pass


async def test_fail_fast_no_race_under_concurrent_arrival(self):
    """Round-8 reviewer-P2 rewrite: two contenders released
    simultaneously through a barrier; exactly one wins the slot,
    the other raises LLMConcurrencyExceeded. The atomic per-profile
    Lock serialises the (check, increment) critical section; the
    loser sees in_flight == capacity and raises without blocking
    on slot availability (only a brief microsecond wait on the
    Lock itself).
    """
    barrier = asyncio.Event()

    class _BarrierLimiter(ProfileRateLimiter):
        async def _take_slot_or_raise(self, profile: str):
            await barrier.wait()  # both contenders queue here
            return await super()._take_slot_or_raise(profile)

    limiter = _BarrierLimiter(per_profile=1, mode="fail_fast")

    async def contend():
        async with limiter.acquire(profile="tier1"):
            await asyncio.sleep(0.05)  # hold briefly so the loser sees saturation

    a = asyncio.create_task(contend())
    b = asyncio.create_task(contend())
    await asyncio.sleep(0.05)  # let both queue at the barrier
    barrier.set()              # release both simultaneously

    results = await asyncio.gather(a, b, return_exceptions=True)
    succeeded = [r for r in results if r is None]
    raised = [r for r in results if isinstance(r, LLMConcurrencyExceeded)]
    assert len(succeeded) == 1, f"expected exactly one winner; got {results}"
    assert len(raised) == 1, f"expected exactly one fail_fast denial; got {results}"
```

- [ ] **Step 2: Run tests to verify they fail**

Expected: ImportError on `cognic_agentos.llm.concurrency`.

- [ ] **Step 3: Implement `ProfileRateLimiter`** with atomic acquisition

Per reviewer-P2#2: a check-then-acquire pair on `asyncio.Semaphore` is **not atomic** — another coroutine can take the last slot between `if sem.locked()` and `await sem.acquire()`, causing a fail_fast caller to block. Use an explicit per-profile counter under a per-profile `asyncio.Lock`:

```python
# src/cognic_agentos/llm/concurrency.py
import asyncio
import contextlib
from typing import Literal


class LLMConcurrencyExceeded(RuntimeError):
    """Raised when a fail_fast acquire finds no slot available."""


class ProfileRateLimiter:
    """Per-profile concurrency primitive.

    Two modes:
      - ``queued``: block on slot via condition variable.
      - ``fail_fast``: raise ``LLMConcurrencyExceeded`` if no slot.

    Atomicity (per reviewer-P2#2 of the Sprint-3 plan): a per-profile
    ``asyncio.Lock`` guards the ``(in_flight, capacity)`` pair so the
    "is there a slot?" check + "take a slot" mutation are a single
    critical section. A naive ``asyncio.Semaphore.locked()`` check
    plus ``await acquire()`` has a race window where another
    coroutine can take the last slot between the check and the await,
    causing fail_fast to block.
    """

    def __init__(self, *, per_profile: int, mode: Literal["queued", "fail_fast"]) -> None:
        self._capacity = per_profile
        self._mode = mode
        self._state: dict[str, _ProfileState] = {}
        self._table_lock = asyncio.Lock()  # guards `_state` dict membership

    async def _state_for(self, profile: str) -> "_ProfileState":
        async with self._table_lock:
            if profile not in self._state:
                self._state[profile] = _ProfileState(self._capacity)
            return self._state[profile]

    async def _take_slot_or_raise(self, profile: str) -> "_ProfileState":
        st = await self._state_for(profile)
        async with st.lock:
            if self._mode == "fail_fast":
                if st.in_flight >= st.capacity:
                    raise LLMConcurrencyExceeded(
                        f"profile {profile!r} saturated (in_flight={st.in_flight}/{st.capacity})"
                    )
                st.in_flight += 1
                return st
            # queued mode: wait via condition until a slot frees.
            while st.in_flight >= st.capacity:
                await st.cond.wait()
            st.in_flight += 1
            return st

    async def _release_slot(self, st: "_ProfileState") -> None:
        async with st.lock:
            st.in_flight -= 1
            st.cond.notify(1)

    @contextlib.asynccontextmanager
    async def acquire(self, *, profile: str):
        st = await self._take_slot_or_raise(profile)
        try:
            yield
        finally:
            await self._release_slot(st)


class _ProfileState:
    __slots__ = ("capacity", "in_flight", "lock", "cond")

    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self.in_flight = 0
        self.lock = asyncio.Lock()
        self.cond = asyncio.Condition(self.lock)
```

Key invariants enforced by this shape:
- **Atomic check-and-take.** The `if in_flight >= capacity` check and the `in_flight += 1` mutation happen inside the same `async with st.lock:` critical section. No coroutine can slip a take between them.
- **Queued mode uses Condition, not Semaphore.** A condition variable on the same lock means the waiter wakes up holding the lock, re-checks the predicate, and only then takes the slot — same atomicity story.
- **Release is also under the lock.** Decrement + `cond.notify(1)` are atomic; the woken waiter sees the freed slot.

- [ ] **Step 4: Run tests to verify they pass**

Expected: PASS, including the saturation + barrier-arrival forced-interleaving tests (Round-8 reviewer-P2 rewrite).

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(sprint-3): per-profile concurrency primitive (T7)

- ProfileRateLimiter — atomic check-and-take under per-profile
  asyncio.Lock + asyncio.Condition. NOT a thin asyncio.Semaphore
  wrapper.
- Two modes: queued (block on Condition) + fail_fast (raise under
  the lock when in_flight >= capacity).
- Per-profile isolation: tier1 saturation does not block tier2.
- Slot released on async context exit incl. exception path.
- Saturation + barrier-arrival forced-interleaving tests prove
  fail_fast never blocks on slot availability — Round-2 P2 ledger
  + Round-8 P2 test-shape rewrite (the prior _PausingLimiter test
  paused before the lock and could not pass as written).
"
```

---

### Task 8: `/system/policy` endpoint

**Files:**
- Create: `src/cognic_agentos/portal/api/system_routes.py`
- Modify: `src/cognic_agentos/portal/api/app.py` (mount router)
- Test: `tests/unit/llm/test_system_policy.py`

- [ ] **Step 1: Write the failing test**

```python
def test_system_policy_returns_current_settings(client_with_self_hosted_settings):
    resp = client_with_self_hosted_settings.get("/api/v1/system/policy")
    assert resp.status_code == 200
    body = resp.json()
    assert body["allow_external_llm"] is False
    assert body["mode"] == "self_hosted"
    assert body["allowed_providers"] == []
```

- [ ] **Step 2: Run test → fail**
- [ ] **Step 3: Implement endpoint** — reads from `get_settings()`; returns shape per ADR-007.
- [ ] **Step 4: Run test → pass**
- [ ] **Step 5: Commit** — `feat(sprint-3): /system/policy endpoint (T8)`

---

### Task 9: `/system/effective-routing` endpoint

**Files:**
- Modify: `src/cognic_agentos/portal/api/system_routes.py`
- Test: `tests/unit/llm/test_effective_routing.py`

- [ ] **Step 1: Write the failing test**

```python
async def test_effective_routing_reads_ledger_authoritatively(client_with_seeded_ledger):
    # Ledger has 3 rows: 2× ollama + 1× openai in last hour.
    resp = client_with_seeded_ledger.get("/api/v1/system/effective-routing")
    body = resp.json()
    assert body["recent_calls_window_minutes"] == 60
    assert body["recent_calls"]["ollama/qwen3:8b"] == 2
    assert body["recent_calls"]["openai/gpt-5.4"] == 1
    assert body["langfuse_available"] is True

async def test_effective_routing_serves_when_langfuse_unreachable(client_with_langfuse_down):
    resp = client_with_langfuse_down.get("/api/v1/system/effective-routing")
    assert resp.status_code == 200
    assert resp.json()["langfuse_available"] is False

async def test_effective_routing_drift_flag_when_external_call_with_flag_off(client_with_drift):
    # Ledger has an openai row but allow_external_llm=False — the
    # PROFILE chip's drift case per ADR-007.
    body = client_with_drift.get("/api/v1/system/effective-routing").json()
    assert body["profile"]["chip"] == "self-hosted (DRIFT)"
```

- [ ] **Step 2: Run tests → fail**
- [ ] **Step 3: Implement endpoint** — reads ledger as authoritative; settings as policy snapshot; Langfuse opportunistic.
- [ ] **Step 4: Run tests → pass**
- [ ] **Step 5: Commit** — `feat(sprint-3): /system/effective-routing endpoint per ADR-007 (T9)`

---

### Task 10: LiteLLM cloud aliases + `.env.example`

**Files:**
- Modify: `infra/litellm/config.yaml` — add `cognic-tier1-cloud-openai`, `cognic-tier2-cloud-openai`, `cognic-tier1-cloud-anthropic`, `cognic-tier2-cloud-anthropic`
- Modify: `.env.example`
- Test: smoke via integration test (env-gated)

- [ ] **Step 1: Add aliases**

```yaml
- model_name: cognic-tier1-cloud-openai
  litellm_params:
    model: openai/${COGNIC_TIER1_CLOUD_OPENAI_MODEL:-gpt-4o}
    api_key: ${OPENAI_API_KEY}

- model_name: cognic-tier1-cloud-anthropic
  litellm_params:
    model: anthropic/${COGNIC_TIER1_CLOUD_ANTHROPIC_MODEL:-claude-3-5-sonnet-20241022}
    api_key: ${ANTHROPIC_API_KEY}
```

- [ ] **Step 2: Document in `.env.example`** — operator sets API key only when `policy_mode != self_hosted`.
- [ ] **Step 3: Verify denial path is exercisable** — manual local: `COGNIC_TIER1_ALIAS=cognic-tier1-cloud-openai COGNIC_ALLOW_EXTERNAL_LLM=false uv run pytest tests/integration/llm/test_cloud_denial_smoke.py`.
- [ ] **Step 4: Commit** — `feat(sprint-3): cloud aliases + denial-path exerciseability (T10)`

---

### Task 11: Per-file critical-controls coverage gate + plan-doc backfill

**Files:**
- Modify: `tools/check_critical_coverage.py` — add `llm/gateway.py` + `llm/policy.py` at ≥95% line / ≥90% branch
- Modify: `docs/superpowers/plans/2026-04-30-sprint-3-llm-gateway-and-provider-honesty.md` — fix any drift between the plan samples + what shipped (Sprint-2.5 pattern)

- [ ] **Step 1: Add to coverage gate**

```python
("src/cognic_agentos/llm/gateway.py", 0.95, 0.90),
("src/cognic_agentos/llm/policy.py", 0.95, 0.90),
("src/cognic_agentos/llm/preflight.py", 0.95, 0.90),
```

- [ ] **Step 2: Run gate** — ensure each module hits the floor.
- [ ] **Step 3: Plan-doc drift sweep** — review T2/T3/T6 samples vs what landed; fix discrepancies in-place.
- [ ] **Step 4: Commit** — `chore(sprint-3): extend per-file critical-controls coverage gate + plan-doc drift fix (T11)`

---

### Task 12: Closeout note + BUILD_PLAN refresh

**Files:**
- Create: `docs/closeouts/2026-04-30-sprint-3-llm-gateway-and-provider-honesty.md`
- Modify: `docs/BUILD_PLAN.md` — flip Sprint 3 status line to **CLOSED**

- [ ] **Step 1: Author closeout note**

Mirror the Sprint-2.5 closeout structure: deliverables refresh, test-count delta off the Sprint-2.5 merge baseline (659+24 = 683), what each critical decision means, READY-FOR-GATE sweep results, **scope-boundary section**: cloud-policy is static-settings, not OPA-Rego (that's Sprint 4 seed + Sprint 13.5 full); no `decision_history` emission yet (that's Sprint 9.5 with model_id); guardrails baseline is Sprint 2.5 regex MVP.
- [ ] **Step 2: BUILD_PLAN sprint-status flip** — `**Status: CLOSED**` in the Sprint 3 section.
- [ ] **Step 3: Run full READY-FOR-GATE sweep** — `uv run ruff check . && uv run ruff format --check . && uv run mypy src tests && uv run pytest -v --cov=cognic_agentos --cov-branch --cov-report=json && uv run python tools/check_critical_coverage.py`. All green.
- [ ] **Step 4: Halt before commit** — surface diff + gate results to user; await `commit` authorization.
- [ ] **Step 5: Commit** — `docs(sprint-3): closeout note + BUILD_PLAN refresh (T12)`.

---

## Verification

- All unit + integration tests green; coverage gate green on every per-file floor.
- ruff/mypy clean.
- Manual smoke 1 — self-hosted: tier1 → ollama → 200 OK → ledger row outcome=ok external=false.
- Manual smoke 2 — denial: tier1=cognic-tier1-cloud-openai + allow_external_llm=False → 403 with policy reason + ledger row outcome=denied + audit_event(gateway.cloud_policy_denied).
- Manual smoke 3 — drift: ledger has openai row + allow_external_llm=False → `/system/effective-routing` returns `profile.chip == "self-hosted (DRIFT)"`.
- Manual smoke 4 — Langfuse down: stop the langfuse container → `/system/effective-routing` returns 200 + `langfuse_available: false`.
- 12 conventional commits on the feature branch; no push, no merge until explicit authorization.

---

## Self-Review patch log

### Round 1 — 2026-04-30 (pre-commit; user-driven)

Five findings (3 P1 + 2 P2) closed before plan-PR commit. Decisions §1, §3, §5 accepted as drafted; the implementation drift in T4/T6/T7 was real and patched in-place.

- **P1 — Ledger persistence opportunism contradicts ADR-007.** The original T6 sample wrote the ledger inside a `finally` block and swallowed write failures with a log. ADR-007 §"two layers" says the ledger is *authoritative* for `/system/effective-routing`; an opportunistic write means a successful cloud call can return while the ledger row is dropped, and the endpoint will falsely report self-hosted. **Fix:** explicit two-regime contract baked into Decision-Locking §5 + T6 implementation. Pre-dispatch failure paths (input trip, policy denial, concurrency exhausted) use a `_best_effort_ledger_write` (audit_event already records the violation). Post-dispatch paths (happy / output trip / drift / upstream HTTP error after dispatch) use `_strict_ledger_write_or_raise` — failure raises new `LedgerWriteFailed` (chained from any in-flight exception via `raise from`), so a successful return without a persisted row is *unreachable*. New load-bearing test `test_gateway_ledger_contract.py` pins both regimes.

- **P1 — Static preflight upstream lookup never re-checks the response.** Original T6 sample resolved upstream from an inline `_LITELLM_ALIAS_TO_UPSTREAM` dict, ran cloud-policy against that, then parsed the LiteLLM response *without re-checking*. If the inline map drifted from the router's actual dispatch, a self-hosted-looking preflight could still send the prompt to OpenAI and return successfully — the exact bug ADR-007 was written against. **Fix:** new `src/cognic_agentos/llm/preflight.py` with `PreflightResolver.from_yaml(infra/litellm/config.yaml)` — same source of truth LiteLLM consumes — eliminating the static-map-drift class. Plus a post-response drift check in T6 flow step 9: `_is_external_alias(actual_upstream) != _is_external_alias(preflight_upstream)` ⇒ emit `audit_event(gateway.upstream_drift_detected)` + raise `UpstreamDriftDetected`. `preflight.py` joins `gateway.py` + `policy.py` on the per-file critical-controls coverage gate (T11).

- **P1 — Migration `down_revision` mis-named.** Original T4 sample set `down_revision = "0001_initial_governance_schema"` but the existing 0001 migration uses bare `revision = "0001"`. Alembic would have failed to resolve the graph. **Fix:** corrected to `revision = "0002"` / `down_revision = "0001"` with an explanatory comment pinning the convention.

- **P2 — T6 sample called Sprint 2.5 APIs that do not exist.** `GuardrailPipeline.check` takes `content` positionally (not `text=`), returns `PipelineResult(passed: bool, results: tuple[GuardrailResult, ...])` with no `tripped_results` attribute or `summary()` method. `SLATimer` is a static-method namespace — `compute_deadline(start, policy)` and `classify(now, deadline)`, no instance, no `.policy` field. **Fix:** T6 implementation snippet rewritten to use the actual signatures: `pipeline.check(content, direction=..., request_id=..., tenant_id=...)`, trips derived from `[r for r in result.results if not r.passed]`, `SLATimer.compute_deadline(start=sla_start, policy=self._sla_policy)` + `SLATimer.classify(now=now, deadline=deadline)`. Stored `_sla_policy` on the gateway instead of wrapping in a non-existent `SLATimer(policy)` constructor.

- **P2 — `fail_fast` semaphore check has a TOCTOU race.** Original T7 sample said `if sem.locked(): raise; await sem.acquire()`. Between the `locked()` check and the `await acquire()`, another coroutine could take the last slot, causing the fail_fast caller to *block* on `acquire()` instead of raising. **Fix:** rewrote `ProfileRateLimiter` to maintain `(in_flight, capacity)` per profile under an `asyncio.Lock`; check + mutate happen inside the same critical section. Queued mode uses `asyncio.Condition` on the same lock so the waiter wakes up holding the lock and re-checks the predicate. New load-bearing test `test_concurrency.py::test_fail_fast_never_blocks_under_concurrent_acquire` uses a `_PausingLimiter` subclass that pauses inside the under-the-lock check; proves two concurrent fail_fast acquisitions cannot both succeed AND that a fail_fast caller never `await`s on a slot.

User-stated decision answers carried into the plan:
- §1 unknown-prefix fail-closed: **accepted** as drafted.
- §3 INPUT-before-policy: **accepted** as drafted, conditional on the P1#2 preflight resolver fix (now landed).
- §5 no `decision_history` in Sprint 3: **accepted** as drafted.

### Round 2 — 2026-04-30 (pre-commit; user-driven, post-Round-1)

Five findings (4 P1 + 1 P2) closed before plan-PR commit. The Round-1 fixes were directionally right but the rewritten plan still had provider-honesty holes around actual-provider recheck and OpenAI-compatible self-hosted routing.

- **P1 — Post-response drift check still permits external→external provider drift.** The Round-1 check compared only `_is_external(actual) != _is_external(preflight)`, which catches self-hosted→cloud drift but misses external→external policy drift. Concrete attack: preflight `openai/gpt-5.4` is allow-listed, LiteLLM actually returns `bedrock/anthropic.claude-3` — both classify as external, so Round-1 saw no divergence and the call succeeded without re-running cloud policy against the actual provider. **Fix:** Decision-Locking §3 + T6 flow now run `enforce_cloud_policy(actual_resolved, settings, post_response=True)` after the response. The drift event is emitted on any `actual_model_string != preflight.model_string` (telemetry, no raise on its own). Actual-policy denial fails loudly with `CloudPolicyViolationError(post_response=True)` and emits a separate `gateway.cloud_policy_denied` event with `post_response: true` in the payload. Three test cases pin all combinations (drift+actual-allowed → call returns; drift+actual-denied → raise; external-to-external silent drift → raise). Removed the standalone `UpstreamDriftDetected` exception — the fail-loud channel is `CloudPolicyViolationError`, the audit-only channel is `gateway.upstream_drift_detected`.

- **P1 — OpenAI-compatible self-hosted aliases classified as cloud.** The Round-1 classifier rejected anything starting with `openai/` as external, but the existing `infra/litellm/config.yaml` declares vLLM/SGLang aliases as `model: openai/${COGNIC_TIER1_VLLM_MODEL}` with a private `api_base` — the canonical production self-hosted shape. Round-1 would have denied these production self-hosted routes under default policy. **Fix:** new `ResolvedUpstream(alias, model_string, api_base, external)` dataclass + new `_is_external(model_string, api_base)` classifier with priority order: api_base on known-cloud allow-list → external · api_base on private/local host → self-hosted · api_base unrecognised → external (fail-closed) · api_base unset → fall back to model prefix · else fail-closed. The `_KNOWN_CLOUD_HOST_SUFFIXES` constant + `_is_private_host` helper (RFC1918 / loopback / `*.local` / `*.svc` / single-label container DNS) live in `preflight.py`. `enforce_cloud_policy` now consumes `ResolvedUpstream` rather than a bare string. T2 simplified to ship only the tier-name → alias-string resolver (classification + ResolvedUpstream live with the YAML parser in preflight.py — co-location, and avoids the `gateway → preflight → gateway` circular import the Round-1 shape had).

- **P1 — `PreflightResolver` eagerly required env vars for unused aliases.** Round-1's `from_yaml()` substituted every `${VAR}` at construction. Real `infra/litellm/config.yaml` declares vLLM/SGLang entries whose env vars are normally unset in dev/CI; constructing the resolver for the default `cognic-tier1-dev` Ollama path would fail before any call was made. **Fix:** `from_yaml()` now stores RAW model + api_base templates; substitution is lazy per `resolve(alias)`. New test `test_lazy_substitution_does_not_require_unused_aliases` pins this — resolver loads cleanly with only dev env, dev alias resolves, vLLM alias raises `ValueError` only when actually selected. New test `test_round_trip_against_real_compose_config_dev_env_only` clears all production env vars and proves the dev path stands alone against the real repo YAML.

- **P1 — `outcome="drift"` not in T5 `_ALLOWED_OUTCOMES`.** T6 writes ledger rows with `outcome="drift"` on the drift-allowed path, and the top-level row-shape table now lists `drift`, but T5's `_ALLOWED_OUTCOMES` frozenset still omitted it. Implementing literally would have made the drift path raise during `GatewayCallRow.__post_init__`, turning intended drift telemetry into `LedgerWriteFailed`. **Fix:** added `"drift"` to `_ALLOWED_OUTCOMES` with an explanatory comment + extended the parametrised `test_known_outcomes_accepted` to cover it.

- **P2 — `LLMConcurrencyExceeded` was never ledgered.** Round-1's `async with self._rate_limiter.acquire(profile=tier):` had no `LLMConcurrencyExceeded` handler around it. A fail_fast saturation would exit silently from the gateway with no ledger attempt and no `outcome="concurrency_exhausted"` row. **Fix:** restructured the slot management in T6 to use explicit `slot_cm.__aenter__()` inside a `try/except LLMConcurrencyExceeded:` that calls `_best_effort_ledger_write` with `outcome="concurrency_exhausted"` before re-raising. Slot release moved to a `finally:` block that runs on every code path. New test `test_gateway_concurrency_ledger.py` asserts the ledger row exists before the exception reaches the caller.

### Round 3 — 2026-04-30 (pre-commit; user-driven, post-Round-2)

Two findings (1 P1 + 1 P2). Both architectural, both close before plan-PR commit.

- **P1 — `reverse_lookup` could misclassify provider drift on model_string collision.** The Round-2 `reverse_lookup` returned the *first* matching `ResolvedUpstream`. That is not conservative when two aliases share a model_string but differ in api_base / classification — the exact OpenAI-compat self-hosted vs cloud-OpenAI shape this plan now supports. Concrete attack: a YAML where `cognic-tier1-vllm-gpt4o-shape` (`model: openai/gpt-4o`, `api_base: http://vllm:8000/v1`) and `cognic-tier1-cloud-openai` (`model: openai/gpt-4o`, `api_key: sk-...`) both exist. LiteLLM's response `model` field of `openai/gpt-4o` is ambiguous; depending on YAML order, the reverse_lookup could map an actual cloud-OpenAI dispatch back to the private vLLM alias and let it pass policy as self-hosted (or vice versa). **Fix:** `PreflightResolver.reverse_lookup(model_string)` now returns `tuple[ResolvedUpstream, ...]` — ALL matching aliases. New `LLMGateway._build_actual_resolved` helper applies fail-closed disambiguation: 0 matches → fail-closed external + preflight api_base; 1 match → use it; N matches with uniform classification → use first; N matches with **mixed** classification → emit new `gateway.upstream_classification_ambiguous` audit event AND fail-closed external (api_base unset). Combined with the post-response policy recheck the ambiguous case now denies under default settings. New load-bearing test `test_gateway_classification_ambiguity.py` pins the collision case + its negative regression (denial holds even when allowed_providers includes the surface provider). Also added `test_reverse_lookup_returns_all_matches_on_collision` to the resolver test module.

- **P2 — Manual context-manager exit dropped exception context.** The Round-2 T6 sample entered the limiter context manually so it could ledger `LLMConcurrencyExceeded`, but the `finally:` always called `__aexit__(None, None, None)` — telling the context manager the body succeeded even when the LiteLLM call, guardrail, post-response policy recheck, or strict ledger write raised. Brittle and breaks any future limiter behaviour that depends on exception context. **Fix:** reverted to the natural `async with self._rate_limiter.acquire(profile=tier):` shape with the dispatch + post-dispatch flow inside. Per the language spec, when `__aenter__` raises, `__aexit__` is NOT called — so a fail_fast saturation propagates `LLMConcurrencyExceeded` directly to the outer `try/except` (which still ledgers + re-raises). Body exceptions trigger the limiter's `__aexit__(type(exc), exc, tb)` correctly. Restores natural exception-context propagation while preserving the Round-2-P2 ledger fix.

### Round 4 — 2026-04-30 (pre-commit; user-driven, post-Round-3)

Four findings (2 P1 + 2 P2). The first one is the load-bearing provider-honesty issue.

- **P1 — Ambiguous reverse lookup could still return when the surface provider was allowed.** The Round-3 fix set `ResolvedUpstream(external=True, api_base=None)` on the mixed-classification collision path and emitted `gateway.upstream_classification_ambiguous`, but nothing on the dataclass marked the result as untrustworthy. `enforce_cloud_policy` would then ALLOW it whenever `allow_external_llm=True` AND the surface provider prefix was on `allowed_providers`. So a bank that legitimately allows cloud OpenAI, with a YAML that declares both a private vLLM `model: openai/gpt-4o` and a cloud OpenAI `model: openai/gpt-4o`, could still get the call back with guessed provenance — exactly the provider-honesty hole this whole drift discipline exists to close. **Fix:** added `ambiguous: bool = False` field to `ResolvedUpstream`. `_build_actual_resolved` sets `ambiguous=True` on the mixed-classification fail-closed path. `enforce_cloud_policy` adds a new highest-priority gate: `if resolved.ambiguous: DENY` — applied BEFORE the `external` check, BEFORE the `allow_external_llm` check, BEFORE the `allowed_providers` check. ADR-007's authoritativeness contract requires per-call provenance; an ambiguous match is a provenance gap that no policy permission can paper over. The audit payload carries `ambiguous=true` so examiners see the YAML-collision config issue caused the denial, not the policy itself. The `test_gateway_classification_ambiguity.py` test gained Subtest B (denial holds with `allow_external_llm=True` + `allowed_providers=["openai"]`) and Subtest C (direct `enforce_cloud_policy` test with the most-permissive settings still denies on `ambiguous=True`).

- **P1 — Upstream HTTP errors used best-effort ledgering despite being post-dispatch.** The Round-3 T6 sample caught `httpx.HTTPError` after the `httpx.post` + `raise_for_status` block, treating connection failures (no dispatch) and HTTP status errors (response received from upstream) the same way — best-effort. That re-introduced the lossy post-dispatch ledger path Round-1 was meant to close: a 4xx/5xx response could hit LiteLLM/upstream and then drop the authoritative ledger row if persistence failed. **Fix:** split the exception handling into two stages. Stage 1 catches `httpx.RequestError` (connection / DNS / timeout — never dispatched) → best-effort regime. Stage 2 (after `httpx.post` succeeded) catches `httpx.HTTPStatusError` from `raise_for_status()` AND `ValueError` from `resp.json()` → strict regime, using `preflight_resolved` as the upstream identity since LiteLLM didn't return a parseable model field. The Decision-Locking §5 emission table now itemises HTTP status / JSON parse errors explicitly under the strict regime.

- **P2 — T5 ledger module docstring still described opportunistic writes.** The T5 docstring read "a failed write surfaces as an exception that the caller logs but does not re-raise (...ledger write is opportunistic for /system/effective-routing)" — directly contradicting the Round-1 ADR-007 success-contract language and able to steer implementation back toward the rejected Round-1 posture. **Fix:** rewrote the docstring to say `write_row` raises on persistence failure and the gateway chooses best-effort vs strict at call site. The ledger primitive itself does NOT swallow failures.

- **P2 — T6 prose still told implementers to use explicit `__aenter__`/`__aexit__`.** The Round-3 code sample correctly used `async with`, but the explanatory note below the code block + the T6 commit-message text still said "the slot uses explicit __aenter__/__aexit__ to make the try/except shape clean" — exactly the Round-3 bug just closed. A reader of the durable plan could regress to the broken shape. **Fix:** rewrote the post-code note to mandate the natural `async with` shape, explain why (`__aenter__`-raises → `__aexit__`-not-called per language spec), and explicitly instruct "do NOT regress" to the manual shape. T6 commit message updated to match.

### Round 5 — 2026-04-30 (pre-commit; user-driven, post-Round-4)

Two findings (2 P1). Both close before plan-PR commit. The reviewer also flagged a non-blocking note that the Round-2 patch log still describes the superseded `__aenter__` fix; not patched (the historical record is intentional, and Rounds 3/4 supersede clearly enough).

- **P1 — Zero-match reverse_lookup was also a provenance gap.** The Round-3 + Round-4 fixes set `ambiguous=True` on the mixed-classification collision path but the zero-match path was building `ResolvedUpstream(model_string=actual, api_base=preflight_resolved.api_base, external=True, ambiguous=False)`. Two problems: (a) the call still passes `enforce_cloud_policy` whenever the surface provider is on `allowed_providers` (same shape as the Round-4 collision-with-allowed-provider attack); (b) the ledger/audit payload would carry the *preflight's* api_base even though the actual model wasn't found in any declared route — a false provenance claim that violates ADR-007 §"two layers". **Fix:** zero matches now set `ambiguous=True` + `api_base=None` AND emit a new `gateway.upstream_unresolved` audit event (distinct from `gateway.upstream_classification_ambiguous` so operators can distinguish "missing route" from "conflicting routes" in evidence). `enforce_cloud_policy` denies unconditionally on `ambiguous=True`, regardless of the zero-match-vs-collision origin. Subtests D + E added to `test_gateway_classification_ambiguity.py`: D with default settings (denies), E with `allow_external_llm=True` + `allowed_providers=["openai"]` (still denies because the actual model is not declared in any route — the gateway cannot truthfully report the api_base).

- **P1 — `httpx.RequestError` was too broad to mean "no dispatch".** The Round-4 split classified ALL `httpx.RequestError` as pre-dispatch best-effort, but `RequestError` is the parent of `ReadTimeout`, `ReadError`, `WriteError`, `WriteTimeout`, `RemoteProtocolError`, etc. — exceptions that fire AFTER the request has been sent on the wire and possibly after LiteLLM has contacted the upstream. So Round 4 still kept a lossy post-dispatch path for the most operationally-relevant timeout cases. **Fix:** narrowed the pre-dispatch best-effort set to `httpx.ConnectError | ConnectTimeout | PoolTimeout | LocalProtocolError` only — exceptions that fire BEFORE any request bytes leave the gateway. All other `httpx.RequestError` subclasses are caught by a second `except` clause and routed through `_strict_ledger_write_or_raise(resolved=preflight_resolved)` because the request may have been (partially or fully) dispatched. New parametrised test module `test_gateway_httpx_dispatch_errors.py` pins all nine exception types to the correct regime + a negative regression where a strict-regime ledger failure during a `ReadTimeout` raises `LedgerWriteFailed` (not the bare `ReadTimeout`), preserving the ADR-007 success contract on dispatch-time httpx errors.

### Round 6 — 2026-04-30 (pre-commit; user-driven, post-Round-5)

Three findings (2 P1 + 1 P2). The ledger schema gap is the architectural one — the policy layer was enforcing provenance discipline that the persisted ledger row could not express, so `/effective-routing` would have to re-resolve current YAML to classify historical rows.

- **P1 — Missing response `model` field fell back to preflight provenance silently.** The Round-5 T6 sample read `actual_model_string = body.get("model") or preflight_resolved.model_string`. If LiteLLM returned a successful response with a missing/empty/non-string `model` field (genuinely possible — some upstreams omit it, or a misconfigured proxy strips it), the gateway silently assumed the preflight route, emitted no drift/unresolved event, and could return successfully with guessed provenance. **Fix:** factored a `_build_unresolved_actual(cause, preflight, ...)` helper used by BOTH the zero-match path AND the missing-field path. The `cause` field on the `gateway.upstream_unresolved` event payload distinguishes `"model_not_in_yaml"` from `"missing_model_field"` for examiner clarity. The unresolved `ResolvedUpstream` carries `provenance="unresolved"` + `api_base=None` + `model_string="<missing>"`. Subtest F + G added (default settings + permissive-allow-list both deny).

- **P1 — Authoritative ledger omitted api_base and provenance status.** The plan repeatedly described `/effective-routing` surfacing `alias + model_string + api_base + external + provenance`, and the new policy rules depended on distinguishing resolved/unresolved/ambiguous upstreams — but `GatewayCallRow` persisted only `upstream_model + external`, dropping `resolved.api_base` and the provenance state on every write. That made the endpoint unable to report historical api_base or provenance status without re-resolving current YAML, which is not authoritative for past calls. **Fix:** ledger schema extended with `upstream_api_base: str | None` + `provenance: str` columns. T4 Alembic migration adds both. T5 dataclass adds both with `_ALLOWED_PROVENANCES` whitelist (`resolved | unresolved | ambiguous | no_dispatch`). `ResolvedUpstream` rename: `ambiguous: bool` → `provenance: Literal["resolved", "unresolved", "ambiguous"]` (the value `"no_dispatch"` is ledger-only — pre-dispatch failures, where there's no actual provenance, only intent). `_strict_ledger_write_or_raise` writes `upstream_api_base=resolved.api_base` + `provenance=resolved.provenance`. `_best_effort_ledger_write` signature changed: takes `preflight: ResolvedUpstream` (always non-None now, since pre-dispatch paths know the preflight identity), writes `upstream_model=preflight.model_string + upstream_api_base=preflight.api_base + external=preflight.external + provenance="no_dispatch"`. `enforce_cloud_policy` highest-priority gate: `if resolved.provenance != "resolved": DENY` — single condition catching unresolved + ambiguous together. `/effective-routing` filters drift detection to `provenance IN ("resolved", "ambiguous")` so `no_dispatch` rows don't false-positive the PROFILE chip.

- **P2 — Flow diagram showed stale zero-match api_base behaviour.** The Round-5 implementation set zero-match actual upstreams to `api_base=None` + `ambiguous=True`, but the Decision-Locking §3 flow diagram still said "if no match: build a fail-closed ResolvedUpstream (model_string=actual, api_base=preflight.api_base, external=True)" — the exact provenance bug Round 5 fixed. **Fix:** rewrote the §3 flow diagram step 9 to enumerate the four reverse_lookup outcomes with their correct provenance values, and step 7 to call out the missing-model-field handling. The diagram is durable implementation guidance; stale wording would let a future implementer regress.

### Round 7 — 2026-04-30 (pre-commit; user-driven, post-Round-6)

Three findings (3 P1). All on the same theme: making every post-dispatch exit path obey the same ledger-first discipline.

- **P1 — `/effective-routing` excluded `unresolved` dispatched rows from drift detection.** Round 6 said the endpoint filtered drift to `provenance IN ("resolved", "ambiguous")`, but `unresolved` is also a post-dispatch state — LiteLLM returned a model that was missing or not declared. Excluding those rows let the PROFILE chip report self-hosted after an unresolved external-looking dispatch was denied post-response. **Fix:** filter widened to `provenance != "no_dispatch"` — includes resolved + unresolved + ambiguous, all three are post-dispatch upstream-contact events the operator must see. Endpoint test extended with a regression seeded with `provenance="unresolved"` + `external=True` + `allow_external_llm=False` → drift count includes the row, PROFILE chip flips to `self-hosted (DRIFT)`.

- **P1 — Post-dispatch audit failures could bypass strict ledgering.** After dispatch the gateway emits `sla.breach`, `gateway.upstream_drift_detected`, post-response `gateway.cloud_policy_denied`, `gateway.upstream_unresolved`, and `gateway.upstream_classification_ambiguous` — five hash-chain emissions on the post-dispatch path. If `AuditStore.append` raised on any of them, the gateway exited without writing a `gateway_call_ledger` row even though LiteLLM was already contacted. Same ADR-007 success-contract violation the strict regime was meant to prevent. **Fix:** wrapped the entire post-dispatch flow in an outer `try` / `except (CloudPolicyViolationError, GuardrailViolationError, LedgerWriteFailed): raise` / `except Exception as exc:` block. The catch-all path strict-ledgers with `actual_resolved or preflight_resolved` (whichever is bound at the failure point) using `outcome="upstream_error"` + `original_exc=exc`, then re-raises. New test module `test_gateway_post_dispatch_strict_discipline.py` pins five subtests (AuditStore raising on each of the three different post-dispatch event types + malformed-content cases) plus a negative regression where the strict ledger ALSO fails → `LedgerWriteFailed` raised, not the bare AuditStore exception.

- **P1 — Malformed response content raised before strict ledger write.** `content = body['choices'][0]['message']['content']` could raise `KeyError` / `IndexError` / `TypeError` after a successful response and after `actual_resolved` had been built. Unlike the JSON-parse / HTTP-status errors split into the strict regime in Round 4, content-extraction errors were uncaught and dropped the ledger row. **Fix:** wrapped the extraction in `try / except (KeyError, IndexError, TypeError): raise _MalformedResponseContent(...) from exc` plus a non-string-content type check. The `_MalformedResponseContent` internal sentinel propagates to the outer post-dispatch catch-all (Round-7 P1#2), which strict-ledgers with `actual_resolved` identity before re-raising. Subtests D + E in the new test module pin both shape failures (no `choices`, non-string content).

### Round 8 — 2026-04-30 (pre-commit; user-driven, post-Round-7)

Two findings (1 P1 + 1 P2). The first is the last provider-honesty hole on the post-dispatch path; the second is an older test-shape bug that would have failed at implementation time.

- **P1 — Provenance-event audit failures could ledger the wrong provenance.** The Round-7 outer-catch did `best_resolved = actual_resolved or preflight_resolved`, but `_build_unresolved_actual` and the mixed-classification branch of `_build_actual_resolved` both emitted their audit events BEFORE returning the unresolved/ambiguous `ResolvedUpstream`. If `gateway.upstream_unresolved` or `gateway.upstream_classification_ambiguous` audit emission failed, `actual_resolved` was unbound and the catch-all strict-ledgered the *preflight* identity as `provenance="resolved"` — false historical provenance recorded as evidence. **Fix:** refactored both helpers to be **synchronous** and return `(ResolvedUpstream, AuditEvent | None)`. The T6 caller assigns `actual_resolved` BEFORE the `await self._audit.append(pending_audit)` call, so an audit failure leaves `actual_resolved` bound to the correct fail-closed object with the correct provenance state. The outer catch-all then strict-ledgers with `provenance="unresolved"` or `provenance="ambiguous"`, not preflight resolved. Three new subtests added to `test_gateway_post_dispatch_strict_discipline.py`: AuditStore raises on `gateway.upstream_unresolved` (model_not_in_yaml cause) → ledger `provenance="unresolved"`; raises on `gateway.upstream_unresolved` (missing_model_field cause) → ledger `provenance="unresolved"`; raises on `gateway.upstream_classification_ambiguous` → ledger `provenance="ambiguous"`. None of the three should ledger as `provenance="resolved"`.

- **P2 — Forced-interleaving fail_fast test could not pass as written.** The Round-2 `_PausingLimiter` subclass paused BEFORE calling `super()._take_slot_or_raise(profile)`, so worker A had not taken a slot or acquired the per-profile lock when worker B arrived. Worker B entered the same override and also waited on the release event, so `assert b.done()` would always fail. Even if the pause were moved inside the lock, B would correctly wait briefly on the lock acquisition, so the assertion remained wrong. **Fix:** rewrote the load-bearing test as two complementary cases: `test_fail_fast_raises_immediately_when_saturated` pre-fills the slot via the public `acquire()` context manager then asserts a nested fail_fast acquire raises immediately (pytest test-level timeout catches the buggy "blocks on sem.acquire()" implementation); `test_fail_fast_no_race_under_concurrent_arrival` uses an `asyncio.Event` barrier to release two contenders simultaneously and asserts exactly one wins + one raises with neither blocking on slot availability. Both shapes are correct semantics for the atomic per-profile-lock implementation.

---

## What this plan does NOT include

- OPA-Rego cloud-policy enforcement (Sprint 4 seed + Sprint 13.5 full per ADR-015).
- `decision_history` emission for gateway calls (Sprint 9.5 — needs ADR-013 model_id).
- Model registry primitive itself (Sprint 9.5).
- LiteLLM-side OAuth/PRM authorization (Sprint 5+ MCP authz territory).
- Bank-grade guardrail program (carryover from Sprint 2.5 closeout — Sprint 3+).
- Pushing the branch, opening PR, merging — those are explicit per-action steps.
