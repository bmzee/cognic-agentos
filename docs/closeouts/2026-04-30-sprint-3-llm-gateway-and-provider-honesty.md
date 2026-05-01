# Sprint 3 — LLM Gateway + Provider-Honesty — Closeout Note

**Date:** 2026-04-30
**Sprints closed:** 3 (LLM gateway, cloud-policy enforcer, provider-honesty ledger, two operator-facing portal endpoints, cloud aliases + denial-path exerciseability).
**State:** **READY-FOR-GATE** on `feat/sprint-3-llm-gateway`. No push, no PR, no merge until the human authorises per the AGENTS.md per-action rule.
**Pre-T12 parent:** `02f2c68 feat(sprint-3): T10 - cloud aliases + denial-path exerciseability`.
**Branch base:** `8804088` on `main` — the Sprint 3 plan-of-record merge head (`chore(plan): sprint 3 llm gateway + provider-honesty plan-of-record (#9)`). The pre-plan main tip was `10715b1`; PR #9 merged the plan-of-record after 8 reviewer rounds, and this branch roots at that merge.
**15 commits total after T12 lands** atop the merged plan-of-record: T1, T1-followup, T2, T3, T4, T5, T6 phase A, T6 phase B, T7, T11, fix(tz-aware-ledger-test), T8, T9, T10, T12 closeout.

## What ships in `feat/sprint-3-llm-gateway` after Sprint 3

### Five new critical-controls modules (under `src/cognic_agentos/llm/`)

- **`llm/gateway.py`** — single LLM chokepoint. `LLMGateway.completion(*, tier, messages, request_id, tenant_id)` returns a `GatewayResponse`. Decision-Locking §3 phases enforced inline: pre-dispatch best-effort regime (tier alias resolve → preflight resolve → INPUT guardrails → pre-call cloud-policy → concurrency-slot acquire), narrow connect-class httpx catch (`ConnectError | ConnectTimeout | PoolTimeout | LocalProtocolError` only — Round-5 P1), post-dispatch strict regime wrapped in an outer `try/except` (Round-7 P1). Strict-ledger-then-return contract per ADR-007 §"two layers": no successful return without a persisted ledger row. Sprint-3 scope deliberately excludes hash-chained `decision_history` emissions (those land Sprint 9.5 with `model_id` per ADR-013). Per-file coverage: 99% line / 100% branch.
- **`llm/policy.py`** — pure-functional cloud-policy enforcer over `(ResolvedUpstream, Settings)`. Decision tree (priority-ordered): provenance != "resolved" → DENY (unconditional, Round-4 P1); not external → ALLOW; allow_external_llm=False → DENY; provider not in allowed_providers → DENY; policy_mode=self_hosted with external attempt → DENY (mode/flag mismatch). Round-10 P2 documented gap: cloud-mode-vs-provider-family binding (`cloud_openai` ⇒ openai-only) is NOT enforced today; that's Sprint 13.5 OPA-Rego. Per-file coverage: 100/100.
- **`llm/preflight.py`** — LiteLLM-alias → `ResolvedUpstream` resolver + the api_base-aware classifier. `PreflightResolver.from_yaml(path)` with lazy `${VAR}` substitution (Round-3 P1#3 — `from_yaml` stores raw templates; substitution happens only at `resolve()` time and only for `model` + `api_base` fields, never `api_key`). `reverse_lookup(model_string) -> tuple[ResolvedUpstream, ...]` returns ALL matching aliases so the gateway can fail-closed on collision (Round-3 P1). Four-state provenance vocabulary: `resolved` | `unresolved` | `ambiguous` | `no_dispatch`. `_is_external` priority order (api_base on cloud-host allow-list → external; private/loopback host → self-hosted; api_base unset + self-hosted prefix → self-hosted; otherwise fail-closed external). Per-file coverage: 100/100.
- **`llm/ledger.py`** — operational ledger writer + reader for ADR-007's authoritative `/effective-routing` source. `GatewayCallLedger.write_row` raises on persistence failure (Round-4 P2 fail-loud contract — best-effort vs strict regime decision is at the gateway, not at the ledger). `read_recent_calls(*, window_minutes)` powers the portal endpoint. `GatewayCallRow` carries `upstream_api_base` + `provenance` (Round-6 P1 — persisted at write so historical rows stay authoritative under YAML rotation). Per-file coverage: 100/100.
- **`llm/concurrency.py`** — `ProfileRateLimiter` per-tier in-flight limiter with `queued` / `fail_fast` modes. Atomic acquisition via `asyncio.Lock` (reviewer-P2#2). `LLMConcurrencyExceeded` raised in fail-fast saturation; queued mode blocks. Per-file coverage: 100/100.

### One additive primitive on the Sprint-2 substrate

- **`gateway_call_ledger` Alembic migration** (`src/cognic_agentos/db/migrations/versions/20260430_0002_gateway_call_ledger.py`) — PG/Oracle dialect-portable; `sa.TIMESTAMP(timezone=True)` matches the `GATEWAY_LEDGER_TS_TYPE` convention so Oracle preserves the offset on read-back. `model_id` reserved nullable for Sprint 9.5 (ADR-013) backfill. The ledger is plain INSERT, NOT hash-chained (per ADR-007 §"two layers" the operational ledger is intentionally lossless-on-write but not tamper-evident — tamper-evidence for the violation cases lives in `audit_event`).

### Two operator-facing portal endpoints

- **`GET /api/v1/system/policy`** — cloud-policy intent surface. Returns `allow_external_llm`, `mode` (operator vocabulary for the internal `policy_mode`), `allowed_providers`, `llm_guardrail_scope`, `tier1_alias`, `tier2_alias`, `provider_honesty_ledger_window_minutes`. Read-only; reflects current `Settings`.
- **`GET /api/v1/system/effective-routing`** — provider-honesty outcome surface (authoritative per ADR-007). Reads the `gateway_call_ledger` over the configured window. Surfaces `recent_calls` (count map by `upstream_model`), `recent_call_details` (per-row detail with persisted `upstream_api_base` + `provenance` — Round-6 P1), `profile.chip` (intent + drift detection — Round-7 P1: filters drift to `provenance != "no_dispatch"`, includes resolved/unresolved/ambiguous), and `langfuse_available` (opportunistic Langfuse health probe; never fails closed per ADR-007 §"two layers" — Round-9 P2 mutation-tested against literal-False return + dropped-except regressions).

### Four cloud aliases in `infra/litellm/config.yaml`

`cognic-tier{1,2}-cloud-{openai,anthropic}` declared so the cloud-policy denial path is exercisable end-to-end against the same router config the runtime uses. No `api_base` on any cloud alias — load-bearing for the api_base-aware classifier (Round-2 P1#2). Round-10 P2 correction: comments in the YAML + `.env.example` describe the *actual* enforcer scope (allow-list + flag + `policy_mode != self_hosted`); the cloud-mode-vs-provider-family binding gap is documented and pinned.

### Critical-controls coverage gate extension

- **`tools/check_critical_coverage.py`** — extended in T11 with the LLM-gateway-shape quintet (`gateway`, `policy`, `preflight`, `ledger`, `concurrency`) at the same single strict floor (`0.95 line / 0.90 branch`) as the Sprint 2 + 2.5 modules. Gate now enforces 12 modules; all PASS at current coverage.

## CI / production-grade gates

| Gate | Workflow | Trigger | Behaviour |
|---|---|---|---|
| Lint + types + tests | `python.yml` → `lint + test` | push / PR | `ruff` + `ruff format --check` + `mypy` strict + `pytest -v` (unit) |
| Per-file critical-controls coverage gate | `python.yml` → `lint + test` | push / PR | `tools/check_critical_coverage.py` against `coverage.json` — fails CI if any of the **12** critical-controls modules drops below 95% line OR 90% branch (extended in T11 to add gateway / policy / preflight / ledger / concurrency) |
| Image-size budget + boot smoke | `python.yml` → `image size budget` | push / PR | unchanged from Phase 1 |
| Live Postgres integration | `python.yml` → `postgres integration` | push / PR | Sprint 3's `gateway_call_ledger` integration tests run alongside Sprint 2 + 2.5 |
| Live Oracle integration | `python.yml` → `oracle integration` | push / PR | same as PG; ledger column types verified portable |

## Doctrine adherence

- **AGENTS.md per-edit halt-before-commit on critical-controls modules.** Every commit that touched `llm/gateway.py`, `llm/policy.py`, `llm/preflight.py`, `llm/ledger.py`, or `llm/concurrency.py` paused for explicit user authorization. T6 was split into Phase A (preflight resolver) + Phase B (full gateway) with separate halts; both went through reviewer rounds before merge. Multiple post-implementation reviewer rounds (R9, R10) folded inline before commit.
- **AGENTS.md `core/canonical.py` per-edit stop rule.** Not touched in Sprint 3.
- **Production-grade rule.** No mocks in runtime paths. The gateway dispatches via real `httpx.AsyncClient` to LiteLLM; only test paths use `respx` for HTTP shaping. The cloud aliases dispatch to the actual public OpenAI / Anthropic APIs when an operator opens the policy gates — they exist precisely to be deniable end-to-end without contrivance. Langfuse-availability is a real `health_check()` against the bundled observability adapter; the `_StubObservabilityAdapter` lives only in tests.
- **Plugin discipline (ADR-001).** No agents, tools, skills, UI, or bank overlays added. All work sits under platform-primitive (`llm/*`, `portal/api/*` surfaces) layer. The cloud-alias declarations are infrastructure config, not pack content.
- **Per-action authorization rule.** All 15 commits (including this T12 closeout) sit on the feature branch with **no push, no PR, no merge** until the human authorises post-READY-FOR-GATE. Each task's commit was a discrete authorization (full-word `commit` after halt-before-commit summary). The Sprint 2.5 CI wiring follow-up flagged after T7 review remains queued separately.

## Test + coverage state

- **Tests:** Sprint 3 ready state is **945 passed + 29 skipped = 974 collected** locally (skips are env-gated PG/Oracle integration). The Sprint-2.5 merge baseline was **659 passed + 24 skipped = 683 collected**. **Delta: +286 passed / +291 collected** vs the BUILD_PLAN-projected `~4 tests` against the original Sprint 3 deliverable list — the actual ratio reflects the depth of plan-review-driven regression tests; see "Plan-review findings closed" below. Both metrics stated to avoid the passed-vs-collected ambiguity that the Sprint-2.5 closeout's `683 collected` denominator surfaced.
- **Coverage:** **96% global** with `db/migrations/env.py` excluded from rollup (alembic CLI subprocess; same exclusion as Sprint 2). Per-file gate now enforces 12 modules:
  - `core/audit.py` — 100/100
  - `core/canonical.py` — 95.7/94.4
  - `core/chain_verifier.py` — 97.9/95.5
  - `core/decision_history.py` — 100/100
  - `core/sla.py` — 100/100
  - `core/escalation.py` — 100/100
  - `core/guardrails.py` — 100/100
  - **`llm/gateway.py` — 99.1/100** *(new)*
  - **`llm/policy.py` — 100/100** *(new)*
  - **`llm/preflight.py` — 100/100** *(new)*
  - **`llm/ledger.py` — 100/100** *(new)*
  - **`llm/concurrency.py` — 100/100** *(new)*
- **Negative-path coverage highlights:** httpx exception taxonomy (parametrized 11 arms across pre-dispatch connect-class vs post-dispatch dispatched-class); strict-vs-best-effort ledger regime matrix; one-call/one-ledger-row contract under HTTP-status, JSON-decode, malformed-content, and audit-emission failures (Round-9 P2-1 closed double-write); guardrail four-mode scope matrix end-to-end (off / external_only / self_hosted_only / all) including asymmetric drift (input gates on preflight, output on actual — Round-9 P2-2); post-dispatch audit-failure preserves correct provenance (Round-7 P1 outer try/except + Round-8 P1 sync-build-then-audit); Langfuse contract (healthy / unreachable / raises) mutation-tested against literal-False return + dropped-except regressions; cloud-alias resolves-then-denies under default policy with NO cloud credentials present (Round-10 P2 lazy-contract correction); policy-mode-vs-provider-family gap pinned as a tripwire so any future enforcement ratchet trips an explicit test.

## Plan-review findings closed

Sprint 3's plan-PR went through **8 reviewer rounds** before any code landed; **2 additional reviewer rounds (R9, R10)** during execution surfaced findings that were folded inline before each commit. All findings produced regression tests pinning the fix:

- **Plan-PR rounds 1-8:** Round-1 P1#1 ledger-as-success-contract (no successful return without a persisted ledger row); R1 P1#2 post-response policy recheck on `actual_resolved` (closed external→external silent-drift class); R2 P1#1 string-equality drift-event emission (catches external→external provider drift even when both classify external); R2 P1#2 api_base-aware classification (vLLM with private api_base classifies as self-hosted even when model is `openai/X`); R3 P1 reverse_lookup tuple disambiguation; R3 P2 clean `async with rate_limiter.acquire()` (no manual `__aenter__` / `__aexit__`); R4 P1 `provenance != "resolved"` DENY unconditionally regardless of allow-list; R5 P1 narrow connect-class set + zero-match treated as `provenance="unresolved"`; R6 P1 missing/empty/non-string `model` field → `provenance="unresolved"`; R7 P1 outer `try/except` around post-dispatch flow + `_MalformedResponseContent` sentinel + `/effective-routing` drift filter widened to `provenance != "no_dispatch"`; R8 P1 sync `_build_actual_resolved` / `_build_unresolved_actual` so audit-emission failures preserve correct provenance state.
- **R9 reviewer P2 (T6 Phase B post-write review):** P2-1 `json.JSONDecodeError` on `resp.json()` was strict-ledgered twice (inner handler + outer catch-all) — closed by adding `_json.JSONDecodeError` to the outer pass-through tuple; one-call/one-ledger-row contract restored. P2-2 guardrail scope matrix incomplete — closed by `TestGuardrailScopeExternalRoutes` + `TestOutputScopeMatrix` + `TestInjectNoneIndependence` + `TestScopeAsymmetryUnderDrift` (9 new tests including the input-gates-on-preflight / output-gates-on-actual asymmetry pin).
- **R9 reviewer P2 (T9 post-write review):** Langfuse availability contract not actually pinned — closed by `_StubObservabilityAdapter` + healthy / unreachable / raises arms; mutation-tested by replacing the probe with `return False` (caught by the healthy arm) and with bare `raise` (caught by the raises arm); production code restored after both mutants tripped.
- **R10 reviewer P2 (T10 post-write review):** P2-A YAML / `.env.example` cloud-alias comments overstated provider-mode enforcement (claimed `cloud_openai` ⇒ openai-only when the runtime only checks `allowed_providers`) — closed by rewriting comments to match runtime + adding `test_policy_mode_does_not_bind_provider_family` as a tripwire that fails when any future runtime ratchet binds policy_mode to provider families. P2-B cloud-key lazy contract was documented backwards (test prose claimed cloud aliases fail at `resolve()` when api_key is unset, but `PreflightResolver` never reads `api_key`) — closed by inverting the prose, removing unnecessary `setenv("OPENAI_API_KEY", ...)` calls from the resolution tests, and adding `test_cloud_alias_resolves_then_denies_under_default_policy` (parametrized × 4) that pins the actual T10 denial-path-exerciseability story end-to-end with NO cloud credentials present.

The deferred T11 plan-doc drift sweep was folded into the T12 authoring pass: T2 / T3 / T6 plan samples already align with what shipped (the plan went through 8 review rounds before any code landed). R9 + R10 reviewer findings post-date the plan-of-record and are pinned by inline tests + commit messages, not plan-doc edits. No discrepancy fixes required in the plan document.

## ADR-007 Provider-Honesty Validation

**Sprint 3 implements the gateway chokepoint + cloud-policy enforcer + provider-honesty ledger + the `/effective-routing` honesty surface, NOT the full ADR-007 program.** This section maps each ADR-007 concern to what Sprint 3 actually delivered vs what remains carryover.

| Concern | Sprint-3 status | Notes |
|---|---|---|
| **Single LLM chokepoint** | **Delivered.** | `llm.gateway.LLMGateway.completion` is the only path to LiteLLM in this repo. No code outside the gateway issues `httpx` requests to a LiteLLM URL. |
| **Cloud-policy fail-closed enforcement** | **Delivered, with documented gap.** | `enforce_cloud_policy` denies on any provenance gap, missing flag, or provider not on allow-list. **Gap (documented + pinned):** `policy_mode=cloud_openai` is NOT bound to provider=openai today; that family-level binding is Sprint 13.5 OPA-Rego. The gap is asserted in `test_policy_mode_does_not_bind_provider_family` so any future runtime ratchet trips an explicit test. |
| **Provider-honesty ledger** | **Delivered.** | `gateway_call_ledger` (PG/Oracle, Alembic-managed) writes per call. Strict regime on dispatched calls (no successful return without a persisted row); best-effort on pre-dispatch failures (hash-chained `audit_event` already records the violation). |
| **`/effective-routing` runtime endpoint** | **Delivered.** | Authoritative on the local ledger; opportunistic Langfuse enrichment via `langfuse_available` flag; never fails closed on missing data. PROFILE-chip drift detection filters to post-dispatch states only (R7 P1). |
| **Drift detection** | **Delivered.** | `gateway.upstream_drift_detected` audit event emitted unconditionally on any `actual_model_string != preflight.model_string`; post-response policy recheck on `actual_resolved` denies via `CloudPolicyViolationError(post_response=True)` when the actual provider isn't on the allow-list. Three test cases pin all combinations (drift+actual-allowed → call returns; drift+actual-denied → raise; external-to-external silent drift → raise). |
| **Tier alias contract** | **Delivered.** | Three layers: `Tier` literal → LiteLLM alias name (operator-configured) → `ResolvedUpstream` (resolved at gateway-boundary from the same `infra/litellm/config.yaml` LiteLLM consumes). No static alias map; eliminates the static-map-drift class. |
| **Decision-history emission** | **Carryover (Sprint 9.5).** | Sprint 3 emits `audit_event` rows (hash-chained) on every cloud-policy denial / drift / unresolved / ambiguous / SLA breach / guardrail trip, but does NOT emit `decision_history` rows. Decision-history requires `model_id` per ADR-013, which is Sprint 9.5 model-registry territory. Ledger row reserves a nullable `model_id` column for that backfill. |
| **OPA-Rego policy engine** | **Carryover (Sprint 4 seed + Sprint 13.5 full).** | The Sprint 3 enforcer is a static decision tree. ADR-015 explicitly defers the full policy engine to Sprint 13.5; Sprint 4 seeds `core/policy/engine.py` for supply-chain decisions only. Cloud-policy + drift recheck migrate to OPA-Rego in Sprint 13.5. |
| **Langfuse trace lifecycle** | **Partial — health probe only.** | `_probe_langfuse` calls `adapters.observability.health_check()`; no parent-child agent span emission, no per-call generation records, no scorer integration. Real Langfuse SDK lifecycle wiring lands Sprint 4-onwards alongside `core/decision_history` consumers and the agent runtime. ADR-007 explicitly defers Langfuse to enrichment-only in Sprint 3. |
| **Per-tenant routing / isolation** | **Carryover (Sprint 13.5).** | `tenant_id` is propagated through `GatewayCallRow.tenant_id` + audit payloads + ledger reads, but no per-tenant routing logic, per-tenant guardrail bundles, or per-tenant cloud-policy overrides exist in Sprint 3. Per-tenant Rego policy (per ADR-015) lands in Sprint 13.5. |
| **Operational metrics / alerting** | **Carryover (Phase 3 observability).** | The gateway emits OTel spans via the existing FastAPI instrumentation but does NOT emit per-call provider metrics, drift-rate SLOs, or breach-rate alerts. Prometheus / Grafana wiring + on-call paging integrations land in the Phase-3 observability work. |
| **Cloud-credential management** | **Partial — env-var only in Sprint 3.** | API keys flow via `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` env vars consumed by LiteLLM at dispatch time. **Carryover:** Vault-backed runtime credential resolution is Sprint 10 territory. The cloud aliases work end-to-end with env-var creds today; Sprint 10 will swap the substitution layer without changing the alias surface. |

**The shorthand:** Sprint 3 ships the **single LLM chokepoint, the cloud-policy enforcer, the authoritative provider-honesty ledger, and the operator-facing `/policy` + `/effective-routing` endpoints**. ADR-007's full vision (per-tenant Rego policies, decision-history with model_id, full Langfuse trace lifecycle, alerting) requires additional sprint work — explicitly named in the carryover rows above. Banks deploying AgentOS post-Sprint-3 get a chokepoint they cannot bypass, fail-closed cloud-policy enforcement at the per-call boundary, an authoritative ledger they can audit against, and a portal endpoint the operator can read in real-time. They do NOT yet get per-tenant policy admission, full Langfuse observability, or model-lifecycle linkage.

## Doctrine amendments accepted in Sprint 3

- **Sprint-2 amendment to `core/canonical.py` stop rule** (out of Sprint 3 scope but landed alongside) — every edit to `core/canonical.py` (canonical-form / hash framing) requires human review on **every** edit, not just non-trivial ones, with an explicit `schema_version` bump in `audit_event` + `decision_history` migrations.
- **AGENTS.md critical-controls list** already named `llm/gateway.py`. Sprint 3 T11 extends the per-file coverage gate with `policy.py`, `preflight.py`, `ledger.py`, and `concurrency.py` at the same strict floor — these four modules are co-load-bearing on the same cloud-policy / provider-honesty path the gateway anchors. No AGENTS.md edit required (the gate config IS the enforcement of the doctrine).
- **BUILD_PLAN Sprint 3 deliverables list** — extended in T12 to surface the Alembic migration, the cloud aliases, the critical-controls gate extension, and both portal endpoints (`/policy` + `/effective-routing`) as load-bearing artifacts. No scope change; clearer accounting.
- **Plan-of-record samples** — no edits required after the T11 deferred drift sweep. The T2 / T3 / T6 samples already match what shipped.

## Carryover for Sprint 4 / 4-onwards

Stored in Sprint 3 / wired in later sprints:

- **Sprint 4 supply-chain enforcement consumers** of `enforce_cloud_policy` — same fail-closed primitive; Sprint 4 starts using the policy-engine seed (`core/policy/engine.py`) for supply-chain grade decisions, leaving cloud-policy on the static enforcer until Sprint 13.5.
- **Sprint 9.5 (model-registry per ADR-013)** — first writer of `gateway_call_ledger.model_id` and first emitter of `decision_history` rows for LLM calls. The ledger schema reserved that column at T4 to avoid a migration churn.
- **Sprint 10 Vault-backed runtime credentials** — the cloud aliases dispatch via env-var creds today; Sprint 10 swaps the substitution layer without changing the alias surface.
- **Sprint 13.5 OPA-Rego full policy engine** — `cloud-policy.rego` migrates the Sprint 3 static enforcer to a Rego bundle; per-tenant policy admission + the policy-mode-vs-provider-family binding land here. The tripwire test in `test_gateway_policy.py` is the migration anchor.
- **Phase-3 observability** — per-call provider metrics + drift-rate SLOs + alerting consume the same `gateway_call_ledger` rows the portal endpoint already reads.

## Out of Sprint 3 scope (deferred per plan)

- ML-based `cloud-policy.rego` / per-tenant Rego — Sprint 13.5 per ADR-015.
- `decision_history` emission for LLM calls — Sprint 9.5 with `model_id` per ADR-013.
- Full Langfuse trace lifecycle (parent-child agent spans, generation records, scorer integration) — Sprint 4-onwards alongside the agent runtime.
- Per-tenant routing / isolation / cloud-policy overrides — Sprint 13.5.
- Vault-backed runtime credential resolution — Sprint 10.
- Operational metrics + alerting — Phase 3 observability work.
- Sprint 2.5 CI wiring follow-up — separately tracked, not in this sprint.
- Push, PR, merge — per per-action rule. This closeout is the READY-FOR-GATE checkpoint.

## Next sprint

**Sprint 4 — Plugin registry + trust gate + supply-chain attestations + policy-engine seed** ([BUILD_PLAN.md](../BUILD_PLAN.md) Sprint 4). Begins after Sprint 3 merges to `main`:

- `protocol/plugin_registry.py` — entry-point discovery for `cognic.tools` / `cognic.skills` / `cognic.agents` packs.
- `protocol/trust_gate.py` — cosign verification with secure subprocess invocation; per-tenant allow-list.
- `protocol/supply_chain.py` — Wave-1 attestation pipeline (cosign + SLSA L3+ + in-toto + SBOM + vuln + license + Sigstore bundle 7-year retention) per ADR-016.
- `core/policy/engine.py` — minimal Rego evaluator seed (used by Sprint 4 supply-chain decisions, expanded to full engine in Sprint 13.5).
- First production caller of `core/decision_history.append_with_precondition` for plugin-registration state-machine emissions.

Sprint 3 ships the LLM chokepoint + provider-honesty surface; Sprint 4 starts gating what packs are even allowed onto the system before any LLM call happens.
