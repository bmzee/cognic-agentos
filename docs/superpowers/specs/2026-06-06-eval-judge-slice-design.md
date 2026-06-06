# Eval Judge Slice — Design Spec (2026-06-06)

**ADR-010 LLM-as-judge — the first in-repo consumer of the harness-built `app.state.llm_gateway`.**

## Goal

Give the runtime `LLMGateway` a real, governed in-repo consumer — converting it from *wired* (Workstream #2 / PR #50) to *exercised*. The consumer is a generic, persona-agnostic OS evaluation primitive (`evaluation/judge.py`) plus a portal surface (`POST /api/v1/eval/judge`) that runs a **single governed judge call** through the gateway and records a hash-chained `eval.judge_verdict` evidence event.

This is a deliberately narrow ADR-010 slice — the LLM-as-judge call path only. It is the legitimate first consumer because evaluation is kernel-adjacent (the eval harness is OS, per AGENTS.md), the judge call genuinely needs the governed gateway, and ADR-010 mandates judge calls run through the same audited gateway as production. It is **not** an agent (no Layer-C smuggling) and **not** a synthetic seam-exerciser.

## Context

- Workstream #2 (PR #50, `fffd621`) built `harness/build_runtime`, which constructs the real `LLMGateway` and publishes it on `app.state.llm_gateway` — but **no in-repo path reads it yet** (the closeout's "primitive-wired, consumption-deferred" marker). This slice closes that gap honestly.
- Reconnaissance (read-only, 2026-06-06) confirmed: no `evaluation/`/`eval/` package exists; `LLMGateway.completion(...)` (`llm/gateway.py:260`) is the call seam; `GatewayResponse.content: str` (`llm/gateway.py:160`) is the model text; `DecisionRecord` (`core/decision_history.py:206`) + `DecisionHistoryStore.append(record)` (`:361`) is the simple-append seam; RBAC convention is `<Domain>RBACScope = Literal[...]` + `<DOMAIN>_SCOPES` frozenset (`portal/rbac/scopes.py`).

## Scope (frozen)

**In:**
- `evaluation/judge.py` — the generic governed-judge primitive (on the CC coverage gate, 113th entry).
- `portal/api/evaluation/routes.py` + `dto.py` — `POST /api/v1/eval/judge` (off-gate).
- Request-time `_require_llm_gateway` DI seam with fail-closed `503` (mirrors T7's `_require_memory_api_factory`).
- `eval.judge.run` RBAC scope family (`portal/rbac/scopes.py`).
- `eval_judge_tier` Setting (`core/config.py`).
- `eval.judge_verdict` chain evidence (value-free; `succeeded` / `errored` statuses).
- `tests/unit/architecture/test_eval_fences.py` — OS/pack architecture fence.

**Out (deferred / forbidden):**
- Corpora, datasets, bulk/simulated/replay runners, scorer registry — the rest of ADR-010.
- **Langfuse / observability trace** — the gateway does not emit it today; deferred to a separate **gateway-observability workstream** (a CC change to `llm/gateway.py` that benefits every caller).
- Per-persona / per-agent scorers — those ship in **agent packs** (AGENTS.md), never here.
- Criterion **weights** / numeric rubric aggregation — explicitly out, to avoid drifting into rubric/scorer land. `score` is a model-supplied scalar, not a computed weighted aggregate.
- Caller-chosen tier — the tier is operator-configured (`eval_judge_tier`), never request-supplied (cost/abuse-routing guard).

> **Package naming:** `evaluation/` (NOT `eval/`) — `eval` is a Python builtin and a package/module named `eval` trips ruff `A005` (builtin-module-shadowing). The URL segment stays `/api/v1/eval/...` (independent of the package name).

## Architecture & data flow

```
POST /api/v1/eval/judge
  → RequireScope("eval.judge.run")               # 403 scope_not_held
  → _require_llm_gateway(request)                # 503 llm_gateway_unavailable (fail-closed)
  → _require_decision_history_store(request)     # 503 decision_history_unavailable (runtime-first; BOTH resolve before any gateway call)
  → JudgeRequest (Pydantic, bounds-validated)    # 422 on shape violation — BEFORE any gateway call
  → run_judge(request, gateway, request_id, tenant_id, tier)   # evaluation/judge.py
        → gateway.completion(tier, messages, request_id, tenant_id) -> GatewayResponse
              # real governance INSIDE: input guardrails + cloud-policy + ledger + policy/drift audit
        → parse GatewayResponse.content -> JudgeVerdict | JudgeUnparseable
  → route maps the outcome:
        JudgeVerdict     → append eval.judge_verdict(status="succeeded") → 200 verdict
        JudgeUnparseable → append eval.judge_verdict(status="errored")   → 502 judge_verdict_unparseable
        gateway raised   → map exception to HTTP; NO eval event (gateway already audited/ledgered)
```

**Module split (single responsibility):**
- `evaluation/judge.py` (the primitive): builds the judge prompt, calls `gateway.completion`, parses `content` into a verdict. It performs **no persistence and no HTTP**; it returns an outcome. It lets gateway exceptions **propagate** (it never catches-and-fabricates). This is the governed-call decision surface → on the CC gate.
- `portal/api/evaluation/routes.py` (the surface): DI + RBAC + request validation + calls the primitive + owns the chain append + HTTP mapping. Off-gate (R32 precedent — `inspection_routes.py` / `evidence_routes.py`), but covered by route tests.

## Request / response contract

**`JudgeRequest`** (Pydantic v2, `dto.py`) — bounds are **wire-validated** (422 before any gateway call):
- `candidate_output: str` — **non-empty AND length-capped** (`min_length=1`, `max_length=_MAX_CANDIDATE_CHARS`). The text being judged — the **largest prompt/cost vector**, so it MUST be bounded.
- `candidate_input: str | None = None` — optional; the input that produced the output (judge-with-context); also capped (`max_length=_MAX_CANDIDATE_CHARS`).
- `criteria: list[JudgeCriterion]` — **1..N** (`min_length=1`, `max_length=_MAX_CRITERIA`); **criterion names unique** (validator); each `JudgeCriterion = {name: str (1..=_MAX_CRITERION_NAME_CHARS), description: str (1..=_MAX_CRITERION_DESC_CHARS)}`.
- **[P1 fix] Named bound constants** (in `dto.py`; proposed defaults, tunable in the plan): `_MAX_CANDIDATE_CHARS = 50_000`, `_MAX_CRITERIA = 20`, `_MAX_CRITERION_NAME_CHARS = 200`, `_MAX_CRITERION_DESC_CHARS = 2_000`. **Every text field is capped** so total prompt size — hence cost — is bounded; over-length is a `422` at the wire, before any gateway call. (Criteria *count* alone was insufficient — the candidate text was the unbounded vector.)
- No `weights` field — out of scope.

**`JudgeVerdict`** (the `succeeded` response, 200):
- `verdict: Literal["pass", "fail", "inconclusive"]`
- `score: float | None` — model-supplied scalar in `[0, 1]` if present; NOT a computed aggregate.
- `rationale: str`
- `criteria_results: list[{name: str, passed: bool, note: str}]` — **must correspond exactly** to the requested criterion names (same set, no extras, no omissions). A mismatch is an `errored` outcome (see failure taxonomy), NOT a 200.
- `model: str`, `tier: str`, `latency_ms: int` — surfaced from `GatewayResponse` (honesty: what was actually hit).

## Judge prompt

The primitive constructs an OpenAI-style `messages: list[dict[str, str]]` for `gateway.completion`:
- **system**: a fixed, persona-agnostic evaluator instruction — "You are a rigorous evaluator. Judge the candidate output against EACH named criterion. Respond with ONLY a JSON object matching this schema: {…}. Use `inconclusive` when the criteria cannot be assessed from the given material." The schema embedded is the `JudgeVerdict` shape with the exact requested criterion names enumerated.
- **user**: the `candidate_input` (if present) + `candidate_output` + the criteria (name + description), clearly delimited.

The system prompt is OS-owned and generic — it encodes *how to be a judge*, never *what a specific agent's rubric is*. Persona rubrics arrive only as caller-supplied `criteria`, never baked in.

## Failure taxonomy (precise — two distinct modes)

The `eval.judge_verdict` event is appended **only when the gateway produced content**. Two cases:

**Mode A — gateway succeeded, verdict unparseable.** `gateway.completion` returned a `GatewayResponse`, but the parser cannot produce a valid `JudgeVerdict` (non-JSON, schema mismatch, or `criteria_results` names ≠ requested names). The primitive returns `JudgeUnparseable(parse_reason, response)`. The route:
- appends `eval.judge_verdict` with `status="errored"` carrying **only safe evidence**: `input_digest`, `output_digest`, `response_digest` (sha256 of the unparseable gateway content), `criteria` (names + descriptions), `parse_reason` (closed-enum: `not_json` / `schema_mismatch` / `criteria_mismatch`), `model`, `tier`, `latency_ms`. **No verdict, no raw content.**
- returns `502 {"reason": "judge_verdict_unparseable"}`.
- Rationale: a judge that cannot produce a clean verdict **refuses** — it never fabricates a pass/fail. But the governed event (a judge ran and could not conclude) is regulator-visible, mirroring how the gateway audits `cloud_policy_denied`.

**Mode B — gateway failed before usable content.** `gateway.completion` raised (e.g. `GuardrailViolationError`, `CloudPolicyViolationError`, concurrency/SLA/upstream errors). The gateway has **already** recorded its own evidence (hash-chained `audit_event` for the violation + best-effort ledger). The eval layer:
- does **NOT** append `eval.judge_verdict` — there is no judge outcome to record, and fabricating one would be dishonest.
- maps the gateway exception to an HTTP status (the gateway exception taxonomy → HTTP enumerated in the plan) and returns it.
- Rationale: let the gateway's own audit/ledger evidence stand; the eval layer adds nothing truthful here.

## Chain evidence: `eval.judge_verdict` (value-free)

Minted as `DecisionRecord(decision_type="eval.judge_verdict", request_id, tenant_id, actor_id=<actor.subject>, payload=…, iso_controls=(…))` → `store.append(record)`.

**Value-free payload** (chain-payload-is-evidence-snapshot + the memory/routes value-free precedent): raw `candidate_input`/`candidate_output`/gateway-content never enter the chain — only **sha256 digests**. The *judgment* (verdict + criteria_results) IS governance evidence and goes in plaintext on `succeeded`.

- `status="succeeded"`: `verdict`, `score`, `criteria_results`, `criteria` (names+descriptions), `input_digest`, `output_digest`, `model`, `tier`, `latency_ms`.
- `status="errored"`: `criteria`, `input_digest`, `output_digest`, `response_digest`, `parse_reason`, `model`, `tier`, `latency_ms` (no verdict).

`request_id` ties the eval event to the gateway's ledger/audit rows for the same call (cross-evidence traceability). `actor_id` records who ran the judge. `langfuse_trace_id` is left `None` (honest — the gateway emits no trace). **`iso_controls = ("ISO42001.A.7.4",)`** — A.7.4 is the fit for this judge slice; A.7.6 stays tied to the **deferred** machine-verified risk-evaluation / adversarial-corpus work and is NOT used here. The ISO tag is part of the chain-row wire contract, so it is **locked at spec time**, not deferred to the plan.

## Settings

`eval_judge_tier: str` (`core/config.py`) — the tier alias the judge dispatches against (resolved via the gateway's `resolve_tier_alias`). **Operator-configured, never caller-supplied.** Default points at a sensible eval tier alias; in strict profiles the existing tier-alias guards (Wave-1) still apply.

## RBAC

New scope family in `portal/rbac/scopes.py` (plain `= Literal[...]` convention, no `TypeAlias`):
```python
EvalRBACScope = Literal["eval.judge.run"]
EVAL_SCOPES: frozenset[EvalRBACScope] = frozenset({"eval.judge.run"})
```
The route guards with `RequireScope("eval.judge.run")` → `403 scope_not_held` on miss. Not a human-only decision (a service actor may run judges).

## DI seam + mount

- `_require_llm_gateway(request) -> LLMGateway` (module-level dep in `routes.py`): reads `request.app.state.llm_gateway`; fail-closed `503 {"reason": "llm_gateway_unavailable"}` when `None`. Directly mirrors T7's `_require_memory_api_factory` — same fail-closed pattern this branch's parent workstream just built. (`app.state.llm_gateway` is populated by `build_runtime` on the adapter path; `None` only in the construction-before-lifespan window or the no-adapter test path.)
- `_require_decision_history_store(request) -> DecisionHistoryStore` (module-level dep): **the store is NOT reliably on `app.state.decision_history_store` in prod** — `create_prod_app()` calls `create_app(adapter_registry=bundled_registry)` *without* a `decision_history_store` kwarg (`app.py:1027`/`:35`), so that attribute is `None` in prod; the real store is `app.state.runtime.decision_history_store` (set by the T8 lifespan at `app.py:548`; `Runtime.decision_history_store` at `harness/runtime.py:44`). Resolve **runtime-first with injected-fallback**: `store = app.state.runtime.decision_history_store if getattr(app.state, "runtime", None) is not None else getattr(app.state, "decision_history_store", None)`; fail-closed `503 {"reason": "decision_history_unavailable"}` when `None`. **[P1 fix]** Both this dep and `_require_llm_gateway` resolve **BEFORE the gateway call** — a judge call must never dispatch unless its `eval.judge_verdict` evidence can also be recorded (no ungoverned / unrecorded judge runs). This closes the gap where prod would dispatch the gateway and then fail to append.
- **Mount:** `build_eval_routes(*, ...)` factory + `create_app` mounts it under `/api/v1/eval` **unconditionally** (the gateway is a core primitive always built by `build_runtime`; no `cache_driver`-style gate needed — the `503` covers the unwired window). `from __future__ import annotations` **omitted** (the FastAPI closure-local-`Depends` invariant — same as the other route modules).

## Governance traversal + honest Langfuse deferral

The judge call traverses the gateway's **real** governance: INPUT guardrails → cloud-policy enforcement (`enforce_cloud_policy`) → provider-honesty ledger (**strict where LiteLLM dispatched; best-effort only on pre-dispatch refusals**) → `gateway.cloud_policy_denied` audit on denial. Exercising that end-to-end is what converts the gateway from "wired" to "proven."

**Langfuse / observability trace is explicitly deferred.** The gateway emits audit events (policy/drift) + the ledger, but does **not** emit Langfuse spans today. This slice makes no trace claim; `langfuse_trace_id` stays `None`. Closing that gap is a **separate gateway-observability workstream** scoped to `LLMGateway` + `ObservabilityAdapter` (a CC change reviewed with `core-controls-engineer` + `/critical-module-mode`, benefiting every gateway caller) — the recommended next workstream after this one.

## OS/pack boundary + architecture fence

The judge primitive is generic and persona-agnostic; per-agent scorers are packs. `tests/unit/architecture/test_eval_fences.py` (AST-scan over `src/cognic_agentos/evaluation/*.py`, absolute-`parents[3]` path + a non-vacuous source-set guard, mirroring `test_harness_fences.py`) pins:
- no import of `cognic_agentos.agents.*` (Layer-C);
- no import of `cognic_agentos.sdk.agent` persona surface;
- the primitive imports the gateway/decision-history contracts only, no agent/persona modules.

## CC-gate (deliberate promotion)

Per [[feedback_verify_on_gate_status_not_plan_claim]], gate status is decided against `tools/check_critical_coverage.py::_CRITICAL_FILES`, not assumed:
- **`evaluation/judge.py` → promoted** as the **113th** `_CRITICAL_FILES` entry (`0.95` line / `0.90` branch). It is the governed-call primitive; it gets negative-path tests (unparseable, criteria-mismatch, each `parse_reason`) and the coverage floor. Promotion is verified against a **fresh `--cov-branch coverage.json` in the same commit** (per [[feedback_verify_promotion_meets_floor_at_promotion_time]]), with the count guard bumped 112 → 113 in lockstep.
- `portal/api/evaluation/routes.py` + `dto.py` stay **off-gate** (R32 precedent: route modules without a Human-only-decisions boundary stay off; the route's enforcement risk is covered by its own tests + the on-gate primitive).
- `llm/gateway.py` is on-gate but **not modified** by this slice — so no gateway-coverage delta.

## Testing

- **Primitive** (`evaluation/judge.py`): happy-path verdict parse; each failure mode (`not_json` / `schema_mismatch` / `criteria_mismatch`) → `JudgeUnparseable`; gateway-exception propagation (does NOT catch). Tests inject a **fake `LLMGateway`** returning a canned `GatewayResponse` (production path is the real gateway — fakes only in tests, per the production-grade rule). The primitive takes the gateway as a parameter → trivially injectable.
- **Route**: `200` verdict; **`503 llm_gateway_unavailable`** (unwired gateway) AND **`503 decision_history_unavailable`** (store unresolved) — both fail-closed **before** any gateway call (pin: a `503` path makes ZERO gateway calls, via a spy gateway); `403` no scope; `422` request-shape violations (empty output, **over-length output / input / name / description**, 0 criteria, dup names, empty description); `502 judge_verdict_unparseable` + the `errored` chain append; gateway-exception (Mode B) → HTTP mapping with **no** eval event (pinned). Chain payload value-free assertion (raw content absent; digests present). Prod-DI regression: an app built like `create_prod_app` (no `decision_history_store` kwarg) resolves the store from `app.state.runtime` — pins the [P1] fix.
- **Fence**: the architecture pins above.
- **Gate**: `check_critical_coverage.py` green at 113/113 against fresh coverage in the promoting commit.

## Honest-scope markers (carry into the closeout)

- The judge is the **first real gateway consumer** — cloud-policy + ledger + audit traversed for real.
- **Langfuse trace deferred** (gateway gap → its own workstream); no trace claimed.
- **No corpora / runners / replay / scorers / agent workflows** — the rest of ADR-010 stays deferred.
- The primitive is an **OS evaluation surface**, not an agent.

## Follow-on (named, out of this scope)

**Gateway-observability workstream** — wire `ObservabilityAdapter` (Langfuse) through `LLMGateway.completion` for all callers (CC change to `llm/gateway.py`). After it lands, the judge's `langfuse_trace_id` becomes real with no eval-layer change.

## Self-review

- **Placeholders:** none — every contract cites a recon'd symbol (`completion`/`GatewayResponse`/`DecisionRecord`/`append`/the RBAC pattern).
- **Consistency:** the `succeeded`/`errored` statuses, the two failure modes, and the value-free payload are referenced identically across the contract, taxonomy, and evidence sections.
- **Scope:** single judge call path; no runner/corpus/scorer; one new Setting, one new scope family, one promoted module. Within one plan.
- **Ambiguity resolved:** "audit unparseable" is precisely Mode A only (gateway produced content); Mode B (gateway failed) writes no eval event. Tier is operator-only. `criteria_results` must match requested names exactly.
- **Open items for the plan (not the spec):** the exact gateway-exception→HTTP table; the default `eval_judge_tier` alias value. (Revised 2026-06-06 per spec review: ISO control **locked to `A.7.4`**; named candidate/criteria **bound constants** added; the **decision-history DI** corrected to runtime-first fail-closed; ledger wording fixed to "strict where LiteLLM dispatched".)
