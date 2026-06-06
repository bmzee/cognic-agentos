# Gateway Observability — Design Spec (2026-06-06)

**Wire `ObservabilityAdapter`/Langfuse through `LLMGateway.completion` for every caller (Option A — metadata-only OTel span), + the live eval-judge proof.**

## Goal

Close the one honest gap the eval-judge closeout still calls out: the gateway emits audit (policy/drift) + the provider-honesty ledger, but **no Langfuse / observability trace**. This workstream emits one best-effort, value-free `llm.gateway.completion` OTel span per call via the existing generic `ObservabilityAdapter.emit_trace`, so **every** gateway caller (the eval judge today; agents later) gets a trace with no per-caller change. It then adds an **env-gated live eval-judge integration proof** (a real-LLM judge call through the real gateway) that retires the eval-judge's **"no live real-LLM judge call"** gap — while keeping **real Langfuse ingestion** an explicitly deferred operational check (the proof uses a hermetic recording adapter; it proves the seam, not the backend).

## Context

- Eval Judge Slice (PR #51) made `app.state.llm_gateway` consumed; its closeout deferred Langfuse to "a separate gateway-observability workstream (a CC change to `llm/gateway.py`)". This is that workstream.
- Read-only scout (2026-06-06): `LLMGateway.completion(...)` already owns tier resolution, preflight/actual upstream, cloud-policy + guardrail outcomes, latency, ledger outcome, and request/tenant IDs (`llm/gateway.py` — `outcome` at `:273`, per-path `_best_effort_ledger_write`, `return GatewayResponse` at `:586`). `ObservabilityAdapter.emit_trace(name, attributes)` (`db/adapters/protocols.py:331`) is the **generic** OTel seam implemented by both `LangfuseOtelAdapter` and `DynatraceAdapter` (ADR-009). `build_runtime` constructs the gateway at `harness/runtime.py:174` and already has `adapters`. Existing observability semantics are non-raising / best-effort.

## Scope (frozen — Option A)

**In:**
- `LLMGateway` gains an optional `observability: ObservabilityAdapter | None = None` constructor seam (`gateway.py:39`).
- `LLMGateway.completion(...)` gains an optional `agent_workforce_id: str | None = None` parameter.
- One best-effort, value-free `llm.gateway.completion` span emitted per call, on **every** exit path.
- `build_runtime` threads `adapters.observability` into the gateway (`harness/runtime.py:174`).
- An env-gated **live eval-judge integration proof**.

**Out (deferred / forbidden):**
- **Langfuse-specific generation API / content capture (Option B)** — would couple the stop-rule `gateway.py` to one backend (Dynatrace has no "generation" concept) and would require capturing prompt/response content (the PII the value-free posture keeps out of evidence). Deferred to "if/when first-class generation records are needed," with content-capture policy as its own gate.
- Prompt/response **content** in the span (metadata only — value-free by default).
- Any new caller-facing behavior (the trace is invisible to callers; a trace failure never changes a response).
- New OTel/exporter infrastructure (the adapters already export).

## Design

### The seam (contained, CC)

- `LLMGateway.__init__` gains `observability: ObservabilityAdapter | None = None` (after the existing optional tail params at `gateway.py:48-51`); `self._observability = observability`.
- `build_runtime` passes `observability=adapters.observability` at `harness/runtime.py:174`. (The adapter pool always carries an observability adapter — Langfuse or Dynatrace — per ADR-009; the seam is `None` only on the no-adapter / unit-test path, where no span emits.)
- `completion(*, tier, messages, request_id, tenant_id=None, agent_workforce_id: str | None = None)` — the new param is keyword-only and defaulted; the eval judge passes none, a future agent caller passes its `agent_workforce_id`.

### The span — one per call, every path, best-effort

A single `llm.gateway.completion` span is emitted for **every** completion exit — success AND each failure mode.

**[P1] A dedicated trace-state, NOT the ambient `outcome` var.** The gateway's `outcome` (`:273`) is initialized to `"ok"` *after* tier resolution and is mutated per-path; reusing it would mis-attribute the early paths (an invalid tier / preflight failure *before* `:273` would emit a stale `"ok"` / uninitialized value) and would not distinguish a **strict-ledger failure** or a post-dispatch exception that changes the real call result. So `completion(...)` initializes a **dedicated trace state** (`trace_outcome` + `actual_resolved` + `usage`) **before tier resolution**, defaulted to a sentinel (`errored_pre_resolution`), and sets it at each exit with a **pinned closed-enum `trace_outcome`**: `invalid_tier` / `preflight_failure` · `policy_denied` · `guardrail_input` / `guardrail_output` · `concurrency_exhausted` · `upstream_error` · `strict_ledger_failure` · `ok` / `drift` (the two success exits — `drift` preserves the ADR-007 provider-honesty signal that the *actual* dispatched model differed from preflight; collapsing it to `ok` would lose that signal). The span reads the trace state, never the ambient `outcome` — so every exit (including those before `outcome` is meaningful) emits a well-defined span. The `trace_outcome` enum is its OWN contract (drift-pinned by a test), distinct from the ledger's `outcome`.

**Mechanism (locked):** a `finally`-style emit — wrap the completion body so `_emit_completion_trace_best_effort(trace_state)` runs on every exit before the response returns or the exception propagates. The trace state (initialized before tier resolution) guarantees the `finally` always has a well-defined outcome. The plan maps each existing exit to its pinned `trace_outcome` and confirms the exact `try`/`finally` placement against the live completion structure.

**Fail-open (best-effort) — non-negotiable.** The emit is **awaited** and wrapped so any failure (adapter raise, serialization error) is caught + logged (`llm.gateway.trace_emit_failed`) and **never fails** the LLM call. It is awaited, so it adds **bounded in-process overhead** — the bundled adapters create OTel spans in-process (not a network round-trip on the hot path); this is **not** a zero-delay claim. Observability is not a governance gate — the hash-chained `audit_event` + the ledger remain the records of truth. This mirrors `_best_effort_ledger_write`. (The adapters are already non-raising; the gateway wraps defensively anyway.)

### Span attributes — value-free, OTel-GenAI-aligned

Metadata only; **no prompt/response content**. Use OTel GenAI semantic-convention keys where they fit (so Langfuse + Dynatrace render natively) + `llm.gateway.*` for gateway-specifics:

| Attribute | Source | Notes |
|---|---|---|
| `llm.gateway.request_id` | `request_id` | ties the span to the ledger + the `eval.judge_verdict` chain row |
| `llm.gateway.tenant_id` | `tenant_id` | nullable |
| `llm.gateway.tier` | `tier` | logical tier |
| `llm.gateway.litellm_alias` | resolved alias | |
| `gen_ai.request.model` | preflight `ResolvedUpstream` | the model the call targeted |
| `gen_ai.response.model` | actual `ResolvedUpstream` | the model LiteLLM dispatched (absent on pre-dispatch failures) |
| `llm.gateway.external` | preflight `.external` | self-hosted vs external (ADR-007 provider honesty) |
| `llm.gateway.provenance` | actual upstream provenance | |
| `llm.gateway.outcome` | `trace_outcome` | the **dedicated** closed-enum exit reason (NOT the ambient `outcome`); includes `drift` |
| `llm.gateway.latency_ms` | `flow_start` → emit time | always present |
| `gen_ai.usage.input_tokens` / `gen_ai.usage.output_tokens` | LiteLLM response `usage` | present on success only; value-free |
| `llm.gateway.agent_workforce_id` | the new param | **only when present** — CLAUDE.md: trace with `agent_workforce_id` *when an agent is involved*; the judge omits it (OTel has no standard workforce key, so the `llm.gateway.*` namespace) |

The attribute key set is **value-free by construction** — a reviewer can confirm no message/content field is included. (A future content-capture policy is the Option-B follow-on, gated.)

### The live eval-judge proof

An env-gated integration test (`tests/integration/...`) makes a **real** judge call through the **real** gateway against a reachable model, asserting BOTH (a) an `llm.gateway.completion` span was emitted **through the adapter seam** — via a **hermetic recording `ObservabilityAdapter`** wired into a real `build_runtime`, NOT a live Langfuse endpoint — AND (b) the `eval.judge_verdict` chain row was recorded. Env-gated on `COGNIC_RUN_GATEWAY_OBSERVABILITY_INTEGRATION=1` (+ a reachable LLM endpoint + an `eval_judge_tier`); **fails loud** (NOT `skip`) when opted-in but misconfigured, per the integration-test discipline. Default CI does not hit a real upstream.

**[P1] What this proves — precisely.** Real-LLM call + the gateway emitting the span through the adapter seam + the chain row, end-to-end. This **retires the eval-judge's "no live real-LLM judge call" marker** (the eval-judge tests used a fake gateway; this uses the real one). It does **NOT** prove real **Langfuse ingestion** (the span landing in a Langfuse instance) — the recording adapter is in-process. Real Langfuse-ingestion verification stays a **separate, deferred operational check** (an ops task, not a code gap).

## CC discipline

`llm/gateway.py` is a **stop-rule** module (cloud-policy enforcer) on the per-file coverage gate (`0.95` line / `0.90` branch, `check_critical_coverage.py:743`) — **the only gated module this workstream edits**. So: `core-controls-engineer` + `/critical-module-mode` from the first line; the emit call + the attribute-building helper must stay within the floor (negative-path tests for the fail-open path + each `trace_outcome`'s span); the gateway's existing coverage (≈99% line / 100% branch) must not regress. `harness/runtime.py` is **off-gate** (security-adjacent composition-root wiring — Doctrine F; **verified absent from `_CRITICAL_FILES`**), so its one-line `observability=` thread is covered by focused harness tests + the full suite, not a per-file floor. **No `_CRITICAL_FILES` count change** (no new module).

## Testing

- **Unit (gateway):** a recording fake `ObservabilityAdapter` injected into `LLMGateway`; assert exactly one `llm.gateway.completion` span per call with the value-free attribute set, on the success path AND each failure path (the span's `outcome` matches); a fail-open test (the fake's `emit_trace` raises → the LLM call still returns / still raises the original error, and `llm.gateway.trace_emit_failed` is logged); `observability=None` → no emit; `agent_workforce_id` present → attribute set, absent → attribute omitted; a value-free assertion (no message content in any span).
- **Unit (harness):** `build_runtime` threads `adapters.observability` into the gateway (assert the gateway holds it).
- **Integration (env-gated):** the live eval-judge proof above.
- **Gate:** `check_critical_coverage.py` green; **`gateway.py` holds its CC floor** (0.95/0.90) on fresh `--cov-branch` coverage; `harness/runtime.py` is **off-gate** (covered by focused harness tests + the full suite, no per-file floor).

## Honest-scope markers (carry into the closeout)

- **Option A — metadata-only.** The span carries OTel-style metadata, not a Langfuse "generation" record; no prompt/response content. First-class Langfuse generation records (with a content-capture policy) are a deferred follow-on, not a regression.
- **The gateway→adapter emit is live-proven against a real LLM** (the env-gated integration test) — retiring the eval-judge's "no live real-LLM judge call" marker. **Real Langfuse ingestion** (the span actually landing in Langfuse) is a separate operational check, **deferred** — the hermetic recording adapter proves the seam, not the backend.
- Best-effort: a trace failure never *fails* an LLM call or a governance record (it does add bounded in-process overhead — not zero-delay).

## Locked decisions (spec-review round, 2026-06-06)

1. **Attribute keys:** the **OTel-GenAI + `llm.gateway.*` hybrid** above (tool-native where conventions exist; custom for gateway-specifics).
2. **`agent_workforce_id` key:** **`llm.gateway.agent_workforce_id`** (OTel has no standard workforce key; the `llm.gateway.*` namespace keeps it unambiguous).
3. **Emit mechanism:** **`finally`-style** with a **dedicated trace-state object** (the [P1] contract above) — every-path-guaranteed.
4. **Live proof:** **hermetic recording `ObservabilityAdapter` + a real LLM** — proves the real-LLM call + the gateway→adapter seam emit + the chain row; **real Langfuse ingestion is deferred** (a separate operational check, not a code gap).

## Self-review

- **Placeholders:** none — every seam cites a recon'd symbol (`emit_trace`/`__init__`/`runtime.py:174`/`outcome`/the gate entry).
- **Consistency:** value-free + best-effort + every-path are stated identically across the design, attributes, and testing sections.
- **Scope:** one gateway seam + one completion param + one span + the harness thread + the live proof. No adapter-protocol change (Option A's whole point). Within one plan.
- **Ambiguity resolved + decisions LOCKED (review round):** the 4 design decisions are locked (above), not open. "Trace" = a metadata OTel span via the existing `emit_trace`, NOT a Langfuse generation record (Option B, deferred). The span reads a **dedicated trace-state** (pinned `trace_outcome` enum), NOT the ambient `outcome`. Fail-open = awaited best-effort (never *fails* the call; adds bounded in-process overhead, not zero-delay). The live proof proves the gateway→adapter seam against a real LLM, NOT real Langfuse ingestion (deferred). `harness/runtime.py` is off-gate (verified); `llm/gateway.py` is the only gated module edited.
