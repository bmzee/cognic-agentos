# Gateway Observability — Closeout (2026-06-06)

**Branch:** `feat/gateway-observability` · **Gateway-observability workstream** — wire the generic `ObservabilityAdapter` through `LLMGateway.completion` so every caller emits a value-free OTel span, + the live eval-judge proof.

**Goal met:** the eval-judge closeout's last honest gap — "the gateway emits audit + the provider-honesty ledger, but **no Langfuse / observability trace**" — is closed at the seam. `LLMGateway.completion` now emits one best-effort, value-free `llm.gateway.completion` span per call **on every exit path** via the existing generic `ObservabilityAdapter.emit_trace`, so **every** gateway caller (the eval judge today; agents later) gets a trace with no per-caller change. An env-gated live eval-judge proof exercises the seam against a real LLM.

Source spec: `docs/superpowers/specs/2026-06-06-gateway-observability-design.md` (`cd2eae2`).
Plan-of-record: `docs/superpowers/plans/2026-06-06-gateway-observability.md` (`ac660d7`).

## The commits (spec + plan + T1–T4 + this closeout)

| Task | Commit | What |
|---|---|---|
| spec | `cd2eae2` | design spec — value-free OTel span via `ObservabilityAdapter` (Option A) |
| plan | `ac660d7` | implementation plan-of-record (5 tasks) |
| T1 | `fe3cd13` | `GatewayTraceOutcome` enum + `_CompletionTrace` + `observability` seam + emit helper |
| T2 | `f863372` | emit the span on every `completion()` exit via `finally` + dedicated trace-state |
| T3 | `63681b1` | thread `adapters.observability` into the gateway in `build_runtime` |
| T4 | `c7bfd27` | env-gated live eval-judge proof (recording adapter + real LLM) |
| T5 | (this doc) | CC-gate verification + closeout |

## Scope (frozen — held)

**In:** the `observability: ObservabilityAdapter | None` constructor seam (`gateway.py:311`); the dedicated `_CompletionTrace` state (`gateway.py:209`) + the pinned `GatewayTraceOutcome` closed enum (`gateway.py:72`); the best-effort, value-free `_emit_completion_trace_best_effort` helper (`gateway.py:956`); the `finally`-style emit + the `strict_ledger_failure` override in the `completion()` wrapper (`gateway.py:337-338`); the `agent_workforce_id` completion param; the `build_runtime` thread (`runtime.py:183`); the env-gated live proof.

**Out (held / forbidden):** Langfuse-specific generation API + prompt/response **content** capture (Option B — would couple the stop-rule `gateway.py` to one backend + capture PII; deferred behind its own content-capture-policy gate); any new caller-facing behavior (a trace failure never changes a response); new OTel/exporter infrastructure (the bundled adapters already export); real **Langfuse ingestion** verification (a deferred operational check — see honest-scope markers).

## Key decisions

- **Dedicated trace-state, NOT the ambient ledger `outcome`.** `completion()` initializes a `_CompletionTrace` **before tier resolution** (sentinel `errored_pre_resolution`) and sets a pinned `GatewayTraceOutcome` at each exit. The span reads that state, never the ledger `outcome` var — the two vocabularies are distinct (the span says `policy_denied` where the ledger says `denied`, and carries `invalid_tier` / `preflight_failure` / `strict_ledger_failure`, which have no ledger equivalent). `drift` is preserved as a distinct success exit (the ADR-007 provider-honesty signal that the actual model differed from preflight).
- **`finally`-style emit + a wrapper-level `LedgerWriteFailed` override.** The thin `completion()` wrapper delegates the 370-line body to `_run_completion` (`gateway.py:343`), then `except LedgerWriteFailed: trace.outcome = "strict_ledger_failure"` (`gateway.py:337-338`) and `finally: await self._emit_completion_trace_best_effort(...)`. The override is at the wrapper (not inline) because the success path sets `trace.outcome="ok"/"drift"` BEFORE the strict ledger write — a failure there means the call ultimately failed on the provenance write, and the span must say so.
- **Type-specific pre-resolution catches.** `except UnknownTierError` (tier) and `except (UnknownAliasError, ValueError)` (preflight), each around the single offending statement — an unexpected resolver bug falls through to the `errored_pre_resolution` sentinel (an honest "unknown") rather than mislabeling.
- **Value-free by construction.** The attribute set is metadata + token counts only (OTel-GenAI keys where they fit — `gen_ai.request.model` / `gen_ai.response.model` / `gen_ai.usage.*` — plus `llm.gateway.*` for gateway-specifics; `agent_workforce_id` keyed `llm.gateway.agent_workforce_id`). No prompt/response content — a reviewer confirms value-freeness by reading the keys.
- **Fail-open (best-effort).** The emit is awaited and wrapped so any failure is caught + logged (`llm.gateway.trace_emit_failed`) and **never fails** the LLM call — mirrors `_best_effort_ledger_write`. `observability=None` (the direct-unit-test seam) emits nothing.

## Honest-scope markers (carry forward)

- **Option A — metadata-only.** The span carries OTel-style metadata, not a Langfuse "generation" record; no prompt/response content. First-class Langfuse generation records (with a content-capture policy) are a deferred follow-on, not a regression.
- **The gateway→adapter emit is live-provable against a real LLM** (the env-gated `tests/integration/llm/test_gateway_observability_live.py`) — retiring the eval-judge's "no live real-LLM judge call" marker. **Real Langfuse ingestion** (the span actually landing in a Langfuse instance) is a separate operational check, **deferred** — the hermetic recording adapter proves the seam, not the backend. The live test **skips** by default and **fails loud** (not skip) when opted-in but misconfigured.
- **Best-effort:** a trace failure never *fails* an LLM call or a governance record (it does add bounded in-process overhead — the bundled adapters create spans in-process, not a hot-path network round-trip; this is **not** a zero-delay claim).

## CC discipline + verification

- **`llm/gateway.py` is the only gated module edited** — a stop-rule module on the per-file coverage gate (`0.95` line / `0.90` branch, `check_critical_coverage.py:743`). It holds **99.38% line / 100% branch** on fresh full-package coverage (verified at the T2 commit where the refactor landed, and unchanged since — T3 touched only `runtime.py`, T4 added a skipped test).
- **`harness/runtime.py` is off-gate** (composition root — Doctrine F; absent from `_CRITICAL_FILES`). Its one-line thread is covered by the focused harness white-box test + the full suite, not a per-file floor.
- **No `_CRITICAL_FILES` count change** — the gate stays at **113** (no new gated module). Pinned by `tests/unit/tools/test_check_critical_coverage.py` (`_EXPECTED_ENTRY_COUNT = 113`).
- **Tests:** 17 span tests pin all 11 `trace_outcome`s + the `strict_ledger_failure` override + fail-open-through-`completion()` + `agent_workforce_id` present/absent + value-free (`tests/unit/llm/test_gateway_observability.py`); a harness white-box pin (`tests/unit/harness/test_runtime.py`); the env-gated live proof. Full suite green; per-file CC gate passed across all 113 files.

## Honest markers for the NEXT workstream

The span lands in the in-process adapter, proven via the recording double + (env-gated) a real LLM. The remaining honest gap is **real Langfuse ingestion** — confirming the span reaches a live Langfuse instance — which is an **operational** check (deploy a Langfuse endpoint, run the env-gated proof against it, inspect the trace), not a code gap. Option B (first-class Langfuse generation records with a content-capture policy) is the deferred richer-capture follow-on, gated on a content-capture decision.
