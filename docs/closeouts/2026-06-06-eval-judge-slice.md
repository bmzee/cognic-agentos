# Eval Judge Slice — Closeout (2026-06-06)

**Branch:** `feat/eval-judge-slice` · **Gateway-consumption workstream** — the first in-repo consumer of the harness-built `app.state.llm_gateway` (ADR-010 LLM-as-judge).

**Goal met:** the runtime `LLMGateway` now has a real in-repo consumer path. `POST /api/v1/eval/judge` runs a single governed judge call through `LLMGateway.completion` (cloud-policy + provider-honesty ledger + audit) via a generic, persona-agnostic OS primitive (`evaluation/judge.py`), and records a value-free `eval.judge_verdict` hash-chained evidence event. This closes the harness closeout's gateway "primitive-wired, **consumption-deferred**" marker at the wiring level — there is now an OS surface that reads `app.state.llm_gateway` and dispatches through the full governed flow.

Source spec: `docs/superpowers/specs/2026-06-06-eval-judge-slice-design.md` (`33c5a00`).
Plan-of-record: `docs/superpowers/plans/2026-06-06-eval-judge-slice.md` (`ee58f06`).

## The 7 commits (spec + plan + T1–T5 + this closeout)

| Task | Commit | What |
|---|---|---|
| spec | `33c5a00` | design spec — ADR-010 LLM-as-judge, first governed gateway consumer |
| plan | `ee58f06` | implementation plan-of-record |
| T1 | `11ca623` | `eval.judge.run` RBAC scope family + `eval_judge_tier` Setting |
| T2 | `cf4241d` | judge request/response DTOs + bound constants |
| T3 | `4f9828c` | governed LLM-as-judge primitive (parse fail-closed, gateway-exception propagate) |
| T4 | `0e8c3aa` | `POST /api/v1/eval/judge` — fail-closed DI + value-free `eval.judge_verdict` |
| T5 | `8a41c34` | mount `/api/v1/eval` + OS/pack architecture fence |
| T6 | (this doc) | CC-gate promotion (112→113) + Z-gate + closeout |

## Scope (frozen — held)

**In:** the `evaluation/judge.py` primitive (CC gate), the `portal/api/evaluation` DTOs + route, the `eval.judge.run` scope, the `eval_judge_tier` Setting, the value-free `eval.judge_verdict` chain row, the OS/pack architecture fence. **Out (held):** corpora / runners / replay / scorer registry (the rest of ADR-010); **Langfuse / observability trace** (the gateway emits none today — a separate workstream); per-persona scorers (packs); caller-chosen tier; criterion weights.

## Key decisions

- **The primitive is generic + persona-agnostic.** `evaluation/judge.py` builds the judge prompt, dispatches `LLMGateway.completion`, and parses the model verdict **fail-closed** — `_parse_verdict` never raises and never fabricates a verdict; malformed content returns `JudgeUnparseable(parse_reason)`. It performs NO HTTP, NO persistence; gateway exceptions **propagate** (the route owns Mode B). It imports no agent/persona surface (the T5 fence pins it).
- **Hardened parsing (review-driven):** strict `score` (rejects `bool` / `NaN` / `inf` / out-of-`[0,1]`); exact **count + set** criteria bijection (rejects duplicate response names a bare set would accept); `rationale` + each `note` capped (`_MAX_VERDICT_TEXT_CHARS`); request text bounded at the DTO (`50k / 20 / 200 / 2k`).
- **Fail-closed DI before any dispatch (review-driven [P1]):** the route resolves BOTH the gateway (`503 llm_gateway_unavailable`) and the decision-history store (**runtime-first** `app.state.runtime.decision_history_store` with injected-fallback; `503 decision_history_unavailable`) as FastAPI `Depends` — a judge call never dispatches unless its evidence can be recorded. (`create_prod_app` does not inject a `decision_history_store` kwarg, so the runtime-first resolution is load-bearing, not cosmetic.)
- **Two-mode failure taxonomy:** **Mode A** (gateway returned content, verdict unparseable) → append `eval.judge_verdict` `status="errored"` with safe evidence only (digests + `parse_reason`, no verdict) + `502 judge_verdict_unparseable`. **Mode B** (gateway failed before content) → an explicit exception→HTTP table (`LLMConcurrencyExceeded`→429; guardrail/cloud-policy→502; **502 default** so nothing leaks as a raw 500) and **NO eval event** — the gateway already recorded its own audit/ledger evidence; `asyncio.CancelledError` (BaseException) is not swallowed.
- **Value-free chain row:** raw candidate/response content never enters the chain — only sha256 digests; the verdict + criteria_results DO (the judgment is the evidence). Tagged `iso_controls = ("ISO42001.A.7.4",)`. `langfuse_trace_id` is `None` (honest — the gateway emits no trace).
- **Unconditional mount.** `/api/v1/eval` mounts at `create_app` time regardless of adapters; the route's DI fails closed `503` until the lifespan's `build_runtime` populates `app.state.llm_gateway`.

## TM-revert ledger (load-bearing, from T3)

The fail-closed parser branches were each pinned by a negative-path test that returns `JudgeUnparseable` on the corresponding malformed input (`not_json` / `schema_mismatch` / `criteria_mismatch`), with parametrized strict-score cases (`true`/`2.0`/`-0.1`/`NaN`/`Infinity`) and the duplicate-response-name case. `judge.py` reached **100% line / 100% branch** — every branch is a hit, so a regression that loosened any guard would drop coverage AND flip a test.

## Gate evidence (Z-gate, fresh `--cov-branch coverage.json`)

- **Full unit suite:** 9715 passed, 96 skipped (the skips are standing env-gated integration tests).
- **Full-tree:** `ruff check .` ✅ · `ruff format --check .` ✅ (762 files) · `mypy src tests` ✅ (746 files).
- **Per-file critical-controls coverage gate: passed — 113/113.** `evaluation/judge.py` promoted as the **113th** entry (`0.95`/`0.90`); verified at **100% line / 100% branch** on fresh coverage IN the promoting commit (per `feedback_verify_promotion_meets_floor_at_promotion_time`); the count guard `_EXPECTED_ENTRY_COUNT` bumped 112→113 in `tests/unit/tools/test_check_critical_coverage.py` in lockstep (per the plan-review [P1] — the guard lives in the test, not the tool). The route + DTOs stay **off-gate** (R32 precedent); **`llm/gateway.py` (on-gate) was NOT modified** — no gateway-coverage delta.
- **No `# type: ignore` in `src/cognic_agentos/evaluation/`.**

## Honesty markers (scope truth)

- **Gateway consumption gap closed at the wiring level — NOT live-proven.** There is now an in-repo OS path that reads `app.state.llm_gateway` and dispatches through the full governed flow; the wiring + governance + parse are unit-tested with a **fake gateway**. A live judge call against a real LLM (a configured `eval_judge_tier` + a reachable model) is **operationally deferred** — no integration test hits a real upstream in this slice (per `feedback_local_verification_vs_live_operational_proof`).
- **Langfuse / observability trace still deferred.** The gateway emits audit (policy/drift) + the ledger, but no Langfuse spans — `langfuse_trace_id` stays `None`. Closing that gap is the named follow-on **gateway-observability workstream** (a CC change to `llm/gateway.py` wiring `ObservabilityAdapter` through `LLMGateway.completion`, benefiting every caller).
- **Mount-without-runtime nuance:** the route mounts unconditionally, but `build_runtime` (hence the gateway) only runs on the adapter/lifespan path — a bare `create_app()` without an adapter pool mounts the route but every request `503`s. This is correct (fail-closed at request time); the `app.py` mount comment's "always built" is a minor imprecision (the gateway is built **on the adapter path**).
- **Still deferred (the rest of ADR-010):** corpora, datasets, bulk/simulated/replay runners, scorer registry, agent workflows. The judge is an OS evaluation **primitive**, not an agent.

## Follow-on (named, out of this scope)

**Gateway-observability workstream** — wire `ObservabilityAdapter` (Langfuse) through `LLMGateway.completion` for all callers (a CC change to `llm/gateway.py`, `core-controls-engineer` + `/critical-module-mode`). After it lands, the judge's `langfuse_trace_id` becomes real with no eval-layer change. A live end-to-end eval-judge integration test (real tier + reachable model, env-gated) is a natural companion.

## READY FOR GATE

All 6 tasks complete; full suite + full-tree lint/type + critical-coverage gate (113/113, `evaluation/judge.py` at 100%/100%) all green. The branch (spec + plan + T1–T5 + this closeout) is ready to push + open as one eval-judge PR on the human's tokens.
