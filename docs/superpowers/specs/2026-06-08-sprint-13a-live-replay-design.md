# Sprint 13a — Live Replay — Design

**Date:** 2026-06-08
**ADR:** ADR-010 (Evaluation harness) — ships as part of the ADR-010 line (Sprint 13a; the ADR-010 Sprint-12 amendment already records replay as deferred-to-Sprint-13).
**Status:** Design approved (brainstorm); pending implementation plan.
**Phase:** Phase 4. First of three Sprint-13 sub-projects (13a replay → 13b adversarial → 13c promotion gate), each its own spec→plan→implementation cycle.

---

## Goal

Eval-run **replay**: re-run a fixed corpus against the **current** operator-configured target and diff the per-case results against a stored baseline eval-run, producing a value-free `eval.replay` evidence row. The bank-useful question it answers: *"We changed the serving model/config — what regressed on our pinned eval corpus?"*

## Architecture

Replay reuses the entire Sprint-12 evaluation substrate (`EvalRunner`, `EvaluationTarget`/`GatewayTarget`, `AssertionScorer`/`JudgeScorer`, `EvalRunStore`, the strict corpus loader, the `eval_runs`/`eval_case_results` tables, the `eval.bulk_run` chain row). The candidate run is produced + persisted exactly like any bulk run; a separate pure-functional diff over (baseline cases, candidate result) yields a `ReplayDiff`; a value-free `eval.replay` chain row links baseline → candidate. **No new table, no new Settings.**

## Tech stack

Python 3.12 · FastAPI · Pydantic v2 (strict) · SQLAlchemy Core (reuse) · Typer · `uv`.

---

## §1 Scope (locked)

- **Eval-run replay** (not single-case, not production-decision replay — those are deferred; see §8).
- **Baseline** = a stored eval-run (`eval_runs`/`eval_case_results`), which ran at some past config (its `tier`/`model` are recorded relationally).
- **Caller re-supplies the corpus** in the request body; replay verifies `corpus_digest(corpus) == baseline.corpus_digest` **before running** (§3 step 4). Mismatch ⇒ refuse.
- **Candidate** = the same fixed corpus re-run against the **current** `GatewayTarget` (current `eval_bulk_target_tier` + current gateway routing/model). **No caller-selectable tier/model knob** — preserves Sprint-12's "caller cannot choose the tier" (cost/abuse).
- **Drift** = per-case eval-result drift between baseline and candidate.
- The candidate is **persisted as a first-class eval-run** (its own `run_id` + `eval.bulk_run` chain row) so it is queryable via `GET /eval/runs/{id}` and can become the next baseline (the upgrade → replay → re-baseline loop).

## §2 Modules

| File | Change | Gate |
|---|---|---|
| `src/cognic_agentos/evaluation/replay.py` | NEW — `drift_kind` enum + `CaseDiff`/`ReplayDiff` dataclasses + `compute_replay_diff(...)` (pure) + `run_replay(...)` orchestrator | **[CC]** |
| `src/cognic_agentos/evaluation/corpus.py` | EXTEND — extract `corpus_digest(corpus) -> str` (the single digest fn; see §7 / P1) | **[CC, already on-gate]** |
| `src/cognic_agentos/evaluation/runner.py` | EXTEND — `EvalRunner.run` calls the shared `corpus_digest(corpus)` instead of the inline `_digest(corpus.model_dump_json())` | **[CC, already on-gate]** |
| `src/cognic_agentos/evaluation/storage.py` | EXTEND — `append_replay_event(...)` (value-free `eval.replay` chain row); `get_run` reused for baseline load | **[CC, already on-gate]** |
| `src/cognic_agentos/portal/api/evaluation/dto.py` | EXTEND — `ReplayRequest` + `ReplayDiffResponse` + `CaseDiffResponse` | off-gate |
| `src/cognic_agentos/portal/api/evaluation/replay_routes.py` | NEW — `build_eval_replay_routes(...)`; `POST /api/v1/eval/replay` | off-gate (R32) |
| `src/cognic_agentos/portal/api/app.py` | EXTEND — mount the replay router | **[STOP-RULE]** |
| `src/cognic_agentos/portal/rbac/scopes.py` | EXTEND — `EvalRBACScope` 3→4: `+ eval.replay.run` | **[STOP-RULE]** |
| `src/cognic_agentos/compliance/iso42001/controls.py` | EXTEND — add `eval.replay` to A.7.6 + A.9.2 `intended_hooks` (both already `implemented`; additive) | **[STOP-RULE]** |
| `src/cognic_agentos/cli/eval.py` + `cli/__init__.py` | EXTEND — `agentos eval replay` command + `replay_*` helpers | off-gate |
| `tools/check_critical_coverage.py` + test | EXTEND — promote `evaluation/replay.py` (121 → **122**) | **[CC]** |
| `docs/adrs/ADR-010-evaluation-harness.md` | EXTEND — Sprint-13a replay amendment | **[STOP-RULE]** |

No Alembic migration (the `eval.replay` chain row is a new `decision_type` on the generic `decision_history`; the candidate reuses `eval_runs`/`eval_case_results`). No new Settings (reuses `eval_bulk_max_cases`, `eval_bulk_target_tier`, `eval_bulk_max_raw_output_chars`).

## §3 Replay flow (`POST /api/v1/eval/replay`)

1. RBAC `eval.replay.run`; fail-closed DI — resolve `app.state.llm_gateway` + decision-history store **before** any work → `503`.
2. **Empty-corpus check on the RAW body first** (P1 pin — `Corpus.cases` has `min_length=1`, so an empty corpus would fail inside `validate_corpus_payload` as a generic `corpus_*` error): `if isinstance(body.corpus.get("cases"), list) and len(...) == 0 → 400 eval_corpus_empty`. Then `validate_corpus_payload(body.corpus)` → `400` + `CorpusLoadReason` on failure. Then cap: `len(corpus.cases) > eval_bulk_max_cases → 413 eval_corpus_too_large`.
3. Load baseline tenant-scoped: `EvalRunStore.get_run(run_id=baseline_run_id, tenant_id=actor.tenant_id)`. `None` (cross-tenant **or** unknown) → **`404 baseline_run_not_found`** (wire-collapse: both render identically).
4. **Corpus-digest guard:** `corpus_digest(corpus) == baseline["run"].corpus_digest`? else **`409 replay_corpus_digest_mismatch`** — refuse before running.
5. Run candidate: `EvalRunner().run(corpus, target=GatewayTarget(gateway=gw, tier=eval_bulk_target_tier), scorers=[AssertionScorer(), JudgeScorer(gateway=gw, tier=eval_judge_tier)], run_id=<minted uuid>, chain_request_id=<minted>, tenant_id=actor.tenant_id, capture_raw_output=body.persist_raw_output)`.
6. Persist candidate via the **existing** `EvalRunStore.persist_run(result=candidate, actor_subject=actor.subject, tenant_id=actor.tenant_id)` → candidate `eval_runs`/`eval_case_results` + its own `eval.bulk_run` chain row.
7. `compute_replay_diff(baseline_cases=baseline["cases"], candidate=candidate_result)` → `ReplayDiff` (pure; §4).
8. `EvalRunStore.append_replay_event(baseline_run_id, candidate_run_id, corpus_id, corpus_digest, diff_summary, *, actor_subject, tenant_id, request_id=<minted eval-replay->)` → value-free `eval.replay` chain row (§5).
9. Return `ReplayDiffResponse` — includes the live model/tier delta computed from baseline + candidate relational rows.

**Two-append partial-failure semantics (locked, documented):** steps 6 and 8 are **two sequential chain appends** — `append_with_precondition` emits exactly one chain row, and replay needs both `eval.bulk_run` (candidate) and `eval.replay` (diff). If step 8 fails after step 6, the candidate is a **valid standalone eval-run** (no data-integrity loss); the endpoint returns 5xx and the replay simply did not complete. **13a is NOT idempotent** — a retry mints a fresh `run_id` and creates a *second* candidate run. This is accepted for Sprint 13a; an idempotency key / single-transaction two-row primitive is out of scope.

## §4 Diff types (`replay.py`)

```python
DriftKind = Literal["regression", "improvement", "unchanged", "output_changed", "errored"]
```
| `drift_kind` | condition (per `case_id`) |
|---|---|
| `errored` | baseline OR candidate `outcome == "errored"` (checked first — comparison not clean) |
| `regression` | both succeeded; baseline passed → candidate failed |
| `improvement` | both succeeded; baseline failed → candidate passed |
| `output_changed` | both succeeded; same pass/fail **but** `output_digest` differs |
| `unchanged` | both succeeded; same pass/fail **and** same `output_digest` |

```python
@dataclass(frozen=True, slots=True)
class CaseDiff:
    case_id: str
    drift_kind: DriftKind
    baseline_passed: bool
    candidate_passed: bool
    baseline_outcome: str           # "succeeded" | "errored"
    candidate_outcome: str
    output_digest_changed: bool
    baseline_model: str
    candidate_model: str
    baseline_tier: str
    candidate_tier: str

@dataclass(frozen=True, slots=True)
class ReplayDiff:
    baseline_run_id: uuid.UUID
    candidate_run_id: uuid.UUID
    corpus_id: str
    corpus_digest: str
    total: int
    regressions: int
    improvements: int
    unchanged: int
    output_changed: int
    errored: int
    has_regressions: bool           # regressions > 0 — one-glance CI/operator verdict
    cases: tuple[CaseDiff, ...]
```
**Case matching (P1 pin):** cases are matched by `case_id`; a `corpus_digest` match guarantees identical case sets. `cases` is emitted in **candidate/corpus order** (the order `EvalRunResult.cases` carries — i.e. corpus order), **not** DB row order. A case present in baseline but not candidate (or vice versa — defensive only, cannot happen under a matching digest) is classified `errored`.

## §5 Chain row + ISO (locked, minimal)

**`eval.replay`** decision_history payload — **value-free, minimal** (no model, no tier, no raw text):
```
{
  "baseline_run_id": str, "candidate_run_id": str,
  "corpus_id": str, "corpus_digest": str,
  "total": int, "regressions": int, "improvements": int,
  "unchanged": int, "output_changed": int, "errored": int,
  "cases": [{"case_id": str, "drift_kind": str,
             "baseline_passed": bool, "candidate_passed": bool,
             "output_digest_changed": bool}]
}
```
Plus `actor_id` (the replay actor's subject) — **not** a model/tier/raw value but governance identity, merged into the payload by the standard `DecisionRecord` actor_id→payload merge exactly as `eval.bulk_run` carries it, so the evidence row answers *"who triggered this replay"* without a join. The explicit dict above sets the 11 listed keys; the store adds the 12th (`actor_id`).

ISO controls: **A.7.6 + A.9.2** (a replay is an AI-system evaluation + operational-logging event; both controls already `implemented` — `eval.replay` is added to their `intended_hooks` for accuracy). The model/tier delta is **not** in the chain row (consistent with `eval.bulk_run`, which carries `tier` but not `model`; replay's row carries neither per the locked minimal set) — it is computed live for the API response from the two persisted runs.

## §6 Surface

- **Portal:** `POST /api/v1/eval/replay`, scope `eval.replay.run`, body `{corpus: dict, baseline_run_id: uuid, persist_raw_output: StrictBool = false}`. No `target` field. Synchronous. Endpoint statuses: `403` (RBAC) · `503` (DI) · `400` (`eval_corpus_empty` / `CorpusLoadReason`) · `413` (`eval_corpus_too_large`) · `404` (`baseline_run_not_found`) · `409` (`replay_corpus_digest_mismatch`) · `422` (body validation, e.g. non-bool `persist_raw_output` / malformed `baseline_run_id`) · `200` · **`5xx`** (the partial-failure path of §3 — if the `eval.replay` evidence append (step 8) fails *after* the candidate was persisted (step 6), the endpoint returns 5xx; the candidate remains a valid standalone run, no `eval.replay` row is written, replay is non-idempotent on retry). Per-case gateway failures during the candidate run surface as `errored` cases in the `200` body (Sprint-12 patch-2 contract). `replay_routes.py` **omits** `from __future__ import annotations` (closure-local `Depends`); AST self-test pins it. Closed-enum `EvalReplayRefusalReason = Literal["baseline_run_not_found", "replay_corpus_digest_mismatch"]` (+ reuses `eval_corpus_empty`/`eval_corpus_too_large` from bulk).
- **CLI:** `agentos eval replay --corpus <dir> --baseline <run-id> --url <…> --token <…> [--dry-run] [--json]`. Thin portal client (never builds runtime/gateway). `--dry-run` validates the corpus (strict load) **and** the `--baseline` UUID shape only — **no portal/model call**. Errors → stderr (repo convention). Exit codes 0/1/2 (0 ok·dry-run valid; 1 corpus/baseline-shape invalid; 2 missing url/token without dry-run, or portal error).
- **RBAC:** new `eval.replay.run` added to `EvalRBACScope` Literal + `EVAL_SCOPES` (3→4). Not Human-only (CI/service may replay). `actor.py`/`enforcement.py` already union `EvalRBACScope` — no edits there.

## §7 Cross-cutting

- **P1 — corpus_digest compatibility (load-bearing):** extracting `corpus_digest(corpus) -> str` and switching `EvalRunner.run` to it MUST produce a **byte-identical** digest to the Sprint-12 calculation `hashlib.sha256(corpus.model_dump_json().encode("utf-8")).hexdigest()` — otherwise replay rejects **every existing baseline run** with a false `409 replay_corpus_digest_mismatch`. Pin with two regression tests: (1) `corpus_digest(corpus) == hashlib.sha256(corpus.model_dump_json().encode("utf-8")).hexdigest()` for a sample corpus (against the literal Sprint-12 formula); (2) a migrated-DB test that runs a bulk-run, then asserts `corpus_digest(same_corpus) == eval_runs.corpus_digest` of the stored row (the helper equals what is persisted). Implement the helper FIRST, switch the runner, and confirm the full Sprint-12 storage/runner suites stay green before any replay code.
- **CC gate:** promote `evaluation/replay.py` (121 → **122**), 95/90 floor, verified against fresh `--cov-branch` in the promotion commit. `storage.py`/`corpus.py`/`runner.py` already on-gate (their extensions must keep them at floor). `replay_routes.py`/`dto.py` off-gate (R32).
- **Testing:** `compute_replay_diff` unit tests covering **every** `drift_kind` (fake baseline cases + candidate `EvalRunResult`) incl. the candidate-order emission pin; `append_replay_event` migrated-DB store test (value-free chain shape — assert no model/tier/raw text; `chain_request_id`/back-link pattern); route tests — `404 baseline_run_not_found` (unknown) **and** a wrong-tenant baseline collapsing to the **same** `404` (P1 pin), `409 replay_corpus_digest_mismatch`, `400 eval_corpus_empty` (raw-body-empty before validate), `413`, `503`, RBAC `403`, no-future-import AST guard; an **e2e** (real migrated DB): seed a baseline run, replay with a candidate target that flips a case → assert `has_regressions=True` + the candidate queryable via `GET /eval/runs/{id}` + one `eval.replay` chain row emitted value-free; a **partial-failure test** (locked §3 behavior) — simulate `append_replay_event` raising **after** `persist_run` succeeds (e.g. patch/inject a failing append) and assert: the candidate run **remains queryable** via `GET /eval/runs/{id}`, **no `eval.replay` chain row** is emitted, and the endpoint returns **5xx**; CLI dry-run (corpus + baseline-UUID shape, no network) + thin-client.
- **Process:** TDD; halt-before-commit on every CC/stop-rule task (replay.py, corpus.py/runner.py/storage.py extensions, scopes.py, controls.py, app.py mount, the CC-gate promotion, the ADR amendment); explicit-path staging; the two untracked docs never staged; full suite at each CC/stop-rule commit; verify-at-promotion on the CC-gate task.

## §8 Deferred (recorded)

- **Caller-selectable candidate tier/model** (head-to-head tier1-vs-tier2) — re-opens the "caller chooses tier" door Sprint 12 closed; deferred.
- **Per-scorer drift in the diff** — derivable by reading the persisted baseline/candidate `eval_case_results` (queryable); not on the `eval.replay` row in 13a.
- **Production agent-run replay** (citations, compliance score, tool-call sequence diff) — the BUILD_PLAN's richest framing; needs a replayable agent-run/pack target that does not exist in OS-only (no agent-run primitive, value-free chain). Deferred until such a target exists.
- **Replay idempotency** (idempotency key / single-transaction two-chain-row primitive) — 13a is explicitly non-idempotent (§3); deferred.
- **`GET /api/v1/eval/replays/{id}`** — Sprint 13a ships only the `POST`; the candidate is inspectable via the existing `GET /eval/runs/{id}` and the `eval.replay` chain row. A dedicated replay-read endpoint is deferred.

## Open items resolved during brainstorm (traceability)

| Decision | Locked |
|---|---|
| Replay framing | Eval-run replay (A) — reuse Sprint-12; not single-case, not production-decision |
| Candidate vs baseline delta | Candidate = current operator config; no caller tier/model knob (A) |
| Persistence/evidence | Persist candidate as first-class eval-run + separate value-free `eval.replay` row (A) |
| Diff granularity | Case-level (A); 5-value `drift_kind`; per-scorer drift deferred |
| Surface | `POST /eval/replay` + `agentos eval replay` + new `eval.replay.run` scope; 404-collapse baseline; 409 digest-mismatch |
| Chain row | Minimal value-free (no model/tier/raw); A.7.6 + A.9.2 |
| Partial-failure | Two sequential appends; candidate valid standalone on step-8 failure; non-idempotent (documented) |
