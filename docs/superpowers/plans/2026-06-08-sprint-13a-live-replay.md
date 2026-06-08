# Sprint 13a — Live Replay Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eval-run replay — re-run a fixed corpus against the current operator-configured target, persist the candidate as a first-class eval-run, and diff per-case vs a stored baseline, emitting a value-free `eval.replay` evidence row.

**Architecture:** Reuses the entire Sprint-12 substrate (`EvalRunner`, `GatewayTarget`, `AssertionScorer`/`JudgeScorer`, `EvalRunStore.persist_run`/`get_run`, the strict corpus loader, the `eval_runs`/`eval_case_results` tables). A pure `compute_replay_diff` over (baseline cases, candidate result) yields a `ReplayDiff`; `EvalRunStore.append_replay_event` emits the value-free `eval.replay` chain row. No Alembic migration, no new Settings.

**Tech Stack:** Python 3.12 · FastAPI · Pydantic v2 (strict) · SQLAlchemy Core (reuse) · Typer · `uv`.

**Spec:** `docs/superpowers/specs/2026-06-08-sprint-13a-live-replay-design.md`.

---

## Process discipline (every task)

- **`uv run` for all Python**; no parallel/background `uv run` (venv-lock).
- **TDD:** test → watch-it-fail (right reason) → implement → green.
- **Explicit-path staging only** (`git add <exact paths>`). Never stage `docs/reviews/` or `docs/superpowers/specs/2026-05-26-agentos-local-managed-agents-gap-analysis.md`. `coverage.json` is gitignored.
- **Commit footer:** every message ends `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- **Branch:** `feat/sprint-13a-live-replay` (already checked out; spec commit `3597f67` is its first commit, off `eefd0a7`).
- **HALT-BEFORE-COMMIT** on every **[CC]** / **[STOP-RULE]** task; produce a halt summary (files modified, tests+results, exact `git add` paths) and WAIT for a full-word commit token. **[normal]** tasks (T10 CLI) commit after their own gates.
- **Gate ladder:** full suite at every [CC]/[STOP-RULE] commit + `ruff check .` + `ruff format --check .` + `mypy src tests`. The CC-gate task (T9) additionally runs fresh `--cov --cov-branch` + `tools/check_critical_coverage.py` (verify-at-promotion). CC subagents report focused `--cov-branch` of the new/changed module so coverage gaps surface at the per-task checkpoint, not at T9.

## File structure

| File | Responsibility | Gate |
|---|---|---|
| `src/cognic_agentos/evaluation/corpus.py` | EXTEND — `corpus_digest(corpus) -> str` (the single digest fn) | **[CC, on-gate]** |
| `src/cognic_agentos/evaluation/runner.py` | EXTEND — `EvalRunner.run` uses `corpus_digest(corpus)` | **[CC, on-gate]** |
| `src/cognic_agentos/evaluation/replay.py` | NEW — `DriftKind`/`CaseDiff`/`ReplayDiff` + `compute_replay_diff` (pure) + `run_replay` orchestrator | **[CC, new]** |
| `src/cognic_agentos/evaluation/storage.py` | EXTEND — `append_replay_event` + `mint_eval_replay_request_id` | **[CC, on-gate]** |
| `src/cognic_agentos/portal/rbac/scopes.py` | EXTEND — `EvalRBACScope` 3→4 (`+ eval.replay.run`) | **[STOP-RULE]** |
| `src/cognic_agentos/compliance/iso42001/controls.py` | EXTEND — `eval.replay` into A.7.6 + A.9.2 `intended_hooks` | **[STOP-RULE]** |
| `src/cognic_agentos/portal/api/evaluation/dto.py` | EXTEND — `ReplayRequest` + `ReplayDiffResponse` + `CaseDiffResponse` | off-gate |
| `src/cognic_agentos/portal/api/evaluation/replay_routes.py` | NEW — `POST /api/v1/eval/replay` | off-gate (R32) |
| `src/cognic_agentos/portal/api/app.py` | EXTEND — mount the replay router | **[STOP-RULE]** |
| `src/cognic_agentos/cli/eval.py` + `cli/__init__.py` | EXTEND — `agentos eval replay` | off-gate |
| `tools/check_critical_coverage.py` + test | EXTEND — promote `evaluation/replay.py` (121→122) | **[CC]** |
| `docs/adrs/ADR-010-evaluation-harness.md` | EXTEND — Sprint-13a amendment | **[STOP-RULE]** |

---

## Task 1 [CC]: `corpus_digest` extraction + byte-compat (P1)

**This is FIRST and load-bearing:** if the extracted helper produces a different digest than Sprint-12's inline `_digest(corpus.model_dump_json())`, replay rejects every existing baseline with a false `409`. Helper-first → switch runner → prove Sprint-12 suites stay green.

**Files:**
- Modify: `src/cognic_agentos/evaluation/corpus.py` (add `corpus_digest`)
- Modify: `src/cognic_agentos/evaluation/runner.py` (use it)
- Test: `tests/unit/evaluation/test_corpus_digest.py`

- [ ] **Step 1: Write the byte-compat tests**

```python
# tests/unit/evaluation/test_corpus_digest.py
from __future__ import annotations

import asyncio
import hashlib
import uuid
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.evaluation.corpus import corpus_digest, validate_corpus_payload
from cognic_agentos.evaluation.runner import EvalRunner
from cognic_agentos.evaluation.storage import EvalRunStore, _eval_runs
from cognic_agentos.evaluation.types import CandidateOutput

_PAYLOAD = {
    "schema_version": 1,
    "corpus_id": "smoke",
    "cases": [
        {
            "id": "c1",
            "case_kind": "completion",
            "messages": [{"role": "user", "content": "q"}],
            "assertions": {"contains": ["ok"]},
        }
    ],
}


def test_corpus_digest_equals_sprint12_literal_formula() -> None:
    corpus = validate_corpus_payload(_PAYLOAD)
    # The Sprint-12 baseline calculation (runner.py inline) was exactly this:
    expected = hashlib.sha256(corpus.model_dump_json().encode("utf-8")).hexdigest()
    assert corpus_digest(corpus) == expected


class _Target:
    target_kind = "gateway"
    tier = "tier1"

    async def run_case(self, case: Any, *, request_id: str, tenant_id: str) -> CandidateOutput:
        return CandidateOutput(text="ok", model="m", tier="tier1", latency_ms=1, outcome="succeeded")


async def _migrated_engine(tmp_path: Any) -> Any:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'digest.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    return create_async_engine(url)


@pytest.mark.asyncio
async def test_corpus_digest_equals_stored_run_digest(tmp_path: Any) -> None:
    # The helper MUST equal what a real persisted run wrote to eval_runs.corpus_digest,
    # else replay's pre-run digest guard rejects existing baselines. A case declares
    # `assertions`, so the runner's fail-closed coverage requires an AssertionScorer.
    from cognic_agentos.evaluation.scorers import AssertionScorer

    eng = await _migrated_engine(tmp_path)
    try:
        corpus = validate_corpus_payload(_PAYLOAD)
        result = await EvalRunner().run(
            corpus,
            target=_Target(),
            scorers=[AssertionScorer()],
            run_id=uuid.uuid4(),
            chain_request_id="r",
            tenant_id="t1",
        )
        store = EvalRunStore(DecisionHistoryStore(eng))
        await store.persist_run(result=result, actor_subject="svc", tenant_id="t1")
        async with eng.connect() as c:
            stored = (
                await c.execute(
                    sa.select(_eval_runs.c.corpus_digest).where(_eval_runs.c.run_id == result.run_id)
                )
            ).scalar_one()
        assert corpus_digest(corpus) == stored
        assert corpus_digest(corpus) == result.corpus_digest
    finally:
        await eng.dispose()
```

- [ ] **Step 2: Run — expect FAIL** (`ImportError: cannot import name 'corpus_digest'`). Run: `uv run pytest tests/unit/evaluation/test_corpus_digest.py -q`

- [ ] **Step 3: Add `corpus_digest` to `corpus.py`** (append near the top-level functions):

```python
import hashlib  # add to corpus.py imports if not present


def corpus_digest(corpus: Corpus) -> str:
    """Canonical digest of a corpus — sha256 of its Pydantic JSON serialization.

    BYTE-IDENTICAL to the Sprint-12 inline runner formula
    ``sha256(corpus.model_dump_json().encode("utf-8")).hexdigest()`` — the
    replay pre-run guard compares this against the stored baseline's
    ``eval_runs.corpus_digest``, so any drift would falsely reject every
    existing baseline. Pinned by tests/unit/evaluation/test_corpus_digest.py.
    """
    return hashlib.sha256(corpus.model_dump_json().encode("utf-8")).hexdigest()
```

- [ ] **Step 4: Switch `runner.py` to the helper.** In `runner.py`, add `from cognic_agentos.evaluation.corpus import corpus_digest` (runtime import — corpus.py does not import runner, no cycle) and change the `EvalRunResult(...)` construction line from `corpus_digest=_digest(corpus.model_dump_json()),` to `corpus_digest=corpus_digest(corpus),`. Keep `_digest` for the per-case input/output digests.

> **Name-shadow caution:** the runner now has a module-level import `corpus_digest` AND constructs `EvalRunResult(corpus_digest=corpus_digest(corpus))` — the kwarg name equals the function name. That is fine (kwarg names are not in scope as values), but mypy/ruff are happy and it reads clearly. If the implementer prefers, alias `from ... import corpus_digest as compute_corpus_digest` and call `compute_corpus_digest(corpus)`; either is acceptable — match whichever keeps ruff/mypy clean.

- [ ] **Step 5: Run the new tests + the full Sprint-12 runner/storage suites** (prove no regression):

```bash
uv run pytest tests/unit/evaluation/test_corpus_digest.py tests/unit/evaluation/test_runner.py tests/unit/evaluation/test_storage.py tests/unit/evaluation/test_corpus.py -q
```
Expected: all pass (the stored-digest equality proves byte-compat).

- [ ] **Step 6: HALT-BEFORE-COMMIT [CC]** (corpus.py + runner.py both on-gate). Full gate ladder; report focused `--cov-branch` of corpus.py + runner.py (must stay ≥95/≥90); halt summary; wait for token.

```bash
uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy src tests
git add src/cognic_agentos/evaluation/corpus.py src/cognic_agentos/evaluation/runner.py tests/unit/evaluation/test_corpus_digest.py
git commit -m "$(printf 'refactor(eval): extract corpus_digest helper (byte-compat) for replay\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 2 [CC]: replay diff types + `compute_replay_diff` (pure)

**Files:**
- Create: `src/cognic_agentos/evaluation/replay.py`
- Test: `tests/unit/evaluation/test_replay_diff.py`

- [ ] **Step 1: Write the failing tests** (every `drift_kind` + candidate-order)

```python
# tests/unit/evaluation/test_replay_diff.py
from __future__ import annotations

import uuid
from typing import Any

from cognic_agentos.evaluation.replay import compute_replay_diff
from cognic_agentos.evaluation.types import CaseResult, EvalRunResult


def _case(case_id: str, *, passed: bool, outcome: str = "succeeded", output_digest: str = "o", model: str = "m2") -> CaseResult:
    return CaseResult(
        case_id=case_id, passed=passed, outcome=outcome, scorer_results=(),
        latency_ms=1, model=model, input_digest="i", output_digest=output_digest,
        candidate_output_text=None, raw_output_persisted=False, output_truncated=False,
    )


def _candidate(cases: list[CaseResult]) -> EvalRunResult:
    return EvalRunResult(
        run_id=uuid.uuid4(), chain_request_id="r", corpus_id="cp", corpus_digest="d",
        target_kind="gateway", tier="tier2", total=len(cases),
        passed=sum(1 for c in cases if c.outcome == "succeeded" and c.passed),
        failed=sum(1 for c in cases if c.outcome == "succeeded" and not c.passed),
        errored=sum(1 for c in cases if c.outcome == "errored"),
        latency_p50_ms=1, latency_p95_ms=1, cases=tuple(cases),
    )


def _baseline_case(case_id: str, *, passed: bool, outcome: str = "succeeded", output_digest: str = "o", model: str = "m1") -> dict[str, Any]:
    # shape of an eval_case_results row._mapping
    return {"case_id": case_id, "passed": passed, "outcome": outcome, "output_digest": output_digest, "model": model}


def test_every_drift_kind() -> None:
    baseline_id = uuid.uuid4()
    baseline_cases = [
        _baseline_case("reg", passed=True),                        # → regression
        _baseline_case("imp", passed=False),                       # → improvement
        _baseline_case("same", passed=True, output_digest="x"),    # → unchanged
        _baseline_case("drift", passed=True, output_digest="x"),   # → output_changed
        _baseline_case("err", passed=True),                        # → errored (candidate errored)
    ]
    candidate = _candidate([
        _case("reg", passed=False),
        _case("imp", passed=True),
        _case("same", passed=True, output_digest="x"),
        _case("drift", passed=True, output_digest="y"),
        _case("err", passed=False, outcome="errored"),
    ])
    diff = compute_replay_diff(baseline_run_id=baseline_id, candidate=candidate,
                               baseline_cases=baseline_cases, baseline_tier="tier1")
    kinds = {cd.case_id: cd.drift_kind for cd in diff.cases}
    assert kinds == {"reg": "regression", "imp": "improvement", "same": "unchanged",
                     "drift": "output_changed", "err": "errored"}
    assert diff.total == 5 and diff.regressions == 1 and diff.improvements == 1
    assert diff.unchanged == 1 and diff.output_changed == 1 and diff.errored == 1
    assert diff.has_regressions is True
    assert diff.baseline_run_id == baseline_id and diff.candidate_run_id == candidate.run_id
    # config delta surfaced per case
    reg = next(cd for cd in diff.cases if cd.case_id == "reg")
    assert reg.baseline_tier == "tier1" and reg.candidate_tier == "tier2"
    assert reg.baseline_model == "m1" and reg.candidate_model == "m2"


def test_cases_emitted_in_candidate_order_not_baseline_order() -> None:
    baseline_id = uuid.uuid4()
    baseline_cases = [_baseline_case("b", passed=True), _baseline_case("a", passed=True)]  # baseline order: b, a
    candidate = _candidate([_case("a", passed=True, output_digest="o"), _case("b", passed=True, output_digest="o")])  # candidate order: a, b
    diff = compute_replay_diff(baseline_run_id=baseline_id, candidate=candidate,
                               baseline_cases=baseline_cases, baseline_tier="tier1")
    assert [cd.case_id for cd in diff.cases] == ["a", "b"]  # candidate/corpus order


def test_no_regressions_flag_false_when_only_improvements() -> None:
    baseline_id = uuid.uuid4()
    baseline_cases = [_baseline_case("x", passed=False)]
    candidate = _candidate([_case("x", passed=True)])
    diff = compute_replay_diff(baseline_run_id=baseline_id, candidate=candidate,
                               baseline_cases=baseline_cases, baseline_tier="tier1")
    assert diff.has_regressions is False and diff.improvements == 1


def test_baseline_only_case_emitted_as_errored_after_candidate_cases() -> None:
    # Defensive pin (spec §4): a baseline case with no candidate is appended as
    # errored AFTER the candidate-order cases (never silently dropped).
    baseline_id = uuid.uuid4()
    baseline_cases = [_baseline_case("present", passed=True), _baseline_case("gone", passed=True)]
    candidate = _candidate([_case("present", passed=True, output_digest="o")])  # "gone" absent
    diff = compute_replay_diff(baseline_run_id=baseline_id, candidate=candidate,
                               baseline_cases=baseline_cases, baseline_tier="tier1")
    assert [cd.case_id for cd in diff.cases] == ["present", "gone"]  # candidate first, baseline-only last
    gone = diff.cases[-1]
    assert gone.drift_kind == "errored" and gone.candidate_outcome == "errored"
    assert gone.candidate_model == "" and gone.baseline_model == "m1"
    assert diff.errored == 1
```

- [ ] **Step 2: Run — expect FAIL** (`ModuleNotFoundError`). Run: `uv run pytest tests/unit/evaluation/test_replay_diff.py -q`

- [ ] **Step 3: Implement the diff half of `replay.py`**

```python
# src/cognic_agentos/evaluation/replay.py
"""Sprint 13a live replay (ADR-010) — CC.

Eval-run replay: re-run a fixed corpus against the current operator-configured
target and diff per-case vs a stored baseline. ``compute_replay_diff`` is pure;
``run_replay`` (added in the route-integration task) orchestrates run + persist +
diff + the value-free ``eval.replay`` chain row.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from cognic_agentos.evaluation.types import EvalRunResult

DriftKind = Literal["regression", "improvement", "unchanged", "output_changed", "errored"]


@dataclass(frozen=True, slots=True)
class CaseDiff:
    case_id: str
    drift_kind: DriftKind
    baseline_passed: bool
    candidate_passed: bool
    baseline_outcome: str
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
    has_regressions: bool
    cases: tuple[CaseDiff, ...]


def _classify(*, baseline: dict[str, Any] | None, candidate: Any) -> DriftKind:
    if baseline is None:
        return "errored"  # defensive — cannot happen under a matching corpus_digest
    b_outcome = str(baseline["outcome"])
    if b_outcome == "errored" or candidate.outcome == "errored":
        return "errored"
    b_passed = bool(baseline["passed"])
    if b_passed and not candidate.passed:
        return "regression"
    if not b_passed and candidate.passed:
        return "improvement"
    if str(baseline["output_digest"]) != candidate.output_digest:
        return "output_changed"
    return "unchanged"


def compute_replay_diff(
    *,
    baseline_run_id: uuid.UUID,
    candidate: EvalRunResult,
    baseline_cases: list[dict[str, Any]],
    baseline_tier: str,
) -> ReplayDiff:
    """Pure diff. Cases keyed by ``case_id``; emitted in CANDIDATE/corpus order."""
    by_id: dict[str, dict[str, Any]] = {bc["case_id"]: bc for bc in baseline_cases}
    diffs: list[CaseDiff] = []
    for cc in candidate.cases:  # candidate/corpus order, NOT baseline DB row order
        bc = by_id.get(cc.case_id)
        kind = _classify(baseline=bc, candidate=cc)
        diffs.append(
            CaseDiff(
                case_id=cc.case_id,
                drift_kind=kind,
                baseline_passed=bool(bc["passed"]) if bc is not None else False,
                candidate_passed=cc.passed,
                baseline_outcome=str(bc["outcome"]) if bc is not None else "errored",
                candidate_outcome=cc.outcome,
                output_digest_changed=(bc is not None and str(bc["output_digest"]) != cc.output_digest),
                baseline_model=str(bc["model"]) if bc is not None else "",
                candidate_model=cc.model,
                baseline_tier=baseline_tier,
                candidate_tier=candidate.tier,
            )
        )
    # Defensive (spec §4 pin): baseline cases with NO candidate cannot happen under
    # a matching corpus_digest, but are emitted as ``errored`` AFTER the candidate-
    # order cases so they are never silently dropped.
    candidate_ids = {cc.case_id for cc in candidate.cases}
    for bc in baseline_cases:
        if str(bc["case_id"]) in candidate_ids:
            continue
        diffs.append(
            CaseDiff(
                case_id=str(bc["case_id"]),
                drift_kind="errored",
                baseline_passed=bool(bc["passed"]),
                candidate_passed=False,
                baseline_outcome=str(bc["outcome"]),
                candidate_outcome="errored",
                output_digest_changed=False,
                baseline_model=str(bc["model"]),
                candidate_model="",
                baseline_tier=baseline_tier,
                candidate_tier=candidate.tier,
            )
        )
    regressions = sum(1 for d in diffs if d.drift_kind == "regression")
    return ReplayDiff(
        baseline_run_id=baseline_run_id,
        candidate_run_id=candidate.run_id,
        corpus_id=candidate.corpus_id,
        corpus_digest=candidate.corpus_digest,
        total=len(diffs),
        regressions=regressions,
        improvements=sum(1 for d in diffs if d.drift_kind == "improvement"),
        unchanged=sum(1 for d in diffs if d.drift_kind == "unchanged"),
        output_changed=sum(1 for d in diffs if d.drift_kind == "output_changed"),
        errored=sum(1 for d in diffs if d.drift_kind == "errored"),
        has_regressions=regressions > 0,
        cases=tuple(diffs),
    )
```

- [ ] **Step 4: Run — expect PASS.** Run: `uv run pytest tests/unit/evaluation/test_replay_diff.py -q`

- [ ] **Step 4b: Update the eval-dir inventory fence** (REQUIRED — adding `replay.py` to `evaluation/` breaks `tests/unit/architecture/test_eval_fences.py::test_eval_dir_has_expected_sources`, which pins the exact source set). Add `"replay.py"` to the expected set in that test (and extend its comment to note Sprint-13a). This MUST land in the T2 commit or the full suite stays red. Run: `uv run pytest tests/unit/architecture/test_eval_fences.py -q` → expect PASS.

- [ ] **Step 5: HALT-BEFORE-COMMIT [CC].** Full gate ladder; report focused `--cov-branch` of `replay.py` (`uv run pytest tests/unit/evaluation/test_replay_diff.py --cov=cognic_agentos.evaluation.replay --cov-branch --cov-report=term-missing -q` — the diff half should be ~100%; `run_replay` lands in T6 and is covered there); halt summary; token.

```bash
uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy src tests
git add src/cognic_agentos/evaluation/replay.py tests/unit/evaluation/test_replay_diff.py tests/unit/architecture/test_eval_fences.py
git commit -m "$(printf 'feat(eval): replay diff types + compute_replay_diff (ADR-010)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 3 [CC]: `EvalRunStore.append_replay_event` + replay request-id minter

**Files:**
- Modify: `src/cognic_agentos/evaluation/storage.py`
- Test: `tests/unit/evaluation/test_storage_replay.py`

- [ ] **Step 1: Write the failing test** (migrated DB; value-free chain shape)

```python
# tests/unit/evaluation/test_storage_replay.py
from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.evaluation.replay import CaseDiff, ReplayDiff
from cognic_agentos.evaluation.storage import EvalRunStore, mint_eval_replay_request_id


async def _migrated_engine(tmp_path: Any) -> Any:
    from alembic import command
    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'replay.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    return create_async_engine(url)


def _diff(baseline_id: uuid.UUID, candidate_id: uuid.UUID) -> ReplayDiff:
    cd = CaseDiff(
        case_id="c1", drift_kind="regression", baseline_passed=True, candidate_passed=False,
        baseline_outcome="succeeded", candidate_outcome="succeeded", output_digest_changed=True,
        baseline_model="m1", candidate_model="m2", baseline_tier="tier1", candidate_tier="tier2",
    )
    return ReplayDiff(
        baseline_run_id=baseline_id, candidate_run_id=candidate_id, corpus_id="cp", corpus_digest="d",
        total=1, regressions=1, improvements=0, unchanged=0, output_changed=0, errored=0,
        has_regressions=True, cases=(cd,),
    )


def test_mint_eval_replay_request_id_bounded_and_prefixed() -> None:
    rid = mint_eval_replay_request_id()
    assert rid.startswith("eval-replay-") and len(rid) <= 64


@pytest.mark.asyncio
async def test_append_replay_event_writes_value_free_chain_row(tmp_path: Any) -> None:
    eng = await _migrated_engine(tmp_path)
    try:
        store = EvalRunStore(DecisionHistoryStore(eng))
        baseline_id, candidate_id = uuid.uuid4(), uuid.uuid4()
        record_id, _hash = await store.append_replay_event(
            diff=_diff(baseline_id, candidate_id), actor_subject="svc", tenant_id="t1",
            request_id="eval-replay-abc",
        )
        async with eng.connect() as c:
            row = (
                await c.execute(sa.text(
                    "SELECT event_type, request_id, iso_controls, payload FROM decision_history "
                    "WHERE event_type='eval.replay'"
                ))
            ).first()
        assert row.event_type == "eval.replay" and row.request_id == "eval-replay-abc"
        assert "ISO42001.A.7.6" in row.iso_controls and "ISO42001.A.9.2" in row.iso_controls
        payload = json.loads(row.payload) if isinstance(row.payload, str) else dict(row.payload)
        # EXACT top-level key set — the locked minimal shape (spec §5) PLUS the
        # store-merged ``actor_id`` (governance identity, NOT model/tier/raw) so the
        # row answers "who triggered this replay" — consistent with eval.bulk_run.
        # The DecisionRecord(actor_id=actor_subject) field is merged into the payload
        # by the store (decision_history.py actor_id→payload merge), exactly as
        # persist_run's eval.bulk_run row carries it.
        assert set(payload.keys()) == {
            "baseline_run_id", "candidate_run_id", "corpus_id", "corpus_digest",
            "total", "regressions", "improvements", "unchanged", "output_changed", "errored", "cases",
            "actor_id",
        }
        assert payload["actor_id"] == "svc"
        # EXACT per-case key set — no model/tier/raw/output text.
        assert set(payload["cases"][0].keys()) == {
            "case_id", "drift_kind", "baseline_passed", "candidate_passed", "output_digest_changed",
        }
        # belt-and-suspenders: no forbidden token anywhere in the serialized payload.
        flat = json.dumps(payload)
        for forbidden in ("model", "tier", "raw", "candidate_output_text", "output_text"):
            assert forbidden not in flat
        assert payload["baseline_run_id"] == str(baseline_id)
        assert payload["candidate_run_id"] == str(candidate_id)
        assert payload["cases"][0]["drift_kind"] == "regression"
    finally:
        await eng.dispose()
```

- [ ] **Step 2: Run — expect FAIL** (`cannot import name 'mint_eval_replay_request_id'`). Run: `uv run pytest tests/unit/evaluation/test_storage_replay.py -q`

- [ ] **Step 3: Append to `storage.py`** (below the existing store; reuses `self._history.append_with_precondition` with a no-op precondition — the `eval.replay` row has NO relational insert):

```python
# add near the existing _EVAL_RUN_REQUEST_ID_PREFIX:
_EVAL_REPLAY_REQUEST_ID_PREFIX: Final[str] = "eval-replay-"  # 12 chars + 32 hex = 44 <= 64


def mint_eval_replay_request_id() -> str:
    return f"{_EVAL_REPLAY_REQUEST_ID_PREFIX}{uuid.uuid4().hex}"


# ... add to the EvalRunStore class:
    async def append_replay_event(
        self,
        *,
        diff: "ReplayDiff",
        actor_subject: str,
        tenant_id: str,
        request_id: str,
    ) -> tuple[uuid.UUID, bytes]:
        """Emit the value-free ``eval.replay`` chain row (NO relational insert).

        Mirrors persist_run's record_builder but with a no-op precondition (the
        candidate run + its rows are already persisted via persist_run). Payload
        is minimal per spec §5: IDs / digests / counts / per-case drift only —
        NO model, NO tier, NO raw text.
        """

        async def _precondition(conn: AsyncConnection, _seq: int, _hash: bytes) -> None:
            return None

        def _build_record(_: None) -> DecisionRecord:
            return DecisionRecord(
                decision_type="eval.replay",
                request_id=request_id,
                actor_id=actor_subject,
                tenant_id=tenant_id,
                iso_controls=_EVAL_ISO_CONTROLS,
                payload={
                    "baseline_run_id": str(diff.baseline_run_id),
                    "candidate_run_id": str(diff.candidate_run_id),
                    "corpus_id": diff.corpus_id,
                    "corpus_digest": diff.corpus_digest,
                    "total": diff.total,
                    "regressions": diff.regressions,
                    "improvements": diff.improvements,
                    "unchanged": diff.unchanged,
                    "output_changed": diff.output_changed,
                    "errored": diff.errored,
                    "cases": [
                        {
                            "case_id": c.case_id,
                            "drift_kind": c.drift_kind,
                            "baseline_passed": c.baseline_passed,
                            "candidate_passed": c.candidate_passed,
                            "output_digest_changed": c.output_digest_changed,
                        }
                        for c in diff.cases
                    ],
                },
            )

        return await self._history.append_with_precondition(
            record_builder=_build_record, precondition=_precondition
        )
```

> Add `from cognic_agentos.evaluation.replay import ReplayDiff` under the existing `if TYPE_CHECKING:` block in `storage.py` (type-only — no runtime cycle: replay.py imports storage at runtime in T6, storage imports replay only for typing).

- [ ] **Step 4: Run — expect PASS.** Run: `uv run pytest tests/unit/evaluation/test_storage_replay.py -q`

- [ ] **Step 5: HALT-BEFORE-COMMIT [CC]** (storage.py on-gate). Full gate ladder; report `storage.py` focused `--cov-branch` (≥95/≥90); halt summary; token.

```bash
uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy src tests
git add src/cognic_agentos/evaluation/storage.py tests/unit/evaluation/test_storage_replay.py
git commit -m "$(printf 'feat(eval): EvalRunStore.append_replay_event value-free chain row (ADR-010)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 4 [STOP-RULE]: RBAC scope `eval.replay.run`

**Files:**
- Modify: `src/cognic_agentos/portal/rbac/scopes.py`
- Test: `tests/unit/portal/rbac/test_eval_replay_scope.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/portal/rbac/test_eval_replay_scope.py
from __future__ import annotations

import typing

from cognic_agentos.portal.rbac.scopes import EVAL_SCOPES, EvalRBACScope


def test_eval_scopes_include_replay_run() -> None:
    expected = {"eval.judge.run", "eval.bulk.run", "eval.runs.read", "eval.replay.run"}
    assert set(typing.get_args(EvalRBACScope)) == expected
    assert frozenset(expected) == EVAL_SCOPES
```

- [ ] **Step 2: Run — expect FAIL.** Run: `uv run pytest tests/unit/portal/rbac/test_eval_replay_scope.py -q`

- [ ] **Step 3: Extend `EvalRBACScope` + `EVAL_SCOPES`** (add the 4th value):

```python
EvalRBACScope = Literal[
    "eval.judge.run",
    "eval.bulk.run",
    "eval.runs.read",
    "eval.replay.run",
]

EVAL_SCOPES: frozenset[EvalRBACScope] = frozenset(
    {"eval.judge.run", "eval.bulk.run", "eval.runs.read", "eval.replay.run"}
)
```

- [ ] **Step 4: Run — expect PASS.** Run: `uv run pytest tests/unit/portal/rbac/test_eval_replay_scope.py -q`

- [ ] **Step 4b: Advance the two Sprint-12 eval-scope drift pins** (REQUIRED — adding `eval.replay.run` legitimately trips them; this advance IS the reviewed act they guard): `tests/unit/portal/rbac/test_eval_scopes.py::test_eval_scope_family_has_exactly_three_values` (rename → `…_four_values`, expected set → 4) and `tests/unit/portal/rbac/test_eval_bulk_scopes.py::test_eval_scopes_include_bulk_and_runs_read` (exact-set assertion → 4). Run: `uv run pytest tests/unit/portal/rbac/ -q` → expect all PASS.

- [ ] **Step 5: HALT-BEFORE-COMMIT [STOP-RULE]** (RBAC). Full gate ladder; halt summary; token.

```bash
uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy src tests
git add src/cognic_agentos/portal/rbac/scopes.py \
        tests/unit/portal/rbac/test_eval_replay_scope.py \
        tests/unit/portal/rbac/test_eval_scopes.py \
        tests/unit/portal/rbac/test_eval_bulk_scopes.py
git commit -m "$(printf 'feat(eval): RBAC scope eval.replay.run (ADR-010)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 5 [STOP-RULE]: ISO controls — tag `eval.replay`

**Files:**
- Modify: `src/cognic_agentos/compliance/iso42001/controls.py`
- Test: `tests/unit/compliance/iso42001/test_eval_replay_iso.py`

A.7.6 + A.9.2 are already `implemented` (Sprint 12); this is an **additive** hook addition (no status flip).

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/compliance/iso42001/test_eval_replay_iso.py
from __future__ import annotations

from cognic_agentos.compliance.iso42001.controls import ISO42001_CONTROLS


def _entry(cid: str):
    return next(e for e in ISO42001_CONTROLS if e.control_id == cid)


def test_eval_replay_tags_a76_and_a92() -> None:
    assert "eval.replay" in _entry("ISO42001.A.7.6").intended_hooks
    assert "eval.replay" in _entry("ISO42001.A.9.2").intended_hooks
    # both stay implemented (no status change)
    assert _entry("ISO42001.A.7.6").hook_status == "implemented"
    assert _entry("ISO42001.A.9.2").hook_status == "implemented"
```

- [ ] **Step 2: Run — expect FAIL.** Run: `uv run pytest tests/unit/compliance/iso42001/test_eval_replay_iso.py -q`

- [ ] **Step 3: Add `"eval.replay"` to the A.7.6 + A.9.2 `intended_hooks` tuples** (append to each existing tuple):

```python
# A.7.6 intended_hooks: ("auto_degradation.evaluate", "compliance_checker.score", "eval.bulk_run", "eval.replay")
# A.9.2 intended_hooks: ("audit.append", "chain_verifier.walk", "eval.bulk_run", "eval.replay")
```

- [ ] **Step 4: Run — expect PASS** (the new test + the whole compliance dir). Run: `uv run pytest tests/unit/compliance/ -q`

> No deferred-count change (no status flip), so the count/coverage tests in `test_control_mapping.py` should remain green. Confirm; if any asserts the exact `intended_hooks` tuple of A.7.6/A.9.2, update it to include `eval.replay`.

- [ ] **Step 5: HALT-BEFORE-COMMIT [STOP-RULE]** (ISO mapping). Full gate ladder; halt summary; token.

```bash
uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy src tests
git add src/cognic_agentos/compliance/iso42001/controls.py tests/unit/compliance/iso42001/test_eval_replay_iso.py
git commit -m "$(printf 'feat(eval): tag eval.replay under ISO A.7.6 + A.9.2 (ADR-010)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 6 [CC]: `run_replay` orchestrator (replay.py)

**Files:**
- Modify: `src/cognic_agentos/evaluation/replay.py` (add `run_replay`)
- Test: `tests/unit/evaluation/test_run_replay.py` (migrated DB + fake gateway)

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/evaluation/test_run_replay.py
from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.evaluation.corpus import validate_corpus_payload
from cognic_agentos.evaluation.replay import run_replay
from cognic_agentos.evaluation.runner import EvalRunner
from cognic_agentos.evaluation.scorers import AssertionScorer
from cognic_agentos.evaluation.storage import EvalRunStore, _eval_runs
from cognic_agentos.evaluation.target import GatewayTarget
from cognic_agentos.llm.gateway import GatewayResponse

_PAYLOAD = {
    "schema_version": 1, "corpus_id": "cp",
    "cases": [{"id": "c1", "case_kind": "completion",
               "messages": [{"role": "user", "content": "q"}],
               "assertions": {"contains": ["ok"]}}],
}


class _Gateway:
    def __init__(self, content: str) -> None:
        self._content = content

    async def completion(self, *, tier, messages, request_id, tenant_id=None):  # type: ignore[no-untyped-def]
        return GatewayResponse(content=self._content, upstream_model="m", api_base=None,
                               external=False, request_id=request_id, tier=tier, latency_ms=1)


async def _migrated_engine(tmp_path: Any) -> Any:
    from alembic import command
    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'runreplay.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    return create_async_engine(url)


@pytest.mark.asyncio
async def test_run_replay_persists_candidate_and_emits_replay_row_with_regression(tmp_path: Any) -> None:
    eng = await _migrated_engine(tmp_path)
    try:
        store = EvalRunStore(DecisionHistoryStore(eng))
        corpus = validate_corpus_payload(_PAYLOAD)
        # seed a baseline that PASSES (output contains "ok")
        baseline = await EvalRunner().run(
            corpus, target=GatewayTarget(gateway=_Gateway("ok"), tier="tier1"),  # type: ignore[arg-type]
            scorers=[AssertionScorer()], run_id=uuid.uuid4(), chain_request_id="b", tenant_id="t1",
        )
        await store.persist_run(result=baseline, actor_subject="svc", tenant_id="t1")
        baseline_loaded = await store.get_run(run_id=baseline.run_id, tenant_id="t1")
        assert baseline_loaded is not None

        # candidate gateway returns "no" → assertion fails → regression
        diff = await run_replay(
            corpus=corpus,
            baseline_run_id=baseline.run_id,
            baseline_cases=[dict(c) for c in baseline_loaded["cases"]],
            baseline_tier=str(baseline_loaded["run"]["tier"]),
            gateway=_Gateway("no"),  # type: ignore[arg-type]
            store=store,
            target_tier="tier1",
            judge_tier="tier1",
            max_raw_output_chars=50_000,
            tenant_id="t1",
            actor_subject="svc",
            persist_raw_output=False,
        )
        assert diff.has_regressions is True and diff.regressions == 1
        # candidate persisted as a first-class run
        async with eng.connect() as c:
            cand = (await c.execute(sa.select(_eval_runs).where(_eval_runs.c.run_id == diff.candidate_run_id))).first()
            replay_rows = (await c.execute(sa.text("SELECT 1 FROM decision_history WHERE event_type='eval.replay'"))).all()
        assert cand is not None
        assert len(replay_rows) == 1
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_run_replay_raw_output_on_truncates_off_none(tmp_path: Any) -> None:
    from cognic_agentos.evaluation.storage import _eval_case_results

    eng = await _migrated_engine(tmp_path)
    try:
        store = EvalRunStore(DecisionHistoryStore(eng))
        corpus = validate_corpus_payload(_PAYLOAD)
        baseline = await EvalRunner().run(
            corpus, target=GatewayTarget(gateway=_Gateway("ok"), tier="tier1"),  # type: ignore[arg-type]
            scorers=[AssertionScorer()], run_id=uuid.uuid4(), chain_request_id="b", tenant_id="t1",
        )
        await store.persist_run(result=baseline, actor_subject="svc", tenant_id="t1")
        bl = await store.get_run(run_id=baseline.run_id, tenant_id="t1")
        assert bl is not None
        long_text = "ok " + "x" * 100  # contains "ok" -> passes; longer than the 10-char cap

        async def _replay(persist: bool):
            return await run_replay(
                corpus=corpus, baseline_run_id=baseline.run_id,
                baseline_cases=[dict(c) for c in bl["cases"]], baseline_tier=str(bl["run"]["tier"]),
                gateway=_Gateway(long_text), store=store,  # type: ignore[arg-type]
                target_tier="tier1", judge_tier="tier1", max_raw_output_chars=10,
                tenant_id="t1", actor_subject="svc", persist_raw_output=persist,
            )

        on = await _replay(True)
        off = await _replay(False)
        async with eng.connect() as c:
            on_row = (await c.execute(sa.select(_eval_case_results).where(_eval_case_results.c.run_id == on.candidate_run_id))).first()
            off_row = (await c.execute(sa.select(_eval_case_results).where(_eval_case_results.c.run_id == off.candidate_run_id))).first()
        assert on_row.candidate_output_text == long_text[:10]
        assert on_row.raw_output_persisted and on_row.output_truncated
        assert off_row.candidate_output_text is None and not off_row.raw_output_persisted
    finally:
        await eng.dispose()
```

- [ ] **Step 2: Run — expect FAIL** (`cannot import name 'run_replay'`). Run: `uv run pytest tests/unit/evaluation/test_run_replay.py -q`

- [ ] **Step 3a: Extract `apply_raw_output` to `runner.py`** (shared by bulk-run + replay — DRY; the raw-output safety contract must not diverge between the two routes). Add to `runner.py` (it already imports `CaseResult`/`EvalRunResult`; add `import dataclasses`):

```python
def apply_raw_output(result: EvalRunResult, *, persist: bool, max_chars: int) -> EvalRunResult:
    """Truncate per-case candidate text to ``max_chars`` + set
    ``raw_output_persisted`` / ``output_truncated`` when ``persist`` is True;
    pass-through when False (cases already carry ``candidate_output_text=None``).
    Shared by the bulk-run + replay routes (one safety contract, no drift)."""
    if not persist:
        return result
    new_cases: list[CaseResult] = []
    for c in result.cases:
        if c.candidate_output_text is None:
            new_cases.append(c)
            continue
        raw = c.candidate_output_text
        new_cases.append(
            dataclasses.replace(
                c,
                candidate_output_text=raw[:max_chars],
                raw_output_persisted=True,
                output_truncated=len(raw) > max_chars,
            )
        )
    return dataclasses.replace(result, cases=tuple(new_cases))
```

Then update `portal/api/evaluation/bulk_routes.py` to use the shared helper: delete its local `_apply_raw_output` definition, add `from cognic_agentos.evaluation.runner import apply_raw_output`, and change the call to `apply_raw_output(result, persist=body.persist_raw_output, max_chars=max_raw_output_chars)`. The Sprint-12 bulk e2e raw-output on/off tests continue to cover the moved logic.

- [ ] **Step 3b: Add `run_replay` to `replay.py`** (runtime imports inside the function to avoid any import-order issues; the diff types live above):

```python
# append to src/cognic_agentos/evaluation/replay.py

async def run_replay(
    *,
    corpus: Any,
    baseline_run_id: uuid.UUID,
    baseline_cases: list[dict[str, Any]],
    baseline_tier: str,
    gateway: Any,
    store: Any,
    target_tier: str,
    judge_tier: str,
    max_raw_output_chars: int,
    tenant_id: str,
    actor_subject: str,
    persist_raw_output: bool,
) -> ReplayDiff:
    """Run the candidate, persist it, diff vs baseline, emit eval.replay.

    Two sequential chain appends (spec §3): persist_run (eval.bulk_run) then
    append_replay_event (eval.replay). If the second raises after the first
    succeeds, the candidate is a valid standalone run; this function propagates
    the exception (route → 5xx). NON-idempotent (a retry mints a fresh candidate).
    """
    from cognic_agentos.evaluation.runner import EvalRunner, apply_raw_output
    from cognic_agentos.evaluation.scorers import AssertionScorer, JudgeScorer
    from cognic_agentos.evaluation.storage import mint_eval_replay_request_id, mint_eval_request_id
    from cognic_agentos.evaluation.target import GatewayTarget

    target = GatewayTarget(gateway=gateway, tier=target_tier)
    scorers = [AssertionScorer(), JudgeScorer(gateway=gateway, tier=judge_tier)]
    candidate = await EvalRunner().run(
        corpus,
        target=target,
        scorers=scorers,
        run_id=uuid.uuid4(),
        chain_request_id=mint_eval_request_id(),
        tenant_id=tenant_id,
        capture_raw_output=persist_raw_output,
    )
    # Apply the Sprint-12 raw-output safety contract BEFORE persisting (truncate to
    # max_raw_output_chars + set raw_output_persisted/output_truncated). output_digest
    # is the digest of the ORIGINAL text (set in the runner), so truncation does not
    # affect the diff — the diff compares output_digest, not the stored text.
    candidate = apply_raw_output(candidate, persist=persist_raw_output, max_chars=max_raw_output_chars)
    # Step 6: persist candidate (eval.bulk_run) — reuses Sprint-12 persist_run.
    await store.persist_run(result=candidate, actor_subject=actor_subject, tenant_id=tenant_id)
    # Step 7: pure diff.
    diff = compute_replay_diff(
        baseline_run_id=baseline_run_id,
        candidate=candidate,
        baseline_cases=baseline_cases,
        baseline_tier=baseline_tier,
    )
    # Step 8: emit eval.replay (value-free). May raise → candidate stays a valid run.
    await store.append_replay_event(
        diff=diff, actor_subject=actor_subject, tenant_id=tenant_id,
        request_id=mint_eval_replay_request_id(),
    )
    return diff
```

> **Type note:** `corpus`/`gateway`/`store` are typed `Any` to keep `replay.py` free of runtime imports of `runner`/`storage`/`llm` at module scope (the function-body imports break any cycle). If full-tree mypy wants tighter types, use `TYPE_CHECKING` imports for `Corpus`/`LLMGateway`/`EvalRunStore` and annotate; keep the function-body runtime imports. Match whatever keeps `mypy src tests` clean.

- [ ] **Step 4: Run — expect PASS.** Run: `uv run pytest tests/unit/evaluation/test_run_replay.py -q`

- [ ] **Step 5: HALT-BEFORE-COMMIT [CC].** Full gate ladder; report `replay.py` focused `--cov-branch` over BOTH replay test files (`uv run pytest tests/unit/evaluation/test_replay_diff.py tests/unit/evaluation/test_run_replay.py --cov=cognic_agentos.evaluation.replay --cov-branch --cov-report=term-missing -q` — aim ≥95/≥90, ideally 100; close any gap with focused tests in THIS commit); halt summary; token.

```bash
uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy src tests
git add src/cognic_agentos/evaluation/replay.py \
        src/cognic_agentos/evaluation/runner.py \
        src/cognic_agentos/portal/api/evaluation/bulk_routes.py \
        tests/unit/evaluation/test_run_replay.py
git commit -m "$(printf 'feat(eval): run_replay orchestrator + shared apply_raw_output (ADR-010)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 7 [STOP-RULE]: Replay DTOs + portal route

**Files:**
- Modify: `src/cognic_agentos/portal/api/evaluation/dto.py`
- Create: `src/cognic_agentos/portal/api/evaluation/replay_routes.py`
- Test: `tests/unit/portal/api/evaluation/test_replay_routes.py` + `tests/unit/portal/api/evaluation/test_replay_routes_e2e.py`

- [ ] **Step 1: Write the failing tests** (unit: 503/403/413/400-empty/404/409/no-future-import; e2e: 200 + regression + candidate queryable + replay row + the partial-failure 5xx)

```python
# tests/unit/portal/api/evaluation/test_replay_routes.py
from __future__ import annotations

import uuid
from typing import Any

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.portal.api.evaluation.replay_routes import build_eval_replay_routes
from cognic_agentos.portal.rbac.actor import Actor


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


def _actor(*, scopes=frozenset({"eval.replay.run"})) -> Actor:
    return Actor(subject="svc", tenant_id="t1", scopes=scopes, actor_type="service")  # type: ignore[arg-type]


class _FakeGateway:
    async def completion(self, *, tier, messages, request_id, tenant_id=None):  # type: ignore[no-untyped-def]
        from cognic_agentos.llm.gateway import GatewayResponse
        return GatewayResponse(content="ok", upstream_model="m", api_base=None, external=False,
                               request_id=request_id, tier=tier, latency_ms=1)


def _dh_store() -> DecisionHistoryStore:
    return DecisionHistoryStore(create_async_engine("sqlite+aiosqlite://"))


def _corpus(n: int) -> dict[str, Any]:
    return {"schema_version": 1, "corpus_id": "cp",
            "cases": [{"id": f"c{i}", "case_kind": "completion",
                       "messages": [{"role": "user", "content": "q"}],
                       "assertions": {"contains": ["ok"]}} for i in range(n)]}


def _body(corpus, baseline_run_id="11111111-1111-1111-1111-111111111111", **extra):
    b = {"corpus": corpus, "baseline_run_id": baseline_run_id}
    b.update(extra)
    return b


def _app(*, actor, gateway, store, runtime=None, max_cases=50) -> FastAPI:
    app = FastAPI()
    app.state.actor_binder = _StubBinder(actor)
    app.state.llm_gateway = gateway
    app.state.decision_history_store = store
    app.state.runtime = runtime
    app.include_router(
        build_eval_replay_routes(max_cases=max_cases, max_raw_output_chars=50_000,
                                 target_tier="tier1", judge_tier="tier1"),
        prefix="/api/v1/eval",
    )
    return app


def test_llm_gateway_unavailable_503() -> None:
    app = _app(actor=_actor(), gateway=None, store=_dh_store())
    r = TestClient(app).post("/api/v1/eval/replay", json=_body(_corpus(1)))
    assert r.status_code == 503 and r.json()["detail"]["reason"] == "llm_gateway_unavailable"


def test_scope_not_held_403() -> None:
    app = _app(actor=_actor(scopes=frozenset({"eval.bulk.run"})), gateway=_FakeGateway(), store=_dh_store())
    assert TestClient(app).post("/api/v1/eval/replay", json=_body(_corpus(1))).status_code == 403


def test_over_cap_413() -> None:
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=_dh_store(), max_cases=1)
    r = TestClient(app).post("/api/v1/eval/replay", json=_body(_corpus(2)))
    assert r.status_code == 413 and r.json()["detail"]["reason"] == "eval_corpus_too_large"


def test_empty_corpus_400() -> None:
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=_dh_store())
    body = _body(_corpus(1)); body["corpus"]["cases"] = []
    r = TestClient(app).post("/api/v1/eval/replay", json=body)
    assert r.status_code == 400 and r.json()["detail"]["reason"] == "eval_corpus_empty"


def test_malformed_baseline_uuid_422() -> None:
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=_dh_store())
    r = TestClient(app).post("/api/v1/eval/replay", json=_body(_corpus(1), baseline_run_id="not-a-uuid"))
    assert r.status_code == 422


def test_store_unavailable_503() -> None:
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=None)
    r = TestClient(app).post("/api/v1/eval/replay", json=_body(_corpus(1)))
    assert r.status_code == 503 and r.json()["detail"]["reason"] == "decision_history_unavailable"


def test_wrong_type_store_503() -> None:
    # a wrong-type store fails closed at DI (isinstance guard) before any work.
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=object())
    r = TestClient(app).post("/api/v1/eval/replay", json=_body(_corpus(1)))
    assert r.status_code == 503 and r.json()["detail"]["reason"] == "decision_history_unavailable"


def test_replay_routes_omits_future_annotations() -> None:
    import ast
    import pathlib
    import cognic_agentos.portal.api.evaluation.replay_routes as m

    tree = ast.parse(pathlib.Path(m.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            raise AssertionError("replay_routes.py must NOT import from __future__ (closure-local Depends)")
```

> **e2e + 404/409/partial-failure** require a real migrated DB. Add `tests/unit/portal/api/evaluation/test_replay_routes_e2e.py` mirroring `test_bulk_routes_e2e.py`: build the app with a real `DecisionHistoryStore(migrated_engine)` as `app.state.decision_history_store`; seed a baseline run via `EvalRunStore.persist_run`; then assert:
> - (a) **404 `baseline_run_not_found`** for an unknown baseline UUID.
> - (b) **404** for a *wrong-tenant* baseline (seed under `t1`, call with an actor in `t2`) — **byte-identical body** to (a)'s unknown-id 404.
> - (c) **409 `replay_corpus_digest_mismatch`** when the supplied corpus differs from the baseline's.
> - (d) **200** happy path with a candidate gateway that flips a case → `has_regressions=True`; **assert the response per-case carries `baseline_outcome` + `candidate_outcome`** (P1 fix); the candidate is **queryable via `EvalRunStore.get_run(run_id=<candidate_run_id>, tenant_id=...)`** (the replay e2e app mounts ONLY the replay router — do NOT require mounting the bulk-run GET route; assert queryability through the store, not an HTTP GET); exactly one `eval.replay` chain row.
> - (e) **partial-failure 5xx** — build the client as **`TestClient(app, raise_server_exceptions=False)`** (so a raised exception returns a 5xx response instead of propagating into the test); monkeypatch `EvalRunStore.append_replay_event` to raise **after** `persist_run` succeeds; assert the candidate run row exists (queryable via `get_run`), **no `eval.replay` row** is present, and the response status is `>= 500`.

- [ ] **Step 2: Run — expect FAIL.** Run: `uv run pytest tests/unit/portal/api/evaluation/test_replay_routes.py -q`

- [ ] **Step 3a: Append DTOs to `dto.py`**

```python
class ReplayRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    corpus: dict[str, Any]
    baseline_run_id: uuid.UUID
    persist_raw_output: StrictBool = False


class ReplayCaseDiffResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: str
    drift_kind: Literal["regression", "improvement", "unchanged", "output_changed", "errored"]
    baseline_passed: bool
    candidate_passed: bool
    baseline_outcome: str
    candidate_outcome: str
    output_digest_changed: bool
    baseline_model: str
    candidate_model: str
    baseline_tier: str
    candidate_tier: str


class ReplayDiffResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    baseline_run_id: str
    candidate_run_id: str
    corpus_id: str
    corpus_digest: str
    total: int
    regressions: int
    improvements: int
    unchanged: int
    output_changed: int
    errored: int
    has_regressions: bool
    cases: list[ReplayCaseDiffResponse]
```
> Add `import uuid` to `dto.py` if absent (`baseline_run_id: uuid.UUID` gives the 422-on-malformed-UUID for free). `StrictBool`/`Literal` are already imported (bulk DTOs use them).

- [ ] **Step 3b: Create `replay_routes.py`** (mirror `bulk_routes.py` DI; no future-import)

```python
# src/cognic_agentos/portal/api/evaluation/replay_routes.py
"""ADR-010 Sprint-13a — POST /api/v1/eval/replay.

Re-run a corpus at the current target config and diff vs a baseline run. DI
fails closed (gateway + decision-history store BEFORE work). Handler-raised
statuses: 403/503/413/400/404/409 (+422 body-validation); a partial-failure of
the eval.replay append after the candidate persists yields 5xx (candidate is a
valid standalone run; non-idempotent). ``from __future__ import annotations`` is
OMITTED (closure-local Depends).
"""

import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request

from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.evaluation.corpus import CorpusLoadError, corpus_digest, validate_corpus_payload
from cognic_agentos.evaluation.replay import run_replay
from cognic_agentos.evaluation.storage import EvalRunStore
from cognic_agentos.llm.gateway import LLMGateway
from cognic_agentos.portal.api.evaluation.dto import (
    ReplayCaseDiffResponse,
    ReplayDiffResponse,
    ReplayRequest,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope

EvalReplayRefusalReason = Literal["baseline_run_not_found", "replay_corpus_digest_mismatch"]


def _require_llm_gateway(request: Request) -> LLMGateway:
    gw = getattr(request.app.state, "llm_gateway", None)
    if gw is None:
        raise HTTPException(status_code=503, detail={"reason": "llm_gateway_unavailable"})
    return gw


def _require_decision_history_store(request: Request) -> DecisionHistoryStore:
    runtime = getattr(request.app.state, "runtime", None)
    store = (
        runtime.decision_history_store
        if runtime is not None
        else getattr(request.app.state, "decision_history_store", None)
    )
    if store is None or not isinstance(store, DecisionHistoryStore):
        raise HTTPException(status_code=503, detail={"reason": "decision_history_unavailable"})
    return store


def build_eval_replay_routes(
    *, max_cases: int, max_raw_output_chars: int, target_tier: str, judge_tier: str
) -> APIRouter:
    router = APIRouter()
    _require_replay = RequireScope("eval.replay.run")

    @router.post("/replay", summary="Re-run a corpus at current config; diff vs a baseline run")
    async def replay(
        request: Request,
        actor: Annotated[Actor, Depends(_require_replay)],
        gateway: Annotated[LLMGateway, Depends(_require_llm_gateway)],
        dh_store: Annotated[DecisionHistoryStore, Depends(_require_decision_history_store)],
        body: ReplayRequest,
    ) -> ReplayDiffResponse:
        raw_cases = body.corpus.get("cases") if isinstance(body.corpus, dict) else None
        if isinstance(raw_cases, list) and len(raw_cases) == 0:
            raise HTTPException(status_code=400, detail={"reason": "eval_corpus_empty"})
        try:
            corpus = validate_corpus_payload(body.corpus)
        except CorpusLoadError as exc:
            raise HTTPException(status_code=400, detail={"reason": exc.reason}) from None
        if len(corpus.cases) > max_cases:
            raise HTTPException(status_code=413, detail={"reason": "eval_corpus_too_large"})

        store = EvalRunStore(dh_store)
        baseline = await store.get_run(run_id=body.baseline_run_id, tenant_id=actor.tenant_id)
        if baseline is None:  # cross-tenant + unknown both collapse
            raise HTTPException(status_code=404, detail={"reason": "baseline_run_not_found"})
        if corpus_digest(corpus) != str(baseline["run"]["corpus_digest"]):
            raise HTTPException(status_code=409, detail={"reason": "replay_corpus_digest_mismatch"})

        diff = await run_replay(
            corpus=corpus,
            baseline_run_id=body.baseline_run_id,
            baseline_cases=[dict(c) for c in baseline["cases"]],
            baseline_tier=str(baseline["run"]["tier"]),
            gateway=gateway,
            store=store,
            target_tier=target_tier,
            judge_tier=judge_tier,
            max_raw_output_chars=max_raw_output_chars,
            tenant_id=actor.tenant_id,
            actor_subject=actor.subject,
            persist_raw_output=body.persist_raw_output,
        )
        return ReplayDiffResponse(
            baseline_run_id=str(diff.baseline_run_id),
            candidate_run_id=str(diff.candidate_run_id),
            corpus_id=diff.corpus_id,
            corpus_digest=diff.corpus_digest,
            total=diff.total,
            regressions=diff.regressions,
            improvements=diff.improvements,
            unchanged=diff.unchanged,
            output_changed=diff.output_changed,
            errored=diff.errored,
            has_regressions=diff.has_regressions,
            cases=[
                ReplayCaseDiffResponse(
                    case_id=c.case_id, drift_kind=c.drift_kind,
                    baseline_passed=c.baseline_passed, candidate_passed=c.candidate_passed,
                    baseline_outcome=c.baseline_outcome, candidate_outcome=c.candidate_outcome,
                    output_digest_changed=c.output_digest_changed,
                    baseline_model=c.baseline_model, candidate_model=c.candidate_model,
                    baseline_tier=c.baseline_tier, candidate_tier=c.candidate_tier,
                )
                for c in diff.cases
            ],
        )

    return router
```

> **Partial-failure (5xx):** `run_replay` propagates the `append_replay_event` exception; FastAPI maps an unhandled exception to 500. No special handling needed — the e2e partial-failure test asserts the candidate row exists, no `eval.replay` row, and a 5xx. Do NOT wrap `run_replay` in a try/except that swallows it.

- [ ] **Step 4: Run — expect PASS** (unit + e2e). Run: `uv run pytest tests/unit/portal/api/evaluation/ -q`

- [ ] **Step 5: HALT-BEFORE-COMMIT [STOP-RULE]** (new auth/mutation surface). Full gate ladder; halt summary (pin 404-wrong-tenant-collapse, 409 digest-mismatch, 400-empty, 503, RBAC 403, partial-failure 5xx); token.

```bash
uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy src tests
git add src/cognic_agentos/portal/api/evaluation/dto.py \
        src/cognic_agentos/portal/api/evaluation/replay_routes.py \
        tests/unit/portal/api/evaluation/test_replay_routes.py \
        tests/unit/portal/api/evaluation/test_replay_routes_e2e.py
git commit -m "$(printf 'feat(eval): replay portal endpoint POST /eval/replay (ADR-010)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 8 [STOP-RULE]: Mount the replay router

**Files:**
- Modify: `src/cognic_agentos/portal/api/app.py` (after the bulk-run include)
- Test: `tests/unit/portal/api/test_app_eval_replay_mount.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/portal/api/test_app_eval_replay_mount.py
from __future__ import annotations

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.portal.api.app import create_app


def test_replay_route_mounted() -> None:
    app = create_app(build_settings_without_env_file())
    paths = {r.path for r in app.routes}  # type: ignore[attr-defined]
    assert "/api/v1/eval/replay" in paths
```

- [ ] **Step 2: Run — expect FAIL.** Run: `uv run pytest tests/unit/portal/api/test_app_eval_replay_mount.py -q`

- [ ] **Step 3: Add the mount** immediately after the existing `build_eval_bulk_routes(...)` include:

```python
    from cognic_agentos.portal.api.evaluation.replay_routes import build_eval_replay_routes

    app.include_router(
        build_eval_replay_routes(
            max_cases=settings.eval_bulk_max_cases,
            max_raw_output_chars=settings.eval_bulk_max_raw_output_chars,
            target_tier=settings.eval_bulk_target_tier,
            judge_tier=settings.eval_judge_tier,
        ),
        prefix="/api/v1/eval",
        tags=["eval"],
    )
```

- [ ] **Step 4: Run — expect PASS.** Run: `uv run pytest tests/unit/portal/api/test_app_eval_replay_mount.py -q`

- [ ] **Step 5: HALT-BEFORE-COMMIT [STOP-RULE]** (app wiring). Full gate ladder; halt summary; token.

```bash
uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy src tests
git add src/cognic_agentos/portal/api/app.py tests/unit/portal/api/test_app_eval_replay_mount.py
git commit -m "$(printf 'feat(eval): mount replay portal router (ADR-010)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 9 [CC]: Promote `replay.py` to the CC gate (121 → 122)

**Files:**
- Modify: `tools/check_critical_coverage.py` (append the entry)
- Modify: `tests/unit/tools/test_check_critical_coverage.py` (`_EXPECTED_ENTRY_COUNT` 121→122 + a `_SPRINT_13A_GATE_MODULES` set-pin)

- [ ] **Step 1: Write the failing test** (count + set-pin, mirroring `_SPRINT_12_GATE_MODULES`)

```python
_SPRINT_13A_GATE_MODULES = ("src/cognic_agentos/evaluation/replay.py",)


def test_sprint_13a_modules_present_with_standard_floors(gate_tool: ModuleType) -> None:
    by_path = {p: (l, b) for p, l, b in gate_tool._CRITICAL_FILES}
    for module in _SPRINT_13A_GATE_MODULES:
        assert module in by_path, f"Sprint 13a module missing from gate: {module}"
        assert by_path[module] == (0.95, 0.90)
```
And bump `_EXPECTED_ENTRY_COUNT` `121` → `122` (+ extend the running-total comment "+ 1 Sprint-13a replay module = 122").

- [ ] **Step 2: Run — expect FAIL.** Run: `uv run pytest tests/unit/tools/test_check_critical_coverage.py -q`

- [ ] **Step 3: Append the entry** to `_CRITICAL_FILES` (before the closing `)`):

```python
    # Sprint 13a (ADR-010) live replay — eval-run replay orchestration + diff;
    # the pass/fail-drift classification + the persist/diff/chain flow. route/DTO off-gate (R32).
    ("src/cognic_agentos/evaluation/replay.py", 0.95, 0.90),
```

- [ ] **Step 4: VERIFY-AT-PROMOTION** (fresh `--cov-branch`):

```bash
uv run pytest -q --cov=src/cognic_agentos --cov-branch --cov-report=json:coverage.json
uv run python tools/check_critical_coverage.py
uv run pytest tests/unit/tools/test_check_critical_coverage.py -q
```
Expected: gate PASS, all 122 entries at/above floor incl. `evaluation/replay.py`. **If `replay.py` is below floor, add focused tests in THIS commit** until it clears.

- [ ] **Step 5: HALT-BEFORE-COMMIT [CC].** Halt summary with the fresh `replay.py` coverage number; token. (`coverage.json` gitignored — not staged.)

```bash
git add tools/check_critical_coverage.py tests/unit/tools/test_check_critical_coverage.py <any added focused tests>
git commit -m "$(printf 'chore(eval): promote evaluation/replay.py to CC gate (121->122)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 10 [normal]: CLI `agentos eval replay`

**Files:**
- Modify: `src/cognic_agentos/cli/eval.py` (add replay helpers)
- Modify: `src/cognic_agentos/cli/__init__.py` (add the `eval replay` command — register flat `@app.command(name="eval-replay")` matching the `eval-bulk` convention)
- Test: `tests/unit/cli/test_eval_replay.py`

> **Naming note:** Sprint-12 registered `eval-bulk` as a FLAT Typer command (no sub-app). Match that: register `@app.command(name="eval-replay")`. (The BUILD_PLAN's `agentos eval replay` two-word form would need a Typer sub-app, which the repo doesn't use — keep the flat hyphenated convention.)

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/cli/test_eval_replay.py
from __future__ import annotations

import textwrap
from pathlib import Path

from typer.testing import CliRunner

from cognic_agentos.cli import app

_GOOD = """\
schema_version: 1
corpus_id: smoke
cases:
  - id: c1
    case_kind: completion
    messages:
      - role: user
        content: "Define CAR."
    assertions:
      contains: ["capital adequacy"]
"""


def _corpus_dir(tmp_path: Path) -> Path:
    (tmp_path / "a.yaml").write_text(textwrap.dedent(_GOOD), encoding="utf-8")
    return tmp_path


def test_dry_run_validates_corpus_and_baseline_uuid_no_network(tmp_path: Path) -> None:
    res = CliRunner().invoke(app, [
        "eval-replay", "--corpus", str(_corpus_dir(tmp_path)),
        "--baseline", "11111111-1111-1111-1111-111111111111", "--dry-run",
    ])
    assert res.exit_code == 0
    assert "smoke" in res.stdout


def test_dry_run_bad_baseline_uuid_exit_1(tmp_path: Path) -> None:
    res = CliRunner().invoke(app, [
        "eval-replay", "--corpus", str(_corpus_dir(tmp_path)), "--baseline", "not-a-uuid", "--dry-run",
    ])
    assert res.exit_code == 1
    assert "baseline" in res.stderr.lower()


def test_dry_run_invalid_corpus_exit_1(tmp_path: Path) -> None:
    (tmp_path / "bad.yaml").write_text("schema_version: 9\ncases: []\n", encoding="utf-8")
    res = CliRunner().invoke(app, [
        "eval-replay", "--corpus", str(tmp_path),
        "--baseline", "11111111-1111-1111-1111-111111111111", "--dry-run",
    ])
    assert res.exit_code == 1
    assert "corpus" in res.stderr.lower()


def test_missing_url_without_dry_run_exit_2(tmp_path: Path) -> None:
    res = CliRunner().invoke(app, [
        "eval-replay", "--corpus", str(_corpus_dir(tmp_path)),
        "--baseline", "11111111-1111-1111-1111-111111111111",
    ])
    assert res.exit_code == 2
```

- [ ] **Step 2: Run — expect FAIL.** Run: `uv run pytest tests/unit/cli/test_eval_replay.py -q`

- [ ] **Step 3a: Add helpers to `cli/eval.py`**

```python
def replay_dry_run_summary(corpus_path: Path, baseline: str) -> dict[str, Any]:
    """Validate corpus + baseline-UUID SHAPE only (no network). Raises CorpusLoadError / ValueError."""
    import uuid as _uuid

    from cognic_agentos.evaluation.corpus import load_corpus

    _uuid.UUID(baseline)  # ValueError on malformed
    corpus = load_corpus(corpus_path)
    return {"corpus_id": corpus.corpus_id, "case_count": len(corpus.cases), "baseline": baseline}


def post_replay(corpus_path: Path, *, baseline: str, url: str, token: str) -> dict[str, Any]:
    import httpx

    from cognic_agentos.evaluation.corpus import load_corpus

    corpus = load_corpus(corpus_path)
    resp = httpx.post(
        f"{url.rstrip('/')}/api/v1/eval/replay",
        headers={"Authorization": f"Bearer {token}"},
        json={"corpus": corpus.model_dump(), "baseline_run_id": baseline, "persist_raw_output": False},
        timeout=120.0,
    )
    resp.raise_for_status()
    return resp.json()  # type: ignore[no-any-return]
```

- [ ] **Step 3b: Register the command in `cli/__init__.py`** (mirror `eval-bulk`; errors → stderr)

```python
@app.command(name="eval-replay")
def eval_replay(
    corpus: Path = typer.Option(..., "--corpus", help="Directory of corpus YAML docs."),  # noqa: B008
    baseline: str = typer.Option(..., "--baseline", help="Baseline eval-run id (UUID)."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Validate corpus + baseline UUID shape only; no portal/model call."),
    url: str | None = typer.Option(None, "--url", help="Portal base URL."),
    token: str | None = typer.Option(None, "--token", help="Bearer token."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Replay a corpus against the current target config and diff vs a baseline run."""
    import json as _json

    from cognic_agentos.cli.eval import post_replay, replay_dry_run_summary, render
    from cognic_agentos.evaluation.corpus import CorpusLoadError

    if dry_run:
        try:
            summary = replay_dry_run_summary(corpus, baseline)
        except ValueError:
            typer.echo(f"eval-replay: --baseline is not a valid UUID: {baseline!r}", err=True)
            raise typer.Exit(code=1) from None
        except CorpusLoadError as exc:
            typer.echo(f"eval-replay: corpus invalid: {exc.reason}", err=True)
            raise typer.Exit(code=1) from None
        typer.echo(render(summary, json_output=json_output))
        return
    if not url or not token:
        typer.echo("eval-replay: --url and --token are required without --dry-run", err=True)
        raise typer.Exit(code=2)
    try:
        body = post_replay(corpus, baseline=baseline, url=url, token=token)
    except CorpusLoadError as exc:
        typer.echo(f"eval-replay: corpus invalid: {exc.reason}", err=True)
        raise typer.Exit(code=1) from None
    except Exception as exc:
        typer.echo(f"eval-replay: portal call failed: {exc}", err=True)
        raise typer.Exit(code=2) from None
    typer.echo(_json.dumps(body, indent=2, sort_keys=True) if json_output else f"replay: {body.get('candidate_run_id')} regressions={body.get('regressions')}")
```
> `render(summary, json_output=...)` is the existing Sprint-12 helper in `cli/eval.py` (prints `corpus:`/`cases:`); reuse it for the dry-run summary.

- [ ] **Step 4: Run — expect PASS.** Run: `uv run pytest tests/unit/cli/test_eval_replay.py -q`

- [ ] **Step 5: ruff + mypy, commit by path** ([normal]).

```bash
uv run pytest tests/unit/cli/test_eval_replay.py -q
uv run ruff check src/cognic_agentos/cli/eval.py src/cognic_agentos/cli/__init__.py tests/unit/cli/test_eval_replay.py
uv run ruff format --check src/cognic_agentos/cli/eval.py src/cognic_agentos/cli/__init__.py tests/unit/cli/test_eval_replay.py
uv run mypy src tests
git add src/cognic_agentos/cli/eval.py src/cognic_agentos/cli/__init__.py tests/unit/cli/test_eval_replay.py
git commit -m "$(printf 'feat(eval): agentos eval-replay CLI (thin client + dry-run)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 11 [STOP-RULE]: ADR-010 Sprint-13a amendment

**Files:**
- Modify: `docs/adrs/ADR-010-evaluation-harness.md` (append a Sprint-13a amendment section)

- [ ] **Step 1: Append the amendment** documenting: eval-run replay (re-run fixed corpus at current config, diff vs baseline); the OS-only/value-free framing (candidate = current `GatewayTarget`, no caller tier knob; baseline corpus re-supplied + `corpus_digest` verified); persistence (candidate = first-class eval-run via `persist_run` + separate value-free `eval.replay` row; `chain_request_id` minted; no model/tier/raw on the row); the 5-value `drift_kind` taxonomy; the two-append partial-failure + **non-idempotency**; the new `eval.replay.run` scope; ISO A.7.6+A.9.2; CC gate 121→122 (`replay.py`); endpoints `POST /api/v1/eval/replay` + CLI `agentos eval-replay`. Record **deferred to later sub-projects/sprints**: caller-selectable candidate tier; per-scorer drift in the diff; production agent-run replay (citations/tool-call sequence); replay idempotency; `GET /eval/replays/{id}`. Verify every code citation grep/Read-backed (per `feedback_verify_code_citations_at_doc_write`).

- [ ] **Step 2: HALT-BEFORE-COMMIT [STOP-RULE]** (ADR source-of-truth). Docs-only; halt summary; token.

```bash
git add docs/adrs/ADR-010-evaluation-harness.md
git commit -m "$(printf 'docs(eval): ADR-010 Sprint-13a live replay amendment\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Self-review (against the spec)

**Spec coverage:** §1 scope → all tasks. §2 modules → T1 (corpus_digest+runner), T2+T6 (replay.py), T3 (storage), T4 (scopes), T5 (controls), T7 (dto+route), T8 (mount), T9 (CC gate), T10 (CLI), T11 (ADR). §3 flow → T6 (run_replay) + T7 (route: empty-before-validate, baseline load+404, digest 409). §4 diff → T2. §5 chain row → T3. §6 surface → T7 (portal) + T10 (CLI) + T4 (RBAC). §7 P1 corpus_digest compat → T1. §7 CC/testing → each task's tests + T9. §8 deferred → T11 ADR. **No spec section unmapped.**

**The 6 locked pins:** (1) corpus_digest byte-compat → T1 (both regression tests). (2) raw empty-corpus before validate → T7 route + `test_empty_corpus_400`. (3) cases keyed by case_id in candidate order → T2 `compute_replay_diff` + `test_cases_emitted_in_candidate_order_not_baseline_order`. (4) minimal value-free `eval.replay` row → T3 `append_replay_event` + `test_append_replay_event_writes_value_free_chain_row` (exact top-level + per-case key sets; no model/tier/raw). (5) wrong-tenant baseline → same 404 → T7 e2e (b). (6) partial-failure 5xx + non-idempotent → T6 (`run_replay` propagates) + T7 e2e (e) (`raise_server_exceptions=False`).

**Six review findings addressed (plan patch):** (P1) raw-output safety restored — `apply_raw_output` extracted to `runner.py` (shared with bulk-run, DRY) + applied in `run_replay` before persist + on/off+truncation test (T6); (P1) `baseline_outcome`/`candidate_outcome` added to `ReplayCaseDiffResponse` + route mapping + e2e (d) pin; (P2) baseline-only case emitted as `errored` after candidate-order cases + `test_baseline_only_case_emitted_as_errored_after_candidate_cases` (T2); (P2) store DI fail-closed — `test_store_unavailable_503` + `test_wrong_type_store_503` (T7); (P2) exact-key value-free chain assertion (T3); (P2) partial-failure e2e uses `TestClient(raise_server_exceptions=False)` + queryability via `EvalRunStore.get_run` (T7 e2e (e)).

**Type consistency:** `corpus_digest(corpus) -> str` (T1 def; T7 route call). `compute_replay_diff(*, baseline_run_id, candidate, baseline_cases, baseline_tier) -> ReplayDiff` (T2 def; T6 call). `EvalRunStore.append_replay_event(*, diff, actor_subject, tenant_id, request_id)` (T3 def; T6 call). `run_replay(*, corpus, baseline_run_id, baseline_cases, baseline_tier, gateway, store, target_tier, judge_tier, max_raw_output_chars, tenant_id, actor_subject, persist_raw_output) -> ReplayDiff` (T6 def; T7 call). `apply_raw_output(result, *, persist, max_chars) -> EvalRunResult` (T6 runner.py def; T6 bulk_routes + run_replay calls). `build_eval_replay_routes(*, max_cases, max_raw_output_chars, target_tier, judge_tier)` (T7 def; T8 call). `mint_eval_replay_request_id()` (T3 def; T6 call). All consistent.

**Deliberate, flagged (not placeholders):** T6 types `run_replay`'s `corpus`/`gateway`/`store` params as `Any` with function-body runtime imports to avoid a module-scope import cycle (`replay` ↔ `runner`/`storage`/`llm`) — flagged inline with a mypy-tightening fallback. T1's name-shadow on `corpus_digest` (import + kwarg) is flagged with an alias fallback. Both are specified concretely; all test/impl code is complete (no TBD/placeholder).
