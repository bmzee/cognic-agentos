# Sprint 12 — Evaluation Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the target-agnostic, scorer-agnostic bulk evaluation substrate (runner + strict corpus loader + Postgres eval storage + portal API + thin CLI + neutral reference corpus) on top of the already-merged `evaluation/judge.py`, per the committed spec `docs/superpowers/specs/2026-06-07-sprint-12-evaluation-harness-design.md` (ADR-010 amendment).

**Architecture:** A pure-library `EvalRunner` runs a loaded `Corpus` against an injected `EvaluationTarget` (Wave-1: `GatewayTarget` over the governed `LLMGateway`), scoring each case with injected `CaseScorer`s (`AssertionScorer` + `JudgeScorer`-reuses-`run_judge`). The portal is the single execution path: it runs synchronously under a corpus-size cap and persists the run + per-case results + a value-free `eval.bulk_run` chain row atomically via `DecisionHistoryStore.append_with_precondition`. The CLI never builds the runtime — it is a thin client + a local `--dry-run`.

**Tech Stack:** Python 3.12 · FastAPI · Pydantic v2 (strict) · SQLAlchemy Core + Alembic · Typer · PyYAML · `uv`.

---

## Process discipline (applies to EVERY task)

- **All Python via `uv run`.** No parallel/background `uv run` (venv-lock deadlock). Run sequentially.
- **TDD:** write the test, run it, WATCH IT FAIL for the right reason, implement minimally, run it green.
- **Explicit-path staging only.** Every commit stages exact file paths (`git add <path> <path>`), never `git add .`/`-A`/a directory. The two intentionally-untracked docs — `docs/reviews/` and `docs/superpowers/specs/2026-05-26-agentos-local-managed-agents-gap-analysis.md` — must stay out of every commit.
- **Commit footer:** every commit message ends with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- **Branch:** all work on `feat/sprint-12-evaluation-harness` (already checked out; the spec commit `00ad745` is its first commit).
- **HALT-BEFORE-COMMIT** on every task tagged **[CC]** or **[STOP-RULE]** below: produce a halt summary (files modified — say "modified", not "staged"; tests run + results; risks; the exact `git add` paths) and WAIT for an explicit full-word commit token. Tasks tagged **[normal]** commit at the end of the task without a separate halt, but still by explicit path.
- **Gate ladder:** at a [CC]/[STOP-RULE] commit, run the full suite (`uv run pytest -q`) plus `uv run ruff check .` + `uv run ruff format --check .` + `uv run mypy src tests`. For [normal] tasks, run the touched-scope tests + ruff/format/mypy. The single coverage-gate task (T15) additionally runs full `--cov --cov-branch` + `tools/check_critical_coverage.py`.
- **Spec file-placement refinements** baked into this plan (deliberate, noted where they occur): the strict `EvalCase`/`Corpus` Pydantic models live in **`corpus.py`** (the CC module that owns the corpus contract), not `types.py`; `EvalRunStore` takes a `DecisionHistoryStore` (not a raw engine); `run_id`/`chain_request_id` are passed into `EvalRunner.run(...)` by the route (the runner does not mint identity). These refine the spec's §1/§2 listings for a cleaner CC boundary and are recorded in the ADR-010 amendment (T16).

### Architecture-fence maintenance (cross-task — added at T2 fix-forward)

There is an inventory fence `tests/unit/architecture/test_eval_fences.py::test_eval_dir_has_expected_sources` that pins the **exact** `evaluation/*.py` source set. It is the **non-vacuous guard** for the two OS/pack import fences (`test_eval_imports_no_layer_c` + `test_eval_imports_no_agent_sdk`): without it, a vanished glob would let those import fences pass trivially over an empty source set.

Because the set is exact, **every task that ADDS a new `evaluation/*.py` file MUST update that expected set AND stage `tests/unit/architecture/test_eval_fences.py` in the SAME task commit**, so the full suite stays green per-commit. (The two import fences need no edit — they already iterate the whole glob and therefore guard each new module automatically.)

Per-task ledger of the expected source set:

- **T1 `types.py`** — landed in `f0ba561`; the matching fence update was folded forward into **T2** (transient-red T1 is acceptable here because the branch squash-merges, so no per-commit-green guarantee is owed mid-branch for T1).
- **T2 `corpus.py`** — set becomes `{__init__.py, judge.py, types.py, corpus.py}` (**this commit** — covers the deferred T1 `types.py` entry as well).
- **T3 `target.py`** — add `target.py` to the set.
- **T4 `scorers.py`** — add `scorers.py` to the set.
- **T5 `runner.py`** — add `runner.py` to the set.
- **T7 `storage.py`** — add `storage.py` to the set (the file is created in T7 Step 3a). (T8 adds no new `evaluation/*.py` file, so it makes no set change.)

---

## File structure

| File | Responsibility | Gate |
|---|---|---|
| `src/cognic_agentos/evaluation/types.py` | Result/outcome dataclasses + outcome Literals (`CandidateOutput`, `CriterionDetail`, `ScorerResult`, `CaseResult`, `EvalRunResult`, `CandidateOutputOutcome`, `CaseOutcome`) | off-gate |
| `src/cognic_agentos/evaluation/corpus.py` | Strict Pydantic `EvalCase`/`Corpus`/`AssertionsBlock`/`JudgeBlock`/`JudgeCriterionSpec` models + `CorpusLoadReason` + `CorpusLoadError` + `load_corpus(path)` + `validate_corpus_payload(dict)` | **[CC]** |
| `src/cognic_agentos/evaluation/target.py` | `EvaluationTarget` Protocol + `GatewayTarget` + the catchable-gateway-exception tuple | off-gate |
| `src/cognic_agentos/evaluation/scorers.py` | `CaseScorer` Protocol + `AssertionScorer` + `JudgeScorer` (reuses `run_judge`) | **[CC]** |
| `src/cognic_agentos/evaluation/runner.py` | `EvalRunner` (pure library) | **[CC]** |
| `src/cognic_agentos/evaluation/storage.py` | `_eval_runs`/`_eval_case_results` Tables + `EvalRunStore` (`append_with_precondition` consumer) + bounded request-id minter | **[CC]** |
| `src/cognic_agentos/db/migrations/versions/20260607_0008_eval_runs_and_case_results.py` | Alembic migration creating both tables | **[STOP-RULE]** |
| `src/cognic_agentos/core/config.py` | `eval_bulk_max_cases` / `eval_bulk_max_raw_output_chars` / `eval_bulk_target_tier` Settings | **[STOP-RULE]** |
| `src/cognic_agentos/portal/rbac/scopes.py` | Extend `EvalRBACScope` + `EVAL_SCOPES` with `eval.bulk.run` + `eval.runs.read` | **[STOP-RULE]** |
| `src/cognic_agentos/portal/api/evaluation/dto.py` | Bulk-run request/response DTOs (extend existing file) | off-gate |
| `src/cognic_agentos/portal/api/evaluation/bulk_routes.py` | `build_eval_bulk_routes(...)` (POST bulk-run + GET runs/{id}) + `EvalBulkRefusalReason` + request-id minter | **[STOP-RULE]** |
| `src/cognic_agentos/portal/api/app.py` | Mount the bulk router | **[STOP-RULE]** |
| `src/cognic_agentos/cli/__init__.py` + `src/cognic_agentos/cli/eval.py` | `agentos eval-bulk` flat command (thin client + `--dry-run`) | off-gate |
| `src/cognic_agentos/compliance/iso42001/controls.py` | Append `eval.bulk_run` to A.7.6 (flip to implemented) + A.9.2 | **[STOP-RULE]** |
| `src/cognic_agentos/evaluation/corpora/example/generic-completion-smoke.yaml` | Neutral reference corpus | off-gate |
| `tools/check_critical_coverage.py` + its test | Promote 4 CC modules (117→121) | **[CC]** |
| `docs/adrs/ADR-010-evaluation-harness.md` + `docs/BUILD_PLAN.md` | ADR-010 amendment + `eval/`→`evaluation/` path correction | **[STOP-RULE]** |

---

## Task 1 [normal]: Result + outcome types (`evaluation/types.py`)

**Files:**
- Create: `src/cognic_agentos/evaluation/types.py`
- Test: `tests/unit/evaluation/test_types.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/evaluation/test_types.py
from __future__ import annotations

import dataclasses

from cognic_agentos.evaluation.types import (
    CandidateOutput,
    CaseResult,
    CriterionDetail,
    EvalRunResult,
    ScorerResult,
)


def test_candidate_output_is_frozen_with_outcome() -> None:
    out = CandidateOutput(
        text="hello", model="m", tier="tier1", latency_ms=5, outcome="succeeded"
    )
    assert out.outcome == "succeeded"
    with __import__("pytest").raises(dataclasses.FrozenInstanceError):
        out.text = "x"  # type: ignore[misc]


def test_scorer_result_carries_criterion_detail_and_critique() -> None:
    detail = CriterionDetail(name="contains:capital adequacy", passed=False, critique="missing")
    sr = ScorerResult(
        scorer="assertions", passed=False, detail=(detail,), verdict=None, score=None, rationale=None
    )
    assert sr.detail[0].critique == "missing"
    assert sr.scorer == "assertions"


def test_eval_run_result_counts_and_identity_fields() -> None:
    import uuid

    case = CaseResult(
        case_id="c1",
        passed=True,
        outcome="succeeded",
        scorer_results=(),
        latency_ms=3,
        model="m",
        input_digest="i",
        output_digest="o",
        candidate_output_text=None,
        raw_output_persisted=False,
        output_truncated=False,
    )
    rid = uuid.uuid4()
    result = EvalRunResult(
        run_id=rid,
        chain_request_id="eval-run-abc",
        corpus_id="cp",
        corpus_digest="d",
        target_kind="gateway",
        tier="tier1",
        total=1,
        passed=1,
        failed=0,
        errored=0,
        latency_p50_ms=3,
        latency_p95_ms=3,
        cases=(case,),
    )
    assert result.run_id == rid
    assert result.total == result.passed + result.failed + result.errored
```

- [ ] **Step 2: Run it — expect FAIL** (`ModuleNotFoundError: cognic_agentos.evaluation.types`).

Run: `uv run pytest tests/unit/evaluation/test_types.py -q`

- [ ] **Step 3: Implement `evaluation/types.py`**

```python
# src/cognic_agentos/evaluation/types.py
"""Sprint 12 evaluation-harness runtime result types (ADR-010 amendment).

Pure dataclasses + closed Literals consumed by ``target.py`` / ``scorers.py`` /
``runner.py`` / ``storage.py``. NO I/O, NO Pydantic — the strict corpus *input*
models live in ``corpus.py`` (the CC module that owns the corpus contract).
"""

from __future__ import annotations

import dataclasses
import uuid
from typing import Literal

CandidateOutputOutcome = Literal["succeeded", "errored"]
CaseOutcome = Literal["succeeded", "errored"]
ScorerName = Literal["assertions", "judge"]


@dataclasses.dataclass(frozen=True, slots=True)
class CandidateOutput:
    """What an EvaluationTarget produces for one case."""

    text: str
    model: str
    tier: str
    latency_ms: int
    outcome: CandidateOutputOutcome
    error_category: str | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class CriterionDetail:
    """Per-assertion-clause / per-judge-criterion detail with an actionable critique."""

    name: str
    passed: bool
    critique: str


@dataclasses.dataclass(frozen=True, slots=True)
class ScorerResult:
    scorer: ScorerName
    passed: bool
    detail: tuple[CriterionDetail, ...]
    verdict: Literal["pass", "fail", "inconclusive"] | None = None
    score: float | None = None
    rationale: str | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class CaseResult:
    case_id: str
    passed: bool
    outcome: CaseOutcome
    scorer_results: tuple[ScorerResult, ...]
    latency_ms: int
    model: str
    input_digest: str
    output_digest: str
    candidate_output_text: str | None
    raw_output_persisted: bool
    output_truncated: bool


@dataclasses.dataclass(frozen=True, slots=True)
class EvalRunResult:
    run_id: uuid.UUID
    chain_request_id: str
    corpus_id: str
    corpus_digest: str
    target_kind: str
    tier: str
    total: int
    passed: int
    failed: int
    errored: int
    latency_p50_ms: int
    latency_p95_ms: int
    cases: tuple[CaseResult, ...]
```

- [ ] **Step 4: Run it — expect PASS.** Run: `uv run pytest tests/unit/evaluation/test_types.py -q`

- [ ] **Step 5: ruff + mypy, then commit.**

```bash
uv run ruff check src/cognic_agentos/evaluation/types.py tests/unit/evaluation/test_types.py
uv run ruff format --check src/cognic_agentos/evaluation/types.py tests/unit/evaluation/test_types.py
uv run mypy src/cognic_agentos/evaluation/types.py
git add src/cognic_agentos/evaluation/types.py tests/unit/evaluation/test_types.py
git commit -m "$(printf 'feat(eval): Sprint 12 evaluation result types\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 2 [CC]: Strict corpus contract + loader (`evaluation/corpus.py`)

**Files:**
- Create: `src/cognic_agentos/evaluation/corpus.py`
- Test: `tests/unit/evaluation/test_corpus.py`

This is the CC owner of the corpus contract: the strict Pydantic models (`extra="forbid"`) + the fail-closed `CorpusLoadReason` taxonomy + the directory loader.

- [ ] **Step 1: Write the failing tests** (one per `CorpusLoadReason` + the happy path)

```python
# tests/unit/evaluation/test_corpus.py
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from cognic_agentos.evaluation.corpus import (
    CorpusLoadError,
    load_corpus,
    validate_corpus_payload,
)

_GOOD = """\
schema_version: 1
corpus_id: smoke
description: demo
cases:
  - id: c1
    case_kind: completion
    messages:
      - role: system
        content: "Be precise."
      - role: user
        content: "Define CAR."
    assertions:
      contains: ["capital adequacy"]
"""


def _write(tmp_path: Path, name: str, body: str) -> Path:
    (tmp_path / name).write_text(textwrap.dedent(body), encoding="utf-8")
    return tmp_path


def test_loads_valid_corpus(tmp_path: Path) -> None:
    d = _write(tmp_path, "a.yaml", _GOOD)
    corpus = load_corpus(d)
    assert corpus.corpus_id == "smoke"
    assert len(corpus.cases) == 1
    assert corpus.cases[0].assertions is not None
    assert corpus.cases[0].assertions.contains == ["capital adequacy"]


def test_no_documents_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(CorpusLoadError) as e:
        load_corpus(tmp_path)
    assert e.value.reason == "corpus_no_documents"


def test_unknown_key_fails_closed(tmp_path: Path) -> None:
    d = _write(tmp_path, "a.yaml", _GOOD + "    surprise: 1\n")
    with pytest.raises(CorpusLoadError) as e:
        load_corpus(d)
    assert e.value.reason == "corpus_unknown_key"


def test_unsupported_schema_version_fails_closed(tmp_path: Path) -> None:
    d = _write(tmp_path, "a.yaml", _GOOD.replace("schema_version: 1", "schema_version: 2"))
    with pytest.raises(CorpusLoadError) as e:
        load_corpus(d)
    assert e.value.reason == "corpus_schema_version_unsupported"


def test_duplicate_case_id_across_files_fails_closed(tmp_path: Path) -> None:
    _write(tmp_path, "a.yaml", _GOOD)
    _write(tmp_path, "b.yaml", _GOOD.replace("corpus_id: smoke", "corpus_id: smoke2"))
    with pytest.raises(CorpusLoadError) as e:
        load_corpus(tmp_path)
    assert e.value.reason == "corpus_duplicate_case_id"


def test_case_without_scorer_fails_closed(tmp_path: Path) -> None:
    body = _GOOD.replace('    assertions:\n      contains: ["capital adequacy"]\n', "")
    d = _write(tmp_path, "a.yaml", body)
    with pytest.raises(CorpusLoadError) as e:
        load_corpus(d)
    assert e.value.reason == "corpus_case_no_scorer"


def test_unsupported_case_kind_fails_closed(tmp_path: Path) -> None:
    d = _write(tmp_path, "a.yaml", _GOOD.replace("case_kind: completion", "case_kind: replay"))
    with pytest.raises(CorpusLoadError) as e:
        load_corpus(d)
    assert e.value.reason == "corpus_case_kind_unsupported"


def test_unparseable_yaml_fails_closed(tmp_path: Path) -> None:
    d = _write(tmp_path, "a.yaml", "schema_version: 1\n  : : :\n")
    with pytest.raises(CorpusLoadError) as e:
        load_corpus(d)
    assert e.value.reason == "corpus_unparseable_yaml"


def test_validate_corpus_payload_shares_the_model(tmp_path: Path) -> None:
    # Portal path: validate an already-parsed dict against the SAME model.
    payload = {
        "schema_version": 1,
        "corpus_id": "smoke",
        "cases": [
            {
                "id": "c1",
                "case_kind": "completion",
                "messages": [{"role": "user", "content": "hi"}],
                "judge": {
                    "rubric": "is a greeting",
                    "criteria": [{"name": "greeting", "description": "says hello"}],
                },
            }
        ],
    }
    corpus = validate_corpus_payload(payload)
    assert corpus.cases[0].judge is not None
    assert corpus.cases[0].judge.criteria[0].description == "says hello"
```

- [ ] **Step 2: Run — expect FAIL** (`ModuleNotFoundError`). Run: `uv run pytest tests/unit/evaluation/test_corpus.py -q`

- [ ] **Step 3: Implement `evaluation/corpus.py`**

```python
# src/cognic_agentos/evaluation/corpus.py
"""Sprint 12 corpus contract + fail-closed loader (ADR-010 amendment) — CC.

The strict Pydantic models (``extra="forbid"``) ARE the single source of truth
for corpus validity: ``load_corpus(path)`` is the directory/YAML wrapper used by
the CLI ``--dry-run``; ``validate_corpus_payload(dict)`` validates an already-
parsed inline body (the portal path) against the SAME models. A corpus valid for
one is valid for the other — no second validator to drift.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

_SUPPORTED_SCHEMA_VERSION = 1

CorpusLoadReason = Literal[
    "corpus_no_documents",
    "corpus_unparseable_yaml",
    "corpus_unknown_key",
    "corpus_schema_version_unsupported",
    "corpus_duplicate_case_id",
    "corpus_case_no_scorer",
    "corpus_case_kind_unsupported",
    "corpus_case_messages_invalid",
]


class CorpusLoadError(Exception):
    """Fail-closed corpus rejection carrying a closed-enum ``reason``."""

    def __init__(self, reason: CorpusLoadReason, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason: CorpusLoadReason = reason
        self.detail = detail


class _Message(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    role: Literal["system", "user", "assistant"]
    content: str = Field(min_length=1, max_length=50_000)


class AssertionsBlock(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    contains: list[str] = Field(default_factory=list)
    not_contains: list[str] = Field(default_factory=list)
    regex: list[str] = Field(default_factory=list)
    json_path: list[dict[str, Any]] = Field(default_factory=list)

    @model_validator(mode="after")
    def _at_least_one_clause(self) -> AssertionsBlock:
        if not (self.contains or self.not_contains or self.regex or self.json_path):
            raise ValueError("assertions block declares no clauses")
        return self


class JudgeCriterionSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=2_000)
    weight: float | None = None  # recorded; non-gating in Sprint 12


class JudgeBlock(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    rubric: str | None = Field(default=None, max_length=2_000)
    criteria: list[JudgeCriterionSpec] = Field(min_length=1, max_length=20)


class EvalCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(min_length=1, max_length=200)
    case_kind: Literal["completion"]
    messages: list[_Message] = Field(min_length=1)
    assertions: AssertionsBlock | None = None
    judge: JudgeBlock | None = None

    @model_validator(mode="after")
    def _declares_a_scorer(self) -> EvalCase:
        if self.assertions is None and self.judge is None:
            raise ValueError("case declares neither assertions nor judge")
        return self


class Corpus(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: int
    corpus_id: str = Field(min_length=1, max_length=200)
    description: str | None = None
    cases: list[EvalCase] = Field(min_length=1)


def _reason_for_validation_error(exc: ValidationError) -> CorpusLoadReason:
    """Map a pydantic ValidationError to the closed CorpusLoadReason taxonomy."""
    for err in exc.errors():
        etype = err.get("type", "")
        loc = err.get("loc", ())
        if etype == "extra_forbidden":
            return "corpus_unknown_key"
        if "case_kind" in loc:
            return "corpus_case_kind_unsupported"
        if "messages" in loc:
            return "corpus_case_messages_invalid"
        msg = str(err.get("msg", ""))
        if "neither assertions nor judge" in msg:
            return "corpus_case_no_scorer"
    return "corpus_case_messages_invalid"


def validate_corpus_payload(payload: dict[str, Any]) -> Corpus:
    """Validate an already-parsed corpus dict against the strict models."""
    if payload.get("schema_version") != _SUPPORTED_SCHEMA_VERSION:
        raise CorpusLoadError(
            "corpus_schema_version_unsupported",
            f"expected {_SUPPORTED_SCHEMA_VERSION}, got {payload.get('schema_version')!r}",
        )
    try:
        return Corpus.model_validate(payload)
    except ValidationError as exc:
        raise CorpusLoadError(_reason_for_validation_error(exc), str(exc)) from exc


def load_corpus(path: Path) -> Corpus:
    """Load + merge every ``*.yaml``/``*.yml`` under ``path`` into one Corpus.

    Deterministic sorted file order; duplicate ``case.id`` across files fails
    closed; the merged corpus inherits the FIRST document's corpus_id/description.
    """
    files = sorted(p for p in path.glob("*.y*ml") if p.suffix in {".yaml", ".yml"})
    if not files:
        raise CorpusLoadError("corpus_no_documents", str(path))

    merged_cases: list[dict[str, Any]] = []
    head: dict[str, Any] | None = None
    seen_ids: set[str] = set()
    for f in files:
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise CorpusLoadError("corpus_unparseable_yaml", f"{f.name}: {exc}") from exc
        if not isinstance(doc, dict):
            raise CorpusLoadError("corpus_unparseable_yaml", f"{f.name}: not a mapping")
        # Validate each document strictly first (catches unknown keys / kinds).
        corpus_doc = validate_corpus_payload(doc)
        if head is None:
            head = {"corpus_id": corpus_doc.corpus_id, "description": corpus_doc.description}
        for case in corpus_doc.cases:
            if case.id in seen_ids:
                raise CorpusLoadError("corpus_duplicate_case_id", case.id)
            seen_ids.add(case.id)
            merged_cases.append(case.model_dump())

    assert head is not None  # files non-empty ⇒ head set
    return validate_corpus_payload(
        {
            "schema_version": _SUPPORTED_SCHEMA_VERSION,
            "corpus_id": head["corpus_id"],
            "description": head["description"],
            "cases": merged_cases,
        }
    )
```

- [ ] **Step 4: Run — expect PASS.** Run: `uv run pytest tests/unit/evaluation/test_corpus.py -q`

- [ ] **Step 5: HALT-BEFORE-COMMIT [CC].** Run the full gate ladder, then produce a halt summary (files modified, tests + results, the exact `git add` paths below) and WAIT for a commit token.

```bash
uv run pytest -q
uv run ruff check . && uv run ruff format --check . && uv run mypy src tests
# stage ONLY:
git add src/cognic_agentos/evaluation/corpus.py tests/unit/evaluation/test_corpus.py
git commit -m "$(printf 'feat(eval): strict fail-closed corpus contract + loader (ADR-010)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 3 [normal]: Evaluation target seam + GatewayTarget (`evaluation/target.py`)

**Files:**
- Create: `src/cognic_agentos/evaluation/target.py`
- Test: `tests/unit/evaluation/test_target.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/evaluation/test_target.py
from __future__ import annotations

import pytest

from cognic_agentos.evaluation.corpus import EvalCase
from cognic_agentos.evaluation.target import GatewayTarget
from cognic_agentos.llm.gateway import GatewayResponse
from cognic_agentos.llm.concurrency import LLMConcurrencyExceeded


def _case() -> EvalCase:
    return EvalCase.model_validate(
        {
            "id": "c1",
            "case_kind": "completion",
            "messages": [{"role": "user", "content": "hi"}],
            "assertions": {"contains": ["x"]},
        }
    )


class _FakeGateway:
    def __init__(self, *, content: str | None = None, raise_exc: Exception | None = None) -> None:
        self._content = content
        self._raise = raise_exc
        self.calls: list[dict] = []

    async def completion(self, *, tier, messages, request_id, tenant_id=None):  # type: ignore[no-untyped-def]
        self.calls.append({"tier": tier, "messages": messages})
        if self._raise is not None:
            raise self._raise
        return GatewayResponse(
            content=self._content or "",
            upstream_model="m",
            api_base=None,
            external=False,
            request_id=request_id,
            tier=tier,
            latency_ms=7,
        )


@pytest.mark.asyncio
async def test_gateway_target_succeeds_and_maps_messages() -> None:
    gw = _FakeGateway(content="capital adequacy ratio")
    target = GatewayTarget(gateway=gw, tier="tier1")  # type: ignore[arg-type]
    assert target.tier == "tier1"
    out = await target.run_case(_case(), request_id="r1", tenant_id="t1")
    assert out.outcome == "succeeded"
    assert out.text == "capital adequacy ratio"
    assert out.model == "m"
    assert gw.calls[0]["messages"] == [{"role": "user", "content": "hi"}]


@pytest.mark.asyncio
async def test_gateway_target_catches_gateway_exception_as_errored() -> None:
    gw = _FakeGateway(raise_exc=LLMConcurrencyExceeded("no slot"))
    target = GatewayTarget(gateway=gw, tier="tier1")  # type: ignore[arg-type]
    out = await target.run_case(_case(), request_id="r1", tenant_id="t1")
    assert out.outcome == "errored"
    assert out.error_category == "LLMConcurrencyExceeded"
    assert out.text == ""
```

- [ ] **Step 2: Run — expect FAIL.** Run: `uv run pytest tests/unit/evaluation/test_target.py -q`

- [ ] **Step 3: Implement `evaluation/target.py`**

```python
# src/cognic_agentos/evaluation/target.py
"""Sprint 12 evaluation target seam (ADR-010 amendment).

``EvaluationTarget`` is the Sprint-13 plug-in surface (MCP / A2A / replay targets
conform later). ``GatewayTarget`` is the only Wave-1 target: it dispatches a case's
message list through the governed ``LLMGateway`` at the operator-configured
``eval_bulk_target_tier`` and catches the known gateway exceptions, surfacing them
as an ``errored`` CandidateOutput so a single bad case never aborts the run.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from cognic_agentos.evaluation.types import CandidateOutput
from cognic_agentos.llm.concurrency import LLMConcurrencyExceeded
from cognic_agentos.llm.gateway import LedgerWriteFailed, UnknownTierError
from cognic_agentos.llm.policy import CloudPolicyViolationError, GuardrailViolationError
from cognic_agentos.llm.preflight import UnknownAliasError

if TYPE_CHECKING:
    from cognic_agentos.evaluation.corpus import EvalCase
    from cognic_agentos.llm.gateway import LLMGateway

#: The closed set of gateway exceptions a target converts to an ``errored`` case.
#: SLA breaches do NOT raise (audit-only), so there is no SLA exception here.
_GATEWAY_EXCEPTIONS: tuple[type[Exception], ...] = (
    LLMConcurrencyExceeded,
    CloudPolicyViolationError,
    GuardrailViolationError,
    UnknownAliasError,
    UnknownTierError,
    LedgerWriteFailed,
)


class EvaluationTarget(Protocol):
    async def run_case(
        self, case: EvalCase, *, request_id: str, tenant_id: str
    ) -> CandidateOutput: ...


class GatewayTarget:
    """Wave-1 target — one governed ``completion()`` per case."""

    target_kind = "gateway"

    def __init__(self, *, gateway: LLMGateway, tier: str) -> None:
        self._gateway = gateway
        self._tier = tier

    @property
    def tier(self) -> str:
        return self._tier

    async def run_case(
        self, case: EvalCase, *, request_id: str, tenant_id: str
    ) -> CandidateOutput:
        messages = [{"role": m.role, "content": m.content} for m in case.messages]
        try:
            resp = await self._gateway.completion(
                tier=self._tier,
                messages=messages,
                request_id=request_id,
                tenant_id=tenant_id,
            )
        except _GATEWAY_EXCEPTIONS as exc:
            return CandidateOutput(
                text="",
                model="",
                tier=self._tier,
                latency_ms=0,
                outcome="errored",
                error_category=type(exc).__name__,
            )
        return CandidateOutput(
            text=resp.content,
            model=resp.upstream_model,
            tier=resp.tier,
            latency_ms=resp.latency_ms,
            outcome="succeeded",
        )
```

- [ ] **Step 4: Run — expect PASS.** Run: `uv run pytest tests/unit/evaluation/test_target.py -q`

- [ ] **Step 5: ruff + mypy, commit by path.**

```bash
uv run ruff check src/cognic_agentos/evaluation/target.py tests/unit/evaluation/test_target.py
uv run ruff format --check src/cognic_agentos/evaluation/target.py tests/unit/evaluation/test_target.py
uv run mypy src/cognic_agentos/evaluation/target.py
git add src/cognic_agentos/evaluation/target.py tests/unit/evaluation/test_target.py
git commit -m "$(printf 'feat(eval): EvaluationTarget seam + GatewayTarget (ADR-010)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 4 [CC]: Scorers — assertions + judge (`evaluation/scorers.py`)

**Files:**
- Create: `src/cognic_agentos/evaluation/scorers.py`
- Test: `tests/unit/evaluation/test_scorers.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/evaluation/test_scorers.py
from __future__ import annotations

import pytest

from cognic_agentos.evaluation.corpus import EvalCase
from cognic_agentos.evaluation.scorers import AssertionScorer, JudgeScorer
from cognic_agentos.evaluation.types import CandidateOutput
from cognic_agentos.llm.gateway import GatewayResponse


def _case(payload: dict) -> EvalCase:
    base = {"id": "c1", "case_kind": "completion", "messages": [{"role": "user", "content": "q"}]}
    base.update(payload)
    return EvalCase.model_validate(base)


def _out(text: str) -> CandidateOutput:
    return CandidateOutput(text=text, model="m", tier="tier1", latency_ms=1, outcome="succeeded")


@pytest.mark.asyncio
async def test_assertion_scorer_contains_pass_and_fail() -> None:
    case = _case({"assertions": {"contains": ["capital adequacy"], "not_contains": ["wrong"]}})
    sc = AssertionScorer()
    ok = await sc.score(case, _out("capital adequacy ratio"), request_id="r", tenant_id="t")
    assert ok.passed is True and ok.scorer == "assertions"
    bad = await sc.score(case, _out("nope wrong nope"), request_id="r", tenant_id="t")
    assert bad.passed is False
    assert any(not d.passed for d in bad.detail)
    assert all(isinstance(d.critique, str) and d.critique for d in bad.detail)


@pytest.mark.asyncio
async def test_assertion_scorer_regex() -> None:
    case = _case({"assertions": {"regex": [r"\bCAR\b"]}})
    sc = AssertionScorer()
    assert (await sc.score(case, _out("the CAR metric"), request_id="r", tenant_id="t")).passed
    assert not (await sc.score(case, _out("scared"), request_id="r", tenant_id="t")).passed


class _FakeGateway:
    def __init__(self, content: str) -> None:
        self._content = content

    async def completion(self, *, tier, messages, request_id, tenant_id=None):  # type: ignore[no-untyped-def]
        return GatewayResponse(
            content=self._content,
            upstream_model="judge-m",
            api_base=None,
            external=False,
            request_id=request_id,
            tier=tier,
            latency_ms=9,
        )


@pytest.mark.asyncio
async def test_judge_scorer_passes_on_verdict_pass() -> None:
    case = _case(
        {"judge": {"rubric": "greeting", "criteria": [{"name": "g", "description": "says hi"}]}}
    )
    content = '{"verdict": "pass", "score": 0.9, "rationale": "ok", "criteria_results": [{"name": "g", "passed": true, "note": "yes"}]}'
    sc = JudgeScorer(gateway=_FakeGateway(content), tier="tier1")  # type: ignore[arg-type]
    res = await sc.score(case, _out("hello there"), request_id="r", tenant_id="t")
    assert res.scorer == "judge"
    assert res.passed is True
    assert res.verdict == "pass"
    assert res.detail[0].name == "g" and res.detail[0].passed is True


@pytest.mark.asyncio
async def test_judge_scorer_fails_on_verdict_fail() -> None:
    case = _case(
        {"judge": {"rubric": "greeting", "criteria": [{"name": "g", "description": "says hi"}]}}
    )
    content = '{"verdict": "fail", "score": 0.1, "rationale": "no", "criteria_results": [{"name": "g", "passed": false, "note": "nope"}]}'
    sc = JudgeScorer(gateway=_FakeGateway(content), tier="tier1")  # type: ignore[arg-type]
    res = await sc.score(case, _out("goodbye"), request_id="r", tenant_id="t")
    assert res.passed is False and res.verdict == "fail"


@pytest.mark.asyncio
async def test_judge_scorer_unparseable_fails_with_parse_reason_critique() -> None:
    case = _case(
        {"judge": {"rubric": "greeting", "criteria": [{"name": "g", "description": "says hi"}]}}
    )
    sc = JudgeScorer(gateway=_FakeGateway("not json at all"), tier="tier1")  # type: ignore[arg-type]
    res = await sc.score(case, _out("x"), request_id="r", tenant_id="t")
    assert res.passed is False
    assert res.detail[0].critique == "not_json"
```

- [ ] **Step 2: Run — expect FAIL.** Run: `uv run pytest tests/unit/evaluation/test_scorers.py -q`

- [ ] **Step 3: Implement `evaluation/scorers.py`**

```python
# src/cognic_agentos/evaluation/scorers.py
"""Sprint 12 case scorers (ADR-010 amendment) — CC.

Deterministic ``AssertionScorer`` (no tokens) + ``JudgeScorer`` that REUSES the
merged ``run_judge(...)`` primitive (no duplicated judge logic). Both emit a
``ScorerResult`` carrying per-clause/criterion ``CriterionDetail`` + critique so a
failure is actionable. ``CaseScorer`` is the Sprint-13 plug-in surface.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Protocol

from cognic_agentos.evaluation.judge import JudgeParsed, run_judge
from cognic_agentos.evaluation.types import CandidateOutput, CriterionDetail, ScorerResult
from cognic_agentos.portal.api.evaluation.dto import JudgeCriterion, JudgeRequest

if TYPE_CHECKING:
    from cognic_agentos.evaluation.corpus import EvalCase
    from cognic_agentos.llm.gateway import LLMGateway


class CaseScorer(Protocol):
    async def score(
        self, case: EvalCase, output: CandidateOutput, *, request_id: str, tenant_id: str
    ) -> ScorerResult: ...


class AssertionScorer:
    """Deterministic closed-set assertion scorer."""

    async def score(
        self, case: EvalCase, output: CandidateOutput, *, request_id: str, tenant_id: str
    ) -> ScorerResult:
        assert case.assertions is not None  # only invoked when the case declares assertions
        a = case.assertions
        text = output.text
        details: list[CriterionDetail] = []
        for needle in a.contains:
            ok = needle in text
            details.append(
                CriterionDetail(
                    name=f"contains:{needle}",
                    passed=ok,
                    critique="" if ok else f'expected substring "{needle}" not found',
                )
            )
        for needle in a.not_contains:
            ok = needle not in text
            details.append(
                CriterionDetail(
                    name=f"not_contains:{needle}",
                    passed=ok,
                    critique="" if ok else f'forbidden substring "{needle}" present',
                )
            )
        for pattern in a.regex:
            ok = re.search(pattern, text) is not None
            details.append(
                CriterionDetail(
                    name=f"regex:{pattern}",
                    passed=ok,
                    critique="" if ok else f"pattern /{pattern}/ did not match",
                )
            )
        for clause in a.json_path:
            ok, critique = self._eval_json_path(text, clause)
            details.append(
                CriterionDetail(name=f"json_path:{clause.get('path')}", passed=ok, critique=critique)
            )
        passed = all(d.passed for d in details)
        return ScorerResult(scorer="assertions", passed=passed, detail=tuple(details))

    @staticmethod
    def _eval_json_path(text: str, clause: dict) -> tuple[bool, str]:
        import json

        path = str(clause.get("path", ""))
        expected = clause.get("equals")
        try:
            doc = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return False, "candidate output is not valid JSON"
        cur: object = doc
        for seg in [p for p in path.split(".") if p]:
            if not isinstance(cur, dict) or seg not in cur:
                return False, f"json path {path!r} not found"
            cur = cur[seg]
        ok = cur == expected
        return ok, "" if ok else f"json path {path!r} = {cur!r}, expected {expected!r}"


class JudgeScorer:
    """Reuses run_judge; passes iff verdict == 'pass'."""

    def __init__(self, *, gateway: LLMGateway, tier: str) -> None:
        self._gateway = gateway
        self._tier = tier

    async def score(
        self, case: EvalCase, output: CandidateOutput, *, request_id: str, tenant_id: str
    ) -> ScorerResult:
        assert case.judge is not None  # only invoked when the case declares a judge block
        user_input = next((m.content for m in case.messages if m.role == "user"), None)
        request = JudgeRequest(
            candidate_output=output.text or " ",
            candidate_input=user_input,
            criteria=[JudgeCriterion(name=c.name, description=c.description) for c in case.judge.criteria],
        )
        outcome = await run_judge(
            request=request,
            gateway=self._gateway,
            request_id=request_id,
            tenant_id=tenant_id,
            tier=self._tier,
        )
        if isinstance(outcome, JudgeParsed):
            details = tuple(
                CriterionDetail(name=r.name, passed=r.passed, critique=r.note)
                for r in outcome.criteria_results
            )
            return ScorerResult(
                scorer="judge",
                passed=outcome.verdict == "pass",
                detail=details,
                verdict=outcome.verdict,
                score=outcome.score,
                rationale=outcome.rationale,
            )
        # JudgeUnparseable — fail-closed with the parse_reason as critique.
        return ScorerResult(
            scorer="judge",
            passed=False,
            detail=(CriterionDetail(name="judge", passed=False, critique=outcome.parse_reason),),
            verdict=None,
            score=None,
            rationale=None,
        )
```

> **Note for the implementer:** `run_judge` does NOT catch gateway exceptions — they propagate out of `JudgeScorer.score`. That is intentional: the `EvalRunner` (Task 5) wraps each scorer call in a per-case `try/except` that converts any exception to an `errored` case. Do not add a broad `except` here.

- [ ] **Step 4: Run — expect PASS.** Run: `uv run pytest tests/unit/evaluation/test_scorers.py -q`

- [ ] **Step 5: HALT-BEFORE-COMMIT [CC].** Full gate ladder, halt summary, wait for token.

```bash
uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy src tests
git add src/cognic_agentos/evaluation/scorers.py tests/unit/evaluation/test_scorers.py
git commit -m "$(printf 'feat(eval): deterministic + judge case scorers (ADR-010)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 5 [CC]: Pure runner (`evaluation/runner.py`)

**Files:**
- Create: `src/cognic_agentos/evaluation/runner.py`
- Test: `tests/unit/evaluation/test_runner.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/evaluation/test_runner.py
from __future__ import annotations

import uuid

import pytest

from cognic_agentos.evaluation.corpus import validate_corpus_payload
from cognic_agentos.evaluation.runner import EvalRunner
from cognic_agentos.evaluation.types import CandidateOutput, CriterionDetail, ScorerResult


def _corpus(*case_ids: str):
    return validate_corpus_payload(
        {
            "schema_version": 1,
            "corpus_id": "cp",
            "cases": [
                {
                    "id": cid,
                    "case_kind": "completion",
                    "messages": [{"role": "user", "content": "q"}],
                    "assertions": {"contains": ["ok"]},
                }
                for cid in case_ids
            ],
        }
    )


class _Target:
    target_kind = "gateway"

    def __init__(self, *, outcomes: dict[str, CandidateOutput], raise_on: str | None = None) -> None:
        self._outcomes = outcomes
        self._raise_on = raise_on

    async def run_case(self, case, *, request_id, tenant_id):  # type: ignore[no-untyped-def]
        if case.id == self._raise_on:
            raise RuntimeError("boom")
        return self._outcomes[case.id]


class _Scorer:
    def __init__(self, results: dict[str, bool]) -> None:
        self._results = results

    async def score(self, case, output, *, request_id, tenant_id):  # type: ignore[no-untyped-def]
        ok = self._results[case.id]
        return ScorerResult(
            scorer="assertions",
            passed=ok,
            detail=(CriterionDetail(name="x", passed=ok, critique="" if ok else "no"),),
        )


def _ok(text: str = "ok") -> CandidateOutput:
    return CandidateOutput(text=text, model="m", tier="tier1", latency_ms=5, outcome="succeeded")


@pytest.mark.asyncio
async def test_run_aggregates_pass_fail_counts() -> None:
    corpus = _corpus("a", "b")
    target = _Target(outcomes={"a": _ok(), "b": _ok()})
    scorer = _Scorer({"a": True, "b": False})
    runner = EvalRunner()
    rid = uuid.uuid4()
    result = await runner.run(
        corpus, target=target, scorers=[scorer], run_id=rid, chain_request_id="r", tenant_id="t1"
    )
    assert result.total == 2 and result.passed == 1 and result.failed == 1 and result.errored == 0
    assert result.run_id == rid and result.chain_request_id == "r"
    assert result.target_kind == "gateway"


@pytest.mark.asyncio
async def test_target_errored_skips_scorers_and_counts_errored() -> None:
    corpus = _corpus("a")
    target = _Target(
        outcomes={"a": CandidateOutput(text="", model="", tier="tier1", latency_ms=0, outcome="errored", error_category="LLMConcurrencyExceeded")}
    )
    scorer = _Scorer({"a": True})  # would pass — must be skipped
    result = await EvalRunner().run(
        corpus, target=target, scorers=[scorer], run_id=uuid.uuid4(), chain_request_id="r", tenant_id="t1"
    )
    assert result.errored == 1 and result.passed == 0 and result.failed == 0
    assert result.cases[0].outcome == "errored"
    assert result.cases[0].scorer_results == ()


@pytest.mark.asyncio
async def test_scorer_exception_isolates_to_errored_case() -> None:
    corpus = _corpus("a", "b")
    target = _Target(outcomes={"a": _ok(), "b": _ok()}, raise_on="a")  # target raises on 'a'
    result = await EvalRunner().run(
        corpus, target=target, scorers=[_Scorer({"a": True, "b": True})],
        run_id=uuid.uuid4(), chain_request_id="r", tenant_id="t1",
    )
    assert result.errored == 1 and result.passed == 1  # 'a' errored, 'b' passed, run continued


@pytest.mark.asyncio
async def test_capture_raw_output_true_carries_candidate_text() -> None:
    corpus = _corpus("a")
    target = _Target(outcomes={"a": _ok("raw answer")})
    result = await EvalRunner().run(
        corpus,
        target=target,
        scorers=[_Scorer({"a": True})],
        run_id=uuid.uuid4(),
        chain_request_id="r",
        tenant_id="t1",
        capture_raw_output=True,
    )
    assert result.cases[0].candidate_output_text == "raw answer"
    assert result.cases[0].raw_output_persisted is False
```

- [ ] **Step 2: Run — expect FAIL.** Run: `uv run pytest tests/unit/evaluation/test_runner.py -q`

- [ ] **Step 3: Implement `evaluation/runner.py`**

```python
# src/cognic_agentos/evaluation/runner.py
"""Sprint 12 bulk eval runner (ADR-010 amendment) — CC.

Pure library: target- and scorer-agnostic. Per-case error isolation is the
governing rule — a single failed case (target raises / returns errored, OR a
scorer raises) becomes an ``errored`` CaseResult and the run continues. A case
passes iff every declared scorer passes. NO I/O — identity (run_id /
chain_request_id) is passed in by the caller; persistence is the store's job.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import TYPE_CHECKING

from cognic_agentos.evaluation.types import CandidateOutput, CaseResult, EvalRunResult, ScorerResult

if TYPE_CHECKING:
    from cognic_agentos.evaluation.corpus import Corpus, EvalCase
    from cognic_agentos.evaluation.scorers import CaseScorer
    from cognic_agentos.evaluation.target import EvaluationTarget


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _percentile(values: list[int], pct: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(round((pct / 100.0) * (len(ordered) - 1))))
    return ordered[idx]


def _errored_case(case_id: str, *, input_digest: str, output: CandidateOutput | None) -> CaseResult:
    return CaseResult(
        case_id=case_id,
        passed=False,
        outcome="errored",
        scorer_results=(),
        latency_ms=output.latency_ms if output is not None else 0,
        model=output.model if output is not None else "",
        input_digest=input_digest,
        output_digest=_digest(output.text if output is not None else ""),
        candidate_output_text=None,
        raw_output_persisted=False,
        output_truncated=False,
    )


class EvalRunner:
    async def run(
        self,
        corpus: Corpus,
        *,
        target: EvaluationTarget,
        scorers: list[CaseScorer],
        run_id: uuid.UUID,
        chain_request_id: str,
        tenant_id: str,
        capture_raw_output: bool = False,
    ) -> EvalRunResult:
        cases: list[CaseResult] = [
            await self._run_case(
                case,
                target=target,
                scorers=scorers,
                chain_request_id=chain_request_id,
                tenant_id=tenant_id,
                capture_raw_output=capture_raw_output,
            )
            for case in corpus.cases
        ]
        passed = sum(1 for c in cases if c.outcome == "succeeded" and c.passed)
        failed = sum(1 for c in cases if c.outcome == "succeeded" and not c.passed)
        errored = sum(1 for c in cases if c.outcome == "errored")
        latencies = [c.latency_ms for c in cases]
        return EvalRunResult(
            run_id=run_id,
            chain_request_id=chain_request_id,
            corpus_id=corpus.corpus_id,
            corpus_digest=_digest(corpus.model_dump_json()),
            target_kind=getattr(target, "target_kind", "gateway"),
            tier=getattr(target, "tier", ""),
            total=len(cases),
            passed=passed,
            failed=failed,
            errored=errored,
            latency_p50_ms=_percentile(latencies, 50),
            latency_p95_ms=_percentile(latencies, 95),
            cases=tuple(cases),
        )

    async def _run_case(
        self,
        case: EvalCase,
        *,
        target: EvaluationTarget,
        scorers: list[CaseScorer],
        chain_request_id: str,
        tenant_id: str,
        capture_raw_output: bool,
    ) -> CaseResult:
        user_input = next((m.content for m in case.messages if m.role == "user"), "")
        input_digest = _digest(user_input)
        try:
            output = await target.run_case(case, request_id=chain_request_id, tenant_id=tenant_id)
            if output.outcome == "errored":
                return _errored_case(case.id, input_digest=input_digest, output=output)
            scorer_results: list[ScorerResult] = [
                await scorer.score(case, output, request_id=chain_request_id, tenant_id=tenant_id)
                for scorer in self._applicable_scorers(case, scorers)
            ]
            return CaseResult(
                case_id=case.id,
                passed=all(s.passed for s in scorer_results),
                outcome="succeeded",
                scorer_results=tuple(scorer_results),
                latency_ms=output.latency_ms,
                model=output.model,
                input_digest=input_digest,
                output_digest=_digest(output.text),
                candidate_output_text=output.text if capture_raw_output else None,
                raw_output_persisted=False,
                output_truncated=False,
            )
        except Exception:  # per-case isolation; a single bad case never aborts the run
            return _errored_case(case.id, input_digest=input_digest, output=None)

    @staticmethod
    def _applicable_scorers(case: EvalCase, scorers: list[CaseScorer]) -> list[CaseScorer]:
        out: list[CaseScorer] = []
        for s in scorers:
            name = type(s).__name__
            if name == "AssertionScorer" and case.assertions is None:
                continue
            if name == "JudgeScorer" and case.judge is None:
                continue
            out.append(s)
        return out
```

- [ ] **Step 4: Run — expect PASS.** Run: `uv run pytest tests/unit/evaluation/test_runner.py -q`

- [ ] **Step 5: HALT-BEFORE-COMMIT [CC].** Full gate ladder, halt summary, wait for token.

```bash
uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy src tests
git add src/cognic_agentos/evaluation/runner.py tests/unit/evaluation/test_runner.py
git commit -m "$(printf 'feat(eval): pure target/scorer-agnostic bulk runner (ADR-010)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 6 [STOP-RULE]: Settings (`core/config.py`)

**Files:**
- Modify: `src/cognic_agentos/core/config.py` (add three fields near `eval_judge_tier`, ~line 526)
- Test: `tests/unit/core/test_config_eval_bulk.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/core/test_config_eval_bulk.py
from __future__ import annotations

import pytest
from pydantic import ValidationError

from cognic_agentos.core.config import Settings


def test_eval_bulk_settings_defaults() -> None:
    s = Settings()
    assert s.eval_bulk_max_cases == 50
    assert s.eval_bulk_max_raw_output_chars == 50_000
    assert s.eval_bulk_target_tier == "tier1"


def test_eval_bulk_max_cases_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        Settings(eval_bulk_max_cases=0)


def test_eval_bulk_target_tier_is_closed_enum() -> None:
    with pytest.raises(ValidationError):
        Settings(eval_bulk_target_tier="tier3")  # type: ignore[arg-type]
```

- [ ] **Step 2: Run — expect FAIL** (`AttributeError`/unexpected default). Run: `uv run pytest tests/unit/core/test_config_eval_bulk.py -q`

- [ ] **Step 3: Add the three fields** immediately after the `eval_judge_tier` Field (after `core/config.py:532`):

```python
    eval_bulk_target_tier: Literal["tier1", "tier2"] = Field(
        default="tier1",
        description=(
            "Logical tier the Sprint-12 bulk-eval GatewayTarget (the model UNDER "
            "TEST) dispatches against. Distinct from eval_judge_tier (the "
            "evaluator). Operator-configured; callers cannot choose. Per ADR-010 "
            "amendment."
        ),
    )
    eval_bulk_max_cases: int = Field(
        default=50,
        gt=0,
        description=(
            "Max cases a single synchronous POST /api/v1/eval/bulk-run may carry. "
            "Over-cap corpora are refused 413 eval_corpus_too_large. Kept low "
            "because a synchronous run with judge scoring can otherwise run long; "
            "background large-corpus runs are deferred. Per ADR-010 amendment."
        ),
    )
    eval_bulk_max_raw_output_chars: int = Field(
        default=50_000,
        gt=0,
        description=(
            "Truncation bound for per-case candidate_output_text persisted when "
            "persist_raw_output=true. Matches the judge candidate bound. Per "
            "ADR-010 amendment."
        ),
    )
```

- [ ] **Step 4: Run — expect PASS.** Run: `uv run pytest tests/unit/core/test_config_eval_bulk.py -q`

- [ ] **Step 5: HALT-BEFORE-COMMIT [STOP-RULE]** (`core/config.py` is a stop-rule surface). Full gate ladder; halt summary; wait for token.

```bash
uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy src tests
git add src/cognic_agentos/core/config.py tests/unit/core/test_config_eval_bulk.py
git commit -m "$(printf 'feat(eval): eval-bulk Settings (cap + raw-output bound + target tier)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 7 [STOP-RULE]: Alembic migration 0008 + in-process Tables

**Files:**
- Create: `src/cognic_agentos/db/migrations/versions/20260607_0008_eval_runs_and_case_results.py`
- Create (Tables only, store body in Task 8): `src/cognic_agentos/evaluation/storage.py` (Table defs + imports)
- Test: `tests/unit/db/test_migration_20260607_0008.py`

- [ ] **Step 1: Write the failing migration round-trip + drift test**

```python
# tests/unit/db/test_migration_20260607_0008.py
from __future__ import annotations

import asyncio
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine


async def _migrated_engine(tmp_path: Any) -> Any:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'eval.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    return create_async_engine(url)


@pytest.mark.asyncio
async def test_eval_tables_exist_after_migration(tmp_path: Any) -> None:
    eng = await _migrated_engine(tmp_path)
    try:
        async with eng.connect() as c:
            names = await c.run_sync(lambda sc: sa.inspect(sc).get_table_names())
        assert "eval_runs" in names
        assert "eval_case_results" in names
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_migration_round_trips(tmp_path: Any) -> None:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'eval_rt.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    await asyncio.to_thread(command.downgrade, cfg, "0007")
    eng = create_async_engine(url)
    try:
        async with eng.connect() as c:
            names = await c.run_sync(lambda sc: sa.inspect(sc).get_table_names())
        assert "eval_runs" not in names and "eval_case_results" not in names
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_migration_tables_match_in_process_tables(tmp_path: Any) -> None:
    from cognic_agentos.evaluation.storage import _eval_case_results, _eval_runs

    eng = await _migrated_engine(tmp_path)
    try:
        async with eng.connect() as c:
            run_cols = await c.run_sync(
                lambda sc: {col["name"] for col in sa.inspect(sc).get_columns("eval_runs")}
            )
            case_cols = await c.run_sync(
                lambda sc: {col["name"] for col in sa.inspect(sc).get_columns("eval_case_results")}
            )
        assert run_cols == {c.name for c in _eval_runs.columns}
        assert case_cols == {c.name for c in _eval_case_results.columns}
    finally:
        await eng.dispose()
```

- [ ] **Step 2: Run — expect FAIL** (migration + tables don't exist). Run: `uv run pytest tests/unit/db/test_migration_20260607_0008.py -q`

- [ ] **Step 3a: Create the in-process Tables** (top of `evaluation/storage.py` — the store body lands in Task 8):

```python
# src/cognic_agentos/evaluation/storage.py  (Tables + imports; store body in Task 8)
"""Sprint 12 eval run store (ADR-010 amendment) — CC.

Postgres-backed eval_runs + eval_case_results, written atomically with the
value-free ``eval.bulk_run`` decision-history chain row via
``append_with_precondition`` (mirrors core/scheduler/storage.py). The relational
rows are INSERTed inside the precondition closure on the same connection that
writes the chain row. Back-link is by request_id (no chain_record_id — record_id
is minted after the closure; see the ADR-023 atomicity class).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

from sqlalchemy import (
    TIMESTAMP,
    Boolean,
    Column,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Uuid,
    insert,
    select,
)
from sqlalchemy.ext.asyncio import AsyncConnection

from cognic_agentos.core.audit import _metadata
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.db.types import GovernanceJSON

if TYPE_CHECKING:
    from cognic_agentos.evaluation.types import EvalRunResult

_EVAL_ISO_CONTROLS: Final[tuple[str, ...]] = ("ISO42001.A.7.6", "ISO42001.A.9.2")
_EVAL_TS_TYPE = TIMESTAMP(timezone=True)

_eval_runs = Table(
    "eval_runs",
    _metadata,
    Column("run_id", Uuid(), primary_key=True),
    Column("tenant_id", String(128), nullable=False),
    Column("corpus_id", String(200), nullable=False),
    Column("corpus_digest", String(64), nullable=False),
    Column("target_kind", String(32), nullable=False),
    Column("tier", String(16), nullable=False),
    Column("actor_subject", String(256), nullable=False),
    Column("status", String(16), nullable=False),
    Column("total", Integer(), nullable=False),
    Column("passed", Integer(), nullable=False),
    Column("failed", Integer(), nullable=False),
    Column("errored", Integer(), nullable=False),
    Column("latency_p50_ms", Integer(), nullable=False),
    Column("latency_p95_ms", Integer(), nullable=False),
    Column("chain_request_id", String(64), nullable=False),
    Column("created_at", _EVAL_TS_TYPE, nullable=False),
    Index("ix_eval_runs_tenant_created", "tenant_id", "created_at"),
)

_eval_case_results = Table(
    "eval_case_results",
    _metadata,
    Column("result_id", Uuid(), primary_key=True),
    Column("run_id", Uuid(), ForeignKey("eval_runs.run_id"), nullable=False),
    Column("case_id", String(200), nullable=False),
    Column("passed", Boolean(), nullable=False),
    Column("outcome", String(16), nullable=False),
    Column("scorer_results", GovernanceJSON(), nullable=False),
    Column("latency_ms", Integer(), nullable=False),
    Column("model", String(256), nullable=False),
    Column("input_digest", String(64), nullable=False),
    Column("output_digest", String(64), nullable=False),
    Column("candidate_output_text", GovernanceJSON(), nullable=True),
    Column("raw_output_persisted", Boolean(), nullable=False),
    Column("output_truncated", Boolean(), nullable=False),
    Index("ix_eval_case_results_run", "run_id"),
)
```

> Note: `candidate_output_text` uses `GovernanceJSON()` (nullable) so the dialect-portable JSON storage path handles long text + None uniformly (Oracle CLOB bridge), consistent with how other governed nullable payload columns are typed. (If the implementer prefers `sa.Text()`, that is acceptable provided the migration + the in-process Table agree — the drift test enforces agreement.)

- [ ] **Step 3b: Create the migration** mirroring `20260606_0007` / `20260526_0005`:

```python
# src/cognic_agentos/db/migrations/versions/20260607_0008_eval_runs_and_case_results.py
"""eval_runs + eval_case_results — Sprint 12 evaluation harness (ADR-010).

Adds the two eval-storage tables backing
``cognic_agentos.evaluation.storage.EvalRunStore``. The value-free
``eval.bulk_run`` aggregate evidence lives in the ``decision_history`` chain;
these tables hold the operational per-run + per-case results (raw candidate
output only when persist_raw_output was set on the run).

Pins (mirroring 0005/0007): ``GovernanceJSON()`` for the dialect-portable JSON
columns + ``sa.TIMESTAMP(timezone=True)`` for ``created_at`` — NOT
``sa.DateTime`` (Oracle drops the offset). Column shapes MUST agree with the
in-process Tables at ``evaluation/storage.py``; drift is pinned by
``tests/unit/db/test_migration_20260607_0008.py``.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from cognic_agentos.db.types import GovernanceJSON

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | None = None
depends_on: str | None = None

_EVAL_TS_TYPE = sa.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.create_table(
        "eval_runs",
        sa.Column("run_id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("corpus_id", sa.String(length=200), nullable=False),
        sa.Column("corpus_digest", sa.String(length=64), nullable=False),
        sa.Column("target_kind", sa.String(length=32), nullable=False),
        sa.Column("tier", sa.String(length=16), nullable=False),
        sa.Column("actor_subject", sa.String(length=256), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("total", sa.Integer(), nullable=False),
        sa.Column("passed", sa.Integer(), nullable=False),
        sa.Column("failed", sa.Integer(), nullable=False),
        sa.Column("errored", sa.Integer(), nullable=False),
        sa.Column("latency_p50_ms", sa.Integer(), nullable=False),
        sa.Column("latency_p95_ms", sa.Integer(), nullable=False),
        sa.Column("chain_request_id", sa.String(length=64), nullable=False),
        sa.Column("created_at", _EVAL_TS_TYPE, nullable=False),
    )
    op.create_index("ix_eval_runs_tenant_created", "eval_runs", ["tenant_id", "created_at"])
    op.create_table(
        "eval_case_results",
        sa.Column("result_id", sa.Uuid(), primary_key=True),
        sa.Column("run_id", sa.Uuid(), sa.ForeignKey("eval_runs.run_id"), nullable=False),
        sa.Column("case_id", sa.String(length=200), nullable=False),
        sa.Column("passed", sa.Boolean(), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("scorer_results", GovernanceJSON(), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("model", sa.String(length=256), nullable=False),
        sa.Column("input_digest", sa.String(length=64), nullable=False),
        sa.Column("output_digest", sa.String(length=64), nullable=False),
        sa.Column("candidate_output_text", GovernanceJSON(), nullable=True),
        sa.Column("raw_output_persisted", sa.Boolean(), nullable=False),
        sa.Column("output_truncated", sa.Boolean(), nullable=False),
    )
    op.create_index("ix_eval_case_results_run", "eval_case_results", ["run_id"])


def downgrade() -> None:
    op.drop_index("ix_eval_case_results_run", table_name="eval_case_results")
    op.drop_table("eval_case_results")
    op.drop_index("ix_eval_runs_tenant_created", table_name="eval_runs")
    op.drop_table("eval_runs")
```

- [ ] **Step 4: Run — expect PASS.** Run: `uv run pytest tests/unit/db/test_migration_20260607_0008.py -q`

- [ ] **Step 5: HALT-BEFORE-COMMIT [STOP-RULE]** (migration). Full gate ladder; halt summary; wait for token.

```bash
uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy src tests
git add src/cognic_agentos/db/migrations/versions/20260607_0008_eval_runs_and_case_results.py \
        src/cognic_agentos/evaluation/storage.py \
        tests/unit/db/test_migration_20260607_0008.py
git commit -m "$(printf 'feat(eval): migration 0008 eval_runs + eval_case_results (ADR-010)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 8 [CC]: EvalRunStore — atomic persist + tenant-scoped read (`evaluation/storage.py`)

**Files:**
- Modify: `src/cognic_agentos/evaluation/storage.py` (append the store class + minter below the Tables)
- Test: `tests/unit/evaluation/test_storage.py` (migrated-DB pattern)

- [ ] **Step 1: Write the failing tests** (migrated DB, NOT create_all)

```python
# tests/unit/evaluation/test_storage.py
from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.evaluation.storage import EvalRunStore, _eval_runs
from cognic_agentos.evaluation.types import CaseResult, CriterionDetail, EvalRunResult, ScorerResult


async def _migrated_engine(tmp_path: Any) -> Any:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'eval_store.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    return create_async_engine(url)


def _result(run_id: uuid.UUID, *, persist_raw: bool = False) -> EvalRunResult:
    case = CaseResult(
        case_id="c1",
        passed=True,
        outcome="succeeded",
        scorer_results=(
            ScorerResult(
                scorer="assertions",
                passed=True,
                detail=(CriterionDetail(name="contains:x", passed=True, critique=""),),
            ),
        ),
        latency_ms=4,
        model="m",
        input_digest="i",
        output_digest="o",
        candidate_output_text="the full model answer" if persist_raw else None,
        raw_output_persisted=persist_raw,
        output_truncated=False,
    )
    return EvalRunResult(
        run_id=run_id,
        chain_request_id="eval-run-abcdef",
        corpus_id="cp",
        corpus_digest="d",
        target_kind="gateway",
        tier="tier1",
        total=1,
        passed=1,
        failed=0,
        errored=0,
        latency_p50_ms=4,
        latency_p95_ms=4,
        cases=(case,),
    )


@pytest.mark.asyncio
async def test_persist_run_writes_rows_and_chain_request_id_matches(tmp_path: Any) -> None:
    eng = await _migrated_engine(tmp_path)
    try:
        store = EvalRunStore(DecisionHistoryStore(eng))
        rid = uuid.uuid4()
        record_id, _hash = await store.persist_run(
            result=_result(rid), actor_subject="svc", tenant_id="t1"
        )
        async with eng.connect() as c:
            run_row = (
                await c.execute(sa.select(_eval_runs).where(_eval_runs.c.run_id == rid))
            ).first()
            dh = (
                await c.execute(
                    sa.text(
                        "SELECT event_type, request_id, iso_controls FROM decision_history "
                        "WHERE event_type = 'eval.bulk_run'"
                    )
                )
            ).first()
        assert run_row is not None
        # Patch-1 back-link: eval_runs.chain_request_id == DecisionRecord.request_id.
        assert run_row.chain_request_id == "eval-run-abcdef"
        assert dh.request_id == "eval-run-abcdef"
        assert "ISO42001.A.7.6" in dh.iso_controls and "ISO42001.A.9.2" in dh.iso_controls
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_chain_payload_is_value_free(tmp_path: Any) -> None:
    eng = await _migrated_engine(tmp_path)
    try:
        store = EvalRunStore(DecisionHistoryStore(eng))
        await store.persist_run(
            result=_result(uuid.uuid4(), persist_raw=True), actor_subject="svc", tenant_id="t1"
        )
        async with eng.connect() as c:
            payload = (
                await c.execute(
                    sa.text("SELECT payload FROM decision_history WHERE event_type='eval.bulk_run'")
                )
            ).scalar_one()
        # raw candidate text must NEVER appear in the value-free chain payload.
        assert "the full model answer" not in str(payload)
        assert "output_digest" in str(payload) or "o" in str(payload)
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_get_run_cross_tenant_returns_none(tmp_path: Any) -> None:
    eng = await _migrated_engine(tmp_path)
    try:
        store = EvalRunStore(DecisionHistoryStore(eng))
        rid = uuid.uuid4()
        result = _result(rid)
        await store.persist_run(result=result, actor_subject="svc", tenant_id="t1")
        assert await store.get_run(run_id=rid, tenant_id="t1") is not None
        assert await store.get_run(run_id=rid, tenant_id="t2") is None  # cross-tenant invisible
        assert await store.get_run(run_id=uuid.uuid4(), tenant_id="t1") is None  # unknown
    finally:
        await eng.dispose()
```

- [ ] **Step 2: Run — expect FAIL.** Run: `uv run pytest tests/unit/evaluation/test_storage.py -q`

- [ ] **Step 3: Append the store + minter to `evaluation/storage.py`**

```python
# ... appended below the Table definitions in evaluation/storage.py ...

_EVAL_RUN_REQUEST_ID_PREFIX: Final[str] = "eval-run-"  # 9 chars + 32 hex = 41 <= 64


def mint_eval_request_id() -> str:
    """Bounded request_id for an eval run (prefix + uuid4().hex)."""
    return f"{_EVAL_RUN_REQUEST_ID_PREFIX}{uuid.uuid4().hex}"


assert len(_EVAL_RUN_REQUEST_ID_PREFIX) + 32 <= 64


class EvalRunStore:
    """Atomic eval-run persistence + tenant-scoped read."""

    def __init__(self, history: DecisionHistoryStore) -> None:
        self._history = history

    async def persist_run(
        self,
        *,
        result: EvalRunResult,
        actor_subject: str,
        tenant_id: str,
    ) -> tuple[uuid.UUID, bytes]:
        now = datetime.now(UTC)

        async def _precondition(conn: AsyncConnection, _seq: int, _hash: bytes) -> None:
            await conn.execute(
                insert(_eval_runs).values(
                    run_id=result.run_id,
                    tenant_id=tenant_id,
                    corpus_id=result.corpus_id,
                    corpus_digest=result.corpus_digest,
                    target_kind=result.target_kind,
                    tier=result.tier,
                    actor_subject=actor_subject,
                    status="completed",
                    total=result.total,
                    passed=result.passed,
                    failed=result.failed,
                    errored=result.errored,
                    latency_p50_ms=result.latency_p50_ms,
                    latency_p95_ms=result.latency_p95_ms,
                    chain_request_id=result.chain_request_id,
                    created_at=now,
                )
            )
            for case in result.cases:
                await conn.execute(
                    insert(_eval_case_results).values(
                        result_id=uuid.uuid4(),
                        run_id=result.run_id,
                        case_id=case.case_id,
                        passed=case.passed,
                        outcome=case.outcome,
                        scorer_results=[_scorer_to_json(s) for s in case.scorer_results],
                        latency_ms=case.latency_ms,
                        model=case.model,
                        input_digest=case.input_digest,
                        output_digest=case.output_digest,
                        candidate_output_text=case.candidate_output_text,
                        raw_output_persisted=case.raw_output_persisted,
                        output_truncated=case.output_truncated,
                    )
                )

        def _build_record(_: None) -> DecisionRecord:
            # Value-free chain payload: digests + counts only, NEVER raw text.
            return DecisionRecord(
                decision_type="eval.bulk_run",
                request_id=result.chain_request_id,
                actor_id=actor_subject,
                tenant_id=tenant_id,
                iso_controls=_EVAL_ISO_CONTROLS,
                payload={
                    "run_id": str(result.run_id),
                    "corpus_id": result.corpus_id,
                    "corpus_digest": result.corpus_digest,
                    "target_kind": result.target_kind,
                    "tier": result.tier,
                    "total": result.total,
                    "passed": result.passed,
                    "failed": result.failed,
                    "errored": result.errored,
                    "cases": [
                        {"case_id": c.case_id, "passed": c.passed, "output_digest": c.output_digest}
                        for c in result.cases
                    ],
                },
            )

        return await self._history.append_with_precondition(
            record_builder=_build_record, precondition=_precondition
        )

    async def get_run(self, *, run_id: uuid.UUID, tenant_id: str) -> dict[str, Any] | None:
        """Tenant-scoped read; cross-tenant / unknown both return None (404 at the route)."""
        async with self._history._engine.begin() as conn:  # noqa: SLF001 — same-engine read
            run = (
                await conn.execute(
                    select(_eval_runs).where(
                        _eval_runs.c.run_id == run_id, _eval_runs.c.tenant_id == tenant_id
                    )
                )
            ).first()
            if run is None:
                return None
            cases = (
                await conn.execute(
                    select(_eval_case_results).where(_eval_case_results.c.run_id == run_id)
                )
            ).all()
        return {"run": run._mapping, "cases": [c._mapping for c in cases]}


def _scorer_to_json(s: Any) -> dict[str, Any]:
    return {
        "scorer": s.scorer,
        "passed": s.passed,
        "detail": [{"name": d.name, "passed": d.passed, "critique": d.critique} for d in s.detail],
        "verdict": s.verdict,
        "score": s.score,
        "rationale": s.rationale,
    }
```

- [ ] **Step 4: Run — expect PASS.** Run: `uv run pytest tests/unit/evaluation/test_storage.py -q`

- [ ] **Step 5: HALT-BEFORE-COMMIT [CC].** Full gate ladder; halt summary (call out the value-free-chain test + the cross-tenant-None test + the chain_request_id back-link test as the load-bearing pins); wait for token.

```bash
uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy src tests
git add src/cognic_agentos/evaluation/storage.py tests/unit/evaluation/test_storage.py
git commit -m "$(printf 'feat(eval): atomic EvalRunStore + tenant-scoped read (ADR-010)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 9 [STOP-RULE]: RBAC scopes (`portal/rbac/scopes.py`)

**Files:**
- Modify: `src/cognic_agentos/portal/rbac/scopes.py` (extend `EvalRBACScope` + `EVAL_SCOPES`, ~line 227)
- Test: `tests/unit/portal/rbac/test_eval_bulk_scopes.py`

Extending the existing `EvalRBACScope` Literal is sufficient — `actor.py` and `enforcement.py` already union `EvalRBACScope`, so no edits there.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/portal/rbac/test_eval_bulk_scopes.py
from __future__ import annotations

import typing

from cognic_agentos.portal.rbac.scopes import EVAL_SCOPES, EvalRBACScope


def test_eval_scopes_include_bulk_and_runs_read() -> None:
    values = set(typing.get_args(EvalRBACScope))
    assert values == {"eval.judge.run", "eval.bulk.run", "eval.runs.read"}
    assert EVAL_SCOPES == frozenset({"eval.judge.run", "eval.bulk.run", "eval.runs.read"})
```

- [ ] **Step 2: Run — expect FAIL.** Run: `uv run pytest tests/unit/portal/rbac/test_eval_bulk_scopes.py -q`

- [ ] **Step 3: Extend the Literal + frozenset** (replace the existing 2 lines at `scopes.py:229,232`):

```python
#: Eval surface scope family (ADR-010 judge slice + Sprint-12 bulk runner).
#: Service or human actors may run evals (NOT a Human-only decision).
EvalRBACScope = Literal[
    "eval.judge.run",
    "eval.bulk.run",
    "eval.runs.read",
]

#: All eval scopes as a frozenset (1:1 with EvalRBACScope) for bank-overlay binders.
EVAL_SCOPES: frozenset[EvalRBACScope] = frozenset(
    {"eval.judge.run", "eval.bulk.run", "eval.runs.read"}
)
```

- [ ] **Step 4: Run — expect PASS.** Run: `uv run pytest tests/unit/portal/rbac/test_eval_bulk_scopes.py -q`

- [ ] **Step 5: HALT-BEFORE-COMMIT [STOP-RULE]** (RBAC). Full gate ladder; halt summary; wait for token.

```bash
uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy src tests
git add src/cognic_agentos/portal/rbac/scopes.py tests/unit/portal/rbac/test_eval_bulk_scopes.py
git commit -m "$(printf 'feat(eval): RBAC scopes eval.bulk.run + eval.runs.read (ADR-010)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 10 [STOP-RULE]: Bulk-run DTOs + portal routes (`portal/api/evaluation/`)

**Files:**
- Modify: `src/cognic_agentos/portal/api/evaluation/dto.py` (append bulk DTOs)
- Create: `src/cognic_agentos/portal/api/evaluation/bulk_routes.py`
- Test: `tests/unit/portal/api/evaluation/test_bulk_routes.py`

- [ ] **Step 1: Write the failing tests** (mirror the judge route test harness)

```python
# tests/unit/portal/api/evaluation/test_bulk_routes.py
from __future__ import annotations

import uuid
from typing import Any

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from cognic_agentos.core.decision_history import DecisionRecord
from cognic_agentos.llm.gateway import GatewayResponse
from cognic_agentos.llm.concurrency import LLMConcurrencyExceeded
from cognic_agentos.portal.api.evaluation.bulk_routes import build_eval_bulk_routes
from cognic_agentos.portal.rbac.actor import Actor


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


def _actor(*, scopes=frozenset({"eval.bulk.run"})) -> Actor:
    return Actor(subject="svc", tenant_id="t1", scopes=scopes, actor_type="service")  # type: ignore[arg-type]


class _FakeGateway:
    def __init__(self, *, content="ok contains capital adequacy", raise_exc=None) -> None:
        self._content = content
        self._raise = raise_exc

    async def completion(self, *, tier, messages, request_id, tenant_id=None):  # type: ignore[no-untyped-def]
        if self._raise is not None:
            raise self._raise
        return GatewayResponse(content=self._content, upstream_model="m", api_base=None,
                               external=False, request_id=request_id, tier=tier, latency_ms=3)


class _CapturingStore:
    def __init__(self) -> None:
        self.records: list[DecisionRecord] = []

    async def append_with_precondition(self, *, record_builder, precondition):  # type: ignore[no-untyped-def]
        # Run precondition against a throwaway connection stand-in is complex; the
        # route constructs a real EvalRunStore around this. For route-level tests we
        # only need a store whose persist path is exercised via a real migrated DB.
        raise NotImplementedError


def _corpus_body(n_cases: int) -> dict[str, Any]:
    return {
        "corpus": {
            "schema_version": 1,
            "corpus_id": "smoke",
            "cases": [
                {
                    "id": f"c{i}",
                    "case_kind": "completion",
                    "messages": [{"role": "user", "content": "Define CAR."}],
                    "assertions": {"contains": ["capital adequacy"]},
                }
                for i in range(n_cases)
            ],
        },
        "target": "gateway",
        "persist_raw_output": False,
    }


def _app(*, actor, gateway, store, runtime, max_cases=50) -> FastAPI:
    app = FastAPI()
    app.state.actor_binder = _StubBinder(actor)
    app.state.llm_gateway = gateway
    app.state.decision_history_store = store
    app.state.runtime = runtime
    app.include_router(
        build_eval_bulk_routes(
            max_cases=max_cases,
            max_raw_output_chars=50_000,
            target_tier="tier1",
            judge_tier="tier1",
        ),
        prefix="/api/v1/eval",
    )
    return app


def test_llm_gateway_unavailable_503() -> None:
    app = _app(actor=_actor(), gateway=None, store=object(), runtime=None)
    resp = TestClient(app).post("/api/v1/eval/bulk-run", json=_corpus_body(1))
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "llm_gateway_unavailable"


def test_scope_not_held_403() -> None:
    app = _app(actor=_actor(scopes=frozenset({"memory.read"})), gateway=_FakeGateway(), store=object(), runtime=None)
    resp = TestClient(app).post("/api/v1/eval/bulk-run", json=_corpus_body(1))
    assert resp.status_code == 403


def test_over_cap_413() -> None:
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=object(), runtime=None, max_cases=1)
    resp = TestClient(app).post("/api/v1/eval/bulk-run", json=_corpus_body(2))
    assert resp.status_code == 413
    assert resp.json()["detail"]["reason"] == "eval_corpus_too_large"


def test_malformed_corpus_400() -> None:
    app = _app(actor=_actor(), gateway=_FakeGateway(), store=object(), runtime=None)
    body = _corpus_body(1)
    body["corpus"]["cases"][0]["surprise"] = 1  # unknown key
    resp = TestClient(app).post("/api/v1/eval/bulk-run", json=body)
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "corpus_unknown_key"
```

```python
# tests/unit/portal/api/evaluation/test_bulk_routes_e2e.py
from __future__ import annotations

import asyncio
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.db.migrations.alembic_config import make_alembic_config
from cognic_agentos.llm.concurrency import LLMConcurrencyExceeded
from cognic_agentos.llm.gateway import GatewayResponse
from cognic_agentos.portal.api.evaluation.bulk_routes import build_eval_bulk_routes
from cognic_agentos.portal.rbac.actor import Actor


async def _migrated_engine(tmp_path: Any) -> Any:
    from alembic import command

    url = f"sqlite+aiosqlite:///{tmp_path / 'eval_route.db'}"
    await asyncio.to_thread(command.upgrade, make_alembic_config(url), "head")
    return create_async_engine(url)


class _StubBinder:
    def bind(self, *, request: Request) -> Actor:
        return Actor(
            subject="svc", tenant_id="t1", scopes=frozenset({"eval.bulk.run"}), actor_type="service"
        )  # type: ignore[arg-type]


class _FakeGateway:
    def __init__(self, *, content: str = "capital adequacy", raise_exc: Exception | None = None) -> None:
        self._content = content
        self._raise = raise_exc

    async def completion(self, *, tier, messages, request_id, tenant_id=None):  # type: ignore[no-untyped-def]
        if self._raise is not None:
            raise self._raise
        return GatewayResponse(
            content=self._content,
            upstream_model="m",
            api_base=None,
            external=False,
            request_id=request_id,
            tier=tier,
            latency_ms=3,
        )


def _body() -> dict[str, Any]:
    return {
        "corpus": {
            "schema_version": 1,
            "corpus_id": "smoke",
            "cases": [
                {
                    "id": "c1",
                    "case_kind": "completion",
                    "messages": [{"role": "user", "content": "Define CAR."}],
                    "assertions": {"contains": ["capital adequacy"]},
                }
            ],
        },
        "target": "gateway",
        "persist_raw_output": False,
    }


async def _app(tmp_path: Any, gateway: _FakeGateway) -> FastAPI:
    eng = await _migrated_engine(tmp_path)
    app = FastAPI()
    app.state.actor_binder = _StubBinder()
    app.state.llm_gateway = gateway
    app.state.decision_history_store = DecisionHistoryStore(eng)
    app.state.runtime = None
    app.include_router(
        build_eval_bulk_routes(
            max_cases=50, max_raw_output_chars=50_000, target_tier="tier1", judge_tier="tier1"
        ),
        prefix="/api/v1/eval",
    )
    return app


@pytest.mark.asyncio
async def test_bulk_run_success_200_persists(tmp_path: Any) -> None:
    app = await _app(tmp_path, _FakeGateway())
    resp = TestClient(app).post("/api/v1/eval/bulk-run", json=_body())
    assert resp.status_code == 200
    assert resp.json()["passed"] == 1


@pytest.mark.asyncio
async def test_per_case_gateway_failure_returns_200_with_errored_case(tmp_path: Any) -> None:
    app = await _app(tmp_path, _FakeGateway(raise_exc=LLMConcurrencyExceeded("no slot")))
    resp = TestClient(app).post("/api/v1/eval/bulk-run", json=_body())
    assert resp.status_code == 200
    assert resp.json()["errored"] == 1
    assert resp.json()["cases"][0]["outcome"] == "errored"
```

- [ ] **Step 2: Run — expect FAIL.** Run: `uv run pytest tests/unit/portal/api/evaluation/test_bulk_routes.py -q`

- [ ] **Step 3a: Append bulk DTOs to `dto.py`**

```python
# ... appended to src/cognic_agentos/portal/api/evaluation/dto.py ...

class BulkRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    corpus: dict  # validated against the corpus.Corpus model in the handler
    target: Literal["gateway"] = "gateway"
    persist_raw_output: bool = False


class BulkCaseResultResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: str
    passed: bool
    outcome: Literal["succeeded", "errored"]
    latency_ms: int
    model: str
    raw_output_persisted: bool
    output_truncated: bool


class BulkRunResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: str
    chain_request_id: str
    corpus_id: str
    target_kind: str
    tier: str
    total: int
    passed: int
    failed: int
    errored: int
    latency_p50_ms: int
    latency_p95_ms: int
    cases: list[BulkCaseResultResponse]
```

- [ ] **Step 3b: Create `bulk_routes.py`** (mirror the judge route's DI + the bounded minter)

```python
# src/cognic_agentos/portal/api/evaluation/bulk_routes.py
"""ADR-010 amendment — POST /api/v1/eval/bulk-run + GET /api/v1/eval/runs/{run_id}.

Single execution path: the portal runs the corpus synchronously under a cap and
persists atomically via EvalRunStore. DI fails closed (gateway + decision-history
store resolved BEFORE execution). Endpoint statuses are bounded to request/infra
problems (403/503/413/400); per-case gateway failures surface as errored cases in
the 200 body. ``from __future__ import annotations`` is OMITTED (closure-local Depends).
"""

import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request

from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.evaluation.corpus import CorpusLoadError, validate_corpus_payload
from cognic_agentos.evaluation.runner import EvalRunner
from cognic_agentos.evaluation.scorers import AssertionScorer, JudgeScorer
from cognic_agentos.evaluation.storage import EvalRunStore, mint_eval_request_id
from cognic_agentos.evaluation.target import GatewayTarget
from cognic_agentos.evaluation.types import CaseResult, EvalRunResult
from cognic_agentos.llm.gateway import LLMGateway
from cognic_agentos.portal.api.evaluation.dto import (
    BulkCaseResultResponse,
    BulkRunRequest,
    BulkRunResponse,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope

EvalBulkRefusalReason = Literal["eval_corpus_too_large", "eval_corpus_empty"]


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


def build_eval_bulk_routes(
    *, max_cases: int, max_raw_output_chars: int, target_tier: str, judge_tier: str
) -> APIRouter:
    router = APIRouter()
    _require_bulk = RequireScope("eval.bulk.run")
    _require_read = RequireScope("eval.runs.read")

    @router.post("/bulk-run", summary="Run a corpus against a target and persist the eval run")
    async def bulk_run(
        request: Request,
        actor: Annotated[Actor, Depends(_require_bulk)],
        gateway: Annotated[LLMGateway, Depends(_require_llm_gateway)],
        dh_store: Annotated[DecisionHistoryStore, Depends(_require_decision_history_store)],
        body: BulkRunRequest,
    ) -> BulkRunResponse:
        try:
            corpus = validate_corpus_payload(body.corpus)
        except CorpusLoadError as exc:
            raise HTTPException(status_code=400, detail={"reason": exc.reason}) from None
        if len(corpus.cases) == 0:
            raise HTTPException(status_code=400, detail={"reason": "eval_corpus_empty"})
        if len(corpus.cases) > max_cases:
            raise HTTPException(status_code=413, detail={"reason": "eval_corpus_too_large"})

        target = GatewayTarget(gateway=gateway, tier=target_tier)
        scorers = [AssertionScorer(), JudgeScorer(gateway=gateway, tier=judge_tier)]
        run_id = uuid.uuid4()
        request_id = mint_eval_request_id()
        result = await EvalRunner().run(
            corpus,
            target=target,
            scorers=scorers,
            run_id=run_id,
            chain_request_id=request_id,
            tenant_id=actor.tenant_id,
            capture_raw_output=body.persist_raw_output,
        )
        result = _apply_raw_output(result, body.persist_raw_output, max_raw_output_chars)
        store = EvalRunStore(dh_store)
        await store.persist_run(result=result, actor_subject=actor.subject, tenant_id=actor.tenant_id)
        return _to_response(result)

    @router.get("/runs/{run_id}", summary="Read a persisted eval run (tenant-scoped)")
    async def get_run(
        request: Request,
        run_id: uuid.UUID,
        actor: Annotated[Actor, Depends(_require_read)],
        dh_store: Annotated[DecisionHistoryStore, Depends(_require_decision_history_store)],
    ) -> dict:
        store = EvalRunStore(dh_store)
        row = await store.get_run(run_id=run_id, tenant_id=actor.tenant_id)
        if row is None:  # cross-tenant + unknown both collapse to 404
            raise HTTPException(status_code=404, detail={"reason": "eval_run_not_found"})
        return {"run": dict(row["run"]), "cases": [dict(c) for c in row["cases"]]}

    return router


def _apply_raw_output(result: EvalRunResult, persist: bool, max_chars: int) -> EvalRunResult:
    if not persist:
        return result
    import dataclasses

    new_cases = []
    for c in result.cases:
        if c.candidate_output_text is None:
            new_cases.append(c)
            continue
        raw = c.candidate_output_text
        truncated = raw[:max_chars]
        new_cases.append(
            dataclasses.replace(
                c,
                candidate_output_text=truncated,
                raw_output_persisted=True,
                output_truncated=len(raw) > max_chars,
            )
        )
    return dataclasses.replace(result, cases=tuple(new_cases))


def _to_response(result) -> BulkRunResponse:  # type: ignore[no-untyped-def]
    return BulkRunResponse(
        run_id=str(result.run_id),
        chain_request_id=result.chain_request_id,
        corpus_id=result.corpus_id,
        target_kind=result.target_kind,
        tier=result.tier,
        total=result.total,
        passed=result.passed,
        failed=result.failed,
        errored=result.errored,
        latency_p50_ms=result.latency_p50_ms,
        latency_p95_ms=result.latency_p95_ms,
        cases=[
            BulkCaseResultResponse(
                case_id=c.case_id,
                passed=c.passed,
                outcome=c.outcome,
                latency_ms=c.latency_ms,
                model=c.model,
                raw_output_persisted=c.raw_output_persisted,
                output_truncated=c.output_truncated,
            )
            for c in result.cases
        ],
    )
```

- [ ] **Step 4: Run — expect PASS** (the 503/403/413/400 unit tests + the e2e 200/errored tests). Run: `uv run pytest tests/unit/portal/api/evaluation/ -q`

- [ ] **Step 5: HALT-BEFORE-COMMIT [STOP-RULE]** (new auth/mutation surface). Full gate ladder; halt summary (pin the 413 cap, the 400 corpus refusal, the 503 fail-closed DI, the per-case-errored-200 e2e); wait for token.

```bash
uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy src tests
git add src/cognic_agentos/portal/api/evaluation/dto.py \
        src/cognic_agentos/portal/api/evaluation/bulk_routes.py \
        tests/unit/portal/api/evaluation/test_bulk_routes.py \
        tests/unit/portal/api/evaluation/test_bulk_routes_e2e.py
git commit -m "$(printf 'feat(eval): bulk-run + runs read portal endpoints (ADR-010)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 11 [STOP-RULE]: Mount the bulk router (`portal/api/app.py`)

**Files:**
- Modify: `src/cognic_agentos/portal/api/app.py` (after the `build_eval_routes` include, ~line 1043)
- Test: `tests/unit/portal/api/test_app_eval_bulk_mount.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/portal/api/test_app_eval_bulk_mount.py
from __future__ import annotations

from cognic_agentos.portal.api.app import create_app


def test_bulk_run_and_runs_routes_mounted() -> None:
    app = create_app()
    paths = {r.path for r in app.routes}  # type: ignore[attr-defined]
    assert "/api/v1/eval/bulk-run" in paths
    assert "/api/v1/eval/runs/{run_id}" in paths
```

> Note: `create_app()` may require minimal settings; mirror the existing `tests/unit/portal/api/test_app_eval_mount.py` setup if it passes settings/fixtures.

- [ ] **Step 2: Run — expect FAIL.** Run: `uv run pytest tests/unit/portal/api/test_app_eval_bulk_mount.py -q`

- [ ] **Step 3: Add the mount** immediately after the existing eval-judge include (`app.py:1043`):

```python
    from cognic_agentos.portal.api.evaluation.bulk_routes import build_eval_bulk_routes

    app.include_router(
        build_eval_bulk_routes(
            max_cases=settings.eval_bulk_max_cases,
            max_raw_output_chars=settings.eval_bulk_max_raw_output_chars,
            target_tier=settings.eval_bulk_target_tier,
            judge_tier=settings.eval_judge_tier,
        ),
        prefix="/api/v1/eval",
        tags=["eval"],
    )
```

- [ ] **Step 4: Run — expect PASS.** Run: `uv run pytest tests/unit/portal/api/test_app_eval_bulk_mount.py -q`

- [ ] **Step 5: HALT-BEFORE-COMMIT [STOP-RULE]** (composition root / app wiring). Full gate ladder; halt summary; wait for token.

```bash
uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy src tests
git add src/cognic_agentos/portal/api/app.py tests/unit/portal/api/test_app_eval_bulk_mount.py
git commit -m "$(printf 'feat(eval): mount bulk-run + runs portal router (ADR-010)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 12 [normal]: CLI `eval-bulk` (thin client + dry-run)

**Files:**
- Create: `src/cognic_agentos/cli/eval.py`
- Modify: `src/cognic_agentos/cli/__init__.py` (add a flat `@app.command(name="eval-bulk")`)
- Test: `tests/unit/cli/test_eval_bulk.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/cli/test_eval_bulk.py
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


def test_dry_run_validates_and_prints_plan_no_network(tmp_path: Path) -> None:
    runner = CliRunner()
    res = runner.invoke(app, ["eval-bulk", "--corpus", str(_corpus_dir(tmp_path)), "--dry-run"])
    assert res.exit_code == 0
    assert "smoke" in res.stdout
    assert "1" in res.stdout  # case count


def test_dry_run_invalid_corpus_exit_1(tmp_path: Path) -> None:
    (tmp_path / "bad.yaml").write_text("schema_version: 9\ncases: []\n", encoding="utf-8")
    res = CliRunner().invoke(app, ["eval-bulk", "--corpus", str(tmp_path), "--dry-run"])
    assert res.exit_code == 1
    assert "corpus_schema_version_unsupported" in res.stdout or "corpus" in res.stdout


def test_missing_url_without_dry_run_exit_2(tmp_path: Path) -> None:
    res = CliRunner().invoke(app, ["eval-bulk", "--corpus", str(_corpus_dir(tmp_path))])
    assert res.exit_code == 2  # needs --url (or --dry-run)
```

- [ ] **Step 2: Run — expect FAIL.** Run: `uv run pytest tests/unit/cli/test_eval_bulk.py -q`

- [ ] **Step 3a: Implement `cli/eval.py`**

```python
# src/cognic_agentos/cli/eval.py
"""`agentos eval-bulk` — thin portal client + local --dry-run (ADR-010)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_and_summarise(corpus_path: Path) -> dict[str, Any]:
    """Strict-load the corpus; return a plan summary. Raises CorpusLoadError."""
    from cognic_agentos.evaluation.corpus import load_corpus

    corpus = load_corpus(corpus_path)
    return {
        "corpus_id": corpus.corpus_id,
        "case_count": len(corpus.cases),
        "cases": [
            {
                "id": c.id,
                "scorers": [s for s, present in (("assertions", c.assertions is not None), ("judge", c.judge is not None)) if present],
            }
            for c in corpus.cases
        ],
    }


def post_bulk_run(corpus_path: Path, *, url: str, token: str) -> dict[str, Any]:
    """POST the loaded corpus to the portal bulk-run endpoint; return the JSON body."""
    import httpx

    from cognic_agentos.evaluation.corpus import load_corpus

    corpus = load_corpus(corpus_path)
    resp = httpx.post(
        f"{url.rstrip('/')}/api/v1/eval/bulk-run",
        headers={"Authorization": f"Bearer {token}"},
        json={"corpus": corpus.model_dump(), "target": "gateway", "persist_raw_output": False},
        timeout=120.0,
    )
    resp.raise_for_status()
    return resp.json()


def render(summary: dict[str, Any], *, json_output: bool) -> str:
    if json_output:
        return json.dumps(summary, indent=2, sort_keys=True)
    lines = [f"corpus: {summary.get('corpus_id')}", f"cases: {summary.get('case_count', summary.get('total'))}"]
    return "\n".join(lines)
```

- [ ] **Step 3b: Register the command in `cli/__init__.py`** (flat command, mirrors `conformance`):

```python
@app.command(name="eval-bulk")
def eval_bulk(
    corpus: Path = typer.Option(  # noqa: B008
        ..., "--corpus", help="Directory of corpus YAML docs (*.yaml / *.yml)."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Load + strict-validate the corpus and print the plan; no model/portal call."
    ),
    url: str | None = typer.Option(None, "--url", help="Portal base URL for a persisted run."),
    token: str | None = typer.Option(None, "--token", help="Bearer token for the portal."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Run a corpus against the portal eval bulk-run endpoint (or validate locally with --dry-run)."""
    from cognic_agentos.cli.eval import load_and_summarise, post_bulk_run, render
    from cognic_agentos.evaluation.corpus import CorpusLoadError

    if dry_run:
        try:
            summary = load_and_summarise(corpus)
        except CorpusLoadError as exc:
            typer.echo(f"eval-bulk: corpus invalid: {exc.reason}", err=True)
            raise typer.Exit(code=1) from None
        typer.echo(render(summary, json_output=json_output))
        return
    if not url or not token:
        typer.echo("eval-bulk: --url and --token are required without --dry-run", err=True)
        raise typer.Exit(code=2)
    try:
        body = post_bulk_run(corpus, url=url, token=token)
    except CorpusLoadError as exc:
        typer.echo(f"eval-bulk: corpus invalid: {exc.reason}", err=True)
        raise typer.Exit(code=1) from None
    except Exception as exc:  # network / portal error
        typer.echo(f"eval-bulk: portal call failed: {exc}", err=True)
        raise typer.Exit(code=2) from None
    typer.echo(render(body, json_output=json_output))
```

- [ ] **Step 4: Run — expect PASS.** Run: `uv run pytest tests/unit/cli/test_eval_bulk.py -q`

- [ ] **Step 5: ruff + mypy, commit by path** (off-gate; touched-scope tests suffice).

```bash
uv run pytest tests/unit/cli/test_eval_bulk.py -q
uv run ruff check src/cognic_agentos/cli/eval.py src/cognic_agentos/cli/__init__.py tests/unit/cli/test_eval_bulk.py
uv run ruff format --check src/cognic_agentos/cli/eval.py src/cognic_agentos/cli/__init__.py tests/unit/cli/test_eval_bulk.py
uv run mypy src/cognic_agentos/cli/eval.py src/cognic_agentos/cli/__init__.py
git add src/cognic_agentos/cli/eval.py src/cognic_agentos/cli/__init__.py tests/unit/cli/test_eval_bulk.py
git commit -m "$(printf 'feat(eval): agentos eval-bulk CLI (thin client + dry-run)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 13 [STOP-RULE]: ISO 42001 control mapping (`compliance/iso42001/controls.py`)

> **DECISION TO CONFIRM AT THIS HALT:** tagging `eval.bulk_run` under **A.7.6** forces flipping A.7.6 from `deferred` → `implemented` and clearing its `deferred_reason` (A.7.6 is currently the SOLE deferred control; the coverage-audit test treats a deferred control as correct only if it has no emitter + a non-empty reason). This is an ISO-mapping status change — surface it explicitly in the halt summary for review. A.9.2 is already `implemented`; we only append the hook there.

**Files:**
- Modify: `src/cognic_agentos/compliance/iso42001/controls.py` (A.7.6 entry ~line 114; A.9.2 entry ~line 152)
- Test: `tests/unit/compliance/iso42001/test_eval_bulk_iso.py` + update any existing `test_control_mapping` count assertions

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/compliance/iso42001/test_eval_bulk_iso.py
from __future__ import annotations

from cognic_agentos.compliance.iso42001.controls import ISO42001_CONTROLS


def _entry(control_id: str):
    return next(e for e in ISO42001_CONTROLS if e.control_id == control_id)


def test_eval_bulk_run_tags_a76_and_a92() -> None:
    a76 = _entry("ISO42001.A.7.6")
    a92 = _entry("ISO42001.A.9.2")
    assert "eval.bulk_run" in a76.intended_hooks
    assert "eval.bulk_run" in a92.intended_hooks


def test_a76_flipped_to_implemented() -> None:
    a76 = _entry("ISO42001.A.7.6")
    assert a76.hook_status == "implemented"
    assert a76.deferred_reason == ""
```

- [ ] **Step 2: Run — expect FAIL.** Run: `uv run pytest tests/unit/compliance/iso42001/test_eval_bulk_iso.py -q`

- [ ] **Step 3: Edit the two control entries.** A.7.6 — append the hook, flip status, clear reason:

```python
    ControlEntry(
        "ISO42001.A.7.6",
        "A.7.6",
        "AI system risk evaluation",
        (
            "auto_degradation.evaluate",
            "compliance_checker.score",
            "eval.bulk_run",  # Sprint 12 (ADR-010) — bulk eval run IS an AI-system evaluation surface.
        ),
        "implemented",
    ),
```

A.9.2 — append the hook:

```python
    ControlEntry(
        "ISO42001.A.9.2",
        "A.9.2",
        "System and operational logging",
        ("audit.append", "chain_verifier.walk", "eval.bulk_run"),
        "implemented",
    ),
```

- [ ] **Step 3b: Update the existing control-mapping test.** In `tests/unit/compliance/iso42001/test_control_mapping.py`, update the Sprint 9.5 docstring/count text and the `_IMPLEMENTED`/`deferred` assertions so A.7.6 is in the implemented set and the deferred set is empty. Replace `test_a76_deferred_reason_acknowledges_reviewer_attested_storage` with a test asserting `hook_status == "implemented"` and `deferred_reason == ""`.

- [ ] **Step 4: Run — expect PASS** (the new test + the updated existing controls tests). Run: `uv run pytest tests/unit/compliance/ -q`

- [ ] **Step 5: HALT-BEFORE-COMMIT [STOP-RULE]** (ISO control mapping). Full gate ladder; halt summary that **explicitly calls out the A.7.6 deferred→implemented flip** for review; wait for token.

```bash
uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy src tests
git add src/cognic_agentos/compliance/iso42001/controls.py \
        tests/unit/compliance/iso42001/test_eval_bulk_iso.py \
        tests/unit/compliance/iso42001/test_control_mapping.py
git commit -m "$(printf 'feat(eval): tag eval.bulk_run under ISO A.7.6 + A.9.2 (ADR-010)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 14 [normal]: Neutral reference corpus

**Files:**
- Create: `src/cognic_agentos/evaluation/corpora/example/generic-completion-smoke.yaml`
- Test: `tests/unit/evaluation/test_reference_corpus.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/evaluation/test_reference_corpus.py
from __future__ import annotations

from pathlib import Path

import cognic_agentos.evaluation as evalpkg
from cognic_agentos.evaluation.corpus import load_corpus


def test_reference_corpus_loads_strictly() -> None:
    corpus_dir = Path(evalpkg.__file__).parent / "corpora" / "example"
    corpus = load_corpus(corpus_dir)
    assert corpus.corpus_id == "generic-completion-smoke"
    assert len(corpus.cases) >= 2
    # demonstrates BOTH scorer kinds across the corpus
    assert any(c.assertions is not None for c in corpus.cases)
    assert any(c.judge is not None for c in corpus.cases)
```

- [ ] **Step 2: Run — expect FAIL.** Run: `uv run pytest tests/unit/evaluation/test_reference_corpus.py -q`

- [ ] **Step 3: Create the neutral corpus** (no persona/bank specifics — format demo only):

```yaml
# src/cognic_agentos/evaluation/corpora/example/generic-completion-smoke.yaml
schema_version: 1
corpus_id: generic-completion-smoke
description: >
  Neutral format-demonstration corpus for the Sprint-12 bulk eval harness.
  Shows the single-shot message-list case shape with deterministic assertions
  and a judge rubric. NOT a persona/bank-specific agent corpus.

cases:
  - id: arithmetic-deterministic
    case_kind: completion
    messages:
      - role: system
        content: "Answer with only the number."
      - role: user
        content: "What is 2 + 2?"
    assertions:
      contains: ["4"]
      not_contains: ["error"]

  - id: greeting-judged
    case_kind: completion
    messages:
      - role: user
        content: "Greet the user politely."
    judge:
      rubric: "The response is a polite greeting."
      criteria:
        - name: politeness
          description: "The response greets the user in a polite, courteous tone."
          weight: 1.0

  - id: combined-assertion-and-judge
    case_kind: completion
    messages:
      - role: user
        content: "Name a primary color and explain why it is primary."
    assertions:
      regex: ["(?i)\\b(red|blue|yellow)\\b"]
    judge:
      rubric: "The answer names a primary color and gives a coherent reason."
      criteria:
        - name: correctness
          description: "Names red, blue, or yellow and explains primacy coherently."
```

- [ ] **Step 4: Run — expect PASS.** Run: `uv run pytest tests/unit/evaluation/test_reference_corpus.py -q`

- [ ] **Step 5: ruff (yaml is data, no mypy), commit by path.**

```bash
uv run pytest tests/unit/evaluation/test_reference_corpus.py -q
git add src/cognic_agentos/evaluation/corpora/example/generic-completion-smoke.yaml tests/unit/evaluation/test_reference_corpus.py
git commit -m "$(printf 'feat(eval): neutral generic-completion-smoke reference corpus (ADR-010)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

> **Packaging note:** no `pyproject.toml` change in Sprint 12. This task exercises the source-tree corpus directly; release-wheel data packaging is part of the Sprint 14 deployment/package check.

---

## Task 15 [CC]: Promote 4 modules to the coverage gate (117 → 121)

**Files:**
- Modify: `tools/check_critical_coverage.py` (`_CRITICAL_FILES` tail, ~line 2098)
- Modify: `tests/unit/tools/test_check_critical_coverage.py` (`_EXPECTED_ENTRY_COUNT` 117→121 + a `_SPRINT_12_GATE_MODULES` set-pin)

- [ ] **Step 1: Write the failing test** (set-pin + count bump, mirroring `_ADR_023_GATE_MODULES`)

```python
# add to tests/unit/tools/test_check_critical_coverage.py
_SPRINT_12_GATE_MODULES = (
    "src/cognic_agentos/evaluation/corpus.py",
    "src/cognic_agentos/evaluation/scorers.py",
    "src/cognic_agentos/evaluation/runner.py",
    "src/cognic_agentos/evaluation/storage.py",
)


def test_sprint_12_modules_present_with_standard_floors(gate_tool: ModuleType) -> None:
    by_path = {path: (line, branch) for path, line, branch in gate_tool._CRITICAL_FILES}
    for module in _SPRINT_12_GATE_MODULES:
        assert module in by_path, f"Sprint 12 module missing from gate: {module}"
        assert by_path[module] == (0.95, 0.90)
```

And bump `_EXPECTED_ENTRY_COUNT = 117` → `121`.

- [ ] **Step 2: Run — expect FAIL** (count guard + set-pin). Run: `uv run pytest tests/unit/tools/test_check_critical_coverage.py -q`

- [ ] **Step 3: Append the 4 entries** to `_CRITICAL_FILES` (before the closing `)`):

```python
    # Sprint 12 (ADR-010 amendment) evaluation harness — 4 CC modules, each
    # landed under its own halt-before-commit critical-controls review:
    #   * corpus.py   — strict fail-closed corpus contract + loader (a bug here
    #     lets malformed corpora through into execution).
    #   * scorers.py  — evaluator/pass-fail logic (the gradable-quality boundary).
    #   * runner.py   — run orchestration + per-case error isolation.
    #   * storage.py  — atomic eval evidence + tenant boundary + value-free chain.
    # target.py / types.py + the portal route/DTO stay OFF-gate (R32 precedent).
    ("src/cognic_agentos/evaluation/corpus.py", 0.95, 0.90),
    ("src/cognic_agentos/evaluation/scorers.py", 0.95, 0.90),
    ("src/cognic_agentos/evaluation/runner.py", 0.95, 0.90),
    ("src/cognic_agentos/evaluation/storage.py", 0.95, 0.90),
```

Also update the running-total comment block above `_EXPECTED_ENTRY_COUNT` to add `+ 4 Sprint-12 eval-harness modules = 121`.

- [ ] **Step 4: VERIFY THE FLOOR AGAINST FRESH COVERAGE** (per `feedback_verify_promotion_meets_floor_at_promotion_time`):

```bash
uv run pytest -q --cov=src/cognic_agentos --cov-branch --cov-report=json:coverage.json
uv run python tools/check_critical_coverage.py
uv run pytest tests/unit/tools/test_check_critical_coverage.py -q
```

Expected: the gate reports all 121 entries at/above 95%/90%, including the 4 new modules. **If any of the 4 is below floor, stop before committing, add focused negative-path tests with exact paths, and update this task's final `git add` line before staging.** Then re-run the fresh coverage gate.

- [ ] **Step 5: HALT-BEFORE-COMMIT [CC].** Halt summary stating the fresh-coverage numbers for the 4 promoted modules; wait for token. (`coverage.json` is gitignored — do not stage it.)

```bash
git add tools/check_critical_coverage.py tests/unit/tools/test_check_critical_coverage.py
git commit -m "$(printf 'chore(eval): promote 4 eval-harness modules to CC gate (117->121)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 16 [STOP-RULE]: ADR-010 amendment + BUILD_PLAN path correction

**Files:**
- Modify: `docs/adrs/ADR-010-evaluation-harness.md` (append a Sprint-12 amendment section)
- Modify: `docs/BUILD_PLAN.md` (correct Sprint 12 `eval/...` → `evaluation/...` paths)
- (No test — docs.)

- [ ] **Step 1: Append the ADR-010 amendment** documenting the Sprint-12 decisions:
  - `EvaluationTarget` / `CaseScorer` plug-in seams; `GatewayTarget` as the only Wave-1 target (OS-only — no Layer-C packs in this repo).
  - Single-shot message-list `completion` case kind; `case_kind` reserved discriminator for Sprint-13 (`replay` / `tool_invocation` / `a2a_agent`).
  - `persist_raw_output` opt-in (default false) + `raw_output_persisted` / `output_truncated` evidence flags.
  - Value-free aggregate `eval.bulk_run` chain row; back-link by `chain_request_id` (no `chain_record_id`); ISO **A.7.6** (flipped to implemented) **+ A.9.2**.
  - Deferred to Sprint 13: replay/adversarial/promotion-gate scorers + targets; multi-turn; weighted scoring; background large-corpus queue.
  - File-placement refinements vs the spec (models in `corpus.py`; `EvalRunStore(history)`; runner receives identity).

- [ ] **Step 2: Correct the BUILD_PLAN** — in the Sprint 12 section, change the `eval/__init__.py`, `eval/runner.py`, `eval/scenarios.py`, `eval/storage.py`, `eval/cli.py`, `eval/corpora/example/` references to the `evaluation/...` paths actually used (and note the bulk endpoint path `POST /api/v1/eval/bulk-run`). Per `feedback_patch_plan_against_doctrine` — fix the source-of-truth claim in the same commit that contradicts it.

- [ ] **Step 3: HALT-BEFORE-COMMIT [STOP-RULE]** (ADR + BUILD_PLAN are source-of-truth docs). Halt summary; wait for token. Docs-only; no pytest required, but run `uv run ruff format --check` is N/A for markdown — skip.

```bash
git add docs/adrs/ADR-010-evaluation-harness.md docs/BUILD_PLAN.md
git commit -m "$(printf 'docs(eval): ADR-010 Sprint-12 amendment + BUILD_PLAN path correction\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Self-review (run against the spec)

**Spec coverage:** §1 layout → Tasks 1–14 + the migration (T7). §2 seams → T3 (target) + T4 (scorers) + T5 (runner). §3 corpus → T2 + T14. §4 portal API → T10 + T11; settings → T6. §5 storage/chain/ISO → T7 + T8 + T13. §6 CLI → T12. §7 closed enums (T2 `CorpusLoadReason`, T10 `EvalBulkRefusalReason`), RBAC (T9), CC gate (T15), ADR (T16), reference corpus (T14), deferred items (T16 ADR). §8 harness alignment → recorded in the ADR amendment (T16). **No spec section is unmapped.**

**Type consistency:** `CandidateOutput` / `ScorerResult` / `CriterionDetail` / `CaseResult` / `EvalRunResult` (T1) are consumed unchanged by T3/T4/T5/T8/T10. `EvalCase`/`Corpus`/`AssertionsBlock`/`JudgeBlock`/`JudgeCriterionSpec` (T2) consumed by T3/T4/T5/T10/T12. `EvalRunner.run(corpus, *, target, scorers, run_id, chain_request_id, tenant_id, capture_raw_output=False)` signature is identical in T5 (def) and T10 (call). `EvalRunStore(history)` + `persist_run(*, result, actor_subject, tenant_id)` + `get_run(*, run_id, tenant_id)` identical in T8 (def) and T10 (call). `build_eval_bulk_routes(*, max_cases, max_raw_output_chars, target_tier, judge_tier)` identical in T10 (def) and T11 (call).

**Placeholder scan:** no `TODO` / `TBD` / `Implementer note` / open staging placeholder remains. The raw-output path, `GatewayTarget.tier`, route e2e tests, A.7.6 control-mapping test update, and CLI `--corpus` contract are all baked into the task bodies with exact code and paths.
