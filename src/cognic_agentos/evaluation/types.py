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
ScorerName = Literal["assertions", "judge", "refusal"]


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
