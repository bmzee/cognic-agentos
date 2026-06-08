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
    out = CandidateOutput(text="hello", model="m", tier="tier1", latency_ms=5, outcome="succeeded")
    assert out.outcome == "succeeded"
    with __import__("pytest").raises(dataclasses.FrozenInstanceError):
        out.text = "x"  # type: ignore[misc]


def test_scorer_result_carries_criterion_detail_and_critique() -> None:
    detail = CriterionDetail(name="contains:capital adequacy", passed=False, critique="missing")
    sr = ScorerResult(
        scorer="assertions",
        passed=False,
        detail=(detail,),
        verdict=None,
        score=None,
        rationale=None,
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
