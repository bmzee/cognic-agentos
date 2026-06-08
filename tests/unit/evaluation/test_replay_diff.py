# tests/unit/evaluation/test_replay_diff.py
from __future__ import annotations

import uuid
from typing import Any

from cognic_agentos.evaluation.replay import compute_replay_diff
from cognic_agentos.evaluation.types import CaseOutcome, CaseResult, EvalRunResult


def _case(
    case_id: str,
    *,
    passed: bool,
    outcome: CaseOutcome = "succeeded",
    output_digest: str = "o",
    model: str = "m2",
) -> CaseResult:
    return CaseResult(
        case_id=case_id,
        passed=passed,
        outcome=outcome,
        scorer_results=(),
        latency_ms=1,
        model=model,
        input_digest="i",
        output_digest=output_digest,
        candidate_output_text=None,
        raw_output_persisted=False,
        output_truncated=False,
    )


def _candidate(cases: list[CaseResult]) -> EvalRunResult:
    return EvalRunResult(
        run_id=uuid.uuid4(),
        chain_request_id="r",
        corpus_id="cp",
        corpus_digest="d",
        target_kind="gateway",
        tier="tier2",
        total=len(cases),
        passed=sum(1 for c in cases if c.outcome == "succeeded" and c.passed),
        failed=sum(1 for c in cases if c.outcome == "succeeded" and not c.passed),
        errored=sum(1 for c in cases if c.outcome == "errored"),
        latency_p50_ms=1,
        latency_p95_ms=1,
        cases=tuple(cases),
    )


def _baseline_case(
    case_id: str,
    *,
    passed: bool,
    outcome: str = "succeeded",
    output_digest: str = "o",
    model: str = "m1",
) -> dict[str, Any]:
    # shape of an eval_case_results row._mapping
    return {
        "case_id": case_id,
        "passed": passed,
        "outcome": outcome,
        "output_digest": output_digest,
        "model": model,
    }


def test_every_drift_kind() -> None:
    baseline_id = uuid.uuid4()
    baseline_cases = [
        _baseline_case("reg", passed=True),  # → regression
        _baseline_case("imp", passed=False),  # → improvement
        _baseline_case("same", passed=True, output_digest="x"),  # → unchanged
        _baseline_case("drift", passed=True, output_digest="x"),  # → output_changed
        _baseline_case("err", passed=True),  # → errored (candidate errored)
    ]
    candidate = _candidate(
        [
            _case("reg", passed=False),
            _case("imp", passed=True),
            _case("same", passed=True, output_digest="x"),
            _case("drift", passed=True, output_digest="y"),
            _case("err", passed=False, outcome="errored"),
        ]
    )
    diff = compute_replay_diff(
        baseline_run_id=baseline_id,
        candidate=candidate,
        baseline_cases=baseline_cases,
        baseline_tier="tier1",
    )
    kinds = {cd.case_id: cd.drift_kind for cd in diff.cases}
    assert kinds == {
        "reg": "regression",
        "imp": "improvement",
        "same": "unchanged",
        "drift": "output_changed",
        "err": "errored",
    }
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
    baseline_cases = [
        _baseline_case("b", passed=True),
        _baseline_case("a", passed=True),
    ]  # baseline order: b, a
    candidate = _candidate(
        [
            _case("a", passed=True, output_digest="o"),
            _case("b", passed=True, output_digest="o"),
        ]
    )  # candidate order: a, b
    diff = compute_replay_diff(
        baseline_run_id=baseline_id,
        candidate=candidate,
        baseline_cases=baseline_cases,
        baseline_tier="tier1",
    )
    assert [cd.case_id for cd in diff.cases] == ["a", "b"]  # candidate/corpus order


def test_no_regressions_flag_false_when_only_improvements() -> None:
    baseline_id = uuid.uuid4()
    baseline_cases = [_baseline_case("x", passed=False)]
    candidate = _candidate([_case("x", passed=True)])
    diff = compute_replay_diff(
        baseline_run_id=baseline_id,
        candidate=candidate,
        baseline_cases=baseline_cases,
        baseline_tier="tier1",
    )
    assert diff.has_regressions is False and diff.improvements == 1


def test_baseline_only_case_emitted_as_errored_after_candidate_cases() -> None:
    # Defensive pin (spec §4): a baseline case with no candidate is appended as
    # errored AFTER the candidate-order cases (never silently dropped).
    baseline_id = uuid.uuid4()
    baseline_cases = [
        _baseline_case("present", passed=True),
        _baseline_case("gone", passed=True),
    ]
    candidate = _candidate([_case("present", passed=True, output_digest="o")])  # "gone" absent
    diff = compute_replay_diff(
        baseline_run_id=baseline_id,
        candidate=candidate,
        baseline_cases=baseline_cases,
        baseline_tier="tier1",
    )
    assert [cd.case_id for cd in diff.cases] == [
        "present",
        "gone",
    ]  # candidate first, baseline-only last
    gone = diff.cases[-1]
    assert gone.drift_kind == "errored" and gone.candidate_outcome == "errored"
    assert gone.candidate_model == "" and gone.baseline_model == "m1"
    assert diff.errored == 1


def test_classify_baseline_none_when_candidate_case_absent_from_baseline() -> None:
    # Exercises the defensive ``if baseline is None: return "errored"`` branch in
    # ``_classify`` — reachable when a candidate case_id has no matching baseline row
    # (should not happen under a matching corpus_digest, but must be covered).
    baseline_id = uuid.uuid4()
    candidate = _candidate([_case("new_case", passed=True)])
    diff = compute_replay_diff(
        baseline_run_id=baseline_id,
        candidate=candidate,
        baseline_cases=[],  # no baseline → baseline lookup returns None
        baseline_tier="tier1",
    )
    assert len(diff.cases) == 1
    cd = diff.cases[0]
    assert cd.drift_kind == "errored"
    assert cd.baseline_passed is False
    assert cd.baseline_outcome == "errored"
    assert cd.baseline_model == ""
