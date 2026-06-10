from __future__ import annotations

from typing import Any

from cognic_agentos.portal.api.packs.review_routes import _build_adversarial_gate_input


def _snap(**over: object) -> dict[str, Any]:
    # A clean, SELF-CONSISTENT baseline-evaluated snapshot (the producer's
    # baseline-supplied shape): regression_evaluated=True ⇒ baseline_run_id is a str.
    base: dict[str, Any] = {
        "pass_rate": 1.0,
        "high_severity_failures": 0,
        "regressions": 0,
        "regression_evaluated": True,
        "candidate_run_id": "run-1",
        "baseline_run_id": "base-1",
    }
    base.update(over)
    return base


def test_clean_snapshot_is_green_with_pointer() -> None:
    gi = _build_adversarial_gate_input(_snap(), pass_rate_floor=0.99)
    assert gi.outcome == "green" and gi.red_reason is None
    assert gi.candidate_run_id == "run-1"
    assert gi.regressions == 0 and gi.regression_evaluated is True


def test_regression_is_red() -> None:
    gi = _build_adversarial_gate_input(_snap(regressions=1), pass_rate_floor=0.99)
    assert gi.outcome == "red" and gi.red_reason == "adversarial_baseline_regression"


def test_precedence_high_severity_beats_regression_and_passrate() -> None:
    gi = _build_adversarial_gate_input(
        _snap(high_severity_failures=1, regressions=3, pass_rate=0.1), pass_rate_floor=0.99
    )
    assert gi.red_reason == "adversarial_high_severity_failure"


def test_precedence_regression_beats_passrate() -> None:
    gi = _build_adversarial_gate_input(_snap(regressions=2, pass_rate=0.1), pass_rate_floor=0.99)
    assert gi.red_reason == "adversarial_baseline_regression"


def test_passrate_below_floor_is_red() -> None:
    gi = _build_adversarial_gate_input(_snap(pass_rate=0.5), pass_rate_floor=0.99)
    assert gi.red_reason == "adversarial_corpus_pass_rate_below_threshold"


def test_legit_absent_baseline_is_green() -> None:
    # The producer's no-baseline shape: evaluated=False, regressions=0, baseline None.
    gi = _build_adversarial_gate_input(
        _snap(regression_evaluated=False, regressions=0, baseline_run_id=None),
        pass_rate_floor=0.99,
    )
    assert gi.outcome == "green" and gi.red_reason is None
    assert gi.regression_evaluated is False and gi.regressions == 0


def test_inconsistent_unevaluated_regression_is_evidence_not_attached() -> None:
    # Reviewer P1: regression_evaluated=False MUST pair with regressions==0 +
    # baseline None. A contradictory snapshot is malformed evidence → fail
    # closed, NOT green (the pre-fix behaviour silently greenlit it).
    gi = _build_adversarial_gate_input(
        _snap(regression_evaluated=False, regressions=5, baseline_run_id=None),
        pass_rate_floor=0.99,
    )
    assert gi.outcome == "evidence_not_attached"
    assert gi.red_reason == "adversarial_evidence_not_attached"


def test_evaluated_true_without_baseline_id_is_evidence_not_attached() -> None:
    # Reviewer P1: regression_evaluated=True with a null baseline_run_id is
    # self-inconsistent → fail closed.
    gi = _build_adversarial_gate_input(
        _snap(regression_evaluated=True, baseline_run_id=None), pass_rate_floor=0.99
    )
    assert gi.outcome == "evidence_not_attached"


def test_missing_candidate_run_id_is_evidence_not_attached() -> None:
    # Reviewer P1: candidate_run_id IS the gate evidence pointer; a dict snapshot
    # missing it fails closed (not a silent None on an otherwise-green gate).
    snap = _snap()
    del snap["candidate_run_id"]
    gi = _build_adversarial_gate_input(snap, pass_rate_floor=0.99)
    assert gi.outcome == "evidence_not_attached"
    assert gi.candidate_run_id is None


def test_non_string_candidate_run_id_is_evidence_not_attached() -> None:
    gi = _build_adversarial_gate_input(_snap(candidate_run_id=123), pass_rate_floor=0.99)
    assert gi.outcome == "evidence_not_attached"
    assert gi.candidate_run_id is None


def test_invalid_regressions_routes_to_evidence_not_attached() -> None:
    for bad in (-1, True, 1.5, "2", None):
        gi = _build_adversarial_gate_input(_snap(regressions=bad), pass_rate_floor=0.99)
        assert gi.outcome == "evidence_not_attached"
        assert gi.red_reason == "adversarial_evidence_not_attached"


def test_invalid_regression_evaluated_routes_to_evidence_not_attached() -> None:
    gi = _build_adversarial_gate_input(_snap(regression_evaluated="yes"), pass_rate_floor=0.99)
    assert gi.outcome == "evidence_not_attached"


def test_missing_payload_still_evidence_not_attached() -> None:
    gi = _build_adversarial_gate_input(None, pass_rate_floor=0.99)
    assert gi.outcome == "evidence_not_attached"
    assert gi.candidate_run_id is None
