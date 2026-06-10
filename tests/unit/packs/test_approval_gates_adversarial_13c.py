from __future__ import annotations

import typing

from cognic_agentos.packs.approval_gates import (
    AdversarialGateInput,
    AdversarialRedReason,
    EvaluationGateInput,
    OwaspGateInput,
    SignatureGateInput,
    compose_approval_gates,
)


def _green_sig() -> SignatureGateInput:
    return SignatureGateInput(outcome="green", red_reason=None, signature_digest="sig123")


def _green_eval() -> EvaluationGateInput:
    return EvaluationGateInput(outcome="green", red_reason=None, pass_rate=1.0, threshold=0.9)


def _green_owasp() -> OwaspGateInput:
    return OwaspGateInput(outcome="green", red_reason=None, owasp_overall_status="green")


_ACK = {
    "data_governance_acknowledged": True,
    "risk_tier_acknowledged": True,
    "supply_chain_acknowledged": True,
    "conformance_acknowledged": True,
}


def test_adversarial_red_reason_has_baseline_regression() -> None:
    assert "adversarial_baseline_regression" in set(typing.get_args(AdversarialRedReason))


def test_gate3_evidence_pointer_is_candidate_run_id() -> None:
    adv = AdversarialGateInput(
        outcome="green",
        red_reason=None,
        pass_rate=1.0,
        high_severity_failures=0,
        regressions=0,
        regression_evaluated=True,
        candidate_run_id="run-xyz",
    )
    comp = compose_approval_gates(
        signature_input=_green_sig(),
        evaluation_input=_green_eval(),
        adversarial_input=adv,
        owasp_input=_green_owasp(),
        pack_kind="tool",
        reviewer_acknowledgement=_ACK,
    )
    g3 = next(g for g in comp.gates if g.gate == "adversarial")
    assert g3.outcome == "green"
    assert g3.evidence_pointer == "run-xyz"
    assert comp.all_green is True


def test_gate3_red_reason_passed_through_verbatim() -> None:
    adv = AdversarialGateInput(
        outcome="red",
        red_reason="adversarial_baseline_regression",
        pass_rate=1.0,
        high_severity_failures=0,
        regressions=2,
        regression_evaluated=True,
        candidate_run_id="r",
    )
    comp = compose_approval_gates(
        signature_input=_green_sig(),
        evaluation_input=_green_eval(),
        adversarial_input=adv,
        owasp_input=_green_owasp(),
        pack_kind="tool",
        reviewer_acknowledgement=_ACK,
    )
    g3 = next(g for g in comp.gates if g.gate == "adversarial")
    assert g3.outcome == "red" and g3.red_reason == "adversarial_baseline_regression"
    assert comp.all_green is False
    # adversarial is overridable (only signature is non-overridable)
    assert "adversarial" not in comp.non_overridable_red_gates
