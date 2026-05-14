"""Sprint 7B.3 T9 Slice C — ApproveRefusalResponse DTO tests.

Per the plan-of-record §177 + §518 + §522: the T9 ``POST
/{pack_id}/approve`` endpoint returns a **412 Precondition Failed**
body when the 5-gate composition is not all-green. The body carries:

- the gate composition's red-state payload (``pack_kind`` / ``gates``
  / ``all_green`` / ``non_overridable_red_gates``) — the SAME shape
  :func:`~cognic_agentos.packs.approval_gates.composition_snapshot`
  emits, so the handler builds the body straight from the snapshot;
- an optional ``override_refusal_reason`` closed-enum
  (:data:`~cognic_agentos.packs.approval_gates.OverrideRefusalReason`)
  populated ONLY on the override-attempted-but-refused 412 branch.

The DTO consumes composer vocabularies (``portal → packs`` arrow);
the composer never imports portal.
"""

from __future__ import annotations

import typing

import pydantic
import pytest

from cognic_agentos.packs.approval_gates import (
    AdversarialGateInput,
    ApprovalGateComposition,
    EvaluationGateInput,
    OwaspGateInput,
    SignatureGateInput,
    compose_approval_gates,
    composition_snapshot,
)
from cognic_agentos.portal.api.packs.dto import (
    ApproveGateResult,
    ApproveRefusalResponse,
)

_ACK_ALL_TRUE = {
    "data_governance_acknowledged": True,
    "risk_tier_acknowledged": True,
    "supply_chain_acknowledged": True,
    "conformance_acknowledged": True,
}


def _red_signature_composition() -> ApprovalGateComposition:
    """A not-all-green composition with a red (non-overridable) gate 1."""
    return compose_approval_gates(
        signature_input=SignatureGateInput(
            outcome="red",
            red_reason="signature_cosign_verify_failed",
            signature_digest=None,
        ),
        evaluation_input=EvaluationGateInput(
            outcome="green", red_reason=None, pass_rate=1.0, threshold=0.9
        ),
        adversarial_input=AdversarialGateInput(
            outcome="green", red_reason=None, pass_rate=1.0, high_severity_failures=0
        ),
        owasp_input=OwaspGateInput(outcome="green", red_reason=None, owasp_overall_status="green"),
        pack_kind="tool",
        reviewer_acknowledgement=_ACK_ALL_TRUE,
    )


class TestSprint7B3T9SliceCApproveRefusalResponse:
    """The 412 refusal body DTO."""

    def test_validates_from_a_composition_snapshot(self) -> None:
        snapshot = composition_snapshot(_red_signature_composition())
        body = ApproveRefusalResponse(**snapshot)
        assert body.pack_kind == "tool"
        assert body.all_green is False
        assert body.non_overridable_red_gates == ["signature"]
        assert [g.gate for g in body.gates] == [
            "signature",
            "evaluation",
            "adversarial",
            "owasp_conformance",
            "reviewer_acknowledgement",
        ]
        assert body.override_refusal_reason is None

    def test_nested_gate_result_projects_red_reason_and_pointer(self) -> None:
        snapshot = composition_snapshot(_red_signature_composition())
        body = ApproveRefusalResponse(**snapshot)
        signature_gate = body.gates[0]
        assert isinstance(signature_gate, ApproveGateResult)
        assert signature_gate.outcome == "red"
        assert signature_gate.red_reason == "signature_cosign_verify_failed"
        assert signature_gate.evidence_pointer is None

    def test_override_refusal_reason_accepts_a_closed_enum_value(self) -> None:
        snapshot = composition_snapshot(_red_signature_composition())
        body = ApproveRefusalResponse(
            **snapshot, override_refusal_reason="non_overridable_red_gate"
        )
        assert body.override_refusal_reason == "non_overridable_red_gate"

    def test_field_set_is_exactly_five_keys(self) -> None:
        assert set(ApproveRefusalResponse.model_fields) == {
            "pack_kind",
            "gates",
            "all_green",
            "non_overridable_red_gates",
            "override_refusal_reason",
        }

    def test_is_frozen(self) -> None:
        snapshot = composition_snapshot(_red_signature_composition())
        body = ApproveRefusalResponse(**snapshot)
        with pytest.raises(pydantic.ValidationError):
            body.all_green = True

    def test_forbids_extra_fields(self) -> None:
        snapshot = composition_snapshot(_red_signature_composition())
        with pytest.raises(pydantic.ValidationError):
            # intentional extra field — exercises ``extra="forbid"``.
            ApproveRefusalResponse(**snapshot, smuggled="x")  # type: ignore[call-arg]

    def test_override_refusal_reason_rejects_out_of_vocab_value(self) -> None:
        snapshot = composition_snapshot(_red_signature_composition())
        with pytest.raises(pydantic.ValidationError):
            # intentional out-of-vocab value — exercises the closed-enum.
            ApproveRefusalResponse(
                **snapshot,
                override_refusal_reason="not_a_real_reason",  # type: ignore[arg-type]
            )

    def test_model_dump_round_trips_to_a_canonical_safe_dict(self) -> None:
        # The handler raises HTTPException(412, detail=body.model_dump()).
        snapshot = composition_snapshot(_red_signature_composition())
        body = ApproveRefusalResponse(**snapshot)
        dumped = body.model_dump()
        assert dumped["non_overridable_red_gates"] == ["signature"]
        assert isinstance(dumped["gates"], list)
        assert all(isinstance(g, dict) for g in dumped["gates"])


class TestSprint7B3T9SliceCArrowInvariant:
    """The DTO consumes composer vocabularies — drift detector."""

    def test_gate_result_red_reason_typed_against_composer_union(self) -> None:
        from cognic_agentos.packs.approval_gates import ApprovalGateRedReason

        hints = typing.get_type_hints(ApproveGateResult)
        assert hints["red_reason"] == (ApprovalGateRedReason | None)
