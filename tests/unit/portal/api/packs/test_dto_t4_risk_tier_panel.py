"""Sprint 7B.3 T4 Slice C — :class:`RiskTierPanel` DTO drift detectors.

The DTO is the wire-protocol contract for ``GET /api/v1/packs/
{pack_id}/evidence/risk-tier``. Drift between the DTO field-set / type
annotations and the :class:`RiskTierPanelData` projector output (or
the :data:`ApprovalFlowKind` Literal at the projector module) is
wire-protocol-public regression — caught here.
"""

from __future__ import annotations

import typing
from typing import ClassVar

import pydantic
import pytest

from cognic_agentos.packs.evidence.risk_tier import (
    ApprovalFlowKind,
    RiskTierPanelData,
)
from cognic_agentos.portal.api.packs.dto import RiskTierPanel


class TestSprint7B3T4SliceCRiskTierPanelDTO:
    """Drift detectors + interop tests for the DTO."""

    _EXPECTED_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "pack_kind",
            "risk_tier",
            "approval_flow",
            "approval_flow_description",
        }
    )

    def test_exact_field_set(self) -> None:
        """Lock the exact 4-field shape per plan §318."""
        assert frozenset(RiskTierPanel.model_fields.keys()) == self._EXPECTED_FIELDS

    def test_dto_is_frozen(self) -> None:
        """``frozen=True`` MUST be inherited from
        :class:`PackBaseModel` so the DTO matches every other pack-
        API response wire-shape (no in-flight mutation)."""
        assert RiskTierPanel.model_config.get("frozen") is True

    def test_dto_rejects_extra_fields(self) -> None:
        """``extra="forbid"`` MUST be inherited — smuggled fields
        refuse at validation."""
        assert RiskTierPanel.model_config.get("extra") == "forbid"

    def test_dto_supports_from_attributes(self) -> None:
        """``from_attributes=True`` lets the route handler call
        :meth:`RiskTierPanel.model_validate` directly on the projector's
        :class:`RiskTierPanelData` output without a
        :func:`dataclasses.asdict` step."""
        assert RiskTierPanel.model_config.get("from_attributes") is True

    def test_approval_flow_is_narrow_literal(self) -> None:
        """The DTO's ``approval_flow`` annotation MUST be the same
        :data:`ApprovalFlowKind` Literal that the projector emits —
        Pydantic v2's strict-mode validates the value against the
        Literal at construction time, refusing any out-of-vocab leak.

        Drift between this annotation and the projector's emitted
        type would be silently caught by Pydantic at runtime; this
        regression catches it at test time."""
        annotation = RiskTierPanel.model_fields["approval_flow"].annotation
        # Compare the Literal members via ``typing.get_args`` rather
        # than identity — mypy sees ``annotation`` as
        # ``type[Any] | None`` while :data:`ApprovalFlowKind` is a
        # Literal special form, so the narrow identity probe fails
        # static analysis. The ``get_args`` round-trip catches drift
        # equivalently: the DTO's annotation MUST carry the same set
        # of Literal members the projector emits.
        assert frozenset(typing.get_args(annotation)) == frozenset(
            typing.get_args(ApprovalFlowKind)
        )

    def test_panel_data_roundtrips_via_model_validate(self) -> None:
        """The interop contract: :meth:`model_validate` on the
        projector's :class:`RiskTierPanelData` output produces a valid
        DTO with identical field values."""
        panel_data = RiskTierPanelData(
            pack_kind="agent",
            risk_tier="payment_action",
            approval_flow="four_eyes",
            approval_flow_description="Four-eyes approval...",
        )
        dto = RiskTierPanel.model_validate(panel_data)
        assert dto.pack_kind == "agent"
        assert dto.risk_tier == "payment_action"
        assert dto.approval_flow == "four_eyes"
        assert dto.approval_flow_description == "Four-eyes approval..."

    def test_dto_refuses_out_of_vocab_approval_flow(self) -> None:
        """Pydantic v2 strict-mode refusal: an out-of-vocab
        ``approval_flow`` value MUST raise
        :class:`pydantic.ValidationError` rather than silently
        accepting. Defends against a future drift where the projector
        starts emitting a stale value the DTO no longer accepts."""
        with pytest.raises(pydantic.ValidationError):
            RiskTierPanel.model_validate(
                {
                    "pack_kind": "tool",
                    "risk_tier": "read_only",
                    "approval_flow": "not_a_valid_flow",
                    "approval_flow_description": "...",
                }
            )

    def test_dto_field_count_matches_projector_field_count(self) -> None:
        """The DTO field count MUST equal the projector dataclass
        field count — a new projector field landing without a
        corresponding DTO field would silently drop on the wire."""
        import dataclasses

        projector_fields = {f.name for f in dataclasses.fields(RiskTierPanelData)}
        assert frozenset(RiskTierPanel.model_fields.keys()) == projector_fields

    def test_approval_flow_kind_covers_all_dto_values(self) -> None:
        """Every value the DTO can carry MUST be a member of
        :data:`ApprovalFlowKind` — vacuous-test guard pinned via
        ``typing.get_args`` on both sides."""
        assert frozenset(typing.get_args(ApprovalFlowKind)) == frozenset(
            {
                "auto_run",
                "audit_emphasis",
                "single_approval",
                "four_eyes",
                "four_eyes_categorised",
                "operator_legal_signoff",
                "pack_declared",
            }
        )
