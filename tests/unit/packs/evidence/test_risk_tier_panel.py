"""Sprint 7B.3 T4 — risk-tier evidence-panel CRITICAL CONTROLS tests.

Slice A coverage (drift detectors): pins the closed-enum 7-value
Literal at
:data:`cognic_agentos.packs.evidence.risk_tier.ApprovalFlowKind` per
plan §319 + the 1:1 ``risk_tier → approval_flow`` mapping table at
module scope per plan §320. Drift between this Literal and:

- The :class:`RiskTierPanel` DTO at ``portal/api/packs/dto.py`` — the
  wire-protocol contract for the ``approval_flow`` field.
- The :data:`~cognic_agentos.cli._governance_vocab.RiskTier` Literal —
  every value must map to exactly one :data:`ApprovalFlowKind`.
- ADR-014 §24-37 (risk-tier table) — the canonical source of truth
  for which approval flow applies to which tier.

is wire-protocol-public regression.

Slice B coverage (projector contract): pins the pure-functional
:func:`project_risk_tier_panel` contract per plan §317-321:

- Reads ``manifest["risk_tier"]["tier"]`` defensively (missing block,
  non-dict block, unknown tier values all default to empty / unknown
  sentinel).
- Echoes ``record_kind`` verbatim onto the output's ``pack_kind``.
- Each of the 8 risk-tier values maps to its expected
  :data:`ApprovalFlowKind` (auto-run / audit-emphasis / single-approval
  / four-eyes / four-eyes-categorised / operator-legal / pack-declared
  per ADR-014).
"""

from __future__ import annotations

import typing
from typing import ClassVar

from cognic_agentos.cli._governance_vocab import RiskTier
from cognic_agentos.packs.evidence import risk_tier as _module
from cognic_agentos.packs.evidence.risk_tier import (
    _RISK_TIER_TO_APPROVAL_FLOW,
    ApprovalFlowKind,
    RiskTierPanelData,
    project_risk_tier_panel,
)

# ---------------------------------------------------------------------------
# Sprint 7B.3 T4 Slice A — :data:`ApprovalFlowKind` vocabulary
# ---------------------------------------------------------------------------


class TestSprint7B3T4SliceAApprovalFlowKindVocab:
    """Drift detectors for :data:`ApprovalFlowKind`."""

    _EXPECTED_VALUES: ClassVar[frozenset[str]] = frozenset(
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

    def test_exact_value_set(self) -> None:
        """Lock the exact 7-value vocabulary per plan §319."""
        assert frozenset(typing.get_args(ApprovalFlowKind)) == self._EXPECTED_VALUES

    def test_exact_count(self) -> None:
        """Count guard pinned independently for crisp drift-diagnosis."""
        assert len(typing.get_args(ApprovalFlowKind)) == 7

    def test_module_all_surface_includes_approval_flow_kind(self) -> None:
        """``ApprovalFlowKind`` MUST appear in the module's ``__all__``."""
        assert "ApprovalFlowKind" in _module.__all__


# ---------------------------------------------------------------------------
# Sprint 7B.3 T4 Slice A — risk_tier → approval_flow mapping table
# ---------------------------------------------------------------------------


class TestSprint7B3T4SliceAMappingTable:
    """The 1:1 mapping table is wire-protocol-public per plan §320.

    Each :data:`RiskTier` value MUST resolve to exactly one
    :data:`ApprovalFlowKind`; drift in either direction (a risk tier
    missing from the table OR a stale tier still in the table after
    the canonical Literal narrows) is caught here.
    """

    def test_mapping_covers_every_risk_tier_exactly_once(self) -> None:
        """The mapping table's keyset MUST equal
        ``frozenset(typing.get_args(RiskTier))`` — one row per tier."""
        assert frozenset(_RISK_TIER_TO_APPROVAL_FLOW.keys()) == frozenset(typing.get_args(RiskTier))

    def test_mapping_values_are_all_approval_flow_kinds(self) -> None:
        """Every mapping value MUST be a member of
        :data:`ApprovalFlowKind` — drift would let a stale value leak
        onto the wire."""
        approval_flow_values = frozenset(typing.get_args(ApprovalFlowKind))
        for tier, flow in _RISK_TIER_TO_APPROVAL_FLOW.items():
            assert flow in approval_flow_values, f"tier {tier} maps to non-flow {flow!r}"

    def test_canonical_mapping_per_adr_014(self) -> None:
        """Per ADR-014 §30-37 — pin the canonical row-by-row mapping.

        ADR-014 is the source of truth; drift in the production
        mapping table is caught by this regression. Any change here
        requires a corresponding amendment to ADR-014 §30-37.

        - ``read_only`` → ``auto_run`` (ADR-014 §30 — "Auto-run. No
          approval. Audit-logged like any call.")
        - ``internal_write`` → ``audit_emphasis`` (§31 — "Auto-run
          with audit emphasis.")
        - ``customer_data_read`` → ``single_approval`` (§32 — "Just-in-
          time approval by a single approver...")
        - ``customer_data_write`` → ``single_approval`` (§33 — "Just-
          in-time approval + per-call reason code"; same single-
          approver flow as customer_data_read per ADR-014 phrasing)
        - ``payment_action`` → ``four_eyes`` (§34 — "4-eyes (two
          distinct approvers...)")
        - ``regulator_communication`` → ``four_eyes_categorised`` (§35
          — "4-eyes + categorised reason...")
        - ``cross_tenant`` → ``operator_legal_signoff`` (§36 — "4-eyes
          + bank legal sign-off scope.")
        - ``high_risk_custom`` → ``pack_declared`` (§37 — "Reviewer-
          defined approval flow per pack manifest")
        """
        assert _RISK_TIER_TO_APPROVAL_FLOW["read_only"] == "auto_run"
        assert _RISK_TIER_TO_APPROVAL_FLOW["internal_write"] == "audit_emphasis"
        assert _RISK_TIER_TO_APPROVAL_FLOW["customer_data_read"] == "single_approval"
        assert _RISK_TIER_TO_APPROVAL_FLOW["customer_data_write"] == "single_approval"
        assert _RISK_TIER_TO_APPROVAL_FLOW["payment_action"] == "four_eyes"
        assert _RISK_TIER_TO_APPROVAL_FLOW["regulator_communication"] == "four_eyes_categorised"
        assert _RISK_TIER_TO_APPROVAL_FLOW["cross_tenant"] == "operator_legal_signoff"
        assert _RISK_TIER_TO_APPROVAL_FLOW["high_risk_custom"] == "pack_declared"


# ---------------------------------------------------------------------------
# Sprint 7B.3 T4 Slice B — :func:`project_risk_tier_panel` contract
# ---------------------------------------------------------------------------


class TestSprint7B3T4SliceBProjectRiskTierPanel:
    """Pure-functional projector contract per plan §317-321."""

    _BASE_MANIFEST: ClassVar[dict[str, object]] = {
        "risk_tier": {"tier": "customer_data_read"},
    }

    def test_returns_risk_tier_panel_data_instance(self) -> None:
        result = project_risk_tier_panel(manifest=self._BASE_MANIFEST, record_kind="tool")
        assert isinstance(result, RiskTierPanelData)

    def test_pack_kind_echoes_record_kind_verbatim(self) -> None:
        """``pack_kind`` MUST come from the authoritative
        :class:`PackRecord.kind` passed in by the route handler."""
        for kind in ("tool", "skill", "agent", "hook"):
            result = project_risk_tier_panel(
                manifest=self._BASE_MANIFEST,
                record_kind=kind,
            )
            assert result.pack_kind == kind

    def test_every_canonical_risk_tier_resolves_to_expected_flow(self) -> None:
        """Each of the 8 :data:`RiskTier` values resolves through the
        projector to its mapping-table approval flow. Single
        regression covers all 8 canonical tiers."""
        expected = {
            "read_only": "auto_run",
            "internal_write": "audit_emphasis",
            "customer_data_read": "single_approval",
            "customer_data_write": "single_approval",
            "payment_action": "four_eyes",
            "regulator_communication": "four_eyes_categorised",
            "cross_tenant": "operator_legal_signoff",
            "high_risk_custom": "pack_declared",
        }
        for tier, flow in expected.items():
            result = project_risk_tier_panel(
                manifest={"risk_tier": {"tier": tier}},
                record_kind="tool",
            )
            assert result.risk_tier == tier
            assert result.approval_flow == flow

    def test_approval_flow_description_present_for_every_tier(self) -> None:
        """Every tier resolution surfaces a non-empty
        ``approval_flow_description`` — wire-protocol-public field
        consumed by the reviewer UI for the "what happens at approve
        time" hint."""
        for tier in typing.get_args(RiskTier):
            result = project_risk_tier_panel(
                manifest={"risk_tier": {"tier": tier}},
                record_kind="tool",
            )
            assert result.approval_flow_description != ""
            assert isinstance(result.approval_flow_description, str)

    def test_missing_risk_tier_block_defaults_unknown(self) -> None:
        """Manifest with no ``risk_tier`` key surfaces ``risk_tier=""``
        + ``approval_flow="pack_declared"`` sentinel (the most-conservative
        fallback — the reviewer MUST explicitly approve a pack that did
        not declare a tier, NOT have it auto-routed). The defensive
        sentinel preserves the route's 200-with-empty-tier contract
        without crashing the projector."""
        result = project_risk_tier_panel(manifest={}, record_kind="tool")
        assert result.risk_tier == ""
        assert result.approval_flow == "pack_declared"

    def test_malformed_risk_tier_block_defaults_unknown(self) -> None:
        """Non-dict ``risk_tier`` value (corrupted persisted manifest)
        surfaces empty tier + ``pack_declared`` fallback."""
        result = project_risk_tier_panel(manifest={"risk_tier": "not-a-dict"}, record_kind="tool")
        assert result.risk_tier == ""
        assert result.approval_flow == "pack_declared"

    def test_missing_tier_field_in_block_defaults_unknown(self) -> None:
        """A ``risk_tier`` block with no ``tier`` key surfaces empty +
        ``pack_declared`` fallback."""
        result = project_risk_tier_panel(manifest={"risk_tier": {}}, record_kind="tool")
        assert result.risk_tier == ""
        assert result.approval_flow == "pack_declared"

    def test_unknown_tier_value_falls_back_to_pack_declared(self) -> None:
        """A ``tier`` value outside the canonical 8 :data:`RiskTier`
        Literal (e.g. corrupted persisted manifest with a stale value
        from a pre-T4 vocab) surfaces with the raw tier echoed AND
        ``approval_flow="pack_declared"`` so the reviewer sees the
        drift and routes via the most-conservative flow."""
        result = project_risk_tier_panel(
            manifest={"risk_tier": {"tier": "legacy_unknown_tier"}},
            record_kind="tool",
        )
        assert result.risk_tier == "legacy_unknown_tier"
        assert result.approval_flow == "pack_declared"

    def test_non_string_tier_value_defaults_unknown(self) -> None:
        """``tier`` field with a non-string value (e.g. dict / list /
        bool from a corrupted manifest) surfaces empty + pack_declared
        fallback (mirrors :func:`project_data_governance_panel` field-
        level defensive shape handling)."""
        result = project_risk_tier_panel(
            manifest={"risk_tier": {"tier": {"nested": "value"}}},
            record_kind="tool",
        )
        assert result.risk_tier == ""
        assert result.approval_flow == "pack_declared"

    def test_panel_data_is_frozen(self) -> None:
        """:class:`RiskTierPanelData` is a frozen dataclass — mutation
        attempts MUST raise :class:`dataclasses.FrozenInstanceError`
        so a downstream consumer cannot mutate the projector output
        out from under the route handler."""
        import dataclasses

        result = project_risk_tier_panel(manifest=self._BASE_MANIFEST, record_kind="tool")
        with __import__("pytest").raises(dataclasses.FrozenInstanceError):
            result.approval_flow = "auto_run"  # type: ignore[misc]
