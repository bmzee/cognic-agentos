"""Sprint 7B.3 T4 — ADR-014 risk-tier evidence panel (CRITICAL CONTROLS).

Per the plan-of-record at
``docs/superpowers/plans/2026-05-13-sprint-7b3-reviewer-evidence-panels-5-gate.md``
§309-323 + ADR-014 §24-37, this module ships the reviewer-facing
risk-tier evidence panel:

- :data:`ApprovalFlowKind` — closed-enum 7-value Literal (one per
  ADR-014 row collapsed where the table specifies the same flow). The
  approval flow IS the wire-protocol contract the reviewer UI consumes
  to render the "what happens at approve time" hint.
- :data:`_RISK_TIER_TO_APPROVAL_FLOW` — 1:1 mapping table at module
  scope per plan §320. The keyset MUST equal
  :data:`~cognic_agentos.cli._governance_vocab.RiskTier` Literal;
  pinned by ``test_risk_tier_panel.py::
  TestSprint7B3T4SliceAMappingTable``.
- :class:`RiskTierPanelData` — pure-functional projector output;
  frozen dataclass mirroring the wire-shape of the
  :class:`RiskTierPanel` Pydantic DTO at ``portal/api/packs/dto.py``.
- :func:`project_risk_tier_panel` — pure projector. No I/O, no DB
  access, no global state. The route handler at
  :mod:`cognic_agentos.portal.api.packs.evidence_routes` fetches the
  persisted manifest via the T2 manifest-evidence-source seam +
  passes the dict in.

**Architectural-arrow invariant**: this module lives in
``packs/evidence/`` (NOT ``portal/api/packs/``) so the 5-gate
composer (T7) can read the same projector output without crossing
layers. The arrow runs ``portal → packs/evidence`` exclusively.

**Vocabulary-alignment doctrine (mirrors 7B.2 R45 for OWASP)**: the
canonical risk-tier vocabulary lives at
:data:`cognic_agentos.cli._governance_vocab.RiskTier`. This module
does NOT import the Literal at runtime — the mapping-table key type
is bare :class:`str` so :func:`project_risk_tier_panel` can perform
the lookup with the un-narrowed manifest-derived ``tier`` argument
without a runtime cast. Vocabulary alignment is enforced at test
time: the drift detector at ``test_risk_tier_panel.py`` imports
:data:`RiskTier` from ``cli/_governance_vocab.py`` and asserts the
mapping table's keyset equals ``frozenset(typing.get_args(RiskTier))``.
The reverse import (cli → packs) is forbidden by the architectural-
arrow rule — the same direction-of-arrow that 7B.2 R45 P2 #2 pinned
for OWASP (``cli → packs``, no reverse).

**Defensive-shape doctrine (mirrors :func:`project_data_governance_panel`)**:
missing block, non-dict block, missing ``tier`` field, non-string
``tier`` value, and unknown ``tier`` (outside the canonical 8) ALL
surface as either an empty string (``risk_tier=""``) or the raw
unknown string (``risk_tier="legacy_unknown_tier"``) PAIRED with the
most-conservative approval flow (``"pack_declared"``). The reviewer
sees the drift on-panel; the route handler does not crash; the
5-gate composer (T7) routes the pack through the most-conservative
approval flow rather than auto-running it on a vacuous default.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Final, Literal

from cognic_agentos.packs.lifecycle import PackKind

__all__ = [
    "ApprovalFlowKind",
    "RiskTierPanelData",
    "project_risk_tier_panel",
]


ApprovalFlowKind = Literal[
    "auto_run",
    "audit_emphasis",
    "single_approval",
    "four_eyes",
    "four_eyes_categorised",
    "operator_legal_signoff",
    "pack_declared",
]
"""Closed-enum 7-value vocabulary for the reviewer-facing approval
flow per plan §319 + ADR-014 §24-37.

One value per ADR-014 row, collapsed where the canonical table
specifies the same flow:

- ``"auto_run"`` — ADR-014 §30 "Auto-run. No approval. Audit-logged
  like any call." Applied to :literal:`read_only` tier.
- ``"audit_emphasis"`` — §31 "Auto-run with audit emphasis." Audit
  event includes ``risk_tier=internal_write`` flag for periodic
  review. Applied to :literal:`internal_write`.
- ``"single_approval"`` — §32-33 "Just-in-time approval by a single
  approver." Applied to BOTH :literal:`customer_data_read` (§32) AND
  :literal:`customer_data_write` (§33; §33 adds a per-call reason
  code as a sub-property — the approval flow is still single-
  approver; the per-call-reason requirement is enforced by the
  approval-engine, not by gate composition).
- ``"four_eyes"`` — §34 "4-eyes (two distinct approvers, both with
  ``tool.approve.payment`` scope...)". Applied to
  :literal:`payment_action`.
- ``"four_eyes_categorised"`` — §35 "4-eyes + categorised reason +
  audit-record reference." Applied to :literal:`regulator_communication`.
- ``"operator_legal_signoff"`` — §36 "4-eyes + bank legal sign-off
  scope. Default-disabled per tenant; operator-enabled with audit."
  Applied to :literal:`cross_tenant`.
- ``"pack_declared"`` — §37 "Reviewer-defined approval flow per pack
  manifest." Applied to :literal:`high_risk_custom` AND to the
  defensive-fallback path (missing / malformed / unknown tier) so
  the pack routes through the most-conservative flow rather than
  auto-running on a vacuous default.

Wave-1 narrow: drift between this Literal and ADR-014 §30-37 is
wire-protocol-public regression — pinned by
``test_risk_tier_panel.py::TestSprint7B3T4SliceAApprovalFlowKindVocab``
+ ``::TestSprint7B3T4SliceAMappingTable``.
"""


#: 1:1 mapping table per plan §320 + ADR-014 §30-37.
#:
#: Key type is bare :class:`str` (NOT the :data:`RiskTier` Literal) so
#: :func:`project_risk_tier_panel` can perform the lookup with a
#: ``tier: str`` argument WITHOUT a runtime cast — the projector
#: receives ``tier`` from the persisted manifest, which is not
#: type-narrowed to :data:`RiskTier` at the seam. The drift detector
#: at ``test_risk_tier_panel.py::TestSprint7B3T4SliceAMappingTable::
#: test_mapping_covers_every_risk_tier_exactly_once`` pins the keyset
#: against ``frozenset(typing.get_args(RiskTier))`` at test time so a
#: future amendment that adds a new tier still forces an explicit
#: mapping decision here. The reverse drift detector at
#: ``::test_mapping_values_are_all_approval_flow_kinds`` pins every
#: mapping value against :data:`ApprovalFlowKind` so a stale value
#: cannot leak onto the wire.
_RISK_TIER_TO_APPROVAL_FLOW: Final[dict[str, ApprovalFlowKind]] = {
    "read_only": "auto_run",
    "internal_write": "audit_emphasis",
    "customer_data_read": "single_approval",
    "customer_data_write": "single_approval",
    "payment_action": "four_eyes",
    "regulator_communication": "four_eyes_categorised",
    "cross_tenant": "operator_legal_signoff",
    "high_risk_custom": "pack_declared",
}


#: Per-flow display description for the reviewer UI's "what happens at
#: approve time" hint per plan §318. Wire-protocol-public — drift
#: detector at ``test_risk_tier_panel.py::
#: TestSprint7B3T4SliceBProjectRiskTierPanel::
#: test_approval_flow_description_present_for_every_tier`` pins that
#: every flow value resolves to a non-empty description.
_APPROVAL_FLOW_DESCRIPTIONS: Final[dict[ApprovalFlowKind, str]] = {
    "auto_run": ("Auto-run with no approval gate — audit-logged like every call (ADR-014 §30)."),
    "audit_emphasis": (
        "Auto-run with audit emphasis — audit event carries the risk_tier flag for "
        "periodic review (ADR-014 §31)."
    ),
    "single_approval": (
        "Just-in-time approval by a single approver with the relevant tool.approve.* "
        "scope; approval expires after a short window (ADR-014 §32-33)."
    ),
    "four_eyes": (
        "Four-eyes approval — two distinct approvers, the second cannot be the "
        "originating user (ADR-014 §34)."
    ),
    "four_eyes_categorised": (
        "Four-eyes approval plus a categorised reason and an audit-record reference "
        "to a justifying decision_history row (ADR-014 §35)."
    ),
    "operator_legal_signoff": (
        "Four-eyes approval plus bank legal sign-off scope — default-disabled per "
        "tenant; operator-enabled with audit (ADR-014 §36)."
    ),
    "pack_declared": (
        "Pack-declared review process — the manifest declares its own approval flow; "
        "the reviewer follows the pack-specific runbook (ADR-014 §37). Also applied "
        "as the conservative fallback when the persisted manifest is missing or "
        "carries an unknown tier value."
    ),
}


@dataclasses.dataclass(frozen=True)
class RiskTierPanelData:
    """Pure-functional projector output per plan §318.

    Mirrors the wire-shape of the :class:`RiskTierPanel` Pydantic DTO
    at ``portal/api/packs/dto.py``; the DTO's ``from_attributes=True``
    config lets the route handler call
    ``RiskTierPanel.model_validate(panel_data)`` directly without an
    intermediate ``dataclasses.asdict`` step.

    Architectural-arrow invariant: this dataclass lives in
    ``packs/evidence/`` (NOT ``portal/api/packs/``) so the 5-gate
    composer (T7) can read the same projector output without crossing
    layers. The arrow runs ``portal → packs/evidence`` exclusively.

    Fields:

    - ``pack_kind``: authoritative :class:`PackRecord.kind` echoed
      verbatim by the projector; the route handler is the authority,
      not the manifest.
    - ``risk_tier``: the manifest's declared tier — either a canonical
      :data:`~cognic_agentos.cli._governance_vocab.RiskTier` value, the
      raw unknown string if the persisted manifest drifted, or ``""``
      if the manifest carried no tier declaration. Type is bare
      :class:`str` (NOT the :data:`RiskTier` Literal) so the defensive
      fallback paths surface without a type cast.
    - ``approval_flow``: resolved :data:`ApprovalFlowKind` via the
      :data:`_RISK_TIER_TO_APPROVAL_FLOW` mapping table; falls back to
      ``"pack_declared"`` for missing / malformed / unknown tier per
      the defensive-shape doctrine.
    - ``approval_flow_description``: per-flow display text from
      :data:`_APPROVAL_FLOW_DESCRIPTIONS`; non-empty for every flow
      value.
    """

    pack_kind: PackKind
    risk_tier: str
    approval_flow: ApprovalFlowKind
    approval_flow_description: str


def project_risk_tier_panel(
    *,
    manifest: dict[str, Any],
    record_kind: PackKind,
) -> RiskTierPanelData:
    """Project a pack manifest's ``risk_tier`` block onto the reviewer-
    facing evidence panel per plan §317-321.

    Pure-functional: no I/O, no DB access, no global state. The route
    handler in :mod:`cognic_agentos.portal.api.packs.evidence_routes`
    fetches the persisted manifest via ``store.load_lifecycle_history``
    + :func:`find_latest_submit_row` + ``payload["manifest"]`` and
    passes the dict in. ``record_kind`` is the authoritative
    :attr:`PackRecord.kind` value — the handler cross-checks it
    against ``manifest["pack"]["kind"]`` BEFORE invoking this projector
    (the cross-check is route-layer concern, not projector-layer).

    Defensive shape handling: missing ``risk_tier`` block, non-dict
    block, missing ``tier`` field, non-string ``tier`` value, and
    unknown ``tier`` (outside the canonical 8) ALL surface with the
    most-conservative ``"pack_declared"`` approval flow. The raw tier
    string is preserved when it is a non-empty string (even outside
    the canonical 8) so the reviewer can see exactly what the
    persisted manifest declared; otherwise it surfaces as ``""``.

    Returns: :class:`RiskTierPanelData` — a frozen dataclass that the
    DTO at ``portal/api/packs/dto.py`` consumes via
    ``from_attributes=True``.
    """
    raw_block = manifest.get("risk_tier")
    block: dict[str, Any] = raw_block if isinstance(raw_block, dict) else {}

    raw_tier = block.get("tier", "")
    tier: str = raw_tier if isinstance(raw_tier, str) else ""

    # Mapping lookup — canonical tiers resolve to their ADR-014 flow;
    # everything else (including the empty-string fallback path) routes
    # through the most-conservative ``"pack_declared"`` flow so the
    # reviewer is never auto-routed on a vacuous default. The
    # ``str``-typed mapping key (NOT the :data:`RiskTier` Literal) lets
    # the lookup accept the un-narrowed ``tier`` directly; the drift
    # detector at ``test_risk_tier_panel.py`` pins the keyset to
    # :data:`RiskTier` at test time.
    approval_flow: ApprovalFlowKind = _RISK_TIER_TO_APPROVAL_FLOW.get(tier, "pack_declared")
    description = _APPROVAL_FLOW_DESCRIPTIONS[approval_flow]

    return RiskTierPanelData(
        pack_kind=record_kind,
        risk_tier=tier,
        approval_flow=approval_flow,
        approval_flow_description=description,
    )
