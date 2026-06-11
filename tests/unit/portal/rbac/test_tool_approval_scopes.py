"""Sprint 13.5b1 (ADR-014) — ToolApprovalRBACScope family unit tests.

Seven values in the ``tool.approve.*`` namespace, value-disjoint from every
other scope family by namespace separation (no other family is
``tool.approve.*``). The Literal is the wire-protocol contract for the 403
``scope_not_held`` denial body on the portal approval API endpoints
(Sprint 13.5b1): ``tool.approve.observe`` (read-only queue/detail) plus the
six high-tier grant scopes consumed by ``grant_scope_for_risk_tier``.

The 13.5a vocabulary lived only in ``scopes.py``; the portal-boundary wiring
(widening ``Actor.scopes`` + ``RequireScope``) is 13.5b1 work — this test pins
that both unions accept the family.
"""

from __future__ import annotations

import typing

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope
from cognic_agentos.portal.rbac.scopes import (
    TOOL_APPROVAL_SCOPES,
    ComplianceRBACScope,
    ConfigOverlayRBACScope,
    EmergencyRBACScope,
    EvalRBACScope,
    MemoryRBACScope,
    ModelRBACScope,
    PackRBACScope,
    ToolApprovalRBACScope,
    UIRBACScope,
)

_EXPECTED: frozenset[ToolApprovalRBACScope] = frozenset(
    {
        "tool.approve.customer_data",
        "tool.approve.customer_data_write",
        "tool.approve.payment",
        "tool.approve.regulator",
        "tool.approve.cross_tenant",
        "tool.approve.high_risk_custom",
        "tool.approve.observe",
    }
)


def test_tool_approval_scope_family_has_exactly_seven_values() -> None:
    assert set(typing.get_args(ToolApprovalRBACScope)) == _EXPECTED


def test_tool_approval_scopes_frozenset_is_1to1_with_literal() -> None:
    assert frozenset(_EXPECTED) == TOOL_APPROVAL_SCOPES
    assert len(TOOL_APPROVAL_SCOPES) == len(typing.get_args(ToolApprovalRBACScope)) == 7


def test_actor_accepts_tool_approval_scopes() -> None:
    a = Actor(
        subject="rev@bank",
        tenant_id="t1",
        scopes=frozenset(_EXPECTED),
        actor_type="human",
    )
    for scope in _EXPECTED:
        assert scope in a.scopes


def test_require_scope_accepts_observe() -> None:
    # The read endpoints gate on tool.approve.observe; RequireScope must accept it.
    dep = RequireScope("tool.approve.observe")
    assert callable(dep)


def test_tool_approval_scope_disjoint_from_every_other_family() -> None:
    others: set[str] = set()
    for fam in (
        PackRBACScope,
        UIRBACScope,
        ComplianceRBACScope,
        ModelRBACScope,
        MemoryRBACScope,
        EmergencyRBACScope,
        EvalRBACScope,
        ConfigOverlayRBACScope,
    ):
        others |= set(typing.get_args(fam))
    assert _EXPECTED.isdisjoint(others)
    # Namespace separation: every tool-approval scope is tool.approve.*
    assert all(v.startswith("tool.approve.") for v in _EXPECTED)
