"""Sprint 9 T5 — compliance RBAC scope family."""

from __future__ import annotations

import typing

from cognic_agentos.portal.rbac.scopes import (
    EXAMINER_COMPLIANCE_SCOPES,
    ComplianceRBACScope,
)


def test_compliance_scope_family_has_exactly_two_values() -> None:
    assert set(typing.get_args(ComplianceRBACScope)) == {
        "compliance.evidence_pack.read",
        "compliance.trace.read",
    }


def test_examiner_compliance_scopes_holds_both() -> None:
    assert (
        frozenset({"compliance.evidence_pack.read", "compliance.trace.read"})
        == EXAMINER_COMPLIANCE_SCOPES
    )


def test_actor_can_carry_a_compliance_scope() -> None:
    from cognic_agentos.portal.rbac.actor import Actor

    actor = Actor(
        subject="examiner-1",
        tenant_id="t-1",
        scopes=frozenset({"compliance.evidence_pack.read"}),
        actor_type="human",
    )
    assert "compliance.evidence_pack.read" in actor.scopes


def test_require_scope_signature_accepts_compliance_scopes() -> None:
    """Pins the `enforcement.py` widening at TEST time, not just mypy:
    `RequireScope`'s `scope` parameter must accept the compliance-scope
    family. Without the Step-4 enforcement widening this fails."""
    from cognic_agentos.portal.rbac import enforcement

    hints = typing.get_type_hints(enforcement.RequireScope)
    accepted: set[str] = set()
    for member in typing.get_args(hints["scope"]):
        accepted |= set(typing.get_args(member))
    assert {"compliance.evidence_pack.read", "compliance.trace.read"} <= accepted


def test_require_scope_constructs_for_each_compliance_scope() -> None:
    """Smoke — `RequireScope` builds a usable dependency for both
    compliance scopes (end-to-end 403/200 behaviour is pinned by the
    T6/T7 endpoint tests)."""
    from cognic_agentos.portal.rbac.enforcement import RequireScope

    assert callable(RequireScope("compliance.evidence_pack.read"))
    assert callable(RequireScope("compliance.trace.read"))
