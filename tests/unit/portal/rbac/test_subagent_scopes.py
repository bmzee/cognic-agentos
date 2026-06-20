"""Sub-agent portal-trigger RBAC scope (ADR-005 + ADR-012 §40)."""

import typing

from cognic_agentos.portal.rbac.scopes import SUBAGENT_SCOPES, SubAgentRBACScope


def test_subagent_scope_has_exactly_one_value() -> None:
    assert set(typing.get_args(SubAgentRBACScope)) == {"subagent.spawn"}


def test_subagent_scopes_frozenset_matches_literal() -> None:
    assert frozenset(typing.get_args(SubAgentRBACScope)) == SUBAGENT_SCOPES
    assert isinstance(SUBAGENT_SCOPES, frozenset)


def test_subagent_scope_namespace_disjoint_from_other_scopes() -> None:
    # subagent.* must not collide with any existing scope namespace.
    from cognic_agentos.portal.rbac.scopes import (
        MCP_SCOPES,
        RUN_SCOPES,
    )

    assert SUBAGENT_SCOPES.isdisjoint(RUN_SCOPES)
    assert SUBAGENT_SCOPES.isdisjoint(MCP_SCOPES)
    assert all(s.startswith("subagent.") for s in SUBAGENT_SCOPES)


def test_actor_accepts_subagent_scope() -> None:
    from cognic_agentos.portal.rbac.actor import Actor

    actor = Actor(
        subject="svc-a",
        tenant_id="tenant-a",
        scopes=frozenset({"subagent.spawn"}),
        actor_type="service",
    )
    assert "subagent.spawn" in actor.scopes


def test_require_scope_accepts_subagent_scope() -> None:
    from cognic_agentos.portal.rbac.enforcement import RequireScope

    dep = RequireScope("subagent.spawn")  # must type-check + construct
    assert dep is not None
