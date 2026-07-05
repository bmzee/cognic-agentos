"""M8 A13 (ADR-027) — agent.ask RBAC scope. Mirrors the SkillRBACScope /
RunRBACScope additive-widening pattern (M6 precedent at
``test_skill_scopes.py``)."""

from __future__ import annotations

from typing import get_args

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope
from cognic_agentos.portal.rbac.scopes import (
    AGENT_SCOPES,
    AgentRBACScope,
    ComplianceRBACScope,
    ConfigOverlayRBACScope,
    EmergencyRBACScope,
    EvalRBACScope,
    MCPInternalAccessRBACScope,
    MCPRBACScope,
    MemoryRBACScope,
    ModelRBACScope,
    PackRBACScope,
    QuotaRBACScope,
    RunRBACScope,
    SkillRBACScope,
    SubAgentRBACScope,
    ToolApprovalRBACScope,
    UIRBACScope,
)

#: Every OTHER scope family (incl. the two the M6 skill test predated /
#: omitted: SubAgentRBACScope + MCPInternalAccessRBACScope) — the
#: disjointness universe for the new agent family.
_OTHER_FAMILIES = (
    PackRBACScope,
    UIRBACScope,
    ComplianceRBACScope,
    ModelRBACScope,
    MemoryRBACScope,
    EmergencyRBACScope,
    QuotaRBACScope,
    EvalRBACScope,
    ConfigOverlayRBACScope,
    ToolApprovalRBACScope,
    RunRBACScope,
    MCPRBACScope,
    MCPInternalAccessRBACScope,
    SubAgentRBACScope,
    SkillRBACScope,
)


def test_agent_scopes_has_exactly_one_value() -> None:
    assert set(get_args(AgentRBACScope)) == {"agent.ask"}
    assert frozenset({"agent.ask"}) == AGENT_SCOPES


def test_agent_scopes_frozenset_matches_literal() -> None:
    assert frozenset(get_args(AgentRBACScope)) == AGENT_SCOPES


def test_agent_scope_namespace_disjoint_from_every_other_family() -> None:
    agent = set(get_args(AgentRBACScope))
    others: set[str] = set()
    for fam in _OTHER_FAMILIES:
        others |= set(get_args(fam))
    assert agent.isdisjoint(others)
    assert all(s.startswith("agent.") for s in agent)


def test_no_other_family_value_squats_the_agent_namespace() -> None:
    """The prefix axis both directions: every agent scope is ``agent.*`` AND no
    other family's value starts with ``agent.`` (``subagent.spawn`` is a
    DIFFERENT prefix — ``"subagent.".startswith("agent.")`` is False)."""
    for fam in _OTHER_FAMILIES:
        for value in get_args(fam):
            assert not value.startswith("agent."), (
                f"{value!r} squats the agent.* namespace reserved for AgentRBACScope"
            )


def test_actor_accepts_agent_ask_scope() -> None:
    actor = Actor(
        subject="analyst", tenant_id="t", scopes=frozenset({"agent.ask"}), actor_type="human"
    )
    assert "agent.ask" in actor.scopes


def test_require_scope_accepts_agent_ask() -> None:
    dep = RequireScope("agent.ask")
    assert callable(dep)
