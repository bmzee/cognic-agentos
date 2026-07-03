"""M6 Task A6 (ADR-025) — skill.invoke RBAC scope. Mirrors the RunRBACScope /
MCPRBACScope additive-widening pattern."""

from __future__ import annotations

from typing import get_args

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope
from cognic_agentos.portal.rbac.scopes import (
    SKILL_SCOPES,
    ComplianceRBACScope,
    ConfigOverlayRBACScope,
    EmergencyRBACScope,
    EvalRBACScope,
    MCPRBACScope,
    MemoryRBACScope,
    ModelRBACScope,
    PackRBACScope,
    QuotaRBACScope,
    RunRBACScope,
    SkillRBACScope,
    ToolApprovalRBACScope,
    UIRBACScope,
)


def test_skill_scopes_has_exactly_one_value() -> None:
    assert set(get_args(SkillRBACScope)) == {"skill.invoke"}
    assert frozenset({"skill.invoke"}) == SKILL_SCOPES


def test_skill_scopes_frozenset_matches_literal() -> None:
    assert frozenset(get_args(SkillRBACScope)) == SKILL_SCOPES


def test_skill_scope_namespace_disjoint_from_every_other_family() -> None:
    skill = set(get_args(SkillRBACScope))
    others: set[str] = set()
    for fam in (
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
    ):
        others |= set(get_args(fam))
    assert skill.isdisjoint(others)
    assert all(s.startswith("skill.") for s in skill)


def test_actor_accepts_skill_invoke_scope() -> None:
    actor = Actor(
        subject="svc", tenant_id="t", scopes=frozenset({"skill.invoke"}), actor_type="service"
    )
    assert "skill.invoke" in actor.scopes


def test_require_scope_accepts_skill_invoke() -> None:
    dep = RequireScope("skill.invoke")
    assert callable(dep)
