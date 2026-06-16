"""Sprint 14A-A2a — run.submit RBAC scope (ADR-022). Mirrors the
ToolApprovalRBACScope additive-widening pattern (13.5b1)."""

from __future__ import annotations

from typing import get_args

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope
from cognic_agentos.portal.rbac.scopes import (
    RUN_SCOPES,
    ComplianceRBACScope,
    ConfigOverlayRBACScope,
    EmergencyRBACScope,
    EvalRBACScope,
    MemoryRBACScope,
    ModelRBACScope,
    PackRBACScope,
    QuotaRBACScope,
    RunRBACScope,
    ToolApprovalRBACScope,
    UIRBACScope,
)


def test_run_scopes_has_exactly_two_values() -> None:
    assert set(get_args(RunRBACScope)) == {"run.submit", "run.resume"}
    assert frozenset({"run.submit", "run.resume"}) == RUN_SCOPES


def test_run_scopes_frozenset_matches_literal() -> None:
    assert frozenset(get_args(RunRBACScope)) == RUN_SCOPES


def test_run_scope_namespace_disjoint_from_every_other_family() -> None:
    run = set(get_args(RunRBACScope))
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
    ):
        others |= set(get_args(fam))
    assert run.isdisjoint(others)
    assert all(s.startswith("run.") for s in run)


def test_actor_accepts_run_submit_scope() -> None:
    actor = Actor(
        subject="svc", tenant_id="t", scopes=frozenset({"run.submit"}), actor_type="service"
    )
    assert "run.submit" in actor.scopes


def test_require_scope_accepts_run_submit() -> None:
    # mypy: RequireScope's param union must admit RunRBACScope. Runtime: returns
    # a callable dependency without raising.
    dep = RequireScope("run.submit")
    assert callable(dep)
