"""MCP tool-invocation RBAC scopes (ADR-002). Mirrors the RunRBACScope
additive-widening pattern (14A-A2a)."""

from __future__ import annotations

from typing import get_args

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope
from cognic_agentos.portal.rbac.scopes import (
    MCP_SCOPES,
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
    ToolApprovalRBACScope,
    UIRBACScope,
)


def test_mcp_scopes_has_exactly_two_values() -> None:
    assert set(get_args(MCPRBACScope)) == {"mcp.tool.list", "mcp.tool.invoke"}
    assert frozenset({"mcp.tool.list", "mcp.tool.invoke"}) == MCP_SCOPES


def test_mcp_scopes_frozenset_matches_literal() -> None:
    assert frozenset(get_args(MCPRBACScope)) == MCP_SCOPES


def test_mcp_scope_namespace_disjoint_from_every_other_family() -> None:
    mcp = set(get_args(MCPRBACScope))
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
        # PR-2b-1 Task 5 — the new MCP operator-config family. SHARES the
        # ``mcp.`` prefix with this ``mcp.tool.*`` family but is VALUE-disjoint
        # (DD-3). Included here so the mcp.tool.* disjointness stays covered
        # against it; the assertion below is value-based so the shared prefix is
        # fine.
        MCPInternalAccessRBACScope,
    ):
        others |= set(get_args(fam))
    assert mcp.isdisjoint(others)
    assert all(s.startswith("mcp.") for s in mcp)


def test_actor_accepts_mcp_invoke_scope() -> None:
    actor = Actor(
        subject="svc", tenant_id="t", scopes=frozenset({"mcp.tool.invoke"}), actor_type="service"
    )
    assert "mcp.tool.invoke" in actor.scopes


def test_require_scope_accepts_mcp_scopes() -> None:
    # Pins the enforcement.py RequireScope union widening — mypy enforces the
    # Literal membership; this also smoke-constructs the dependency factory.
    assert RequireScope("mcp.tool.list") is not None
    assert RequireScope("mcp.tool.invoke") is not None
