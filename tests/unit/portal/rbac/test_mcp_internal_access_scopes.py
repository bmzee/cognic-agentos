"""PR-2b-1 Task 5 (ADR-002) — ``MCPInternalAccessRBACScope`` family unit tests.

The MCP operator-config surface (the override + internal-host-allow-list
write/read endpoints landing in Task 6) carries a **new** RBAC family — kept
DISJOINT from the ``mcp.tool.*`` :data:`MCPRBACScope` family (DD-3), NOT mixed
into it. Operator-config scopes (``mcp.override.*`` / ``mcp.allowlist.*``) are a
distinct privilege surface from tool-invoke scopes.

Four values in the ``mcp.*`` namespace:

  - ``mcp.override.read``    ← GET  the per-(tenant,pack) server_url override.
  - ``mcp.override.write``   ← PUT/DELETE the override (human-only mutation).
  - ``mcp.allowlist.read``   ← GET  the per-tenant internal-host allow-list.
  - ``mcp.allowlist.write``  ← PUT/DELETE an allow-list IP (human-only mutation).

The Literal is the wire-protocol contract for the 403 ``scope_not_held`` denial
body on those endpoints. **Critical subtlety:** this family SHARES the ``mcp.``
prefix with :data:`MCPRBACScope` (``mcp.tool.*``), so the two ``mcp.*`` families
are **value-disjoint, NOT prefix-disjoint** — the disjointness pins below assert
value-disjointness against ``MCPRBACScope`` (a prefix check would be wrong here).
"""

from __future__ import annotations

import typing

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope
from cognic_agentos.portal.rbac.scopes import (
    MCP_INTERNAL_ACCESS_SCOPES,
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
    SubAgentRBACScope,
    ToolApprovalRBACScope,
    UIRBACScope,
)

_EXPECTED = {
    "mcp.override.read",
    "mcp.override.write",
    "mcp.allowlist.read",
    "mcp.allowlist.write",
}

#: Every OTHER RBAC family — the new family must be value-disjoint from all of
#: them, including the sibling ``mcp.tool.*`` family (which shares the ``mcp.``
#: prefix). Iterated by :func:`test_value_disjoint_from_every_other_family`.
_OTHER_FAMILIES = (
    PackRBACScope,
    UIRBACScope,
    ComplianceRBACScope,
    ModelRBACScope,
    MemoryRBACScope,
    EmergencyRBACScope,
    QuotaRBACScope,
    EvalRBACScope,
    ToolApprovalRBACScope,
    RunRBACScope,
    MCPRBACScope,
    SubAgentRBACScope,
    ConfigOverlayRBACScope,
)


def test_mcp_internal_access_scope_family_has_exactly_four_values() -> None:
    # (a) — the exact 4-value vocabulary is the wire-protocol contract.
    assert set(typing.get_args(MCPInternalAccessRBACScope)) == _EXPECTED


def test_mcp_internal_access_scopes_frozenset_is_1to1_with_literal() -> None:
    assert frozenset(_EXPECTED) == MCP_INTERNAL_ACCESS_SCOPES
    assert len(MCP_INTERNAL_ACCESS_SCOPES) == len(typing.get_args(MCPInternalAccessRBACScope)) == 4


def test_all_four_values_carry_mcp_prefix() -> None:
    # (b) — every value is in the mcp.* namespace.
    assert all(v.startswith("mcp.") for v in _EXPECTED)


def test_value_disjoint_from_every_other_family() -> None:
    # (c) — value-disjoint from EVERY other family, including MCPRBACScope.
    others: set[str] = set()
    for fam in _OTHER_FAMILIES:
        others |= set(typing.get_args(fam))
    assert _EXPECTED.isdisjoint(others), (
        f"MCPInternalAccessRBACScope MUST be value-disjoint from every other "
        f"family; overlapping values: {_EXPECTED & others}"
    )


def test_value_disjoint_from_mcp_tool_family_despite_shared_prefix() -> None:
    # (c) explicit — the two mcp.* families share the prefix but MUST NOT share
    # any VALUE. A prefix-disjointness check would be wrong here (both are
    # ``mcp.*``); the contract is value-disjointness.
    mcp_tool = set(typing.get_args(MCPRBACScope))
    assert _EXPECTED.isdisjoint(mcp_tool)
    # Both families live under the shared mcp.* namespace — proving the
    # disjointness above is genuinely value-based, not prefix-based.
    assert all(v.startswith("mcp.") for v in _EXPECTED)
    assert all(v.startswith("mcp.") for v in mcp_tool)


def test_actor_accepts_mcp_internal_access_scopes() -> None:
    # (d) — the new family is in Actor.scopes' union (Pydantic-validation
    # boundary). mypy enforces the Literal membership at every call site; this
    # smoke-constructs the frozen Actor with a value from the new family.
    actor = Actor(
        subject="op@bank",
        tenant_id="t1",
        scopes=frozenset({"mcp.allowlist.write"}),
        actor_type="human",
    )
    assert "mcp.allowlist.write" in actor.scopes


def test_require_scope_accepts_mcp_internal_access_scopes() -> None:
    # (d) — the new family is in RequireScope's union. mypy enforces the Literal
    # membership; this also smoke-constructs the dependency factory for all 4.
    assert RequireScope("mcp.override.read") is not None
    assert RequireScope("mcp.override.write") is not None
    assert RequireScope("mcp.allowlist.read") is not None
    assert RequireScope("mcp.allowlist.write") is not None
