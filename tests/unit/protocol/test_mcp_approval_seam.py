"""Sprint 13.5b2 (ADR-014) — MCP-host approval seam cutover tests."""

from __future__ import annotations

import typing


def test_tool_invocation_refusal_reason_has_exactly_six_values() -> None:
    # Wire-protocol-public vocabulary (spec §4). Drift-pinned: adding or
    # removing a value fails here until the spec/ADR amendment moves with it.
    from cognic_agentos.protocol.mcp_host import ToolInvocationRefusalReason

    assert set(typing.get_args(ToolInvocationRefusalReason)) == {
        "tool_approval_engine_not_available",
        "tool_approval_pending",
        "tool_approval_denied",
        "tool_approval_expired",
        "tool_approval_binding_mismatch",
        "tool_approval_request_not_found",
    }
