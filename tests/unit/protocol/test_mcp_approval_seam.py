"""Sprint 13.5b2 (ADR-014) — MCP-host approval seam cutover tests."""

from __future__ import annotations

import typing
from typing import Any


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


def test_server_entry_carries_data_classes_with_empty_default() -> None:
    # Spec §5: carried at registration time; additive default keeps every
    # existing constructor green. DiscoveredMCPServer deliberately NOT extended.
    from cognic_agentos.protocol.mcp_host import MCPServerEntry

    base: dict[str, Any] = dict(
        server_id="pack.x",
        server_url="https://server.example/mcp",
        transport_kind="http",
        manifest_scopes=("mcp:tools",),
        risk_tier="read_only",
        pack_signature_digest="sha256:deadbeef",
    )
    assert MCPServerEntry(**base).data_classes == ()
    entry = MCPServerEntry(**base, data_classes=("customer_pii",))
    assert entry.data_classes == ("customer_pii",)
