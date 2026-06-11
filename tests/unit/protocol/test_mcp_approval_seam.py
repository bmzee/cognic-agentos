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


def test_canonical_tool_identity_shape_and_determinism() -> None:
    from cognic_agentos.protocol.mcp_host import _canonical_tool_identity

    ident = _canonical_tool_identity(server_id="pack.a", tool_name="lookup")
    assert ident.startswith("mcp:")
    assert len(ident) == 4 + 64  # "mcp:" + sha256 hexdigest — fits String(256)
    assert ident == _canonical_tool_identity(server_id="pack.a", tool_name="lookup")
    assert ident != _canonical_tool_identity(server_id="pack.b", tool_name="lookup")


def test_canonical_tool_identity_is_collision_proof_across_separators() -> None:
    # The reason raw f"{server_id}:{tool_name}" was rejected: these two pairs
    # would collide under naive concatenation. The canonical-object digest
    # MUST distinguish them.
    from cognic_agentos.protocol.mcp_host import _canonical_tool_identity

    a = _canonical_tool_identity(server_id="a:b", tool_name="c")
    b = _canonical_tool_identity(server_id="a", tool_name="b:c")
    assert a != b
