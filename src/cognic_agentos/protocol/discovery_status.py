"""Per-(tenant, pack) MCP discovery-status axis (ADR-002 trust-register-then-defer, PR-1 Slice 2).

Registration is trust-only (the OAuth-PRM network probe was removed from registration in
Slice 1). This module owns the INVOKE-time endpoint-reachability axis: it is recorded when
``MCPHost.list_tools`` / ``MCPHost.call_tool`` run the OAuth probe (``acquire_token``), and
surfaced on ``GET /api/v1/system/plugins``.

The axis is **OBSERVATIONAL** — ``list_tools`` / ``call_tool`` stay fail-closed (they still
raise on a probe failure); the recorder only observes the outcome. ``auth_ready`` means
PRM-discovery + token-acquire SUCCEEDED — **not** that a session / tools are reachable (a true
endpoint-health axis is a later addition).

The store is keyed by ``(tenant_id, pack_id)`` where ``pack_id`` is the registry
``distribution_name`` — equal to ``MCPServerEntry.server_id`` for startup-discovered packs
(pinned by the host-builder test). ``tenant_id`` on the read side is an operator OBSERVATION
selector on ``/system/plugins``, not an auth boundary.
"""

from __future__ import annotations

from typing import Literal, Protocol, runtime_checkable

#: The 4-value closed-enum discovery-status axis. WIRE-PROTOCOL-PUBLIC — surfaced on
#: ``GET /api/v1/system/plugins``; drift-pinned by ``tests/unit/protocol/test_discovery_status.py``.
#:   - ``unprobed``    — no cold probe has run for this ``(tenant, pack)`` yet (the default).
#:   - ``auth_ready``  — the last cold probe's PRM-discovery + token-acquire SUCCEEDED
#:                       (NOT "healthy"; a token is not a reachable session / tool list).
#:   - ``refused``     — the last probe was refused on policy/auth grounds (SSRF guard /
#:                       AS-not-allow-listed / audience / scope / PRM-invalid / credentials /
#:                       token-endpoint / token-response).
#:   - ``unreachable`` — the last probe failed at the network layer (timeout / DNS / TLS / connect).
DiscoveryStatus = Literal["unprobed", "auth_ready", "refused", "unreachable"]

#: The ``MCPAuthzError.reason`` values that map to ``unreachable`` (network-layer failures).
#: EVERY OTHER ``acquire_token`` failure reason maps to ``refused``. Drift-pinned alongside the
#: enum so a new network-failure reason is a deliberate, reviewed change.
_UNREACHABLE_AUTHZ_REASONS: frozenset[str] = frozenset(
    {
        "mcp_oauth_request_timeout",  # PRM/AS/token request exceeded the timeout
        "mcp_oauth_transport_failure",  # DNS / TLS / connect failure (non-timeout)
    }
)


def discovery_status_for_authz_reason(reason: str) -> DiscoveryStatus:
    """Map an ``MCPAuthzError.reason`` (a probe FAILURE) to the discovery-status axis:
    ``unreachable`` for the two network-layer reasons, ``refused`` for every other
    policy/auth failure.

    Probe SUCCESS is recorded directly as ``auth_ready`` — it never flows through this
    function (there is no "success reason").
    """
    return "unreachable" if reason in _UNREACHABLE_AUTHZ_REASONS else "refused"


@runtime_checkable
class DiscoveryStatusRecorder(Protocol):
    """Narrow writer + reader seam for the discovery-status axis.

    ``MCPHost`` holds an instance (injected) so it gains NO ``PluginRegistry`` dependency;
    the ``/system/plugins`` route reads the same store. Implementations MUST be safe to call
    from the async invoke path (the Wave-1 in-memory impl is a plain dict — no I/O).
    """

    def record(self, *, tenant_id: str, pack_id: str, status: DiscoveryStatus) -> None:
        """Record the latest probe outcome for ``(tenant_id, pack_id)`` (last-write-wins)."""
        ...

    def get(self, *, tenant_id: str, pack_id: str) -> DiscoveryStatus:
        """Return the recorded status for ``(tenant_id, pack_id)``, or ``unprobed`` if none."""
        ...


class InMemoryDiscoveryStatusRecorder:
    """Process-local dict-backed :class:`DiscoveryStatusRecorder`.

    Wave-1 single-process store (mirrors the scheduler's single-asyncio-loop assumption); a
    multi-instance distributed store is Wave-2. The same instance is the WRITER injected into
    ``MCPHost`` and the READER attached to ``app.state`` for the ``/system/plugins`` route.
    """

    def __init__(self) -> None:
        self._statuses: dict[tuple[str, str], DiscoveryStatus] = {}

    def record(self, *, tenant_id: str, pack_id: str, status: DiscoveryStatus) -> None:
        self._statuses[(tenant_id, pack_id)] = status

    def get(self, *, tenant_id: str, pack_id: str) -> DiscoveryStatus:
        return self._statuses.get((tenant_id, pack_id), "unprobed")
