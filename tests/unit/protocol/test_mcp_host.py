"""Sprint-5 T9 — MCPHost orchestrator contract tests.

Critical-controls module per AGENTS.md. The MCPHost is the runtime
boundary that turns a registered MCP pack + a tool invocation into
an authenticated SDK-backed session round-trip plus the audit /
decision-history evidence rows that examiners replay.

T9 ships the orchestrator surface:

  - ``MCPHost(*, servers, transports, authz, audit_store,
    decision_history_store, settings)`` — constructed once at portal
    startup. Calls ``require_mcp()`` at construction (R3 P1
    doctrine — MCPHost orchestrates SDK-backed sessions; kernel-
    image-equivalent venv MUST fail with MCPNotAvailableError).
  - ``async discover_servers() -> list[DiscoveredMCPServer]`` —
    metadata only, no token, no session.
  - ``async list_tools(*, server_id, request_id, tenant_id)`` —
    acquires token → opens session → loops on the SDK's
    paginated ``ListToolsResult`` (per R3 P1) → close (best-effort)
    → caches per (tenant_id, server_id, scopes) with deep-copy
    on read/write (per R2 P2 #2).
  - ``async call_tool(*, server_id, tool_name, arguments,
    request_id, tenant_id)`` — acquires token → opens session
    WITH the token → sends call_tool → 401/403 retry semantics
    via ``__cause__`` walk for ``httpx.HTTPStatusError`` +
    WWW-Authenticate parsing (per R1 P2 #3) → close (best-effort)
    → returns CallResult with correlation IDs.

Doctrinal scope-decisions for T9 (called out so reviewer can
challenge cleanly):

  1. **``servers`` parameter is a typed Mapping[str,
     MCPServerEntry], not the raw PluginRegistry.** The plan's
     ``registry`` wording is interpreted at the system-architecture
     level — MCPServerEntry is a stable public type the portal
     lifespan code populates from the registry walk + per-pack MCP
     manifest extraction. Decoupling MCPHost from
     plugin_registry's internals avoids touching a critical-
     controls module in T9 and keeps tests honest (no mocked
     PluginRegistry; tests pass real MCPServerEntry instances).

  2. **401/403 retry semantics IMPLEMENTED in R1 P2 #3 — no
     longer deferred.** Plan §T9's auth-retry spec lands in T9
     itself: ``call_tool`` walks the ``__cause__`` chain of an
     ``MCPTransportError`` for ``httpx.HTTPStatusError``, parses
     ``WWW-Authenticate`` for OAuth ``error="..."`` + ``scope="..."``,
     and routes to either authz_lost (401 / 403 invalid_token /
     malformed → drop cached token via
     ``MCPAuthzClient.invalidate_cached_token``, reacquire, retry
     once; second 401 → ``MCPAuthzError("mcp_authorisation_lost")``)
     or step_up (403 insufficient_scope with scope hint →
     ``authz.step_up_token`` then retry; ``mcp_step_up_unauthorised``
     propagates from the authz client unchanged). This avoids
     extending T7's MCPTransportReason closed enum (T7 stays
     locked); detection lives in T9 where the orchestration logic
     already runs.

  3. **Audit / decision-history emission for the happy path is
     scoped to T11.** T9 wires the constructor-required deps
     (audit_store, decision_history_store) and emits ONLY the
     close-failure tolerance audit row — both transport-class
     failures (``MCPTransportError``) and hook-class failures
     (generic ``Exception`` from a buggy session_close hook, per
     R3 P2). T11 expands with ``audit.tool_invocation`` /
     ``audit.tool_invocation_refused`` /
     ``audit.tool_invocation_error`` and the parallel
     ``decision_history`` rows.
"""

from __future__ import annotations

import ast
import asyncio
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.protocol import MCPNotAvailableError, mcp_host
from cognic_agentos.protocol.discovery_status import InMemoryDiscoveryStatusRecorder
from cognic_agentos.protocol.mcp_authz import AuthzReason, MCPAuthzClient, MCPAuthzError, Token

# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


def _token(value: str = "secret-token") -> Token:
    return Token(
        value=value,
        expires_at=time.time() + 3600,
        as_issuer="https://as.example",
        scopes=("mcp:tools",),
        resource_indicator="https://server.example/mcp",
        client_id="client-a",
    )


@pytest.fixture
def settings() -> Any:
    return build_settings_without_env_file().model_copy(
        update={
            "mcp_oauth_request_timeout_s": 7,
            "mcp_call_tool_timeout_s": 13,
        }
    )


@pytest.fixture
def host_module(monkeypatch: pytest.MonkeyPatch) -> Any:
    from cognic_agentos.protocol import mcp_host

    monkeypatch.setattr(mcp_host, "require_mcp", MagicMock())
    return mcp_host


@pytest.fixture
def authz() -> MagicMock:
    client = MagicMock(spec=MCPAuthzClient)
    client.acquire_token = AsyncMock(return_value=_token())
    # invalidate_cached_token is the new R1 P2 #3 surface
    client.invalidate_cached_token = AsyncMock(return_value=None)
    # step_up_token for the 403 insufficient_scope path
    client.step_up_token = AsyncMock(return_value=_token("stepped-up"))
    return client


@pytest.fixture
def audit_store() -> MagicMock:
    store = MagicMock(spec=AuditStore)
    store.append = AsyncMock(return_value=("uuid", b"hash"))
    return store


@pytest.fixture
def decision_history_store() -> MagicMock:
    store = MagicMock(spec=DecisionHistoryStore)
    store.append = AsyncMock(return_value=("uuid", b"hash"))
    return store


def _make_session(host_module: Any, server_url: str, session_id: str = "sess-1") -> Any:
    """Build a real MCPSession dataclass instance (cheaper than mocking)."""
    from contextlib import AsyncExitStack

    from cognic_agentos.protocol.mcp_transports import MCPSession

    sdk_session = MagicMock()
    sdk_session.call_tool = AsyncMock(return_value={"content": "ok"})
    sdk_session.list_tools = AsyncMock(
        return_value=[{"name": "lookup", "description": "Look up X"}]
    )
    return MCPSession(
        server_url=server_url,
        sdk_session=sdk_session,
        exit_stack=AsyncExitStack(),
        get_session_id=lambda: session_id,
        token_scopes=("mcp:tools",),
        token_client_id="client-a",
    )


def _http_transport(host_module: Any, server_url: str) -> MagicMock:
    """A MagicMock transport that satisfies the MCPTransport protocol shape."""
    transport = MagicMock()
    session = _make_session(host_module, server_url)
    transport.open_session = AsyncMock(return_value=session)
    transport.send = AsyncMock(return_value={"content": "ok"})
    transport.close_session = AsyncMock(return_value=None)
    return transport


@pytest.fixture
def http_transport(host_module: Any) -> MagicMock:
    return _http_transport(host_module, "https://server.example/mcp")


@pytest.fixture
def server_entry(host_module: Any) -> Any:
    return host_module.MCPServerEntry(
        server_id="example.mcp",
        server_url="https://server.example/mcp",
        transport_kind="http",
        manifest_scopes=("mcp:tools",),
        risk_tier="read_only",
        pack_signature_digest="sha256:deadbeef",
    )


@pytest.fixture
def host(
    host_module: Any,
    server_entry: Any,
    http_transport: MagicMock,
    authz: MagicMock,
    audit_store: MagicMock,
    decision_history_store: MagicMock,
    settings: Any,
) -> Any:
    return host_module.MCPHost(
        servers={server_entry.server_id: server_entry},
        transports={"http": http_transport},
        authz=authz,
        audit_store=audit_store,
        decision_history_store=decision_history_store,
        settings=settings,
    )


# ---------------------------------------------------------------------------
# Constructor — require_mcp gating + dep wiring
# ---------------------------------------------------------------------------


class TestMCPHostConstructor:
    def test_constructor_calls_require_mcp(
        self,
        host_module: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        """R3 P1 doctrine: MCPHost orchestrates SDK-backed sessions, so
        construction MUST gate on the SDK being installed."""
        host_module.MCPHost(
            servers={server_entry.server_id: server_entry},
            transports={"http": http_transport},
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )
        host_module.require_mcp.assert_called_once_with()

    def test_constructor_propagates_missing_sdk(
        self,
        host_module: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Kernel-image equivalent venv: require_mcp raises → MCPHost
        construction MUST fail-loud with the same MCPNotAvailableError."""
        monkeypatch.setattr(
            host_module,
            "require_mcp",
            MagicMock(side_effect=MCPNotAvailableError("no mcp sdk in this venv")),
        )
        with pytest.raises(MCPNotAvailableError, match="no mcp sdk"):
            host_module.MCPHost(
                servers={server_entry.server_id: server_entry},
                transports={"http": http_transport},
                authz=authz,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                settings=settings,
            )

    def test_constructor_rejects_server_with_unknown_transport_kind(
        self,
        host_module: Any,
        server_entry: Any,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        """A server entry referencing a transport_kind that's not in the
        ``transports`` mapping is a misconfiguration that MUST surface
        at startup — not at first invocation."""
        with pytest.raises(ValueError, match="transport_kind"):
            host_module.MCPHost(
                servers={server_entry.server_id: server_entry},
                transports={},  # No transports at all
                authz=authz,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                settings=settings,
            )

    def test_constructor_accepts_empty_servers(
        self,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        """Empty servers mapping is valid (kernel image with MCP SDK
        installed but no MCP packs registered yet — discover_servers
        returns []). Constructor MUST NOT require any servers."""
        host = host_module.MCPHost(
            servers={},
            transports={"http": http_transport},
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )
        assert host is not None


# ---------------------------------------------------------------------------
# discover_servers — pure read, returns metadata only
# ---------------------------------------------------------------------------


class TestDiscoverServers:
    async def test_returns_all_configured_entries(self, host: Any, server_entry: Any) -> None:
        servers = await host.discover_servers()
        assert len(servers) == 1
        s = servers[0]
        assert s.server_id == server_entry.server_id
        assert s.server_url == server_entry.server_url
        assert s.transport_kind == "http"
        assert s.manifest_scopes == ("mcp:tools",)

    async def test_does_not_open_session_or_acquire_token(
        self,
        host: Any,
        http_transport: MagicMock,
        authz: MagicMock,
    ) -> None:
        """discover_servers() returns metadata only — no token, no session,
        no audit row. Per plan: 'walks the plugin registry for packs
        with [tool.cognic.mcp] blocks; returns metadata only'."""
        await host.discover_servers()
        http_transport.open_session.assert_not_called()
        authz.acquire_token.assert_not_called()

    async def test_idempotent(self, host: Any) -> None:
        first = await host.discover_servers()
        second = await host.discover_servers()
        assert [s.server_id for s in first] == [s.server_id for s in second]

    async def test_returns_empty_for_kernel_image_with_no_packs(
        self,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        host = host_module.MCPHost(
            servers={},
            transports={"http": http_transport},
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )
        assert await host.discover_servers() == []


# ---------------------------------------------------------------------------
# list_tools — token + open + send + close + cache
# ---------------------------------------------------------------------------


class TestListTools:
    async def test_acquires_token_then_opens_session(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
    ) -> None:
        """Per the plan call order: acquire token first, THEN open
        session WITH the token (open is an authenticated request for
        HTTP MCP)."""
        await host.list_tools(server_id=server_entry.server_id, request_id="req-1", tenant_id="t-1")
        authz.acquire_token.assert_awaited_once()
        ack = authz.acquire_token.await_args
        assert ack.kwargs["server_url"] == server_entry.server_url
        assert ack.kwargs["manifest_scopes"] == server_entry.manifest_scopes
        # Token-injected at open_session
        http_transport.open_session.assert_awaited_once()
        opk = http_transport.open_session.await_args
        assert opk.kwargs["server_url"] == server_entry.server_url
        assert opk.kwargs["token"] is authz.acquire_token.return_value

    async def test_returns_sdk_list_tools_response(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
    ) -> None:
        """The return value is whatever the SDK session's list_tools
        method returns (plus possibly a normalisation wrapper)."""
        result = await host.list_tools(
            server_id=server_entry.server_id, request_id="req-1", tenant_id="t-1"
        )
        # The SDK session's list_tools mock returns a single tool descriptor
        assert len(result) == 1
        assert result[0]["name"] == "lookup"

    async def test_closes_session_after_listing(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
    ) -> None:
        """Session MUST be closed after list_tools — leaked sessions
        eventually exhaust connection pools at the SDK / httpx layer."""
        await host.list_tools(server_id=server_entry.server_id, request_id="req-1", tenant_id="t-1")
        http_transport.close_session.assert_awaited_once()

    async def test_close_failure_audit_logged_does_not_fail_result(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        """Per plan §T9: 'close failures are audit-logged but don't
        fail the list_tools result'. The list_tools result is the
        primary contract; teardown failures are operator-visible via
        audit but don't propagate."""
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        http_transport.close_session.side_effect = MCPTransportError(
            "mcp_session_close_failed", "stuck", server_url=server_entry.server_url
        )
        result = await host.list_tools(
            server_id=server_entry.server_id, request_id="req-1", tenant_id="t-1"
        )
        # Primary result still returned
        assert result is not None
        # Audit row emitted for the close failure
        appended_events = [c.args[0] for c in audit_store.append.await_args_list]
        close_failure_events = [
            e for e in appended_events if "close" in e.event_type or "close" in str(e.payload)
        ]
        assert close_failure_events, (
            "expected at least one audit row for the close failure; "
            f"got events: {[e.event_type for e in appended_events]}"
        )

    async def test_caches_per_server(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
    ) -> None:
        """Per plan §T9 step 5 + T9 R1 P2 #2: cache list_tools result
        per (tenant_id, server_id, manifest_scopes) tuple with TTL =
        ``settings.mcp_call_tool_timeout_s * 5``. Two consecutive
        calls from the SAME tenant against the SAME server with the
        SAME manifest scopes MUST hit the cache (no second
        acquire_token, no second open_session). Cross-tenant cache
        isolation is pinned separately by
        :class:`TestListToolsCachePerTenant`."""
        await host.list_tools(server_id=server_entry.server_id, request_id="req-1", tenant_id="t-1")
        authz.acquire_token.reset_mock()
        http_transport.open_session.reset_mock()

        await host.list_tools(server_id=server_entry.server_id, request_id="req-2", tenant_id="t-1")
        authz.acquire_token.assert_not_called()
        http_transport.open_session.assert_not_called()

    async def test_cache_ttl_expires_triggers_refetch(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When the TTL window has passed, the cache MUST refetch."""
        # First call populates cache at monotonic=0
        monkeypatch.setattr("cognic_agentos.protocol.mcp_host.time.monotonic", lambda: 0.0)
        await host.list_tools(server_id=server_entry.server_id, request_id="req-1", tenant_id="t-1")
        authz.acquire_token.reset_mock()
        http_transport.open_session.reset_mock()

        # Jump past the TTL window (TTL = call_tool_timeout_s * 5; with
        # mcp_call_tool_timeout_s=13, TTL=65s). Move monotonic clock to 100s.
        monkeypatch.setattr("cognic_agentos.protocol.mcp_host.time.monotonic", lambda: 100.0)
        await host.list_tools(server_id=server_entry.server_id, request_id="req-2", tenant_id="t-1")
        # Cache MUST have refetched
        authz.acquire_token.assert_called_once()
        http_transport.open_session.assert_called_once()
        # monkeypatch teardown auto-restores time.monotonic

    async def test_unknown_server_raises(self, host: Any) -> None:
        """An unknown server_id is an operator misconfiguration —
        fail-loud with a closed-enum error rather than silent None."""
        with pytest.raises(LookupError, match=r"unknown.*server"):
            await host.list_tools(server_id="not-registered", request_id="req-1", tenant_id="t-1")


# ---------------------------------------------------------------------------
# call_tool — token → open → send → close → CallResult
# ---------------------------------------------------------------------------


class TestCallTool:
    async def test_happy_path_acquires_token_opens_sends_closes(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
    ) -> None:
        """Plan §T9 call_tool steps 2-6 in order: acquire token → open
        session WITH token → send call_tool request → close (best-
        effort)."""
        await host.call_tool(
            server_id=server_entry.server_id,
            tool_name="lookup",
            arguments={"q": "x"},
            request_id="req-1",
            tenant_id="t-1",
        )
        authz.acquire_token.assert_awaited_once()
        http_transport.open_session.assert_awaited_once()
        http_transport.send.assert_awaited_once()
        http_transport.close_session.assert_awaited_once()

    async def test_returns_call_result_with_correlation_ids(
        self,
        host: Any,
        server_entry: Any,
    ) -> None:
        """CallResult carries the correlation IDs examiners need to
        replay the invocation: request_id, mcp_session_id, as_issuer,
        scopes, client_id."""
        result = await host.call_tool(
            server_id=server_entry.server_id,
            tool_name="lookup",
            arguments={"q": "x"},
            request_id="req-1",
            tenant_id="t-1",
        )
        assert result.request_id == "req-1"
        assert result.mcp_session_id == "sess-1"
        assert result.as_issuer == "https://as.example"
        assert result.scopes == ("mcp:tools",)
        assert result.client_id == "client-a"
        assert result.payload == {"content": "ok"}

    async def test_unknown_server_raises(self, host: Any) -> None:
        with pytest.raises(LookupError, match=r"unknown.*server"):
            await host.call_tool(
                server_id="not-registered",
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )

    async def test_authz_error_propagates_with_closed_enum_reason(
        self,
        host: Any,
        server_entry: Any,
        authz: MagicMock,
    ) -> None:
        """authz.acquire_token failures (closed-enum AuthzReason) MUST
        propagate to the caller unchanged — they are the canonical
        signal for OAuth/PRM-related refusals and feed T11's
        decision-history rows."""
        authz.acquire_token.side_effect = MCPAuthzError(
            "mcp_as_not_allowlisted",
            "AS not on tenant allow-list",
            server_url=server_entry.server_url,
        )
        with pytest.raises(MCPAuthzError) as exc:
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
        assert exc.value.reason == "mcp_as_not_allowlisted"

    async def test_transport_send_failure_propagates(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
    ) -> None:
        """Transport-level closed-enum errors (mcp_call_tool_timeout
        / mcp_transport_send_failed) MUST propagate to the caller —
        they feed T11's audit.tool_invocation_error row."""
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        http_transport.send.side_effect = MCPTransportError(
            "mcp_call_tool_timeout", "timeout", server_url=server_entry.server_url
        )
        with pytest.raises(MCPTransportError) as exc:
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
        assert exc.value.reason == "mcp_call_tool_timeout"

    async def test_send_failure_still_attempts_session_close(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
    ) -> None:
        """Even on send failure, the session MUST be closed (leaked
        sessions exhaust pools). Close-failure tolerance still
        applies — the original send error wins."""
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        http_transport.send.side_effect = MCPTransportError(
            "mcp_transport_send_failed", "boom", server_url=server_entry.server_url
        )
        with pytest.raises(MCPTransportError):
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
        http_transport.close_session.assert_awaited_once()

    async def test_close_failure_does_not_mask_send_result(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        """Send succeeds, close fails → CallResult returned; close
        failure audit-logged."""
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        http_transport.close_session.side_effect = MCPTransportError(
            "mcp_session_close_failed", "stuck", server_url=server_entry.server_url
        )
        result = await host.call_tool(
            server_id=server_entry.server_id,
            tool_name="lookup",
            arguments={},
            request_id="req-1",
            tenant_id="t-1",
        )
        assert result.payload == {"content": "ok"}
        appended = [c.args[0] for c in audit_store.append.await_args_list]
        assert any("close" in e.event_type or "close" in str(e.payload) for e in appended), (
            f"expected close-failure audit row; got: {[e.event_type for e in appended]}"
        )

    async def test_close_failure_does_not_mask_send_failure(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
    ) -> None:
        """Send fails, close also fails → caller sees the SEND error
        (the primary fault), NOT the close error. Close-failure
        masking would lose the operator's diagnostic of why the call
        actually failed."""
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        http_transport.send.side_effect = MCPTransportError(
            "mcp_transport_send_failed", "boom", server_url=server_entry.server_url
        )
        http_transport.close_session.side_effect = MCPTransportError(
            "mcp_session_close_failed", "stuck", server_url=server_entry.server_url
        )
        with pytest.raises(MCPTransportError) as exc:
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
        # Original send error reaches the caller — NOT the close error
        assert exc.value.reason == "mcp_transport_send_failed"

    async def test_passes_arguments_to_send(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
    ) -> None:
        """Tool arguments pass through to the SDK send call unchanged
        (the SDK is the layer that serialises them to MCP wire format)."""
        from cognic_agentos.protocol.mcp_transports import MCPToolCallRequest

        await host.call_tool(
            server_id=server_entry.server_id,
            tool_name="lookup",
            arguments={"q": "hello", "limit": 10},
            request_id="req-1",
            tenant_id="t-1",
        )
        http_transport.send.assert_awaited_once()
        send_args = http_transport.send.await_args
        request = send_args.args[1]
        assert isinstance(request, MCPToolCallRequest)
        assert request.name == "lookup"
        assert request.arguments == {"q": "hello", "limit": 10}


# ---------------------------------------------------------------------------
# Transport selection — server_entry.transport_kind picks the right transport
# ---------------------------------------------------------------------------


class TestTransportSelection:
    async def test_dispatches_to_http_for_http_servers(
        self,
        host_module: Any,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        http_t = _http_transport(host_module, "https://server.example/mcp")
        stdio_t = MagicMock()
        stdio_t.open_session = AsyncMock()
        stdio_t.send = AsyncMock()
        stdio_t.close_session = AsyncMock()

        entry = host_module.MCPServerEntry(
            server_id="http-srv",
            server_url="https://server.example/mcp",
            transport_kind="http",
            manifest_scopes=("mcp:tools",),
            risk_tier="read_only",
            pack_signature_digest="sha256:a",
        )
        host = host_module.MCPHost(
            servers={entry.server_id: entry},
            transports={"http": http_t, "stdio": stdio_t},
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )
        await host.call_tool(
            server_id=entry.server_id,
            tool_name="x",
            arguments={},
            request_id="r",
            tenant_id="t",
        )
        # HTTP got the call, STDIO did not
        http_t.open_session.assert_awaited_once()
        stdio_t.open_session.assert_not_called()


# ---------------------------------------------------------------------------
# Concurrency: list_tools cache survives concurrent callers
# ---------------------------------------------------------------------------


class TestConcurrency:
    async def test_audit_failure_during_close_failure_does_not_mask_primary_result(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        """Defensive: send succeeds, close fails, AND the audit append
        for the close-failure event itself fails. The primary result
        (the successful send) MUST still reach the caller — the
        audit-pipeline failure is logged token-free but suppressed,
        same discipline as the T7 transport's _emit_send_error_safe."""
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        http_transport.close_session.side_effect = MCPTransportError(
            "mcp_session_close_failed", "stuck", server_url=server_entry.server_url
        )
        audit_store.append.side_effect = RuntimeError("audit chain DB unreachable")

        result = await host.call_tool(
            server_id=server_entry.server_id,
            tool_name="lookup",
            arguments={},
            request_id="req-1",
            tenant_id="t-1",
        )
        # Primary result still reaches the caller despite double failure
        assert result.payload == {"content": "ok"}

    async def test_concurrent_list_tools_share_cache_after_first(
        self,
        host: Any,
        server_entry: Any,
        authz: MagicMock,
    ) -> None:
        """First call populates the cache; subsequent in-flight or
        post-population concurrent calls MUST hit the cache. We
        sequence to avoid race in the simple test (no in-flight
        coalescing required for T9; just post-population cache hits)."""
        await host.list_tools(server_id=server_entry.server_id, request_id="r1", tenant_id="t-1")
        authz.acquire_token.reset_mock()
        results = await asyncio.gather(
            host.list_tools(server_id=server_entry.server_id, request_id="r2", tenant_id="t-1"),
            host.list_tools(server_id=server_entry.server_id, request_id="r3", tenant_id="t-1"),
            host.list_tools(server_id=server_entry.server_id, request_id="r4", tenant_id="t-1"),
        )
        assert all(r is not None for r in results)
        # No additional acquires after the first call populated the cache
        authz.acquire_token.assert_not_called()


# ---------------------------------------------------------------------------
# R1 P2 #1 — canonical streamable-http transport accepted at runtime
# ---------------------------------------------------------------------------


class TestStreamableHttpCanonicalTransportKind:
    """T6's capability validator + plugin_registry treat ``"http"`` and
    ``"streamable-http"`` as the same HTTP transport family
    (``_HTTP_TRANSPORT_VALUES``). A pack admitted by T6 with
    ``transport = "streamable-http"`` (the spec-canonical name) MUST
    dispatch through MCPHost without operators duplicating the same
    HTTP transport under both keys.
    """

    async def test_server_with_streamable_http_kind_accepted_at_construction(
        self,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        """A server entry declaring transport_kind='streamable-http'
        and a transports mapping containing only 'http' (or only
        'streamable-http') MUST construct cleanly — both keys point
        at the same canonical HTTP transport."""
        entry = host_module.MCPServerEntry(
            server_id="canon.mcp",
            server_url="https://server.example/mcp",
            transport_kind="streamable-http",
            manifest_scopes=("mcp:tools",),
            risk_tier="read_only",
            pack_signature_digest="sha256:a",
        )
        # transports keyed under "http" (the canonical key); entry
        # uses the spec-canonical name "streamable-http"
        host = host_module.MCPHost(
            servers={entry.server_id: entry},
            transports={"http": http_transport},
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )
        # Constructor MUST NOT raise
        assert host is not None

    async def test_server_with_streamable_http_kind_dispatches_to_http_transport(
        self,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        """call_tool against a streamable-http server MUST reach the
        configured HTTP transport (the same physical transport that
        serves transport_kind='http')."""
        entry = host_module.MCPServerEntry(
            server_id="canon.mcp",
            server_url="https://server.example/mcp",
            transport_kind="streamable-http",
            manifest_scopes=("mcp:tools",),
            risk_tier="read_only",
            pack_signature_digest="sha256:a",
        )
        host = host_module.MCPHost(
            servers={entry.server_id: entry},
            transports={"http": http_transport},
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )
        await host.call_tool(
            server_id=entry.server_id,
            tool_name="lookup",
            arguments={},
            request_id="r1",
            tenant_id="t-1",
        )
        http_transport.open_session.assert_awaited_once()
        http_transport.send.assert_awaited_once()

    async def test_transports_keyed_under_streamable_http_also_works(
        self,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        """Symmetric case: a transports mapping keyed under
        'streamable-http' MUST also serve servers declaring
        transport_kind='http'. Both key forms refer to the same
        canonical HTTP transport family."""
        entry = host_module.MCPServerEntry(
            server_id="legacy.mcp",
            server_url="https://server.example/mcp",
            transport_kind="http",
            manifest_scopes=("mcp:tools",),
            risk_tier="read_only",
            pack_signature_digest="sha256:a",
        )
        host = host_module.MCPHost(
            servers={entry.server_id: entry},
            transports={"streamable-http": http_transport},
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )
        await host.call_tool(
            server_id=entry.server_id,
            tool_name="lookup",
            arguments={},
            request_id="r1",
            tenant_id="t-1",
        )
        http_transport.open_session.assert_awaited_once()


# ---------------------------------------------------------------------------
# R1 P2 #2 — list_tools cache MUST NOT leak across tenants
# ---------------------------------------------------------------------------


class TestListToolsCachePerTenant:
    """The cache key MUST include tenant_id (and the requested scope
    set) so per-tenant AS allow-list checks fire on every tenant's
    first call. Cross-tenant cache leak would let tenant B receive a
    tool catalogue tenant A's authz already cleared, bypassing tenant
    B's allow-list entirely."""

    async def test_tenant_b_call_after_tenant_a_warms_cache_still_acquires_token(
        self,
        host: Any,
        server_entry: Any,
        authz: MagicMock,
        http_transport: MagicMock,
    ) -> None:
        """Tenant A warms the cache → tenant B's call MUST re-run
        authz.acquire_token (because the per-tenant AS allow-list
        check happens inside acquire_token)."""
        # Tenant A populates the cache
        await host.list_tools(
            server_id=server_entry.server_id, request_id="ra", tenant_id="tenant-a"
        )
        authz.acquire_token.reset_mock()
        http_transport.open_session.reset_mock()

        # Tenant B issues the same logical request — MUST acquire
        # a fresh token (its own per-tenant allow-list applies)
        await host.list_tools(
            server_id=server_entry.server_id, request_id="rb", tenant_id="tenant-b"
        )
        authz.acquire_token.assert_called_once()
        http_transport.open_session.assert_called_once()
        # The acquire_token call MUST carry tenant_id="tenant-b"
        ack = authz.acquire_token.await_args
        assert ack.kwargs["tenant_id"] == "tenant-b"

    async def test_same_tenant_back_to_back_still_caches(
        self,
        host: Any,
        server_entry: Any,
        authz: MagicMock,
    ) -> None:
        """Sanity preservation: the per-tenant cache scoping does NOT
        defeat the same-tenant cache hit (which is what justifies
        having the cache at all)."""
        await host.list_tools(server_id=server_entry.server_id, request_id="r1", tenant_id="t-1")
        authz.acquire_token.reset_mock()

        await host.list_tools(server_id=server_entry.server_id, request_id="r2", tenant_id="t-1")
        authz.acquire_token.assert_not_called()

    async def test_returns_a_copy_so_callers_cannot_mutate_cache(
        self,
        host: Any,
        server_entry: Any,
    ) -> None:
        """The cached tool list is internal state. Returning the
        internal list itself would let a caller mutate the cache
        contents (clear it / append to it / remove tools) — silently
        affecting every later read. MUST return a fresh copy."""
        first = await host.list_tools(
            server_id=server_entry.server_id, request_id="r1", tenant_id="t-1"
        )
        first.clear()
        second = await host.list_tools(
            server_id=server_entry.server_id, request_id="r2", tenant_id="t-1"
        )
        assert second, (
            "second cached read MUST not be empty after the caller cleared the first list"
        )
        # And the two return values are distinct list objects
        assert first is not second


# ---------------------------------------------------------------------------
# R1 P2 #3 — 401/403 retry semantics + step-up via authz
# ---------------------------------------------------------------------------


def _httpx_status_error(status_code: int, www_authenticate: str = "") -> Exception:
    """Build an httpx.HTTPStatusError stand-in carrying the status +
    WWW-Authenticate header. Real httpx.HTTPStatusError requires a
    Request + Response object, which is heavyweight for unit tests;
    use the real httpx classes so the classifier's isinstance check
    matches production exception flow."""
    import httpx

    request = httpx.Request("POST", "https://server.example/mcp")
    headers: dict[str, str] = {}
    if www_authenticate:
        headers["WWW-Authenticate"] = www_authenticate
    response = httpx.Response(status_code, request=request, headers=headers)
    # ``raise_for_status`` would normally raise HTTPStatusError;
    # construct it directly instead
    return httpx.HTTPStatusError(f"HTTP {status_code}", request=request, response=response)


class TestCallToolAuthRetryOn401:
    """Per ADR-002 + plan §T9 retry semantics: 401 from the MCP server
    means the cached token is no longer accepted (e.g., AS rotated
    keys, token revoked). MCPHost MUST drop the cached token,
    re-acquire (forcing fresh PRM discovery), and retry once. A
    second 401 is the terminal failure mode."""

    async def test_401_triggers_drop_reacquire_retry_then_success(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
    ) -> None:
        """First send raises 401; second send (after token re-acquired)
        succeeds → caller sees CallResult."""
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        first_send_error = MCPTransportError(
            "mcp_transport_send_failed",
            "send failed",
            server_url=server_entry.server_url,
        )
        first_send_error.__cause__ = _httpx_status_error(401)
        http_transport.send.side_effect = [first_send_error, {"content": "ok-after-retry"}]

        result = await host.call_tool(
            server_id=server_entry.server_id,
            tool_name="lookup",
            arguments={},
            request_id="r1",
            tenant_id="t-1",
        )
        assert result.payload == {"content": "ok-after-retry"}
        # Token re-acquired (MUST have been invalidated then re-acquired)
        assert authz.acquire_token.await_count == 2
        # Authz client's invalidate_cached_token MUST have been called
        # for this server's URL
        authz.invalidate_cached_token.assert_called_once()
        ic_call = authz.invalidate_cached_token.await_args
        assert ic_call.kwargs["server_url"] == server_entry.server_url
        # send called twice: original + retry
        assert http_transport.send.await_count == 2
        # Two sessions opened (one closed after first 401, fresh open for retry)
        assert http_transport.open_session.await_count == 2
        assert http_transport.close_session.await_count == 2

    async def test_second_401_terminates_with_authorisation_lost(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
    ) -> None:
        """Second 401 in a row → fail with mcp_authorisation_lost (no
        infinite retry loop). The reviewer's ADR citation."""
        from cognic_agentos.protocol.mcp_authz import MCPAuthzError
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        e1 = MCPTransportError(
            "mcp_transport_send_failed", "401a", server_url=server_entry.server_url
        )
        e1.__cause__ = _httpx_status_error(401)
        e2 = MCPTransportError(
            "mcp_transport_send_failed", "401b", server_url=server_entry.server_url
        )
        e2.__cause__ = _httpx_status_error(401)
        http_transport.send.side_effect = [e1, e2]

        with pytest.raises(MCPAuthzError) as exc:
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="r1",
                tenant_id="t-1",
            )
        assert exc.value.reason == "mcp_authorisation_lost"
        # Second send happened (proves we did try the retry)
        assert http_transport.send.await_count == 2


class TestCallToolStepUpOn403InsufficientScope:
    """403 with WWW-Authenticate ``error="insufficient_scope",
    scope="<wider>"`` → call ``authz.step_up_token`` with the wider
    scope. If the manifest declares the wider scope, step_up succeeds
    and we retry; if not, ``mcp_step_up_unauthorised`` propagates."""

    async def test_403_insufficient_scope_step_up_then_retry_succeeds(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
    ) -> None:
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        first_send_error = MCPTransportError(
            "mcp_transport_send_failed",
            "403 needs wider scope",
            server_url=server_entry.server_url,
        )
        first_send_error.__cause__ = _httpx_status_error(
            403,
            'Bearer error="insufficient_scope", scope="mcp:tools.write"',
        )
        # Simulate step_up_token returning a fresh stepped-up token
        stepped_up = _token("stepped-up-token")
        authz.step_up_token = AsyncMock(return_value=stepped_up)
        http_transport.send.side_effect = [first_send_error, {"content": "ok-after-stepup"}]

        result = await host.call_tool(
            server_id=server_entry.server_id,
            tool_name="lookup",
            arguments={},
            request_id="r1",
            tenant_id="t-1",
        )
        assert result.payload == {"content": "ok-after-stepup"}
        # step_up called with the requested wider scope
        authz.step_up_token.assert_awaited_once()
        su_call = authz.step_up_token.await_args
        assert su_call.kwargs["requested_scope"] == "mcp:tools.write"
        assert su_call.kwargs["server_url"] == server_entry.server_url
        # Second open uses the stepped-up token
        second_open = http_transport.open_session.await_args_list[1]
        assert second_open.kwargs["token"] is stepped_up

    async def test_403_insufficient_scope_step_up_unauthorised_propagates(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
    ) -> None:
        """Manifest does NOT declare the wider scope → step_up_token
        raises mcp_step_up_unauthorised → propagates to caller. T5's
        existing step-up audit machinery fires from inside
        step_up_token (which writes the audit row)."""
        from cognic_agentos.protocol.mcp_authz import MCPAuthzError
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        first_send_error = MCPTransportError(
            "mcp_transport_send_failed",
            "403",
            server_url=server_entry.server_url,
        )
        first_send_error.__cause__ = _httpx_status_error(
            403,
            'Bearer error="insufficient_scope", scope="mcp:secret"',
        )
        http_transport.send.side_effect = [first_send_error]
        authz.step_up_token = AsyncMock(
            side_effect=MCPAuthzError(
                "mcp_step_up_unauthorised",
                "manifest does not declare mcp:secret",
                server_url=server_entry.server_url,
            )
        )

        with pytest.raises(MCPAuthzError) as exc:
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="r1",
                tenant_id="t-1",
            )
        assert exc.value.reason == "mcp_step_up_unauthorised"


class TestCallTool403InvalidToken:
    """403 with ``error="invalid_token"`` follows the SAME drop-and-
    rediscover path as 401 — spec says invalid_token can return
    either status."""

    async def test_403_invalid_token_drops_and_retries(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
    ) -> None:
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        first_send_error = MCPTransportError(
            "mcp_transport_send_failed",
            "403 invalid_token",
            server_url=server_entry.server_url,
        )
        first_send_error.__cause__ = _httpx_status_error(403, 'Bearer error="invalid_token"')
        http_transport.send.side_effect = [first_send_error, {"content": "ok-after-rediscover"}]

        result = await host.call_tool(
            server_id=server_entry.server_id,
            tool_name="lookup",
            arguments={},
            request_id="r1",
            tenant_id="t-1",
        )
        assert result.payload == {"content": "ok-after-rediscover"}
        authz.invalidate_cached_token.assert_called_once()
        # NOT step_up_token — invalid_token is not a scope deficit
        assert getattr(authz.step_up_token, "await_count", 0) == 0


class TestCallToolNon401403TransportErrorPropagatesUnchanged:
    """Existing contract preserved: an mcp_transport_send_failed whose
    underlying cause is NOT an HTTP 401/403 (e.g., DNS failure,
    timeout, malformed response) propagates to the caller as before
    — no retry, no token invalidation."""

    async def test_dns_error_propagates_no_retry(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
    ) -> None:
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        first_send_error = MCPTransportError(
            "mcp_transport_send_failed",
            "dns resolve failed",
            server_url=server_entry.server_url,
        )
        first_send_error.__cause__ = ConnectionError("dns resolution failure")
        http_transport.send.side_effect = first_send_error

        with pytest.raises(MCPTransportError) as exc:
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="r1",
                tenant_id="t-1",
            )
        assert exc.value.reason == "mcp_transport_send_failed"
        authz.invalidate_cached_token.assert_not_called()
        assert http_transport.send.await_count == 1


class TestCallToolTimeoutPropagatesUnchanged:
    """The timeout path raised mcp_call_tool_timeout — no retry. Same
    no-retry contract as the existing transport-failure path."""

    async def test_call_tool_timeout_no_retry(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
    ) -> None:
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        http_transport.send.side_effect = MCPTransportError(
            "mcp_call_tool_timeout",
            "timeout",
            server_url=server_entry.server_url,
        )

        with pytest.raises(MCPTransportError) as exc:
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="r1",
                tenant_id="t-1",
            )
        assert exc.value.reason == "mcp_call_tool_timeout"
        authz.invalidate_cached_token.assert_not_called()


# ---------------------------------------------------------------------------
# Defensive branch coverage for the auth-classifier + retry paths
# ---------------------------------------------------------------------------


class TestClassifySendErrorEdgeCases:
    """Defensive coverage for the ``_classify_send_error`` helper +
    the call_tool retry path edge cases. Each test exercises a branch
    that protects against malformed-but-plausible HTTP responses or
    second-attempt failure modes."""

    async def test_403_insufficient_scope_without_scope_hint_falls_through_to_authz_lost(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
    ) -> None:
        """``WWW-Authenticate: Bearer error="insufficient_scope"`` with
        no ``scope=`` hint is malformed but plausible (some AS
        implementations omit it). MUST fall through to authz_lost
        (drop+rediscover) so we at least retry — better than
        propagating a generic transport error."""
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        first_send_error = MCPTransportError(
            "mcp_transport_send_failed",
            "403 no scope hint",
            server_url=server_entry.server_url,
        )
        first_send_error.__cause__ = _httpx_status_error(403, 'Bearer error="insufficient_scope"')
        http_transport.send.side_effect = [first_send_error, {"content": "ok-after-rediscover"}]

        result = await host.call_tool(
            server_id=server_entry.server_id,
            tool_name="lookup",
            arguments={},
            request_id="r1",
            tenant_id="t-1",
        )
        assert result.payload == {"content": "ok-after-rediscover"}
        # Took the authz_lost path (NOT step_up — there was no scope to step up to)
        authz.invalidate_cached_token.assert_called_once()
        # step_up_token NOT called (no scope hint = no step-up target)
        assert getattr(authz.step_up_token, "await_count", 0) == 0

    async def test_403_with_no_www_authenticate_header_falls_through_to_authz_lost(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
    ) -> None:
        """403 with NO WWW-Authenticate header at all → authz_lost
        fallback (same drop+rediscover remediation)."""
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        first_send_error = MCPTransportError(
            "mcp_transport_send_failed",
            "403 bare",
            server_url=server_entry.server_url,
        )
        first_send_error.__cause__ = _httpx_status_error(403)  # no WWW-Authenticate
        http_transport.send.side_effect = [first_send_error, {"content": "ok"}]

        result = await host.call_tool(
            server_id=server_entry.server_id,
            tool_name="lookup",
            arguments={},
            request_id="r1",
            tenant_id="t-1",
        )
        assert result.payload == {"content": "ok"}
        authz.invalidate_cached_token.assert_called_once()

    async def test_send_returns_500_propagates_as_transport_failed(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
    ) -> None:
        """Non-401/403 HTTPStatusError (5xx etc.) → transport_failed
        path → propagate unchanged. NOT an auth issue; no retry."""
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        first_send_error = MCPTransportError(
            "mcp_transport_send_failed",
            "500",
            server_url=server_entry.server_url,
        )
        first_send_error.__cause__ = _httpx_status_error(500)
        http_transport.send.side_effect = first_send_error

        with pytest.raises(MCPTransportError) as exc:
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="r1",
                tenant_id="t-1",
            )
        assert exc.value.reason == "mcp_transport_send_failed"
        authz.invalidate_cached_token.assert_not_called()
        assert http_transport.send.await_count == 1

    async def test_retry_after_401_then_non_auth_failure_propagates_second_error(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
    ) -> None:
        """First send: 401 (triggers retry). Second send: timeout
        (mcp_call_tool_timeout, not auth-related). Caller MUST see
        the SECOND error (mcp_call_tool_timeout), not the original
        401 nor a wrapped mcp_authorisation_lost — the second error
        is the actual blocker."""
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        e1 = MCPTransportError(
            "mcp_transport_send_failed",
            "401",
            server_url=server_entry.server_url,
        )
        e1.__cause__ = _httpx_status_error(401)
        e2 = MCPTransportError(
            "mcp_call_tool_timeout",
            "timeout",
            server_url=server_entry.server_url,
        )
        http_transport.send.side_effect = [e1, e2]

        with pytest.raises(MCPTransportError) as exc:
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="r1",
                tenant_id="t-1",
            )
        # Caller sees the SECOND error class — operator diagnostic preserved
        assert exc.value.reason == "mcp_call_tool_timeout"
        # Retry happened (proves the auth path triggered)
        assert http_transport.send.await_count == 2
        authz.invalidate_cached_token.assert_called_once()


class TestCanonicalizeTransportKindHelper:
    """Direct coverage for ``_canonicalize_transport_kind`` — both
    the canonical-family branches (covered indirectly by other
    tests) AND the unknown-kind passthrough (the defensive branch
    the constructor's validation depends on for its error message)."""

    def test_http_family_canonicalizes_to_http(self, host_module: Any) -> None:
        assert host_module._canonicalize_transport_kind("http") == "http"
        assert host_module._canonicalize_transport_kind("streamable-http") == "http"

    def test_stdio_canonicalizes_to_stdio(self, host_module: Any) -> None:
        assert host_module._canonicalize_transport_kind("stdio") == "stdio"

    def test_unknown_kind_returned_unchanged(self, host_module: Any) -> None:
        """The constructor's validation depends on this passthrough
        to surface the original (unknown) kind in its error message
        rather than masking it with a normalised value."""
        assert host_module._canonicalize_transport_kind("websocket") == "websocket"
        assert host_module._canonicalize_transport_kind("") == ""


class TestDuplicateTransportFamilyKeysWarning:
    """R1 P2 #1 implementation detail: if an operator wires BOTH
    ``"http"`` and ``"streamable-http"`` keys (e.g., copy-paste
    mistake or transitional config), the second-registered transport
    silently wins for the canonical key. We log a warning so the
    operator sees the misconfiguration at startup."""

    def test_duplicate_http_family_keys_logs_warning(
        self,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        import logging

        # Two physical transports under the two HTTP-family keys
        other_http = _http_transport(host_module, "https://server.example/mcp")
        with caplog.at_level(logging.WARNING, logger="cognic_agentos.protocol.mcp_host"):
            host_module.MCPHost(
                servers={},  # empty — focus on transport-key handling
                transports={"http": http_transport, "streamable-http": other_http},
                authz=authz,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                settings=settings,
            )
        warnings = [r.getMessage() for r in caplog.records if "canonical" in r.getMessage()]
        assert warnings, (
            "expected a warning about duplicate canonical-family keys; "
            f"got: {[r.getMessage() for r in caplog.records]}"
        )


# ---------------------------------------------------------------------------
# R2 P2 #1 — reject UNKNOWN transport families at construction
# ---------------------------------------------------------------------------


class TestUnknownTransportKindRejectedAtConstruction:
    """Type hints (``TransportKind = Literal[...]``) only protect
    statically-typed call sites. Pack manifests + runtime wiring data
    are typed as plain strings at the boundary, so a future refactor
    or operator-supplied config could plant ``transport_kind="websocket"``
    and a transports mapping ``{"websocket": <fake>}``. T6's
    capability validator refuses unknown transports at registration
    (the load-bearing fence); MCPHost MUST do the same at startup
    so transport-bypass is impossible at the runtime boundary too.
    """

    def test_server_with_unknown_transport_kind_rejected_even_when_wired(
        self,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        """A server entry declaring a transport_kind outside the
        canonical allow-list (http / streamable-http / stdio) MUST
        be rejected at MCPHost construction even if the operator
        wires a matching key in the transports mapping. Bypass would
        defeat T6's transport allow-list."""
        bad_entry = host_module.MCPServerEntry(
            server_id="websocket.mcp",
            server_url="wss://server.example/mcp",
            transport_kind="websocket",
            manifest_scopes=("mcp:tools",),
            risk_tier="read_only",
            pack_signature_digest="sha256:a",
        )
        with pytest.raises(ValueError, match="websocket"):
            host_module.MCPHost(
                servers={bad_entry.server_id: bad_entry},
                transports={"websocket": http_transport},
                authz=authz,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                settings=settings,
            )

    def test_transports_mapping_with_unknown_key_rejected(
        self,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        """An unknown key in the transports mapping (even with no
        corresponding server entry referencing it) MUST be rejected
        — operator misconfiguration that signals an attempt to wire
        a transport family AgentOS does not support."""
        with pytest.raises(ValueError, match="websocket"):
            host_module.MCPHost(
                servers={},
                transports={"http": http_transport, "websocket": http_transport},
                authz=authz,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                settings=settings,
            )

    def test_server_unknown_kind_rejected_even_when_transports_mapping_is_clean(
        self,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        """Belt-and-suspenders: if the transports mapping is fully
        valid (only known keys) but a server entry sneaks in with an
        unknown transport_kind, the server-side check MUST still
        reject — protects against the case where a registry walk
        captured a malformed entry that bypassed T6 (e.g., test
        harness or future bug)."""
        bad_entry = host_module.MCPServerEntry(
            server_id="websocket.mcp",
            server_url="wss://server.example/mcp",
            transport_kind="websocket",
            manifest_scopes=("mcp:tools",),
            risk_tier="read_only",
            pack_signature_digest="sha256:a",
        )
        with pytest.raises(ValueError, match="websocket"):
            host_module.MCPHost(
                servers={bad_entry.server_id: bad_entry},
                # transports mapping is CLEAN — only the known "http"
                # key. The transports-side check passes; the server-
                # side check is what fires.
                transports={"http": http_transport},
                authz=authz,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                settings=settings,
            )

    def test_known_kinds_explicit_allow_list_pinned(self, host_module: Any) -> None:
        """The canonical allow-list pins exactly the three known
        transport-kind strings (http / streamable-http / stdio).
        Adding a new transport family is a Sprint-N task that MUST
        explicitly extend this set + land the corresponding
        transport implementation; until then, anything else is
        rejected at startup."""
        assert frozenset({"http", "streamable-http", "stdio"}) == (
            host_module._KNOWN_TRANSPORT_KINDS
        ), (
            "The canonical transport-kind allow-list MUST stay pinned "
            "to {http, streamable-http, stdio}. Adding a new family "
            "without explicit Sprint-N review is a doctrine violation."
        )


# ---------------------------------------------------------------------------
# R2 P2 #2 — list_tools cache MUST deep-copy tool descriptors
# ---------------------------------------------------------------------------


class TestListToolsCacheDeepCopiesDescriptors:
    """``list(cached.tools)`` only protects the OUTER list. The cached
    tool entries themselves are still the same dict / list objects.
    The SDK currently returns dict-shaped descriptors, so a caller
    can mutate ``first[0]['name']`` and poison every later cached
    response for that tenant/server/scope. The cache MUST deep-copy
    on write AND read so the cache is fully isolated from caller-
    side mutation in either direction.
    """

    async def test_caller_mutating_inner_dict_does_not_poison_later_reads(
        self,
        host: Any,
        server_entry: Any,
    ) -> None:
        """First call returns a list of dict descriptors. Caller
        mutates ``first[0]["name"]`` to a poison value. Second call
        (cache hit) MUST return the original tool descriptors —
        unaffected by the caller's mutation."""
        first = await host.list_tools(
            server_id=server_entry.server_id, request_id="r1", tenant_id="t-1"
        )
        # Caller mutates an inner descriptor — would poison cache if
        # we didn't deep-copy
        assert first[0]["name"] == "lookup"
        first[0]["name"] = "POISONED-NAME"
        first[0]["malicious_field"] = "injected"

        second = await host.list_tools(
            server_id=server_entry.server_id, request_id="r2", tenant_id="t-1"
        )
        # Second cached read MUST return the original descriptor
        assert second[0]["name"] == "lookup", (
            "Cache was poisoned by a caller-side mutation of an inner "
            "descriptor. list_tools cache MUST deep-copy tool "
            "descriptors on write AND read."
        )
        assert "malicious_field" not in second[0], (
            "Cache picked up an extra field a caller injected via inner-descriptor mutation."
        )

    async def test_two_consecutive_callers_get_independent_descriptor_copies(
        self,
        host: Any,
        server_entry: Any,
    ) -> None:
        """Two consecutive cached reads MUST return distinct dict
        instances (deep-copies) so neither caller can affect the
        other through a shared inner reference."""
        first = await host.list_tools(
            server_id=server_entry.server_id, request_id="r1", tenant_id="t-1"
        )
        second = await host.list_tools(
            server_id=server_entry.server_id, request_id="r2", tenant_id="t-1"
        )
        assert first[0] is not second[0], (
            "Two cached reads returned the SAME inner descriptor object "
            "— caller A mutating their copy would affect caller B. Use "
            "deep-copy on cache write/read."
        )

    async def test_sdk_response_mutation_after_first_call_does_not_poison_cache(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
    ) -> None:
        """If the SDK returns a list of descriptor dicts and the SDK
        (or test fixture) holds a reference that gets mutated AFTER
        the cache stored them, the cache MUST still serve the
        original values. Tests deep-copy on cache WRITE."""
        # Trigger the first call — cache stores the descriptors
        await host.list_tools(server_id=server_entry.server_id, request_id="r1", tenant_id="t-1")
        # Reach into the SDK fixture and mutate the original list
        sdk_session = http_transport.open_session.return_value.sdk_session
        sdk_response = sdk_session.list_tools.return_value
        # Mutate the SDK's internal response
        if isinstance(sdk_response, list) and sdk_response and isinstance(sdk_response[0], dict):
            sdk_response[0]["name"] = "POISONED-AT-SOURCE"

        # Second call should hit the cache and return the original
        # descriptor name (deep-copy on write decoupled the cache
        # from the SDK's response object)
        second = await host.list_tools(
            server_id=server_entry.server_id, request_id="r2", tenant_id="t-1"
        )
        assert second[0]["name"] == "lookup", (
            "Cache was poisoned by mutation of the SDK response object "
            "after the cache stored it. list_tools cache MUST deep-copy "
            "tool descriptors on WRITE."
        )


# ---------------------------------------------------------------------------
# R3 P1 — normalize real SDK ListToolsResult + pagination
# ---------------------------------------------------------------------------


class TestListToolsRealSDKResultShape:
    """Production reality: ``ClientSession.list_tools()`` returns
    ``mcp.types.ListToolsResult`` (Pydantic) — NOT a bare list. The
    earlier tests passed with bare-list mocks, but ``list(result)``
    on a Pydantic model yields field tuples like
    ``[('meta', None), ('nextCursor', None), ('tools', [...])]`` —
    completely wrong shape. MCPHost.list_tools MUST normalize via
    ``result.tools``, and MUST loop on ``nextCursor`` so the caller
    receives every tool the server has."""

    async def test_real_list_tools_result_is_normalized_to_tools_field(
        self,
        host_module: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        """Use a real :class:`mcp.types.ListToolsResult` (Pydantic)
        as the SDK response. The host MUST return the
        ``result.tools`` list (a list of ``Tool`` instances) — NOT
        the field-tuple iteration of the Pydantic model."""
        from mcp.types import ListToolsResult, Tool

        real_result = ListToolsResult(
            tools=[
                Tool(name="lookup", description="Look up X", inputSchema={"type": "object"}),
                Tool(name="search", description="Search Y", inputSchema={"type": "object"}),
            ]
        )
        # Replace the fixture's bare-list mock with a real Pydantic
        # model (production shape)
        http_transport.open_session.return_value.sdk_session.list_tools = AsyncMock(
            return_value=real_result
        )
        host = host_module.MCPHost(
            servers={server_entry.server_id: server_entry},
            transports={"http": http_transport},
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )

        result = await host.list_tools(
            server_id=server_entry.server_id, request_id="r1", tenant_id="t-1"
        )
        # Two tools, properly extracted
        assert len(result) == 2
        # Each entry is a Tool instance with the expected name —
        # NOT a Pydantic field tuple like ('tools', [...])
        assert result[0].name == "lookup"
        assert result[1].name == "search"

    async def test_paginated_list_tools_walks_next_cursor_to_completion(
        self,
        host_module: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        """Per the SDK signature
        ``list_tools(cursor: str | None = None) -> ListToolsResult``,
        the orchestrator MUST loop on ``nextCursor`` until exhausted
        (None / empty) and return the accumulated tool list across
        every page. A pack with > 1 page of tools would otherwise
        silently lose half its catalogue."""
        from mcp.types import ListToolsResult, Tool

        page_1 = ListToolsResult(
            tools=[Tool(name="page1.a", description="", inputSchema={"type": "object"})],
            nextCursor="cursor-2",
        )
        page_2 = ListToolsResult(
            tools=[Tool(name="page2.a", description="", inputSchema={"type": "object"})],
            nextCursor="cursor-3",
        )
        page_3 = ListToolsResult(
            tools=[Tool(name="page3.a", description="", inputSchema={"type": "object"})],
            nextCursor=None,
        )
        sdk_list = AsyncMock(side_effect=[page_1, page_2, page_3])
        http_transport.open_session.return_value.sdk_session.list_tools = sdk_list

        host = host_module.MCPHost(
            servers={server_entry.server_id: server_entry},
            transports={"http": http_transport},
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )
        result = await host.list_tools(
            server_id=server_entry.server_id, request_id="r1", tenant_id="t-1"
        )
        # All three tools accumulated
        assert [t.name for t in result] == ["page1.a", "page2.a", "page3.a"]
        # Three SDK calls (the orchestrator looped on nextCursor)
        assert sdk_list.await_count == 3
        # The second + third calls passed the cursor from the
        # previous page
        assert sdk_list.await_args_list[1].args == ("cursor-2",)
        assert sdk_list.await_args_list[2].args == ("cursor-3",)

    async def test_empty_string_next_cursor_treated_as_exhausted(
        self,
        host_module: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        """Defensive: some servers may signal exhaustion with an
        empty-string cursor rather than None. Both MUST be treated
        as "no more pages"."""
        from mcp.types import ListToolsResult, Tool

        page = ListToolsResult(
            tools=[Tool(name="only", description="", inputSchema={"type": "object"})],
            nextCursor="",
        )
        http_transport.open_session.return_value.sdk_session.list_tools = AsyncMock(
            return_value=page
        )
        host = host_module.MCPHost(
            servers={server_entry.server_id: server_entry},
            transports={"http": http_transport},
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )
        result = await host.list_tools(
            server_id=server_entry.server_id, request_id="r1", tenant_id="t-1"
        )
        assert len(result) == 1
        # SDK called exactly once — empty cursor halted the loop
        assert http_transport.open_session.return_value.sdk_session.list_tools.await_count == 1


# ---------------------------------------------------------------------------
# R3 P2 — best_effort_close must catch hook exceptions too
# ---------------------------------------------------------------------------


class TestBestEffortCloseHookFailureToleration:
    """T7's :meth:`StreamableHTTPTransport.close_session` emits the
    ``session_close`` event AFTER ``stack.aclose()`` succeeds. That
    hook is NOT wrapped in a safe-emit shim (unlike the send-error
    path), so a buggy audit hook can raise a generic exception that
    propagates out of ``close_session``.

    MCPHost's ``_best_effort_close`` previously only caught
    :class:`MCPTransportError`, so the generic hook exception would
    escape and mask the primary result/error of the surrounding
    list_tools / call_tool. Same discipline as T7's
    ``_emit_send_error_safe``: catch ``Exception`` (NOT
    ``BaseException`` — task teardown still propagates), log token-
    free with ``error_type``, emit a close-failure audit row with
    ``failure_class="hook"`` so operators see the audit-pipeline bug
    without losing the primary outcome.
    """

    async def test_close_hook_failure_does_not_mask_call_tool_result(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        """Send succeeds, close raises a generic ``RuntimeError``
        (audit hook bug) — caller MUST still see the CallResult
        payload. Close-hook failure logged token-free + audit-row
        emitted with ``failure_class="hook"``."""
        http_transport.close_session.side_effect = RuntimeError(
            "audit hook for session_close raised: bearer eyJabc..."
        )

        result = await host.call_tool(
            server_id=server_entry.server_id,
            tool_name="lookup",
            arguments={},
            request_id="r1",
            tenant_id="t-1",
        )
        # Primary result preserved
        assert result.payload == {"content": "ok"}

        # Close-hook-failure audit row emitted with hook
        # classification
        appended = [c.args[0] for c in audit_store.append.await_args_list]
        hook_rows = [e for e in appended if e.payload.get("failure_class") == "hook"]
        assert hook_rows, (
            "expected at least one close-failure audit row with "
            f"failure_class='hook'; got: {[e.payload for e in appended]}"
        )

        # The hook exception MESSAGE TEXT (which carried a fake
        # bearer token) MUST NOT appear in any audit row payload —
        # only the class name.
        for row in appended:
            assert "Bearer eyJabc" not in str(row.payload), (
                f"audit row leaked the hook exception's message text: {row.payload}"
            )
            assert "audit hook for session_close" not in str(row.payload)
        assert any(row.payload.get("error_type") == "RuntimeError" for row in hook_rows)

    async def test_close_hook_failure_does_not_mask_send_error(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
    ) -> None:
        """Send raises a transport error AND close raises a generic
        hook exception. The caller MUST see the SEND error (the
        primary fault), NOT the close-hook exception."""
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        http_transport.send.side_effect = MCPTransportError(
            "mcp_transport_send_failed",
            "boom",
            server_url=server_entry.server_url,
        )
        http_transport.close_session.side_effect = RuntimeError("hook raised")

        with pytest.raises(MCPTransportError) as exc:
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="r1",
                tenant_id="t-1",
            )
        assert exc.value.reason == "mcp_transport_send_failed"

    async def test_close_hook_cancellation_propagates(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
    ) -> None:
        """Cancellation (``BaseException`` subclass) is the ONE class
        that's allowed to escape ``_best_effort_close`` — task
        teardown should not be silently absorbed by the close
        helper."""
        http_transport.close_session.side_effect = asyncio.CancelledError()

        with pytest.raises(asyncio.CancelledError):
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="r1",
                tenant_id="t-1",
            )

    def test_normalize_list_tools_page_defensive_typeerror_on_unknown_shape(
        self, host_module: Any
    ) -> None:
        """Defensive: a future SDK refactor that returns a dict /
        custom object that's neither ``ListToolsResult`` nor a bare
        list MUST raise so the failure surfaces immediately rather
        than being silently ignored as zero tools."""
        with pytest.raises(TypeError, match="Unexpected list_tools"):
            host_module.MCPHost._normalize_list_tools_page({"unexpected": "shape"})

    async def test_close_hook_failure_does_not_mask_list_tools_result(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        """Same contract for list_tools: close-hook failure logged
        + audit-emitted but the cached + returned tool list is
        unaffected."""
        http_transport.close_session.side_effect = RuntimeError("hook raised")

        result = await host.list_tools(
            server_id=server_entry.server_id, request_id="r1", tenant_id="t-1"
        )
        assert result is not None
        appended = [c.args[0] for c in audit_store.append.await_args_list]
        assert any(e.payload.get("failure_class") == "hook" for e in appended), (
            f"expected close-hook-failure audit row; got: {[e.payload for e in appended]}"
        )


# ---------------------------------------------------------------------------
# R4 P2 #1 — pagination MUST be bounded against cycles + runaway page counts
# ---------------------------------------------------------------------------


class TestListToolsPaginationBounded:
    """A buggy or malicious MCP server can return the same non-empty
    cursor forever, or an unbounded sequence of distinct cursors.
    The orchestrator MUST detect both classes (cycle / cap exceeded)
    and fail with a controlled :class:`MCPTransportError` rather
    than looping forever — the SDK's per-call timeout never fires
    if the server returns each page quickly.
    """

    async def test_repeated_cursor_detected_and_raised(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
    ) -> None:
        from mcp.types import ListToolsResult, Tool

        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        loop_page = ListToolsResult(
            tools=[Tool(name="loop", description="", inputSchema={"type": "object"})],
            nextCursor="STUCK-CURSOR",
        )
        http_transport.open_session.return_value.sdk_session.list_tools = AsyncMock(
            return_value=loop_page
        )

        with pytest.raises(MCPTransportError) as exc:
            await host.list_tools(
                server_id=server_entry.server_id, request_id="r1", tenant_id="t-1"
            )
        assert exc.value.reason == "mcp_transport_send_failed"
        assert exc.value.payload.get("pagination_failure") == "cycle_detected"
        # R5 P2: the verbatim cursor MUST NOT appear; a non-reversible
        # fingerprint + length is what flows into T11's audit/error
        # rows. The fingerprint is sufficient to correlate with
        # server-side debugging without leaking the opaque cursor.
        assert "cursor_repeated" not in exc.value.payload
        assert exc.value.payload.get("cursor_repeated_fingerprint") is not None
        assert exc.value.payload.get("cursor_repeated_length") == len("STUCK-CURSOR")

    async def test_page_cap_exceeded_raises(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
    ) -> None:
        from mcp.types import ListToolsResult, Tool

        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        page_counter = {"n": 0}

        async def _page(_cursor: Any = None) -> ListToolsResult:
            page_counter["n"] += 1
            return ListToolsResult(
                tools=[
                    Tool(
                        name=f"t-{page_counter['n']}",
                        description="",
                        inputSchema={"type": "object"},
                    )
                ],
                nextCursor=f"cursor-{page_counter['n'] + 1}",
            )

        http_transport.open_session.return_value.sdk_session.list_tools = _page

        with pytest.raises(MCPTransportError) as exc:
            await host.list_tools(
                server_id=server_entry.server_id, request_id="r1", tenant_id="t-1"
            )
        assert exc.value.reason == "mcp_transport_send_failed"
        assert exc.value.payload.get("pagination_failure") == "cap_exceeded"
        assert exc.value.payload.get("pages_walked", 0) <= 200

    def test_page_cap_constant_pinned(self, host_module: Any) -> None:
        """The page cap is a deliberate fence — pin its value so a
        future refactor that bumps it past a sane bound is reviewer-
        visible."""
        assert host_module._MAX_LIST_TOOLS_PAGES == 100, (
            "list_tools page cap drift detected. Any change requires explicit Sprint-N review."
        )


# ---------------------------------------------------------------------------
# R4 P2 #2 — list_tools SDK errors mapped to closed-enum MCPTransportError
# ---------------------------------------------------------------------------


class TestListToolsPaginationCursorOpacity:
    """**R5 P2 contract** — MCP pagination cursors are opaque server-
    controlled continuation tokens. They may encode internal session
    state, query offsets, signed payloads, or other server-side data
    operators MUST NOT see. The cycle-detection error payload MUST
    include only a non-reversible fingerprint + length; the verbatim
    cursor MUST NEVER reach the structured ``MCPTransportError.payload``
    (which T11 will pipe into ``audit.tool_invocation_error`` rows +
    operator logs).

    Same discipline as T7's send-error paths: never put server-
    controlled bytes verbatim into a closed-enum payload field.
    """

    async def test_secret_looking_cursor_never_appears_in_payload(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
    ) -> None:
        """Use a cursor that LOOKS like a secret (signed JWT-ish
        payload). The verbatim string MUST NOT appear anywhere in
        the raised ``MCPTransportError.payload`` or its repr."""
        from mcp.types import ListToolsResult, Tool

        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        secret_cursor = "eyJhbGciOiJIUzI1NiJ9.LEAKED-SESSION-STATE-INTERNAL-OFFSET-42.sig"
        loop_page = ListToolsResult(
            tools=[Tool(name="x", description="", inputSchema={"type": "object"})],
            nextCursor=secret_cursor,
        )
        http_transport.open_session.return_value.sdk_session.list_tools = AsyncMock(
            return_value=loop_page
        )

        with pytest.raises(MCPTransportError) as exc:
            await host.list_tools(
                server_id=server_entry.server_id, request_id="r1", tenant_id="t-1"
            )
        # The verbatim cursor MUST NOT appear in any payload field
        payload_repr = repr(exc.value.payload)
        for marker in (
            secret_cursor,
            "LEAKED-SESSION-STATE-INTERNAL-OFFSET-42",
            "eyJhbGciOiJIUzI1NiJ9",
        ):
            assert marker not in payload_repr, (
                f"verbatim pagination cursor leaked into payload "
                f"({marker!r}); use the fingerprint + length instead. "
                f"payload={exc.value.payload!r}"
            )
        # And not in the exception message either
        assert secret_cursor not in str(exc.value)
        # Fingerprint + length DO appear (operator-debuggable
        # without leaking the cursor)
        fingerprint = exc.value.payload.get("cursor_repeated_fingerprint")
        assert fingerprint is not None
        assert isinstance(fingerprint, str)
        # Fingerprint is short + bounded (sha256 prefix); not the
        # whole hash either, since even the hash could be replayed
        # against rainbow tables for known cursor schemes
        assert len(fingerprint) <= 32
        assert exc.value.payload.get("cursor_repeated_length") == len(secret_cursor)

    async def test_fingerprint_distinguishes_different_cursors(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
    ) -> None:
        """Two cycle-detections triggered by different cursors MUST
        produce different fingerprints — operators can correlate
        repeat occurrences of the SAME bug without seeing the
        cursor itself."""
        from mcp.types import ListToolsResult, Tool

        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        async def _trip_cycle(cursor: str) -> str:
            page = ListToolsResult(
                tools=[Tool(name="x", description="", inputSchema={"type": "object"})],
                nextCursor=cursor,
            )
            http_transport.open_session.return_value.sdk_session.list_tools = AsyncMock(
                return_value=page
            )
            with pytest.raises(MCPTransportError) as exc:
                await host.list_tools(
                    server_id=server_entry.server_id, request_id="r", tenant_id="t-1"
                )
            fingerprint = exc.value.payload["cursor_repeated_fingerprint"]
            assert isinstance(fingerprint, str)
            return fingerprint

        fp_a = await _trip_cycle("cursor-A")
        fp_b = await _trip_cycle("cursor-B")
        fp_a2 = await _trip_cycle("cursor-A")
        # Same cursor → same fingerprint (correlatable)
        assert fp_a == fp_a2
        # Different cursor → different fingerprint (distinguishable)
        assert fp_a != fp_b


class TestListToolsSDKErrorTaxonomy:
    """The real MCP SDK's ``ClientSession.list_tools`` can raise
    ``asyncio.TimeoutError``, ``mcp.shared.exceptions.McpError``, or
    other transport-level failures. Calling the SDK directly without
    wrapping leaks raw SDK exceptions, bypassing T7's send-error
    closed-enum taxonomy. The orchestrator MUST wrap with
    ``asyncio.wait_for`` + a try/except mapping to the same
    ``MCPTransportReason`` values T7 uses, so list_tools and
    call_tool failures land in the same audit shape."""

    async def test_list_tools_timeout_mapped_to_mcp_call_tool_timeout(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        settings: Any,
    ) -> None:
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        async def _slow(_cursor: Any = None) -> Any:
            await asyncio.sleep(60)

        settings.mcp_call_tool_timeout_s = 0.001
        http_transport.open_session.return_value.sdk_session.list_tools = _slow

        with pytest.raises(MCPTransportError) as exc:
            await host.list_tools(
                server_id=server_entry.server_id, request_id="r1", tenant_id="t-1"
            )
        assert exc.value.reason == "mcp_call_tool_timeout"
        assert exc.value.payload.get("timeout_s") == 0.001

    async def test_list_tools_generic_sdk_exception_mapped_to_send_failed(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
    ) -> None:
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        class _SimulatedMcpError(RuntimeError):
            pass

        secret_in_msg = "Bearer eyJ.LEAKED.sig server-stack /var/secret/db.creds"
        http_transport.open_session.return_value.sdk_session.list_tools = AsyncMock(
            side_effect=_SimulatedMcpError(f"JSON-RPC error: {secret_in_msg}")
        )

        with pytest.raises(MCPTransportError) as exc:
            await host.list_tools(
                server_id=server_entry.server_id, request_id="r1", tenant_id="t-1"
            )
        assert exc.value.reason == "mcp_transport_send_failed"
        assert exc.value.payload.get("error_type") == "_SimulatedMcpError"
        assert secret_in_msg not in str(exc.value.payload), (
            f"SDK exception MESSAGE TEXT leaked into closed-enum payload: {exc.value.payload}"
        )

    async def test_list_tools_failure_still_closes_session(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
    ) -> None:
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        http_transport.open_session.return_value.sdk_session.list_tools = AsyncMock(
            side_effect=RuntimeError("simulated SDK failure")
        )

        with pytest.raises(MCPTransportError):
            await host.list_tools(
                server_id=server_entry.server_id, request_id="r1", tenant_id="t-1"
            )
        http_transport.close_session.assert_awaited_once()

    async def test_list_tools_already_typed_transport_error_propagates_unchanged(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
    ) -> None:
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        original = MCPTransportError(
            "mcp_session_closed",
            "session already closed",
            server_url=server_entry.server_url,
            preserved_marker="kept",
        )
        http_transport.open_session.return_value.sdk_session.list_tools = AsyncMock(
            side_effect=original
        )

        with pytest.raises(MCPTransportError) as exc:
            await host.list_tools(
                server_id=server_entry.server_id, request_id="r1", tenant_id="t-1"
            )
        assert exc.value.reason == "mcp_session_closed"
        assert exc.value.payload.get("preserved_marker") == "kept"


# ---------------------------------------------------------------------------
# PR-1 Slice 2 — invoke-time discovery_status recording (ADR-002).
#
# MCPHost records the per-(tenant, pack) discovery_status at the OAuth probe
# (acquire_token): `auth_ready` on success; `refused`/`unreachable` on
# MCPAuthzError (the error is STILL re-raised — the axis is observational, the
# invoke path stays fail-closed). Key = (tenant_id, pack_id) where pack_id is
# the registry distribution_name == MCPServerEntry.server_id (drift-pinned in
# tests/unit/harness/test_mcp_host_builder.py).
# ---------------------------------------------------------------------------


def _host_with_recorder(
    host_module: Any,
    *,
    server_entry: Any,
    http_transport: MagicMock,
    authz: MagicMock,
    audit_store: MagicMock,
    decision_history_store: MagicMock,
    settings: Any,
    recorder: InMemoryDiscoveryStatusRecorder,
) -> Any:
    return host_module.MCPHost(
        servers={server_entry.server_id: server_entry},
        transports={"http": http_transport},
        authz=authz,
        audit_store=audit_store,
        decision_history_store=decision_history_store,
        settings=settings,
        discovery_status_recorder=recorder,
    )


class TestDiscoveryStatusRecording:
    async def test_list_tools_records_auth_ready_on_probe_success(
        self,
        host_module: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        recorder = InMemoryDiscoveryStatusRecorder()
        host = _host_with_recorder(
            host_module,
            server_entry=server_entry,
            http_transport=http_transport,
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
            recorder=recorder,
        )
        await host.list_tools(server_id=server_entry.server_id, request_id="r-1", tenant_id="t-1")
        assert recorder.get(tenant_id="t-1", pack_id=server_entry.server_id) == "auth_ready"

    async def test_list_tools_records_refused_on_ssrf_and_still_raises(
        self,
        host_module: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        authz.acquire_token = AsyncMock(
            side_effect=MCPAuthzError("mcp_discovery_url_refused", "loopback server_url")
        )
        recorder = InMemoryDiscoveryStatusRecorder()
        host = _host_with_recorder(
            host_module,
            server_entry=server_entry,
            http_transport=http_transport,
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
            recorder=recorder,
        )
        with pytest.raises(MCPAuthzError):  # fail-closed preserved
            await host.list_tools(
                server_id=server_entry.server_id, request_id="r-1", tenant_id="t-1"
            )
        assert recorder.get(tenant_id="t-1", pack_id=server_entry.server_id) == "refused"

    async def test_list_tools_records_unreachable_on_timeout(
        self,
        host_module: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        authz.acquire_token = AsyncMock(
            side_effect=MCPAuthzError("mcp_oauth_request_timeout", "PRM timed out")
        )
        recorder = InMemoryDiscoveryStatusRecorder()
        host = _host_with_recorder(
            host_module,
            server_entry=server_entry,
            http_transport=http_transport,
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
            recorder=recorder,
        )
        with pytest.raises(MCPAuthzError):
            await host.list_tools(
                server_id=server_entry.server_id, request_id="r-1", tenant_id="t-1"
            )
        assert recorder.get(tenant_id="t-1", pack_id=server_entry.server_id) == "unreachable"

    async def test_call_tool_records_auth_ready_on_probe_success(
        self,
        host_module: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        recorder = InMemoryDiscoveryStatusRecorder()
        host = _host_with_recorder(
            host_module,
            server_entry=server_entry,
            http_transport=http_transport,
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
            recorder=recorder,
        )
        await host.call_tool(
            server_id=server_entry.server_id,
            tool_name="lookup",
            arguments={},
            request_id="r-1",
            tenant_id="t-1",
        )
        assert recorder.get(tenant_id="t-1", pack_id=server_entry.server_id) == "auth_ready"

    async def test_call_tool_records_refused_on_ssrf_and_still_raises(
        self,
        host_module: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        authz.acquire_token = AsyncMock(
            side_effect=MCPAuthzError("mcp_discovery_url_refused", "loopback server_url")
        )
        recorder = InMemoryDiscoveryStatusRecorder()
        host = _host_with_recorder(
            host_module,
            server_entry=server_entry,
            http_transport=http_transport,
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
            recorder=recorder,
        )
        with pytest.raises(MCPAuthzError):  # fail-closed preserved
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="r-1",
                tenant_id="t-1",
            )
        assert recorder.get(tenant_id="t-1", pack_id=server_entry.server_id) == "refused"

    async def test_call_tool_records_unreachable_on_retry_reacquire_timeout(
        self,
        host_module: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        """The post-dispatch REACQUIRE site (call_tool 401-retry path, mcp_host.py:1706): the
        first send → 401 (auth-lost) → the retry acquire_token raises mcp_oauth_request_timeout
        → host STILL raises AND the recorder's final status is `unreachable` (the reacquire
        outcome overwrites the initial auth_ready, proving the THIRD probe site records)."""
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        # Initial acquire succeeds; the reacquire (after the 401) times out.
        authz.acquire_token = AsyncMock(
            side_effect=[
                _token(),
                MCPAuthzError("mcp_oauth_request_timeout", "PRM timed out on reacquire"),
            ]
        )
        first_send_error = MCPTransportError(
            "mcp_transport_send_failed", "401", server_url=server_entry.server_url
        )
        first_send_error.__cause__ = _httpx_status_error(401)
        http_transport.send.side_effect = [first_send_error]
        recorder = InMemoryDiscoveryStatusRecorder()
        host = _host_with_recorder(
            host_module,
            server_entry=server_entry,
            http_transport=http_transport,
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
            recorder=recorder,
        )
        with pytest.raises(MCPAuthzError):  # fail-closed preserved
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="r-1",
                tenant_id="t-1",
            )
        assert recorder.get(tenant_id="t-1", pack_id=server_entry.server_id) == "unreachable"


# ---------------------------------------------------------------------------
# PR-2a Task 4 — discovery_status recording at the step-up call site
# ---------------------------------------------------------------------------


def _host_with_step_up_raising(
    recorder: InMemoryDiscoveryStatusRecorder,
    step_up_error: MCPAuthzError,
    *,
    server_id: str = "example.mcp",
    tenant_id: str = "t-1",
) -> tuple[Any, Any, str]:
    """Build a real ``MCPHost`` (recorder injected) wired to drive the GENUINE
    ``call_tool`` → 403-insufficient_scope → ``step_up_token`` production path,
    with ``step_up_token`` stubbed to raise ``step_up_error``.

    Mirrors two existing patterns verbatim so the recording is exercised at the
    actual production call site (never a direct ``step_up_token`` call):

      * ``TestCallToolStepUpOn403InsufficientScope`` (test_mcp_host.py:1192-1208):
        the 403 signal is a real ``MCPTransportError`` whose ``__cause__`` is an
        httpx 403 carrying ``error="insufficient_scope", scope="<wider>"``, fed
        through ``http_transport.send.side_effect`` so ``call_tool`` →
        ``_attempt`` → ``transport.send`` raises it, ``_classify_send_error``
        returns ``("step_up", ...)`` (mcp_host.py:443-446), and the production
        ``else: # signal == "step_up"`` branch (mcp_host.py:1803-1810) awaits
        ``step_up_token``.
      * ``_host_with_recorder`` (test_mcp_host.py:2363-2382): the
        ``discovery_status_recorder=`` constructor injection.

    Returns ``(host, entry, tenant_id)``.
    """
    from cognic_agentos.protocol import mcp_host
    from cognic_agentos.protocol.mcp_transports import MCPTransportError

    server_url = "https://server.example/mcp"

    # Real 403-insufficient_scope signal — identical shape to
    # TestCallToolStepUpOn403InsufficientScope:1192-1208 (a transport error whose
    # __cause__ is an httpx 403 with WWW-Authenticate insufficient_scope+scope).
    first_send_error = MCPTransportError(
        "mcp_transport_send_failed",
        "403 needs wider scope",
        server_url=server_url,
    )
    first_send_error.__cause__ = _httpx_status_error(
        403,
        'Bearer error="insufficient_scope", scope="mcp:tools.write"',
    )

    http_transport = _http_transport(mcp_host, server_url)
    # Mirrors test_mcp_host.py:1201 — the first (and only) send raises the 403.
    http_transport.send.side_effect = [first_send_error]

    authz = MagicMock(spec=MCPAuthzClient)
    authz.acquire_token = AsyncMock(return_value=_token())
    authz.invalidate_cached_token = AsyncMock(return_value=None)
    # The GENUINE production call site (mcp_host.py:1810) — stubbed to raise,
    # mirroring test_mcp_host.py:1202-1208.
    authz.step_up_token = AsyncMock(side_effect=step_up_error)

    audit_store = MagicMock(spec=AuditStore)
    audit_store.append = AsyncMock(return_value=("uuid", b"hash"))
    decision_history_store = MagicMock(spec=DecisionHistoryStore)
    decision_history_store.append = AsyncMock(return_value=("uuid", b"hash"))

    settings = build_settings_without_env_file().model_copy(
        update={"mcp_oauth_request_timeout_s": 7, "mcp_call_tool_timeout_s": 13}
    )

    entry = mcp_host.MCPServerEntry(
        server_id=server_id,
        server_url=server_url,
        transport_kind="http",
        manifest_scopes=("mcp:tools",),
        risk_tier="read_only",
        pack_signature_digest="sha256:deadbeef",
    )

    # ``require_mcp`` is a no-op when the SDK is installed; patch defensively so
    # the helper constructs in a kernel-image-equivalent (no-mcp) venv too,
    # mirroring the ``host_module`` fixture's monkeypatch (test_mcp_host.py:116).
    with patch.object(mcp_host, "require_mcp", MagicMock()):
        host = mcp_host.MCPHost(
            servers={entry.server_id: entry},
            transports={"http": http_transport},
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
            discovery_status_recorder=recorder,
        )
    return host, entry, tenant_id


async def _drive_call_tool_into_step_up(host: Any, entry: Any, tenant_id: str) -> Any:
    """Drive the REAL ``call_tool`` flow into the step-up branch.

    ``call_tool`` → ``acquire_token`` (records ``auth_ready``) → ``_attempt`` →
    ``transport.send`` raises the 403-insufficient_scope ``MCPTransportError`` →
    ``_classify_send_error`` returns ``("step_up", ...)`` → the production
    ``else: # signal == "step_up"`` branch awaits ``self._authz.step_up_token``
    (mcp_host.py:1810). The stub's ``MCPAuthzError`` raises THERE and propagates
    up through the Task-4 ``except MCPAuthzError`` wrapper — i.e. the recording is
    exercised at the genuine production call site, never a direct
    ``step_up_token`` invocation and never a stubbed-out ``call_tool``.

    Mirrors TestCallToolStepUpOn403InsufficientScope:1161-1167 / 1210-1217.
    """
    return await host.call_tool(
        server_id=entry.server_id,
        tool_name="lookup",
        arguments={},
        request_id="r1",
        tenant_id=tenant_id,
    )


class TestStepUpDiscoveryStatusRecording:
    @pytest.mark.parametrize(
        "reason,expected",
        [
            ("mcp_discovery_url_refused", "refused"),  # leg-4/leg-5 SSRF refusal
            ("mcp_oauth_request_timeout", "unreachable"),  # endpoint unreachable
        ],
    )
    async def test_step_up_reachability_failure_records(
        self, reason: AuthzReason, expected: str
    ) -> None:
        """A step-up failure reflecting endpoint/OAuth reachability surfaces on the
        discovery-status axis via the shared mapper — the step-up path is not a
        second unobserved invoke path. (step_up_token reaches _request_token, which
        can fail with SSRF/timeout/transport/discovery/token errors.)"""
        recorder = InMemoryDiscoveryStatusRecorder()
        host, entry, tenant_id = _host_with_step_up_raising(
            recorder, MCPAuthzError(reason, "step-up reachability failure")
        )
        with pytest.raises(MCPAuthzError):
            await _drive_call_tool_into_step_up(host, entry, tenant_id)
        assert recorder.get(tenant_id=tenant_id, pack_id=entry.server_id) == expected

    async def test_step_up_authorization_denial_does_not_record(self) -> None:
        """mcp_step_up_unauthorised is an AUTHORIZATION denial (the original token is
        fine, only the wider scope was denied), NOT endpoint reachability — it must
        NOT touch the discovery-status axis (it stays whatever it was). The first
        acquire records ``auth_ready``; a BROKEN exclusion would overwrite it with
        ``refused`` via the mapper, so this assertion is load-bearing."""
        recorder = InMemoryDiscoveryStatusRecorder()
        recorder.record(tenant_id="bank_a", pack_id="pack-x", status="auth_ready")
        host, entry, tenant_id = _host_with_step_up_raising(
            recorder,
            MCPAuthzError("mcp_step_up_unauthorised", "scope denied"),
            server_id="pack-x",
            tenant_id="bank_a",
        )
        with pytest.raises(MCPAuthzError):
            await _drive_call_tool_into_step_up(host, entry, tenant_id)
        assert recorder.get(tenant_id=tenant_id, pack_id=entry.server_id) == "auth_ready"


def test_mcp_host_has_no_refresh_token_call_path() -> None:
    """PR-2a §3.3 drift pin: refresh_token is guarded-but-unrecorded by design —
    it carries no server_id/pack key and MCPHost never invokes it, so there is no
    production call site that could record discovery_status. If a future MCPHost
    path calls refresh_token, this pin fails and forces the recording decision to
    be revisited (the OAuth-leg guard still applies in _request_token regardless)."""
    src = Path(mcp_host.__file__).read_text()
    tree = ast.parse(src)
    refresh_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "refresh_token"
    ]
    assert refresh_calls == [], (
        "MCPHost now calls refresh_token — revisit PR-2a §3.3 discovery_status recording"
    )
