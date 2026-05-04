"""Sprint-5 T11 — audit-chain linkage for MCP call_tool outcomes.

Critical-controls module per AGENTS.md. Every ``MCPHost.call_tool``
exit path emits exactly one ``audit_event`` row + exactly one
``decision_history`` mcp_call row, correlated by ``request_id`` (per
MCP-CONFORMANCE.md §"Authorization" item 9). This file pins the
audit-chain side; the parallel ``decision_history`` rows are pinned
in :mod:`tests.unit.protocol.test_mcp_decision_history_linkage`.

Audit-chain event vocabulary (per plan §T11):

  - ``audit.tool_invocation`` — every successful call_tool. Carries
    ``pack_id`` + ``pack_signature_digest`` + ``tool_name`` +
    ``mcp_session_id`` + ``as_issuer`` + ``scopes`` (sorted) +
    ``resource_indicator`` + ``client_id`` + ``duration_ms`` +
    ``outcome="ok"``.
  - ``audit.tool_invocation_refused`` — every refusal: ADR-014
    transitional gate (T10 — already wired); pre-dispatch authz
    refusals (T11 adds); 403-step-up-unauthorised (T11 adds).
  - ``audit.tool_invocation_error`` — call dispatched but failed:
    transport timeout / send failure (T11 adds);
    ``mcp_authorisation_lost`` second-401 retry exhaustion
    (T11 adds).

Doctrinal invariant: tokens NEVER appear in audit payloads.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.core.audit import AuditEvent, AuditStore
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.protocol.mcp_authz import MCPAuthzClient, MCPAuthzError, Token

# ---------------------------------------------------------------------------
# Fixtures (mirror test_mcp_host.py)
# ---------------------------------------------------------------------------


def _token(value: str = "secret-token") -> Token:
    return Token(
        value=value,
        expires_at=time.time() + 3600,
        as_issuer="https://as.example",
        scopes=("mcp:tools.write", "mcp:tools"),  # unsorted on purpose
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
    client.invalidate_cached_token = AsyncMock(return_value=None)
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


def _make_session(server_url: str, session_id: str = "sess-1") -> Any:
    from contextlib import AsyncExitStack

    from cognic_agentos.protocol.mcp_transports import MCPSession

    sdk_session = MagicMock()
    sdk_session.call_tool = AsyncMock(return_value={"content": "ok"})
    sdk_session.list_tools = AsyncMock(return_value=[])
    return MCPSession(
        server_url=server_url,
        sdk_session=sdk_session,
        exit_stack=AsyncExitStack(),
        get_session_id=lambda: session_id,
        token_scopes=("mcp:tools",),
        token_client_id="client-a",
    )


@pytest.fixture
def http_transport() -> MagicMock:
    transport = MagicMock()
    transport.open_session = AsyncMock(return_value=_make_session("https://server.example/mcp"))
    transport.send = AsyncMock(return_value={"content": "ok"})
    transport.close_session = AsyncMock(return_value=None)
    return transport


@pytest.fixture
def server_entry(host_module: Any) -> Any:
    return host_module.MCPServerEntry(
        server_id="example.mcp",
        server_url="https://server.example/mcp",
        transport_kind="http",
        manifest_scopes=("mcp:tools",),
        risk_tier="read_only",
        pack_signature_digest="sha256:cafebabe",
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


def _audit_rows(audit_store: MagicMock, event_type: str | None = None) -> list[AuditEvent]:
    rows = [c.args[0] for c in audit_store.append.await_args_list]
    if event_type is None:
        return rows
    return [r for r in rows if r.event_type == event_type]


def _httpx_status_error(status_code: int, www_authenticate: str = "") -> Exception:
    import httpx

    request = httpx.Request("POST", "https://server.example/mcp")
    headers: dict[str, str] = {}
    if www_authenticate:
        headers["WWW-Authenticate"] = www_authenticate
    response = httpx.Response(status_code, request=request, headers=headers)
    return httpx.HTTPStatusError(f"HTTP {status_code}", request=request, response=response)


# ---------------------------------------------------------------------------
# audit.tool_invocation — successful call_tool
# ---------------------------------------------------------------------------


class TestSuccessfulCallEmitsToolInvocationAudit:
    """Every successful ``call_tool`` MUST emit exactly one
    ``audit.tool_invocation`` row carrying the full T11 payload
    schema."""

    async def test_emits_audit_tool_invocation_on_success(
        self,
        host: Any,
        server_entry: Any,
        audit_store: MagicMock,
    ) -> None:
        await host.call_tool(
            server_id=server_entry.server_id,
            tool_name="lookup",
            arguments={"q": "x"},
            request_id="req-42",
            tenant_id="bank-a",
        )
        rows = _audit_rows(audit_store, "audit.tool_invocation")
        assert len(rows) == 1, f"expected exactly 1 audit.tool_invocation row; got {len(rows)}"

    async def test_payload_schema_complete(
        self,
        host: Any,
        server_entry: Any,
        audit_store: MagicMock,
    ) -> None:
        await host.call_tool(
            server_id=server_entry.server_id,
            tool_name="transfer_funds",
            arguments={},
            request_id="req-1",
            tenant_id="bank-a",
        )
        row = _audit_rows(audit_store, "audit.tool_invocation")[0]
        # Top-level fields
        assert row.request_id == "req-1"
        assert row.tenant_id == "bank-a"
        # Payload schema (per plan §T11)
        p = row.payload
        assert p["pack_id"] == server_entry.server_id
        assert p["pack_signature_digest"] == server_entry.pack_signature_digest
        assert p["tool_name"] == "transfer_funds"
        assert p["mcp_session_id"] == "sess-1"
        assert p["as_issuer"] == "https://as.example"
        assert p["resource_indicator"] == "https://server.example/mcp"
        assert p["client_id"] == "client-a"
        assert p["outcome"] == "ok"
        # duration_ms is a non-negative int
        assert isinstance(p["duration_ms"], int)
        assert p["duration_ms"] >= 0

    async def test_scopes_sorted_for_hash_stability(
        self,
        host: Any,
        server_entry: Any,
        audit_store: MagicMock,
    ) -> None:
        """Per plan §T11: ``scopes`` is emitted as a SORTED tuple/list
        so the hash-chain envelope is stable across runs even if the
        token's scope tuple was unsorted."""
        await host.call_tool(
            server_id=server_entry.server_id,
            tool_name="lookup",
            arguments={},
            request_id="req-1",
            tenant_id="t-1",
        )
        row = _audit_rows(audit_store, "audit.tool_invocation")[0]
        # The fixture token has unsorted scopes ("mcp:tools.write",
        # "mcp:tools"); the audit payload MUST emit them sorted
        scopes = row.payload["scopes"]
        assert scopes == sorted(scopes), (
            f"audit.tool_invocation scopes must be sorted for hash stability; got {scopes!r}"
        )

    async def test_audit_payload_never_carries_token_value(
        self,
        host: Any,
        server_entry: Any,
        audit_store: MagicMock,
    ) -> None:
        """Sprint-5 token-free doctrine: the bearer token's ``value``
        bytes MUST NEVER appear in any audit payload field."""
        await host.call_tool(
            server_id=server_entry.server_id,
            tool_name="lookup",
            arguments={},
            request_id="req-1",
            tenant_id="t-1",
        )
        row = _audit_rows(audit_store, "audit.tool_invocation")[0]
        payload_repr = repr(row.payload)
        # The fixture token's value
        assert "secret-token" not in payload_repr, (
            f"token value leaked into audit.tool_invocation payload: {payload_repr}"
        )

    async def test_no_refused_or_error_audit_on_success_path(
        self,
        host: Any,
        server_entry: Any,
        audit_store: MagicMock,
    ) -> None:
        await host.call_tool(
            server_id=server_entry.server_id,
            tool_name="lookup",
            arguments={},
            request_id="req-1",
            tenant_id="t-1",
        )
        assert not _audit_rows(audit_store, "audit.tool_invocation_refused")
        assert not _audit_rows(audit_store, "audit.tool_invocation_error")


# ---------------------------------------------------------------------------
# audit.tool_invocation_refused — ADR-014 path (T10 already wires; T11 verifies)
# ---------------------------------------------------------------------------


class TestAdr014RefusalEmitsToolInvocationRefusedAudit:
    """T10 already emits ``audit.tool_invocation_refused`` for the
    ADR-014 transitional gate. T11 verifies the row schema is
    consistent with the wider invocation-row family — same
    event_type + same top-level fields + payload extension with
    ``declared_risk_tier`` + ``sprint_13_5_followup``."""

    async def test_adr014_refusal_emits_tool_invocation_refused(
        self,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        entry = host_module.MCPServerEntry(
            server_id="pack.high-risk",
            server_url="https://server.example/mcp",
            transport_kind="http",
            manifest_scopes=("mcp:tools",),
            risk_tier="payment_action",
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
        with pytest.raises(host_module.MCPToolInvocationRefused):
            await host.call_tool(
                server_id=entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
        rows = _audit_rows(audit_store, "audit.tool_invocation_refused")
        assert len(rows) == 1
        p = rows[0].payload
        assert p["refusal_reason"] == "tool_approval_engine_not_available"
        assert p["declared_risk_tier"] == "payment_action"
        assert p["sprint_13_5_followup"] is True


# ---------------------------------------------------------------------------
# audit.tool_invocation_refused — pre-dispatch authz refusal
# ---------------------------------------------------------------------------


class TestPreDispatchAuthzRefusalEmitsToolInvocationRefusedAudit:
    """When ``authz.acquire_token`` raises a closed-enum
    :class:`MCPAuthzError` before any session work, the call is
    REFUSED (not ERRORED) — the call never reached the MCP server.
    T11 emits ``audit.tool_invocation_refused`` with the authz
    closed-enum reason."""

    async def test_authz_acquire_token_failure_emits_tool_invocation_refused(
        self,
        host: Any,
        server_entry: Any,
        audit_store: MagicMock,
        authz: MagicMock,
    ) -> None:
        authz.acquire_token.side_effect = MCPAuthzError(
            "mcp_as_not_allowlisted",
            "AS not on tenant allow-list",
            server_url=server_entry.server_url,
        )
        with pytest.raises(MCPAuthzError):
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
        rows = _audit_rows(audit_store, "audit.tool_invocation_refused")
        assert len(rows) == 1
        assert rows[0].payload["refusal_reason"] == "mcp_as_not_allowlisted"
        # No tool_invocation_error row (refused != errored)
        assert not _audit_rows(audit_store, "audit.tool_invocation_error")


# ---------------------------------------------------------------------------
# audit.tool_invocation_refused — 403 step_up_unauthorised path
# ---------------------------------------------------------------------------


class TestStepUpUnauthorisedEmitsToolInvocationRefusedAudit:
    """403 insufficient_scope where the manifest does NOT declare
    the wider scope → ``authz.step_up_token`` raises
    ``mcp_step_up_unauthorised``. Per plan §T11 the call is
    REFUSED (the orchestrator never re-issued the request with a
    new token)."""

    async def test_step_up_unauthorised_emits_tool_invocation_refused(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        send_err = MCPTransportError(
            "mcp_transport_send_failed",
            "403",
            server_url=server_entry.server_url,
        )
        send_err.__cause__ = _httpx_status_error(
            403, 'Bearer error="insufficient_scope", scope="mcp:secret"'
        )
        http_transport.send.side_effect = [send_err]
        authz.step_up_token = AsyncMock(
            side_effect=MCPAuthzError(
                "mcp_step_up_unauthorised",
                "manifest does not declare mcp:secret",
                server_url=server_entry.server_url,
            )
        )
        with pytest.raises(MCPAuthzError):
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
        rows = _audit_rows(audit_store, "audit.tool_invocation_refused")
        assert len(rows) == 1
        assert rows[0].payload["refusal_reason"] == "mcp_step_up_unauthorised"


# ---------------------------------------------------------------------------
# audit.tool_invocation_error — transport timeout / send failure
# ---------------------------------------------------------------------------


class TestTransportErrorEmitsToolInvocationErrorAudit:
    """Call DISPATCHED but FAILED — transport timeout / send failure
    / malformed response. The call reached the MCP server, so it's
    ERRORED not REFUSED."""

    async def test_transport_timeout_emits_tool_invocation_error(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        http_transport.send.side_effect = MCPTransportError(
            "mcp_call_tool_timeout",
            "timeout",
            server_url=server_entry.server_url,
            timeout_s=13,
        )
        with pytest.raises(MCPTransportError):
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
        rows = _audit_rows(audit_store, "audit.tool_invocation_error")
        assert len(rows) == 1
        assert rows[0].payload["error_taxonomy"] == "mcp_call_tool_timeout"
        # No refused-class audit row
        assert not _audit_rows(audit_store, "audit.tool_invocation_refused")

    async def test_transport_send_failed_emits_tool_invocation_error(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        http_transport.send.side_effect = MCPTransportError(
            "mcp_transport_send_failed",
            "boom",
            server_url=server_entry.server_url,
            error_type="ConnectionError",
        )
        with pytest.raises(MCPTransportError):
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
        rows = _audit_rows(audit_store, "audit.tool_invocation_error")
        assert len(rows) == 1
        assert rows[0].payload["error_taxonomy"] == "mcp_transport_send_failed"


# ---------------------------------------------------------------------------
# audit.tool_invocation_error — mcp_authorisation_lost (second-401 retry)
# ---------------------------------------------------------------------------


class TestAuthorisationLostEmitsToolInvocationErrorAudit:
    """Second-401 retry exhaustion → MCPAuthzError(mcp_authorisation_lost).
    The call DID reach the server (twice), so this is ERRORED not
    REFUSED."""

    async def test_second_401_emits_tool_invocation_error(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        e1 = MCPTransportError(
            "mcp_transport_send_failed",
            "401a",
            server_url=server_entry.server_url,
        )
        e1.__cause__ = _httpx_status_error(401)
        e2 = MCPTransportError(
            "mcp_transport_send_failed",
            "401b",
            server_url=server_entry.server_url,
        )
        e2.__cause__ = _httpx_status_error(401)
        http_transport.send.side_effect = [e1, e2]

        with pytest.raises(MCPAuthzError) as exc:
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
        assert exc.value.reason == "mcp_authorisation_lost"
        rows = _audit_rows(audit_store, "audit.tool_invocation_error")
        assert len(rows) == 1
        assert rows[0].payload["error_taxonomy"] == "mcp_authorisation_lost"


# ---------------------------------------------------------------------------
# Correlation by request_id + audit-emit failure tolerance
# ---------------------------------------------------------------------------


class TestAuditEmissionFailureTolerance:
    """Per T9/T10 doctrine: audit-pipeline failure does NOT mask
    the primary outcome. The caller still receives the result /
    error / refusal even if the audit row couldn't be persisted."""

    async def test_audit_failure_on_success_path_does_not_mask_result(
        self,
        host: Any,
        server_entry: Any,
        audit_store: MagicMock,
    ) -> None:
        audit_store.append.side_effect = RuntimeError("audit chain DB unreachable")
        # Call still succeeds — result reaches caller despite audit failure
        result = await host.call_tool(
            server_id=server_entry.server_id,
            tool_name="lookup",
            arguments={},
            request_id="req-1",
            tenant_id="t-1",
        )
        assert result.payload == {"content": "ok"}

    async def test_audit_failure_on_error_path_does_not_mask_error(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        http_transport.send.side_effect = MCPTransportError(
            "mcp_call_tool_timeout",
            "timeout",
            server_url=server_entry.server_url,
        )
        audit_store.append.side_effect = RuntimeError("audit down")
        # Caller sees the original transport error
        with pytest.raises(MCPTransportError) as exc:
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
        assert exc.value.reason == "mcp_call_tool_timeout"


class TestRequestIdCorrelation:
    """Every call_tool produces exactly 1 invocation-class audit row
    (one of the 3 event types) carrying the request_id top-level
    field. The decision-history side is pinned in
    :mod:`tests.unit.protocol.test_mcp_decision_history_linkage`."""

    async def test_success_audit_row_carries_request_id(
        self,
        host: Any,
        server_entry: Any,
        audit_store: MagicMock,
    ) -> None:
        await host.call_tool(
            server_id=server_entry.server_id,
            tool_name="lookup",
            arguments={},
            request_id="unique-req-id-42",
            tenant_id="t-1",
        )
        invocation_rows = (
            _audit_rows(audit_store, "audit.tool_invocation")
            + _audit_rows(audit_store, "audit.tool_invocation_refused")
            + _audit_rows(audit_store, "audit.tool_invocation_error")
        )
        # Exactly 1 invocation-class row
        assert len(invocation_rows) == 1
        assert invocation_rows[0].request_id == "unique-req-id-42"


# ---------------------------------------------------------------------------
# R1 P1 — dispatched-error rows MUST carry session + auth context
# ---------------------------------------------------------------------------


class TestDispatchedErrorRowsCarrySessionAndAuthContext:
    """When ``transport.send()`` raises after ``open_session()``
    succeeded, the call HAS been dispatched (a bearer token reached
    the MCP server). The audit + decision rows for that error MUST
    carry the correlation context — ``mcp_session_id``, ``as_issuer``,
    ``scopes``, ``resource_indicator``, ``client_id`` — so examiners
    replaying the call from ``decision_history`` can see what auth
    context the server actually saw.

    Without this, ``audit.tool_invocation_error`` rows for timeouts /
    send failures / mcp_authorisation_lost report
    ``mcp_session_id=None`` + ``as_issuer=None`` etc. — which lies
    about whether the call reached the server.
    """

    async def test_transport_timeout_audit_row_carries_session_id(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        http_transport.send.side_effect = MCPTransportError(
            "mcp_call_tool_timeout",
            "timeout",
            server_url=server_entry.server_url,
        )
        with pytest.raises(MCPTransportError):
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
        row = _audit_rows(audit_store, "audit.tool_invocation_error")[0]
        p = row.payload
        # Dispatch context — the call DID reach the server with a
        # bearer token; the audit row MUST record that
        assert p["mcp_session_id"] == "sess-1", (
            f"timeout audit row missing mcp_session_id (call WAS "
            f"dispatched with a bearer token); payload={p!r}"
        )
        assert p["as_issuer"] == "https://as.example"
        assert p["client_id"] == "client-a"
        assert p["resource_indicator"] == "https://server.example/mcp"
        assert p["scopes"] == sorted(["mcp:tools.write", "mcp:tools"])

    async def test_transport_send_failure_audit_row_carries_session_id(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        http_transport.send.side_effect = MCPTransportError(
            "mcp_transport_send_failed",
            "boom",
            server_url=server_entry.server_url,
            error_type="ConnectionError",
        )
        with pytest.raises(MCPTransportError):
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
        row = _audit_rows(audit_store, "audit.tool_invocation_error")[0]
        p = row.payload
        assert p["mcp_session_id"] == "sess-1"
        assert p["as_issuer"] == "https://as.example"
        assert p["client_id"] == "client-a"

    async def test_authorisation_lost_audit_row_carries_session_id(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        """Second-401 retry exhaustion → mcp_authorisation_lost. Both
        sends reached the server. The audit row MUST carry session
        context (the second send's session_id, since that's the
        dispatch attempt the error correlates to)."""
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        e1 = MCPTransportError(
            "mcp_transport_send_failed",
            "401a",
            server_url=server_entry.server_url,
        )
        e1.__cause__ = _httpx_status_error(401)
        e2 = MCPTransportError(
            "mcp_transport_send_failed",
            "401b",
            server_url=server_entry.server_url,
        )
        e2.__cause__ = _httpx_status_error(401)
        http_transport.send.side_effect = [e1, e2]
        with pytest.raises(MCPAuthzError):
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
        row = _audit_rows(audit_store, "audit.tool_invocation_error")[0]
        p = row.payload
        assert p["mcp_session_id"] is not None, (
            f"mcp_authorisation_lost audit row MUST carry session_id "
            f"(call reached the server twice); payload={p!r}"
        )
        assert p["as_issuer"] == "https://as.example"
        assert p["client_id"] == "client-a"

    async def test_step_up_unauthorised_refusal_row_carries_first_send_session(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        """403-step-up-unauthorised: the first send DID reach the
        server (with the original token). The refusal row MUST
        carry that dispatch context."""
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        send_err = MCPTransportError(
            "mcp_transport_send_failed",
            "403",
            server_url=server_entry.server_url,
        )
        send_err.__cause__ = _httpx_status_error(
            403, 'Bearer error="insufficient_scope", scope="mcp:secret"'
        )
        http_transport.send.side_effect = [send_err]
        authz.step_up_token = AsyncMock(
            side_effect=MCPAuthzError(
                "mcp_step_up_unauthorised",
                "manifest does not declare mcp:secret",
                server_url=server_entry.server_url,
            )
        )
        with pytest.raises(MCPAuthzError):
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
        row = _audit_rows(audit_store, "audit.tool_invocation_refused")[0]
        p = row.payload
        assert p["mcp_session_id"] == "sess-1", (
            f"step_up_unauthorised refusal row MUST carry the first "
            f"send's session_id; payload={p!r}"
        )
        assert p["as_issuer"] == "https://as.example"
        assert p["client_id"] == "client-a"


class TestPreDispatchRefusalRowsCarryNoneSessionContext:
    """Symmetric contract: refusal rows for paths that did NOT reach
    the server (ADR-014 gate, pre-dispatch acquire_token failure)
    MUST report ``mcp_session_id=None``. Operators rely on this
    distinction to triage "did the server see the call?"."""

    async def test_adr014_refusal_row_has_none_session_id(
        self,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        entry = host_module.MCPServerEntry(
            server_id="pack.high-risk",
            server_url="https://server.example/mcp",
            transport_kind="http",
            manifest_scopes=("mcp:tools",),
            risk_tier="payment_action",
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
        with pytest.raises(host_module.MCPToolInvocationRefused):
            await host.call_tool(
                server_id=entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
        row = _audit_rows(audit_store, "audit.tool_invocation_refused")[0]
        assert row.payload["mcp_session_id"] is None
        assert row.payload["as_issuer"] is None

    async def test_acquire_token_failure_row_has_none_session_id(
        self,
        host: Any,
        server_entry: Any,
        authz: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        authz.acquire_token.side_effect = MCPAuthzError(
            "mcp_anonymous_refused",
            "no PRM advertised",
            server_url=server_entry.server_url,
        )
        with pytest.raises(MCPAuthzError):
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
        row = _audit_rows(audit_store, "audit.tool_invocation_refused")[0]
        assert row.payload["mcp_session_id"] is None
        assert row.payload["as_issuer"] is None
        assert row.payload["client_id"] is None


# ---------------------------------------------------------------------------
# R1 P2 — post-dispatch reacquire failure MUST be ERRORED not REFUSED
# ---------------------------------------------------------------------------


class TestPostDispatchReacquireFailureClassifiesAsErrored:
    """First send raises 401 → orchestrator invalidates cache + calls
    ``acquire_token`` again. If that SECOND acquire raises (e.g.
    ``mcp_oauth_request_timeout`` because the AS is now slow, or
    ``mcp_oauth_credentials_missing`` because Vault rotated), the
    call already reached the server once with a bearer token — the
    correct evidence class is ERRORED, not REFUSED."""

    async def test_reacquire_timeout_after_first_401_emits_errored(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        e1 = MCPTransportError(
            "mcp_transport_send_failed",
            "401",
            server_url=server_entry.server_url,
        )
        e1.__cause__ = _httpx_status_error(401)
        http_transport.send.side_effect = [e1]
        # Reacquire fails — NOT mcp_authorisation_lost
        first_token = _token()
        authz.acquire_token.side_effect = [
            first_token,
            MCPAuthzError(
                "mcp_oauth_request_timeout",
                "AS slow",
                server_url=server_entry.server_url,
            ),
        ]
        with pytest.raises(MCPAuthzError) as exc:
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
        assert exc.value.reason == "mcp_oauth_request_timeout"
        # MUST be classified as errored, not refused
        error_rows = _audit_rows(audit_store, "audit.tool_invocation_error")
        refused_rows = _audit_rows(audit_store, "audit.tool_invocation_refused")
        assert len(error_rows) == 1, (
            f"post-dispatch reacquire failure MUST emit "
            f"audit.tool_invocation_error; got error_rows={len(error_rows)} "
            f"refused_rows={len(refused_rows)}"
        )
        assert not refused_rows
        # Carries dispatch context from the first send
        assert error_rows[0].payload["mcp_session_id"] is not None
        assert error_rows[0].payload["error_taxonomy"] == "mcp_oauth_request_timeout"

    async def test_reacquire_credentials_missing_after_first_401_emits_errored(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        e1 = MCPTransportError(
            "mcp_transport_send_failed",
            "401",
            server_url=server_entry.server_url,
        )
        e1.__cause__ = _httpx_status_error(401)
        http_transport.send.side_effect = [e1]
        first_token = _token()
        authz.acquire_token.side_effect = [
            first_token,
            MCPAuthzError(
                "mcp_oauth_credentials_missing",
                "Vault rotated",
                server_url=server_entry.server_url,
            ),
        ]
        with pytest.raises(MCPAuthzError) as exc:
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
        assert exc.value.reason == "mcp_oauth_credentials_missing"
        error_rows = _audit_rows(audit_store, "audit.tool_invocation_error")
        assert len(error_rows) == 1
        assert error_rows[0].payload["error_taxonomy"] == "mcp_oauth_credentials_missing"


# ---------------------------------------------------------------------------
# R2 P2 — dispatched context MUST be separate from candidate retry token
# ---------------------------------------------------------------------------


class TestDispatchedContextSeparateFromCandidateRetryToken:
    """When the retry path opens a session with a freshly reacquired
    or stepped-up token, that token has NOT yet reached the server.
    If the retry's ``open_session`` raises (e.g. server unreachable
    by then), the error-evidence row MUST report the FIRST dispatch's
    session + token (what the server actually saw) — NOT the
    candidate retry token (which never reached the server).

    Without this fix, the audit / decision row falsely reports the
    wider scopes / fresh credentials against the first session_id —
    wrong for the step-up case especially, where evidence would
    suggest the wider scope was sent on the original session even
    though only the under-scoped first send happened.
    """

    async def test_retry_open_failure_after_first_401_uses_first_dispatch_context(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        """First send: dispatched with T1 → 401. Reacquire → T2.
        Retry's ``open_session`` raises ``mcp_session_open_timeout``
        BEFORE T2 is sent. Audit row MUST report the first
        dispatch's correlation context (T1's scopes / client_id /
        as_issuer) — NOT T2's (which never reached the server)."""
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        # First send: 401
        e1 = MCPTransportError(
            "mcp_transport_send_failed",
            "401",
            server_url=server_entry.server_url,
        )
        e1.__cause__ = _httpx_status_error(401)
        http_transport.send.side_effect = [e1]
        # Retry's open_session raises (no second send happens)
        first_session = _make_session("https://server.example/mcp", session_id="sess-FIRST")
        retry_open_error = MCPTransportError(
            "mcp_session_open_timeout",
            "server unreachable",
            server_url=server_entry.server_url,
            timeout_s=7,
        )
        http_transport.open_session.side_effect = [
            first_session,
            retry_open_error,
        ]

        # Two distinct tokens — first dispatched, second never sent
        first_token = Token(
            value="first",
            expires_at=time.time() + 3600,
            as_issuer="https://as.example",
            scopes=("mcp:tools",),
            resource_indicator="https://server.example/mcp",
            client_id="client-FIRST",
        )
        second_token = Token(
            value="second-never-sent",
            expires_at=time.time() + 3600,
            as_issuer="https://as.example",
            scopes=("mcp:tools",),
            resource_indicator="https://server.example/mcp",
            client_id="client-SECOND-NEVER-SENT",
        )
        authz.acquire_token.side_effect = [first_token, second_token]

        with pytest.raises(MCPTransportError):
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="r1",
                tenant_id="t-1",
            )
        rows = _audit_rows(audit_store, "audit.tool_invocation_error")
        assert len(rows) == 1
        p = rows[0].payload
        # MUST report the FIRST dispatch's context — NOT the retry
        # token's. T2 (second_token) never reached the server.
        assert p["client_id"] == "client-FIRST", (
            f"audit row reports retry-candidate token's client_id "
            f"{p['client_id']!r} instead of the first dispatch's "
            f"client_id; payload={p!r}"
        )
        assert p["mcp_session_id"] == "sess-FIRST"
        # Confirm: NOT the never-sent token's identity
        assert "client-SECOND-NEVER-SENT" not in str(p)
        assert "second-never-sent" not in str(p)

    async def test_retry_open_failure_after_step_up_uses_first_dispatch_context(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        """First send: dispatched with under-scoped T1 → 403
        insufficient_scope. ``step_up_token`` returns wider-scope
        T2. Retry's ``open_session`` raises BEFORE T2 is sent. The
        evidence MUST report T1's NARROWER scopes for the original
        session_id — NOT T2's wider scopes (which never reached
        the server).

        This is the high-risk case the reviewer flagged: leaking
        T2's wider scopes into the audit row would falsely suggest
        the server accepted / saw the wider scope set."""
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        send_err = MCPTransportError(
            "mcp_transport_send_failed",
            "403",
            server_url=server_entry.server_url,
        )
        send_err.__cause__ = _httpx_status_error(
            403, 'Bearer error="insufficient_scope", scope="mcp:tools.write"'
        )
        http_transport.send.side_effect = [send_err]

        first_session = _make_session("https://server.example/mcp", session_id="sess-NARROW")
        retry_open_error = MCPTransportError(
            "mcp_session_open_timeout",
            "server unreachable",
            server_url=server_entry.server_url,
        )
        http_transport.open_session.side_effect = [
            first_session,
            retry_open_error,
        ]

        narrow_token = Token(
            value="narrow",
            expires_at=time.time() + 3600,
            as_issuer="https://as.example",
            scopes=("mcp:tools",),  # NARROW
            resource_indicator="https://server.example/mcp",
            client_id="client-narrow",
        )
        wide_token_never_sent = Token(
            value="wide-never-sent",
            expires_at=time.time() + 3600,
            as_issuer="https://as.example",
            scopes=("mcp:tools", "mcp:tools.write"),  # WIDE
            resource_indicator="https://server.example/mcp",
            client_id="client-wide-never-sent",
        )
        authz.acquire_token.side_effect = [narrow_token]
        authz.step_up_token = AsyncMock(return_value=wide_token_never_sent)

        with pytest.raises(MCPTransportError):
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="r1",
                tenant_id="t-1",
            )
        rows = _audit_rows(audit_store, "audit.tool_invocation_error")
        assert len(rows) == 1
        p = rows[0].payload
        # The audit row MUST show the NARROW scopes (what the
        # server actually saw on sess-NARROW), NOT the wider ones
        # from the never-sent step-up token.
        assert p["scopes"] == sorted(["mcp:tools"]), (
            f"audit row leaked wider step-up scopes onto the first "
            f"session's row; scopes={p['scopes']!r} payload={p!r}"
        )
        assert p["mcp_session_id"] == "sess-NARROW"
        assert p["client_id"] == "client-narrow"
        # Confirm: never the wider/never-sent token
        assert "mcp:tools.write" not in str(p["scopes"])
        assert "client-wide-never-sent" not in str(p)


# ---------------------------------------------------------------------------
# R3 P2 — generic Exception from open_session MUST still emit T11 evidence
# ---------------------------------------------------------------------------


class TestGenericOpenSessionExceptionEmitsToolInvocationError:
    """T7's :meth:`StreamableHTTPTransport.open_session` re-raises
    generic ``Exception`` (not just ``MCPTransportError``) from the
    session_open audit hook failure path — its R2 P2 #1 fix closes
    the AsyncExitStack but lets the original exception propagate.
    Without an explicit ``except Exception`` in :meth:`call_tool`,
    those errors would bypass T11 evidence emission entirely (no
    ``audit.tool_invocation_error`` row, no ``mcp_call`` decision
    row), violating the plan's "every request_id produces 1 audit
    row + 1 decision row" invariant.

    Contract: catch non-cancellation ``Exception`` after the
    typed handlers; emit token-free invocation-error evidence with
    a sanitised ``error_type`` (NEVER ``str(exc)`` — could carry
    server-side debug strings or token bytes); re-raise.
    ``BaseException`` (incl. ``CancelledError``) intentionally
    NOT caught — task teardown propagates.
    """

    async def test_generic_open_session_runtime_error_emits_invocation_error(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        """``open_session`` raises a bare ``RuntimeError`` (e.g.
        from a buggy session_open audit hook). MUST emit
        ``audit.tool_invocation_error`` and propagate."""
        secret_in_msg = "Bearer eyJ.LEAKED-TOKEN.sig"
        http_transport.open_session.side_effect = RuntimeError(
            f"audit hook crashed: {secret_in_msg}"
        )
        with pytest.raises(RuntimeError):
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
        rows = _audit_rows(audit_store, "audit.tool_invocation_error")
        assert len(rows) == 1, (
            f"generic open_session Exception MUST emit "
            f"audit.tool_invocation_error; got {len(rows)} rows"
        )
        p = rows[0].payload
        # R4 P2: closed-enum vocabulary doctrine. ``error_taxonomy``
        # MUST be a reviewed closed value (NOT the Python class
        # name); the sanitised class name lives in a separate
        # ``error_type`` field for operator debugging.
        assert p["error_taxonomy"] == "mcp_orchestrator_error"
        assert p["error_type"] == "RuntimeError"
        # Class name MUST NOT bleed into the closed-enum field —
        # operators querying audit_event WHERE error_taxonomy = ?
        # rely on the closed vocabulary
        assert p["error_taxonomy"] != "RuntimeError"
        # Token-free: the exception's secret-bearing message MUST
        # NOT appear anywhere in the payload
        for marker in (secret_in_msg, "LEAKED-TOKEN", "Bearer eyJ"):
            assert marker not in str(p), (
                f"open_session exception message text leaked into "
                f"payload: marker={marker!r} payload={p!r}"
            )
        # Pre-dispatch open_session failure: no session was ever
        # opened; dispatched_* stays None
        assert p["mcp_session_id"] is None

    async def test_generic_open_session_exception_propagates_unchanged(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
    ) -> None:
        """The original generic exception MUST propagate to the
        caller unchanged — evidence emission is a side effect, not
        a transformer."""

        class _BuggyHookError(RuntimeError):
            pass

        original = _BuggyHookError("audit hook misconfigured")
        http_transport.open_session.side_effect = original
        with pytest.raises(_BuggyHookError) as exc_info:
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
        assert exc_info.value is original

    async def test_generic_exception_does_not_propagate_through_typed_handlers(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        """The generic-Exception handler MUST be the LAST one — a
        ``RuntimeError`` should not accidentally route through
        ``MCPAuthzError`` or ``MCPTransportError`` paths (which
        would mis-classify it)."""

        http_transport.open_session.side_effect = RuntimeError("not a transport error")
        with pytest.raises(RuntimeError):
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
        rows = _audit_rows(audit_store, "audit.tool_invocation_error")
        assert len(rows) == 1
        # R4 P2: closed-enum reason MUST NOT be a transport-class
        # reason (reserved for MCPTransportError instances) — and
        # MUST NOT be a Python class name. The closed reason for
        # the generic-Exception path is ``mcp_orchestrator_error``;
        # the actual class name lives in ``error_type``.
        p = rows[0].payload
        assert p["error_taxonomy"] == "mcp_orchestrator_error"
        assert p["error_type"] == "RuntimeError"
        # Sanity: closed-enum reason field is NOT the class name
        assert p["error_taxonomy"] != "RuntimeError"

    async def test_cancellation_during_open_session_propagates_uncaught(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
    ) -> None:
        """``CancelledError`` (a ``BaseException`` subclass) MUST
        NOT be caught by the generic handler — task teardown must
        propagate. The orchestrator does not emit evidence for
        cancellation."""
        http_transport.open_session.side_effect = asyncio.CancelledError()
        with pytest.raises(asyncio.CancelledError):
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
