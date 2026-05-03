"""Sprint-5 T11 — decision_history linkage for MCP call_tool outcomes.

Critical-controls module per AGENTS.md. Companion to
:mod:`tests.unit.protocol.test_mcp_audit_linkage` — both files pin
the parallel evidence-emission contracts established by R1 P2 #6
(separating ``AuditStore`` chain from ``DecisionHistoryStore`` rows).

Per MCP-CONFORMANCE.md §"Authorization" item 9:

    Every MCP call records ``client_id`` + scopes used + AS issuer +
    resource indicator in ``decision_history``.

Decision-history rows for MCP call_tool (per plan §T11):

  - **mcp_call** decision row — written on every call_tool outcome
    (ok / refused / errored). Schema: ``request_id``,
    ``mcp_session_id``, ``pack_id``, ``tool_name``, ``decision`` ∈
    {``invoked``, ``refused``, ``errored``}, ``decision_reason``
    (closed-enum or ``null`` for ok), ``as_issuer``, ``scopes``,
    ``resource_indicator``, ``client_id``, ``tenant_id``,
    ``declared_risk_tier``.

  - **mcp_token_refresh** decision row — already wired in T5
    (mcp_authz). Verified here as a sanity check.

The parallel surface to the audit chain is queryable by
``request_id`` / ``mcp_session_id`` for examiner replay; the
chain is queryable by hash sequence for tamper-evidence. T11 writes
to BOTH for every MCP call outcome, correlated by request_id.
"""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.protocol.mcp_authz import MCPAuthzClient, MCPAuthzError, Token

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _token(value: str = "secret-token") -> Token:
    return Token(
        value=value,
        expires_at=time.time() + 3600,
        as_issuer="https://as.example",
        scopes=("mcp:tools.write", "mcp:tools"),
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


def _make_session(server_url: str, session_id: str = "sess-7") -> Any:
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


def _decision_rows(
    decision_history_store: MagicMock, decision_type: str | None = None
) -> list[DecisionRecord]:
    rows = [c.args[0] for c in decision_history_store.append.await_args_list]
    if decision_type is None:
        return rows
    return [r for r in rows if r.decision_type == decision_type]


def _httpx_status_error(status_code: int, www_authenticate: str = "") -> Exception:
    import httpx

    request = httpx.Request("POST", "https://server.example/mcp")
    headers: dict[str, str] = {}
    if www_authenticate:
        headers["WWW-Authenticate"] = www_authenticate
    response = httpx.Response(status_code, request=request, headers=headers)
    return httpx.HTTPStatusError(f"HTTP {status_code}", request=request, response=response)


# ---------------------------------------------------------------------------
# Successful call → decision="invoked"
# ---------------------------------------------------------------------------


class TestSuccessfulCallEmitsInvokedDecisionRow:
    async def test_emits_one_mcp_call_decision_row_on_success(
        self,
        host: Any,
        server_entry: Any,
        decision_history_store: MagicMock,
    ) -> None:
        await host.call_tool(
            server_id=server_entry.server_id,
            tool_name="lookup",
            arguments={},
            request_id="req-1",
            tenant_id="bank-a",
        )
        rows = _decision_rows(decision_history_store, "mcp_call")
        assert len(rows) == 1, f"expected exactly 1 mcp_call decision row; got {len(rows)}"

    async def test_decision_invoked_with_no_reason_on_success(
        self,
        host: Any,
        server_entry: Any,
        decision_history_store: MagicMock,
    ) -> None:
        await host.call_tool(
            server_id=server_entry.server_id,
            tool_name="transfer_funds",
            arguments={},
            request_id="req-1",
            tenant_id="bank-a",
        )
        row = _decision_rows(decision_history_store, "mcp_call")[0]
        p = row.payload
        assert p["decision"] == "invoked"
        # decision_reason is null (None / absent) on the success path
        assert p.get("decision_reason") in (None, "")

    async def test_payload_carries_full_correlation_context(
        self,
        host: Any,
        server_entry: Any,
        decision_history_store: MagicMock,
    ) -> None:
        """Per MCP-CONFORMANCE §observability item 9: the
        decision_history row carries client_id + scopes + AS issuer
        + resource indicator (so examiners can replay the auth
        context for any MCP call)."""
        await host.call_tool(
            server_id=server_entry.server_id,
            tool_name="lookup",
            arguments={},
            request_id="req-1",
            tenant_id="bank-a",
        )
        row = _decision_rows(decision_history_store, "mcp_call")[0]
        # Top-level fields
        assert row.request_id == "req-1"
        assert row.tenant_id == "bank-a"
        # Payload schema
        p = row.payload
        assert p["pack_id"] == server_entry.server_id
        assert p["tool_name"] == "lookup"
        assert p["mcp_session_id"] == "sess-7"
        assert p["as_issuer"] == "https://as.example"
        assert p["resource_indicator"] == "https://server.example/mcp"
        assert p["client_id"] == "client-a"
        assert p["declared_risk_tier"] == "read_only"

    async def test_decision_payload_never_carries_token_value(
        self,
        host: Any,
        server_entry: Any,
        decision_history_store: MagicMock,
    ) -> None:
        await host.call_tool(
            server_id=server_entry.server_id,
            tool_name="lookup",
            arguments={},
            request_id="req-1",
            tenant_id="t-1",
        )
        row = _decision_rows(decision_history_store, "mcp_call")[0]
        assert "secret-token" not in repr(row.payload)


# ---------------------------------------------------------------------------
# ADR-014 refusal → decision="refused"
# ---------------------------------------------------------------------------


class TestAdr014RefusalEmitsRefusedDecisionRow:
    async def test_high_risk_tier_emits_refused_decision_row(
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
        rows = _decision_rows(decision_history_store, "mcp_call")
        assert len(rows) == 1
        p = rows[0].payload
        assert p["decision"] == "refused"
        assert p["decision_reason"] == "tool_approval_engine_not_available"
        assert p["declared_risk_tier"] == "payment_action"


# ---------------------------------------------------------------------------
# Pre-dispatch authz refusal → decision="refused"
# ---------------------------------------------------------------------------


class TestAuthzRefusalEmitsRefusedDecisionRow:
    async def test_authz_acquire_token_failure_emits_refused_decision(
        self,
        host: Any,
        server_entry: Any,
        authz: MagicMock,
        decision_history_store: MagicMock,
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
        rows = _decision_rows(decision_history_store, "mcp_call")
        assert len(rows) == 1
        assert rows[0].payload["decision"] == "refused"
        assert rows[0].payload["decision_reason"] == "mcp_anonymous_refused"

    async def test_step_up_unauthorised_emits_refused_decision(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        decision_history_store: MagicMock,
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
        rows = _decision_rows(decision_history_store, "mcp_call")
        assert len(rows) == 1
        assert rows[0].payload["decision"] == "refused"
        assert rows[0].payload["decision_reason"] == "mcp_step_up_unauthorised"


# ---------------------------------------------------------------------------
# Transport error → decision="errored"
# ---------------------------------------------------------------------------


class TestTransportErrorEmitsErroredDecisionRow:
    async def test_transport_timeout_emits_errored_decision(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        decision_history_store: MagicMock,
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
        rows = _decision_rows(decision_history_store, "mcp_call")
        assert len(rows) == 1
        assert rows[0].payload["decision"] == "errored"
        assert rows[0].payload["decision_reason"] == "mcp_call_tool_timeout"

    async def test_authorisation_lost_emits_errored_decision(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        decision_history_store: MagicMock,
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
        rows = _decision_rows(decision_history_store, "mcp_call")
        assert len(rows) == 1
        assert rows[0].payload["decision"] == "errored"
        assert rows[0].payload["decision_reason"] == "mcp_authorisation_lost"


# ---------------------------------------------------------------------------
# Decision-emit failure tolerance + correlation
# ---------------------------------------------------------------------------


class TestDecisionEmissionFailureTolerance:
    """Per the audit-pipeline-failure doctrine: decision-history
    pipeline failure does NOT mask the primary outcome — the
    caller sees the result/error regardless."""

    async def test_decision_failure_on_success_path_does_not_mask_result(
        self,
        host: Any,
        server_entry: Any,
        decision_history_store: MagicMock,
    ) -> None:
        decision_history_store.append.side_effect = RuntimeError("dh chain down")
        result = await host.call_tool(
            server_id=server_entry.server_id,
            tool_name="lookup",
            arguments={},
            request_id="req-1",
            tenant_id="t-1",
        )
        assert result.payload == {"content": "ok"}

    async def test_decision_failure_on_refusal_path_does_not_mask_refusal(
        self,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        decision_history_store.append.side_effect = RuntimeError("dh down")
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
        with pytest.raises(host_module.MCPToolInvocationRefused) as exc:
            await host.call_tool(
                server_id=entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
        # Refusal still propagates
        assert exc.value.reason == "tool_approval_engine_not_available"


class TestRequestIdCorrelation:
    async def test_decision_row_carries_request_id_for_examiner_replay(
        self,
        host: Any,
        server_entry: Any,
        decision_history_store: MagicMock,
    ) -> None:
        """Per MCP-CONFORMANCE §observability: examiners query
        ``decision_history WHERE request_id = ?`` to replay an MCP
        call. The mcp_call row MUST carry the request_id in the
        top-level field."""
        await host.call_tool(
            server_id=server_entry.server_id,
            tool_name="lookup",
            arguments={},
            request_id="examiner-replay-target",
            tenant_id="t-1",
        )
        row = _decision_rows(decision_history_store, "mcp_call")[0]
        assert row.request_id == "examiner-replay-target"


# ---------------------------------------------------------------------------
# R2 P3 #1 — decision-history rows MUST also carry dispatch context
# ---------------------------------------------------------------------------


class TestDecisionHistoryDispatchContextOnErrorPaths:
    """R1 P1's audit-side fixes are mirrored here on the
    decision_history surface — ``decision_history`` is the
    examiner-replay surface; T11's contract says BOTH surfaces
    carry the dispatch correlation context for dispatched
    failures. Without these mirrored assertions, a future helper
    split could silently regress the decision side while audit
    assertions still pass."""

    async def test_transport_timeout_decision_row_carries_dispatch_context(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        decision_history_store: MagicMock,
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
        row = _decision_rows(decision_history_store, "mcp_call")[0]
        p = row.payload
        assert p["decision"] == "errored"
        assert p["mcp_session_id"] == "sess-7"
        assert p["as_issuer"] == "https://as.example"
        assert p["client_id"] == "client-a"
        assert p["resource_indicator"] == "https://server.example/mcp"

    async def test_transport_send_failure_decision_row_carries_dispatch_context(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        decision_history_store: MagicMock,
    ) -> None:
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        http_transport.send.side_effect = MCPTransportError(
            "mcp_transport_send_failed",
            "boom",
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
        row = _decision_rows(decision_history_store, "mcp_call")[0]
        p = row.payload
        assert p["decision"] == "errored"
        assert p["mcp_session_id"] == "sess-7"
        assert p["as_issuer"] == "https://as.example"
        assert p["client_id"] == "client-a"

    async def test_authorisation_lost_decision_row_carries_dispatch_context(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        decision_history_store: MagicMock,
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
        with pytest.raises(MCPAuthzError):
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
        row = _decision_rows(decision_history_store, "mcp_call")[0]
        p = row.payload
        assert p["decision"] == "errored"
        assert p["decision_reason"] == "mcp_authorisation_lost"
        assert p["mcp_session_id"] is not None
        assert p["as_issuer"] == "https://as.example"
        assert p["client_id"] == "client-a"

    async def test_step_up_unauthorised_decision_row_carries_first_dispatch_context(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        decision_history_store: MagicMock,
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
        row = _decision_rows(decision_history_store, "mcp_call")[0]
        p = row.payload
        # step_up_unauthorised stays REFUSED but with first
        # dispatch's context — under-scoped token, sess-7
        assert p["decision"] == "refused"
        assert p["decision_reason"] == "mcp_step_up_unauthorised"
        assert p["mcp_session_id"] == "sess-7"
        assert p["as_issuer"] == "https://as.example"
        assert p["client_id"] == "client-a"
        # T11 R2 P2: the wider step-up scope MUST NOT appear in
        # the decision row (it was never sent)
        assert "mcp:secret" not in str(p["scopes"])


class TestDecisionHistoryPostDispatchReacquireFailureClassification:
    """R1 P2's audit-side classification (post-dispatch reacquire
    failure → errored) mirrored on the decision_history side.
    Examiners query mcp_call rows by ``decision`` to triage 'did
    this call ever reach the server' — wrong classification here
    misleads triage."""

    async def test_reacquire_timeout_after_first_401_decision_is_errored(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        decision_history_store: MagicMock,
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
                "mcp_oauth_request_timeout",
                "AS slow",
                server_url=server_entry.server_url,
            ),
        ]
        with pytest.raises(MCPAuthzError):
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
        row = _decision_rows(decision_history_store, "mcp_call")[0]
        p = row.payload
        assert p["decision"] == "errored", (
            f"post-dispatch reacquire failure decision row MUST be 'errored'; got {p['decision']!r}"
        )
        assert p["decision_reason"] == "mcp_oauth_request_timeout"
        # Carries first dispatch's session context
        assert p["mcp_session_id"] is not None


# ---------------------------------------------------------------------------
# R3 P3 #1 — mirror R2 retry-token separation on decision-history
# ---------------------------------------------------------------------------


class TestDecisionHistoryDispatchedContextSeparateFromCandidateRetryToken:
    """R2 P2's audit-side regressions (retry's open_session fails
    → never-sent candidate token doesn't leak into the audit row)
    mirrored on the decision_history surface. The mcp_call decision
    row is the examiner-replay surface and uses the same
    correlation context fields; without these mirrored assertions
    a future refactor could regress the decision side silently."""

    async def test_retry_open_failure_after_first_401_decision_uses_first_dispatch(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        decision_history_store: MagicMock,
    ) -> None:
        from cognic_agentos.protocol.mcp_transports import MCPTransportError

        e1 = MCPTransportError(
            "mcp_transport_send_failed",
            "401",
            server_url=server_entry.server_url,
        )
        e1.__cause__ = _httpx_status_error(401)
        http_transport.send.side_effect = [e1]
        first_session = _make_session("https://server.example/mcp", session_id="sess-FIRST")
        retry_open_error = MCPTransportError(
            "mcp_session_open_timeout",
            "server unreachable",
            server_url=server_entry.server_url,
        )
        http_transport.open_session.side_effect = [
            first_session,
            retry_open_error,
        ]

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
                request_id="req-1",
                tenant_id="t-1",
            )
        rows = _decision_rows(decision_history_store, "mcp_call")
        assert len(rows) == 1
        p = rows[0].payload
        # Decision row carries FIRST dispatch's correlation context
        assert p["client_id"] == "client-FIRST"
        assert p["mcp_session_id"] == "sess-FIRST"
        # Never-sent candidate token MUST NOT appear
        assert "client-SECOND-NEVER-SENT" not in str(p)
        assert "second-never-sent" not in str(p)

    async def test_retry_open_failure_after_step_up_decision_uses_first_narrow_scope(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        decision_history_store: MagicMock,
    ) -> None:
        """The high-risk step-up case: wider scopes from the
        never-sent step-up token MUST NOT appear in the decision
        row. Operator querying decision_history would otherwise
        falsely conclude the wider scope was sent."""
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
            scopes=("mcp:tools",),
            resource_indicator="https://server.example/mcp",
            client_id="client-narrow",
        )
        wide_token_never_sent = Token(
            value="wide-never-sent",
            expires_at=time.time() + 3600,
            as_issuer="https://as.example",
            scopes=("mcp:tools", "mcp:tools.write"),
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
                request_id="req-1",
                tenant_id="t-1",
            )
        rows = _decision_rows(decision_history_store, "mcp_call")
        assert len(rows) == 1
        p = rows[0].payload
        # Decision row shows NARROW scopes — what the server saw
        assert p["scopes"] == sorted(["mcp:tools"])
        assert p["mcp_session_id"] == "sess-NARROW"
        assert p["client_id"] == "client-narrow"
        # Never-sent wider token's identity MUST NOT appear
        assert "mcp:tools.write" not in str(p["scopes"])
        assert "client-wide-never-sent" not in str(p)


# ---------------------------------------------------------------------------
# R3 P2 — generic Exception decision row mirrors audit row
# ---------------------------------------------------------------------------


class TestDecisionHistoryGenericOpenSessionException:
    """Mirror R3 P2 audit-side fix on the decision-history surface:
    a generic ``Exception`` from ``open_session`` MUST emit the
    ``mcp_call`` decision row too."""

    async def test_generic_open_session_runtime_error_emits_decision_row(
        self,
        host: Any,
        server_entry: Any,
        http_transport: MagicMock,
        decision_history_store: MagicMock,
    ) -> None:
        http_transport.open_session.side_effect = RuntimeError("audit hook crashed")
        with pytest.raises(RuntimeError):
            await host.call_tool(
                server_id=server_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="req-1",
                tenant_id="t-1",
            )
        rows = _decision_rows(decision_history_store, "mcp_call")
        assert len(rows) == 1
        p = rows[0].payload
        assert p["decision"] == "errored"
        # R4 P2: decision_reason is closed-enum-or-null. The
        # generic-Exception path uses the closed value
        # ``mcp_orchestrator_error``; the actual class name lives
        # in a separate ``error_type`` field. Class names MUST
        # NOT bleed into the closed-enum reason.
        assert p["decision_reason"] == "mcp_orchestrator_error"
        assert p["error_type"] == "RuntimeError"
        assert p["decision_reason"] != "RuntimeError"
        assert p["mcp_session_id"] is None
