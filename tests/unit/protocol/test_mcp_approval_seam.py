"""Sprint 13.5b2 (ADR-014) — MCP-host approval seam cutover tests."""

from __future__ import annotations

import asyncio
import time
import typing
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.core.approval._types import APPROVAL_REDACTED_CONTEXT_MAX_LEN
from cognic_agentos.core.approval.engine import ApprovalEngine
from cognic_agentos.core.approval.storage import ApprovalRequestStore
from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.protocol.mcp_authz import MCPAuthzClient, Token


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


# ---------------------------------------------------------------------------
# T4+ fixtures (mirror test_mcp_high_risk_tier_refused.py:68-176 for the host
# side; tests/unit/portal/api/approvals/test_routes.py for the engine side)
# ---------------------------------------------------------------------------


class _MutableClock:
    """Advanceable engine clock (the expired-recall test moves time past the
    flow TTL; everything else uses the fixed default)."""

    def __init__(self) -> None:
        self.now = datetime(2026, 6, 11, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


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
    return build_settings_without_env_file()


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


def _make_session(server_url: str) -> Any:
    from contextlib import AsyncExitStack

    from cognic_agentos.protocol.mcp_transports import MCPSession

    sdk_session = MagicMock()
    sdk_session.call_tool = AsyncMock(return_value={"content": "ok"})
    sdk_session.list_tools = AsyncMock(return_value=[])
    return MCPSession(
        server_url=server_url,
        sdk_session=sdk_session,
        exit_stack=AsyncExitStack(),
        get_session_id=lambda: "sess-1",
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


class _StubPolicy:
    """Fixed-flow classifier (OPA-free; mirrors test_routes.py::_StubPolicy)."""

    def __init__(self, flow: str = "require_single_approval") -> None:
        self._flow = flow

    async def classify(self, *, risk_tier: str) -> str:
        return self._flow


async def _mk_approval_store(tmp_path: Any) -> ApprovalRequestStore:
    from alembic import command
    from sqlalchemy.ext.asyncio import create_async_engine

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'seam.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    return ApprovalRequestStore(DecisionHistoryStore(create_async_engine(url)))


def _mk_approval_engine(
    store: ApprovalRequestStore, *, flow: str, clock: Any = None
) -> ApprovalEngine:
    return ApprovalEngine(
        policy=_StubPolicy(flow),
        store=store,
        settings=build_settings_without_env_file(),
        clock=clock or (lambda: datetime(2026, 6, 11, 12, 0, tzinfo=UTC)),
    )


def _entry(host_module: Any, *, risk_tier: str = "customer_data_read") -> Any:
    return host_module.MCPServerEntry(
        server_id=f"pack.{risk_tier}",
        server_url="https://server.example/mcp",
        transport_kind="http",
        manifest_scopes=("mcp:tools",),
        risk_tier=risk_tier,
        pack_signature_digest="sha256:deadbeef",
        data_classes=("customer_pii",),
    )


def _wired_host(
    host_module: Any,
    entry: Any,
    engine: ApprovalEngine,
    *,
    http_transport: MagicMock,
    authz: MagicMock,
    audit_store: MagicMock,
    decision_history_store: MagicMock,
    settings: Any,
) -> Any:
    return host_module.MCPHost(
        servers={entry.server_id: entry},
        transports={"http": http_transport},
        authz=authz,
        audit_store=audit_store,
        decision_history_store=decision_history_store,
        settings=settings,
        approval_engine=engine,
    )


# ---------------------------------------------------------------------------
# T4 — wired first-call path
# ---------------------------------------------------------------------------


class TestWiredFirstCall:
    async def test_high_tier_first_call_refuses_pending_with_request_id(
        self,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
        tmp_path: Any,
    ) -> None:
        store = await _mk_approval_store(tmp_path)
        entry = _entry(host_module)
        host = _wired_host(
            host_module,
            entry,
            _mk_approval_engine(store, flow="require_single_approval"),
            http_transport=http_transport,
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )
        with pytest.raises(host_module.MCPToolInvocationRefused) as exc_info:
            await host.call_tool(
                server_id=entry.server_id,
                tool_name="lookup",
                arguments={"q": "x"},
                request_id="r1",
                tenant_id="t-1",
                originator_subject="agent-1",
            )
        exc = exc_info.value
        assert exc.reason == "tool_approval_pending"
        rid = uuid.UUID(exc.payload["approval_request_id"])  # parseable correlator
        assert exc.payload["flow"] == "require_single_approval"
        # the pending request actually persisted (engine path, not a stub)
        detail = await store.load_detail(request_id=rid, tenant_id="t-1")
        assert detail is not None and detail.state == "pending"
        # Envelope-sourcing pin (spec §3.3): the persisted detail carries the
        # sanitized human-readable pair in redacted_context (what the 13.5b1
        # portal reviewer panel shows), bounded by the cap, while
        # tool_identity stays the collision-proof digest form.
        assert detail.redacted_context.startswith("mcp_tool server_id=")
        assert "pack.customer_data_read" in detail.redacted_context
        assert "lookup" in detail.redacted_context
        assert len(detail.redacted_context) <= APPROVAL_REDACTED_CONTEXT_MAX_LEN
        assert detail.tool_identity.startswith("mcp:")
        # gate fired BEFORE token-acquire + session-open (T10 sequencing kept)
        authz.acquire_token.assert_not_awaited()
        http_transport.open_session.assert_not_awaited()
        # refused evidence row carries the correlator (spec §4/§6)
        refused = [
            c.args[0]
            for c in audit_store.append.await_args_list
            if c.args[0].event_type == "audit.tool_invocation_refused"
        ]
        assert len(refused) == 1
        assert refused[0].payload["refusal_reason"] == "tool_approval_pending"
        assert refused[0].payload["approval_request_id"] == str(rid)
        assert refused[0].payload["flow"] == "require_single_approval"

    async def test_auto_flow_dispatches_without_approval_row(
        self,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
        tmp_path: Any,
    ) -> None:
        # F2=B pin (overlay direction 1): the engine classified auto_run ->
        # dispatch, even though the DECLARED tier is high. Proves the static
        # set is NOT consulted on the wired path.
        store = await _mk_approval_store(tmp_path)
        entry = _entry(host_module, risk_tier="customer_data_read")
        host = _wired_host(
            host_module,
            entry,
            _mk_approval_engine(store, flow="auto_run"),
            http_transport=http_transport,
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )
        result = await host.call_tool(
            server_id=entry.server_id,
            tool_name="lookup",
            arguments={},
            request_id="r2",
            tenant_id="t-1",
            originator_subject="agent-1",
        )
        assert result.payload == {"content": "ok"}
        assert await store.list_pending("t-1") == []  # no approval row created

    async def test_tightened_low_tier_requires_approval(
        self,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
        tmp_path: Any,
    ) -> None:
        # F2=B pin (overlay direction 2): a bank overlay that TIGHTENS
        # tools.rego (read_only -> require_single_approval) is honoured —
        # the static {read_only, internal_write} set would have bypassed it.
        store = await _mk_approval_store(tmp_path)
        entry = _entry(host_module, risk_tier="read_only")
        host = _wired_host(
            host_module,
            entry,
            _mk_approval_engine(store, flow="require_single_approval"),
            http_transport=http_transport,
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )
        with pytest.raises(host_module.MCPToolInvocationRefused) as exc_info:
            await host.call_tool(
                server_id=entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="r3",
                tenant_id="t-1",
                originator_subject="agent-1",
            )
        assert exc_info.value.reason == "tool_approval_pending"

    async def test_regulator_tier_required_refs_carries_audit_record_ref(
        self,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
        tmp_path: Any,
    ) -> None:
        # F3 pin: regulator_communication envelopes carry
        # {"audit_record_ref": <invocation request_id>} — creatable, not refused
        # ApprovalEnvelopeInvalid("regulator_audit_ref_missing").
        store = await _mk_approval_store(tmp_path)
        entry = _entry(host_module, risk_tier="regulator_communication")
        host = _wired_host(
            host_module,
            entry,
            _mk_approval_engine(store, flow="require_4_eyes"),
            http_transport=http_transport,
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )
        with pytest.raises(host_module.MCPToolInvocationRefused) as exc_info:
            await host.call_tool(
                server_id=entry.server_id,
                tool_name="notify",
                arguments={},
                request_id="r-reg-1",
                tenant_id="t-1",
                originator_subject="agent-1",
            )
        assert exc_info.value.reason == "tool_approval_pending"
        rid = uuid.UUID(exc_info.value.payload["approval_request_id"])
        detail = await store.load_detail(request_id=rid, tenant_id="t-1")
        assert detail is not None
        assert detail.required_refs == {"audit_record_ref": "r-reg-1"}

    async def test_empty_originator_routes_errored_not_refused(
        self,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
        tmp_path: Any,
    ) -> None:
        # Spec §3.4/§3.5: delegate-first — the engine refuses
        # originator_subject_missing; the seam routes it through the generic
        # arm as ERRORED with the closed generic taxonomy. The errored row
        # EXISTS (the §3.6 placement pin: before-the-try placement would
        # emit ZERO rows).
        store = await _mk_approval_store(tmp_path)
        entry = _entry(host_module)
        host = _wired_host(
            host_module,
            entry,
            _mk_approval_engine(store, flow="require_single_approval"),
            http_transport=http_transport,
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )
        from cognic_agentos.core.approval._types import ApprovalEnvelopeInvalid

        with pytest.raises(ApprovalEnvelopeInvalid):
            await host.call_tool(
                server_id=entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="r4",
                tenant_id="t-1",  # originator_subject omitted -> ""
            )
        errored = [
            c.args[0]
            for c in audit_store.append.await_args_list
            if c.args[0].event_type == "audit.tool_invocation_error"
        ]
        assert len(errored) == 1
        assert errored[0].payload["error_taxonomy"] == "mcp_orchestrator_error"

    async def test_engine_absent_fallback_byte_compat(
        self,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        # No approval_engine -> the T10 transitional gate verbatim (the FULL
        # byte-compat suite is test_mcp_high_risk_tier_refused.py, unchanged;
        # this is the in-file smoke pin).
        entry = _entry(host_module, risk_tier="customer_data_read")
        host = host_module.MCPHost(
            servers={entry.server_id: entry},
            transports={"http": http_transport},
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )
        with pytest.raises(host_module.MCPToolInvocationRefused) as exc_info:
            await host.call_tool(
                server_id=entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="r5",
                tenant_id="t-1",
            )
        assert exc_info.value.reason == "tool_approval_engine_not_available"
        assert exc_info.value.payload["sprint_13_5_followup"] is True
