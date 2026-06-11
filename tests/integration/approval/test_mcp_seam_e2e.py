"""Sprint 13.5b2 — MCP seam cross-surface e2e on a migrated DB.

(1) real tools.rego classification (OPA-gated, mirrors test_tools_rego.py:13);
(2) host pending -> 13.5b1 HTTP grant -> re-call dispatches.
"""

from __future__ import annotations

import asyncio
import shutil
import time
import uuid
from contextlib import AsyncExitStack
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine
from starlette.requests import Request

from cognic_agentos.core.approval.engine import ApprovalEngine
from cognic_agentos.core.approval.policy import ApprovalPolicy
from cognic_agentos.core.approval.storage import ApprovalRequestStore
from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.core.policy.engine import OPAEngine
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.protocol.mcp_authz import MCPAuthzClient, Token

_opa_required = pytest.mark.skipif(shutil.which("opa") is None, reason="opa binary required")


# -- helpers (mirror test_approval_api_e2e.py + test_mcp_approval_seam.py) --


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


def _make_actor(*, scopes: frozenset[str]) -> Actor:
    return Actor(
        subject="rev@bank.example",
        tenant_id="t-1",
        scopes=scopes,  # type: ignore[arg-type]
        actor_type="human",
    )


class _StubPolicy:
    async def classify(self, *, risk_tier: str) -> str:
        return "require_single_approval"


async def _mk_store(tmp_path: Any) -> ApprovalRequestStore:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'mcp-e2e.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    return ApprovalRequestStore(DecisionHistoryStore(create_async_engine(url)))


def _token() -> Token:
    return Token(
        value="secret-token",
        expires_at=time.time() + 3600,
        as_issuer="https://as.example",
        scopes=("mcp:tools",),
        resource_indicator="https://server.example/mcp",
        client_id="client-a",
    )


def _mk_mock_stores() -> tuple[MagicMock, MagicMock]:
    audit = MagicMock(spec=AuditStore)
    audit.append = AsyncMock(return_value=("uuid", b"hash"))
    dh = MagicMock(spec=DecisionHistoryStore)
    dh.append = AsyncMock(return_value=("uuid", b"hash"))
    return audit, dh


def _mk_session() -> Any:
    from cognic_agentos.protocol.mcp_transports import MCPSession

    sdk_session = MagicMock()
    sdk_session.call_tool = AsyncMock(return_value={"content": "ok"})
    return MCPSession(
        server_url="https://server.example/mcp",
        sdk_session=sdk_session,
        exit_stack=AsyncExitStack(),
        get_session_id=lambda: "sess-1",
        token_scopes=("mcp:tools",),
        token_client_id="client-a",
    )


def _wired_host(host_module: Any, entry: Any, engine: ApprovalEngine) -> Any:
    authz = MagicMock(spec=MCPAuthzClient)
    authz.acquire_token = AsyncMock(return_value=_token())
    transport = MagicMock()
    transport.open_session = AsyncMock(return_value=_mk_session())
    transport.send = AsyncMock(return_value={"content": "ok"})
    transport.close_session = AsyncMock(return_value=None)
    audit, dh = _mk_mock_stores()
    return host_module.MCPHost(
        servers={entry.server_id: entry},
        transports={"http": transport},
        authz=authz,
        audit_store=audit,
        decision_history_store=dh,
        settings=build_settings_without_env_file(),
        approval_engine=engine,
    )


def _entry(host_module: Any, *, risk_tier: str) -> Any:
    return host_module.MCPServerEntry(
        server_id=f"pack.{risk_tier}",
        server_url="https://server.example/mcp",
        transport_kind="http",
        manifest_scopes=("mcp:tools",),
        risk_tier=risk_tier,
        pack_signature_digest="sha256:deadbeef",
        data_classes=("customer_pii",),
    )


@pytest.fixture
def host_module(monkeypatch: pytest.MonkeyPatch) -> Any:
    from cognic_agentos.protocol import mcp_host

    monkeypatch.setattr(mcp_host, "require_mcp", MagicMock())
    return mcp_host


@_opa_required
async def test_real_tools_rego_classifies_read_only_auto_run(
    host_module: Any, tmp_path: Any
) -> None:
    # The ONE real-Rego seam test (spec §8): read_only -> auto_run -> dispatch,
    # no approval row, via the REAL ApprovalPolicy + tools.rego bundle.
    store = await _mk_store(tmp_path)
    settings = build_settings_without_env_file()
    opa = await OPAEngine.create(
        bundle_path=settings.tools_policy_bundle,
        audit_store=AuditStore(store._engine),
        decision_history_store=DecisionHistoryStore(store._engine),
        opa_path=settings.opa_path,
        eval_timeout_s=settings.opa_eval_timeout_s,
    )
    engine = ApprovalEngine(
        policy=ApprovalPolicy(opa_engine=opa),
        store=store,
        settings=settings,
        clock=lambda: datetime(2026, 6, 11, 12, 0, tzinfo=UTC),
    )
    entry = _entry(host_module, risk_tier="read_only")
    host = _wired_host(host_module, entry, engine)
    result = await host.call_tool(
        server_id=entry.server_id,
        tool_name="lookup",
        arguments={},
        request_id="rego-1",
        tenant_id="t-1",
        originator_subject="agent-1",
    )
    assert result.payload == {"content": "ok"}
    assert await store.list_pending("t-1") == []


async def test_pending_http_grant_recall_dispatches(host_module: Any, tmp_path: Any) -> None:
    # The cross-surface e2e (spec §8): seam pending -> 13.5b1 portal grant
    # over HTTP -> re-call dispatches through the replay-binding gate.
    store = await _mk_store(tmp_path)
    engine = ApprovalEngine(
        policy=_StubPolicy(),
        store=store,
        settings=build_settings_without_env_file(),
        clock=lambda: datetime(2026, 6, 11, 12, 0, tzinfo=UTC),
    )
    entry = _entry(host_module, risk_tier="customer_data_read")
    host = _wired_host(host_module, entry, engine)

    with pytest.raises(host_module.MCPToolInvocationRefused) as exc_info:
        await host.call_tool(
            server_id=entry.server_id,
            tool_name="lookup",
            arguments={"q": "x"},
            request_id="e2e-1",
            tenant_id="t-1",
            originator_subject="agent-1",
        )
    rid = uuid.UUID(exc_info.value.payload["approval_request_id"])

    reviewer = _make_actor(scopes=frozenset({"tool.approve.customer_data"}))
    app = create_app(
        actor_binder=_StubBinder(reviewer), approval_store=store, approval_engine=engine
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(f"/api/v1/approvals/{rid}/grant", json={})
        assert resp.status_code == 200
        assert resp.json()["state"] == "granted"

    result = await host.call_tool(
        server_id=entry.server_id,
        tool_name="lookup",
        arguments={"q": "x"},
        request_id="e2e-2",
        tenant_id="t-1",
        originator_subject="agent-1",
        approval_request_id=rid,
    )
    assert result.payload == {"content": "ok"}
