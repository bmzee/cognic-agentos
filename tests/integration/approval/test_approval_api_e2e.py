"""Sprint 13.5b1 (ADR-014) — portal approval API end-to-end on a migrated DB.

Real ApprovalRequestStore + ApprovalEngine mounted via the REAL
``create_app(approval_store=…, approval_engine=…)`` (Task 8). The request is
created IN-PROCESS via ``engine.create_request(envelope=…)`` — the producer
13.5b2's MCP seam will use — then driven over HTTP:
create -> list -> detail -> grant -> detail-after + cross-tenant invisibility.

Helpers mirror tests/unit/portal/api/approvals/test_routes.py.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine
from starlette.requests import Request

from cognic_agentos.core.approval._types import ApprovalEnvelope
from cognic_agentos.core.approval.engine import ApprovalEngine
from cognic_agentos.core.approval.storage import ApprovalRequestStore
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.rbac.actor import Actor


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


def _make_actor(
    *,
    subject: str = "rev@bank.example",
    tenant_id: str = "t1",
    scopes: frozenset[str] = frozenset({"tool.approve.observe"}),
    actor_type: str = "human",
) -> Actor:
    return Actor(
        subject=subject,
        tenant_id=tenant_id,
        scopes=scopes,  # type: ignore[arg-type]
        actor_type=actor_type,  # type: ignore[arg-type]
    )


class _StubPolicy:
    async def classify(self, *, risk_tier: str) -> str:
        return "require_single_approval"


async def _mk_store(tmp_path: Any) -> ApprovalRequestStore:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'e2e.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    return ApprovalRequestStore(DecisionHistoryStore(create_async_engine(url)))


def _mk_engine(store: ApprovalRequestStore) -> ApprovalEngine:
    return ApprovalEngine(
        policy=_StubPolicy(),
        store=store,
        settings=build_settings_without_env_file(),
        clock=lambda: datetime(2026, 6, 11, 12, 0, tzinfo=UTC),
    )


async def test_create_list_detail_grant_e2e(tmp_path: Any) -> None:
    store = await _mk_store(tmp_path)
    engine = _mk_engine(store)  # _StubPolicy -> require_single_approval
    env = ApprovalEnvelope(
        risk_tier="customer_data_read",
        tool_identity="cognic-tool-x",
        originator_subject="agent-1",
        tenant_id="t1",
        data_classes=("customer_pii",),
        args_digest=b"\x02" * 32,
        redacted_context="ctx",
        required_refs={},
    )
    req = await engine.create_request(envelope=env)
    rid = req.request_id

    reviewer = _make_actor(scopes=frozenset({"tool.approve.observe", "tool.approve.customer_data"}))
    app = create_app(
        actor_binder=_StubBinder(reviewer), approval_store=store, approval_engine=engine
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        listed = await client.get("/api/v1/approvals/")
        assert listed.status_code == 200
        assert str(rid) in [r["request_id"] for r in listed.json()]

        detail = await client.get(f"/api/v1/approvals/{rid}")
        assert detail.status_code == 200
        assert detail.json()["state"] == "pending"

        grant_resp = await client.post(f"/api/v1/approvals/{rid}/grant", json={})
        assert grant_resp.status_code == 200
        assert grant_resp.json() == {"request_id": str(rid), "state": "granted"}

        after = await client.get(f"/api/v1/approvals/{rid}")
        assert after.json()["state"] == "granted"

    # cross-tenant invisibility from a t2 reviewer
    t2_app = create_app(
        actor_binder=_StubBinder(
            _make_actor(tenant_id="t2", scopes=frozenset({"tool.approve.observe"}))
        ),
        approval_store=store,
        approval_engine=engine,
    )
    async with AsyncClient(transport=ASGITransport(app=t2_app), base_url="http://t") as t2:
        cross_tenant_resp = await t2.get(f"/api/v1/approvals/{rid}")
        unknown_resp = await t2.get(f"/api/v1/approvals/{uuid.uuid4()}")
    assert cross_tenant_resp.status_code == unknown_resp.status_code == 404
    assert cross_tenant_resp.json() == unknown_resp.json()  # invisibility
