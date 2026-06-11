from __future__ import annotations

import asyncio
import logging
import typing
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine
from starlette.requests import Request

from cognic_agentos.core.approval._types import ApprovalTransitionRefusedReason
from cognic_agentos.core.approval.engine import ApprovalEngine
from cognic_agentos.core.approval.storage import ApprovalRequestStore
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.portal.api.approvals.routes import _REFUSAL_STATUS, build_approval_routes
from cognic_agentos.portal.rbac.actor import Actor


class _StubBinder:
    """Test-only ActorBinder (lives in the test module per the AGENTS.md
    test-fixture-placement rule; mirrors test_author_routes.py:68)."""

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
    """Returns a fixed flow without touching OPA (matches the
    test_engine_grant_side.py::_StubPolicy duck shape — no type:ignore needed
    at the ApprovalEngine call site)."""

    def __init__(self, flow: str = "require_single_approval") -> None:
        self._flow = flow

    async def classify(self, *, risk_tier: str) -> str:
        return self._flow


async def _mk_store(tmp_path: Any, *, name: str = "routes.db") -> ApprovalRequestStore:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / name}"
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


async def _seed(
    store: ApprovalRequestStore,
    *,
    request_id: uuid.UUID,
    tenant: str = "t1",
    flow: str = "require_single_approval",
    expires_at: datetime | None = None,
) -> None:
    # Default expiry is FUTURE relative to the _mk_engine clock (12:00) — the
    # engine lazy-expires on clock() >= expires_at, so a now-expiring seed would
    # 409 every decision path. Pass expires_at=now explicitly to test expiry.
    now = datetime(2026, 6, 11, 12, 0, tzinfo=UTC)
    await store.create_request_row(
        request_id=request_id,
        tenant_id=tenant,
        flow=flow,
        risk_tier="customer_data_read",
        tool_identity="cognic-tool-x",
        originator_subject="agent-1",
        envelope_digest=b"\x03" * 32,
        args_digest=b"\x02" * 32,
        redacted_context="ctx",
        data_classes=["customer_pii"],
        required_refs={},
        request_request_id=f"appr-{request_id.hex}",
        created_at=now,
        expires_at=expires_at if expires_at is not None else now + timedelta(hours=1),
    )


def _client(actor: Actor, store: ApprovalRequestStore, engine: ApprovalEngine) -> AsyncClient:
    app = FastAPI()
    app.state.actor_binder = _StubBinder(actor)
    app.state.ui_event_broker = None
    app.include_router(build_approval_routes(store=store, engine=engine))
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://t")


@pytest.mark.asyncio
async def test_list_queue_returns_tenant_rows(tmp_path: Any) -> None:
    store = await _mk_store(tmp_path)
    rid = uuid.uuid4()
    await _seed(store, request_id=rid)
    async with _client(_make_actor(), store, _mk_engine(store)) as client:
        resp = await client.get("/api/v1/approvals/")
    assert resp.status_code == 200
    assert [r["request_id"] for r in resp.json()] == [str(rid)]


@pytest.mark.asyncio
async def test_get_detail_renders_hex_digest(tmp_path: Any) -> None:
    store = await _mk_store(tmp_path)
    rid = uuid.uuid4()
    await _seed(store, request_id=rid)
    async with _client(_make_actor(), store, _mk_engine(store)) as client:
        resp = await client.get(f"/api/v1/approvals/{rid}")
    assert resp.status_code == 200
    assert resp.json()["request_id"] == str(rid)
    assert resp.json()["args_digest"] == "02" * 32  # hex on the wire, never bytes


@pytest.mark.asyncio
async def test_get_detail_cross_tenant_404_identical_to_unknown(tmp_path: Any) -> None:
    store = await _mk_store(tmp_path)
    rid_t2 = uuid.uuid4()
    await _seed(store, request_id=rid_t2, tenant="t2")
    actor_t1 = _make_actor(tenant_id="t1")  # cannot see t2's request
    async with _client(actor_t1, store, _mk_engine(store)) as client:
        cross = await client.get(f"/api/v1/approvals/{rid_t2}")
        unknown = await client.get(f"/api/v1/approvals/{uuid.uuid4()}")
    assert cross.status_code == unknown.status_code == 404
    assert cross.json() == unknown.json()  # byte-identical invisibility


@pytest.mark.asyncio
async def test_list_actor_tenant_id_missing_returns_500(tmp_path: Any) -> None:
    store = await _mk_store(tmp_path)
    actor = _make_actor(tenant_id="")  # empty tenant — the only reachable falsy str
    async with _client(actor, store, _mk_engine(store)) as client:
        resp = await client.get("/api/v1/approvals/")
    assert resp.status_code == 500
    # FastAPI wraps HTTPException.detail as {"detail": ...} (see
    # test_inspection_routes.py:377 for the grounded precedent).
    assert resp.json()["detail"] == {"reason": "actor_tenant_id_missing"}


# ---- Task 6: POST grant / grant-second / deny -------------------------------


def test_every_transition_reason_has_a_status_mapping() -> None:
    # USER PIN: adding an 11th engine reason FAILS here until the wire
    # mapping is updated. Drives from typing.get_args of the engine enum.
    assert set(_REFUSAL_STATUS) == set(typing.get_args(ApprovalTransitionRefusedReason))
    assert all(v in (400, 403, 409) for v in _REFUSAL_STATUS.values())


@pytest.mark.asyncio
async def test_grant_happy_path_emits_exactly_one_green_log(tmp_path: Any, caplog: Any) -> None:
    store = await _mk_store(tmp_path)
    rid = uuid.uuid4()
    await _seed(store, request_id=rid)  # customer_data_read -> needs tool.approve.customer_data
    actor = _make_actor(scopes=frozenset({"tool.approve.customer_data"}))
    caplog.set_level(logging.INFO)
    async with _client(actor, store, _mk_engine(store)) as client:
        resp = await client.post(f"/api/v1/approvals/{rid}/grant", json={})
    assert resp.status_code == 200
    assert resp.json() == {"request_id": str(rid), "state": "granted"}
    names = [r.getMessage() for r in caplog.records]
    assert names.count("portal.approvals.grant") == 1
    assert "portal.approvals.grant_refused" not in names


@pytest.mark.asyncio
async def test_grant_service_actor_refused_403(tmp_path: Any, caplog: Any) -> None:
    store = await _mk_store(tmp_path)
    rid = uuid.uuid4()
    await _seed(store, request_id=rid)
    svc = _make_actor(actor_type="service", scopes=frozenset({"tool.approve.customer_data"}))
    caplog.set_level(logging.INFO)
    async with _client(svc, store, _mk_engine(store)) as client:
        resp = await client.post(f"/api/v1/approvals/{rid}/grant", json={})
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "actor_type_must_be_human"
    # Dep-chain refusal emits ZERO route-level approval logs — the sibling
    # RequireHumanActor guard's _emit_denial_or_500 carries that axis.
    names = [r.getMessage() for r in caplog.records]
    assert not any(n.startswith("portal.approvals.") for n in names)


@pytest.mark.asyncio
async def test_grant_unknown_request_404(tmp_path: Any) -> None:
    store = await _mk_store(tmp_path)
    actor = _make_actor(scopes=frozenset({"tool.approve.customer_data"}))
    async with _client(actor, store, _mk_engine(store)) as client:
        resp = await client.post(f"/api/v1/approvals/{uuid.uuid4()}/grant", json={})
    assert resp.status_code == 404
    assert resp.json()["detail"] == {"reason": "approval_request_not_found"}


@pytest.mark.asyncio
async def test_grant_wrong_tier_scope_refused_403(tmp_path: Any) -> None:
    # engine enforces scope-per-tier: customer_data_read needs
    # tool.approve.customer_data; actor holds only payment -> 403.
    store = await _mk_store(tmp_path)
    rid = uuid.uuid4()
    await _seed(store, request_id=rid)
    actor = _make_actor(scopes=frozenset({"tool.approve.payment"}))
    async with _client(actor, store, _mk_engine(store)) as client:
        resp = await client.post(f"/api/v1/approvals/{rid}/grant", json={})
    assert resp.status_code == 403
    assert resp.json()["detail"] == {"reason": "approver_scope_not_held"}


@pytest.mark.asyncio
async def test_grant_expired_request_409(tmp_path: Any) -> None:
    # Pins the 409 dispatch arm end-to-end: seed expiring exactly at the engine
    # clock instant -> lazy-expire on the decision path -> approval_expired.
    store = await _mk_store(tmp_path)
    rid = uuid.uuid4()
    now = datetime(2026, 6, 11, 12, 0, tzinfo=UTC)
    await _seed(store, request_id=rid, expires_at=now)
    actor = _make_actor(scopes=frozenset({"tool.approve.customer_data"}))
    async with _client(actor, store, _mk_engine(store)) as client:
        resp = await client.post(f"/api/v1/approvals/{rid}/grant", json={})
    assert resp.status_code == 409
    assert resp.json()["detail"] == {"reason": "approval_expired"}


@pytest.mark.asyncio
async def test_deny_missing_reason_422(tmp_path: Any) -> None:
    store = await _mk_store(tmp_path)
    rid = uuid.uuid4()
    await _seed(store, request_id=rid)
    actor = _make_actor(scopes=frozenset({"tool.approve.customer_data"}))
    async with _client(actor, store, _mk_engine(store)) as client:
        resp = await client.post(f"/api/v1/approvals/{rid}/deny", json={})  # no reason
    assert resp.status_code == 422  # Pydantic — DenyRequest.reason required


@pytest.mark.asyncio
async def test_deny_green_path_emits_exactly_one_green_log(tmp_path: Any, caplog: Any) -> None:
    store = await _mk_store(tmp_path)
    rid = uuid.uuid4()
    await _seed(store, request_id=rid)
    actor = _make_actor(scopes=frozenset({"tool.approve.customer_data"}))
    caplog.set_level(logging.INFO)
    async with _client(actor, store, _mk_engine(store)) as client:
        resp = await client.post(f"/api/v1/approvals/{rid}/deny", json={"reason": "not justified"})
    assert resp.status_code == 200
    assert resp.json() == {"request_id": str(rid), "state": "denied"}
    names = [r.getMessage() for r in caplog.records]
    assert names.count("portal.approvals.deny") == 1
    assert "portal.approvals.deny_refused" not in names


@pytest.mark.asyncio
async def test_grant_second_4eyes_flow_green(tmp_path: Any, caplog: Any) -> None:
    # 4-eyes: grant by A -> awaiting_second; grant-second by distinct B -> granted.
    store = await _mk_store(tmp_path)
    rid = uuid.uuid4()
    await _seed(store, request_id=rid, flow="require_4_eyes")
    first = _make_actor(scopes=frozenset({"tool.approve.customer_data"}))
    second = _make_actor(
        subject="rev2@bank.example", scopes=frozenset({"tool.approve.customer_data"})
    )
    caplog.set_level(logging.INFO)
    async with _client(first, store, _mk_engine(store)) as client:
        r1 = await client.post(f"/api/v1/approvals/{rid}/grant", json={})
    assert r1.status_code == 200
    assert r1.json() == {"request_id": str(rid), "state": "awaiting_second"}
    async with _client(second, store, _mk_engine(store)) as client:
        r2 = await client.post(f"/api/v1/approvals/{rid}/grant-second", json={})
    assert r2.status_code == 200
    assert r2.json() == {"request_id": str(rid), "state": "granted"}
    names = [r.getMessage() for r in caplog.records]
    assert names.count("portal.approvals.grant") == 1
    assert names.count("portal.approvals.grant_second") == 1
