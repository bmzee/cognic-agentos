from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from typing import Any
from unittest.mock import patch

import pytest
import sqlalchemy as sa
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from starlette.requests import Request

from cognic_agentos.core.approval._types import ApprovalActor
from cognic_agentos.core.approval.assignments import ApprovalAssignmentStore
from cognic_agentos.core.approval.engine import ApprovalEngine
from cognic_agentos.core.approval.storage import ApprovalRequestStore
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.portal.api.approvals.routes import build_approval_routes
from cognic_agentos.portal.rbac.actor import Actor


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


class _StubPolicy:
    async def classify(self, *, risk_tier: str) -> str:
        return "require_single_approval"


def _actor(
    *,
    subject: str = "operator.olivia",
    tenant_id: str = "t1",
    scopes: frozenset[str] = frozenset({"tool.approve.assign"}),
    actor_type: str = "human",
) -> Actor:
    return Actor(
        subject=subject,
        tenant_id=tenant_id,
        scopes=scopes,  # type: ignore[arg-type]
        actor_type=actor_type,  # type: ignore[arg-type]
    )


def _approval_actor(subject: str = "operator.seed", *, tenant_id: str = "t1") -> ApprovalActor:
    return ApprovalActor(
        subject=subject,
        tenant_id=tenant_id,
        scopes=frozenset({"tool.approve.assign"}),
        actor_type="human",
    )


async def _stores(
    tmp_path: Any,
) -> tuple[ApprovalRequestStore, ApprovalAssignmentStore, AsyncEngine]:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'assignment-routes.db'}"
    await asyncio.to_thread(command.upgrade, make_alembic_config(url), "head")
    engine = create_async_engine(url)
    history = DecisionHistoryStore(engine)
    return ApprovalRequestStore(history), ApprovalAssignmentStore(history), engine


def _client(
    actor: Actor,
    store: ApprovalRequestStore,
    assignments: ApprovalAssignmentStore,
) -> AsyncClient:
    app = FastAPI()
    app.state.actor_binder = _StubBinder(actor)
    app.state.ui_event_broker = None
    engine = ApprovalEngine(
        policy=_StubPolicy(),
        store=store,
        settings=build_settings_without_env_file(),
        clock=lambda: datetime.now(UTC),
    )
    app.include_router(build_approval_routes(store=store, engine=engine, assignments=assignments))
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://t")


async def _assignment_events(engine: AsyncEngine) -> list[dict[str, Any]]:
    async with engine.connect() as conn:
        rows = (
            await conn.execute(
                sa.text(
                    "SELECT payload FROM decision_history "
                    "WHERE event_type='approval.assignment_changed' ORDER BY sequence"
                )
            )
        ).all()
    return [row[0] if isinstance(row[0], dict) else json.loads(row[0]) for row in rows]


def _assignment_logs(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [
        record
        for record in caplog.records
        if record.name == "cognic_agentos.portal.api.approvals.routes"
        and record.getMessage().startswith("portal.approvals.assignment_")
    ]


@pytest.mark.asyncio
async def test_put_assignment_returns_persisted_record_and_emits_once(
    tmp_path: Any,
    caplog: pytest.LogCaptureFixture,
) -> None:
    store, assignments, db = await _stores(tmp_path)
    try:
        with (
            caplog.at_level(logging.INFO, logger="cognic_agentos.portal.api.approvals.routes"),
            patch.object(
                assignments,
                "load",
                side_effect=AssertionError("PUT must not re-read after its committed write"),
            ),
        ):
            async with _client(_actor(), store, assignments) as client:
                response = await client.put(
                    "/api/v1/approvals/assignments/server/probe_write",
                    json={"approver_subjects": ["zara", "dana", "erin"]},
                )

        assert response.status_code == 200
        assert response.json() == {
            "tool_identity": "server/probe_write",
            "approver_subjects": ["dana", "erin", "zara"],
            "required_count": 3,
            "updated_by": "operator.olivia",
            "updated_at": response.json()["updated_at"],
        }
        assert datetime.fromisoformat(response.json()["updated_at"]).tzinfo is not None
        logs = _assignment_logs(caplog)
        assert [record.getMessage() for record in logs] == ["portal.approvals.assignment_changed"]
        assert getattr(logs[0], "action", None) == "assign"
        assert len(await _assignment_events(db)) == 1
    finally:
        await db.dispose()


@pytest.mark.asyncio
async def test_put_empty_assignment_maps_closed_reason_to_422(
    tmp_path: Any,
) -> None:
    store, assignments, db = await _stores(tmp_path)
    try:
        async with _client(_actor(), store, assignments) as client:
            response = await client.put(
                "/api/v1/approvals/assignments/server/probe_write",
                json={"approver_subjects": []},
            )
        assert response.status_code == 422
        assert response.json() == {"detail": {"reason": "assignment_empty"}}
        assert await _assignment_events(db) == []
    finally:
        await db.dispose()


@pytest.mark.asyncio
async def test_put_extra_field_is_refused_by_dto(tmp_path: Any) -> None:
    store, assignments, db = await _stores(tmp_path)
    try:
        async with _client(_actor(), store, assignments) as client:
            response = await client.put(
                "/api/v1/approvals/assignments/server/probe_write",
                json={"approver_subjects": ["dana"], "tenant_id": "t2"},
            )
        assert response.status_code == 422
        assert await assignments.resolve(tenant_id="t1", tool_identity="server/probe_write") is None
    finally:
        await db.dispose()


@pytest.mark.asyncio
async def test_service_put_is_403_with_zero_route_assignment_logs(
    tmp_path: Any,
    caplog: pytest.LogCaptureFixture,
) -> None:
    store, assignments, db = await _stores(tmp_path)
    service = _actor(subject="service.scheduler", actor_type="service")
    try:
        with caplog.at_level(logging.INFO):
            async with _client(service, store, assignments) as client:
                response = await client.put(
                    "/api/v1/approvals/assignments/server/probe_write",
                    json={"approver_subjects": ["dana"]},
                )
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "actor_type_must_be_human"
        assert _assignment_logs(caplog) == []
        assert await _assignment_events(db) == []
    finally:
        await db.dispose()


@pytest.mark.asyncio
async def test_put_requires_assignment_scope(tmp_path: Any) -> None:
    store, assignments, db = await _stores(tmp_path)
    observer = _actor(scopes=frozenset({"tool.approve.observe"}))
    try:
        async with _client(observer, store, assignments) as client:
            response = await client.put(
                "/api/v1/approvals/assignments/server/probe_write",
                json={"approver_subjects": ["dana"]},
            )
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "scope_not_held"
    finally:
        await db.dispose()


@pytest.mark.asyncio
async def test_get_assignment_requires_observe_and_returns_record(tmp_path: Any) -> None:
    store, assignments, db = await _stores(tmp_path)
    await assignments.assign(
        tenant_id="t1",
        tool_identity="server/probe_write",
        approver_subjects=("dana", "erin"),
        actor=_approval_actor(),
        request_request_id="seed-assignment-get",
    )
    observer = _actor(scopes=frozenset({"tool.approve.observe"}))
    try:
        async with _client(observer, store, assignments) as client:
            response = await client.get("/api/v1/approvals/assignments/server/probe_write")
        assert response.status_code == 200
        assert response.json()["approver_subjects"] == ["dana", "erin"]
        assert response.json()["required_count"] == 2
        assert response.json()["updated_by"] == "operator.seed"
    finally:
        await db.dispose()


@pytest.mark.asyncio
async def test_get_cross_tenant_is_identical_to_unknown(tmp_path: Any) -> None:
    store, assignments, db = await _stores(tmp_path)
    await assignments.assign(
        tenant_id="t2",
        tool_identity="server/probe_write",
        approver_subjects=("dana",),
        actor=_approval_actor(tenant_id="t2"),
        request_request_id="seed-assignment-cross-tenant",
    )
    observer = _actor(scopes=frozenset({"tool.approve.observe"}))
    try:
        async with _client(observer, store, assignments) as client:
            cross = await client.get("/api/v1/approvals/assignments/server/probe_write")
            unknown = await client.get("/api/v1/approvals/assignments/server/unknown_write")
        assert cross.status_code == unknown.status_code == 404
        assert cross.content == unknown.content
        assert cross.json() == {"detail": {"reason": "approval_assignment_not_found"}}
    finally:
        await db.dispose()


@pytest.mark.asyncio
async def test_delete_assignment_clears_resolution_and_emits_once(
    tmp_path: Any,
    caplog: pytest.LogCaptureFixture,
) -> None:
    store, assignments, db = await _stores(tmp_path)
    await assignments.assign(
        tenant_id="t1",
        tool_identity="server/probe_write",
        approver_subjects=("dana",),
        actor=_approval_actor(),
        request_request_id="seed-assignment-delete",
    )
    caplog.clear()
    try:
        with caplog.at_level(logging.INFO, logger="cognic_agentos.portal.api.approvals.routes"):
            async with _client(_actor(), store, assignments) as client:
                response = await client.delete("/api/v1/approvals/assignments/server/probe_write")
        assert response.status_code == 204
        assert await assignments.resolve(tenant_id="t1", tool_identity="server/probe_write") is None
        logs = _assignment_logs(caplog)
        assert [record.getMessage() for record in logs] == ["portal.approvals.assignment_changed"]
        assert getattr(logs[0], "action", None) == "unassign"
    finally:
        await db.dispose()


@pytest.mark.asyncio
async def test_delete_unknown_and_cross_tenant_have_identical_404(tmp_path: Any) -> None:
    store, assignments, db = await _stores(tmp_path)
    await assignments.assign(
        tenant_id="t2",
        tool_identity="server/probe_write",
        approver_subjects=("dana",),
        actor=_approval_actor(tenant_id="t2"),
        request_request_id="seed-assignment-delete-cross",
    )
    try:
        async with _client(_actor(), store, assignments) as client:
            cross = await client.delete("/api/v1/approvals/assignments/server/probe_write")
            unknown = await client.delete("/api/v1/approvals/assignments/server/unknown_write")
        assert cross.status_code == unknown.status_code == 404
        assert cross.content == unknown.content
        assert (
            await assignments.resolve(tenant_id="t2", tool_identity="server/probe_write")
            is not None
        )
    finally:
        await db.dispose()
