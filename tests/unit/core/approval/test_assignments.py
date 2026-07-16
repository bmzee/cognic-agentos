from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.approval._types import ApprovalActor
from cognic_agentos.core.approval.assignments import (
    ApprovalAssignmentInvalid,
    ApprovalAssignmentStore,
)
from cognic_agentos.core.decision_history import DecisionHistoryStore


async def _store(tmp_path: Any) -> tuple[ApprovalAssignmentStore, AsyncEngine]:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'assignments.db'}"
    await asyncio.to_thread(command.upgrade, make_alembic_config(url), "head")
    engine = create_async_engine(url)
    return ApprovalAssignmentStore(DecisionHistoryStore(engine)), engine


def _actor(
    subject: str = "operator.olivia",
    *,
    actor_type: str = "human",
) -> ApprovalActor:
    return ApprovalActor(
        subject=subject,
        tenant_id="t1",
        scopes=frozenset({"tool.approve.assign"}),
        actor_type=actor_type,  # type: ignore[arg-type]
    )


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


@pytest.mark.asyncio
async def test_resolve_absent_returns_none(tmp_path: Any) -> None:
    store, engine = await _store(tmp_path)
    try:
        assert await store.resolve(tenant_id="t1", tool_identity="s/probe_write") is None
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_assign_then_resolve_returns_set_and_count(tmp_path: Any) -> None:
    store, engine = await _store(tmp_path)
    try:
        eligibility = await store.assign(
            tenant_id="t1",
            tool_identity="s/probe_write",
            approver_subjects=("zara", "dana", "erin"),
            actor=_actor(),
            request_request_id="appr-assign-1",
        )
        assert eligibility.eligible_approvers == frozenset({"dana", "erin", "zara"})
        assert eligibility.required_count == 3
        assert await store.resolve(tenant_id="t1", tool_identity="s/probe_write") == eligibility
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_assign_empty_refuses_without_evidence(tmp_path: Any) -> None:
    store, engine = await _store(tmp_path)
    try:
        with pytest.raises(ApprovalAssignmentInvalid) as exc:
            await store.assign(
                tenant_id="t1",
                tool_identity="s/probe_write",
                approver_subjects=(),
                actor=_actor(),
                request_request_id="appr-assign-2",
            )
        assert exc.value.reason == "assignment_empty"
        assert await _assignment_events(engine) == []
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_assign_duplicate_subject_refuses(tmp_path: Any) -> None:
    store, engine = await _store(tmp_path)
    try:
        with pytest.raises(ApprovalAssignmentInvalid) as exc:
            await store.assign(
                tenant_id="t1",
                tool_identity="s/probe_write",
                approver_subjects=("dana", "dana"),
                actor=_actor(),
                request_request_id="appr-assign-3",
            )
        assert exc.value.reason == "assignment_subject_duplicate"
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_assign_service_actor_refuses(tmp_path: Any) -> None:
    store, engine = await _store(tmp_path)
    try:
        with pytest.raises(ApprovalAssignmentInvalid) as exc:
            await store.assign(
                tenant_id="t1",
                tool_identity="s/probe_write",
                approver_subjects=("dana",),
                actor=_actor("service.scheduler", actor_type="service"),
                request_request_id="appr-assign-4",
            )
        assert exc.value.reason == "assignment_actor_not_human"
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_assign_emits_chain_row_with_from_to(tmp_path: Any) -> None:
    store, engine = await _store(tmp_path)
    try:
        await store.assign(
            tenant_id="t1",
            tool_identity="s/probe_write",
            approver_subjects=("dana", "erin"),
            actor=_actor(),
            request_request_id="appr-assign-5",
        )
        await store.assign(
            tenant_id="t1",
            tool_identity="s/probe_write",
            approver_subjects=("zara", "dana"),
            actor=_actor("operator.peter"),
            request_request_id="appr-assign-6",
        )
        events = await _assignment_events(engine)
        assert events == [
            {
                "tenant_id": "t1",
                "tool_identity": "s/probe_write",
                "previous_subjects": [],
                "new_subjects": ["dana", "erin"],
                "actor_subject": "operator.olivia",
                "actor_id": "operator.olivia",
            },
            {
                "tenant_id": "t1",
                "tool_identity": "s/probe_write",
                "previous_subjects": ["dana", "erin"],
                "new_subjects": ["dana", "zara"],
                "actor_subject": "operator.peter",
                "actor_id": "operator.peter",
            },
        ]
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_unassign_reverts_resolve_to_none_and_emits(tmp_path: Any) -> None:
    store, engine = await _store(tmp_path)
    try:
        await store.assign(
            tenant_id="t1",
            tool_identity="s/probe_write",
            approver_subjects=("dana", "erin"),
            actor=_actor(),
            request_request_id="appr-assign-7",
        )
        removed = await store.unassign(
            tenant_id="t1",
            tool_identity="s/probe_write",
            actor=_actor("operator.peter"),
            request_request_id="appr-assign-8",
        )
        assert removed is True
        assert await store.resolve(tenant_id="t1", tool_identity="s/probe_write") is None
        assert (await _assignment_events(engine))[-1]["previous_subjects"] == ["dana", "erin"]
        assert (await _assignment_events(engine))[-1]["new_subjects"] == []
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_unassign_absent_returns_false_without_evidence(tmp_path: Any) -> None:
    store, engine = await _store(tmp_path)
    try:
        assert not await store.unassign(
            tenant_id="t1",
            tool_identity="s/missing",
            actor=_actor(),
            request_request_id="appr-assign-9",
        )
        assert await _assignment_events(engine) == []
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_unassign_service_actor_refuses(tmp_path: Any) -> None:
    store, engine = await _store(tmp_path)
    try:
        with pytest.raises(ApprovalAssignmentInvalid) as exc:
            await store.unassign(
                tenant_id="t1",
                tool_identity="s/probe_write",
                actor=_actor("service.scheduler", actor_type="service"),
                request_request_id="appr-assign-10",
            )
        assert exc.value.reason == "assignment_actor_not_human"
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_resolve_is_tenant_scoped(tmp_path: Any) -> None:
    store, engine = await _store(tmp_path)
    try:
        await store.assign(
            tenant_id="t1",
            tool_identity="s/probe_write",
            approver_subjects=("dana",),
            actor=_actor(),
            request_request_id="appr-assign-11",
        )
        assert await store.resolve(tenant_id="t2", tool_identity="s/probe_write") is None
    finally:
        await engine.dispose()
