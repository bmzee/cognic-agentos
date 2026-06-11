from __future__ import annotations

import asyncio
import json
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.approval._types import ApprovalRequestNotFound
from cognic_agentos.core.approval.storage import ApprovalRequestStore
from cognic_agentos.core.decision_history import DecisionHistoryStore


async def _store(tmp_path: Any) -> tuple[ApprovalRequestStore, Any]:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'appr.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    eng = create_async_engine(url)
    return ApprovalRequestStore(DecisionHistoryStore(eng)), eng


def _now() -> datetime:
    return datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC)


async def _create(
    store: ApprovalRequestStore, *, flow: str, tier: str, tenant: str = "t1"
) -> uuid.UUID:
    rid = uuid.uuid4()
    await store.create_request_row(
        request_id=rid,
        tenant_id=tenant,
        flow=flow,
        risk_tier=tier,
        tool_identity="cognic-tool-x",
        originator_subject="agent-1",
        envelope_digest=b"\x01" * 32,
        args_digest=b"\x02" * 32,
        redacted_context="ctx",
        data_classes=["customer_pii"],
        required_refs={},
        request_request_id="appr-" + uuid.uuid4().hex,
        created_at=_now(),
        expires_at=datetime(2026, 6, 10, 12, 5, 0, tzinfo=UTC),
    )
    return rid


async def _events(eng: Any) -> list[str]:
    async with eng.connect() as c:
        rows = (
            await c.execute(
                sa.text(
                    "SELECT event_type FROM decision_history "
                    "WHERE event_type LIKE 'approval.%' ORDER BY sequence"
                )
            )
        ).all()
    return [r[0] for r in rows]


@pytest.mark.asyncio
async def test_create_then_transition_grant_single(tmp_path: Any) -> None:
    store, eng = await _store(tmp_path)
    try:
        rid = await _create(store, flow="require_single_approval", tier="customer_data_read")
        row = await store.load(request_id=rid, tenant_id="t1")
        assert row is not None and row.state == "pending"
        new_state = await store.transition(
            request_id=rid,
            tenant_id="t1",
            action="grant_first",
            actor_subject="reviewer-1",
            request_request_id="appr-" + uuid.uuid4().hex,
        )
        assert new_state == "granted"
        row2 = await store.load(request_id=rid, tenant_id="t1")
        assert row2 is not None and row2.state == "granted" and row2.first_approver == "reviewer-1"
        assert await _events(eng) == ["approval.requested", "approval.granted_first"]
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_four_eyes_two_grants(tmp_path: Any) -> None:
    store, eng = await _store(tmp_path)
    try:
        rid = await _create(store, flow="require_4_eyes", tier="payment_action")
        s1 = await store.transition(
            request_id=rid,
            tenant_id="t1",
            action="grant_first",
            actor_subject="rev-a",
            request_request_id="appr-" + uuid.uuid4().hex,
        )
        assert s1 == "awaiting_second"
        s2 = await store.transition(
            request_id=rid,
            tenant_id="t1",
            action="grant_second",
            actor_subject="rev-b",
            request_request_id="appr-" + uuid.uuid4().hex,
        )
        assert s2 == "granted"
        assert await _events(eng) == [
            "approval.requested",
            "approval.granted_first",
            "approval.granted_second",
        ]
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_persisted_flow_is_authoritative_no_downgrade(tmp_path: Any) -> None:
    # P1: a persisted require_4_eyes request's first grant lands awaiting_second,
    # NOT granted. The store reads the row-locked persisted flow; there is no
    # caller-supplied flow arg to downgrade with. A single grant can never make a
    # 4-eyes request executable.
    store, eng = await _store(tmp_path)
    try:
        rid = await _create(store, flow="require_4_eyes", tier="payment_action")
        s = await store.transition(
            request_id=rid,
            tenant_id="t1",
            action="grant_first",
            actor_subject="rev-a",
            request_request_id="appr-" + uuid.uuid4().hex,
        )
        assert s == "awaiting_second"
        row = await store.load(request_id=rid, tenant_id="t1")
        assert row is not None and row.state == "awaiting_second"
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_load_cross_tenant_returns_none(tmp_path: Any) -> None:
    store, eng = await _store(tmp_path)
    try:
        rid = await _create(store, flow="require_4_eyes", tier="payment_action")
        assert await store.load(request_id=rid, tenant_id="t2") is None
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_transition_unknown_request_raises_not_found(tmp_path: Any) -> None:
    store, eng = await _store(tmp_path)
    try:
        with pytest.raises(ApprovalRequestNotFound):
            await store.transition(
                request_id=uuid.uuid4(),
                tenant_id="t1",
                action="deny",
                actor_subject="r",
                reason="x",
                request_request_id="appr-" + uuid.uuid4().hex,
            )
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_deny_emits_denied_and_records_denier(tmp_path: Any) -> None:
    store, eng = await _store(tmp_path)
    try:
        rid = await _create(store, flow="require_single_approval", tier="customer_data_read")
        s = await store.transition(
            request_id=rid,
            tenant_id="t1",
            action="deny",
            actor_subject="rev-d",
            reason="not allowed",
            request_request_id="appr-" + uuid.uuid4().hex,
        )
        assert s == "denied"
        row = await store.load(request_id=rid, tenant_id="t1")
        assert row is not None and row.denier == "rev-d"
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_value_free_payload_exact_key_set(tmp_path: Any) -> None:
    store, eng = await _store(tmp_path)
    try:
        await _create(store, flow="require_single_approval", tier="customer_data_read")
        async with eng.connect() as c:
            row = (
                await c.execute(
                    sa.text(
                        "SELECT payload FROM decision_history WHERE event_type='approval.requested'"
                    )
                )
            ).first()
        assert row is not None
        payload = row[0] if isinstance(row[0], dict) else json.loads(row[0])
        assert set(payload.keys()) == {
            "request_id",
            "tenant_id",
            "flow",
            "risk_tier",
            "tool_identity",
            "originator_subject",
            "state",
            "envelope_digest",
            "args_digest",
            "redacted_context",
            "required_refs",
            "first_approver",
            "second_approver",
            "denier",
            # store-merged governance identity (the triggering subject), exactly
            # as eval.* / scheduler.* chain rows carry it.
            "actor_id",
        }
        # value-free: no raw args anywhere; digests are hex strings.
        assert payload["args_digest"] == (b"\x02" * 32).hex()
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_transition_expire_sets_no_approver(tmp_path: Any) -> None:
    store, eng = await _store(tmp_path)
    try:
        rid = await _create(store, flow="require_single_approval", tier="customer_data_read")
        s = await store.transition(
            request_id=rid,
            tenant_id="t1",
            action="expire",
            actor_subject=None,
            request_request_id="appr-" + uuid.uuid4().hex,
        )
        assert s == "expired"
        row = await store.load(request_id=rid, tenant_id="t1")
        assert row is not None
        assert row.first_approver is None and row.second_approver is None and row.denier is None
        assert await _events(eng) == ["approval.requested", "approval.expired"]
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_first_approver_read(tmp_path: Any) -> None:
    store, eng = await _store(tmp_path)
    try:
        rid = await _create(store, flow="require_4_eyes", tier="payment_action")
        assert await store.first_approver(request_id=rid, tenant_id="t1") is None
        await store.transition(
            request_id=rid,
            tenant_id="t1",
            action="grant_first",
            actor_subject="rev-a",
            request_request_id="appr-" + uuid.uuid4().hex,
        )
        assert await store.first_approver(request_id=rid, tenant_id="t1") == "rev-a"
        # unknown / cross-tenant -> None
        assert await store.first_approver(request_id=uuid.uuid4(), tenant_id="t1") is None
    finally:
        await eng.dispose()
