from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.approval._types import (
    ApprovalActor,
    ApprovalEnvelope,
    ApprovalTransitionRefused,
)
from cognic_agentos.core.approval.engine import ApprovalEngine
from cognic_agentos.core.approval.storage import ApprovalRequestStore, _approval_requests
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.decision_history import DecisionHistoryStore, _decision_history


class _SingleApprovalPolicy:
    async def classify(self, *, risk_tier: str) -> str:
        return "require_single_approval"


async def _harness(tmp_path: Any) -> tuple[ApprovalRequestStore, AsyncEngine]:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'consumption.db'}"
    await asyncio.to_thread(command.upgrade, make_alembic_config(url), "head")
    engine = create_async_engine(url)
    return ApprovalRequestStore(DecisionHistoryStore(engine)), engine


async def _seed(
    store: ApprovalRequestStore,
    *,
    state: str,
    tenant_id: str = "t1",
) -> uuid.UUID:
    request_id = uuid.uuid4()
    now = datetime(2026, 7, 16, 12, 0, tzinfo=UTC)
    await store.create_request_row(
        request_id=request_id,
        tenant_id=tenant_id,
        flow="require_single_approval",
        risk_tier="customer_data_write",
        tool_identity="mcp:probe",
        originator_subject="analyst.amir",
        envelope_digest=b"e" * 32,
        args_digest=b"a" * 32,
        redacted_context="probe_write",
        data_classes=["internal"],
        required_refs={},
        request_request_id=f"consume-create-{request_id.hex}",
        created_at=now,
        expires_at=now + timedelta(minutes=5),
        required_count=1,
    )
    if state == "granted":
        await store.transition(
            request_id=request_id,
            tenant_id=tenant_id,
            action="grant_first",
            actor_subject="approver.dana",
            request_request_id=f"consume-grant-{request_id.hex}",
        )
    elif state == "denied":
        await store.transition(
            request_id=request_id,
            tenant_id=tenant_id,
            action="deny",
            actor_subject="approver.dana",
            request_request_id=f"consume-deny-{request_id.hex}",
            reason="declined",
        )
    elif state != "pending":
        raise AssertionError(f"unsupported seed state {state!r}")
    return request_id


async def _consumed_rows(engine: AsyncEngine) -> list[sa.Row[Any]]:
    async with engine.connect() as conn:
        return list(
            (
                await conn.execute(
                    sa.select(
                        _decision_history.c.request_id,
                        _decision_history.c.payload,
                    ).where(_decision_history.c.event_type == "approval.consumed")
                )
            ).all()
        )


@pytest.mark.parametrize("state", ["pending", "denied"])
async def test_claim_refuses_non_granted_without_evidence(tmp_path: Any, state: str) -> None:
    store, engine = await _harness(tmp_path)
    try:
        request_id = await _seed(store, state=state)
        assert (
            await store.claim_consumption(
                request_id=request_id,
                tenant_id="t1",
                consumed_by="mcp-call-not-granted",
            )
            == "not_granted"
        )
        assert await _consumed_rows(engine) == []
    finally:
        await engine.dispose()


async def test_first_claim_wins_and_second_claim_is_already_consumed(tmp_path: Any) -> None:
    store, engine = await _harness(tmp_path)
    try:
        request_id = await _seed(store, state="granted")
        assert (
            await store.claim_consumption(
                request_id=request_id,
                tenant_id="t1",
                consumed_by="mcp-call-first",
            )
            == "first_claim"
        )
        assert (
            await store.claim_consumption(
                request_id=request_id,
                tenant_id="t1",
                consumed_by="mcp-call-second",
            )
            == "already_consumed"
        )

        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    sa.select(
                        _approval_requests.c.consumed_at,
                        _approval_requests.c.consumed_by,
                    ).where(_approval_requests.c.request_id == request_id)
                )
            ).one()
        assert row.consumed_at is not None
        assert row.consumed_by == "mcp-call-first"
        consumed = await _consumed_rows(engine)
        assert len(consumed) == 1
        assert consumed[0].request_id == "mcp-call-first"
        assert consumed[0].payload == {
            "request_id": str(request_id),
            "consumed_by": "mcp-call-first",
            "tool_identity": "mcp:probe",
        }
    finally:
        await engine.dispose()


async def test_concurrent_claims_have_exactly_one_first_claim(tmp_path: Any) -> None:
    store, engine = await _harness(tmp_path)
    try:
        request_id = await _seed(store, state="granted")
        outcomes = await asyncio.gather(
            store.claim_consumption(
                request_id=request_id,
                tenant_id="t1",
                consumed_by="mcp-race-a",
            ),
            store.claim_consumption(
                request_id=request_id,
                tenant_id="t1",
                consumed_by="mcp-race-b",
            ),
        )
        assert outcomes.count("first_claim") == 1
        assert outcomes.count("already_consumed") == 1
        assert len(await _consumed_rows(engine)) == 1
    finally:
        await engine.dispose()


async def test_reconciler_query_returns_only_old_granted_unconsumed_rows(tmp_path: Any) -> None:
    store, engine = await _harness(tmp_path)
    try:
        old_unconsumed = await _seed(store, state="granted", tenant_id="t1")
        recent_unconsumed = await _seed(store, state="granted", tenant_id="t2")
        consumed = await _seed(store, state="granted", tenant_id="t3")
        pending = await _seed(store, state="pending", tenant_id="t4")
        cutoff = datetime(2026, 7, 16, 13, 0, tzinfo=UTC)
        async with engine.begin() as conn:
            await conn.execute(
                sa.update(_approval_requests)
                .where(_approval_requests.c.request_id.in_([old_unconsumed, consumed, pending]))
                .values(updated_at=cutoff - timedelta(seconds=1))
            )
            await conn.execute(
                sa.update(_approval_requests)
                .where(_approval_requests.c.request_id == recent_unconsumed)
                .values(updated_at=cutoff + timedelta(seconds=1))
            )
        await store.claim_consumption(
            request_id=consumed,
            tenant_id="t3",
            consumed_by="already-consumed",
        )
        assert await store.list_granted_unconsumed_before(cutoff=cutoff) == (
            (old_unconsumed, "t1"),
        )
    finally:
        await engine.dispose()


async def test_claim_rolls_back_when_consumed_evidence_cannot_append(tmp_path: Any) -> None:
    store, engine = await _harness(tmp_path)
    request_id = await _seed(store, state="granted")

    def _refuse_consumed_insert(
        _conn: Any,
        _cursor: Any,
        statement: str,
        _parameters: Any,
        _context: Any,
        _executemany: bool,
    ) -> None:
        if statement.lstrip().upper().startswith("INSERT INTO DECISION_HISTORY"):
            raise RuntimeError("forced approval.consumed evidence failure")

    sa.event.listen(engine.sync_engine, "before_cursor_execute", _refuse_consumed_insert)
    try:
        with pytest.raises(RuntimeError, match=r"forced approval\.consumed"):
            await store.claim_consumption(
                request_id=request_id,
                tenant_id="t1",
                consumed_by="mcp-evidence-failure",
            )
    finally:
        sa.event.remove(engine.sync_engine, "before_cursor_execute", _refuse_consumed_insert)

    try:
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    sa.select(
                        _approval_requests.c.consumed_at,
                        _approval_requests.c.consumed_by,
                    ).where(_approval_requests.c.request_id == request_id)
                )
            ).one()
        assert row.consumed_at is None
        assert row.consumed_by is None
        assert await _consumed_rows(engine) == []
    finally:
        await engine.dispose()


async def test_claim_is_tenant_scoped(tmp_path: Any) -> None:
    store, engine = await _harness(tmp_path)
    try:
        request_id = await _seed(store, state="granted", tenant_id="t1")
        assert (
            await store.claim_consumption(
                request_id=request_id,
                tenant_id="t2",
                consumed_by="mcp-cross-tenant",
            )
            == "not_granted"
        )
        assert await _consumed_rows(engine) == []
    finally:
        await engine.dispose()


async def test_engine_consume_verifies_then_claims_once(tmp_path: Any) -> None:
    store, engine = await _harness(tmp_path)
    approval = ApprovalEngine(
        policy=_SingleApprovalPolicy(),
        store=store,
        settings=build_settings_without_env_file(),
        clock=lambda: datetime(2026, 7, 16, 12, 0, tzinfo=UTC),
    )
    try:
        envelope = ApprovalEnvelope(
            risk_tier="customer_data_read",
            tool_identity="mcp:probe",
            originator_subject="analyst.amir",
            tenant_id="t1",
            data_classes=("internal",),
            args_digest=b"a" * 32,
            redacted_context="probe_write",
            required_refs={},
        )
        request = await approval.create_request(envelope=envelope)
        await approval.grant(
            request_id=request.request_id,
            tenant_id="t1",
            approver=ApprovalActor(
                subject="approver.dana",
                tenant_id="t1",
                scopes=frozenset({"tool.approve.customer_data"}),
                actor_type="human",
            ),
        )
        result = await approval.consume_grant_for_action(
            request_id=request.request_id,
            tenant_id="t1",
            expected_args_digest=b"a" * 32,
            expected_tool_identity="mcp:probe",
            expected_originator_subject="analyst.amir",
            consumed_by="mcp-engine-first",
        )
        assert result.state == "granted"

        with pytest.raises(ApprovalTransitionRefused) as wrong_actor:
            await approval.consume_grant_for_action(
                request_id=request.request_id,
                tenant_id="t1",
                expected_args_digest=b"a" * 32,
                expected_tool_identity="mcp:probe",
                expected_originator_subject="analyst.sara",
                consumed_by="mcp-engine-wrong-actor",
            )
        assert wrong_actor.value.reason == "approval_originator_mismatch"
        with pytest.raises(ApprovalTransitionRefused) as wrong_binding:
            await approval.consume_grant_for_action(
                request_id=request.request_id,
                tenant_id="t1",
                expected_args_digest=b"b" * 32,
                expected_tool_identity="mcp:probe",
                expected_originator_subject="analyst.amir",
                consumed_by="mcp-engine-wrong-binding",
            )
        assert wrong_binding.value.reason == "approval_binding_mismatch"

        with pytest.raises(ApprovalTransitionRefused) as exc_info:
            await approval.consume_grant_for_action(
                request_id=request.request_id,
                tenant_id="t1",
                expected_args_digest=b"a" * 32,
                expected_tool_identity="mcp:probe",
                expected_originator_subject="analyst.amir",
                consumed_by="mcp-engine-second",
            )
        assert exc_info.value.reason == "approval_consumed"
    finally:
        await engine.dispose()


async def test_engine_fails_closed_if_verified_grant_cannot_be_claimed(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, engine = await _harness(tmp_path)
    approval = ApprovalEngine(
        policy=_SingleApprovalPolicy(),
        store=store,
        settings=build_settings_without_env_file(),
        clock=lambda: datetime(2026, 7, 16, 12, 0, tzinfo=UTC),
    )
    try:
        request_id = await _seed(store, state="granted")
        monkeypatch.setattr(
            store,
            "claim_consumption",
            AsyncMock(return_value="not_granted"),
        )
        with pytest.raises(RuntimeError, match="became non-granted"):
            await approval.consume_grant_for_action(
                request_id=request_id,
                tenant_id="t1",
                expected_args_digest=b"a" * 32,
                expected_tool_identity="mcp:probe",
                expected_originator_subject="analyst.amir",
                consumed_by="mcp-impossible-race",
            )
    finally:
        await engine.dispose()
