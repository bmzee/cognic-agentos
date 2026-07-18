from __future__ import annotations

import asyncio
import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.approval.replay import (
    ApprovalReplayStore,
    ApprovalReplayUnavailable,
    _approval_replay_payloads,
)
from cognic_agentos.core.approval.storage import ApprovalRequestStore
from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.decision_history import DecisionHistoryStore


async def _stores(
    tmp_path: Any,
) -> tuple[ApprovalReplayStore, ApprovalRequestStore, AsyncEngine]:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'replay.db'}"
    await asyncio.to_thread(command.upgrade, make_alembic_config(url), "head")
    engine = create_async_engine(url)
    return (
        ApprovalReplayStore(engine),
        ApprovalRequestStore(DecisionHistoryStore(engine)),
        engine,
    )


async def _request(store: ApprovalRequestStore, *, tenant_id: str = "t1") -> uuid.UUID:
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
        request_request_id=f"replay-test-{request_id.hex}",
        created_at=now,
        expires_at=now,
        required_count=1,
    )
    return request_id


def _args() -> tuple[bytes, bytes]:
    payload = canonical_bytes({"amount": 10, "currency": "USD"})
    return payload, hashlib.sha256(payload).digest()


async def test_persist_and_load_returns_exact_approved_bytes(tmp_path: Any) -> None:
    replay, requests, engine = await _stores(tmp_path)
    try:
        request_id = await _request(requests)
        payload, digest = _args()
        await replay.persist(
            request_id=request_id,
            tenant_id="t1",
            canonical_args=payload,
            args_digest=digest,
        )

        assert await replay.load(request_id=request_id, tenant_id="t1") == payload
    finally:
        await engine.dispose()


async def test_persist_recomputes_digest_and_refuses_mismatch(tmp_path: Any) -> None:
    replay, requests, engine = await _stores(tmp_path)
    try:
        request_id = await _request(requests)
        payload, _digest = _args()
        with pytest.raises(ApprovalReplayUnavailable) as exc_info:
            await replay.persist(
                request_id=request_id,
                tenant_id="t1",
                canonical_args=payload,
                args_digest=b"x" * 32,
            )
        assert exc_info.value.reason == "replay_digest_mismatch"
        async with engine.connect() as conn:
            count = await conn.scalar(
                sa.select(sa.func.count()).select_from(_approval_replay_payloads)
            )
        assert count == 0
    finally:
        await engine.dispose()


async def test_request_replay_and_chain_write_roll_back_together_on_digest_failure(
    tmp_path: Any,
) -> None:
    _replay, requests, engine = await _stores(tmp_path)
    try:
        request_id = uuid.uuid4()
        now = datetime(2026, 7, 16, 12, 0, tzinfo=UTC)
        with pytest.raises(ApprovalReplayUnavailable) as exc_info:
            await requests.create_request_row(
                request_id=request_id,
                tenant_id="t1",
                flow="require_single_approval",
                risk_tier="customer_data_write",
                tool_identity="mcp:probe",
                originator_subject="analyst.amir",
                envelope_digest=b"e" * 32,
                args_digest=b"a" * 32,
                redacted_context="probe_write",
                data_classes=["internal"],
                required_refs={},
                request_request_id="replay-atomicity",
                created_at=now,
                expires_at=now,
                required_count=1,
                replay_payload=b"wrong bytes",
            )
        assert exc_info.value.reason == "replay_digest_mismatch"
        async with engine.connect() as conn:
            request_count = await conn.scalar(
                sa.text("SELECT COUNT(*) FROM approval_requests WHERE request_id = :rid"),
                {"rid": request_id.hex},
            )
            replay_count = await conn.scalar(
                sa.select(sa.func.count()).select_from(_approval_replay_payloads)
            )
            chain_count = await conn.scalar(
                sa.text("SELECT COUNT(*) FROM decision_history WHERE request_id = :rid"),
                {"rid": "replay-atomicity"},
            )
        assert (request_count, replay_count, chain_count) == (0, 0, 0)
    finally:
        await engine.dispose()


async def test_load_recomputes_digest_and_refuses_stored_byte_drift(tmp_path: Any) -> None:
    replay, requests, engine = await _stores(tmp_path)
    try:
        request_id = await _request(requests)
        payload, digest = _args()
        await replay.persist(
            request_id=request_id,
            tenant_id="t1",
            canonical_args=payload,
            args_digest=digest,
        )
        async with engine.begin() as conn:
            await conn.execute(
                sa.update(_approval_replay_payloads)
                .where(_approval_replay_payloads.c.request_id == request_id)
                .values(canonical_args=payload + b"!")
            )

        with pytest.raises(ApprovalReplayUnavailable) as exc_info:
            await replay.load(request_id=request_id, tenant_id="t1")
        assert exc_info.value.reason == "replay_digest_mismatch"
    finally:
        await engine.dispose()


async def test_load_refuses_null_arguments_without_an_erasure_stamp(tmp_path: Any) -> None:
    replay, requests, engine = await _stores(tmp_path)
    try:
        request_id = await _request(requests)
        payload, digest = _args()
        await replay.persist(
            request_id=request_id,
            tenant_id="t1",
            canonical_args=payload,
            args_digest=digest,
        )
        async with engine.begin() as conn:
            await conn.execute(
                sa.update(_approval_replay_payloads)
                .where(_approval_replay_payloads.c.request_id == request_id)
                .values(canonical_args=None)
            )

        with pytest.raises(ApprovalReplayUnavailable) as exc_info:
            await replay.load(request_id=request_id, tenant_id="t1")
        assert exc_info.value.reason == "replay_digest_mismatch"
    finally:
        await engine.dispose()


async def test_load_is_tenant_scoped_and_absent_collapses(tmp_path: Any) -> None:
    replay, requests, engine = await _stores(tmp_path)
    try:
        request_id = await _request(requests, tenant_id="t1")
        payload, digest = _args()
        await replay.persist(
            request_id=request_id,
            tenant_id="t1",
            canonical_args=payload,
            args_digest=digest,
        )
        for tenant_id in ("t2", "unknown"):
            with pytest.raises(ApprovalReplayUnavailable) as exc_info:
                await replay.load(request_id=request_id, tenant_id=tenant_id)
            assert exc_info.value.reason == "replay_not_persisted"
    finally:
        await engine.dispose()


async def test_result_round_trip_recomputes_digest_on_read(tmp_path: Any) -> None:
    replay, requests, engine = await _stores(tmp_path)
    try:
        request_id = await _request(requests)
        payload, digest = _args()
        await replay.persist(
            request_id=request_id,
            tenant_id="t1",
            canonical_args=payload,
            args_digest=digest,
        )
        assert await replay.load_result(request_id=request_id, tenant_id="t1") is None

        result = canonical_bytes({"status": "ok"})
        executed_at = datetime(2026, 7, 16, 12, 1, tzinfo=UTC)
        await replay.record_result(
            request_id=request_id,
            tenant_id="t1",
            result_canonical=result,
            executed_at=executed_at,
        )
        assert await replay.load_result(request_id=request_id, tenant_id="t1") == result

        async with engine.begin() as conn:
            await conn.execute(
                sa.update(_approval_replay_payloads)
                .where(_approval_replay_payloads.c.request_id == request_id)
                .values(result_canonical=result + b"!")
            )
        with pytest.raises(ApprovalReplayUnavailable) as exc_info:
            await replay.load_result(request_id=request_id, tenant_id="t1")
        assert exc_info.value.reason == "replay_digest_mismatch"
    finally:
        await engine.dispose()


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("result_canonical", None),
        ("result_digest", None),
    ],
)
async def test_load_result_refuses_inconsistent_value_digest_pair(
    tmp_path: Any,
    column: str,
    value: None,
) -> None:
    replay, requests, engine = await _stores(tmp_path)
    try:
        request_id = await _request(requests)
        payload, digest = _args()
        result = canonical_bytes({"status": "ok"})
        await replay.persist(
            request_id=request_id,
            tenant_id="t1",
            canonical_args=payload,
            args_digest=digest,
        )
        await replay.record_result(
            request_id=request_id,
            tenant_id="t1",
            result_canonical=result,
            executed_at=datetime(2026, 7, 16, 12, 1, tzinfo=UTC),
        )
        async with engine.begin() as conn:
            await conn.execute(
                sa.update(_approval_replay_payloads)
                .where(_approval_replay_payloads.c.request_id == request_id)
                .values({column: value})
            )

        with pytest.raises(ApprovalReplayUnavailable) as exc_info:
            await replay.load_result(request_id=request_id, tenant_id="t1")
        assert exc_info.value.reason == "replay_digest_mismatch"
    finally:
        await engine.dispose()


async def test_load_result_collapses_absent_and_cross_tenant(tmp_path: Any) -> None:
    replay, requests, engine = await _stores(tmp_path)
    try:
        request_id = await _request(requests)
        for tenant_id in ("t1", "t2"):
            with pytest.raises(ApprovalReplayUnavailable) as exc_info:
                await replay.load_result(request_id=request_id, tenant_id=tenant_id)
            assert exc_info.value.reason == "replay_not_persisted"
    finally:
        await engine.dispose()


async def test_erase_nulls_values_but_retains_row_and_digests(tmp_path: Any) -> None:
    replay, requests, engine = await _stores(tmp_path)
    try:
        request_id = await _request(requests)
        payload, digest = _args()
        result = canonical_bytes({"status": "ok"})
        await replay.persist(
            request_id=request_id,
            tenant_id="t1",
            canonical_args=payload,
            args_digest=digest,
        )
        await replay.record_result(
            request_id=request_id,
            tenant_id="t1",
            result_canonical=result,
            executed_at=datetime(2026, 7, 16, 12, 1, tzinfo=UTC),
        )

        assert await replay.erase(request_id=request_id, tenant_id="t1") is True
        assert await replay.erase(request_id=request_id, tenant_id="t1") is False
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    sa.select(_approval_replay_payloads).where(
                        _approval_replay_payloads.c.request_id == request_id
                    )
                )
            ).one()
        assert row.canonical_args is None
        assert row.result_canonical is None
        assert row.args_digest == digest
        assert row.result_digest == hashlib.sha256(result).digest()
        assert row.erased_at is not None
        with pytest.raises(ApprovalReplayUnavailable) as exc_info:
            await replay.load(request_id=request_id, tenant_id="t1")
        assert exc_info.value.reason == "replay_erased"
        with pytest.raises(ApprovalReplayUnavailable) as result_exc:
            await replay.load_result(request_id=request_id, tenant_id="t1")
        assert result_exc.value.reason == "replay_erased"
    finally:
        await engine.dispose()


async def test_record_result_refuses_absent_or_erased_replay(tmp_path: Any) -> None:
    replay, requests, engine = await _stores(tmp_path)
    try:
        request_id = await _request(requests)
        with pytest.raises(ApprovalReplayUnavailable) as absent:
            await replay.record_result(
                request_id=request_id,
                tenant_id="t1",
                result_canonical=b"{}",
                executed_at=datetime.now(UTC),
            )
        assert absent.value.reason == "replay_not_persisted"

        payload, digest = _args()
        await replay.persist(
            request_id=request_id,
            tenant_id="t1",
            canonical_args=payload,
            args_digest=digest,
        )
        assert await replay.erase(request_id=request_id, tenant_id="t1") is True
        with pytest.raises(ApprovalReplayUnavailable) as erased:
            await replay.record_result(
                request_id=request_id,
                tenant_id="t1",
                result_canonical=b"{}",
                executed_at=datetime.now(UTC),
            )
        assert erased.value.reason == "replay_erased"
    finally:
        await engine.dispose()
