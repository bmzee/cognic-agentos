"""Shared async fixtures for the sub-agent unit tests. engine + chain-head
seeding mirror tests/unit/core/test_decision_history.py:37-70."""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import DecisionHistoryStore, _decision_history


@pytest.fixture
async def engine(tmp_path: Any) -> Any:
    url = f"sqlite+aiosqlite:///{tmp_path / 'subagent.db'}"
    eng: AsyncEngine = create_async_engine(url)
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id,
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=datetime.now(UTC),
                )
            )
    yield eng
    await eng.dispose()


@pytest.fixture
async def decision_store(engine: AsyncEngine) -> DecisionHistoryStore:
    return DecisionHistoryStore(engine)


@pytest.fixture
def decision_store_rows(engine: AsyncEngine) -> Callable[[], Awaitable[list[Any]]]:
    """Zero-arg async reader: all decision_history rows ordered by sequence."""

    async def _read() -> list[Any]:
        async with engine.begin() as conn:
            result = await conn.execute(
                select(_decision_history).order_by(_decision_history.c.sequence)
            )
            return list(result.all())

    return _read


@pytest.fixture
def insert_raw_decision_row(
    engine: AsyncEngine,
) -> Callable[..., Awaitable[None]]:
    """Fabricate a decision_history row with controlled columns, bypassing the
    hash-chain append. The linkage verifier is independent of the hash-walk, so
    a chain-detached row is still read by its SELECT — this reaches the negative
    cases (forward links, malformed parent_record_id) the in-order API cannot."""

    async def _insert(
        *,
        record_id: uuid.UUID,
        sequence: int,
        event_type: str,
        payload: dict[str, Any],
        tenant_id: str | None = None,
    ) -> None:
        async with engine.begin() as conn:
            await conn.execute(
                _decision_history.insert().values(
                    record_id=record_id,
                    sequence=sequence,
                    schema_version=1,
                    tenant_id=tenant_id,
                    prev_hash=ZERO_HASH,
                    hash=hashlib.sha256(str(record_id).encode()).digest(),
                    created_at=datetime.now(UTC),
                    event_type=event_type,
                    request_id="fab",
                    payload=payload,
                )
            )

    return _insert
