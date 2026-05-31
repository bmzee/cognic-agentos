from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import DecisionHistoryStore, _decision_history
from cognic_agentos.core.memory.storage import PostgresMemoryAdapter, _memory_records


@pytest.fixture
async def _mem_engine(tmp_path):
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'memory.db'}")
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)  # core chain tables
        await conn.run_sync(_memory_records.metadata.create_all)  # memory_records table (+ CHECK)
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
def dh_store(_mem_engine):
    return DecisionHistoryStore(_mem_engine)


@pytest.fixture
def memory_adapter(_mem_engine, dh_store):
    return PostgresMemoryAdapter(engine=_mem_engine, dh_store=dh_store)


@pytest.fixture
def decision_history_rows(_mem_engine):
    # Zero-arg async reader of all decision_history rows ordered by sequence.
    async def _read():
        async with _mem_engine.begin() as conn:
            result = await conn.execute(
                select(_decision_history).order_by(_decision_history.c.sequence)
            )
            return list(result.all())

    return _read
