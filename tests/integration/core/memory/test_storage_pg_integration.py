"""Sprint 11.5a T6 — ``PostgresMemoryAdapter`` live-Postgres proof.

Mirrors ``tests/integration/packs/test_storage_lock_serialisation.py``
(Sprint 7B.1 T3) for the env-gate + superuser-DSN + marker convention:

  - **Env-gated** via ``COGNIC_RUN_POSTGRES_INTEGRATION=1`` + the matching
    ``COGNIC_DATABASE_URL_POSTGRES_TEST`` superuser DSN. Without those, the
    test self-skips cleanly (0 errors) so the unit suite stays fast +
    hermetic.
  - **Superuser DSN** because the test resets chain + memory state via raw
    SQL. Same posture as the Sprint-2 / Sprint-2.5 / Sprint-7B.1 suites.

The ``PostgresMemoryAdapter`` is a ``DecisionHistoryStore.append_with_
precondition`` consumer: the per-write ``memory.write`` chain row is
inserted atomically with the ``memory_records`` row under the chain-head
``FOR UPDATE`` lock. This proof exercises the green path end-to-end on
real Postgres — ``put()`` then ``get()`` round-trips the value through the
``memory_records.value`` column, and the chain row carries the
``redacted_value_digest`` (never the raw value).
"""

from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import delete, select, text, update
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import DecisionHistoryStore, _decision_history
from cognic_agentos.core.memory.storage import PostgresMemoryAdapter, _memory_records
from tests.unit.core.memory._builders import SUBJECT, _task_record

# ---- env-gate skipif -------------------------------------------------


_PG_SKIPIF = pytest.mark.skipif(
    not (
        os.environ.get("COGNIC_RUN_POSTGRES_INTEGRATION")
        and os.environ.get("COGNIC_DATABASE_URL_POSTGRES_TEST")
    ),
    reason=(
        "live Postgres required; set COGNIC_RUN_POSTGRES_INTEGRATION=1 "
        "+ apply migrations + export COGNIC_DATABASE_URL_POSTGRES_TEST"
    ),
)


def _superuser_url() -> str:
    return os.environ["COGNIC_DATABASE_URL_POSTGRES_TEST"]


async def _reset_state(engine: AsyncEngine) -> None:
    """Ensure chain + memory tables exist; wipe rows; reset the
    ``decision_history`` chain head to genesis. Each run starts from a
    clean baseline.

    The ``memory_records`` Table lives on a distinct ``MetaData`` from the
    Sprint-2 chain tables, so both ``create_all`` calls are required
    (``checkfirst`` makes them harmless if the migration already ran)."""

    async with engine.begin() as conn:
        await conn.run_sync(_metadata.create_all)  # chain tables
        await conn.run_sync(_memory_records.metadata.create_all)  # memory_records
        await conn.execute(delete(_memory_records))
        await conn.execute(delete(_decision_history))
        await conn.execute(
            update(_chain_heads)
            .where(_chain_heads.c.chain_id == "decision_history")
            .values(latest_sequence=0, latest_hash=ZERO_HASH)
        )


@pytest.mark.postgres
@_PG_SKIPIF
async def test_postgres_put_then_get_round_trips_value_and_emits_chain_row() -> None:
    """``put()`` persists the value in ``memory_records.value`` + emits one
    ``memory.write`` chain row atomically; ``get()`` reads the value back;
    the chain row carries the digest, never the raw value."""

    engine = create_async_engine(_superuser_url(), pool_size=2, max_overflow=0)
    try:
        await _reset_state(engine)
        store = PostgresMemoryAdapter(engine=engine, dh_store=DecisionHistoryStore(engine))

        rid = await store.put(_task_record(value="hello-pg", tenant_id="t1"))
        assert isinstance(rid, uuid.UUID)

        # get() round-trips the raw value out of memory_records.value.
        hit = await store.get(
            tenant_id="t1", agent_id="kyc", subject=SUBJECT, tier="task", key="greeting"
        )
        assert hit is not None
        assert hit.value == "hello-pg"
        assert hit.record_id == rid

        # Exactly one memory.write chain row; value never enters the chain.
        async with engine.connect() as conn:
            count = (
                await conn.execute(
                    text("SELECT COUNT(*) FROM decision_history WHERE event_type = 'memory.write'")
                )
            ).scalar_one()
            assert count == 1
            row = (
                await conn.execute(
                    select(_decision_history).where(
                        _decision_history.c.event_type == "memory.write"
                    )
                )
            ).one()
        assert "value" not in row.payload
        assert "redacted_value_digest" in row.payload
    finally:
        await engine.dispose()
