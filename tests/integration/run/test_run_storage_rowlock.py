"""Sprint 14A-A3a — RunRecordStore SELECT ... FOR UPDATE serialisation on real
Postgres + Oracle. Mirrors tests/integration/packs/test_storage_lock_serialisation.py
canary 1. Env-gated; per-test skipif self-skips without the live DB + DSN."""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest
from sqlalchemy import delete, text, update
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import _decision_history
from cognic_agentos.core.run._types import RunTransitionRefused
from cognic_agentos.core.run.storage import RunRecordStore, _runs

pytestmark = pytest.mark.asyncio

_PG_SKIPIF = pytest.mark.skipif(
    not (
        os.environ.get("COGNIC_RUN_POSTGRES_INTEGRATION")
        and os.environ.get("COGNIC_DATABASE_URL_POSTGRES_TEST")
    ),
    reason=(
        "live Postgres required; set COGNIC_RUN_POSTGRES_INTEGRATION=1 + apply "
        "migrations + export COGNIC_DATABASE_URL_POSTGRES_TEST"
    ),
)
_ORACLE_SKIPIF = pytest.mark.skipif(
    not (
        os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION")
        and os.environ.get("COGNIC_DATABASE_URL_ORACLE_TEST")
    ),
    reason=(
        "live Oracle XE required; set COGNIC_RUN_ORACLE_INTEGRATION=1 + apply "
        "migrations + export COGNIC_DATABASE_URL_ORACLE_TEST"
    ),
)


def _superuser_url(driver: str) -> str:
    return os.environ[f"COGNIC_DATABASE_URL_{driver.upper()}_TEST"]


async def _reset_state(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        await conn.execute(delete(_runs))
        await conn.execute(delete(_decision_history))
        await conn.execute(
            update(_chain_heads)
            .where(_chain_heads.c.chain_id == "decision_history")
            .values(latest_sequence=0, latest_hash=ZERO_HASH)
        )


async def _canary_row_lock_serialisation(driver: str) -> None:
    """Two concurrent transition(pending→running) for the same run — exactly one
    wins; the loser sees the advanced state and refuses
    run_transition_invalid_state_pair. Loser rolls back; chain count for
    run.lifecycle.% is exactly 2 (genesis pending + winner's running); final
    state is running."""
    engine = create_async_engine(_superuser_url(driver), pool_size=4, max_overflow=0)
    try:
        await _reset_state(engine)
        store = RunRecordStore(engine)
        run_id = uuid.uuid4()
        await store.create_run(
            run_id=run_id,
            tenant_id="t",
            pack_id="cognic-tool-canary",
            pack_uuid=uuid.uuid4(),
            pack_version="1.0.0",
            request_id="genesis",
        )

        async def _do(label: str) -> tuple[uuid.UUID, bytes] | RunTransitionRefused:
            try:
                return await store.transition(
                    run_id=run_id,
                    tenant_id="t",
                    from_state="pending",
                    to_state="running",
                    actor_id=label,
                    request_id=f"race-{label}",
                )
            except RunTransitionRefused as exc:
                return exc

        results = await asyncio.gather(_do("a"), _do("b"))
        wins = [r for r in results if not isinstance(r, RunTransitionRefused)]
        losses = [r for r in results if isinstance(r, RunTransitionRefused)]
        assert len(wins) == 1, f"expected one winner; got {results}"
        assert len(losses) == 1, f"expected one loser; got {results}"
        assert losses[0].reason == "run_transition_invalid_state_pair"

        async with engine.connect() as conn:
            chain_count = (
                await conn.execute(
                    text(
                        "SELECT COUNT(*) FROM decision_history "
                        "WHERE event_type LIKE 'run.lifecycle.%'"
                    )
                )
            ).scalar_one()
        assert chain_count == 2, f"expected 2 chain rows (pending+running); got {chain_count}"

        loaded = await store.load(run_id, tenant_id="t")
        assert loaded is not None and loaded.state == "running"
    finally:
        await engine.dispose()


@pytest.mark.postgres
@_PG_SKIPIF
async def test_postgres_row_lock_serialises_competing_transitions() -> None:
    await _canary_row_lock_serialisation("postgres")


@pytest.mark.oracle
@_ORACLE_SKIPIF
async def test_oracle_row_lock_serialises_competing_transitions() -> None:
    await _canary_row_lock_serialisation("oracle")
