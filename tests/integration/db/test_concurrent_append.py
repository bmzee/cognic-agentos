"""Concurrent-append serialisation proof on real Postgres + Oracle.

Sprint 2 Task 12 — production-grade verification that the
``governance_chain_heads`` ``SELECT ... FOR UPDATE`` lock actually
serialises concurrent appenders into a contiguous, hash-linked chain.

SQLite cannot prove this locally (no row-level locking — the unit
suite exercises shape only). On Postgres + Oracle the FOR UPDATE
primitive is the production guarantee; this test fires
``NUM_CONCURRENT`` parallel ``Store.append()`` calls via
``asyncio.gather`` and asserts:

  1. **All N appends succeed** — none raise. (A broken lock would
     surface as the compare-and-set ``rowcount != 1`` error
     ``AuditStore.append`` raises on chain-head drift.)
  2. **All record_ids are distinct.** No two appenders shared a
     UUID, which would corrupt evidence.
  3. **All hashes are distinct.** Two rows hashing to the same value
     means either the canonical envelope collided or the chain was
     desynced — both are critical-controls failures.
  4. **Sequences are exactly ``1..N`` contiguous.** Proves no
     appender skipped or reused a sequence under contention.
  5. **ChainVerifier.walk() reports clean.** End-to-end the chain
     re-verifies under read-only audit traversal (the chain-head
     row also moved to ``(N, last_hash)`` so the head_mismatch check
     is also covered).

Test setup uses a **superuser** DSN (``COGNIC_DATABASE_URL_*_TEST``)
because the test resets chain state to genesis via raw SQL —
``DELETE FROM <evidence>`` + ``UPDATE governance_chain_heads SET
latest_sequence=0, latest_hash=<ZERO_HASH>``. Per the user's
"only ``Store.append()`` mutates ``governance_chain_heads``" rule:
that constraint is a **runtime / production** invariant, enforced
by the operator runbook + the runtime-role canary in
``test_runtime_role_is_append_only.py``. Test infrastructure that
needs a clean slate before each parameterisation is allowed to
reset state via raw SQL through a superuser DSN — exactly the same
posture as ``alembic downgrade base; alembic upgrade head``.

**Local self-skip.** Tests opt in via
``COGNIC_RUN_POSTGRES_INTEGRATION=1`` (or
``COGNIC_RUN_ORACLE_INTEGRATION=1``) + the matching superuser DSN
env var. Without those the tests self-skip cleanly so the unit
suite stays fast and hermetic.
"""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest
from sqlalchemy import delete, text, update
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import (
    AuditEvent,
    AuditStore,
    _audit_event,
    _chain_heads,
)
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.chain_verifier import ChainVerifier
from cognic_agentos.core.decision_history import (
    DecisionHistoryStore,
    DecisionRecord,
    _decision_history,
)

#: How many concurrent appenders to fire. 50 is the sweet spot for
#: PG+Oracle CI under default container limits — large enough to
#: actually exercise contention (a single chain-head row → 50
#: serialised commits), small enough that the test wall-time stays
#: under ~5s on PG / ~30s on Oracle XE.
NUM_CONCURRENT: int = 50


def _superuser_url(driver: str) -> str:
    """Read the superuser DSN env var. Tests calling this guard with
    ``@pytest.mark.skipif`` so the env var is always present."""

    return os.environ[f"COGNIC_DATABASE_URL_{driver.upper()}_TEST"]


def _evidence_table(chain_id: str):  # type: ignore[no-untyped-def]
    return _audit_event if chain_id == "audit_event" else _decision_history


async def _reset_chain_state(engine: AsyncEngine, chain_id: str) -> None:
    """Wipe evidence rows + reset the chain head to genesis.

    Superuser-only — uses raw chain_heads UPDATE which the runtime
    role intentionally does not have outside the production
    ``Store.append`` path. Each parametrised test case starts from
    the same (sequence=0, hash=ZERO_HASH) baseline so independent
    parameterisations don't interfere.
    """

    evidence = _evidence_table(chain_id)
    async with engine.begin() as conn:
        await conn.execute(delete(evidence))
        await conn.execute(
            update(_chain_heads)
            .where(_chain_heads.c.chain_id == chain_id)
            .values(latest_sequence=0, latest_hash=ZERO_HASH)
        )


async def _do_one_append(
    engine: AsyncEngine, chain_id: str, *, request_id: str
) -> tuple[uuid.UUID, bytes]:
    """Drive a single Store.append for the parametrised chain. Used
    by ``asyncio.gather`` to spawn ``NUM_CONCURRENT`` of these in
    parallel against the shared engine pool."""

    if chain_id == "audit_event":
        return await AuditStore(engine).append(
            AuditEvent(
                event_type="concurrent_canary",
                request_id=request_id,
                payload={"k": "v", "rid": request_id},
            )
        )
    return await DecisionHistoryStore(engine).append(
        DecisionRecord(
            decision_type="concurrent_canary",
            request_id=request_id,
            payload={"k": "v", "rid": request_id},
        )
    )


async def _canary_concurrent_append(driver: str, chain_id: str) -> None:
    """Shared canary body — both PG + Oracle reuse this.

    Reset → fire NUM_CONCURRENT parallel appends → assert distinct
    record_ids, distinct hashes, contiguous 1..N sequences, chain
    walks clean.
    """

    # The pool needs to have at least NUM_CONCURRENT slots so
    # genuine concurrent transactions can race; otherwise gather()
    # serialises them at the pool layer and we're not actually
    # testing FOR UPDATE.
    engine = create_async_engine(
        _superuser_url(driver),
        pool_size=NUM_CONCURRENT,
        max_overflow=0,
    )
    try:
        await _reset_chain_state(engine, chain_id)

        results: list[tuple[uuid.UUID, bytes]] = await asyncio.gather(
            *[
                _do_one_append(
                    engine,
                    chain_id,
                    request_id=f"concurrent-{driver}-{chain_id}-{i:03d}",
                )
                for i in range(NUM_CONCURRENT)
            ]
        )

        record_ids = {r[0] for r in results}
        hashes = {r[1] for r in results}
        assert len(record_ids) == NUM_CONCURRENT, (
            f"expected {NUM_CONCURRENT} distinct record_ids; got {len(record_ids)}"
        )
        assert len(hashes) == NUM_CONCURRENT, (
            f"expected {NUM_CONCURRENT} distinct hashes; got {len(hashes)}"
        )

        # Verify sequences are exactly 1..NUM_CONCURRENT contiguous.
        evidence = _evidence_table(chain_id)
        async with engine.connect() as conn:
            seq_rows = (
                await conn.execute(
                    text(f"SELECT sequence FROM {evidence.name} ORDER BY sequence ASC")
                )
            ).all()
        sequences = [int(r.sequence) for r in seq_rows]
        assert sequences == list(range(1, NUM_CONCURRENT + 1)), (
            f"sequences not contiguous 1..{NUM_CONCURRENT}: {sequences}"
        )

        # End-to-end chain walk. ChainVerifier acquires its own
        # FOR UPDATE on chain_heads before the evidence-row scan, so
        # this also exercises the snapshot-safety primitive against a
        # chain that just finished racing NUM_CONCURRENT writers.
        report = await ChainVerifier(engine, chain_id).walk()
        assert report.is_clean is True, (
            f"chain dirty after {NUM_CONCURRENT} concurrent appends: {report}"
        )
        assert report.records_checked == NUM_CONCURRENT
    finally:
        await engine.dispose()


# ---- Postgres ------------------------------------------------------


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


@pytest.mark.postgres
@_PG_SKIPIF
@pytest.mark.parametrize("chain_id", ["audit_event", "decision_history"])
async def test_postgres_concurrent_append_serialises(chain_id: str) -> None:
    await _canary_concurrent_append("postgres", chain_id)


# ---- Oracle --------------------------------------------------------


_ORACLE_SKIPIF = pytest.mark.skipif(
    not (
        os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION")
        and os.environ.get("COGNIC_DATABASE_URL_ORACLE_TEST")
    ),
    reason=(
        "live Oracle XE required; set COGNIC_RUN_ORACLE_INTEGRATION=1 "
        "+ apply migrations + export COGNIC_DATABASE_URL_ORACLE_TEST"
    ),
)


@pytest.mark.oracle
@_ORACLE_SKIPIF
@pytest.mark.parametrize("chain_id", ["audit_event", "decision_history"])
async def test_oracle_concurrent_append_serialises(chain_id: str) -> None:
    await _canary_concurrent_append("oracle", chain_id)
