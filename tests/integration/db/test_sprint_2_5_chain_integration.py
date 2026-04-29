"""Sprint 2.5 live-DB integration tests — escalation lifecycle +
chain integrity on real Postgres + Oracle.

End-to-end proof that the Sprint-2.5 escalation primitives produce
hash-chained ``decision_history`` rows that walk clean under
``ChainVerifier``, AND that the read-side projection agrees with
the chain end-state. Mirrors Sprint 2's integration-test shape
(``test_concurrent_append.py`` / ``test_runtime_role_is_append_only.py``):

  - Env-gated via ``COGNIC_RUN_POSTGRES_INTEGRATION=1`` /
    ``COGNIC_RUN_ORACLE_INTEGRATION=1`` + the corresponding
    ``COGNIC_DATABASE_URL_*_TEST`` superuser DSN. Without those,
    the tests self-skip cleanly so the unit suite stays hermetic.
  - Uses the SUPERUSER DSN (not the runtime-role DSN) because the
    test resets chain state via raw SQL — same posture as Sprint 2
    T12's concurrent-append canary.

T8 in this file: deterministic sequential lifecycle proof (open →
ack → assigned → resolved). T9 (live race) and T10 (guardrail
trip) extend this file in subsequent commits.
"""

from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.chain_verifier import ChainVerifier
from cognic_agentos.core.decision_history import _decision_history
from cognic_agentos.core.escalation import EscalationState, EscalationStore


def _superuser_url(driver: str) -> str:
    """Read the superuser DSN env var. Tests calling this guard with
    ``@pytest.mark.skipif`` so the env var is always present."""

    return os.environ[f"COGNIC_DATABASE_URL_{driver.upper()}_TEST"]


async def _reset_decision_history(engine: AsyncEngine) -> None:
    """Wipe decision_history rows + reset the chain head to genesis.

    Superuser-only — uses raw chain_heads UPDATE which the runtime
    role intentionally does not have outside the production
    ``Store.append`` path. Sprint-2 T12 introduced this posture for
    the concurrent-append canary; T8 reuses it so each parametrised
    test case starts from a clean (sequence=0, hash=ZERO_HASH)
    baseline.
    """

    async with engine.begin() as conn:
        await conn.execute(delete(_decision_history))
        await conn.execute(
            update(_chain_heads)
            .where(_chain_heads.c.chain_id == "decision_history")
            .values(latest_sequence=0, latest_hash=ZERO_HASH)
        )


async def _drive_full_lifecycle(store: EscalationStore) -> uuid.UUID:
    """Drive an escalation through the full lifecycle:
    open → acknowledged → assigned → resolved. Returns the
    escalation_id."""

    eid, _, _ = await store.open(
        actor_id="canary",
        level="p1",
        reason="canary-escalation",
        request_id="req-t8-canary-open",
    )
    await store.transition(
        escalation_id=eid,
        actor_id="canary",
        new_state=EscalationState.ACKNOWLEDGED,
        reason="ack",
        request_id="req-t8-canary-ack",
    )
    await store.transition(
        escalation_id=eid,
        actor_id="canary",
        new_state=EscalationState.ASSIGNED,
        reason="assign",
        request_id="req-t8-canary-assign",
    )
    await store.transition(
        escalation_id=eid,
        actor_id="canary",
        new_state=EscalationState.RESOLVED,
        reason="done",
        request_id="req-t8-canary-resolve",
    )
    return eid


async def _assert_lifecycle_landed_clean(
    engine: AsyncEngine, store: EscalationStore, eid: uuid.UUID
) -> None:
    """Shared assertion body: 4 rows landed, event_type sequence
    matches the documented lifecycle, ChainVerifier walks clean,
    and the read-side projection agrees with the chain."""

    # 1. Four decision_history rows for the escalation, in chain
    #    sequence order, with the documented event_type sequence.
    async with engine.connect() as conn:
        rows = (
            await conn.execute(
                select(
                    _decision_history.c.event_type,
                    _decision_history.c.sequence,
                ).order_by(_decision_history.c.sequence)
            )
        ).all()
    assert len(rows) == 4, f"expected 4 decision_history rows for the lifecycle; got {len(rows)}"
    assert [r.event_type for r in rows] == [
        "escalation.opened",
        "escalation.acknowledged",
        "escalation.assigned",
        "escalation.resolved",
    ], f"event_type sequence mismatch: {[r.event_type for r in rows]!r}"
    # Sequences are contiguous 1..4 (the chain advanced one row per
    # transition + the open).
    assert [int(r.sequence) for r in rows] == [1, 2, 3, 4]

    # 2. ChainVerifier walks the decision_history chain clean —
    #    every row's hash matches its envelope, prev_hash linkage
    #    holds, head_mismatch is absent.
    report = await ChainVerifier(engine, "decision_history").walk()
    assert report.is_clean is True, f"chain dirty after escalation lifecycle: {report}"
    assert report.records_checked == 4

    # 3. Read-side projection agrees with the chain end-state. The
    #    transitions tuple has 4 entries (genesis + 3 transitions),
    #    current_state is RESOLVED.
    proj = await store.get_by_id(eid)
    assert proj.escalation_id == eid
    assert proj.current_state == EscalationState.RESOLVED
    assert len(proj.transitions) == 4
    # Per-transition shape: (from, to, at, actor_id) — oldest first.
    to_states = [t[1] for t in proj.transitions]
    assert to_states == [
        EscalationState.OPEN,
        EscalationState.ACKNOWLEDGED,
        EscalationState.ASSIGNED,
        EscalationState.RESOLVED,
    ]
    # The genesis row carries from=None; subsequent rows carry the
    # in-lock-captured prior state.
    assert proj.transitions[0][0] is None
    assert proj.transitions[1][0] == EscalationState.OPEN
    assert proj.transitions[2][0] == EscalationState.ACKNOWLEDGED
    assert proj.transitions[3][0] == EscalationState.ASSIGNED


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
async def test_escalation_lifecycle_walks_clean_postgres() -> None:
    """Live Postgres: full lifecycle emits 4 hash-chained rows;
    chain walks clean; read-side projection agrees."""

    engine = create_async_engine(_superuser_url("postgres"))
    try:
        await _reset_decision_history(engine)
        store = EscalationStore(engine)
        eid = await _drive_full_lifecycle(store)
        await _assert_lifecycle_landed_clean(engine, store, eid)
    finally:
        await engine.dispose()


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
async def test_escalation_lifecycle_walks_clean_oracle() -> None:
    """Live Oracle XE: full lifecycle emits 4 hash-chained rows;
    chain walks clean; read-side projection agrees."""

    engine = create_async_engine(_superuser_url("oracle"))
    try:
        await _reset_decision_history(engine)
        store = EscalationStore(engine)
        eid = await _drive_full_lifecycle(store)
        await _assert_lifecycle_landed_clean(engine, store, eid)
    finally:
        await engine.dispose()
