"""Alembic migration round-trip on real Postgres + Oracle.

Sprint 2 Task 5 — schema-design verification. Each test does:

  alembic upgrade head   →   alembic downgrade base   →   alembic upgrade head

against a live database. The first upgrade creates the governance
tables; the downgrade drops them; the second upgrade proves the
migration is idempotent + reversible (catches op.create_table /
op.drop_table asymmetry, missing index drops, etc.).

Env-gated like the Sprint 1D oracle tests; runs only when the
matching ``COGNIC_RUN_*_INTEGRATION`` env var is set + the matching
compose service is up.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.db.types import GovernanceJSON

# Default DSNs match the Sprint-1C compose stack. Operators can
# override via the env var if their local stack uses different ports
# or credentials.
POSTGRES_URL = os.environ.get(
    "COGNIC_DATABASE_URL_POSTGRES_TEST",
    "postgresql+asyncpg://cognic:cognic_dev_only@localhost:5432/cognic",
)

ORACLE_URL = os.environ.get(
    "COGNIC_DATABASE_URL_ORACLE_TEST",
    "oracle+oracledb://cognic:cognic_dev_only@localhost:1521/?service_name=XEPDB1",
)


def _alembic(env_url: str, *args: str) -> subprocess.CompletedProcess[str]:
    """Run alembic with COGNIC_DATABASE_URL pinned to the test DSN.

    Returns the CompletedProcess on success; raises CalledProcessError
    on non-zero exit (each command is required to succeed).
    """

    env = os.environ.copy()
    env["COGNIC_DATABASE_URL"] = env_url
    return subprocess.run(
        ["uv", "run", "alembic", *args],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )


@pytest.mark.postgres
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_POSTGRES_INTEGRATION"),
    reason=(
        "live Postgres integration; opt in via "
        "COGNIC_RUN_POSTGRES_INTEGRATION=1 + compose up postgres"
    ),
)
def test_postgres_upgrade_downgrade_upgrade_roundtrip() -> None:
    _alembic(POSTGRES_URL, "upgrade", "head")
    _alembic(POSTGRES_URL, "downgrade", "base")
    _alembic(POSTGRES_URL, "upgrade", "head")


@pytest.mark.oracle
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION"),
    reason=(
        "live Oracle XE integration; opt in via COGNIC_RUN_ORACLE_INTEGRATION=1 + compose up oracle"
    ),
)
def test_oracle_upgrade_downgrade_upgrade_roundtrip() -> None:
    _alembic(ORACLE_URL, "upgrade", "head")
    _alembic(ORACLE_URL, "downgrade", "base")
    _alembic(ORACLE_URL, "upgrade", "head")


# ---------------------------------------------------------------------------
# M8.5-B (migration 0016) — SEEDED 0015 -> 0016 backfill on the LIVE engines.
#
# The sqlite unit suite (tests/unit/db/test_migration_20260710_0016.py) covers
# the failure classes; THESE tests exist because empty-schema roundtrips never
# exercise the PostgreSQL JSON / Oracle CLOB payload decoding the backfill
# depends on (maintainer ruling, 2026-07-10). Each test: downgrade base ->
# upgrade 0015 -> seed a real conversation + turn + its
# conversation.turn_completed chain row -> upgrade head -> assert the
# correlation column backfilled + constraints enforced -> ALSO prove the
# fail-loud orphan-turn class + re-runnability live -> clean up seeded rows,
# leaving the shared DB at head and empty.
# ---------------------------------------------------------------------------

_BF_TENANT = "t-0016-live"
_BF_CREATOR = "analyst.live"
_BF_COLUMN = "turn_completed_request_id"

_conversations_t = sa.table(
    "conversations",
    sa.column("conversation_id", sa.Uuid()),
    sa.column("tenant_id", sa.String(128)),
    sa.column("agent_id", sa.String(128)),
    sa.column("creator_subject", sa.String(256)),
    sa.column("state", sa.String(32)),
    sa.column("turn_count", sa.Integer()),
    sa.column("cumulative_tokens", sa.Integer()),
    sa.column("turn_in_progress", sa.Boolean()),
    sa.column("created_at", sa.TIMESTAMP(timezone=True)),
)
_turns_t = sa.table(
    "conversation_turns",
    sa.column("turn_id", sa.Uuid()),
    sa.column("conversation_id", sa.Uuid()),
    sa.column("seq", sa.Integer()),
    sa.column("user_message", sa.Text()),
    sa.column("answer", sa.Text()),
    sa.column("agent_run_id", sa.String(64)),
    sa.column("prompt_tokens", sa.Integer()),
    sa.column("completion_tokens", sa.Integer()),
    sa.column("created_at", sa.TIMESTAMP(timezone=True)),
    sa.column(_BF_COLUMN, sa.String(64)),
)
_dh_t = sa.table(
    "decision_history",
    sa.column("record_id", sa.Uuid()),
    sa.column("sequence", sa.BigInteger()),
    sa.column("schema_version", sa.SmallInteger()),
    sa.column("tenant_id", sa.String(64)),
    sa.column("prev_hash", sa.LargeBinary(32)),
    sa.column("hash", sa.LargeBinary(32)),
    sa.column("created_at", sa.TIMESTAMP(timezone=True)),
    sa.column("event_type", sa.String(64)),
    sa.column("request_id", sa.String(64)),
    # GovernanceJSON: the Oracle dialect has no generic sa.JSON processors;
    # the kernel's type serializes dicts to CLOB text itself.
    sa.column("payload", GovernanceJSON()),
)


async def _seed_0015_rows(
    url: str, *, orphan_extra_turn: bool
) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID | None, str]:
    """Seed one matched conversation+turn+chain row (payload as a JSON dict on
    the wire — native JSON on PostgreSQL, serialized into CLOB on Oracle) and
    optionally one ORPHAN turn (no chain row). The payload is a Python dict
    on BOTH databases — GovernanceJSON owns the per-dialect serialization
    (native JSON on PostgreSQL, CLOB text on Oracle)."""
    conversation_id, turn_id = uuid.uuid4(), uuid.uuid4()
    orphan_id: uuid.UUID | None = uuid.uuid4() if orphan_extra_turn else None
    request_id = f"conv-turn-{uuid.uuid4().hex}"
    payload = {
        "conversation_id": str(conversation_id),
        "turn_id": str(turn_id),
        "seq": 1,
        "agent_run_id": "agent-run-live-0016",
        "actor_id": _BF_CREATOR,
        "question_sha256": "0" * 64,
        "question_bytes": 1,
        "answer_sha256": "1" * 64,
        "answer_bytes": 1,
        "prompt_tokens": 1,
        "completion_tokens": 1,
    }
    engine = create_async_engine(url)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                sa.insert(_conversations_t).values(
                    conversation_id=conversation_id,
                    tenant_id=_BF_TENANT,
                    agent_id="bank-analyst",
                    creator_subject=_BF_CREATOR,
                    state="active",
                    turn_count=2 if orphan_extra_turn else 1,
                    cumulative_tokens=0,
                    turn_in_progress=False,
                    created_at=datetime.now(UTC),
                )
            )
            for seq, tid in [(1, turn_id)] + ([(2, orphan_id)] if orphan_extra_turn else []):
                await conn.execute(
                    sa.insert(_turns_t).values(
                        turn_id=tid,
                        conversation_id=conversation_id,
                        seq=seq,
                        user_message="q",
                        answer="a",
                        agent_run_id="agent-run-live-0016",
                        prompt_tokens=1,
                        completion_tokens=1,
                        created_at=datetime.now(UTC),
                    )
                )
            await conn.execute(
                sa.insert(_dh_t).values(
                    record_id=uuid.uuid4(),
                    sequence=900_001,
                    schema_version=1,
                    tenant_id=_BF_TENANT,
                    prev_hash=(1).to_bytes(32, "big"),
                    hash=(2).to_bytes(32, "big"),
                    created_at=datetime.now(UTC),
                    event_type="conversation.turn_completed",
                    request_id=request_id,
                    # A Python dict on BOTH databases: GovernanceJSON stores
                    # native JSON on PostgreSQL and serialized CLOB text on
                    # Oracle — both live decode paths are exercised.
                    payload=payload,
                )
            )
    finally:
        await engine.dispose()
    return conversation_id, turn_id, orphan_id, request_id


async def _fetch_backfilled(url: str, turn_id: uuid.UUID) -> tuple[str | None, bool]:
    engine = create_async_engine(url)
    try:
        async with engine.connect() as conn:
            value = (
                await conn.execute(
                    sa.select(_turns_t.c[_BF_COLUMN]).where(_turns_t.c.turn_id == turn_id)
                )
            ).scalar_one()
            nullable = await conn.run_sync(
                lambda sc: {c["name"]: c for c in sa.inspect(sc).get_columns("conversation_turns")}[
                    _BF_COLUMN
                ]["nullable"]
            )
        return value, bool(nullable)
    finally:
        await engine.dispose()


async def _delete_orphan_turn(url: str, orphan_id: uuid.UUID) -> None:
    engine = create_async_engine(url)
    try:
        async with engine.begin() as conn:
            await conn.execute(sa.delete(_turns_t).where(_turns_t.c.turn_id == orphan_id))
    finally:
        await engine.dispose()


async def _cleanup_seeded(url: str, conversation_id: uuid.UUID) -> None:
    engine = create_async_engine(url)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                sa.delete(_turns_t).where(_turns_t.c.conversation_id == conversation_id)
            )
            await conn.execute(
                sa.delete(_conversations_t).where(
                    _conversations_t.c.conversation_id == conversation_id
                )
            )
            await conn.execute(sa.delete(_dh_t).where(_dh_t.c.tenant_id == _BF_TENANT))
    finally:
        await engine.dispose()


def _seeded_backfill_roundtrip(url: str) -> None:
    """downgrade base -> 0015 -> seed (incl. one ORPHAN turn) -> head FAILS
    loud -> remove the orphan -> head completes + backfilled -> cleanup."""
    _alembic(url, "downgrade", "base")
    _alembic(url, "upgrade", "0015")
    conversation_id, turn_id, orphan_id, request_id = asyncio.run(
        _seed_0015_rows(url, orphan_extra_turn=True)
    )
    assert orphan_id is not None

    # The orphan-turn failure class fires LIVE (fail-loud, unstamped).
    with pytest.raises(subprocess.CalledProcessError) as exc:
        _alembic(url, "upgrade", "head")
    assert "0016 backfill: orphan turn" in (exc.value.stderr or "") + (exc.value.stdout or "")

    # Remove the orphan; the plain RE-RUN over the partial state completes.
    asyncio.run(_delete_orphan_turn(url, orphan_id))
    _alembic(url, "upgrade", "head")

    value, nullable = asyncio.run(_fetch_backfilled(url, turn_id))
    assert value == request_id
    assert nullable is False

    asyncio.run(_cleanup_seeded(url, conversation_id))


@pytest.mark.postgres
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_POSTGRES_INTEGRATION"),
    reason=(
        "live Postgres integration; opt in via "
        "COGNIC_RUN_POSTGRES_INTEGRATION=1 + compose up postgres"
    ),
)
def test_postgres_seeded_0016_backfill() -> None:
    _seeded_backfill_roundtrip(POSTGRES_URL)


@pytest.mark.oracle
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION"),
    reason=(
        "live Oracle XE integration; opt in via COGNIC_RUN_ORACLE_INTEGRATION=1 + compose up oracle"
    ),
)
def test_oracle_seeded_0016_backfill() -> None:
    _seeded_backfill_roundtrip(ORACLE_URL)


# ---------------------------------------------------------------------------
# 0017 (HP-4): the approval-queue index — live roundtrip + guard-skip rerun
# ---------------------------------------------------------------------------

_IDX_0017 = "ix_approval_requests_tenant_created_request"
_IDX_0017_COLUMNS = ["tenant_id", "created_at", "request_id"]


async def _approval_indexes(url: str) -> dict[str, dict[str, Any]]:
    engine = create_async_engine(url)
    try:
        async with engine.connect() as conn:
            rows = await conn.run_sync(lambda sc: sa.inspect(sc).get_indexes("approval_requests"))
        return {str(i["name"]).lower(): dict(i) for i in rows}
    finally:
        await engine.dispose()


async def _stamp_version(url: str, revision: str) -> None:
    engine = create_async_engine(url)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                sa.text("UPDATE alembic_version SET version_num = :rev"), {"rev": revision}
            )
    finally:
        await engine.dispose()


def _index_roundtrip_0017(url: str) -> None:
    """head -> assert exact shape -> stamped fully-applied RERUN (the guard
    must skip live, not raise) -> downgrade 0016 removes ONLY the index ->
    head recreates it."""
    _alembic(url, "upgrade", "head")
    idx = asyncio.run(_approval_indexes(url))
    assert _IDX_0017 in idx
    assert [str(c).lower() for c in idx[_IDX_0017]["column_names"]] == _IDX_0017_COLUMNS
    assert not idx[_IDX_0017]["unique"]

    asyncio.run(_stamp_version(url, "0016"))
    _alembic(url, "upgrade", "head")  # fully-applied rerun: guard-skip, no raise
    assert _IDX_0017 in asyncio.run(_approval_indexes(url))

    _alembic(url, "downgrade", "0016")
    assert _IDX_0017 not in asyncio.run(_approval_indexes(url))
    _alembic(url, "upgrade", "head")
    assert _IDX_0017 in asyncio.run(_approval_indexes(url))


@pytest.mark.postgres
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_POSTGRES_INTEGRATION"),
    reason=(
        "live Postgres integration; opt in via "
        "COGNIC_RUN_POSTGRES_INTEGRATION=1 + compose up postgres"
    ),
)
def test_postgres_0017_index_roundtrip() -> None:
    _index_roundtrip_0017(POSTGRES_URL)


@pytest.mark.oracle
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION"),
    reason=(
        "live Oracle XE integration; opt in via COGNIC_RUN_ORACLE_INTEGRATION=1 + compose up oracle"
    ),
)
def test_oracle_0017_index_roundtrip() -> None:
    _index_roundtrip_0017(ORACLE_URL)
