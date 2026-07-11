"""HP-4 (M8.5-C T1) — the reviewer-queue chronological keyset on live
PostgreSQL + Oracle.

The unit battery proves the keyset on the Alembic-migrated sqlite DB; this
lane proves the SAME builder against the real dialects the 0017 index and the
Oracle-portable tuple expansion exist for: equal-``created_at`` tiebreak, a
foreign-tenant decoy EARLIER than every visible row, ``limit=1`` cursor
walks with round-tripped opaque cursors, and a cursor-free final page.
Env-gated + self-cleaning, mirroring
``tests/integration/db/test_alembic_migrations.py``.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine

from cognic_agentos.core.approval.storage import ApprovalRequestStore, _approval_requests
from cognic_agentos.core.decision_history import DecisionHistoryStore

POSTGRES_URL = os.environ.get(
    "COGNIC_DATABASE_URL_POSTGRES_TEST",
    "postgresql+asyncpg://cognic:cognic_dev_only@localhost:5432/cognic",
)

ORACLE_URL = os.environ.get(
    "COGNIC_DATABASE_URL_ORACLE_TEST",
    "oracle+oracledb://cognic:cognic_dev_only@localhost:1521/?service_name=XEPDB1",
)

_TENANT = "t-keyset-live"
_DECOY_TENANT = "t-keyset-decoy"


def _alembic_head(env_url: str) -> None:
    env = os.environ.copy()
    env["COGNIC_DATABASE_URL"] = env_url
    subprocess.run(
        ["uv", "run", "alembic", "upgrade", "head"],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )


async def _seed_direct(
    conn: AsyncConnection, *, tenant: str, rid: uuid.UUID, when: datetime
) -> None:
    """Seed one ``pending`` row DIRECTLY into the migrated ``approval_requests``
    table — NOT via ``create_request_row``. This is a pure keyset QUERY test:
    it must not append hash-chained ``decision_history`` rows or advance
    ``governance_chain_heads``, so the cleanup can safely delete only the
    approval rows without ever subset-deleting chained evidence."""
    await conn.execute(
        _approval_requests.insert().values(
            request_id=rid,
            tenant_id=tenant,
            flow="require_single_approval",
            risk_tier="customer_data_read",
            tool_identity="cognic-tool-keyset",
            originator_subject="analyst.keyset",
            state="pending",
            first_approver=None,
            second_approver=None,
            denier=None,
            envelope_digest=b"\x03" * 32,
            args_digest=b"\x02" * 32,
            redacted_context="ctx",
            data_classes=["customer_pii"],
            required_refs={},
            created_at=when,
            expires_at=when + timedelta(hours=2),
            updated_at=when,
        )
    )


async def _keyset_walk(url: str) -> None:
    engine = create_async_engine(url)
    base = datetime(2026, 7, 11, 12, 0, tzinfo=UTC)
    rid_a, rid_b, rid_c = uuid.UUID(int=1), uuid.UUID(int=2), uuid.UUID(int=3)
    try:
        async with engine.begin() as conn:
            # A foreign-tenant decoy EARLIER than every visible row: with a
            # broken tenant filter it would surface first.
            await _seed_direct(
                conn, tenant=_DECOY_TENANT, rid=uuid.uuid4(), when=base - timedelta(hours=1)
            )
            # The equal-created_at tiebreak pair (inserted in REVERSE id order)
            # + one later row.
            await _seed_direct(conn, tenant=_TENANT, rid=rid_b, when=base)
            await _seed_direct(conn, tenant=_TENANT, rid=rid_a, when=base)
            await _seed_direct(conn, tenant=_TENANT, rid=rid_c, when=base + timedelta(minutes=1))

        # Reads via the REAL store (list_pending is a pure SELECT — no chain
        # write); constructing the store over the same engine does no I/O.
        store = ApprovalRequestStore(DecisionHistoryStore(engine))
        walked: list[uuid.UUID] = []
        cursor: str | None = None
        pages = 0
        while True:
            page = await store.list_pending(_TENANT, limit=1, cursor=cursor)
            walked.extend(r.request_id for r in page.items)
            pages += 1
            if page.next_cursor is None:
                break
            cursor = page.next_cursor
        assert pages == 3
        assert walked == [rid_a, rid_b, rid_c], (
            f"chronological keyset order: equal created_at tiebreaks by request_id; got {walked}"
        )
        # The decoy tenant sees only its own row.
        decoy_page = await store.list_pending(_DECOY_TENANT, limit=50, cursor=None)
        assert len(decoy_page.items) == 1
        assert decoy_page.next_cursor is None
    finally:
        # Clean ONLY the approval rows we inserted — never chained evidence
        # (none was written; the direct seed leaves decision_history +
        # governance_chain_heads untouched).
        async with engine.begin() as conn:
            await conn.execute(
                sa.delete(_approval_requests).where(
                    _approval_requests.c.tenant_id.in_((_TENANT, _DECOY_TENANT))
                )
            )
        await engine.dispose()


@pytest.mark.postgres
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_POSTGRES_INTEGRATION"),
    reason=(
        "live Postgres integration; opt in via "
        "COGNIC_RUN_POSTGRES_INTEGRATION=1 + compose up postgres"
    ),
)
def test_postgres_queue_keyset_walk() -> None:
    _alembic_head(POSTGRES_URL)
    asyncio.run(_keyset_walk(POSTGRES_URL))


@pytest.mark.oracle
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION"),
    reason=(
        "live Oracle XE integration; opt in via COGNIC_RUN_ORACLE_INTEGRATION=1 + compose up oracle"
    ),
)
def test_oracle_queue_keyset_walk() -> None:
    _alembic_head(ORACLE_URL)
    asyncio.run(_keyset_walk(ORACLE_URL))
