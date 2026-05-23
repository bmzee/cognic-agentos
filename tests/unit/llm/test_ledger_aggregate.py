"""Sprint 9.5b C3 — ``GatewayCallLedger.count_by_model_id`` aggregate
read.

**User-locked review bar #1:** the aggregate must be exact-match on
``model_id``, time-bounded, and return zero for unknown / unmapped /
null rows.

The query is index-served by ``ix_gateway_call_ledger_model_id_ts``
(btree on ``(model_id, ts)``, created in migration 0004). Backend
parity is asserted indirectly: the same module-level
``_ledger_table`` carries the index declaration on Postgres + Oracle
+ SQLite via the migration round-trip in
``tests/unit/db/test_run_migrations.py``.
"""

from __future__ import annotations

import datetime as _dt
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.llm.ledger import GatewayCallLedger, GatewayCallRow, _ledger_table


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    """Per-test SQLite-aiosqlite engine with only the gateway_call_ledger
    table created. The aggregate-read test writes only ledger rows, so
    chain-head seeding is unnecessary (separate ``MetaData()`` instance
    per ``ledger.py:133``)."""
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'c3_aggregate.db'}")
    async with eng.begin() as conn:
        await conn.run_sync(_ledger_table.metadata.create_all)
    yield eng
    await eng.dispose()


def _row(model_id: str | None, ts: _dt.datetime) -> GatewayCallRow:
    """Minimal row builder; all fields except the two we vary
    (``model_id`` + ``ts``) are fixed at deterministic non-None
    defaults."""
    return GatewayCallRow(
        id=uuid.uuid4(),
        ts=ts,
        request_id="r",
        tenant_id="t",
        tier="tier1",
        litellm_alias="al",
        upstream_model="u",
        upstream_api_base=None,
        external=False,
        provenance="resolved",
        latency_ms=1,
        outcome="ok",
        model_id=model_id,
    )


async def test_count_by_model_id_filters_to_window_and_id(engine: AsyncEngine) -> None:
    """Plan-provided base test — window filter + id filter compose.
    Bar #1 (combined: exact-match + time-bound)."""
    ledger = GatewayCallLedger(engine)
    now = _dt.datetime.now(_dt.UTC)
    await ledger.write_row(_row("m-a", now))
    await ledger.write_row(_row("m-a", now))
    await ledger.write_row(_row("m-b", now))
    await ledger.write_row(_row(None, now))
    # Outside the window:
    old = now - _dt.timedelta(days=7)
    await ledger.write_row(_row("m-a", old))

    count = await ledger.count_by_model_id(
        model_id="m-a",
        since=now - _dt.timedelta(hours=1),
        until=now + _dt.timedelta(hours=1),
    )
    assert count == 2

    # "missing" outside the window finds 0 (defense against accidental
    # full-table scans that ignore the window).
    assert (
        await ledger.count_by_model_id(
            model_id="missing",
            since=old,
            until=now + _dt.timedelta(hours=1),
        )
        == 0
    )


async def test_count_by_model_id_returns_zero_for_unknown_model_id(
    engine: AsyncEngine,
) -> None:
    """Bar #1 — unknown ``model_id`` returns zero. The aggregate must
    NEVER raise; missing identity is a normal operator scenario (no
    calls yet, or a pre-C2 row predates the model)."""
    ledger = GatewayCallLedger(engine)
    now = _dt.datetime.now(_dt.UTC)
    await ledger.write_row(_row("m-a", now))

    count = await ledger.count_by_model_id(
        model_id="m-z-never-registered",
        since=now - _dt.timedelta(hours=1),
        until=now + _dt.timedelta(hours=1),
    )
    assert count == 0


async def test_count_by_model_id_ignores_rows_with_null_model_id(
    engine: AsyncEngine,
) -> None:
    """Bar #1 — rows with ``model_id IS NULL`` (pre-C2 historical
    rows + unmapped-alias post-C2 rows) NEVER count against any
    model_id query, including a query for the literal ``"None"``
    string. SQL's ``column == "None"`` does NOT match NULL — this
    test pins the SQL semantic so a future refactor that
    accidentally uses ``IS NULL`` on the right-hand side gets
    caught."""
    ledger = GatewayCallLedger(engine)
    now = _dt.datetime.now(_dt.UTC)
    # All 3 rows are null model_id.
    await ledger.write_row(_row(None, now))
    await ledger.write_row(_row(None, now))
    await ledger.write_row(_row(None, now))

    # Querying for ANY model_id (even the literal "None" string) finds 0.
    assert (
        await ledger.count_by_model_id(
            model_id="anything",
            since=now - _dt.timedelta(hours=1),
            until=now + _dt.timedelta(hours=1),
        )
        == 0
    )
    assert (
        await ledger.count_by_model_id(
            model_id="None",
            since=now - _dt.timedelta(hours=1),
            until=now + _dt.timedelta(hours=1),
        )
        == 0
    )


async def test_count_by_model_id_is_exact_match_not_prefix(
    engine: AsyncEngine,
) -> None:
    """Bar #1 — exact match, NOT prefix / substring / LIKE. A query
    for ``"m-a"`` MUST NOT match a row with ``model_id="m-a-extended"``
    (false positive: distinct models share a prefix in the wild)
    OR ``model_id="prefix-m-a"`` (false positive: SQL LIKE-with-
    wildcards regression)."""
    ledger = GatewayCallLedger(engine)
    now = _dt.datetime.now(_dt.UTC)
    await ledger.write_row(_row("m-a", now))
    await ledger.write_row(_row("m-a-extended", now))
    await ledger.write_row(_row("prefix-m-a", now))
    await ledger.write_row(_row("m-a-v2", now))
    await ledger.write_row(_row("M-A", now))  # case-sensitive guard

    count = await ledger.count_by_model_id(
        model_id="m-a",
        since=now - _dt.timedelta(hours=1),
        until=now + _dt.timedelta(hours=1),
    )
    # Only the exact "m-a" row counts; the 4 lookalikes do NOT.
    assert count == 1
