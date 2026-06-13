# tests/unit/db/test_migration_20260613_0010.py
"""Sprint 13.6b T2 — migration 0010 adds the gateway_call_ledger quota
evidence columns (ADR-018 F6). Additive nullable; downgrade drops them;
the migrated table matches the in-process `_ledger_table` declaration."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

_QUOTA_COLS = {"prompt_tokens", "completion_tokens", "estimated_cost_usd"}


async def _migrated_engine(tmp_path: Any) -> Any:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'ledger_0010.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    return create_async_engine(url)


@pytest.mark.asyncio
async def test_quota_columns_exist_after_migration(tmp_path: Any) -> None:
    eng = await _migrated_engine(tmp_path)
    try:
        async with eng.connect() as c:
            cols = await c.run_sync(
                lambda sc: {
                    col["name"] for col in sa.inspect(sc).get_columns("gateway_call_ledger")
                }
            )
        assert cols >= _QUOTA_COLS
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_migration_round_trips(tmp_path: Any) -> None:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'ledger_0010_rt.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    await asyncio.to_thread(command.downgrade, cfg, "0009")
    eng = create_async_engine(url)
    try:
        async with eng.connect() as c:
            cols = await c.run_sync(
                lambda sc: {
                    col["name"] for col in sa.inspect(sc).get_columns("gateway_call_ledger")
                }
            )
        assert _QUOTA_COLS.isdisjoint(cols)  # the 3 columns dropped
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_migration_table_matches_in_process_ledger_table(tmp_path: Any) -> None:
    from cognic_agentos.llm.ledger import _ledger_table

    eng = await _migrated_engine(tmp_path)
    try:
        async with eng.connect() as c:
            cols = await c.run_sync(
                lambda sc: {
                    col["name"] for col in sa.inspect(sc).get_columns("gateway_call_ledger")
                }
            )
        assert cols == {col.name for col in _ledger_table.columns}
    finally:
        await eng.dispose()
