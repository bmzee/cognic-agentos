"""Sprint 14A-A3a — pin migration 0011 (runs) via real alembic upgrade + inspect
(mirrors tests/unit/db/test_migration_20260607_0008.py)."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine


async def _migrated_engine(tmp_path: Any) -> Any:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'runs.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    return create_async_engine(url)


@pytest.mark.asyncio
async def test_runs_table_exists_after_migration(tmp_path: Any) -> None:
    eng = await _migrated_engine(tmp_path)
    try:
        async with eng.connect() as c:
            names = await c.run_sync(lambda sc: sa.inspect(sc).get_table_names())
        assert "runs" in names
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_migration_round_trips(tmp_path: Any) -> None:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'runs_rt.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    await asyncio.to_thread(command.downgrade, cfg, "0010")
    eng = create_async_engine(url)
    try:
        async with eng.connect() as c:
            names = await c.run_sync(lambda sc: sa.inspect(sc).get_table_names())
        assert "runs" not in names
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_migration_table_matches_in_process_table(tmp_path: Any) -> None:
    from cognic_agentos.core.run.storage import _runs

    eng = await _migrated_engine(tmp_path)
    try:
        async with eng.connect() as c:
            cols = await c.run_sync(
                lambda sc: {col["name"] for col in sa.inspect(sc).get_columns("runs")}
            )
        assert cols == {c.name for c in _runs.columns}
    finally:
        await eng.dispose()


def test_runs_checkpoint_id_is_string_32_not_uuid() -> None:
    # The P1: checkpoint_id is the sandbox CheckpointId hex (32 chars), a String,
    # NOT a Uuid column. Pinned at the in-process Table level (reliable across
    # dialects, unlike DB-introspected length).
    from cognic_agentos.core.run.storage import _runs

    col = _runs.c.checkpoint_id
    assert isinstance(col.type, sa.String) and col.type.length == 32
