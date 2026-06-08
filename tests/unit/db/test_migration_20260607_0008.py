# tests/unit/db/test_migration_20260607_0008.py
from __future__ import annotations

import asyncio
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine


async def _migrated_engine(tmp_path: Any) -> Any:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'eval.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    return create_async_engine(url)


@pytest.mark.asyncio
async def test_eval_tables_exist_after_migration(tmp_path: Any) -> None:
    eng = await _migrated_engine(tmp_path)
    try:
        async with eng.connect() as c:
            names = await c.run_sync(lambda sc: sa.inspect(sc).get_table_names())
        assert "eval_runs" in names
        assert "eval_case_results" in names
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_migration_round_trips(tmp_path: Any) -> None:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'eval_rt.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    await asyncio.to_thread(command.downgrade, cfg, "0007")
    eng = create_async_engine(url)
    try:
        async with eng.connect() as c:
            names = await c.run_sync(lambda sc: sa.inspect(sc).get_table_names())
        assert "eval_runs" not in names and "eval_case_results" not in names
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_migration_tables_match_in_process_tables(tmp_path: Any) -> None:
    from cognic_agentos.evaluation.storage import _eval_case_results, _eval_runs

    eng = await _migrated_engine(tmp_path)
    try:
        async with eng.connect() as c:
            run_cols = await c.run_sync(
                lambda sc: {col["name"] for col in sa.inspect(sc).get_columns("eval_runs")}
            )
            case_cols = await c.run_sync(
                lambda sc: {col["name"] for col in sa.inspect(sc).get_columns("eval_case_results")}
            )
        assert run_cols == {c.name for c in _eval_runs.columns}
        assert case_cols == {c.name for c in _eval_case_results.columns}
    finally:
        await eng.dispose()
