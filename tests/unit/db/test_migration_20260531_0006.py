# Numeric-prefixed migration modules can't be dotted-imported; load by path.
# Column/constraint parity REFLECTS the migrated DB (mirrors the 0005 pattern) —
# NOT the in-process Table — so a migration that drops/renames a column FAILS here.
import asyncio
import importlib.util
import pathlib
from types import ModuleType
from typing import Any

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.ext.asyncio import create_async_engine


def _load_migration() -> ModuleType:
    path = pathlib.Path("src/cognic_agentos/db/migrations/versions/20260531_0006_memory.py")
    spec = importlib.util.spec_from_file_location("_mig_0006", path)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


async def _upgrade_to_head(url: str) -> None:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    await asyncio.to_thread(command.upgrade, make_alembic_config(url), "head")


def test_revision_lineage() -> None:
    m = _load_migration()
    assert m.revision == "0006"
    assert m.down_revision == "0005"


async def test_migrated_db_columns_match_storage_table(tmp_path: Any) -> None:
    from cognic_agentos.core.memory.storage import _memory_records

    url = f"sqlite+aiosqlite:///{tmp_path / 'cols.db'}"
    await _upgrade_to_head(url)
    eng = create_async_engine(url)
    async with eng.connect() as conn:
        cols = await conn.run_sync(
            lambda c: {col["name"]: col for col in sa_inspect(c).get_columns("memory_records")}
        )
    await eng.dispose()
    # EXACT set parity (NOT subset) + nullability parity + SQLite-dialect type parity.
    assert set(cols) == {c.name for c in _memory_records.columns}
    for col in _memory_records.columns:
        assert cols[col.name]["nullable"] is col.nullable
    from sqlalchemy.dialects import sqlite

    d = sqlite.dialect()
    for col in _memory_records.columns:
        assert (
            cols[col.name]["type"].compile(dialect=d).upper() == col.type.compile(dialect=d).upper()
        )


async def test_migrated_db_has_key_xor_block_kind_check(tmp_path: Any) -> None:
    url = f"sqlite+aiosqlite:///{tmp_path / 'ck.db'}"
    await _upgrade_to_head(url)
    eng = create_async_engine(url)
    async with eng.connect() as conn:
        ccs = await conn.run_sync(lambda c: sa_inspect(c).get_check_constraints("memory_records"))
    await eng.dispose()
    assert "ck_memory_records_key_xor_block_kind" in {cc["name"] for cc in ccs}
