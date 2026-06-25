"""PR-2b-1 — pin migration 0012 (mcp ``server_url`` override + internal-host
allow-list) via real alembic upgrade + inspect.

Mirrors ``tests/unit/db/test_migration_20260531_0006.py``: numeric-prefixed
migration modules can't be dotted-imported, so load by path; constraint/column
parity REFLECTS the Alembic-MIGRATED DB (the 0005/0006 doctrine) so a migration
that drops/renames a column or constraint FAILS here. The named unique
constraints are the migration-only invariants the store layer depends on.
"""

import asyncio
import importlib.util
import pathlib
import uuid
from datetime import UTC, datetime
from types import ModuleType
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine

_MIGRATION_PATH = pathlib.Path(
    "src/cognic_agentos/db/migrations/versions/20260625_0012_mcp_override_and_allowlist.py"
)


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_mig_0012", _MIGRATION_PATH)
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
    assert m.revision == "0012"
    assert m.down_revision == "0011"


async def test_migration_round_trips_downgrade_to_0011(tmp_path: Any) -> None:
    # Down-revision reversibility (codebase doctrine — asymmetric create/drop
    # must round-trip): upgrade head -> downgrade 0011 drops BOTH tables.
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'mcp_0012_rt.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    await asyncio.to_thread(command.downgrade, cfg, "0011")
    eng = create_async_engine(url)
    try:
        async with eng.connect() as conn:
            names = await conn.run_sync(lambda c: set(sa_inspect(c).get_table_names()))
    finally:
        await eng.dispose()
    assert "mcp_server_url_override" not in names
    assert "mcp_internal_host_allowlist" not in names


async def test_both_tables_exist_after_migration(tmp_path: Any) -> None:
    url = f"sqlite+aiosqlite:///{tmp_path / 'mcp_0012.db'}"
    await _upgrade_to_head(url)
    eng = create_async_engine(url)
    try:
        async with eng.connect() as conn:
            names = await conn.run_sync(lambda c: set(sa_inspect(c).get_table_names()))
    finally:
        await eng.dispose()
    assert "mcp_server_url_override" in names
    assert "mcp_internal_host_allowlist" in names


async def test_table_columns_match_expected(tmp_path: Any) -> None:
    url = f"sqlite+aiosqlite:///{tmp_path / 'mcp_0012_cols.db'}"
    await _upgrade_to_head(url)
    eng = create_async_engine(url)
    try:
        async with eng.connect() as conn:
            ov_cols = await conn.run_sync(
                lambda c: {
                    col["name"] for col in sa_inspect(c).get_columns("mcp_server_url_override")
                }
            )
            al_cols = await conn.run_sync(
                lambda c: {
                    col["name"] for col in sa_inspect(c).get_columns("mcp_internal_host_allowlist")
                }
            )
    finally:
        await eng.dispose()
    assert ov_cols == {
        "id",
        "tenant_id",
        "pack_id",
        "server_url_override",
        "set_by_actor",
        "set_at",
        "last_request_id",
    }
    assert al_cols == {
        "id",
        "tenant_id",
        "ip",
        "set_by_actor",
        "set_at",
        "last_request_id",
    }


def _unique_names_and_colsets(
    uniques: list[Any], indexes: list[Any]
) -> tuple[set[str], list[set[str]]]:
    # SQLite can surface a named ``UniqueConstraint`` either as a reflected
    # unique constraint OR as a unique index (the 0004 fallback doctrine).
    names = {u["name"] for u in uniques if u.get("name")} | {
        i["name"] for i in indexes if i.get("unique") and i.get("name")
    }
    colsets = [set(u["column_names"]) for u in uniques] + [
        set(i["column_names"]) for i in indexes if i.get("unique")
    ]
    return names, colsets


async def test_unique_constraints_present(tmp_path: Any) -> None:
    url = f"sqlite+aiosqlite:///{tmp_path / 'mcp_0012_uq.db'}"
    await _upgrade_to_head(url)
    eng = create_async_engine(url)
    try:
        async with eng.connect() as conn:
            ov_u = await conn.run_sync(
                lambda c: sa_inspect(c).get_unique_constraints("mcp_server_url_override")
            )
            ov_i = await conn.run_sync(
                lambda c: sa_inspect(c).get_indexes("mcp_server_url_override")
            )
            al_u = await conn.run_sync(
                lambda c: sa_inspect(c).get_unique_constraints("mcp_internal_host_allowlist")
            )
            al_i = await conn.run_sync(
                lambda c: sa_inspect(c).get_indexes("mcp_internal_host_allowlist")
            )
    finally:
        await eng.dispose()
    ov_names, ov_colsets = _unique_names_and_colsets(ov_u, ov_i)
    al_names, al_colsets = _unique_names_and_colsets(al_u, al_i)
    assert {"tenant_id", "pack_id"} in ov_colsets
    assert "uq_mcp_server_url_override_tenant_pack" in ov_names
    assert {"tenant_id", "ip"} in al_colsets
    assert "uq_mcp_internal_host_allowlist_tenant_ip" in al_names


async def test_tenant_id_indexes_present(tmp_path: Any) -> None:
    url = f"sqlite+aiosqlite:///{tmp_path / 'mcp_0012_idx.db'}"
    await _upgrade_to_head(url)
    eng = create_async_engine(url)
    try:
        async with eng.connect() as conn:
            ov_i = await conn.run_sync(
                lambda c: sa_inspect(c).get_indexes("mcp_server_url_override")
            )
            al_i = await conn.run_sync(
                lambda c: sa_inspect(c).get_indexes("mcp_internal_host_allowlist")
            )
    finally:
        await eng.dispose()
    assert "ix_mcp_server_url_override_tenant_id" in {i["name"] for i in ov_i}
    assert "ix_mcp_internal_host_allowlist_tenant_id" in {i["name"] for i in al_i}


async def test_unique_constraint_blocks_duplicate_tenant_ip(tmp_path: Any) -> None:
    # Functional proof the migration-only (tenant_id, ip) unique constraint is
    # LIVE in the migrated DB — a duplicate (tenant, ip) INSERT raises
    # IntegrityError. Reflect the table so the Uuid/TIMESTAMP column types bind
    # correctly without depending on the in-process storage Table.
    url = f"sqlite+aiosqlite:///{tmp_path / 'mcp_0012_dup.db'}"
    await _upgrade_to_head(url)
    eng = create_async_engine(url)
    md = sa.MetaData()
    try:
        async with eng.connect() as conn:
            await conn.run_sync(lambda c: md.reflect(c, only=["mcp_internal_host_allowlist"]))
        tbl = md.tables["mcp_internal_host_allowlist"]
        now = datetime.now(UTC)
        async with eng.begin() as conn:
            await conn.execute(
                tbl.insert().values(
                    id=uuid.uuid4().hex,
                    tenant_id="t1",
                    ip="10.0.0.7",
                    set_by_actor="op@bank",
                    set_at=now,
                    last_request_id="r1",
                )
            )
        with pytest.raises(IntegrityError):
            async with eng.begin() as conn:
                await conn.execute(
                    tbl.insert().values(
                        id=uuid.uuid4().hex,
                        tenant_id="t1",
                        ip="10.0.0.7",
                        set_by_actor="op@bank",
                        set_at=now,
                        last_request_id="r2",
                    )
                )
    finally:
        await eng.dispose()
