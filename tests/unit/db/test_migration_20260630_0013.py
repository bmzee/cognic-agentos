"""M4 Task 1 — pin migration 0013 (``pack_runtime_config``) via real alembic
upgrade + inspect.

Mirrors ``tests/unit/db/test_migration_20260625_0012.py``: numeric-prefixed
migration modules can't be dotted-imported, so load by path; constraint/column
parity REFLECTS the Alembic-MIGRATED DB so a migration that drops/renames a
column or constraint FAILS here, and the column set is cross-checked against the
in-process ``_pack_runtime_config`` Table. The named unique constraint is the
migration-only single-row-per-``(tenant, pack)`` invariant the store depends on.
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
    "src/cognic_agentos/db/migrations/versions/20260630_0013_pack_runtime_config.py"
)


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_mig_0013", _MIGRATION_PATH)
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
    assert m.revision == "0013"
    assert m.down_revision == "0012"


async def test_migration_round_trips_downgrade_to_0012(tmp_path: Any) -> None:
    # Down-revision reversibility (codebase doctrine — asymmetric create/drop
    # must round-trip): upgrade head -> downgrade 0012 drops the table.
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'prc_0013_rt.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    await asyncio.to_thread(command.downgrade, cfg, "0012")
    eng = create_async_engine(url)
    try:
        async with eng.connect() as conn:
            names = await conn.run_sync(lambda c: set(sa_inspect(c).get_table_names()))
    finally:
        await eng.dispose()
    assert "pack_runtime_config" not in names


async def test_table_exists_after_migration(tmp_path: Any) -> None:
    url = f"sqlite+aiosqlite:///{tmp_path / 'prc_0013.db'}"
    await _upgrade_to_head(url)
    eng = create_async_engine(url)
    try:
        async with eng.connect() as conn:
            names = await conn.run_sync(lambda c: set(sa_inspect(c).get_table_names()))
    finally:
        await eng.dispose()
    assert "pack_runtime_config" in names


async def test_migration_table_matches_in_process_table(tmp_path: Any) -> None:
    # Drift guard: the migrated column set MUST equal the in-process Table's.
    from cognic_agentos.core.mcp_config.runtime_config import _pack_runtime_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'prc_0013_cols.db'}"
    await _upgrade_to_head(url)
    eng = create_async_engine(url)
    try:
        async with eng.connect() as conn:
            cols = await conn.run_sync(
                lambda c: {col["name"] for col in sa_inspect(c).get_columns("pack_runtime_config")}
            )
    finally:
        await eng.dispose()
    assert cols == {c.name for c in _pack_runtime_config.columns}
    assert cols == {
        "id",
        "tenant_id",
        "pack_id",
        "server_url_override",
        "internal_host_allowlist",
        "oauth_credential_ref",
        "as_allowlist_ref",
        "activation_status",
        "generation",
        "set_by_actor",
        "set_at",
        "last_request_id",
    }


def _unique_names_and_colsets(
    uniques: list[Any], indexes: list[Any]
) -> tuple[set[str], list[set[str]]]:
    # SQLite can surface a named UniqueConstraint either as a reflected unique
    # constraint OR as a unique index (the 0004 fallback doctrine).
    names = {u["name"] for u in uniques if u.get("name")} | {
        i["name"] for i in indexes if i.get("unique") and i.get("name")
    }
    colsets = [set(u["column_names"]) for u in uniques] + [
        set(i["column_names"]) for i in indexes if i.get("unique")
    ]
    return names, colsets


async def test_unique_constraint_present(tmp_path: Any) -> None:
    url = f"sqlite+aiosqlite:///{tmp_path / 'prc_0013_uq.db'}"
    await _upgrade_to_head(url)
    eng = create_async_engine(url)
    try:
        async with eng.connect() as conn:
            u = await conn.run_sync(
                lambda c: sa_inspect(c).get_unique_constraints("pack_runtime_config")
            )
            i = await conn.run_sync(lambda c: sa_inspect(c).get_indexes("pack_runtime_config"))
    finally:
        await eng.dispose()
    names, colsets = _unique_names_and_colsets(u, i)
    assert {"tenant_id", "pack_id"} in colsets
    assert "uq_pack_runtime_config_tenant_pack" in names


async def test_tenant_id_index_present(tmp_path: Any) -> None:
    url = f"sqlite+aiosqlite:///{tmp_path / 'prc_0013_idx.db'}"
    await _upgrade_to_head(url)
    eng = create_async_engine(url)
    try:
        async with eng.connect() as conn:
            i = await conn.run_sync(lambda c: sa_inspect(c).get_indexes("pack_runtime_config"))
    finally:
        await eng.dispose()
    assert "ix_pack_runtime_config_tenant_id" in {idx["name"] for idx in i}


async def test_unique_constraint_blocks_duplicate_tenant_pack(tmp_path: Any) -> None:
    # Functional proof the migration-only (tenant_id, pack_id) unique constraint
    # is LIVE in the migrated DB — a duplicate (tenant, pack) INSERT raises
    # IntegrityError. Reflect the table so the Uuid/JSON/TIMESTAMP column types
    # bind correctly without depending on the in-process storage Table.
    url = f"sqlite+aiosqlite:///{tmp_path / 'prc_0013_dup.db'}"
    await _upgrade_to_head(url)
    eng = create_async_engine(url)
    md = sa.MetaData()
    try:
        async with eng.connect() as conn:
            await conn.run_sync(lambda c: md.reflect(c, only=["pack_runtime_config"]))
        tbl = md.tables["pack_runtime_config"]
        now = datetime.now(UTC)

        async def _insert(request_id: str) -> None:
            async with eng.begin() as conn:
                await conn.execute(
                    tbl.insert().values(
                        id=uuid.uuid4().hex,
                        tenant_id="t1",
                        pack_id="p1",
                        server_url_override=None,
                        internal_host_allowlist=[],
                        oauth_credential_ref=None,
                        as_allowlist_ref=None,
                        activation_status="configured",
                        generation=1,
                        set_by_actor="op@bank",
                        set_at=now,
                        last_request_id=request_id,
                    )
                )

        await _insert("r1")
        with pytest.raises(IntegrityError):
            await _insert("r2")
    finally:
        await eng.dispose()


async def test_activation_status_check_constraint_blocks_invalid_status(tmp_path: Any) -> None:
    # Functional proof the migration-only CHECK constraint is LIVE in the migrated
    # DB — an out-of-vocabulary activation_status INSERT raises IntegrityError, so a
    # governance state the Python Literal cannot represent cannot reach the table.
    url = f"sqlite+aiosqlite:///{tmp_path / 'prc_0013_ck.db'}"
    await _upgrade_to_head(url)
    eng = create_async_engine(url)
    md = sa.MetaData()
    try:
        async with eng.connect() as conn:
            await conn.run_sync(lambda c: md.reflect(c, only=["pack_runtime_config"]))
        tbl = md.tables["pack_runtime_config"]
        with pytest.raises(IntegrityError):
            async with eng.begin() as conn:
                await conn.execute(
                    tbl.insert().values(
                        id=uuid.uuid4().hex,
                        tenant_id="t1",
                        pack_id="p1",
                        server_url_override=None,
                        internal_host_allowlist=[],
                        oauth_credential_ref=None,
                        as_allowlist_ref=None,
                        activation_status="bogus",  # not in the closed enum
                        generation=1,
                        set_by_actor="op@bank",
                        set_at=datetime.now(UTC),
                        last_request_id="r-ck",
                    )
                )
    finally:
        await eng.dispose()
