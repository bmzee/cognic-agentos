"""M8 Task A3/A4 (ADR-027) — pin migration 0014 (``data_scopes`` +
``entitlements`` + ``agent_assignments``) via real alembic upgrade + inspect.

Mirrors ``tests/unit/db/test_migration_20260615_0011.py`` (migrated engine +
run_sync inspect + round-trip downgrade + in-process-Table column parity) with
the constraint proofs of ``tests/unit/db/test_migration_20260630_0013.py``
(reflect-then-insert IntegrityError pins). Migrated DB, NOT ``create_all``,
per ``feedback_storage_test_migrated_db_not_create_all``. The migration is
DATA-FREE — scope/entitlement/assignment ROWS are proof-side seed.
"""

from __future__ import annotations

import asyncio
import importlib.util
import pathlib
import uuid
from datetime import UTC, datetime
from types import ModuleType
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine

_MIGRATION_PATH = pathlib.Path(
    "src/cognic_agentos/db/migrations/versions/20260705_0014_agent_entitlements.py"
)

_NEW_TABLES = ("data_scopes", "entitlements", "agent_assignments")


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_mig_0014", _MIGRATION_PATH)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


async def _migrated_engine(tmp_path: Any) -> Any:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'agent_ent.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    return create_async_engine(url)


def test_revision_lineage() -> None:
    m = _load_migration()
    assert m.revision == "0014"
    assert m.down_revision == "0013"


async def test_all_three_tables_exist_after_migration(tmp_path: Any) -> None:
    eng = await _migrated_engine(tmp_path)
    try:
        async with eng.connect() as c:
            names = await c.run_sync(lambda sc: set(sa.inspect(sc).get_table_names()))
        for table in _NEW_TABLES:
            assert table in names, f"missing table after upgrade-to-head: {table}"
    finally:
        await eng.dispose()


async def test_migration_round_trips_downgrade_to_0013(tmp_path: Any) -> None:
    # Down-revision reversibility (codebase doctrine — asymmetric create/drop
    # must round-trip): upgrade head -> downgrade 0013 drops all three tables.
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'agent_ent_rt.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    await asyncio.to_thread(command.downgrade, cfg, "0013")
    eng = create_async_engine(url)
    try:
        async with eng.connect() as c:
            names = await c.run_sync(lambda sc: set(sa.inspect(sc).get_table_names()))
        for table in _NEW_TABLES:
            assert table not in names, f"table survived downgrade to 0013: {table}"
    finally:
        await eng.dispose()


async def _migrated_column_names(tmp_path: Any, table: str) -> set[str]:
    eng = await _migrated_engine(tmp_path)
    try:
        async with eng.connect() as c:
            cols: set[str] = await c.run_sync(
                lambda sc: {col["name"] for col in sa.inspect(sc).get_columns(table)}
            )
        return cols
    finally:
        await eng.dispose()


async def test_migration_data_scopes_matches_in_process_table(tmp_path: Any) -> None:
    from cognic_agentos.core.entitlements.store import _data_scopes

    cols = await _migrated_column_names(tmp_path, "data_scopes")
    assert cols == {c.name for c in _data_scopes.columns}
    assert cols == {
        "tenant_id",
        "scope_id",
        "schema_name",
        "objects",
        "proxy_db_identity",
        "created_at",
    }


async def test_migration_entitlements_matches_in_process_table(tmp_path: Any) -> None:
    from cognic_agentos.core.entitlements.store import _entitlements

    cols = await _migrated_column_names(tmp_path, "entitlements")
    assert cols == {c.name for c in _entitlements.columns}
    assert cols == {"id", "tenant_id", "subject", "scope_id", "created_at"}


async def test_migration_agent_assignments_matches_in_process_table(tmp_path: Any) -> None:
    from cognic_agentos.core.agent.assignments import _agent_assignments

    cols = await _migrated_column_names(tmp_path, "agent_assignments")
    assert cols == {c.name for c in _agent_assignments.columns}
    assert cols == {
        "id",
        "tenant_id",
        "agent_id",
        "capability_kind",
        "capability_ref",
        "created_at",
    }


async def test_entitlements_unique_constraint_blocks_duplicate(tmp_path: Any) -> None:
    # Functional proof the migration-only (tenant_id, subject, scope_id) unique
    # constraint is LIVE in the migrated DB — a duplicate INSERT raises
    # IntegrityError. Reflect the table so the Uuid/TIMESTAMP column types bind
    # correctly without depending on the in-process storage Table.
    eng = await _migrated_engine(tmp_path)
    md = sa.MetaData()
    try:
        async with eng.connect() as conn:
            await conn.run_sync(lambda c: md.reflect(c, only=["entitlements"]))
        tbl = md.tables["entitlements"]

        async def _insert() -> None:
            async with eng.begin() as conn:
                await conn.execute(
                    tbl.insert().values(
                        id=uuid.uuid4().hex,
                        tenant_id="t1",
                        subject="analyst.amir",
                        scope_id="retail_analytics",
                        created_at=datetime.now(UTC),
                    )
                )

        await _insert()
        with pytest.raises(IntegrityError):
            await _insert()
    finally:
        await eng.dispose()


async def test_agent_assignments_unique_constraint_blocks_duplicate(tmp_path: Any) -> None:
    # Functional proof the migration-only (tenant_id, agent_id, capability_kind,
    # capability_ref) unique constraint is LIVE — a duplicate INSERT raises
    # IntegrityError.
    eng = await _migrated_engine(tmp_path)
    md = sa.MetaData()
    try:
        async with eng.connect() as conn:
            await conn.run_sync(lambda c: md.reflect(c, only=["agent_assignments"]))
        tbl = md.tables["agent_assignments"]

        async def _insert() -> None:
            async with eng.begin() as conn:
                await conn.execute(
                    tbl.insert().values(
                        id=uuid.uuid4().hex,
                        tenant_id="t1",
                        agent_id="bank-analyst",
                        capability_kind="skill",
                        capability_ref="customer-data",
                        created_at=datetime.now(UTC),
                    )
                )

        await _insert()
        with pytest.raises(IntegrityError):
            await _insert()
    finally:
        await eng.dispose()


async def test_agent_assignments_check_constraint_blocks_builtin_kind(tmp_path: Any) -> None:
    # Functional proof the migration-only CHECK constraint is LIVE in the
    # migrated DB — an out-of-vocabulary capability_kind INSERT raises
    # IntegrityError, so an out-of-band write cannot create a kind the Python
    # Literal can't represent (built-ins are kernel-owned: NEVER assignment
    # rows).
    eng = await _migrated_engine(tmp_path)
    md = sa.MetaData()
    try:
        async with eng.connect() as conn:
            await conn.run_sync(lambda c: md.reflect(c, only=["agent_assignments"]))
        tbl = md.tables["agent_assignments"]
        with pytest.raises(IntegrityError):
            async with eng.begin() as conn:
                await conn.execute(
                    tbl.insert().values(
                        id=uuid.uuid4().hex,
                        tenant_id="t1",
                        agent_id="bank-analyst",
                        capability_kind="builtin",  # not in the closed enum
                        capability_ref="read_skill",
                        created_at=datetime.now(UTC),
                    )
                )
    finally:
        await eng.dispose()
