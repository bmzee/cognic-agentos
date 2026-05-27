"""Sprint 10.5a T4 — Alembic migration ``20260526_0005_scheduler_tasks``.

Migration drift detector. Mirrors the
``tests/unit/db/test_migration_20260522_0004.py`` pattern: applies the
migration against a SQLite-aiosqlite tmp DB via the same alembic
``upgrade head`` seam, reflects the migrated DB, and asserts:

1. Migration upgrades cleanly + creates the ``scheduler_tasks`` table
   with the column inventory matching
   :data:`cognic_agentos.core.scheduler.storage._scheduler_tasks`
   (single-source-of-truth invariant — the in-process Table object and
   the production migration MUST agree).
2. Indexes ``ix_scheduler_tasks_tenant_class_state`` (composite for the
   T5 SchedulerEngine current-concurrent-count query per spec §4.5) +
   ``ix_scheduler_tasks_parent`` (Sprint 11 sub-agent budget inheritance
   per spec §4.10) are both present.
3. CHECK constraints ``ck_scheduler_tasks_state`` (7 SchedulerTaskState
   values per spec §4.4) + ``ck_scheduler_tasks_class_`` (2 Wave-1
   SchedulerPriorityClass values per spec §4.1) are present in the
   **migrated DB** (reflection) AND declared in the **migration source**
   (inspection).
4. Clean round-trip: ``head -> 0004 -> head`` drops and restores
   ``scheduler_tasks`` without residual state.
5. ``SCHEDULER_TS_TYPE`` Oracle-compiles to
   ``TIMESTAMP WITH TIME ZONE`` (NOT bare ``TIMESTAMP`` / ``DATE``).
6. ``upgrade()`` + ``downgrade()`` function bodies do NOT reference
   ``decision_history`` (plan/spec §3.2 hard constraint — scheduler
   storage is a consumer of the chain substrate, not a modifier).
7. Module surface: revision = ``"0005"``, down_revision = ``"0004"``,
   callable upgrade/downgrade, exported ``SCHEDULER_TS_TYPE`` constant.

Why this matters: the storage tests use ``_metadata.create_all`` (the
in-process Table object) — they cannot catch migration-vs-Table drift.
A regression that drops/renames a column in the migration WOULD slip
past the storage tests because both sides of the implicit equality
come from the same source. Real upgrade-and-reflect closes that loophole.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect as py_inspect
from typing import Any

import sqlalchemy as sa
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.ext.asyncio import create_async_engine

MIGRATION_MODULE_NAME = "cognic_agentos.db.migrations.versions.20260526_0005_scheduler_tasks"


async def _upgrade_to_head(url: str) -> None:
    """Apply the full migration graph (0001 → 0002 → 0003 → 0004 → 0005)."""
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")


async def _downgrade_to(url: str, revision: str) -> None:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.downgrade, cfg, revision)


class TestSprint105aMigration0005UpgradeShape:
    async def test_upgrade_creates_scheduler_tasks_table(self, tmp_path: Any) -> None:
        url = f"sqlite+aiosqlite:///{tmp_path / 't5_upgrade.db'}"
        await _upgrade_to_head(url)

        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            tables = await conn.run_sync(lambda c: set(sa_inspect(c).get_table_names()))
        await check_engine.dispose()

        # Existing substrate untouched
        assert "audit_event" in tables
        assert "decision_history" in tables
        assert "governance_chain_heads" in tables
        assert "gateway_call_ledger" in tables
        assert "packs" in tables
        assert "models" in tables
        # Sprint-10.5a T4: 0005 adds scheduler_tasks
        assert "scheduler_tasks" in tables

    async def test_scheduler_tasks_columns_match_storage_table_object(self, tmp_path: Any) -> None:
        """Single-source-of-truth invariant: the MIGRATED DB's column
        inventory MUST agree with
        :data:`cognic_agentos.core.scheduler.storage._scheduler_tasks`.
        Reflects the real migrated table (not the in-process Table
        object) so a regression that drops/renames a column in the
        migration would fail this assertion.
        """
        from cognic_agentos.core.scheduler.storage import _scheduler_tasks

        url = f"sqlite+aiosqlite:///{tmp_path / 't5_cols.db'}"
        await _upgrade_to_head(url)

        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            cols = await conn.run_sync(
                lambda c: {col["name"]: col for col in sa_inspect(c).get_columns("scheduler_tasks")}
            )
        await check_engine.dispose()

        expected_cols = {col.name for col in _scheduler_tasks.columns}
        assert set(cols.keys()) == expected_cols, (
            f"migrated DB column set {set(cols.keys())} does not match "
            f"_scheduler_tasks Table column set {expected_cols}"
        )

        # Nullability parity with _scheduler_tasks
        for col in _scheduler_tasks.columns:
            mig_nullable = cols[col.name]["nullable"]
            assert mig_nullable is col.nullable, (
                f"column {col.name!r}: migration nullable={mig_nullable} "
                f"but _scheduler_tasks Table nullable={col.nullable}"
            )

        # Round-4 reviewer P3 finding — type parity per column.
        # Compiles BOTH the reflected migrated column type AND the
        # in-process Table column type against the same SQLite dialect
        # and compares the compiled DDL strings. Dialect-aware
        # comparison handles the ``Uuid() → CHAR(32)`` SQLite
        # reflection asymmetry (SQLite has no native UUID type) while
        # still catching real drift like ``String(128) → String(64)``
        # which the name + nullability checks above would miss.
        from sqlalchemy.dialects import sqlite

        sqlite_dialect = sqlite.dialect()
        for col in _scheduler_tasks.columns:
            mig_compiled = cols[col.name]["type"].compile(dialect=sqlite_dialect).upper()
            table_compiled = col.type.compile(dialect=sqlite_dialect).upper()
            assert mig_compiled == table_compiled, (
                f"column {col.name!r} type drift on SQLite: migration "
                f"reflects {mig_compiled!r}; _scheduler_tasks Table "
                f"declares {table_compiled!r}"
            )

        # PK parity — task_id is the natural PK (NOT a surrogate `id`;
        # scheduler-side decision per spec §4.4)
        pk_cols = {col.name for col in _scheduler_tasks.primary_key.columns}
        assert pk_cols == {"task_id"}, (
            f"_scheduler_tasks primary key cols={pk_cols} (expected {{'task_id'}})"
        )

    async def test_scheduler_tasks_indexes_present(self, tmp_path: Any) -> None:
        url = f"sqlite+aiosqlite:///{tmp_path / 't5_idx.db'}"
        await _upgrade_to_head(url)

        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            indexes = await conn.run_sync(lambda c: sa_inspect(c).get_indexes("scheduler_tasks"))
        await check_engine.dispose()

        idx_names = {i["name"] for i in indexes}
        # Composite serving the per-tenant per-class concurrent-count
        # query (spec §4.5)
        assert "ix_scheduler_tasks_tenant_class_state" in idx_names
        # Parent-task lookup serving sub-agent budget inheritance
        # (spec §4.10; Sprint 11)
        assert "ix_scheduler_tasks_parent" in idx_names

        tenant_class_state = next(
            i for i in indexes if i["name"] == "ix_scheduler_tasks_tenant_class_state"
        )
        assert tenant_class_state["column_names"] == ["tenant_id", "class_", "state"]


class TestSprint105aMigration0005RoundTrip:
    async def test_downgrade_to_0004_drops_scheduler_tasks(self, tmp_path: Any) -> None:
        url = f"sqlite+aiosqlite:///{tmp_path / 't5_down.db'}"
        await _upgrade_to_head(url)

        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            pre_tables = await conn.run_sync(lambda c: set(sa_inspect(c).get_table_names()))
        await check_engine.dispose()
        assert "scheduler_tasks" in pre_tables, (
            "migration 0005 did not create scheduler_tasks at head — "
            "RED-state or upgrade path is broken"
        )

        await _downgrade_to(url, "0004")

        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            tables = await conn.run_sync(lambda c: set(sa_inspect(c).get_table_names()))
        await check_engine.dispose()

        assert "scheduler_tasks" not in tables, (
            "downgrade did not drop scheduler_tasks — asymmetric op.create_table / op.drop_table"
        )
        # Substrate untouched by the downgrade
        assert "audit_event" in tables
        assert "decision_history" in tables
        assert "governance_chain_heads" in tables
        assert "models" in tables

    async def test_downgrade_then_upgrade_restores_scheduler_tasks(self, tmp_path: Any) -> None:
        url = f"sqlite+aiosqlite:///{tmp_path / 't5_rt.db'}"
        await _upgrade_to_head(url)
        await _downgrade_to(url, "0004")
        await _upgrade_to_head(url)

        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            tables = await conn.run_sync(lambda c: set(sa_inspect(c).get_table_names()))
        await check_engine.dispose()

        assert "scheduler_tasks" in tables


class TestSprint105aMigration0005TimestampTypeIsOracleSafe:
    def test_ts_type_compiles_to_timestamp_with_time_zone_on_oracle(self) -> None:
        from sqlalchemy.dialects import oracle, postgresql

        migration = importlib.import_module(MIGRATION_MODULE_NAME)
        ts_type = migration.SCHEDULER_TS_TYPE

        oracle_compiled = ts_type.compile(dialect=oracle.dialect())  # type: ignore[no-untyped-call]
        postgres_compiled = ts_type.compile(dialect=postgresql.dialect())  # type: ignore[no-untyped-call]

        assert "TIMESTAMP" in oracle_compiled.upper()
        assert "TIME ZONE" in oracle_compiled.upper(), (
            f"SCHEDULER_TS_TYPE lost timezone on Oracle: compiled to {oracle_compiled!r}"
        )
        assert "TIMESTAMP" in postgres_compiled.upper()
        assert "TIME ZONE" in postgres_compiled.upper()


class TestSprint105aMigration0005CheckConstraints:
    async def test_migrated_db_has_ck_scheduler_tasks_state(self, tmp_path: Any) -> None:
        url = f"sqlite+aiosqlite:///{tmp_path / 't5_ck_state.db'}"
        await _upgrade_to_head(url)

        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            ccs = await conn.run_sync(
                lambda c: sa_inspect(c).get_check_constraints("scheduler_tasks")
            )
        await check_engine.dispose()

        names = {cc["name"] for cc in ccs}
        assert "ck_scheduler_tasks_state" in names
        state_check = next(cc for cc in ccs if cc["name"] == "ck_scheduler_tasks_state")
        sqltext = state_check["sqltext"]
        for expected in (
            "pending",
            "running",
            "completed",
            "failed",
            "cancelled",
            "preempted",
            "expired",
        ):
            assert expected in sqltext, (
                f"ck_scheduler_tasks_state missing SchedulerTaskState value {expected!r}"
            )

    async def test_migrated_db_has_ck_scheduler_tasks_class_(self, tmp_path: Any) -> None:
        url = f"sqlite+aiosqlite:///{tmp_path / 't5_ck_class.db'}"
        await _upgrade_to_head(url)

        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            ccs = await conn.run_sync(
                lambda c: sa_inspect(c).get_check_constraints("scheduler_tasks")
            )
        await check_engine.dispose()

        names = {cc["name"] for cc in ccs}
        assert "ck_scheduler_tasks_class_" in names
        class_check = next(cc for cc in ccs if cc["name"] == "ck_scheduler_tasks_class_")
        sqltext = class_check["sqltext"]
        for expected in ("interactive", "background"):
            assert expected in sqltext

    def test_migration_source_declares_both_check_constraints(self) -> None:
        migration = importlib.import_module(MIGRATION_MODULE_NAME)
        src = py_inspect.getsource(migration)
        assert 'name="ck_scheduler_tasks_state"' in src
        assert 'name="ck_scheduler_tasks_class_"' in src
        # Closed-enum vocabulary present in source
        for value in ("'pending'", "'running'", "'expired'"):
            assert value in src
        for value in ("'interactive'", "'background'"):
            assert value in src


class TestSprint105aMigration0005NoDecisionHistorySchemaChange:
    def test_upgrade_and_downgrade_do_not_reference_decision_history(self) -> None:
        migration = importlib.import_module(MIGRATION_MODULE_NAME)
        for fn, label in (
            (migration.upgrade, "upgrade"),
            (migration.downgrade, "downgrade"),
        ):
            body = py_inspect.getsource(fn)
            assert "decision_history" not in body, (
                f"{label}() references decision_history — schema change forbidden"
            )


class TestSprint105aMigration0005ModuleSurface:
    def test_migration_exports_revision_metadata(self) -> None:
        migration = importlib.import_module(MIGRATION_MODULE_NAME)
        assert migration.revision == "0005"
        assert migration.down_revision == "0004"
        assert migration.branch_labels is None
        assert migration.depends_on is None

    def test_migration_exports_scheduler_ts_type_constant(self) -> None:
        migration = importlib.import_module(MIGRATION_MODULE_NAME)
        assert hasattr(migration, "SCHEDULER_TS_TYPE")
        assert isinstance(migration.SCHEDULER_TS_TYPE, sa.TIMESTAMP), (
            f"SCHEDULER_TS_TYPE must be sa.TIMESTAMP, got "
            f"{type(migration.SCHEDULER_TS_TYPE).__name__}"
        )

    def test_migration_defines_upgrade_and_downgrade_callables(self) -> None:
        migration = importlib.import_module(MIGRATION_MODULE_NAME)
        assert callable(migration.upgrade)
        assert callable(migration.downgrade)
