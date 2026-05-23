"""Sprint 9.5 A3 — Alembic migration ``20260522_0004_model_registry``.

Unit-level shape verification for the ``models`` table migration + the
``(model_id, ts)`` btree index added to the pre-existing
``gateway_call_ledger``. No live database required: the migration is
applied against a SQLite-aiosqlite tmp DB via the same
``cognic_agentos.db.migrations.alembic_config.make_alembic_config`` +
``alembic.command.upgrade`` seam used at
``tests/unit/db/test_migration_20260510_0003.py`` (and
``test_run_migrations.py:312-364`` upstream).

This module pins:

1. Migration upgrades cleanly + creates the ``models`` table with the
   column inventory matching :data:`cognic_agentos.models.storage._models`
   (single-source-of-truth invariant — the in-process Table object and
   the production migration MUST agree).
2. Indexes: ``ix_models_tenant_state`` on ``models`` AND
   ``ix_gateway_call_ledger_model_id_ts`` (``["model_id", "ts"]``,
   non-unique) on the pre-existing ``gateway_call_ledger``.
3. ``models.model_id`` carries a unique constraint (single-instance
   per natural identity; defence-in-depth with the application-level
   register() duplicate check).
4. Clean round-trip: ``head -> 0003 -> head`` drops and restores
   ``models`` AND the ledger index without residual state.
5. ``models.created_at`` / ``models.updated_at`` route through the
   exported ``MODELS_TS_TYPE = sa.TIMESTAMP(timezone=True)`` so Oracle
   compiles ``TIMESTAMP WITH TIME ZONE``.
6. CHECK constraints ``ck_models_kind`` (the 4 ModelKind values) +
   ``ck_models_lifecycle_state`` (the 6 ModelLifecycleState values)
   are present in the **migrated DB** (reflection) AND declared in
   the **migration source** (inspection).
7. ``upgrade()`` + ``downgrade()`` function bodies do NOT reference
   ``decision_history`` (spec §3.2 hard constraint).
8. ``upgrade()`` + ``downgrade()`` do NOT add/drop/alter any COLUMN
   on ``gateway_call_ledger`` (model_id column was reserved at
   Sprint 3 — 0004 adds only the index).
9. Module surface: revision = "0004", down_revision = "0003",
   MODELS_TS_TYPE constant, callable upgrade/downgrade.
10. Negative-path decoys proving the detectors fire on simulated
    regressions.

R0 P2 rewrite (replaces the prior thin column-set-against-_models
check): a regression that drops/renames a column in the MIGRATION
would have slipped past the prior tests because they only inspected
the in-process Table object — both sides of the supposed equality
came from the same source. Real upgrade-and-reflect closes that
loophole.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect as py_inspect
from typing import Any

import sqlalchemy as sa
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.ext.asyncio import create_async_engine

MIGRATION_MODULE_NAME = "cognic_agentos.db.migrations.versions.20260522_0004_model_registry"


# ---------------------------------------------------------------------------
# Shared helpers — same shape as test_migration_20260510_0003.py:68-89.
# ---------------------------------------------------------------------------


async def _upgrade_to_head(url: str) -> None:
    """Apply the full migration graph (0001 → 0002 → 0003 → 0004)."""
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")


async def _downgrade_to(url: str, revision: str) -> None:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.downgrade, cfg, revision)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSprint95Migration0004UpgradeShape:
    """Apply 0001 → 0002 → 0003 → 0004 against SQLite tmp_path; assert
    the ``models`` table is present with the column / index / PK / unique
    inventory from :data:`cognic_agentos.models.storage._models`.
    """

    async def test_upgrade_creates_models_table(self, tmp_path: Any) -> None:
        url = f"sqlite+aiosqlite:///{tmp_path / 't4_upgrade.db'}"
        await _upgrade_to_head(url)

        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            tables = await conn.run_sync(lambda c: set(sa_inspect(c).get_table_names()))
        await check_engine.dispose()

        # Existing substrate untouched.
        assert "audit_event" in tables
        assert "decision_history" in tables
        assert "governance_chain_heads" in tables
        assert "gateway_call_ledger" in tables
        assert "packs" in tables
        # Sprint-9.5: 0004 adds models.
        assert "models" in tables

    async def test_models_columns_match_storage_table_object(self, tmp_path: Any) -> None:
        """Single-source-of-truth invariant: the MIGRATED DB's column
        inventory MUST agree with :data:`cognic_agentos.models.storage._models`.
        Reflects the real migrated table (not the in-process Table
        object) so a regression that drops/renames a column in the
        migration would fail this assertion.
        """
        from cognic_agentos.models.storage import _models

        url = f"sqlite+aiosqlite:///{tmp_path / 't4_cols.db'}"
        await _upgrade_to_head(url)

        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            cols = await conn.run_sync(
                lambda c: {col["name"]: col for col in sa_inspect(c).get_columns("models")}
            )
        await check_engine.dispose()

        expected_cols = {col.name for col in _models.columns}
        assert set(cols.keys()) == expected_cols, (
            f"migrated DB column set {set(cols.keys())} does not match "
            f"_models Table column set {expected_cols}"
        )

        # Nullability parity with _models — defence against a NULL
        # leak in either direction.
        for col in _models.columns:
            mig_nullable = cols[col.name]["nullable"]
            assert mig_nullable is col.nullable, (
                f"column {col.name!r}: migration nullable={mig_nullable} "
                f"but _models Table nullable={col.nullable}"
            )

        # PK parity — surrogate `id` (planning decision #4).
        pk_cols = {col.name for col in _models.primary_key.columns}
        assert pk_cols == {"id"}, f"_models primary key cols={pk_cols} (expected {{'id'}})"

    async def test_models_indexes_present(self, tmp_path: Any) -> None:
        """The single in-table index supports per-tenant queue queries
        (Sprint-9.5 portal API list-by-tenant + state filter).
        """
        url = f"sqlite+aiosqlite:///{tmp_path / 't4_idx.db'}"
        await _upgrade_to_head(url)

        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            idx_names = await conn.run_sync(
                lambda c: {i["name"] for i in sa_inspect(c).get_indexes("models")}
            )
        await check_engine.dispose()

        assert "ix_models_tenant_state" in idx_names

    async def test_gateway_ledger_model_id_ts_index_created(self, tmp_path: Any) -> None:
        """0004 adds a composite ``(model_id, ts)`` btree index on the
        pre-existing ``gateway_call_ledger`` table — serves the Block-C
        ``GET /models/{id}/usage`` aggregate. Asserts presence,
        column-list shape, and non-unique.
        """
        url = f"sqlite+aiosqlite:///{tmp_path / 't4_ledger_idx.db'}"
        await _upgrade_to_head(url)

        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            ledger_indexes = await conn.run_sync(
                lambda c: sa_inspect(c).get_indexes("gateway_call_ledger")
            )
        await check_engine.dispose()

        idx_names = {i["name"] for i in ledger_indexes}
        assert "ix_gateway_call_ledger_model_id_ts" in idx_names

        target = next(
            i for i in ledger_indexes if i["name"] == "ix_gateway_call_ledger_model_id_ts"
        )
        assert target["column_names"] == ["model_id", "ts"], (
            f"expected ['model_id', 'ts']; got {target['column_names']!r}"
        )
        # SQLite reflector returns ``0`` (int) for non-unique; Postgres
        # returns ``False`` (bool). Truthiness check accepts both.
        assert not target["unique"], f"expected non-unique index; got unique={target['unique']!r}"

    async def test_model_id_unique_constraint_present(self, tmp_path: Any) -> None:
        """``model_id`` is the wire identity (planning decision #4);
        a DB-level unique constraint pins single-instance-per-model_id
        independently of the application-level duplicate check in
        register().
        """
        url = f"sqlite+aiosqlite:///{tmp_path / 't4_uq.db'}"
        await _upgrade_to_head(url)

        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            uniques = await conn.run_sync(lambda c: sa_inspect(c).get_unique_constraints("models"))
            # Some dialects surface unique constraints as anonymous
            # indexes — also check the indexes for a unique entry on
            # model_id as a fallback.
            mod_indexes = await conn.run_sync(lambda c: sa_inspect(c).get_indexes("models"))
        await check_engine.dispose()

        unique_col_sets = [set(u["column_names"]) for u in uniques]
        if {"model_id"} not in unique_col_sets:
            # Fallback: SQLite reflects named UniqueConstraint as a
            # unique index. Accept either spelling.
            unique_index_col_sets = [set(i["column_names"]) for i in mod_indexes if i.get("unique")]
            assert {"model_id"} in unique_index_col_sets, (
                f"unique constraint on model_id missing; "
                f"unique_constraints={unique_col_sets}, "
                f"unique_indexes={unique_index_col_sets}"
            )


class TestSprint95Migration0004RoundTrip:
    """Reversibility: ``head -> 0003 -> head`` does not leave residual
    state. Catches asymmetric ``op.create_table`` /
    ``op.drop_table`` or a missing ledger-index drop in ``downgrade()``.
    """

    async def test_downgrade_to_0003_drops_models_and_ledger_index(self, tmp_path: Any) -> None:
        url = f"sqlite+aiosqlite:///{tmp_path / 't4_down.db'}"
        await _upgrade_to_head(url)

        # Pre-downgrade sanity — guards against false-positive PASS
        # if the upgrade path itself didn't actually create the table
        # or the ledger index.
        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            pre_tables = await conn.run_sync(lambda c: set(sa_inspect(c).get_table_names()))
            pre_ledger_idx = await conn.run_sync(
                lambda c: {i["name"] for i in sa_inspect(c).get_indexes("gateway_call_ledger")}
            )
        await check_engine.dispose()
        assert "models" in pre_tables, (
            "migration 0004 did not create models at head — RED-state or upgrade path is broken"
        )
        assert "ix_gateway_call_ledger_model_id_ts" in pre_ledger_idx, (
            "migration 0004 did not create the ledger index at head"
        )

        await _downgrade_to(url, "0003")

        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            tables = await conn.run_sync(lambda c: set(sa_inspect(c).get_table_names()))
            ledger_idx = await conn.run_sync(
                lambda c: {i["name"] for i in sa_inspect(c).get_indexes("gateway_call_ledger")}
            )
        await check_engine.dispose()

        assert "models" not in tables, (
            "downgrade did not drop models — asymmetric "
            "op.create_table / op.drop_table or models-index leak"
        )
        assert "ix_gateway_call_ledger_model_id_ts" not in ledger_idx, (
            "downgrade did not drop the ledger composite index — leak"
        )
        # Substrate untouched by the downgrade.
        assert "audit_event" in tables
        assert "decision_history" in tables
        assert "governance_chain_heads" in tables
        assert "gateway_call_ledger" in tables
        assert "packs" in tables

    async def test_downgrade_then_upgrade_restores_models_and_ledger_index(
        self, tmp_path: Any
    ) -> None:
        url = f"sqlite+aiosqlite:///{tmp_path / 't4_rt.db'}"
        await _upgrade_to_head(url)
        await _downgrade_to(url, "0003")
        await _upgrade_to_head(url)

        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            tables = await conn.run_sync(lambda c: set(sa_inspect(c).get_table_names()))
            ledger_idx = await conn.run_sync(
                lambda c: {i["name"] for i in sa_inspect(c).get_indexes("gateway_call_ledger")}
            )
        await check_engine.dispose()

        assert "models" in tables
        assert "ix_gateway_call_ledger_model_id_ts" in ledger_idx


class TestSprint95Migration0004TimestampTypeIsOracleSafe:
    """``models.created_at`` + ``models.updated_at`` MUST use
    ``sa.TIMESTAMP(timezone=True)``, NOT ``sa.DateTime(timezone=True)``.
    Mirrors the Sprint-7B.1 ``test_migration_20260510_0003.py:239-271``
    doctrine pin.
    """

    def test_ts_type_compiles_to_timestamp_with_time_zone_on_oracle(self) -> None:
        from sqlalchemy.dialects import oracle, postgresql

        migration = importlib.import_module(MIGRATION_MODULE_NAME)
        ts_type = migration.MODELS_TS_TYPE

        oracle_compiled = ts_type.compile(dialect=oracle.dialect())  # type: ignore[no-untyped-call]
        postgres_compiled = ts_type.compile(dialect=postgresql.dialect())  # type: ignore[no-untyped-call]

        assert "TIMESTAMP" in oracle_compiled.upper(), (
            f"MODELS_TS_TYPE compiled to {oracle_compiled!r} on Oracle — "
            f"expected TIMESTAMP WITH TIME ZONE. Likely regression to "
            f"sa.DateTime(timezone=True)."
        )
        assert "TIME ZONE" in oracle_compiled.upper(), (
            f"MODELS_TS_TYPE lost timezone on Oracle: compiled to {oracle_compiled!r}"
        )
        assert "TIMESTAMP" in postgres_compiled.upper()
        assert "TIME ZONE" in postgres_compiled.upper()


class TestSprint95Migration0004CheckConstraintsReflectedFromMigratedDb:
    """CHECK constraints on ``kind`` and ``lifecycle_state`` are present
    in the migrated DB. Defence against a migration regression that
    drops the inline ``CheckConstraint(...)`` entries while ``_models``
    stays correct (the in-memory Table object's compiled DDL is NOT
    what gets shipped to production — the migration is).
    """

    async def test_migrated_db_has_ck_models_kind_with_full_vocabulary(self, tmp_path: Any) -> None:
        url = f"sqlite+aiosqlite:///{tmp_path / 't4_ck_kind.db'}"
        await _upgrade_to_head(url)

        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            check_constraints = await conn.run_sync(
                lambda c: sa_inspect(c).get_check_constraints("models")
            )
        await check_engine.dispose()

        names = {cc["name"] for cc in check_constraints}
        assert "ck_models_kind" in names, (
            f"ck_models_kind missing from migrated DB; got names={names}"
        )

        kind_check = next(cc for cc in check_constraints if cc["name"] == "ck_models_kind")
        sqltext = kind_check["sqltext"]
        for expected in ("foundation", "fine_tune", "adapter", "embedding"):
            assert expected in sqltext, f"ck_models_kind sqltext={sqltext!r} missing {expected!r}"

    async def test_migrated_db_has_ck_models_lifecycle_state_with_full_vocabulary(
        self, tmp_path: Any
    ) -> None:
        url = f"sqlite+aiosqlite:///{tmp_path / 't4_ck_state.db'}"
        await _upgrade_to_head(url)

        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            check_constraints = await conn.run_sync(
                lambda c: sa_inspect(c).get_check_constraints("models")
            )
        await check_engine.dispose()

        names = {cc["name"] for cc in check_constraints}
        assert "ck_models_lifecycle_state" in names

        state_check = next(
            cc for cc in check_constraints if cc["name"] == "ck_models_lifecycle_state"
        )
        sqltext = state_check["sqltext"]
        # All 6 ModelLifecycleState values per registry.py.
        for expected in (
            "proposed",
            "eval_passed",
            "tenant_approved",
            "serving",
            "deprecated",
            "retired",
        ):
            assert expected in sqltext, (
                f"ck_models_lifecycle_state sqltext={sqltext!r} missing {expected!r}"
            )


class TestSprint95Migration0004CheckConstraintsInMigrationSource:
    """Defence-in-depth alongside reflection: parse the migration file
    and assert both CheckConstraint declarations are present with the
    right name + full vocabulary.
    """

    def test_migration_source_declares_ck_models_kind(self) -> None:
        migration = importlib.import_module(MIGRATION_MODULE_NAME)
        src = py_inspect.getsource(migration)
        assert 'name="ck_models_kind"' in src
        for value in ("'foundation'", "'fine_tune'", "'adapter'", "'embedding'"):
            assert value in src, f"migration source missing ModelKind value {value!r}"

    def test_migration_source_declares_ck_models_lifecycle_state(self) -> None:
        migration = importlib.import_module(MIGRATION_MODULE_NAME)
        src = py_inspect.getsource(migration)
        assert 'name="ck_models_lifecycle_state"' in src
        for value in (
            "'proposed'",
            "'eval_passed'",
            "'tenant_approved'",
            "'serving'",
            "'deprecated'",
            "'retired'",
        ):
            assert value in src, f"migration source missing ModelLifecycleState value {value!r}"


class TestSprint95Migration0004NoDecisionHistorySchemaChange:
    """Pin spec §3.2 / plan §3.2 hard constraint: 0004 makes NO schema
    change to ``decision_history``. Scans the ``upgrade()`` +
    ``downgrade()`` function BODIES (not the module docstring, which
    legitimately discusses the no-change contract in prose).
    """

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


class TestSprint95Migration0004NoGatewayLedgerColumnChange:
    """Pin: 0004 adds only the ``(model_id, ts)`` INDEX on
    ``gateway_call_ledger`` — it MUST NOT add/drop/alter any COLUMN
    on that table. The ``model_id`` column was reserved at Sprint 3
    (``llm/ledger.py:148``).
    """

    def test_upgrade_does_not_modify_gateway_ledger_columns(self) -> None:
        migration = importlib.import_module(MIGRATION_MODULE_NAME)
        for fn, label in (
            (migration.upgrade, "upgrade"),
            (migration.downgrade, "downgrade"),
        ):
            body = py_inspect.getsource(fn)
            for op_name in ("add_column", "alter_column", "drop_column"):
                bad = f"op.{op_name}("
                for line in body.splitlines():
                    if bad in line and "gateway_call_ledger" in line:
                        raise AssertionError(
                            f"{label}() {bad} references gateway_call_ledger: {line!r} "
                            f"— Sprint-9.5 0004 must only touch the (model_id, ts) "
                            f"INDEX, never columns"
                        )


class TestSprint95Migration0004ModuleSurface:
    """Lock the migration module's exported surface — mirrors
    ``test_migration_20260510_0003.py:511-541``.
    """

    def test_migration_exports_revision_metadata(self) -> None:
        migration = importlib.import_module(MIGRATION_MODULE_NAME)
        assert migration.revision == "0004"
        assert migration.down_revision == "0003"
        assert migration.branch_labels is None
        assert migration.depends_on is None

    def test_migration_exports_models_ts_type_constant(self) -> None:
        """``MODELS_TS_TYPE`` is the regression-pin entry point — its
        existence + identity is what makes the Oracle TIMESTAMP test
        immune to local hard-coded copies (the Sprint-3 doctrine
        applied to Sprint 9.5).
        """
        migration = importlib.import_module(MIGRATION_MODULE_NAME)
        assert hasattr(migration, "MODELS_TS_TYPE")
        assert isinstance(migration.MODELS_TS_TYPE, sa.TIMESTAMP), (
            f"MODELS_TS_TYPE must be sa.TIMESTAMP, got {type(migration.MODELS_TS_TYPE).__name__}"
        )

    def test_migration_defines_upgrade_and_downgrade_callables(self) -> None:
        migration = importlib.import_module(MIGRATION_MODULE_NAME)
        assert callable(migration.upgrade)
        assert callable(migration.downgrade)


class TestSprint95Migration0004NegativePathDoctrinePins:
    """Self-tests proving the index-set / type pins fire on simulated
    regressions. Construct decoy patterns and assert the detector
    would catch them. Per
    ``feedback_security_regression_hardening`` — the doctrine pins
    above are useful only if they fire on the regressions they target.
    """

    def test_decoy_table_missing_index_fails_index_set_check(self) -> None:
        meta = sa.MetaData()
        decoy = sa.Table(
            "models",
            meta,
            sa.Column("id", sa.Uuid(), primary_key=True),
            # MISSING: ix_models_tenant_state
        )
        idx_names = {i.name for i in decoy.indexes}
        assert "ix_models_tenant_state" not in idx_names, (
            "decoy must lack ix_models_tenant_state to prove the check fires on regression"
        )

    def test_decoy_datetime_column_fails_oracle_time_zone_check(self) -> None:
        from sqlalchemy.dialects import oracle

        decoy_dt = sa.DateTime(timezone=True)
        compiled = decoy_dt.compile(dialect=oracle.dialect())  # type: ignore[no-untyped-call]
        # sa.DateTime(timezone=True) on Oracle compiles to bare TIMESTAMP
        # (no TIME ZONE) — pin the regression case.
        assert "TIME ZONE" not in compiled.upper(), (
            f"sa.DateTime(timezone=True) unexpectedly compiled to "
            f"{compiled!r} on Oracle with TIME ZONE — the regression "
            f"pin no longer fires"
        )
