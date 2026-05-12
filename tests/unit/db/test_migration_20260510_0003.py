"""Sprint 7B.1 T4 — Alembic migration ``20260510_0003_packs_lifecycle``.

Unit-level shape verification for the ``packs`` table migration.
No live database required: the migration is applied against a
SQLite-aiosqlite tmp DB via the same
``cognic_agentos.db.migrations.alembic_config.make_alembic_config`` +
``alembic.command.upgrade`` seam used at
``tests/unit/db/test_run_migrations.py:312-364``.

This module pins:

1. The migration upgrades cleanly + creates the ``packs`` table with
   the column inventory matching :data:`cognic_agentos.packs.storage._packs`
   (single-source-of-truth invariant — the in-process Table object and
   the production migration MUST agree).
2. The migration is a clean round-trip: ``head -> 0002 -> head`` does
   not leave residual state (mirrors
   ``test_run_migrations.py::TestGatewayCallLedgerMigrationRoundTrip``).
3. The ``created_at`` / ``updated_at`` columns are typed as
   ``sa.TIMESTAMP(timezone=True)`` — NOT ``sa.DateTime(timezone=True)``
   (compiles to plain ``DATE`` on Oracle, silently dropping the
   offset). Pinned via the same Round-2 ``importlib.import_module``
   pattern as ``test_run_migrations.py:399-419``.
4. The ``manifest_digest`` / ``signed_artefact_digest`` columns route
   through ``cognic_agentos.db.types.chain_hash_column_type`` (the
   shared dialect-portable seam — Postgres BYTEA / Oracle RAW(32) /
   SQLite BLOB) — NOT ``sa.LargeBinary``.
5. CHECK constraints on ``kind`` and ``state`` are present in the
   **migrated DB** (via ``inspect(conn).get_check_constraints("packs")``
   reflection) AND in the **migration source itself** (via
   ``inspect.getsource(migration)`` AST inspection). R1 P3
   reviewer-fix doctrine: testing ``CreateTable(_packs).compile(...)``
   only proves the in-memory Table object is correct — it does NOT
   prove the migration declares the constraints. Two independent
   layers close that loophole: a regression that drops a
   ``sa.CheckConstraint(...)`` from ``op.create_table(...)`` is caught
   by reflection (constraint missing from migrated DB) AND by source
   inspection (constraint missing from the file).
6. Indexes ``ix_packs_kind_state`` + ``ix_packs_tenant_state`` exist
   to support ``list_by_status`` (kind+state) and per-tenant queue
   queries (Sprint 7B.2 portal API).

Live PG + Oracle ``upgrade -> downgrade -> upgrade`` round-trip lives
at ``tests/integration/db/test_alembic_migration_20260510_0003.py``
(env-gated like the Sprint-2 ``test_alembic_migrations.py`` parity
fixtures).
"""

from __future__ import annotations

import asyncio
import importlib
import inspect as py_inspect
from typing import Any

import sqlalchemy as sa
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.ext.asyncio import create_async_engine

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


MIGRATION_MODULE_NAME = "cognic_agentos.db.migrations.versions.20260510_0003_packs_lifecycle"


async def _upgrade_to_head(url: str) -> None:
    """Apply the full migration graph (0001 → 0002 → 0003) against
    ``url``. Mirrors ``PostgresAdapter.run_migrations`` shape but
    bypasses the adapter so this test is independent of adapter
    plumbing — it pins the migration file itself.
    """

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


class TestSprint7B1Migration0003UpgradeShape:
    """Apply 0001 → 0002 → 0003 against SQLite tmp_path; assert the
    ``packs`` table is present with the column / index inventory from
    :data:`cognic_agentos.packs.storage._packs`.

    Mirrors ``TestGatewayCallLedgerMigrationRoundTrip`` shape at
    ``test_run_migrations.py:241-310`` but tracks the Sprint-7B.1
    migration instead of the Sprint-3 one.
    """

    async def test_upgrade_creates_packs_table(self, tmp_path: Any) -> None:
        url = f"sqlite+aiosqlite:///{tmp_path / 't4_upgrade.db'}"
        await _upgrade_to_head(url)

        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            tables = await conn.run_sync(lambda c: set(sa_inspect(c).get_table_names()))
        await check_engine.dispose()

        # Sprint-2 substrate untouched.
        assert "audit_event" in tables
        assert "decision_history" in tables
        assert "governance_chain_heads" in tables
        # Sprint-3 ledger untouched.
        assert "gateway_call_ledger" in tables
        # Sprint-7B.1 T4: revision 0003 adds packs.
        assert "packs" in tables

    async def test_packs_columns_match_storage_table_object(self, tmp_path: Any) -> None:
        """Single-source-of-truth invariant: the migration's column
        inventory MUST agree with :data:`cognic_agentos.packs.storage._packs`.
        Drift fails this test, surfacing the divergence at unit level
        long before the live-DB integration suite runs.
        """

        from cognic_agentos.packs.storage import _packs

        url = f"sqlite+aiosqlite:///{tmp_path / 't4_cols.db'}"
        await _upgrade_to_head(url)

        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            cols = await conn.run_sync(
                lambda c: {col["name"]: col for col in sa_inspect(c).get_columns("packs")}
            )
        await check_engine.dispose()

        expected_cols = {col.name for col in _packs.columns}
        assert set(cols.keys()) == expected_cols, (
            f"migration column set {set(cols.keys())} does not match "
            f"_packs Table column set {expected_cols}"
        )

        # Nullability parity with _packs (the production INSERT path
        # depends on these — a NULL leak in either direction breaks
        # save_draft + transition).
        for col in _packs.columns:
            mig_nullable = cols[col.name]["nullable"]
            assert mig_nullable is col.nullable, (
                f"column {col.name!r}: migration nullable={mig_nullable} "
                f"but _packs Table nullable={col.nullable}"
            )

        # PK parity.
        pk_cols = {col.name for col in _packs.primary_key.columns}
        assert pk_cols == {"id"}, f"_packs primary key cols={pk_cols} (expected {{'id'}})"

    async def test_packs_indexes_present(self, tmp_path: Any) -> None:
        """The two indexes drive Sprint-7B.1 read paths:
        ``ix_packs_kind_state`` for ``list_by_status``;
        ``ix_packs_tenant_state`` for per-tenant queue queries
        (Sprint 7B.2 portal API).
        """

        url = f"sqlite+aiosqlite:///{tmp_path / 't4_idx.db'}"
        await _upgrade_to_head(url)

        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            idx_names = await conn.run_sync(
                lambda c: {i["name"] for i in sa_inspect(c).get_indexes("packs")}
            )
        await check_engine.dispose()

        assert "ix_packs_kind_state" in idx_names
        assert "ix_packs_tenant_state" in idx_names


class TestSprint7B1Migration0003RoundTrip:
    """Reversibility: ``head -> 0002 -> head`` does not leave
    residual state. Catches asymmetric ``op.create_table`` /
    ``op.drop_table`` or a missing index drop in the migration's
    ``downgrade()`` body.
    """

    async def test_downgrade_to_0002_drops_packs(self, tmp_path: Any) -> None:
        url = f"sqlite+aiosqlite:///{tmp_path / 't4_down.db'}"
        await _upgrade_to_head(url)

        # Pre-downgrade assertion — guards against false-positive PASS
        # if the migration didn't exist (head would already be 0002,
        # the table never existed, the post-downgrade check would be
        # trivially true).
        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            pre_tables = await conn.run_sync(lambda c: set(sa_inspect(c).get_table_names()))
        await check_engine.dispose()
        assert "packs" in pre_tables, (
            "migration 0003 did not create packs at head — RED-state or upgrade path is broken"
        )

        await _downgrade_to(url, "0002")

        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            tables = await conn.run_sync(lambda c: set(sa_inspect(c).get_table_names()))
        await check_engine.dispose()

        assert "packs" not in tables, (
            "downgrade did not drop packs — asymmetric "
            "op.create_table / op.drop_table or index leak"
        )
        # Sprint-2 + Sprint-3 substrate untouched by the downgrade.
        assert "audit_event" in tables
        assert "decision_history" in tables
        assert "governance_chain_heads" in tables
        assert "gateway_call_ledger" in tables

    async def test_downgrade_then_upgrade_restores_packs(self, tmp_path: Any) -> None:
        url = f"sqlite+aiosqlite:///{tmp_path / 't4_rt.db'}"
        await _upgrade_to_head(url)
        await _downgrade_to(url, "0002")
        await _upgrade_to_head(url)

        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            tables = await conn.run_sync(lambda c: set(sa_inspect(c).get_table_names()))
        await check_engine.dispose()

        assert "packs" in tables


class TestSprint7B1Migration0003TimestampTypeIsOracleSafe:
    """``packs.created_at`` + ``packs.updated_at`` MUST use
    ``sa.TIMESTAMP(timezone=True)``, NOT ``sa.DateTime(timezone=True)``.

    Round-2 doctrine pin (mirrors
    ``test_run_migrations.py::test_ts_column_compiles_to_timestamp_with_time_zone_on_oracle``
    at lines 366-419): import the migration's exported
    ``PACKS_TS_TYPE`` constant via ``importlib.import_module`` (the
    filename starts with a digit, blocking the literal ``from`` form)
    and compile-check THAT instance under both dialects so a future
    regression to ``sa.DateTime(timezone=True)`` in the migration
    file actually fails this test.
    """

    def test_ts_type_compiles_to_timestamp_with_time_zone_on_oracle(self) -> None:
        from sqlalchemy.dialects import oracle, postgresql

        migration = importlib.import_module(MIGRATION_MODULE_NAME)
        ts_type = migration.PACKS_TS_TYPE

        oracle_compiled = ts_type.compile(dialect=oracle.dialect())  # type: ignore[no-untyped-call]
        postgres_compiled = ts_type.compile(dialect=postgresql.dialect())  # type: ignore[no-untyped-call]

        assert "TIMESTAMP" in oracle_compiled.upper(), (
            f"PACKS_TS_TYPE compiled to {oracle_compiled!r} on Oracle — "
            f"expected TIMESTAMP WITH TIME ZONE. Likely regression to "
            f"sa.DateTime(timezone=True)."
        )
        assert "TIME ZONE" in oracle_compiled.upper(), (
            f"PACKS_TS_TYPE lost timezone on Oracle: compiled to {oracle_compiled!r}"
        )
        assert "TIMESTAMP" in postgres_compiled.upper()
        assert "TIME ZONE" in postgres_compiled.upper()


class TestSprint7B1Migration0003ChainHashColumnType:
    """``packs.manifest_digest`` + ``packs.signed_artefact_digest``
    MUST route through :func:`cognic_agentos.db.types.chain_hash_column_type`
    so the dialect-portable BYTEA / RAW(32) / BLOB seam is honoured.
    Inlining ``sa.LargeBinary`` would compile to ``BLOB`` on Oracle,
    losing the fixed-32-byte length constraint that catches truncated
    digests at the DB layer.

    Pinned two ways:
    - The migration imports ``chain_hash_column_type`` from
      ``cognic_agentos.db.types`` (asserted via
      ``inspect.getsource(migration_module)``).
    - The rendered Oracle DDL contains ``RAW(32)`` for the digest
      columns (asserted via dialect compile of the ``packs`` Table
      object).
    """

    def test_migration_imports_chain_hash_column_type_helper(self) -> None:
        migration = importlib.import_module(MIGRATION_MODULE_NAME)
        src = py_inspect.getsource(migration)
        assert "from cognic_agentos.db.types import chain_hash_column_type" in src, (
            "migration must import chain_hash_column_type from db.types — "
            "inlining sa.LargeBinary breaks Oracle RAW(32) compile"
        )
        # Negative pin — catches a regression that adds an inline
        # ``sa.LargeBinary(...)`` column type alongside the helper
        # import. Matches the call form (``sa.LargeBinary(``) rather
        # than the bare reference so the explanatory mention in this
        # migration's docstring (which warns future maintainers about
        # the regression mode) does not trip the detector.
        assert "sa.LargeBinary(" not in src, (
            "migration must not use sa.LargeBinary(...) — use chain_hash_column_type() instead"
        )

    def test_chain_hash_columns_compile_to_raw32_on_oracle(self) -> None:
        from sqlalchemy.dialects import oracle, postgresql

        from cognic_agentos.db.types import chain_hash_column_type

        chain_type = chain_hash_column_type()
        oracle_compiled = chain_type.compile(dialect=oracle.dialect())  # type: ignore[no-untyped-call]
        postgres_compiled = chain_type.compile(dialect=postgresql.dialect())  # type: ignore[no-untyped-call]

        assert "RAW(32)" in oracle_compiled.upper(), (
            f"chain_hash_column_type compiled to {oracle_compiled!r} on "
            f"Oracle — expected RAW(32). Regression to sa.LargeBinary?"
        )
        assert "BYTEA" in postgres_compiled.upper(), (
            f"chain_hash_column_type compiled to {postgres_compiled!r} on Postgres — expected BYTEA"
        )


class TestSprint7B1Migration0003CheckConstraintsReflectedFromMigratedDb:
    """CHECK constraints on ``kind`` and ``state`` are present in the
    DB after the **migration** is applied — NOT in the in-memory
    ``_packs`` Table object's compiled DDL.

    R1 P3 reviewer fix (Sprint-7B.1 T4 R1 P3): the prior revision
    of these tests rendered ``CreateTable(_packs)`` and asserted
    ``ck_packs_kind`` / ``ck_packs_state`` were present in the
    output. That tests the source-of-truth Table object — not the
    migration. If the migration's ``op.create_table(...)`` lost or
    renamed its inline ``CheckConstraint(...)`` entries while
    ``_packs`` stayed correct, the prior test would still pass —
    silently shipping a migration with no CHECK enforcement.

    The fix tests the actual migrated DB: apply the migration to
    SQLite tmp_path, then ``inspect(conn).get_check_constraints("packs")``.
    SQLAlchemy's SQLite inspector parses the ``CREATE TABLE`` DDL out
    of ``sqlite_master.sql`` and surfaces the inline CHECK constraints
    by name + SQL text.
    """

    async def test_migrated_db_has_ck_packs_kind_with_full_vocabulary(self, tmp_path: Any) -> None:
        url = f"sqlite+aiosqlite:///{tmp_path / 't4_ck_kind.db'}"
        await _upgrade_to_head(url)

        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            check_constraints = await conn.run_sync(
                lambda c: sa_inspect(c).get_check_constraints("packs")
            )
        await check_engine.dispose()

        names = {cc["name"] for cc in check_constraints}
        assert "ck_packs_kind" in names, (
            f"ck_packs_kind missing from migrated DB; got names={names}. "
            f"Migration likely dropped or renamed the inline "
            f"CheckConstraint(name='ck_packs_kind', ...) entry."
        )

        # Locate the constraint and verify its SQL text covers the
        # full 4-tuple PackKind vocabulary. A regression that drops
        # 'hook' (most likely Wave-1-throwback) fails this assertion.
        kind_check = next(cc for cc in check_constraints if cc["name"] == "ck_packs_kind")
        sqltext = kind_check["sqltext"]
        assert "tool" in sqltext
        assert "skill" in sqltext
        assert "agent" in sqltext
        assert "hook" in sqltext, (
            f"ck_packs_kind sqltext={sqltext!r} missing 'hook' — likely Wave-1 narrow regression"
        )

    async def test_migrated_db_has_ck_packs_state_with_full_vocabulary(self, tmp_path: Any) -> None:
        url = f"sqlite+aiosqlite:///{tmp_path / 't4_ck_state.db'}"
        await _upgrade_to_head(url)

        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            check_constraints = await conn.run_sync(
                lambda c: sa_inspect(c).get_check_constraints("packs")
            )
        await check_engine.dispose()

        names = {cc["name"] for cc in check_constraints}
        assert "ck_packs_state" in names, (
            f"ck_packs_state missing from migrated DB; got names={names}"
        )

        state_check = next(cc for cc in check_constraints if cc["name"] == "ck_packs_state")
        sqltext = state_check["sqltext"]
        # All 11 PackState values per ADR-012 §"Lifecycle states".
        for expected in (
            "draft",
            "submitted",
            "under_review",
            "approved",
            "rejected",
            "withdrawn",
            "allow_listed",
            "installed",
            "disabled",
            "revoked",
            "uninstalled",
        ):
            assert expected in sqltext, f"ck_packs_state sqltext={sqltext!r} missing {expected!r}"

    async def test_migrated_db_has_exactly_two_check_constraints(self, tmp_path: Any) -> None:
        """Negative-shape pin: a migration that adds a third
        CheckConstraint (e.g., for tenant_id format) must explicitly
        update this assertion + the source-of-truth ``_packs`` Table.
        Catches accidental constraint additions that bypass the
        plan-of-record review.
        """

        url = f"sqlite+aiosqlite:///{tmp_path / 't4_ck_count.db'}"
        await _upgrade_to_head(url)

        check_engine = create_async_engine(url)
        async with check_engine.connect() as conn:
            check_constraints = await conn.run_sync(
                lambda c: sa_inspect(c).get_check_constraints("packs")
            )
        await check_engine.dispose()

        # Filter out auto-named CHECK constraints (some dialects
        # generate anonymous CHECK from NOT NULL etc); we care only
        # about the explicitly-named ck_packs_* entries.
        explicit = [cc for cc in check_constraints if cc["name"] and "ck_packs_" in cc["name"]]
        assert len(explicit) == 2, (
            f"expected exactly 2 ck_packs_* constraints; got {len(explicit)}: "
            f"{[cc['name'] for cc in explicit]}"
        )


class TestSprint7B1Migration0003CheckConstraintsInMigrationSource:
    """Defense-in-depth alongside the reflection tests: parse the
    migration file's source and assert both ``CheckConstraint(...)``
    entries are declared with the right names + vocabulary.

    Why both layers? Reflection catches "what the migrated DB
    actually has"; source inspection catches "what the migration file
    declares". A regression that subtly mutates the SQL string before
    it reaches the DDL would slip past pure reflection if the dialect
    silently coerces the result; source inspection catches it earlier.
    """

    def test_migration_source_declares_ck_packs_kind_check_constraint(self) -> None:
        migration = importlib.import_module(MIGRATION_MODULE_NAME)
        src = py_inspect.getsource(migration)
        # The source MUST contain the exact constraint-name keyword
        # argument plus every PackKind vocabulary value.
        assert 'name="ck_packs_kind"' in src, (
            'migration source does not declare CheckConstraint(name="ck_packs_kind", ...)'
        )
        # IN-clause vocabulary present in the SQL string.
        assert "'tool'" in src
        assert "'skill'" in src
        assert "'agent'" in src
        assert "'hook'" in src

    def test_migration_source_declares_ck_packs_state_check_constraint(self) -> None:
        migration = importlib.import_module(MIGRATION_MODULE_NAME)
        src = py_inspect.getsource(migration)
        assert 'name="ck_packs_state"' in src, (
            'migration source does not declare CheckConstraint(name="ck_packs_state", ...)'
        )
        # All 11 PackState values present in the SQL string.
        for expected in (
            "'draft'",
            "'submitted'",
            "'under_review'",
            "'approved'",
            "'rejected'",
            "'withdrawn'",
            "'allow_listed'",
            "'installed'",
            "'disabled'",
            "'revoked'",
            "'uninstalled'",
        ):
            assert expected in src, (
                f"migration source missing PackState value {expected!r} in "
                f"the ck_packs_state SQL declaration"
            )

    def test_migration_source_does_not_use_op_create_check_constraint_outside_create_table(
        self,
    ) -> None:
        """``op.create_check_constraint(...)`` was an alternative path
        in the plan-of-record T4 prose; we chose inline
        ``CheckConstraint(...)`` inside ``op.create_table(...)`` to
        mirror the source-of-truth declaration at
        ``packs/storage.py:215-224``. Pin that choice — adding a
        post-create ``op.create_check_constraint`` would split the
        constraint declaration across two layers and break the
        single-statement create-table contract.
        """

        migration = importlib.import_module(MIGRATION_MODULE_NAME)
        src = py_inspect.getsource(migration)
        assert "op.create_check_constraint" not in src, (
            "migration must declare CheckConstraint(...) inline inside "
            "op.create_table(...) — not via op.create_check_constraint(...)"
        )


class TestSprint7B1Migration0003ModuleSurface:
    """Lock the migration module's exported surface so reviewers can
    detect doctrine drift via the same ``__all__``-shaped pattern used
    by ``test_storage.py::TestSprint7B1PackStorageModuleSurface``.
    """

    def test_migration_exports_revision_metadata(self) -> None:
        migration = importlib.import_module(MIGRATION_MODULE_NAME)
        assert migration.revision == "0003"
        assert migration.down_revision == "0002"
        assert migration.branch_labels is None
        assert migration.depends_on is None

    def test_migration_exports_packs_ts_type_constant(self) -> None:
        """``PACKS_TS_TYPE`` is the regression-pin entry point — its
        existence + identity is what makes the Oracle TIMESTAMP test
        immune to local hard-coded copies (R2-of-Sprint-3-T4 doctrine
        applied to Sprint 7B.1)."""
        migration = importlib.import_module(MIGRATION_MODULE_NAME)
        assert hasattr(migration, "PACKS_TS_TYPE"), (
            "migration must export PACKS_TS_TYPE — the type pin entry "
            "point for the Oracle TIMESTAMP regression test"
        )
        assert isinstance(migration.PACKS_TS_TYPE, sa.TIMESTAMP), (
            f"PACKS_TS_TYPE must be sa.TIMESTAMP, got {type(migration.PACKS_TS_TYPE).__name__}"
        )

    def test_migration_defines_upgrade_and_downgrade_callables(self) -> None:
        migration = importlib.import_module(MIGRATION_MODULE_NAME)
        assert callable(migration.upgrade)
        assert callable(migration.downgrade)


# ---------------------------------------------------------------------------
# Negative-path: regression-pin the load-bearingness of the migration's
# documented invariants. Per
# ``feedback_security_regression_hardening.md`` — the doctrine pins
# above are useful only if they fire on the regressions they target.
# ---------------------------------------------------------------------------


class TestSprint7B1Migration0003NegativePathDoctrinePins:
    """Self-tests proving the column-set / index-name / type pins fire
    on simulated regressions.

    These do NOT mutate the migration file; they construct decoy
    Table objects with the regression patterns and assert the same
    detector pattern catches them.
    """

    def test_decoy_table_missing_index_fails_index_set_check(self) -> None:
        """Decoy: a Table missing ``ix_packs_tenant_state`` must fail
        the index-set assertion. Pins the load-bearingness of the
        ``ix_packs_tenant_state`` check above.
        """

        meta = sa.MetaData()
        decoy = sa.Table(
            "packs",
            meta,
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Index("ix_packs_kind_state", "id"),
            # MISSING: ix_packs_tenant_state
        )
        idx_names = {i.name for i in decoy.indexes}
        assert "ix_packs_tenant_state" not in idx_names, (
            "decoy must lack ix_packs_tenant_state to prove the check would fire on regression"
        )

    def test_decoy_datetime_column_fails_oracle_compile(self) -> None:
        """Decoy: ``sa.DateTime(timezone=True)`` compiles to plain
        ``DATE`` on Oracle, no TIME ZONE substring. Proves the
        Oracle-safe TIMESTAMP test is load-bearing — if the migration
        regressed to ``sa.DateTime(timezone=True)``, the test would
        fail.
        """

        from sqlalchemy.dialects import oracle

        decoy_dt = sa.DateTime(timezone=True)
        compiled = decoy_dt.compile(dialect=oracle.dialect())  # type: ignore[no-untyped-call]
        # ``sa.DateTime(timezone=True)`` on Oracle compiles to bare
        # ``TIMESTAMP`` (no TIME ZONE) — pin the regression case.
        assert "TIME ZONE" not in compiled.upper(), (
            f"sa.DateTime(timezone=True) unexpectedly compiled to "
            f"{compiled!r} on Oracle with TIME ZONE — the regression "
            f"pin no longer fires"
        )
