"""run_migrations() wiring on PostgresAdapter + OracleAdapter.

Sprint 2 Task 9 retires the Phase 1 NotImplementedError stubs by
wiring both adapters to invoke alembic.command.upgrade against the
adapter's own URL. Per the Sprint-2 doctrine amendment in PR #5:
production migrations are an operator job; the lifespan does NOT
auto-invoke this. The method is callable from operator-driven
contexts (CLI, deploy jobs, integration tests) only.

Unit tests run against in-memory-style SQLite-aiosqlite (file-backed
tmp DB so migrations can persist across the alembic invocation +
follow-up SELECTs). The same code path runs against PG and Oracle in
the env-gated integration suite (tests/integration/db/).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.db.adapters.oracle_adapter import OracleAdapter
from cognic_agentos.db.adapters.postgres_adapter import PostgresAdapter


class TestPostgresAdapterRunMigrations:
    """The PostgresAdapter is constructed with any SQLAlchemy URL; for
    unit tests we use SQLite-aiosqlite so the alembic invocation is
    fast + hermetic. The adapter's run_migrations should apply
    migration 0001 against whatever DB the URL points at."""

    async def test_applies_migration_0001(self, tmp_path: Any) -> None:
        url = f"sqlite+aiosqlite:///{tmp_path / 'pg_test.db'}"
        adapter = PostgresAdapter(url=url)
        await adapter.connect()
        try:
            await adapter.run_migrations(dir="ignored")
            # Verify the migration applied: alembic_version + the three
            # governance tables exist.
            check_engine = create_async_engine(url)
            async with check_engine.connect() as conn:
                result = await conn.execute(
                    text("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
                )
                tables = {r.name for r in result}
            await check_engine.dispose()
            assert "alembic_version" in tables
            assert "audit_event" in tables
            assert "decision_history" in tables
            assert "governance_chain_heads" in tables
            # Sprint 3 T4: revision 0002 adds the operational ledger.
            assert "gateway_call_ledger" in tables
        finally:
            await adapter.close()

    async def test_idempotent_second_call_no_op(self, tmp_path: Any) -> None:
        # alembic upgrade head is idempotent — second call sees
        # alembic_version at HEAD and exits cleanly.
        url = f"sqlite+aiosqlite:///{tmp_path / 'pg_idem.db'}"
        adapter = PostgresAdapter(url=url)
        await adapter.connect()
        try:
            await adapter.run_migrations()
            await adapter.run_migrations()  # must not raise
        finally:
            await adapter.close()

    async def test_dir_argument_accepted(self, tmp_path: Any) -> None:
        # The protocol's `dir` parameter is honoured for backwards
        # compatibility with the Sprint 1C/1D shape but ignored at
        # runtime — Sprint 2 anchors the canonical alembic env at
        # src/cognic_agentos/db/migrations/. Verify the arg passes
        # through without error regardless of value.
        url = f"sqlite+aiosqlite:///{tmp_path / 'pg_dir.db'}"
        adapter = PostgresAdapter(url=url)
        await adapter.connect()
        try:
            await adapter.run_migrations(dir="/some/ignored/path")
        finally:
            await adapter.close()

    async def test_no_longer_raises_not_implemented(self, tmp_path: Any) -> None:
        # Phase-1 stub raised NotImplementedError. Sprint 2 must NOT.
        url = f"sqlite+aiosqlite:///{tmp_path / 'pg_no_ni.db'}"
        adapter = PostgresAdapter(url=url)
        await adapter.connect()
        try:
            # Should complete without NotImplementedError.
            await adapter.run_migrations()
        except NotImplementedError:
            pytest.fail("PostgresAdapter.run_migrations still raises NotImplementedError")
        finally:
            await adapter.close()


class TestOracleAdapterRunMigrations:
    """OracleAdapter.run_migrations follows the same shape as the
    Postgres path. SQLite-aiosqlite is the unit-test substrate; live
    Oracle XE integration runs in tests/integration/db/."""

    async def test_applies_migration_0001(self, tmp_path: Any) -> None:
        url = f"sqlite+aiosqlite:///{tmp_path / 'oracle_test.db'}"
        adapter = OracleAdapter(url=url)
        await adapter.connect()
        try:
            await adapter.run_migrations()
            check_engine = create_async_engine(url)
            async with check_engine.connect() as conn:
                result = await conn.execute(
                    text("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
                )
                tables = {r.name for r in result}
            await check_engine.dispose()
            assert "alembic_version" in tables
            assert "audit_event" in tables
            assert "decision_history" in tables
            assert "governance_chain_heads" in tables
            # Sprint 3 T4: revision 0002 adds the operational ledger.
            assert "gateway_call_ledger" in tables
        finally:
            await adapter.close()

    async def test_idempotent_second_call_no_op(self, tmp_path: Any) -> None:
        url = f"sqlite+aiosqlite:///{tmp_path / 'oracle_idem.db'}"
        adapter = OracleAdapter(url=url)
        await adapter.connect()
        try:
            await adapter.run_migrations()
            await adapter.run_migrations()
        finally:
            await adapter.close()

    async def test_no_longer_raises_not_implemented(self, tmp_path: Any) -> None:
        url = f"sqlite+aiosqlite:///{tmp_path / 'oracle_no_ni.db'}"
        adapter = OracleAdapter(url=url)
        await adapter.connect()
        try:
            await adapter.run_migrations()
        except NotImplementedError:
            pytest.fail("OracleAdapter.run_migrations still raises NotImplementedError")
        finally:
            await adapter.close()


class TestRunMigrationsCwdIndependence:
    """Regression test for PR #6 P1 finding.

    Originally both adapters built ``Config("alembic.ini")`` — a
    CWD-relative path that worked from the repo root in CI but raised
    ``CommandError: No 'script_location' key found in configuration``
    from any other CWD or inside the production Docker images (which
    intentionally do not ship ``alembic.ini``). The fix routes both
    adapters through ``cognic_agentos.db.migrations.alembic_config.
    make_alembic_config``, which resolves ``script_location`` from the
    package via ``Path(__file__).parent`` — immune to CWD.

    These tests exercise the fix by chdir'ing to a CWD that
    *deliberately does not contain* an ``alembic.ini`` (a tmp_path
    sibling) and asserting ``run_migrations()`` still applies the
    migration. They guard against any future regression that
    re-introduces a relative ``Config(...)`` path.
    """

    async def test_postgres_run_migrations_works_from_unrelated_cwd(self, tmp_path: Any) -> None:
        url = f"sqlite+aiosqlite:///{tmp_path / 'pg_cwd.db'}"
        # CWD is a fresh empty directory with NO alembic.ini.
        cwd = tmp_path / "unrelated_cwd"
        cwd.mkdir()
        assert not (cwd / "alembic.ini").exists()

        adapter = PostgresAdapter(url=url)
        await adapter.connect()
        original_cwd = Path.cwd()
        try:
            os.chdir(cwd)
            await adapter.run_migrations()
            # Verify the migration actually applied (not just no-raise).
            check_engine = create_async_engine(url)
            async with check_engine.connect() as conn:
                result = await conn.execute(
                    text("SELECT name FROM sqlite_master WHERE type='table'")
                )
                tables = {r.name for r in result}
            await check_engine.dispose()
            assert "alembic_version" in tables
            assert "audit_event" in tables
            assert "decision_history" in tables
            assert "governance_chain_heads" in tables
            # Sprint 3 T4: revision 0002 adds the operational ledger.
            assert "gateway_call_ledger" in tables
        finally:
            os.chdir(original_cwd)
            await adapter.close()

    async def test_oracle_run_migrations_works_from_unrelated_cwd(self, tmp_path: Any) -> None:
        url = f"sqlite+aiosqlite:///{tmp_path / 'oracle_cwd.db'}"
        cwd = tmp_path / "unrelated_cwd"
        cwd.mkdir()
        assert not (cwd / "alembic.ini").exists()

        adapter = OracleAdapter(url=url)
        await adapter.connect()
        original_cwd = Path.cwd()
        try:
            os.chdir(cwd)
            await adapter.run_migrations()
            check_engine = create_async_engine(url)
            async with check_engine.connect() as conn:
                result = await conn.execute(
                    text("SELECT name FROM sqlite_master WHERE type='table'")
                )
                tables = {r.name for r in result}
            await check_engine.dispose()
            assert "alembic_version" in tables
            assert "audit_event" in tables
            assert "decision_history" in tables
            assert "governance_chain_heads" in tables
            # Sprint 3 T4: revision 0002 adds the operational ledger.
            assert "gateway_call_ledger" in tables
        finally:
            os.chdir(original_cwd)
            await adapter.close()


# ---------------------------------------------------------------------------
# Sprint 3 T4 — gateway_call_ledger round-trip.
#
# The Alembic graph now spans 0001 -> 0002. The single-shot
# ``adapter.run_migrations()`` only exercises the upgrade-to-head path;
# this class exercises the explicit ``upgrade(head) -> downgrade(0001)
# -> upgrade(head)`` cycle so an asymmetric op.create_table /
# op.drop_table or a missing index drop fails locally rather than at
# the live-Postgres / live-Oracle integration layer.
# ---------------------------------------------------------------------------


class TestGatewayCallLedgerMigrationRoundTrip:
    """Round-trip 0002 against the existing SQLite tmp_path fixture.

    Sprint 3 T4 — verifies revision 0002 (``gateway_call_ledger``) is
    reversible, so a future operator-driven downgrade (rare, but
    supported) does not leave residual state. Also pins the column +
    index inventory at the SQLite layer; live PG + Oracle round-trip
    runs in ``tests/integration/db/test_alembic_migrations.py``.
    """

    async def test_upgrade_creates_gateway_call_ledger_with_round6_columns(
        self, tmp_path: Any
    ) -> None:
        """Per Round-6 reviewer-P1 schema: rows persist
        ``upstream_api_base`` + ``provenance`` so
        ``/api/v1/system/effective-routing`` can classify historical
        rows authoritatively without re-resolving the current YAML."""
        from sqlalchemy import inspect

        url = f"sqlite+aiosqlite:///{tmp_path / 't4.db'}"
        adapter = PostgresAdapter(url=url)
        await adapter.connect()
        try:
            await adapter.run_migrations()
            check_engine = create_async_engine(url)
            async with check_engine.connect() as conn:
                cols = await conn.run_sync(
                    lambda c: {
                        col["name"]: col for col in inspect(c).get_columns("gateway_call_ledger")
                    }
                )
                idx_names = await conn.run_sync(
                    lambda c: {i["name"] for i in inspect(c).get_indexes("gateway_call_ledger")}
                )
            await check_engine.dispose()

            # Plan §5 ledger row shape (Round-6 reviewer-P1).
            expected_cols = {
                "id",
                "ts",
                "request_id",
                "tenant_id",
                "tier",
                "litellm_alias",
                "upstream_model",
                "upstream_api_base",  # Round-6
                "external",
                "provenance",  # Round-6
                "latency_ms",
                "outcome",
                "model_id",  # reserved — Sprint 9.5 (ADR-013)
            }
            assert expected_cols.issubset(set(cols.keys())), (
                f"missing columns: {expected_cols - set(cols.keys())}"
            )

            # Nullability matches Plan §5.
            assert cols["tenant_id"]["nullable"] is True
            assert cols["upstream_api_base"]["nullable"] is True
            assert cols["model_id"]["nullable"] is True
            assert cols["upstream_model"]["nullable"] is False
            assert cols["external"]["nullable"] is False
            assert cols["provenance"]["nullable"] is False

            # Plan T4: indexes on ts, request_id, provenance.
            assert "ix_gateway_ledger_ts" in idx_names
            assert "ix_gateway_ledger_request_id" in idx_names
            assert "ix_gateway_ledger_provenance" in idx_names
        finally:
            await adapter.close()

    async def test_downgrade_to_0001_drops_gateway_call_ledger(self, tmp_path: Any) -> None:
        """Down-revision must be reversible: ``alembic downgrade 0001``
        drops ``gateway_call_ledger`` + every index — leaves the
        Sprint-2 substrate intact."""
        from alembic import command

        from cognic_agentos.db.migrations.alembic_config import make_alembic_config

        url = f"sqlite+aiosqlite:///{tmp_path / 't4_down.db'}"
        adapter = PostgresAdapter(url=url)
        await adapter.connect()
        try:
            await adapter.run_migrations()  # head = 0002
            # alembic.command is sync; env.py runs async migrations via
            # ``asyncio.run`` which cannot be re-entered from a running
            # event loop. Match the adapter's ``asyncio.to_thread`` shape
            # so the alembic invocation runs in a separate thread.
            import asyncio

            # Pre-downgrade assertion — guards against a false-positive
            # PASS in the absence of revision 0002: if the migration
            # doesn't exist, head is already 0001, the table never
            # existed, and the post-downgrade ``not in`` assertion would
            # be trivially true.
            check_engine = create_async_engine(url)
            async with check_engine.connect() as conn:
                result = await conn.execute(
                    text("SELECT name FROM sqlite_master WHERE type='table'")
                )
                pre_downgrade = {r.name for r in result}
            await check_engine.dispose()
            assert "gateway_call_ledger" in pre_downgrade, (
                "migration 0002 did not create gateway_call_ledger at head"
            )

            cfg = make_alembic_config(url)  # env.py needs the async driver
            await asyncio.to_thread(command.downgrade, cfg, "0001")

            check_engine = create_async_engine(url)
            async with check_engine.connect() as conn:
                result = await conn.execute(
                    text("SELECT name FROM sqlite_master WHERE type='table'")
                )
                tables = {r.name for r in result}
            await check_engine.dispose()

            assert "gateway_call_ledger" not in tables
            # Sprint-2 substrate must still be present.
            assert "audit_event" in tables
            assert "decision_history" in tables
            assert "governance_chain_heads" in tables
        finally:
            await adapter.close()

    def test_ts_column_compiles_to_timestamp_with_time_zone_on_oracle(
        self,
    ) -> None:
        """Sprint 3 T4 reviewer-P1 regression — round 2.

        ``sa.DateTime(timezone=True)`` compiles to ``DATE`` on Oracle —
        no timezone. Since ``gateway_call_ledger.ts`` is ADR-007's
        authoritative timing source for ``/effective-routing``,
        silently truncating the offset on Oracle would make the
        endpoint's recent-window query dialect-dependent. The migration
        must use ``sa.TIMESTAMP(timezone=True)``, which compiles to
        ``TIMESTAMP WITH TIME ZONE`` on both Oracle + Postgres.
        Matches the 0001 migration's convention for
        ``audit_event.created_at`` / ``decision_history.created_at``.

        Round-2 of T4 review: import the migration's
        ``GATEWAY_LEDGER_TS_TYPE`` constant via ``importlib`` and
        compile-check THAT instance — not a fresh hard-coded copy —
        so a future regression to ``sa.DateTime(timezone=True)`` in
        the migration file actually fails this test. (Round-1 of the
        regression test compiled a locally-constructed
        ``sa.TIMESTAMP(timezone=True)``, which would have passed
        regardless of what the migration said.)

        ``importlib.import_module`` rather than ``from ... import``
        is required because the migration filename starts with a
        digit (``20260430_0002_...``) — Python identifier rules
        forbid the literal ``from`` statement on that path.
        """
        import importlib

        from sqlalchemy.dialects import oracle, postgresql

        migration = importlib.import_module(
            "cognic_agentos.db.migrations.versions.20260430_0002_gateway_call_ledger"
        )
        ts_column_type = migration.GATEWAY_LEDGER_TS_TYPE

        # ``# type: ignore[no-untyped-call]`` covers the bare
        # ``oracle.dialect()`` / ``postgresql.dialect()`` calls — the
        # dialects modules expose ``dialect()`` at runtime but lack
        # typeshed stubs.
        oracle_compiled = ts_column_type.compile(dialect=oracle.dialect())  # type: ignore[no-untyped-call]
        postgres_compiled = ts_column_type.compile(dialect=postgresql.dialect())  # type: ignore[no-untyped-call]

        assert "TIMESTAMP" in oracle_compiled.upper(), (
            f"GATEWAY_LEDGER_TS_TYPE compiled to {oracle_compiled!r} on Oracle "
            "— expected TIMESTAMP WITH TIME ZONE. Likely regression to "
            "sa.DateTime(timezone=True)."
        )
        assert "TIME ZONE" in oracle_compiled.upper(), (
            f"GATEWAY_LEDGER_TS_TYPE lost timezone on Oracle: compiled to {oracle_compiled!r}"
        )
        assert "TIMESTAMP" in postgres_compiled.upper()
        assert "TIME ZONE" in postgres_compiled.upper()

    async def test_downgrade_then_upgrade_reapplies_gateway_call_ledger(
        self, tmp_path: Any
    ) -> None:
        """Full round-trip: head -> 0001 -> head. Catches asymmetric
        op.create_table / op.drop_table or a missing index drop."""
        import asyncio

        from alembic import command

        from cognic_agentos.db.migrations.alembic_config import make_alembic_config

        url = f"sqlite+aiosqlite:///{tmp_path / 't4_rt.db'}"
        adapter = PostgresAdapter(url=url)
        await adapter.connect()
        try:
            await adapter.run_migrations()  # head = 0002
            cfg = make_alembic_config(url)  # env.py needs the async driver
            # asyncio.to_thread wrap — same reason as the prior test.
            await asyncio.to_thread(command.downgrade, cfg, "0001")
            await asyncio.to_thread(command.upgrade, cfg, "head")

            check_engine = create_async_engine(url)
            async with check_engine.connect() as conn:
                result = await conn.execute(
                    text("SELECT name FROM sqlite_master WHERE type='table'")
                )
                tables = {r.name for r in result}
            await check_engine.dispose()

            assert "gateway_call_ledger" in tables
            assert "audit_event" in tables
            assert "decision_history" in tables
            assert "governance_chain_heads" in tables
        finally:
            await adapter.close()
