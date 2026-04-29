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
        finally:
            os.chdir(original_cwd)
            await adapter.close()
