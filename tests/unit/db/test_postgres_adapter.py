"""PostgresAdapter — uses aiosqlite URL for tests so SQLAlchemy machinery
exercises without a live Postgres process.

Per BUILD_PLAN exit criterion this sprint covers ``health_check`` +
lifecycle only; full integration tests come with Sprint 1C compose stack."""

from __future__ import annotations

import pytest

from cognic_agentos.db.adapters import bundled_registry
from cognic_agentos.db.adapters import protocols as P
from cognic_agentos.db.adapters.postgres_adapter import PostgresAdapter


class TestRegistration:
    def test_postgres_registered_under_bundled(self) -> None:
        # Importing the module registers it
        assert bundled_registry.has("relational", "postgres")
        assert bundled_registry.resolve("relational", "postgres") is PostgresAdapter


class TestConstruction:
    def test_constructor_refuses_empty_url(self) -> None:
        with pytest.raises(ValueError, match="database_url"):
            PostgresAdapter(None)
        with pytest.raises(ValueError, match="database_url"):
            PostgresAdapter("")


class TestLifecycle:
    async def test_health_then_close(self) -> None:
        # aiosqlite URL — exercises SQLAlchemy async engine without Postgres
        a = PostgresAdapter("sqlite+aiosqlite:///:memory:")
        await a.connect()
        h = await a.health_check()
        assert h.status == "ok"
        assert h.driver == "postgres"
        assert h.latency_ms is not None
        await a.close()
        h2 = await a.health_check()
        assert h2.status == "unreachable"

    async def test_unreachable_before_connect(self) -> None:
        a = PostgresAdapter("sqlite+aiosqlite:///:memory:")
        h = await a.health_check()
        assert h.status == "unreachable"


# NOTE: TestRunMigrationsRaises was retired in Sprint 2 Task 9. The
# Sprint 1C stub raised NotImplementedError; Sprint 2 wires real
# alembic.command.upgrade. The replacement test surface lives in
# tests/unit/db/test_run_migrations.py.


class TestSatisfiesProtocol:
    def test_protocol_conformance(self) -> None:
        a = PostgresAdapter("sqlite+aiosqlite:///:memory:")
        assert isinstance(a, P.RelationalAdapter)
