"""OracleAdapter — SQLAlchemy[asyncio] + python-oracledb async.

Unit tests mock the SQLAlchemy engine boundary so they never need a live
Oracle instance. The integration test (at the bottom) opts INTO the
``docker-compose.oracle.yml`` overlay via ``@pytest.mark.skipif`` gated on
``COGNIC_RUN_ORACLE_INTEGRATION=1``; the CI ``oracle-integration`` job
sets the env var. Default ``pytest`` invocations skip the integration
class entirely (markers alone do NOT auto-skip — see Sprint 1D plan
review note).
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cognic_agentos.db.adapters import bundled_registry
from cognic_agentos.db.adapters import protocols as P
from cognic_agentos.db.adapters.oracle_adapter import OracleAdapter

ORACLE_URL = "oracle+oracledb://cognic:cognic_dev_only@localhost:1521/?service_name=XEPDB1"


class TestRegistration:
    def test_oracle_registered_under_bundled(self) -> None:
        # Importing the module registers it
        assert bundled_registry.has("relational", "oracle")
        assert bundled_registry.resolve("relational", "oracle") is OracleAdapter


class TestConstruction:
    def test_constructor_refuses_empty_url(self) -> None:
        with pytest.raises(ValueError, match="database_url"):
            OracleAdapter(None)
        with pytest.raises(ValueError, match="database_url"):
            OracleAdapter("")


class TestLifecycle:
    async def test_connect_uses_oracle_async_drivername(self) -> None:
        """``create_async_engine`` should be called with the same URL the
        operator configured. We assert URL pass-through rather than
        normalising the driver-name in adapter code (the SQLAlchemy URL
        is the source of truth)."""

        with patch("cognic_agentos.db.adapters.oracle_adapter.create_async_engine") as ce:
            ce.return_value = MagicMock()
            a = OracleAdapter(ORACLE_URL)
            await a.connect()
            ce.assert_called_once()
            assert ce.call_args[0][0] == ORACLE_URL
            assert ce.call_args[1]["echo"] is False

    async def test_unreachable_before_connect(self) -> None:
        a = OracleAdapter(ORACLE_URL)
        h = await a.health_check()
        assert h.status == "unreachable"
        assert h.driver == "oracle"

    async def test_health_check_runs_select_1_from_dual(self) -> None:
        """Oracle's no-table-required SELECT is ``SELECT 1 FROM dual``;
        Postgres uses ``SELECT 1``. The dialect difference is the only
        place this adapter diverges from PostgresAdapter at the SQL
        layer."""

        with patch("cognic_agentos.db.adapters.oracle_adapter.create_async_engine") as ce:
            mock_engine = MagicMock()
            mock_conn = AsyncMock()
            mock_engine.connect.return_value.__aenter__.return_value = mock_conn
            mock_engine.connect.return_value.__aexit__.return_value = None
            mock_engine.dispose = AsyncMock()
            ce.return_value = mock_engine

            a = OracleAdapter(ORACLE_URL)
            await a.connect()
            h = await a.health_check()

            assert h.status == "ok"
            assert h.driver == "oracle"
            assert h.latency_ms is not None
            # Verify the SELECT statement passed to conn.execute renders
            # to ``SELECT 1 FROM dual``.
            call_args = mock_conn.execute.call_args
            executed = call_args[0][0]
            rendered = str(executed)
            assert "SELECT 1 FROM dual" in rendered

    async def test_close_disposes_engine(self) -> None:
        with patch("cognic_agentos.db.adapters.oracle_adapter.create_async_engine") as ce:
            mock_engine = MagicMock()
            mock_engine.dispose = AsyncMock()
            ce.return_value = mock_engine

            a = OracleAdapter(ORACLE_URL)
            await a.connect()
            await a.close()
            mock_engine.dispose.assert_awaited_once()

            h = await a.health_check()
            assert h.status == "unreachable"


class TestRunMigrationsRaises:
    """Production-grade rule: production adapters never silently no-op.
    Alembic invocation lands in Sprint 2 alongside core/ schema work.
    Same shape as PostgresAdapter."""

    async def test_run_migrations_not_implemented(self) -> None:
        a = OracleAdapter(ORACLE_URL)
        with pytest.raises(NotImplementedError, match="Sprint 2"):
            await a.run_migrations("db/migrations/oracle")


class TestSatisfiesProtocol:
    def test_protocol_conformance(self) -> None:
        a = OracleAdapter(ORACLE_URL)
        assert isinstance(a, P.RelationalAdapter)


# --- Integration test (live Oracle XE compose overlay) ---------------


@pytest.mark.oracle
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION"),
    reason=(
        "live Oracle XE integration; opt in via "
        "COGNIC_RUN_ORACLE_INTEGRATION=1 + compose overlay up"
    ),
)
class TestOracleLiveIntegration:
    """Activated only when:
      1. The compose overlay is up:
           docker compose -f infra/dev/docker-compose.yml \\
                          -f infra/dev/docker-compose.oracle.yml up -d
      2. The env-gate is set:
           export COGNIC_RUN_ORACLE_INTEGRATION=1

    The CI ``oracle-integration`` job sets both. Default ``pytest`` runs
    skip via ``skipif`` (the marker alone does NOT auto-skip; pytest's
    ``--strict-markers`` only validates that markers are *registered*).
    """

    async def test_health_check_against_live_oracle(self) -> None:
        a = OracleAdapter(ORACLE_URL)
        await a.connect()
        h = await a.health_check()
        assert h.status == "ok"
        assert h.driver == "oracle"
        assert h.latency_ms is not None
        await a.close()
