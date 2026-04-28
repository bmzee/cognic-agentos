"""OracleAdapter — RelationalAdapter via SQLAlchemy[asyncio] + python-oracledb.

Driver name: ``oracle``. Auto-registers into ``bundled_registry`` on import.

Production runtime path uses python-oracledb thin-mode async (no Oracle
client install required) via SQLAlchemy's ``oracle+oracledb`` driver.
Mirrors PostgresAdapter's shape; the only Oracle-specific divergence is
the ``SELECT 1 FROM dual`` health probe (Oracle has no implicit
no-table-required SELECT).

Per CLAUDE.md production-grade rule: ``run_migrations`` RAISES
``NotImplementedError`` rather than silently no-op'ing. Alembic-driven
migration invocation lands in Sprint 2 alongside ``core/`` schema work
(see ADR-009 §"Migration policy"). Oracle migration files will live in
``db/migrations/oracle/`` (directory pre-created in this sprint).
"""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from cognic_agentos.db.adapters.protocols import AdapterHealth
from cognic_agentos.db.adapters.registry import bundled_registry


class OracleAdapter:
    driver = "oracle"

    def __init__(self, url: str | None) -> None:
        if not url:
            raise ValueError("OracleAdapter requires database_url; got empty/None")
        self._url = url
        self._engine: AsyncEngine | None = None
        self._session_factory: async_sessionmaker[Any] | None = None
        self._closed = False

    async def connect(self) -> None:
        self._engine = create_async_engine(self._url, echo=False, future=True)
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)
        self._closed = False

    def session(self) -> Any:
        if self._session_factory is None:
            raise RuntimeError("connect() must be awaited first")
        return self._session_factory()

    async def run_migrations(self, dir: str | None = None) -> None:
        """Run Alembic upgrade head against this adapter's database URL.

        **OPERATOR-CALLABLE ONLY.** Per the Sprint-2 doctrine amendment
        landed in PR #5: the lifespan does not auto-invoke this.
        Production deployments run ``uv run alembic upgrade head`` (or
        a Kubernetes job) ahead of rolling out the runtime container.
        This method exists for dev tooling + integration tests
        (programmatic invocation that doesn't require shelling out).

        ``dir`` is accepted for backwards compatibility with the
        Sprint 1D protocol shape but ignored: Sprint 2 anchors the
        canonical alembic env at ``src/cognic_agentos/db/migrations/``.
        ``db/migrations/oracle/`` is reserved for future Oracle-only
        PL/SQL hooks (empty in Sprint 2).

        Idempotent: alembic upgrade head is a no-op when
        alembic_version already records HEAD.
        """

        import asyncio

        from alembic import command
        from alembic.config import Config

        def _run() -> None:
            config = Config("alembic.ini")
            # Pin sqlalchemy.url at runtime so the adapter's own URL
            # wins over whatever env.py would otherwise read from
            # core.config.Settings. env.py honours a pre-set
            # sqlalchemy.url and only falls back to Settings when
            # none is provided (CLI path).
            config.set_main_option("sqlalchemy.url", self._url)
            command.upgrade(config, "head")

        await asyncio.to_thread(_run)

    async def close(self) -> None:
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None
        self._closed = True

    async def health_check(self) -> AdapterHealth:
        if self._closed or self._engine is None:
            return AdapterHealth(status="unreachable", driver=self.driver, detail="not connected")
        start = time.perf_counter()
        try:
            async with self._engine.connect() as conn:
                await conn.execute(text("SELECT 1 FROM dual"))
        except Exception as exc:
            return AdapterHealth(
                status="unreachable",
                driver=self.driver,
                detail=type(exc).__name__,
            )
        return AdapterHealth(
            status="ok",
            driver=self.driver,
            latency_ms=(time.perf_counter() - start) * 1000.0,
        )


bundled_registry.register("relational", "oracle", OracleAdapter)
