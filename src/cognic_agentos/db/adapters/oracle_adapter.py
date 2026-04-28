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

    async def run_migrations(self, dir: str) -> None:
        # Per CLAUDE.md production-grade rule: production code paths never
        # silently no-op. Alembic invocation lands in Sprint 2 alongside
        # core/ schema work; until then this method fails loudly so a
        # caller cannot accidentally believe migrations ran. See ADR-009
        # §"Migration policy".
        raise NotImplementedError(
            "OracleAdapter.run_migrations is wired in Sprint 2 alongside "
            "core/ Alembic migrations (ADR-009 §'Migration policy'). "
            "Sprint 1D ships the protocol-method shape only; "
            "db/migrations/oracle/ is pre-reserved for the Oracle-dialect "
            "migration set."
        )

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
