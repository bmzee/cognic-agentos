"""PostgresAdapter — RelationalAdapter via SQLAlchemy[asyncio] + asyncpg.

Driver name: ``postgres``. Auto-registers into ``bundled_registry`` on import.

Production runtime path is real (asyncpg). Tests use
``sqlite+aiosqlite:///:memory:`` to exercise SQLAlchemy machinery without
a live Postgres process — the adapter does not branch on URL shape;
SQLAlchemy picks the right driver.

Per CLAUDE.md production-grade rule: ``run_migrations`` RAISES
``NotImplementedError`` rather than silently no-op'ing. Alembic-driven
migration invocation lands in Sprint 2 alongside ``core/`` schema work
(see ADR-009 §"Migration policy").
"""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from cognic_agentos.db.adapters.protocols import AdapterHealth
from cognic_agentos.db.adapters.registry import bundled_registry


class PostgresAdapter:
    driver = "postgres"

    def __init__(self, url: str | None) -> None:
        if not url:
            raise ValueError("PostgresAdapter requires database_url; got empty/None")
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

    @property
    def engine(self) -> AsyncEngine:
        if self._engine is None:
            raise RuntimeError("connect() must be awaited first")
        return self._engine

    async def run_migrations(self, dir: str | None = None) -> None:
        """Run Alembic upgrade head against this adapter's database URL.

        **OPERATOR-CALLABLE ONLY.** Per the Sprint-2 doctrine amendment
        landed in PR #5: the lifespan does not auto-invoke this.
        Production deployments run ``uv run alembic upgrade head`` (or
        a Kubernetes job) ahead of rolling out the runtime container.
        This method exists for dev tooling + integration tests
        (programmatic invocation that doesn't require shelling out).

        ``dir`` is accepted for backwards compatibility with the
        Sprint 1C protocol shape but ignored: Sprint 2 anchors the
        canonical alembic env at ``src/cognic_agentos/db/migrations/``.
        Banks running downstream Alembic envs do so out-of-band.

        Idempotent: alembic upgrade head is a no-op when
        alembic_version already records HEAD.
        """

        import asyncio

        from alembic import command

        from cognic_agentos.db.migrations.alembic_config import (
            make_alembic_config,
        )

        def _run() -> None:
            # ``make_alembic_config`` resolves ``script_location`` from
            # the package (immune to CWD) + pins ``sqlalchemy.url`` so
            # the adapter's own URL wins over whatever env.py would
            # otherwise read from core.config.Settings. The previous
            # ``Config("alembic.ini")`` shape was CWD-sensitive — it
            # worked from the repo root in CI but raised
            # ``CommandError: No 'script_location' key found in
            # configuration`` from any other CWD or inside the runtime
            # Docker images (which deliberately do not ship alembic.ini).
            config = make_alembic_config(self._url)
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
                await conn.execute(text("SELECT 1"))
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


bundled_registry.register("relational", "postgres", PostgresAdapter)
