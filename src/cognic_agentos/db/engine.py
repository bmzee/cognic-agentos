"""Async SQLAlchemy engine + session factory.

Layer classification: **persistence wiring** (governance kernel side).

Sprint 2 introduces this module so ``core/audit`` + ``core/decision_history``
+ ``core/chain_verifier`` can share a single engine + session factory.
The kernel image carries the SQLAlchemy + greenlet runtime (Round-2
amendment of the Sprint-2 plan) so this module is importable without
the ``--extra adapters`` flag; driver-specific wheels (``asyncpg``,
``oracledb``) still live in the adapters extra.

Engine + factory creation is intentionally minimal — no pool tuning
beyond ``pool_pre_ping=True`` (catches stale connections after a DB
restart). Operators tune ``pool_size`` / ``max_overflow`` per
deployment via SQLAlchemy URL query params or a future Settings
extension.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from cognic_agentos.core.config import Settings


def create_engine_from_settings(settings: Settings) -> AsyncEngine:
    """Construct an async engine from runtime settings.

    Raises ``ValueError`` if ``database_url`` is unset or empty —
    silent fallback to a default URL would let a misconfigured
    runtime appear healthy while writing to the wrong database.
    """

    if not settings.database_url:
        raise ValueError("database_url must be set; got empty/None")
    return create_async_engine(
        settings.database_url,
        echo=False,
        future=True,
        pool_pre_ping=True,
    )


def session_factory_from_engine(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Return an ``async_sessionmaker`` bound to the given engine.

    ``expire_on_commit=False`` so commit doesn't invalidate ORM-loaded
    instances — Sprint-2 callers (``AuditStore``, ``DecisionHistoryStore``)
    use SQLAlchemy Core for the chain transactions, so this only
    matters if a future caller layers an ORM session on top.
    """

    return async_sessionmaker[AsyncSession](engine, expire_on_commit=False)


async def dispose_engine(engine: AsyncEngine) -> None:
    """Dispose the engine pool. Idempotent.

    Lifespan shutdown should call this for every engine the runtime
    created so connections drain cleanly before the container exits.
    """

    await engine.dispose()


__all__: tuple[str, ...] = (
    "create_engine_from_settings",
    "dispose_engine",
    "session_factory_from_engine",
)


# Re-export typing convenience for callers that wire the factory into
# DI containers (Sprint 4+ will introduce one). ``Any`` is the catch-all
# for typed sessions when callers don't bind to AsyncSession explicitly.
_TypingExport: Any = AsyncSession
