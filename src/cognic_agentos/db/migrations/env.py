"""Alembic env — Sprint 2 baseline.

Reads `COGNIC_DATABASE_URL` from `core.config.Settings` at runtime.
Per the Sprint-2 doctrine amendment in PR #5: production migrations
are an operator job; the lifespan does NOT auto-invoke this. Operators
run ``uv run alembic upgrade head`` (or a Kubernetes job) ahead of
rolling out the runtime container.

Async-shaped to match the rest of the persistence stack — callers
include both ``alembic upgrade head`` invocations from the CLI (sync
context, falls into ``asyncio.run`` here) and programmatic invocations
from ``PostgresAdapter.run_migrations`` / ``OracleAdapter.run_migrations``
(themselves async, but ``alembic.command.upgrade`` is sync and gets
wrapped in ``asyncio.to_thread``).

target_metadata is None until Sprint-2 Task 5 lands the initial
migration; that migration uses explicit ``op.create_table(...)`` rather
than autogenerate, so no metadata wiring is needed yet.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig
from typing import Any

from alembic import context
from sqlalchemy import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from cognic_agentos.core.config import get_settings

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

settings = get_settings()
if not settings.database_url:
    raise RuntimeError(
        "Alembic env requires COGNIC_DATABASE_URL — set it in the operator's "
        "environment, or in `.env` for dev runs."
    )
config.set_main_option("sqlalchemy.url", settings.database_url)

target_metadata: Any = None


def run_migrations_offline() -> None:
    """Generate SQL without connecting to the database."""

    context.configure(
        url=settings.database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations against a live async engine."""

    section = config.get_section(config.config_ini_section, {})
    connectable = async_engine_from_config(
        section,
        prefix="sqlalchemy.",
        future=True,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
