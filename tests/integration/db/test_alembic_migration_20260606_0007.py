"""ADR-023 — Alembic migration ``0007_tenant_config_overlay`` round-trip on
real Postgres + Oracle.

Mirrors ``test_alembic_migration_20260510_0003.py``. Each dialect does:

  alembic upgrade head   →   alembic downgrade base   →   alembic upgrade head

then asserts the ``tenant_config_overlay`` table actually exists after upgrade
(a TRUE RED before 0007 lands — a bare ``upgrade head`` is a false RED because
``0006`` is already head) and that the ``uq_tenant_config_overlay_tenant_field``
unique constraint is reflected at the DB layer (the contract the storage layer's
in-closure upsert depends on; operator runbooks reference the constraint name).

Env-gated like the prior integration tests; every test self-skips when the
matching ``COGNIC_RUN_*_INTEGRATION`` env var is unset.
"""

from __future__ import annotations

import os
import subprocess

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

# Default DSNs match the Sprint-1C compose stack — same defaults as
# ``tests/integration/db/test_alembic_migration_20260510_0003.py:34-42``.
POSTGRES_URL = os.environ.get(
    "COGNIC_DATABASE_URL_POSTGRES_TEST",
    "postgresql+asyncpg://cognic:cognic_dev_only@localhost:5432/cognic",
)

ORACLE_URL = os.environ.get(
    "COGNIC_DATABASE_URL_ORACLE_TEST",
    "oracle+oracledb://cognic:cognic_dev_only@localhost:1521/?service_name=XEPDB1",
)

_TABLE = "tenant_config_overlay"
_UNIQUE_CONSTRAINT = "uq_tenant_config_overlay_tenant_field"


def _alembic(env_url: str, *args: str) -> subprocess.CompletedProcess[str]:
    """Run alembic with COGNIC_DATABASE_URL pinned to the test DSN."""
    env = os.environ.copy()
    env["COGNIC_DATABASE_URL"] = env_url
    return subprocess.run(
        ["uv", "run", "alembic", *args],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )


async def _table_exists(url: str) -> bool:
    engine = create_async_engine(url)
    try:
        async with engine.connect() as conn:
            names = await conn.run_sync(lambda c: sa.inspect(c).get_table_names())
        # Oracle reflects identifiers upper-cased by default — match
        # case-insensitively (mirrors the constraint-name handling below).
        return _TABLE.upper() in {name.upper() for name in names}
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# Postgres
# ---------------------------------------------------------------------------


@pytest.mark.postgres
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_POSTGRES_INTEGRATION"),
    reason=(
        "live Postgres integration; opt in via "
        "COGNIC_RUN_POSTGRES_INTEGRATION=1 + compose up postgres"
    ),
)
def test_postgres_upgrade_downgrade_upgrade_roundtrip() -> None:
    """upgrade/downgrade symmetry on real Postgres — catches a missing
    index drop or asymmetric ``create_table`` / ``drop_table``."""
    _alembic(POSTGRES_URL, "upgrade", "head")
    _alembic(POSTGRES_URL, "downgrade", "base")
    _alembic(POSTGRES_URL, "upgrade", "head")


@pytest.mark.postgres
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_POSTGRES_INTEGRATION"),
    reason="live Postgres integration; opt in via COGNIC_RUN_POSTGRES_INTEGRATION=1",
)
async def test_postgres_overlay_table_created_and_dropped() -> None:
    """Table EXISTS after upgrade (TRUE RED before 0007), ABSENT after a
    single downgrade step (proving ``downgrade()`` drops it), EXISTS again
    after re-upgrade."""
    _alembic(POSTGRES_URL, "upgrade", "head")
    assert await _table_exists(POSTGRES_URL)
    _alembic(POSTGRES_URL, "downgrade", "-1")
    assert not await _table_exists(POSTGRES_URL)
    _alembic(POSTGRES_URL, "upgrade", "head")
    assert await _table_exists(POSTGRES_URL)


@pytest.mark.postgres
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_POSTGRES_INTEGRATION"),
    reason="live Postgres integration; opt in via COGNIC_RUN_POSTGRES_INTEGRATION=1",
)
async def test_postgres_unique_constraint_inventory() -> None:
    """``uq_tenant_config_overlay_tenant_field`` reflected in
    ``information_schema.table_constraints`` after upgrade."""
    from sqlalchemy import text

    _alembic(POSTGRES_URL, "upgrade", "head")
    engine = create_async_engine(POSTGRES_URL)
    try:
        async with engine.connect() as conn:
            result = await conn.execute(
                text(
                    "SELECT constraint_name FROM information_schema.table_constraints "
                    "WHERE table_name = :t AND constraint_type = 'UNIQUE'"
                ),
                {"t": _TABLE},
            )
            names = {r.constraint_name for r in result}
        assert _UNIQUE_CONSTRAINT in names, f"unique constraint missing; got {names}"
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# Oracle
# ---------------------------------------------------------------------------


@pytest.mark.oracle
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION"),
    reason=(
        "live Oracle XE integration; opt in via COGNIC_RUN_ORACLE_INTEGRATION=1 + compose up oracle"
    ),
)
def test_oracle_upgrade_downgrade_upgrade_roundtrip() -> None:
    """upgrade/downgrade symmetry on real Oracle XE — catches the
    Oracle-specific TIMESTAMP WITH TIME ZONE + UNIQUE-constraint compile
    asymmetries the SQLite unit substrate cannot reach."""
    _alembic(ORACLE_URL, "upgrade", "head")
    _alembic(ORACLE_URL, "downgrade", "base")
    _alembic(ORACLE_URL, "upgrade", "head")


@pytest.mark.oracle
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION"),
    reason="live Oracle XE integration; opt in via COGNIC_RUN_ORACLE_INTEGRATION=1",
)
async def test_oracle_overlay_table_created() -> None:
    """Table EXISTS after upgrade on real Oracle (TRUE RED before 0007)."""
    _alembic(ORACLE_URL, "upgrade", "head")
    assert await _table_exists(ORACLE_URL)


@pytest.mark.oracle
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION"),
    reason="live Oracle XE integration; opt in via COGNIC_RUN_ORACLE_INTEGRATION=1",
)
async def test_oracle_unique_constraint_inventory() -> None:
    """``uq_tenant_config_overlay_tenant_field`` reflected via
    ``user_constraints`` (type ``U``) after upgrade. Oracle upper-cases
    names by default — match case-insensitively."""
    from sqlalchemy import text

    _alembic(ORACLE_URL, "upgrade", "head")
    engine = create_async_engine(ORACLE_URL)
    try:
        async with engine.connect() as conn:
            result = await conn.execute(
                text(
                    "SELECT constraint_name FROM user_constraints "
                    "WHERE constraint_type = 'U' AND UPPER(table_name) = :t"
                ),
                {"t": _TABLE.upper()},
            )
            names = {r.constraint_name.upper() for r in result}
        assert any(_UNIQUE_CONSTRAINT.upper() in n for n in names), (
            f"unique constraint missing in Oracle user_constraints; got {names}"
        )
    finally:
        await engine.dispose()
