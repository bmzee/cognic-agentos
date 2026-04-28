"""Alembic migration round-trip on real Postgres + Oracle.

Sprint 2 Task 5 — schema-design verification. Each test does:

  alembic upgrade head   →   alembic downgrade base   →   alembic upgrade head

against a live database. The first upgrade creates the governance
tables; the downgrade drops them; the second upgrade proves the
migration is idempotent + reversible (catches op.create_table /
op.drop_table asymmetry, missing index drops, etc.).

Env-gated like the Sprint 1D oracle tests; runs only when the
matching ``COGNIC_RUN_*_INTEGRATION`` env var is set + the matching
compose service is up.
"""

from __future__ import annotations

import os
import subprocess

import pytest

# Default DSNs match the Sprint-1C compose stack. Operators can
# override via the env var if their local stack uses different ports
# or credentials.
POSTGRES_URL = os.environ.get(
    "COGNIC_DATABASE_URL_POSTGRES_TEST",
    "postgresql+asyncpg://cognic:cognic_dev_only@localhost:5432/cognic",
)

ORACLE_URL = os.environ.get(
    "COGNIC_DATABASE_URL_ORACLE_TEST",
    "oracle+oracledb://cognic:cognic_dev_only@localhost:1521/?service_name=XEPDB1",
)


def _alembic(env_url: str, *args: str) -> subprocess.CompletedProcess[str]:
    """Run alembic with COGNIC_DATABASE_URL pinned to the test DSN.

    Returns the CompletedProcess on success; raises CalledProcessError
    on non-zero exit (each command is required to succeed).
    """

    env = os.environ.copy()
    env["COGNIC_DATABASE_URL"] = env_url
    return subprocess.run(
        ["uv", "run", "alembic", *args],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )


@pytest.mark.postgres
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_POSTGRES_INTEGRATION"),
    reason=(
        "live Postgres integration; opt in via "
        "COGNIC_RUN_POSTGRES_INTEGRATION=1 + compose up postgres"
    ),
)
def test_postgres_upgrade_downgrade_upgrade_roundtrip() -> None:
    _alembic(POSTGRES_URL, "upgrade", "head")
    _alembic(POSTGRES_URL, "downgrade", "base")
    _alembic(POSTGRES_URL, "upgrade", "head")


@pytest.mark.oracle
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION"),
    reason=(
        "live Oracle XE integration; opt in via COGNIC_RUN_ORACLE_INTEGRATION=1 + compose up oracle"
    ),
)
def test_oracle_upgrade_downgrade_upgrade_roundtrip() -> None:
    _alembic(ORACLE_URL, "upgrade", "head")
    _alembic(ORACLE_URL, "downgrade", "base")
    _alembic(ORACLE_URL, "upgrade", "head")
