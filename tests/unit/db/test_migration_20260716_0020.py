from __future__ import annotations

import importlib
from typing import Any

import pytest
import sqlalchemy as sa
from alembic import command

from cognic_agentos.db.migrations.alembic_config import make_alembic_config

MIGRATION = "cognic_agentos.db.migrations.versions.20260716_0020_action_entitlements"
TABLE = "action_entitlements"
EXPECTED_COLUMNS = {"id", "tenant_id", "subject", "tool_identity", "created_at"}
UQ = "uq_action_entitlements_tenant_subject_tool"
INDEX = "ix_action_entitlements_tenant_subject"


def _url(tmp_path: Any, name: str) -> str:
    return f"sqlite:///{tmp_path / name}"


def _async_url(url: str) -> str:
    return url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)


def _upgrade(url: str, revision: str) -> None:
    command.upgrade(make_alembic_config(_async_url(url)), revision)


def _downgrade(url: str, revision: str) -> None:
    command.downgrade(make_alembic_config(_async_url(url)), revision)


def _stamp(url: str, revision: str) -> None:
    engine = sa.create_engine(url)
    try:
        with engine.begin() as conn:
            conn.execute(
                sa.text("UPDATE alembic_version SET version_num = :revision"),
                {"revision": revision},
            )
    finally:
        engine.dispose()


def test_revision_wiring() -> None:
    migration = importlib.import_module(MIGRATION)
    assert migration.revision == "0020"
    assert migration.down_revision == "0019"


def test_upgrade_creates_exact_action_entitlement_shape(tmp_path: Any) -> None:
    url = _url(tmp_path, "shape.sqlite")
    _upgrade(url, "head")
    engine = sa.create_engine(url)
    try:
        inspector = sa.inspect(engine)
        columns = {column["name"]: column for column in inspector.get_columns(TABLE)}
        assert set(columns) == EXPECTED_COLUMNS
        assert columns["tenant_id"]["nullable"] is False
        assert columns["subject"]["nullable"] is False
        assert columns["tool_identity"]["nullable"] is False
        unique = {
            constraint["name"]: list(constraint["column_names"])
            for constraint in inspector.get_unique_constraints(TABLE)
        }
        assert unique[UQ] == ["tenant_id", "subject", "tool_identity"]
        indexes = {
            index["name"]: (list(index["column_names"]), bool(index["unique"]))
            for index in inspector.get_indexes(TABLE)
        }
        assert indexes[INDEX] == (["tenant_id", "subject"], False)
    finally:
        engine.dispose()


def test_fully_applied_unstamped_rerun_is_idempotent(tmp_path: Any) -> None:
    url = _url(tmp_path, "rerun.sqlite")
    _upgrade(url, "head")
    _stamp(url, "0019")
    _upgrade(url, "head")
    engine = sa.create_engine(url)
    try:
        assert TABLE in sa.inspect(engine).get_table_names()
    finally:
        engine.dispose()


def test_guard_fails_loud_on_wrong_shaped_existing_table(tmp_path: Any) -> None:
    url = _url(tmp_path, "wrong.sqlite")
    _upgrade(url, "0019")
    engine = sa.create_engine(url)
    try:
        with engine.begin() as conn:
            conn.execute(sa.text("CREATE TABLE action_entitlements (id CHAR(32) PRIMARY KEY)"))
    finally:
        engine.dispose()
    with pytest.raises(RuntimeError, match="0020 ddl: existing object shape mismatch"):
        _upgrade(url, "head")


def test_downgrade_round_trip_preserves_existing_entitlement_tables(tmp_path: Any) -> None:
    url = _url(tmp_path, "downgrade.sqlite")
    _upgrade(url, "head")
    _downgrade(url, "0019")
    engine = sa.create_engine(url)
    try:
        tables = set(sa.inspect(engine).get_table_names())
        assert TABLE not in tables
        assert "entitlements" in tables
        assert "action_entitlements" not in tables
    finally:
        engine.dispose()
    _upgrade(url, "head")


def test_runtime_table_matches_migration(tmp_path: Any) -> None:
    from cognic_agentos.core.entitlements.store import _action_entitlements

    url = _url(tmp_path, "parity.sqlite")
    _upgrade(url, "head")
    engine = sa.create_engine(url)
    try:
        reflected = {column["name"] for column in sa.inspect(engine).get_columns(TABLE)}
    finally:
        engine.dispose()
    assert reflected == {column.name for column in _action_entitlements.columns}
