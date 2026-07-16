from __future__ import annotations

import importlib
from typing import Any

import pytest
import sqlalchemy as sa
from alembic import command

from cognic_agentos.db.migrations.alembic_config import make_alembic_config

MIGRATION = "cognic_agentos.db.migrations.versions.20260716_0019_approval_replay_payloads"
TABLE = "approval_replay_payloads"
EXPECTED_COLUMNS = {
    "request_id",
    "tenant_id",
    "canonical_args",
    "args_digest",
    "result_canonical",
    "result_digest",
    "created_at",
    "executed_at",
    "erased_at",
}


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
    assert migration.revision == "0019"
    assert migration.down_revision == "0018"


def test_upgrade_creates_exact_replay_shape(tmp_path: Any) -> None:
    url = _url(tmp_path, "shape.sqlite")
    _upgrade(url, "head")
    engine = sa.create_engine(url)
    try:
        inspector = sa.inspect(engine)
        assert TABLE in inspector.get_table_names()
        columns = {column["name"]: column for column in inspector.get_columns(TABLE)}
        assert set(columns) == EXPECTED_COLUMNS
        assert inspector.get_pk_constraint(TABLE)["constrained_columns"] == ["request_id"]
        assert columns["canonical_args"]["nullable"] is True
        assert columns["args_digest"]["nullable"] is False
        assert columns["result_canonical"]["nullable"] is True
        assert columns["result_digest"]["nullable"] is True
        assert columns["erased_at"]["nullable"] is True
    finally:
        engine.dispose()


def test_fully_applied_unstamped_rerun_is_idempotent(tmp_path: Any) -> None:
    url = _url(tmp_path, "rerun.sqlite")
    _upgrade(url, "head")
    _stamp(url, "0018")
    _upgrade(url, "head")
    engine = sa.create_engine(url)
    try:
        assert TABLE in sa.inspect(engine).get_table_names()
    finally:
        engine.dispose()


def test_guard_fails_loud_on_wrong_shaped_existing_table(tmp_path: Any) -> None:
    url = _url(tmp_path, "wrong.sqlite")
    _upgrade(url, "0018")
    engine = sa.create_engine(url)
    try:
        with engine.begin() as conn:
            conn.execute(
                sa.text(
                    "CREATE TABLE approval_replay_payloads "
                    "(request_id CHAR(32) PRIMARY KEY, tenant_id VARCHAR(128))"
                )
            )
    finally:
        engine.dispose()
    with pytest.raises(RuntimeError, match="0019 ddl: existing object shape mismatch"):
        _upgrade(url, "head")


def test_guard_fails_loud_when_request_foreign_key_is_missing(tmp_path: Any) -> None:
    url = _url(tmp_path, "missing-fk.sqlite")
    _upgrade(url, "0018")
    engine = sa.create_engine(url)
    try:
        with engine.begin() as conn:
            conn.execute(
                sa.text(
                    "CREATE TABLE approval_replay_payloads ("
                    "request_id CHAR(32) NOT NULL PRIMARY KEY, "
                    "tenant_id VARCHAR(128) NOT NULL, canonical_args BLOB, "
                    "args_digest BLOB NOT NULL, result_canonical BLOB, "
                    "result_digest BLOB, created_at TIMESTAMP NOT NULL, "
                    "executed_at TIMESTAMP, erased_at TIMESTAMP)"
                )
            )
    finally:
        engine.dispose()
    with pytest.raises(RuntimeError, match="fk_approval_replay_payloads_request"):
        _upgrade(url, "head")


def test_downgrade_round_trip_preserves_approval_requests(tmp_path: Any) -> None:
    url = _url(tmp_path, "downgrade.sqlite")
    _upgrade(url, "head")
    _downgrade(url, "0018")
    engine = sa.create_engine(url)
    try:
        tables = set(sa.inspect(engine).get_table_names())
        assert TABLE not in tables
        assert "approval_requests" in tables
    finally:
        engine.dispose()
    _upgrade(url, "head")


def test_runtime_table_matches_migration(tmp_path: Any) -> None:
    from cognic_agentos.core.approval.replay import _approval_replay_payloads

    url = _url(tmp_path, "parity.sqlite")
    _upgrade(url, "head")
    engine = sa.create_engine(url)
    try:
        reflected = {column["name"] for column in sa.inspect(engine).get_columns(TABLE)}
    finally:
        engine.dispose()
    assert reflected == {column.name for column in _approval_replay_payloads.columns}
