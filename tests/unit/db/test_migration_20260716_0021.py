"""M8.5-D D2 migration 0021: pending-approval conversation columns."""

from __future__ import annotations

import importlib
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
import sqlalchemy as sa
from alembic import command

from cognic_agentos.db.migrations.alembic_config import make_alembic_config

MIGRATION = "cognic_agentos.db.migrations.versions.20260716_0021_conversation_turn_approval"
TABLE = "conversation_turns"


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


_turns = sa.table(
    TABLE,
    sa.column("turn_id", sa.Uuid()),
    sa.column("conversation_id", sa.Uuid()),
    sa.column("seq", sa.Integer()),
    sa.column("user_message", sa.Text()),
    sa.column("answer", sa.Text()),
    sa.column("agent_run_id", sa.String(64)),
    sa.column("prompt_tokens", sa.Integer()),
    sa.column("completion_tokens", sa.Integer()),
    sa.column("created_at", sa.TIMESTAMP(timezone=True)),
    sa.column("turn_completed_request_id", sa.String(64)),
    sa.column("approval_request_id", sa.String(64)),
    sa.column("turn_kind", sa.String(16)),
)


def test_revision_wiring() -> None:
    migration = importlib.import_module(MIGRATION)
    assert migration.revision == "0021"
    assert migration.down_revision == "0020"


def test_head_has_exact_additive_column_shapes(tmp_path: Any) -> None:
    url = _url(tmp_path, "shape.sqlite")
    _upgrade(url, "head")
    engine = sa.create_engine(url)
    try:
        columns = {column["name"]: column for column in sa.inspect(engine).get_columns(TABLE)}
        approval_type = columns["approval_request_id"]["type"]
        kind_type = columns["turn_kind"]["type"]
        assert isinstance(approval_type, sa.String)
        assert approval_type.length == 64
        assert columns["approval_request_id"]["nullable"] is True
        assert isinstance(kind_type, sa.String)
        assert kind_type.length == 16
        assert columns["turn_kind"]["nullable"] is False
        assert "exchange" in str(columns["turn_kind"]["default"])
    finally:
        engine.dispose()


def test_upgrade_backfills_existing_turn_as_exchange(tmp_path: Any) -> None:
    url = _url(tmp_path, "backfill.sqlite")
    _upgrade(url, "0020")
    engine = sa.create_engine(url)
    turn_id = uuid.uuid4()
    try:
        with engine.begin() as conn:
            conn.execute(
                sa.insert(_turns).values(
                    turn_id=turn_id,
                    conversation_id=uuid.uuid4(),
                    seq=1,
                    user_message="q",
                    answer="a",
                    agent_run_id="agent-run-existing",
                    prompt_tokens=1,
                    completion_tokens=1,
                    created_at=datetime.now(UTC),
                    turn_completed_request_id=f"conv-turn-{uuid.uuid4().hex}",
                )
            )
        _upgrade(url, "head")
        with engine.connect() as conn:
            row = conn.execute(
                sa.select(_turns.c.turn_kind, _turns.c.approval_request_id).where(
                    _turns.c.turn_id == turn_id
                )
            ).one()
        assert row.turn_kind == "exchange"
        assert row.approval_request_id is None
    finally:
        engine.dispose()


def test_fully_applied_unstamped_rerun_is_idempotent(tmp_path: Any) -> None:
    url = _url(tmp_path, "rerun.sqlite")
    _upgrade(url, "head")
    _stamp(url, "0020")
    _upgrade(url, "head")
    engine = sa.create_engine(url)
    try:
        columns = {column["name"] for column in sa.inspect(engine).get_columns(TABLE)}
        assert {"approval_request_id", "turn_kind"} <= columns
    finally:
        engine.dispose()


def test_wrong_length_existing_approval_column_fails_loud(tmp_path: Any) -> None:
    url = _url(tmp_path, "wrong-approval.sqlite")
    _upgrade(url, "0020")
    engine = sa.create_engine(url)
    try:
        with engine.begin() as conn:
            conn.execute(
                sa.text("ALTER TABLE conversation_turns ADD approval_request_id VARCHAR(32)")
            )
    finally:
        engine.dispose()
    with pytest.raises(RuntimeError, match="0021 ddl: existing object shape mismatch"):
        _upgrade(url, "head")


def test_wrong_nullable_existing_turn_kind_fails_loud(tmp_path: Any) -> None:
    url = _url(tmp_path, "wrong-kind.sqlite")
    _upgrade(url, "0020")
    engine = sa.create_engine(url)
    try:
        with engine.begin() as conn:
            conn.execute(sa.text("ALTER TABLE conversation_turns ADD turn_kind VARCHAR(16) NULL"))
    finally:
        engine.dispose()
    with pytest.raises(RuntimeError, match="0021 ddl: existing object shape mismatch"):
        _upgrade(url, "head")


def test_downgrade_removes_only_the_0021_columns(tmp_path: Any) -> None:
    url = _url(tmp_path, "downgrade.sqlite")
    _upgrade(url, "head")
    _downgrade(url, "0020")
    engine = sa.create_engine(url)
    try:
        columns = {column["name"] for column in sa.inspect(engine).get_columns(TABLE)}
        assert "approval_request_id" not in columns
        assert "turn_kind" not in columns
        assert "turn_completed_request_id" in columns
    finally:
        engine.dispose()


def test_runtime_table_matches_migration(tmp_path: Any) -> None:
    from cognic_agentos.core.conversation.storage import _conversation_turns

    url = _url(tmp_path, "parity.sqlite")
    _upgrade(url, "head")
    engine = sa.create_engine(url)
    try:
        reflected = {column["name"] for column in sa.inspect(engine).get_columns(TABLE)}
    finally:
        engine.dispose()
    assert reflected == {column.name for column in _conversation_turns.columns}
