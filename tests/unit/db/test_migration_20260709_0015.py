"""ADR-028 M8.5-A — pin migration 0015 (conversations + conversation_turns) via
real alembic upgrade + inspect (mirrors tests/unit/db/test_migration_20260615_0011.py).

Per the recorded doctrine, storage shape is proven against the ALEMBIC-MIGRATED
database, never ``metadata.create_all`` — ``create_all`` omits migration-only
constraints (CHECK / unique indexes) and would let real drift pass.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

_CONVERSATION_COLUMNS = {
    "conversation_id",
    "tenant_id",
    "agent_id",
    "creator_subject",
    "state",
    "turn_count",
    "cumulative_tokens",
    "turn_in_progress",
    "turn_claimed_at",
    "retention_class",
    "created_at",
    "last_turn_at",
    "erased_at",
}

_TURN_COLUMNS = {
    "turn_id",
    "conversation_id",
    "seq",
    "user_message",
    "answer",
    "agent_run_id",
    "prompt_tokens",
    "completion_tokens",
    "created_at",
    "erased_at",
}


async def _migrated_engine(tmp_path: Any, name: str = "conv.db") -> Any:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / name}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    return create_async_engine(url)


@pytest.mark.asyncio
async def test_both_tables_exist_after_migration(tmp_path: Any) -> None:
    eng = await _migrated_engine(tmp_path)
    try:
        async with eng.connect() as c:
            names = await c.run_sync(lambda sc: sa.inspect(sc).get_table_names())
        assert "conversations" in names
        assert "conversation_turns" in names
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_migration_round_trips(tmp_path: Any) -> None:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'conv_rt.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    await asyncio.to_thread(command.downgrade, cfg, "0014")
    eng = create_async_engine(url)
    try:
        async with eng.connect() as c:
            names = await c.run_sync(lambda sc: sa.inspect(sc).get_table_names())
        assert "conversations" not in names
        assert "conversation_turns" not in names
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_conversation_columns(tmp_path: Any) -> None:
    eng = await _migrated_engine(tmp_path)
    try:
        async with eng.connect() as c:
            cols = await c.run_sync(
                lambda sc: {col["name"] for col in sa.inspect(sc).get_columns("conversations")}
            )
        assert cols == _CONVERSATION_COLUMNS
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_turn_columns(tmp_path: Any) -> None:
    eng = await _migrated_engine(tmp_path)
    try:
        async with eng.connect() as c:
            cols = await c.run_sync(
                lambda sc: {col["name"] for col in sa.inspect(sc).get_columns("conversation_turns")}
            )
        assert cols == _TURN_COLUMNS
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_tenant_id_is_not_nullable_the_isolation_boundary(tmp_path: Any) -> None:
    """tenant_id IS the isolation boundary (ADR-028 §3)."""
    eng = await _migrated_engine(tmp_path)
    try:
        async with eng.connect() as c:
            cols = await c.run_sync(lambda sc: sa.inspect(sc).get_columns("conversations"))
        by_name = {col["name"]: col for col in cols}
        assert by_name["tenant_id"]["nullable"] is False
        assert by_name["creator_subject"]["nullable"] is False
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_plaintext_columns_are_nullable_for_erasure(tmp_path: Any) -> None:
    """Erasure NULLs plaintext; the row, its seq, and agent_run_id survive."""
    eng = await _migrated_engine(tmp_path)
    try:
        async with eng.connect() as c:
            cols = await c.run_sync(lambda sc: sa.inspect(sc).get_columns("conversation_turns"))
        by_name = {col["name"]: col for col in cols}
        assert by_name["user_message"]["nullable"] is True
        assert by_name["answer"]["nullable"] is True
        assert by_name["seq"]["nullable"] is False
        assert by_name["agent_run_id"]["nullable"] is False
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_seq_is_unique_per_conversation(tmp_path: Any) -> None:
    eng = await _migrated_engine(tmp_path)
    try:
        async with eng.connect() as c:
            uniques = await c.run_sync(
                lambda sc: sa.inspect(sc).get_unique_constraints("conversation_turns")
            )
        assert any(set(u["column_names"]) == {"conversation_id", "seq"} for u in uniques), uniques
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_tenant_creator_state_index_exists(tmp_path: Any) -> None:
    eng = await _migrated_engine(tmp_path)
    try:
        async with eng.connect() as c:
            idx = await c.run_sync(lambda sc: sa.inspect(sc).get_indexes("conversations"))
        assert any(i["name"] == "ix_conversations_tenant_creator_state" for i in idx), idx
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_migration_tables_match_in_process_tables(tmp_path: Any) -> None:
    """The migrated DDL and the in-process Tables must not drift."""
    from cognic_agentos.core.conversation.storage import (
        _conversation_turns,
        _conversations,
    )

    eng = await _migrated_engine(tmp_path, "conv_drift.db")
    try:
        async with eng.connect() as c:
            conv = await c.run_sync(
                lambda sc: {col["name"] for col in sa.inspect(sc).get_columns("conversations")}
            )
            turns = await c.run_sync(
                lambda sc: {col["name"] for col in sa.inspect(sc).get_columns("conversation_turns")}
            )
        assert conv == {c.name for c in _conversations.columns}
        assert turns == {c.name for c in _conversation_turns.columns}
    finally:
        await eng.dispose()
