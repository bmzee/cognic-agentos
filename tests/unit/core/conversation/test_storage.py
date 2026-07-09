"""ADR-028 M8.5-A — ConversationStore over a REAL DecisionHistoryStore
(file-backed sqlite), mirroring tests/unit/core/run/test_run_storage.py.

Two enforcement boundaries are pinned here:
  1. tenant + creator isolation -- a foreign conversation_id reads as ABSENT.
  2. chain atomicity + the digest-only payload contract.

The fixture uses the SHARED ``core.audit._metadata`` and seeds the
``governance_chain_heads`` rows, because ``append_with_precondition`` reads the
head with ``.one()`` (``core/decision_history.py:489``) and raises
``NoResultFound`` when it is absent.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.conversation._types import (
    ConversationNotFound,
    ConversationTransitionRefused,
    ConversationTurnRefused,
)
from cognic_agentos.core.conversation.storage import (
    ConversationStore,
    _conversation_turns,
)
from cognic_agentos.core.decision_history import _decision_history

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def db(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'conv.db'}")
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id,
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=datetime.now(UTC),
                )
            )
    yield eng
    await eng.dispose()


@pytest.fixture
async def store(db: AsyncEngine) -> ConversationStore:
    return ConversationStore(db)


async def _new(store: ConversationStore, *, tenant: str = "t1", subject: str = "s1") -> uuid.UUID:
    cid = uuid.uuid4()
    await store.create_conversation(
        conversation_id=cid,
        tenant_id=tenant,
        agent_id="analyst",
        creator_subject=subject,
        request_id="req-create",
    )
    return cid


async def _chain_rows(db: AsyncEngine) -> list[sa.Row[tuple[str, dict[str, Any]]]]:
    """``DecisionRecord.decision_type`` persists to the ``event_type`` column."""
    async with db.connect() as conn:
        res = await conn.execute(
            sa.select(_decision_history.c.event_type, _decision_history.c.payload)
        )
        return list(res.fetchall())


# --- tenant + creator isolation ------------------------------------------------


async def test_cross_tenant_read_is_absent(store: ConversationStore) -> None:
    cid = await _new(store, tenant="tenant-a")
    assert await store.load(cid, tenant_id="tenant-a", creator_subject="s1") is not None
    assert await store.load(cid, tenant_id="tenant-b", creator_subject="s1") is None


async def test_cross_actor_read_is_absent(store: ConversationStore) -> None:
    cid = await _new(store, subject="alice")
    assert await store.load(cid, tenant_id="t1", creator_subject="bob") is None


async def test_unknown_conversation_reads_as_absent(store: ConversationStore) -> None:
    assert await store.load(uuid.uuid4(), tenant_id="t1", creator_subject="s1") is None


# --- the atomic single-writer claim -------------------------------------------


async def test_claim_is_exclusive_second_claim_refuses(store: ConversationStore) -> None:
    cid = await _new(store)
    now = datetime.now(UTC)
    await store.claim_turn(cid, tenant_id="t1", creator_subject="s1", now=now, claim_ttl_s=300.0)
    with pytest.raises(ConversationTurnRefused) as exc:
        await store.claim_turn(
            cid, tenant_id="t1", creator_subject="s1", now=now, claim_ttl_s=300.0
        )
    assert exc.value.reason == "conversation_turn_in_progress"
    assert exc.value.current_state == "active"


async def test_release_allows_reclaim(store: ConversationStore) -> None:
    cid = await _new(store)
    now = datetime.now(UTC)
    await store.claim_turn(cid, tenant_id="t1", creator_subject="s1", now=now, claim_ttl_s=300.0)
    await store.release_claim(cid, tenant_id="t1")
    await store.claim_turn(cid, tenant_id="t1", creator_subject="s1", now=now, claim_ttl_s=300.0)


async def test_stale_claim_is_reclaimable_after_ttl(store: ConversationStore) -> None:
    cid = await _new(store)
    t0 = datetime.now(UTC)
    await store.claim_turn(cid, tenant_id="t1", creator_subject="s1", now=t0, claim_ttl_s=60.0)
    later = t0 + timedelta(seconds=61)
    await store.claim_turn(cid, tenant_id="t1", creator_subject="s1", now=later, claim_ttl_s=60.0)


async def test_live_claim_inside_ttl_still_refuses(store: ConversationStore) -> None:
    cid = await _new(store)
    t0 = datetime.now(UTC)
    await store.claim_turn(cid, tenant_id="t1", creator_subject="s1", now=t0, claim_ttl_s=60.0)
    with pytest.raises(ConversationTurnRefused) as exc:
        await store.claim_turn(
            cid,
            tenant_id="t1",
            creator_subject="s1",
            now=t0 + timedelta(seconds=59),
            claim_ttl_s=60.0,
        )
    assert exc.value.reason == "conversation_turn_in_progress"


async def test_claim_on_closed_conversation_refuses_not_active(
    store: ConversationStore,
) -> None:
    cid = await _new(store)
    await store.transition(
        conversation_id=cid,
        tenant_id="t1",
        to_state="closed",
        actor_id="s1",
        request_id="req-close",
    )
    with pytest.raises(ConversationTurnRefused) as exc:
        await store.claim_turn(
            cid,
            tenant_id="t1",
            creator_subject="s1",
            now=datetime.now(UTC),
            claim_ttl_s=300.0,
        )
    assert exc.value.reason == "conversation_not_active"
    assert exc.value.current_state == "closed"


async def test_claim_on_missing_conversation_raises_not_found(
    store: ConversationStore,
) -> None:
    with pytest.raises(ConversationNotFound):
        await store.claim_turn(
            uuid.uuid4(),
            tenant_id="t1",
            creator_subject="s1",
            now=datetime.now(UTC),
            claim_ttl_s=300.0,
        )


async def test_claim_cross_tenant_raises_not_found(store: ConversationStore) -> None:
    cid = await _new(store, tenant="tenant-a")
    with pytest.raises(ConversationNotFound):
        await store.claim_turn(
            cid,
            tenant_id="tenant-b",
            creator_subject="s1",
            now=datetime.now(UTC),
            claim_ttl_s=300.0,
        )


# --- turn persistence: chain-atomic, digest-only -------------------------------


async def test_append_turn_returns_the_id_it_actually_inserted(
    store: ConversationStore, db: AsyncEngine
) -> None:
    cid = await _new(store)
    turn_id = await store.append_turn(
        conversation_id=cid,
        tenant_id="t1",
        seq=1,
        user_message="q",
        answer="a",
        agent_run_id="agent-run-1",
        prompt_tokens=1,
        completion_tokens=1,
        actor_id="s1",
        request_id="req-t",
    )
    async with db.connect() as conn:
        found = (
            await conn.execute(
                sa.select(_conversation_turns.c.turn_id).where(
                    _conversation_turns.c.turn_id == turn_id
                )
            )
        ).first()
    assert found is not None


async def test_turn_chain_row_carries_digests_never_plaintext(
    store: ConversationStore, db: AsyncEngine
) -> None:
    cid = await _new(store)
    turn_id = await store.append_turn(
        conversation_id=cid,
        tenant_id="t1",
        seq=1,
        user_message="who is the top depositor",
        answer="Acme Corp",
        agent_run_id="agent-run-abc",
        prompt_tokens=10,
        completion_tokens=5,
        actor_id="s1",
        request_id="req-t2",
    )
    rows = [r for r in await _chain_rows(db) if r.event_type == "conversation.turn_completed"]
    assert len(rows) == 1
    payload = rows[0].payload
    assert payload["agent_run_id"] == "agent-run-abc"
    assert payload["seq"] == 1
    assert payload["turn_id"] == str(turn_id)
    assert set(payload) >= {
        "question_sha256",
        "answer_sha256",
        "question_bytes",
        "answer_bytes",
    }
    blob = str(payload)
    assert "top depositor" not in blob
    assert "Acme Corp" not in blob


async def test_append_turn_bumps_counters(store: ConversationStore) -> None:
    cid = await _new(store)
    await store.append_turn(
        conversation_id=cid,
        tenant_id="t1",
        seq=1,
        user_message="q",
        answer="a",
        agent_run_id="r1",
        prompt_tokens=7,
        completion_tokens=3,
        actor_id="s1",
        request_id="req-t3",
    )
    rec = await store.load(cid, tenant_id="t1", creator_subject="s1")
    assert rec is not None
    assert rec.turn_count == 1
    assert rec.cumulative_tokens == 10
    assert rec.last_turn_at is not None


async def test_create_conversation_emits_created_chain_row(
    store: ConversationStore, db: AsyncEngine
) -> None:
    cid = await _new(store)
    rows = [r for r in await _chain_rows(db) if r.event_type == "conversation.created"]
    assert len(rows) == 1
    assert rows[0].payload["conversation_id"] == str(cid)
    assert rows[0].payload["agent_id"] == "analyst"


# --- bounded-replay source -----------------------------------------------------


async def _seed_turns(store: ConversationStore, cid: uuid.UUID, n: int) -> None:
    for i in range(1, n + 1):
        await store.append_turn(
            conversation_id=cid,
            tenant_id="t1",
            seq=i,
            user_message=f"q{i}",
            answer=f"a{i}",
            agent_run_id=f"r{i}",
            prompt_tokens=1,
            completion_tokens=1,
            actor_id="s1",
            request_id=f"req-{i}",
        )


async def test_replay_turns_returns_first_then_last_n_in_seq_order(
    store: ConversationStore,
) -> None:
    cid = await _new(store)
    await _seed_turns(store, cid, 5)
    turns = await store.load_replay_turns(cid, tenant_id="t1", last_n=2)
    assert [t.seq for t in turns] == [1, 4, 5]


async def test_replay_turns_dedupes_when_window_covers_first(
    store: ConversationStore,
) -> None:
    cid = await _new(store)
    await _seed_turns(store, cid, 3)
    turns = await store.load_replay_turns(cid, tenant_id="t1", last_n=10)
    assert [t.seq for t in turns] == [1, 2, 3]


async def test_replay_turns_last_n_zero_yields_only_the_grounding_turn(
    store: ConversationStore,
) -> None:
    cid = await _new(store)
    await _seed_turns(store, cid, 3)
    turns = await store.load_replay_turns(cid, tenant_id="t1", last_n=0)
    assert [t.seq for t in turns] == [1]


async def test_replay_turns_on_empty_conversation(store: ConversationStore) -> None:
    cid = await _new(store)
    assert await store.load_replay_turns(cid, tenant_id="t1", last_n=5) == []


async def test_replay_turns_is_tenant_scoped(store: ConversationStore) -> None:
    cid = await _new(store, tenant="tenant-a")
    await store.append_turn(
        conversation_id=cid,
        tenant_id="tenant-a",
        seq=1,
        user_message="q",
        answer="a",
        agent_run_id="r1",
        prompt_tokens=1,
        completion_tokens=1,
        actor_id="s1",
        request_id="req-x",
    )
    assert await store.load_replay_turns(cid, tenant_id="tenant-b", last_n=5) == []


# --- lifecycle -----------------------------------------------------------------


async def test_transition_records_the_locked_from_state(
    store: ConversationStore, db: AsyncEngine
) -> None:
    cid = await _new(store)
    await store.transition(
        conversation_id=cid,
        tenant_id="t1",
        to_state="closed",
        actor_id="s1",
        request_id="req-c",
    )
    rows = [r for r in await _chain_rows(db) if r.event_type == "conversation.closed"]
    assert len(rows) == 1
    assert rows[0].payload["from_state"] == "active"
    assert rows[0].payload["to_state"] == "closed"


async def test_transition_updates_state_and_clears_claim(
    store: ConversationStore,
) -> None:
    cid = await _new(store)
    await store.claim_turn(
        cid,
        tenant_id="t1",
        creator_subject="s1",
        now=datetime.now(UTC),
        claim_ttl_s=300.0,
    )
    await store.transition(
        conversation_id=cid,
        tenant_id="t1",
        to_state="closed",
        actor_id="s1",
        request_id="req-c2",
    )
    rec = await store.load(cid, tenant_id="t1", creator_subject="s1")
    assert rec is not None and rec.state == "closed"


async def test_transition_on_missing_conversation_raises_not_found(
    store: ConversationStore,
) -> None:
    with pytest.raises(ConversationNotFound):
        await store.transition(
            conversation_id=uuid.uuid4(),
            tenant_id="t1",
            to_state="closed",
            actor_id="s1",
            request_id="req-c3",
        )


async def test_transition_cross_tenant_raises_not_found(
    store: ConversationStore,
) -> None:
    cid = await _new(store, tenant="tenant-a")
    with pytest.raises(ConversationNotFound):
        await store.transition(
            conversation_id=cid,
            tenant_id="tenant-b",
            to_state="closed",
            actor_id="s1",
            request_id="req-c4",
        )


async def test_illegal_transition_refuses_and_writes_no_chain_row(
    store: ConversationStore, db: AsyncEngine
) -> None:
    """Refusal rolls the transaction back: no chain row, no state mutation."""
    cid = await _new(store)
    before = len(await _chain_rows(db))
    with pytest.raises(ConversationTransitionRefused) as exc:
        await store.transition(
            conversation_id=cid,
            tenant_id="t1",
            to_state="expired",  # reserved pair in M8.5-A
            actor_id="s1",
            request_id="req-bad",
        )
    assert exc.value.reason == "conversation_transition_invalid_state_pair"
    assert len(await _chain_rows(db)) == before
    rec = await store.load(cid, tenant_id="t1", creator_subject="s1")
    assert rec is not None and rec.state == "active"


async def test_double_close_refuses(store: ConversationStore) -> None:
    cid = await _new(store)
    await store.transition(
        conversation_id=cid,
        tenant_id="t1",
        to_state="closed",
        actor_id="s1",
        request_id="req-c5",
    )
    with pytest.raises(ConversationTransitionRefused):
        await store.transition(
            conversation_id=cid,
            tenant_id="t1",
            to_state="closed",
            actor_id="s1",
            request_id="req-c6",
        )


async def test_unknown_target_state_refuses_before_any_db_work(
    store: ConversationStore, db: AsyncEngine
) -> None:
    """Preflight guard: an out-of-vocabulary target never reaches the chain."""
    cid = await _new(store)
    before = len(await _chain_rows(db))
    with pytest.raises(ConversationTransitionRefused) as exc:
        await store.transition(
            conversation_id=cid,
            tenant_id="t1",
            to_state="bogus",  # type: ignore[arg-type]
            actor_id="s1",
            request_id="req-c7",
        )
    assert exc.value.reason == "conversation_transition_invalid_state_pair"
    assert len(await _chain_rows(db)) == before
