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
from cognic_agentos.core.chain_verifier import ChainVerifier
from cognic_agentos.core.conversation._types import (
    ConversationNotFound,
    ConversationTransitionRefused,
    ConversationTurnRefused,
)
from cognic_agentos.core.conversation.storage import (
    ConversationStore,
    _conversation_turns,
    _conversations,
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


async def _claim(
    store: ConversationStore, cid: uuid.UUID, *, tenant: str = "t1", subject: str = "s1"
) -> Any:
    return await store.claim_turn(
        cid,
        tenant_id=tenant,
        creator_subject=subject,
        now=datetime.now(UTC),
        claim_ttl_s=300.0,
    )


async def _append(
    store: ConversationStore,
    cid: uuid.UUID,
    seq: int,
    *,
    tenant: str = "t1",
    subject: str = "s1",
    q: str = "q",
    a: str = "a",
    run: str | None = None,
    pt: int = 1,
    ct: int = 1,
    approval_request_id: str | None = None,
    request_id: str | None = None,
) -> uuid.UUID:
    """The honest flow: claim -> append(fenced) -> release(own claim)."""
    claim = await _claim(store, cid, tenant=tenant, subject=subject)
    turn_id = await store.append_turn(
        conversation_id=cid,
        tenant_id=tenant,
        seq=seq,
        user_message=q,
        answer=a,
        agent_run_id=run if run is not None else f"r{seq}",
        prompt_tokens=pt,
        completion_tokens=ct,
        actor_id=subject,
        request_id=request_id if request_id is not None else f"req-{seq}",
        claim_id=claim.claim_id,
        approval_request_id=approval_request_id,
    )
    await store.release_claim(cid, tenant_id=tenant, claim_id=claim.claim_id)
    return turn_id


async def _chain_rows(
    db: AsyncEngine,
) -> list[sa.Row[tuple[str, str, dict[str, Any]]]]:
    """``DecisionRecord.decision_type`` persists to the ``event_type`` column."""
    async with db.connect() as conn:
        res = await conn.execute(
            sa.select(
                _decision_history.c.event_type,
                _decision_history.c.request_id,
                _decision_history.c.payload,
            )
        )
        return list(res.fetchall())


async def _decision_chain_state(db: AsyncEngine) -> tuple[int, bytes, int]:
    """Snapshot the decision-chain head plus its physical row count."""
    async with db.connect() as conn:
        head = (
            await conn.execute(
                sa.select(_chain_heads.c.latest_sequence, _chain_heads.c.latest_hash).where(
                    _chain_heads.c.chain_id == "decision_history"
                )
            )
        ).one()
        row_count = (
            await conn.execute(sa.select(sa.func.count()).select_from(_decision_history))
        ).scalar_one()
    return int(head.latest_sequence), bytes(head.latest_hash), int(row_count)


async def _refuse_erasure_evidence_inserts(db: AsyncEngine) -> None:
    """Make the evidence phase fail after a redaction precondition has run."""
    async with db.begin() as conn:
        await conn.execute(
            sa.text(
                """
                CREATE TRIGGER refuse_conversation_erased
                BEFORE INSERT ON decision_history
                WHEN NEW.event_type = 'conversation.erased'
                BEGIN
                    SELECT RAISE(ABORT, 'forced conversation.erased insert failure');
                END
                """
            )
        )


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
    claim = await store.claim_turn(
        cid, tenant_id="t1", creator_subject="s1", now=now, claim_ttl_s=300.0
    )
    await store.release_claim(cid, tenant_id="t1", claim_id=claim.claim_id)
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


async def test_system_claim_cross_tenant_raises_not_found(store: ConversationStore) -> None:
    cid = await _new(store, tenant="tenant-a")
    with pytest.raises(ConversationNotFound):
        await store.claim_system_turn(
            cid,
            tenant_id="tenant-b",
            now=datetime.now(UTC),
            claim_ttl_s=300.0,
        )


# --- turn persistence: chain-atomic, digest-only -------------------------------


async def test_append_turn_returns_the_id_it_actually_inserted(
    store: ConversationStore, db: AsyncEngine
) -> None:
    cid = await _new(store)
    turn_id = await _append(store, cid, 1, run="agent-run-1")
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
    turn_id = await _append(
        store,
        cid,
        1,
        q="who is the top depositor",
        a="Acme Corp",
        run="agent-run-abc",
        pt=10,
        ct=5,
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
    await _append(store, cid, 1, pt=7, ct=3)
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
        await _append(store, cid, i, q=f"q{i}", a=f"a{i}")


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


async def test_replay_source_excludes_system_turns_before_windowing(
    store: ConversationStore,
) -> None:
    cid = await _new(store)
    await _append(store, cid, 1, q="q1", a="a1")
    claim = await store.claim_system_turn(
        cid,
        tenant_id="t1",
        now=datetime.now(UTC),
        claim_ttl_s=300.0,
    )
    await store.append_system_turn(
        conversation_id=cid,
        tenant_id="t1",
        text="approved",
        approval_request_id="a1b2c3d4-1111-4222-8333-444455556666",
        actor_id="system:approval-executor",
        request_id="req-system",
        claim_id=claim.claim_id,
    )
    await store.release_claim(cid, tenant_id="t1", claim_id=claim.claim_id)
    await _append(store, cid, 3, q="q2", a="a2")

    turns = await store.load_replay_turns(cid, tenant_id="t1", last_n=10)
    assert [(turn.seq, turn.turn_kind) for turn in turns] == [
        (1, "exchange"),
        (3, "exchange"),
    ]


async def test_resolve_approval_context_returns_tenant_scoped_conversation_and_agent(
    store: ConversationStore,
) -> None:
    approval_id = "a1b2c3d4-1111-4222-8333-444455556666"
    cid = await _new(store, tenant="tenant-a")
    await _append(
        store,
        cid,
        1,
        tenant="tenant-a",
        approval_request_id=approval_id,
    )
    assert await store.resolve_approval_context(
        approval_request_id=uuid.UUID(approval_id),
        tenant_id="tenant-a",
    ) == (cid, "analyst")
    assert (
        await store.resolve_approval_context(
            approval_request_id=uuid.UUID(approval_id),
            tenant_id="tenant-b",
        )
        is None
    )


async def test_resolve_approval_context_refuses_duplicate_correlation(
    store: ConversationStore,
) -> None:
    approval_id = "a1b2c3d4-1111-4222-8333-444455556666"
    first = await _new(store)
    second = await _new(store)
    await _append(store, first, 1, approval_request_id=approval_id)
    await _append(
        store,
        second,
        1,
        approval_request_id=approval_id,
        request_id="req-duplicate-correlation",
    )
    with pytest.raises(RuntimeError, match="approval conversation correlation is not unique"):
        await store.resolve_approval_context(
            approval_request_id=uuid.UUID(approval_id),
            tenant_id="t1",
        )


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
    await _append(store, cid, 1, tenant="tenant-a")
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


async def test_close_is_graceful_and_preserves_an_in_flight_claim(
    store: ConversationStore, db: AsyncEngine
) -> None:
    """GRACEFUL CLOSE (ruled 2026-07-09): closing blocks NEW turns but does not
    cancel work already admitted.

    ``close`` is NOT an emergency cancel. The in-flight executor keeps its claim
    and releases it in its own ``finally``; clearing the claim inside
    ``transition`` would let the store forget that a turn was still running.
    """
    import sqlalchemy as sa

    from cognic_agentos.core.conversation.storage import _conversations

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

    async with db.connect() as conn:
        row = (
            (
                await conn.execute(
                    sa.select(
                        _conversations.c.turn_in_progress,
                        _conversations.c.turn_claimed_at,
                        _conversations.c.turn_claim_id,
                    ).where(_conversations.c.conversation_id == cid)
                )
            )
            .mappings()
            .first()
        )
    assert row is not None
    assert row["turn_in_progress"] is True, "close must not cancel admitted work"
    assert row["turn_claimed_at"] is not None
    assert row["turn_claim_id"] is not None, "the fencing token survives close"


async def test_admitted_turn_settles_after_close_then_new_turns_refuse(
    store: ConversationStore,
) -> None:
    """The race ruling 1 pins: claim -> close -> the admitted turn still lands,
    the executor releases, and only THEN does the conversation reject new work.
    """
    cid = await _new(store)
    claim = await store.claim_turn(
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
        request_id="req-race",
    )
    # the in-flight turn settles: ``closed`` is a persistable state (the
    # active|closed rule), and the write is FENCED by its own claim_id
    turn_id = await store.append_turn(
        conversation_id=cid,
        tenant_id="t1",
        seq=1,
        user_message="in flight",
        answer="settled",
        agent_run_id="agent-run-race",
        prompt_tokens=1,
        completion_tokens=1,
        actor_id="s1",
        request_id="req-race-turn",
        claim_id=claim.claim_id,
    )
    assert turn_id is not None
    await store.release_claim(cid, tenant_id="t1", claim_id=claim.claim_id)

    rec = await store.load(cid, tenant_id="t1", creator_subject="s1")
    assert rec is not None and rec.turn_count == 1 and rec.state == "closed"

    # a NEW turn is refused -- not because of the claim, but because it is closed
    with pytest.raises(ConversationTurnRefused) as exc:
        await store.claim_turn(
            cid,
            tenant_id="t1",
            creator_subject="s1",
            now=datetime.now(UTC),
            claim_ttl_s=300.0,
        )
    assert exc.value.reason == "conversation_not_active"


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


# --- FENCING (P0, 2026-07-10): TTL expiry is liveness, not mutual exclusion -----


async def test_stale_worker_append_is_fenced_out(store: ConversationStore, db: AsyncEngine) -> None:
    """A claims -> stalls past TTL -> B steals the lease -> delayed A tries to
    persist. A's token is stale: refused ``conversation_turn_claim_stale``,
    transaction rolled back whole -- no turn row, no chain row, no counters."""
    cid = await _new(store)
    t0 = datetime.now(UTC)
    claim_a = await store.claim_turn(
        cid, tenant_id="t1", creator_subject="s1", now=t0, claim_ttl_s=60.0
    )
    # TTL expires; B reclaims (liveness) and mints a NEW token
    claim_b = await store.claim_turn(
        cid,
        tenant_id="t1",
        creator_subject="s1",
        now=t0 + timedelta(seconds=61),
        claim_ttl_s=60.0,
    )
    assert claim_a.claim_id != claim_b.claim_id

    before = len(await _chain_rows(db))
    with pytest.raises(ConversationTurnRefused) as exc:
        await store.append_turn(
            conversation_id=cid,
            tenant_id="t1",
            seq=1,
            user_message="delayed A",
            answer="must not land",
            agent_run_id="agent-run-A",
            prompt_tokens=1,
            completion_tokens=1,
            actor_id="s1",
            request_id="req-stale-a",
            claim_id=claim_a.claim_id,
        )
    assert exc.value.reason == "conversation_turn_claim_stale"
    assert len(await _chain_rows(db)) == before  # rolled back: no chain row
    rec = await store.load(cid, tenant_id="t1", creator_subject="s1")
    assert rec is not None and rec.turn_count == 0 and rec.cumulative_tokens == 0

    # B, holding the CURRENT token, persists fine
    turn_id = await store.append_turn(
        conversation_id=cid,
        tenant_id="t1",
        seq=1,
        user_message="B's turn",
        answer="lands",
        agent_run_id="agent-run-B",
        prompt_tokens=1,
        completion_tokens=1,
        actor_id="s1",
        request_id="req-b",
        claim_id=claim_b.claim_id,
    )
    assert turn_id is not None


async def test_stale_worker_release_is_a_noop(store: ConversationStore, db: AsyncEngine) -> None:
    """After B steals, delayed A's release must NOT unlock B's lease."""
    cid = await _new(store)
    t0 = datetime.now(UTC)
    claim_a = await store.claim_turn(
        cid, tenant_id="t1", creator_subject="s1", now=t0, claim_ttl_s=60.0
    )
    claim_b = await store.claim_turn(
        cid,
        tenant_id="t1",
        creator_subject="s1",
        now=t0 + timedelta(seconds=61),
        claim_ttl_s=60.0,
    )

    await store.release_claim(cid, tenant_id="t1", claim_id=claim_a.claim_id)  # stale: no-op

    async with db.connect() as conn:
        row = (
            (
                await conn.execute(
                    sa.select(
                        _conversations.c.turn_in_progress,
                        _conversations.c.turn_claim_id,
                    ).where(_conversations.c.conversation_id == cid)
                )
            )
            .mappings()
            .first()
        )
    assert row is not None
    assert row["turn_in_progress"] is True, "stale release must not unlock B"
    assert row["turn_claim_id"] == claim_b.claim_id

    # a third claim while B's lease is live still refuses
    with pytest.raises(ConversationTurnRefused) as exc:
        await store.claim_turn(
            cid,
            tenant_id="t1",
            creator_subject="s1",
            now=t0 + timedelta(seconds=62),
            claim_ttl_s=60.0,
        )
    assert exc.value.reason == "conversation_turn_in_progress"

    # B's OWN release works, and is idempotent
    await store.release_claim(cid, tenant_id="t1", claim_id=claim_b.claim_id)
    await store.release_claim(cid, tenant_id="t1", claim_id=claim_b.claim_id)
    await store.claim_turn(
        cid,
        tenant_id="t1",
        creator_subject="s1",
        now=t0 + timedelta(seconds=63),
        claim_ttl_s=60.0,
    )


async def test_fenced_append_on_a_vanished_conversation_raises_not_found(
    store: ConversationStore,
) -> None:
    """The fence's defensive arm: the row is gone (or cross-tenant) at append
    time. Rolled back whole; surfaces as the same absent signal as every other
    cross-boundary read."""
    with pytest.raises(ConversationNotFound):
        await store.append_turn(
            conversation_id=uuid.uuid4(),
            tenant_id="t1",
            seq=1,
            user_message="q",
            answer="a",
            agent_run_id="r1",
            prompt_tokens=1,
            completion_tokens=1,
            actor_id="s1",
            request_id="req-vanished",
            claim_id=uuid.uuid4(),
        )


# --- RESURRECTION PREVENTION (ruled 2026-07-10): active|closed persist only -----


@pytest.mark.parametrize("terminal", ["expired", "erased"])
async def test_valid_lease_cannot_write_into_expired_or_erased(
    store: ConversationStore, db: AsyncEngine, terminal: str
) -> None:
    """A VALID claim does not override the lifecycle boundary: persisting
    plaintext into an erased conversation would resurrect content after a
    regulator erasure; an expired one is past its retention decision. Refused
    at persist time, rolled back whole."""
    cid = await _new(store)
    claim = await _claim(store, cid)
    # model the future reaper / erasure slices flipping the row mid-turn
    # (no legal transition exists in this slice -- the rule must hold however
    # the state got there)
    async with db.begin() as conn:
        await conn.execute(
            sa.update(_conversations)
            .where(_conversations.c.conversation_id == cid)
            .values(state=terminal)
        )
    before = len(await _chain_rows(db))
    with pytest.raises(ConversationTurnRefused) as exc:
        await store.append_turn(
            conversation_id=cid,
            tenant_id="t1",
            seq=1,
            user_message="resurrected?",
            answer="must not land",
            agent_run_id="agent-run-res",
            prompt_tokens=1,
            completion_tokens=1,
            actor_id="s1",
            request_id=f"req-res-{terminal}",
            claim_id=claim.claim_id,
        )
    assert exc.value.reason == "conversation_not_active"
    assert exc.value.current_state == terminal
    assert len(await _chain_rows(db)) == before  # rolled back: no chain row
    async with db.connect() as conn:
        n = (
            await conn.execute(sa.select(sa.func.count()).select_from(_conversation_turns))
        ).scalar_one()
    assert n == 0  # no plaintext row resurrected


async def test_stale_lease_on_an_erased_row_refuses_as_stale(
    store: ConversationStore, db: AsyncEngine
) -> None:
    """Ownership precedes lifecycle: with NO valid lease the refusal is
    conversation_turn_claim_stale even on an erased row."""
    cid = await _new(store)
    t0 = datetime.now(UTC)
    claim_a = await store.claim_turn(
        cid, tenant_id="t1", creator_subject="s1", now=t0, claim_ttl_s=60.0
    )
    await store.claim_turn(  # B steals after TTL
        cid,
        tenant_id="t1",
        creator_subject="s1",
        now=t0 + timedelta(seconds=61),
        claim_ttl_s=60.0,
    )
    async with db.begin() as conn:
        await conn.execute(
            sa.update(_conversations)
            .where(_conversations.c.conversation_id == cid)
            .values(state="erased")
        )
    with pytest.raises(ConversationTurnRefused) as exc:
        await store.append_turn(
            conversation_id=cid,
            tenant_id="t1",
            seq=1,
            user_message="x",
            answer="y",
            agent_run_id="r",
            prompt_tokens=1,
            completion_tokens=1,
            actor_id="s1",
            request_id="req-stale-erased",
            claim_id=claim_a.claim_id,
        )
    assert exc.value.reason == "conversation_turn_claim_stale"


# --- M8.5-B (migration 0016): the hop-1 correlation column ------------------------


async def test_append_turn_persists_the_turn_completed_request_id(
    store: ConversationStore, db: AsyncEngine
) -> None:
    """CORRELATION EQUALITY: the turn row carries the SAME caller-minted
    request_id as its exactly-one conversation.turn_completed chain row — the
    correlation the M8.5-B chain-join read resolves hop 1 through. (The
    ATOMICITY of the pairing is proven by the rollback test below.)"""
    cid = await _new(store)
    claim = await _claim(store, cid)
    rid = f"conv-turn-{uuid.uuid4().hex}"
    await store.append_turn(
        conversation_id=cid,
        tenant_id="t1",
        seq=1,
        user_message="q",
        answer="a",
        agent_run_id="agent-run-corr",
        prompt_tokens=1,
        completion_tokens=1,
        actor_id="s1",
        request_id=rid,
        claim_id=claim.claim_id,
    )
    async with db.connect() as conn:
        stored = (
            await conn.execute(
                sa.select(_conversation_turns.c.turn_completed_request_id).where(
                    _conversation_turns.c.conversation_id == cid
                )
            )
        ).scalar_one()
        chain_count = (
            await conn.execute(
                sa.select(sa.func.count())
                .select_from(_decision_history)
                .where(
                    _decision_history.c.request_id == rid,
                    _decision_history.c.event_type == "conversation.turn_completed",
                )
            )
        ).scalar_one()
    assert stored == rid  # the turn row carries the minted request id
    assert chain_count == 1  # and exactly one chain row pairs with it


async def test_duplicate_turn_completed_request_id_rolls_back_turn_and_chain(
    store: ConversationStore, db: AsyncEngine
) -> None:
    """ROLLBACK ATOMICITY: a duplicate correlation id violates the named
    unique constraint (in-process metadata parity with migration 0016) and the
    single transaction rolls back BOTH the turn row AND the chain row — no
    orphan on either side, counters untouched."""
    from sqlalchemy.exc import IntegrityError

    cid = await _new(store)
    claim = await _claim(store, cid)
    rid = f"conv-turn-{uuid.uuid4().hex}"
    await store.append_turn(
        conversation_id=cid,
        tenant_id="t1",
        seq=1,
        user_message="q1",
        answer="a1",
        agent_run_id="agent-run-dup-a",
        prompt_tokens=1,
        completion_tokens=1,
        actor_id="s1",
        request_id=rid,
        claim_id=claim.claim_id,
    )
    await store.release_claim(cid, tenant_id="t1", claim_id=claim.claim_id)

    claim2 = await _claim(store, cid)
    with pytest.raises(IntegrityError):
        await store.append_turn(
            conversation_id=cid,
            tenant_id="t1",
            seq=2,
            user_message="q2",
            answer="a2",
            agent_run_id="agent-run-dup-b",
            prompt_tokens=1,
            completion_tokens=1,
            actor_id="s1",
            request_id=rid,  # DUPLICATE correlation id
            claim_id=claim2.claim_id,
        )

    async with db.connect() as conn:
        turn_rows = (
            await conn.execute(
                sa.select(sa.func.count())
                .select_from(_conversation_turns)
                .where(_conversation_turns.c.conversation_id == cid)
            )
        ).scalar_one()
        chain_rows = (
            await conn.execute(
                sa.select(sa.func.count())
                .select_from(_decision_history)
                .where(
                    _decision_history.c.request_id == rid,
                    _decision_history.c.event_type == "conversation.turn_completed",
                )
            )
        ).scalar_one()
        counters = (
            await conn.execute(
                sa.select(_conversations.c.turn_count, _conversations.c.cumulative_tokens).where(
                    _conversations.c.conversation_id == cid
                )
            )
        ).one()
    assert turn_rows == 1  # the second turn row rolled back
    assert chain_rows == 1  # and so did its chain row — no orphan evidence
    assert tuple(counters) == (1, 2)  # counters reflect ONLY the first turn


# --- M8.5-F S1: tenant-scoped value erasure, intact evidence -------------------


async def test_redact_turn_nulls_only_values_and_appends_value_free_evidence(
    store: ConversationStore, db: AsyncEngine
) -> None:
    cid = await _new(store)
    turn_id = await _append(
        store,
        cid,
        1,
        q="sensitive user value",
        a="sensitive answer value",
        run="agent-run-redact",
        approval_request_id="a1b2c3d4-1111-4222-8333-444455556666",
        request_id="req-original-turn",
    )

    assert await store.redact_turn(
        conversation_id=cid,
        tenant_id="t1",
        seq=1,
        actor_id="compliance-officer",
        request_id="req-redact-turn",
    )

    async with db.connect() as conn:
        row = (
            (
                await conn.execute(
                    sa.select(_conversation_turns).where(_conversation_turns.c.turn_id == turn_id)
                )
            )
            .mappings()
            .one()
        )
    assert row["user_message"] is None
    assert row["answer"] is None
    assert row["erased_at"] is not None
    assert row["agent_run_id"] == "agent-run-redact"
    assert row["approval_request_id"] == "a1b2c3d4-1111-4222-8333-444455556666"
    assert row["turn_completed_request_id"] == "req-original-turn"

    replay = await store.load_replay_turns(cid, tenant_id="t1", last_n=10)
    assert len(replay) == 1
    assert replay[0].user_message is None
    assert replay[0].answer is None

    rows = await _chain_rows(db)
    completed = [row for row in rows if row.event_type == "conversation.turn_completed"]
    erased = [row for row in rows if row.event_type == "conversation.erased"]
    assert len(completed) == 1
    assert len(erased) == 1
    assert erased[0].payload == {
        "actor_id": "compliance-officer",
        "conversation_id": str(cid),
        "erased_turn_count": 1,
        "scope": "turn",
        "seq": 1,
    }
    evidence_blob = str(erased[0].payload)
    assert "sensitive user value" not in evidence_blob
    assert "sensitive answer value" not in evidence_blob


async def test_redact_turn_is_idempotent_and_emits_no_duplicate_evidence(
    store: ConversationStore, db: AsyncEngine
) -> None:
    cid = await _new(store)
    await _append(store, cid, 1, q="erase once", a="only once")

    first = await store.redact_turn(
        conversation_id=cid,
        tenant_id="t1",
        seq=1,
        actor_id="compliance-officer",
        request_id="req-redact-turn-first",
    )
    second = await store.redact_turn(
        conversation_id=cid,
        tenant_id="t1",
        seq=1,
        actor_id="compliance-officer",
        request_id="req-redact-turn-second",
    )

    assert first is True
    assert second is False
    erased = [row for row in await _chain_rows(db) if row.event_type == "conversation.erased"]
    assert len(erased) == 1
    assert erased[0].request_id == "req-redact-turn-first"


async def test_redact_turn_rolls_back_values_when_erasure_evidence_insert_fails(
    store: ConversationStore, db: AsyncEngine
) -> None:
    """Doctrine Lock D: the turn UPDATE cannot commit without its chain row."""
    cid = await _new(store)
    await _append(store, cid, 1, q="must survive rollback", a="answer survives too")
    chain_before = await _decision_chain_state(db)
    await _refuse_erasure_evidence_inserts(db)

    with pytest.raises(sa.exc.DBAPIError, match=r"forced conversation\.erased insert failure"):
        await store.redact_turn(
            conversation_id=cid,
            tenant_id="t1",
            seq=1,
            actor_id="compliance-officer",
            request_id="req-redact-turn-forced-chain-failure",
        )

    async with db.connect() as conn:
        turn = (
            await conn.execute(
                sa.select(
                    _conversation_turns.c.user_message,
                    _conversation_turns.c.answer,
                    _conversation_turns.c.erased_at,
                ).where(
                    _conversation_turns.c.conversation_id == cid,
                    _conversation_turns.c.seq == 1,
                )
            )
        ).one()
    assert tuple(turn) == ("must survive rollback", "answer survives too", None)
    assert await _decision_chain_state(db) == chain_before
    assert not [
        event for event in await _chain_rows(db) if event.event_type == "conversation.erased"
    ]


async def test_redact_turn_cross_tenant_is_indistinguishable_from_unknown(
    store: ConversationStore, db: AsyncEngine
) -> None:
    cid = await _new(store, tenant="tenant-a")
    await _append(
        store,
        cid,
        1,
        tenant="tenant-a",
        q="must remain",
        a="must remain too",
    )

    cross_tenant = await store.redact_turn(
        conversation_id=cid,
        tenant_id="tenant-b",
        seq=1,
        actor_id="compliance-officer",
        request_id="req-cross-tenant-redact",
    )
    unknown = await store.redact_turn(
        conversation_id=uuid.uuid4(),
        tenant_id="tenant-b",
        seq=1,
        actor_id="compliance-officer",
        request_id="req-unknown-redact",
    )

    assert cross_tenant is False
    assert unknown is False
    async with db.connect() as conn:
        row = (
            await conn.execute(
                sa.select(
                    _conversation_turns.c.user_message,
                    _conversation_turns.c.answer,
                    _conversation_turns.c.erased_at,
                ).where(_conversation_turns.c.conversation_id == cid)
            )
        ).one()
    assert tuple(row) == ("must remain", "must remain too", None)
    assert not [
        event for event in await _chain_rows(db) if event.event_type == "conversation.erased"
    ]


async def test_redact_conversation_erases_parent_and_all_turn_values_atomically(
    store: ConversationStore, db: AsyncEngine
) -> None:
    cid = await _new(store)
    await _append(store, cid, 1, q="first user value", a="first answer value")
    await _append(store, cid, 2, q="second user value", a="second answer value")

    assert await store.redact_conversation(
        conversation_id=cid,
        tenant_id="t1",
        actor_id="compliance-officer",
        request_id="req-redact-conversation",
    )

    async with db.connect() as conn:
        parent = (
            await conn.execute(
                sa.select(_conversations.c.state, _conversations.c.erased_at).where(
                    _conversations.c.conversation_id == cid
                )
            )
        ).one()
        turns = (
            await conn.execute(
                sa.select(
                    _conversation_turns.c.seq,
                    _conversation_turns.c.user_message,
                    _conversation_turns.c.answer,
                    _conversation_turns.c.erased_at,
                )
                .where(_conversation_turns.c.conversation_id == cid)
                .order_by(_conversation_turns.c.seq)
            )
        ).all()
    assert parent.state == "erased"
    assert parent.erased_at is not None
    assert [row.seq for row in turns] == [1, 2]
    assert all(row.user_message is None and row.answer is None for row in turns)
    assert all(row.erased_at is not None for row in turns)

    erased = [row for row in await _chain_rows(db) if row.event_type == "conversation.erased"]
    assert len(erased) == 1
    assert erased[0].payload == {
        "actor_id": "compliance-officer",
        "conversation_id": str(cid),
        "erased_turn_count": 2,
        "scope": "conversation",
    }
    report = await ChainVerifier(db, "decision_history").walk()
    assert report.is_clean is True


async def test_redact_conversation_rolls_back_parent_and_turns_when_evidence_insert_fails(
    store: ConversationStore, db: AsyncEngine
) -> None:
    """Doctrine Lock D: parent and bulk tombstones share the chain transaction."""
    cid = await _new(store)
    await _append(store, cid, 1, q="first survives", a="first answer survives")
    await _append(store, cid, 2, q="second survives", a="second answer survives")
    chain_before = await _decision_chain_state(db)
    await _refuse_erasure_evidence_inserts(db)

    with pytest.raises(sa.exc.DBAPIError, match=r"forced conversation\.erased insert failure"):
        await store.redact_conversation(
            conversation_id=cid,
            tenant_id="t1",
            actor_id="compliance-officer",
            request_id="req-redact-conversation-forced-chain-failure",
        )

    async with db.connect() as conn:
        parent = (
            await conn.execute(
                sa.select(_conversations.c.state, _conversations.c.erased_at).where(
                    _conversations.c.conversation_id == cid
                )
            )
        ).one()
        turns = (
            await conn.execute(
                sa.select(
                    _conversation_turns.c.seq,
                    _conversation_turns.c.user_message,
                    _conversation_turns.c.answer,
                    _conversation_turns.c.erased_at,
                )
                .where(_conversation_turns.c.conversation_id == cid)
                .order_by(_conversation_turns.c.seq)
            )
        ).all()
    assert tuple(parent) == ("active", None)
    assert [tuple(row) for row in turns] == [
        (1, "first survives", "first answer survives", None),
        (2, "second survives", "second answer survives", None),
    ]
    assert await _decision_chain_state(db) == chain_before
    assert not [
        event for event in await _chain_rows(db) if event.event_type == "conversation.erased"
    ]


async def test_redact_conversation_is_idempotent_and_cross_tenant_safe(
    store: ConversationStore, db: AsyncEngine
) -> None:
    cid = await _new(store, tenant="tenant-a")
    await _append(store, cid, 1, tenant="tenant-a", q="private", a="private")

    assert (
        await store.redact_conversation(
            conversation_id=cid,
            tenant_id="tenant-b",
            actor_id="compliance-officer",
            request_id="req-wrong-tenant",
        )
        is False
    )
    assert await store.redact_conversation(
        conversation_id=cid,
        tenant_id="tenant-a",
        actor_id="compliance-officer",
        request_id="req-right-tenant",
    )
    assert (
        await store.redact_conversation(
            conversation_id=cid,
            tenant_id="tenant-a",
            actor_id="compliance-officer",
            request_id="req-repeat",
        )
        is False
    )
    erased = [row for row in await _chain_rows(db) if row.event_type == "conversation.erased"]
    assert len(erased) == 1
    assert erased[0].request_id == "req-right-tenant"


async def test_redact_conversation_fences_an_admitted_turn_from_resurrection(
    store: ConversationStore,
) -> None:
    cid = await _new(store)
    claim = await _claim(store, cid)

    assert await store.redact_conversation(
        conversation_id=cid,
        tenant_id="t1",
        actor_id="compliance-officer",
        request_id="req-redact-during-turn",
    )
    with pytest.raises(ConversationTurnRefused) as exc:
        await store.append_turn(
            conversation_id=cid,
            tenant_id="t1",
            seq=1,
            user_message="must not resurrect",
            answer="must not land",
            agent_run_id="agent-run-late",
            prompt_tokens=1,
            completion_tokens=1,
            actor_id="s1",
            request_id="req-late-turn",
            claim_id=claim.claim_id,
        )
    assert exc.value.reason == "conversation_not_active"
    assert exc.value.current_state == "erased"


async def test_redact_conversation_erases_system_turn_values_uniformly(
    store: ConversationStore, db: AsyncEngine
) -> None:
    """Erasure is shape-based, never conditional on the kind of turn."""
    cid = await _new(store)
    claim = await store.claim_system_turn(
        cid,
        tenant_id="t1",
        now=datetime.now(UTC),
        claim_ttl_s=300.0,
    )
    await store.append_system_turn(
        conversation_id=cid,
        tenant_id="t1",
        text="kernel-authored sensitive value",
        approval_request_id="a1b2c3d4-1111-4222-8333-444455556666",
        actor_id="system:approval-executor",
        request_id="req-system-before-redaction",
        claim_id=claim.claim_id,
    )
    await store.release_claim(cid, tenant_id="t1", claim_id=claim.claim_id)

    assert await store.redact_conversation(
        conversation_id=cid,
        tenant_id="t1",
        actor_id="compliance-officer",
        request_id="req-redact-system-turn",
    )

    async with db.connect() as conn:
        row = (
            await conn.execute(
                sa.select(
                    _conversation_turns.c.turn_kind,
                    _conversation_turns.c.user_message,
                    _conversation_turns.c.answer,
                    _conversation_turns.c.erased_at,
                ).where(_conversation_turns.c.conversation_id == cid)
            )
        ).one()
    assert row.turn_kind == "system"
    assert row.user_message is None
    assert row.answer is None
    assert row.erased_at is not None
