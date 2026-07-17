"""ADR-028 M8.5-B — ConversationReadModel over the ALEMBIC-MIGRATED sqlite DB
(the house rule: create_all omits migration-only constraints; the read model's
guarantees lean on the 0016 unique constraint + indexes).

Evidence is seeded through the REAL ``ConversationStore`` +
``DecisionHistoryStore`` with payload shapes mirroring ``core/agent/loop.py``
and ``core/agent/dispatch.py`` — corruption cases then tamper the migrated
rows directly (the chain is append-only in production; tests simulate the
defect classes the integrity doctrine refuses).
"""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from alembic import command
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.conversation.read_model import (
    PAGE_LIMIT_DEFAULT,
    PAGE_LIMIT_MAX,
    ConversationChainIntegrityError,
    ConversationChainProjectionLimit,
    ConversationReadModel,
    ConversationTranscriptIntegrityError,
    CursorInvalid,
    TurnNotFound,
    _build_chain_row_stmt,
    _build_dispatch_window_stmt,
    _build_list_stmt,
    _build_transcript_stmt,
    _encode_cursor,
)
from cognic_agentos.core.conversation.storage import (
    ConversationStore,
    _conversation_turns,
    _conversations,
)
from cognic_agentos.core.decision_history import (
    DecisionHistoryStore,
    DecisionRecord,
    _decision_history,
)
from cognic_agentos.db.migrations.alembic_config import make_alembic_config

pytestmark = pytest.mark.asyncio

_TENANT = "t1"
_CREATOR = "analyst.amir"
_AGENT = "bank-analyst"


@pytest.fixture
async def db(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    url = f"sqlite+aiosqlite:///{tmp_path / 'rm.db'}"
    await asyncio.to_thread(command.upgrade, make_alembic_config(url), "head")
    # The MIGRATED schema seeds the governance_chain_heads rows itself
    # (unlike metadata.create_all — the storage-test fixtures seed manually).
    eng = create_async_engine(url)
    yield eng
    await eng.dispose()


@pytest.fixture
async def store(db: AsyncEngine) -> ConversationStore:
    return ConversationStore(db)


@pytest.fixture
async def history(db: AsyncEngine) -> DecisionHistoryStore:
    return DecisionHistoryStore(db)


@pytest.fixture
async def reader(db: AsyncEngine) -> ConversationReadModel:
    return ConversationReadModel(db, chain_candidate_limit=10_000)


async def _new_conversation(
    store: ConversationStore,
    *,
    tenant: str = _TENANT,
    creator: str = _CREATOR,
    agent: str = _AGENT,
) -> uuid.UUID:
    cid = uuid.uuid4()
    await store.create_conversation(
        conversation_id=cid,
        tenant_id=tenant,
        agent_id=agent,
        creator_subject=creator,
        request_id=f"conv-create-{uuid.uuid4().hex}",
    )
    return cid


def _started_payload(
    run_id: str,
    *,
    creator: str = _CREATOR,
    agent: str = _AGENT,
    question_sha256: str = "a" * 64,
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "agent_id": agent,
        "actor_id": creator,
        "originator_subject": creator,
        "question_sha256": question_sha256,
        "question_bytes": 10,
        "max_steps": 6,
        "token_budget": 60_000,
        "wall_clock_s": 300.0,
        "prior_context_turns": 0,
        "prior_context_sha256": "b" * 64,
    }


def _dispatch_payload(
    run_id: str,
    *,
    step_index: int = 0,
    outcome: str = "ok",
    refusal_reason: str | None = None,
    scope_id: str | None = "retail_analytics",
    creator: str = _CREATOR,
    agent: str = _AGENT,
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "agent_id": agent,
        "actor_id": creator,
        "originator_subject": creator,
        "capability_kind": "tool",
        "capability_ref": "cognic-tool-oracle-schema/run_readonly_query",
        "scope_id": scope_id,
        "outcome": outcome,
        "refusal_reason": refusal_reason,
        "step_index": step_index,
        "args_sha256": "c" * 64,
        "result_sha256": "d" * 64 if outcome == "ok" else None,
        "result_bytes": 128 if outcome == "ok" else None,
    }


def _terminal_payload(
    run_id: str,
    *,
    state: str = "completed",
    creator: str = _CREATOR,
    agent: str = _AGENT,
    answer_sha256: str = "e" * 64,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "run_id": run_id,
        "agent_id": agent,
        "actor_id": creator,
        "originator_subject": creator,
        "answer_sha256": answer_sha256,
        "answer_bytes": 42,
        "steps_used": 1,
        "prompt_tokens_total": 100,
        "completion_tokens_total": 20,
    }
    if state == "refused":
        payload["refusal_reason"] = "agent_max_steps_exceeded"
        payload["bound"] = "token_budget"
    elif state == "failed":
        payload["error_class"] = "HTTPStatusError"
    return payload


async def _append_run_rows(
    history: DecisionHistoryStore,
    run_id: str,
    *,
    dispatches: int = 1,
    terminal_state: str = "completed",
    tenant: str = _TENANT,
    creator: str = _CREATOR,
    agent: str = _AGENT,
    question_sha256: str = "a" * 64,
    answer_sha256: str = "e" * 64,
) -> None:
    """Realistic agent.run.% evidence in chain order: started -> dispatches ->
    terminal (mirrors the loop's request-id + payload contracts)."""
    await history.append(
        DecisionRecord(
            decision_type="agent.run.started",
            request_id=f"{run_id}-started",
            payload=_started_payload(
                run_id, creator=creator, agent=agent, question_sha256=question_sha256
            ),
            actor_id=creator,
            tenant_id=tenant,
            iso_controls=("A.6.2.4",),
        )
    )
    for n in range(dispatches):
        await history.append(
            DecisionRecord(
                decision_type="agent.run.dispatch",
                request_id=f"agent-dispatch-{uuid.uuid4().hex}",
                payload=_dispatch_payload(run_id, step_index=n, creator=creator, agent=agent),
                actor_id=creator,
                tenant_id=tenant,
                iso_controls=("A.6.2.4",),
            )
        )
    await history.append(
        DecisionRecord(
            decision_type=f"agent.run.{terminal_state}",
            request_id=f"{run_id}-terminal",
            payload=_terminal_payload(
                run_id,
                state=terminal_state,
                creator=creator,
                agent=agent,
                answer_sha256=answer_sha256,
            ),
            actor_id=creator,
            tenant_id=tenant,
            iso_controls=("A.6.2.4",),
        )
    )


async def _append_turn(
    store: ConversationStore,
    cid: uuid.UUID,
    seq: int,
    *,
    run_id: str,
    tenant: str = _TENANT,
    creator: str = _CREATOR,
    approval_request_id: str | None = None,
) -> str:
    """Claim + persist one turn (the executor's flow); returns the minted
    correlation request id."""
    claim = await store.claim_turn(
        cid,
        tenant_id=tenant,
        creator_subject=creator,
        now=datetime.now(UTC),
        claim_ttl_s=600.0,
    )
    rid = f"conv-turn-{uuid.uuid4().hex}"
    await store.append_turn(
        conversation_id=cid,
        tenant_id=tenant,
        seq=seq,
        user_message=f"question {seq}",
        answer=f"answer {seq}",
        agent_run_id=run_id,
        prompt_tokens=100,
        completion_tokens=20,
        actor_id=creator,
        request_id=rid,
        claim_id=claim.claim_id,
        approval_request_id=approval_request_id,
    )
    await store.release_claim(cid, tenant_id=tenant, claim_id=claim.claim_id)
    return rid


async def _drive_turn(
    store: ConversationStore,
    history: DecisionHistoryStore,
    cid: uuid.UUID,
    seq: int,
    *,
    dispatches: int = 1,
    terminal_state: str = "completed",
    tenant: str = _TENANT,
    creator: str = _CREATOR,
    agent: str = _AGENT,
) -> str:
    """One full governed turn: run evidence rows THEN the turn (the
    production ordering). Returns the run id."""
    run_id = f"agent-run-{uuid.uuid4().hex}"
    await _append_run_rows(
        history,
        run_id,
        dispatches=dispatches,
        terminal_state=terminal_state,
        tenant=tenant,
        creator=creator,
        agent=agent,
        # The coupled writer contract: the started row digests the SAME
        # question and the terminal row the SAME answer the turn row stores.
        question_sha256=hashlib.sha256(f"question {seq}".encode()).hexdigest(),
        answer_sha256=hashlib.sha256(f"answer {seq}".encode()).hexdigest(),
    )
    await _append_turn(store, cid, seq, run_id=run_id, tenant=tenant, creator=creator)
    return run_id


# ---------------------------------------------------------------------------
# Isolation: absent / cross-tenant / cross-actor all read as None
# ---------------------------------------------------------------------------


async def test_transcript_isolation_triple_reads_none(
    store: ConversationStore, history: DecisionHistoryStore, reader: ConversationReadModel
) -> None:
    cid = await _new_conversation(store)
    await _drive_turn(store, history, cid, 1)
    assert (
        await reader.read_transcript(uuid.uuid4(), tenant_id=_TENANT, creator_subject=_CREATOR)
        is None
    )  # absent
    assert (
        await reader.read_transcript(cid, tenant_id="t-other", creator_subject=_CREATOR) is None
    )  # cross-tenant
    assert (
        await reader.read_transcript(cid, tenant_id=_TENANT, creator_subject="analyst.sara") is None
    )  # cross-actor


async def test_transcript_surfaces_pending_approval_request_id(
    store: ConversationStore,
    reader: ConversationReadModel,
) -> None:
    cid = await _new_conversation(store)
    approval_id = "a1b2c3d4-1111-4222-8333-444455556666"
    await _append_turn(
        store,
        cid,
        1,
        run_id="agent-run-pending",
        approval_request_id=approval_id,
    )

    page = await reader.read_transcript(
        cid,
        tenant_id=_TENANT,
        creator_subject=_CREATOR,
    )

    assert page is not None
    assert page.turns[0].approval_request_id == approval_id


async def test_chain_isolation_triple_reads_none(
    store: ConversationStore, history: DecisionHistoryStore, reader: ConversationReadModel
) -> None:
    cid = await _new_conversation(store)
    await _drive_turn(store, history, cid, 1)
    assert (
        await reader.read_turn_chain(uuid.uuid4(), 1, tenant_id=_TENANT, creator_subject=_CREATOR)
        is None
    )
    assert (
        await reader.read_turn_chain(cid, 1, tenant_id="t-other", creator_subject=_CREATOR) is None
    )
    assert (
        await reader.read_turn_chain(cid, 1, tenant_id=_TENANT, creator_subject="analyst.sara")
        is None
    )


async def test_list_returns_only_the_callers_rows(
    store: ConversationStore, reader: ConversationReadModel
) -> None:
    mine = await _new_conversation(store)
    await _new_conversation(store, creator="analyst.sara")  # same tenant, other actor
    await _new_conversation(store, tenant="t-other")  # other tenant
    page = await reader.list_conversations(tenant_id=_TENANT, creator_subject=_CREATOR)
    assert [c.conversation_id for c in page.items] == [mine]
    assert page.next_cursor is None


# ---------------------------------------------------------------------------
# List: recent-first keyset, tiebreak, filter binding, clamps, cursor matrix
# ---------------------------------------------------------------------------


async def test_list_orders_recent_first_and_paginates_with_cursor(
    store: ConversationStore, reader: ConversationReadModel, db: AsyncEngine
) -> None:
    cids = [await _new_conversation(store) for _ in range(3)]
    # Force strictly increasing created_at so the order is deterministic.
    async with db.begin() as conn:
        for i, cid in enumerate(cids):
            await conn.execute(
                sa.update(_conversations)
                .where(_conversations.c.conversation_id == cid)
                .values(created_at=datetime(2026, 7, 10, 12, 0, i, tzinfo=UTC))
            )
    page1 = await reader.list_conversations(tenant_id=_TENANT, creator_subject=_CREATOR, limit=2)
    assert [c.conversation_id for c in page1.items] == [cids[2], cids[1]]
    assert page1.next_cursor is not None
    page2 = await reader.list_conversations(
        tenant_id=_TENANT, creator_subject=_CREATOR, limit=2, cursor=page1.next_cursor
    )
    assert [c.conversation_id for c in page2.items] == [cids[0]]
    assert page2.next_cursor is None  # exact fit -> no probe row -> no cursor


async def test_list_tiebreaks_equal_created_at_by_conversation_id_desc(
    store: ConversationStore, reader: ConversationReadModel, db: AsyncEngine
) -> None:
    cids = [await _new_conversation(store) for _ in range(3)]
    same = datetime(2026, 7, 10, 12, 0, 0, tzinfo=UTC)
    async with db.begin() as conn:
        await conn.execute(sa.update(_conversations).values(created_at=same))
    page1 = await reader.list_conversations(tenant_id=_TENANT, creator_subject=_CREATOR, limit=2)
    expected = sorted(cids, key=lambda c: str(c), reverse=True)
    assert [c.conversation_id for c in page1.items] == expected[:2]
    page2 = await reader.list_conversations(
        tenant_id=_TENANT, creator_subject=_CREATOR, limit=2, cursor=page1.next_cursor
    )
    assert [c.conversation_id for c in page2.items] == expected[2:]


async def test_list_state_filter_binds_into_the_cursor(
    store: ConversationStore, reader: ConversationReadModel
) -> None:
    open_cids = [await _new_conversation(store) for _ in range(2)]
    closed_cid = await _new_conversation(store)
    await store.transition(
        conversation_id=closed_cid,
        tenant_id=_TENANT,
        to_state="closed",
        actor_id=_CREATOR,
        request_id="req-close",
    )
    page = await reader.list_conversations(
        tenant_id=_TENANT, creator_subject=_CREATOR, state="active", limit=1
    )
    assert all(c.state == "active" for c in page.items)
    assert page.next_cursor is not None
    # Continuation with a DIFFERENT state param: mismatched cursor.
    with pytest.raises(CursorInvalid, match="state filter"):
        await reader.list_conversations(
            tenant_id=_TENANT,
            creator_subject=_CREATOR,
            state="closed",
            cursor=page.next_cursor,
        )
    # Continuation with the SAME param (or none): the cursor's filter rules.
    page2 = await reader.list_conversations(
        tenant_id=_TENANT, creator_subject=_CREATOR, cursor=page.next_cursor
    )
    returned = {c.conversation_id for c in page.items} | {c.conversation_id for c in page2.items}
    assert returned == set(open_cids)
    assert closed_cid not in returned


async def test_list_limit_clamps(store: ConversationStore, reader: ConversationReadModel) -> None:
    await _new_conversation(store)
    await _new_conversation(store)
    page = await reader.list_conversations(tenant_id=_TENANT, creator_subject=_CREATOR, limit=0)
    assert len(page.items) == 1  # clamped up to 1
    assert PAGE_LIMIT_DEFAULT == 50 and PAGE_LIMIT_MAX == 200  # vocabulary pin


@pytest.mark.parametrize(
    "cursor",
    [
        "not-base64!!!",
        _encode_cursor({"v": 99, "created_at": "2026-07-10T00:00:00+00:00"}),
        _encode_cursor({"v": 1, "created_at": 123, "conversation_id": "x"}),
        _encode_cursor({"v": 1, "created_at": "nope", "conversation_id": str(uuid.uuid4())}),
        _encode_cursor(
            {
                "v": 1,
                "created_at": "2026-07-10T00:00:00+00:00",
                "conversation_id": str(uuid.uuid4()),
                "state": "bogus",
            }
        ),
    ],
    ids=["malformed-encoding", "wrong-version", "invalid-types", "bad-timestamp", "bad-state"],
)
async def test_list_cursor_invalid_matrix(reader: ConversationReadModel, cursor: str) -> None:
    with pytest.raises(CursorInvalid):
        await reader.list_conversations(tenant_id=_TENANT, creator_subject=_CREATOR, cursor=cursor)


async def test_list_cursor_rejects_trailing_garbage_on_a_valid_cursor(
    store: ConversationStore, reader: ConversationReadModel
) -> None:
    """finding 5 (2026-07-10): ``urlsafe_b64decode`` silently DISCARDS
    non-alphabet bytes, so ``<valid-cursor>!!!`` decoded to the untampered
    payload and was accepted. Strict validation refuses it."""
    await _new_conversation(store)
    await _new_conversation(store)
    page = await reader.list_conversations(tenant_id=_TENANT, creator_subject=_CREATOR, limit=1)
    assert page.next_cursor is not None
    with pytest.raises(CursorInvalid, match="base64url"):
        await reader.list_conversations(
            tenant_id=_TENANT, creator_subject=_CREATOR, cursor=page.next_cursor + "!!!"
        )


async def test_cursor_version_true_is_not_version_1(reader: ConversationReadModel) -> None:
    """finding 5: JSON ``true == 1`` in Python — a bool must not impersonate
    the integer cursor version."""
    cursor = _encode_cursor(
        {
            "v": True,
            "created_at": "2026-07-10T00:00:00+00:00",
            "conversation_id": str(uuid.uuid4()),
            "state": None,
        }
    )
    with pytest.raises(CursorInvalid, match="version"):
        await reader.list_conversations(tenant_id=_TENANT, creator_subject=_CREATOR, cursor=cursor)


async def test_mint_aware_utc_normalizes_naive_and_passes_aware_through() -> None:
    """Both arms of the mint normalization (the aware arm is unreachable on
    sqlite, whose driver always returns naive): a naive instant gains UTC
    unchanged; an aware instant passes through IDENTICALLY."""
    from cognic_agentos.core.conversation.read_model import _mint_aware_utc

    naive = datetime(2026, 7, 10, 12, 0, 0)
    normalized = _mint_aware_utc(naive)
    assert normalized.tzinfo is UTC
    assert normalized.replace(tzinfo=None) == naive
    aware = datetime(2026, 7, 10, 12, 0, 0, tzinfo=UTC)
    assert _mint_aware_utc(aware) is aware


async def test_list_cursor_naive_timestamp_refused(reader: ConversationReadModel) -> None:
    """finding 5: a naive keyset timestamp compared against the tz-aware
    column is a dialect-level 500, not a governed 422 — refuse at decode."""
    cursor = _encode_cursor(
        {
            "v": 1,
            "created_at": "2026-07-10T00:00:00",
            "conversation_id": str(uuid.uuid4()),
            "state": None,
        }
    )
    with pytest.raises(CursorInvalid, match="timezone-aware"):
        await reader.list_conversations(tenant_id=_TENANT, creator_subject=_CREATOR, cursor=cursor)


# ---------------------------------------------------------------------------
# Transcript: watermark snapshot, pagination, contiguity, erasure shape
# ---------------------------------------------------------------------------


async def test_transcript_returns_turns_in_order_with_plaintext(
    store: ConversationStore, history: DecisionHistoryStore, reader: ConversationReadModel
) -> None:
    cid = await _new_conversation(store)
    await _drive_turn(store, history, cid, 1)
    await _drive_turn(store, history, cid, 2)
    page = await reader.read_transcript(cid, tenant_id=_TENANT, creator_subject=_CREATOR)
    assert page is not None
    assert [t.seq for t in page.turns] == [1, 2]
    assert page.turns[0].user_message == "question 1"
    assert page.turns[0].answer == "answer 1"
    assert page.turns[0].erased_at is None
    assert page.watermark == 2
    assert page.next_cursor is None
    assert page.conversation.turn_count == 2


async def test_transcript_watermark_freezes_the_snapshot_across_pages(
    store: ConversationStore, history: DecisionHistoryStore, reader: ConversationReadModel
) -> None:
    cid = await _new_conversation(store)
    await _drive_turn(store, history, cid, 1)
    await _drive_turn(store, history, cid, 2)
    page1 = await reader.read_transcript(cid, tenant_id=_TENANT, creator_subject=_CREATOR, limit=1)
    assert page1 is not None and page1.next_cursor is not None
    assert [t.seq for t in page1.turns] == [1]
    # A turn appended MID-PAGINATION must not appear in the continuation.
    await _drive_turn(store, history, cid, 3)
    page2 = await reader.read_transcript(
        cid, tenant_id=_TENANT, creator_subject=_CREATOR, limit=5, cursor=page1.next_cursor
    )
    assert page2 is not None
    assert [t.seq for t in page2.turns] == [2]  # the watermark-frozen tail
    assert page2.next_cursor is None
    # A FRESH read sees all three.
    fresh = await reader.read_transcript(cid, tenant_id=_TENANT, creator_subject=_CREATOR)
    assert fresh is not None and [t.seq for t in fresh.turns] == [1, 2, 3]


async def test_empty_conversation_mints_no_cursor(
    store: ConversationStore, reader: ConversationReadModel
) -> None:
    cid = await _new_conversation(store)
    page = await reader.read_transcript(cid, tenant_id=_TENANT, creator_subject=_CREATOR)
    assert page is not None
    assert page.turns == ()
    assert page.watermark == 0
    assert page.next_cursor is None


async def test_transcript_surfaces_the_erasure_shape(
    store: ConversationStore,
    history: DecisionHistoryStore,
    reader: ConversationReadModel,
    db: AsyncEngine,
) -> None:
    """Nullable plaintext + erased_at IS the M8.5-F erasure shape; the read
    model surfaces it honestly (no store-level erase API exists yet — the
    schema contract is simulated directly)."""
    cid = await _new_conversation(store)
    await _drive_turn(store, history, cid, 1)
    erased_when = datetime(2026, 7, 10, 13, 0, 0, tzinfo=UTC)
    async with db.begin() as conn:
        await conn.execute(
            sa.update(_conversation_turns)
            .where(_conversation_turns.c.conversation_id == cid)
            .values(user_message=None, answer=None, erased_at=erased_when)
        )
    page = await reader.read_transcript(cid, tenant_id=_TENANT, creator_subject=_CREATOR)
    assert page is not None
    turn = page.turns[0]
    assert turn.user_message is None and turn.answer is None
    assert turn.erased_at is not None


async def test_transcript_gap_is_integrity_failure(
    store: ConversationStore,
    history: DecisionHistoryStore,
    reader: ConversationReadModel,
    db: AsyncEngine,
) -> None:
    cid = await _new_conversation(store)
    for seq in (1, 2, 3):
        await _drive_turn(store, history, cid, seq)
    async with db.begin() as conn:  # corrupt: hole in the middle
        await conn.execute(
            sa.delete(_conversation_turns).where(
                _conversation_turns.c.conversation_id == cid,
                _conversation_turns.c.seq == 2,
            )
        )
    with pytest.raises(ConversationTranscriptIntegrityError, match="gap inside"):
        await reader.read_transcript(cid, tenant_id=_TENANT, creator_subject=_CREATOR)


async def test_transcript_gap_visible_in_the_probe_fails_immediately(
    store: ConversationStore,
    history: DecisionHistoryStore,
    reader: ConversationReadModel,
    db: AsyncEngine,
) -> None:
    """finding 4a (2026-07-10): stored seqs (1, 3) with limit=1 — the gap is
    already visible in the limit+1 PROBE row, so page one must fail NOW
    rather than hand out a cursor into corruption (the old check validated
    only the returned page and deferred detection to page two)."""
    cid = await _new_conversation(store)
    for seq in (1, 2, 3):
        await _drive_turn(store, history, cid, seq)
    async with db.begin() as conn:
        await conn.execute(
            sa.delete(_conversation_turns).where(
                _conversation_turns.c.conversation_id == cid,
                _conversation_turns.c.seq == 2,
            )
        )
    with pytest.raises(ConversationTranscriptIntegrityError, match="gap inside"):
        await reader.read_transcript(cid, tenant_id=_TENANT, creator_subject=_CREATOR, limit=1)


async def test_transcript_missing_tail_is_integrity_failure(
    store: ConversationStore,
    history: DecisionHistoryStore,
    reader: ConversationReadModel,
    db: AsyncEngine,
) -> None:
    cid = await _new_conversation(store)
    await _drive_turn(store, history, cid, 1)
    await _drive_turn(store, history, cid, 2)
    async with db.begin() as conn:  # corrupt: the tail row is gone
        await conn.execute(
            sa.delete(_conversation_turns).where(
                _conversation_turns.c.conversation_id == cid,
                _conversation_turns.c.seq == 2,
            )
        )
    with pytest.raises(ConversationTranscriptIntegrityError, match="missing tail"):
        await reader.read_transcript(cid, tenant_id=_TENANT, creator_subject=_CREATOR)


async def test_transcript_cursor_invalid_matrix(
    store: ConversationStore, history: DecisionHistoryStore, reader: ConversationReadModel
) -> None:
    cid = await _new_conversation(store)
    await _drive_turn(store, history, cid, 1)
    await _drive_turn(store, history, cid, 2)

    def cur(**kw: object) -> str:
        base: dict[str, object] = {
            "v": 1,
            "conversation_id": str(cid),
            "watermark": 2,
            "after_seq": 1,
        }
        base.update(kw)
        return _encode_cursor(dict(base))

    cases = {
        "cross-conversation": cur(conversation_id=str(uuid.uuid4())),
        "non-uuid-cid": cur(conversation_id="nope"),
        "negative-after-seq": cur(after_seq=-1),
        "after-seq-at-watermark": cur(after_seq=2),
        "zero-watermark": cur(watermark=0, after_seq=0),
        "watermark-above-turn-count": cur(watermark=99, after_seq=1),
        "bool-typed-int": cur(after_seq=True),
        "wrong-version": cur(v=2),
    }
    for _name, cursor in cases.items():
        with pytest.raises(CursorInvalid):
            await reader.read_transcript(
                cid, tenant_id=_TENANT, creator_subject=_CREATOR, cursor=cursor
            )


# ---------------------------------------------------------------------------
# Chain join: the four projections, empty dispatches, window filtering
# ---------------------------------------------------------------------------


async def test_chain_happy_path_projects_all_four_curated_blocks(
    store: ConversationStore, history: DecisionHistoryStore, reader: ConversationReadModel
) -> None:
    cid = await _new_conversation(store)
    run_id = await _drive_turn(store, history, cid, 1, dispatches=2)
    join = await reader.read_turn_chain(cid, 1, tenant_id=_TENANT, creator_subject=_CREATOR)
    assert join is not None
    assert join.turn_completed.agent_run_id == run_id
    assert join.turn_completed.seq == 1
    assert join.turn_completed.actor_id == _CREATOR
    assert join.turn_completed.question_sha256 and join.turn_completed.answer_sha256
    assert join.started.run_id == run_id
    assert join.started.agent_id == _AGENT
    assert join.started.token_budget == 60_000
    assert join.started.wall_clock_s == 300.0
    assert join.started.prior_context_turns == 0
    assert join.terminal.terminal_state == "completed"
    assert join.terminal.refusal_reason is None
    assert [d.step_index for d in join.dispatches] == [0, 1]
    assert join.dispatches[0].outcome == "ok"
    assert join.dispatches[0].scope_id == "retail_analytics"
    # Ordering invariant: started < terminal < turn_completed.
    assert join.started.sequence < join.terminal.sequence < join.turn_completed.sequence


async def test_chain_empty_dispatches_are_valid(
    store: ConversationStore, history: DecisionHistoryStore, reader: ConversationReadModel
) -> None:
    """Run-5 semantics: a context-reuse turn dispatches nothing and that is
    correct behaviour, never an integrity failure."""
    cid = await _new_conversation(store)
    await _drive_turn(store, history, cid, 1, dispatches=0)
    join = await reader.read_turn_chain(cid, 1, tenant_id=_TENANT, creator_subject=_CREATOR)
    assert join is not None
    assert join.dispatches == ()


async def test_chain_excludes_interleaved_concurrent_runs(
    store: ConversationStore,
    history: DecisionHistoryStore,
    reader: ConversationReadModel,
) -> None:
    """Concurrent runs interleave sequences INSIDE the window; foreign
    dispatch rows are expected there and silently excluded by the Python-side
    run_id filter — never projected, never an integrity failure."""
    cid = await _new_conversation(store)
    run_id = f"agent-run-{uuid.uuid4().hex}"
    foreign_run = f"agent-run-{uuid.uuid4().hex}"
    # Coupled digests for the manual seed: _append_turn(seq=1) below stores
    # "question 1"/"answer 1", and the reader enforces started<->turn +
    # terminal<->turn digest equality.
    q_sha = hashlib.sha256(b"question 1").hexdigest()
    a_sha = hashlib.sha256(b"answer 1").hexdigest()
    await history.append(
        DecisionRecord(
            decision_type="agent.run.started",
            request_id=f"{run_id}-started",
            payload=_started_payload(run_id, question_sha256=q_sha),
            actor_id=_CREATOR,
            tenant_id=_TENANT,
            iso_controls=("A.6.2.4",),
        )
    )
    # A FOREIGN run's dispatch lands inside this run's window (same tenant).
    await history.append(
        DecisionRecord(
            decision_type="agent.run.dispatch",
            request_id=f"agent-dispatch-{uuid.uuid4().hex}",
            payload=_dispatch_payload(foreign_run),
            actor_id=_CREATOR,
            tenant_id=_TENANT,
            iso_controls=("A.6.2.4",),
        )
    )
    await history.append(
        DecisionRecord(
            decision_type="agent.run.dispatch",
            request_id=f"agent-dispatch-{uuid.uuid4().hex}",
            payload=_dispatch_payload(run_id),
            actor_id=_CREATOR,
            tenant_id=_TENANT,
            iso_controls=("A.6.2.4",),
        )
    )
    await history.append(
        DecisionRecord(
            decision_type="agent.run.completed",
            request_id=f"{run_id}-terminal",
            payload=_terminal_payload(run_id, answer_sha256=a_sha),
            actor_id=_CREATOR,
            tenant_id=_TENANT,
            iso_controls=("A.6.2.4",),
        )
    )
    await _append_turn(store, cid, 1, run_id=run_id)
    join = await reader.read_turn_chain(cid, 1, tenant_id=_TENANT, creator_subject=_CREATOR)
    assert join is not None
    assert len(join.dispatches) == 1  # the foreign row is filtered, not fatal


async def test_chain_terminal_refused_and_failed_projections(
    store: ConversationStore, history: DecisionHistoryStore, reader: ConversationReadModel
) -> None:
    cid = await _new_conversation(store)
    await _drive_turn(store, history, cid, 1, terminal_state="refused", dispatches=0)
    await _drive_turn(store, history, cid, 2, terminal_state="failed", dispatches=0)
    refused = await reader.read_turn_chain(cid, 1, tenant_id=_TENANT, creator_subject=_CREATOR)
    failed = await reader.read_turn_chain(cid, 2, tenant_id=_TENANT, creator_subject=_CREATOR)
    assert refused is not None and failed is not None
    assert refused.terminal.terminal_state == "refused"
    assert refused.terminal.refusal_reason == "agent_max_steps_exceeded"
    assert refused.terminal.bound == "token_budget"
    assert failed.terminal.terminal_state == "failed"
    assert failed.terminal.error_class == "HTTPStatusError"


async def test_chain_turn_not_found_for_out_of_range_seq(
    store: ConversationStore, history: DecisionHistoryStore, reader: ConversationReadModel
) -> None:
    cid = await _new_conversation(store)
    await _drive_turn(store, history, cid, 1)
    for seq in (0, 2, 99):
        with pytest.raises(TurnNotFound):
            await reader.read_turn_chain(cid, seq, tenant_id=_TENANT, creator_subject=_CREATOR)


# ---------------------------------------------------------------------------
# Chain integrity — corruption classes (each generic on the wire, internal
# reason for the operator log) + the DISTINCT projection limit
# ---------------------------------------------------------------------------


async def _corrupt(
    db: AsyncEngine, *, where: Any, values: dict[str, Any] | None = None, delete: bool = False
) -> None:
    async with db.begin() as conn:
        if delete:
            await conn.execute(sa.delete(_decision_history).where(where))
        else:
            assert values is not None
            await conn.execute(sa.update(_decision_history).where(where).values(**values))


async def _seeded_join(
    store: ConversationStore, history: DecisionHistoryStore
) -> tuple[uuid.UUID, str]:
    cid = await _new_conversation(store)
    run_id = await _drive_turn(store, history, cid, 1)
    return cid, run_id


async def test_chain_integrity_hop1_missing(
    store: ConversationStore,
    history: DecisionHistoryStore,
    reader: ConversationReadModel,
    db: AsyncEngine,
) -> None:
    cid, _run = await _seeded_join(store, history)
    await _corrupt(
        db, where=_decision_history.c.event_type == "conversation.turn_completed", delete=True
    )
    with pytest.raises(ConversationChainIntegrityError) as exc:
        await reader.read_turn_chain(cid, 1, tenant_id=_TENANT, creator_subject=_CREATOR)
    assert exc.value.internal_reason == "hop1_missing"


async def test_chain_integrity_hop1_duplicated(
    store: ConversationStore,
    history: DecisionHistoryStore,
    reader: ConversationReadModel,
    db: AsyncEngine,
) -> None:
    cid, _run = await _seeded_join(store, history)
    async with db.connect() as conn:
        rid = (
            await conn.execute(
                sa.select(_conversation_turns.c.turn_completed_request_id).where(
                    _conversation_turns.c.conversation_id == cid
                )
            )
        ).scalar_one()
    # A second chain row under the SAME correlation id (request_id carries no
    # unique constraint on decision_history).
    await history.append(
        DecisionRecord(
            decision_type="conversation.turn_completed",
            request_id=rid,
            payload={"conversation_id": str(cid)},
            actor_id=_CREATOR,
            tenant_id=_TENANT,
            iso_controls=("A.6.2.4",),
        )
    )
    with pytest.raises(ConversationChainIntegrityError) as exc:
        await reader.read_turn_chain(cid, 1, tenant_id=_TENANT, creator_subject=_CREATOR)
    assert exc.value.internal_reason == "hop1_duplicated"


async def test_chain_integrity_hop1_mismatch(
    store: ConversationStore,
    history: DecisionHistoryStore,
    reader: ConversationReadModel,
    db: AsyncEngine,
) -> None:
    cid, _run = await _seeded_join(store, history)
    async with db.connect() as conn:
        row = (
            (
                await conn.execute(
                    sa.select(_decision_history).where(
                        _decision_history.c.event_type == "conversation.turn_completed"
                    )
                )
            )
            .mappings()
            .one()
        )
    tampered = dict(row["payload"])
    tampered["seq"] = 99
    await _corrupt(
        db,
        where=_decision_history.c.record_id == row["record_id"],
        values={"payload": tampered},
    )
    with pytest.raises(ConversationChainIntegrityError) as exc:
        await reader.read_turn_chain(cid, 1, tenant_id=_TENANT, creator_subject=_CREATOR)
    assert exc.value.internal_reason == "hop1_mismatch"


@pytest.mark.parametrize("anchor", ["started", "terminal"])
async def test_chain_integrity_anchor_missing_and_duplicated(
    store: ConversationStore,
    history: DecisionHistoryStore,
    reader: ConversationReadModel,
    db: AsyncEngine,
    anchor: str,
) -> None:
    cid, run_id = await _seeded_join(store, history)
    rid = f"{run_id}-{anchor}"
    # duplicated first (append a second row under the anchor request id)
    await history.append(
        DecisionRecord(
            decision_type="agent.run.started" if anchor == "started" else "agent.run.completed",
            request_id=rid,
            payload={"run_id": run_id},
            actor_id=_CREATOR,
            tenant_id=_TENANT,
            iso_controls=("A.6.2.4",),
        )
    )
    with pytest.raises(ConversationChainIntegrityError) as exc:
        await reader.read_turn_chain(cid, 1, tenant_id=_TENANT, creator_subject=_CREATOR)
    assert exc.value.internal_reason == "anchor_duplicated"
    # then missing (delete both copies)
    await _corrupt(db, where=_decision_history.c.request_id == rid, delete=True)
    with pytest.raises(ConversationChainIntegrityError) as exc2:
        await reader.read_turn_chain(cid, 1, tenant_id=_TENANT, creator_subject=_CREATOR)
    assert exc2.value.internal_reason == "anchor_missing"


async def test_chain_integrity_dual_identity_mismatch_on_run_rows(
    store: ConversationStore,
    history: DecisionHistoryStore,
    reader: ConversationReadModel,
    db: AsyncEngine,
) -> None:
    """Event-specific identity (precision lock): run rows validate run_id,
    agent_id AND originator_subject against the conversation."""
    cid, run_id = await _seeded_join(store, history)
    async with db.connect() as conn:
        row = (
            (
                await conn.execute(
                    sa.select(_decision_history).where(
                        _decision_history.c.request_id == f"{run_id}-started"
                    )
                )
            )
            .mappings()
            .one()
        )
    tampered = dict(row["payload"])
    tampered["agent_id"] = "some-other-agent"
    await _corrupt(
        db,
        where=_decision_history.c.record_id == row["record_id"],
        values={"payload": tampered},
    )
    with pytest.raises(ConversationChainIntegrityError) as exc:
        await reader.read_turn_chain(cid, 1, tenant_id=_TENANT, creator_subject=_CREATOR)
    assert exc.value.internal_reason == "dual_identity_mismatch"


async def test_chain_integrity_anchor_malformed_payload(
    store: ConversationStore,
    history: DecisionHistoryStore,
    reader: ConversationReadModel,
    db: AsyncEngine,
) -> None:
    cid, run_id = await _seeded_join(store, history)
    async with db.connect() as conn:
        row = (
            (
                await conn.execute(
                    sa.select(_decision_history).where(
                        _decision_history.c.request_id == f"{run_id}-terminal"
                    )
                )
            )
            .mappings()
            .one()
        )
    tampered = dict(row["payload"])
    tampered["steps_used"] = "not-an-int"
    await _corrupt(
        db,
        where=_decision_history.c.record_id == row["record_id"],
        values={"payload": tampered},
    )
    with pytest.raises(ConversationChainIntegrityError) as exc:
        await reader.read_turn_chain(cid, 1, tenant_id=_TENANT, creator_subject=_CREATOR)
    assert exc.value.internal_reason == "anchor_malformed"


async def test_chain_integrity_misordered_anchors(
    store: ConversationStore,
    history: DecisionHistoryStore,
    reader: ConversationReadModel,
    db: AsyncEngine,
) -> None:
    """started.sequence < terminal.sequence < turn_completed.sequence is the
    production ordering; a violation is corruption. Simulated by swapping the
    two anchors' sequences through a temporary value (sequence is UNIQUE)."""
    cid, run_id = await _seeded_join(store, history)
    async with db.connect() as conn:
        rows = {
            r["request_id"]: r
            for r in (
                await conn.execute(
                    sa.select(_decision_history).where(
                        _decision_history.c.request_id.in_(
                            [f"{run_id}-started", f"{run_id}-terminal"]
                        )
                    )
                )
            ).mappings()
        }
    started, terminal = rows[f"{run_id}-started"], rows[f"{run_id}-terminal"]
    s_seq, t_seq = started["sequence"], terminal["sequence"]
    async with db.begin() as conn:
        await conn.execute(
            sa.update(_decision_history)
            .where(_decision_history.c.record_id == started["record_id"])
            .values(sequence=999_999)
        )
        await conn.execute(
            sa.update(_decision_history)
            .where(_decision_history.c.record_id == terminal["record_id"])
            .values(sequence=s_seq)
        )
        await conn.execute(
            sa.update(_decision_history)
            .where(_decision_history.c.record_id == started["record_id"])
            .values(sequence=t_seq)
        )
    with pytest.raises(ConversationChainIntegrityError) as exc:
        await reader.read_turn_chain(cid, 1, tenant_id=_TENANT, creator_subject=_CREATOR)
    assert exc.value.internal_reason == "anchor_misordered"


async def test_chain_projection_limit_is_distinct_from_corruption(
    store: ConversationStore, history: DecisionHistoryStore, db: AsyncEngine
) -> None:
    """Exceeding the configured candidate cap is an OPERATIONAL condition
    (raise the limit or remediate), raised as the DISTINCT projection-limit
    error — never masqueraded as chain corruption."""
    cid = await _new_conversation(store)
    run_id = await _drive_turn(store, history, cid, 1, dispatches=3)
    tight = ConversationReadModel(db, chain_candidate_limit=2)
    with pytest.raises(ConversationChainProjectionLimit):
        await tight.read_turn_chain(cid, 1, tenant_id=_TENANT, creator_subject=_CREATOR)
    assert run_id  # the seeded run stays valid under the default-cap reader


async def test_reader_refuses_a_non_positive_candidate_limit(tmp_path: Path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'x.db'}")
    with pytest.raises(ValueError, match="chain_candidate_limit"):
        ConversationReadModel(engine, chain_candidate_limit=0)


# ---------------------------------------------------------------------------
# SQL-shape regressions: the compiled statements ride the intended indexes
# (the shared-builder pattern — the packs `_build_list_for_tenant_stmt`
# precedent: the tests compile the SAME builders production executes).
# ---------------------------------------------------------------------------


async def test_list_stmt_compiles_with_the_keyset_index_columns() -> None:
    stmt = _build_list_stmt(
        tenant_id="t",
        creator_subject="s",
        state=None,
        after=_list_cursor_for_shape(),
        limit_plus_one=51,
    )
    sql = str(stmt.compile(compile_kwargs={"literal_binds": False}))
    for needle in (
        "conversations.tenant_id =",
        "conversations.creator_subject =",
        "conversations.created_at <",
        "conversations.conversation_id <",
        "ORDER BY conversations.created_at DESC, conversations.conversation_id DESC",
    ):
        assert needle in sql, f"missing {needle!r} in: {sql}"


def _list_cursor_for_shape() -> Any:
    from cognic_agentos.core.conversation.read_model import _ListCursor

    return _ListCursor(
        created_at=datetime(2026, 7, 10, tzinfo=UTC),
        conversation_id=uuid.uuid4(),
        state=None,
    )


async def test_dispatch_window_stmt_uses_the_composite_index_never_payload() -> None:
    stmt = _build_dispatch_window_stmt(tenant_id="t", seq_start=1, seq_end=9, limit_plus_one=11)
    sql = str(stmt.compile(compile_kwargs={"literal_binds": False}))
    for needle in (
        "decision_history.tenant_id =",
        "decision_history.event_type =",
        "decision_history.sequence >",
        "decision_history.sequence <",
    ):
        assert needle in sql, f"missing {needle!r} in: {sql}"
    # payload is NEVER the access path (Oracle CLOB — no portable index).
    assert "payload" not in sql.split("FROM")[1].split("ORDER BY")[0].replace(
        ", decision_history.payload", ""
    )


async def test_chain_row_stmt_is_an_exact_request_id_lookup() -> None:
    stmt = _build_chain_row_stmt(request_id="agent-run-x-started", tenant_id="t")
    sql = str(stmt.compile(compile_kwargs={"literal_binds": False}))
    assert "decision_history.request_id =" in sql
    assert "decision_history.tenant_id =" in sql
    assert "LIKE" not in sql.upper().split("WHERE")[1]
    # finding 6 (2026-07-10): request_id is NON-unique — without a LIMIT a
    # corrupt duplicate set could consume unbounded memory before the
    # duplicate check. Two rows distinguish missing / unique / duplicated.
    assert "LIMIT" in sql.upper(), sql


async def test_transcript_stmt_is_seq_bounded_and_ordered() -> None:
    stmt = _build_transcript_stmt(
        conversation_id=uuid.uuid4(), after_seq=0, watermark=5, limit_plus_one=6
    )
    sql = str(stmt.compile(compile_kwargs={"literal_binds": False}))
    for needle in (
        "conversation_turns.conversation_id =",
        "conversation_turns.seq >",
        "conversation_turns.seq <=",
        "ORDER BY conversation_turns.seq ASC",
    ):
        assert needle in sql, f"missing {needle!r} in: {sql}"


# ---------------------------------------------------------------------------
# Validator negative arms — driven through the EXACT production methods with
# synthetic rows (the promotion gate found these arms unpinned; each is a
# corruption class that cannot be reached without tampering, so direct-call
# coverage of the production validators is the honest form).
# ---------------------------------------------------------------------------


def _fake_conversation_row(cid: uuid.UUID) -> dict[str, Any]:
    return {"conversation_id": cid, "agent_id": _AGENT, "creator_subject": _CREATOR}


def _fake_chain(event_type: str, payload: Any, *, sequence: int = 5) -> dict[str, Any]:
    return {
        "event_type": event_type,
        "payload": payload,
        "sequence": sequence,
        "created_at": datetime(2026, 7, 10, tzinfo=UTC),
    }


@pytest.fixture
async def bare_reader() -> ConversationReadModel:
    return ConversationReadModel(
        create_async_engine("sqlite+aiosqlite://"), chain_candidate_limit=100
    )


async def test_hop1_validator_negative_arms(bare_reader: ConversationReadModel) -> None:
    cid, tid = uuid.uuid4(), uuid.uuid4()
    row = _fake_conversation_row(cid)
    turn = {"turn_id": tid, "seq": 1}
    run_id = "agent-run-x"

    def hop1(chain_rows: list[dict[str, Any]]) -> None:
        bare_reader._validate_hop1(chain_rows, turn=turn, row=row, run_id=run_id)

    good = {
        "conversation_id": str(cid),
        "turn_id": str(tid),
        "seq": 1,
        "agent_run_id": run_id,
        "actor_id": _CREATOR,
        "question_sha256": "a" * 64,
        "question_bytes": 1,
        "answer_sha256": "b" * 64,
        "answer_bytes": 1,
        "prompt_tokens": 1,
        "completion_tokens": 1,
    }
    # Wrong event type under the correlation id.
    with pytest.raises(ConversationChainIntegrityError) as exc:
        hop1([_fake_chain("agent.run.started", good)])
    assert exc.value.internal_reason == "hop1_mismatch"
    # Payload is not an object.
    with pytest.raises(ConversationChainIntegrityError) as exc:
        hop1([_fake_chain("conversation.turn_completed", ["not", "an", "object"])])
    assert exc.value.internal_reason == "hop1_malformed"
    # A required key missing entirely (the _payload_str hop1 arm).
    with pytest.raises(ConversationChainIntegrityError) as exc:
        hop1([_fake_chain("conversation.turn_completed", {"turn_id": str(tid)})])
    assert exc.value.internal_reason == "hop1_malformed"
    # The identity tuple disagrees (conversation_id arm of the composite).
    with pytest.raises(ConversationChainIntegrityError) as exc:
        hop1(
            [
                _fake_chain(
                    "conversation.turn_completed",
                    {**good, "conversation_id": str(uuid.uuid4())},
                )
            ]
        )
    assert exc.value.internal_reason == "hop1_mismatch"
    # The hop-1 actor arm: actor_id != the conversation's creator.
    with pytest.raises(ConversationChainIntegrityError) as exc:
        hop1([_fake_chain("conversation.turn_completed", {**good, "actor_id": "someone.else"})])
    assert exc.value.internal_reason == "dual_identity_mismatch"
    # finding 3 (2026-07-10): a str is not evidence — question_sha256="x"
    # previously projected as a valid digest.
    with pytest.raises(ConversationChainIntegrityError) as exc:
        hop1([_fake_chain("conversation.turn_completed", {**good, "question_sha256": "x"})])
    assert exc.value.internal_reason == "hop1_malformed"
    # Uppercase 64-hex is NOT the canonical form the writers emit.
    with pytest.raises(ConversationChainIntegrityError) as exc:
        hop1([_fake_chain("conversation.turn_completed", {**good, "answer_sha256": "A" * 64})])
    assert exc.value.internal_reason == "hop1_malformed"


async def test_started_validator_negative_arms(bare_reader: ConversationReadModel) -> None:
    cid = uuid.uuid4()
    row = _fake_conversation_row(cid)
    run_id = "agent-run-x"
    good = _started_payload(run_id)

    def started(chain_rows: list[dict[str, Any]]) -> None:
        bare_reader._validate_started(chain_rows, row=row, run_id=run_id)

    # The anchor resolves to a non-started event type.
    with pytest.raises(ConversationChainIntegrityError) as exc:
        started([_fake_chain("agent.run.completed", good)])
    assert exc.value.internal_reason == "anchor_mismatch"
    # Payload is not an object.
    with pytest.raises(ConversationChainIntegrityError) as exc:
        started([_fake_chain("agent.run.started", "not-an-object")])
    assert exc.value.internal_reason == "anchor_malformed"
    # run_id disagreement (the _run_row_identity run arm).
    with pytest.raises(ConversationChainIntegrityError) as exc:
        started([_fake_chain("agent.run.started", {**good, "run_id": "agent-run-OTHER"})])
    assert exc.value.internal_reason == "anchor_mismatch"
    # originator disagreement (the _run_row_identity identity arm).
    with pytest.raises(ConversationChainIntegrityError) as exc:
        started([_fake_chain("agent.run.started", {**good, "originator_subject": "someone.else"})])
    assert exc.value.internal_reason == "dual_identity_mismatch"
    # forged persisted actor_id (finding 3, 2026-07-10: originator alone was
    # checked; a forged actor_id was accepted and the projection substituted
    # the creator).
    with pytest.raises(ConversationChainIntegrityError) as exc:
        started([_fake_chain("agent.run.started", {**good, "actor_id": "forged"})])
    assert exc.value.internal_reason == "dual_identity_mismatch"
    # finding 3: prior_context_sha256="y" previously projected as evidence.
    with pytest.raises(ConversationChainIntegrityError) as exc:
        started([_fake_chain("agent.run.started", {**good, "prior_context_sha256": "y"})])
    assert exc.value.internal_reason == "anchor_malformed"
    # wall_clock_s missing/non-numeric.
    with pytest.raises(ConversationChainIntegrityError) as exc:
        started([_fake_chain("agent.run.started", {**good, "wall_clock_s": None})])
    assert exc.value.internal_reason == "anchor_malformed"


async def test_terminal_validator_negative_arms(bare_reader: ConversationReadModel) -> None:
    cid = uuid.uuid4()
    row = _fake_conversation_row(cid)
    run_id = "agent-run-x"
    good = _terminal_payload(run_id)

    def terminal(chain_rows: list[dict[str, Any]]) -> None:
        bare_reader._validate_terminal(chain_rows, row=row, run_id=run_id)

    # The anchor resolves to a non-terminal event type.
    with pytest.raises(ConversationChainIntegrityError) as exc:
        terminal([_fake_chain("agent.run.started", good)])
    assert exc.value.internal_reason == "anchor_mismatch"
    # Payload is not an object.
    with pytest.raises(ConversationChainIntegrityError) as exc:
        terminal([_fake_chain("agent.run.completed", 42)])
    assert exc.value.internal_reason == "anchor_malformed"
    # An optional key present with a non-string type.
    with pytest.raises(ConversationChainIntegrityError) as exc:
        terminal([_fake_chain("agent.run.completed", {**good, "refusal_reason": 123})])
    assert exc.value.internal_reason == "anchor_malformed"
    # forged persisted actor_id (finding 3).
    with pytest.raises(ConversationChainIntegrityError) as exc:
        terminal([_fake_chain("agent.run.completed", {**good, "actor_id": "forged"})])
    assert exc.value.internal_reason == "dual_identity_mismatch"
    # finding 3: a malformed answer digest is corruption, not evidence.
    with pytest.raises(ConversationChainIntegrityError) as exc:
        terminal([_fake_chain("agent.run.completed", {**good, "answer_sha256": "zz"})])
    assert exc.value.internal_reason == "anchor_malformed"


async def test_dispatch_projection_negative_arms(bare_reader: ConversationReadModel) -> None:
    cid = uuid.uuid4()
    row = _fake_conversation_row(cid)
    run_id = "agent-run-x"
    good = _dispatch_payload(run_id)

    def project(chain_rows: list[dict[str, Any]]) -> None:
        bare_reader._project_dispatches(chain_rows, row=row, run_id=run_id)

    with pytest.raises(ConversationChainIntegrityError) as exc:
        project([_fake_chain("agent.run.dispatch", "not-an-object")])
    assert exc.value.internal_reason == "anchor_malformed"
    with pytest.raises(ConversationChainIntegrityError) as exc:
        project([_fake_chain("agent.run.dispatch", {**good, "scope_id": 123})])
    assert exc.value.internal_reason == "anchor_malformed"
    with pytest.raises(ConversationChainIntegrityError) as exc:
        project([_fake_chain("agent.run.dispatch", {**good, "result_bytes": "many"})])
    assert exc.value.internal_reason == "anchor_malformed"
    # forged persisted actor_id (finding 3) — dispatch rows validate it too.
    with pytest.raises(ConversationChainIntegrityError) as exc:
        project([_fake_chain("agent.run.dispatch", {**good, "actor_id": "forged"})])
    assert exc.value.internal_reason == "dual_identity_mismatch"
    # finding 3: args_sha256 is REQUIRED 64-hex; result_sha256 is 64-hex
    # WHEN PRESENT (nullable by the writer contract), and a non-string
    # result refuses through the same arm.
    with pytest.raises(ConversationChainIntegrityError) as exc:
        project([_fake_chain("agent.run.dispatch", {**good, "args_sha256": "not-a-digest"})])
    assert exc.value.internal_reason == "anchor_malformed"
    with pytest.raises(ConversationChainIntegrityError) as exc:
        project([_fake_chain("agent.run.dispatch", {**good, "result_sha256": "not-a-digest"})])
    assert exc.value.internal_reason == "anchor_malformed"
    with pytest.raises(ConversationChainIntegrityError) as exc:
        project([_fake_chain("agent.run.dispatch", {**good, "result_sha256": 42})])
    assert exc.value.internal_reason == "anchor_malformed"


async def test_cursor_payload_must_be_an_object(reader: ConversationReadModel) -> None:
    import base64 as b64
    import json as js

    array_cursor = b64.urlsafe_b64encode(js.dumps([1, 2, 3]).encode()).decode()
    with pytest.raises(CursorInvalid, match="not an object"):
        await reader.list_conversations(
            tenant_id=_TENANT, creator_subject=_CREATOR, cursor=array_cursor
        )


async def test_transcript_cursor_non_string_cid_type(
    store: ConversationStore, history: DecisionHistoryStore, reader: ConversationReadModel
) -> None:
    cid = await _new_conversation(store)
    await _drive_turn(store, history, cid, 1)
    cursor = _encode_cursor({"v": 1, "conversation_id": 123, "watermark": 1, "after_seq": 0})
    with pytest.raises(CursorInvalid, match="invalid type"):
        await reader.read_transcript(
            cid, tenant_id=_TENANT, creator_subject=_CREATOR, cursor=cursor
        )


async def test_chain_cross_block_digest_coupling_is_enforced(
    store: ConversationStore,
    history: DecisionHistoryStore,
    reader: ConversationReadModel,
) -> None:
    """finding 3 (2026-07-10): a joined chain whose anchors disagree on
    content is corruption. A VALID-hex but WRONG started question digest —
    and separately a wrong terminal answer digest — must refuse as
    anchor_mismatch, never project."""
    a_sha = hashlib.sha256(b"answer 1").hexdigest()
    q_sha = hashlib.sha256(b"question 1").hexdigest()

    cid = await _new_conversation(store)
    run_id = f"agent-run-{uuid.uuid4().hex}"
    await _append_run_rows(history, run_id, question_sha256="c" * 64, answer_sha256=a_sha)
    await _append_turn(store, cid, 1, run_id=run_id)
    with pytest.raises(ConversationChainIntegrityError) as exc:
        await reader.read_turn_chain(cid, 1, tenant_id=_TENANT, creator_subject=_CREATOR)
    assert exc.value.internal_reason == "anchor_mismatch"
    assert "started question_sha256" in exc.value.detail

    cid2 = await _new_conversation(store)
    run_id2 = f"agent-run-{uuid.uuid4().hex}"
    await _append_run_rows(history, run_id2, question_sha256=q_sha, answer_sha256="d" * 64)
    await _append_turn(store, cid2, 1, run_id=run_id2)
    with pytest.raises(ConversationChainIntegrityError) as exc:
        await reader.read_turn_chain(cid2, 1, tenant_id=_TENANT, creator_subject=_CREATOR)
    assert exc.value.internal_reason == "anchor_mismatch"
    assert "terminal answer_sha256" in exc.value.detail


async def test_chain_turn_row_missing_within_watermark_is_transcript_integrity(
    store: ConversationStore,
    history: DecisionHistoryStore,
    reader: ConversationReadModel,
    db: AsyncEngine,
) -> None:
    """turn_count admits the seq but the row is gone (finding 4b,
    2026-07-10): the record CLAIMS the turn exists, so an absent row inside
    1..watermark is transcript-store corruption — integrity 500, never the
    owner-visible turn_not_found 404 (which stays reserved for
    seq > turn_count)."""
    cid = await _new_conversation(store)
    await _drive_turn(store, history, cid, 1)
    async with db.begin() as conn:
        await conn.execute(
            sa.delete(_conversation_turns).where(_conversation_turns.c.conversation_id == cid)
        )
    with pytest.raises(ConversationTranscriptIntegrityError, match="missing"):
        await reader.read_turn_chain(cid, 1, tenant_id=_TENANT, creator_subject=_CREATOR)
    # seq ABOVE the watermark stays the owner-visible 404.
    with pytest.raises(TurnNotFound):
        await reader.read_turn_chain(cid, 2, tenant_id=_TENANT, creator_subject=_CREATOR)
