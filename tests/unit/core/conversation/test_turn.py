"""ADR-028 M8.5-B (Sprint B, Task 6) — ConversationTurnExecutor.

REAL ConversationStore + REAL DecisionHistoryStore (file-backed sqlite) wrapped
in a call-recording spy, plus a stub AgentLoop that records whether it was
invoked at all.

The load-bearing pins:
  * terminal-state / bounds refusals fire with ZERO AgentLoop invocation
  * ``claim_turn`` (the ONLY creator-scoped step) precedes ``append_turn``
  * a cross-actor post raises ConversationNotFound with ZERO append_turn
  * the cumulative token budget is fed by REAL counts, never zeros
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.agent._types import AgentAskResult
from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.conversation._types import (
    ConversationNotFound,
    ConversationTurnRefused,
)
from cognic_agentos.core.conversation.storage import ConversationStore
from cognic_agentos.core.conversation.turn import ConversationTurnExecutor, TurnResult

pytestmark = pytest.mark.asyncio

_TENANT = "t1"
_SUBJECT = "s1"


class _SpyLoop:
    """Records every ``ask`` kwargs dict; returns a canned result."""

    def __init__(self, *, prompt_tokens: int = 3, completion_tokens: int = 2) -> None:
        self.calls: list[dict[str, Any]] = []
        self._pt = prompt_tokens
        self._ct = completion_tokens

    async def ask(self, **kw: Any) -> AgentAskResult:
        self.calls.append(kw)
        return AgentAskResult(
            run_id="agent-run-1",
            terminal_state="completed",
            answer="Acme Corp",
            steps_used=1,
            refusal_reason=None,
            prompt_tokens=self._pt,
            completion_tokens=self._ct,
        )


class _RaisingLoop:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def ask(self, **kw: Any) -> AgentAskResult:
        self.calls.append(kw)
        raise RuntimeError("gateway exploded")


class _OrderRecordingStore:
    """Delegates to the REAL store while recording the call order + kwargs."""

    def __init__(self, inner: ConversationStore) -> None:
        self._inner = inner
        self.order: list[str] = []
        self.claim_kwargs: list[dict[str, Any]] = []
        self.append_kwargs: list[dict[str, Any]] = []
        self.release_kwargs: list[dict[str, Any]] = []
        self.minted_claims: list[Any] = []

    async def claim_turn(self, conversation_id: uuid.UUID, **kw: Any) -> Any:
        self.order.append("claim_turn")
        self.claim_kwargs.append(kw)
        claim = await self._inner.claim_turn(conversation_id, **kw)
        self.minted_claims.append(claim)
        return claim

    async def load_replay_turns(self, conversation_id: uuid.UUID, **kw: Any) -> Any:
        self.order.append("load_replay_turns")
        return await self._inner.load_replay_turns(conversation_id, **kw)

    async def append_turn(self, **kw: Any) -> uuid.UUID:
        self.order.append("append_turn")
        self.append_kwargs.append(kw)
        return await self._inner.append_turn(**kw)

    async def release_claim(self, conversation_id: uuid.UUID, **kw: Any) -> None:
        self.order.append("release_claim")
        self.release_kwargs.append(kw)
        await self._inner.release_claim(conversation_id, **kw)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


@pytest.fixture
async def db(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'turn.db'}")
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


def _executor(
    store: Any,
    loop: Any,
    *,
    max_turns: int = 20,
    cumulative_token_budget: int = 1000,
) -> ConversationTurnExecutor:
    return ConversationTurnExecutor(
        store=store,
        loop=loop,
        max_turns=max_turns,
        cumulative_token_budget=cumulative_token_budget,
        replay_last_n=10,
        replay_token_ceiling=8000,
        claim_ttl_s=300.0,
        agent_run_wall_clock_s=120.0,
    )


async def _conversation(store: ConversationStore) -> uuid.UUID:
    cid = uuid.uuid4()
    await store.create_conversation(
        conversation_id=cid,
        tenant_id=_TENANT,
        agent_id="analyst",
        creator_subject=_SUBJECT,
        request_id="req-create",
    )
    return cid


async def _post(ex: ConversationTurnExecutor, cid: uuid.UUID, msg: str = "who?") -> TurnResult:
    return await ex.post_turn(
        conversation_id=cid, tenant_id=_TENANT, actor_subject=_SUBJECT, user_message=msg
    )


# --- happy path ----------------------------------------------------------------


async def test_happy_path_persists_turn_and_returns_answer(db: AsyncEngine) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    ex = _executor(store, _SpyLoop())
    result = await _post(ex, cid)
    assert isinstance(result, TurnResult)
    assert result.seq == 1
    assert result.answer == "Acme Corp"
    assert result.agent_run_id == "agent-run-1"
    rec = await store.load(cid, tenant_id=_TENANT, creator_subject=_SUBJECT)
    assert rec is not None and rec.turn_count == 1


async def test_returned_turn_id_names_a_real_row(db: AsyncEngine) -> None:
    import sqlalchemy as sa

    from cognic_agentos.core.conversation.storage import _conversation_turns

    store = ConversationStore(db)
    cid = await _conversation(store)
    ex = _executor(store, _SpyLoop())
    result = await _post(ex, cid)
    async with db.connect() as conn:
        found = (
            await conn.execute(
                sa.select(_conversation_turns.c.turn_id).where(
                    _conversation_turns.c.turn_id == result.turn_id
                )
            )
        ).first()
    assert found is not None


async def test_first_turn_has_empty_prior_context(db: AsyncEngine) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    loop = _SpyLoop()
    await _post(_executor(store, loop), cid)
    assert loop.calls[0]["prior_context"] == ()


async def test_second_turn_replays_the_first(db: AsyncEngine) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    loop = _SpyLoop()
    ex = _executor(store, loop)
    await _post(ex, cid, "who?")
    await _post(ex, cid, "and second?")
    prior = loop.calls[1]["prior_context"]
    assert [p.role for p in prior] == ["user", "assistant"]
    assert prior[0].content == "who?"
    assert prior[1].content == "Acme Corp"


async def test_real_token_counts_accumulate_into_the_conversation(db: AsyncEngine) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    await _post(_executor(store, _SpyLoop(prompt_tokens=3, completion_tokens=2)), cid)
    rec = await store.load(cid, tenant_id=_TENANT, creator_subject=_SUBJECT)
    assert rec is not None and rec.cumulative_tokens == 5


# --- ORDERING PIN: claim_turn (creator-scoped) precedes append_turn -------------


async def test_claim_precedes_append_and_carries_creator_subject(db: AsyncEngine) -> None:
    """append_turn / transition take tenant_id but NOT creator_subject.

    Creator scoping lives ENTIRELY in the claim_turn that must precede them. A
    reorder would silently drop the creator boundary, and no other test would
    notice.
    """
    inner = ConversationStore(db)
    cid = await _conversation(inner)
    spy = _OrderRecordingStore(inner)
    await _post(_executor(spy, _SpyLoop()), cid)

    assert spy.order.index("claim_turn") < spy.order.index("append_turn")
    assert spy.claim_kwargs[0]["creator_subject"] == _SUBJECT
    assert spy.claim_kwargs[0]["tenant_id"] == _TENANT


async def test_cross_actor_post_is_not_found_with_zero_append(db: AsyncEngine) -> None:
    inner = ConversationStore(db)
    cid = await _conversation(inner)
    spy = _OrderRecordingStore(inner)
    loop = _SpyLoop()
    ex = _executor(spy, loop)
    with pytest.raises(ConversationNotFound):
        await ex.post_turn(
            conversation_id=cid,
            tenant_id=_TENANT,
            actor_subject="mallory",
            user_message="q",
        )
    assert spy.append_kwargs == []
    assert "append_turn" not in spy.order
    assert loop.calls == []


async def test_cross_tenant_post_is_not_found_with_zero_append(db: AsyncEngine) -> None:
    inner = ConversationStore(db)
    cid = await _conversation(inner)
    spy = _OrderRecordingStore(inner)
    loop = _SpyLoop()
    ex = _executor(spy, loop)
    with pytest.raises(ConversationNotFound):
        await ex.post_turn(
            conversation_id=cid,
            tenant_id="tenant-b",
            actor_subject=_SUBJECT,
            user_message="q",
        )
    assert "append_turn" not in spy.order
    assert loop.calls == []


# --- terminal-state + bounds refuse BEFORE the loop ----------------------------


async def test_closed_conversation_refuses_without_invoking_the_loop(db: AsyncEngine) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    await store.transition(
        conversation_id=cid,
        tenant_id=_TENANT,
        to_state="closed",
        actor_id=_SUBJECT,
        request_id="req-close",
    )
    loop = _SpyLoop()
    with pytest.raises(ConversationTurnRefused) as exc:
        await _post(_executor(store, loop), cid)
    assert exc.value.reason == "conversation_not_active"
    assert exc.value.current_state == "closed"
    assert loop.calls == []  # <-- ZERO AgentLoop invocation


async def test_max_turns_exceeded_refuses_without_invoking_the_loop(db: AsyncEngine) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    loop = _SpyLoop()
    ex = _executor(store, loop, max_turns=1)
    await _post(ex, cid, "q1")
    loop.calls.clear()
    with pytest.raises(ConversationTurnRefused) as exc:
        await _post(ex, cid, "q2")
    assert exc.value.reason == "conversation_max_turns_exceeded"
    assert loop.calls == []


async def test_token_budget_exhaustion_refuses_without_invoking_the_loop(
    db: AsyncEngine,
) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    loop = _SpyLoop(prompt_tokens=3, completion_tokens=2)  # 5 per turn
    ex = _executor(store, loop, cumulative_token_budget=4)
    await _post(ex, cid, "q1")
    loop.calls.clear()
    with pytest.raises(ConversationTurnRefused) as exc:
        await _post(ex, cid, "q2")
    assert exc.value.reason == "conversation_token_budget_exceeded"
    assert loop.calls == []


async def test_bounds_refusal_writes_no_turn_row(db: AsyncEngine) -> None:
    inner = ConversationStore(db)
    cid = await _conversation(inner)
    spy = _OrderRecordingStore(inner)
    ex = _executor(spy, _SpyLoop(), max_turns=0)
    with pytest.raises(ConversationTurnRefused):
        await _post(ex, cid)
    assert "append_turn" not in spy.order


# --- claim lifecycle -----------------------------------------------------------


async def test_claim_is_released_when_the_loop_raises(db: AsyncEngine) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    ex = _executor(store, _RaisingLoop())
    with pytest.raises(RuntimeError):
        await _post(ex, cid)
    # a crashed turn must not wedge the conversation
    await store.claim_turn(
        cid,
        tenant_id=_TENANT,
        creator_subject=_SUBJECT,
        now=datetime.now(UTC),
        claim_ttl_s=300.0,
    )


async def test_claim_is_released_on_the_happy_path(db: AsyncEngine) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    await _post(_executor(store, _SpyLoop()), cid)
    await store.claim_turn(
        cid,
        tenant_id=_TENANT,
        creator_subject=_SUBJECT,
        now=datetime.now(UTC),
        claim_ttl_s=300.0,
    )


async def test_concurrent_turn_refuses_turn_in_progress(db: AsyncEngine) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    await store.claim_turn(
        cid,
        tenant_id=_TENANT,
        creator_subject=_SUBJECT,
        now=datetime.now(UTC),
        claim_ttl_s=300.0,
    )
    loop = _SpyLoop()
    with pytest.raises(ConversationTurnRefused) as exc:
        await _post(_executor(store, loop), cid)
    assert exc.value.reason == "conversation_turn_in_progress"
    assert loop.calls == []


# --- construction guard --------------------------------------------------------


async def test_claim_ttl_must_exceed_agent_wall_clock(db: AsyncEngine) -> None:
    """Else a slow turn has its claim stolen and can be double-run."""
    store = ConversationStore(db)
    with pytest.raises(ValueError, match="claim_ttl_s"):
        ConversationTurnExecutor(
            store=store,
            loop=_SpyLoop(),
            max_turns=20,
            cumulative_token_budget=1000,
            replay_last_n=10,
            replay_token_ceiling=8000,
            claim_ttl_s=1.0,
            agent_run_wall_clock_s=120.0,
        )


async def test_loop_receives_the_conversation_agent_id_and_actor(db: AsyncEngine) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    loop = _SpyLoop()
    await _post(_executor(store, loop), cid)
    kw = loop.calls[0]
    assert kw["agent_id"] == "analyst"
    assert kw["actor_tenant_id"] == _TENANT
    assert kw["actor_subject"] == _SUBJECT


# --- FENCING (P0, 2026-07-10): the executor threads ITS OWN lease --------------


async def test_executor_threads_the_minted_claim_id_to_append_and_release(
    db: AsyncEngine,
) -> None:
    """The claim_id minted at claim_turn is the one append_turn verifies and
    the one release_claim conditions on. Any break in this chain reopens the
    lost-lease race."""
    inner = ConversationStore(db)
    cid = await _conversation(inner)
    spy = _OrderRecordingStore(inner)
    await _post(_executor(spy, _SpyLoop()), cid)

    minted = spy.minted_claims[0].claim_id
    assert spy.append_kwargs[0]["claim_id"] == minted
    assert spy.release_kwargs[0]["claim_id"] == minted


async def test_release_is_fenced_even_when_the_loop_raises(db: AsyncEngine) -> None:
    inner = ConversationStore(db)
    cid = await _conversation(inner)
    spy = _OrderRecordingStore(inner)
    with pytest.raises(RuntimeError):
        await _post(_executor(spy, _RaisingLoop()), cid)
    assert spy.release_kwargs[0]["claim_id"] == spy.minted_claims[0].claim_id
