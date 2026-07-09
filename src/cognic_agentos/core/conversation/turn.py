"""ADR-028 M8.5-B — the governed conversation turn loop.

CRITICAL CONTROLS. Owns the terminal-state refusal contract: posting a turn to a
``closed`` / ``expired`` / ``erased`` conversation refuses with
``conversation_not_active`` and NEVER invokes the AgentLoop. The refusal fires at
the lifecycle gate, before context assembly and before any model/gateway
activity.

Flow (ADR-028 §4)::

    claim (atomic, single-writer, CREATOR-SCOPED)
      -> bounds (max_turns, cumulative token budget)
      -> context assembly (bounded replay, kernel store ONLY -- invariant I-1)
      -> AgentLoop.ask(prior_context=...)   [the M8 dispatch chokepoint re-checks
                                             the CURRENT envelope -- invariant I-2]
      -> persist turn + digests, bump counters, append conversation.turn_completed
      -> release claim (finally-guarded)

**Creator scoping lives in the claim.** ``ConversationStore.append_turn`` and
``.transition`` take ``tenant_id`` but NOT ``creator_subject``; the only
creator-bound step is ``claim_turn``, which therefore MUST precede them. The
ordering is pinned by ``tests/unit/core/conversation/test_turn.py`` with a
call-recording store, not left to call-site discipline.

**The envelope is never cached across turns.** This module holds no entitlement
state at all: it hands the actor's identity to the loop, and the M8 dispatcher
re-resolves assignment -> entitlement -> policy on every dispatch of every turn.
That absence IS the I-2 enforcement, and BAR 3 pins it.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final, Protocol

from cognic_agentos.core.agent._types import (
    AgentDispatchRefusalReason,
    AgentRunTerminalState,
    PriorTurn,
)
from cognic_agentos.core.conversation._context import assemble_prior_context
from cognic_agentos.core.conversation._types import (
    ConversationRecord,
    ConversationTurnRefused,
    TurnRecord,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from cognic_agentos.core.agent._types import AgentAskResult

_TURN_REQUEST_ID_PREFIX: Final[str] = "conv-turn-"


class _StoreLike(Protocol):
    """The narrow ``ConversationStore`` surface this executor consumes.

    Signatures are EXACT, not ``**kwargs: Any``: a loose Protocol would
    structurally accept a store whose ``claim_turn`` omitted
    ``creator_subject``, silently dropping the creator boundary.
    """

    async def claim_turn(
        self,
        conversation_id: uuid.UUID,
        *,
        tenant_id: str,
        creator_subject: str,
        now: datetime,
        claim_ttl_s: float,
    ) -> ConversationRecord: ...

    async def load_replay_turns(
        self, conversation_id: uuid.UUID, *, tenant_id: str, last_n: int
    ) -> list[TurnRecord]: ...

    async def append_turn(
        self,
        *,
        conversation_id: uuid.UUID,
        tenant_id: str,
        seq: int,
        user_message: str,
        answer: str,
        agent_run_id: str,
        prompt_tokens: int,
        completion_tokens: int,
        actor_id: str,
        request_id: str,
    ) -> uuid.UUID: ...

    async def release_claim(self, conversation_id: uuid.UUID, *, tenant_id: str) -> None: ...


class _LoopLike(Protocol):
    """The narrow ``AgentLoop`` surface. Exact signature for the same reason."""

    async def ask(
        self,
        *,
        agent_id: str,
        question: str,
        actor_tenant_id: str,
        actor_subject: str,
        prior_context: tuple[PriorTurn, ...] = (),
    ) -> AgentAskResult: ...


@dataclass(frozen=True, slots=True)
class TurnResult:
    """Terminal result of one governed conversation turn.

    ``turn_id`` is the id the store minted and inserted -- never a fresh uuid.
    """

    turn_id: uuid.UUID
    seq: int
    answer: str
    agent_run_id: str
    terminal_state: AgentRunTerminalState
    refusal_reason: AgentDispatchRefusalReason | None


class ConversationTurnExecutor:
    """Wraps the M8 ``AgentLoop`` with the ADR-028 conversation turn contract."""

    def __init__(
        self,
        *,
        store: _StoreLike,
        loop: _LoopLike,
        max_turns: int,
        cumulative_token_budget: int,
        replay_last_n: int,
        replay_token_ceiling: int,
        claim_ttl_s: float,
        agent_run_wall_clock_s: float,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if claim_ttl_s <= agent_run_wall_clock_s:
            raise ValueError(
                "claim_ttl_s must exceed agent_run_wall_clock_s, else a slow turn "
                "has its claim stolen and can be double-run"
            )
        self._store = store
        self._loop = loop
        self._max_turns = max_turns
        self._cumulative_token_budget = cumulative_token_budget
        self._replay_last_n = replay_last_n
        self._replay_token_ceiling = replay_token_ceiling
        self._claim_ttl_s = claim_ttl_s
        self._clock = clock

    async def post_turn(
        self,
        *,
        conversation_id: uuid.UUID,
        tenant_id: str,
        actor_subject: str,
        user_message: str,
    ) -> TurnResult:
        """Run one governed conversation turn.

        Raises:
            ConversationNotFound: absent / cross-tenant / cross-actor. The route
                collapses it to a 404 byte-identical to a genuine not-found.
            ConversationTurnRefused: a closed-enum governed refusal raised
                BEFORE the AgentLoop is invoked.
        """
        now = self._clock()

        # 1. Atomic, CREATOR-SCOPED claim. Raises ConversationNotFound or
        #    ConversationTurnRefused (conversation_not_active /
        #    conversation_turn_in_progress) BEFORE any context assembly, any
        #    model call, or any gateway activity.
        record = await self._store.claim_turn(
            conversation_id,
            tenant_id=tenant_id,
            creator_subject=actor_subject,
            now=now,
            claim_ttl_s=self._claim_ttl_s,
        )
        try:
            # 2. Conversation-level bounds. Still no loop invocation.
            if record.turn_count >= self._max_turns:
                raise ConversationTurnRefused(
                    "conversation_max_turns_exceeded", current_state=record.state
                )
            if record.cumulative_tokens >= self._cumulative_token_budget:
                raise ConversationTurnRefused(
                    "conversation_token_budget_exceeded", current_state=record.state
                )

            # 3. Context assembly -- the kernel store ONLY (invariant I-1).
            turns = await self._store.load_replay_turns(
                conversation_id, tenant_id=tenant_id, last_n=self._replay_last_n
            )
            prior_context = assemble_prior_context(
                turns,
                replay_last_n=self._replay_last_n,
                token_ceiling=self._replay_token_ceiling,
            )

            # 4. The M8 governed loop. Its dispatch chokepoint re-checks the
            #    CURRENT envelope on every dispatch (invariant I-2).
            result = await self._loop.ask(
                agent_id=record.agent_id,
                question=user_message,
                actor_tenant_id=tenant_id,
                actor_subject=actor_subject,
                prior_context=prior_context,
            )

            # 5. Persist + chain row (digest-only). append_turn returns the
            #    turn_id it actually inserted -- surface THAT, never a fresh uuid.
            seq = record.turn_count + 1
            turn_id = await self._store.append_turn(
                conversation_id=conversation_id,
                tenant_id=tenant_id,
                seq=seq,
                user_message=user_message,
                answer=result.answer,
                agent_run_id=result.run_id,
                prompt_tokens=result.prompt_tokens,
                completion_tokens=result.completion_tokens,
                actor_id=actor_subject,
                request_id=f"{_TURN_REQUEST_ID_PREFIX}{uuid.uuid4().hex}",
            )
            return TurnResult(
                turn_id=turn_id,
                seq=seq,
                answer=result.answer,
                agent_run_id=result.run_id,
                terminal_state=result.terminal_state,
                refusal_reason=result.refusal_reason,
            )
        finally:
            # 6. Always release. A crashed turn must never wedge the conversation.
            await self._store.release_claim(conversation_id, tenant_id=tenant_id)
