"""ADR-028 M8.5-A — Postgres/Oracle/sqlite-backed conversation store.

CRITICAL CONTROLS. Two enforcement boundaries live here:

1. **Tenant isolation.** User-facing reads and claims additionally carry the
   immutable ``creator_subject`` predicate. Compliance erasure is deliberately
   tenant-wide, so its writes carry ``WHERE tenant_id = :tenant_id`` without
   creator scope. A cross-tenant or cross-actor ``conversation_id`` reads as
   ABSENT (``None`` / :class:`ConversationNotFound`), never as a permission
   error -- the route collapses it to a 404 byte-identical to a genuine
   not-found, so a probe cannot enumerate conversations across tenants or
   actors.

2. **Chain atomicity (Doctrine Lock D).** Every write drives
   ``DecisionHistoryStore.append_with_precondition`` so the chain row, the
   state-cache UPDATE and the chain-head UPDATE commit in ONE transaction. A
   refusal raised inside the precondition rolls all three back: no chain row,
   no state mutation.

**Plaintext NEVER enters a chain payload.** ``conversation.turn_completed``
carries ``question_sha256`` / ``answer_sha256`` + byte counts (the M8
digest-only doctrine extended to conversations, ADR-028 §3). The erasable
plaintext lives only in ``conversation_turns.user_message`` / ``.answer``.
R21's ``conversation.turn_refused`` carries token counts plus the screened
question digest and the original screened answer digest while persisting no
turn row and no plaintext. F-S2a conversation phases admit no transformation;
F-S3 owns transformations together with hook-aware examiner projection and
before/after digest continuity. The counter update and chain append are one
transaction.

Tables register on the SHARED ``core.audit._metadata``, as every other
chain-consuming store does (``core/run/storage.py``, ``core/scheduler/storage.py``).
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any, Final, Literal

import sqlalchemy as sa
from sqlalchemy import (
    TIMESTAMP,
    Boolean,
    Column,
    ForeignKeyConstraint,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
    Uuid,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from cognic_agentos.core.audit import _metadata
from cognic_agentos.core.conversation._types import (
    ConversationNotFound,
    ConversationRecord,
    ConversationState,
    ConversationTransitionRefused,
    ConversationTurnRefused,
    TurnClaim,
    TurnRecord,
    _validate_output_hook_correlation,
    validate_transition,
)
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord

#: Column widths mirror the ``runs`` / ``entitlements`` substrates.
CONVERSATION_TENANT_ID_MAX_LEN: Final[int] = 128

CONVERSATION_AGENT_ID_MAX_LEN: Final[int] = 128
CONVERSATION_SUBJECT_MAX_LEN: Final[int] = 256
CONVERSATION_AGENT_RUN_ID_MAX_LEN: Final[int] = 64
CONVERSATION_RETENTION_CLASS_MAX_LEN: Final[int] = 64

#: ISO 42001 controls stamped on every conversation lifecycle chain row.
CONVERSATION_ISO_CONTROLS: Final[tuple[str, ...]] = ("A.5.31", "A.6.2.4")

#: The only transition targets M8.5-A can produce. Preflight-guarded BEFORE any
#: DB work so an out-of-vocabulary target never opens a transaction.
_STATE_TO_DECISION_TYPE: Final[dict[str, str]] = {
    "closed": "conversation.closed",
}

#: The PERSISTENCE RULE (ruled 2026-07-10): a fenced turn may settle while the
#: conversation is ``active`` or gracefully ``closed`` -- and NEVER when it is
#: ``expired`` or ``erased``. Writing plaintext into an erased conversation
#: would RESURRECT content after a regulator erasure (ADR-028 §3); an expired
#: conversation is past its retention decision. A valid lease does not override
#: the lifecycle boundary.
_PERSISTABLE_STATES: Final[frozenset[ConversationState]] = frozenset({"active", "closed"})

_TS = TIMESTAMP(timezone=True)


class _RedactionNotApplied(Exception):
    """Internal rollback signal for absent or already-erased targets."""


_conversations = Table(
    "conversations",
    _metadata,
    Column("conversation_id", Uuid(), primary_key=True),
    Column("tenant_id", String(CONVERSATION_TENANT_ID_MAX_LEN), nullable=False),
    Column("agent_id", String(CONVERSATION_AGENT_ID_MAX_LEN), nullable=False),
    Column("creator_subject", String(CONVERSATION_SUBJECT_MAX_LEN), nullable=False),
    Column("state", String(32), nullable=False),
    Column("turn_count", Integer(), nullable=False, server_default="0"),
    Column("cumulative_tokens", Integer(), nullable=False, server_default="0"),
    Column("turn_in_progress", Boolean(), nullable=False, server_default=sa.false()),
    Column("turn_claimed_at", _TS, nullable=True),
    Column("turn_claim_id", Uuid(), nullable=True),
    Column("retention_class", String(CONVERSATION_RETENTION_CLASS_MAX_LEN), nullable=True),
    Column("created_at", _TS, nullable=False),
    Column("last_turn_at", _TS, nullable=True),
    Column("erased_at", _TS, nullable=True),
)

_conversation_turns = Table(
    "conversation_turns",
    _metadata,
    Column("turn_id", Uuid(), primary_key=True),
    Column("conversation_id", Uuid(), nullable=False),
    Column("seq", Integer(), nullable=False),
    Column("user_message", Text(), nullable=True),
    Column("answer", Text(), nullable=True),
    Column("agent_run_id", String(CONVERSATION_AGENT_RUN_ID_MAX_LEN), nullable=False),
    Column("prompt_tokens", Integer(), nullable=False, server_default="0"),
    Column("completion_tokens", Integer(), nullable=False, server_default="0"),
    Column("created_at", _TS, nullable=False),
    Column("erased_at", _TS, nullable=True),
    Column("approval_request_id", String(64), nullable=True),
    Column("turn_kind", String(16), nullable=False, server_default="exchange"),
    # M8.5-B (migration 0016): the hop-1 correlation column — the SAME
    # request_id the caller (ConversationTurnExecutor) minted for this turn's
    # conversation.turn_completed chain row, persisted atomically with it.
    # Makes the chain-join read addressable via the indexed
    # decision_history.request_id instead of a JSON-payload predicate
    # (Oracle CLOB — no portable index).
    Column("turn_completed_request_id", String(64), nullable=False),
    ForeignKeyConstraint(
        ["conversation_id"],
        ["conversations.conversation_id"],
        name="fk_conversation_turns_conversation_id",
    ),
    UniqueConstraint("conversation_id", "seq", name="uq_conversation_turns_conversation_seq"),
    # Parity with migration 0016: create_all databases (unit fixtures) must
    # reject duplicate correlation ids exactly as migrated deployments do.
    UniqueConstraint(
        "turn_completed_request_id",
        name="uq_conversation_turns_turn_completed_request_id",
    ),
)


def _digest(text: str) -> tuple[str, int]:
    raw = text.encode("utf-8")
    return hashlib.sha256(raw).hexdigest(), len(raw)


def _validate_token_counts(prompt_tokens: object, completion_tokens: object) -> None:
    """Refuse malformed usage before it can move a governed budget counter."""

    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in (prompt_tokens, completion_tokens)
    ):
        raise ValueError("prompt_tokens and completion_tokens must be non-negative integers")


def _to_record(row: Any) -> ConversationRecord:
    return ConversationRecord(
        conversation_id=row["conversation_id"],
        tenant_id=row["tenant_id"],
        agent_id=row["agent_id"],
        creator_subject=row["creator_subject"],
        state=row["state"],
        turn_count=row["turn_count"],
        cumulative_tokens=row["cumulative_tokens"],
        created_at=row["created_at"],
        last_turn_at=row["last_turn_at"],
    )


async def _require_persistable_claim(
    conn: AsyncConnection,
    *,
    conversation_id: uuid.UUID,
    tenant_id: str,
    claim_id: uuid.UUID,
) -> ConversationState:
    """Lock and verify the shared user/system turn fence.

    Ownership deliberately precedes lifecycle: a stale holder has no claim,
    even when the conversation was erased after its lease was reclaimed.
    """
    fence = (
        await conn.execute(
            select(_conversations.c.state, _conversations.c.turn_claim_id)
            .where(
                _conversations.c.conversation_id == conversation_id,
                _conversations.c.tenant_id == tenant_id,
            )
            .with_for_update()
        )
    ).first()
    if fence is None:
        raise ConversationNotFound(str(conversation_id))
    state: ConversationState = fence[0]
    if fence[1] != claim_id:
        raise ConversationTurnRefused("conversation_turn_claim_stale", current_state=state)
    if state not in _PERSISTABLE_STATES:
        raise ConversationTurnRefused("conversation_not_active", current_state=state)
    return state


class ConversationStore:
    """Async; raises on every refusal/failure (no silent-skip)."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._history = DecisionHistoryStore(engine)

    # -- genesis ---------------------------------------------------------------

    async def create_conversation(
        self,
        *,
        conversation_id: uuid.UUID,
        tenant_id: str,
        agent_id: str,
        creator_subject: str,
        request_id: str,
    ) -> tuple[uuid.UUID, bytes]:
        """Genesis: INSERT an ``active`` row + append ``conversation.created``
        atomically. Returns ``(chain_record_id, chain_hash)``."""
        now = datetime.now(UTC)

        async def _precondition(conn: AsyncConnection, _seq: int, _hash: bytes) -> None:
            await conn.execute(
                sa.insert(_conversations).values(
                    conversation_id=conversation_id,
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    creator_subject=creator_subject,
                    state="active",
                    turn_count=0,
                    cumulative_tokens=0,
                    turn_in_progress=False,
                    turn_claimed_at=None,
                    created_at=now,
                    last_turn_at=None,
                )
            )

        def _build(_: None) -> DecisionRecord:
            return DecisionRecord(
                decision_type="conversation.created",
                request_id=request_id,
                payload={
                    "conversation_id": str(conversation_id),
                    "agent_id": agent_id,
                    "creator_subject": creator_subject,
                    "created_at": now.isoformat(),
                },
                actor_id=creator_subject,
                tenant_id=tenant_id,
                iso_controls=CONVERSATION_ISO_CONTROLS,
            )

        return await self._history.append_with_precondition(
            record_builder=_build, precondition=_precondition
        )

    # -- reads (tenant + creator scoped) ---------------------------------------

    async def load(
        self, conversation_id: uuid.UUID, *, tenant_id: str, creator_subject: str
    ) -> ConversationRecord | None:
        """Absent / cross-tenant / cross-actor all read as ``None``."""
        stmt = select(_conversations).where(
            _conversations.c.conversation_id == conversation_id,
            _conversations.c.tenant_id == tenant_id,
            _conversations.c.creator_subject == creator_subject,
        )
        async with self._engine.connect() as conn:
            row = (await conn.execute(stmt)).mappings().first()
        return None if row is None else _to_record(row)

    async def resolve_approval_context(
        self,
        *,
        approval_request_id: uuid.UUID,
        tenant_id: str,
    ) -> tuple[uuid.UUID, str] | None:
        """Resolve a pending chat approval to its conversation and agent.

        The tenant predicate is the isolation boundary. Exactly one exchange
        turn may own an approval id; duplicates are corruption and fail loud.
        Direct-MCP approvals have no conversation turn and return ``None``.
        """
        stmt = (
            select(_conversation_turns.c.conversation_id, _conversations.c.agent_id)
            .select_from(
                _conversation_turns.join(
                    _conversations,
                    _conversation_turns.c.conversation_id == _conversations.c.conversation_id,
                )
            )
            .where(
                _conversation_turns.c.approval_request_id == str(approval_request_id),
                _conversation_turns.c.turn_kind == "exchange",
                _conversations.c.tenant_id == tenant_id,
            )
            .limit(2)
        )
        async with self._engine.connect() as conn:
            matches = (await conn.execute(stmt)).all()
        if not matches:
            return None
        if len(matches) != 1:
            raise RuntimeError("approval conversation correlation is not unique")
        return matches[0].conversation_id, str(matches[0].agent_id)

    async def load_replay_turns(
        self, conversation_id: uuid.UUID, *, tenant_id: str, last_n: int
    ) -> list[TurnRecord]:
        """Bounded-replay source: the FIRST turn (grounding) + the LAST ``n``
        turns, de-duplicated, in ascending ``seq`` order.

        Tenant-scoped via a join on the parent conversation -- a foreign tenant
        reads as an empty list.
        """
        joined = _conversation_turns.join(
            _conversations,
            _conversation_turns.c.conversation_id == _conversations.c.conversation_id,
        )
        base = (
            select(_conversation_turns)
            .select_from(joined)
            .where(
                _conversation_turns.c.conversation_id == conversation_id,
                _conversations.c.tenant_id == tenant_id,
                _conversation_turns.c.turn_kind == "exchange",
            )
        )
        first_stmt = base.order_by(_conversation_turns.c.seq.asc()).limit(1)
        async with self._engine.connect() as conn:
            first = (await conn.execute(first_stmt)).mappings().all()
            last = (
                (await conn.execute(base.order_by(_conversation_turns.c.seq.desc()).limit(last_n)))
                .mappings()
                .all()
                if last_n > 0
                else []
            )
        by_seq: dict[int, Any] = {r["seq"]: r for r in [*first, *last]}
        return [
            TurnRecord(
                turn_id=r["turn_id"],
                seq=r["seq"],
                user_message=r["user_message"],
                answer=r["answer"],
                agent_run_id=r["agent_run_id"],
                prompt_tokens=r["prompt_tokens"],
                completion_tokens=r["completion_tokens"],
                created_at=r["created_at"],
                approval_request_id=r["approval_request_id"],
                turn_kind=r["turn_kind"],
            )
            for _, r in sorted(by_seq.items())
        ]

    async def claim_system_turn(
        self,
        conversation_id: uuid.UUID,
        *,
        tenant_id: str,
        now: datetime,
        claim_ttl_s: float,
    ) -> TurnClaim:
        """Claim for a kernel-authored turn without weakening tenant scope.

        ``creator_subject`` is immutable conversation metadata. Resolve it by
        tenant, then enter the exact creator-scoped claim path used by user
        turns; the second step still owns lifecycle, TTL and collision checks.
        """
        stmt = select(_conversations.c.creator_subject).where(
            _conversations.c.conversation_id == conversation_id,
            _conversations.c.tenant_id == tenant_id,
        )
        async with self._engine.connect() as conn:
            creator_subject = (await conn.execute(stmt)).scalar_one_or_none()
        if creator_subject is None:
            raise ConversationNotFound(str(conversation_id))
        return await self.claim_turn(
            conversation_id,
            tenant_id=tenant_id,
            creator_subject=creator_subject,
            now=now,
            claim_ttl_s=claim_ttl_s,
        )

    # -- the atomic single-writer claim (ADR-028 §4, PT-6) ---------------------

    async def claim_turn(
        self,
        conversation_id: uuid.UUID,
        *,
        tenant_id: str,
        creator_subject: str,
        now: datetime,
        claim_ttl_s: float,
    ) -> TurnClaim:
        """Atomically claim the conversation for one turn and mint its
        FENCING TOKEN.

        A DB predicate, never an in-process lock -- turn POSTs may land on any
        replica. Stale-claim detection compares ``turn_claimed_at`` against
        ``now`` in Python under the row lock, which is portable across
        Postgres / Oracle / sqlite (do NOT reach for ``sa.func.make_interval``).

        TTL expiry is LIVENESS recovery only: a reclaim mints a NEW
        ``claim_id``, immediately fencing the previous holder out of
        :meth:`append_turn` and :meth:`release_claim`. Without the token, a
        stalled worker could persist over -- and then unlock -- the thief's
        lease (the P0 lost-lease race, corrected 2026-07-10).

        Raises:
            ConversationNotFound: absent / cross-tenant / cross-actor.
            ConversationTurnRefused: ``conversation_not_active`` (carrying the
                current state) or ``conversation_turn_in_progress``.
        """
        claim_id = uuid.uuid4()
        async with self._engine.begin() as conn:
            row = (
                (
                    await conn.execute(
                        select(_conversations)
                        .where(
                            _conversations.c.conversation_id == conversation_id,
                            _conversations.c.tenant_id == tenant_id,
                            _conversations.c.creator_subject == creator_subject,
                        )
                        .with_for_update()
                    )
                )
                .mappings()
                .first()
            )
            if row is None:
                raise ConversationNotFound(str(conversation_id))

            state: ConversationState = row["state"]
            if state != "active":
                raise ConversationTurnRefused("conversation_not_active", current_state=state)

            claimed_at = row["turn_claimed_at"]
            claim_is_live = bool(row["turn_in_progress"]) and (
                claimed_at is not None
                and (now - _as_aware(claimed_at)).total_seconds() < claim_ttl_s
            )
            if claim_is_live:
                raise ConversationTurnRefused("conversation_turn_in_progress", current_state=state)

            await conn.execute(
                update(_conversations)
                .where(_conversations.c.conversation_id == conversation_id)
                .values(
                    turn_in_progress=True,
                    turn_claimed_at=now,
                    turn_claim_id=claim_id,
                )
            )
        return TurnClaim(record=_to_record(row), claim_id=claim_id)

    async def release_claim(
        self, conversation_id: uuid.UUID, *, tenant_id: str, claim_id: uuid.UUID
    ) -> None:
        """Release ONLY the caller's own lease.

        The ``turn_claim_id == claim_id`` predicate is the fencing half of
        release: a stale worker's release is a silent no-op, so it can never
        unlock the current holder's claim. Idempotent for the owner (a second
        release finds ``turn_claim_id`` already ``NULL`` and matches nothing).
        A crashed turn never wedges the conversation -- its lease is either
        released here or reclaimed after TTL by the next :meth:`claim_turn`.
        """
        async with self._engine.begin() as conn:
            await conn.execute(
                update(_conversations)
                .where(
                    _conversations.c.conversation_id == conversation_id,
                    _conversations.c.tenant_id == tenant_id,
                    _conversations.c.turn_claim_id == claim_id,
                )
                .values(
                    turn_in_progress=False,
                    turn_claimed_at=None,
                    turn_claim_id=None,
                )
            )

    async def next_turn_seq(
        self,
        conversation_id: uuid.UUID,
        *,
        tenant_id: str,
        claim_id: uuid.UUID,
    ) -> int:
        """Return the next PHYSICAL sequence under the caller's live fence."""
        async with self._engine.begin() as conn:
            await _require_persistable_claim(
                conn,
                conversation_id=conversation_id,
                tenant_id=tenant_id,
                claim_id=claim_id,
            )
            latest = (
                await conn.execute(
                    select(sa.func.max(_conversation_turns.c.seq)).where(
                        _conversation_turns.c.conversation_id == conversation_id
                    )
                )
            ).scalar_one()
            return int(latest or 0) + 1

    # -- turn persistence (chain-atomic, digest-only) --------------------------

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
        claim_id: uuid.UUID,
        approval_request_id: str | None = None,
        turn_kind: Literal["exchange", "system"] = "exchange",
        conversation_output_request_id: str | None = None,
        conversation_output_hook_count: int = 0,
    ) -> uuid.UUID:
        """Persist the turn + append ``conversation.turn_completed`` atomically.

        Returns the ``turn_id`` THIS METHOD minted and inserted. The caller
        surfaces that exact id on the wire -- minting a fresh uuid downstream
        would name a row that does not exist.

        **Fenced.** ``claim_id`` must equal the conversation's CURRENT
        ``turn_claim_id``, verified under the row lock inside the same
        transaction as the insert. A worker whose lease was reclaimed after TTL
        expiry refuses ``conversation_turn_claim_stale`` and the transaction
        rolls back whole: no turn row, no chain row, no counter movement. TTL
        expiry alone is not mutual exclusion; this check is.

        **Graceful-close-aware, not state-agnostic.** A fenced turn settles
        while the conversation is ``active`` or gracefully ``closed`` (an
        already-admitted turn must land even if the conversation closed
        mid-flight). It refuses ``conversation_not_active`` when the row is
        ``expired`` or ``erased`` -- persisting plaintext there would resurrect
        content after a retention/erasure decision, and a valid lease does not
        override that lifecycle boundary (the ``_PERSISTABLE_STATES`` rule).
        This refusal fires AT PERSIST TIME, after the AgentLoop has run.
        """
        _validate_token_counts(prompt_tokens, completion_tokens)
        _validate_output_hook_correlation(
            request_id=conversation_output_request_id,
            hook_count=conversation_output_hook_count,
        )
        now = datetime.now(UTC)
        turn_id = uuid.uuid4()
        q_sha, q_bytes = _digest(user_message)
        a_sha, a_bytes = _digest(answer)

        async def _precondition(conn: AsyncConnection, _seq: int, _hash: bytes) -> None:
            await _require_persistable_claim(
                conn,
                conversation_id=conversation_id,
                tenant_id=tenant_id,
                claim_id=claim_id,
            )
            await conn.execute(
                sa.insert(_conversation_turns).values(
                    turn_id=turn_id,
                    conversation_id=conversation_id,
                    seq=seq,
                    user_message=user_message,
                    answer=answer,
                    agent_run_id=agent_run_id,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    created_at=now,
                    # Hop-1 correlation (0016): the chain row this transaction
                    # appends carries this SAME caller-minted request_id — one
                    # atomic commit; a duplicate rolls back turn AND chain row.
                    turn_completed_request_id=request_id,
                    approval_request_id=approval_request_id,
                    turn_kind=turn_kind,
                )
            )
            await conn.execute(
                update(_conversations)
                .where(
                    _conversations.c.conversation_id == conversation_id,
                    _conversations.c.tenant_id == tenant_id,
                )
                .values(
                    turn_count=_conversations.c.turn_count + 1,
                    cumulative_tokens=_conversations.c.cumulative_tokens
                    + prompt_tokens
                    + completion_tokens,
                    last_turn_at=now,
                )
            )

        def _build(_: None) -> DecisionRecord:
            payload: dict[str, Any] = {
                "conversation_id": str(conversation_id),
                "turn_id": str(turn_id),
                "seq": seq,
                "agent_run_id": agent_run_id,
                "question_sha256": q_sha,
                "question_bytes": q_bytes,
                "answer_sha256": a_sha,
                "answer_bytes": a_bytes,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
            }
            if conversation_output_request_id is not None:
                payload["conversation_output_request_id"] = conversation_output_request_id
                payload["conversation_output_hook_count"] = conversation_output_hook_count
            return DecisionRecord(
                decision_type="conversation.turn_completed",
                request_id=request_id,
                payload=payload,
                actor_id=actor_id,
                tenant_id=tenant_id,
                iso_controls=CONVERSATION_ISO_CONTROLS,
            )

        await self._history.append_with_precondition(
            record_builder=_build, precondition=_precondition
        )
        return turn_id

    async def settle_refused_turn(
        self,
        *,
        conversation_id: uuid.UUID,
        tenant_id: str,
        seq: int,
        question: str,
        answer: str,
        agent_run_id: str,
        prompt_tokens: int,
        completion_tokens: int,
        actor_id: str,
        request_id: str,
        claim_id: uuid.UUID,
        conversation_output_request_id: str | None = None,
        conversation_output_hook_count: int = 0,
    ) -> ConversationState:
        """Chain-atomically settle usage for one output-suppressed model turn.

        The model ran, so its token usage must count toward the conversation
        budget. The answer never shipped and therefore is not a transcript
        turn: no ``conversation_turns`` row is inserted and ``turn_count`` is
        deliberately unchanged. ``seq`` is the prospective physical sequence
        for the refused attempt; because no turn row is inserted, repeated
        refused attempts can truthfully carry the same prospective sequence.
        ``question`` is the screened loop input. ``answer`` is the original
        screened model output because F-S2a conversation phases admit only
        PASS/REFUSE. Plaintext is used only to derive sibling content digests
        in memory; neither value enters persistence or evidence. F-S3 must add
        transformation and the hook-aware examiner continuity contract
        together.
        """

        _validate_token_counts(prompt_tokens, completion_tokens)
        _validate_output_hook_correlation(
            request_id=conversation_output_request_id,
            hook_count=conversation_output_hook_count,
        )
        question_sha, question_bytes = _digest(question)
        answer_sha, answer_bytes = _digest(answer)

        settled_state: ConversationState | None = None

        async def _precondition(conn: AsyncConnection, _seq: int, _hash: bytes) -> None:
            nonlocal settled_state
            settled_state = await _require_persistable_claim(
                conn,
                conversation_id=conversation_id,
                tenant_id=tenant_id,
                claim_id=claim_id,
            )
            await conn.execute(
                update(_conversations)
                .where(
                    _conversations.c.conversation_id == conversation_id,
                    _conversations.c.tenant_id == tenant_id,
                )
                .values(
                    cumulative_tokens=_conversations.c.cumulative_tokens
                    + prompt_tokens
                    + completion_tokens
                )
            )

        def _build(_: None) -> DecisionRecord:
            payload: dict[str, Any] = {
                "conversation_id": str(conversation_id),
                "seq": seq,
                "agent_run_id": agent_run_id,
                "question_sha256": question_sha,
                "question_bytes": question_bytes,
                "answer_sha256": answer_sha,
                "answer_bytes": answer_bytes,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
            }
            if conversation_output_request_id is not None:
                payload["conversation_output_request_id"] = conversation_output_request_id
                payload["conversation_output_hook_count"] = conversation_output_hook_count
            return DecisionRecord(
                decision_type="conversation.turn_refused",
                request_id=request_id,
                payload=payload,
                actor_id=actor_id,
                tenant_id=tenant_id,
                iso_controls=CONVERSATION_ISO_CONTROLS,
            )

        await self._history.append_with_precondition(
            record_builder=_build,
            precondition=_precondition,
        )
        if settled_state is None:  # pragma: no cover - append contract violation
            raise RuntimeError("refused-turn precondition did not report the locked state")
        return settled_state

    async def append_system_turn(
        self,
        *,
        conversation_id: uuid.UUID,
        tenant_id: str,
        text: str,
        approval_request_id: str,
        actor_id: str,
        request_id: str,
        claim_id: uuid.UUID,
        conversation_output_request_id: str | None = None,
        conversation_output_hook_count: int = 0,
    ) -> uuid.UUID:
        """Persist a replay-excluded completion row + digest-only evidence.

        The row consumes a physical ``seq`` but changes neither ``turn_count``
        nor ``cumulative_tokens``; those are user/model budget counters.
        """
        now = datetime.now(UTC)
        _validate_output_hook_correlation(
            request_id=conversation_output_request_id,
            hook_count=conversation_output_hook_count,
        )
        turn_id = uuid.uuid4()
        answer_sha, answer_bytes = _digest(text)

        async def _precondition(conn: AsyncConnection, _seq: int, _hash: bytes) -> int:
            await _require_persistable_claim(
                conn,
                conversation_id=conversation_id,
                tenant_id=tenant_id,
                claim_id=claim_id,
            )
            latest = (
                await conn.execute(
                    select(sa.func.max(_conversation_turns.c.seq)).where(
                        _conversation_turns.c.conversation_id == conversation_id
                    )
                )
            ).scalar_one()
            physical_seq = int(latest or 0) + 1
            await conn.execute(
                sa.insert(_conversation_turns).values(
                    turn_id=turn_id,
                    conversation_id=conversation_id,
                    seq=physical_seq,
                    user_message=None,
                    answer=text,
                    agent_run_id=f"system-{approval_request_id}",
                    prompt_tokens=0,
                    completion_tokens=0,
                    created_at=now,
                    approval_request_id=approval_request_id,
                    turn_kind="system",
                    turn_completed_request_id=request_id,
                )
            )
            await conn.execute(
                update(_conversations)
                .where(
                    _conversations.c.conversation_id == conversation_id,
                    _conversations.c.tenant_id == tenant_id,
                )
                .values(last_turn_at=now)
            )
            return physical_seq

        def _build(physical_seq: int) -> DecisionRecord:
            payload: dict[str, Any] = {
                "conversation_id": str(conversation_id),
                "turn_id": str(turn_id),
                "seq": physical_seq,
                "agent_run_id": f"system-{approval_request_id}",
                "approval_request_id": approval_request_id,
                "answer_sha256": answer_sha,
                "answer_bytes": answer_bytes,
            }
            if conversation_output_request_id is not None:
                payload["conversation_output_request_id"] = conversation_output_request_id
                payload["conversation_output_hook_count"] = conversation_output_hook_count
            return DecisionRecord(
                decision_type="conversation.system_turn_appended",
                request_id=request_id,
                payload=payload,
                actor_id=actor_id,
                tenant_id=tenant_id,
                iso_controls=CONVERSATION_ISO_CONTROLS,
            )

        await self._history.append_with_precondition(
            record_builder=_build,
            precondition=_precondition,
        )
        return turn_id

    # -- erasure ---------------------------------------------------------------

    async def redact_turn(
        self,
        *,
        conversation_id: uuid.UUID,
        tenant_id: str,
        seq: int,
        actor_id: str,
        request_id: str,
    ) -> bool:
        """Erase one turn's values and append ``conversation.erased`` atomically.

        Compliance authority is tenant-wide: creator identity is deliberately
        not part of this predicate. Absent, cross-tenant and already-erased
        targets all return ``False`` without appending evidence. The retained
        row keeps identifiers, correlation and the original digest-only chain
        row intact.
        """
        now = datetime.now(UTC)

        async def _precondition(conn: AsyncConnection, _seq: int, _hash: bytes) -> None:
            tenant_match = sa.exists(
                select(1).where(
                    _conversations.c.conversation_id == conversation_id,
                    _conversations.c.tenant_id == tenant_id,
                )
            )
            result = await conn.execute(
                update(_conversation_turns)
                .where(
                    _conversation_turns.c.conversation_id == conversation_id,
                    _conversation_turns.c.seq == seq,
                    _conversation_turns.c.erased_at.is_(None),
                    tenant_match,
                )
                .values(
                    user_message=None,
                    answer=None,
                    erased_at=now,
                )
            )
            if result.rowcount != 1:
                raise _RedactionNotApplied

        def _build(_: None) -> DecisionRecord:
            return DecisionRecord(
                decision_type="conversation.erased",
                request_id=request_id,
                payload={
                    "conversation_id": str(conversation_id),
                    "scope": "turn",
                    "seq": seq,
                    "erased_turn_count": 1,
                },
                actor_id=actor_id,
                tenant_id=tenant_id,
                iso_controls=CONVERSATION_ISO_CONTROLS,
            )

        try:
            await self._history.append_with_precondition(
                record_builder=_build,
                precondition=_precondition,
            )
        except _RedactionNotApplied:
            return False
        return True

    async def redact_conversation(
        self,
        *,
        conversation_id: uuid.UUID,
        tenant_id: str,
        actor_id: str,
        request_id: str,
    ) -> bool:
        """Erase a conversation and all of its turn values atomically.

        Marking the parent ``erased`` in the same transaction is the
        resurrection fence: an already-admitted worker reaches
        :func:`_require_persistable_claim` before persistence and refuses. The
        parent UPDATE carries the tenant and ``erased_at IS NULL`` guards; a
        zero rowcount is the same absent/already-erased ``False`` result as the
        turn-scoped verb.
        """
        now = datetime.now(UTC)

        async def _precondition(conn: AsyncConnection, _seq: int, _hash: bytes) -> int:
            parent = await conn.execute(
                update(_conversations)
                .where(
                    _conversations.c.conversation_id == conversation_id,
                    _conversations.c.tenant_id == tenant_id,
                    _conversations.c.erased_at.is_(None),
                )
                .values(
                    state="erased",
                    erased_at=now,
                )
            )
            if parent.rowcount != 1:
                raise _RedactionNotApplied
            turns = await conn.execute(
                update(_conversation_turns)
                .where(
                    _conversation_turns.c.conversation_id == conversation_id,
                    _conversation_turns.c.erased_at.is_(None),
                )
                .values(
                    user_message=None,
                    answer=None,
                    erased_at=now,
                )
            )
            return int(turns.rowcount)

        def _build(erased_turn_count: int) -> DecisionRecord:
            return DecisionRecord(
                decision_type="conversation.erased",
                request_id=request_id,
                payload={
                    "conversation_id": str(conversation_id),
                    "scope": "conversation",
                    "erased_turn_count": erased_turn_count,
                },
                actor_id=actor_id,
                tenant_id=tenant_id,
                iso_controls=CONVERSATION_ISO_CONTROLS,
            )

        try:
            await self._history.append_with_precondition(
                record_builder=_build,
                precondition=_precondition,
            )
        except _RedactionNotApplied:
            return False
        return True

    # -- lifecycle -------------------------------------------------------------

    async def transition(
        self,
        *,
        conversation_id: uuid.UUID,
        tenant_id: str,
        to_state: ConversationState,
        actor_id: str,
        request_id: str,
    ) -> tuple[uuid.UUID, bytes]:
        """State-machine transition (tenant-scoped, atomic).

        Preflight: ``to_state`` must be a known transition target, refused
        BEFORE any DB work. ``from_state`` is NOT a parameter -- the
        precondition reads it under the row lock and PROJECTS it to the record
        builder, so the chain row records the locked truth and a caller's stale
        read can never enter evidence.

        **Graceful close.** Closing blocks NEW turns but does NOT cancel work
        already admitted: any in-flight claim is preserved, the running executor
        settles its turn (``append_turn`` persists while the row is in
        ``_PERSISTABLE_STATES`` -- ``active`` or ``closed``; ``expired`` /
        ``erased`` refuse to prevent resurrection) and releases the claim in its
        own ``finally``. ``close`` is not an emergency cancel. New turns are
        then refused at :meth:`claim_turn` with ``conversation_not_active`` --
        the state check precedes the claim check, so a preserved claim never
        blocks the refusal.
        """
        if to_state not in _STATE_TO_DECISION_TYPE:
            raise ConversationTransitionRefused("conversation_transition_invalid_state_pair")
        decision_type = _STATE_TO_DECISION_TYPE[to_state]

        async def _precondition(
            conn: AsyncConnection, _seq: int, _hash: bytes
        ) -> ConversationState:
            row = (
                await conn.execute(
                    select(_conversations.c.state)
                    .where(
                        _conversations.c.conversation_id == conversation_id,
                        _conversations.c.tenant_id == tenant_id,
                    )
                    .with_for_update()
                )
            ).first()
            if row is None:
                raise ConversationNotFound(str(conversation_id))
            from_state: ConversationState = row[0]
            validate_transition(from_state=from_state, to_state=to_state)
            # GRACEFUL CLOSE (ruled 2026-07-09): the claim is deliberately NOT
            # cleared here. Closing blocks NEW turns; it does not cancel work
            # already admitted. An in-flight executor keeps its claim and
            # releases it in its own ``finally``. Clearing it here would make the
            # store forget that a turn was still running -- and a subsequent
            # crash would leave no trace of the in-flight work. ``close`` is NOT
            # an emergency cancel; the M8.5-F kill path is a separate primitive.
            await conn.execute(
                update(_conversations)
                .where(_conversations.c.conversation_id == conversation_id)
                .values(state=to_state)
            )
            return from_state

        def _build(from_state: ConversationState) -> DecisionRecord:
            return DecisionRecord(
                decision_type=decision_type,
                request_id=request_id,
                payload={
                    "conversation_id": str(conversation_id),
                    "from_state": from_state,
                    "to_state": to_state,
                },
                actor_id=actor_id,
                tenant_id=tenant_id,
                iso_controls=CONVERSATION_ISO_CONTROLS,
            )

        return await self._history.append_with_precondition(
            record_builder=_build, precondition=_precondition
        )


def _as_aware(value: datetime) -> datetime:
    """sqlite returns naive datetimes; Postgres/Oracle return aware ones.

    The claim comparison must not raise on a naive value, so normalise to UTC.
    """
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
