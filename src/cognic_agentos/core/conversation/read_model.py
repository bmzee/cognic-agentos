"""ADR-028 M8.5-B — the conversation read model (HP-1).

CRITICAL CONTROLS. Three enforcement boundaries live here:

1. **Tenant + creator isolation.** Every read resolves the conversation with
   ``WHERE tenant_id = :t AND creator_subject = :s`` FIRST; absent,
   cross-tenant and cross-actor all read as ``None`` and the route collapses
   them to a 404 byte-identical to a genuine not-found. The chain read
   touches ``decision_history`` only AFTER that gate, and every evidence
   query carries a tenant predicate besides.

2. **Bounded, index-addressable evidence queries — never an unbounded
   ``decision_history`` scan.** Hop 1 rides the 0016 correlation column
   through the 0001 ``request_id`` index; the run anchors ride deterministic
   ``{run_id}-started`` / ``{run_id}-terminal`` request ids; hop 3 rides the
   0016 ``(tenant_id, event_type, sequence)`` index between the anchor
   sequences with a configured candidate cap. ``payload`` is verification
   INSIDE a bounded window, never the access path (Oracle CLOB — no portable
   JSON index).

3. **Chain integrity is corruption, not unavailability.** A persisted turn's
   evidence rows are written BEFORE the turn commits and the chain is
   append-only — so missing / duplicated / malformed / mismatched /
   misordered anchors raise :class:`ConversationChainIntegrityError`
   (generic on the wire, detailed internal reason for operator logs).
   Exceeding the candidate cap raises the DISTINCT
   :class:`ConversationChainProjectionLimit` (operator remediation or a
   higher configured limit — not corruption, and not automatically
   retryable).

Cursors are UNSIGNED and NON-AUTHORITATIVE: they carry presentation position
only — every request re-binds tenant/creator in the WHERE clause, so a
re-encoded cursor can never widen visibility. Malformed encoding, wrong
version, invalid types, impossible bounds, filter mismatch and
cross-conversation reuse all raise :class:`CursorInvalid` (422).

Projections are CURATED per-key — raw chain payloads and chain hashes are
never exposed (hash packaging is ``conversation.export``, M8.5-F).
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Literal, NoReturn

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.core.conversation._types import ConversationState
from cognic_agentos.core.conversation.storage import (
    _conversation_turns,
    _conversations,
)
from cognic_agentos.core.decision_history import _decision_history

#: Pagination bounds (both endpoints).
PAGE_LIMIT_DEFAULT: Final[int] = 50
PAGE_LIMIT_MAX: Final[int] = 200

_CURSOR_VERSION: Final[int] = 1

_STATE_VOCAB: Final[frozenset[str]] = frozenset({"active", "closed", "expired", "erased"})

#: The four legal terminal event types (loop.py `_finish`).
_TERMINAL_EVENT_TYPES: Final[frozenset[str]] = frozenset(
    {
        "agent.run.completed",
        "agent.run.refused",
        "agent.run.failed",
        "agent.run.pending_approval",
    }
)

#: Internal (log-only) integrity reasons — the wire stays generic.
ChainIntegrityReason = Literal[
    "hop1_missing",
    "hop1_duplicated",
    "hop1_malformed",
    "hop1_mismatch",
    "anchor_missing",
    "anchor_duplicated",
    "anchor_malformed",
    "anchor_mismatch",
    "anchor_misordered",
    "dual_identity_mismatch",
]


class CursorInvalid(Exception):
    """Malformed / wrong-version / invalid-type / impossible-bounds /
    filter-mismatched / cross-conversation cursor. Route maps to 422."""


class TurnNotFound(Exception):
    """The conversation IS owned but the seq lies beyond ``1..turn_count``.
    Owner-visible only — ownership failures collapse to the byte-identical
    conversation 404 upstream of this, and an ABSENT row INSIDE the
    watermark is never this exception: the record claims that turn exists,
    so it raises :class:`ConversationTranscriptIntegrityError` instead."""


class ConversationTranscriptIntegrityError(Exception):
    """A gap inside ``1..watermark``: turns are appended with contiguous
    seqs under a single-writer claim, so a hole is corruption."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class ConversationChainIntegrityError(Exception):
    """Chain evidence for a persisted turn is defective. Generic on the
    wire; ``internal_reason`` + ``detail`` are for operator logs only."""

    def __init__(self, internal_reason: ChainIntegrityReason, detail: str) -> None:
        super().__init__(f"{internal_reason}: {detail}")
        self.internal_reason: ChainIntegrityReason = internal_reason
        self.detail = detail


class ConversationChainProjectionLimit(Exception):
    """The dispatch-window candidate fetch exceeded the configured cap.
    OPERATIONAL, distinct from corruption: served as 503, and the SAME
    request succeeds again once an operator raises
    ``conversation_chain_candidate_limit`` — clients gain nothing by
    retrying before that remediation."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


def _integrity(reason: ChainIntegrityReason, detail: str) -> NoReturn:
    raise ConversationChainIntegrityError(reason, detail)


# ---------------------------------------------------------------------------
# Cursor codecs — unsigned, non-authoritative, strictly validated.
# ---------------------------------------------------------------------------


def _encode_cursor(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _decode_cursor(cursor: str) -> dict[str, Any]:
    try:
        # validate=True: STRICT alphabet — urlsafe_b64decode silently discards
        # non-alphabet bytes, so a tampered cursor with trailing garbage would
        # otherwise decode to the untampered payload.
        raw = base64.b64decode(cursor.encode("ascii"), altchars=b"-_", validate=True)
        decoded = json.loads(raw)
    except (ValueError, binascii.Error, UnicodeDecodeError) as exc:
        raise CursorInvalid("cursor is not base64url(JSON)") from exc
    if not isinstance(decoded, dict):
        raise CursorInvalid("cursor payload is not an object")
    version = decoded.get("v")
    # bool-guarded exact int: JSON true == 1 in Python and would impersonate
    # version 1.
    if not isinstance(version, int) or isinstance(version, bool) or version != _CURSOR_VERSION:
        raise CursorInvalid(f"unsupported cursor version {version!r}")
    return decoded


@dataclass(frozen=True, slots=True)
class _ListCursor:
    created_at: datetime
    conversation_id: uuid.UUID
    state: ConversationState | None


def _decode_list_cursor(cursor: str) -> _ListCursor:
    decoded = _decode_cursor(cursor)
    created_raw, cid_raw, state = (
        decoded.get("created_at"),
        decoded.get("conversation_id"),
        decoded.get("state"),
    )
    if not isinstance(created_raw, str) or not isinstance(cid_raw, str):
        raise CursorInvalid("list cursor fields have invalid types")
    try:
        created_at = datetime.fromisoformat(created_raw)
        conversation_id = uuid.UUID(cid_raw)
    except ValueError as exc:
        raise CursorInvalid("list cursor carries an unparseable position") from exc
    # tz-aware or refused: a naive timestamp compared against the tz-aware
    # created_at column is a dialect-level error (a 500), not a keyset.
    if created_at.tzinfo is None or created_at.tzinfo.utcoffset(created_at) is None:
        raise CursorInvalid("list cursor timestamp must be timezone-aware")
    if state is not None and state not in _STATE_VOCAB:
        raise CursorInvalid(f"list cursor carries an unknown state filter {state!r}")
    return _ListCursor(created_at=created_at, conversation_id=conversation_id, state=state)


@dataclass(frozen=True, slots=True)
class _TranscriptCursor:
    conversation_id: uuid.UUID
    watermark: int
    after_seq: int


def _decode_transcript_cursor(cursor: str, *, conversation_id: uuid.UUID) -> _TranscriptCursor:
    decoded = _decode_cursor(cursor)
    cid_raw, watermark, after_seq = (
        decoded.get("conversation_id"),
        decoded.get("watermark"),
        decoded.get("after_seq"),
    )
    if not isinstance(cid_raw, str):
        raise CursorInvalid("transcript cursor conversation_id has an invalid type")
    for name, value in (("watermark", watermark), ("after_seq", after_seq)):
        if not isinstance(value, int) or isinstance(value, bool):
            raise CursorInvalid(f"transcript cursor {name} has an invalid type")
    try:
        cursor_cid = uuid.UUID(cid_raw)
    except ValueError as exc:
        raise CursorInvalid("transcript cursor carries a non-UUID conversation_id") from exc
    if cursor_cid != conversation_id:
        raise CursorInvalid("transcript cursor belongs to a different conversation")
    # Precision locks (2026-07-10): watermark must be positive and the
    # continuation must satisfy 0 <= after_seq < watermark.
    assert isinstance(watermark, int) and isinstance(after_seq, int)
    if watermark <= 0:
        raise CursorInvalid("transcript cursor watermark must be positive")
    if after_seq < 0 or after_seq >= watermark:
        raise CursorInvalid("transcript cursor after_seq is out of bounds")
    return _TranscriptCursor(conversation_id=cursor_cid, watermark=watermark, after_seq=after_seq)


# ---------------------------------------------------------------------------
# Curated projections (frozen; never raw payload dicts, never chain hashes).
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConversationSummary:
    conversation_id: uuid.UUID
    agent_id: str
    state: ConversationState
    turn_count: int
    cumulative_tokens: int
    created_at: datetime
    last_turn_at: datetime | None


@dataclass(frozen=True, slots=True)
class ListPage:
    items: tuple[ConversationSummary, ...]
    next_cursor: str | None


@dataclass(frozen=True, slots=True)
class TranscriptTurn:
    turn_id: uuid.UUID
    seq: int
    user_message: str | None
    answer: str | None
    agent_run_id: str
    prompt_tokens: int
    completion_tokens: int
    created_at: datetime
    erased_at: datetime | None
    approval_request_id: str | None = None
    turn_kind: Literal["exchange", "system"] = "exchange"


@dataclass(frozen=True, slots=True)
class TranscriptPage:
    conversation: ConversationSummary
    turns: tuple[TranscriptTurn, ...]
    watermark: int
    next_cursor: str | None


@dataclass(frozen=True, slots=True)
class TurnCompletedProjection:
    sequence: int
    created_at: datetime
    turn_id: uuid.UUID
    seq: int
    agent_run_id: str
    actor_id: str
    question_sha256: str
    question_bytes: int
    answer_sha256: str
    answer_bytes: int
    prompt_tokens: int
    completion_tokens: int


@dataclass(frozen=True, slots=True)
class RunStartedProjection:
    sequence: int
    created_at: datetime
    run_id: str
    agent_id: str
    actor_id: str
    originator_subject: str
    question_sha256: str
    question_bytes: int
    max_steps: int
    token_budget: int
    wall_clock_s: float
    prior_context_turns: int
    prior_context_sha256: str


@dataclass(frozen=True, slots=True)
class RunTerminalProjection:
    sequence: int
    created_at: datetime
    terminal_state: str
    answer_sha256: str
    answer_bytes: int
    steps_used: int
    prompt_tokens_total: int
    completion_tokens_total: int
    refusal_reason: str | None
    bound: str | None
    error_class: str | None


@dataclass(frozen=True, slots=True)
class DispatchProjection:
    sequence: int
    step_index: int
    capability_kind: str
    capability_ref: str
    scope_id: str | None
    outcome: str
    refusal_reason: str | None
    args_sha256: str | None
    result_sha256: str | None
    result_bytes: int | None


@dataclass(frozen=True, slots=True)
class TurnChainJoin:
    turn_completed: TurnCompletedProjection
    started: RunStartedProjection
    terminal: RunTerminalProjection
    dispatches: tuple[DispatchProjection, ...]


# ---------------------------------------------------------------------------
# Shared statement builders (the SQL-shape regressions import these — the
# packs `_build_list_for_tenant_stmt` precedent).
# ---------------------------------------------------------------------------


def _build_list_stmt(
    *,
    tenant_id: str,
    creator_subject: str,
    state: ConversationState | None,
    after: _ListCursor | None,
    limit_plus_one: int,
) -> sa.Select[Any]:
    stmt = (
        sa.select(_conversations)
        .where(
            _conversations.c.tenant_id == tenant_id,
            _conversations.c.creator_subject == creator_subject,
        )
        .order_by(_conversations.c.created_at.desc(), _conversations.c.conversation_id.desc())
        .limit(limit_plus_one)
    )
    if state is not None:
        stmt = stmt.where(_conversations.c.state == state)
    if after is not None:
        # Portable keyset (Oracle lacks general row-value comparison).
        stmt = stmt.where(
            sa.or_(
                _conversations.c.created_at < after.created_at,
                sa.and_(
                    _conversations.c.created_at == after.created_at,
                    _conversations.c.conversation_id < after.conversation_id,
                ),
            )
        )
    return stmt


def _build_transcript_stmt(
    *, conversation_id: uuid.UUID, after_seq: int, watermark: int, limit_plus_one: int
) -> sa.Select[Any]:
    return (
        sa.select(_conversation_turns)
        .where(
            _conversation_turns.c.conversation_id == conversation_id,
            _conversation_turns.c.seq > after_seq,
            _conversation_turns.c.seq <= watermark,
        )
        .order_by(_conversation_turns.c.seq.asc())
        .limit(limit_plus_one)
    )


def _build_chain_row_stmt(*, request_id: str, tenant_id: str) -> sa.Select[Any]:
    """An exact-match anchor lookup — index-addressable via the 0001
    ``ix_decision_history_request_id``; tenant-scoped besides. LIMIT 2:
    ``request_id`` is non-unique, so a corrupt duplicate set must not be
    able to consume unbounded memory before the duplicate check — two rows
    are exactly enough to distinguish missing / unique / duplicated."""
    return (
        sa.select(_decision_history)
        .where(
            _decision_history.c.request_id == request_id,
            _decision_history.c.tenant_id == tenant_id,
        )
        .limit(2)
    )


def _build_dispatch_window_stmt(
    *, tenant_id: str, seq_start: int, seq_end: int, limit_plus_one: int
) -> sa.Select[Any]:
    """The bounded hop-3 window — rides the 0016
    ``(tenant_id, event_type, sequence)`` index; ``payload.run_id`` is
    verified in Python INSIDE this window, never used as the access path."""
    return (
        sa.select(_decision_history)
        .where(
            _decision_history.c.tenant_id == tenant_id,
            _decision_history.c.event_type == "agent.run.dispatch",
            _decision_history.c.sequence > seq_start,
            _decision_history.c.sequence < seq_end,
        )
        .order_by(_decision_history.c.sequence.asc())
        .limit(limit_plus_one)
    )


def _mint_aware_utc(value: datetime) -> datetime:
    """The write path persists tz-aware UTC; drivers without tz storage
    (sqlite) hand the same instant back naive — normalize at cursor-mint
    time so the strict aware-required decode holds on every dialect."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def _clamp_limit(limit: int | None) -> int:
    if limit is None:
        return PAGE_LIMIT_DEFAULT
    return max(1, min(limit, PAGE_LIMIT_MAX))


def _payload_str(payload: dict[str, Any], key: str, *, where: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        _integrity(
            "anchor_malformed" if where != "hop1" else "hop1_malformed",
            f"{where}: payload key {key!r} missing or non-string",
        )
    return value


_SHA256_HEX: Final = re.compile(r"[0-9a-f]{64}")


def _payload_sha256(payload: dict[str, Any], key: str, *, where: str) -> str:
    """A REQUIRED lowercase 64-hex SHA-256 payload field. ``str`` alone is
    not evidence — a tampered ``question_sha256=\"x\"`` must refuse as
    corruption, never project as a valid digest."""
    value = _payload_str(payload, key, where=where)
    if _SHA256_HEX.fullmatch(value) is None:
        _integrity(
            "anchor_malformed" if where != "hop1" else "hop1_malformed",
            f"{where}: payload key {key!r} is not a lowercase 64-hex sha256",
        )
    return value


def _payload_int(payload: dict[str, Any], key: str, *, where: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        _integrity(
            "anchor_malformed" if where != "hop1" else "hop1_malformed",
            f"{where}: payload key {key!r} missing or non-int",
        )
    return value


class ConversationReadModel:
    """Async read-only surface; raises on every refusal/failure."""

    def __init__(self, engine: AsyncEngine, *, chain_candidate_limit: int) -> None:
        if chain_candidate_limit <= 0:
            raise ValueError("chain_candidate_limit must be positive")
        self._engine = engine
        self._chain_candidate_limit = chain_candidate_limit

    # -- the isolation gate ------------------------------------------------------

    async def _load_owned(
        self, conversation_id: uuid.UUID, *, tenant_id: str, creator_subject: str
    ) -> Any | None:
        stmt = sa.select(_conversations).where(
            _conversations.c.conversation_id == conversation_id,
            _conversations.c.tenant_id == tenant_id,
            _conversations.c.creator_subject == creator_subject,
        )
        async with self._engine.connect() as conn:
            return (await conn.execute(stmt)).mappings().first()

    # -- list ---------------------------------------------------------------------

    async def list_conversations(
        self,
        *,
        tenant_id: str,
        creator_subject: str,
        limit: int | None = None,
        state: ConversationState | None = None,
        cursor: str | None = None,
    ) -> ListPage:
        page_size = _clamp_limit(limit)
        after: _ListCursor | None = None
        effective_state = state
        if cursor is not None:
            after = _decode_list_cursor(cursor)
            # The filter is BOUND INTO the cursor: a continuation passing a
            # DIFFERENT state param is a mismatched cursor, not a new query.
            if state is not None and state != after.state:
                raise CursorInvalid("cursor state filter does not match the request")
            effective_state = after.state
        stmt = _build_list_stmt(
            tenant_id=tenant_id,
            creator_subject=creator_subject,
            state=effective_state,
            after=after,
            limit_plus_one=page_size + 1,
        )
        async with self._engine.connect() as conn:
            rows = (await conn.execute(stmt)).mappings().all()
        has_more = len(rows) > page_size
        page = rows[:page_size]
        items = tuple(
            ConversationSummary(
                conversation_id=row["conversation_id"],
                agent_id=row["agent_id"],
                state=row["state"],
                turn_count=row["turn_count"],
                cumulative_tokens=row["cumulative_tokens"],
                created_at=row["created_at"],
                last_turn_at=row["last_turn_at"],
            )
            for row in page
        )
        next_cursor: str | None = None
        if has_more and page:
            last = page[-1]
            next_cursor = _encode_cursor(
                {
                    "v": _CURSOR_VERSION,
                    "created_at": _mint_aware_utc(last["created_at"]).isoformat(),
                    "conversation_id": str(last["conversation_id"]),
                    "state": effective_state,
                }
            )
        return ListPage(items=items, next_cursor=next_cursor)

    # -- transcript -----------------------------------------------------------------

    async def read_transcript(
        self,
        conversation_id: uuid.UUID,
        *,
        tenant_id: str,
        creator_subject: str,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> TranscriptPage | None:
        row = await self._load_owned(
            conversation_id, tenant_id=tenant_id, creator_subject=creator_subject
        )
        if row is None:
            return None
        page_size = _clamp_limit(limit)
        if cursor is not None:
            decoded = _decode_transcript_cursor(cursor, conversation_id=conversation_id)
            # turn_count never decreases; a watermark above it is impossible.
            if decoded.watermark > row["turn_count"]:
                raise CursorInvalid("transcript cursor watermark exceeds the conversation")
            watermark, after_seq = decoded.watermark, decoded.after_seq
        else:
            watermark, after_seq = row["turn_count"], 0

        summary = ConversationSummary(
            conversation_id=row["conversation_id"],
            agent_id=row["agent_id"],
            state=row["state"],
            turn_count=row["turn_count"],
            cumulative_tokens=row["cumulative_tokens"],
            created_at=row["created_at"],
            last_turn_at=row["last_turn_at"],
        )
        if watermark == 0:
            # An empty conversation mints NO cursor (precision lock).
            return TranscriptPage(conversation=summary, turns=(), watermark=0, next_cursor=None)

        stmt = _build_transcript_stmt(
            conversation_id=conversation_id,
            after_seq=after_seq,
            watermark=watermark,
            limit_plus_one=page_size + 1,
        )
        async with self._engine.connect() as conn:
            turn_rows = (await conn.execute(stmt)).mappings().all()
        has_more = len(turn_rows) > page_size
        page = turn_rows[:page_size]

        # Contiguity over EVERY fetched row — the limit+1 probe row included:
        # with stored seqs (1, 3) and limit=1 the gap is already visible in
        # the probe, and paging past it would hand out a cursor into
        # corruption. The rows must be exactly after_seq+1 .. after_seq+n,
        # and when the probe row is absent the page must END at the
        # watermark — a hole inside 1..watermark is corruption
        # (single-writer contiguous seqs), never a shorter page.
        expected = after_seq
        for turn_row in turn_rows:
            expected += 1
            if turn_row["seq"] != expected:
                raise ConversationTranscriptIntegrityError(
                    f"conversation {conversation_id}: expected seq {expected}, "
                    f"found {turn_row['seq']} (gap inside 1..{watermark})"
                )
        last_returned = after_seq + len(page)
        if not has_more and last_returned != watermark:
            raise ConversationTranscriptIntegrityError(
                f"conversation {conversation_id}: transcript ends at seq {last_returned}, "
                f"watermark is {watermark} (missing tail)"
            )

        turns = tuple(
            TranscriptTurn(
                turn_id=turn_row["turn_id"],
                seq=turn_row["seq"],
                user_message=turn_row["user_message"],
                answer=turn_row["answer"],
                agent_run_id=turn_row["agent_run_id"],
                prompt_tokens=turn_row["prompt_tokens"],
                completion_tokens=turn_row["completion_tokens"],
                created_at=turn_row["created_at"],
                erased_at=turn_row["erased_at"],
                approval_request_id=turn_row["approval_request_id"],
                turn_kind=turn_row["turn_kind"],
            )
            for turn_row in page
        )
        next_cursor = (
            _encode_cursor(
                {
                    "v": _CURSOR_VERSION,
                    "conversation_id": str(conversation_id),
                    "watermark": watermark,
                    "after_seq": last_returned,
                }
            )
            if has_more
            else None
        )
        return TranscriptPage(
            conversation=summary, turns=turns, watermark=watermark, next_cursor=next_cursor
        )

    # -- the chain join ---------------------------------------------------------------

    async def read_turn_chain(
        self,
        conversation_id: uuid.UUID,
        seq: int,
        *,
        tenant_id: str,
        creator_subject: str,
    ) -> TurnChainJoin | None:
        row = await self._load_owned(
            conversation_id, tenant_id=tenant_id, creator_subject=creator_subject
        )
        if row is None:
            return None
        if seq < 1 or seq > row["turn_count"]:
            raise TurnNotFound(f"seq {seq} outside 1..{row['turn_count']}")
        turn_stmt = sa.select(_conversation_turns).where(
            _conversation_turns.c.conversation_id == conversation_id,
            _conversation_turns.c.seq == seq,
        )
        async with self._engine.connect() as conn:
            turn = (await conn.execute(turn_stmt)).mappings().first()
            if turn is None:
                # seq passed the 1..turn_count guard above, so the record
                # CLAIMS this turn exists — a missing row inside the
                # watermark is a transcript-store gap (integrity 500),
                # never the owner-visible turn_not_found 404.
                raise ConversationTranscriptIntegrityError(
                    f"conversation {conversation_id}: turn row seq {seq} missing "
                    f"inside 1..{row['turn_count']}"
                )
            hop1_rows = (
                (
                    await conn.execute(
                        _build_chain_row_stmt(
                            request_id=turn["turn_completed_request_id"], tenant_id=tenant_id
                        )
                    )
                )
                .mappings()
                .all()
            )
            run_id: str = turn["agent_run_id"]
            started_rows = (
                (
                    await conn.execute(
                        _build_chain_row_stmt(request_id=f"{run_id}-started", tenant_id=tenant_id)
                    )
                )
                .mappings()
                .all()
            )
            terminal_rows = (
                (
                    await conn.execute(
                        _build_chain_row_stmt(request_id=f"{run_id}-terminal", tenant_id=tenant_id)
                    )
                )
                .mappings()
                .all()
            )

            hop1 = self._validate_hop1(hop1_rows, turn=turn, row=row, run_id=run_id)
            started = self._validate_started(started_rows, row=row, run_id=run_id)
            terminal = self._validate_terminal(terminal_rows, row=row, run_id=run_id)

            # Ordering: started < terminal < hop1 (the turn persists AFTER
            # the run settles).
            if not (started.sequence < terminal.sequence < hop1.sequence):
                _integrity(
                    "anchor_misordered",
                    f"run {run_id}: started seq {started.sequence}, terminal seq "
                    f"{terminal.sequence}, turn_completed seq {hop1.sequence}",
                )

            # Cross-block digest coupling: the started row digests the SAME
            # question and the terminal row the SAME answer the turn row
            # recorded — a joined chain whose anchors disagree on content is
            # corruption, not evidence.
            if started.question_sha256 != hop1.question_sha256:
                _integrity(
                    "anchor_mismatch",
                    f"run {run_id}: started question_sha256 disagrees with the turn row",
                )
            if terminal.answer_sha256 != hop1.answer_sha256:
                _integrity(
                    "anchor_mismatch",
                    f"run {run_id}: terminal answer_sha256 disagrees with the turn row",
                )

            cap = self._chain_candidate_limit
            window = (
                (
                    await conn.execute(
                        _build_dispatch_window_stmt(
                            tenant_id=tenant_id,
                            seq_start=started.sequence,
                            seq_end=terminal.sequence,
                            limit_plus_one=cap + 1,
                        )
                    )
                )
                .mappings()
                .all()
            )
        if len(window) > cap:
            raise ConversationChainProjectionLimit(
                f"run {run_id}: dispatch-window candidates exceed the configured "
                f"limit ({cap}) between sequences {started.sequence}..{terminal.sequence}"
            )
        dispatches = self._project_dispatches(window, row=row, run_id=run_id)
        return TurnChainJoin(
            turn_completed=hop1, started=started, terminal=terminal, dispatches=dispatches
        )

    # -- per-event validation + projection (event-specific identity rules) --------

    def _validate_hop1(
        self, rows: Sequence[Any], *, turn: Any, row: Any, run_id: str
    ) -> TurnCompletedProjection:
        if not rows:
            _integrity("hop1_missing", f"turn {turn['turn_id']}: no turn_completed chain row")
        if len(rows) > 1:
            _integrity(
                "hop1_duplicated",
                f"turn {turn['turn_id']}: {len(rows)} rows share the correlation id",
            )
        chain = rows[0]
        if chain["event_type"] != "conversation.turn_completed":
            _integrity(
                "hop1_mismatch",
                f"correlation id resolves to event_type {chain['event_type']!r}",
            )
        payload = chain["payload"]
        if not isinstance(payload, dict):
            _integrity("hop1_malformed", "turn_completed payload is not an object")
        # Hop-1 identity: conversation / turn / run / actor (precision lock).
        if (
            _payload_str(payload, "conversation_id", where="hop1") != str(row["conversation_id"])
            or _payload_str(payload, "turn_id", where="hop1") != str(turn["turn_id"])
            or _payload_int(payload, "seq", where="hop1") != turn["seq"]
            or _payload_str(payload, "agent_run_id", where="hop1") != run_id
        ):
            _integrity("hop1_mismatch", f"turn {turn['turn_id']}: payload tuple disagrees")
        actor = _payload_str(payload, "actor_id", where="hop1")
        if actor != row["creator_subject"]:
            _integrity(
                "dual_identity_mismatch",
                f"hop1 actor_id {actor!r} != creator {row['creator_subject']!r}",
            )
        return TurnCompletedProjection(
            sequence=chain["sequence"],
            created_at=chain["created_at"],
            turn_id=turn["turn_id"],
            seq=turn["seq"],
            agent_run_id=run_id,
            actor_id=actor,
            question_sha256=_payload_sha256(payload, "question_sha256", where="hop1"),
            question_bytes=_payload_int(payload, "question_bytes", where="hop1"),
            answer_sha256=_payload_sha256(payload, "answer_sha256", where="hop1"),
            answer_bytes=_payload_int(payload, "answer_bytes", where="hop1"),
            prompt_tokens=_payload_int(payload, "prompt_tokens", where="hop1"),
            completion_tokens=_payload_int(payload, "completion_tokens", where="hop1"),
        )

    def _run_row_identity(
        self, payload: dict[str, Any], *, row: Any, run_id: str, where: str
    ) -> None:
        """Run + dispatch rows validate run_id, agent_id, originator_subject
        AND the persisted ``actor_id`` (precision lock: event-specific
        identity — ``actor_id == originator_subject == creator_subject``;
        ``DecisionRecord.actor_id`` merges into the payload at append)."""
        if _payload_str(payload, "run_id", where=where) != run_id:
            _integrity("anchor_mismatch", f"{where}: payload run_id disagrees")
        agent_id = _payload_str(payload, "agent_id", where=where)
        if agent_id != row["agent_id"]:
            _integrity(
                "dual_identity_mismatch",
                f"{where}: agent_id {agent_id!r} != conversation agent {row['agent_id']!r}",
            )
        originator = _payload_str(payload, "originator_subject", where=where)
        if originator != row["creator_subject"]:
            _integrity(
                "dual_identity_mismatch",
                f"{where}: originator {originator!r} != creator {row['creator_subject']!r}",
            )
        actor = _payload_str(payload, "actor_id", where=where)
        if actor != row["creator_subject"]:
            _integrity(
                "dual_identity_mismatch",
                f"{where}: actor_id {actor!r} != creator {row['creator_subject']!r}",
            )

    def _validate_started(
        self, rows: Sequence[Any], *, row: Any, run_id: str
    ) -> RunStartedProjection:
        if not rows:
            _integrity("anchor_missing", f"run {run_id}: no agent.run.started row")
        if len(rows) > 1:
            _integrity("anchor_duplicated", f"run {run_id}: {len(rows)} started rows")
        chain = rows[0]
        if chain["event_type"] != "agent.run.started":
            _integrity(
                "anchor_mismatch",
                f"started anchor resolves to event_type {chain['event_type']!r}",
            )
        payload = chain["payload"]
        if not isinstance(payload, dict):
            _integrity("anchor_malformed", "started payload is not an object")
        self._run_row_identity(payload, row=row, run_id=run_id, where="started")
        token_budget = _payload_int(payload, "token_budget", where="started")
        wall_clock = payload.get("wall_clock_s")
        if not isinstance(wall_clock, (int, float)) or isinstance(wall_clock, bool):
            _integrity("anchor_malformed", "started: wall_clock_s missing or non-numeric")
        return RunStartedProjection(
            sequence=chain["sequence"],
            created_at=chain["created_at"],
            run_id=run_id,
            agent_id=row["agent_id"],
            # The persisted, validated values (never the conversation row
            # substituted): _run_row_identity proved both == creator_subject.
            actor_id=_payload_str(payload, "actor_id", where="started"),
            originator_subject=_payload_str(payload, "originator_subject", where="started"),
            question_sha256=_payload_sha256(payload, "question_sha256", where="started"),
            question_bytes=_payload_int(payload, "question_bytes", where="started"),
            max_steps=_payload_int(payload, "max_steps", where="started"),
            token_budget=token_budget,
            wall_clock_s=float(wall_clock),
            prior_context_turns=_payload_int(payload, "prior_context_turns", where="started"),
            prior_context_sha256=_payload_sha256(payload, "prior_context_sha256", where="started"),
        )

    def _validate_terminal(
        self, rows: Sequence[Any], *, row: Any, run_id: str
    ) -> RunTerminalProjection:
        if not rows:
            _integrity("anchor_missing", f"run {run_id}: no terminal row")
        if len(rows) > 1:
            _integrity("anchor_duplicated", f"run {run_id}: {len(rows)} terminal rows")
        chain = rows[0]
        if chain["event_type"] not in _TERMINAL_EVENT_TYPES:
            _integrity(
                "anchor_mismatch",
                f"terminal anchor resolves to event_type {chain['event_type']!r}",
            )
        payload = chain["payload"]
        if not isinstance(payload, dict):
            _integrity("anchor_malformed", "terminal payload is not an object")
        self._run_row_identity(payload, row=row, run_id=run_id, where="terminal")
        refusal_reason = payload.get("refusal_reason")
        bound = payload.get("bound")
        error_class = payload.get("error_class")
        for name, value in (
            ("refusal_reason", refusal_reason),
            ("bound", bound),
            ("error_class", error_class),
        ):
            if value is not None and not isinstance(value, str):
                _integrity("anchor_malformed", f"terminal: {name} is non-string")
        return RunTerminalProjection(
            sequence=chain["sequence"],
            created_at=chain["created_at"],
            terminal_state=chain["event_type"].removeprefix("agent.run."),
            answer_sha256=_payload_sha256(payload, "answer_sha256", where="terminal"),
            answer_bytes=_payload_int(payload, "answer_bytes", where="terminal"),
            steps_used=_payload_int(payload, "steps_used", where="terminal"),
            prompt_tokens_total=_payload_int(payload, "prompt_tokens_total", where="terminal"),
            completion_tokens_total=_payload_int(
                payload, "completion_tokens_total", where="terminal"
            ),
            refusal_reason=refusal_reason,
            bound=bound,
            error_class=error_class,
        )

    def _project_dispatches(
        self, window: Sequence[Any], *, row: Any, run_id: str
    ) -> tuple[DispatchProjection, ...]:
        projected: list[DispatchProjection] = []
        for chain in window:
            payload = chain["payload"]
            if not isinstance(payload, dict):
                _integrity("anchor_malformed", "dispatch payload is not an object")
            # The Python-side exact filter INSIDE the bounded window:
            # concurrent runs interleave sequences, so foreign run_ids are
            # EXPECTED here and silently skipped.
            if payload.get("run_id") != run_id:
                continue
            self._run_row_identity(payload, row=row, run_id=run_id, where="dispatch")
            for name in ("refusal_reason", "scope_id"):
                value = payload.get(name)
                if value is not None and not isinstance(value, str):
                    _integrity("anchor_malformed", f"dispatch: {name} is non-string")
            result_sha256 = payload.get("result_sha256")
            if result_sha256 is not None and (
                not isinstance(result_sha256, str) or _SHA256_HEX.fullmatch(result_sha256) is None
            ):
                _integrity(
                    "anchor_malformed",
                    "dispatch: result_sha256 is not a lowercase 64-hex sha256",
                )
            result_bytes = payload.get("result_bytes")
            if result_bytes is not None and (
                not isinstance(result_bytes, int) or isinstance(result_bytes, bool)
            ):
                _integrity("anchor_malformed", "dispatch: result_bytes is non-int")
            projected.append(
                DispatchProjection(
                    sequence=chain["sequence"],
                    step_index=_payload_int(payload, "step_index", where="dispatch"),
                    capability_kind=_payload_str(payload, "capability_kind", where="dispatch"),
                    capability_ref=_payload_str(payload, "capability_ref", where="dispatch"),
                    scope_id=payload.get("scope_id"),
                    outcome=_payload_str(payload, "outcome", where="dispatch"),
                    refusal_reason=payload.get("refusal_reason"),
                    args_sha256=_payload_sha256(payload, "args_sha256", where="dispatch"),
                    result_sha256=result_sha256,
                    result_bytes=result_bytes,
                )
            )
        # Empty dispatches are VALID (run-5 semantics: context reuse).
        return tuple(projected)
