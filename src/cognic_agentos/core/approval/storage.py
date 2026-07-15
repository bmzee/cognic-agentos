"""Sprint 13.5a (ADR-014) — ApprovalRequestStore: relational approval-request
row + the 5 value-free ``approval.*`` chain events. ``core/`` stop-rule + CC.

Mirrors ``core/scheduler/storage.py`` for the atomic-transition machinery:
``create_request_row`` is the genesis write (INSERT pending + ``approval.requested``
in one transaction) and ``transition`` is the state-machine write (SELECT ... FOR
UPDATE -> ``validate_transition`` under the lock -> UPDATE state + approver column
-> the matching ``approval.<event>`` chain row), both via
``DecisionHistoryStore.append_with_precondition`` (Doctrine Lock D). Value-free:
no raw tool args ever — only the caller's ``args_digest`` + the engine's
``envelope_digest``.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import json
import uuid
from datetime import UTC, datetime
from typing import Any, Final

from sqlalchemy import (
    TIMESTAMP,
    CheckConstraint,
    Column,
    Index,
    LargeBinary,
    Select,
    String,
    Table,
    Text,
    Uuid,
    and_,
    insert,
    or_,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from cognic_agentos.core.approval._types import (
    ApprovalRequestNotFound,
    ApprovalState,
    validate_transition,
)
from cognic_agentos.core.audit import _metadata
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.db.types import GovernanceJSON

#: ISO 42001 controls stamped on every ``approval.*`` chain row (spec §9):
#: A.6.2.5 (operational responsibilities) + A.7.4 (impact assessment) +
#: A.10.2 (transparency).
_APPROVAL_ISO_CONTROLS: Final[tuple[str, ...]] = (
    "ISO42001.A.6.2.5",
    "ISO42001.A.7.4",
    "ISO42001.A.10.2",
)

#: ``action`` -> the value-free chain event emitted by ``transition``.
_ACTION_TO_DECISION_TYPE: Final[dict[str, str]] = {
    "grant_first": "approval.granted_first",
    "grant_second": "approval.granted_second",
    "deny": "approval.denied",
    "expire": "approval.expired",
}

#: ``action`` -> the approver column the transition stamps (None for ``expire``).
_ACTION_TO_APPROVER_COL: Final[dict[str, str | None]] = {
    "grant_first": "first_approver",
    "grant_second": "second_approver",
    "deny": "denier",
    "expire": None,
}

_TS = TIMESTAMP(timezone=True)

#: In-process Table — registered against the shared ``core.audit._metadata`` so
#: ``_metadata.create_all`` (tests) + ``alembic upgrade head`` (migration 0009)
#: both build it. MUST agree column-for-column with
#: ``20260610_0009_approval_requests.py``.
_approval_requests = Table(
    "approval_requests",
    _metadata,
    Column("request_id", Uuid(), primary_key=True),
    Column("tenant_id", String(128), nullable=False),
    Column("flow", String(32), nullable=False),
    Column("risk_tier", String(32), nullable=False),
    Column("tool_identity", String(256), nullable=False),
    Column("originator_subject", String(256), nullable=False),
    Column("state", String(16), nullable=False),
    Column("first_approver", String(256), nullable=True),
    Column("second_approver", String(256), nullable=True),
    Column("denier", String(256), nullable=True),
    Column("envelope_digest", LargeBinary(), nullable=False),
    Column("args_digest", LargeBinary(), nullable=False),
    Column("redacted_context", Text(), nullable=False),
    Column("data_classes", GovernanceJSON(), nullable=False),
    Column("required_refs", GovernanceJSON(), nullable=False),
    Column("created_at", _TS, nullable=False),
    Column("expires_at", _TS, nullable=False),
    Column("updated_at", _TS, nullable=False),
    CheckConstraint(
        "state IN ('pending', 'awaiting_second', 'granted', 'denied', 'expired')",
        name="ck_approval_requests_state",
    ),
    Index("ix_approval_requests_tenant_state", "tenant_id", "state"),
    # Migration 0017 (HP-4): the reviewer queue's tenant-leading chronological
    # index — (created_at, request_id) is the keyset list_pending walks.
    Index("ix_approval_requests_tenant_created_request", "tenant_id", "created_at", "request_id"),
)


@dataclasses.dataclass(frozen=True, slots=True)
class ApprovalRequestRow:
    """Tenant-scoped read projection returned by :meth:`ApprovalRequestStore.load`.
    The engine reads ``state``/``flow``/``risk_tier``/``expires_at``/``args_digest``
    /``first_approver`` etc. for lazy-expiry + RBAC + distinctness + the binding
    gate."""

    request_id: uuid.UUID
    tenant_id: str
    state: ApprovalState
    flow: str
    risk_tier: str
    tool_identity: str
    originator_subject: str
    envelope_digest: bytes
    args_digest: bytes
    first_approver: str | None
    second_approver: str | None
    denier: str | None
    expires_at: datetime
    # Sprint 13.5c3 (ADR-014) — projected for the verify-time evidence echo
    # (spec §3.2); defaulted so existing construction sites stay green.
    required_refs: dict[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True, slots=True)
class ApprovalRequestSummary:
    """Lighter list-item projection returned by
    :meth:`ApprovalRequestStore.list_pending` (no ``redacted_context`` body —
    that is the detail view)."""

    request_id: uuid.UUID
    tenant_id: str
    flow: str
    risk_tier: str
    tool_identity: str
    originator_subject: str
    state: ApprovalState
    first_approver: str | None
    created_at: datetime
    expires_at: datetime


@dataclasses.dataclass(frozen=True, slots=True)
class ApprovalRequestDetail:
    """Full reviewer detail projection returned by
    :meth:`ApprovalRequestStore.load_detail` — every ``ApprovalRequestRow`` field
    PLUS ``data_classes`` + ``redacted_context`` + ``created_at`` for the reviewer
    panel. Digests stay ``bytes`` here; the DTO renders them hex."""

    request_id: uuid.UUID
    tenant_id: str
    state: ApprovalState
    flow: str
    risk_tier: str
    tool_identity: str
    originator_subject: str
    envelope_digest: bytes
    args_digest: bytes
    data_classes: tuple[str, ...]
    redacted_context: str
    required_refs: dict[str, str]
    first_approver: str | None
    second_approver: str | None
    denier: str | None
    created_at: datetime
    expires_at: datetime


@dataclasses.dataclass(frozen=True, slots=True)
class _LockedSnapshot:
    """Row-locked projection threaded ``_precondition`` -> ``_build_record`` so the
    chain payload is the canonical evidence snapshot (post-UPDATE state +
    approver columns)."""

    state: ApprovalState
    flow: str
    risk_tier: str
    tool_identity: str
    originator_subject: str
    envelope_digest: bytes
    args_digest: bytes
    redacted_context: str
    required_refs: dict[str, str]
    first_approver: str | None
    second_approver: str | None
    denier: str | None


def _value_free_payload(
    *, request_id: uuid.UUID, tenant_id: str, snap: _LockedSnapshot
) -> dict[str, Any]:
    """The value-free chain payload (spec §4) — 14 keys built HERE; the store
    additionally merges ``actor_id`` (the triggering governance subject, the
    eval/scheduler convention) so the PERSISTED payload is 15 keys. Digests are
    hex strings; NO raw args. The persisted 15-key set is pinned by
    ``test_storage.py::test_value_free_payload_exact_key_set``."""
    return {
        "request_id": str(request_id),
        "tenant_id": tenant_id,
        "flow": snap.flow,
        "risk_tier": snap.risk_tier,
        "tool_identity": snap.tool_identity,
        "originator_subject": snap.originator_subject,
        "state": snap.state,
        "envelope_digest": snap.envelope_digest.hex(),
        "args_digest": snap.args_digest.hex(),
        "redacted_context": snap.redacted_context,
        "required_refs": dict(snap.required_refs),
        "first_approver": snap.first_approver,
        "second_approver": snap.second_approver,
        "denier": snap.denier,
    }


#: The actionable states a reviewer can act on (the queue). Terminal states
#: (granted / denied / expired) are excluded from ``list_pending``.
_ACTIONABLE_STATES: Final[tuple[str, ...]] = ("pending", "awaiting_second")

#: HP-4 (M8.5-C T1): the queue cursor's wire ceiling — enforced BEFORE any
#: decode work so an oversized input never reaches base64/json.
APPROVAL_CURSOR_MAX_ENCODED_LEN: Final[int] = 256

_CURSOR_VERSION: Final[int] = 1

#: The exact key set a version-1 cursor payload carries — extra or missing
#: keys refuse (a malformed cursor is refused whole, never partially honoured).
_CURSOR_KEYS: Final[frozenset[str]] = frozenset({"v", "created_at", "request_id"})


class ApprovalCursorInvalid(Exception):
    """Malformed / wrong-version / invalid-type / over-length queue cursor.
    The route maps this to ``422 {"detail": {"reason": "cursor_invalid"}}``.

    Cursor doctrine: the cursor is an UNSIGNED, NON-AUTHORITATIVE presentation
    position (the last returned row's ``(created_at, request_id)`` keyset), NOT
    a security token. The actual authorization boundary is the tenant-scoped
    WHERE clause on every query — a caller cannot widen their view by forging a
    cursor. Strict decoding therefore exists to reject MALFORMED / AMBIGUOUS
    input (so a bad cursor is a clean 422, never a silent wrong-page or a
    dialect-level 500), not to detect tampering."""


@dataclasses.dataclass(frozen=True, slots=True)
class ApprovalQueueCursor:
    """The typed keyset position: the last returned row's chronological pair."""

    created_at: datetime
    request_id: uuid.UUID


@dataclasses.dataclass(frozen=True, slots=True)
class ListPendingPage:
    """One reviewer-queue page. ``items`` is a tuple (a frozen page never
    carries a mutable list); ``next_cursor`` is None on the final page."""

    items: tuple[ApprovalRequestSummary, ...]
    next_cursor: str | None


def _mint_aware_utc(value: datetime) -> datetime:
    """The write path persists tz-aware UTC; drivers without tz storage
    (sqlite) hand the same instant back naive — normalize at cursor-mint time
    so the strict aware-required decode holds on every dialect. LOCAL copy of
    the read-model helper (drift-pinned test-only; no runtime cross-import)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def encode_queue_cursor(cursor: ApprovalQueueCursor) -> str:
    raw = json.dumps(
        {
            "v": _CURSOR_VERSION,
            "created_at": _mint_aware_utc(cursor.created_at).isoformat(),
            "request_id": str(cursor.request_id),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decode_queue_cursor(raw: str) -> ApprovalQueueCursor:
    if len(raw) > APPROVAL_CURSOR_MAX_ENCODED_LEN:
        raise ApprovalCursorInvalid("cursor exceeds the maximum encoded length")
    try:
        # validate=True: STRICT alphabet — urlsafe_b64decode silently discards
        # non-alphabet bytes, so a cursor with trailing garbage would otherwise
        # decode to a DIFFERENT position than it presents. Refuse it cleanly as
        # 422 rather than serve an ambiguous page (the cursor is a
        # non-authoritative position, not a security token — see the
        # ApprovalCursorInvalid doctrine note).
        decoded = json.loads(base64.b64decode(raw.encode("ascii"), altchars=b"-_", validate=True))
    except (ValueError, binascii.Error, UnicodeDecodeError) as exc:
        raise ApprovalCursorInvalid("cursor is not base64url(JSON)") from exc
    if not isinstance(decoded, dict) or set(decoded) != _CURSOR_KEYS:
        raise ApprovalCursorInvalid("cursor payload has an invalid key set")
    version = decoded["v"]
    # bool-guarded exact int: JSON true == 1 in Python and would impersonate
    # version 1.
    if not isinstance(version, int) or isinstance(version, bool) or version != _CURSOR_VERSION:
        raise ApprovalCursorInvalid(f"unsupported cursor version {version!r}")
    created_raw, rid_raw = decoded["created_at"], decoded["request_id"]
    if not isinstance(created_raw, str) or not isinstance(rid_raw, str):
        raise ApprovalCursorInvalid("cursor fields have invalid types")
    try:
        created_at = datetime.fromisoformat(created_raw)
        request_id = uuid.UUID(rid_raw)
    except ValueError as exc:
        raise ApprovalCursorInvalid("cursor carries an unparseable position") from exc
    # tz-aware or refused: a naive keyset timestamp compared against the
    # tz-aware column is a dialect-level error (a 500), not a governed 422.
    if created_at.tzinfo is None or created_at.tzinfo.utcoffset(created_at) is None:
        raise ApprovalCursorInvalid("cursor timestamp must be timezone-aware")
    return ApprovalQueueCursor(created_at=created_at, request_id=request_id)


def _build_list_pending_stmt(
    tenant_id: str, *, limit_plus_one: int, after: ApprovalQueueCursor | None
) -> Select[Any]:
    """SOLE query-construction path for :meth:`ApprovalRequestStore.list_pending`.
    The SQL-shape regression imports this SAME builder (no vacuous duplicate
    select). WHERE: ``tenant_id == :tenant_id`` (ALWAYS — the server-side tenant
    boundary) AND ``state IN ('pending','awaiting_second')`` (ALWAYS) AND the
    HP-4 chronological keyset ``(created_at, request_id) > cursor`` via the
    Oracle-portable tuple expansion (when a cursor is present). Ordered by
    ``(created_at ASC, request_id ASC)``; the 0017
    ``ix_approval_requests_tenant_created_request`` index backs the WHERE +
    ORDER BY."""
    stmt = (
        select(_approval_requests)
        .where(
            _approval_requests.c.tenant_id == tenant_id,
            _approval_requests.c.state.in_(_ACTIONABLE_STATES),
        )
        .order_by(_approval_requests.c.created_at.asc(), _approval_requests.c.request_id.asc())
        .limit(limit_plus_one)
    )
    if after is not None:
        # Portable keyset (Oracle lacks general row-value comparison).
        stmt = stmt.where(
            or_(
                _approval_requests.c.created_at > after.created_at,
                and_(
                    _approval_requests.c.created_at == after.created_at,
                    _approval_requests.c.request_id > after.request_id,
                ),
            )
        )
    return stmt


class ApprovalRequestStore:
    """Postgres/Oracle/SQLite-backed approval-request store. Public methods are
    async + raise on every refusal/failure path (production-grade rule)."""

    def __init__(self, history: DecisionHistoryStore) -> None:
        self._history = history
        self._engine: AsyncEngine = history._engine

    async def create_request_row(
        self,
        *,
        request_id: uuid.UUID,
        tenant_id: str,
        flow: str,
        risk_tier: str,
        tool_identity: str,
        originator_subject: str,
        envelope_digest: bytes,
        args_digest: bytes,
        redacted_context: str,
        data_classes: list[str],
        required_refs: dict[str, str],
        request_request_id: str,
        created_at: datetime,
        expires_at: datetime,
    ) -> tuple[uuid.UUID, bytes]:
        """Genesis write: INSERT a ``pending`` row + append ``approval.requested``
        atomically. Returns the ``(chain_record_id, chain_hash)`` pair."""
        snap = _LockedSnapshot(
            state="pending",
            flow=flow,
            risk_tier=risk_tier,
            tool_identity=tool_identity,
            originator_subject=originator_subject,
            envelope_digest=envelope_digest,
            args_digest=args_digest,
            redacted_context=redacted_context,
            required_refs=required_refs,
            first_approver=None,
            second_approver=None,
            denier=None,
        )

        async def _precondition(conn: AsyncConnection, _seq: int, _hash: bytes) -> None:
            await conn.execute(
                insert(_approval_requests).values(
                    request_id=request_id,
                    tenant_id=tenant_id,
                    flow=flow,
                    risk_tier=risk_tier,
                    tool_identity=tool_identity,
                    originator_subject=originator_subject,
                    state="pending",
                    first_approver=None,
                    second_approver=None,
                    denier=None,
                    envelope_digest=envelope_digest,
                    args_digest=args_digest,
                    redacted_context=redacted_context,
                    data_classes=list(data_classes),
                    required_refs=dict(required_refs),
                    created_at=created_at,
                    expires_at=expires_at,
                    updated_at=created_at,
                )
            )

        def _build_record(_: None) -> DecisionRecord:
            return DecisionRecord(
                decision_type="approval.requested",
                request_id=request_request_id,
                payload=_value_free_payload(request_id=request_id, tenant_id=tenant_id, snap=snap),
                actor_id=originator_subject,
                tenant_id=tenant_id,
                iso_controls=_APPROVAL_ISO_CONTROLS,
            )

        return await self._history.append_with_precondition(
            record_builder=_build_record, precondition=_precondition
        )

    async def transition(
        self,
        *,
        request_id: uuid.UUID,
        tenant_id: str,
        action: str,
        actor_subject: str | None,
        request_request_id: str,
        reason: str | None = None,
    ) -> ApprovalState:
        """State-machine transition under the row lock. SELECT ... FOR UPDATE the
        tenant-scoped row, ``validate_transition`` against the locked state AND the
        row-locked persisted ``flow``, UPDATE state + the action's approver column,
        emit ``approval.<event>``. Returns the new state.

        There is deliberately NO caller-supplied ``flow`` argument (P1): the
        persisted ``flow`` is the single authoritative source. Accepting a caller
        flow would let a persisted ``require_4_eyes`` request be downgraded to
        single-approval at grant time (``grant_first`` -> ``granted`` instead of
        ``awaiting_second``), defeating the 4-eyes control.

        Raises :class:`ApprovalRequestNotFound` (missing / cross-tenant row) or
        :class:`~cognic_agentos.core.approval._types.ApprovalTransitionRefused`
        (illegal state pair) from inside the precondition (transaction rolls back).
        """
        # Preflight: out-of-vocabulary action -> fail loud BEFORE any DB work.
        decision_type = _ACTION_TO_DECISION_TYPE[action]
        approver_col = _ACTION_TO_APPROVER_COL[action]
        now = datetime.now(UTC)
        captured: list[ApprovalState] = []

        async def _precondition(conn: AsyncConnection, _seq: int, _hash: bytes) -> _LockedSnapshot:
            row = (
                await conn.execute(
                    select(
                        _approval_requests.c.state,
                        _approval_requests.c.flow,
                        _approval_requests.c.risk_tier,
                        _approval_requests.c.tool_identity,
                        _approval_requests.c.originator_subject,
                        _approval_requests.c.envelope_digest,
                        _approval_requests.c.args_digest,
                        _approval_requests.c.redacted_context,
                        _approval_requests.c.required_refs,
                        _approval_requests.c.first_approver,
                        _approval_requests.c.second_approver,
                        _approval_requests.c.denier,
                    )
                    .where(
                        _approval_requests.c.request_id == request_id,
                        _approval_requests.c.tenant_id == tenant_id,
                    )
                    .with_for_update()
                )
            ).first()
            if row is None:
                raise ApprovalRequestNotFound(str(request_id))

            # P1: the row-locked persisted ``row.flow`` is AUTHORITATIVE — the
            # store never trusts a caller-supplied flow (there is no such arg).
            to_state = validate_transition(from_state=row.state, action=action, flow=row.flow)

            update_values: dict[str, Any] = {"state": to_state, "updated_at": now}
            new_first, new_second, new_denier = row.first_approver, row.second_approver, row.denier
            if approver_col is not None and actor_subject is not None:
                update_values[approver_col] = actor_subject
                if approver_col == "first_approver":
                    new_first = actor_subject
                elif approver_col == "second_approver":
                    new_second = actor_subject
                else:
                    new_denier = actor_subject
            await conn.execute(
                update(_approval_requests)
                .where(_approval_requests.c.request_id == request_id)
                .values(**update_values)
            )
            captured.append(to_state)
            return _LockedSnapshot(
                state=to_state,
                flow=row.flow,
                risk_tier=row.risk_tier,
                tool_identity=row.tool_identity,
                originator_subject=row.originator_subject,
                envelope_digest=row.envelope_digest,
                args_digest=row.args_digest,
                redacted_context=row.redacted_context,
                required_refs=dict(row.required_refs),
                first_approver=new_first,
                second_approver=new_second,
                denier=new_denier,
            )

        def _build_record(snap: _LockedSnapshot) -> DecisionRecord:
            payload = _value_free_payload(request_id=request_id, tenant_id=tenant_id, snap=snap)
            if reason is not None:
                payload["reason"] = reason
            return DecisionRecord(
                decision_type=decision_type,
                request_id=request_request_id,
                payload=payload,
                actor_id=actor_subject,
                tenant_id=tenant_id,
                iso_controls=_APPROVAL_ISO_CONTROLS,
            )

        await self._history.append_with_precondition(
            record_builder=_build_record, precondition=_precondition
        )
        return captured[0]

    async def load(self, *, request_id: uuid.UUID, tenant_id: str) -> ApprovalRequestRow | None:
        """Tenant-scoped read; cross-tenant / unknown -> ``None``."""
        async with self._engine.begin() as conn:
            row = (
                await conn.execute(
                    select(_approval_requests).where(
                        _approval_requests.c.request_id == request_id,
                        _approval_requests.c.tenant_id == tenant_id,
                    )
                )
            ).first()
        if row is None:
            return None
        return ApprovalRequestRow(
            request_id=row.request_id,
            tenant_id=row.tenant_id,
            state=row.state,
            flow=row.flow,
            risk_tier=row.risk_tier,
            tool_identity=row.tool_identity,
            originator_subject=row.originator_subject,
            envelope_digest=row.envelope_digest,
            args_digest=row.args_digest,
            first_approver=row.first_approver,
            second_approver=row.second_approver,
            denier=row.denier,
            # tz-normalise: SQLite returns naive datetimes for TIMESTAMP(tz)
            # (PG/Oracle return aware); expires_at was written UTC-aware, so a
            # naive read is re-stamped UTC. Branchless so both arms are covered.
            expires_at=row.expires_at.replace(tzinfo=row.expires_at.tzinfo or UTC),
            # Sprint 13.5c3 (ADR-014): None-guard for pre-13.5a rows / NULL
            # JSON reads; the column is written as a dict at create_request_row.
            required_refs=dict(row.required_refs or {}),
        )

    async def first_approver(self, *, request_id: uuid.UUID, tenant_id: str) -> str | None:
        """The recorded first-approver subject (for 4-eyes distinctness)."""
        async with self._engine.begin() as conn:
            row = (
                await conn.execute(
                    select(_approval_requests.c.first_approver).where(
                        _approval_requests.c.request_id == request_id,
                        _approval_requests.c.tenant_id == tenant_id,
                    )
                )
            ).first()
        return row[0] if row is not None else None

    async def list_pending(
        self, tenant_id: str, *, limit: int = 50, cursor: str | None = None
    ) -> ListPendingPage:
        """The reviewer queue (HP-4): actionable (``pending`` +
        ``awaiting_second``) requests for ``tenant_id``, chronologically
        keyset-paginated by ``(created_at, request_id)`` via the typed opaque
        cursor. Tenant scoping is the WHERE clause (no in-handler filter can
        leak cross-tenant rows). ``limit`` is clamped defensively to 1..200 —
        the route owns the wire 422. Raises :class:`ApprovalCursorInvalid` on
        any cursor decode failure."""
        page_size = max(1, min(limit, 200))
        after = decode_queue_cursor(cursor) if cursor is not None else None
        stmt = _build_list_pending_stmt(tenant_id, limit_plus_one=page_size + 1, after=after)
        async with self._engine.connect() as conn:
            rows = (await conn.execute(stmt)).all()
        has_more = len(rows) > page_size
        page = rows[:page_size]
        items = tuple(
            ApprovalRequestSummary(
                request_id=r.request_id,
                tenant_id=r.tenant_id,
                flow=r.flow,
                risk_tier=r.risk_tier,
                tool_identity=r.tool_identity,
                originator_subject=r.originator_subject,
                state=r.state,
                first_approver=r.first_approver,
                created_at=r.created_at.replace(tzinfo=r.created_at.tzinfo or UTC),
                expires_at=r.expires_at.replace(tzinfo=r.expires_at.tzinfo or UTC),
            )
            for r in page
        )
        next_cursor: str | None = None
        if has_more and page:
            last = page[-1]
            next_cursor = encode_queue_cursor(
                ApprovalQueueCursor(created_at=last.created_at, request_id=last.request_id)
            )
        return ListPendingPage(items=items, next_cursor=next_cursor)

    async def load_detail(
        self, *, request_id: uuid.UUID, tenant_id: str
    ) -> ApprovalRequestDetail | None:
        """Tenant-scoped reviewer detail read; cross-tenant / unknown -> ``None``
        (the route maps None -> 404 per the cross-tenant-invisibility doctrine).
        Richer than the engine-facing :meth:`load`."""
        async with self._engine.begin() as conn:
            row = (
                await conn.execute(
                    select(_approval_requests).where(
                        _approval_requests.c.request_id == request_id,
                        _approval_requests.c.tenant_id == tenant_id,
                    )
                )
            ).first()
        if row is None:
            return None
        return ApprovalRequestDetail(
            request_id=row.request_id,
            tenant_id=row.tenant_id,
            state=row.state,
            flow=row.flow,
            risk_tier=row.risk_tier,
            tool_identity=row.tool_identity,
            originator_subject=row.originator_subject,
            envelope_digest=row.envelope_digest,
            args_digest=row.args_digest,
            data_classes=tuple(row.data_classes),
            redacted_context=row.redacted_context,
            required_refs=dict(row.required_refs),
            first_approver=row.first_approver,
            second_approver=row.second_approver,
            denier=row.denier,
            created_at=row.created_at.replace(tzinfo=row.created_at.tzinfo or UTC),
            expires_at=row.expires_at.replace(tzinfo=row.expires_at.tzinfo or UTC),
        )
