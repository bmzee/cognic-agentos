"""Postgres/Oracle-backed scheduler task store — Sprint 10.5a per ADR-022.

The scheduler mirror of ``packs/storage.py`` + ``models/storage.py``.

CRITICAL CONTROL (core/ stop-rule per AGENTS.md). Consumer of
``DecisionHistoryStore.append_with_precondition`` — appends
``scheduler.admission_accepted`` + ``scheduler.task_*`` chain rows.
Does NOT modify the chain substrate.

Two distinct write paths:
  * ``submit()`` — genesis: INSERT the ``scheduler_tasks`` row in
    ``pending`` state + append ``scheduler.admission_accepted`` in one
    transaction.
  * ``transition()`` — state-machine: SELECT ... FOR UPDATE the row,
    validate via ``validate_transition`` (pure-functional state-machine
    from T2), UPDATE the state cache, append
    ``scheduler.task_<terminal_or_running_state>``.

Atomic semantics (mirrors Doctrine Lock D from packs/storage): chain-
head SELECT FOR UPDATE → task-row SELECT FOR UPDATE → validate_transition
→ state-cache UPDATE → chain row INSERT → chain-head UPDATE, all inside
a single ``engine.begin()`` transaction owned by
``DecisionHistoryStore.append_with_precondition``. Failure at any step
rolls back all three — fail-closed.

Every edit is halt-before-commit per
[[feedback_strict_review_off_gate]].
"""

from __future__ import annotations

import typing
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from sqlalchemy import (
    TIMESTAMP,
    CheckConstraint,
    Column,
    Index,
    Integer,
    Select,
    String,
    Table,
    Uuid,
    insert,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from cognic_agentos.core.audit import _metadata
from cognic_agentos.core.decision_history import (
    DecisionHistoryStore,
    DecisionRecord,
)
from cognic_agentos.core.scheduler._types import (
    SCHEDULER_ISO_CONTROLS,
    SchedulerRefusalReason,
    SchedulerTaskState,
    SubmitInput,
)
from cognic_agentos.core.scheduler._types import (
    SchedulerTransitionRefused as _SchedulerTransitionRefused,
)
from cognic_agentos.core.scheduler._types import (
    validate_transition as _validate_transition,
)

SCHEDULER_TENANT_ID_MAX_LEN: Final[int] = 128
SCHEDULER_PACK_ID_MAX_LEN: Final[int] = 128
SCHEDULER_ACTOR_MAX_LEN: Final[int] = 256
SCHEDULER_PACK_KIND_MAX_LEN: Final[int] = 32
SCHEDULER_PACK_RISK_TIER_MAX_LEN: Final[int] = 64


#: Reserved chain-payload keys that ``transition()`` builds from the
#: row-locked ``_LockedTaskSnapshot`` + caller arguments. Caller-supplied
#: ``payload_extras`` MUST NOT overlap with these keys — overlap raises
#: ``ValueError`` at the function-entry preflight guard BEFORE any DB
#: state is mutated. This closes the round-4 reviewer P1 finding:
#: without the guard, ``payload_extras={"tenant_id": "wrong", ...}``
#: would silently corrupt the hash-chained evidence snapshot while the
#: row UPDATE + top-level chain-row ``tenant_id`` remained correct —
#: breaking the chain-payload-is-evidence-snapshot doctrine per
#: ``[[feedback_chain_payload_is_evidence_snapshot]]``.
_RESERVED_TRANSITION_PAYLOAD_KEYS: Final[frozenset[str]] = frozenset(
    {
        "task_id",
        "from_state",
        "to_state",
        "tenant_id",
        "pack_id",
        "actor_subject",
        "class_",
        "pack_kind",
        "pack_risk_tier",
        "requested_estimated_tokens",
        "parent_task_id",
        "submitted_at",
        "started_at",
        "terminal_at",
    }
)

#: Mapping from terminal-or-running state → chain-audit decision_type.
#: Per spec §4.9: 8 events total (admission_accepted + admission_refused
#: are emitted by SchedulerEngine, NOT by storage; storage emits the
#: 6 transition-driven events). Build-time invariant below pins the
#: mapping against SchedulerTaskState.
_STATE_TO_DECISION_TYPE: Final[dict[SchedulerTaskState, str]] = {
    "running": "scheduler.task_started",
    "completed": "scheduler.task_completed",
    "failed": "scheduler.task_failed",
    "cancelled": "scheduler.task_cancelled",
    "preempted": "scheduler.task_preempted",
    "expired": "scheduler.task_expired",
}

#: Round-6 reviewer P2 fix: wire-public closed-enum guard for the
#: ``scheduler.admission_refused`` chain row's ``payload.reason``
#: field. Mirrors the ``_STATE_TO_DECISION_TYPE`` preflight pattern —
#: any value outside the 5-value ``SchedulerRefusalReason`` Literal
#: raises ``ValueError`` BEFORE the chain row is persisted so a
#: caller-side bug cannot smuggle a non-enum value into hash-chained
#: evidence. Built from the Literal at module load via ``get_args`` so
#: drift between the Literal and the guard is impossible.
_VALID_REFUSAL_REASONS: Final[frozenset[str]] = frozenset(typing.get_args(SchedulerRefusalReason))

#: SQLAlchemy Core Table for the scheduler task store, registered against
#: the shared ``core.audit._metadata`` so ``_metadata.create_all`` (tests)
#: and ``alembic upgrade head`` (migration 0005) both build it. The
#: migration at ``20260526_0005_scheduler_tasks.py`` MUST mirror this
#: Table exactly; drift is pinned by
#: ``tests/unit/db/test_migration_20260526_0005.py``.
_scheduler_tasks = Table(
    "scheduler_tasks",
    _metadata,
    Column("task_id", Uuid(), primary_key=True),
    Column("tenant_id", String(SCHEDULER_TENANT_ID_MAX_LEN), nullable=False),
    Column("pack_id", String(SCHEDULER_PACK_ID_MAX_LEN), nullable=False),
    Column("actor_subject", String(SCHEDULER_ACTOR_MAX_LEN), nullable=False),
    Column("class_", String(16), nullable=False),
    Column("state", String(16), nullable=False),
    Column("pack_kind", String(SCHEDULER_PACK_KIND_MAX_LEN), nullable=False),
    Column("pack_risk_tier", String(SCHEDULER_PACK_RISK_TIER_MAX_LEN), nullable=False),
    Column("requested_estimated_tokens", Integer(), nullable=False),
    Column("parent_task_id", Uuid(), nullable=True),
    Column("submitted_at", TIMESTAMP(timezone=True), nullable=False),
    Column("started_at", TIMESTAMP(timezone=True), nullable=True),
    Column("terminal_at", TIMESTAMP(timezone=True), nullable=True),
    CheckConstraint(
        "state IN ('pending', 'running', 'completed', 'failed', "
        "'cancelled', 'preempted', 'expired')",
        name="ck_scheduler_tasks_state",
    ),
    CheckConstraint(
        "class_ IN ('interactive', 'background')",
        name="ck_scheduler_tasks_class_",
    ),
    Index("ix_scheduler_tasks_tenant_class_state", "tenant_id", "class_", "state"),
    Index("ix_scheduler_tasks_parent", "parent_task_id"),
)


@dataclass(frozen=True, slots=True)
class _LockedTaskSnapshot:
    """Module-private projection of the row-locked scheduler_tasks row
    threaded from ``_precondition`` to ``_build_record`` so the chain
    payload is the canonical evidence snapshot per
    ``[[feedback_chain_payload_is_evidence_snapshot]]``.

    All fields read under the SELECT ... FOR UPDATE lock + reflect the
    post-UPDATE state (started_at / terminal_at carry the just-set
    values when the transition stamps them)."""

    tenant_id: str
    pack_id: str
    actor_subject: str
    class_: str
    pack_kind: str
    pack_risk_tier: str
    requested_estimated_tokens: int
    parent_task_id: str | None
    submitted_at: datetime
    started_at: datetime | None
    terminal_at: datetime | None


class SchedulerTaskNotFound(Exception):
    """Raised when transition() targets a task_id with no row in
    scheduler_tasks. Caller-distinct from SchedulerTransitionRefused —
    not-found is a missing-row failure mode, not a state-machine
    refusal."""

    def __init__(self, task_id: uuid.UUID) -> None:
        super().__init__(f"scheduler_task_not_found: {task_id}")
        self.task_id = task_id


@dataclass(frozen=True)
class _BudgetSnapshot:
    """Pure-read projection for the parent-budget resolver: the granted token
    budget + the lifecycle state of a tenant-scoped scheduler task."""

    granted_tokens: int
    state: SchedulerTaskState


def _build_budget_snapshot_stmt(*, task_id: uuid.UUID, tenant_id: str) -> Select[Any]:
    """SOLE query-construction path for get_budget_snapshot. The WHERE on BOTH
    task_id AND tenant_id IS the cross-tenant boundary (absent OR cross-tenant
    → no row). Shared with the SQL-shape regression (no vacuous duplicate)."""
    return (
        select(
            _scheduler_tasks.c.requested_estimated_tokens,
            _scheduler_tasks.c.state,
        )
        .where(_scheduler_tasks.c.task_id == task_id)
        .where(_scheduler_tasks.c.tenant_id == tenant_id)
    )


class SchedulerStorage:
    """Postgres-backed task lifecycle store. Public methods are async
    + raise on every refusal/failure path; no silent-skip fallbacks
    (production-grade rule)."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._history = DecisionHistoryStore(engine)

    async def get_budget_snapshot(
        self, task_id: uuid.UUID, *, tenant_id: str
    ) -> _BudgetSnapshot | None:
        """Tenant-scoped granted-budget snapshot for the parent-budget resolver.
        Returns None when the task is absent OR belongs to another tenant (the
        cross-tenant-invisibility boundary). Pure read — no lock, no mutation."""
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    _build_budget_snapshot_stmt(task_id=task_id, tenant_id=tenant_id)
                )
            ).first()
        if row is None:
            return None
        return _BudgetSnapshot(granted_tokens=row.requested_estimated_tokens, state=row.state)

    async def submit(
        self,
        *,
        task_id: uuid.UUID,
        submit_input: SubmitInput,
        request_id: str,
    ) -> tuple[uuid.UUID, bytes]:
        """Genesis write: INSERT a ``pending`` row + append
        ``scheduler.admission_accepted`` chain row atomically.

        Returns ``(chain_record_id, chain_hash)``.

        Raises if INSERT fails (e.g. duplicate task_id PK violation).
        The chain row is NOT inserted on INSERT failure because the
        precondition raises BEFORE record_builder + chain INSERT.
        """
        now = datetime.now(UTC)

        async def _precondition(conn: AsyncConnection, _prev_seq: int, _prev_hash: bytes) -> None:
            # Insert the pending row under the chain-head FOR UPDATE
            # lock. If the INSERT raises (e.g. PK collision), the
            # outer engine.begin() rolls back — no chain row written.
            await conn.execute(
                insert(_scheduler_tasks).values(
                    task_id=task_id,
                    tenant_id=submit_input.tenant_id,
                    pack_id=submit_input.pack_id,
                    actor_subject=submit_input.actor.subject,
                    class_=submit_input.class_,
                    state="pending",
                    pack_kind=submit_input.pack_kind,
                    pack_risk_tier=submit_input.pack_risk_tier,
                    requested_estimated_tokens=submit_input.requested_estimated_tokens,
                    parent_task_id=(
                        uuid.UUID(submit_input.parent_task_id)
                        if submit_input.parent_task_id is not None
                        else None
                    ),
                    submitted_at=now,
                    started_at=None,
                    terminal_at=None,
                )
            )

        def _build_record(_: None) -> DecisionRecord:
            payload: dict[str, Any] = {
                "task_id": str(task_id),
                "tenant_id": submit_input.tenant_id,
                "pack_id": submit_input.pack_id,
                "actor_subject": submit_input.actor.subject,
                "actor_type": submit_input.actor.actor_type,
                "class_": submit_input.class_,
                "pack_kind": submit_input.pack_kind,
                "pack_risk_tier": submit_input.pack_risk_tier,
                "requested_estimated_tokens": (submit_input.requested_estimated_tokens),
                "parent_task_id": submit_input.parent_task_id,
                "submitted_at": now.isoformat(),
                # Sprint 13.5c2 (ADR-014): the attestation is ALWAYS present
                # post-c2 (False on safe/auto admissions); the correlator is
                # conditional — ONLY a granted re-submit carries it, so the
                # examiner can join accepted -> approval.* rows (spec §6).
                "approval_verified": submit_input.approval_verified,
            }
            if submit_input.approval_verified and submit_input.approval_request_id is not None:
                payload["approval_request_id"] = submit_input.approval_request_id
            # Sprint 14A-A4a (ADR-022 + ADR-014): honest delegation evidence —
            # present ONLY when non-None, alongside approval_verified=False and NO
            # scheduler approval_request_id (the sandbox owns the checkpoint).
            if submit_input.approval_delegated_to is not None:
                payload["approval_delegated_to"] = submit_input.approval_delegated_to
            return DecisionRecord(
                decision_type="scheduler.admission_accepted",
                request_id=request_id,
                payload=payload,
                actor_id=submit_input.actor.subject,
                tenant_id=submit_input.tenant_id,
                iso_controls=SCHEDULER_ISO_CONTROLS,
            )

        return await self._history.append_with_precondition(
            record_builder=_build_record,
            precondition=_precondition,
        )

    async def record_admission_refused(
        self,
        *,
        refused_task_id: uuid.UUID,
        submit_input: SubmitInput,
        reason: SchedulerRefusalReason,
        request_id: str,
        policy_reason: str | None = None,
        approval_request_id: str | None = None,
        approval_flow: str | None = None,
    ) -> tuple[uuid.UUID, bytes]:
        """Emit a ``scheduler.admission_refused`` chain row for an
        admission outcome that was refused. NO row inserted into
        ``scheduler_tasks`` — the task was never admitted; the chain
        row alone records the refusal for the audit substrate.

        Per spec §4.9 audit-event taxonomy: ``scheduler.admission_refused``
        carries ``payload.reason`` (the wire-public closed-enum
        ``SchedulerRefusalReason`` value) + ``payload.policy_reason``
        (the internal diagnostic string, audit-only per round-4 P2
        vocabulary separation).

        Added per round-5 reviewer P1 #5 — the engine's refusal paths
        (kill-switch, policy, quota, queue-full, pack-not-installed)
        previously returned ``AdmissionDecision`` to the caller without
        emitting any chain row, leaving an audit-pack gap.

        ``refused_task_id`` is the UUID the engine would have used had
        admission succeeded. It is recorded in the chain payload so
        operators can correlate refusal audit rows to the request that
        produced them (e.g. for retry-loop analysis).

        Round-6 reviewer P2 fix: runtime preflight guard rejects any
        ``reason`` value outside the closed-enum ``SchedulerRefusalReason``
        Literal BEFORE the chain row is persisted. The Literal type
        annotation alone is insufficient — Python does not enforce
        Literal at runtime, so a caller bug or runtime-built string
        could silently land non-enum values in hash-chained evidence.
        """
        if reason not in _VALID_REFUSAL_REASONS:
            raise ValueError(
                f"scheduler_admission_refused_reason_not_in_closed_enum: "
                f"reason={reason!r} not in {sorted(_VALID_REFUSAL_REASONS)!r}"
            )
        now = datetime.now(UTC)

        async def _precondition(conn: AsyncConnection, _prev_seq: int, _prev_hash: bytes) -> None:
            # Refusal events have NO scheduler_tasks row insert — task
            # was never admitted. The chain row is the only persisted
            # evidence.
            return None

        def _build_record(_: None) -> DecisionRecord:
            payload: dict[str, Any] = {
                "task_id": str(refused_task_id),
                "tenant_id": submit_input.tenant_id,
                "pack_id": submit_input.pack_id,
                "actor_subject": submit_input.actor.subject,
                "actor_type": submit_input.actor.actor_type,
                "class_": submit_input.class_,
                "pack_kind": submit_input.pack_kind,
                "pack_risk_tier": submit_input.pack_risk_tier,
                "requested_estimated_tokens": (submit_input.requested_estimated_tokens),
                "parent_task_id": submit_input.parent_task_id,
                "submitted_at": now.isoformat(),
                "reason": reason,
                "policy_reason": policy_reason,
            }
            # Sprint 13.5c2 (ADR-014): conditional evidence keys — included
            # ONLY when known so every non-approval refusal row stays
            # byte-identical to its pre-c2 shape (additive-only schema).
            if approval_request_id is not None:
                payload["approval_request_id"] = approval_request_id
            if approval_flow is not None:
                payload["approval_flow"] = approval_flow
            return DecisionRecord(
                decision_type="scheduler.admission_refused",
                request_id=request_id,
                payload=payload,
                actor_id=submit_input.actor.subject,
                tenant_id=submit_input.tenant_id,
                iso_controls=SCHEDULER_ISO_CONTROLS,
            )

        return await self._history.append_with_precondition(
            record_builder=_build_record,
            precondition=_precondition,
        )

    async def transition(
        self,
        *,
        task_id: uuid.UUID,
        from_state: SchedulerTaskState,
        to_state: SchedulerTaskState,
        actor_id: str,
        request_id: str,
        payload_extras: dict[str, Any],
    ) -> tuple[uuid.UUID, bytes]:
        """State-machine transition: SELECT FOR UPDATE the row, validate
        the (from_state, to_state) pair via the pure-functional T2
        validator, UPDATE state, emit the matching
        ``scheduler.task_<state>`` chain row.

        Atomic semantics (Doctrine Lock D mirror): chain-head SELECT
        FOR UPDATE → task-row SELECT FOR UPDATE → validate_transition
        → state-cache UPDATE → chain row INSERT → chain-head UPDATE,
        all inside a single ``engine.begin()`` transaction owned by
        ``append_with_precondition``.

        Raises (PREFLIGHT — NO DB connection acquired):
          :class:`SchedulerTransitionRefused` with reason
            ``"scheduler_transition_invalid_state_pair"`` — the supplied
            ``to_state`` is not a member of ``_STATE_TO_DECISION_TYPE``
            (e.g. ``to_state="pending"``). The runtime guard fires at
            function entry (mirrors the ``packs/storage.py:839-840``
            preflight guard). No transaction is started, so there is
            nothing to roll back. Without this guard, the indexed
            ``_STATE_TO_DECISION_TYPE[to_state]`` access at the
            decision-type computation step would leak a raw ``KeyError``
            past the closed-enum boundary that downstream consumers
            (T5 SchedulerEngine) catch on ``SchedulerTransitionRefused``.
            Round-3 reviewer finding (P1).
          :class:`ValueError` — caller's ``payload_extras`` dict overlaps
            with any key in ``_RESERVED_TRANSITION_PAYLOAD_KEYS`` (the
            14 fixed evidence-snapshot keys storage builds from the
            row-locked task). Round-4 reviewer P1 finding: without this
            guard, ``payload_extras={"tenant_id": "wrong", ...}`` would
            silently corrupt the hash-chained payload because dict
            ``**spread`` merges last-writer-wins. The reserved-key
            guard preserves the chain-payload-is-evidence-snapshot
            doctrine. Fires BEFORE any DB connection acquisition.

        Raises (IN-PRECONDITION — transaction rolls back atomically):
          * :class:`SchedulerTaskNotFound` when no row matches task_id
          * :class:`SchedulerTransitionRefused` when the locked row's
            actual state ≠ from_state OR when (from_state, to_state)
            is not a legal pair per the T2 state-machine table.
            Closed-enum reason: ``scheduler_transition_invalid_state_pair``.
        """
        # Preflight guard #1 (round-3 P1): ``SchedulerTaskState`` is a
        # Literal but Python does not enforce Literal at runtime, so a
        # caller passing ``to_state="pending"`` would raise ``KeyError``
        # from the ``_STATE_TO_DECISION_TYPE[to_state]`` indexed access
        # below — leaking an unstructured exception past the closed-enum
        # boundary. Mirrors ``packs/storage.py:839-840``.
        if to_state not in _STATE_TO_DECISION_TYPE:
            raise _SchedulerTransitionRefused("scheduler_transition_invalid_state_pair")

        # Preflight guard #2 (round-4 P1): caller's ``payload_extras``
        # MUST NOT overlap with the reserved evidence-snapshot keys
        # storage builds from the row-locked task. Without this guard
        # the ``**payload_extras`` merge at the end of ``_build_record``
        # would silently clobber the canonical fields, corrupting the
        # hash-chained payload while the row UPDATE + top-level
        # ``DecisionRecord.tenant_id`` remained correct. Per
        # ``[[feedback_chain_payload_is_evidence_snapshot]]`` — chain
        # payload IS the evidence; clobbering it via caller-supplied
        # extras breaks examiner replay.
        overlapping_keys = _RESERVED_TRANSITION_PAYLOAD_KEYS & payload_extras.keys()
        if overlapping_keys:
            raise ValueError(
                f"payload_extras overlaps reserved transition evidence "
                f"keys: {sorted(overlapping_keys)}. The 14-key reserved "
                f"set is built from the row-locked scheduler_tasks row "
                f"per the chain-payload-is-evidence-snapshot doctrine; "
                f"callers cannot override these fields. "
                f"Reserved: {sorted(_RESERVED_TRANSITION_PAYLOAD_KEYS)}."
            )

        now = datetime.now(UTC)
        decision_type = _STATE_TO_DECISION_TYPE[to_state]

        async def _precondition(
            conn: AsyncConnection, _prev_seq: int, _prev_hash: bytes
        ) -> _LockedTaskSnapshot:
            # SELECT FOR UPDATE the FULL row (not just state). Per spec
            # §4.9 + [[feedback_chain_payload_is_evidence_snapshot]]:
            # transition chain rows must carry the full task evidence
            # snapshot so examiners can reconstruct the task without
            # joining back to scheduler_tasks (which is a mutable
            # cache, not the audit substrate). Round-3 reviewer P1
            # finding #2.
            row = (
                await conn.execute(
                    select(
                        _scheduler_tasks.c.state,
                        _scheduler_tasks.c.tenant_id,
                        _scheduler_tasks.c.pack_id,
                        _scheduler_tasks.c.actor_subject,
                        _scheduler_tasks.c.class_,
                        _scheduler_tasks.c.pack_kind,
                        _scheduler_tasks.c.pack_risk_tier,
                        _scheduler_tasks.c.requested_estimated_tokens,
                        _scheduler_tasks.c.parent_task_id,
                        _scheduler_tasks.c.submitted_at,
                        _scheduler_tasks.c.started_at,
                        _scheduler_tasks.c.terminal_at,
                    )
                    .where(_scheduler_tasks.c.task_id == task_id)
                    .with_for_update()
                )
            ).first()
            if row is None:
                raise SchedulerTaskNotFound(task_id)

            actual_from_state: SchedulerTaskState = row.state
            # Cross-check the caller's from_state against the row-locked
            # actual state. Mismatch = stale read; refuse with the same
            # closed-enum reason the state-machine validator uses for
            # any illegal pair (no separate vocabulary for stale-read).
            if actual_from_state != from_state:
                raise _SchedulerTransitionRefused("scheduler_transition_invalid_state_pair")

            # Pure-functional state-machine check under the row lock.
            _validate_transition(from_state=from_state, to_state=to_state)

            # State-cache UPDATE under the same lock. Per spec §4.4:
            # pending → running stamps started_at; running → terminal
            # OR pending → expired/failed/cancelled stamps terminal_at.
            new_started_at = row.started_at
            new_terminal_at = row.terminal_at
            update_values: dict[str, Any] = {"state": to_state}
            if from_state == "pending" and to_state == "running":
                update_values["started_at"] = now
                new_started_at = now
            if to_state in {
                "completed",
                "failed",
                "cancelled",
                "preempted",
                "expired",
            }:
                update_values["terminal_at"] = now
                new_terminal_at = now
            await conn.execute(
                update(_scheduler_tasks)
                .where(_scheduler_tasks.c.task_id == task_id)
                .values(**update_values)
            )
            return _LockedTaskSnapshot(
                tenant_id=row.tenant_id,
                pack_id=row.pack_id,
                actor_subject=row.actor_subject,
                class_=row.class_,
                pack_kind=row.pack_kind,
                pack_risk_tier=row.pack_risk_tier,
                requested_estimated_tokens=row.requested_estimated_tokens,
                parent_task_id=(
                    str(row.parent_task_id) if row.parent_task_id is not None else None
                ),
                submitted_at=row.submitted_at,
                started_at=new_started_at,
                terminal_at=new_terminal_at,
            )

        def _build_record(captured: _LockedTaskSnapshot) -> DecisionRecord:
            # Full chain-payload evidence snapshot per
            # [[feedback_chain_payload_is_evidence_snapshot]]: every
            # mutable scheduler_tasks column lands on the chain row so
            # the chain is self-contained for examiner replay.
            payload: dict[str, Any] = {
                "task_id": str(task_id),
                "from_state": from_state,
                "to_state": to_state,
                "tenant_id": captured.tenant_id,
                "pack_id": captured.pack_id,
                "actor_subject": captured.actor_subject,
                "class_": captured.class_,
                "pack_kind": captured.pack_kind,
                "pack_risk_tier": captured.pack_risk_tier,
                "requested_estimated_tokens": captured.requested_estimated_tokens,
                "parent_task_id": captured.parent_task_id,
                "submitted_at": captured.submitted_at.isoformat(),
                "started_at": (
                    captured.started_at.isoformat() if captured.started_at is not None else None
                ),
                "terminal_at": (
                    captured.terminal_at.isoformat() if captured.terminal_at is not None else None
                ),
                **payload_extras,
            }
            return DecisionRecord(
                decision_type=decision_type,
                request_id=request_id,
                payload=payload,
                actor_id=actor_id,
                tenant_id=captured.tenant_id,
                iso_controls=SCHEDULER_ISO_CONTROLS,
            )

        return await self._history.append_with_precondition(
            record_builder=_build_record,
            precondition=_precondition,
        )
