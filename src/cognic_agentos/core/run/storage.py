"""Sprint 14A-A3a — Postgres/Oracle-backed run-record store (ADR-022 + ADR-004).

The run mirror of ``core/scheduler/storage.py`` + ``packs/storage.py``. CRITICAL
CONTROL (core/ stop-rule per AGENTS.md). Consumer of
``DecisionHistoryStore.append_with_precondition`` — appends
``run.lifecycle.<state>`` chain rows. Does NOT modify the chain substrate.

STORE-ONLY / DORMANT (Sprint 14A-A3a): no production caller yet — A3b wires the
executor + the resolver. Two write paths: ``create_run()`` (genesis: INSERT a
``pending`` row + append ``run.lifecycle.pending``) and ``transition()``
(SELECT ... FOR UPDATE → validate_transition → UPDATE state + optional nullable
columns → append ``run.lifecycle.<to_state>``). Atomic semantics (Doctrine Lock
D): chain-head FOR UPDATE → run-row FOR UPDATE → validate → state-cache UPDATE →
chain row INSERT → chain-head UPDATE, all in one ``engine.begin()`` transaction.

Tenant isolation: every read (``load`` / ``list_for_tenant``) + the transition
SELECT is tenant-scoped — a cross-tenant ``run_id`` reads as absent (``load`` →
None; ``transition`` → ``RunNotFound``), the wire-collapse doctrine
``packs``/``models`` ship.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from sqlalchemy import (
    TIMESTAMP,
    CheckConstraint,
    Column,
    Index,
    String,
    Table,
    Uuid,
    insert,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from cognic_agentos.core.audit import _metadata
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.core.run._types import (
    RunRecord,
    RunState,
    RunTransitionRefused,
    validate_transition,
)

RUN_TENANT_ID_MAX_LEN: Final[int] = 128
RUN_PACK_ID_MAX_LEN: Final[int] = 128
RUN_PACK_VERSION_MAX_LEN: Final[int] = 128
RUN_SESSION_ID_MAX_LEN: Final[int] = 128
RUN_CHECKPOINT_ID_MAX_LEN: Final[int] = 32  # sandbox CheckpointId = uuid4().hex (32 hex chars)

#: run.* ISO-control mapping deferred (Human-only decision), matching the
#: executor's _RUN_EVIDENCE_ISO_CONTROLS = ().
RUN_LIFECYCLE_ISO_CONTROLS: Final[tuple[str, ...]] = ()

#: Reserved chain-payload keys that transition() builds from the row-locked
#: snapshot — caller-supplied payload_extras MUST NOT overlap (chain-payload-is-
#: evidence-snapshot doctrine; mirrors scheduler storage's reserved-key guard).
_RESERVED_TRANSITION_PAYLOAD_KEYS: Final[frozenset[str]] = frozenset(
    {
        "run_id",
        "from_state",
        "to_state",
        "tenant_id",
        "pack_id",
        "pack_uuid",
        "pack_version",
        "task_id",
        "session_id",
        "checkpoint_id",
        "approval_request_id",
        "created_at",
        "updated_at",
    }
)

#: Transition-target state → chain decision_type. The A3a subset (5 reachable
#: transition targets; genesis ``pending`` uses run.lifecycle.pending in
#: create_run). A3b EXPANDS this map (suspended/woken/cancelled) alongside
#: _A3A_VALID_TRANSITIONS — NEVER the RunState vocabulary (the doctrine pin).
_STATE_TO_DECISION_TYPE: Final[dict[RunState, str]] = {
    "running": "run.lifecycle.running",
    "completed": "run.lifecycle.completed",
    "failed": "run.lifecycle.failed",
    "refused": "run.lifecycle.refused",
    "pending_approval": "run.lifecycle.pending_approval",
}

_GENESIS_DECISION_TYPE: Final[str] = "run.lifecycle.pending"

#: SQLAlchemy Core Table, registered against the shared core.audit._metadata so
#: _metadata.create_all (tests) + alembic upgrade head (migration 0011) both
#: build it. The migration at 20260615_0011_runs.py MUST mirror this Table
#: exactly; drift pinned by tests/unit/db/test_migration_20260615_0011.py.
_runs = Table(
    "runs",
    _metadata,
    Column("run_id", Uuid(), primary_key=True),
    Column("tenant_id", String(RUN_TENANT_ID_MAX_LEN), nullable=False),
    Column("pack_id", String(RUN_PACK_ID_MAX_LEN), nullable=False),
    Column("pack_uuid", Uuid(), nullable=False),
    Column("pack_version", String(RUN_PACK_VERSION_MAX_LEN), nullable=False),
    Column("task_id", Uuid(), nullable=True),
    Column("session_id", String(RUN_SESSION_ID_MAX_LEN), nullable=True),
    Column("checkpoint_id", String(RUN_CHECKPOINT_ID_MAX_LEN), nullable=True),
    Column("approval_request_id", Uuid(), nullable=True),
    Column("state", String(32), nullable=False),
    Column("created_at", TIMESTAMP(timezone=True), nullable=False),
    Column("updated_at", TIMESTAMP(timezone=True), nullable=False),
    CheckConstraint(
        "state IN ('pending', 'running', 'completed', 'failed', 'refused', "
        "'pending_approval', 'suspended', 'woken', 'cancelled')",
        name="ck_runs_state",
    ),
    Index("ix_runs_tenant_state", "tenant_id", "state"),
)


@dataclass(frozen=True, slots=True)
class _LockedRunSnapshot:
    """Row-locked runs projection threaded precondition → record builder so the
    chain payload is the canonical evidence snapshot. Reflects the post-UPDATE
    values (nullable columns carry the just-set values when the transition
    supplied them)."""

    tenant_id: str
    pack_id: str
    pack_uuid: uuid.UUID
    pack_version: str
    task_id: uuid.UUID | None
    session_id: str | None
    checkpoint_id: str | None
    approval_request_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class RunNotFound(Exception):
    """Raised when transition() / a tenant-scoped read targets a run_id with no
    (tenant-visible) row. Caller-distinct from RunTransitionRefused."""

    def __init__(self, run_id: uuid.UUID) -> None:
        super().__init__(f"run_not_found: {run_id}")
        self.run_id = run_id


def _to_record(row: Any) -> RunRecord:
    return RunRecord(
        run_id=row.run_id,
        tenant_id=row.tenant_id,
        pack_id=row.pack_id,
        pack_uuid=row.pack_uuid,
        pack_version=row.pack_version,
        task_id=row.task_id,
        session_id=row.session_id,
        checkpoint_id=row.checkpoint_id,
        approval_request_id=row.approval_request_id,
        state=row.state,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


class RunRecordStore:
    """Postgres/Oracle-backed run lifecycle store. Async; raises on every
    refusal/failure (no silent-skip)."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._history = DecisionHistoryStore(engine)

    async def create_run(
        self,
        *,
        run_id: uuid.UUID,
        tenant_id: str,
        pack_id: str,
        pack_uuid: uuid.UUID,
        pack_version: str,
        task_id: uuid.UUID | None = None,
        request_id: str,
    ) -> tuple[uuid.UUID, bytes]:
        """Genesis: INSERT a ``pending`` runs row + append run.lifecycle.pending
        atomically. Returns (chain_record_id, chain_hash). INSERT failure (PK
        collision) rolls back before any chain row."""
        now = datetime.now(UTC)

        async def _precondition(conn: AsyncConnection, _seq: int, _hash: bytes) -> None:
            await conn.execute(
                insert(_runs).values(
                    run_id=run_id,
                    tenant_id=tenant_id,
                    pack_id=pack_id,
                    pack_uuid=pack_uuid,
                    pack_version=pack_version,
                    task_id=task_id,
                    session_id=None,
                    checkpoint_id=None,
                    approval_request_id=None,
                    state="pending",
                    created_at=now,
                    updated_at=now,
                )
            )

        def _build(_: None) -> DecisionRecord:
            return DecisionRecord(
                decision_type=_GENESIS_DECISION_TYPE,
                request_id=request_id,
                payload={
                    "run_id": str(run_id),
                    "from_state": None,
                    "to_state": "pending",
                    "tenant_id": tenant_id,
                    "pack_id": pack_id,
                    "pack_uuid": str(pack_uuid),
                    "pack_version": pack_version,
                    "task_id": str(task_id) if task_id is not None else None,
                    "session_id": None,
                    "checkpoint_id": None,
                    "approval_request_id": None,
                    "created_at": now.isoformat(),
                    "updated_at": now.isoformat(),
                },
                actor_id=tenant_id,  # genesis has no actor context yet; A3b threads the real actor
                tenant_id=tenant_id,
                iso_controls=RUN_LIFECYCLE_ISO_CONTROLS,
            )

        return await self._history.append_with_precondition(
            record_builder=_build, precondition=_precondition
        )

    async def transition(
        self,
        *,
        run_id: uuid.UUID,
        tenant_id: str,
        from_state: RunState,
        to_state: RunState,
        actor_id: str,
        request_id: str,
        session_id: str | None = None,
        task_id: uuid.UUID | None = None,
        checkpoint_id: str | None = None,
        approval_request_id: uuid.UUID | None = None,
        payload_extras: dict[str, Any] | None = None,
    ) -> tuple[uuid.UUID, bytes]:
        """State-machine transition (tenant-scoped, atomic). Preflight: to_state
        must be a known A3a transition target; payload_extras must not overlap
        the reserved evidence keys. In-precondition: SELECT ... FOR UPDATE the
        tenant-scoped row (absent → RunNotFound) → from_state cross-check (stale
        → RunTransitionRefused) → validate_transition → UPDATE state + updated_at
        + any provided nullable columns → append run.lifecycle.<to_state>.

        The nullable column kwargs (session_id/task_id/checkpoint_id/
        approval_request_id) are additive A3b/A3c seams: set ONLY when non-None
        (None = leave column unchanged). A3a tests exercise them; no production
        caller."""
        extras = payload_extras or {}
        # Preflight #1 — known A3a transition target (mirrors scheduler preflight).
        if to_state not in _STATE_TO_DECISION_TYPE:
            raise RunTransitionRefused("run_transition_invalid_state_pair")
        # Preflight #2 — reserved evidence-key overlap guard.
        overlap = _RESERVED_TRANSITION_PAYLOAD_KEYS & extras.keys()
        if overlap:
            raise ValueError(
                f"payload_extras overlaps reserved transition evidence keys: "
                f"{sorted(overlap)}. Reserved: {sorted(_RESERVED_TRANSITION_PAYLOAD_KEYS)}."
            )

        now = datetime.now(UTC)
        decision_type = _STATE_TO_DECISION_TYPE[to_state]

        async def _precondition(
            conn: AsyncConnection, _seq: int, _hash: bytes
        ) -> _LockedRunSnapshot:
            row = (
                await conn.execute(
                    select(
                        _runs.c.state,
                        _runs.c.pack_id,
                        _runs.c.pack_uuid,
                        _runs.c.pack_version,
                        _runs.c.task_id,
                        _runs.c.session_id,
                        _runs.c.checkpoint_id,
                        _runs.c.approval_request_id,
                        _runs.c.created_at,
                    )
                    .where(_runs.c.run_id == run_id)
                    .where(_runs.c.tenant_id == tenant_id)  # tenant boundary
                    .with_for_update()
                )
            ).first()
            if row is None:
                raise RunNotFound(run_id)
            if row.state != from_state:
                raise RunTransitionRefused("run_transition_invalid_state_pair")
            validate_transition(from_state=from_state, to_state=to_state)

            update_values: dict[str, Any] = {"state": to_state, "updated_at": now}
            new_session = row.session_id
            new_task = row.task_id
            new_ckpt = row.checkpoint_id
            new_appr = row.approval_request_id
            if session_id is not None:
                update_values["session_id"] = session_id
                new_session = session_id
            if task_id is not None:
                update_values["task_id"] = task_id
                new_task = task_id
            if checkpoint_id is not None:
                update_values["checkpoint_id"] = checkpoint_id
                new_ckpt = checkpoint_id
            if approval_request_id is not None:
                update_values["approval_request_id"] = approval_request_id
                new_appr = approval_request_id
            await conn.execute(
                update(_runs).where(_runs.c.run_id == run_id).values(**update_values)
            )
            return _LockedRunSnapshot(
                tenant_id=tenant_id,
                pack_id=row.pack_id,
                pack_uuid=row.pack_uuid,
                pack_version=row.pack_version,
                task_id=new_task,
                session_id=new_session,
                checkpoint_id=new_ckpt,
                approval_request_id=new_appr,
                created_at=row.created_at,
                updated_at=now,
            )

        def _build(cap: _LockedRunSnapshot) -> DecisionRecord:
            payload: dict[str, Any] = {
                "run_id": str(run_id),
                "from_state": from_state,
                "to_state": to_state,
                "tenant_id": cap.tenant_id,
                "pack_id": cap.pack_id,
                "pack_uuid": str(cap.pack_uuid),
                "pack_version": cap.pack_version,
                "task_id": str(cap.task_id) if cap.task_id is not None else None,
                "session_id": cap.session_id,
                "checkpoint_id": cap.checkpoint_id,
                "approval_request_id": (
                    str(cap.approval_request_id) if cap.approval_request_id is not None else None
                ),
                "created_at": cap.created_at.isoformat(),
                "updated_at": cap.updated_at.isoformat(),
                **extras,
            }
            return DecisionRecord(
                decision_type=decision_type,
                request_id=request_id,
                payload=payload,
                actor_id=actor_id,
                tenant_id=cap.tenant_id,
                iso_controls=RUN_LIFECYCLE_ISO_CONTROLS,
            )

        return await self._history.append_with_precondition(
            record_builder=_build, precondition=_precondition
        )

    async def load(self, run_id: uuid.UUID, *, tenant_id: str) -> RunRecord | None:
        """Tenant-scoped read (the A3b resolver substrate). A run owned by
        another tenant returns None (cross-tenant-invisible)."""
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(_runs)
                    .where(_runs.c.run_id == run_id)
                    .where(_runs.c.tenant_id == tenant_id)
                )
            ).first()
        return _to_record(row) if row is not None else None

    async def list_for_tenant(
        self,
        tenant_id: str,
        *,
        limit: int = 50,
        cursor: uuid.UUID | None = None,
        state: RunState | None = None,
    ) -> list[RunRecord]:
        """Paginated tenant-scoped list (mirrors packs.storage.list_for_tenant).
        The ``tenant_id`` WHERE clause IS the boundary. ``cursor`` is the last
        run_id of the previous page (None = first page); ordering is by
        ``runs.run_id`` so keyset cursor pagination is dialect-portable across
        PG/Oracle/SQLite. Optional ``state`` filter over ix_runs_tenant_state."""
        stmt = select(_runs).where(_runs.c.tenant_id == tenant_id)
        if state is not None:
            stmt = stmt.where(_runs.c.state == state)
        if cursor is not None:
            stmt = stmt.where(_runs.c.run_id > cursor)
        stmt = stmt.order_by(_runs.c.run_id).limit(limit)
        async with self._engine.connect() as conn:
            rows = (await conn.execute(stmt)).all()
        return [_to_record(r) for r in rows]
