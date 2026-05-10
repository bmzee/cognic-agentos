"""Sprint 7B.1 T3 — bank pack record store (per ADR-012).

This module is **CRITICAL CONTROLS** per AGENTS.md "Authoring — Bank pack
lifecycle (Sprint 7B.1)". 95% line / 90% branch coverage required by the
gate at ``tools/check_critical_coverage.py`` (T7 promotion).

Responsibilities
----------------

- **Write side.** :meth:`PackRecordStore.save_draft` inserts a fresh
  ``draft``-state pack row (no chain event — draft creation is the
  state-machine genesis, not a transition).
  :meth:`PackRecordStore.transition` is the load-bearing primitive:
  every state advance flows through
  :meth:`cognic_agentos.core.decision_history.DecisionHistoryStore.append_with_precondition`
  (Sprint-2.5 T2 atomic primitive). The precondition closure
  ``SELECT ... FOR UPDATE``s the pack row, calls
  :func:`cognic_agentos.packs.lifecycle.validate_transition` under the
  chain-head lock, and either raises ``LifecycleTransitionRefused``
  (transaction rolls back) or atomically advances the
  ``packs.state`` cache + emits the ``pack.lifecycle.<to_state>``
  chain row (Doctrine Lock D in the plan-of-record).
- **Read side.** :meth:`PackRecordStore.load`,
  :meth:`PackRecordStore.list_by_status`, and
  :meth:`PackRecordStore.load_lifecycle_history` read denormalised
  ``packs.state`` (O(1)) or walk the
  ``decision_history.event_type LIKE 'pack.lifecycle.%'`` slice
  filtered to ``payload['pack_id'] == str(pack_id)`` — same JSON-key
  client-side filter pattern as
  :meth:`cognic_agentos.core.escalation.EscalationStore._read_current_state_within_txn`.

Doctrine
--------

- **No silent fallback.** Three orthogonal failure categories, each
  with a distinct exception class so callers can dispatch on the
  difference without parsing strings (T3 R1 P3 doctrine clarification —
  pre-R1 the doctrine listed only two categories because
  :class:`PackRecordRefused` did not yet exist):

  1. **API-contract refusal** — :class:`PackRecordRefused` carries the
     closed-enum :data:`PackRecordRefusalReason` (Wave-1: only
     ``pack_record_save_draft_initial_state_not_draft``). Raised by
     :meth:`PackRecordStore.save_draft` BEFORE any DB connection is
     acquired when the supplied record violates the API's preconditions
     (``state != "draft"`` would bypass the lifecycle audit chain).
  2. **State-machine transition refusal** —
     :class:`LifecycleTransitionRefused` carries the closed-enum
     :data:`cognic_agentos.packs.lifecycle.LifecycleRefusalReason`
     (13 reasons). Raised by :meth:`PackRecordStore.transition` from
     either path: PREFLIGHT
     (``lifecycle_transition_name_unknown`` — runtime guard at
     function entry; no DB connection acquired) or IN-PRECONDITION
     (any other reason — from
     :func:`cognic_agentos.packs.lifecycle.validate_transition` running
     under the chain-head lock; transaction rolls back atomically).
  3. **Lookup miss** — :class:`PackNotFound` carries the missing
     ``pack_id: uuid.UUID`` (NOT a closed enum — no enum is needed
     because the failure mode is single-valued; the structured field
     IS the diagnostic). Raised by :meth:`PackRecordStore.transition`'s
     precondition when the pack row's ``SELECT ... FOR UPDATE``
     returns no row. Distinct from refusals because no decision was
     made — the caller asked about a row that does not exist.
- **Chain is the source of truth** (Doctrine Lock D, mirroring
  ``governance_chain_heads`` denormalisation). ``packs.state`` is an
  atomically-maintained cache for O(1) reads; the canonical history
  lives in ``decision_history``.
- **Atomicity guarantee.** The chain INSERT + ``packs.state`` UPDATE
  + ``governance_chain_heads`` UPDATE all commit in a single
  ``engine.begin()`` transaction owned by ``append_with_precondition``.
  Failure at any step rolls back all three — fail-closed.
- **No RBAC enforcement** (Doctrine Lock G). ``actor_id`` is recorded
  in the chain payload + ``packs.last_actor`` but role gates are
  Sprint 7B.2 (alongside the 14 RBAC scopes per ADR-012).
- **No portal API surface** (Doctrine Lock F). HTTP DTOs + endpoints
  land in Sprint 7B.2.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Final, Literal

import pydantic
from sqlalchemy import (
    CheckConstraint,
    Column,
    Index,
    String,
    Table,
    Text,
    insert,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine
from sqlalchemy.types import TIMESTAMP, Uuid

from cognic_agentos.core.audit import _metadata
from cognic_agentos.core.decision_history import (
    DecisionHistoryStore,
    DecisionRecord,
    _decision_history,
)
from cognic_agentos.db.types import chain_hash_column_type
from cognic_agentos.packs.lifecycle import (
    _VALID_TRANSITIONS,
    LifecycleRefusalReason,
    PackKind,
    PackState,
    TransitionName,
    validate_transition,
)

#: Each :data:`TransitionName` in the canonical 10-tuple has exactly one
#: legal ``to_state`` (verified at build time by
#: ``tests/unit/packs/test_storage.py::TestSprint7B1TransitionToTargetStateMap``
#: against ``_VALID_TRANSITIONS``). Storage derives ``to_state`` from
#: ``transition`` alone so the public ``transition()`` API does not have
#: to take a redundant ``to_state`` argument that the lifecycle table
#: already implies. Drift is caught by the build-time test — adding a
#: new transition without an entry here OR adding a ``_VALID_TRANSITIONS``
#: row whose pair set has a different ``to_state`` than mapped here
#: would fail the drift detector.
_TRANSITION_TO_TARGET_STATE: Final[Mapping[TransitionName, PackState]] = {
    "submit": "submitted",
    "claim": "under_review",
    "approve": "approved",
    "reject": "rejected",
    "withdraw": "withdrawn",
    "allow_list": "allow_listed",
    "install": "installed",
    "disable": "disabled",
    "revoke": "revoked",
    "uninstall": "uninstalled",
}

#: Module-level Table object registered against the SAME ``_metadata`` as
#: ``audit_event`` + ``decision_history`` (imported from ``core/audit``).
#: A single ``_metadata.create_all()`` (in tests) or ``alembic upgrade
#: head`` (in production) creates ``packs`` alongside the chain tables.
#:
#: Column types use the shared dialect-portable seam at ``db/types`` —
#: ``chain_hash_column_type()`` for the 32-byte digest columns,
#: ``TIMESTAMP(timezone=True)`` for timestamps (NOT ``DateTime`` — same
#: Oracle-compile-output rationale documented at
#: ``20260430_0002_gateway_call_ledger.py:49+65-67``). T4's Alembic
#: migration mirrors this exact shape.
_packs = Table(
    "packs",
    _metadata,
    Column("id", Uuid(), primary_key=True),
    Column("kind", String(16), nullable=False),
    Column("pack_id", String(256), nullable=False),
    Column("display_name", String(256), nullable=False),
    Column("state", String(32), nullable=False),
    Column("manifest_digest", chain_hash_column_type(), nullable=False),
    Column("signed_artefact_digest", chain_hash_column_type(), nullable=False),
    Column("sbom_pointer", Text(), nullable=True),
    Column("tenant_id", String(256), nullable=True),
    Column("created_by", String(256), nullable=False),
    Column("last_actor", String(256), nullable=False),
    Column("created_at", TIMESTAMP(timezone=True), nullable=False),
    Column("updated_at", TIMESTAMP(timezone=True), nullable=False),
    CheckConstraint(
        "kind IN ('tool', 'skill', 'agent', 'hook')",
        name="ck_packs_kind",
    ),
    CheckConstraint(
        "state IN ('draft', 'submitted', 'under_review', 'approved', "
        "'rejected', 'withdrawn', 'allow_listed', 'installed', 'disabled', "
        "'revoked', 'uninstalled')",
        name="ck_packs_state",
    ),
    Index("ix_packs_kind_state", "kind", "state"),
    Index("ix_packs_tenant_state", "tenant_id", "state"),
)


class LifecycleTransitionRefused(Exception):
    """Raised by :meth:`PackRecordStore.transition` when the lifecycle
    state machine refuses the transition. Carries the closed-enum
    :data:`cognic_agentos.packs.lifecycle.LifecycleRefusalReason` so
    callers (T6+, Sprint 7B.2 portal handlers) can dispatch on the
    exact failure mode without parsing strings.

    The exception fires from inside the ``append_with_precondition``
    precondition closure — the entire transaction rolls back, no
    chain row inserted, no state cache mutation.
    """

    def __init__(self, reason: LifecycleRefusalReason) -> None:
        self.reason = reason
        super().__init__(reason)


class PackNotFound(Exception):
    """Raised by :meth:`PackRecordStore.transition` when the requested
    ``pack_id`` has no row in ``packs``. Distinct from
    :class:`LifecycleTransitionRefused` so callers can dispatch on the
    difference between "the pack does not exist" and "the pack exists
    but the transition is refused"."""

    def __init__(self, pack_id: uuid.UUID) -> None:
        self.pack_id = pack_id
        super().__init__(f"pack not found: {pack_id}")


#: Closed-enum vocabulary for ``save_draft``-API contract refusals. The
#: only Wave-1 reason is the genesis-state guard; future kind-specific
#: or identity-specific preconditions land alongside without breaking
#: the closed-enum dispatch contract.
PackRecordRefusalReason = Literal["pack_record_save_draft_initial_state_not_draft",]


class PackRecordRefused(Exception):
    """Raised by :meth:`PackRecordStore.save_draft` when the supplied
    :class:`PackRecord` violates the API contract. The Wave-1 contract
    is genesis-state-only: ``save_draft`` is the entry point to the
    state machine, so ``record.state`` MUST be ``"draft"``. Calling
    ``save_draft(state="installed")`` would persist a row with no
    ``decision_history`` predecessor, bypassing the lifecycle audit
    path entirely (T3 R1 P2 finding).

    Distinct from :class:`LifecycleTransitionRefused` because this is
    NOT a state-machine refusal — the lifecycle table never had a
    chance to fire. Callers (Sprint 7B.2 portal author handlers) can
    dispatch on the exception class to distinguish "your draft request
    was malformed" from "the state machine refused your transition".
    """

    def __init__(
        self,
        reason: PackRecordRefusalReason,
        *,
        state: PackState | None = None,
    ) -> None:
        self.reason = reason
        self.state = state
        if state is not None:
            super().__init__(f"{reason} (state={state!r})")
        else:
            super().__init__(reason)


class PackRecord(pydantic.BaseModel):
    """Frozen + ``extra="forbid"`` Pydantic v2 model for a pack record.

    Pack-kind / pack-state vocabulary correctness is enforced at
    construction (Doctrine Lock E layer 1) — out-of-vocabulary values
    are rejected before they reach the Postgres CHECK constraint or the
    chain-emission path. The model is wire-shape parallel to the
    ``packs`` table; column-for-field mapping is implicit (same
    canonical names).
    """

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")

    id: uuid.UUID
    kind: PackKind
    pack_id: str
    display_name: str
    state: PackState
    manifest_digest: bytes
    signed_artefact_digest: bytes
    sbom_pointer: str | None
    tenant_id: str | None
    created_by: str
    last_actor: str
    created_at: datetime
    updated_at: datetime


class PackRecordStore:
    """Async pack-record store. Constructor takes an
    :class:`AsyncEngine` and lazily wraps it in a
    :class:`DecisionHistoryStore` (mirrors
    ``core/escalation.py:463-465``).

    Transitions go through the Sprint-2.5 T2 atomic primitive
    :meth:`DecisionHistoryStore.append_with_precondition`; the
    precondition closure does the row-locked state read + validation +
    state-cache UPDATE under the chain-head lock. The chain INSERT +
    state UPDATE + chain-head UPDATE all commit atomically.
    """

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._history = DecisionHistoryStore(engine)

    async def save_draft(self, record: PackRecord) -> uuid.UUID:
        """Insert a fresh ``draft``-state pack row. Returns the row id.

        No chain event is emitted — draft creation is the state-machine
        genesis, not a transition. The first chain event fires on the
        first ``transition()`` (typically ``submit``).

        Refuses (fail-loud, fail-closed) any record whose ``state`` is
        not ``"draft"``. This is the API contract guard that prevents
        callers from bypassing the lifecycle audit path: ``PackRecord``
        is wire-shape for rows in every lifecycle state (so ``load()``
        can return them), but ``save_draft`` is specifically the
        entry point to the state machine. Without this guard,
        ``save_draft(record_with_state='installed')`` would persist
        a row with no ``decision_history`` predecessor — bypassing the
        chain emission and producing an audit-unrooted pack record.
        Raises :class:`PackRecordRefused` with closed-enum reason
        ``pack_record_save_draft_initial_state_not_draft``; no pack
        row is inserted (the guard runs BEFORE the INSERT).
        """

        if record.state != "draft":
            raise PackRecordRefused(
                "pack_record_save_draft_initial_state_not_draft",
                state=record.state,
            )

        async with self._engine.begin() as conn:
            await conn.execute(
                insert(_packs).values(
                    id=record.id,
                    kind=record.kind,
                    pack_id=record.pack_id,
                    display_name=record.display_name,
                    state=record.state,
                    manifest_digest=record.manifest_digest,
                    signed_artefact_digest=record.signed_artefact_digest,
                    sbom_pointer=record.sbom_pointer,
                    tenant_id=record.tenant_id,
                    created_by=record.created_by,
                    last_actor=record.last_actor,
                    created_at=record.created_at,
                    updated_at=record.updated_at,
                )
            )
        return record.id

    async def transition(
        self,
        *,
        pack_id: uuid.UUID,
        transition: TransitionName,
        actor_id: str,
        tenant_id: str | None,
        evidence_pointer: str | None,
        iso_controls: tuple[str, ...],
        request_id: str,
    ) -> tuple[uuid.UUID, bytes]:
        """Atomically advance a pack through a named lifecycle
        transition. Returns ``(record_id, chain_hash)`` from the chain
        insert.

        Atomic semantics (Doctrine Lock D): chain-head ``SELECT FOR
        UPDATE`` → pack-row ``SELECT FOR UPDATE`` → ``validate_transition``
        → state-cache UPDATE → chain row INSERT → chain-head UPDATE,
        all inside a single ``engine.begin()`` transaction owned by
        :meth:`DecisionHistoryStore.append_with_precondition`. Failure
        at any step rolls back all three — fail-closed.

        Raises (PREFLIGHT — NO DB connection acquired):
          :class:`LifecycleTransitionRefused` with reason
            ``"lifecycle_transition_name_unknown"`` — the supplied
            ``transition`` is not a member of
            :data:`cognic_agentos.packs.lifecycle.TransitionName`.
            The runtime guard fires at function entry (mirrors the
            ``packs/lifecycle.py`` step-3 guard from T2 R1 P2 + the
            T3 R1 P2 #2 reviewer fix). No transaction is started, so
            there is nothing to roll back.

        Raises (IN-PRECONDITION — transaction rolls back atomically):
          :class:`PackNotFound` — ``pack_id`` has no row in ``packs``
            after the precondition's ``SELECT ... FOR UPDATE`` returns.
          :class:`LifecycleTransitionRefused` with any reason OTHER
            than ``"lifecycle_transition_name_unknown"`` — the state
            machine refused the transition; the closed-enum reason
            came from
            :func:`cognic_agentos.packs.lifecycle.validate_transition`
            running under the chain-head FOR UPDATE lock. Examples:
            ``"lifecycle_transition_invalid_state_pair"``,
            ``"lifecycle_transition_terminal_state"``,
            ``"lifecycle_transition_approve_without_review_claim"``.

        The contract — no chain row inserted, no ``packs.state`` cache
        mutation — holds for BOTH preflight and in-precondition refusal
        paths; only the rollback mechanism differs. Preflight: nothing
        to roll back because the function returns before
        ``append_with_precondition`` is called. In-precondition: the
        ``engine.begin()`` transaction owned by
        ``DecisionHistoryStore.append_with_precondition`` rolls back
        atomically (mirror of Sprint-2.5 T2's rollback contract).
        """

        # Runtime guard: ``TransitionName`` is a Literal but Python
        # does not enforce Literal at runtime, so a caller passing
        # ``transition="archive"`` would raise ``KeyError`` from the
        # ``_TRANSITION_TO_TARGET_STATE[transition]`` indexed access
        # below — leaking an unstructured exception past the
        # closed-enum boundary that downstream consumers (Sprint 7B.2
        # portal handlers, T6 harness dispatch) catch on
        # ``LifecycleTransitionRefused``. Mirrors the asymmetric-runtime-
        # guard fix at ``packs/lifecycle.py`` step 3 (T2 R1 P2): both
        # layers MUST refuse out-of-vocabulary transition names with
        # the same ``lifecycle_transition_name_unknown`` closed-enum
        # reason. T3 R1 P2 finding.
        if transition not in _TRANSITION_TO_TARGET_STATE:
            raise LifecycleTransitionRefused("lifecycle_transition_name_unknown")

        target_state = _TRANSITION_TO_TARGET_STATE[transition]

        async def _precondition(
            conn: AsyncConnection,
            prev_sequence: int,
            prev_hash: bytes,
        ) -> tuple[PackState, PackKind]:
            # SELECT FOR UPDATE on the pack row. Locks the row even
            # though the chain-head lock already serialises chain
            # appends — documents future-writer safety per Doctrine
            # Lock D step 1.
            row = (
                await conn.execute(
                    select(_packs.c.state, _packs.c.kind)
                    .where(_packs.c.id == pack_id)
                    .with_for_update()
                )
            ).first()
            if row is None:
                raise PackNotFound(pack_id)

            from_state: PackState = row.state
            kind: PackKind = row.kind

            reason = validate_transition(
                from_state=from_state,
                to_state=target_state,
                kind=kind,
                transition=transition,
            )
            if reason is not None:
                raise LifecycleTransitionRefused(reason)

            # State-cache UPDATE under the lock. ``packs`` is not a
            # chain table per ``core/decision_history.py:461-462`` —
            # preconditions MAY write non-chain tables under the same
            # transaction. last_actor + updated_at moved here so
            # the chain row's payload reflects the persisted state.
            await conn.execute(
                update(_packs)
                .where(_packs.c.id == pack_id)
                .values(
                    state=target_state,
                    last_actor=actor_id,
                    updated_at=datetime.now(UTC),
                )
            )
            return from_state, kind

        def _build_record(captured: tuple[PackState, PackKind]) -> DecisionRecord:
            from_state, kind = captured
            return DecisionRecord(
                decision_type=f"pack.lifecycle.{target_state}",
                request_id=request_id,
                actor_id=actor_id,
                tenant_id=tenant_id,
                payload={
                    "pack_id": str(pack_id),
                    "kind": kind,
                    "from_state": from_state,
                    "to_state": target_state,
                    "transition_name": transition,
                    "evidence_pointer": evidence_pointer,
                    "iso_controls": list(iso_controls),
                },
                iso_controls=iso_controls,
            )

        return await self._history.append_with_precondition(
            record_builder=_build_record,
            precondition=_precondition,
        )

    async def load(self, pack_id: uuid.UUID) -> PackRecord | None:
        """Return the pack record for ``pack_id`` or ``None`` if none
        exists. O(1) read against the ``packs.state`` cache; the
        canonical history walks via :meth:`load_lifecycle_history`.
        """

        async with self._engine.connect() as conn:
            row = (await conn.execute(select(_packs).where(_packs.c.id == pack_id))).first()
        if row is None:
            return None
        return _row_to_record(dict(row._mapping))

    async def list_by_status(
        self,
        state: PackState,
        limit: int = 50,
        cursor: uuid.UUID | None = None,
    ) -> list[PackRecord]:
        """Paginated state-filter read. Returns records whose
        denormalised ``packs.state`` cache matches.

        ``cursor`` is the last id returned by the previous page; pass
        ``None`` (default) for the first page. Ordering is by
        ``packs.id`` so the cursor pagination is dialect-portable
        across PG / Oracle / SQLite without depending on
        ``ORDER BY ... NULLS LAST`` quirks.
        """

        stmt = select(_packs).where(_packs.c.state == state).order_by(_packs.c.id)
        if cursor is not None:
            stmt = stmt.where(_packs.c.id > cursor)
        stmt = stmt.limit(limit)
        async with self._engine.connect() as conn:
            rows = (await conn.execute(stmt)).all()
        return [_row_to_record(dict(r._mapping)) for r in rows]

    async def load_lifecycle_history(self, pack_id: uuid.UUID) -> list[DecisionRecord]:
        """Walk the ``decision_history.event_type LIKE 'pack.lifecycle.%'``
        slice filtered to ``payload['pack_id'] == str(pack_id)``,
        sorted by ``sequence`` ascending. Mirrors
        :meth:`cognic_agentos.core.escalation.EscalationStore._read_current_state_within_txn`
        JSON-key extraction (client-side filter on payload key —
        dialect-portable across PG native JSON / SQLite native JSON /
        Oracle CLOB-with-app-side-serialisation).
        """

        target_id = str(pack_id)
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(
                        _decision_history.c.event_type,
                        _decision_history.c.request_id,
                        _decision_history.c.tenant_id,
                        _decision_history.c.trace_id,
                        _decision_history.c.span_id,
                        _decision_history.c.langfuse_trace_id,
                        _decision_history.c.provider_label,
                        _decision_history.c.iso_controls,
                        _decision_history.c.payload,
                        _decision_history.c.sequence,
                    )
                    .where(_decision_history.c.event_type.like("pack.lifecycle.%"))
                    .order_by(_decision_history.c.sequence)
                )
            ).all()

        history: list[DecisionRecord] = []
        for row in rows:
            payload: dict[str, Any] = row.payload or {}
            if payload.get("pack_id") != target_id:
                continue
            iso_controls_raw = row.iso_controls or []
            history.append(
                DecisionRecord(
                    decision_type=row.event_type,
                    request_id=row.request_id,
                    payload=payload,
                    actor_id=None,
                    tenant_id=row.tenant_id,
                    trace_id=row.trace_id,
                    span_id=row.span_id,
                    langfuse_trace_id=row.langfuse_trace_id,
                    provider_label=row.provider_label,
                    iso_controls=tuple(iso_controls_raw),
                )
            )
        return history


def _row_to_record(mapping: Mapping[str, Any]) -> PackRecord:
    """Project a ``packs`` row mapping back into a :class:`PackRecord`.
    Single source of truth for column → field name parity.
    """

    return PackRecord(
        id=mapping["id"],
        kind=mapping["kind"],
        pack_id=mapping["pack_id"],
        display_name=mapping["display_name"],
        state=mapping["state"],
        manifest_digest=bytes(mapping["manifest_digest"]),
        signed_artefact_digest=bytes(mapping["signed_artefact_digest"]),
        sbom_pointer=mapping["sbom_pointer"],
        tenant_id=mapping["tenant_id"],
        created_by=mapping["created_by"],
        last_actor=mapping["last_actor"],
        created_at=mapping["created_at"],
        updated_at=mapping["updated_at"],
    )


# Build-time invariant: the cached _TRANSITION_TO_TARGET_STATE map and
# the lifecycle module's _VALID_TRANSITIONS table MUST agree on the
# (transition_name → to_state) projection. Asserted here so import-time
# alone surfaces drift; the build-time test in test_storage.py provides
# the operator-facing diagnostic.
assert set(_TRANSITION_TO_TARGET_STATE.keys()) == set(_VALID_TRANSITIONS.keys()), (
    "_TRANSITION_TO_TARGET_STATE keys diverge from _VALID_TRANSITIONS keys"
)
for _t, _target in _TRANSITION_TO_TARGET_STATE.items():
    _to_states = {to for _, to in _VALID_TRANSITIONS[_t]}
    assert _to_states == {_target}, (
        f"_TRANSITION_TO_TARGET_STATE[{_t!r}]={_target!r} diverges from "
        f"_VALID_TRANSITIONS[{_t!r}] to_state set {_to_states!r}"
    )
del _t, _target, _to_states


__all__: tuple[str, ...] = (
    "LifecycleTransitionRefused",
    "PackNotFound",
    "PackRecord",
    "PackRecordRefusalReason",
    "PackRecordRefused",
    "PackRecordStore",
)
