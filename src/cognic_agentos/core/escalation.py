"""Strict escalation state machine — every transition emits one
hash-chained ``DecisionRecord`` into the existing ``decision_history``
chain via T2's ``DecisionHistoryStore.append_with_precondition``
primitive.

**Critical-controls module.** Per AGENTS.md + the Sprint 2.5 plan-
of-record (PR #7 / commit ``4733b52``): ≥95% line + ≥90% branch
coverage; halt-before-commit per edit. Sprint 2.5 plan T3 contract
implemented verbatim.

State machine (locked at the plan-of-record):

    open ──► acknowledged ──► assigned ──► (resolved | re-escalated)
                ▲                                │
                └────────────── re-escalated ────┘

  - ``open`` is the genesis state; produced by ``EscalationStore.open()``.
  - ``acknowledged`` is reached from ``open`` (initial) or
    ``re-escalated`` (loopback).
  - ``assigned`` is reached only from ``acknowledged``.
  - ``resolved`` is the terminal state; reached only from
    ``assigned``.
  - ``re-escalated`` is reached only from ``assigned``; loops back
    through ``acknowledged``.

Every other transition is illegal and raises
``IllegalEscalationTransition``. Self-transitions are also illegal
(no-op transitions would emit chain-noise rows that examiners would
have to filter — explicitly forbidden).

Concurrency / atomicity (load-bearing — closes the TOCTOU window
the original draft of the plan had):

  - ``transition()`` uses ``DecisionHistoryStore.append_with_precondition``
    (T2 Option-A primitive). The precondition runs INSIDE the
    chain-head FOR UPDATE locked transaction:
      1. SELECT FOR UPDATE on chain_heads → (prev_seq, prev_hash).
      2. Precondition reads the chain's current end-state for the
         given escalation_id. Validates against ``_LEGAL_TRANSITIONS``.
         If the requested ``new_state`` is not legal from that state,
         raises ``IllegalEscalationTransition`` → transaction rolls
         back; no row inserted; chain head unchanged.
      3. Precondition returns the captured in-lock ``current_state``
         (the from_state value).
      4. ``record_builder(from_state)`` constructs a DecisionRecord
         whose payload includes ``from_state`` — the validated value
         from step 2 lands in the hashed envelope.
      5. The record is INSERTed + chain head advanced under the same
         lock.
  - Two concurrent legal transitions from the same state (e.g. both
    ASSIGNED → RESOLVED and ASSIGNED → RE_ESCALATED) serialise on
    the chain-head row lock. The winner advances the chain; the
    loser sees the new end-state when the lock releases + raises
    against it. Live PG/Oracle proof of this is in T9; SQLite
    cannot honour ``FOR UPDATE`` so the unit suite asserts only
    sequential semantics.

Read-side projection (``Escalation``, ``get_by_id``, ``list_open``)
lives in T4. T3 ships the write side + an in-lock state-reader
helper used by ``transition()``.

Schema-naming reminder (Sprint 2 R3 contract): Sprint 2's
``decision_history`` table stores the discriminator in the
``event_type`` column (column shape stays parallel with
``audit_event``). ``DecisionRecord.decision_type`` is the caller-
side dataclass field that maps onto ``event_type`` during INSERT.
All SQL against the persisted chain rows uses ``event_type``.

Decision-type naming for transitions: the dataclass
``decision_type`` is ``escalation.{state.value.replace('-', '_')}``
because Python attribute conventions favour underscores; the
``EscalationState`` value uses the hyphenated ``"re-escalated"``
form for human readability in the payload. The persisted column
values are:

  - ``escalation.opened`` (genesis)
  - ``escalation.acknowledged``
  - ``escalation.assigned``
  - ``escalation.resolved``
  - ``escalation.re_escalated``  (underscore form; payload to_state
    is the hyphen form ``"re-escalated"``)
"""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import Select, select
from sqlalchemy.engine import Row
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from cognic_agentos.core.decision_history import (
    DecisionHistoryStore,
    DecisionRecord,
    _decision_history,
)


class EscalationState(StrEnum):
    """Escalation lifecycle states. StrEnum so the value round-trips
    through canonical-form serialisation per Sprint 2 R3 (only
    string-valued enums are accepted in the chain payload)."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    ASSIGNED = "assigned"
    RESOLVED = "resolved"
    RE_ESCALATED = "re-escalated"


#: Adjacency map enforced at runtime. Each key is the FROM state;
#: each value is the frozenset of legal TO states. ``ASSIGNED`` is
#: the fork point with two legal targets — exactly the case where
#: the original plan draft's TOCTOU window opened. With T2's
#: precondition primitive landed, two concurrent transitions from
#: ASSIGNED serialise on the chain-head FOR UPDATE lock; the loser
#: sees the new state (RESOLVED or RE_ESCALATED) and raises against
#: it.
_LEGAL_TRANSITIONS: dict[EscalationState, frozenset[EscalationState]] = {
    EscalationState.OPEN: frozenset({EscalationState.ACKNOWLEDGED}),
    EscalationState.ACKNOWLEDGED: frozenset({EscalationState.ASSIGNED}),
    EscalationState.ASSIGNED: frozenset({EscalationState.RESOLVED, EscalationState.RE_ESCALATED}),
    EscalationState.RE_ESCALATED: frozenset({EscalationState.ACKNOWLEDGED}),
    EscalationState.RESOLVED: frozenset(),  # terminal
}


class IllegalEscalationTransition(ValueError):
    """Raised inside the precondition validator when the requested
    transition is not in ``_LEGAL_TRANSITIONS`` for the chain's
    current end-state. Raising from inside the validator causes the
    locked transaction to roll back; no row inserted, chain head
    unchanged. Carries ``escalation_id``, ``from_state``,
    ``to_state`` for diagnostics + structured logging."""

    def __init__(
        self,
        escalation_id: uuid.UUID,
        from_state: EscalationState,
        to_state: EscalationState,
    ) -> None:
        super().__init__(
            f"escalation {escalation_id}: illegal transition {from_state.value} → {to_state.value}"
        )
        self.escalation_id = escalation_id
        self.from_state = from_state
        self.to_state = to_state


class EscalationNotFound(LookupError):
    """Raised when ``transition()`` is called against an
    ``escalation_id`` that has no ``escalation.opened`` record in
    the chain. Carries ``escalation_id`` for diagnostics."""

    def __init__(self, escalation_id: uuid.UUID) -> None:
        super().__init__(f"no escalation.opened record for {escalation_id}")
        self.escalation_id = escalation_id


def _decision_type_for_state(state: EscalationState) -> str:
    """Map an EscalationState onto its persisted ``event_type``
    column value. Values use underscore form (``re_escalated``)
    while the EscalationState.value uses hyphen form
    (``re-escalated``) — see module docstring for rationale.
    """

    return f"escalation.{state.value.replace('-', '_')}"


@dataclasses.dataclass(frozen=True, slots=True)
class Escalation:
    """Read-side projection of an escalation lifecycle. Built by
    walking the ``decision_history`` chain (server-side filter on
    ``event_type LIKE 'escalation.%'``); the source of truth is the
    chain itself, this dataclass is a per-escalation summary view
    captured at query time.

    Eventually-consistent: a query racing against a concurrent
    ``transition()`` may return either pre- or post-transition
    state, but never a partial / inconsistent one (the chain rows
    are the atomic units).

    Attributes:
        escalation_id: Logical lifecycle identity (UUID), stable
            across all rows for this escalation.
        current_state: The chain's end-state for this escalation
            at query time.
        opened_at: ``created_at`` of the ``escalation.opened`` row.
        last_transition_at: ``created_at`` of the most recent row
            for this escalation. Equals ``opened_at`` when no
            transitions have been applied.
        level: Severity level carried from the opened row's
            payload (free-form string; pack contracts may pin it
            later).
        transitions: Tuple of ``(from_state, to_state, at,
            actor_id)`` per chain row, oldest first. The opened
            row's tuple has ``from_state=None``; subsequent rows
            have the in-lock-captured from_state from T3.
    """

    escalation_id: uuid.UUID
    current_state: EscalationState
    opened_at: datetime
    last_transition_at: datetime
    level: str
    transitions: tuple[tuple[EscalationState | None, EscalationState, datetime, str], ...]


def _normalise_datetime(value: datetime) -> datetime:
    """Re-attach UTC tzinfo if missing.

    Mirrors ``core/chain_verifier._normalise_datetime`` from Sprint 2:
    SQLite's ``TIMESTAMP`` column drops tzinfo on round-trip; PG +
    Oracle preserve it. The original write was always tz-aware
    (``datetime.now(UTC)`` on every emit path), so re-attaching UTC
    reconstructs the original datetime that participated in the
    chain hash. No-op on dialects that preserve tzinfo.
    """

    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    # pragma: no cover — SQLite-substrate test path always drops
    # tzinfo on round-trip; PG + Oracle preserve it (covered by T9
    # live integration).
    return value  # pragma: no cover


def _escalation_rows_query() -> Select[Any]:
    """Server-side scan: ``event_type LIKE 'escalation.%' ORDER BY
    sequence``. Returns the columns both T3's in-lock state-reader
    and T4's public read-side projections need: ``event_type``,
    ``payload``, ``sequence``, ``created_at``, ``actor_id`` (from
    payload).

    The escalation_id filter is intentionally NOT in the WHERE
    clause: Sprint 2's ``GovernanceJSON`` TypeDecorator means
    PG/SQLite use native JSON while Oracle uses CLOB-with-app-side-
    serialisation, so a portable JSON-key WHERE clause would need
    dialect branching. Client-side ``payload['escalation_id']``
    filtering is dialect-portable and O(n) over the escalation-
    typed slice — acceptable for Sprint 2.5; flagged for Sprint 5+
    snapshot-table optimisation if escalation volume becomes a
    hotspot.

    T3's ``_read_current_state_within_txn`` and T4's
    ``get_by_id`` / ``list_open`` all share this query shape.
    """

    return (
        select(
            _decision_history.c.event_type,
            _decision_history.c.payload,
            _decision_history.c.sequence,
            _decision_history.c.created_at,
        )
        .where(_decision_history.c.event_type.like("escalation.%"))
        .order_by(_decision_history.c.sequence)
    )


def _project_escalations(
    rows: Sequence[Row[Any]],
) -> dict[uuid.UUID, Escalation]:
    """Group escalation-typed chain rows by ``escalation_id`` and
    project each group into an ``Escalation``, validating the per-id
    lifecycle while projecting.

    Malformed-chain semantics — the WHOLE GROUP is rejected (skipped
    in the returned dict) on any of:

      - The first row for the escalation_id is not
        ``escalation.opened`` (or the group is empty). T3's
        ``seen_opened`` guard caught the case where an
        ``escalation.opened`` row was missing entirely; this
        check generalises it: the genesis row MUST come first,
        with the right shape (``from_state=None``,
        ``to_state="open"``).
      - A subsequent row's ``from_state`` does not equal the
        prior row's ``to_state`` (chain linkage break).
      - A subsequent row's ``(from_state, to_state)`` is not in
        ``_LEGAL_TRANSITIONS`` (illegal adjacency).
      - A subsequent row is another ``escalation.opened`` (duplicate
        genesis).
      - Any row in the group has malformed payload fields
        (non-string ``from_state`` / ``to_state`` / unparseable
        EscalationState values).

    These checks close the T4-reviewer-P1 hole: a direct
    ``DecisionHistoryStore.append`` of ``escalation.resolved`` after
    a legitimate ``open()`` would otherwise project as RESOLVED
    (and ``list_open`` would silently omit an actually-open
    escalation as resolved). With validation, the malformed group
    is rejected; ``get_by_id`` raises ``EscalationNotFound`` and
    ``list_open`` skips it — same observable behaviour as the
    no-opened-row case, so consumers see consistent malformed-
    chain semantics regardless of which level of corruption
    happened.

    Properly-shaped emits — even those that bypass ``EscalationStore``
    by emitting through ``DecisionHistoryStore.append`` directly,
    AS LONG AS each row carries the right ``from_state`` / ``to_state``
    matching the prior row + a legal adjacency — are accepted because
    they are indistinguishable from legitimate ones at this layer.
    Hash-chain integrity (T8 chain verifier) and runtime-role
    GRANTs (Sprint 2 operator runbook) are the layers that defend
    against fully-faked emits.
    """

    # Per-id accumulator. Each group: list of (event_type, payload,
    # created_at_utc) tuples in chain order.
    groups: dict[uuid.UUID, list[tuple[str, dict[str, Any], datetime]]] = {}
    for row in rows:
        payload: dict[str, Any] = row.payload or {}
        eid_str = payload.get("escalation_id")
        if not isinstance(eid_str, str):  # pragma: no cover
            # Defensive: every emit path (open, transition) writes
            # a string escalation_id. Reachable only if a non-T3
            # caller emits a malformed escalation row directly via
            # raw SQL or DecisionHistoryStore — skipped because we
            # can't map to a UUID-keyed projection anyway.
            continue
        try:
            eid = uuid.UUID(eid_str)
        except ValueError:  # pragma: no cover — defensive
            continue
        groups.setdefault(eid, []).append(
            (row.event_type, payload, _normalise_datetime(row.created_at))
        )

    projections: dict[uuid.UUID, Escalation] = {}
    for eid, group in groups.items():
        if not group:  # pragma: no cover — defensive
            continue

        # Genesis-row shape check. group[0] MUST be
        # escalation.opened with from=None + to="open".
        first_event_type, first_payload, first_at = group[0]
        if first_event_type != "escalation.opened":
            continue
        if first_payload.get("from_state") is not None:
            continue
        if first_payload.get("to_state") != EscalationState.OPEN.value:
            continue

        # Begin the projection with the genesis row.
        first_actor_raw = first_payload.get("actor_id")
        first_actor = first_actor_raw if isinstance(first_actor_raw, str) else ""
        transitions_list: list[tuple[EscalationState | None, EscalationState, datetime, str]] = [
            (None, EscalationState.OPEN, first_at, first_actor)
        ]
        prior_to_state: EscalationState = EscalationState.OPEN
        invalid = False

        # Walk subsequent rows; validate each transition's
        # linkage + adjacency against the state machine.
        for event_type, payload, at in group[1:]:
            # Reject duplicate genesis rows.
            if event_type == "escalation.opened":
                invalid = True
                break

            from_raw = payload.get("from_state")
            to_raw = payload.get("to_state")
            if not isinstance(from_raw, str) or not isinstance(to_raw, str):
                invalid = True
                break
            try:
                from_state = EscalationState(from_raw)
                to_state = EscalationState(to_raw)
            except ValueError:
                invalid = True
                break

            # event_type / to_state agreement: the persisted
            # ``event_type`` column is independent evidence; it MUST
            # agree with the payload's ``to_state`` per the
            # ``_decision_type_for_state`` mapping that
            # ``EscalationStore.transition`` uses to construct
            # legitimate rows. A bypass-emit that writes
            # ``event_type='escalation.resolved'`` with
            # ``payload['to_state']='acknowledged'`` would otherwise
            # be projected as ACKNOWLEDGED — hiding the mismatch
            # from operators while an auditor reading the raw
            # ``event_type`` column sees a different story. Rejecting
            # the group keeps the projection consistent with the
            # persisted discriminator. (T4-reviewer-P2 fix.)
            if event_type != _decision_type_for_state(to_state):
                invalid = True
                break

            # Chain linkage: the row's claimed from_state must
            # equal the prior row's to_state. A bypass-emit that
            # fakes a from_state out of sync with the chain is
            # rejected here.
            if from_state != prior_to_state:
                invalid = True
                break

            # State-machine adjacency: the (from, to) pair must
            # be in _LEGAL_TRANSITIONS. A bypass-emit that claims
            # from=OPEN to=RESOLVED (skipping the ack/assigned
            # path) is rejected here even though linkage holds —
            # exactly the T4-reviewer-P1 threat shape.
            if to_state not in _LEGAL_TRANSITIONS[from_state]:
                invalid = True
                break

            actor_raw = payload.get("actor_id")
            actor = actor_raw if isinstance(actor_raw, str) else ""
            transitions_list.append((from_state, to_state, at, actor))
            prior_to_state = to_state

        if invalid:
            continue  # reject the whole group

        level_raw = first_payload.get("level")
        level = level_raw if isinstance(level_raw, str) else ""

        # current_state is the to_state of the last (highest-
        # sequence) row in the validated chain; last_transition_at
        # is its created_at.
        last_to = transitions_list[-1][1]
        last_at = transitions_list[-1][2]

        projections[eid] = Escalation(
            escalation_id=eid,
            current_state=last_to,
            opened_at=first_at,
            last_transition_at=last_at,
            level=level,
            transitions=tuple(transitions_list),
        )

    return projections


class EscalationStore:
    """Write-side of the escalation state machine + atomic state
    validation.

    Concurrency: every transition goes through
    ``DecisionHistoryStore.append_with_precondition`` (T2 primitive).
    The precondition validator runs INSIDE the chain-head FOR
    UPDATE lock and reads the chain's current end-state for the
    given escalation_id. If the requested transition is illegal
    from that state, the validator raises
    ``IllegalEscalationTransition`` and the locked transaction
    rolls back. Two concurrent legal transitions from the same
    state → exactly one wins; the loser sees the new end-state
    and raises against it. (Live PG/Oracle proof in T9; SQLite-
    substrate unit tests assert only sequential semantics.)

    Public read-side queries (``Escalation``, ``get_by_id``,
    ``list_open``) live in T4; T3 implements only the write side
    + the in-lock state-reader helper that ``transition()`` uses.
    """

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._history = DecisionHistoryStore(engine)

    async def open(
        self,
        *,
        actor_id: str,
        level: str,
        reason: str,
        request_id: str,
        tenant_id: str | None = None,
    ) -> tuple[uuid.UUID, uuid.UUID, bytes]:
        """Open a new escalation. Returns
        ``(escalation_id, decision_record_id, hash)``.

        ``escalation_id`` is generated by ``uuid.uuid4()`` here. A
        fresh escalation has no prior chain state by construction,
        so no precondition is needed — this routes through the
        plain ``append`` path. The genesis row's payload carries
        ``from_state=None``, ``to_state=EscalationState.OPEN.value``,
        ``level``, and ``reason``.

        ``actor_id`` is merged into the payload by the Sprint 2
        DecisionRecord contract; ``request_id`` ties the
        escalation back to the originating request; ``tenant_id``
        is forwarded for Wave-2 multi-tenant policy enforcement.
        """

        escalation_id = uuid.uuid4()
        record_id, h = await self._history.append(
            DecisionRecord(
                decision_type="escalation.opened",
                request_id=request_id,
                actor_id=actor_id,
                tenant_id=tenant_id,
                payload={
                    "escalation_id": str(escalation_id),
                    "level": level,
                    "reason": reason,
                    "from_state": None,
                    "to_state": EscalationState.OPEN.value,
                },
            )
        )
        return escalation_id, record_id, h

    async def transition(
        self,
        *,
        escalation_id: uuid.UUID,
        actor_id: str,
        new_state: EscalationState,
        reason: str,
        request_id: str,
        tenant_id: str | None = None,
    ) -> tuple[uuid.UUID, bytes]:
        """Transition an existing escalation to ``new_state``.

        Atomic semantics: chain read + adjacency validation +
        record construction + INSERT + chain-head update all
        happen inside one ``DecisionHistoryStore.append_with_precondition``
        transaction (T2 primitive, Option A). The precondition both
        validates AND captures the from_state value; the captured
        value flows into the synchronous record_builder so
        ``from_state`` lands in the hashed envelope.

        Raises ``IllegalEscalationTransition`` if the chain's
        current end-state for this escalation does not allow
        ``new_state``. Raises ``EscalationNotFound`` if no
        ``escalation.opened`` record exists for ``escalation_id``.

        Both raises happen inside the locked transaction → the
        transaction rolls back atomically; no row inserted, chain
        head unchanged. Mirror of T2's rollback contract.
        """

        async def _precondition(
            conn: AsyncConnection,
            prev_sequence: int,
            prev_hash: bytes,
        ) -> EscalationState:
            current_state = await self._read_current_state_within_txn(conn, escalation_id)
            # Validation runs INSIDE the lock. The TOCTOU window
            # the original draft had is closed because both the
            # state read AND the validation happen here, before
            # the row is built or inserted.
            legal_targets = _LEGAL_TRANSITIONS[current_state]
            if new_state not in legal_targets:
                raise IllegalEscalationTransition(escalation_id, current_state, new_state)
            # Captured in-lock; flows to record_builder via the
            # T2 Option-A primitive.
            return current_state

        def _build_record(from_state: EscalationState) -> DecisionRecord:
            return DecisionRecord(
                decision_type=_decision_type_for_state(new_state),
                request_id=request_id,
                actor_id=actor_id,
                tenant_id=tenant_id,
                payload={
                    "escalation_id": str(escalation_id),
                    "reason": reason,
                    "from_state": from_state.value,
                    "to_state": new_state.value,
                },
            )

        return await self._history.append_with_precondition(
            record_builder=_build_record,
            precondition=_precondition,
        )

    async def _read_current_state_within_txn(
        self, conn: AsyncConnection, escalation_id: uuid.UUID
    ) -> EscalationState:
        """Read the chain's current end-state for the given
        ``escalation_id``. MUST be called from inside a locked
        transaction (the FOR UPDATE on chain_heads serialises
        appends, so the result is the committed-up-to-the-lock
        state).

        Implementation: server-side filter on
        ``event_type LIKE 'escalation.%'`` (Sprint 2 ``event_type``
        column shape — see module docstring); client-side filter
        on ``payload['escalation_id'] == str(escalation_id)`` for
        dialect-portable JSON-key extraction (Sprint 2's
        GovernanceJSON TypeDecorator means PG/SQLite use native
        JSON while Oracle uses CLOB-with-app-side-serialisation; a
        portable JSON-key WHERE clause would need dialect
        branching).

        O(n) over the escalation-typed slice of the chain. Flagged
        for Sprint 5+ snapshot-table optimisation if escalation
        volume becomes a hotspot — see plan T4 read-side notes.

        Raises ``EscalationNotFound`` if no
        ``escalation.opened`` row exists for the given
        ``escalation_id``. The contract is specifically about
        ``escalation.opened`` — not any matching row — so the
        reader tracks whether that row was seen and refuses to
        synthesise an end-state from a malformed chain that has
        only transition rows. This is the load-bearing guard
        against bypass-``open()`` emits (test bugs, direct
        INSERTs, chain corruption); without it, a chain
        containing only ``escalation.acknowledged`` rows for an
        id would let ``transition()`` proceed as if the
        escalation had been legitimately opened, which would
        silently corrupt the state machine. (PR-#7-T3 reviewer
        P2 fix.)
        """

        target_id = str(escalation_id)
        rows = (
            await conn.execute(
                select(
                    _decision_history.c.event_type,
                    _decision_history.c.payload,
                    _decision_history.c.sequence,
                )
                .where(_decision_history.c.event_type.like("escalation.%"))
                .order_by(_decision_history.c.sequence)
            )
        ).all()

        # Walk the escalation-typed slice; require the
        # ``escalation.opened`` row to be present AND track the
        # highest-sequence row's ``to_state`` for the matching
        # escalation_id. The two checks are independent — opened
        # presence proves legitimacy; latest_state is what
        # transition() validates against.
        seen_opened = False
        latest_state: EscalationState | None = None
        for row in rows:
            payload: dict[str, Any] = row.payload or {}
            if payload.get("escalation_id") != target_id:
                continue
            if row.event_type == "escalation.opened":
                seen_opened = True
            # to_state is the canonical end-state for this row.
            # The genesis ("escalation.opened") row carries
            # to_state=="open"; subsequent transitions carry the
            # transition's target.
            to_state_str = payload.get("to_state")
            if not isinstance(to_state_str, str):  # pragma: no cover
                # Defensive: every emit path writes a string
                # to_state. If this fires, a non-T3 caller bypassed
                # the contract and emitted a malformed escalation
                # row; we'd rather fail loudly than misclassify.
                raise RuntimeError(
                    f"escalation row {row.sequence} has non-string to_state: {to_state_str!r}"
                )
            latest_state = EscalationState(to_state_str)

        if not seen_opened:
            # Either no rows match, OR the chain has rows for this
            # id but no ``escalation.opened`` row — both are
            # malformed-chain failures from transition()'s point
            # of view. Fail loudly rather than synthesise a state.
            raise EscalationNotFound(escalation_id)
        # seen_opened is True → at least one matching row was
        # processed AND latest_state was set in that iteration
        # (or a later one).
        assert latest_state is not None
        return latest_state

    async def get_by_id(self, escalation_id: uuid.UUID) -> Escalation:
        """Project the full escalation lifecycle from
        ``decision_history``. Eventually-consistent — separate from
        ``_read_current_state_within_txn`` (which holds the
        chain-head FOR UPDATE lock for in-lock validation). A query
        racing against a concurrent ``transition()`` may return
        either pre- or post-transition state, but never a partial
        one.

        Raises ``EscalationNotFound`` if no ``escalation.opened``
        row exists for the given ``escalation_id``. This includes
        chains with only transition rows for the id (malformed,
        bypass-``open()`` emits) — consistent with T3's
        ``_read_current_state_within_txn`` ``seen_opened`` guard.

        Implementation reuses the ``_escalation_rows_query`` SQL
        shape + the ``_project_escalations`` projection helper that
        lives at module scope; both ``get_by_id`` and ``list_open``
        share that pipeline.
        """

        async with self._engine.connect() as conn:
            rows = (await conn.execute(_escalation_rows_query())).all()
        projections = _project_escalations(rows)
        if escalation_id not in projections:
            raise EscalationNotFound(escalation_id)
        return projections[escalation_id]

    async def list_open(self) -> tuple[Escalation, ...]:
        """Return all escalations whose ``current_state`` is not
        ``EscalationState.RESOLVED``. Walks the escalation-typed
        slice of ``decision_history`` once via the shared
        ``_escalation_rows_query`` + ``_project_escalations``
        pipeline. O(n) over that slice.

        Malformed-chain entries (transition rows without an
        ``escalation.opened`` row) are SKIPPED — NOT synthesised
        into pseudo-projections. Mirror of ``get_by_id``'s
        ``EscalationNotFound`` semantics in collection form: a
        bypass-``open()`` emit doesn't show up as an "escalation"
        examiners need to investigate.

        Ordering: implementation-defined (currently insertion
        order of the underlying dict, which is the order the
        first row for each escalation_id appeared in the chain
        scan). Callers MUST NOT rely on a particular ordering;
        sort client-side if needed. Sprint 5+ snapshot-table
        introduction may change the ordering.
        """

        async with self._engine.connect() as conn:
            rows = (await conn.execute(_escalation_rows_query())).all()
        projections = _project_escalations(rows)
        return tuple(e for e in projections.values() if e.current_state != EscalationState.RESOLVED)


__all__: tuple[str, ...] = (
    "_LEGAL_TRANSITIONS",
    "Escalation",
    "EscalationNotFound",
    "EscalationState",
    "EscalationStore",
    "IllegalEscalationTransition",
)
