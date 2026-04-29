"""Sprint 2.5 Task 3 — escalation state machine + write side.

``core/escalation`` drives a strict state machine. Each transition
emits exactly ONE hash-chained ``DecisionRecord`` into the existing
``decision_history`` chain via T2's
``DecisionHistoryStore.append_with_precondition`` primitive. State
read + validation + record construction + append all happen INSIDE
the chain-head FOR UPDATE locked transaction — closing the TOCTOU
window the original draft had.

State machine:

  open ──► acknowledged ──► assigned ──► (resolved | re-escalated)
                  ▲                           │
                  └──────── re-escalated ─────┘

  resolved is terminal. re-escalated loops back to acknowledged.

**Critical-controls module.** Per AGENTS.md + the Sprint 2.5 plan:
≥95% line + ≥90% branch coverage, halt-before-commit per edit.

Tests cover:

  - ``EscalationState`` StrEnum has exactly the documented members.
  - ``_LEGAL_TRANSITIONS`` adjacency map matches the documented
    state machine literally.
  - ``EscalationStore.open()`` emits one ``escalation.opened``
    decision_history row with correct payload shape.
  - 50 SEQUENTIAL ``open()`` calls produce 50 distinct
    ``escalation_id`` UUIDs (uuid4 generation contract; pure
    sequential semantics — concurrent open() on SQLite trips the
    sequence UNIQUE constraint because aiosqlite cannot honour
    FOR UPDATE; the production-grade serialisation proof is in T9).
  - ``EscalationStore.transition()`` happy lifecycle paths:
      open → acknowledged → assigned → resolved
      open → acknowledged → assigned → re-escalated → acknowledged
        → assigned → resolved
    Each transition emits a row with correct ``from_state`` /
    ``to_state`` payload (from_state captured in-lock by the
    precondition + flowed into record_builder per T2 Option-A).
  - ``IllegalEscalationTransition`` raises for every (from, to)
    pair NOT in ``_LEGAL_TRANSITIONS`` (parametrised across the
    full Cartesian product, with ``RESOLVED → *`` covered as
    terminal).
  - On ``IllegalEscalationTransition``: chain head + row count are
    unchanged after the call raises (transaction rolled back).
    Sequential test — deterministic on SQLite.
  - ``EscalationNotFound`` raises when ``transition()`` is called
    against an ``escalation_id`` with no ``escalation.opened``
    record in the chain.
  - Validator-invocation order is deterministic: precondition runs
    BEFORE record_builder, and on success its return value flows
    into the builder verbatim. SHAPE assertion of T2's Option-A
    primitive — fully sequential.

**No SQLite race-outcome assertion.** SQLite's async substrate
does not honour ``FOR UPDATE`` row-level locking; the production-
grade race proof (two competing legal transitions from ``ASSIGNED``
→ exactly one wins, loser raises) lives in T9 against real PG +
Oracle.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import _decision_history
from cognic_agentos.core.escalation import (
    _LEGAL_TRANSITIONS,
    Escalation,
    EscalationNotFound,
    EscalationState,
    EscalationStore,
    IllegalEscalationTransition,
)


@pytest.fixture
async def engine(tmp_path: Any) -> Any:
    """Per-test SQLite-aiosqlite engine with the governance schema +
    seeded chain heads. Mirrors migration 0001's shape via the shared
    Sprint-2 _metadata. Both ``audit_event`` and ``decision_history``
    chain-head rows are seeded so the escalation store's transitions
    (which write to decision_history) work end-to-end."""

    url = f"sqlite+aiosqlite:///{tmp_path / 'escalation.db'}"
    eng: AsyncEngine = create_async_engine(url)
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="audit_event",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=datetime.now(UTC),
            )
        )
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="decision_history",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=datetime.now(UTC),
            )
        )
    yield eng
    await eng.dispose()


@pytest.fixture
async def store(engine: AsyncEngine) -> EscalationStore:
    return EscalationStore(engine)


# ===========================================================================
# State-machine shape
# ===========================================================================


class TestEscalationStateEnum:
    """EscalationState is a StrEnum with the documented five members."""

    def test_values_match_contract(self) -> None:
        assert EscalationState.OPEN.value == "open"
        assert EscalationState.ACKNOWLEDGED.value == "acknowledged"
        assert EscalationState.ASSIGNED.value == "assigned"
        assert EscalationState.RESOLVED.value == "resolved"
        assert EscalationState.RE_ESCALATED.value == "re-escalated"

    def test_five_members_exact(self) -> None:
        assert {s.value for s in EscalationState} == {
            "open",
            "acknowledged",
            "assigned",
            "resolved",
            "re-escalated",
        }

    def test_str_enum_is_str_subclass(self) -> None:
        # canonical-form serializer relies on this; same shape as
        # SLAStatus from T1.
        assert isinstance(EscalationState.OPEN, str)
        assert str(EscalationState.OPEN) == "open"


class TestLegalTransitionsMap:
    """_LEGAL_TRANSITIONS is the adjacency map for the state machine.
    Assert the literal shape so a future refactor can't silently
    relax / tighten the rules."""

    def test_open_transitions_only_to_acknowledged(self) -> None:
        assert _LEGAL_TRANSITIONS[EscalationState.OPEN] == frozenset({EscalationState.ACKNOWLEDGED})

    def test_acknowledged_transitions_only_to_assigned(self) -> None:
        assert _LEGAL_TRANSITIONS[EscalationState.ACKNOWLEDGED] == frozenset(
            {EscalationState.ASSIGNED}
        )

    def test_assigned_transitions_to_resolved_or_re_escalated(self) -> None:
        # The fork — ASSIGNED is the state that can produce a TOCTOU
        # window if validation runs outside the lock. T9 will exercise
        # the live-DB race proof; here we just assert the map allows
        # both legal targets.
        assert _LEGAL_TRANSITIONS[EscalationState.ASSIGNED] == frozenset(
            {EscalationState.RESOLVED, EscalationState.RE_ESCALATED}
        )

    def test_re_escalated_loops_back_to_acknowledged(self) -> None:
        assert _LEGAL_TRANSITIONS[EscalationState.RE_ESCALATED] == frozenset(
            {EscalationState.ACKNOWLEDGED}
        )

    def test_resolved_is_terminal(self) -> None:
        assert _LEGAL_TRANSITIONS[EscalationState.RESOLVED] == frozenset()

    def test_map_covers_all_states(self) -> None:
        # Every state must have an entry — so the validator never
        # KeyErrors on a state observed in the chain.
        assert set(_LEGAL_TRANSITIONS.keys()) == set(EscalationState)


# ===========================================================================
# EscalationStore.open()
# ===========================================================================


class TestEscalationStoreOpen:
    """Open emits one escalation.opened decision_history row."""

    async def test_returns_escalation_id_record_id_hash(self, store: EscalationStore) -> None:
        eid, rid, h = await store.open(
            actor_id="agent-canary",
            level="p1",
            reason="canary opens an escalation",
            request_id="req-open-1",
        )
        assert isinstance(eid, uuid.UUID)
        assert isinstance(rid, uuid.UUID)
        assert isinstance(h, bytes)
        assert len(h) == 32
        # eid != rid: one is the escalation lifecycle identity, the
        # other is the chain-row identity.
        assert eid != rid

    async def test_emits_one_decision_history_row(
        self, store: EscalationStore, engine: AsyncEngine
    ) -> None:
        eid, _, _ = await store.open(
            actor_id="agent-canary",
            level="p1",
            reason="emit-shape",
            request_id="req-open-2",
        )

        async with engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(
                        _decision_history.c.event_type,
                        _decision_history.c.request_id,
                        _decision_history.c.payload,
                    )
                )
            ).all()
        assert len(rows) == 1
        row = rows[0]
        # Per Sprint 2 schema: discriminator is in event_type column;
        # DecisionRecord.decision_type maps onto it during INSERT.
        assert row.event_type == "escalation.opened"
        assert row.request_id == "req-open-2"
        # Payload shape: actor_id merged in by Sprint 2 contract;
        # escalation-specific fields under their documented keys.
        assert row.payload["escalation_id"] == str(eid)
        assert row.payload["level"] == "p1"
        assert row.payload["reason"] == "emit-shape"
        assert row.payload["from_state"] is None
        assert row.payload["to_state"] == "open"
        assert row.payload["actor_id"] == "agent-canary"

    async def test_chain_head_advances_to_one(
        self, store: EscalationStore, engine: AsyncEngine
    ) -> None:
        _, _, h = await store.open(
            actor_id="agent-canary",
            level="p2",
            reason="head-check",
            request_id="req-open-3",
        )
        async with engine.connect() as conn:
            head = (
                await conn.execute(
                    select(
                        _chain_heads.c.latest_sequence,
                        _chain_heads.c.latest_hash,
                    ).where(_chain_heads.c.chain_id == "decision_history")
                )
            ).one()
        assert int(head.latest_sequence) == 1
        assert bytes(head.latest_hash) == h

    async def test_50_sequential_opens_yield_50_distinct_escalation_ids(
        self, store: EscalationStore
    ) -> None:
        # Sequential opens (NOT concurrent — SQLite-aiosqlite does
        # not honour FOR UPDATE, so concurrent appends race past the
        # head SELECT and trip the sequence UNIQUE constraint with
        # IntegrityError; that's a chain-serialisation assertion in
        # disguise, which T9 owns on live PG/Oracle).
        #
        # This sequential variant proves the UUID-generation
        # contract: 50 distinct calls to ``open()`` produce 50
        # distinct ``escalation_id`` UUIDs — uuid4 collision
        # probability is negligible.
        eids: set[uuid.UUID] = set()
        for i in range(50):
            eid, _, _ = await store.open(
                actor_id=f"agent-{i}",
                level="p1",
                reason=f"sequential open #{i}",
                request_id=f"req-sequential-{i}",
            )
            eids.add(eid)
        assert len(eids) == 50, f"expected 50 distinct escalation_ids; got {len(eids)}"


# ===========================================================================
# EscalationStore.transition() — happy lifecycle paths
# ===========================================================================


class TestTransitionHappyPaths:
    """Sequential transition lifecycles — each step verifies row +
    payload + chain-head shape."""

    async def _open(self, store: EscalationStore) -> uuid.UUID:
        eid, _, _ = await store.open(
            actor_id="agent-canary",
            level="p1",
            reason="lifecycle",
            request_id="req-lifecycle-open",
        )
        return eid

    async def _payloads(self, engine: AsyncEngine) -> list[dict[str, Any]]:
        async with engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(
                        _decision_history.c.event_type,
                        _decision_history.c.payload,
                    ).order_by(_decision_history.c.sequence)
                )
            ).all()
        return [{"event_type": r.event_type, "payload": r.payload} for r in rows]

    async def test_open_acknowledged_assigned_resolved(
        self, store: EscalationStore, engine: AsyncEngine
    ) -> None:
        eid = await self._open(store)
        await store.transition(
            escalation_id=eid,
            actor_id="agent-canary",
            new_state=EscalationState.ACKNOWLEDGED,
            reason="ack",
            request_id="req-ack",
        )
        await store.transition(
            escalation_id=eid,
            actor_id="agent-canary",
            new_state=EscalationState.ASSIGNED,
            reason="assign",
            request_id="req-assign",
        )
        await store.transition(
            escalation_id=eid,
            actor_id="agent-canary",
            new_state=EscalationState.RESOLVED,
            reason="resolve",
            request_id="req-resolve",
        )

        rows = await self._payloads(engine)
        assert [r["event_type"] for r in rows] == [
            "escalation.opened",
            "escalation.acknowledged",
            "escalation.assigned",
            "escalation.resolved",
        ]
        # from_state/to_state on each transition row reflects the chain.
        assert rows[1]["payload"]["from_state"] == "open"
        assert rows[1]["payload"]["to_state"] == "acknowledged"
        assert rows[2]["payload"]["from_state"] == "acknowledged"
        assert rows[2]["payload"]["to_state"] == "assigned"
        assert rows[3]["payload"]["from_state"] == "assigned"
        assert rows[3]["payload"]["to_state"] == "resolved"

    async def test_re_escalated_loops_back_through_acknowledged(
        self, store: EscalationStore, engine: AsyncEngine
    ) -> None:
        eid = await self._open(store)
        for s in (
            EscalationState.ACKNOWLEDGED,
            EscalationState.ASSIGNED,
            EscalationState.RE_ESCALATED,
            EscalationState.ACKNOWLEDGED,
            EscalationState.ASSIGNED,
            EscalationState.RESOLVED,
        ):
            await store.transition(
                escalation_id=eid,
                actor_id="agent-canary",
                new_state=s,
                reason=f"to-{s.value}",
                request_id=f"req-{s.value}",
            )

        rows = await self._payloads(engine)
        assert [r["event_type"] for r in rows] == [
            "escalation.opened",
            "escalation.acknowledged",
            "escalation.assigned",
            "escalation.re_escalated",  # decision_type uses underscore-form
            "escalation.acknowledged",
            "escalation.assigned",
            "escalation.resolved",
        ]
        # The re-escalation row carries the hyphen-form ``to_state``
        # (matches the EscalationState.RE_ESCALATED.value); the
        # decision_type uses the underscore-substituted form so it's
        # a valid event_type column value (column shape is parallel
        # with audit_event; underscores read more naturally).
        assert rows[3]["payload"]["from_state"] == "assigned"
        assert rows[3]["payload"]["to_state"] == "re-escalated"
        # And the re-escalation correctly routes back through ack.
        assert rows[4]["payload"]["from_state"] == "re-escalated"
        assert rows[4]["payload"]["to_state"] == "acknowledged"


# ===========================================================================
# Illegal transitions — every (from, to) pair NOT in the adjacency map
# ===========================================================================


def _all_illegal_pairs() -> list[tuple[EscalationState, EscalationState]]:
    """Cartesian product minus the adjacency map. Each pair is a
    transition that MUST raise IllegalEscalationTransition."""

    illegal: list[tuple[EscalationState, EscalationState]] = []
    for from_s in EscalationState:
        for to_s in EscalationState:
            if from_s == to_s:
                # Self-transitions are not in the adjacency map; we
                # treat them as illegal (the state machine does not
                # allow no-op transitions — they would emit a
                # decision_history row for a state that didn't change,
                # which is a chain-noise pattern we explicitly forbid).
                illegal.append((from_s, to_s))
                continue
            if to_s in _LEGAL_TRANSITIONS[from_s]:
                continue
            illegal.append((from_s, to_s))
    return illegal


class TestIllegalTransitions:
    """Every (from, to) pair NOT in _LEGAL_TRANSITIONS raises
    IllegalEscalationTransition + the transaction rolls back."""

    @pytest.mark.parametrize(
        ("from_state", "to_state"),
        _all_illegal_pairs(),
        ids=lambda v: v.value if isinstance(v, EscalationState) else str(v),
    )
    async def test_illegal_transition_raises_and_rolls_back(
        self,
        store: EscalationStore,
        engine: AsyncEngine,
        from_state: EscalationState,
        to_state: EscalationState,
    ) -> None:
        # Drive the chain to ``from_state`` via the legal path.
        eid = await self._drive_to_state(store, from_state)

        # Capture pre-state.
        pre_rows = await self._row_count(engine)
        pre_head = await self._head(engine)

        # Attempt the illegal transition.
        with pytest.raises(IllegalEscalationTransition) as exc_info:
            await store.transition(
                escalation_id=eid,
                actor_id="agent-canary",
                new_state=to_state,
                reason="illegal",
                request_id="req-illegal",
            )
        # Exception carries diagnostic fields.
        assert exc_info.value.escalation_id == eid
        assert exc_info.value.from_state == from_state
        assert exc_info.value.to_state == to_state

        # Chain unchanged — transaction rolled back.
        post_rows = await self._row_count(engine)
        post_head = await self._head(engine)
        assert post_rows == pre_rows
        assert post_head == pre_head

    async def _drive_to_state(self, store: EscalationStore, target: EscalationState) -> uuid.UUID:
        """Produce an escalation whose chain-end-state == target by
        walking the legal path. RESOLVED is reached via
        open→ack→assigned→resolved; RE_ESCALATED via
        open→ack→assigned→re_escalated."""

        eid, _, _ = await store.open(
            actor_id="agent-canary",
            level="p1",
            reason="drive",
            request_id=f"req-drive-{target.value}",
        )
        if target == EscalationState.OPEN:
            return eid
        await store.transition(
            escalation_id=eid,
            actor_id="agent-canary",
            new_state=EscalationState.ACKNOWLEDGED,
            reason="drive ack",
            request_id=f"req-drive-ack-{target.value}",
        )
        if target == EscalationState.ACKNOWLEDGED:
            return eid
        await store.transition(
            escalation_id=eid,
            actor_id="agent-canary",
            new_state=EscalationState.ASSIGNED,
            reason="drive assigned",
            request_id=f"req-drive-assigned-{target.value}",
        )
        if target == EscalationState.ASSIGNED:
            return eid
        if target == EscalationState.RESOLVED:
            await store.transition(
                escalation_id=eid,
                actor_id="agent-canary",
                new_state=EscalationState.RESOLVED,
                reason="drive resolved",
                request_id=f"req-drive-resolved-{target.value}",
            )
            return eid
        if target == EscalationState.RE_ESCALATED:
            await store.transition(
                escalation_id=eid,
                actor_id="agent-canary",
                new_state=EscalationState.RE_ESCALATED,
                reason="drive re-escalated",
                request_id=f"req-drive-re_escalated-{target.value}",
            )
            return eid
        raise RuntimeError(f"unreachable: target={target!r}")  # pragma: no cover

    async def _row_count(self, engine: AsyncEngine) -> int:
        from sqlalchemy import func
        from sqlalchemy import select as _select

        async with engine.connect() as conn:
            r = await conn.execute(_select(func.count()).select_from(_decision_history))
        return int(r.scalar() or 0)

    async def _head(self, engine: AsyncEngine) -> tuple[int, bytes]:
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    select(
                        _chain_heads.c.latest_sequence,
                        _chain_heads.c.latest_hash,
                    ).where(_chain_heads.c.chain_id == "decision_history")
                )
            ).one()
        return int(row.latest_sequence), bytes(row.latest_hash)


# ===========================================================================
# EscalationNotFound
# ===========================================================================


class TestEscalationNotFound:
    """transition() against an unknown escalation_id raises
    EscalationNotFound + the transaction rolls back."""

    async def test_unknown_id_raises(self, store: EscalationStore, engine: AsyncEngine) -> None:
        unknown_id = uuid.uuid4()
        # Capture pre-state (chain may have other escalations or be
        # empty — fixture-fresh, it's empty).
        pre_seq, pre_hash = await self._head(engine)
        pre_count = await self._row_count(engine)

        with pytest.raises(EscalationNotFound) as exc_info:
            await store.transition(
                escalation_id=unknown_id,
                actor_id="agent-canary",
                new_state=EscalationState.ACKNOWLEDGED,
                reason="against-unknown",
                request_id="req-unknown",
            )
        assert exc_info.value.escalation_id == unknown_id

        post_seq, post_hash = await self._head(engine)
        post_count = await self._row_count(engine)
        assert (pre_seq, pre_hash, pre_count) == (post_seq, post_hash, post_count)

    async def test_unknown_id_after_other_escalations_still_raises(
        self, store: EscalationStore, engine: AsyncEngine
    ) -> None:
        # Open a different escalation; assert transition() against an
        # UNRELATED escalation_id still raises EscalationNotFound (the
        # store filters by escalation_id in payload, not just by chain
        # presence).
        eid_other, _, _ = await store.open(
            actor_id="other",
            level="p1",
            reason="other",
            request_id="req-other-open",
        )
        unknown_id = uuid.uuid4()
        assert unknown_id != eid_other  # uuid4 collision negligible

        with pytest.raises(EscalationNotFound):
            await store.transition(
                escalation_id=unknown_id,
                actor_id="agent",
                new_state=EscalationState.ACKNOWLEDGED,
                reason="x",
                request_id="req-unknown-2",
            )

    async def test_chain_with_only_transition_rows_no_opened_raises_not_found(
        self,
        store: EscalationStore,
        engine: AsyncEngine,
    ) -> None:
        """Regression — PR-#7-T3 reviewer P2.

        The original ``_read_current_state_within_txn`` accepted any
        ``escalation.%`` row matching the escalation_id and returned
        its ``to_state`` — which silently let bypass-``open()``
        emits proceed through ``transition()`` as if the escalation
        had been legitimately opened. The contract docstring said
        ``EscalationNotFound`` for a missing opened row, but the
        implementation didn't enforce it.

        Fix: track ``seen_opened`` separately from ``latest_state``;
        if no ``escalation.opened`` row was seen for the
        escalation_id, raise regardless of any transition rows
        present.

        This test reproduces the malformed-chain shape by emitting a
        bare ``escalation.acknowledged`` row directly through
        ``DecisionHistoryStore.append`` (bypassing ``open()``) and
        confirms ``transition()`` raises ``EscalationNotFound``.
        """

        from cognic_agentos.core.decision_history import (
            DecisionHistoryStore,
            DecisionRecord,
        )

        fake_eid = uuid.uuid4()
        hist = DecisionHistoryStore(store._engine)
        await hist.append(
            DecisionRecord(
                decision_type="escalation.acknowledged",
                request_id="req-malformed-emit",
                actor_id="rogue",
                payload={
                    "escalation_id": str(fake_eid),
                    "from_state": "open",
                    "to_state": "acknowledged",
                    "reason": "emitted directly, bypassing open()",
                },
            )
        )

        # transition() against the malformed-chain escalation_id
        # MUST raise EscalationNotFound — the chain has rows for
        # this id but none is an ``escalation.opened``, so the
        # escalation was never legitimately opened.
        with pytest.raises(EscalationNotFound) as exc_info:
            await store.transition(
                escalation_id=fake_eid,
                actor_id="legitimate-caller",
                new_state=EscalationState.ASSIGNED,
                reason="should be blocked by opened-row guard",
                request_id="req-after-malformed",
            )
        assert exc_info.value.escalation_id == fake_eid

    async def _head(self, engine: AsyncEngine) -> tuple[int, bytes]:
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    select(
                        _chain_heads.c.latest_sequence,
                        _chain_heads.c.latest_hash,
                    ).where(_chain_heads.c.chain_id == "decision_history")
                )
            ).one()
        return int(row.latest_sequence), bytes(row.latest_hash)

    async def _row_count(self, engine: AsyncEngine) -> int:
        from sqlalchemy import func
        from sqlalchemy import select as _select

        async with engine.connect() as conn:
            r = await conn.execute(_select(func.count()).select_from(_decision_history))
        return int(r.scalar() or 0)


# ===========================================================================
# Validator/builder ordering + payload shape (T2 Option-A primitive)
# ===========================================================================


class TestValidatorBuilderOrdering:
    """The transition() implementation must use T2's
    append_with_precondition primitive correctly: precondition runs
    BEFORE record_builder, and the precondition's return value
    (the captured in-lock current_state) flows into the builder
    verbatim. Both surfaces are observable through the persisted
    payload's ``from_state`` field (set from the precondition's
    return value)."""

    async def test_from_state_in_payload_matches_chain_end_state(
        self, store: EscalationStore, engine: AsyncEngine
    ) -> None:
        # Drive open → ack. Then transition to assigned. The
        # transition row's payload.from_state MUST be "acknowledged"
        # (the chain end-state at the moment the precondition ran).
        eid, _, _ = await store.open(
            actor_id="canary",
            level="p1",
            reason="ordering",
            request_id="req-ord-open",
        )
        await store.transition(
            escalation_id=eid,
            actor_id="canary",
            new_state=EscalationState.ACKNOWLEDGED,
            reason="to-ack",
            request_id="req-ord-ack",
        )
        await store.transition(
            escalation_id=eid,
            actor_id="canary",
            new_state=EscalationState.ASSIGNED,
            reason="to-assigned",
            request_id="req-ord-assigned",
        )

        async with engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(
                        _decision_history.c.event_type,
                        _decision_history.c.payload,
                    ).order_by(_decision_history.c.sequence)
                )
            ).all()
        # Last row is the assigned-transition; its from_state must be
        # the chain-end-state at the moment the precondition ran.
        last = rows[-1]
        assert last.event_type == "escalation.assigned"
        assert last.payload["from_state"] == "acknowledged"
        assert last.payload["to_state"] == "assigned"
        assert last.payload["escalation_id"] == str(eid)
        assert last.payload["reason"] == "to-assigned"
        # actor_id merged into payload by Sprint 2 contract.
        assert last.payload["actor_id"] == "canary"

    async def test_payload_only_contains_documented_keys(
        self, store: EscalationStore, engine: AsyncEngine
    ) -> None:
        # The transition record_builder produces a payload with
        # exactly: escalation_id, reason, from_state, to_state. The
        # store merges actor_id (Sprint 2 contract). No other keys
        # should appear — the persisted row is the audit surface
        # examiners read.
        eid, _, _ = await store.open(
            actor_id="canary",
            level="p1",
            reason="payload-shape",
            request_id="req-shape-open",
        )
        await store.transition(
            escalation_id=eid,
            actor_id="canary",
            new_state=EscalationState.ACKNOWLEDGED,
            reason="ack",
            request_id="req-shape-ack",
        )
        async with engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(_decision_history.c.payload).order_by(_decision_history.c.sequence)
                )
            ).all()
        # Open row carries level too (an additional field for the
        # genesis row only); transition rows do NOT carry level.
        assert set(rows[0].payload.keys()) == {
            "escalation_id",
            "level",
            "reason",
            "from_state",
            "to_state",
            "actor_id",
        }
        assert set(rows[1].payload.keys()) == {
            "escalation_id",
            "reason",
            "from_state",
            "to_state",
            "actor_id",
        }


# ===========================================================================
# Sprint 2.5 T4 — public read-side projection (Escalation, get_by_id, list_open)
# ===========================================================================
#
# T4 is read-only: it adds the public ``Escalation`` dataclass plus
# ``EscalationStore.get_by_id`` + ``.list_open()``. T3's write
# contract is unchanged. Malformed-chain semantics MUST be consistent
# with T3's ``_read_current_state_within_txn`` (PR-#7-T3 reviewer P2):
# a chain slice with only transition rows and no ``escalation.opened``
# row for an id is malformed, and:
#   - ``get_by_id`` MUST raise ``EscalationNotFound``.
#   - ``list_open`` MUST skip the malformed entry (NOT synthesize a
#     projection from a partial chain).


class TestEscalationProjectionDataclass:
    """The Escalation projection is frozen + slotted; mutation
    rejected; field set matches the contract."""

    def _sample(self) -> Escalation:
        from cognic_agentos.core.escalation import Escalation as _E

        opened_at = datetime(2026, 4, 29, 12, 0, 0, tzinfo=UTC)
        return _E(
            escalation_id=uuid.uuid4(),
            current_state=EscalationState.OPEN,
            opened_at=opened_at,
            last_transition_at=opened_at,
            level="p1",
            transitions=((None, EscalationState.OPEN, opened_at, "agent-x"),),
        )

    def test_dataclass_is_frozen(self) -> None:
        import dataclasses

        e = self._sample()
        with pytest.raises(dataclasses.FrozenInstanceError):
            e.level = "other"  # type: ignore[misc]

    def test_dataclass_field_set_matches_contract(self) -> None:
        import dataclasses

        e = self._sample()
        names = {f.name for f in dataclasses.fields(e)}
        assert names == {
            "escalation_id",
            "current_state",
            "opened_at",
            "last_transition_at",
            "level",
            "transitions",
        }


class TestGetById:
    """``get_by_id`` projects the full lifecycle from
    decision_history. Eventually-consistent — separate from T3's
    in-lock validator read."""

    async def test_returns_projection_for_open_only_chain(self, store: EscalationStore) -> None:
        eid, _, _ = await store.open(
            actor_id="agent-x",
            level="p2",
            reason="just opened",
            request_id="req-getbyid-1",
        )
        e = await store.get_by_id(eid)
        assert e.escalation_id == eid
        assert e.current_state == EscalationState.OPEN
        assert e.level == "p2"
        # Only the opened row is in the chain; opened_at == last_transition_at.
        assert e.opened_at == e.last_transition_at
        assert e.opened_at.tzinfo is not None  # always tz-aware
        # transitions tuple has one entry: the open event itself.
        assert len(e.transitions) == 1
        from_s, to_s, at, actor = e.transitions[0]
        assert from_s is None
        assert to_s == EscalationState.OPEN
        assert at == e.opened_at
        assert actor == "agent-x"

    async def test_returns_projection_for_full_lifecycle(self, store: EscalationStore) -> None:
        eid, _, _ = await store.open(
            actor_id="agent-x",
            level="p1",
            reason="full lifecycle",
            request_id="req-full-1",
        )
        await store.transition(
            escalation_id=eid,
            actor_id="agent-y",
            new_state=EscalationState.ACKNOWLEDGED,
            reason="ack",
            request_id="req-full-2",
        )
        await store.transition(
            escalation_id=eid,
            actor_id="agent-z",
            new_state=EscalationState.ASSIGNED,
            reason="assign",
            request_id="req-full-3",
        )
        await store.transition(
            escalation_id=eid,
            actor_id="agent-w",
            new_state=EscalationState.RESOLVED,
            reason="resolve",
            request_id="req-full-4",
        )

        e = await store.get_by_id(eid)
        assert e.escalation_id == eid
        assert e.current_state == EscalationState.RESOLVED
        assert e.level == "p1"  # carried from opened row
        # Four transitions, oldest first.
        assert len(e.transitions) == 4
        # Transition tuples: (from, to, at, actor_id).
        from_states = [t[0] for t in e.transitions]
        to_states = [t[1] for t in e.transitions]
        actors = [t[3] for t in e.transitions]
        assert from_states == [
            None,
            EscalationState.OPEN,
            EscalationState.ACKNOWLEDGED,
            EscalationState.ASSIGNED,
        ]
        assert to_states == [
            EscalationState.OPEN,
            EscalationState.ACKNOWLEDGED,
            EscalationState.ASSIGNED,
            EscalationState.RESOLVED,
        ]
        assert actors == ["agent-x", "agent-y", "agent-z", "agent-w"]
        # Timestamps: opened_at is first; last_transition_at is last.
        assert e.opened_at == e.transitions[0][2]
        assert e.last_transition_at == e.transitions[-1][2]
        # Strictly non-decreasing — sequence-ordered.
        ats = [t[2] for t in e.transitions]
        assert ats == sorted(ats)

    async def test_re_escalation_lifecycle_projects_all_transitions(
        self, store: EscalationStore
    ) -> None:
        eid, _, _ = await store.open(
            actor_id="canary",
            level="p1",
            reason="re-escalate",
            request_id="req-re-open",
        )
        for s in (
            EscalationState.ACKNOWLEDGED,
            EscalationState.ASSIGNED,
            EscalationState.RE_ESCALATED,
            EscalationState.ACKNOWLEDGED,
            EscalationState.ASSIGNED,
            EscalationState.RESOLVED,
        ):
            await store.transition(
                escalation_id=eid,
                actor_id="canary",
                new_state=s,
                reason=f"to-{s.value}",
                request_id=f"req-re-{s.value}",
            )

        e = await store.get_by_id(eid)
        assert e.current_state == EscalationState.RESOLVED
        # Open + 6 transitions = 7 entries.
        assert len(e.transitions) == 7
        to_states = [t[1] for t in e.transitions]
        assert to_states == [
            EscalationState.OPEN,
            EscalationState.ACKNOWLEDGED,
            EscalationState.ASSIGNED,
            EscalationState.RE_ESCALATED,
            EscalationState.ACKNOWLEDGED,
            EscalationState.ASSIGNED,
            EscalationState.RESOLVED,
        ]

    async def test_unknown_id_raises_escalation_not_found(self, store: EscalationStore) -> None:
        unknown = uuid.uuid4()
        with pytest.raises(EscalationNotFound) as exc_info:
            await store.get_by_id(unknown)
        assert exc_info.value.escalation_id == unknown

    async def test_empty_chain_raises_escalation_not_found(self, store: EscalationStore) -> None:
        # Fixture chain starts empty — any get_by_id raises.
        with pytest.raises(EscalationNotFound):
            await store.get_by_id(uuid.uuid4())

    async def test_malformed_chain_no_opened_row_raises(self, store: EscalationStore) -> None:
        """Malformed-chain semantics consistent with T3's
        _read_current_state_within_txn seen_opened guard. A chain
        with only transition rows for an id (no escalation.opened)
        is malformed; get_by_id MUST raise EscalationNotFound, not
        synthesize an Escalation from the partial chain."""

        from cognic_agentos.core.decision_history import (
            DecisionHistoryStore,
            DecisionRecord,
        )

        fake_eid = uuid.uuid4()
        hist = DecisionHistoryStore(store._engine)
        await hist.append(
            DecisionRecord(
                decision_type="escalation.acknowledged",
                request_id="req-malformed-getbyid",
                actor_id="rogue",
                payload={
                    "escalation_id": str(fake_eid),
                    "from_state": "open",
                    "to_state": "acknowledged",
                    "reason": "bypass-open emit",
                },
            )
        )

        with pytest.raises(EscalationNotFound) as exc_info:
            await store.get_by_id(fake_eid)
        assert exc_info.value.escalation_id == fake_eid

    async def test_picks_correct_escalation_from_multi_id_chain(
        self, store: EscalationStore
    ) -> None:
        eid_a, _, _ = await store.open(
            actor_id="a",
            level="p1",
            reason="a",
            request_id="req-multi-a",
        )
        eid_b, _, _ = await store.open(
            actor_id="b",
            level="p2",
            reason="b",
            request_id="req-multi-b",
        )
        # Drive a forward; leave b at OPEN.
        await store.transition(
            escalation_id=eid_a,
            actor_id="a",
            new_state=EscalationState.ACKNOWLEDGED,
            reason="ack-a",
            request_id="req-multi-a-ack",
        )

        e_a = await store.get_by_id(eid_a)
        e_b = await store.get_by_id(eid_b)

        assert e_a.escalation_id == eid_a
        assert e_a.current_state == EscalationState.ACKNOWLEDGED
        assert e_a.level == "p1"
        assert len(e_a.transitions) == 2  # opened + acknowledged

        assert e_b.escalation_id == eid_b
        assert e_b.current_state == EscalationState.OPEN
        assert e_b.level == "p2"
        assert len(e_b.transitions) == 1  # opened only


class TestListOpen:
    """``list_open`` returns all escalations whose current_state is
    not RESOLVED. Walks the escalation-typed slice once. O(n)."""

    async def test_empty_chain_returns_empty(self, store: EscalationStore) -> None:
        result = await store.list_open()
        assert result == ()

    async def test_returns_tuple_with_single_open(self, store: EscalationStore) -> None:
        eid, _, _ = await store.open(
            actor_id="a",
            level="p1",
            reason="single open",
            request_id="req-listopen-1",
        )
        result = await store.list_open()
        assert isinstance(result, tuple)
        assert len(result) == 1
        assert result[0].escalation_id == eid
        assert result[0].current_state == EscalationState.OPEN

    async def test_resolved_escalation_not_listed(self, store: EscalationStore) -> None:
        eid, _, _ = await store.open(
            actor_id="a",
            level="p1",
            reason="will resolve",
            request_id="req-resolve-open",
        )
        for s in (
            EscalationState.ACKNOWLEDGED,
            EscalationState.ASSIGNED,
            EscalationState.RESOLVED,
        ):
            await store.transition(
                escalation_id=eid,
                actor_id="a",
                new_state=s,
                reason=f"to-{s.value}",
                request_id=f"req-resolve-{s.value}",
            )
        result = await store.list_open()
        assert result == ()

    async def test_mixed_states_only_non_resolved_listed(self, store: EscalationStore) -> None:
        # Build a chain with escalations in each non-RESOLVED state +
        # one RESOLVED. list_open MUST return only the non-RESOLVED
        # ones (4 of them).
        eid_open, _, _ = await store.open(
            actor_id="a", level="p1", reason="open-only", request_id="req-mix-1"
        )
        eid_ack, _, _ = await store.open(
            actor_id="b", level="p1", reason="will-ack", request_id="req-mix-2"
        )
        await store.transition(
            escalation_id=eid_ack,
            actor_id="b",
            new_state=EscalationState.ACKNOWLEDGED,
            reason="ack",
            request_id="req-mix-2-ack",
        )
        eid_assigned, _, _ = await store.open(
            actor_id="c", level="p1", reason="will-assign", request_id="req-mix-3"
        )
        for s in (EscalationState.ACKNOWLEDGED, EscalationState.ASSIGNED):
            await store.transition(
                escalation_id=eid_assigned,
                actor_id="c",
                new_state=s,
                reason=f"to-{s.value}",
                request_id=f"req-mix-3-{s.value}",
            )
        eid_re, _, _ = await store.open(
            actor_id="d", level="p1", reason="will-re-escalate", request_id="req-mix-4"
        )
        for s in (
            EscalationState.ACKNOWLEDGED,
            EscalationState.ASSIGNED,
            EscalationState.RE_ESCALATED,
        ):
            await store.transition(
                escalation_id=eid_re,
                actor_id="d",
                new_state=s,
                reason=f"to-{s.value}",
                request_id=f"req-mix-4-{s.value}",
            )
        eid_resolved, _, _ = await store.open(
            actor_id="e", level="p1", reason="will-resolve", request_id="req-mix-5"
        )
        for s in (
            EscalationState.ACKNOWLEDGED,
            EscalationState.ASSIGNED,
            EscalationState.RESOLVED,
        ):
            await store.transition(
                escalation_id=eid_resolved,
                actor_id="e",
                new_state=s,
                reason=f"to-{s.value}",
                request_id=f"req-mix-5-{s.value}",
            )

        result = await store.list_open()
        # Set-equality (order is implementation-defined; don't pin it).
        result_ids = {e.escalation_id for e in result}
        assert result_ids == {eid_open, eid_ack, eid_assigned, eid_re}
        # Per-id state check.
        by_id = {e.escalation_id: e for e in result}
        assert by_id[eid_open].current_state == EscalationState.OPEN
        assert by_id[eid_ack].current_state == EscalationState.ACKNOWLEDGED
        assert by_id[eid_assigned].current_state == EscalationState.ASSIGNED
        assert by_id[eid_re].current_state == EscalationState.RE_ESCALATED
        # And the resolved one is genuinely absent.
        assert eid_resolved not in result_ids

    async def test_malformed_chain_entries_skipped_not_synthesized(
        self, store: EscalationStore
    ) -> None:
        """Malformed-chain consistency with T3 + get_by_id: entries
        in the chain that have only transition rows (no
        escalation.opened) MUST be skipped, NOT synthesized into
        Escalation projections. Mirror of get_by_id's
        EscalationNotFound semantics in collection form."""

        from cognic_agentos.core.decision_history import (
            DecisionHistoryStore,
            DecisionRecord,
        )

        # One legitimate open escalation.
        legit_eid, _, _ = await store.open(
            actor_id="legit",
            level="p1",
            reason="legitimate",
            request_id="req-list-legit",
        )

        # One malformed chain entry: only acknowledged, no opened.
        malformed_eid = uuid.uuid4()
        hist = DecisionHistoryStore(store._engine)
        await hist.append(
            DecisionRecord(
                decision_type="escalation.acknowledged",
                request_id="req-list-malformed",
                actor_id="rogue",
                payload={
                    "escalation_id": str(malformed_eid),
                    "from_state": "open",
                    "to_state": "acknowledged",
                    "reason": "bypass-open in list_open scan",
                },
            )
        )

        result = await store.list_open()
        result_ids = {e.escalation_id for e in result}
        # Only the legitimate one is in the result.
        assert legit_eid in result_ids
        assert malformed_eid not in result_ids


class TestProjectionLifecycleValidation:
    """Reviewer T4 P1 regression tests: ``_project_escalations``
    validates the per-id lifecycle while projecting. Direct emits
    that produce illegal sequences after a legitimate ``open()``
    row MUST cause the whole group to be rejected — same observable
    behaviour as the no-opened-row case (T3 P2 fix).

    These tests exercise the malformed-chain shapes that would have
    slipped through the original T4 projection (which only checked
    "opened row exists somewhere" and accepted any subsequent rows
    verbatim). Without the lifecycle guard, ``list_open()`` would
    have silently omitted an actually-open escalation as resolved
    when a bypass-emit injected ``escalation.resolved`` directly
    after the open.
    """

    async def _emit_direct(
        self,
        store: EscalationStore,
        *,
        escalation_id: uuid.UUID,
        decision_type: str,
        from_state: str | None,
        to_state: str,
        actor_id: str = "rogue",
        request_id: str = "req-direct",
    ) -> None:
        """Emit a single decision_history row via the bypass path
        (``DecisionHistoryStore.append`` directly, not
        ``EscalationStore.transition``). Used to construct the
        malformed-chain shapes the new validator rejects."""

        from cognic_agentos.core.decision_history import (
            DecisionHistoryStore,
            DecisionRecord,
        )

        hist = DecisionHistoryStore(store._engine)
        await hist.append(
            DecisionRecord(
                decision_type=decision_type,
                request_id=request_id,
                actor_id=actor_id,
                payload={
                    "escalation_id": str(escalation_id),
                    "from_state": from_state,
                    "to_state": to_state,
                    "reason": "bypass-EscalationStore direct emit",
                },
            )
        )

    async def test_open_then_direct_resolved_skipping_states_rejected(
        self, store: EscalationStore
    ) -> None:
        """Reviewer's exact threat shape: legitimate ``open()`` then
        a direct emit of ``escalation.resolved`` (skipping ack +
        assigned). Linkage (from=open) holds, but adjacency
        (RESOLVED not in _LEGAL_TRANSITIONS[OPEN]) does not.

        get_by_id MUST raise EscalationNotFound — the projection
        treats the whole group as malformed.
        """

        eid, _, _ = await store.open(
            actor_id="legit",
            level="p1",
            reason="will be corrupted",
            request_id="req-corrupted-1",
        )
        # Direct emit of resolved, claiming from=open. Linkage
        # passes; adjacency fails (OPEN -> RESOLVED is illegal).
        await self._emit_direct(
            store,
            escalation_id=eid,
            decision_type="escalation.resolved",
            from_state="open",
            to_state="resolved",
        )

        with pytest.raises(EscalationNotFound):
            await store.get_by_id(eid)

    async def test_open_then_direct_resolved_skipping_states_omitted_from_list_open(
        self, store: EscalationStore
    ) -> None:
        """Same threat shape, list_open side. Without the lifecycle
        guard, the projection would set current_state=RESOLVED and
        list_open would silently OMIT the corrupt escalation —
        operators would see "no open escalations" while a real-but-
        bypassed escalation sat in the chain. With the guard, the
        whole group is skipped: it appears nowhere in list_open.
        """

        eid, _, _ = await store.open(
            actor_id="legit",
            level="p1",
            reason="should-be-open-but-corrupted",
            request_id="req-corrupted-2",
        )
        await self._emit_direct(
            store,
            escalation_id=eid,
            decision_type="escalation.resolved",
            from_state="open",
            to_state="resolved",
        )

        result = await store.list_open()
        result_ids = {e.escalation_id for e in result}
        # The corrupted escalation MUST NOT appear — neither as
        # OPEN (which it logically is) nor as RESOLVED (which the
        # bypass-emit faked).
        assert eid not in result_ids

    async def test_broken_linkage_rejected(self, store: EscalationStore) -> None:
        """``open()`` + legitimate ``transition(ACKNOWLEDGED)``,
        then a direct emit whose ``from_state`` does not match the
        prior row's ``to_state`` (claims from=assigned, but the
        actual chain end-state is acknowledged). The new validator
        rejects the whole group on linkage break.
        """

        eid, _, _ = await store.open(
            actor_id="legit",
            level="p1",
            reason="linkage-test",
            request_id="req-linkage-1",
        )
        await store.transition(
            escalation_id=eid,
            actor_id="legit",
            new_state=EscalationState.ACKNOWLEDGED,
            reason="legit ack",
            request_id="req-linkage-2",
        )
        # Direct emit: claim from="assigned", to="resolved". Adjacency
        # is technically legal (ASSIGNED -> RESOLVED is in the map),
        # but linkage is broken (prior to_state was acknowledged,
        # not assigned).
        await self._emit_direct(
            store,
            escalation_id=eid,
            decision_type="escalation.resolved",
            from_state="assigned",
            to_state="resolved",
        )

        with pytest.raises(EscalationNotFound):
            await store.get_by_id(eid)

    async def test_duplicate_opened_row_rejected(self, store: EscalationStore) -> None:
        """Two ``escalation.opened`` rows for the same escalation_id
        — only one legitimate genesis is allowed; duplicates are
        rejected as malformed."""

        eid, _, _ = await store.open(
            actor_id="legit",
            level="p1",
            reason="will-double-open",
            request_id="req-dup-1",
        )
        # Direct emit of a second escalation.opened.
        await self._emit_direct(
            store,
            escalation_id=eid,
            decision_type="escalation.opened",
            from_state=None,
            to_state="open",
        )

        with pytest.raises(EscalationNotFound):
            await store.get_by_id(eid)

    async def test_genesis_row_with_wrong_to_state_rejected(self, store: EscalationStore) -> None:
        """A bypass-emit that crafts an ``escalation.opened`` row but
        with ``to_state != "open"`` is rejected: the genesis-row shape
        check requires from=None AND to="open"."""

        from cognic_agentos.core.decision_history import (
            DecisionHistoryStore,
            DecisionRecord,
        )

        fake_eid = uuid.uuid4()
        hist = DecisionHistoryStore(store._engine)
        await hist.append(
            DecisionRecord(
                decision_type="escalation.opened",
                request_id="req-wrong-genesis",
                actor_id="rogue",
                payload={
                    "escalation_id": str(fake_eid),
                    "from_state": None,
                    "to_state": "acknowledged",  # wrong — should be "open"
                    "level": "p1",
                    "reason": "wrong genesis to_state",
                },
            )
        )

        with pytest.raises(EscalationNotFound):
            await store.get_by_id(fake_eid)

    async def test_genesis_row_with_non_none_from_state_rejected(
        self, store: EscalationStore
    ) -> None:
        """An ``escalation.opened`` row with a non-None ``from_state``
        is rejected: the genesis row by definition has no prior state.
        """

        from cognic_agentos.core.decision_history import (
            DecisionHistoryStore,
            DecisionRecord,
        )

        fake_eid = uuid.uuid4()
        hist = DecisionHistoryStore(store._engine)
        await hist.append(
            DecisionRecord(
                decision_type="escalation.opened",
                request_id="req-wrong-from",
                actor_id="rogue",
                payload={
                    "escalation_id": str(fake_eid),
                    "from_state": "acknowledged",  # wrong — should be None
                    "to_state": "open",
                    "level": "p1",
                    "reason": "wrong genesis from_state",
                },
            )
        )

        with pytest.raises(EscalationNotFound):
            await store.get_by_id(fake_eid)

    async def test_non_string_from_or_to_state_in_post_open_row_rejected(
        self, store: EscalationStore
    ) -> None:
        """Bypass-emit with malformed payload shape: ``from_state``
        or ``to_state`` is not a string. The validator's isinstance
        check rejects the group."""

        from cognic_agentos.core.decision_history import (
            DecisionHistoryStore,
            DecisionRecord,
        )

        eid, _, _ = await store.open(
            actor_id="legit",
            level="p1",
            reason="will-emit-non-string",
            request_id="req-non-string-1",
        )
        # Direct emit: from_state is a number, not a string.
        # canonical_bytes accepts numbers; the payload lands in the
        # chain. The lifecycle validator rejects on isinstance.
        hist = DecisionHistoryStore(store._engine)
        await hist.append(
            DecisionRecord(
                decision_type="escalation.acknowledged",
                request_id="req-non-string-2",
                actor_id="rogue",
                payload={
                    "escalation_id": str(eid),
                    "from_state": 42,  # type-wrong: should be a string
                    "to_state": "acknowledged",
                    "reason": "non-string from_state",
                },
            )
        )

        with pytest.raises(EscalationNotFound):
            await store.get_by_id(eid)

    async def test_unknown_state_string_in_post_open_row_rejected(
        self, store: EscalationStore
    ) -> None:
        """Bypass-emit whose ``from_state`` / ``to_state`` is a
        string but does not match any ``EscalationState`` value
        (e.g. typo, future-state, deliberate corruption). The
        validator's ``EscalationState(...)`` ValueError-trap rejects
        the group."""

        from cognic_agentos.core.decision_history import (
            DecisionHistoryStore,
            DecisionRecord,
        )

        eid, _, _ = await store.open(
            actor_id="legit",
            level="p1",
            reason="will-emit-unknown-state",
            request_id="req-unknown-state-1",
        )
        hist = DecisionHistoryStore(store._engine)
        await hist.append(
            DecisionRecord(
                decision_type="escalation.acknowledged",
                request_id="req-unknown-state-2",
                actor_id="rogue",
                payload={
                    "escalation_id": str(eid),
                    "from_state": "open",
                    "to_state": "wibble",  # not an EscalationState value
                    "reason": "unknown to_state value",
                },
            )
        )

        with pytest.raises(EscalationNotFound):
            await store.get_by_id(eid)

    async def test_event_type_disagrees_with_to_state_rejected(
        self, store: EscalationStore
    ) -> None:
        """Reviewer T4 P2 regression: the persisted ``event_type``
        column is independent evidence and MUST agree with the
        payload's ``to_state``. A bypass-emit that writes
        ``event_type='escalation.resolved'`` while
        ``payload['to_state']='acknowledged'`` is rejected — the row's
        discriminator and its claimed target state disagree.

        Without this guard, the projection would surface an
        ACKNOWLEDGED state while an auditor reading raw rows would
        see ``event_type=escalation.resolved`` for the same chain
        sequence — two stories about the same evidence row.
        """

        from cognic_agentos.core.decision_history import (
            DecisionHistoryStore,
            DecisionRecord,
        )

        eid, _, _ = await store.open(
            actor_id="legit",
            level="p1",
            reason="will-emit-mismatch",
            request_id="req-mismatch-1",
        )
        # Direct emit: event_type says "resolved" but payload says
        # the target is "acknowledged". Linkage holds (from=open
        # matches the chain's prior to_state); adjacency holds
        # (OPEN -> ACKNOWLEDGED is legal). The disagreement between
        # event_type and to_state is the only hole.
        hist = DecisionHistoryStore(store._engine)
        await hist.append(
            DecisionRecord(
                decision_type="escalation.resolved",  # row's event_type
                request_id="req-mismatch-2",
                actor_id="rogue",
                payload={
                    "escalation_id": str(eid),
                    "from_state": "open",
                    "to_state": "acknowledged",  # payload disagrees
                    "reason": "event_type / to_state mismatch",
                },
            )
        )

        with pytest.raises(EscalationNotFound):
            await store.get_by_id(eid)

    async def test_event_type_disagrees_with_to_state_omitted_from_list_open(
        self, store: EscalationStore
    ) -> None:
        """Same threat shape on the list_open side: malformed groups
        are silently skipped rather than projected with the
        payload's claimed state."""

        from cognic_agentos.core.decision_history import (
            DecisionHistoryStore,
            DecisionRecord,
        )

        eid, _, _ = await store.open(
            actor_id="legit",
            level="p1",
            reason="will-emit-mismatch-listopen",
            request_id="req-mismatch-3",
        )
        hist = DecisionHistoryStore(store._engine)
        await hist.append(
            DecisionRecord(
                decision_type="escalation.assigned",  # event_type says assigned
                request_id="req-mismatch-4",
                actor_id="rogue",
                payload={
                    "escalation_id": str(eid),
                    "from_state": "open",
                    "to_state": "acknowledged",  # payload says ack
                    "reason": "list_open mismatch shape",
                },
            )
        )

        result = await store.list_open()
        result_ids = {e.escalation_id for e in result}
        assert eid not in result_ids

    async def test_legit_lifecycle_unaffected(self, store: EscalationStore) -> None:
        """Belt-and-braces regression: a fully-legitimate lifecycle
        through ``EscalationStore.open`` + ``transition`` MUST still
        project correctly with the lifecycle guard in place."""

        eid, _, _ = await store.open(
            actor_id="legit",
            level="p1",
            reason="legitimate end-to-end",
            request_id="req-legit-end-1",
        )
        for s in (
            EscalationState.ACKNOWLEDGED,
            EscalationState.ASSIGNED,
            EscalationState.RESOLVED,
        ):
            await store.transition(
                escalation_id=eid,
                actor_id="legit",
                new_state=s,
                reason=f"to-{s.value}",
                request_id=f"req-legit-end-{s.value}",
            )

        e = await store.get_by_id(eid)
        assert e.current_state == EscalationState.RESOLVED
        assert len(e.transitions) == 4

    async def test_perfectly_faked_lifecycle_via_direct_emits_accepted(
        self, store: EscalationStore
    ) -> None:
        """Documents the contract boundary: a bypass-emit sequence
        that PERFECTLY mimics a legitimate lifecycle (each row's
        from_state matches the prior to_state + adjacency holds) is
        ACCEPTED. The projection layer cannot distinguish such
        emits from legitimate ones — that defence lives at the
        runtime-role GRANTs (Sprint 2 operator runbook) and the
        chain verifier (T8). The projection's job is to surface
        valid-LOOKING lifecycles; runtime-role enforcement and
        evidence-pack signatures defend against fully-faked emits.

        This is NOT a defect — it's the boundary where projection
        guards stop. Pinning it as a documented contract.
        """

        from cognic_agentos.core.decision_history import (
            DecisionHistoryStore,
            DecisionRecord,
        )

        fake_eid = uuid.uuid4()
        hist = DecisionHistoryStore(store._engine)
        # Perfect bypass-emit lifecycle:
        # opened -> acknowledged -> assigned -> resolved.
        sequence = [
            ("escalation.opened", None, "open"),
            ("escalation.acknowledged", "open", "acknowledged"),
            ("escalation.assigned", "acknowledged", "assigned"),
            ("escalation.resolved", "assigned", "resolved"),
        ]
        for i, (decision_type, from_state, to_state) in enumerate(sequence):
            await hist.append(
                DecisionRecord(
                    decision_type=decision_type,
                    request_id=f"req-faked-{i}",
                    actor_id="rogue",
                    payload={
                        "escalation_id": str(fake_eid),
                        "from_state": from_state,
                        "to_state": to_state,
                        "level": "p1" if i == 0 else None,
                        "reason": f"faked {decision_type}",
                    },
                )
            )

        # Projection accepts the faked-but-shape-correct lifecycle.
        # Defence-in-depth lives at other layers.
        e = await store.get_by_id(fake_eid)
        assert e.current_state == EscalationState.RESOLVED
        assert len(e.transitions) == 4


class TestT3WriteContractUnchanged:
    """T4 is read-only — T3's write contract is preserved. Sanity-
    check that the write path still works end-to-end after T4 lands.
    The full T3 test surface still passes (this class is an extra
    smoke test focused on the write-path contract specifically)."""

    async def test_t3_write_path_still_works_after_t4(
        self, store: EscalationStore, engine: AsyncEngine
    ) -> None:
        eid, rid, h = await store.open(
            actor_id="canary",
            level="p1",
            reason="t3 still works",
            request_id="req-t3-still-works",
        )
        await store.transition(
            escalation_id=eid,
            actor_id="canary",
            new_state=EscalationState.ACKNOWLEDGED,
            reason="ack",
            request_id="req-t3-still-works-ack",
        )
        # Verify by reading the chain directly (NOT through T4 reader,
        # just to keep this test scoped to T3's write contract).
        async with engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(_decision_history.c.event_type).order_by(_decision_history.c.sequence)
                )
            ).all()
        assert [r.event_type for r in rows] == [
            "escalation.opened",
            "escalation.acknowledged",
        ]
        assert isinstance(eid, uuid.UUID)
        assert isinstance(rid, uuid.UUID)
        assert len(h) == 32
