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
