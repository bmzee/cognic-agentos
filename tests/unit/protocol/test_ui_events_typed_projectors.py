"""Sprint 7B.4 T4 — typed-projector dispatch + canonical projection order
regressions for the decision_history typed projector table.

Verifies:
  - All 5 known decision_types (4 exact-match + 1 prefix-match) project to
    the correct typed family/type slot
  - Unknown decision_types fall through to None (mirror-only path)
  - Projector event_ids are deterministic per (sequence, family.type) tuple
  - Canonical projection order holds: typed at ordinal 0, mirror at ordinal 1
  - Live `_on_decision_append` and the shared `_build_decision_audit_for_dh_snapshot`
    helper produce byte-identical decision_audit events (R3 #2 parity)
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, get_args

from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import AppendedDecisionSnapshot
from cognic_agentos.protocol.ui_events import (
    _DECISION_HISTORY_TYPED_PROJECTORS,
    DecisionAuditEventAppended,
    FrontendActionAccepted,
    FrontendActionRejected,
    FrontendActionSubmitted,
    PolicyDecisionEvaluated,
    PolicyRBACDenied,
    _build_decision_audit_for_dh_snapshot,
    _chain_derived_event_id,
    _project_typed_decision_history,
)


def _make_snapshot(
    *,
    decision_type: str,
    sequence: int = 42,
    payload: dict[str, Any] | None = None,
    tenant_id: str = "t1",
    request_id: str = "portal-req-test",
) -> AppendedDecisionSnapshot:
    """Build an AppendedDecisionSnapshot with fixed-but-arbitrary defaults
    suitable for projector dispatch tests. Avoids any DB I/O — the
    projector functions are pure over snapshot inputs."""
    return AppendedDecisionSnapshot(
        record_id=uuid.UUID(int=0),
        chain_id="decision_history",
        sequence=sequence,
        new_hash=b"\xaa" * 32,
        created_at=datetime.now(UTC),
        decision_type=decision_type,
        request_id=request_id,
        payload=payload if payload is not None else {"k": "v"},
        tenant_id=tenant_id,
        trace_id="trace-x",
    )


class TestDecisionHistoryTypedRoutingCoversAll5DecisionTypes:
    """The 4 exact-match entries + the `rbac.*` prefix matcher cover the
    full Wave-1 typed-projector surface. Each one MUST project to the
    correct family/type slot — drift means a typed event gets routed to
    the wrong Pydantic model and downstream consumers see schema drift."""

    def test_frontend_action_submitted(self) -> None:
        evt = _project_typed_decision_history(
            _make_snapshot(decision_type="frontend_action.submitted")
        )
        assert isinstance(evt, FrontendActionSubmitted)
        assert evt.family == "frontend_action"
        assert evt.type == "submitted"

    def test_frontend_action_accepted(self) -> None:
        evt = _project_typed_decision_history(
            _make_snapshot(decision_type="frontend_action.accepted")
        )
        assert isinstance(evt, FrontendActionAccepted)
        assert evt.type == "accepted"

    def test_frontend_action_rejected(self) -> None:
        evt = _project_typed_decision_history(
            _make_snapshot(decision_type="frontend_action.rejected")
        )
        assert isinstance(evt, FrontendActionRejected)
        assert evt.type == "rejected"

    def test_policy_decision_evaluated(self) -> None:
        evt = _project_typed_decision_history(
            _make_snapshot(decision_type="policy.decision_evaluated")
        )
        assert isinstance(evt, PolicyDecisionEvaluated)
        assert evt.family == "policy"
        assert evt.type == "decision_evaluated"

    def test_rbac_prefix_matches_any_denial_type(self) -> None:
        """The `rbac.*` prefix matcher accepts ANY denial_type — the
        9 closed-enum values of RBACDenialType all flow through this
        path. Tested with one representative each to confirm dispatch
        + a few invariant assertions on the projected event."""
        for denial_type in (
            "actor_unauthenticated",
            "scope_not_held",
            "tenant_id_mismatch",
            "actor_type_must_be_human",
            "actor_cannot_review_own_pack",
        ):
            evt = _project_typed_decision_history(
                _make_snapshot(decision_type=f"rbac.{denial_type}")
            )
            assert isinstance(evt, PolicyRBACDenied), (
                f"rbac.{denial_type} → expected PolicyRBACDenied, got {type(evt).__name__}"
            )
            assert evt.family == "policy"
            assert evt.type == "rbac_denied"

    def test_table_keyset_pinned(self) -> None:
        """Drift detector — the 12 exact-match keys are the only allowed
        Wave-1 vocabulary on the typed-dispatch table (4 frontend_action +
        policy.decision_evaluated + the 2 subagent entries wired in Sprint
        11b T9 + the 4 memory.* entries wired in Sprint 11.5c T6 + the 2
        emergency.kill_switch_* entries wired in Sprint 13.6 T3 per the
        ADR-018 spec + plan of record). Adding a further entry requires a
        deliberate plan-of-record amendment + the corresponding class added
        to `_TYPED_PROJECTION_CLASSES`. Note: `rbac.*` (prefix) and the
        subagent depth-cap (scoped `escalation.opened`) route via
        CONDITIONAL branches, NOT this exact-match table."""
        assert set(_DECISION_HISTORY_TYPED_PROJECTORS.keys()) == {
            "frontend_action.submitted",
            "frontend_action.accepted",
            "frontend_action.rejected",
            "policy.decision_evaluated",
            "subagent.spawn",
            "subagent.return",
            # Sprint 11.5c T6 — memory.* chain event projectors.
            "memory.read",
            "memory.forget",
            "memory.regulator_erasure",
            "memory.redact",
            # Sprint 13.6 T3 — emergency kill-switch flip/revert (ADR-018).
            "emergency.kill_switch_flipped",
            "emergency.kill_switch_reverted",
        }


class TestDecisionHistoryTypedRoutingUnknownDecisionTypeOnlyMirror:
    """Unknown decision_types fall through the typed dispatcher to None;
    the emitter's `_on_decision_append` then emits ONLY the mirror at
    ordinal 1 (no typed event at ordinal 0). Pinned at unit-test layer
    for the dispatcher's behavior; integration coverage of the full
    emit path lives at
    test_ui_events_broker.TestDecisionAuditMirrorStillEmittedAfterT4Refactor."""

    def test_unknown_decision_type_returns_none(self) -> None:
        evt = _project_typed_decision_history(_make_snapshot(decision_type="something.unmapped"))
        assert evt is None

    def test_rbac_without_dot_does_not_match(self) -> None:
        """Defence-in-depth: the prefix check requires `rbac.` exactly
        (with the trailing dot). A bare `rbac` decision_type MUST fall
        through to None, not silently route to PolicyRBACDenied."""
        evt = _project_typed_decision_history(_make_snapshot(decision_type="rbac"))
        assert evt is None

    def test_empty_decision_type_returns_none(self) -> None:
        evt = _project_typed_decision_history(_make_snapshot(decision_type=""))
        assert evt is None

    def test_unknown_rbac_suffix_falls_through_to_none(self) -> None:
        """R1 #1 regression: the `rbac.*` prefix matcher MUST gate against
        the 9-value :data:`RBACDenialType` closed enum. A typo like
        `rbac.not_a_real_denial` MUST fall through to None (mirror-only
        path) rather than silently routing to :class:`PolicyRBACDenied` —
        a wrong-projection would emit a typed event whose `data.denial_type`
        is outside the locked vocabulary, weakening the wire contract.

        Threat-model-revert verified: this test FAILS if the dispatcher
        drops the closed-set check (proven by R1 commit verification)."""
        evt = _project_typed_decision_history(
            _make_snapshot(decision_type="rbac.not_a_real_denial")
        )
        assert evt is None

    def test_known_rbac_suffix_still_projects(self) -> None:
        """Round-trip pin: every member of the 9-value closed enum still
        routes to PolicyRBACDenied (no false negatives from the gate)."""
        from cognic_agentos.protocol.ui_events import RBACDenialType

        for denial_type in get_args(RBACDenialType):
            evt = _project_typed_decision_history(
                _make_snapshot(decision_type=f"rbac.{denial_type}")
            )
            assert isinstance(evt, PolicyRBACDenied), (
                f"rbac.{denial_type} (in closed enum) should project to PolicyRBACDenied, "
                f"got {type(evt).__name__}"
            )


class TestTypedProjectorEventIdDeterministic:
    """The same snapshot MUST produce the same event_id every time —
    determinism is load-bearing for the broker's ContextVar capture
    seam and for SSE-resume cursor semantics. Two projector calls on
    equivalent snapshots → byte-equal event_ids."""

    def test_same_sequence_same_event_id(self) -> None:
        snap_a = _make_snapshot(decision_type="frontend_action.submitted", sequence=100)
        snap_b = _make_snapshot(decision_type="frontend_action.submitted", sequence=100)
        evt_a = _project_typed_decision_history(snap_a)
        evt_b = _project_typed_decision_history(snap_b)
        assert evt_a is not None and evt_b is not None
        assert evt_a.event_id == evt_b.event_id

    def test_different_sequence_different_event_id(self) -> None:
        evt_a = _project_typed_decision_history(
            _make_snapshot(decision_type="policy.decision_evaluated", sequence=1)
        )
        evt_b = _project_typed_decision_history(
            _make_snapshot(decision_type="policy.decision_evaluated", sequence=2)
        )
        assert evt_a is not None and evt_b is not None
        assert evt_a.event_id != evt_b.event_id


class TestCanonicalProjectionOrderHoldsForBroker:
    """The typed event is projected at **ordinal 0**; the mirror at
    **ordinal 1**. Pinned at the projector-level (typed projectors
    hardcode ordinal=0; mirror helper hardcodes ordinal=1). A future
    refactor that swaps these would invalidate the broker's ContextVar
    capture (which filters _TYPED_PROJECTION_CLASSES, excluding the
    mirror) AND would break the SSE-resume cursor's ordinal-axis
    distinction between typed and mirror cursors on the same row."""

    def test_typed_event_id_carries_ordinal_zero(self) -> None:
        from cognic_agentos.protocol.ui_events import _decode_chain_cursor

        evt = _project_typed_decision_history(
            _make_snapshot(decision_type="frontend_action.submitted", sequence=7)
        )
        assert evt is not None
        cursor = _decode_chain_cursor(evt.event_id)
        assert cursor.ordinal == 0

    def test_mirror_event_id_carries_ordinal_one(self) -> None:
        from cognic_agentos.protocol.ui_events import _decode_chain_cursor

        mirror = _build_decision_audit_for_dh_snapshot(
            _make_snapshot(decision_type="frontend_action.submitted", sequence=7)
        )
        cursor = _decode_chain_cursor(mirror.event_id)
        assert cursor.ordinal == 1

    def test_typed_and_mirror_event_ids_diverge_on_same_sequence(self) -> None:
        """Same sequence, different ordinals → different cursors — this
        is what makes Last-Event-ID resume unambiguous on a row that
        emitted both events."""
        snap = _make_snapshot(decision_type="frontend_action.submitted", sequence=99)
        typed = _project_typed_decision_history(snap)
        mirror = _build_decision_audit_for_dh_snapshot(snap)
        assert typed is not None
        assert typed.event_id != mirror.event_id


class TestSharedDecisionAuditHelperParity:
    """R3 #2 invariant: the shared `_build_decision_audit_for_dh_snapshot`
    helper is the SINGLE SOURCE OF TRUTH for the
    decision_audit.event_appended projection — used by both
    `UIEventEmitter._on_decision_append` (live emit) AND by the T10 SSE
    replay path. The live + replay paths MUST produce byte-identical
    events for the same snapshot or SSE-resume would skip / duplicate
    events at the boundary."""

    def test_shared_helper_produces_expected_event_id(self) -> None:
        """Direct calls to the helper produce the same event_id as the
        encoder's deterministic output for (chain_id, sequence, ordinal=1,
        decision_audit, event_appended)."""
        snap = _make_snapshot(decision_type="x.y", sequence=123)
        mirror = _build_decision_audit_for_dh_snapshot(snap)
        expected_id = _chain_derived_event_id(
            chain_id="decision_history",
            sequence=123,
            ordinal=1,
            family="decision_audit",
            type_="event_appended",
        )
        assert mirror.event_id == expected_id

    def test_mirror_data_keyset_includes_source_identity_fields(self) -> None:
        """Per T12 R2 P2 #2: the mirror's `data` field carries the
        source row's identity (event_type, payload_digest, request_id,
        sequence, chain_id, tenant_id) so a reconnecting UI / examiner
        can identify the source without fetching the DB row. Drift
        here is a wire-protocol break for examiner consumers."""
        snap = _make_snapshot(
            decision_type="frontend_action.accepted",
            sequence=55,
            payload={"action_class": "approve", "outcome": "accepted"},
            tenant_id="bank-a",
            request_id="portal-req-mirror-1",
        )
        mirror = _build_decision_audit_for_dh_snapshot(snap)
        assert isinstance(mirror, DecisionAuditEventAppended)
        # Keyset pinned — drift detector for examiner-facing wire shape.
        assert set(mirror.data.keys()) == {
            "event_type",
            "payload_digest",
            "request_id",
            "sequence",
            "chain_id",
            "tenant_id",
        }
        assert mirror.data["event_type"] == "frontend_action.accepted"
        assert mirror.data["sequence"] == 55
        assert mirror.data["chain_id"] == "decision_history"
        assert mirror.data["tenant_id"] == "bank-a"
        assert mirror.data["request_id"] == "portal-req-mirror-1"

    def test_two_calls_on_equivalent_snapshots_are_byte_equal(self) -> None:
        """Live emit path and replay path BOTH go through this helper —
        same snapshot input MUST produce equal (event_id, data) outputs
        so SSE-resume sees no boundary drift."""
        snap_a = AppendedDecisionSnapshot(
            record_id=uuid.UUID(int=42),
            chain_id="decision_history",
            sequence=7,
            new_hash=ZERO_HASH,
            created_at=datetime(2026, 5, 16, tzinfo=UTC),
            decision_type="frontend_action.submitted",
            request_id="portal-req-parity",
            payload={"action_class": "approve"},
            tenant_id="t1",
            trace_id="trace-parity",
        )
        snap_b = AppendedDecisionSnapshot(
            record_id=uuid.UUID(int=42),
            chain_id="decision_history",
            sequence=7,
            new_hash=ZERO_HASH,
            created_at=datetime(2026, 5, 16, tzinfo=UTC),
            decision_type="frontend_action.submitted",
            request_id="portal-req-parity",
            payload={"action_class": "approve"},
            tenant_id="t1",
            trace_id="trace-parity",
        )
        mirror_a = _build_decision_audit_for_dh_snapshot(snap_a)
        mirror_b = _build_decision_audit_for_dh_snapshot(snap_b)
        assert mirror_a.event_id == mirror_b.event_id
        assert mirror_a.data == mirror_b.data
        assert mirror_a.model_dump() == mirror_b.model_dump()
