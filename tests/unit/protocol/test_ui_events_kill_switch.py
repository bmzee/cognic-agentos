"""Sprint 13.6 T3 — kill_switch family chain-row projectors (ADR-018 + ADR-020).

The flip/revert evidence rows (``emergency.kill_switch_flipped`` /
``emergency.kill_switch_reverted``, T2) project to the Sprint-6 model stubs
``KillSwitchFlipped`` / ``KillSwitchReverted`` via the
``_DECISION_HISTORY_TYPED_PROJECTORS`` registry — both the live append-hook
path AND the SSE replay path consume the same projectors, and the payload
rides ``data`` (the policy-family precedent; NO model field changes).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from cognic_agentos.core.decision_history import AppendedDecisionSnapshot
from cognic_agentos.protocol.ui_events import (
    _DECISION_HISTORY_TYPED_PROJECTORS,
    KillSwitchFlipped,
    KillSwitchReverted,
    _project_typed_decision_history,
)


def _snapshot(decision_type: str) -> AppendedDecisionSnapshot:
    return AppendedDecisionSnapshot(
        record_id=uuid.uuid4(),
        chain_id="decision_history",
        sequence=7,
        new_hash=b"\x01" * 32,
        created_at=datetime(2026, 6, 13, tzinfo=UTC),
        decision_type=decision_type,
        request_id="emrg-flip-" + "0" * 32,
        payload={
            "class": "model",
            "scope_key": "tier1",
            "category": "incident_response",
            "reason": "cve",
            "active": decision_type.endswith("flipped"),
            "enforcement_status": "live",
            "actor_id": "ops-1",  # the DH store merges actor_id into payload
        },
        actor_id="ops-1",
        tenant_id=None,
    )


class TestKillSwitchProjectors:
    def test_registry_has_both_entries(self) -> None:
        assert "emergency.kill_switch_flipped" in _DECISION_HISTORY_TYPED_PROJECTORS
        assert "emergency.kill_switch_reverted" in _DECISION_HISTORY_TYPED_PROJECTORS

    def test_flipped_projects_typed_event_with_payload_as_data(self) -> None:
        snap = _snapshot("emergency.kill_switch_flipped")
        event = _project_typed_decision_history(snap)
        assert isinstance(event, KillSwitchFlipped)
        assert event.family == "kill_switch"
        assert event.type == "flipped"
        assert event.data == snap.payload
        assert event.ts == snap.created_at

    def test_reverted_projects_typed_event(self) -> None:
        snap = _snapshot("emergency.kill_switch_reverted")
        event = _project_typed_decision_history(snap)
        assert isinstance(event, KillSwitchReverted)
        assert event.family == "kill_switch"
        assert event.type == "reverted"
        assert event.data == snap.payload

    def test_event_id_is_chain_derived_and_replay_stable(self) -> None:
        # The SAME chain row must project the SAME event_id on live emit and
        # on SSE replay (reconnect-safe per ADR-020).
        snap = _snapshot("emergency.kill_switch_flipped")
        e1 = _project_typed_decision_history(snap)
        e2 = _project_typed_decision_history(snap)
        assert e1 is not None
        assert e2 is not None
        assert e1.event_id == e2.event_id
