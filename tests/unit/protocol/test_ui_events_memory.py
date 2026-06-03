"""Sprint 11.5c T6 — memory.* chain event typed-projector tests.

Verifies:
  - `memory.read` → MemoryRecallCompleted (family="memory", type="recall_completed")
  - `memory.forget` → MemoryForget (type="forget", data["purged"] is False)
  - `memory.regulator_erasure` → MemoryForget (type="forget", data["purged"] is True)
  - `memory.redact` → MemoryRedact (type="redact")
  - No-value invariant: "value" not in evt.data for all 4 projected events
  - For `memory.redact`: `redacted_value_digest` IS present (safe hash), no raw `value`
  - `event_id`, `ts`, `tenant`, `audit_chain_hash` are populated from the snapshot
  - Drift: all 4 memory.* decision_types are keys in _DECISION_HISTORY_TYPED_PROJECTORS
  - MemoryRecallStarted is NOT in _TYPED_PROJECTION_CLASSES (stays a model-only stub;
    `recall_started` has no chain row at recall-start)
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from cognic_agentos.core.decision_history import AppendedDecisionSnapshot
from cognic_agentos.protocol.ui_events import (
    _DECISION_HISTORY_TYPED_PROJECTORS,
    _TYPED_PROJECTION_CLASSES,
    MemoryForget,
    MemoryRecallCompleted,
    MemoryRecallStarted,
    MemoryRedact,
    _chain_derived_event_id,
    _project_typed_decision_history,
)

# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------


def _make_snapshot(
    *,
    decision_type: str,
    sequence: int = 77,
    payload: dict[str, Any] | None = None,
    tenant_id: str = "bank-a",
    trace_id: str = "trace-mem-1",
    request_id: str = "mem-req-test",
    new_hash: bytes = b"\xbb" * 32,
) -> AppendedDecisionSnapshot:
    """Build an AppendedDecisionSnapshot with fixed defaults suitable for
    memory projector dispatch tests. No DB I/O — projector functions are
    pure over snapshot inputs."""
    return AppendedDecisionSnapshot(
        record_id=uuid.UUID(int=1),
        chain_id="decision_history",
        sequence=sequence,
        new_hash=new_hash,
        created_at=datetime(2026, 6, 2, 12, 0, 0, tzinfo=UTC),
        decision_type=decision_type,
        request_id=request_id,
        payload=payload if payload is not None else {},
        tenant_id=tenant_id,
        trace_id=trace_id,
    )


# ---------------------------------------------------------------------------
# Representative value-free payloads (11.5a/11.5b invariant)
# ---------------------------------------------------------------------------

_RECALL_PAYLOAD: dict[str, Any] = {
    # Enumerate-shaped memory.read: post-T4.1 these are DURABLE-ONLY
    # (_ENUMERATE_TIERS = ("task", "long_term")); scratch never appears here.
    "op": "list_records",
    "tiers": ["task", "long_term"],
    "subject_ref": "agent:acme-advisor",
    "hit": True,
    "count": 3,
}

_FORGET_PAYLOAD: dict[str, Any] = {
    "record_id": "rec-abc",
    "reason": "user_request",
    "tenant_id": "bank-a",
    "agent_id": "acme-advisor",
}

_REGULATOR_ERASURE_PAYLOAD: dict[str, Any] = {
    "record_id": "rec-abc",
    "regulator_order_id": "order-123",
    "requester_scope": "regulator",
    "subject_id": "user-xyz",
    "actor_id": "regulator-bot",
    "tenant_id": "bank-a",
    "agent_id": "acme-advisor",
}

_REDACT_PAYLOAD: dict[str, Any] = {
    "record_id": "rec-def",
    "new_version_id": "rec-def-v2",
    "redaction_version": 2,
    "reason": "pii_correction",
    "tenant_id": "bank-a",
    "agent_id": "acme-advisor",
    "redacted_value_digest": "sha256:aabbcc",  # digest of NEW value — safe
}


# ---------------------------------------------------------------------------
# Test classes
# ---------------------------------------------------------------------------


class TestMemoryRecallCompleted:
    """memory.read → MemoryRecallCompleted."""

    def test_projects_to_memory_recall_completed(self) -> None:
        snap = _make_snapshot(decision_type="memory.read", payload=_RECALL_PAYLOAD)
        evt = _project_typed_decision_history(snap)
        assert isinstance(evt, MemoryRecallCompleted)

    def test_family_and_type(self) -> None:
        snap = _make_snapshot(decision_type="memory.read", payload=_RECALL_PAYLOAD)
        evt = _project_typed_decision_history(snap)
        assert isinstance(evt, MemoryRecallCompleted)
        assert evt.family == "memory"
        assert evt.type == "recall_completed"

    def test_snapshot_fields_propagated(self) -> None:
        snap = _make_snapshot(decision_type="memory.read", payload=_RECALL_PAYLOAD)
        evt = _project_typed_decision_history(snap)
        assert evt is not None
        assert evt.tenant == snap.tenant_id
        assert evt.ts == snap.created_at
        assert evt.trace_id == snap.trace_id

    def test_audit_chain_hash_populated(self) -> None:
        snap = _make_snapshot(decision_type="memory.read", payload=_RECALL_PAYLOAD)
        evt = _project_typed_decision_history(snap)
        assert evt is not None
        assert evt.audit_chain_hash.startswith("sha256:")

    def test_event_id_populated(self) -> None:
        snap = _make_snapshot(decision_type="memory.read", payload=_RECALL_PAYLOAD)
        evt = _project_typed_decision_history(snap)
        assert evt is not None
        assert evt.event_id.startswith("evt_")

    def test_event_id_matches_chain_derived(self) -> None:
        snap = _make_snapshot(decision_type="memory.read", sequence=10, payload=_RECALL_PAYLOAD)
        evt = _project_typed_decision_history(snap)
        expected_id = _chain_derived_event_id(
            chain_id="decision_history",
            sequence=10,
            ordinal=0,
            family="memory",
            type_="recall_completed",
        )
        assert evt is not None
        assert evt.event_id == expected_id

    def test_data_is_snapshot_payload(self) -> None:
        snap = _make_snapshot(decision_type="memory.read", payload=_RECALL_PAYLOAD)
        evt = _project_typed_decision_history(snap)
        assert evt is not None
        assert evt.data == _RECALL_PAYLOAD

    def test_no_value_in_data(self) -> None:
        """No-value invariant: recall payloads must never leak raw memory values."""
        snap = _make_snapshot(decision_type="memory.read", payload=_RECALL_PAYLOAD)
        evt = _project_typed_decision_history(snap)
        assert evt is not None
        assert "value" not in evt.data


class TestMemoryForget:
    """memory.forget → MemoryForget (purged=False)."""

    def test_projects_to_memory_forget(self) -> None:
        snap = _make_snapshot(decision_type="memory.forget", payload=_FORGET_PAYLOAD)
        evt = _project_typed_decision_history(snap)
        assert isinstance(evt, MemoryForget)

    def test_type_is_forget(self) -> None:
        snap = _make_snapshot(decision_type="memory.forget", payload=_FORGET_PAYLOAD)
        evt = _project_typed_decision_history(snap)
        assert isinstance(evt, MemoryForget)
        assert evt.type == "forget"

    def test_purged_is_false(self) -> None:
        """Tombstone (forget) sets purged=False to distinguish from physical erasure."""
        snap = _make_snapshot(decision_type="memory.forget", payload=_FORGET_PAYLOAD)
        evt = _project_typed_decision_history(snap)
        assert evt is not None
        assert evt.data["purged"] is False

    def test_snapshot_fields_propagated(self) -> None:
        snap = _make_snapshot(decision_type="memory.forget", payload=_FORGET_PAYLOAD)
        evt = _project_typed_decision_history(snap)
        assert evt is not None
        assert evt.tenant == snap.tenant_id
        assert evt.ts == snap.created_at
        assert evt.trace_id == snap.trace_id

    def test_audit_chain_hash_populated(self) -> None:
        snap = _make_snapshot(decision_type="memory.forget", payload=_FORGET_PAYLOAD)
        evt = _project_typed_decision_history(snap)
        assert evt is not None
        assert evt.audit_chain_hash.startswith("sha256:")

    def test_event_id_matches_chain_derived(self) -> None:
        snap = _make_snapshot(decision_type="memory.forget", sequence=20, payload=_FORGET_PAYLOAD)
        evt = _project_typed_decision_history(snap)
        expected_id = _chain_derived_event_id(
            chain_id="decision_history",
            sequence=20,
            ordinal=0,
            family="memory",
            type_="forget",
        )
        assert evt is not None
        assert evt.event_id == expected_id

    def test_payload_fields_present_in_data(self) -> None:
        snap = _make_snapshot(decision_type="memory.forget", payload=_FORGET_PAYLOAD)
        evt = _project_typed_decision_history(snap)
        assert evt is not None
        for key in _FORGET_PAYLOAD:
            assert key in evt.data

    def test_no_value_in_data(self) -> None:
        """No-value invariant: forget payloads must never leak raw memory values."""
        snap = _make_snapshot(decision_type="memory.forget", payload=_FORGET_PAYLOAD)
        evt = _project_typed_decision_history(snap)
        assert evt is not None
        assert "value" not in evt.data


class TestMemoryRegulatorErasure:
    """memory.regulator_erasure → MemoryForget (purged=True)."""

    def test_projects_to_memory_forget(self) -> None:
        snap = _make_snapshot(
            decision_type="memory.regulator_erasure", payload=_REGULATOR_ERASURE_PAYLOAD
        )
        evt = _project_typed_decision_history(snap)
        assert isinstance(evt, MemoryForget)

    def test_type_is_forget(self) -> None:
        snap = _make_snapshot(
            decision_type="memory.regulator_erasure", payload=_REGULATOR_ERASURE_PAYLOAD
        )
        evt = _project_typed_decision_history(snap)
        assert isinstance(evt, MemoryForget)
        assert evt.type == "forget"

    def test_purged_is_true(self) -> None:
        """Regulator erasure (physical purge) sets purged=True to distinguish from tombstone."""
        snap = _make_snapshot(
            decision_type="memory.regulator_erasure", payload=_REGULATOR_ERASURE_PAYLOAD
        )
        evt = _project_typed_decision_history(snap)
        assert evt is not None
        assert evt.data["purged"] is True

    def test_snapshot_fields_propagated(self) -> None:
        snap = _make_snapshot(
            decision_type="memory.regulator_erasure", payload=_REGULATOR_ERASURE_PAYLOAD
        )
        evt = _project_typed_decision_history(snap)
        assert evt is not None
        assert evt.tenant == snap.tenant_id
        assert evt.ts == snap.created_at
        assert evt.trace_id == snap.trace_id

    def test_audit_chain_hash_populated(self) -> None:
        snap = _make_snapshot(
            decision_type="memory.regulator_erasure", payload=_REGULATOR_ERASURE_PAYLOAD
        )
        evt = _project_typed_decision_history(snap)
        assert evt is not None
        assert evt.audit_chain_hash.startswith("sha256:")

    def test_event_id_matches_chain_derived(self) -> None:
        snap = _make_snapshot(
            decision_type="memory.regulator_erasure",
            sequence=30,
            payload=_REGULATOR_ERASURE_PAYLOAD,
        )
        evt = _project_typed_decision_history(snap)
        expected_id = _chain_derived_event_id(
            chain_id="decision_history",
            sequence=30,
            ordinal=0,
            family="memory",
            type_="forget",
        )
        assert evt is not None
        assert evt.event_id == expected_id

    def test_payload_fields_present_in_data(self) -> None:
        snap = _make_snapshot(
            decision_type="memory.regulator_erasure", payload=_REGULATOR_ERASURE_PAYLOAD
        )
        evt = _project_typed_decision_history(snap)
        assert evt is not None
        for key in _REGULATOR_ERASURE_PAYLOAD:
            assert key in evt.data

    def test_no_value_in_data(self) -> None:
        """No-value invariant: regulator erasure payloads must never leak raw memory values."""
        snap = _make_snapshot(
            decision_type="memory.regulator_erasure", payload=_REGULATOR_ERASURE_PAYLOAD
        )
        evt = _project_typed_decision_history(snap)
        assert evt is not None
        assert "value" not in evt.data

    def test_regulator_erasure_and_forget_use_same_model_different_purged(self) -> None:
        """Both forget and regulator_erasure collapse to MemoryForget.type=='forget';
        only data['purged'] distinguishes them — pin this explicitly."""
        forget_snap = _make_snapshot(decision_type="memory.forget", payload=_FORGET_PAYLOAD)
        erasure_snap = _make_snapshot(
            decision_type="memory.regulator_erasure", payload=_REGULATOR_ERASURE_PAYLOAD
        )
        forget_evt = _project_typed_decision_history(forget_snap)
        erasure_evt = _project_typed_decision_history(erasure_snap)
        assert isinstance(forget_evt, MemoryForget)
        assert isinstance(erasure_evt, MemoryForget)
        assert forget_evt.type == erasure_evt.type == "forget"
        assert forget_evt.data["purged"] is False
        assert erasure_evt.data["purged"] is True


class TestMemoryRedact:
    """memory.redact → MemoryRedact."""

    def test_projects_to_memory_redact(self) -> None:
        snap = _make_snapshot(decision_type="memory.redact", payload=_REDACT_PAYLOAD)
        evt = _project_typed_decision_history(snap)
        assert isinstance(evt, MemoryRedact)

    def test_family_and_type(self) -> None:
        snap = _make_snapshot(decision_type="memory.redact", payload=_REDACT_PAYLOAD)
        evt = _project_typed_decision_history(snap)
        assert isinstance(evt, MemoryRedact)
        assert evt.family == "memory"
        assert evt.type == "redact"

    def test_snapshot_fields_propagated(self) -> None:
        snap = _make_snapshot(decision_type="memory.redact", payload=_REDACT_PAYLOAD)
        evt = _project_typed_decision_history(snap)
        assert evt is not None
        assert evt.tenant == snap.tenant_id
        assert evt.ts == snap.created_at
        assert evt.trace_id == snap.trace_id

    def test_audit_chain_hash_populated(self) -> None:
        snap = _make_snapshot(decision_type="memory.redact", payload=_REDACT_PAYLOAD)
        evt = _project_typed_decision_history(snap)
        assert evt is not None
        assert evt.audit_chain_hash.startswith("sha256:")

    def test_event_id_matches_chain_derived(self) -> None:
        snap = _make_snapshot(decision_type="memory.redact", sequence=40, payload=_REDACT_PAYLOAD)
        evt = _project_typed_decision_history(snap)
        expected_id = _chain_derived_event_id(
            chain_id="decision_history",
            sequence=40,
            ordinal=0,
            family="memory",
            type_="redact",
        )
        assert evt is not None
        assert evt.event_id == expected_id

    def test_data_is_snapshot_payload(self) -> None:
        snap = _make_snapshot(decision_type="memory.redact", payload=_REDACT_PAYLOAD)
        evt = _project_typed_decision_history(snap)
        assert evt is not None
        assert evt.data == _REDACT_PAYLOAD

    def test_no_raw_value_in_data(self) -> None:
        """No-value invariant: redact payloads must carry only the digest — NOT the raw value."""
        snap = _make_snapshot(decision_type="memory.redact", payload=_REDACT_PAYLOAD)
        evt = _project_typed_decision_history(snap)
        assert evt is not None
        assert "value" not in evt.data

    def test_redacted_value_digest_is_present(self) -> None:
        """The digest of the NEW value IS present (safe — it is a sha256 hash,
        not the raw value). Pin explicitly so a future payload change that
        drops the digest is caught."""
        snap = _make_snapshot(decision_type="memory.redact", payload=_REDACT_PAYLOAD)
        evt = _project_typed_decision_history(snap)
        assert evt is not None
        assert "redacted_value_digest" in evt.data


# ---------------------------------------------------------------------------
# Drift detectors
# ---------------------------------------------------------------------------


class TestMemoryDecisionTypeDriftDetectors:
    """Drift detectors: pin that all 4 memory.* decision_types are wired
    into the dispatch table and that MemoryRecallStarted (stub-only, no
    chain row at recall-start) is excluded from _TYPED_PROJECTION_CLASSES."""

    def test_all_4_memory_decision_types_are_in_projectors_dict(self) -> None:
        """All 4 chain decision_types that map to memory UI events MUST
        appear as exact-match keys in _DECISION_HISTORY_TYPED_PROJECTORS.
        Drift here means a memory chain row silently falls through to
        mirror-only emission (no typed event) — a UI wire-protocol gap."""
        for dt in ("memory.read", "memory.forget", "memory.regulator_erasure", "memory.redact"):
            assert dt in _DECISION_HISTORY_TYPED_PROJECTORS, (
                f"{dt!r} missing from _DECISION_HISTORY_TYPED_PROJECTORS; "
                "memory typed events would not be emitted for this chain row type"
            )

    def test_memory_recall_started_not_in_typed_projection_classes(self) -> None:
        """MemoryRecallStarted stays a schema-only stub — there is no chain row
        at recall-START (only at recall-COMPLETE). Pinned so a future wiring
        attempt is explicit and deliberate rather than silently included."""
        assert MemoryRecallStarted not in _TYPED_PROJECTION_CLASSES, (
            "MemoryRecallStarted is in _TYPED_PROJECTION_CLASSES but has no "
            "projector or chain row; this is a wiring error"
        )

    @pytest.mark.parametrize(
        "decision_type,expected_class",
        [
            ("memory.read", MemoryRecallCompleted),
            ("memory.forget", MemoryForget),
            ("memory.regulator_erasure", MemoryForget),
            ("memory.redact", MemoryRedact),
        ],
    )
    def test_projected_class_matches_expected(
        self, decision_type: str, expected_class: type
    ) -> None:
        """Round-trip: each decision_type projects to exactly the expected class."""
        snap = _make_snapshot(decision_type=decision_type, payload={"k": "v"})
        evt = _project_typed_decision_history(snap)
        assert isinstance(evt, expected_class), (
            f"{decision_type!r} → expected {expected_class.__name__}, got {type(evt).__name__}"
        )

    def test_memory_wired_classes_in_typed_projection_classes(self) -> None:
        """MemoryRecallCompleted, MemoryForget, MemoryRedact MUST be in
        _TYPED_PROJECTION_CLASSES so the ContextVar capture fires for these
        events during broker.append* calls."""
        for cls in (MemoryRecallCompleted, MemoryForget, MemoryRedact):
            assert cls in _TYPED_PROJECTION_CLASSES, (
                f"{cls.__name__} missing from _TYPED_PROJECTION_CLASSES; "
                "the ContextVar capture would NOT fire for this event type"
            )
