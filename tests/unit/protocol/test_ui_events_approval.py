"""M8.5-D D2 T10 — approval decision rows surface as typed UI events."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any, cast

import pydantic
import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import (
    AppendedDecisionSnapshot,
    DecisionHistoryStore,
    DecisionRecord,
)
from cognic_agentos.protocol.ui_events import (
    _DECISION_HISTORY_TYPED_PROJECTORS,
    _TYPED_PROJECTION_CLASSES,
    ApprovalDenied,
    ApprovalExecuted,
    ApprovalExpired,
    ApprovalGranted,
    ApprovalGrantedSecond,
    ApprovalGrantRecorded,
    ApprovalPending,
    UIEvent,
    UIEventEmitter,
    _DHReplaySnapshot,
    _project_typed_decision_history,
)

_APPROVAL_PROJECTORS = {
    "approval.requested": (ApprovalPending, "pending"),
    "approval.granted_first": (ApprovalGranted, "granted"),
    "approval.granted_second": (ApprovalGrantedSecond, "granted_second"),
    "approval.grant_recorded": (ApprovalGrantRecorded, "grant_recorded"),
    "approval.denied": (ApprovalDenied, "denied"),
    "approval.expired": (ApprovalExpired, "expired"),
    "approval.executed": (ApprovalExecuted, "executed"),
}


@pytest.fixture
async def engine(tmp_path: Any) -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'approval-ui.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id,
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=datetime.now(UTC),
                )
            )
    yield engine
    await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("decision_type", "event_cls", "event_type"),
    [
        (decision_type, event_cls, event_type)
        for decision_type, (event_cls, event_type) in _APPROVAL_PROJECTORS.items()
    ],
)
async def test_each_approval_transition_emits_exactly_one_typed_event(
    engine: AsyncEngine,
    decision_type: str,
    event_cls: type[Any],
    event_type: str,
) -> None:
    store = DecisionHistoryStore(engine)
    emitted: list[Any] = []

    async def collect(event: Any) -> None:
        emitted.append(event)

    emitter = UIEventEmitter(audit_store=AuditStore(engine), decision_history_store=store)
    emitter.register_hook(collect)
    payload = {"decision_index": 2, "required_count": 4}

    await store.append(
        DecisionRecord(
            decision_type=decision_type,
            request_id=f"approval-{uuid.uuid4()}",
            tenant_id="bank-a",
            payload=payload,
        )
    )

    approval_events = [event for event in emitted if event.family == "approval"]
    assert len(approval_events) == 1
    assert len(emitted) == 2  # one typed event plus one decision_audit mirror
    event = approval_events[0]
    assert isinstance(event, event_cls)
    assert event.type == event_type
    assert event.data == payload


@pytest.mark.parametrize(
    "event_cls,event_type",
    [(ApprovalGrantRecorded, "grant_recorded"), (ApprovalExecuted, "executed")],
)
def test_new_approval_models_discriminate_through_ui_event(
    event_cls: type[Any], event_type: str
) -> None:
    raw = event_cls(ts=datetime.now(UTC), audit_chain_hash="sha256:" + "00" * 32).model_dump()
    restored: Any = pydantic.TypeAdapter(UIEvent).validate_python(raw)
    assert type(restored) is event_cls
    assert restored.family == "approval"
    assert restored.type == event_type


def test_replay_projects_grant_progress_payload() -> None:
    payload = {"decision_index": 2, "required_count": 4, "approver_subject": "reviewer-2"}
    snapshot = _DHReplaySnapshot(
        sequence=17,
        decision_type="approval.grant_recorded",
        tenant_id="bank-a",
        trace_id="trace-17",
        request_id="approval-request-17",
        payload=payload,
        new_hash=b"\x17" * 32,
        chain_id="decision_history",
        created_at=datetime.now(UTC),
    )
    event = _project_typed_decision_history(cast(AppendedDecisionSnapshot, snapshot))
    assert isinstance(event, ApprovalGrantRecorded)
    assert event.data == payload


def test_consumed_is_deliberately_mirror_only() -> None:
    assert "approval.consumed" not in _DECISION_HISTORY_TYPED_PROJECTORS
    snapshot = _DHReplaySnapshot(
        sequence=18,
        decision_type="approval.consumed",
        tenant_id="bank-a",
        trace_id=None,
        request_id="approval-request-18",
        payload={"consumed_by": "executor"},
        new_hash=b"\x18" * 32,
        chain_id="decision_history",
        created_at=datetime.now(UTC),
    )
    assert _project_typed_decision_history(cast(AppendedDecisionSnapshot, snapshot)) is None


def test_approval_projector_registry_and_capture_membership_are_exact() -> None:
    assert {
        key: (projector.__name__, event_cls.__name__, event_type)
        for key, (event_cls, event_type) in _APPROVAL_PROJECTORS.items()
        for projector in (_DECISION_HISTORY_TYPED_PROJECTORS[key],)
    } == {
        "approval.requested": ("_project_approval_pending", "ApprovalPending", "pending"),
        "approval.granted_first": ("_project_approval_granted", "ApprovalGranted", "granted"),
        "approval.granted_second": (
            "_project_approval_granted_second",
            "ApprovalGrantedSecond",
            "granted_second",
        ),
        "approval.grant_recorded": (
            "_project_approval_grant_recorded",
            "ApprovalGrantRecorded",
            "grant_recorded",
        ),
        "approval.denied": ("_project_approval_denied", "ApprovalDenied", "denied"),
        "approval.expired": ("_project_approval_expired", "ApprovalExpired", "expired"),
        "approval.executed": ("_project_approval_executed", "ApprovalExecuted", "executed"),
    }
    assert {event_cls for event_cls, _ in _APPROVAL_PROJECTORS.values()} <= (
        _TYPED_PROJECTION_CLASSES
    )
