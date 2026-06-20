"""Sprint 10.5a T4 — SchedulerStorage (SQLite-aiosqlite test substrate).

Mirrors tests/unit/models/test_storage.py + tests/unit/packs/test_storage.py
patterns. Pins:
  - submit() inserts pending row + emits scheduler.admission_accepted
    chain row atomically (single transaction; rollback on failure)
  - transition() uses append_with_precondition with SELECT FOR UPDATE
    on the row, validates state-machine via validate_transition,
    UPDATEs state, emits scheduler.task_<terminal> chain row
  - SchedulerTransitionRefused from inside _precondition rolls back
    (no orphan UPDATE; no orphan chain row)
  - iso_controls derived via SCHEDULER_ISO_CONTROLS is stamped on
    every chain row (caller cannot override)
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import _decision_history
from cognic_agentos.core.scheduler import (
    SCHEDULER_ISO_CONTROLS,
    SchedulerTransitionRefused,
    SubmitInput,
    TaskActor,
)
from cognic_agentos.core.scheduler._types import SchedulerTaskState
from cognic_agentos.core.scheduler.storage import (
    SchedulerStorage,
    SchedulerTaskNotFound,
    _BudgetSnapshot,
    _build_budget_snapshot_stmt,
    _scheduler_tasks,
)


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    url = f"sqlite+aiosqlite:///{tmp_path / 'scheduler.db'}"
    eng: AsyncEngine = create_async_engine(url)
    async with eng.begin() as conn:
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
    yield eng
    await eng.dispose()


@pytest.fixture
async def store(engine: AsyncEngine) -> SchedulerStorage:
    return SchedulerStorage(engine)


def _make_submit_input(
    tenant_id: str = "tenant-acme",
    pack_id: str = "cognic-tool-loan-eligibility",
    class_: str = "interactive",
    risk_tier: str = "internal_write",
) -> SubmitInput:
    return SubmitInput(
        tenant_id=tenant_id,
        pack_id=pack_id,
        actor=TaskActor(subject="svc-loan-app", tenant_id=tenant_id, actor_type="service"),
        class_=class_,  # type: ignore[arg-type]
        pack_kind="tool",
        pack_risk_tier=risk_tier,
        requested_estimated_tokens=500,
    )


async def _count_chain_rows(eng: AsyncEngine) -> int:
    async with eng.connect() as conn:
        return int(
            (await conn.execute(select(func.count(_decision_history.c.sequence)))).scalar_one()
        )


async def _read_state(eng: AsyncEngine, task_id: uuid.UUID) -> str | None:
    async with eng.connect() as conn:
        row = (
            await conn.execute(
                select(_scheduler_tasks.c.state).where(_scheduler_tasks.c.task_id == task_id)
            )
        ).first()
        return None if row is None else str(row.state)


async def _read_latest_chain_row(eng: AsyncEngine) -> dict[str, object]:
    async with eng.connect() as conn:
        row = (
            await conn.execute(
                select(_decision_history).order_by(_decision_history.c.sequence.desc()).limit(1)
            )
        ).first()
        assert row is not None
        return dict(row._mapping)


# --- submit() (genesis path) ----------------------------------------------


async def test_submit_inserts_pending_row_and_genesis_chain_event(
    store: SchedulerStorage, engine: AsyncEngine
) -> None:
    task_id = uuid.uuid4()
    submit = _make_submit_input()
    await store.submit(task_id=task_id, submit_input=submit, request_id="req-test-abc")
    # Row inserted in pending state
    assert await _read_state(engine, task_id) == "pending"
    # Exactly one chain row emitted (scheduler.admission_accepted)
    assert await _count_chain_rows(engine) == 1
    chain_row = await _read_latest_chain_row(engine)
    assert chain_row["event_type"] == "scheduler.admission_accepted"
    assert chain_row["request_id"] == "req-test-abc"
    # iso_controls stamped from SCHEDULER_ISO_CONTROLS (caller cannot override)
    iso_controls = chain_row["iso_controls"]
    assert isinstance(iso_controls, list)
    assert tuple(iso_controls) == SCHEDULER_ISO_CONTROLS
    payload = chain_row["payload"]
    assert isinstance(payload, dict)
    assert payload["task_id"] == str(task_id)
    assert payload["tenant_id"] == "tenant-acme"
    assert payload["pack_id"] == "cognic-tool-loan-eligibility"
    assert payload["class_"] == "interactive"
    assert payload["pack_risk_tier"] == "internal_write"


async def test_submit_duplicate_task_id_refused_and_rolled_back(
    store: SchedulerStorage, engine: AsyncEngine
) -> None:
    task_id = uuid.uuid4()
    submit = _make_submit_input()
    await store.submit(task_id=task_id, submit_input=submit, request_id="req-test-1")
    # Second submit with same task_id raises PK violation; row + chain unchanged
    with pytest.raises(IntegrityError):
        await store.submit(task_id=task_id, submit_input=submit, request_id="req-test-2")
    # Still exactly one chain row + one row in scheduler_tasks
    assert await _count_chain_rows(engine) == 1


async def test_submit_records_approval_delegated_to_when_set(
    store: SchedulerStorage, engine: AsyncEngine
) -> None:
    import dataclasses

    task_id = uuid.uuid4()
    submit = dataclasses.replace(
        _make_submit_input(),
        pack_risk_tier="payment_action",
        approval_delegated_to="sandbox_admission",
    )
    await store.submit(task_id=task_id, submit_input=submit, request_id="req-a4a-1")
    payload = (await _read_latest_chain_row(engine))["payload"]
    assert isinstance(payload, dict)
    assert payload["approval_delegated_to"] == "sandbox_admission"
    assert payload["approval_verified"] is False  # honest: no fake grant
    assert "approval_request_id" not in payload  # no scheduler correlator


async def test_submit_omits_approval_delegated_to_when_none(
    store: SchedulerStorage, engine: AsyncEngine
) -> None:
    task_id = uuid.uuid4()
    await store.submit(task_id=task_id, submit_input=_make_submit_input(), request_id="req-a4a-2")
    payload = (await _read_latest_chain_row(engine))["payload"]
    assert isinstance(payload, dict)
    assert "approval_delegated_to" not in payload


# --- transition() (state-machine path) ------------------------------------


async def test_transition_pending_to_running_updates_state_and_emits_chain(
    store: SchedulerStorage, engine: AsyncEngine
) -> None:
    task_id = uuid.uuid4()
    await store.submit(
        task_id=task_id,
        submit_input=_make_submit_input(),
        request_id="req-test-submit",
    )
    await store.transition(
        task_id=task_id,
        from_state="pending",
        to_state="running",
        actor_id="scheduler-engine",
        request_id="req-test-start",
        payload_extras={},
    )
    assert await _read_state(engine, task_id) == "running"
    assert await _count_chain_rows(engine) == 2
    chain_row = await _read_latest_chain_row(engine)
    assert chain_row["event_type"] == "scheduler.task_started"
    iso_controls = chain_row["iso_controls"]
    assert isinstance(iso_controls, list)
    assert tuple(iso_controls) == SCHEDULER_ISO_CONTROLS


@pytest.mark.parametrize(
    "to_state,expected_decision_type",
    [
        ("completed", "scheduler.task_completed"),
        ("failed", "scheduler.task_failed"),
        ("cancelled", "scheduler.task_cancelled"),
        ("preempted", "scheduler.task_preempted"),
    ],
)
async def test_transition_from_running_to_terminal_states(
    store: SchedulerStorage,
    engine: AsyncEngine,
    to_state: str,
    expected_decision_type: str,
) -> None:
    task_id = uuid.uuid4()
    await store.submit(
        task_id=task_id,
        submit_input=_make_submit_input(),
        request_id="req-submit",
    )
    await store.transition(
        task_id=task_id,
        from_state="pending",
        to_state="running",
        actor_id="scheduler-engine",
        request_id="req-start",
        payload_extras={},
    )
    await store.transition(
        task_id=task_id,
        from_state="running",
        to_state=to_state,  # type: ignore[arg-type]
        actor_id="scheduler-engine",
        request_id=f"req-{to_state}",
        payload_extras={},
    )
    assert await _read_state(engine, task_id) == to_state
    chain_row = await _read_latest_chain_row(engine)
    assert chain_row["event_type"] == expected_decision_type


async def test_transition_pending_to_expired_emits_task_expired(
    store: SchedulerStorage, engine: AsyncEngine
) -> None:
    task_id = uuid.uuid4()
    await store.submit(
        task_id=task_id,
        submit_input=_make_submit_input(),
        request_id="req-submit",
    )
    await store.transition(
        task_id=task_id,
        from_state="pending",
        to_state="expired",
        actor_id="scheduler-reaper",
        request_id="req-reap",
        payload_extras={},
    )
    assert await _read_state(engine, task_id) == "expired"
    chain_row = await _read_latest_chain_row(engine)
    assert chain_row["event_type"] == "scheduler.task_expired"


async def test_transition_illegal_state_pair_refused_and_rolled_back(
    store: SchedulerStorage, engine: AsyncEngine
) -> None:
    task_id = uuid.uuid4()
    await store.submit(
        task_id=task_id,
        submit_input=_make_submit_input(),
        request_id="req-submit",
    )
    # Try pending → completed (illegal; pending cannot skip running)
    with pytest.raises(SchedulerTransitionRefused) as exc_info:
        await store.transition(
            task_id=task_id,
            from_state="pending",
            to_state="completed",
            actor_id="scheduler-engine",
            request_id="req-bad",
            payload_extras={},
        )
    assert exc_info.value.reason == "scheduler_transition_invalid_state_pair"
    # State unchanged (still pending) + chain has exactly 1 row (the submit)
    assert await _read_state(engine, task_id) == "pending"
    assert await _count_chain_rows(engine) == 1


@pytest.mark.parametrize(
    "to_state,expected_event_type",
    [
        ("failed", "scheduler.task_failed"),
        ("cancelled", "scheduler.task_cancelled"),
    ],
)
async def test_transition_pending_to_adr022_amendment_terminal_states(
    store: SchedulerStorage,
    engine: AsyncEngine,
    to_state: str,
    expected_event_type: str,
) -> None:
    """Round-4 reviewer P2 finding — T2 added two NEW ADR-022 amendment
    transitions (pending → failed for create/projection failure;
    pending → cancelled for cancel-during-create). T4 storage is where
    those transitions become persisted state + scheduler.task_<terminal>
    chain rows; pin both at the storage layer."""
    task_id = uuid.uuid4()
    await store.submit(
        task_id=task_id,
        submit_input=_make_submit_input(),
        request_id="req-submit",
    )
    await store.transition(
        task_id=task_id,
        from_state="pending",
        to_state=to_state,  # type: ignore[arg-type]
        actor_id="scheduler-engine",
        request_id=f"req-{to_state}",
        payload_extras={
            # Realistic shape: failed carries scheduler-side reason;
            # cancelled carries actor-driven reason.
            "reason": (
                "scheduler_task_failed_sandbox_create_refused"
                if to_state == "failed"
                else "actor_cancelled"
            ),
        },
    )
    assert await _read_state(engine, task_id) == to_state
    chain_row = await _read_latest_chain_row(engine)
    assert chain_row["event_type"] == expected_event_type
    payload = chain_row["payload"]
    assert isinstance(payload, dict)
    assert payload["from_state"] == "pending"
    assert payload["to_state"] == to_state
    # Per spec §4.4 amended: pending → terminal stamps terminal_at
    # (NOT started_at — task never reached running)
    assert payload["terminal_at"] is not None
    assert payload["started_at"] is None
    # Caller-supplied reason rides through payload_extras intact
    if to_state == "failed":
        assert payload["reason"] == "scheduler_task_failed_sandbox_create_refused"
    else:
        assert payload["reason"] == "actor_cancelled"


async def test_transition_payload_extras_reserved_key_overlap_refused(
    store: SchedulerStorage, engine: AsyncEngine
) -> None:
    """Round-4 reviewer P1 finding — caller-supplied payload_extras
    MUST NOT overlap with the 14 reserved evidence-snapshot keys
    storage builds from the row-locked task. Without the preflight
    guard, the **payload_extras merge would silently clobber
    canonical chain-payload fields, corrupting hash-chained evidence
    while row UPDATE + top-level DecisionRecord.tenant_id stayed
    correct — breaking the chain-payload-is-evidence-snapshot doctrine
    per [[feedback_chain_payload_is_evidence_snapshot]]."""
    task_id = uuid.uuid4()
    await store.submit(
        task_id=task_id,
        submit_input=_make_submit_input(),
        request_id="req-submit",
    )
    # Attempt to clobber canonical evidence fields via payload_extras
    with pytest.raises(ValueError) as exc_info:
        await store.transition(
            task_id=task_id,
            from_state="pending",
            to_state="running",
            actor_id="scheduler-engine",
            request_id="req-bad",
            payload_extras={
                "tenant_id": "tenant-impostor",
                "task_id": "other-uuid",
                "from_state": "running",  # try to lie about the source state
            },
        )
    # Message names the overlapping keys for examiner diagnosis
    msg = str(exc_info.value)
    assert "tenant_id" in msg
    assert "task_id" in msg
    assert "from_state" in msg
    # NO state mutation, NO chain row written (preflight runs before DB)
    assert await _read_state(engine, task_id) == "pending"
    assert await _count_chain_rows(engine) == 1  # only the original submit


@pytest.mark.parametrize(
    "single_overlap_key",
    [
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
    ],
)
async def test_transition_payload_extras_each_reserved_key_refused(
    store: SchedulerStorage, single_overlap_key: str
) -> None:
    """Per-key drift detector — every one of the 14 reserved keys MUST
    trip the preflight guard. If a future refactor adds a new evidence
    field to the snapshot without updating _RESERVED_TRANSITION_PAYLOAD_KEYS,
    this parametrize catches it as soon as the field is exercised."""
    task_id = uuid.uuid4()
    await store.submit(
        task_id=task_id,
        submit_input=_make_submit_input(),
        request_id="req-submit",
    )
    with pytest.raises(ValueError, match=single_overlap_key):
        await store.transition(
            task_id=task_id,
            from_state="pending",
            to_state="running",
            actor_id="scheduler-engine",
            request_id="req-bad",
            payload_extras={single_overlap_key: "anything"},
        )


async def test_transition_to_pending_preflight_refused_with_closed_enum(
    store: SchedulerStorage, engine: AsyncEngine
) -> None:
    """Round-3 reviewer P1 finding #1 — to_state='pending' is not in
    _STATE_TO_DECISION_TYPE. Without the preflight guard the indexed
    access would raise KeyError, leaking a non-closed-enum exception
    past the SchedulerTransitionRefused boundary that T5 SchedulerEngine
    catches on. Preflight guard mirrors packs/storage.py:839-840."""
    task_id = uuid.uuid4()
    await store.submit(
        task_id=task_id,
        submit_input=_make_submit_input(),
        request_id="req-submit",
    )
    # Reach 'running' so from_state="running" passes the row-lock check
    await store.transition(
        task_id=task_id,
        from_state="pending",
        to_state="running",
        actor_id="scheduler-engine",
        request_id="req-start",
        payload_extras={},
    )
    # Try running → pending (illegal pair AND pending not in event map).
    # to_state="pending" is a valid SchedulerTaskState Literal value, but
    # NOT a valid transition target — the preflight guard at the entry of
    # transition() catches it BEFORE the indexed _STATE_TO_DECISION_TYPE
    # lookup would have raised KeyError, mirroring packs/storage.py:839-840.
    with pytest.raises(SchedulerTransitionRefused) as exc_info:
        await store.transition(
            task_id=task_id,
            from_state="running",
            to_state="pending",
            actor_id="scheduler-engine",
            request_id="req-bad",
            payload_extras={},
        )
    assert exc_info.value.reason == "scheduler_transition_invalid_state_pair"
    # State still running; chain has 2 rows (admission + task_started)
    assert await _read_state(engine, task_id) == "running"
    assert await _count_chain_rows(engine) == 2


async def test_transition_chain_payload_carries_full_evidence_snapshot(
    store: SchedulerStorage, engine: AsyncEngine
) -> None:
    """Round-3 reviewer P1 finding #2 + [[feedback_chain_payload_is_evidence_snapshot]] —
    transition chain rows must carry the full task evidence snapshot
    (tenant_id, pack_id, actor_subject, class_, pack_kind, risk_tier,
    requested_estimated_tokens, parent_task_id, submitted_at,
    started_at, terminal_at) so examiners can replay the task from
    the chain alone without joining back to scheduler_tasks (mutable
    cache)."""
    task_id = uuid.uuid4()
    await store.submit(
        task_id=task_id,
        submit_input=_make_submit_input(
            tenant_id="tenant-evidence",
            pack_id="pack-evidence",
            risk_tier="read_only",
        ),
        request_id="req-submit",
    )
    await store.transition(
        task_id=task_id,
        from_state="pending",
        to_state="running",
        actor_id="scheduler-engine",
        request_id="req-start",
        payload_extras={},
    )
    chain_row = await _read_latest_chain_row(engine)
    payload = chain_row["payload"]
    assert isinstance(payload, dict)
    # Full evidence snapshot present:
    assert payload["task_id"] == str(task_id)
    assert payload["from_state"] == "pending"
    assert payload["to_state"] == "running"
    assert payload["tenant_id"] == "tenant-evidence"
    assert payload["pack_id"] == "pack-evidence"
    assert payload["actor_subject"] == "svc-loan-app"
    assert payload["class_"] == "interactive"
    assert payload["pack_kind"] == "tool"
    assert payload["pack_risk_tier"] == "read_only"
    assert payload["requested_estimated_tokens"] == 500
    assert payload["parent_task_id"] is None
    assert payload["submitted_at"] is not None  # ISO timestamp
    assert payload["started_at"] is not None  # just stamped by pending→running
    assert payload["terminal_at"] is None  # not yet terminal
    # Top-level tenant_id on the chain row (NOT just inside payload)
    assert chain_row["tenant_id"] == "tenant-evidence"


async def test_transition_unknown_task_id_raises_not_found(
    store: SchedulerStorage, engine: AsyncEngine
) -> None:
    bogus = uuid.uuid4()
    with pytest.raises(SchedulerTaskNotFound):
        await store.transition(
            task_id=bogus,
            from_state="pending",
            to_state="running",
            actor_id="scheduler-engine",
            request_id="req-bad",
            payload_extras={},
        )
    # No chain row written (we never even started a transition)
    assert await _count_chain_rows(engine) == 0


async def test_transition_with_from_state_mismatch_refused(
    store: SchedulerStorage, engine: AsyncEngine
) -> None:
    """Caller's from_state must match the locked row's actual state.
    Mismatch = stale read; refuse + rollback."""
    task_id = uuid.uuid4()
    await store.submit(
        task_id=task_id,
        submit_input=_make_submit_input(),
        request_id="req-submit",
    )
    # Row is "pending" but caller claims "running"; storage refuses
    with pytest.raises(SchedulerTransitionRefused) as exc_info:
        await store.transition(
            task_id=task_id,
            from_state="running",
            to_state="completed",
            actor_id="scheduler-engine",
            request_id="req-bad",
            payload_extras={},
        )
    assert exc_info.value.reason == "scheduler_transition_invalid_state_pair"
    assert await _read_state(engine, task_id) == "pending"


async def test_transition_payload_extras_threaded_into_chain_row(
    store: SchedulerStorage, engine: AsyncEngine
) -> None:
    """Per spec §4.2 + §4.9: task_failed payload carries
    sandbox_refusal_reason + sandbox_event_id for cross-layer correlation."""
    task_id = uuid.uuid4()
    await store.submit(
        task_id=task_id,
        submit_input=_make_submit_input(),
        request_id="req-submit",
    )
    await store.transition(
        task_id=task_id,
        from_state="pending",
        to_state="running",
        actor_id="scheduler-engine",
        request_id="req-start",
        payload_extras={},
    )
    await store.transition(
        task_id=task_id,
        from_state="running",
        to_state="failed",
        actor_id="scheduler-engine",
        request_id="req-fail",
        payload_extras={
            "reason": "scheduler_task_failed_sandbox_create_refused",
            "sandbox_refusal_reason": "sandbox_credential_projection_field_set_mismatch",
            "sandbox_event_id": "evt-abc-123",
        },
    )
    chain_row = await _read_latest_chain_row(engine)
    payload = chain_row["payload"]
    assert isinstance(payload, dict)
    assert payload["reason"] == "scheduler_task_failed_sandbox_create_refused"
    assert payload["sandbox_refusal_reason"] == "sandbox_credential_projection_field_set_mismatch"
    assert payload["sandbox_event_id"] == "evt-abc-123"


# --- Round-6 reviewer regression coverage --------------------------------


async def test_round6_record_admission_refused_accepts_each_closed_enum_value(
    store: SchedulerStorage,
    engine: AsyncEngine,
) -> None:
    """Round-6 reviewer P2 — every SchedulerRefusalReason Literal
    value must clear the runtime preflight guard."""
    valid_reasons = (
        "refused_queue_full",
        "refused_quota_exhausted",
        "refused_policy_denied",
        "refused_kill_switch_active",
        "refused_pack_not_installed",
    )
    pre = await _count_chain_rows(engine)
    for i, reason in enumerate(valid_reasons):
        await store.record_admission_refused(
            refused_task_id=uuid.uuid4(),
            submit_input=_make_submit_input(),
            reason=reason,  # type: ignore[arg-type]
            request_id=f"req-{i}",
        )
    post = await _count_chain_rows(engine)
    assert post == pre + len(valid_reasons)


async def test_round6_record_admission_refused_rejects_unknown_reason(
    store: SchedulerStorage,
    engine: AsyncEngine,
) -> None:
    """Round-6 reviewer P2 — the wire-public closed-enum guard rejects
    any value outside the 5-value SchedulerRefusalReason Literal
    BEFORE the chain row is persisted. Without this guard, a caller
    bug could smuggle a non-enum string into hash-chained evidence
    where downstream examiners + bank-overlay consumers would see an
    unrecognised refusal reason."""
    pre = await _count_chain_rows(engine)
    with pytest.raises(ValueError, match="scheduler_admission_refused_reason_not_in_closed_enum"):
        await store.record_admission_refused(
            refused_task_id=uuid.uuid4(),
            submit_input=_make_submit_input(),
            reason="refused_made_up_reason",  # type: ignore[arg-type]
            request_id="req-bogus",
        )
    # No chain row written
    post = await _count_chain_rows(engine)
    assert post == pre


# --- get_budget_snapshot (parent-budget resolver read seam) ---------------


async def _seed_task(
    store: SchedulerStorage, *, tenant_id: str, tokens: int, state: SchedulerTaskState
) -> uuid.UUID:
    """Seed a scheduler task in `state` via the real submit→transition path
    (NO raw INSERT). Terminal states follow _VALID_TRANSITIONS; `expired` goes
    directly from pending (running→expired is illegal), the others via running."""
    task_id = uuid.uuid4()
    submit = SubmitInput(
        tenant_id=tenant_id,
        pack_id="cognic-tool-loan-eligibility",
        actor=TaskActor(subject="svc", tenant_id=tenant_id, actor_type="service"),
        class_="interactive",
        pack_kind="tool",
        pack_risk_tier="internal_write",
        requested_estimated_tokens=tokens,
    )
    await store.submit(task_id=task_id, submit_input=submit, request_id=f"seed-{task_id}")
    if state == "pending":
        return task_id
    if state == "expired":
        # expired goes DIRECTLY from pending (running→expired is NOT in _VALID_TRANSITIONS).
        await store.transition(
            task_id=task_id,
            from_state="pending",
            to_state="expired",
            actor_id="seed",
            request_id=f"seed-expire-{task_id}",
            payload_extras={},
        )
        return task_id
    await store.transition(
        task_id=task_id,
        from_state="pending",
        to_state="running",
        actor_id="seed",
        request_id=f"seed-run-{task_id}",
        payload_extras={},
    )
    if state != "running":
        await store.transition(
            task_id=task_id,
            from_state="running",
            to_state=state,
            actor_id="seed",
            request_id=f"seed-term-{task_id}",
            payload_extras={},
        )
    return task_id


def test_budget_snapshot_stmt_where_carries_task_id_and_tenant_id() -> None:
    # SQL-shape regression: the PRODUCTION builder is used; both predicates present.
    compiled = str(_build_budget_snapshot_stmt(task_id=uuid.uuid4(), tenant_id="t"))
    assert "scheduler_tasks.task_id = " in compiled
    assert "scheduler_tasks.tenant_id = " in compiled


async def test_budget_snapshot_absent_returns_none(store: SchedulerStorage) -> None:
    assert await store.get_budget_snapshot(uuid.uuid4(), tenant_id="tenant-acme") is None


async def test_budget_snapshot_present_returns_tokens_and_state(store: SchedulerStorage) -> None:
    task_id = await _seed_task(store, tenant_id="tenant-acme", tokens=500, state="running")
    assert await store.get_budget_snapshot(task_id, tenant_id="tenant-acme") == _BudgetSnapshot(
        granted_tokens=500, state="running"
    )


async def test_budget_snapshot_cross_tenant_returns_none(store: SchedulerStorage) -> None:
    task_id = await _seed_task(store, tenant_id="tenant-b", tokens=500, state="running")
    # Same UUID, different tenant → invisible (the cross-tenant boundary).
    assert await store.get_budget_snapshot(task_id, tenant_id="tenant-a") is None
