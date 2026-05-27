"""Sprint 10.5a T5 — SchedulerEngine orchestrator tests.

End-to-end coverage via a real SchedulerStorage backed by SQLite +
in-test stub conformers for the 4 _seams.py Protocols (QuotaInterrogator,
KillSwitchInterrogator, ParentBudgetResolver, PackStateInterrogator)
+ a stub policy callable.

Tests cover ALL 7 SchedulerAdmissionOutcome values from spec §4.2:
2 accepted (immediate, queued) + 5 refused (queue_full,
quota_exhausted, policy_denied, kill_switch_active,
pack_not_installed). Round-5 reviewer findings folded in:
PackStateInterrogator seam added, terminal counter decrement
verified, queued-task cancellation verified, queue rollback on
storage failure verified, admission_refused chain rows verified
per refusal path, quota release on refused_queue_full verified."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.scheduler import (
    AdmissionDecision,
    SubmitInput,
    TaskActor,
    TaskFailedPayload,
)
from cognic_agentos.core.scheduler._seams import (
    _NullParentBudgetResolver,
    _NullQuotaInterrogator,
)
from cognic_agentos.core.scheduler.engine import (
    PolicyDecision,
    SchedulerEngine,
    SchedulerPromotionRefused,
)
from cognic_agentos.core.scheduler.queue import ConcurrencyCaps
from cognic_agentos.core.scheduler.storage import (
    SchedulerStorage,
    _scheduler_tasks,
)

# --- Engine fixtures + stubs ---------------------------------------------


@pytest.fixture
async def engine_db(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    url = f"sqlite+aiosqlite:///{tmp_path / 'engine.db'}"
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
def caps() -> ConcurrencyCaps:
    return ConcurrencyCaps(
        per_tenant_interactive=2,
        per_tenant_background=4,
        per_pack=4,
        per_actor=4,
    )


@pytest.fixture
def class_settings() -> dict[str, tuple[int, float]]:
    # (max_depth, sla_s) per class
    return {
        "interactive": (2, 0.200),
        "background": (4, 5.0),
    }


class _StubQuotaInterrogator:
    """Test stub allowing controlled would_admit + release tracking."""

    def __init__(self, allow: bool = True) -> None:
        self.allow = allow
        self.reservations: list[uuid.UUID] = []
        self.releases: list[uuid.UUID] = []

    async def would_admit(
        self,
        *,
        task_id: uuid.UUID,
        tenant_id: str,
        pack_id: str,
        estimated_tokens: int,
    ) -> bool:
        if self.allow:
            self.reservations.append(task_id)
        return self.allow

    async def release_reservation(self, task_id: uuid.UUID) -> None:
        self.releases.append(task_id)


class _StubKillSwitchInterrogator:
    def __init__(self, active: bool = False) -> None:
        self.active = active
        self.calls: list[tuple[str, str]] = []

    async def is_active(self, *, tenant_id: str, pack_id: str) -> bool:
        self.calls.append((tenant_id, pack_id))
        return self.active


class _StubPackStateInterrogator:
    """Test stub for PackStateInterrogator. Default: pack always
    installed (so the round-5 reviewer-added refused_pack_not_installed
    check passes through happy-path tests). Set ``installed=False`` to
    exercise the refusal path."""

    def __init__(self, installed: bool = True) -> None:
        self.installed = installed
        self.calls: list[tuple[str, str]] = []

    async def is_installed(self, *, tenant_id: str, pack_id: str) -> bool:
        self.calls.append((tenant_id, pack_id))
        return self.installed


class _StubParentBudgetResolver:
    def __init__(self, budget: int = 1000) -> None:
        self.budget = budget
        self.calls: list[uuid.UUID] = []

    async def remaining_budget_for(self, parent_task_id: uuid.UUID) -> int:
        self.calls.append(parent_task_id)
        return self.budget


def _stub_policy_allow() -> Callable[[SubmitInput], Awaitable[PolicyDecision]]:
    async def _allow(_: SubmitInput) -> PolicyDecision:
        return PolicyDecision(allow=True, policy_reason=None)

    return _allow


def _stub_policy_deny(
    reason: str = "scheduler_high_risk_tier_refused_pre_13_5",
) -> Callable[[SubmitInput], Awaitable[PolicyDecision]]:
    async def _deny(_: SubmitInput) -> PolicyDecision:
        return PolicyDecision(allow=False, policy_reason=reason)

    return _deny


def _make_submit_input(
    tenant_id: str = "tenant-a",
    pack_id: str = "pack-x",
    actor_subject: str = "svc-a",
    class_: str = "interactive",
    parent_task_id: str | None = None,
    requested_tokens: int = 500,
) -> SubmitInput:
    return SubmitInput(
        tenant_id=tenant_id,
        pack_id=pack_id,
        actor=TaskActor(subject=actor_subject, tenant_id=tenant_id, actor_type="service"),
        class_=class_,  # type: ignore[arg-type]
        pack_kind="tool",
        pack_risk_tier="internal_write",
        requested_estimated_tokens=requested_tokens,
        parent_task_id=parent_task_id,
    )


def _make_engine(
    *,
    db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
    quota: Any = None,
    kill_switch: Any = None,
    parent_budget: Any = None,
    policy: Any = None,
    pack_state: Any = None,
) -> SchedulerEngine:
    return SchedulerEngine(
        storage=SchedulerStorage(db),
        caps=caps,
        class_settings=class_settings,  # type: ignore[arg-type]
        quota_interrogator=quota if quota is not None else _StubQuotaInterrogator(),
        kill_switch_interrogator=(
            kill_switch if kill_switch is not None else _StubKillSwitchInterrogator()
        ),
        parent_budget_resolver=(
            parent_budget if parent_budget is not None else _NullParentBudgetResolver()
        ),
        pack_state_interrogator=(
            pack_state if pack_state is not None else _StubPackStateInterrogator()
        ),
        policy_evaluator=policy if policy is not None else _stub_policy_allow(),
    )


# --- submit() admission outcomes ----------------------------------------


async def test_submit_returns_accepted_immediate_when_all_allow(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings)
    decision = await engine.submit(submit_input=_make_submit_input(), request_id="req-1")
    assert isinstance(decision, AdmissionDecision)
    assert decision.outcome == "accepted_immediate"
    assert decision.task_id is not None


async def test_submit_returns_accepted_queued_when_caps_saturated(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    """When per-tenant interactive cap (2) is saturated by 2
    in-flight tasks but the queue (max_depth=2) has room, the 3rd
    submission returns accepted_queued — NOT refused."""
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings)
    # Fill the interactive cap
    d1 = await engine.submit(submit_input=_make_submit_input(), request_id="req-1")
    d2 = await engine.submit(submit_input=_make_submit_input(), request_id="req-2")
    assert d1.outcome == "accepted_immediate"
    assert d2.outcome == "accepted_immediate"
    # Per-tenant interactive cap = 2; 3rd should queue (queue max_depth=2)
    d3 = await engine.submit(submit_input=_make_submit_input(), request_id="req-3")
    assert d3.outcome == "accepted_queued"
    assert d3.task_id is not None


async def test_submit_returns_refused_queue_full_when_queue_at_max(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    """When caps saturated AND queue is full, submit refuses with
    retry_after_s >= 1."""
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings)
    # Saturate cap (2) + fill queue (max_depth=2) = 4 submissions total
    for i in range(4):
        d = await engine.submit(submit_input=_make_submit_input(), request_id=f"req-{i}")
        assert d.outcome in ("accepted_immediate", "accepted_queued")
    # 5th submission: queue full
    refused = await engine.submit(submit_input=_make_submit_input(), request_id="req-5")
    assert refused.outcome == "refused_queue_full"
    assert refused.task_id is None
    assert refused.retry_after_s is not None
    assert refused.retry_after_s >= 1


async def test_submit_returns_refused_quota_exhausted_when_quota_denies(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    quota = _StubQuotaInterrogator(allow=False)
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings, quota=quota)
    decision = await engine.submit(submit_input=_make_submit_input(), request_id="req-1")
    assert decision.outcome == "refused_quota_exhausted"
    assert decision.task_id is None
    # No reservation made on False
    assert quota.reservations == []


async def test_submit_returns_refused_policy_denied_when_policy_denies(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    engine = _make_engine(
        db=engine_db,
        caps=caps,
        class_settings=class_settings,
        policy=_stub_policy_deny("scheduler_high_risk_tier_refused_pre_13_5"),
    )
    decision = await engine.submit(submit_input=_make_submit_input(), request_id="req-1")
    assert decision.outcome == "refused_policy_denied"
    # Internal policy_reason rides through (audit-payload-only; NOT in
    # wire-public SchedulerRefusalReason Literal)
    assert decision.policy_reason == "scheduler_high_risk_tier_refused_pre_13_5"


async def test_submit_returns_refused_kill_switch_active_when_switch_flipped(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    kill_switch = _StubKillSwitchInterrogator(active=True)
    engine = _make_engine(
        db=engine_db,
        caps=caps,
        class_settings=class_settings,
        kill_switch=kill_switch,
    )
    decision = await engine.submit(submit_input=_make_submit_input(), request_id="req-1")
    assert decision.outcome == "refused_kill_switch_active"
    assert decision.task_id is None


# --- Fail-loud sentinel propagation (production-grade rule) -----------


async def test_submit_propagates_NotImplementedError_from_NullQuotaInterrogator(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    """Default _NullQuotaInterrogator MUST raise NotImplementedError on
    submission — production-grade rule: no silent fallback."""
    engine = _make_engine(
        db=engine_db,
        caps=caps,
        class_settings=class_settings,
        quota=_NullQuotaInterrogator(),
    )
    with pytest.raises(NotImplementedError, match=r"Sprint 13\.5"):
        await engine.submit(submit_input=_make_submit_input(), request_id="req-1")


# --- Reservation-leak guard (round-4 P1 contract) ----------------------


async def test_submit_releases_quota_on_storage_failure_after_reservation(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    """Round-4 P1 plan contract: if would_admit succeeds (reserves)
    but subsequent storage work raises, submit MUST call
    release_reservation(task_id) before re-raising. Idempotent release
    means a later terminal-state release is safe."""
    quota = _StubQuotaInterrogator(allow=True)
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings, quota=quota)

    # Inject a storage that raises on submit. Wrap the real storage's
    # submit to raise after the would_admit reservation lands.
    original_submit = engine._storage.submit

    async def boom(**kwargs: Any) -> tuple[uuid.UUID, bytes]:
        raise RuntimeError("simulated storage outage")

    engine._storage.submit = boom  # type: ignore[method-assign]
    try:
        with pytest.raises(RuntimeError, match="simulated storage outage"):
            await engine.submit(submit_input=_make_submit_input(), request_id="req-1")
    finally:
        engine._storage.submit = original_submit  # type: ignore[method-assign]

    # would_admit reserved one task; release_reservation was called for the
    # same task_id before the exception propagated.
    assert len(quota.reservations) == 1
    assert len(quota.releases) == 1
    assert quota.reservations[0] == quota.releases[0]


# --- mark_running / complete / fail / cancel / preempt -----------------


async def test_mark_running_transitions_pending_to_running(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings)
    decision = await engine.submit(submit_input=_make_submit_input(), request_id="req-1")
    assert decision.task_id is not None
    await engine.mark_running(uuid.UUID(decision.task_id), request_id="req-start")
    # State should be running now
    state = await _read_state(engine_db, uuid.UUID(decision.task_id))
    assert state == "running"


async def test_complete_transitions_running_to_completed(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    quota = _StubQuotaInterrogator(allow=True)
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings, quota=quota)
    decision = await engine.submit(submit_input=_make_submit_input(), request_id="req-1")
    assert decision.task_id is not None
    task_id = uuid.UUID(decision.task_id)
    await engine.mark_running(task_id, request_id="req-start")
    await engine.complete(task_id, request_id="req-done")
    assert await _read_state(engine_db, task_id) == "completed"
    # Quota released on terminal state per spec §4.7
    assert task_id in quota.releases


async def test_fail_transitions_running_to_failed_with_payload(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings)
    decision = await engine.submit(submit_input=_make_submit_input(), request_id="req-1")
    assert decision.task_id is not None
    task_id = uuid.UUID(decision.task_id)
    await engine.mark_running(task_id, request_id="req-start")
    await engine.fail(
        task_id,
        request_id="req-fail",
        payload=TaskFailedPayload(
            reason="scheduler_task_failed_sandbox_create_refused",
            sandbox_refusal_reason="sandbox_credential_projection_field_set_mismatch",
            sandbox_event_id="evt-1",
        ),
    )
    assert await _read_state(engine_db, task_id) == "failed"


async def test_cancel_transitions_running_to_cancelled_with_actor_reason(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings)
    decision = await engine.submit(submit_input=_make_submit_input(), request_id="req-1")
    assert decision.task_id is not None
    task_id = uuid.UUID(decision.task_id)
    await engine.mark_running(task_id, request_id="req-start")
    actor = TaskActor(subject="admin", tenant_id="tenant-a", actor_type="human")
    await engine.cancel(
        task_id,
        actor=actor,
        reason="actor_cancelled",
        request_id="req-cancel",
    )
    assert await _read_state(engine_db, task_id) == "cancelled"


async def test_cancel_can_cancel_pending_task(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    """ADR-022 amendment: pending → cancelled (cancel-during-create)."""
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings)
    decision = await engine.submit(submit_input=_make_submit_input(), request_id="req-1")
    assert decision.task_id is not None
    task_id = uuid.UUID(decision.task_id)
    actor = TaskActor(subject="admin", tenant_id="tenant-a", actor_type="human")
    # Cancel WITHOUT calling mark_running first
    await engine.cancel(
        task_id,
        actor=actor,
        reason="actor_cancelled",
        request_id="req-cancel",
    )
    assert await _read_state(engine_db, task_id) == "cancelled"


async def test_preempt_transitions_running_to_preempted(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings)
    decision = await engine.submit(submit_input=_make_submit_input(), request_id="req-1")
    assert decision.task_id is not None
    task_id = uuid.UUID(decision.task_id)
    await engine.mark_running(task_id, request_id="req-start")
    await engine.preempt(task_id, request_id="req-preempt")
    assert await _read_state(engine_db, task_id) == "preempted"


# --- helpers -----------------------------------------------------------


async def _read_state(eng: AsyncEngine, task_id: uuid.UUID) -> str | None:
    from sqlalchemy import select

    async with eng.connect() as conn:
        row = (
            await conn.execute(
                select(_scheduler_tasks.c.state).where(_scheduler_tasks.c.task_id == task_id)
            )
        ).first()
        return None if row is None else str(row.state)


# --- Round-5 reviewer regression coverage --------------------------------


async def test_round5_p1_1_refused_queue_full_releases_quota_reservation(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    """Round-5 P1 #1 — after quota.would_admit reserves, if subsequent
    work returns refused_queue_full (no exception raised), the engine
    MUST release_reservation BEFORE returning the refusal."""
    quota = _StubQuotaInterrogator(allow=True)
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings, quota=quota)
    # Saturate caps + fill queue (max_depth=2) per existing tests
    for i in range(4):
        await engine.submit(submit_input=_make_submit_input(), request_id=f"req-{i}")
    # 5th: refused_queue_full
    refused = await engine.submit(submit_input=_make_submit_input(), request_id="req-5")
    assert refused.outcome == "refused_queue_full"
    # 4 admitted reservations + 1 reserved-then-released for the
    # refused_queue_full task
    assert len(quota.reservations) == 5
    assert len(quota.releases) == 1
    # The release is for the refused task (the one NOT in reservations
    # that ALSO appears in releases — actually all releases match a
    # reservation; the refused one is the 5th reservation)
    assert quota.reservations[4] == quota.releases[0]


async def test_round5_p1_2_terminal_transition_decrements_concurrency_counts(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    """Round-5 P1 #2 — after two interactive tasks complete, future
    submissions should see the per-tenant interactive cap as having
    headroom (count should decrement to 0). Pre-fix: counts only
    incremented, never decremented; capacity never reopened."""
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings)
    # Submit 2 (fills cap=2)
    d1 = await engine.submit(submit_input=_make_submit_input(), request_id="r1")
    d2 = await engine.submit(submit_input=_make_submit_input(), request_id="r2")
    assert d1.outcome == "accepted_immediate"
    assert d2.outcome == "accepted_immediate"
    # Complete both
    assert d1.task_id is not None
    assert d2.task_id is not None
    await engine.mark_running(uuid.UUID(d1.task_id), request_id="r1-start")
    await engine.mark_running(uuid.UUID(d2.task_id), request_id="r2-start")
    await engine.complete(uuid.UUID(d1.task_id), request_id="r1-done")
    await engine.complete(uuid.UUID(d2.task_id), request_id="r2-done")
    # Now a 3rd submission should be accepted_immediate (cap reopened)
    d3 = await engine.submit(submit_input=_make_submit_input(), request_id="r3")
    assert d3.outcome == "accepted_immediate", (
        f"Expected accepted_immediate after 2 completions; got {d3.outcome}. "
        "Counters likely not decrementing on terminal transition."
    )


async def test_round5_p1_3_cancel_of_queued_task_removes_from_queue(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    """Round-5 P1 #3 — queued tasks must be removed from the queue
    when cancelled, otherwise the queue slot is permanently consumed
    and future submissions falsely refuse with refused_queue_full."""
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings)
    # Saturate cap (2) so subsequent submits queue
    d1 = await engine.submit(submit_input=_make_submit_input(), request_id="r1")
    d2 = await engine.submit(submit_input=_make_submit_input(), request_id="r2")
    assert d1.outcome == "accepted_immediate"
    assert d2.outcome == "accepted_immediate"
    # Queue 2 (max_depth=2): both queued
    q1 = await engine.submit(submit_input=_make_submit_input(), request_id="q1")
    q2 = await engine.submit(submit_input=_make_submit_input(), request_id="q2")
    assert q1.outcome == "accepted_queued"
    assert q2.outcome == "accepted_queued"
    # Cancel one queued task
    assert q1.task_id is not None
    actor = TaskActor(subject="admin", tenant_id="tenant-a", actor_type="human")
    await engine.cancel(
        uuid.UUID(q1.task_id),
        actor=actor,
        reason="tenant_admin_cancelled",
        request_id="q1-cancel",
    )
    # A new submission should now successfully queue (queue slot opened)
    q3 = await engine.submit(submit_input=_make_submit_input(), request_id="q3")
    assert q3.outcome == "accepted_queued", (
        f"Expected accepted_queued after cancelling a queued task; got "
        f"{q3.outcome}. Queue likely not removing cancelled tasks."
    )


async def test_round5_p1_4_storage_failure_in_queued_path_rolls_back_queue(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    """Round-5 P1 #4 — if storage.submit raises after queue.enqueue
    succeeds, engine MUST remove the enqueued task_id so it doesn't
    permanently consume queue depth. Both quota release (round-4) AND
    queue removal (round-5) must fire."""
    quota = _StubQuotaInterrogator(allow=True)
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings, quota=quota)
    # Saturate caps so the next submit takes the queued path
    await engine.submit(submit_input=_make_submit_input(), request_id="r1")
    await engine.submit(submit_input=_make_submit_input(), request_id="r2")
    # Patch storage.submit to fail on the next call
    original_submit = engine._storage.submit
    call_count = {"n": 0}

    async def _maybe_fail(**kwargs: Any) -> tuple[uuid.UUID, bytes]:
        call_count["n"] += 1
        raise RuntimeError("simulated storage outage on queued path")

    engine._storage.submit = _maybe_fail  # type: ignore[method-assign]
    try:
        with pytest.raises(RuntimeError, match="simulated storage outage"):
            await engine.submit(submit_input=_make_submit_input(), request_id="q1-fails")
    finally:
        engine._storage.submit = original_submit  # type: ignore[method-assign]

    # Quota was reserved + released
    assert call_count["n"] == 1
    assert len(quota.releases) >= 1
    # Critical: queue must be empty (the failed enqueue was rolled
    # back). Verify by adding 2 more submissions; both should succeed
    # as accepted_queued (queue capacity=2, fully open after rollback).
    q1 = await engine.submit(submit_input=_make_submit_input(), request_id="q1")
    q2 = await engine.submit(submit_input=_make_submit_input(), request_id="q2")
    assert q1.outcome == "accepted_queued"
    assert q2.outcome == "accepted_queued"


async def test_round5_p1_5_all_refusal_paths_emit_admission_refused_chain_row(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    """Round-5 P1 #5 — every refusal path (kill-switch, policy, quota,
    queue-full, pack-not-installed) MUST emit a
    scheduler.admission_refused chain row carrying the closed-enum
    reason. Pre-fix: refusals returned only an AdmissionDecision to
    the caller without persisting any audit evidence."""
    from sqlalchemy import func, select

    from cognic_agentos.core.decision_history import _decision_history

    async def _count_refused_rows() -> int:
        async with engine_db.connect() as conn:
            return int(
                (
                    await conn.execute(
                        select(func.count(_decision_history.c.sequence)).where(
                            _decision_history.c.event_type == "scheduler.admission_refused"
                        )
                    )
                ).scalar_one()
            )

    # Reset by using a fresh DB for each refusal scenario would be
    # cleaner, but the count delta after each submit works too.

    # Scenario 1: kill switch
    engine = _make_engine(
        db=engine_db,
        caps=caps,
        class_settings=class_settings,
        kill_switch=_StubKillSwitchInterrogator(active=True),
    )
    pre = await _count_refused_rows()
    decision = await engine.submit(submit_input=_make_submit_input(), request_id="r-ks")
    assert decision.outcome == "refused_kill_switch_active"
    post = await _count_refused_rows()
    assert post == pre + 1, "kill_switch refusal did not emit admission_refused chain row"

    # Scenario 2: policy denied
    engine = _make_engine(
        db=engine_db,
        caps=caps,
        class_settings=class_settings,
        policy=_stub_policy_deny("scheduler_high_risk_tier_refused_pre_13_5"),
    )
    pre = await _count_refused_rows()
    decision = await engine.submit(submit_input=_make_submit_input(), request_id="r-pol")
    assert decision.outcome == "refused_policy_denied"
    post = await _count_refused_rows()
    assert post == pre + 1, "policy_denied refusal did not emit admission_refused chain row"

    # Scenario 3: quota exhausted
    engine = _make_engine(
        db=engine_db,
        caps=caps,
        class_settings=class_settings,
        quota=_StubQuotaInterrogator(allow=False),
    )
    pre = await _count_refused_rows()
    decision = await engine.submit(submit_input=_make_submit_input(), request_id="r-q")
    assert decision.outcome == "refused_quota_exhausted"
    post = await _count_refused_rows()
    assert post == pre + 1, "quota_exhausted refusal did not emit admission_refused chain row"

    # Scenario 4: pack not installed
    engine = _make_engine(
        db=engine_db,
        caps=caps,
        class_settings=class_settings,
        pack_state=_StubPackStateInterrogator(installed=False),
    )
    pre = await _count_refused_rows()
    decision = await engine.submit(submit_input=_make_submit_input(), request_id="r-pkg")
    assert decision.outcome == "refused_pack_not_installed"
    post = await _count_refused_rows()
    assert post == pre + 1, "pack_not_installed refusal did not emit admission_refused chain row"

    # Scenario 5: queue_full (saturate then overflow)
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings)
    for i in range(4):
        await engine.submit(submit_input=_make_submit_input(), request_id=f"r-{i}")
    pre = await _count_refused_rows()
    decision = await engine.submit(submit_input=_make_submit_input(), request_id="r-qf")
    assert decision.outcome == "refused_queue_full"
    post = await _count_refused_rows()
    assert post == pre + 1, "queue_full refusal did not emit admission_refused chain row"


async def test_round5_p2_6_refused_pack_not_installed_when_pack_state_false(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    """Round-5 P2 #6 — PackStateInterrogator seam now wired; engine
    returns the 5th wire-public refusal value when the seam reports
    pack not installed."""
    pack_state = _StubPackStateInterrogator(installed=False)
    engine = _make_engine(
        db=engine_db, caps=caps, class_settings=class_settings, pack_state=pack_state
    )
    decision = await engine.submit(submit_input=_make_submit_input(), request_id="r-pkg")
    assert decision.outcome == "refused_pack_not_installed"
    assert decision.task_id is None
    # Pack-state seam was actually consulted
    assert pack_state.calls == [("tenant-a", "pack-x")]


# --- Round-6 reviewer regression coverage --------------------------------


async def test_round6_p1_mark_running_promotes_queued_task_through_full_lifecycle(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    """Round-6 reviewer P1 — promotion path. A task admitted as
    accepted_queued must, on mark_running, be dequeued from the
    BoundedQueue + have its attribution migrated to _running_attribution
    + increment the matching concurrency counters BEFORE the
    pending → running storage transition. The round-5 mark_running
    silently skipped all of this.
    """
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings)
    # Saturate interactive cap (per_tenant_interactive=2), then queue 1
    immediate_a = await engine.submit(
        submit_input=_make_submit_input(actor_subject="svc-a1"), request_id="r-1"
    )
    immediate_b = await engine.submit(
        submit_input=_make_submit_input(actor_subject="svc-a2"), request_id="r-2"
    )
    assert immediate_a.outcome == "accepted_immediate"
    assert immediate_b.outcome == "accepted_immediate"
    # mark_running both so complete() can fire later (complete expects
    # from_state=running)
    await engine.mark_running(uuid.UUID(immediate_a.task_id), request_id="r-1-start")
    await engine.mark_running(uuid.UUID(immediate_b.task_id), request_id="r-2-start")
    # Now queue saturates → queued
    queued = await engine.submit(
        submit_input=_make_submit_input(actor_subject="svc-a3"), request_id="r-3"
    )
    assert queued.outcome == "accepted_queued"
    queued_id = uuid.UUID(queued.task_id)
    # Sanity: task is in the queue + queued_attribution before promotion
    queue = engine._queues[("tenant-a", "interactive")]
    assert queue.depth == 1
    assert queued_id in engine._queued_attribution
    assert queued_id not in engine._running_attribution
    # Free a slot
    await engine.complete(uuid.UUID(immediate_a.task_id), request_id="r-1-done")
    # Promote: mark_running on the queued task
    await engine.mark_running(queued_id, request_id="r-3-start")
    # Post-promotion invariants
    assert queue.depth == 0, "queued task was not removed from BoundedQueue"
    assert queued_id not in engine._queued_attribution
    assert queued_id in engine._running_attribution, "attribution was not migrated"
    # Counter incremented (was 1 after complete; now 2 again)
    assert engine._tenant_class_counts[("tenant-a", "interactive")] == 2
    # Storage state correctly transitioned
    state = await _read_state(engine_db, queued_id)
    assert state == "running"


async def test_round6_p1_mark_running_raises_when_caps_still_saturated(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    """Round-6 reviewer P1 — caps enforcement on promotion. If
    mark_running fires for a queued task while caps are still
    saturated (caller bug or race), the engine MUST raise
    SchedulerPromotionRefused rather than silently violate the caps
    contract. Task stays in the queue for the next retry.
    """
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings)
    a = await engine.submit(
        submit_input=_make_submit_input(actor_subject="svc-a1"), request_id="r-1"
    )
    b = await engine.submit(
        submit_input=_make_submit_input(actor_subject="svc-a2"), request_id="r-2"
    )
    queued = await engine.submit(
        submit_input=_make_submit_input(actor_subject="svc-a3"), request_id="r-3"
    )
    assert a.outcome == "accepted_immediate"
    assert b.outcome == "accepted_immediate"
    assert queued.outcome == "accepted_queued"
    queued_id = uuid.UUID(queued.task_id)
    # Caller bug: invoke mark_running BEFORE any terminal-state event
    with pytest.raises(SchedulerPromotionRefused):
        await engine.mark_running(queued_id, request_id="r-3-start")
    # Task remains queued — state still pending, queue still holds it
    queue = engine._queues[("tenant-a", "interactive")]
    assert queue.depth == 1
    assert queued_id in engine._queued_attribution
    assert queued_id not in engine._running_attribution
    # Counter unchanged
    assert engine._tenant_class_counts[("tenant-a", "interactive")] == 2
    state = await _read_state(engine_db, queued_id)
    assert state == "pending"


async def test_round6_p1_reap_expired_transitions_queued_to_expired_and_releases_quota(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    """Round-6 reviewer P1/P2 — reap_expired is the public seam the
    plan + spec listed but round-5 omitted, leaving pending → expired
    unreachable through the engine. Method MUST transition aged
    queued tasks pending → expired + release quota + remove from
    queue + emit scheduler.task_expired chain row.
    """
    quota = _StubQuotaInterrogator(allow=True)
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings, quota=quota)
    # Saturate caps + queue 1
    await engine.submit(submit_input=_make_submit_input(actor_subject="svc-a1"), request_id="r-1")
    await engine.submit(submit_input=_make_submit_input(actor_subject="svc-a2"), request_id="r-2")
    queued = await engine.submit(
        submit_input=_make_submit_input(actor_subject="svc-a3"), request_id="r-3"
    )
    assert queued.outcome == "accepted_queued"
    queued_id = uuid.UUID(queued.task_id)
    # Force the queued attribution's enqueued_at to far in the past so
    # reap_expired's age check fires deterministically.
    attribution = engine._queued_attribution[queued_id]
    aged = type(attribution)(
        tenant_id=attribution.tenant_id,
        class_=attribution.class_,
        pack_id=attribution.pack_id,
        actor_subject=attribution.actor_subject,
        enqueued_at=datetime(2000, 1, 1, tzinfo=UTC),
    )
    engine._queued_attribution[queued_id] = aged
    # Reap with a 5s TTL (task aged years past it)
    expired_count = await engine.reap_expired(
        queue_ttl_s_per_class={"interactive": 5.0, "background": 300.0},
        request_id="r-reap",
    )
    assert expired_count == 1
    # Storage state transitioned
    state = await _read_state(engine_db, queued_id)
    assert state == "expired"
    # Queue + attribution swept
    assert engine._queues[("tenant-a", "interactive")].depth == 0
    assert queued_id not in engine._queued_attribution
    # Quota released
    assert queued_id in quota.releases


async def test_round6_p1_reap_expired_ignores_tasks_under_ttl(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    """Round-6 reviewer P1 — only over-TTL tasks are reaped; fresh
    queued tasks are untouched."""
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings)
    await engine.submit(submit_input=_make_submit_input(actor_subject="svc-a1"), request_id="r-1")
    await engine.submit(submit_input=_make_submit_input(actor_subject="svc-a2"), request_id="r-2")
    queued = await engine.submit(
        submit_input=_make_submit_input(actor_subject="svc-a3"), request_id="r-3"
    )
    queued_id = uuid.UUID(queued.task_id)
    # Fresh queued task (enqueued_at is "now"); TTL 30 minutes — well above age
    expired_count = await engine.reap_expired(
        queue_ttl_s_per_class={"interactive": 1800.0, "background": 1800.0},
        request_id="r-reap",
    )
    assert expired_count == 0
    assert queued_id in engine._queued_attribution
    state = await _read_state(engine_db, queued_id)
    assert state == "pending"


# --- Round-7 reviewer regression coverage --------------------------------


async def test_round7_p1_submit_with_parent_task_id_raises_not_implemented(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    """Round-7 reviewer P1 — pre-Sprint-10.5b-T10, submitting with
    ``parent_task_id`` set MUST fail loud (NotImplementedError pointing
    at T10) rather than silently pass through without parent-budget
    narrowing. The round-6 patch removed the call to
    ``ParentBudgetResolver.remaining_budget_for`` (which previously
    fired the sentinel as a side effect), losing the fail-loud guard
    in the process. Round-7 restores it explicitly."""
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings)
    submit_input = _make_submit_input(parent_task_id="00000000-0000-0000-0000-000000000001")
    with pytest.raises(NotImplementedError, match="parent-budget narrowing not wired"):
        await engine.submit(submit_input=submit_input, request_id="req-child")


async def test_round7_p1_mark_running_refuses_when_not_at_queue_head(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    """Round-7 reviewer P1 — FIFO-within-class promotion contract.
    With two queued tasks q1 (older) and q2 (younger), promoting q2
    via mark_running MUST raise SchedulerPromotionRefused(reason=
    'not_at_queue_head') without mutating state. Only q1 is
    promotable until it transitions out."""
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings)
    # Saturate interactive cap (2)
    a = await engine.submit(
        submit_input=_make_submit_input(actor_subject="svc-a1"), request_id="r-1"
    )
    b = await engine.submit(
        submit_input=_make_submit_input(actor_subject="svc-a2"), request_id="r-2"
    )
    await engine.mark_running(uuid.UUID(a.task_id), request_id="r-1-start")
    await engine.mark_running(uuid.UUID(b.task_id), request_id="r-2-start")
    # Queue q1 then q2 (q1 is FIFO head)
    q1 = await engine.submit(
        submit_input=_make_submit_input(actor_subject="svc-a3"), request_id="r-3"
    )
    q2 = await engine.submit(
        submit_input=_make_submit_input(actor_subject="svc-a4"), request_id="r-4"
    )
    assert q1.outcome == "accepted_queued"
    assert q2.outcome == "accepted_queued"
    # Free a slot so caps-check would pass
    await engine.complete(uuid.UUID(a.task_id), request_id="r-1-done")
    q1_id = uuid.UUID(q1.task_id)
    q2_id = uuid.UUID(q2.task_id)
    # Attempt to promote q2 (out of order) — MUST raise
    with pytest.raises(SchedulerPromotionRefused) as exc_info:
        await engine.mark_running(q2_id, request_id="r-4-start")
    assert exc_info.value.reason == "not_at_queue_head"
    assert exc_info.value.task_id == q2_id
    # Q2 still queued; q1 still queued; no state mutation
    queue = engine._queues[("tenant-a", "interactive")]
    assert queue.depth == 2
    assert q1_id in engine._queued_attribution
    assert q2_id in engine._queued_attribution
    assert q2_id not in engine._running_attribution
    # State unchanged
    assert await _read_state(engine_db, q2_id) == "pending"
    # q1 promotion (head) succeeds
    await engine.mark_running(q1_id, request_id="r-3-start")
    assert queue.depth == 1
    assert q1_id in engine._running_attribution
    assert q2_id in engine._queued_attribution


async def test_round7_p1_promotion_refused_carries_caps_saturated_reason(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    """Round-7 reviewer P1 — caps-saturated path carries the
    distinguishing closed-enum reason value. Pins both refusal
    surfaces use the closed-enum vocabulary."""
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings)
    a = await engine.submit(
        submit_input=_make_submit_input(actor_subject="svc-a1"), request_id="r-1"
    )
    b = await engine.submit(
        submit_input=_make_submit_input(actor_subject="svc-a2"), request_id="r-2"
    )
    queued = await engine.submit(
        submit_input=_make_submit_input(actor_subject="svc-a3"), request_id="r-3"
    )
    assert a.outcome == "accepted_immediate"
    assert b.outcome == "accepted_immediate"
    assert queued.outcome == "accepted_queued"
    queued_id = uuid.UUID(queued.task_id)
    # Caps still saturated (immediate_a + b never completed)
    with pytest.raises(SchedulerPromotionRefused) as exc_info:
        await engine.mark_running(queued_id, request_id="r-3-start")
    assert exc_info.value.reason == "caps_saturated"
    assert exc_info.value.task_id == queued_id


async def test_round7_p2_mark_running_storage_failure_leaves_in_memory_state_unchanged(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    """Round-7 reviewer P2 — durable-first ordering. If
    storage.transition raises (DB unreachable, integrity error, etc),
    the in-memory bookkeeping MUST be untouched so engine state
    matches DB state — no need for rollback code because nothing was
    mutated. Round-6 reversed the order (bookkeeping first, then
    storage), leaving engine ahead of DB on failure."""
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings)
    a = await engine.submit(
        submit_input=_make_submit_input(actor_subject="svc-a1"), request_id="r-1"
    )
    b = await engine.submit(
        submit_input=_make_submit_input(actor_subject="svc-a2"), request_id="r-2"
    )
    await engine.mark_running(uuid.UUID(a.task_id), request_id="r-1-start")
    await engine.mark_running(uuid.UUID(b.task_id), request_id="r-2-start")
    q = await engine.submit(
        submit_input=_make_submit_input(actor_subject="svc-a3"), request_id="r-3"
    )
    assert q.outcome == "accepted_queued"
    queued_id = uuid.UUID(q.task_id)
    await engine.complete(uuid.UUID(a.task_id), request_id="r-1-done")
    # Pre-promotion state
    pre_running = set(engine._running_attribution.keys())
    pre_queued = set(engine._queued_attribution.keys())
    pre_tenant_class = engine._tenant_class_counts[("tenant-a", "interactive")]
    pre_queue_depth = engine._queues[("tenant-a", "interactive")].depth
    # Monkeypatch storage.transition to fail
    original_transition = engine._storage.transition

    async def _failing_transition(**kwargs: Any) -> Any:
        raise RuntimeError("simulated storage failure")

    engine._storage.transition = _failing_transition  # type: ignore[method-assign]
    try:
        with pytest.raises(RuntimeError, match="simulated storage failure"):
            await engine.mark_running(queued_id, request_id="r-3-start")
    finally:
        engine._storage.transition = original_transition  # type: ignore[method-assign]
    # In-memory state UNCHANGED on storage failure
    assert set(engine._running_attribution.keys()) == pre_running
    assert set(engine._queued_attribution.keys()) == pre_queued
    assert engine._tenant_class_counts[("tenant-a", "interactive")] == pre_tenant_class
    assert engine._queues[("tenant-a", "interactive")].depth == pre_queue_depth
    # Retry after restoring storage succeeds
    await engine.mark_running(queued_id, request_id="r-3-start-retry")
    assert queued_id in engine._running_attribution
    assert queued_id not in engine._queued_attribution


def test_round7_p1_promotion_refused_reason_vocabulary_in_lockstep_with_literal() -> None:
    """Round-7 drift detector — closed-enum vocabulary set MUST match
    the SchedulerPromotionRefusedReason Literal arms. Drift = wire-
    protocol-public regression for bank-overlay consumers reading
    the exception's ``reason`` attribute."""
    import typing as t_

    from cognic_agentos.core.scheduler.engine import (
        _VALID_PROMOTION_REFUSED_REASONS,
        SchedulerPromotionRefusedReason,
    )

    assert (
        frozenset(t_.get_args(SchedulerPromotionRefusedReason)) == _VALID_PROMOTION_REFUSED_REASONS
    )


# --- Z1a focused negative-path repair (gate-promotion coverage) ---------


async def test_z1a_reap_expired_skips_class_with_no_ttl_configured(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    """Z1a focused coverage — pin engine.py:595 ``continue`` branch
    (reap_expired with no TTL configured for a queued task's class).
    Without a TTL entry, the task is left in place per the per-class
    opt-in contract."""
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings)
    # Saturate interactive cap (2) so the third submit queues
    await engine.submit(submit_input=_make_submit_input(actor_subject="svc-a1"), request_id="r-1")
    await engine.submit(submit_input=_make_submit_input(actor_subject="svc-a2"), request_id="r-2")
    queued = await engine.submit(
        submit_input=_make_submit_input(actor_subject="svc-a3"), request_id="r-3"
    )
    assert queued.outcome == "accepted_queued"
    queued_id = uuid.UUID(queued.task_id)
    # Force enqueued_at to far in the past so age check would otherwise fire
    attribution = engine._queued_attribution[queued_id]
    aged = type(attribution)(
        tenant_id=attribution.tenant_id,
        class_=attribution.class_,
        pack_id=attribution.pack_id,
        actor_subject=attribution.actor_subject,
        enqueued_at=datetime(2000, 1, 1, tzinfo=UTC),
    )
    engine._queued_attribution[queued_id] = aged
    # Reap with ONLY background TTL configured — interactive class
    # (the queued task's class) has no entry → skip path fires
    expired_count = await engine.reap_expired(
        queue_ttl_s_per_class={"background": 5.0},
        request_id="r-reap",
    )
    assert expired_count == 0
    assert queued_id in engine._queued_attribution
    assert await _read_state(engine_db, queued_id) == "pending"


async def test_z1a_read_state_raises_scheduler_task_not_found_on_unknown_uuid(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    """Z1a focused coverage — pin engine.py:776-780 SchedulerTaskNotFound
    raise path. _read_state is called by fail() + cancel() to probe
    storage; an unknown task_id MUST raise the typed exception rather
    than crash with AttributeError on the None row."""
    from cognic_agentos.core.scheduler.storage import SchedulerTaskNotFound

    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings)
    bogus_id = uuid.uuid4()
    actor = TaskActor(subject="admin", tenant_id="tenant-a", actor_type="human")
    with pytest.raises(SchedulerTaskNotFound):
        await engine.cancel(
            bogus_id,
            actor=actor,
            reason="actor_cancelled",
            request_id="req-cancel",
        )
    with pytest.raises(SchedulerTaskNotFound):
        await engine.fail(
            bogus_id,
            payload=TaskFailedPayload(
                reason="scheduler_task_failed_sandbox_create_refused",
                sandbox_refusal_reason=None,
                sandbox_event_id=None,
            ),
            request_id="req-fail",
        )


# --- T9 seam-integration regressions (Option A doctrine — engine owns
# pack_state + kill_switch + quota; policy owns Rego only). ---------------


class _RaisingQuotaInterrogator:
    """T9 stub: would_admit raises if ever called. Used to prove
    upstream refusals (pack_state / kill_switch / policy) short-
    circuit BEFORE engine consults quota."""

    async def would_admit(self, **_: Any) -> bool:
        raise AssertionError(
            "would_admit must not be called when an upstream gate "
            "(pack_state / kill_switch / policy) has already refused"
        )

    async def release_reservation(self, task_id: uuid.UUID) -> None:
        # Allowed — release is idempotent per Protocol contract
        return None


class _RecordingPolicy:
    """T9 stub: records every evaluate() call so the kill-switch-
    beats-policy test can assert the policy was NEVER consulted when
    kill_switch fired first."""

    def __init__(self, allow: bool = True) -> None:
        self.allow = allow
        self.calls: list[SubmitInput] = []

    async def __call__(self, submit_input: SubmitInput) -> PolicyDecision:
        self.calls.append(submit_input)
        return PolicyDecision(
            allow=self.allow,
            policy_reason=None if self.allow else "scheduler_high_risk_tier_refused_pre_13_5",
        )


async def test_t9_kill_switch_short_circuits_before_policy_evaluator(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    """T9 ordering invariant (kill-switch beats policy): when
    kill_switch=True AND policy would also deny, the public outcome
    is refused_kill_switch_active AND the policy evaluator is
    NEVER consulted. Pins the engine's submit() pipeline order
    documented at engine.py:174 (Step 3 kill_switch BEFORE Step 4
    policy)."""
    recording_policy = _RecordingPolicy(allow=False)
    engine = _make_engine(
        db=engine_db,
        caps=caps,
        class_settings=class_settings,
        kill_switch=_StubKillSwitchInterrogator(active=True),
        policy=recording_policy,
    )
    decision = await engine.submit(submit_input=_make_submit_input(), request_id="req-1")
    assert decision.outcome == "refused_kill_switch_active"
    # Strict ordering: policy was NEVER called because kill_switch fired first
    assert recording_policy.calls == []


@pytest.mark.parametrize(
    "refusal_scenario,expected_outcome",
    [
        ("pack_not_installed", "refused_pack_not_installed"),
        ("kill_switch_active", "refused_kill_switch_active"),
        ("policy_denied", "refused_policy_denied"),
    ],
)
async def test_t9_upstream_refusals_never_call_quota_would_admit(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
    refusal_scenario: str,
    expected_outcome: str,
) -> None:
    """T9 invariant (1) + (2): upstream refusal gates (pack_state /
    kill_switch / policy) short-circuit BEFORE engine consults
    quota.would_admit. Pinning prevents future refactor from
    silently inverting the order — a quota call on an upstream-
    refused submission would be a phantom reservation."""
    quota = _RaisingQuotaInterrogator()
    kwargs: dict[str, Any] = {
        "db": engine_db,
        "caps": caps,
        "class_settings": class_settings,
        "quota": quota,
    }
    if refusal_scenario == "pack_not_installed":
        kwargs["pack_state"] = _StubPackStateInterrogator(installed=False)
    elif refusal_scenario == "kill_switch_active":
        kwargs["kill_switch"] = _StubKillSwitchInterrogator(active=True)
    elif refusal_scenario == "policy_denied":
        kwargs["policy"] = _stub_policy_deny()
    engine = _make_engine(**kwargs)
    decision = await engine.submit(submit_input=_make_submit_input(), request_id="r-t9")
    assert decision.outcome == expected_outcome
    # The _RaisingQuotaInterrogator would have raised if would_admit had been called


async def test_t9_complete_releases_quota_reservation_exactly_once(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    """T9 invariant (4): successful complete() terminal release
    fires exactly once. Mirrors test_complete_transitions_running_to_completed
    but tightens the assertion to exact call count."""
    quota = _StubQuotaInterrogator(allow=True)
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings, quota=quota)
    decision = await engine.submit(submit_input=_make_submit_input(), request_id="req-1")
    task_id = uuid.UUID(decision.task_id)
    await engine.mark_running(task_id, request_id="req-start")
    await engine.complete(task_id, request_id="req-done")
    assert quota.releases.count(task_id) == 1


async def test_t9_fail_releases_quota_reservation_exactly_once(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    """T9 invariant (4): fail() terminal release fires exactly once
    on the running → failed path."""
    quota = _StubQuotaInterrogator(allow=True)
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings, quota=quota)
    decision = await engine.submit(submit_input=_make_submit_input(), request_id="req-1")
    task_id = uuid.UUID(decision.task_id)
    await engine.mark_running(task_id, request_id="req-start")
    await engine.fail(
        task_id,
        request_id="req-fail",
        payload=TaskFailedPayload(
            reason="scheduler_task_failed_sandbox_create_refused",
            sandbox_refusal_reason=None,
            sandbox_event_id=None,
        ),
    )
    assert quota.releases.count(task_id) == 1


@pytest.mark.parametrize("from_state", ["pending", "running"])
async def test_t9_cancel_releases_quota_reservation_exactly_once(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
    from_state: str,
) -> None:
    """T9 invariant (4): cancel() terminal release fires exactly once
    on BOTH pending → cancelled (cancel-during-create per ADR-022
    amendment) AND running → cancelled (cooperative cancellation per
    spec §4.6) paths. Round-1 P2 reviewer fix — the original test
    only covered the pending path while its docstring claimed both;
    parametrize closes the gap."""
    quota = _StubQuotaInterrogator(allow=True)
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings, quota=quota)
    decision = await engine.submit(submit_input=_make_submit_input(), request_id="req-1")
    task_id = uuid.UUID(decision.task_id)
    if from_state == "running":
        # mark_running to advance to the running state before cancel
        await engine.mark_running(task_id, request_id="req-start")
    # Else: cancel from pending (no mark_running first)
    actor = TaskActor(subject="admin", tenant_id="tenant-a", actor_type="human")
    await engine.cancel(
        task_id,
        actor=actor,
        reason="actor_cancelled",
        request_id="req-cancel",
    )
    assert quota.releases.count(task_id) == 1
    # Sanity: terminal state reached
    assert await _read_state(engine_db, task_id) == "cancelled"


async def test_t9_preempt_releases_quota_reservation_exactly_once(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    """T9 invariant (4): preempt() terminal release fires exactly
    once on the running → preempted path."""
    quota = _StubQuotaInterrogator(allow=True)
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings, quota=quota)
    decision = await engine.submit(submit_input=_make_submit_input(), request_id="req-1")
    task_id = uuid.UUID(decision.task_id)
    await engine.mark_running(task_id, request_id="req-start")
    await engine.preempt(task_id, request_id="req-preempt")
    assert quota.releases.count(task_id) == 1


async def test_t9_invalid_second_terminal_attempt_does_not_release_twice(
    engine_db: AsyncEngine,
    caps: ConcurrencyCaps,
    class_settings: dict[str, tuple[int, float]],
) -> None:
    """T9 invariant (4) — refined per user-locked tweak #1: a second
    complete() on an already-completed task hits storage's invalid-
    state-transition path. _transition_terminal only releases AFTER
    successful storage transition, so the second invalid attempt
    MUST NOT mutate engine bookkeeping nor fire a second release.

    Pins that the round-7 P2 durable-first ordering contract extends
    to terminal transitions: bookkeeping (including release) gates on
    storage success."""
    quota = _StubQuotaInterrogator(allow=True)
    engine = _make_engine(db=engine_db, caps=caps, class_settings=class_settings, quota=quota)
    decision = await engine.submit(submit_input=_make_submit_input(), request_id="req-1")
    task_id = uuid.UUID(decision.task_id)
    await engine.mark_running(task_id, request_id="req-start")
    await engine.complete(task_id, request_id="req-done")
    # Snapshot post-first-complete state
    releases_before = list(quota.releases)
    tenant_count_before = engine._tenant_class_counts.get(("tenant-a", "interactive"), 0)
    pack_count_before = engine._pack_counts.get("pack-x", 0)
    actor_count_before = engine._actor_counts.get("svc-a", 0)
    running_attr_before = dict(engine._running_attribution)
    # Second complete — round-1 P2 fix: tighten the assertion from
    # `pytest.raises(Exception)` to the specific typed exception +
    # closed-enum reason. Without this, a bug that raised BEFORE the
    # storage state-machine guard (e.g. a KeyError in attribution
    # lookup) would silently pass the test.
    from cognic_agentos.core.scheduler._types import SchedulerTransitionRefused

    with pytest.raises(SchedulerTransitionRefused) as exc_info:
        await engine.complete(task_id, request_id="req-done-again")
    assert exc_info.value.reason == "scheduler_transition_invalid_state_pair"
    # No second release; no further bookkeeping mutation
    assert list(quota.releases) == releases_before
    assert engine._tenant_class_counts.get(("tenant-a", "interactive"), 0) == tenant_count_before
    assert engine._pack_counts.get("pack-x", 0) == pack_count_before
    assert engine._actor_counts.get("svc-a", 0) == actor_count_before
    assert engine._running_attribution == running_attr_before
