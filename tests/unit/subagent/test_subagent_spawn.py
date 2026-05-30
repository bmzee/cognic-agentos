"""Sprint 11b T6 — scheduler-mediated sub-agent spawn orchestrator.

The spawn flow runs through a REAL SchedulerEngine (submit -> mark_running ->
complete/preempt/fail) backed by the conftest `engine` (which created the
scheduler_tasks + decision_history schema), with injected allow-all conformers
+ a fake ChildRunner. 11b is test/DI-proven, NOT a production dispatch path
(memo D1).

Happy path + the negative paths: privilege-before-scheduler, depth escalation,
child over-budget preempt, runner-error fail, scheduler-inheritance narrowing."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import select

from cognic_agentos.core.escalation import EscalationStore
from cognic_agentos.core.scheduler._types import SubmitInput, TaskActor
from cognic_agentos.core.scheduler.engine import PolicyDecision, SchedulerEngine
from cognic_agentos.core.scheduler.queue import ConcurrencyCaps
from cognic_agentos.core.scheduler.storage import SchedulerStorage, _scheduler_tasks
from cognic_agentos.subagent._types import (
    ChildResult,
    ChildRunContext,
    ChildRunner,
    SubAgentChildQuotaZero,
    SubAgentDepthExceeded,
    SubAgentPrivilegeEscalation,
    SubAgentSpawnRequest,
)
from cognic_agentos.subagent.audit import SubAgentAuditEmitter
from cognic_agentos.subagent.audit_verifier import verify_subagent_linkage
from cognic_agentos.subagent.conformers import LocalParentBudgetResolver
from cognic_agentos.subagent.spawn import SubAgentSpawner


# --- minimal allow-all scheduler stub conformers (11b test/DI) -------------
class _AllowQuota:
    """Allow-all quota stub; records the (narrowed) estimated_tokens the
    scheduler passed, so the inheritance test can prove the scheduler narrowed."""

    def __init__(self) -> None:
        self.seen_tokens: list[int] = []

    async def would_admit(
        self, *, task_id: uuid.UUID, tenant_id: str, pack_id: str, estimated_tokens: int
    ) -> bool:
        self.seen_tokens.append(estimated_tokens)
        return True

    async def release_reservation(self, task_id: uuid.UUID) -> None:
        return None


class _InactiveKillSwitch:
    async def is_active(self, *, tenant_id: str, pack_id: str) -> bool:
        return False


class _InstalledPackState:
    async def is_installed(self, *, tenant_id: str, pack_id: str) -> bool:
        return True


class _NotInstalledPackState:
    """Forces a `refused_pack_not_installed` admission (decision.task_id is None)."""

    async def is_installed(self, *, tenant_id: str, pack_id: str) -> bool:
        return False


async def _policy_allow(_: SubmitInput) -> PolicyDecision:
    return PolicyDecision(allow=True, policy_reason=None)


class _FakeChildRunner:
    """Records every ChildRunContext it receives; returns a fixed ChildResult."""

    def __init__(self, result: ChildResult) -> None:
        self.result = result
        self.contexts: list[ChildRunContext] = []

    async def run(self, context: ChildRunContext) -> ChildResult:
        self.contexts.append(context)
        return self.result


class _RaisingChildRunner:
    """Always raises — exercises the runner-error -> scheduler.fail path."""

    def __init__(self) -> None:
        self.contexts: list[ChildRunContext] = []

    async def run(self, context: ChildRunContext) -> ChildResult:
        self.contexts.append(context)
        raise RuntimeError("child runner blew up")


@pytest.fixture
def spawn_harness(engine: Any, decision_store: Any) -> Any:
    """Factory: build a SubAgentSpawner over a REAL SchedulerEngine + a runner,
    all on the conftest `engine`. Returns (spawner, runner, quota, scheduler)."""

    def _build(
        *,
        child_result: ChildResult | None = None,
        runner: ChildRunner | None = None,
        parent_budget_snapshot: dict[uuid.UUID, int] | None = None,
        max_depth: int = 3,
        per_tenant_interactive: int = 4,
        pack_installed: bool = True,
    ) -> tuple[SubAgentSpawner, Any, _AllowQuota, SchedulerEngine]:
        snapshot = parent_budget_snapshot or {}
        quota = _AllowQuota()
        scheduler = SchedulerEngine(
            storage=SchedulerStorage(engine),
            caps=ConcurrencyCaps(
                per_tenant_interactive=per_tenant_interactive,
                per_tenant_background=4,
                per_pack=4,
                per_actor=4,
            ),
            class_settings={"interactive": (4, 0.5), "background": (4, 5.0)},
            quota_interrogator=quota,
            kill_switch_interrogator=_InactiveKillSwitch(),
            parent_budget_resolver=LocalParentBudgetResolver(snapshot),
            pack_state_interrogator=(
                _InstalledPackState() if pack_installed else _NotInstalledPackState()
            ),
            policy_evaluator=_policy_allow,
        )
        the_runner: Any = runner
        if the_runner is None:
            assert child_result is not None, "pass child_result or runner"
            the_runner = _FakeChildRunner(child_result)
        spawner = SubAgentSpawner(
            scheduler=scheduler,
            audit=SubAgentAuditEmitter(decision_store),
            child_runner=the_runner,
            escalation=EscalationStore(engine),
            parent_budget=LocalParentBudgetResolver(snapshot),
            max_recursion_depth=max_depth,
        )
        return spawner, the_runner, quota, scheduler

    return _build


def _request(**overrides: Any) -> SubAgentSpawnRequest:
    base: dict[str, Any] = {
        "prompt": "verify AML",
        "parent_tool_allow_list": frozenset({"aml_check", "read"}),
        "requested_tool_allow_list": frozenset({"aml_check"}),
        "current_depth": 0,
        "requested_estimated_tokens": 300,
        "tenant_id": "bank-a",
        "parent_task_id": None,
    }
    base.update(overrides)
    return SubAgentSpawnRequest(**base)


def _actor() -> TaskActor:
    return TaskActor(subject="orchestrator", tenant_id="bank-a", actor_type="service")


async def _spawn(spawner: SubAgentSpawner, **request_overrides: Any) -> Any:
    return await spawner.spawn(
        request=_request(**request_overrides),
        pack_id="cognic-tool-aml",
        actor=_actor(),
        class_="interactive",
        pack_kind="tool",
        pack_risk_tier="internal_write",
        parent_trace_id="ptrace",
    )


@pytest.mark.asyncio
async def test_happy_path_spawn_completes_and_chain_verifies(
    engine: Any, spawn_harness: Any, decision_store_rows: Any
) -> None:
    spawner, runner, _quota, _scheduler = spawn_harness(
        child_result=ChildResult(summary="ok", tokens_used=120, wall_time_used_s=0.3)
    )
    result = await _spawn(spawner)

    assert result.child_result.summary == "ok"
    assert result.preempted is False

    assert len(runner.contexts) == 1
    ctx = runner.contexts[0]
    assert ctx.granted_tools == frozenset({"aml_check"})
    assert ctx.budget == 300
    assert ctx.current_depth == 1
    assert ctx.parent_record_id == result.spawn_record_id

    rows = await decision_store_rows()
    subagent_rows = [r for r in rows if r.event_type.startswith("subagent.")]
    assert [r.event_type for r in subagent_rows] == [
        "subagent.spawn",
        "subagent.start",
        "subagent.return",
        "subagent.budget",
    ]
    ret = next(r for r in subagent_rows if r.event_type == "subagent.return")
    assert ret.payload["outcome"] == "completed"
    report = await verify_subagent_linkage(engine)
    assert report.is_clean is True
    assert report.records_checked == 3  # start + return + budget carry parent linkage


@pytest.mark.asyncio
async def test_privilege_escalation_blocks_before_scheduler(
    spawn_harness: Any, decision_store_rows: Any
) -> None:
    spawner, runner, _quota, _scheduler = spawn_harness(
        child_result=ChildResult(summary="x", tokens_used=0, wall_time_used_s=0.0)
    )
    with pytest.raises(SubAgentPrivilegeEscalation):
        # 'wire_transfer' is not in the parent allow-list {'aml_check', 'read'}
        await _spawn(spawner, requested_tool_allow_list=frozenset({"aml_check", "wire_transfer"}))
    # Policy gate raises BEFORE emit_spawn + scheduler.submit: zero rows, no child run.
    assert await decision_store_rows() == []
    assert runner.contexts == []


@pytest.mark.asyncio
async def test_depth_exceeded_escalates_and_blocks(
    spawn_harness: Any, decision_store_rows: Any
) -> None:
    spawner, runner, _quota, _scheduler = spawn_harness(
        child_result=ChildResult(summary="x", tokens_used=0, wall_time_used_s=0.0),
        max_depth=3,
    )
    with pytest.raises(SubAgentDepthExceeded):
        await _spawn(spawner, current_depth=3)  # child would be depth 4 > max 3
    rows = await decision_store_rows()
    # an escalation row was opened; NO subagent.spawn row (depth check precedes emit_spawn)
    assert any(r.event_type == "escalation.opened" for r in rows)
    assert not any(r.event_type.startswith("subagent.") for r in rows)
    assert runner.contexts == []


@pytest.mark.asyncio
async def test_child_over_budget_preempts_and_returns_failed(
    engine: Any, spawn_harness: Any, decision_store_rows: Any
) -> None:
    spawner, _runner, _quota, _scheduler = spawn_harness(
        child_result=ChildResult(summary="over", tokens_used=5000, wall_time_used_s=0.1)
    )
    result = await _spawn(spawner, requested_estimated_tokens=300)  # 5000 > 300 budget
    assert result.preempted is True
    rows = await decision_store_rows()
    ret = next(r for r in rows if r.event_type == "subagent.return")
    assert ret.payload["outcome"] == "failed"
    assert (await verify_subagent_linkage(engine)).is_clean is True


@pytest.mark.asyncio
async def test_runner_error_fails_task_and_emits_failed_return(
    engine: Any, spawn_harness: Any, decision_store_rows: Any
) -> None:
    spawner, _runner, _quota, _scheduler = spawn_harness(runner=_RaisingChildRunner())
    with pytest.raises(RuntimeError):
        await _spawn(spawner)
    rows = await decision_store_rows()
    ret = next(r for r in rows if r.event_type == "subagent.return")
    assert ret.payload["outcome"] == "failed"
    # the fail path emits no budget row (it re-raises before the budget emit)
    assert not any(r.event_type == "subagent.budget" for r in rows)
    assert (await verify_subagent_linkage(engine)).is_clean is True


@pytest.mark.asyncio
async def test_scheduler_inheritance_narrows_budget(spawn_harness: Any) -> None:
    parent_uuid = uuid.uuid4()
    spawner, runner, quota, _scheduler = spawn_harness(
        child_result=ChildResult(summary="ok", tokens_used=50, wall_time_used_s=0.1),
        parent_budget_snapshot={parent_uuid: 200},  # parent has 200 remaining
    )
    await _spawn(spawner, requested_estimated_tokens=300, parent_task_id=str(parent_uuid))
    # spawn.py narrowed the child budget to min(200, 300) = 200 for the ChildRunContext
    assert runner.contexts[0].budget == 200
    # the scheduler ALSO narrowed: quota saw 200, not the raw requested 300
    assert quota.seen_tokens == [200]


@pytest.mark.asyncio
async def test_accepted_queued_is_cancelled_not_run(
    engine: Any, spawn_harness: Any, decision_store_rows: Any
) -> None:
    """accepted_queued returns a valid task_id but the task is PENDING in the
    queue. The 11b seam (no queue worker) must NOT mark_running it — it cancels
    the queued task (no leaked pending row / reservation), emits a failed return,
    and returns ok=False. Forced by saturating the per-tenant interactive cap."""
    spawner, runner, _quota, scheduler = spawn_harness(
        child_result=ChildResult(summary="x", tokens_used=10, wall_time_used_s=0.0),
        per_tenant_interactive=1,
    )
    # Pre-saturate the cap (1) with a held running task for bank-a/interactive.
    pre = await scheduler.submit(
        submit_input=SubmitInput(
            tenant_id="bank-a",
            pack_id="filler",
            actor=_actor(),
            class_="interactive",
            pack_kind="tool",
            pack_risk_tier="internal_write",
            requested_estimated_tokens=10,
            parent_task_id=None,
        ),
        request_id="pre",
    )
    assert pre.outcome == "accepted_immediate"
    assert pre.task_id is not None
    await scheduler.mark_running(uuid.UUID(pre.task_id), request_id="pre")

    # The spawn's submit (2nd interactive for bank-a) is now cap-saturated with
    # queue room -> accepted_queued.
    result = await _spawn(spawner, requested_estimated_tokens=10)
    assert result.child_result.ok is False
    assert result.preempted is False
    assert runner.contexts == []  # child never ran

    rows = await decision_store_rows()
    ret = next(r for r in rows if r.event_type == "subagent.return")
    assert ret.payload["outcome"] == "failed"

    # The queued child was cancelled — no pending/queued row leaked; only the
    # pre-saturation task remains running.
    async with engine.begin() as conn:
        states = [r.state for r in (await conn.execute(select(_scheduler_tasks.c.state))).all()]
    assert "cancelled" in states
    assert "pending" not in states
    assert states.count("running") == 1


@pytest.mark.asyncio
async def test_refused_admission_returns_failed_and_runs_no_child(
    engine: Any, spawn_harness: Any, decision_store_rows: Any
) -> None:
    """A refused scheduler admission (here: pack not installed) returns a valid
    decision with task_id=None. spawn must emit a failed return + return ok=False
    WITHOUT mark_running / running the child — and leave NO scheduler_tasks row
    (a refused admission inserts none). Covers the refused branch (spawn.py:149)."""
    spawner, runner, _quota, _scheduler = spawn_harness(
        child_result=ChildResult(summary="x", tokens_used=10, wall_time_used_s=0.0),
        pack_installed=False,
    )
    result = await _spawn(spawner)
    assert result.child_result.ok is False
    assert result.preempted is False
    assert runner.contexts == []  # child never ran

    rows = await decision_store_rows()
    subagent_rows = [r for r in rows if r.event_type.startswith("subagent.")]
    # spawn root + failed return only — no start, no budget (child never ran).
    assert [r.event_type for r in subagent_rows] == ["subagent.spawn", "subagent.return"]
    ret = next(r for r in subagent_rows if r.event_type == "subagent.return")
    assert ret.payload["outcome"] == "failed"

    # A refused admission inserts NO scheduler_tasks row.
    async with engine.begin() as conn:
        task_rows = (await conn.execute(select(_scheduler_tasks.c.state))).all()
    assert task_rows == []
    # the failed return still carries parent linkage and verifies clean.
    assert (await verify_subagent_linkage(engine)).is_clean is True


@pytest.mark.asyncio
async def test_top_level_zero_quota_refuses_before_any_emit(
    spawn_harness: Any, decision_store_rows: Any
) -> None:
    """A top-level spawn (parent_task_id=None) with a zero pack quota is refused
    by _resolve_budget BEFORE emit_spawn / submit: SubAgentChildQuotaZero, and
    NO chain rows / no child run. Covers the top-level zero arm (spawn.py:76)."""
    spawner, runner, _quota, _scheduler = spawn_harness(
        child_result=ChildResult(summary="x", tokens_used=0, wall_time_used_s=0.0)
    )
    with pytest.raises(SubAgentChildQuotaZero):
        await _spawn(spawner, requested_estimated_tokens=0)
    assert await decision_store_rows() == []
    assert runner.contexts == []


@pytest.mark.asyncio
async def test_child_returns_not_ok_fails_not_preempts(
    engine: Any, spawn_harness: Any, decision_store_rows: Any
) -> None:
    """A child that RETURNS ok=False (without raising) WITHIN budget is a child
    FAILURE -> scheduler.fail (running -> failed), NOT a budget preemption. The
    result is not-preempted + not-ok; the scheduler task lands in 'failed'. This
    is the review P2.3 split: not-ok must not stamp the over-budget preempt
    reason. Covers the `elif not child.ok` branch (spawn.py)."""
    spawner, runner, _quota, _scheduler = spawn_harness(
        child_result=ChildResult(
            summary="soft fail", tokens_used=50, wall_time_used_s=0.1, ok=False
        )
    )
    result = await _spawn(spawner, requested_estimated_tokens=300)  # 50 < 300: within budget
    assert result.preempted is False  # a fail, NOT a preemption
    assert result.child_result.ok is False
    assert len(runner.contexts) == 1  # the child DID run

    rows = await decision_store_rows()
    subagent_rows = [r for r in rows if r.event_type.startswith("subagent.")]
    # child ran -> spawn, start, return, budget (the not-ok path still emits budget).
    assert [r.event_type for r in subagent_rows] == [
        "subagent.spawn",
        "subagent.start",
        "subagent.return",
        "subagent.budget",
    ]
    ret = next(r for r in subagent_rows if r.event_type == "subagent.return")
    assert ret.payload["outcome"] == "failed"

    # the scheduler task landed in 'failed' (NOT preempted, NOT completed).
    async with engine.begin() as conn:
        states = [r.state for r in (await conn.execute(select(_scheduler_tasks.c.state))).all()]
    assert states == ["failed"]
    assert (await verify_subagent_linkage(engine)).is_clean is True
