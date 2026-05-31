"""Sprint 11b T7 — SubAgent facade (thin public delegation over T6's
SubAgentSpawner). These tests prove the facade is FAITHFUL delegation:

- end-to-end it preserves the full T6 contract (one spawn over a REAL
  SchedulerEngine on the conftest engine emits the four parent-chain rows,
  hands the runner the narrowed ChildRunContext, and verifies clean);
- depth + privilege refusals propagate unchanged (delegated, not re-raised);
- it reads ``Settings.subagent_max_recursion_depth`` rather than hardcoding 3;
- it maps every invoke field onto the SubAgentSpawnRequest + routing kwargs
  with no drop / rename / reinterpretation.

The facade adds NO lifecycle / policy / budget logic of its own — that all
lives in spawn.py / policy.py (memo D1: test/DI-proven, not a production
dispatch path). The stub conformers below are re-declared INLINE (NOT imported
from test_subagent_spawn.py) to keep this file self-contained."""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from cognic_agentos.core.config import Settings
from cognic_agentos.core.escalation import EscalationStore
from cognic_agentos.core.scheduler._types import SubmitInput, TaskActor
from cognic_agentos.core.scheduler.engine import PolicyDecision, SchedulerEngine
from cognic_agentos.core.scheduler.queue import ConcurrencyCaps
from cognic_agentos.core.scheduler.storage import SchedulerStorage
from cognic_agentos.subagent import SubAgent
from cognic_agentos.subagent._types import (
    ChildResult,
    ChildRunContext,
    SubAgentDepthExceeded,
    SubAgentPrivilegeEscalation,
    SubAgentResult,
    SubAgentSpawnRequest,
)
from cognic_agentos.subagent.audit import SubAgentAuditEmitter
from cognic_agentos.subagent.audit_verifier import verify_subagent_linkage
from cognic_agentos.subagent.conformers import LocalParentBudgetResolver


# --- minimal allow-all scheduler stub conformers (11b test/DI) -------------
class _AllowQuota:
    async def would_admit(
        self, *, task_id: uuid.UUID, tenant_id: str, pack_id: str, estimated_tokens: int
    ) -> bool:
        return True

    async def release_reservation(self, task_id: uuid.UUID) -> None:
        return None


class _InactiveKillSwitch:
    async def is_active(self, *, tenant_id: str, pack_id: str) -> bool:
        return False


class _InstalledPackState:
    async def is_installed(self, *, tenant_id: str, pack_id: str) -> bool:
        return True


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


def _actor() -> TaskActor:
    return TaskActor(subject="orchestrator", tenant_id="bank-a", actor_type="service")


def _scheduler(engine: Any, *, per_tenant_interactive: int = 4) -> SchedulerEngine:
    """A REAL SchedulerEngine on the conftest engine + allow-all conformers."""
    return SchedulerEngine(
        storage=SchedulerStorage(engine),
        caps=ConcurrencyCaps(
            per_tenant_interactive=per_tenant_interactive,
            per_tenant_background=4,
            per_pack=4,
            per_actor=4,
        ),
        class_settings={"interactive": (4, 0.5), "background": (4, 5.0)},
        quota_interrogator=_AllowQuota(),
        kill_switch_interrogator=_InactiveKillSwitch(),
        parent_budget_resolver=LocalParentBudgetResolver({}),
        pack_state_interrogator=_InstalledPackState(),
        policy_evaluator=_policy_allow,
    )


def _subagent(
    engine: Any,
    decision_store: Any,
    *,
    runner: _FakeChildRunner,
    settings: Settings,
    parent_budget_snapshot: dict[uuid.UUID, int] | None = None,
) -> SubAgent:
    """Build a SubAgent facade over a REAL SchedulerEngine + a fake runner."""
    return SubAgent(
        scheduler=_scheduler(engine),
        audit=SubAgentAuditEmitter(decision_store),
        child_runner=runner,
        escalation=EscalationStore(engine),
        parent_budget=LocalParentBudgetResolver(parent_budget_snapshot or {}),
        settings=settings,
    )


async def _invoke(sub: SubAgent, **overrides: Any) -> Any:
    """Drive SubAgent.invoke with the canonical happy-path args + overrides."""
    kwargs: dict[str, Any] = {
        "parent_tool_allow_list": frozenset({"aml_check", "read"}),
        "requested_tool_allow_list": frozenset({"aml_check"}),
        "current_depth": 0,
        "requested_estimated_tokens": 300,
        "tenant_id": "bank-a",
        "pack_id": "cognic-tool-aml",
        "actor": _actor(),
        "class_": "interactive",
        "pack_kind": "tool",
        "pack_risk_tier": "internal_write",
        "parent_trace_id": "ptrace",
        "parent_task_id": None,
    }
    prompt = overrides.pop("prompt", "verify AML")
    kwargs.update(overrides)
    return await sub.invoke(prompt, **kwargs)


@pytest.mark.asyncio
async def test_invoke_delegates_and_returns_child_result(
    engine: Any, decision_store: Any, decision_store_rows: Any
) -> None:
    """The facade preserves the full T6 contract end-to-end: it returns the
    child result, hands the runner exactly one narrowed ChildRunContext, emits
    the four parent-chain rows in order, and verifies clean."""
    runner = _FakeChildRunner(ChildResult(summary="ok", tokens_used=120, wall_time_used_s=0.3))
    sub = _subagent(engine, decision_store, runner=runner, settings=Settings())

    result = await _invoke(sub)

    assert isinstance(result, SubAgentResult)
    assert result.child_result.summary == "ok"
    assert result.preempted is False

    assert len(runner.contexts) == 1
    ctx = runner.contexts[0]
    assert ctx.granted_tools == frozenset({"aml_check"})
    assert ctx.budget == 300
    assert ctx.current_depth == 1  # parent depth 0 -> child depth 1

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


@pytest.mark.asyncio
async def test_invoke_propagates_privilege_escalation(
    engine: Any, decision_store: Any, decision_store_rows: Any
) -> None:
    """A requested allow-list not ⊆ the parent's raises
    SubAgentPrivilegeEscalation (delegated, unchanged) BEFORE any emit/run."""
    runner = _FakeChildRunner(ChildResult(summary="x", tokens_used=0, wall_time_used_s=0.0))
    sub = _subagent(engine, decision_store, runner=runner, settings=Settings())

    with pytest.raises(SubAgentPrivilegeEscalation):
        await _invoke(sub, requested_tool_allow_list=frozenset({"aml_check", "wire_transfer"}))
    # delegated refusal short-circuits before emit: no rows, no child run.
    assert await decision_store_rows() == []
    assert runner.contexts == []


@pytest.mark.asyncio
async def test_invoke_propagates_depth_exceeded(engine: Any, decision_store: Any) -> None:
    """current_depth=3 under a max of 3 makes the child depth 4 > 3 ->
    SubAgentDepthExceeded propagates from the delegated spawn."""
    runner = _FakeChildRunner(ChildResult(summary="x", tokens_used=0, wall_time_used_s=0.0))
    sub = _subagent(
        engine,
        decision_store,
        runner=runner,
        settings=Settings(subagent_max_recursion_depth=3),
    )

    with pytest.raises(SubAgentDepthExceeded):
        await _invoke(sub, current_depth=3)
    assert runner.contexts == []


@pytest.mark.asyncio
async def test_facade_reads_settings_max_recursion_depth(engine: Any, decision_store: Any) -> None:
    """The facade threads Settings.subagent_max_recursion_depth into the
    spawner: with a cap of 2, current_depth=2 makes the child depth 3 > 2 ->
    refused. (This would NOT refuse if the facade hardcoded 3.)"""
    runner = _FakeChildRunner(ChildResult(summary="x", tokens_used=0, wall_time_used_s=0.0))
    sub = _subagent(
        engine,
        decision_store,
        runner=runner,
        settings=Settings(subagent_max_recursion_depth=2),
    )

    with pytest.raises(SubAgentDepthExceeded):
        await _invoke(sub, current_depth=2)
    assert runner.contexts == []


@pytest.mark.asyncio
async def test_invoke_maps_request_and_routing_args_exactly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pins that the facade maps every invoke field onto the spawner with no
    drop / rename / reinterpretation: a recording fake SubAgentSpawner captures
    its construction kwargs + spawn kwargs; the facade must read the settings
    depth (7) and thread the five deps + every request + routing field."""
    sentinel = SubAgentResult(
        spawn_record_id=uuid.uuid4(),
        child_result=ChildResult(summary="sentinel", tokens_used=1, wall_time_used_s=0.0),
    )

    class _RecordingSpawner:
        def __init__(self, **kwargs: Any) -> None:
            self.init_kwargs = kwargs

        async def spawn(self, **kwargs: Any) -> SubAgentResult:
            self.spawn_kwargs = kwargs
            return sentinel

    import cognic_agentos.subagent._facade as facade_mod

    monkeypatch.setattr(facade_mod, "SubAgentSpawner", _RecordingSpawner)

    audit = object()
    runner = object()
    escalation = object()
    parent_budget = object()
    actor = _actor()

    sub = SubAgent(
        scheduler="sched-sentinel",  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        child_runner=runner,  # type: ignore[arg-type]
        escalation=escalation,  # type: ignore[arg-type]
        parent_budget=parent_budget,  # type: ignore[arg-type]
        settings=Settings(subagent_max_recursion_depth=7),
    )

    spawner = sub._spawner
    assert isinstance(spawner, _RecordingSpawner)
    # construction: settings depth read + the five deps threaded straight through.
    assert spawner.init_kwargs == {
        "scheduler": "sched-sentinel",
        "audit": audit,
        "child_runner": runner,
        "escalation": escalation,
        "parent_budget": parent_budget,
        "max_recursion_depth": 7,
    }

    parent_task_id = str(uuid.uuid4())
    result = await sub.invoke(
        "distinctive prompt",
        parent_tool_allow_list=frozenset({"a", "b", "c"}),
        requested_tool_allow_list=frozenset({"a"}),
        current_depth=1,
        requested_estimated_tokens=4321,
        tenant_id="tenant-z",
        pack_id="cognic-tool-z",
        actor=actor,
        class_="background",
        pack_kind="skill",
        pack_risk_tier="customer_data_read",
        parent_trace_id="trace-z",
        parent_task_id=parent_task_id,
    )

    assert result is sentinel

    sk = spawner.spawn_kwargs
    # routing kwargs pass through verbatim.
    assert sk["pack_id"] == "cognic-tool-z"
    assert sk["actor"] is actor
    assert sk["class_"] == "background"
    assert sk["pack_kind"] == "skill"
    assert sk["pack_risk_tier"] == "customer_data_read"
    assert sk["parent_trace_id"] == "trace-z"
    # the request object carries EXACTLY the seven invoke-supplied fields.
    req = sk["request"]
    assert req == SubAgentSpawnRequest(
        prompt="distinctive prompt",
        parent_tool_allow_list=frozenset({"a", "b", "c"}),
        requested_tool_allow_list=frozenset({"a"}),
        current_depth=1,
        requested_estimated_tokens=4321,
        tenant_id="tenant-z",
        parent_task_id=parent_task_id,
    )
    # the facade passes ONLY request + the six routing kwargs — nothing else.
    assert set(sk.keys()) == {
        "request",
        "pack_id",
        "actor",
        "class_",
        "pack_kind",
        "pack_risk_tier",
        "parent_trace_id",
    }
