"""Sprint 11b T8 — the thin module-level spawn_subagent(...) seam (memo D2).

spawn_subagent constructs a SubAgent (threading the six deps + settings) and
delegates to SubAgent.invoke, destructuring the explicit SubAgentSpawnRequest
into invoke's loose args + the routing args. It adds NO behavior of its own.

These tests mirror T7: an exact argument-mapping pin (a recording fake SubAgent
captures construction + invoke kwargs), real end-to-end delegation over a REAL
SchedulerEngine, and refusal propagation. No harness/, no base_agent.py (memo
D2). The stub conformers are re-declared INLINE (NOT imported from the sibling
test modules) to keep this file self-contained."""

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
from cognic_agentos.subagent import spawn_subagent
from cognic_agentos.subagent._types import (
    ChildResult,
    ChildRunContext,
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


def _scheduler(engine: Any) -> SchedulerEngine:
    """A REAL SchedulerEngine on the conftest engine + allow-all conformers."""
    return SchedulerEngine(
        storage=SchedulerStorage(engine),
        caps=ConcurrencyCaps(
            per_tenant_interactive=4, per_tenant_background=4, per_pack=4, per_actor=4
        ),
        class_settings={"interactive": (4, 0.5), "background": (4, 5.0)},
        quota_interrogator=_AllowQuota(),
        kill_switch_interrogator=_InactiveKillSwitch(),
        parent_budget_resolver=LocalParentBudgetResolver({}),
        pack_state_interrogator=_InstalledPackState(),
        policy_evaluator=_policy_allow,
    )


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


async def _seam(
    engine: Any,
    decision_store: Any,
    *,
    runner: _FakeChildRunner,
    request: SubAgentSpawnRequest,
    settings: Settings | None = None,
) -> Any:
    """Drive spawn_subagent over a REAL SchedulerEngine + a fake runner."""
    return await spawn_subagent(
        request=request,
        pack_id="cognic-tool-aml",
        actor=_actor(),
        class_="interactive",
        pack_kind="tool",
        pack_risk_tier="internal_write",
        parent_trace_id="ptrace",
        scheduler=_scheduler(engine),
        audit=SubAgentAuditEmitter(decision_store),
        child_runner=runner,
        escalation=EscalationStore(engine),
        parent_budget=LocalParentBudgetResolver({}),
        settings=settings or Settings(),
    )


@pytest.mark.asyncio
async def test_seam_delegates_and_returns_child_result(
    engine: Any, decision_store: Any, decision_store_rows: Any
) -> None:
    """End-to-end the seam preserves the T6/T7 contract: returns the child
    result, hands the runner the narrowed ChildRunContext, emits the four
    parent-chain rows, and verifies clean."""
    runner = _FakeChildRunner(ChildResult(summary="ok", tokens_used=120, wall_time_used_s=0.3))
    result = await _seam(engine, decision_store, runner=runner, request=_request())

    assert isinstance(result, SubAgentResult)
    assert result.child_result.summary == "ok"
    assert result.preempted is False

    assert len(runner.contexts) == 1
    ctx = runner.contexts[0]
    assert ctx.granted_tools == frozenset({"aml_check"})
    assert ctx.requested_estimated_tokens == 300
    assert ctx.current_depth == 1

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
    assert (await verify_subagent_linkage(engine)).is_clean is True


@pytest.mark.asyncio
async def test_seam_propagates_privilege_escalation(
    engine: Any, decision_store: Any, decision_store_rows: Any
) -> None:
    """A requested allow-list not ⊆ the parent's raises
    SubAgentPrivilegeEscalation (propagated from invoke) BEFORE any emit/run."""
    runner = _FakeChildRunner(ChildResult(summary="x", tokens_used=0, wall_time_used_s=0.0))
    with pytest.raises(SubAgentPrivilegeEscalation):
        await _seam(
            engine,
            decision_store,
            runner=runner,
            request=_request(requested_tool_allow_list=frozenset({"aml_check", "wire_transfer"})),
        )
    assert await decision_store_rows() == []
    assert runner.contexts == []


@pytest.mark.asyncio
async def test_seam_maps_args_exactly(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pins that the seam constructs SubAgent with EXACTLY the six deps (+
    settings, NOT a pre-read depth — the facade reads the field) and delegates
    to invoke with the request destructured + the six routing kwargs, dropping /
    renaming / adding nothing. A recording fake SubAgent captures both."""
    sentinel = SubAgentResult(
        spawn_record_id=uuid.uuid4(),
        child_result=ChildResult(summary="sentinel", tokens_used=1, wall_time_used_s=0.0),
    )
    created: list[Any] = []

    class _RecordingSubAgent:
        def __init__(self, **kwargs: Any) -> None:
            self.init_kwargs = kwargs
            created.append(self)

        async def invoke(self, prompt: str, **kwargs: Any) -> SubAgentResult:
            self.invoke_prompt = prompt
            self.invoke_kwargs = kwargs
            return sentinel

    import cognic_agentos.subagent._facade as facade_mod

    monkeypatch.setattr(facade_mod, "SubAgent", _RecordingSubAgent)

    scheduler = object()
    audit = object()
    runner = object()
    escalation = object()
    parent_budget = object()
    actor = _actor()
    settings = Settings(subagent_max_recursion_depth=5)
    parent_task_id = str(uuid.uuid4())
    request = SubAgentSpawnRequest(
        prompt="distinctive",
        parent_tool_allow_list=frozenset({"a", "b"}),
        requested_tool_allow_list=frozenset({"a"}),
        current_depth=2,
        requested_estimated_tokens=999,
        tenant_id="tenant-z",
        parent_task_id=parent_task_id,
    )

    result = await spawn_subagent(
        request=request,
        pack_id="cognic-tool-z",
        actor=actor,
        class_="background",
        pack_kind="skill",
        pack_risk_tier="customer_data_read",
        parent_trace_id="trace-z",
        scheduler=scheduler,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        child_runner=runner,  # type: ignore[arg-type]
        escalation=escalation,  # type: ignore[arg-type]
        parent_budget=parent_budget,  # type: ignore[arg-type]
        settings=settings,
    )

    assert result is sentinel
    assert len(created) == 1
    sub = created[0]
    # constructed with exactly the six deps; settings passed through (the seam
    # does NOT pre-read subagent_max_recursion_depth — the facade does).
    assert sub.init_kwargs == {
        "scheduler": scheduler,
        "audit": audit,
        "child_runner": runner,
        "escalation": escalation,
        "parent_budget": parent_budget,
        "settings": settings,
    }
    # invoke got the request destructured (prompt positional) + routing kwargs.
    assert sub.invoke_prompt == "distinctive"
    assert sub.invoke_kwargs == {
        "parent_tool_allow_list": frozenset({"a", "b"}),
        "requested_tool_allow_list": frozenset({"a"}),
        "current_depth": 2,
        "requested_estimated_tokens": 999,
        "tenant_id": "tenant-z",
        "parent_task_id": parent_task_id,
        "pack_id": "cognic-tool-z",
        "actor": actor,
        "class_": "background",
        "pack_kind": "skill",
        "pack_risk_tier": "customer_data_read",
        "parent_trace_id": "trace-z",
    }
