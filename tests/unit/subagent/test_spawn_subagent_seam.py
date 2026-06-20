"""Sprint 11b T8 (refactored 2026-06-20) — the thin module-level
spawn_subagent(...) seam (memo D2).

spawn_subagent constructs a SubAgent (threading the three deps + settings) and
delegates to SubAgent.invoke, destructuring the explicit SubAgentSpawnRequest
into invoke's loose args + the managed-run routing args (managed_run + actor).
It adds NO behavior of its own.

These tests mirror T7: an exact argument-mapping pin (a recording fake SubAgent
captures construction + invoke kwargs), real end-to-end delegation over a real
audit emitter + escalation store, and refusal propagation. No harness/, no
base_agent.py (memo D2). The live spawn path has no scheduler — admission + the
task lifecycle + budget narrowing live in the managed-run executor +
core/scheduler. The stub deps are re-declared INLINE to keep this file
self-contained."""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from cognic_agentos.core.config import Settings
from cognic_agentos.core.escalation import EscalationStore
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.subagent import spawn_subagent
from cognic_agentos.subagent._types import (
    ChildResult,
    ChildRunContext,
    ManagedRunChildSpec,
    SubAgentPrivilegeEscalation,
    SubAgentResult,
    SubAgentSpawnRequest,
)
from cognic_agentos.subagent.audit import SubAgentAuditEmitter
from cognic_agentos.subagent.audit_verifier import verify_subagent_linkage

_MANAGED_RUN = ManagedRunChildSpec(pack_id="cognic-tool-aml", pack_version="1.0.0", argv=("--run",))


class _FakeChildRunner:
    """Records every ChildRunContext it receives; returns a fixed ChildResult."""

    def __init__(self, result: ChildResult) -> None:
        self.result = result
        self.contexts: list[ChildRunContext] = []

    async def run(self, context: ChildRunContext) -> ChildResult:
        self.contexts.append(context)
        return self.result


def _actor() -> Actor:
    return Actor(
        subject="orchestrator", tenant_id="bank-a", scopes=frozenset(), actor_type="service"
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
    """Drive spawn_subagent over a real audit emitter + escalation store + a
    fake runner (no scheduler in the live spawn path)."""
    return await spawn_subagent(
        request=request,
        managed_run=_MANAGED_RUN,
        actor=_actor(),
        parent_trace_id="ptrace",
        audit=SubAgentAuditEmitter(decision_store),
        child_runner=runner,
        escalation=EscalationStore(engine),
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
    assert ctx.managed_run == _MANAGED_RUN

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
    """Pins that the seam constructs SubAgent with EXACTLY the three deps (+
    settings, NOT a pre-read depth — the facade reads the field) and delegates
    to invoke with the request destructured + the managed-run routing kwargs,
    dropping / renaming / adding nothing. A recording fake SubAgent captures
    both."""
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

    audit = object()
    runner = object()
    escalation = object()
    actor = _actor()
    managed_run = ManagedRunChildSpec(pack_id="cognic-tool-z", pack_version="2.0.0", argv=("--go",))
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
        managed_run=managed_run,
        actor=actor,
        parent_trace_id="trace-z",
        audit=audit,  # type: ignore[arg-type]
        child_runner=runner,  # type: ignore[arg-type]
        escalation=escalation,  # type: ignore[arg-type]
        settings=settings,
    )

    assert result is sentinel
    assert len(created) == 1
    sub = created[0]
    # constructed with exactly the three deps; settings passed through (the seam
    # does NOT pre-read subagent_max_recursion_depth — the facade does).
    assert sub.init_kwargs == {
        "audit": audit,
        "child_runner": runner,
        "escalation": escalation,
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
        "managed_run": managed_run,
        "actor": actor,
        "parent_trace_id": "trace-z",
    }
