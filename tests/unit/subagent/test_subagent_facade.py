"""Sprint 11b T7 (refactored 2026-06-20) — SubAgent facade (thin public
delegation over the live SubAgentSpawner). These tests prove the facade is
FAITHFUL delegation:

- end-to-end it preserves the spawner contract (one spawn emits the four
  parent-chain rows, hands the runner the narrowed ChildRunContext, and
  verifies clean);
- depth + privilege refusals propagate unchanged (delegated, not re-raised);
- it reads ``Settings.subagent_max_recursion_depth`` rather than hardcoding 3;
- it maps every invoke field onto the SubAgentSpawnRequest + routing kwargs
  (managed_run + actor) with no drop / rename / reinterpretation.

The facade adds NO lifecycle / policy / budget logic of its own — that all
lives in spawn.py / policy.py; the scheduler task lifecycle + budget narrowing
live in the managed-run executor + core/scheduler. There is no scheduler in the
spawn path any more."""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from cognic_agentos.core.config import Settings
from cognic_agentos.core.escalation import EscalationStore
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.subagent import SubAgent
from cognic_agentos.subagent._types import (
    ChildResult,
    ChildRunContext,
    ManagedRunChildSpec,
    SubAgentDepthExceeded,
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


def _subagent(
    engine: Any,
    decision_store: Any,
    *,
    runner: _FakeChildRunner,
    settings: Settings,
) -> SubAgent:
    """Build a SubAgent facade over a real audit emitter + escalation store +
    a fake runner (no scheduler in the live spawn path)."""
    return SubAgent(
        audit=SubAgentAuditEmitter(decision_store),
        child_runner=runner,
        escalation=EscalationStore(engine),
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
        "managed_run": _MANAGED_RUN,
        "actor": _actor(),
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
    """The facade preserves the spawner contract end-to-end: it returns the
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
    assert ctx.requested_estimated_tokens == 300
    assert ctx.current_depth == 1  # parent depth 0 -> child depth 1
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
    depth (7) and thread the three deps + every request + routing field
    (managed_run + actor)."""
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
    actor = _actor()
    managed_run = ManagedRunChildSpec(pack_id="cognic-tool-z", pack_version="2.0.0", argv=("--go",))

    sub = SubAgent(
        audit=audit,  # type: ignore[arg-type]
        child_runner=runner,  # type: ignore[arg-type]
        escalation=escalation,  # type: ignore[arg-type]
        settings=Settings(subagent_max_recursion_depth=7),
    )

    spawner = sub._spawner
    assert isinstance(spawner, _RecordingSpawner)
    # construction: settings depth read + the three deps threaded straight through.
    assert spawner.init_kwargs == {
        "audit": audit,
        "child_runner": runner,
        "escalation": escalation,
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
        managed_run=managed_run,
        actor=actor,
        parent_trace_id="trace-z",
        parent_task_id=parent_task_id,
    )

    assert result is sentinel

    sk = spawner.spawn_kwargs
    # routing kwargs pass through verbatim.
    assert sk["managed_run"] is managed_run
    assert sk["actor"] is actor
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
    # the facade passes ONLY request + the three routing kwargs — nothing else.
    assert set(sk.keys()) == {"request", "managed_run", "actor", "parent_trace_id"}
