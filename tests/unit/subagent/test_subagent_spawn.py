"""2026-06-20 — the LIVE sub-agent spawn path (ADR-005). After the dispatch
refactor spawn.py owns ONLY the privilege/depth policy gate + the parent-chain
audit emit + delegation to the injected ChildRunner. It makes NO scheduler
calls — admission, the task lifecycle, and budget narrowing now live in the
managed-run executor + core/scheduler (T1/T2).

The harness builds a SubAgentSpawner over a real audit emitter + escalation
store (on the conftest `engine`) + a fake ChildRunner that records the
ChildRunContext it receives. The three behaviours: the live narrow ->
audit -> delegate happy path, privilege-escalation refusal before the runner,
and depth-cap escalation before the runner."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from cognic_agentos.core.escalation import EscalationStore
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.subagent._types import (
    ChildResult,
    ChildRunContext,
    ManagedRunChildSpec,
    SubAgentDepthExceeded,
    SubAgentPrivilegeEscalation,
    SubAgentSpawnRequest,
)
from cognic_agentos.subagent.audit import SubAgentAuditEmitter
from cognic_agentos.subagent.spawn import SubAgentSpawner

_MANAGED_RUN = ManagedRunChildSpec(pack_id="cognic-tool-x", pack_version="1.0.0", argv=("--run",))


class _FakeChildRunner:
    """Records the single ChildRunContext it receives; returns a fixed result."""

    def __init__(self, result: ChildResult) -> None:
        self.result = result
        self.seen_context: ChildRunContext | None = None

    async def run(self, context: ChildRunContext) -> ChildResult:
        self.seen_context = context
        return self.result


@pytest.fixture
def spawn_harness(engine: Any, decision_store: Any) -> Any:
    """Build a SubAgentSpawner with the live-path constructor (no scheduler /
    parent_budget) over a real audit emitter + escalation store, plus a portal
    Actor + a recording fake runner. Exposes spawner / actor / child_runner /
    parent_tools / max_depth."""
    parent_tools = frozenset({"aml_check", "read"})
    runner = _FakeChildRunner(
        ChildResult(summary="ok", tokens_used=10, wall_time_used_s=0.1, ok=True)
    )
    actor = Actor(
        subject="orchestrator", tenant_id="bank-a", scopes=frozenset(), actor_type="service"
    )
    max_depth = 3
    spawner = SubAgentSpawner(
        audit=SubAgentAuditEmitter(decision_store),
        child_runner=runner,
        escalation=EscalationStore(engine),
        max_recursion_depth=max_depth,
    )
    return SimpleNamespace(
        spawner=spawner,
        actor=actor,
        child_runner=runner,
        parent_tools=parent_tools,
        max_depth=max_depth,
    )


def _make_request(**overrides: Any) -> SubAgentSpawnRequest:
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


@pytest.mark.asyncio
async def test_spawn_live_path_narrows_audits_and_delegates_to_runner(
    spawn_harness: Any,
) -> None:
    # The live path: narrow_tool_allow_list -> check_depth -> emit_spawn ->
    # child_runner.run(ctx) -> emit_return + emit_budget. NO scheduler calls.
    h = spawn_harness
    result = await h.spawner.spawn(
        request=_make_request(requested_estimated_tokens=120, parent_task_id=None),
        managed_run=_MANAGED_RUN,
        actor=h.actor,  # a portal Actor (the harness builds an Actor, not a TaskActor)
        parent_trace_id="trace-1",
    )
    assert result.child_result.ok is True
    # The fake runner captured the ChildRunContext it received:
    ctx = h.child_runner.seen_context
    assert ctx.managed_run == _MANAGED_RUN
    assert ctx.actor is h.actor  # the full Actor threaded onto the context
    assert ctx.requested_estimated_tokens == 120
    assert ctx.granted_tools <= h.parent_tools  # privilege subset preserved


@pytest.mark.asyncio
async def test_spawn_privilege_escalation_blocks_before_runner(spawn_harness: Any) -> None:
    h = spawn_harness
    with pytest.raises(SubAgentPrivilegeEscalation):
        await h.spawner.spawn(
            request=_make_request(requested_tool_allow_list=frozenset({"forbidden"})),
            managed_run=_MANAGED_RUN,
            actor=h.actor,
            parent_trace_id="t",
        )
    assert h.child_runner.seen_context is None  # never reached the runner


@pytest.mark.asyncio
async def test_spawn_depth_exceeded_escalates_before_runner(spawn_harness: Any) -> None:
    h = spawn_harness
    with pytest.raises(SubAgentDepthExceeded):
        await h.spawner.spawn(
            request=_make_request(current_depth=h.max_depth),
            managed_run=_MANAGED_RUN,
            actor=h.actor,
            parent_trace_id="t",
        )
    assert h.child_runner.seen_context is None
