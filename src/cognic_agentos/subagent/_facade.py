"""Sprint 11b T7 — the thin public SubAgent facade over the SubAgentSpawner
(ADR-005 Wave-1). Composes a SubAgentSpawnRequest + delegates to
``SubAgentSpawner.spawn(...)`` — nothing else.

The facade owns NO lifecycle semantics, policy reinterpretation, budget math,
depth/privilege logic, or audit emission — all of that lives in spawn.py /
policy.py (the scheduler task lifecycle + budget narrowing live in the
managed-run executor + core/scheduler). The facade only composes + delegates.
Critical-controls (subagent/ stop-rule)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cognic_agentos.core.config import Settings
from cognic_agentos.core.escalation import EscalationStore
from cognic_agentos.subagent._types import (
    ChildRunner,
    ManagedRunChildSpec,
    SubAgentResult,
    SubAgentSpawnRequest,
)
from cognic_agentos.subagent.audit import SubAgentAuditEmitter
from cognic_agentos.subagent.spawn import SubAgentSpawner

if TYPE_CHECKING:
    from cognic_agentos.portal.rbac.actor import Actor


class SubAgent:
    """Thin public facade / privilege-de-escalation enforcement boundary that
    delegates to :class:`SubAgentSpawner`.

    It constructs ONE :class:`SubAgentSpawner` internally (threading the three
    deps straight through and reading the recursion cap from ``settings``), and
    its :meth:`invoke` builds a :class:`SubAgentSpawnRequest` then awaits
    ``spawner.spawn(...)``. No lifecycle / policy / budget logic of its own."""

    def __init__(
        self,
        *,
        audit: SubAgentAuditEmitter,
        child_runner: ChildRunner,
        escalation: EscalationStore,
        settings: Settings,
    ) -> None:
        self._spawner = SubAgentSpawner(
            audit=audit,
            child_runner=child_runner,
            escalation=escalation,
            max_recursion_depth=settings.subagent_max_recursion_depth,
        )

    async def invoke(
        self,
        prompt: str,
        *,
        parent_tool_allow_list: frozenset[str],
        requested_tool_allow_list: frozenset[str],
        current_depth: int,
        requested_estimated_tokens: int,
        tenant_id: str,
        managed_run: ManagedRunChildSpec,
        actor: Actor,
        parent_trace_id: str,
        parent_task_id: str | None = None,
    ) -> SubAgentResult:
        """Compose a :class:`SubAgentSpawnRequest` from the request fields and
        delegate to ``SubAgentSpawner.spawn(...)``. Pure delegation: depth /
        privilege refusals propagate from the spawner unchanged; the result is
        returned untransformed."""
        request = SubAgentSpawnRequest(
            prompt=prompt,
            parent_tool_allow_list=parent_tool_allow_list,
            requested_tool_allow_list=requested_tool_allow_list,
            current_depth=current_depth,
            requested_estimated_tokens=requested_estimated_tokens,
            tenant_id=tenant_id,
            parent_task_id=parent_task_id,
        )
        return await self._spawner.spawn(
            request=request,
            managed_run=managed_run,
            actor=actor,
            parent_trace_id=parent_trace_id,
        )


async def spawn_subagent(
    *,
    request: SubAgentSpawnRequest,
    managed_run: ManagedRunChildSpec,
    actor: Actor,
    parent_trace_id: str,
    audit: SubAgentAuditEmitter,
    child_runner: ChildRunner,
    escalation: EscalationStore,
    settings: Settings,
) -> SubAgentResult:
    """Thin module-level convenience seam (decision memo D2): construct a
    :class:`SubAgent` over the injected deps + ``settings``, then delegate to
    :meth:`SubAgent.invoke`, destructuring the explicit ``request`` into
    invoke's loose args + the managed-run routing args. No ``harness/`` package,
    no ``base_agent.py``, and no behavior of its own — depth / privilege
    refusals propagate from the facade unchanged.

    The ``request`` carries the seven "what to run" fields; ``managed_run`` /
    ``actor`` / ``parent_trace_id`` are the routing args ``spawn`` requires; the
    remaining three are the SubAgent constructor deps."""
    return await SubAgent(
        audit=audit,
        child_runner=child_runner,
        escalation=escalation,
        settings=settings,
    ).invoke(
        request.prompt,
        parent_tool_allow_list=request.parent_tool_allow_list,
        requested_tool_allow_list=request.requested_tool_allow_list,
        current_depth=request.current_depth,
        requested_estimated_tokens=request.requested_estimated_tokens,
        tenant_id=request.tenant_id,
        parent_task_id=request.parent_task_id,
        managed_run=managed_run,
        actor=actor,
        parent_trace_id=parent_trace_id,
    )
