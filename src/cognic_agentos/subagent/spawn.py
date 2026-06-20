"""Live sub-agent spawn path (ADR-005 Wave-1): privilege de-escalation +
parent-chain audit emit + delegation to the injected ChildRunner.

Ownership boundary: spawn.py owns the policy gate (tool allow-list narrowing +
recursion-depth cap, escalating on exceed) and the parent-chain audit emit
(spawn / child-genesis / return / budget); the injected ChildRunner executes
the child with the already-narrowed ChildRunContext. The scheduler task
lifecycle (submit -> mark_running -> complete) + the token-budget narrowing +
the effective-budget admission guard + the run-record evidence now live in the
managed-run executor + core/scheduler (the 2026-06-20 sub-agent dispatch slice),
NOT here. No app wiring or production agent runtime in this module. Critical-
controls (subagent/ stop-rule)."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from cognic_agentos.core.escalation import EscalationStore
from cognic_agentos.subagent._types import (
    ChildRunContext,
    ChildRunner,
    ManagedRunChildSpec,
    SubAgentDepthExceeded,
    SubAgentResult,
    SubAgentSpawnRequest,
)
from cognic_agentos.subagent.audit import ReturnOutcome, SubAgentAuditEmitter
from cognic_agentos.subagent.policy import check_depth, narrow_tool_allow_list

if TYPE_CHECKING:
    from cognic_agentos.portal.rbac.actor import Actor

_REQUEST_ID_PREFIX = "subagent-spawn-"  # 15 chars + 32 uuid hex = 47 <= 64 cap


def _mint_request_id() -> str:
    return f"{_REQUEST_ID_PREFIX}{uuid.uuid4().hex}"


class SubAgentSpawner:
    """Live sub-agent spawn orchestrator: narrow privilege + audit + delegate
    execution to the injected ChildRunner. No scheduler / budget logic of its
    own (the managed-run executor + core/scheduler own that)."""

    def __init__(
        self,
        *,
        audit: SubAgentAuditEmitter,
        child_runner: ChildRunner,
        escalation: EscalationStore,
        max_recursion_depth: int,
    ) -> None:
        self._audit = audit
        self._runner = child_runner
        self._escalation = escalation
        self._max_depth = max_recursion_depth

    async def spawn(
        self,
        *,
        request: SubAgentSpawnRequest,
        managed_run: ManagedRunChildSpec,
        actor: Actor,
        parent_trace_id: str,
    ) -> SubAgentResult:
        """Spawn a sub-agent on the live path: policy gate (privilege subset +
        depth cap, escalating on exceed) -> emit_spawn -> emit_child_genesis ->
        run the child via the injected runner -> emit return + budget. Makes NO
        scheduler calls: admission + the task lifecycle + budget narrowing are
        the managed-run executor's / core/scheduler's. Returns the child result
        + the spawn record id."""
        request_id = _mint_request_id()
        tenant_id = request.tenant_id

        # 1. policy gate (pure): privilege subset + depth cap (escalate on exceed).
        granted = narrow_tool_allow_list(
            parent=request.parent_tool_allow_list,
            requested=request.requested_tool_allow_list,
        )
        try:
            check_depth(current_depth=request.current_depth, max_depth=self._max_depth)
        except SubAgentDepthExceeded:
            await self._escalation.open(
                actor_id=actor.subject,
                level="depth_exceeded",
                reason=(
                    f"sub-agent spawn at depth {request.current_depth + 1} "
                    f"exceeds max {self._max_depth}"
                ),
                request_id=request_id,
                tenant_id=tenant_id,
            )
            raise

        # 2. emit_spawn -> R_spawn (the parent-chain root). The budget in the
        # snapshot is the REQUESTED tokens; the effective/narrowed value lives in
        # the scheduler chain row (the executor's submit), not here.
        spawn_id = await self._audit.emit_spawn(
            actor_id=actor.subject,
            tenant_id=tenant_id,
            request_id=request_id,
            parent_trace_id=parent_trace_id,
            child_request={"prompt": request.prompt},
            policy_snapshot={
                "granted_tools": sorted(granted),
                "requested_estimated_tokens": request.requested_estimated_tokens,
            },
        )

        # 3. build the already-narrowed-privilege context + delegate execution.
        child_trace_id = uuid.uuid4().hex
        await self._audit.emit_child_genesis(
            actor_id=actor.subject,
            tenant_id=tenant_id,
            request_id=request_id,
            parent_record_id=spawn_id,
            child_trace_id=child_trace_id,
        )
        context = ChildRunContext(
            prompt=request.prompt,
            granted_tools=granted,
            requested_estimated_tokens=request.requested_estimated_tokens,
            tenant_id=tenant_id,
            current_depth=request.current_depth + 1,
            child_trace_id=child_trace_id,
            request_id=request_id,
            parent_record_id=spawn_id,
            actor=actor,
            parent_task_id=request.parent_task_id,
            managed_run=managed_run,
            memory_scope=None,
        )
        child = await self._runner.run(context)

        # 4. emit return; the child's run lifecycle/evidence is the executor's
        # (run-record + run.* rows), not re-emitted here. A pending-approval child
        # cold-create-pended BEFORE the workload ran, so it carries the ids on the
        # return row and skips the budget row entirely (zero work to account for).
        pending = child.terminal_state == "pending_approval"
        outcome: ReturnOutcome = (
            "pending_approval" if pending else ("completed" if child.ok else "failed")
        )
        await self._audit.emit_return(
            actor_id=actor.subject,
            tenant_id=tenant_id,
            request_id=request_id,
            parent_record_id=spawn_id,
            result_summary=child.summary,
            outcome=outcome,
            approval_request_id=child.approval_request_id if pending else None,
            run_id=child.run_id if pending else None,
        )
        if not pending:
            await self._audit.emit_budget(
                actor_id=actor.subject,
                tenant_id=tenant_id,
                request_id=request_id,
                parent_record_id=spawn_id,
                tokens_used=child.tokens_used,
                wall_time_used_s=child.wall_time_used_s,
            )
        return SubAgentResult(spawn_record_id=spawn_id, child_result=child)
