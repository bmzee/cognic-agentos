"""Sprint 11b — in-process scheduler-mediated sub-agent spawn (ADR-005
Wave-1). NOT a deployable production path (decision memo D1): runs only
under an injected SchedulerEngine + conformers + a fake/real ChildRunner.

Ownership boundary (memo D1): spawn.py owns policy narrowing + the scheduler
task lifecycle (submit -> mark_running -> complete/preempt/fail) + audit emit
+ budget accounting; the injected ChildRunner ONLY executes the child with the
already-granted ChildRunContext. No harness/, no app wiring, no production
agent runtime here. Critical-controls (subagent/ stop-rule)."""

from __future__ import annotations

import uuid

from cognic_agentos.core.escalation import EscalationStore
from cognic_agentos.core.scheduler._seams import ParentBudgetResolver
from cognic_agentos.core.scheduler._types import (
    SchedulerPriorityClass,
    SubmitInput,
    TaskActor,
    TaskFailedPayload,
)
from cognic_agentos.core.scheduler.engine import SchedulerEngine
from cognic_agentos.subagent._types import (
    ChildResult,
    ChildRunContext,
    ChildRunner,
    SubAgentChildQuotaZero,
    SubAgentDepthExceeded,
    SubAgentResult,
    SubAgentSpawnRequest,
)
from cognic_agentos.subagent.audit import ReturnOutcome, SubAgentAuditEmitter
from cognic_agentos.subagent.policy import (
    check_depth,
    compute_spawn_budget,
    narrow_tool_allow_list,
)

_REQUEST_ID_PREFIX = "subagent-spawn-"  # 15 chars + 32 uuid hex = 47 <= 64 cap


def _mint_request_id() -> str:
    return f"{_REQUEST_ID_PREFIX}{uuid.uuid4().hex}"


class SubAgentSpawner:
    """In-process scheduler-mediated sub-agent spawn orchestrator."""

    def __init__(
        self,
        *,
        scheduler: SchedulerEngine,
        audit: SubAgentAuditEmitter,
        child_runner: ChildRunner,
        escalation: EscalationStore,
        parent_budget: ParentBudgetResolver,
        max_recursion_depth: int,
    ) -> None:
        self._scheduler = scheduler
        self._audit = audit
        self._runner = child_runner
        self._escalation = escalation
        self._parent_budget = parent_budget
        self._max_depth = max_recursion_depth

    async def _resolve_budget(
        self, *, parent_task_id: str | None, requested: int, tenant_id: str
    ) -> int:
        """Budget accounting (memo: spawn.py owns it). A top-level spawn
        (parent_task_id is None) grants the child its pack quota; a child
        spawn narrows against the parent's remaining budget via the injected
        ParentBudgetResolver. Both gate a zero child quota / parent-exhausted
        via the T4.5 split refusals (SubAgentChildQuotaZero /
        SubAgentBudgetExhausted). ``tenant_id`` is threaded into the resolver
        for Protocol-compat (the dict-snapshot conformer ignores it; the
        scheduler-backed resolver tenant-scopes)."""
        if parent_task_id is None:
            if requested == 0:
                raise SubAgentChildQuotaZero(child_pack_quota=requested)
            return requested
        parent_remaining = await self._parent_budget.remaining_budget_for(
            uuid.UUID(parent_task_id), tenant_id=tenant_id
        )
        return compute_spawn_budget(
            parent_remaining_budget=parent_remaining, child_pack_quota=requested
        )

    async def spawn(
        self,
        *,
        request: SubAgentSpawnRequest,
        pack_id: str,
        actor: TaskActor,
        class_: SchedulerPriorityClass,
        pack_kind: str,
        pack_risk_tier: str,
        parent_trace_id: str,
    ) -> SubAgentResult:
        """Spawn a sub-agent: policy gate -> emit_spawn -> scheduler submit ->
        mark_running -> run child -> complete/preempt/fail -> emit return +
        budget. Returns the child result + the spawn record id (memo D1)."""
        request_id = _mint_request_id()
        tenant_id = request.tenant_id

        # 1. policy gate (pure). Privilege subset + depth cap (escalate on exceed).
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

        budget = await self._resolve_budget(
            parent_task_id=request.parent_task_id,
            requested=request.requested_estimated_tokens,
            tenant_id=tenant_id,
        )

        # 2. emit_spawn -> R_spawn (the parent-chain root every child row links to).
        spawn_id = await self._audit.emit_spawn(
            actor_id=actor.subject,
            tenant_id=tenant_id,
            request_id=request_id,
            parent_trace_id=parent_trace_id,
            child_request={"prompt": request.prompt},
            policy_snapshot={"granted_tools": sorted(granted), "budget": budget},
        )

        # 3. scheduler submit — every child flows through core/scheduler.
        decision = await self._scheduler.submit(
            submit_input=SubmitInput(
                tenant_id=tenant_id,
                pack_id=pack_id,
                actor=actor,
                class_=class_,
                pack_kind=pack_kind,
                pack_risk_tier=pack_risk_tier,
                requested_estimated_tokens=request.requested_estimated_tokens,
                parent_task_id=request.parent_task_id,
            ),
            request_id=request_id,
        )
        if decision.task_id is None:
            # Refused at admission: emit a failed return; no child runs.
            await self._audit.emit_return(
                actor_id=actor.subject,
                tenant_id=tenant_id,
                request_id=request_id,
                parent_record_id=spawn_id,
                result_summary=f"scheduler refused: {decision.outcome}",
                outcome="failed",
            )
            return SubAgentResult(
                spawn_record_id=spawn_id,
                child_result=ChildResult(
                    summary=f"refused:{decision.outcome}",
                    tokens_used=0,
                    wall_time_used_s=0.0,
                    ok=False,
                ),
            )
        task_id = uuid.UUID(decision.task_id)

        if decision.outcome == "accepted_queued":
            # The 11b spawn seam runs synchronously and has no queue worker, so a
            # queued task can never start here. Calling mark_running on it would
            # re-check caps and can raise SchedulerPromotionRefused, leaking a
            # pending/queued row + quota reservation. Instead cancel it
            # immediately (pending -> cancelled; releases the reservation), emit a
            # failed return, and return ok=False — never leave a pending row.
            # `actor_cancelled` is the closest wire-legal SchedulerTaskCancelledReason:
            # no actor literally cancelled, but the synchronous seam structurally
            # abandons the queued task (Wave-1; a dedicated reason could land later).
            await self._scheduler.cancel(
                task_id,
                actor=actor,
                reason="actor_cancelled",
                request_id=request_id,
            )
            await self._audit.emit_return(
                actor_id=actor.subject,
                tenant_id=tenant_id,
                request_id=request_id,
                parent_record_id=spawn_id,
                result_summary="scheduler queued; 11b spawn seam runs synchronously only",
                outcome="failed",
            )
            return SubAgentResult(
                spawn_record_id=spawn_id,
                child_result=ChildResult(
                    summary="queued_not_supported",
                    tokens_used=0,
                    wall_time_used_s=0.0,
                    ok=False,
                ),
            )

        # 4. mark_running (pending -> running; workload has actually started).
        await self._scheduler.mark_running(task_id, request_id=request_id)

        # 5. emit_child_genesis — the child's own genesis row, payload-linked.
        child_trace_id = uuid.uuid4().hex
        await self._audit.emit_child_genesis(
            actor_id=actor.subject,
            tenant_id=tenant_id,
            request_id=request_id,
            parent_record_id=spawn_id,
            child_trace_id=child_trace_id,
        )

        # 6. run the child via the injected runner (already-granted context).
        context = ChildRunContext(
            prompt=request.prompt,
            granted_tools=granted,
            requested_estimated_tokens=budget,
            tenant_id=tenant_id,
            current_depth=request.current_depth + 1,
            child_trace_id=child_trace_id,
            request_id=request_id,
            parent_record_id=spawn_id,
            memory_scope=None,
        )
        try:
            child = await self._runner.run(context)
        except Exception:
            # Runner error -> fail the scheduler task + emit a failed return.
            await self._scheduler.fail(
                task_id,
                payload=TaskFailedPayload(reason="scheduler_task_failed_workload_runtime_error"),
                request_id=request_id,
            )
            await self._audit.emit_return(
                actor_id=actor.subject,
                tenant_id=tenant_id,
                request_id=request_id,
                parent_record_id=spawn_id,
                result_summary="child runner raised",
                outcome="failed",
            )
            raise

        # 7. Terminal lifecycle — distinct paths (review P2.3):
        #    - over budget                    -> preempt (running -> preempted)
        #    - child returned not-ok (no raise) -> fail (running -> failed): a child
        #      failure is NOT a budget preemption, so it must not stamp the
        #      quota_exhausted_in_flight reason.
        #    - ok + within budget             -> complete (running -> completed)
        # The child ran in all three, so each still emits a return + budget row.
        outcome: ReturnOutcome
        if child.tokens_used > budget:
            await self._scheduler.preempt(task_id, request_id=request_id)
            preempted = True
            outcome = "failed"
        elif not child.ok:
            await self._scheduler.fail(
                task_id,
                payload=TaskFailedPayload(reason="scheduler_task_failed_workload_runtime_error"),
                request_id=request_id,
            )
            preempted = False
            outcome = "failed"
        else:
            await self._scheduler.complete(task_id, request_id=request_id)
            preempted = False
            outcome = "completed"

        # 8. emit return + budget; return the result to the parent.
        await self._audit.emit_return(
            actor_id=actor.subject,
            tenant_id=tenant_id,
            request_id=request_id,
            parent_record_id=spawn_id,
            result_summary=child.summary,
            outcome=outcome,
        )
        await self._audit.emit_budget(
            actor_id=actor.subject,
            tenant_id=tenant_id,
            request_id=request_id,
            parent_record_id=spawn_id,
            tokens_used=child.tokens_used,
            wall_time_used_s=child.wall_time_used_s,
        )
        return SubAgentResult(spawn_record_id=spawn_id, child_result=child, preempted=preempted)
