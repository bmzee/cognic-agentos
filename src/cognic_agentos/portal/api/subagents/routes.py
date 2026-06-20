"""POST /api/v1/subagents — the production caller of the live SubAgentSpawner
(ADR-005, Fork B). Mounted UNCONDITIONALLY; the request-time combined dep returns
503 when the SDK-gated lifespan did not populate the spawner + run-record store.

``from __future__ import annotations`` is INTENTIONALLY OMITTED so FastAPI can
resolve the closure-local ``Depends(...)`` annotations eagerly.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request

from cognic_agentos.core.run.storage import RunRecordStore
from cognic_agentos.portal.api.subagents.dto import (
    ChildResultBody,
    SubAgentSpawnRequestBody,
    SubAgentSpawnResponse,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope
from cognic_agentos.subagent import SubAgentPrivilegeEscalation
from cognic_agentos.subagent._types import ManagedRunChildSpec, SubAgentSpawnRequest
from cognic_agentos.subagent.spawn import SubAgentSpawner


def _require_subagent_runtime(request: Request) -> tuple[SubAgentSpawner, RunRecordStore]:
    """Co-populated in one SDK-gated lifespan block; a single 503 covers either
    being absent (the dormant-lifespan pattern, mirroring the run route)."""
    spawner: SubAgentSpawner | None = getattr(request.app.state, "subagent_spawner", None)
    run_store: RunRecordStore | None = getattr(request.app.state, "run_record_store", None)
    if spawner is None or run_store is None:
        raise HTTPException(status_code=503, detail={"reason": "subagent_spawner_unavailable"})
    return spawner, run_store


def build_subagent_routes() -> APIRouter:
    router = APIRouter()
    _require_spawn = RequireScope("subagent.spawn")

    @router.post("", response_model=SubAgentSpawnResponse)
    async def spawn_subagent_route(
        body: SubAgentSpawnRequestBody,
        actor: Annotated[Actor, Depends(_require_spawn)],
        runtime: Annotated[
            tuple[SubAgentSpawner, RunRecordStore], Depends(_require_subagent_runtime)
        ],
    ) -> SubAgentSpawnResponse:
        spawner, run_store = runtime
        # 1. Resolve parent_run_id -> task_id, tenant-scoped (cross-tenant -> None -> 404).
        record = await run_store.load(body.parent_run_id, tenant_id=actor.tenant_id)
        if record is None:
            raise HTTPException(status_code=404, detail={"reason": "parent_run_not_found"})
        if record.task_id is None:
            raise HTTPException(status_code=409, detail={"reason": "parent_run_not_admitted"})
        # 2. Build the spawn request (route-derived: current_depth=0, parent_task_id,
        #    tenant, parent_trace_id) + the child spec.
        spawn_request = SubAgentSpawnRequest(
            prompt=body.prompt,
            parent_tool_allow_list=frozenset(body.parent_tool_allow_list),
            requested_tool_allow_list=frozenset(body.requested_tool_allow_list),
            current_depth=0,
            requested_estimated_tokens=body.requested_estimated_tokens,
            tenant_id=actor.tenant_id,
            parent_task_id=str(record.task_id),
        )
        managed_run = ManagedRunChildSpec(
            pack_id=body.managed_run.pack_id,
            pack_version=body.managed_run.pack_version,
            argv=tuple(body.managed_run.argv),
        )
        # 3. Spawn (privilege escalation -> 403).
        try:
            result = await spawner.spawn(
                request=spawn_request,
                managed_run=managed_run,
                actor=actor,
                parent_trace_id=f"run:{body.parent_run_id}",
            )
        except SubAgentPrivilegeEscalation as exc:
            raise HTTPException(
                status_code=403,
                detail={
                    "reason": "subagent_privilege_escalation",
                    "extra_tools": sorted(exc.extra_tools),
                },
            ) from None
        # 4. Coarse 200 (a pending/failed child rides child_result.ok=false; §6).
        return SubAgentSpawnResponse(
            spawn_record_id=str(result.spawn_record_id),
            child_result=ChildResultBody(
                ok=result.child_result.ok,
                summary=result.child_result.summary,
                tokens_used=result.child_result.tokens_used,
                wall_time_used_s=result.child_result.wall_time_used_s,
            ),
        )

    return router
