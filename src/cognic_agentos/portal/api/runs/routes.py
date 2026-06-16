"""Sprint 14A-A2a — POST /api/v1/runs managed-run caller (ADR-022 + ADR-004).

The production caller that LIVE-exercises ManagedRunExecutor + (via
scheduler.submit) the scheduler approval seam. Mounted UNCONDITIONALLY at
construction; the request-time _require_managed_run_executor dep returns 503
when the lifespan did not populate app.state.managed_run_executor.

``from __future__ import annotations`` is INTENTIONALLY OMITTED so FastAPI can
resolve the closure-local ``Depends(...)`` annotations eagerly.
"""

import base64
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from cognic_agentos.core.run.executor import ManagedRunExecutor, RunRequest, RunResult
from cognic_agentos.portal.api.runs.dto import RunResponse, RunSubmitRequest
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope

#: terminal_state -> HTTP status. completed (incl. non-zero exit) is a run
#: result (200); pending_approval is 202; refused is 409; infra-failed is 502.
#: Sprint 14A-A3b — "suspended" maps to 202 (accepted, awaiting resume), mirroring
#: pending_approval per the locked F5 design; the synchronous run route cannot
#: currently produce it (no suspend_after_exec field on RunSubmitRequest), so this
#: arm is unreachable until the dedicated resume route lands.
_STATUS_BY_TERMINAL: dict[str, int] = {
    "completed": 200,
    "pending_approval": 202,
    "refused": 409,
    "failed": 502,
    "suspended": 202,
}


def _require_managed_run_executor(request: Request) -> ManagedRunExecutor:
    executor: ManagedRunExecutor | None = getattr(request.app.state, "managed_run_executor", None)
    if executor is None:
        raise HTTPException(status_code=503, detail={"reason": "sandbox_runtime_unavailable"})
    return executor


def build_run_routes() -> APIRouter:
    router = APIRouter()
    _require_submit = RequireScope("run.submit")

    @router.post("", response_model=RunResponse)
    async def submit_run(
        body: RunSubmitRequest,
        response: Response,
        actor: Annotated[Actor, Depends(_require_submit)],
        executor: Annotated[ManagedRunExecutor, Depends(_require_managed_run_executor)],
    ) -> RunResponse:
        run_request = RunRequest(
            tenant_id=actor.tenant_id,
            pack_id=body.pack_id,
            pack_uuid=body.pack_uuid,
            pack_version=body.pack_version,
            argv=tuple(body.argv),
            actor=actor,
            approval_request_id=body.approval_request_id,
        )
        result: RunResult = await executor.run(run_request)
        # One consistent body shape across all outcomes; the status varies. A
        # programmatic caller always gets task_id + terminal_state +
        # refusal_reason + approval_request_id without parsing a {"detail": ...}
        # envelope.
        response.status_code = _STATUS_BY_TERMINAL[result.terminal_state]
        return RunResponse(
            task_id=result.task_id,
            terminal_state=result.terminal_state,
            exit_code=result.exit_code,
            stdout_b64=base64.b64encode(result.stdout).decode("ascii"),
            stderr_b64=base64.b64encode(result.stderr).decode("ascii"),
            stdout_bytes=len(result.stdout),
            stderr_bytes=len(result.stderr),
            refusal_reason=result.refusal_reason,
            approval_request_id=result.approval_request_id,
        )

    return router
