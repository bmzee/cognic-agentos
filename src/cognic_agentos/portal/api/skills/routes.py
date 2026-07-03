"""M6 Task A6 (ADR-025) — POST /api/v1/skills/{skill_id}/invoke.

The deterministic production caller that LIVE-exercises ``SkillExecutor`` (the
governed sandboxed run + broker-mediated declared-tool enforcement). Mounted
UNCONDITIONALLY at construction; the request-time ``_require_skill_executor``
dep returns 503 ``skill_executor_unavailable`` when the SDK-gated lifespan did
not populate ``app.state.skill_executor``.

``skill_id`` rides the URL path (a caller-supplied identity resolved
tenant-scoped INSIDE the executor via the loader); tenant + actor come from the
bound :class:`Actor` ONLY. Status map (by exception-free result inspection):
200 ``completed`` / 403 ``skill_tool_not_declared`` (THE load-bearing broker
refusal) / 404 ``skill_not_found`` / 409 ``skill_not_registered`` / 502
``skill_runtime_error``.

``from __future__ import annotations`` is INTENTIONALLY OMITTED so FastAPI can
resolve the closure-local ``Depends(...)`` annotations eagerly
(``feedback_pep563_breaks_closure_local_depends``).
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from cognic_agentos.core.skill._types import SkillInvokeResult
from cognic_agentos.core.skill.executor import SkillExecutor
from cognic_agentos.portal.api.skills.dto import SkillInvokeRequest, SkillInvokeResponse
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope

#: refusal-reason -> HTTP status. ``completed`` -> 200 (handled separately);
#: ``skill_tool_not_declared`` is the load-bearing broker refusal (403); the two
#: pre-flight refusals split 404 (absent) vs 409 (present-but-not-invokable);
#: infra failure -> 502. An unmapped ``refused`` reason (a defensive broker
#: passthrough) falls back to 403 — a governance refusal, never a 200/5xx leak.
_STATUS_BY_REASON: dict[str, int] = {
    "skill_tool_not_declared": 403,
    "skill_not_found": 404,
    "skill_not_registered": 409,
    "skill_runtime_error": 502,
}
_REFUSED_FALLBACK_STATUS = 403
_FAILED_STATUS = 502


def _require_skill_executor(request: Request) -> SkillExecutor:
    executor: SkillExecutor | None = getattr(request.app.state, "skill_executor", None)
    if executor is None:
        raise HTTPException(status_code=503, detail={"reason": "skill_executor_unavailable"})
    return executor


def _status_for(result: SkillInvokeResult) -> int:
    if result.terminal_state == "completed":
        return 200
    if result.terminal_state == "refused":
        return _STATUS_BY_REASON.get(result.refusal_reason or "", _REFUSED_FALLBACK_STATUS)
    return _FAILED_STATUS  # failed -> skill_runtime_error


def build_skill_routes() -> APIRouter:
    router = APIRouter()
    _require_invoke = RequireScope("skill.invoke")

    @router.post("/{skill_id}/invoke", response_model=SkillInvokeResponse)
    async def invoke_skill(
        skill_id: str,
        body: SkillInvokeRequest,
        response: Response,
        actor: Annotated[Actor, Depends(_require_invoke)],
        executor: Annotated[SkillExecutor, Depends(_require_skill_executor)],
    ) -> SkillInvokeResponse:
        result = await executor.invoke(
            skill_id=skill_id, arguments=dict(body.arguments), actor=actor
        )
        response.status_code = _status_for(result)
        return SkillInvokeResponse(
            skill_id=skill_id,
            terminal_state=result.terminal_state,
            result=result.result,
            refusal_reason=result.refusal_reason,
        )

    return router


__all__ = ["build_skill_routes"]
