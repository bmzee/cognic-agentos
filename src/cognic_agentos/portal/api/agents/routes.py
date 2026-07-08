"""M8 Task A13 (ADR-027) — POST /api/v1/agents/{agent_id}/ask.

The production caller that LIVE-exercises :class:`AgentLoop.ask` (the A11
governed reasoning loop: assignment/entitlement/policy-gated dispatch through
the A10 chokepoint, run-level bounds, digest-only ``agent.run.*`` evidence
rows). Mounted UNCONDITIONALLY at construction; the request-time
``_require_agent_loop`` dep returns 503 ``agent_loop_unavailable`` when the
lifespan did not populate ``app.state.agent_loop``.

``agent_id`` rides the URL path (a caller-supplied identity resolved INSIDE
the loop via the record-loader seam); tenant + originator come from the bound
:class:`Actor` ONLY. Status map (by exception-free result inspection):
200 ``completed`` / 200 ``refused`` (a governed refusal IS a successful
governed answer — the evidence rows carry it) / 502 ``failed`` / 404
``agent_not_found`` on ``LookupError`` (wire-collapse: unknown and
unregistered agents read identically). ``AgentGrantNotRequested`` (config
drift) and the dispatcher's fail-loud ``RuntimeError`` (deployment error)
deliberately PROPAGATE to the generic 500 handler — never collapsed.

``from __future__ import annotations`` is INTENTIONALLY OMITTED so FastAPI can
resolve the closure-local ``Depends(...)`` annotations eagerly
(``feedback_pep563_breaks_closure_local_depends``).
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from cognic_agentos.core.agent._types import AgentAskResult
from cognic_agentos.core.agent.loop import AgentLoop
from cognic_agentos.portal.api.agents.dto import AgentAskRequest, AgentAskResponse
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope

_FAILED_STATUS = 502


def _require_agent_loop(request: Request) -> AgentLoop:
    loop: AgentLoop | None = getattr(request.app.state, "agent_loop", None)
    if loop is None:
        raise HTTPException(status_code=503, detail={"reason": "agent_loop_unavailable"})
    return loop


def _status_for(result: AgentAskResult) -> int:
    # ``refused`` is 200 alongside ``completed``: a run-level bound refusal is
    # a GOVERNED answer (closed-form text + the agent.run.refused evidence
    # row), not a transport/backend error. Only ``failed`` is a 502.
    if result.terminal_state == "failed":
        return _FAILED_STATUS
    return 200


def build_agent_routes() -> APIRouter:
    router = APIRouter()
    _require_ask = RequireScope("agent.ask")

    @router.post("/{agent_id}/ask", response_model=AgentAskResponse)
    async def ask_agent(
        agent_id: str,
        body: AgentAskRequest,
        response: Response,
        actor: Annotated[Actor, Depends(_require_ask)],
        loop: Annotated[AgentLoop, Depends(_require_agent_loop)],
    ) -> AgentAskResponse:
        try:
            result = await loop.ask(
                agent_id=agent_id,
                question=body.question,
                actor_tenant_id=actor.tenant_id,
                actor_subject=actor.subject,
            )
        except LookupError:
            # Pre-flight unknown/unregistered agent — NO run minted, NO
            # evidence. Wire-collapse per the cross-tenant-invisibility
            # doctrine: both cases read as the same 404.
            raise HTTPException(status_code=404, detail={"reason": "agent_not_found"}) from None
        response.status_code = _status_for(result)
        return AgentAskResponse(
            run_id=result.run_id,
            terminal_state=result.terminal_state,
            answer=result.answer,
            steps_used=result.steps_used,
            refusal_reason=result.refusal_reason,
        )

    return router


__all__ = ["build_agent_routes"]
