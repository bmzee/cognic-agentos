"""Sprint 13.5b1 (ADR-014) — portal approval API router. Thin delegate-to-engine
surface; the engine is authoritative for every enforcement decision.

NOTE: ``from __future__ import annotations`` is INTENTIONALLY OMITTED — PEP 563
string-deferred annotations break FastAPI's get_type_hints on
``Annotated[..., Depends(<closure-local>)]`` (the shared deps are closure-locals
inside build_approval_routes, not module globals)."""

import logging
import uuid
from collections.abc import Awaitable, Callable
from typing import Annotated, cast

from fastapi import APIRouter, Depends, HTTPException, Request

from cognic_agentos.core.approval._types import (
    ApprovalActor,
    ApprovalFlow,
    ApprovalRequestNotFound,
    ApprovalState,
    ApprovalTransitionRefused,
)
from cognic_agentos.core.approval.engine import ApprovalEngine
from cognic_agentos.core.approval.storage import (
    ApprovalRequestDetail,
    ApprovalRequestStore,
    ApprovalRequestSummary,
)
from cognic_agentos.portal.api.approvals.dto import (
    ApprovalActionResponse,
    ApprovalDetailResponse,
    ApprovalSummaryResponse,
    DenyRequest,
    GrantRequest,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import (
    RequireScope,
    _emit_denial_or_500,
    _resolve_request_id,
)
from cognic_agentos.portal.rbac.human_actor import RequireHumanActor

_LOG = logging.getLogger(__name__)

#: Wire mapping for the 10-value ApprovalTransitionRefusedReason (_types.py:35).
#: Pinned EXACTLY by test_every_transition_reason_has_a_status_mapping via
#: typing.get_args — an 11th engine reason fails the test until mapped here.
_REFUSAL_STATUS: dict[str, int] = {
    "approver_not_human": 403,
    "approver_scope_not_held": 403,
    "grant_reason_required": 400,
    "approval_expired": 409,
    "approval_already_finalized": 409,
    "four_eyes_approver_not_distinct": 409,
    "grant_second_requires_awaiting_second": 409,
    "deny_requires_non_terminal": 409,
    "auto_tier_no_approval_required": 409,
    "approval_binding_mismatch": 409,
}


def _to_approval_actor(actor: Actor) -> ApprovalActor:
    # Boundary projection: the core engine MUST NOT import portal/rbac, so the
    # portal binds Actor -> the core-owned ApprovalActor here (_types.py:107).
    return ApprovalActor(
        subject=actor.subject,
        tenant_id=actor.tenant_id,
        scopes=frozenset(actor.scopes),
        actor_type=actor.actor_type,
    )


async def _dispatch_decision(
    *,
    verb: str,
    request_id: uuid.UUID,
    actor: Actor,
    call: Callable[[], Awaitable[ApprovalState]],
) -> ApprovalActionResponse:
    """Shared refusal-dispatch for the three decision verbs. The ENGINE is
    authoritative for tenant-binding / scope-per-tier / human-only / state /
    expiry / 4-eyes / reason-policy — the portal only maps refusals onto HTTP.

    Mutually-exclusive log contract (spec §4): exactly ONE route-level log per
    request — green ``portal.approvals.<verb>`` OR refused
    ``portal.approvals.<verb>_refused``; dep-chain refusals emit ZERO
    route-level logs (the sibling guard's _emit_denial_or_500 carries that axis).
    """
    try:
        state = await call()
    except ApprovalRequestNotFound:
        _LOG.warning(
            f"portal.approvals.{verb}_refused",
            extra={"reason": "approval_request_not_found", "actor_subject": actor.subject},
        )
        raise HTTPException(
            status_code=404, detail={"reason": "approval_request_not_found"}
        ) from None
    except ApprovalTransitionRefused as exc:
        _LOG.warning(
            f"portal.approvals.{verb}_refused",
            extra={"reason": exc.reason, "actor_subject": actor.subject},
        )
        raise HTTPException(
            status_code=_REFUSAL_STATUS[exc.reason], detail={"reason": exc.reason}
        ) from None
    _LOG.info(
        f"portal.approvals.{verb}",
        extra={"actor_subject": actor.subject, "request_id": str(request_id), "state": state},
    )
    return ApprovalActionResponse(request_id=request_id, state=state)


def _summary_dto(s: ApprovalRequestSummary) -> ApprovalSummaryResponse:
    # storage projects flow as plain str; the DTO tightens it to the
    # ApprovalFlow Literal (Pydantic validates the value on construction).
    return ApprovalSummaryResponse(
        request_id=s.request_id,
        tenant_id=s.tenant_id,
        flow=cast(ApprovalFlow, s.flow),
        risk_tier=s.risk_tier,
        tool_identity=s.tool_identity,
        originator_subject=s.originator_subject,
        state=s.state,
        first_approver=s.first_approver,
        created_at=s.created_at.isoformat(),
        expires_at=s.expires_at.isoformat(),
    )


def _detail_dto(d: ApprovalRequestDetail) -> ApprovalDetailResponse:
    return ApprovalDetailResponse(
        request_id=d.request_id,
        tenant_id=d.tenant_id,
        state=d.state,
        flow=cast(ApprovalFlow, d.flow),
        risk_tier=d.risk_tier,
        tool_identity=d.tool_identity,
        originator_subject=d.originator_subject,
        envelope_digest=d.envelope_digest.hex(),
        args_digest=d.args_digest.hex(),
        data_classes=d.data_classes,
        redacted_context=d.redacted_context,
        first_approver=d.first_approver,
        second_approver=d.second_approver,
        denier=d.denier,
        created_at=d.created_at.isoformat(),
        expires_at=d.expires_at.isoformat(),
    )


def build_approval_routes(*, store: ApprovalRequestStore, engine: ApprovalEngine) -> APIRouter:
    router = APIRouter(prefix="/api/v1/approvals", tags=["approvals"])
    _require_observe = RequireScope("tool.approve.observe")
    _require_human = RequireHumanActor()

    @router.get("/", response_model=list[ApprovalSummaryResponse])
    async def list_queue(
        request: Request,
        actor: Annotated[Actor, Depends(_require_observe)],
    ) -> list[ApprovalSummaryResponse]:
        # bare-list preflight: no {request_id} path-param, so no tenant-ownership
        # dep can run; the only reachable falsy tenant_id under live Pydantic is "".
        # Mirrors inspection_routes.py:167-181.
        if not actor.tenant_id:
            broker = getattr(request.app.state, "ui_event_broker", None)
            await _emit_denial_or_500(
                broker,
                denial_type="actor_tenant_id_missing",
                actor_subject=actor.subject,
                tenant_id=None,
                request_id=_resolve_request_id(request),
                http_status=500,
                pack_id="<list>",  # sentinel — no {request_id} path-param
            )
            raise HTTPException(status_code=500, detail={"reason": "actor_tenant_id_missing"})
        rows = await store.list_pending(actor.tenant_id)
        return [_summary_dto(r) for r in rows]

    @router.get("/{request_id}", response_model=ApprovalDetailResponse)
    async def get_detail(
        request_id: uuid.UUID,
        actor: Annotated[Actor, Depends(_require_observe)],
    ) -> ApprovalDetailResponse:
        detail = await store.load_detail(request_id=request_id, tenant_id=actor.tenant_id)
        if detail is None:
            raise HTTPException(status_code=404, detail={"reason": "approval_request_not_found"})
        return _detail_dto(detail)

    @router.post("/{request_id}/grant", response_model=ApprovalActionResponse)
    async def grant(
        request_id: uuid.UUID,
        body: GrantRequest,
        actor: Annotated[Actor, Depends(_require_human)],
    ) -> ApprovalActionResponse:
        # RequireHumanActor is defence-in-depth; the engine's approver_not_human
        # check is authoritative (spec §5 authority boundary).
        return await _dispatch_decision(
            verb="grant",
            request_id=request_id,
            actor=actor,
            call=lambda: engine.grant(
                request_id=request_id,
                tenant_id=actor.tenant_id,
                approver=_to_approval_actor(actor),
                reason=body.reason,
            ),
        )

    @router.post("/{request_id}/grant-second", response_model=ApprovalActionResponse)
    async def grant_second(
        request_id: uuid.UUID,
        body: GrantRequest,
        actor: Annotated[Actor, Depends(_require_human)],
    ) -> ApprovalActionResponse:
        return await _dispatch_decision(
            verb="grant_second",
            request_id=request_id,
            actor=actor,
            call=lambda: engine.grant_second(
                request_id=request_id,
                tenant_id=actor.tenant_id,
                approver=_to_approval_actor(actor),
                reason=body.reason,
            ),
        )

    @router.post("/{request_id}/deny", response_model=ApprovalActionResponse)
    async def deny(
        request_id: uuid.UUID,
        body: DenyRequest,
        actor: Annotated[Actor, Depends(_require_human)],
    ) -> ApprovalActionResponse:
        return await _dispatch_decision(
            verb="deny",
            request_id=request_id,
            actor=actor,
            call=lambda: engine.deny(
                request_id=request_id,
                tenant_id=actor.tenant_id,
                approver=_to_approval_actor(actor),
                reason=body.reason,
            ),
        )

    return router
