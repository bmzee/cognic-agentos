"""Sprint 13.5b1 (ADR-014) — portal approval API router. Thin delegate-to-engine
surface; the engine is authoritative for every enforcement decision.

NOTE: ``from __future__ import annotations`` is INTENTIONALLY OMITTED — PEP 563
string-deferred annotations break FastAPI's get_type_hints on
``Annotated[..., Depends(<closure-local>)]`` (the shared deps are closure-locals
inside build_approval_routes, not module globals)."""

import logging
import uuid
from typing import Annotated, cast

from fastapi import APIRouter, Depends, HTTPException, Request

from cognic_agentos.core.approval._types import ApprovalFlow
from cognic_agentos.core.approval.engine import ApprovalEngine
from cognic_agentos.core.approval.storage import (
    ApprovalRequestDetail,
    ApprovalRequestStore,
    ApprovalRequestSummary,
)
from cognic_agentos.portal.api.approvals.dto import (
    ApprovalDetailResponse,
    ApprovalSummaryResponse,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import (
    RequireScope,
    _emit_denial_or_500,
    _resolve_request_id,
)

_LOG = logging.getLogger(__name__)


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

    return router
