"""Sprint 13.5b1 (ADR-014) — portal approval API router. Thin delegate-to-engine
surface; the engine is authoritative for every enforcement decision.

NOTE: ``from __future__ import annotations`` is INTENTIONALLY OMITTED — PEP 563
string-deferred annotations break FastAPI's get_type_hints on
``Annotated[..., Depends(<closure-local>)]`` (the shared deps are closure-locals
inside build_approval_routes, not module globals)."""

import logging
import uuid
from collections.abc import Awaitable, Callable
from typing import Annotated, Protocol, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

from cognic_agentos.core.approval._types import (
    ApprovalActor,
    ApprovalFlow,
    ApprovalRequestNotFound,
    ApprovalState,
    ApprovalTransitionRefused,
)
from cognic_agentos.core.approval.assignments import (
    ApprovalAssignment,
    ApprovalAssignmentInvalid,
    ApprovalAssignmentStore,
)
from cognic_agentos.core.approval.engine import ApprovalEngine
from cognic_agentos.core.approval.executor import ExecutionOutcome
from cognic_agentos.core.approval.storage import (
    ApprovalCursorInvalid,
    ApprovalRequestDetail,
    ApprovalRequestStore,
    ApprovalRequestSummary,
)
from cognic_agentos.portal.api.approvals.dto import (
    ApprovalActionResponse,
    ApprovalDetailResponse,
    ApprovalSummaryResponse,
    AssignmentRequest,
    AssignmentResponse,
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

#: Wire mapping for the 15-value ApprovalTransitionRefusedReason (_types.py:39;
#: HP-4 added approval_originator_mismatch -> 403; the 2026-07-16 maker-checker
#: amendment added originator_cannot_approve -> 409; D2 phase B adds
#: approval_consumed -> 409). Pinned EXACTLY by
#: test_every_transition_reason_has_a_status_mapping via typing.get_args — a
#: 16th engine reason fails the test until mapped here.
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
    "approval_originator_mismatch": 403,
    "originator_cannot_approve": 409,
    "approver_not_assigned": 409,
    "approver_not_distinct": 409,
    "approval_consumed": 409,
}

# A final decision retry can fail before the state-machine's terminal-state
# check: the engine's established duplicate-decider precedence fires first for
# an approver who already participated. These three reasons alone are eligible
# for stored-result recovery; maker-checker, scope, assignment and reason-policy
# refusals must remain refusals even when the request is already final.
_FINAL_EXECUTION_RETRY_REASONS = frozenset(
    {
        "approval_already_finalized",
        "four_eyes_approver_not_distinct",
        "approver_not_distinct",
    }
)


class _ApprovalExecutor(Protocol):
    async def supports_request(self, *, request_id: uuid.UUID, tenant_id: str) -> bool: ...

    async def execute_granted(
        self, *, request_id: uuid.UUID, tenant_id: str
    ) -> ExecutionOutcome: ...

    async def post_denied(
        self,
        *,
        request_id: uuid.UUID,
        tenant_id: str,
        approver_subject: str,
        reason: str,
    ) -> bool: ...


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
    after: Callable[[ApprovalState], Awaitable[ExecutionOutcome | None]] | None = None,
    recover: Callable[
        [ApprovalTransitionRefused],
        Awaitable[tuple[ApprovalState, ExecutionOutcome] | None],
    ]
    | None = None,
) -> ApprovalActionResponse:
    """Shared refusal-dispatch for the three decision verbs. The ENGINE is
    authoritative for tenant-binding / scope-per-tier / human-only / state /
    expiry / 4-eyes / reason-policy — the portal only maps refusals onto HTTP.

    Mutually-exclusive log contract (spec §4): exactly ONE route-level log per
    request — green ``portal.approvals.<verb>`` OR refused
    ``portal.approvals.<verb>_refused``; dep-chain refusals emit ZERO
    route-level logs (the sibling guard's _emit_denial_or_500 carries that axis).
    """
    execution: ExecutionOutcome | None = None
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
        recovered = await recover(exc) if recover is not None else None
        if recovered is None:
            _LOG.warning(
                f"portal.approvals.{verb}_refused",
                extra={"reason": exc.reason, "actor_subject": actor.subject},
            )
            raise HTTPException(
                status_code=_REFUSAL_STATUS[exc.reason], detail={"reason": exc.reason}
            ) from None
        state, execution = recovered
    else:
        execution = await after(state) if after is not None else None
    _LOG.info(
        f"portal.approvals.{verb}",
        extra={"actor_subject": actor.subject, "request_id": str(request_id), "state": state},
    )
    return ApprovalActionResponse(request_id=request_id, state=state, execution=execution)


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
        decisions_recorded=s.decisions_recorded,
        required_count=s.required_count,
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
        decisions_recorded=d.decisions_recorded,
        required_count=d.required_count,
        created_at=d.created_at.isoformat(),
        expires_at=d.expires_at.isoformat(),
    )


def _assignment_dto(assignment: ApprovalAssignment) -> AssignmentResponse:
    return AssignmentResponse(
        tool_identity=assignment.tool_identity,
        approver_subjects=assignment.approver_subjects,
        required_count=assignment.required_count,
        updated_by=assignment.updated_by,
        updated_at=assignment.updated_at.isoformat(),
    )


def build_approval_routes(
    *,
    store: ApprovalRequestStore,
    engine: ApprovalEngine,
    assignments: ApprovalAssignmentStore | None = None,
    executor_provider: Callable[[], _ApprovalExecutor | None] | None = None,
) -> APIRouter:
    router = APIRouter(prefix="/api/v1/approvals", tags=["approvals"])
    _require_observe = RequireScope("tool.approve.observe")
    _require_assign = RequireScope("tool.approve.assign")
    _require_human = RequireHumanActor()

    async def _execute_if_final(
        *, request_id: uuid.UUID, tenant_id: str, state: ApprovalState
    ) -> ExecutionOutcome | None:
        if state != "granted" or executor_provider is None:
            return None
        executor = executor_provider()
        if executor is None or not await executor.supports_request(
            request_id=request_id,
            tenant_id=tenant_id,
        ):
            return None
        return await executor.execute_granted(
            request_id=request_id,
            tenant_id=tenant_id,
        )

    async def _recover_final_execution(
        *,
        refusal: ApprovalTransitionRefused,
        request_id: uuid.UUID,
        tenant_id: str,
    ) -> tuple[ApprovalState, ExecutionOutcome] | None:
        """Retry a post-commit final grant through stored-result recovery."""

        if refusal.reason not in _FINAL_EXECUTION_RETRY_REASONS:
            return None
        current = await engine.check(request_id=request_id, tenant_id=tenant_id)
        if current.state != "granted":
            return None
        execution = await _execute_if_final(
            request_id=request_id,
            tenant_id=tenant_id,
            state="granted",
        )
        return None if execution is None else ("granted", execution)

    @router.get(
        "/",
        response_model=list[ApprovalSummaryResponse],
        responses={
            200: {
                "headers": {
                    "Link": {
                        "description": (
                            "Present when more actionable requests exist: a RELATIVE "
                            "continuation `</api/v1/approvals/?cursor=<opaque>&limit=<n>>; "
                            'rel="next"`. Clients extract only the opaque cursor and '
                            "reconstruct the allow-listed request themselves."
                        ),
                        "schema": {"type": "string"},
                    }
                }
            },
            422: {"description": 'Invalid cursor: `{"detail": {"reason": "cursor_invalid"}}`.'},
        },
    )
    async def list_queue(
        request: Request,
        response: Response,
        actor: Annotated[Actor, Depends(_require_observe)],
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        cursor: Annotated[str | None, Query()] = None,
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
        # HP-4: the route owns the wire bounds (Query ge/le above); the body
        # stays list[...] — pagination rides the RELATIVE Link header only.
        try:
            page = await store.list_pending(actor.tenant_id, limit=limit, cursor=cursor)
        except ApprovalCursorInvalid:
            raise HTTPException(status_code=422, detail={"reason": "cursor_invalid"}) from None
        if page.next_cursor is not None:
            response.headers["Link"] = (
                f'</api/v1/approvals/?cursor={page.next_cursor}&limit={limit}>; rel="next"'
            )
        return [_summary_dto(r) for r in page.items]

    if assignments is not None:

        @router.put(
            "/assignments/{tool_identity:path}",
            response_model=AssignmentResponse,
        )
        async def put_assignment(
            tool_identity: str,
            body: AssignmentRequest,
            request: Request,
            actor: Annotated[Actor, Depends(_require_assign)],
            _human: Annotated[Actor, Depends(_require_human)],
        ) -> AssignmentResponse:
            try:
                assignment = await assignments.assign_record(
                    tenant_id=actor.tenant_id,
                    tool_identity=tool_identity,
                    approver_subjects=tuple(body.approver_subjects),
                    actor=_to_approval_actor(actor),
                    request_request_id=_resolve_request_id(request),
                )
            except ApprovalAssignmentInvalid as exc:
                _LOG.warning(
                    "portal.approvals.assignment_change_refused",
                    extra={
                        "reason": exc.reason,
                        "actor_subject": actor.subject,
                        "tool_identity": tool_identity,
                    },
                )
                raise HTTPException(status_code=422, detail={"reason": exc.reason}) from None
            _LOG.info(
                "portal.approvals.assignment_changed",
                extra={
                    "action": "assign",
                    "actor_subject": actor.subject,
                    "tool_identity": tool_identity,
                    "required_count": assignment.required_count,
                },
            )
            return _assignment_dto(assignment)

        @router.get(
            "/assignments/{tool_identity:path}",
            response_model=AssignmentResponse,
        )
        async def get_assignment(
            tool_identity: str,
            actor: Annotated[Actor, Depends(_require_observe)],
        ) -> AssignmentResponse:
            assignment = await assignments.load(
                tenant_id=actor.tenant_id, tool_identity=tool_identity
            )
            if assignment is None:
                raise HTTPException(
                    status_code=404,
                    detail={"reason": "approval_assignment_not_found"},
                )
            return _assignment_dto(assignment)

        @router.delete(
            "/assignments/{tool_identity:path}",
            status_code=204,
        )
        async def delete_assignment(
            tool_identity: str,
            request: Request,
            actor: Annotated[Actor, Depends(_require_assign)],
            _human: Annotated[Actor, Depends(_require_human)],
        ) -> Response:
            try:
                deleted = await assignments.unassign(
                    tenant_id=actor.tenant_id,
                    tool_identity=tool_identity,
                    actor=_to_approval_actor(actor),
                    request_request_id=_resolve_request_id(request),
                )
            except ApprovalAssignmentInvalid as exc:
                _LOG.warning(
                    "portal.approvals.assignment_change_refused",
                    extra={
                        "reason": exc.reason,
                        "actor_subject": actor.subject,
                        "tool_identity": tool_identity,
                    },
                )
                raise HTTPException(status_code=422, detail={"reason": exc.reason}) from None
            if not deleted:
                raise HTTPException(
                    status_code=404,
                    detail={"reason": "approval_assignment_not_found"},
                )
            _LOG.info(
                "portal.approvals.assignment_changed",
                extra={
                    "action": "unassign",
                    "actor_subject": actor.subject,
                    "tool_identity": tool_identity,
                    "required_count": 0,
                },
            )
            return Response(status_code=204)

    @router.get("/{request_id}", response_model=ApprovalDetailResponse)
    async def get_detail(
        request_id: uuid.UUID,
        actor: Annotated[Actor, Depends(_require_observe)],
    ) -> ApprovalDetailResponse:
        detail = await store.load_detail(request_id=request_id, tenant_id=actor.tenant_id)
        if detail is None:
            raise HTTPException(status_code=404, detail={"reason": "approval_request_not_found"})
        return _detail_dto(detail)

    @router.post(
        "/{request_id}/grant",
        response_model=ApprovalActionResponse,
        response_model_exclude_none=True,
    )
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
            after=lambda state: _execute_if_final(
                request_id=request_id,
                tenant_id=actor.tenant_id,
                state=state,
            ),
            recover=lambda refusal: _recover_final_execution(
                refusal=refusal,
                request_id=request_id,
                tenant_id=actor.tenant_id,
            ),
        )

    @router.post(
        "/{request_id}/grant-second",
        response_model=ApprovalActionResponse,
        response_model_exclude_none=True,
    )
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
            after=lambda state: _execute_if_final(
                request_id=request_id,
                tenant_id=actor.tenant_id,
                state=state,
            ),
            recover=lambda refusal: _recover_final_execution(
                refusal=refusal,
                request_id=request_id,
                tenant_id=actor.tenant_id,
            ),
        )

    @router.post(
        "/{request_id}/deny",
        response_model=ApprovalActionResponse,
        response_model_exclude_none=True,
    )
    async def deny(
        request_id: uuid.UUID,
        body: DenyRequest,
        actor: Annotated[Actor, Depends(_require_human)],
    ) -> ApprovalActionResponse:
        async def _post_denial(state: ApprovalState) -> ExecutionOutcome | None:
            if state != "denied" or executor_provider is None:
                return None
            executor = executor_provider()
            if executor is not None and await executor.supports_request(
                request_id=request_id,
                tenant_id=actor.tenant_id,
            ):
                await executor.post_denied(
                    request_id=request_id,
                    tenant_id=actor.tenant_id,
                    approver_subject=actor.subject,
                    reason=body.reason,
                )
            return None

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
            after=_post_denial,
        )

    return router
