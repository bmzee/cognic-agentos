"""Sprint-7B.4 T11 — POST /api/v1/ui/actions per ADR-020 §22.

Single POST endpoint accepting a Pydantic v2 discriminated-union body
(``ActionRequest`` with 6 ``action_class`` variants), dispatched via:

  1. ``RequireUIAction(broker)`` FastAPI dep — parses body + binds
     actor + maps ``action_class`` → ``ui.action.<class>`` required
     scope + enforces + emits ``policy.rbac_denied`` on miss +
     returns :class:`UIActionContext`.
  2. ``broker.append_frontend_action_submitted(...)`` — always (audit
     completeness; chain row pinned BEFORE dispatch so the resolution
     row can carry its event_id as the ``submitted_event_id`` cursor).
  3. Per-class dispatch:
       - ``submit_elicitation`` → :func:`evaluate_elicitation_submission`
         (T8 gate); green-path calls ``adapter.handle_submission``;
         rejected/exception paths emit
         ``frontend_action.rejected`` with the closed-enum reason.
       - 5 stub paths (approve / deny / cancel_run / interrupt /
         resume) emit ``frontend_action.rejected`` with the matching
         ``action_backend_deferred_*`` closed-enum reason (deferred to
         later sprints per the ``_STUB_REASONS`` mapping below).
  4. Response body :class:`ActionResponse` carries the deterministic
     ``submitted_event_id`` + ``resolution_event_id`` cursors so SSE
     consumers can reconcile the POST + stream without a round-trip.

**P1 #2 scope lock:** ``RequireUIAction`` lives HERE (in
``action_routes.py``), NOT in ``dto.py``. The dep is FastAPI + broker
+ RBAC coupled; placing it in the type-only DTO module would drag
route deps into the wire-types module and break the NOT-CC
classification on dto.py.

**T7/T8 forward watchpoint honored:** :class:`ElicitationAdapter` is
``@runtime_checkable`` but isinstance only checks method-presence
(not signature/asyncness). The action handler does NOT isinstance-
check the adapter; the authoritative shape check is at the
``await adapter.handle_submission(...)`` call site — duck typing
through the actual call surfaces any signature drift via
:exc:`TypeError` or :exc:`AttributeError`, which the wrapping
``try/except Exception`` translates to ``elicitation_backend_failed``.

NOTE: ``from __future__ import annotations`` is DELIBERATELY OMITTED
(standing-offer invariant for FastAPI route modules with
``Annotated[..., Depends(closure-local)]`` deps; same as
``stream_routes.py`` / ``operator_routes.py``)."""

import hashlib
import logging
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.policy.engine import OPAEngine
from cognic_agentos.portal.api.ui.dto import (
    ActionClass,
    ActionOutcome,
    ActionRejectionReason,
    ActionRequest,
    ActionResponse,
    UIActionContext,
)
from cognic_agentos.portal.api.ui.elicitation_gate import (
    evaluate_elicitation_submission,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import _bind_actor, _emit_denial_or_500
from cognic_agentos.protocol.elicitation_adapter import ElicitationAdapter
from cognic_agentos.protocol.ui_events import AppendResult, UIEventBroker

_LOG = logging.getLogger(__name__)


#: Closed-enum mapping from non-submit_elicitation ``action_class``
#: to the deferred-stub ``ActionRejectionReason``. The mapping is
#: wire-protocol-public — bank-overlay clients receive the reason on
#: ``ActionResponse.reason`` AND the chain row's
#: ``frontend_action.rejected`` payload. Mapping rationale:
#:
#:   - ``approve`` / ``deny`` → ``action_backend_deferred_to_sprint_13_5``:
#:     the approval-engine primitive lands at Sprint 13.5 per ADR-014.
#:   - ``cancel_run`` / ``interrupt`` → ``action_backend_deferred_no_run_primitive``:
#:     no ``agent_run`` primitive in Wave 1; lands at Sprint 11.5.
#:   - ``resume`` → ``action_backend_deferred_sandbox_unwired``:
#:     sandbox resume primitive lands at Sprint 8.
#:
#: ``submit_elicitation`` is NOT in this map — it routes through the
#: T8 elicitation gate + adapter.handle_submission call.
_STUB_REASONS: dict[ActionClass, ActionRejectionReason] = {
    "approve": "action_backend_deferred_to_sprint_13_5",
    "deny": "action_backend_deferred_to_sprint_13_5",
    "cancel_run": "action_backend_deferred_no_run_primitive",
    "interrupt": "action_backend_deferred_no_run_primitive",
    "resume": "action_backend_deferred_sandbox_unwired",
}


def _payload_digest(body: ActionRequest) -> str:
    """``sha256`` of ``canonical_bytes`` of the validated DTO (post-
    Pydantic-parse) per spec §4.4g.

    Sensitive fields (URL completion signals, form payloads) enter the
    hash but NEVER appear plaintext in the chain row — the payload
    digest is the audit handle that examiners use to detect tampering
    without ever seeing the cleartext content."""
    return f"sha256:{hashlib.sha256(canonical_bytes(body.model_dump(mode='json'))).hexdigest()}"


def RequireUIAction(
    broker: UIEventBroker,
) -> Any:
    """FastAPI dep factory: parses body + binds actor + enforces
    ``ui.action.<class>`` scope + returns :class:`UIActionContext`.

    P1 #2: this dep LIVES HERE (action_routes.py), NOT in dto.py —
    the dep is FastAPI + broker + RBAC coupled; dto.py is type-only.

    On scope miss:
      - Delegates to :func:`_emit_denial_or_500` for the dual-surface
        emission contract (log FIRST, broker SECOND, 500
        ``rbac_denial_emit_failed`` on broker exception). The
        ``_emit_denial_or_500`` helper handles the log itself — DO
        NOT add a manual ``_LOG.warning`` here (would double-log).
      - Raises ``HTTPException(403)`` with
        ``{"reason": "scope_not_held", "required_scope": <scope>}``.

    Returns: :class:`UIActionContext` carrying body + actor + request_id.
    """

    async def _resolve(
        request: Request,
        body: Annotated[ActionRequest, Body(...)],
        actor: Annotated[Actor, Depends(_bind_actor)],
    ) -> UIActionContext:
        request_id = request.state.request_id
        required_scope = f"ui.action.{body.action_class}"
        if required_scope not in actor.scopes:
            # Dual-surface emission: log + broker chain row. The
            # helper raises HTTPException(500, "rbac_denial_emit_failed")
            # if broker.emit_rbac_denial fails — propagates up; the
            # 403 raise below is unreached on emit failure (correct
            # fail-closed behavior).
            await _emit_denial_or_500(
                broker,
                denial_type="scope_not_held",
                actor_subject=actor.subject,
                tenant_id=actor.tenant_id,
                request_id=request_id,
                http_status=403,
                required_scope=required_scope,
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "reason": "scope_not_held",
                    "required_scope": required_scope,
                },
            )
        return UIActionContext(body=body, actor=actor, request_id=request_id)

    return _resolve


def build_action_routes(
    *,
    broker: UIEventBroker,
    elicitation_adapter: ElicitationAdapter | None = None,
    rego_engine: OPAEngine | None = None,
) -> APIRouter:
    """Build the POST /actions router with closure-captured deps.

    ``elicitation_adapter`` and ``rego_engine`` are optional —
    submit_elicitation routes that lack either MUST surface the
    matching ``elicitation_backend_unwired`` / ``elicitation_unwired_evaluator``
    closed-enum reason per the T8 gate's Step 1 / Step 5 refusals.

    The returned :class:`APIRouter` carries ONE POST endpoint at
    ``/actions``; the caller MUST include it under ``/api/v1/ui``
    (the prefix is owned by ``create_app``'s mounting block, not this
    factory)."""
    router = APIRouter()
    _require_ui_action = RequireUIAction(broker)

    @router.post("/actions", response_model=ActionResponse, status_code=200)
    async def submit_action(
        ctx: Annotated[UIActionContext, Depends(_require_ui_action)],
    ) -> ActionResponse:
        body = ctx.body
        actor = ctx.actor
        request_id = ctx.request_id
        digest = _payload_digest(body)

        # Step 2: append frontend_action.submitted ALWAYS (audit
        # completeness; pinned BEFORE dispatch so the resolution row's
        # ``submitted_event_id`` cursor references this row's
        # deterministic event_id).
        submitted: AppendResult = await broker.append_frontend_action_submitted(
            request_id=request_id,
            action_class=body.action_class,
            actor_subject=actor.subject,
            client_correlation_id=body.client_correlation_id,
            payload_digest=digest,
            tenant_id=actor.tenant_id,
            elicitation_mode=(body.mode if body.action_class == "submit_elicitation" else None),
        )

        # Step 3-4: per-class dispatch.
        if body.action_class == "submit_elicitation":
            return await _dispatch_submit_elicitation(
                body=body,
                actor=actor,
                request_id=request_id,
                submitted=submitted,
                broker=broker,
                elicitation_adapter=elicitation_adapter,
                rego_engine=rego_engine,
            )

        # 5 stub paths — emit frontend_action.rejected with the
        # mapped ``action_backend_deferred_*`` reason; return 200.
        stub_reason = _STUB_REASONS[body.action_class]
        resolution = await broker.append_frontend_action_rejected(
            request_id=request_id,
            action_class=body.action_class,
            actor_subject=actor.subject,
            client_correlation_id=body.client_correlation_id,
            submitted_event_id=submitted.event_id,
            reason=stub_reason,
            tenant_id=actor.tenant_id,
        )
        return _build_response(
            request_id=request_id,
            body=body,
            outcome="rejected",
            reason=stub_reason,
            submitted_event_id=submitted.event_id,
            resolution_event_id=resolution.event_id,
        )

    return router


async def _dispatch_submit_elicitation(
    *,
    body: Any,  # SubmitElicitationActionRequest — Any keeps the import surface narrow
    actor: Actor,
    request_id: str,
    submitted: AppendResult,
    broker: UIEventBroker,
    elicitation_adapter: ElicitationAdapter | None,
    rego_engine: OPAEngine | None,
) -> ActionResponse:
    """Routes a submit_elicitation request through the T8 gate +
    (on green) the adapter ``handle_submission`` call.

    Emit invariants:
      - Gate refusal → ``frontend_action.rejected`` with the gate's
        closed-enum ``reason``; ``originating_decision_record_id``
        threaded onto the payload when the gate resolved a context
        (Steps 3+; Step 1/2 refusals have ctx=None).
      - Backend exception AFTER gate-green →
        ``frontend_action.rejected`` with reason
        ``elicitation_backend_failed`` (distinct from gate refusals so
        operators can tell "gate refused" apart from "backend rejected"
        in audit logs).
      - Backend success → ``frontend_action.accepted`` with
        ``originating_decision_record_id`` from the gate's context."""
    gate = await evaluate_elicitation_submission(
        request=body,
        actor=actor,
        adapter=elicitation_adapter,
        rego_engine=rego_engine,
    )
    if not gate.allowed:
        assert gate.reason is not None  # gate contract: not allowed → reason set
        resolution = await broker.append_frontend_action_rejected(
            request_id=request_id,
            action_class=body.action_class,
            actor_subject=actor.subject,
            client_correlation_id=body.client_correlation_id,
            submitted_event_id=submitted.event_id,
            reason=gate.reason,
            tenant_id=actor.tenant_id,
            elicitation_mode=body.mode,
            originating_decision_record_id=(
                str(gate.ctx.originating_decision_record_id) if gate.ctx else None
            ),
        )
        return _build_response(
            request_id=request_id,
            body=body,
            outcome="rejected",
            reason=gate.reason,
            submitted_event_id=submitted.event_id,
            resolution_event_id=resolution.event_id,
        )

    # Gate green — adapter is non-None (Step 1 of the gate would have
    # refused on adapter=None); ctx is non-None (Step 2). Call
    # ``adapter.handle_submission``; any exception surfaces as
    # ``elicitation_backend_failed``.
    assert elicitation_adapter is not None  # narrowed by gate Step 1
    assert gate.ctx is not None  # narrowed by gate Step 2
    payload = body.form_payload if body.mode == "form" else body.url_completion_signal
    try:
        await elicitation_adapter.handle_submission(
            ctx=gate.ctx,
            mode=body.mode,
            payload=payload or {},
        )
    except Exception:
        _LOG.error("ui.elicitation.handle_submission_failed", exc_info=True)
        resolution = await broker.append_frontend_action_rejected(
            request_id=request_id,
            action_class=body.action_class,
            actor_subject=actor.subject,
            client_correlation_id=body.client_correlation_id,
            submitted_event_id=submitted.event_id,
            reason="elicitation_backend_failed",
            tenant_id=actor.tenant_id,
            elicitation_mode=body.mode,
            originating_decision_record_id=str(gate.ctx.originating_decision_record_id),
        )
        return _build_response(
            request_id=request_id,
            body=body,
            outcome="rejected",
            reason="elicitation_backend_failed",
            submitted_event_id=submitted.event_id,
            resolution_event_id=resolution.event_id,
        )

    # Backend success.
    resolution = await broker.append_frontend_action_accepted(
        request_id=request_id,
        action_class=body.action_class,
        actor_subject=actor.subject,
        client_correlation_id=body.client_correlation_id,
        submitted_event_id=submitted.event_id,
        tenant_id=actor.tenant_id,
        elicitation_mode=body.mode,
        originating_decision_record_id=str(gate.ctx.originating_decision_record_id),
    )
    return _build_response(
        request_id=request_id,
        body=body,
        outcome="accepted",
        reason=None,
        submitted_event_id=submitted.event_id,
        resolution_event_id=resolution.event_id,
    )


def _build_response(
    *,
    request_id: str,
    body: ActionRequest,
    outcome: ActionOutcome,
    reason: ActionRejectionReason | None,
    submitted_event_id: str,
    resolution_event_id: str,
) -> ActionResponse:
    """Build an :class:`ActionResponse` from the per-dispatch outputs.

    ``outcome`` is typed as the closed-enum :data:`ActionOutcome`
    Literal (``"accepted" | "rejected"``) per R3 P2 review — typing
    here is the static guard that catches typos at mypy time rather
    than letting a typo propagate to Pydantic runtime validation."""
    return ActionResponse(
        request_id=request_id,
        action_class=body.action_class,
        outcome=outcome,
        reason=reason,
        submitted_at=datetime.now(UTC),
        submitted_event_id=submitted_event_id,
        resolution_event_id=resolution_event_id,
        client_correlation_id=body.client_correlation_id,
    )


__all__ = [
    "RequireUIAction",
    "build_action_routes",
]


# Suppress unused-import lint warning — JSONResponse is imported so
# the future error-handling extension is one edit; not referenced now.
_ = JSONResponse
