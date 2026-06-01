"""Sprint 7B.2 T2 — :class:`RequireScope` FastAPI dependency + closed-enum :data:`RBACDenialReason`.

Plan Round 2 P2 #4 narrowing (STRUCTURED HTTP DENIAL ONLY in 7B.2):

RBAC denials emit a structured HTTP response (403 / 500 with a closed-enum
``reason`` in the body) plus a structured log record at the application-
logging layer for SIEM correlation. They DO NOT emit hash-chained audit
events in 7B.2 — that integration ships in Sprint 7B.4 per plan Round 5
P3 #5 alongside the ADR-020 UI event-taxonomy extension; the denial-event
schema fits the ``policy.*`` event family slot already reserved in
:file:`src/cognic_agentos/protocol/ui_events.py`.

The 7B.2 audit-chain remains the system-of-record for STATE TRANSITIONS
only. The access-control gate emits to the logging stack so SIEM
correlation still works without a chain-row write.

Three closed-enum :data:`RBACDenialReason` values cover the three failure
modes — each with a real emit path:

- ``scope_not_held``           ← scope-membership-check miss
- ``actor_unauthenticated``    ← :class:`ActorBinderUnauthenticated` catch
- ``actor_binder_not_configured`` ← :class:`NotImplementedError` catch
  from :class:`~cognic_agentos.portal.rbac.actor.KernelDefaultActorBinder`
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Annotated, Any, Literal

from fastapi import Depends, HTTPException, Request

from cognic_agentos.portal.rbac.actor import (
    Actor,
    ActorBinder,
    ActorBinderUnauthenticated,
)
from cognic_agentos.portal.rbac.scopes import (
    ComplianceRBACScope,
    MemoryRBACScope,
    ModelRBACScope,
    PackRBACScope,
    UIRBACScope,
)

if TYPE_CHECKING:
    from cognic_agentos.protocol.ui_events import RBACDenialType, UIEventBroker

_LOG = logging.getLogger(__name__)


#: Closed-enum vocabulary for portal RBAC denial bodies. Every 403 / 500
#: denial response carries one of these values in ``detail.reason``.
#:
#: Plan Round 2 P2 #4: 7B.2 emits these via structured HTTP + a structured
#: log record. Hash-chained ``policy.rbac_denied`` events ship in
#: Sprint 7B.4 alongside the ADR-020 UI event-taxonomy extension.
#:
#: Style note: plain ``= Literal[...]`` (no ``TypeAlias`` annotation) to
#: match the Sprint-7B.1 repo convention at ``packs/lifecycle.py:111``.
RBACDenialReason = Literal[
    "actor_unauthenticated",
    "scope_not_held",
    "actor_binder_not_configured",
]


def _resolve_request_id(request: Request) -> str:
    """Resolve a request_id from `request.state.request_id` (set by the
    T6 portal request-id middleware on every `/api/v1/*` path). Mints a
    `portal-rbac-denial-<uuid4>` fallback if unset — should never fire
    under normal portal traffic but covers non-portal callers that
    bypass the middleware (52 chars ≤ 64 column cap).
    """
    return getattr(request.state, "request_id", None) or f"portal-rbac-denial-{uuid.uuid4().hex}"


async def _emit_denial_or_500(
    broker: UIEventBroker | None,
    *,
    denial_type: RBACDenialType,
    actor_subject: str | None,
    tenant_id: str | None,
    request_id: str,
    http_status: int,
    required_scope: str | None = None,
    pack_id: str | None = None,
    actor_type: str | None = None,
    pack_created_by: str | None = None,
    resource_type: str | None = None,
) -> None:
    """Sprint-7B.4 T6 shared dual-surface emission helper.

    Used by :func:`_bind_actor` + the 4 `Require*` deps across the RBAC
    modules (enforcement, tenant_isolation, human_actor, role_separation).
    The kwargs match :meth:`UIEventBroker.emit_rbac_denial` 1:1.

    Emission order — log FIRST (operations surface, guaranteed), broker
    SECOND (examiner surface, conditional):

      1. ``_LOG.warning(f"portal.rbac.{denial_type}", extra={"reason", "actor_subject",
         "tenant_id", "request_id", "http_status", ...optional...})`` — wire
         shape: the log message itself encodes the denial_type so log routing /
         alerting can key on the constant suffix. ALWAYS fires.

      2. If ``broker is None`` → return (R3 #3 backward-compat: pack-only
         deployments that omit the new optional deps to ``create_app`` stay
         green; structured log preserves the operations surface).

      3. ``await broker.emit_rbac_denial(...)`` — chain row append. Failure
         raises ``HTTPException(500, detail={"reason": "rbac_denial_emit_failed"})``
         (NO silent audit loss — fail-closed per the P1 fail-closed contract;
         pinned by the threat-model-revert regression in
         ``test_rbac_denial_chain_emission.py``).

    `tenant_id` contract (per design spec P1 #5):
      - actor IS resolved at the call site → pass ``actor.tenant_id``.
      - actor is UNRESOLVED (the 2 ``_bind_actor`` failure paths —
        actor_unauthenticated, actor_binder_not_configured) → pass
        ``tenant_id=None``. The chain row writes (audit surface preserved);
        SSE subscribers filter by event.tenant so unauth denials never
        reach any tenant's stream by design.
    """
    log_extra: dict[str, Any] = {
        "reason": denial_type,
        "actor_subject": actor_subject,
        "tenant_id": tenant_id,
        "request_id": request_id,
        "http_status": http_status,
    }
    if required_scope is not None:
        log_extra["required_scope"] = required_scope
    if pack_id is not None:
        log_extra["pack_id"] = pack_id
    if actor_type is not None:
        log_extra["actor_type"] = actor_type
    if pack_created_by is not None:
        log_extra["pack_created_by"] = pack_created_by
    if resource_type is not None:
        log_extra["resource_type"] = resource_type
    _LOG.warning(f"portal.rbac.{denial_type}", extra=log_extra)

    if broker is None:  # R3 #3 backward-compat: pack-only deployments
        return

    try:
        await broker.emit_rbac_denial(
            denial_type=denial_type,
            actor_subject=actor_subject,
            tenant_id=tenant_id,
            request_id=request_id,
            http_status=http_status,
            required_scope=required_scope,
            pack_id=pack_id,
            actor_type=actor_type,
            pack_created_by=pack_created_by,
            resource_type=resource_type,
        )
    except Exception as exc:
        _LOG.error("portal.rbac.denial_emit_failed", exc_info=True)
        raise HTTPException(
            500,
            detail={"reason": "rbac_denial_emit_failed"},
        ) from exc


async def _bind_actor(request: Request) -> Actor:
    """Sprint-7B.4 T6: async wrapper around the existing SYNC
    :meth:`ActorBinder.bind` so denial paths can ``await
    broker.emit_rbac_denial``. The binder.bind call itself stays
    synchronous — the existing :class:`ActorBinder` Protocol at
    ``portal/rbac/actor.py:122`` is sync `def bind(...)`; broadening
    it is out of scope for 7B.4.

    Resolves :class:`ActorBinder` from ``request.app.state.actor_binder``;
    surfaces the 3 closed-enum :data:`RBACDenialReason` values through
    the shared :func:`_emit_denial_or_500` helper:

    - ``binder is None`` → 500 ``actor_binder_not_configured`` (wiring miss).
    - :class:`ActorBinderUnauthenticated` → 403 ``actor_unauthenticated``.
    - :class:`NotImplementedError` (kernel-default binder) → 500
      ``actor_binder_not_configured`` (overlay never wired).

    All 3 paths pass ``tenant_id=None`` to the helper (per design spec
    P1 #5 — no actor resolved → chain row has NULL tenant_id; SSE
    subscribers filter by tenant so unauth denials never reach any
    tenant's stream).
    """
    binder: ActorBinder | None = getattr(request.app.state, "actor_binder", None)
    broker: UIEventBroker | None = getattr(request.app.state, "ui_event_broker", None)
    request_id = _resolve_request_id(request)

    if binder is None:
        await _emit_denial_or_500(
            broker,
            denial_type="actor_binder_not_configured",
            actor_subject=None,
            tenant_id=None,
            request_id=request_id,
            http_status=500,
        )
        raise HTTPException(
            status_code=500,
            detail={"reason": "actor_binder_not_configured"},
        )

    try:
        # SYNC call — preserves the existing ActorBinder Protocol contract.
        return binder.bind(request=request)
    except ActorBinderUnauthenticated:
        await _emit_denial_or_500(
            broker,
            denial_type="actor_unauthenticated",
            actor_subject=None,
            tenant_id=None,
            request_id=request_id,
            http_status=403,
        )
        raise HTTPException(
            status_code=403,
            detail={"reason": "actor_unauthenticated"},
        ) from None
    except NotImplementedError:
        # Kernel-default binder still in place — bank overlay forgot to
        # inject a real binder via ``create_app(actor_binder=...)``.
        await _emit_denial_or_500(
            broker,
            denial_type="actor_binder_not_configured",
            actor_subject=None,
            tenant_id=None,
            request_id=request_id,
            http_status=500,
        )
        raise HTTPException(
            status_code=500,
            detail={"reason": "actor_binder_not_configured"},
        ) from None


def RequireScope(
    scope: PackRBACScope | UIRBACScope | ComplianceRBACScope | ModelRBACScope | MemoryRBACScope,
) -> Callable[..., Awaitable[Actor]]:
    """FastAPI dependency factory — admit the request iff the bound
    :class:`Actor` holds ``scope``.

    Sprint-7B.4 T5 widened the scope parameter to accept both
    :data:`PackRBACScope` and :data:`UIRBACScope` (the T11 POST /actions
    + T10 SSE endpoints depend on this widening — they call
    ``RequireScope("ui.action.approve")`` etc.).

    Sprint-9 T5 further widened it with :data:`ComplianceRBACScope` so
    the ADR-006 examiner endpoints can call
    ``RequireScope("compliance.evidence_pack.read")`` etc.

    Sprint-9.5 B1 further widened it with :data:`ModelRBACScope` so the
    ADR-013 model-registry endpoints can call
    ``RequireScope("model.register")`` / ``RequireScope("model.audit.read")``
    / ``RequireScope("model.promote.<target_state>")`` etc. The body-aware
    POST /promote handler resolves the target scope per-request from the
    body's ``target_state`` and constructs a fresh ``RequireScope`` per
    target (the per-target dep itself is cheap; the actor bind is shared
    via the FastAPI sub-dep cache).

    Sprint-11.5a T12 further widened it with :data:`MemoryRBACScope` so the
    ADR-019 memory endpoints can call ``RequireScope("memory.read")`` /
    ``RequireScope("memory.write.long_term")`` etc.

    Sprint-7B.4 T6 converted the inner dependency to async so the
    denial path can ``await broker.emit_rbac_denial`` via the shared
    :func:`_emit_denial_or_500` helper. ``_bind_actor`` is also async;
    FastAPI handles async sub-deps transparently — no callsite changes
    required for existing pack-route handlers.

    Returns the bound :class:`Actor` on success so downstream handlers
    consume the resolved identity without re-binding.
    """

    async def dependency(
        request: Request,
        actor: Annotated[Actor, Depends(_bind_actor)],
    ) -> Actor:
        if scope not in actor.scopes:
            broker: UIEventBroker | None = getattr(request.app.state, "ui_event_broker", None)
            await _emit_denial_or_500(
                broker,
                denial_type="scope_not_held",
                actor_subject=actor.subject,
                tenant_id=actor.tenant_id,  # P1 #5: actor IS resolved here
                request_id=_resolve_request_id(request),
                http_status=403,
                required_scope=scope,
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "reason": "scope_not_held",
                    "required_scope": scope,
                    "actor_subject": actor.subject,
                },
            )
        return actor

    return dependency


#: Sprint 9.5 B1 — public alias for the internal :func:`_bind_actor`
#: FastAPI dependency. Body-aware authz routes (the upcoming Block-B4
#: ``POST /api/v1/models/{model_id}/promote``, where the required scope
#: depends on the request body's ``target_state``) declare
#: ``Annotated[Actor, Depends(bind_actor)]`` to receive the bound actor
#: directly without a fixed :func:`RequireScope` wrapper, then resolve
#: the per-request scope inside the handler body and apply a body-aware
#: scope check.
#:
#: **Aliased by identity rebinding** (``bind_actor = _bind_actor``), NOT
#: by a forwarding wrapper. FastAPI's sub-dep cache keys on the
#: dependency callable's identity; ``Depends(bind_actor)`` and
#: ``Depends(_bind_actor)`` resolving to the same object means a single
#: actor bind serves both the public-alias dep AND any :func:`RequireScope`
#: / :func:`RequireTenantOwnership` sub-deps on the same request — no
#: re-bind of the same Actor twice per request. Pinned by
#: :file:`tests/unit/portal/rbac/test_model_scopes.py::TestBindActorPublicAlias`.
bind_actor = _bind_actor
