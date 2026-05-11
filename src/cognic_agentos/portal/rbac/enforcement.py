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
from collections.abc import Callable
from typing import Annotated, Literal

from fastapi import Depends, HTTPException, Request

from cognic_agentos.portal.rbac.actor import (
    Actor,
    ActorBinder,
    ActorBinderUnauthenticated,
)
from cognic_agentos.portal.rbac.scopes import PackRBACScope

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


def _emit_denial_log(
    *,
    reason: RBACDenialReason,
    required_scope: PackRBACScope | None = None,
    actor_subject: str | None = None,
) -> None:
    """Application-logging emit path for RBAC denials.

    Plan Round 5 P3 #5 placeholder — full hash-chain emission ships in
    Sprint 7B.4. For 7B.2 this records the denial to the SIEM-fed
    logging stack with structured ``extra`` so log-search queries can
    filter on ``reason`` / ``required_scope`` / ``actor_subject`` without
    string parsing.

    ``required_scope`` is included only when the scope is known at the
    emit site — i.e. for the ``scope_not_held`` reason emitted by
    :func:`RequireScope`. The two auth-related reasons (emitted by
    :func:`_bind_actor`) cannot know which scope the caller wanted,
    so the field is omitted there.
    """
    extra: dict[str, object] = {"reason": reason}
    if required_scope is not None:
        extra["required_scope"] = required_scope
    if actor_subject is not None:
        extra["actor_subject"] = actor_subject
    _LOG.warning("portal.rbac.denied", extra=extra)


def _bind_actor(request: Request) -> Actor:
    """Shared actor-binding dependency.

    Resolves :class:`ActorBinder` from ``request.app.state.actor_binder``,
    calls ``.bind(request=request)``, and surfaces the two auth-related
    :data:`RBACDenialReason` values:

    - :class:`ActorBinderUnauthenticated` → 403 ``actor_unauthenticated``.
    - :class:`NotImplementedError` (kernel-default binder) → 500
      ``actor_binder_not_configured``.

    Used by :func:`RequireScope` and
    :func:`~cognic_agentos.portal.rbac.tenant_isolation.RequireTenantOwnership`
    via ``Depends(_bind_actor)``. FastAPI caches dependencies by callable
    identity within a request, so the binder is invoked once even when
    both gates run on the same route.

    Scope-membership refusal lives in :func:`RequireScope`, NOT here —
    keeping the two concerns separate so tenant-isolation can reuse the
    binding without a redundant scope check.
    """
    binder: ActorBinder | None = getattr(request.app.state, "actor_binder", None)
    if binder is None:
        _emit_denial_log(reason="actor_binder_not_configured")
        raise HTTPException(
            status_code=500,
            detail={"reason": "actor_binder_not_configured"},
        )
    try:
        return binder.bind(request=request)
    except ActorBinderUnauthenticated:
        _emit_denial_log(reason="actor_unauthenticated")
        raise HTTPException(
            status_code=403,
            detail={"reason": "actor_unauthenticated"},
        ) from None
    except NotImplementedError:
        # Kernel-default binder still in place — bank overlay forgot to
        # inject a real binder via ``create_app(actor_binder=...)``.
        _emit_denial_log(reason="actor_binder_not_configured")
        raise HTTPException(
            status_code=500,
            detail={"reason": "actor_binder_not_configured"},
        ) from None


def RequireScope(scope: PackRBACScope) -> Callable[..., Actor]:
    """FastAPI dependency factory — admit the request iff the bound
    :class:`Actor` holds ``scope``.

    Resolves :class:`ActorBinder` from ``request.app.state.actor_binder``
    (set by ``create_app(actor_binder=...)``) and calls ``.bind(request=
    request)``. Three exception classes drive the three closed-enum
    :data:`RBACDenialReason` values:

    - :class:`ActorBinderUnauthenticated` (real binder, per-request auth
      failure) → 403 ``actor_unauthenticated``.
    - :class:`NotImplementedError` (kernel-default binder still plugged
      in — bank overlay never injected a real one) → 500
      ``actor_binder_not_configured``. Distinct from 403 so a client
      cannot mistake kernel-misconfig for an auth failure that retrying
      with different credentials might fix.
    - Scope-membership miss → 403 ``scope_not_held`` with the missing
      scope + actor subject in the response body so callers can trace
      the denial without re-binding.

    Returns the bound :class:`Actor` on success so downstream handlers
    (T4-T6 endpoints) can consume the resolved identity without
    re-binding.
    """

    def dependency(actor: Annotated[Actor, Depends(_bind_actor)]) -> Actor:
        if scope not in actor.scopes:
            _emit_denial_log(
                reason="scope_not_held",
                required_scope=scope,
                actor_subject=actor.subject,
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
