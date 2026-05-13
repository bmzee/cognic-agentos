"""Sprint 7B.2 T2 — Actor model + ActorBinder Protocol + kernel-default fail-loud binder.

The portal RBAC layer treats the authenticated principal as an opaque
:class:`Actor` value object. The kernel does not assume an auth backend
(OIDC bearer / SAML / mTLS / etc.); bank overlays inject a real binder
via ``create_app(actor_binder=...)`` per ADR-008.

Closed-enum :data:`ActorType` discriminates ``"human"`` from ``"service"``;
plan Round 1 P3 #8 added this so :class:`RequireHumanActor` can gate
operator-surface endpoints that finalise per-tenant changes (specifically
``/allow-list`` — per :file:`AGENTS.md` "Per-tenant allow-list changes"
human-only-decisions rule).

Two distinct typed exceptions are intentional:

- :class:`ActorBinderUnauthenticated` — raised by a real binder when the
  request carries no resolvable auth primitive. :class:`RequireScope`
  catches it and surfaces 403 ``actor_unauthenticated`` (plan Round 3
  P2 #2 emit path).
- :class:`NotImplementedError` (from :class:`KernelDefaultActorBinder`) —
  raised when no overlay binder has been injected. :class:`RequireScope`
  catches it and surfaces 500 ``actor_binder_not_configured`` (kernel
  misconfig, NOT a client error).

Dispatching on exception class lets :class:`RequireScope` keep all three
closed-enum :data:`RBACDenialReason` values reachable through real emit
paths.
"""

from __future__ import annotations

from typing import Literal, Protocol

import pydantic
from fastapi import Request

from cognic_agentos.portal.rbac.scopes import ScopeSet

#: 2-value closed-enum actor-type discriminator per plan Round 1 P3 #8.
#:
#: Bank overlays set this when minting actor identities from the
#: underlying auth backend (OIDC token claim, mTLS cert OU, service-
#: account marker, etc.). Used by :class:`RequireHumanActor` to gate
#: operator-surface endpoints that finalise per-tenant changes
#: (specifically ``/allow-list``).
#:
#: Style note: plain ``= Literal[...]`` (no ``TypeAlias`` annotation) to
#: match the Sprint-7B.1 repo convention at ``packs/lifecycle.py:111``.
ActorType = Literal["human", "service"]


class Actor(pydantic.BaseModel):
    """Frozen actor identity bound from the incoming request.

    The bank overlay or test fixture is responsible for producing this
    from whatever auth backend the deployment uses (OIDC bearer / SAML /
    mTLS). The kernel does not assume an auth backend.

    ``frozen=True`` + ``extra="forbid"`` together pin the wire-shape:

    - Frozen so a downstream handler cannot mutate the actor mid-request
      (defence-in-depth against confused-deputy bugs).
    - ``extra="forbid"`` so a bank-overlay binder cannot smuggle extra
      claims through the model without an explicit kernel update —
      every field added here is a deliberate wire-protocol decision.
    """

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")

    subject: str
    tenant_id: str
    scopes: ScopeSet
    actor_type: ActorType


class ActorBinderUnauthenticated(Exception):
    """Plan Round 3 P2 #2 emit path for the ``actor_unauthenticated``
    :data:`RBACDenialReason` value.

    Raised by an :class:`ActorBinder.bind` implementation when the
    request carries no resolvable auth primitive (missing or invalid
    bearer token, expired session, unknown mTLS cert). The
    :class:`RequireScope` FastAPI dependency catches this exception and
    translates it to ``HTTPException(403, detail={"reason":
    "actor_unauthenticated"})`` — preserving the :data:`RBACDenialReason`
    closed-enum as the wire-protocol surface while keeping the binder's
    typed exception idiomatic with the rest of the codebase
    (:class:`~cognic_agentos.packs.lifecycle.LifecycleTransitionRefused`
    / :class:`~cognic_agentos.packs.storage.PackRecordRefused` / etc.).

    Intentionally NOT a subclass of :class:`NotImplementedError` —
    :class:`RequireScope` distinguishes per-request auth failure (403)
    from kernel-misconfig (500) by catching the two exception classes
    in separate branches.
    """


class ActorBinder(Protocol):
    """Pluggable actor-binding contract per ADR-008 production-grade-rule.

    The kernel ships only the Protocol + a fail-loud default
    (:class:`KernelDefaultActorBinder`). Production deployments inject
    an implementation that maps the request's auth primitives to an
    :class:`Actor`.

    Implementations may raise :class:`ActorBinderUnauthenticated` when
    the request has no valid auth primitive (vs
    :class:`NotImplementedError` from the kernel default binder when no
    overlay has been configured at all).
    """

    def bind(self, *, request: Request) -> Actor: ...


class KernelDefaultActorBinder:
    """Fail-loud default per ADR-008 + production-grade-rule.

    Raised at request time when no overlay binder has been injected via
    ``create_app(actor_binder=...)``. Surfaces a structured
    :class:`NotImplementedError` rather than a silent identity fallback.

    Distinct from :class:`ActorBinderUnauthenticated`: this is a
    kernel-misconfig (no binder plugged in at all), NOT a per-request
    auth failure. :class:`RequireScope` catches each in a separate
    branch so the two failure modes land on distinct
    :data:`RBACDenialReason` closed-enum values
    (``actor_binder_not_configured`` vs ``actor_unauthenticated``).
    """

    def bind(self, *, request: Request) -> Actor:
        raise NotImplementedError(
            "No ActorBinder configured per ADR-008. Bank overlays must "
            "inject an ActorBinder via create_app(actor_binder=...) "
            "before serving portal API requests. The kernel does not "
            "assume an auth backend."
        )
