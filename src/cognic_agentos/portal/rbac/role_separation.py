"""Sprint 7B.2 T5 — RequireDifferentActorThanCreator dependency + role-separation closed-enum.

Plan Round 11 P2 #4 — ADR-012 §17 cross-role separation: the same human
cannot both submit AND review their own pack. This module is the fourth
orthogonal enforcement axis alongside :class:`RequireScope` (scope
membership) + :class:`RequireTenantOwnership` (tenant boundary) +
:class:`RequireHumanActor` (actor-type).

Round 14 P2 #3 design — closure-factory pattern (function, NOT class):
the inner closure declares ``Annotated[PackRecord, Depends(tenant_ownership)]``
referring to the captured ``tenant_ownership`` factory parameter. FastAPI's
per-request callable-identity sub-dependency cache deduplicates the
PackRecord load between the endpoint's tenant-ownership declaration and
this guard's nested Depends → ONE ``store.load`` call on the happy path.

Round 15 P2 #1 — module-header invariants (CRITICAL — load-bearing for
FastAPI introspection):

1. **OMIT ``from __future__ import annotations``** — sibling RBAC modules
   carry it (``tenant_isolation.py:37``, ``human_actor.py:26``,
   ``enforcement.py:26``) but PEP 563 string-deferred annotations would
   make ``Annotated[PackRecord, Depends(tenant_ownership)]`` inside the
   inner closure unresolvable: ``tenant_ownership`` is a closure cell,
   NOT a module global, so a lazy string evaluation against module
   globals would ``NameError`` — or worse, FastAPI would silently treat
   ``record`` + ``actor`` as query params (the T4-era query-param-leakage
   bug). Live annotations let FastAPI's ``inspect.signature()`` /
   ``typing.get_type_hints()`` resolve against the function's
   ``__closure__`` cells.

2. **Type alias :data:`TenantOwnershipDep`** at module scope —
   ``Callable[..., Awaitable[PackRecord]]``. The factory parameter is
   typed against this alias because ``RequireTenantOwnership`` (the
   symbol at ``tenant_isolation.py:96``) is a factory FUNCTION, NOT a
   class — its return value is what the endpoint declares as
   ``Depends(...)``. Annotating ``tenant_ownership: RequireTenantOwnership``
   would refer to the function itself, not instances.

Round 16 P2 #3 — structured-log emission BEFORE every ``HTTPException``
raise; module-scoped ``_LOG = logging.getLogger(__name__)`` mirrors
sibling guards (``tenant_isolation._LOG`` at ``:50``,
``human_actor._LOG`` at ``:37``, ``enforcement`` likewise).

Round 11 P2 #4 wire-protocol-public closed-enum
:data:`RoleSeparationFailure` carries the 403 denial body's ``reason``
field. Any change is a wire-protocol break.
"""

# Round 15 P2 #1 — `from __future__ import annotations` INTENTIONALLY OMITTED.
# Sibling RBAC modules carry it; this module does NOT — see module docstring
# for the FastAPI closure-cell resolution rationale.
#
# Load-bearing per `feedback_security_regression_hardening.md`: TWO tests
# pin this invariant against silent regression. Each was verified to FAIL
# deterministically when this future-import is added back:
#   * `test_module_must_not_import_future_annotations` (AST self-test) —
#     catches the source-level regression.
#   * `test_role_separation_resolves_under_fastapi_introspection`
#     (FastAPI OpenAPI introspection) — catches the runtime symptom
#     (Pydantic raises PydanticUserError on the unresolved
#     `ForwardRef('Annotated[PackRecord, Depends(tenant_ownership)]')`
#     because `tenant_ownership` is a closure-local name, not a module
#     global, so the lazy-eval can't resolve it).

import logging
from collections.abc import Awaitable, Callable
from typing import Annotated, Literal

from fastapi import Depends, HTTPException

from cognic_agentos.packs.storage import PackRecord
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import _bind_actor

#: Module-scoped logger (Round 16 P2 #3). Mirrors sibling RBAC guards
#: at ``tenant_isolation._LOG`` (``:50``), ``human_actor._LOG`` (``:37``),
#: ``enforcement._emit_denial_log``. Structured-log emission BEFORE every
#: ``HTTPException`` raise so observability tooling sees the denial
#: regardless of caller HTTP-response capture.
_LOG = logging.getLogger(__name__)

#: Closed-enum literal of role-separation refusal reasons. Wire-protocol-
#: public — carried in 403 denial bodies under the ``detail.reason``
#: field. Any addition/rename/removal is a wire-protocol break per
#: AGENTS.md "Wire-protocol contracts" stop rule + the
#: ``feedback_strict_review_off_gate.md`` closed-enum stability doctrine.
#:
#: Style note: assigned as plain ``= Literal[...]`` (without
#: ``TypeAlias`` annotation) to match the Sprint-7B.1 repo convention at
#: ``packs/lifecycle.py:111`` + the T2-era closed-enum declarations in
#: ``scopes.py:41`` / ``enforcement.py`` / ``tenant_isolation.py`` /
#: ``human_actor.py``.
RoleSeparationFailure = Literal["actor_cannot_review_own_pack"]

#: Round 15 P2 #1 — type alias for the ``tenant_ownership`` factory
#: parameter. ``RequireTenantOwnership`` at ``tenant_isolation.py:96-98``
#: is a factory FUNCTION (``-> Callable[..., Awaitable[PackRecord]]``),
#: NOT a class — its return value is the actual dependency the endpoint
#: declares as ``Depends(...)``. The alias documents the shape this
#: module ACCEPTS (the return value), not the factory function itself.
#:
#: Style note: plain ``= ...`` assignment (no ``TypeAlias`` annotation) to
#: match the T2-era convention at ``scopes.py:61`` (``ScopeSet =
#: frozenset[PackRBACScope]``) per the Sprint-7B.1 repo convention at
#: ``packs/lifecycle.py:111``.
TenantOwnershipDep = Callable[..., Awaitable[PackRecord]]


def RequireDifferentActorThanCreator(
    *,
    tenant_ownership: TenantOwnershipDep,
) -> Callable[..., Awaitable[None]]:
    """Build a FastAPI-compatible dependency that asserts
    ``actor.subject != record.created_by`` (ADR-012 §17 cross-role
    separation: the same human cannot both submit AND review their own
    pack).

    **Closure-factory pattern (Round 14 P2 #3):** the caller passes the
    SAME :func:`~cognic_agentos.portal.rbac.tenant_isolation.RequireTenantOwnership`
    instance that the endpoint also declares as ``Depends(...)``;
    FastAPI's per-request sub-dependency cache (keyed by callable
    identity) deduplicates the ``PackRecord`` load between the
    endpoint's tenant-ownership declaration and this guard's nested
    ``Depends(tenant_ownership)`` → ONE ``store.load`` call on the
    happy claim/reject/approve path.

    **Round 15 P2 #1 — annotation-object capture at def-time:** under
    the live (non-future-import) annotation regime, the inner closure's
    ``Annotated[PackRecord, Depends(tenant_ownership)]`` annotation is
    evaluated at ``def _check(...)`` time — producing an actual
    ``Annotated`` object whose metadata embeds the
    ``Depends(tenant_ownership)`` instance with the captured factory
    parameter. FastAPI's
    ``typing.get_type_hints(..., include_extras=True)`` then reads the
    embedded ``Depends`` and resolves the captured ``tenant_ownership``
    reference. Adding ``from __future__ import annotations`` would
    break this: the annotation becomes a lazy string, the lazy-eval
    against module globals fails because ``tenant_ownership`` is a
    closure-local name (NOT a module global), and FastAPI silently
    falls back to query-param resolution — the T4-era query-param-
    leakage silent-failure bug. Pinned load-bearingly by
    ``test_module_must_not_import_future_annotations`` (AST self-test) +
    ``test_role_separation_resolves_under_fastapi_introspection``
    (live FastAPI OpenAPI introspection).

    **Round 16 P2 #3 — structured-log emission BEFORE raise:** mirrors
    sibling RBAC guards (``tenant_isolation._emit_isolation_log`` +
    ``human_actor._LOG.warning`` + ``enforcement._emit_denial_log``)
    so observability tooling sees the denial regardless of caller
    HTTP-response handling.

    :param tenant_ownership: the EXACT instance returned by
        ``RequireTenantOwnership(pack_id_param="pack_id")`` that the
        endpoint also declares as ``Depends(...)``. Sharing the
        instance is what triggers FastAPI's per-request cache hit and
        deduplicates the ``store.load`` call.
    :returns: an async callable suitable for ``Depends(...)`` on
        review-surface endpoints (claim / approve / reject).
    """

    async def _check(
        actor: Annotated[Actor, Depends(_bind_actor)],
        record: Annotated[PackRecord, Depends(tenant_ownership)],
    ) -> None:
        if actor.subject == record.created_by:
            # Round 16 P2 #3 — structured-log emission BEFORE the raise
            # so observability tooling sees the denial regardless of
            # how the caller handles the HTTP response. Mirrors
            # sibling-guard pattern in tenant_isolation + human_actor.
            _LOG.warning(
                "portal.rbac.role_separation_refused",
                extra={
                    "reason": "actor_cannot_review_own_pack",
                    "actor_subject": actor.subject,
                    "pack_id": str(record.id),
                    "pack_created_by": record.created_by,
                },
            )
            raise HTTPException(
                status_code=403,
                detail={"reason": "actor_cannot_review_own_pack"},
            )

    return _check
