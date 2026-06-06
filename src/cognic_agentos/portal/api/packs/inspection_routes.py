"""Sprint 7B.2 T7 — inspection surface endpoints.

Per the plan-of-record at
``docs/superpowers/plans/2026-05-11-sprint-7b2-portal-api-rbac-owasp.md``
§"Task 7: Inspection surface endpoints" — ships the 4 inspection-surface
endpoints behind ``/api/v1/packs``:

- ``GET /api/v1/packs`` — list scoped to ``actor.tenant_id``;
  ``pack.audit.read``. Calls
  ``store.list_for_tenant(actor.tenant_id, ...)`` so the tenant filter
  applies SERVER-SIDE via the ``ix_packs_tenant_state`` composite index
  per migration L129. No per-pack ``RequireTenantOwnership`` dep
  (there is no ``{pack_id}`` to verify); the storage WHERE clause IS
  the authoritative tenant boundary.
- ``GET /api/v1/packs/{pack_id}`` — pack detail incl. lifecycle
  history; ``pack.audit.read`` + ``RequireTenantOwnership``.
- ``GET /api/v1/packs/{pack_id}/audit`` — hash-chained audit events;
  ``pack.audit.read`` + ``RequireTenantOwnership``.
- ``GET /api/v1/packs/{pack_id}/invocations?from&to`` — audit-derived
  invocations; ``pack.invocation.read`` + ``RequireTenantOwnership``.
  Sprint 7B.2 returns ``[]`` per plan §1000 deeper-analytics-deferred
  scope.

**Route-shape split** — the bare list endpoint is registered DIRECTLY
on the parent pack-router (path ``""`` + parent prefix ``/api/v1/packs``
yields the exact wire-protocol path ``/api/v1/packs`` with no trailing
slash); the three ``{pack_id}`` sub-handlers live on a separate
sub-router returned by :func:`build_inspection_routes`. The split is
required because FastAPI's ``include_router`` rejects an empty-prefix
include of a sub-router with an empty-path route (``FastAPIError:
Prefix and path cannot be both empty``). Registering ``path=""`` on
the parent router (which carries a non-empty prefix) is allowed and
produces the canonical no-trailing-slash path per plan §997 +
ADR-012 §75. An earlier draft used ``@router.get("/")`` on the
sub-router, producing ``/api/v1/packs/`` (with trailing slash) + relying
on FastAPI's ``redirect_slashes=True`` 307 fallback; the doctrine
decision in R33 was that the slashless form IS the wire-protocol
contract — a 307 redirect is a workaround, not a contract — so the
list endpoint moved to the parent.

**Plan R20 P2 #2 + R21 P2 #1 — list-endpoint route-level
``actor_tenant_id_missing`` preflight guard**: ``GET /api/v1/packs``
bypasses :func:`RequireTenantOwnership` (no ``{pack_id}`` path-param)
which means it ALSO bypasses the existing 500
``actor_tenant_id_missing`` emission at
``tenant_isolation.py:144-152``. The handler MUST run an explicit
preflight check that emits the SAME structured log AND returns the
SAME 500 + ``detail={"reason": "actor_tenant_id_missing"}`` body
when ``actor.tenant_id`` is falsy. ``Actor.tenant_id: str`` per
``actor.py:71`` — the only reachable falsy case under live Pydantic
validation is the empty string ``""``. The
:func:`_emit_isolation_log(pack_id: str)` helper signature at
``tenant_isolation.py:75-80`` requires ``str`` so the preflight
passes the stable sentinel ``pack_id="<list>"`` (NOT ``None`` — that
was the R20 P2 #2 misclaim corrected at R21 P2 #1). Pinned by
``test_list_returns_500_when_actor_tenant_id_missing`` +
``test_list_emits_actor_tenant_id_missing_log_with_pack_id_sentinel``.

**Plan R15 P2 #1 / Round 25 §30 — module-header invariant**:
``from __future__ import annotations`` is INTENTIONALLY OMITTED
(mirrors ``review_routes.py`` + ``operator_routes.py`` + ``author_routes.py``).
PEP 563 string-deferred annotations would break FastAPI's
``inspect.signature()`` / ``typing.get_type_hints()`` resolution on
``Annotated[..., Depends(<closure-local>)]`` annotations — the
``RequireScope(...)`` + ``RequireTenantOwnership(...)`` dependency
instances are LOCAL variables inside :func:`build_inspection_routes`
and :func:`register_inspection_list`, NOT module globals. A regression
that adds the future-import would make FastAPI silently fall back to
treating handler parameters as query params — exactly the bug pinned
for sibling pack routers.
"""

import datetime
import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from cognic_agentos.packs.storage import PackRecord, PackRecordStore
from cognic_agentos.portal.api.packs.dto import (
    PackDetailResponse,
    PackLifecycleEventResponse,
    PackResponse,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import (
    RequireScope,
    _emit_denial_or_500,
    _resolve_request_id,
)
from cognic_agentos.portal.rbac.tenant_isolation import RequireTenantOwnership

_LOG = logging.getLogger(__name__)


def register_inspection_list(
    parent: APIRouter,
    *,
    store: PackRecordStore,
) -> None:
    """Register the bare list endpoint on the parent pack-router.

    The list endpoint lands at the resource root of the parent
    router. Because the parent's prefix is non-empty
    (``/api/v1/packs``) and the route-local path is ``""``, FastAPI's
    ``add_api_route`` concatenates to exactly ``/api/v1/packs`` (no
    trailing slash) — the wire-protocol path per plan §997 +
    ADR-012 §75.

    Why this lives on the PARENT (not on the
    :func:`build_inspection_routes` sub-router) — FastAPI's
    ``include_router`` rejects an empty-prefix include of a
    sub-router with an empty-path route (``FastAPIError: Prefix and
    path cannot be both empty``). The parent has a non-empty prefix
    so registering ``path=""`` directly on it is allowed and
    produces the canonical no-trailing-slash path. R33 P2 doctrine
    decision: the slashless form IS the wire-protocol contract — a
    307 redirect is a workaround, not a contract.

    The ``store`` argument is captured in this function so the
    handler closes over a single :class:`PackRecordStore` instance
    per app lifespan (mirrors :func:`build_review_routes` at
    ``portal/api/packs/review_routes.py:104``).
    """

    # Closure-local dependency instance — the ``from __future__
    # import annotations`` MUST stay omitted per the module-header
    # doctrine so FastAPI's ``inspect.signature()`` can resolve
    # ``Depends(_require_pack_audit_read)`` against this local
    # variable rather than treating the parameter as a query param.
    _require_pack_audit_read = RequireScope("pack.audit.read")

    @parent.get("", summary="List packs scoped to actor.tenant_id")
    async def list_packs(
        request: Request,
        actor: Annotated[Actor, Depends(_require_pack_audit_read)],
        limit: int = 50,
        cursor: uuid.UUID | None = None,
    ) -> list[PackResponse]:
        """List packs visible to ``actor.tenant_id``.

        Plan R2 P3 #8 — gated by ``pack.audit.read`` (examiner-facing
        per ADR-012 §75).

        Plan R19 P2 #4 — calls
        ``store.list_for_tenant(actor.tenant_id, limit=…, cursor=…,
        state=None)`` so the tenant filter applies SERVER-SIDE via
        the ``ix_packs_tenant_state`` composite index per migration
        L129. The storage WHERE clause IS the authoritative tenant
        boundary; no in-handler filtering can leak cross-tenant rows.

        Plan R20 P2 #2 + R21 P2 #1 — explicit
        ``actor_tenant_id_missing`` preflight before storage call.
        Kernel binder misconfig (empty ``actor.tenant_id``) MUST
        surface as 500 + the same closed-enum reason the
        path-param-tenant-isolated endpoints emit, NOT silently mask
        as a 200 empty-list response. ``pack_id="<list>"`` sentinel
        keeps log-aggregator bucketing discoverable while staying
        type-safe under mypy.

        Sprint-7B.4 T6: now routes through the shared
        :func:`_emit_denial_or_500` helper (same dual-surface
        contract as the path-param-tenant-isolated endpoints — log
        first, then chain row via the broker if wired).
        """
        if not actor.tenant_id:
            broker = getattr(request.app.state, "ui_event_broker", None)
            await _emit_denial_or_500(
                broker,
                denial_type="actor_tenant_id_missing",
                actor_subject=actor.subject,
                tenant_id=None,  # actor.tenant_id is empty
                request_id=_resolve_request_id(request),
                http_status=500,
                pack_id="<list>",  # sentinel — no {pack_id} path-param
            )
            raise HTTPException(
                status_code=500,
                detail={"reason": "actor_tenant_id_missing"},
            )

        records = await store.list_for_tenant(
            actor.tenant_id,
            limit=limit,
            cursor=cursor,
            state=None,
        )
        return [PackResponse.model_validate(r) for r in records]


def build_inspection_routes(*, store: PackRecordStore) -> APIRouter:
    """Build the inspection-surface sub-router for ``{pack_id}`` endpoints.

    Returns an :class:`APIRouter` carrying the three ``{pack_id}``
    inspection endpoints (detail, audit, invocations). The bare list
    endpoint lives separately on the parent router via
    :func:`register_inspection_list` (route-shape split rationale
    documented at the module docstring above).

    The ``store`` argument is captured so each endpoint closes over
    a single :class:`PackRecordStore` instance per app lifespan
    (mirrors :func:`build_review_routes` at
    ``portal/api/packs/review_routes.py:104``).

    The returned router does NOT carry a prefix —
    :func:`build_packs_router` mounts it under the parent
    ``/api/v1/packs`` prefix so each endpoint's full path is
    ``/api/v1/packs/{pack_id}[…]``.

    **Shared dependency instance** —
    ``_require_tenant_ownership = RequireTenantOwnership(pack_id_param=
    "pack_id")`` is built ONCE per router-factory invocation and
    reused across the three ``{pack_id}`` endpoints. FastAPI's
    per-request sub-dependency cache then dedupes the ``store.load``
    round-trip behind it to ONE call per request even when multiple
    endpoint layers consume the same :class:`PackRecord`. Mirrors
    the T5 review-router pattern at ``review_routes.py:133``.
    """

    router = APIRouter()

    # Closure-local dependency instances — the ``from __future__
    # import annotations`` MUST stay omitted per the module-header
    # doctrine so FastAPI's ``inspect.signature()`` can resolve
    # ``Depends(...)`` against these local variables rather than
    # treating the parameters as query params.
    _require_pack_audit_read = RequireScope("pack.audit.read")
    _require_pack_invocation_read = RequireScope("pack.invocation.read")
    _require_tenant_ownership = RequireTenantOwnership(pack_id_param="pack_id")

    # Register the SPECIFIC ``{pack_id}/audit`` + ``{pack_id}/invocations``
    # sub-paths BEFORE the broad ``{pack_id}`` detail endpoint.
    # FastAPI's matcher is exact on path-segment count so a request
    # to ``{pack_id}/audit`` will NOT match the single-segment
    # ``{pack_id}`` template — order is not strictly required for
    # correctness today. The defensive ordering is documented inline
    # so a future endpoint extension (e.g. a catch-all wildcard)
    # cannot silently mis-route.

    @router.get("/{pack_id}/audit", summary="Hash-chained audit events for a pack")
    async def get_pack_audit(
        actor: Annotated[Actor, Depends(_require_pack_audit_read)],
        record: Annotated[PackRecord, Depends(_require_tenant_ownership)],
    ) -> list[PackLifecycleEventResponse]:
        """Return the hash-chained audit events for this pack.

        Reads via :meth:`PackRecordStore.load_pack_audit_events`, which
        walks BOTH the ``decision_history.event_type LIKE
        'pack.lifecycle.%'`` slice AND the ``pack.approval_override``
        force-approve authorisation event (review §4.4, C-narrow —
        ADR-012 §107 designates the override row the examiner's
        force-approve authorisation fact, and this endpoint is its read
        surface). Both are filtered to ``payload['pack_id'] ==
        str(pack_id)`` at the storage seam — no cross-pack rows reach
        this handler.

        ``pack.evidence_read.*`` rows are deliberately NOT surfaced here
        yet (deferred per the §4.4 C-narrow decision). The detail
        endpoint ``GET /{pack_id}`` stays lifecycle-only via
        :meth:`load_lifecycle_history`.

        Dependency chain:

        1. ``_require_pack_audit_read`` (RequireScope) — 403
           ``scope_not_held`` for missing ``pack.audit.read`` scope.
        2. ``_require_tenant_ownership`` (RequireTenantOwnership) —
           404 ``tenant_id_mismatch`` for cross-tenant; 404
           ``pack_not_found`` for unknown UUID (via the dependency's
           ``store.load`` fall-through).

        The ``actor`` parameter is unused by the handler body (the
        scope check fires in the dependency itself); FastAPI requires
        the binding so the dependency executes.
        """
        del actor  # bound for scope-dep side-effect; not consumed here.
        history = await store.load_pack_audit_events(record.id)
        return [PackLifecycleEventResponse.model_validate(event) for event in history]

    @router.get(
        "/{pack_id}/invocations",
        summary="Pack invocation history (audit-derived)",
    )
    async def get_pack_invocations(
        actor: Annotated[Actor, Depends(_require_pack_invocation_read)],
        record: Annotated[PackRecord, Depends(_require_tenant_ownership)],
        from_: Annotated[
            datetime.datetime | None,
            Query(alias="from", description="ISO-8601 window-start"),
        ] = None,
        to: Annotated[
            datetime.datetime | None,
            Query(description="ISO-8601 window-end"),
        ] = None,
    ) -> list[PackLifecycleEventResponse]:
        """Return pack invocation history derived from audit events.

        Plan §1000 — Sprint 7B.2 scope: returns audit-derived
        invocation events only; deeper analytics deferred. The
        invocation-event-type vocabulary lands alongside the
        agent-workflow runtime work — Sprint 7B.2 returns an empty
        list (the shape pin) until those event types are emitted by
        the runtime.

        Dependency chain — DIFFERENT scope from detail/audit:

        1. ``_require_pack_invocation_read`` (RequireScope) — 403
           ``scope_not_held`` for missing ``pack.invocation.read``;
           ``pack.audit.read`` alone is NOT sufficient (the two scopes
           are distinct grants per ``portal/rbac/scopes.py:52-53``).
        2. ``_require_tenant_ownership`` (RequireTenantOwnership) —
           404 ``tenant_id_mismatch`` for cross-tenant.

        ``from`` and ``to`` query params are ISO-8601 datetime
        strings carrying the window for invocation-history
        narrowing. They are validated for shape (so a malformed value
        surfaces as a FastAPI 422 rather than a silent 200 with
        ignored params) but the Sprint 7B.2 empty-list response
        renders the window inert until the invocation-event-type
        vocabulary lands.
        """
        del actor, record  # bound for dep side-effects; not consumed here.
        del from_, to  # accepted + shape-validated; semantics deferred.
        return []

    # Register the broad ``{pack_id}`` detail endpoint LAST per the
    # defensive registration ordering above.
    @router.get(
        "/{pack_id}",
        summary="Pack detail incl. lifecycle history",
    )
    async def get_pack_detail(
        actor: Annotated[Actor, Depends(_require_pack_audit_read)],
        record: Annotated[PackRecord, Depends(_require_tenant_ownership)],
    ) -> PackDetailResponse:
        """Return the pack record + its lifecycle history.

        Plan §998 — composite response keyed by ``pack`` (the
        :class:`PackResponse` projection of the tenant-checked
        :class:`PackRecord`) + ``history`` (the lifecycle event
        walk). The ``PackRecord`` flows directly from
        ``_require_tenant_ownership`` per the handling-note's
        "no second ``store.load``" guidance — the dependency already
        loaded + tenant-checked the row, FastAPI's per-request
        sub-dep cache memoises it, and a second ``store.load`` here
        would be wasteful + introduce a TOCTOU window between the
        check and the read.

        Dependency chain:

        1. ``_require_pack_audit_read`` (RequireScope) — 403
           ``scope_not_held`` for missing ``pack.audit.read`` scope.
        2. ``_require_tenant_ownership`` (RequireTenantOwnership) —
           404 ``tenant_id_mismatch`` for cross-tenant; 404
           ``pack_not_found`` for unknown UUID.
        """
        del actor  # bound for scope-dep side-effect; not consumed here.
        history = await store.load_lifecycle_history(record.id)
        return PackDetailResponse(
            pack=PackResponse.model_validate(record),
            history=[PackLifecycleEventResponse.model_validate(event) for event in history],
        )

    return router
