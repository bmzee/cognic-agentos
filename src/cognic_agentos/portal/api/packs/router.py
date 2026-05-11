"""Sprint 7B.2 T3 — pack-router scaffolding.

The :func:`build_packs_router` factory returns a single
:class:`fastapi.APIRouter` carrying the canonical ``/api/v1/packs``
prefix per ADR-012 §55-105 + BUILD_PLAN §616. T3 ships an EMPTY router
(no sub-routes); T4-T7 add the author / review / operator / inspection
endpoints in turn (per the plan-of-record's ``author_routes.py`` /
``review_routes.py`` / ``operator_routes.py`` /
``inspection_routes.py`` filenames).

The :class:`~cognic_agentos.packs.storage.PackRecordStore` is threaded
as a keyword-only argument so T4-T7 can build endpoint handlers that
close over it (mirrors the Sprint-2 + Sprint-5 router-factory pattern
at ``portal/api/system_routes.py``).

Wave-1 RBAC enforcement is route-level: every T4-T7 endpoint declares
its own ``RequireScope(...)`` + (where applicable)
``RequireTenantOwnership(...)`` dependency. T3 does not wire any RBAC
guards at the router level — guards belong on the endpoints themselves
so the closed-enum :data:`~cognic_agentos.portal.rbac.scopes.PackRBACScope`
required-scope field per endpoint stays explicit + readable.
"""

from __future__ import annotations

from fastapi import APIRouter

from cognic_agentos.packs.storage import PackRecordStore

#: Canonical prefix per ADR-012 §55. Renaming this breaks every T4-T7
#: endpoint test plus the docs / OpenAPI surface; treat as wire-protocol
#: contract.
PACK_ROUTER_PREFIX = "/api/v1/packs"


def build_packs_router(*, store: PackRecordStore) -> APIRouter:
    """Build the pack-router sub-tree.

    :param store: live :class:`PackRecordStore` instance threaded
        through to T4-T7 endpoint handlers via closure (keyword-only so
        a future signature drift cannot silently shift the argument).
    :returns: empty :class:`APIRouter` mounted at ``/api/v1/packs``;
        T4-T7 sub-tasks populate it with author / review / operator /
        inspection sub-routes.

    The ``store`` argument is captured in this factory so T4-T7 can
    build their own endpoint-specific routers + include them on the
    returned router. T3's scope is the empty parent only.
    """
    # The store will be threaded through to T4-T7 sub-routers as they
    # land. Reference it here so type checkers + linters confirm the
    # parameter is exercised; the local binding becomes a closure
    # capture for T4-T7 sub-routes.
    _ = store
    router = APIRouter(prefix=PACK_ROUTER_PREFIX, tags=["packs"])
    return router
