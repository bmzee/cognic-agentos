"""Sprint 7B.2 — pack-router scaffolding + author sub-router wiring.

The :func:`build_packs_router` factory returns a single
:class:`fastapi.APIRouter` carrying the canonical ``/api/v1/packs``
prefix per ADR-012 §55-105 + BUILD_PLAN §616. T3 shipped the empty
parent router; T4 wires the author sub-router under
``/api/v1/packs/drafts``. T5-T7 will add the review / operator /
inspection endpoints in turn (per the plan-of-record's
``review_routes.py`` / ``operator_routes.py`` / ``inspection_routes.py``
filenames).

The :class:`~cognic_agentos.packs.storage.PackRecordStore` is threaded
as a keyword-only argument so T4-T7 endpoint handlers can close over
it (mirrors the Sprint-2 + Sprint-5 router-factory pattern at
``portal/api/system_routes.py``).

Wave-1 RBAC enforcement is route-level: every T4-T7 endpoint declares
its own ``RequireScope(...)`` + (where applicable)
``RequireTenantOwnership(...)`` dependency. The parent router does NOT
mount RBAC guards at the prefix level — guards belong on the endpoints
themselves so the closed-enum
:data:`~cognic_agentos.portal.rbac.scopes.PackRBACScope` required-scope
field per endpoint stays explicit + readable.
"""

from __future__ import annotations

from fastapi import APIRouter

from cognic_agentos.packs.storage import PackRecordStore
from cognic_agentos.portal.api.packs.author_routes import build_author_routes

#: Canonical prefix per ADR-012 §55. Renaming this breaks every T4-T7
#: endpoint test plus the docs / OpenAPI surface; treat as wire-protocol
#: contract.
PACK_ROUTER_PREFIX = "/api/v1/packs"


def build_packs_router(*, store: PackRecordStore) -> APIRouter:
    """Build the pack-router sub-tree.

    :param store: live :class:`PackRecordStore` instance threaded
        through to T4-T7 endpoint handlers via closure (keyword-only so
        a future signature drift cannot silently shift the argument).
    :returns: :class:`APIRouter` mounted at ``/api/v1/packs`` with the
        Sprint 7B.2 T4 author sub-router included under
        ``/api/v1/packs/drafts``; T5-T7 sub-tasks add their sub-routers
        in turn.

    The ``store`` argument is captured in this factory and re-threaded
    into the author sub-router (and T5-T7 sub-routers as they land).
    """
    router = APIRouter(prefix=PACK_ROUTER_PREFIX, tags=["packs"])
    # Sprint 7B.2 T4 — author surface endpoints under ``/drafts``
    router.include_router(build_author_routes(store=store))
    return router
