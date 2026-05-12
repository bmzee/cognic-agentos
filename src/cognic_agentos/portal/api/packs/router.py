"""Sprint 7B.2 — pack-router scaffolding + sub-router wiring.

The :func:`build_packs_router` factory returns a single
:class:`fastapi.APIRouter` carrying the canonical ``/api/v1/packs``
prefix per ADR-012 §55-105 + BUILD_PLAN §616. T3 shipped the empty
parent router; T4 wired the author sub-router under
``/api/v1/packs/drafts``; T5 wired the review sub-router under
``/api/v1/packs`` for ``/review-queue`` + ``/{pack_id}/claim`` +
``/{pack_id}/approve`` + ``/{pack_id}/reject`` + ``/{pack_id}/evidence``;
T6 wired the operator sub-router under ``/api/v1/packs`` for
``/{pack_id}/allow-list`` + ``/{pack_id}/install`` (POST + DELETE) +
``/{pack_id}/disable`` + ``/{pack_id}/revoke``;
**T7 wires the inspection surface under ``/api/v1/packs``**: the bare
list endpoint is registered DIRECTLY on the parent router via
:func:`register_inspection_list` so the compiled path is exactly
``/api/v1/packs`` (no trailing slash; matches plan §997 + ADR-012 §75
wire-protocol contract); the three ``{pack_id}`` sub-handlers
(detail / audit / invocations) live on a sub-router returned by
:func:`build_inspection_routes`.

The :class:`~cognic_agentos.packs.storage.PackRecordStore` is threaded
as a keyword-only argument so T4-T7 endpoint handlers can close over
it (mirrors the Sprint-2 + Sprint-5 router-factory pattern at
``portal/api/system_routes.py``).

Wave-1 RBAC enforcement is route-level: every T4-T7 endpoint declares
its own ``RequireScope(...)`` + (where applicable)
``RequireTenantOwnership(...)`` + (T6 allow-list only)
``RequireHumanActor()`` dependency. The parent router does NOT mount
RBAC guards at the prefix level — guards belong on the endpoints
themselves so the closed-enum
:data:`~cognic_agentos.portal.rbac.scopes.PackRBACScope` required-scope
field per endpoint stays explicit + readable.
"""

from __future__ import annotations

from fastapi import APIRouter

from cognic_agentos.packs.storage import PackRecordStore
from cognic_agentos.portal.api.packs.author_routes import build_author_routes
from cognic_agentos.portal.api.packs.inspection_routes import (
    build_inspection_routes,
    register_inspection_list,
)
from cognic_agentos.portal.api.packs.operator_routes import build_operator_routes
from cognic_agentos.portal.api.packs.review_routes import build_review_routes

#: Canonical prefix per ADR-012 §55. Renaming this breaks every T4-T7
#: endpoint test plus the docs / OpenAPI surface; treat as wire-protocol
#: contract.
PACK_ROUTER_PREFIX = "/api/v1/packs"


def build_packs_router(*, store: PackRecordStore) -> APIRouter:
    """Build the pack-router sub-tree.

    :param store: live :class:`PackRecordStore` instance threaded
        through to T4-T7 endpoint handlers via closure (keyword-only so
        a future signature drift cannot silently shift the argument).
    :returns: :class:`APIRouter` mounted at ``/api/v1/packs`` with:

        - T4 author sub-router under ``/api/v1/packs/drafts``
        - T5 review sub-router under ``/api/v1/packs`` for
          ``/review-queue`` + ``/{pack_id}/claim/approve/reject/evidence``
        - T6 operator sub-router under ``/api/v1/packs`` for
          ``/{pack_id}/{allow-list,install,disable,revoke}`` (POST) +
          ``/{pack_id}/install`` (DELETE — uninstall verb shares the
          install path per the plan endpoint table)
        - T7 inspection surface under ``/api/v1/packs`` — bare list
          endpoint at exactly ``/api/v1/packs`` (registered directly
          on the parent router so path ``""`` + parent prefix yields
          the no-trailing-slash wire-protocol contract) +
          ``{pack_id}`` / ``{pack_id}/audit`` /
          ``{pack_id}/invocations`` sub-handlers (sub-router)

    The ``store`` argument is captured in this factory and re-threaded
    into each sub-router (so all endpoint handlers share a single
    :class:`PackRecordStore` instance per app lifespan).
    """
    router = APIRouter(prefix=PACK_ROUTER_PREFIX, tags=["packs"])
    # T4 — author surface endpoints under ``/drafts``
    router.include_router(build_author_routes(store=store))
    # T5 — review surface endpoints under ``/api/v1/packs``
    # (review-queue + {pack_id}/claim/approve/reject/evidence)
    router.include_router(build_review_routes(store=store))
    # T6 — operator surface endpoints under ``/api/v1/packs``
    # ({pack_id}/allow-list + {pack_id}/install [POST + DELETE] +
    # {pack_id}/disable + {pack_id}/revoke)
    router.include_router(build_operator_routes(store=store))
    # T7 inspection surface under ``/api/v1/packs``: list endpoint
    # registered DIRECTLY on the parent (path "" + parent prefix
    # produces exact /api/v1/packs); {pack_id} sub-handlers on
    # a sub-router included below.
    register_inspection_list(router, store=store)
    router.include_router(build_inspection_routes(store=store))
    return router
