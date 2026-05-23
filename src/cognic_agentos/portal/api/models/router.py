"""Sprint 9.5 B5 — model-registry portal router composition.

Mirrors :file:`portal/api/packs/router.py`'s factory pattern: a single
parent :class:`fastapi.APIRouter` carries the canonical
``/api/v1/models`` prefix per spec §6.1, with the lifecycle sub-router
(B4) + the inspection sub-router (B5) mounted under it.

The bare list endpoint is registered DIRECTLY on the parent router
(via :func:`register_model_inspection_list`) so the compiled path is
exactly ``/api/v1/models`` (no trailing slash). Mirrors the
pack-router T7 R33 P2 doctrine.

NOT-CC at the critical-controls floor — composition glue only; no
decision logic. The substantive enforcement boundaries are in
``lifecycle_routes.py`` (CC) and ``inspection_routes.py`` (NOT-CC,
pure read).
"""

from __future__ import annotations

from fastapi import APIRouter

from cognic_agentos.core.config import Settings
from cognic_agentos.llm.ledger import GatewayCallLedger
from cognic_agentos.models.storage import ModelRecordStore
from cognic_agentos.models.trust import ModelTrustGate
from cognic_agentos.portal.api.models.inspection_routes import (
    build_model_inspection_routes,
    register_model_inspection_list,
)
from cognic_agentos.portal.api.models.lifecycle_routes import (
    build_model_lifecycle_routes,
    register_model_lifecycle_register,
)

#: Canonical parent prefix for the model-registry portal API per
#: spec §6.1. Wire-protocol-public; bank overlays MUST mount the
#: router at this path.
MODEL_ROUTER_PREFIX = "/api/v1/models"


def build_models_router(
    *,
    store: ModelRecordStore,
    trust_gate: ModelTrustGate,
    settings: Settings,
    ledger: GatewayCallLedger | None = None,
) -> APIRouter:
    """Compose the model-registry portal router.

    Returns a single :class:`APIRouter` carrying the
    :data:`MODEL_ROUTER_PREFIX` parent prefix with:

    * The B4 lifecycle sub-router (POST register / POST promote /
      POST retire) — mounted via ``include_router`` (no extra
      prefix; the parent's prefix flows down).
    * The B5 bare-list endpoint (GET ``/api/v1/models``) — registered
      DIRECTLY on the parent so the path stays slashless.
    * The B5 ``{model_id}`` sub-router (GET detail + GET audit + the
      C3 GET usage) — mounted via ``include_router``.

    Wire-protocol surface: 7 endpoints total under
    ``/api/v1/models`` (POST register / POST promote / POST retire /
    GET list / GET detail / GET audit / GET usage). The C3
    ``/usage`` endpoint is mounted REGARDLESS of ledger presence per
    the PR #35 R2 plan-patch D7 user-locked policy — the handler
    returns 503 ``gateway_ledger_not_configured`` if the backend is
    not wired at call time.
    """
    router = APIRouter(prefix=MODEL_ROUTER_PREFIX, tags=["models"])
    # The two BARE-PREFIX endpoints (POST register + GET list) are
    # registered DIRECTLY on the parent so their compiled paths are
    # exactly ``/api/v1/models`` (no trailing slash). FastAPI's
    # ``include_router`` rejects an empty-prefix include of a
    # sub-router containing an empty-path route, so neither can be
    # carried via include_router.
    register_model_lifecycle_register(router, store=store)
    register_model_inspection_list(router, store=store)
    # The ``{model_id}``-keyed sub-routers — both are include_router-
    # safe because every route inside them has a non-empty path. The
    # C3 ``ledger`` kwarg threads to ``build_model_inspection_routes``
    # so the ``/usage`` handler can read it; ``None`` (the default)
    # triggers the D7 503-policy path at call time.
    router.include_router(
        build_model_lifecycle_routes(store=store, trust_gate=trust_gate, settings=settings)
    )
    router.include_router(build_model_inspection_routes(store=store, ledger=ledger))
    return router


__all__ = ["MODEL_ROUTER_PREFIX", "build_models_router"]
