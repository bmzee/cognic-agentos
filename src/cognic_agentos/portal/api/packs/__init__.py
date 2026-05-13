"""Sprint 7B.2 — Pack API package.

Modules:

- :mod:`.dto` — Pydantic v2 wire-shape DTOs (T3 scaffolding +
  endpoint-specific DTOs added in T4-T7).
- :mod:`.router` — :func:`build_packs_router` factory mounting the
  ``/api/v1/packs`` sub-tree.

T4-T7 add per-endpoint sub-modules per the plan-of-record filenames:
``author_routes`` (T4) / ``review_routes`` (T5) / ``operator_routes``
(T6) / ``inspection_routes`` (T7).
"""

from cognic_agentos.portal.api.packs.router import (
    PACK_ROUTER_PREFIX,
    build_packs_router,
)

__all__ = ["PACK_ROUTER_PREFIX", "build_packs_router"]
