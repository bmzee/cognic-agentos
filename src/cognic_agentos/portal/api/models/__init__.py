"""Cognic AgentOS portal model-registry API surface — Sprint 9.5.

Public surface:

* :data:`MODEL_ROUTER_PREFIX` — the canonical ``/api/v1/models``
  parent prefix per spec §6.1.
* :func:`build_models_router` — compose the lifecycle + inspection
  sub-routers under the parent prefix; consumed by
  :func:`portal.api.app.create_app`.

DTOs (:mod:`.dto`) and route modules (:mod:`.lifecycle_routes`,
:mod:`.inspection_routes`) are imported by name where needed; this
``__init__`` only re-exports the public router factory + prefix to
keep ``create_app``'s import surface narrow.
"""

from cognic_agentos.portal.api.models.router import (
    MODEL_ROUTER_PREFIX,
    build_models_router,
)

__all__ = ["MODEL_ROUTER_PREFIX", "build_models_router"]
