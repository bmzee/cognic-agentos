"""Sprint 11.5c T5 — portal /memory API package.

Exports :func:`build_memory_routes` — the closure factory for the
``/api/v1/memory`` router. Mounted by ``create_app`` when
``memory_api_factory`` is supplied.
"""

from cognic_agentos.portal.api.memory.routes import build_memory_routes

__all__ = ("build_memory_routes",)
