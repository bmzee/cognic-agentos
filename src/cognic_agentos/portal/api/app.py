"""FastAPI application factory.

Layer classification: **portal surface**.

Sprint 1A scope:
- ``GET {api_prefix}/healthz`` — Kubernetes-style liveness probe (no
  dependency checks). Always 200 unless the process is wedged.
- ``GET {api_prefix}/version`` — build metadata for examiners + ops.

Sprint 1B adds ``/readyz``, structured logging middleware, OpenAPI export at
``{api_prefix}/openapi.json``, Prometheus ``/metrics``, OTel context.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, FastAPI

from cognic_agentos import __version__
from cognic_agentos.core.config import Settings, get_settings


def _build_router(settings: Settings) -> APIRouter:
    router = APIRouter(prefix=settings.api_prefix)

    @router.get("/healthz", tags=["probes"], summary="Liveness probe")
    async def healthz() -> dict[str, Any]:
        """Kubernetes-style liveness probe.

        Returns immediately with the process version. Does **not** check any
        external dependency — that responsibility belongs to ``/readyz``
        (Sprint 1B/1C).
        """

        return {"alive": True, "version": __version__}

    @router.get("/version", tags=["probes"], summary="Build metadata")
    async def version() -> dict[str, Any]:
        return {
            "version": __version__,
            "build_sha": settings.build_sha,
            "build_time": settings.build_time,
            "python_version": settings.python_version,
            "platform": settings.platform_string,
            "runtime_profile": settings.runtime_profile,
        }

    return router


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build and return the FastAPI application.

    Sprint 1A keeps this minimal; later sprints register additional routers,
    middleware (request-id, OTel, structured logging), the lifespan that
    wires adapter pools, and the supply-chain / pack-registry plumbing.
    """

    settings = settings or get_settings()
    app = FastAPI(
        title="Cognic AgentOS",
        version=__version__,
        description=(
            "Bank-grade governance kernel + runtime + protocol layer for "
            "agent plugin packs. Sprint 1A bootstrap surface."
        ),
        docs_url=None,  # Swagger UI added under api_prefix in Sprint 1B
        redoc_url=None,
        openapi_url=None,  # OpenAPI schema exported under api_prefix in Sprint 1B
    )
    app.include_router(_build_router(settings))
    return app
