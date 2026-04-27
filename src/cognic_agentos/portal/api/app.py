"""FastAPI application factory.

Layer classification: **portal surface**.

Sprint 1A scope:
- ``GET {api_prefix}/healthz`` — Kubernetes-style liveness probe (no
  dependency checks). Always 200 unless the process is wedged.
- ``GET {api_prefix}/version`` — build metadata for examiners + ops.

Sprint 1B adds:
- ``GET {api_prefix}/readyz`` — readiness probe; per-component status. 503
  when any critical component reports not-ready.
- Structured-logging stack (JSON formatter; request_id + trace_id bound to
  every record).
- ``RequestIdMiddleware`` (UUID gen + ``X-Request-Id`` echo).
- CORS allow-list middleware (refuses ``*``; default-deny when no origins).
- OpenTelemetry FastAPI auto-instrumentation + tracer provider.
- Prometheus metrics scrape endpoint at ``{api_prefix}{prometheus_metrics_path}``.
- OpenAPI 3 schema exported at ``{api_prefix}/openapi.json``.

Sprint 1C extends ``/readyz`` with per-adapter health probes.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, FastAPI
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator

from cognic_agentos import __version__
from cognic_agentos.core.config import Settings, get_settings
from cognic_agentos.observability import (
    configure_logging,
    configure_tracing,
    install_access_log_middleware,
    install_cors_middleware,
    install_otel_instrumentation,
    install_request_id_middleware,
    silence_uvicorn_access_log,
)


def _readiness_components(settings: Settings) -> dict[str, dict[str, object]]:
    """Internal-only readiness signal for Sprint 1B.

    Sprint 1C extends this dict with per-adapter probes — e.g.
    ``{"db": {"driver": "postgres", "status": "ok", "latency_ms": 12}}``.
    The shape is **nested per-component** so adapter probes can attach
    arbitrary metadata (driver name, latency, last-error, lease TTL)
    without rewriting the response shape.
    """

    return {
        "settings": {"status": "ok"},
        "logging": {"status": "ok"},
        "tracing": {"status": "ok"},
    }


def _build_router(settings: Settings) -> APIRouter:
    router = APIRouter(prefix=settings.api_prefix)

    @router.get("/healthz", tags=["probes"], summary="Liveness probe")
    async def healthz() -> dict[str, Any]:
        """Kubernetes-style liveness probe.

        Returns immediately with the process version. Does **not** check any
        external dependency — that responsibility belongs to ``/readyz``.
        """

        return {"alive": True, "version": __version__}

    @router.get("/readyz", tags=["probes"], summary="Readiness probe")
    async def readyz() -> JSONResponse:
        """Kubernetes-style readiness probe.

        Sprint 1B reports only on internal readiness (process started,
        middleware mounted, tracer configured). Sprint 1C wires per-adapter
        probes (db, vector, secrets, embedding, observability) into the
        ``components`` map under the same nested
        ``{<name>: {"status": ..., ...}}`` shape; when any component
        reports a non-``ok`` status the response is 503.
        """

        components = _readiness_components(settings)
        ready = all(comp.get("status") == "ok" for comp in components.values())
        body: dict[str, Any] = {
            "ready": ready,
            "runtime_profile": settings.runtime_profile,
            "components": components,
        }
        return JSONResponse(content=body, status_code=200 if ready else 503)

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

    Sprint 1B: configures the observability stack before mounting routes
    so the very first request emits a structured log line with
    ``request_id`` + ``trace_id``. Sprint 1C extends the lifespan with
    adapter-pool wiring; Sprint 4+ extends with the plugin registry.
    """

    settings = settings or get_settings()
    configure_logging(settings)
    silence_uvicorn_access_log()
    configure_tracing(settings)

    api_prefix = settings.api_prefix
    app = FastAPI(
        title="Cognic AgentOS",
        version=__version__,
        description=(
            "Bank-grade governance kernel + runtime + protocol layer for agent plugin packs."
        ),
        docs_url=None,
        redoc_url=None,
        openapi_url=f"{api_prefix}/openapi.json",
    )

    # Middleware add order is OUTER-LAST in Starlette: the call chain
    # walks the most-recently-added middleware first. We want the
    # access-log middleware to run INSIDE the OTel span (so trace_id is
    # populated at log time) but OUTSIDE the route handler, so it goes
    # in first. Request-id binds the per-request UUID before the access
    # log fires, so it ends up outermost (added last).
    install_access_log_middleware(app)
    install_cors_middleware(app, settings)
    install_otel_instrumentation(app)
    install_request_id_middleware(app)

    app.include_router(_build_router(settings))

    # Mount Prometheus AFTER routes so the instrumentator's metric registry
    # captures the route table; the scrape endpoint is mounted under
    # api_prefix so it sits alongside /healthz/readyz/version.
    Instrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        should_respect_env_var=False,
        excluded_handlers=[f"{api_prefix}{settings.prometheus_metrics_path}"],
    ).instrument(app).expose(
        app,
        endpoint=f"{api_prefix}{settings.prometheus_metrics_path}",
        include_in_schema=False,
    )

    return app
