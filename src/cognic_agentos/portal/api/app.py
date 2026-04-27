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

Sprint 1C extends ``/readyz`` with per-adapter health probes wired
through the FastAPI ``lifespan``. Adapter wiring is **opt-in** via the
``adapter_registry`` kwarg on ``create_app`` so Sprint 1A/1B tests stay
unchanged. Production launchers go through ``create_prod_app()`` which
defaults to the process-wide ``bundled_registry``.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator

from cognic_agentos import __version__
from cognic_agentos.core.config import Settings, get_settings
from cognic_agentos.db.adapters import (
    AdapterRegistry,
    Adapters,
    build_adapters,
    bundled_registry,
    load_bundled_adapters,
)
from cognic_agentos.observability import (
    configure_logging,
    configure_tracing,
    install_access_log_middleware,
    install_cors_middleware,
    install_otel_instrumentation,
    install_request_id_middleware,
    silence_uvicorn_access_log,
)

logger = logging.getLogger(__name__)


def _readiness_components(settings: Settings) -> dict[str, dict[str, object]]:
    """Internal-only readiness signal for Sprint 1B.

    Sprint 1C ATTACHES adapter components to this dict at the route
    handler boundary (not here) so monkeypatch-based test fixtures can
    still inject failures into the internal triplet.
    """

    return {
        "settings": {"status": "ok"},
        "logging": {"status": "ok"},
        "tracing": {"status": "ok"},
    }


async def _adapter_components(adapters: Adapters) -> dict[str, dict[str, object]]:
    """Probe each registered adapter and return per-driver status entries.

    Each entry has the shape ``{"driver": <name>, "status": <ok|degraded|
    unreachable>, "latency_ms"?: <float>, "detail"?: <str>}``. The
    response keys (``relational`` / ``vector`` / ``secret`` / ``embedding``
    / ``observability``) align with the ``Adapters`` dataclass fields so
    operators see a consistent kind→driver mapping in /readyz output.
    """

    out: dict[str, dict[str, object]] = {}
    for kind, adapter in (
        ("relational", adapters.relational),
        ("vector", adapters.vector),
        ("secret", adapters.secret),
        ("embedding", adapters.embedding),
        ("observability", adapters.observability),
    ):
        health = await adapter.health_check()
        comp: dict[str, object] = {
            "driver": health.driver,
            "status": health.status,
        }
        if health.detail is not None:
            comp["detail"] = health.detail
        if health.latency_ms is not None:
            comp["latency_ms"] = round(health.latency_ms, 2)
        out[kind] = comp
    return out


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
    async def readyz(request: Request) -> JSONResponse:
        """Kubernetes-style readiness probe.

        Sprint 1B reports only on internal readiness (process started,
        middleware mounted, tracer configured). Sprint 1C extends this
        with per-adapter probes when ``app.state.adapters`` is populated
        (i.e. the app was constructed with ``adapter_registry`` set);
        when any component reports a non-``ok`` status the response is 503.
        """

        components = _readiness_components(settings)
        adapters: Adapters | None = getattr(request.app.state, "adapters", None)
        if adapters is not None:
            components.update(await _adapter_components(adapters))
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


def create_app(
    settings: Settings | None = None,
    *,
    adapter_registry: AdapterRegistry | None = None,
) -> FastAPI:
    """Build and return the FastAPI application.

    Sprint 1B: configures the observability stack before mounting routes
    so the very first request emits a structured log line with
    ``request_id`` + ``trace_id``.

    Sprint 1C: when ``adapter_registry`` is provided, the lifespan
    invokes :func:`load_bundled_adapters` (kernel-resilient on optional-
    dep misses) and :func:`build_adapters`, then attaches the resulting
    :class:`Adapters` container to ``app.state.adapters`` so ``/readyz``
    can probe each driver. When ``adapter_registry`` is None (Sprint
    1A/1B test default), no adapters are built and ``/readyz`` reports
    only the internal triplet — preserving Sprint 1B test behaviour.

    Production launchers go through :func:`create_prod_app` to default
    ``adapter_registry`` to the process-wide ``bundled_registry``.
    """

    settings = settings or get_settings()
    configure_logging(settings)
    silence_uvicorn_access_log()
    configure_tracing(settings)

    api_prefix = settings.api_prefix

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if adapter_registry is None:
            app.state.adapters = None
            yield
            return

        # Trigger bundled-adapter registration side-effects. In the
        # default-adapters image this loads all five drivers; in the
        # kernel image (no `adapters` extras installed) every module
        # ImportErrors quietly per its allowlist and any configured
        # driver fails fast at build_adapters().
        if adapter_registry is bundled_registry:
            load_bundled_adapters()

        adapters = build_adapters(settings, registry=adapter_registry)
        await adapters.open_all()
        app.state.adapters = adapters
        try:
            yield
        finally:
            await adapters.close_all()
            app.state.adapters = None

    app = FastAPI(
        title="Cognic AgentOS",
        version=__version__,
        description=(
            "Bank-grade governance kernel + runtime + protocol layer for agent plugin packs."
        ),
        docs_url=None,
        redoc_url=None,
        openapi_url=f"{api_prefix}/openapi.json",
        lifespan=lifespan,
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


def create_prod_app() -> FastAPI:
    """Production-launcher entry point.

    Wraps ``create_app`` with ``adapter_registry=bundled_registry`` so
    uvicorn's ``--factory`` invocation (configured in the Dockerfile CMD)
    builds the default adapter set. Splitting this out keeps
    ``create_app`` a pure factory that doesn't side-effect adapter
    construction unless asked.
    """

    return create_app(adapter_registry=bundled_registry)
