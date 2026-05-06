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
from cognic_agentos.llm.ledger import GatewayCallLedger
from cognic_agentos.observability import (
    configure_logging,
    configure_tracing,
    install_access_log_middleware,
    install_cors_middleware,
    install_otel_instrumentation,
    install_request_id_middleware,
    silence_uvicorn_access_log,
)
from cognic_agentos.portal.api.system_routes import build_system_router
from cognic_agentos.protocol import is_a2a_available, is_mcp_available
from cognic_agentos.protocol.plugin_registry import PluginRegistry

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
    gateway_ledger: GatewayCallLedger | None = None,
    plugin_registry: PluginRegistry | None = None,
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

    Sprint 3 T9: ``gateway_ledger`` (optional) is attached to
    ``app.state.gateway_ledger`` so ``/api/v1/system/effective-routing``
    can read it as the authoritative source per ADR-007. When unset,
    the endpoint reports an empty post-dispatch picture — the public
    contract still serves 200 (per ADR-007 the honesty claim never
    fails closed on missing ledger; the operator sees zero rows + the
    intent surface from settings).

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
        # Attach the optional Sprint-3 ledger reader regardless of the
        # adapter-registry path so /effective-routing works in both
        # the lifespan-managed adapter mode and the test injection mode.
        app.state.gateway_ledger = gateway_ledger
        # Sprint-4 T11: same pattern for the plugin registry. When
        # unset, /api/v1/system/plugins serves an empty list (NOT
        # 503) per the read-only honesty surface contract.
        app.state.plugin_registry = plugin_registry
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
    app.include_router(build_system_router(settings))

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

    Sprint 5 T2 adds the kernel-vs-default-adapters MCP availability
    check at startup. Per the Sprint-5 plan §T2 step 5 + R3 P1
    doctrine: ``create_prod_app`` checks :func:`is_mcp_available` once
    and either logs that the SDK is present (default-adapters image →
    MCPHost can be wired by T9) or logs a structured warning that
    MCP runtime serving is unavailable (kernel image or any venv
    missing ``mcp``).

    Narrow scope of the MCP-availability log: the warning's payload
    explicitly notes that "the Sprint-5 MCP admission modules
    (mcp_manifest, mcp_capabilities, mcp_authz) import + construct on
    the kernel image without the SDK installed" — module imports +
    construction, not end-to-end admission. **Full Sprint-4
    signed-pack admission still depends on cosign + OPA which are
    default-adapters-only**; that boundary is independent of the MCP
    runtime gate. Operators reading the structured warning's
    ``remediation`` field see both constraints called out so misconfig
    diagnosis stays unambiguous.

    The actual ``MCPHost`` wiring lands at Sprint-5 T9 (when the
    class itself exists). T2 establishes the availability-check
    contract + the structured-warning shape so T9 just extends the
    available-branch to construct + attach ``app.state.mcp_host``.
    """

    app = create_app(adapter_registry=bundled_registry)
    if is_mcp_available():
        # Sprint-5 T2: log SDK presence. T9 extends this branch to
        # construct + attach app.state.mcp_host = MCPHost(...).
        logger.info("mcp.sdk_present_at_startup", extra={"image": "default-adapters"})
    else:
        # Kernel image (or any venv missing `mcp`). Admission-side
        # MCP modules (mcp_manifest, mcp_capabilities, mcp_authz)
        # import + construct without the SDK installed (per R3 P1
        # doctrine — SDK-free); runtime invocation (MCPHost.call_tool
        # / list_tools) is unavailable here. End-to-end signed-pack
        # admission has its own separate dependency on Sprint-4 cosign
        # + OPA, documented in `protocol.MCPNotAvailableError`'s docstring.
        logger.warning(
            "mcp.host_unavailable_in_image",
            extra={
                "missing_module": "mcp",
                "optional_dep_group": "adapters",
                "remediation": (
                    "rebuild image with --extra adapters to wire MCPHost, "
                    "or use the kernel image only for governance + audit + "
                    "registry-discovery + /system/* read surfaces (note: "
                    "end-to-end signed-pack admission also requires cosign "
                    "+ OPA which are default-adapters-only per Sprint-4 "
                    "doctrine, independent of this MCP-runtime gate)"
                ),
            },
        )

    # Sprint-6 T2: A2A SDK presence check. Mirrors the MCP branch
    # above — same R3 P1 doctrine: kernel image stays SDK-free;
    # default-adapters image carries the SDK. T2 ONLY logs SDK
    # presence here. Route mounting is deferred per the plan's
    # R0 P2 reviewer correction (the factory MUST NOT promise wiring
    # it doesn't actually do — same overclaim trap Sprint-5 T15 R1
    # P2 #1 caught with MCPHost):
    #   - T9 will mount `routes.a2a` (POST /api/v1/a2a receiver)
    #   - T11 will mount `routes.a2a_capabilities` /
    #     `routes.a2a_cancellation` / `routes.a2a_artifacts`
    #   - T12 will wire UI-event emit hooks at the harness boundary
    #     (NO HTTP route — Sprint 7B owns the SSE endpoint per
    #     ADR-020 phase table)
    if is_a2a_available():
        logger.info("a2a.sdk_present_at_startup", extra={"image": "default-adapters"})
    else:
        # Kernel image (or any venv missing `a2a-sdk`). Admission-side
        # A2A modules (a2a_authz, a2a_agent_cards, a2a_schema,
        # a2a_version) import + construct without the SDK installed
        # (per Sprint-5 R3 P1 + Sprint-6 same doctrine — SDK-free);
        # runtime serving (A2AEndpoint.handle, streaming, artifacts)
        # is unavailable here.
        logger.warning(
            "a2a.endpoint_unavailable_in_image",
            extra={
                "missing_module": "a2a",
                "optional_dep_group": "adapters",
                "remediation": (
                    "rebuild image with --extra adapters to wire "
                    "A2AEndpoint, or use the kernel image only for "
                    "governance + audit + admission-side surfaces "
                    "(per-tenant token validation, AgentCard JWS "
                    "verification, manifest checks all work without "
                    "the SDK per Sprint-6 R3 P1 doctrine)"
                ),
            },
        )

    return app
