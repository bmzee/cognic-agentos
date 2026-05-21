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

import asyncio
import logging
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator

from cognic_agentos import __version__
from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.config import Settings, get_settings
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.db.adapters import (
    AdapterRegistry,
    Adapters,
    build_adapters,
    bundled_registry,
    load_bundled_adapters,
)
from cognic_agentos.llm.ledger import GatewayCallLedger
from cognic_agentos.observability import (
    bind_request_id,
    configure_logging,
    configure_tracing,
    install_access_log_middleware,
    install_cors_middleware,
    install_otel_instrumentation,
    install_request_id_middleware,
    silence_uvicorn_access_log,
)
from cognic_agentos.packs.storage import PackRecordStore
from cognic_agentos.portal.api.packs import build_packs_router
from cognic_agentos.portal.api.system_routes import build_system_router
from cognic_agentos.portal.rbac.actor import ActorBinder
from cognic_agentos.protocol import is_a2a_available, is_mcp_available
from cognic_agentos.protocol.elicitation_adapter import ElicitationAdapter
from cognic_agentos.protocol.plugin_registry import PluginRegistry
from cognic_agentos.protocol.trust_gate import TrustGate
from cognic_agentos.protocol.trust_root_resolver import TrustRootResolver
from cognic_agentos.protocol.ui_events import UIEventBroker, UIEventEmitter

if TYPE_CHECKING:
    # Sprint-7B.4 T12: type-only refs for the create_app signature.
    # ``OPAEngine`` lives in ``core/policy/engine`` (CC module per the
    # AGENTS.md stop rule); importing it at runtime would extend the
    # core module's blast radius into the portal layer for callers
    # that don't wire OPA. TYPE_CHECKING keeps the kwarg typed without
    # pulling the engine module into the import graph.
    from cognic_agentos.core.policy.engine import OPAEngine

    # Sprint 8.5 T10: type-only ref for the create_app ``checkpoint_store``
    # kwarg. The runtime ``CheckpointReaper`` import is local to the
    # lifespan (only pulled in when a store is actually wired) so the
    # portal import graph stays free of the sandbox package by default.
    from cognic_agentos.sandbox.checkpoint_store import CheckpointStore

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
    actor_binder: ActorBinder | None = None,
    pack_record_store: PackRecordStore | None = None,
    trust_gate: TrustGate | None = None,
    trust_root_resolver: TrustRootResolver | None = None,
    # Sprint-7B.4 T6: backward-compatible optional deps (None-default
    # follows the 7B.3 T9 trust_gate / trust_root_resolver precedent).
    # When all 3 are wired AND settings is non-None, create_app constructs
    # the UIEventBroker + registers it on the emitter + mounts a periodic
    # reap_idle lifespan task. Existing test fixtures + bank-overlay
    # callers that omit them continue working — broker stays None,
    # RBAC deps' shared _emit_denial_or_500 helper takes its log-only
    # fallback path (R3 #3 backward-compat).
    decision_history_store: DecisionHistoryStore | None = None,
    audit_store: AuditStore | None = None,
    ui_event_emitter: UIEventEmitter | None = None,
    # Sprint-7B.4 T12: optional UI-router deps (same None-default
    # pattern). When ANY of the broker-prerequisite triple
    # (decision_history_store + ui_event_emitter + settings) is
    # missing AND ``broker`` is not pre-injected, UI routes do NOT
    # mount + .well-known is NOT registered.
    #
    # ``broker`` is the test-fixture-injection seam: pass a pre-built
    # UIEventBroker so the route + the test share subscriber state
    # (production callers pass None and let create_app build internally
    # from the T6 deps).
    #
    # ``elicitation_adapter`` + ``rego_engine`` route through to
    # ``build_action_routes`` for the submit_elicitation path; absent
    # values surface the matching elicitation_backend_unwired /
    # elicitation_unwired_evaluator refusal at request time per the
    # T8 gate's Step 1 / Step 5.
    broker: UIEventBroker | None = None,
    elicitation_adapter: ElicitationAdapter | None = None,
    rego_engine: OPAEngine | None = None,
    # Sprint 8.5 T10: optional checkpoint-reaper wiring seam. When a
    # CheckpointStore is provided, the FastAPI lifespan starts a
    # single-instance CheckpointReaper background task (retention-floor
    # enforcement per ADR-004 / spec §4.2) and cancels it on shutdown.
    # When None — the dev / test / pack-only default — NO reaper task is
    # created and startup is unaffected. Same opt-in None-default
    # pattern as every other dependency on this factory.
    checkpoint_store: CheckpointStore | None = None,
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

    Sprint 7B.3 T9: ``trust_gate`` + ``trust_root_resolver`` (both
    optional) are attached to ``app.state.trust_gate`` /
    ``app.state.trust_root_resolver`` and threaded into
    :func:`build_packs_router` → :func:`build_review_routes` for the
    ``POST /api/v1/packs/{pack_id}/approve`` endpoint's gate-1 (cosign
    signature) resolution. When either is ``None`` the approve handler
    resolves Gate 1 to a ``red`` ``SignatureGateInput`` — fail-closed,
    never a crash. Production launchers inject a real
    :class:`~cognic_agentos.protocol.trust_gate.TrustGate` + a
    bank-overlay
    :class:`~cognic_agentos.protocol.trust_root_resolver.TrustRootResolver`.

    Sprint 7B.2 T3: ``actor_binder`` + ``pack_record_store`` are
    attached to ``app.state.actor_binder`` / ``app.state.pack_record_store``
    so the T4-T7 pack-router endpoints can resolve the per-request
    :class:`~cognic_agentos.portal.rbac.actor.Actor` + load
    :class:`~cognic_agentos.packs.storage.PackRecord` rows. The pack
    router (mounted at ``/api/v1/packs`` per ADR-012 §55) is included
    ONLY when BOTH kwargs are provided — RBAC enforcement at every
    pack endpoint requires a working actor binder; mounting the
    router without one would create routes that always 500 at request
    time. When ``pack_record_store`` is provided but ``actor_binder``
    is None the kernel emits a structured fail-loud warning at the
    ``cognic_agentos.portal.api.app`` logger; mirrors the
    ``mcp.host_unavailable_in_image`` pattern in
    :func:`create_prod_app`.

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
        # Sprint-7B.4 T6: lifespan-managed reap task ONLY.
        # All synchronous-object state attaches (gateway_ledger,
        # plugin_registry, actor_binder, pack_record_store, trust_gate,
        # trust_root_resolver, decision_history_store, audit_store,
        # ui_event_emitter, ui_event_broker) now happen at module level
        # right after `app = FastAPI(...)` below — so they are visible
        # to httpx.ASGITransport callers that don't run lifespan.
        # The reap_task DOES belong in lifespan because it needs an
        # asyncio event loop + clean cancellation on app shutdown.
        reap_task: asyncio.Task[None] | None = None
        broker_for_lifespan = app.state.ui_event_broker
        if broker_for_lifespan is not None and settings is not None:
            _idle_s = settings.ui_event_stream_idle_timeout_s

            async def _reap_loop() -> None:
                """Periodic SSE-subscriber reaper. Runs at 1/3 the idle
                timeout so a stale subscriber is detected within one
                reap window; logs + swallows any per-iteration exception
                so a single failure does NOT kill the loop for the
                entire process lifetime."""
                while True:
                    await asyncio.sleep(_idle_s / 3)
                    try:
                        broker_for_lifespan.reap_idle(datetime.now(UTC))
                    except Exception:
                        logger.exception("ui.broker.reap_idle_failed")

            reap_task = asyncio.create_task(_reap_loop())

        # Sprint 8.5 T10 — single-instance CheckpointReaper background
        # task. Created HERE (inside the one-shot lifespan; not per
        # request, not at import) so it starts exactly once per AgentOS
        # process per spec §13. Skipped entirely when no CheckpointStore
        # is wired — the dev / test / pack-only path MUST NOT fail
        # startup. The runtime CheckpointReaper import is local so the
        # portal import graph stays sandbox-free unless a store is wired.
        reaper_task: asyncio.Task[None] | None = None
        checkpoint_store_for_lifespan = app.state.checkpoint_store
        if checkpoint_store_for_lifespan is not None and settings is not None:
            from cognic_agentos.sandbox.reaper import CheckpointReaper

            _reaper = CheckpointReaper(
                checkpoint_store=checkpoint_store_for_lifespan,
                settings=settings,
            )
            reaper_task = asyncio.create_task(_reaper.run_forever())
        app.state.reaper_task = reaper_task

        # Outer try/finally guarantees both background tasks are
        # cancelled even on the adapter-registry-None early-return path.
        try:
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
        finally:
            # Sprint-7B.4 T6: reap-task cleanup. Always runs even when
            # adapter-registry-None path early-returned.
            if reap_task is not None:
                reap_task.cancel()
                with suppress(asyncio.CancelledError):
                    await reap_task
            # Sprint 8.5 T10: checkpoint-reaper cleanup. cancel() then
            # await so CancelledError propagates cleanly to the task
            # boundary — the reaper re-raises it out of run_forever (it
            # NEVER swallows cancellation); suppress() here absorbs it
            # at the OWNER awaiting its own cancelled task. No zombie
            # reaper task survives the lifespan.
            if reaper_task is not None:
                reaper_task.cancel()
                with suppress(asyncio.CancelledError):
                    await reaper_task

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

    # Sprint-7B.4 T6: eager app.state attach for all synchronous-object
    # deps (everything except the adapter pool, which needs async
    # open_all() in lifespan).
    #
    # Why eager (NOT inside lifespan): httpx.ASGITransport (used by
    # test fixtures via
    # `tests/unit/portal/api/ui/sse_test_helpers._async_client`) does
    # NOT run lifespan startup. RBAC deps reading
    # `request.app.state.<dep>` would always see None under httpx test
    # transport, taking degraded fallback paths — chain rows would
    # never persist; pack routes would 500 with
    # `pack_store_not_configured`; etc. Module-level attach guarantees
    # state is observable from the FIRST request regardless of
    # transport choice (TestClient runs lifespan; httpx does not; both
    # see the same app.state now).
    #
    # Pre-T6 the attaches lived inside lifespan; that worked for the
    # Sprint-7B.2/7B.3 tests because they used TestClient. T6 RBAC
    # tests use httpx.ASGITransport (because the broker chain-emit
    # path requires async test bodies) → the lifespan-attach pattern
    # is no longer adequate.
    app.state.gateway_ledger = gateway_ledger
    app.state.plugin_registry = plugin_registry
    app.state.actor_binder = actor_binder
    app.state.pack_record_store = pack_record_store
    app.state.trust_gate = trust_gate
    app.state.trust_root_resolver = trust_root_resolver

    # Sprint-7B.4 T6: broker construction + eager attach.
    # Sprint-7B.4 T12: extended to accept a pre-built broker via the
    # ``broker=`` kwarg (test-fixture-injection seam — the route + the
    # test then share subscriber state). When ``broker`` is None AND
    # the T6 deps are wired, build internally from the T6 deps.
    # Backward-compat: callers that omit ANY of the prerequisites get
    # ``app.state.ui_event_broker = None``; the shared
    # ``_emit_denial_or_500`` helper's ``if broker is None: return``
    # log-only fallback (per R3 #3) keeps existing pack-only test
    # fixtures green.
    portal_broker: UIEventBroker | None = broker
    if (
        portal_broker is None
        and decision_history_store is not None
        and ui_event_emitter is not None
        and settings is not None
    ):
        portal_broker = UIEventBroker(
            decision_history_store=decision_history_store,
            settings=settings,
        )
        portal_broker.register_with_emitter(ui_event_emitter)

    app.state.ui_event_broker = portal_broker
    app.state.decision_history_store = decision_history_store
    app.state.audit_store = audit_store
    app.state.ui_event_emitter = ui_event_emitter
    # Sprint-7B.4 T12: cache the optional UI deps on app.state for
    # introspection (e.g. operator tools, debug endpoints) — the UI
    # router itself reads them from closure capture, NOT from
    # ``app.state.*``, so changing these post-construction has NO
    # effect on route behavior.
    app.state.elicitation_adapter = elicitation_adapter
    app.state.rego_engine = rego_engine
    app.state.settings = settings
    # Sprint 8.5 T10: checkpoint-reaper wiring seam. ``checkpoint_store``
    # is attached eagerly so the lifespan can read it off app.state
    # (mirrors the ``ui_event_broker`` pattern); ``reaper_task`` is
    # pre-seeded to None so introspection — and the lifespan-wiring
    # tests' pre-startup assertion — see a defined attribute before
    # startup creates the task.
    app.state.checkpoint_store = checkpoint_store
    app.state.reaper_task = None

    # Middleware add order is OUTER-LAST in Starlette: the call chain
    # walks the most-recently-added middleware first. We want the
    # access-log middleware to run INSIDE the OTel span (so trace_id is
    # populated at log time) but OUTSIDE the route handler, so it goes
    # in first. Request-id binds the per-request UUID before the access
    # log fires, so it ends up outermost (added last).
    install_access_log_middleware(app)
    install_cors_middleware(app, settings)
    install_otel_instrumentation(app)

    # Sprint-7B.4 T6: portal request-id middleware. Mints a
    # ``portal-req-<uuid4.hex>`` (43 chars ≤ the decision_history
    # request_id column cap of 64) onto ``request.state.request_id``
    # for every ``/api/v1/*`` path so the RBAC denial helpers
    # (`_emit_denial_or_500` via `_resolve_request_id`) have a stable
    # correlation id on EVERY denial. The fallback
    # `portal-rbac-denial-<uuid4.hex>` in `_resolve_request_id` covers
    # non-portal callers that bypass this middleware (should never fire
    # under normal traffic).
    #
    # ALSO rebinds the observability `REQUEST_ID_CONTEXT` contextvar
    # via `bind_request_id(...)` so the structured-log shape carries
    # the portal-prefixed id (otherwise the
    # `observability.logging._ContextFilter` would emit the
    # observability-bound uuid4.hex value — operators need ONE
    # consistent id per request across log + chain row).
    #
    # **Registration order matters**: this middleware is added BEFORE
    # `install_request_id_middleware(app)` below so observability's
    # request-id middleware ends up OUTERMOST in the Starlette
    # call chain (Starlette runs most-recently-added first on ingress).
    # observability fires first → sets contextvar from X-Request-Id
    # header (or default) → T6 fires next INSIDE → overwrites contextvar
    # with the portal-prefixed id for the rest of the request lifetime.
    # Reversing the order would let observability clobber T6's value.
    @app.middleware("http")
    async def _portal_request_id_middleware(request: Request, call_next: Any) -> Any:
        if request.url.path.startswith("/api/v1/") and not getattr(
            request.state, "request_id", None
        ):
            portal_rid = f"portal-req-{uuid.uuid4().hex}"
            request.state.request_id = portal_rid
            bind_request_id(portal_rid)
            # The X-Request-Id response header is written by
            # observability's RequestIdMiddleware reading the contextvar
            # FRESH at response time (Sprint-7B.4 T6 amendment at
            # `observability/middleware.py:78-83`); rebinding the
            # contextvar here means the response header AND the access
            # log AND the denial log AND the chain row all carry the
            # SAME portal-req-* id on portal traffic.
        return await call_next(request)

    install_request_id_middleware(app)

    app.include_router(_build_router(settings))
    app.include_router(build_system_router(settings))

    # Sprint-7B.2 T3: pack-router wiring. Mount only when BOTH
    # ``actor_binder`` and ``pack_record_store`` are provided — the
    # T4-T7 endpoints declare per-route ``RequireScope(...)`` /
    # ``RequireTenantOwnership(...)`` dependencies that read both off
    # ``app.state``; mounting routes without one would either fail-open
    # (silently skip RBAC) or 500 at request time with a confusing
    # AttributeError. Both partial-config branches are no-mount AND
    # both emit a structured fail-loud warning naming the missing
    # kwarg — symmetric coverage closes the T3-R1 P2 finding that a
    # half-wired pack store (binder set, store None) would otherwise
    # silently disable the pack API in production with no operator
    # signal.
    #
    # ``app.state.pack_router_mounted`` is the introspection flag tests
    # + future read-only honesty surfaces use to confirm the mount
    # decision. Set at factory-body time (NOT lifespan) so the flag is
    # available immediately on the returned ``FastAPI`` instance, before
    # the first request fires lifespan startup. T3 ships an empty
    # router so the FastAPI route table doesn't gain a path entry that
    # a test could grep for; the flag IS the wire-protocol-public
    # "is the pack router available?" signal.
    app.state.pack_router_mounted = False
    if actor_binder is not None and pack_record_store is not None:
        app.include_router(
            build_packs_router(
                store=pack_record_store,
                trust_gate=trust_gate,
                trust_root_resolver=trust_root_resolver,
            )
        )
        app.state.pack_router_mounted = True
    elif pack_record_store is not None:
        # Fail-loud misconfig — operator provided a pack store but no
        # binder. Mirrors the ``mcp.host_unavailable_in_image`` pattern
        # in :func:`create_prod_app` (structured warning at startup,
        # closed-enum ``reason`` field, explicit remediation string).
        logger.warning(
            "portal.packs_router_unmounted_actor_binder_missing",
            extra={
                "reason": "actor_binder_required_for_pack_router",
                "remediation": (
                    "create_app(actor_binder=<bank-overlay-binder>, "
                    "pack_record_store=<store>) wires the pack router; "
                    "without actor_binder, RBAC enforcement at every "
                    "pack endpoint would have no source of Actor "
                    "identity. The kernel default "
                    "KernelDefaultActorBinder fails-loud at request "
                    "time, but the wiring boundary refuses earlier so "
                    "misconfig is caught at startup."
                ),
            },
        )
    elif actor_binder is not None:
        # Symmetric fail-loud misconfig — operator provided a binder
        # but no pack store. Closed at T3-R1 P2 review: without this
        # warning, a half-wired deployment (binder configured, store
        # missing) would silently disable the pack API in production
        # with no operator signal. Mirrors the warning above with a
        # distinct ``reason`` enum value so operators can fingerprint
        # WHICH half of the wiring boundary is missing.
        logger.warning(
            "portal.packs_router_unmounted_pack_record_store_missing",
            extra={
                "reason": "pack_record_store_required_for_pack_router",
                "remediation": (
                    "create_app(actor_binder=<bank-overlay-binder>, "
                    "pack_record_store=<store>) wires the pack router; "
                    "without pack_record_store, the pack endpoints "
                    "would have no backing storage and every T4-T7 "
                    "route would surface a confusing 500 at request "
                    "time. The wiring boundary refuses earlier so "
                    "misconfig is caught at startup."
                ),
            },
        )

    # Sprint-7B.4 T12: UI router mount + .well-known registration.
    # Gated on ``portal_broker is not None`` — pack-only deployments
    # that don't wire the T6 deps OR the ``broker=`` kwarg get NO UI
    # routes + NO .well-known endpoint (the R3 #3 backward-compat
    # invariant). When the broker IS wired, mount the composed UI
    # router (stream + action) + register .well-known at the app
    # root per RFC 8615.
    if portal_broker is not None:
        # decision_history_store + settings are guaranteed non-None
        # here: portal_broker is non-None only if either (a) it was
        # injected via the ``broker=`` kwarg (caller owns wiring) or
        # (b) the auto-build branch above required both. The
        # ``assert`` pins the invariant for mypy + future maintainers.
        assert decision_history_store is not None
        assert settings is not None
        from cognic_agentos.portal.api.ui.router import build_ui_routes
        from cognic_agentos.portal.api.ui.well_known_routes import (
            register_well_known_routes,
        )

        app.include_router(
            build_ui_routes(
                broker=portal_broker,
                settings=settings,
                decision_history_store=decision_history_store,
                elicitation_adapter=elicitation_adapter,
                rego_engine=rego_engine,
            )
        )
        register_well_known_routes(app)

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
