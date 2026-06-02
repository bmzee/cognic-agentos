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
from cognic_agentos.models.storage import ModelRecordStore
from cognic_agentos.models.trust import ModelTrustGate
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
from cognic_agentos.portal.api.models import build_models_router
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
    # Sprint 11.5b T7: type-only ref for the create_app ``memory_reaper``
    # kwarg. There is NO runtime ``MemoryTombstoneReaper`` import in app.py —
    # the reaper is supplied PRE-CONSTRUCTED by the caller. The portal import
    # graph stays free of the memory package by default; this TYPE_CHECKING-only
    # ref types the kwarg without pulling the module into the import graph.
    from cognic_agentos.core.memory.reaper import MemoryTombstoneReaper
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


def _build_checkpoint_store_from_adapters(
    adapters: Adapters,
    settings: Settings,
) -> CheckpointStore:
    """#489 — construct a production CheckpointStore from the live adapter pool.

    The checkpoint stores reuse the relational adapter's own AsyncEngine
    (read-only — they never dispose it; the adapter owns its lifecycle)
    and the bundled object-store adapter. Called by the lifespan ONLY
    after build_adapters() + open_all(), so adapters.relational.engine is
    connected.

    Fails loud — naming the missing dependency — when the object store OR
    the relational engine is unavailable. A setting-driven reaper an
    operator explicitly enabled must never be silently disabled (#489 spec
    §4.3.2 / AC4). The relational-engine-unavailable RuntimeError (raised
    by the RelationalAdapter.engine property when the adapter is not
    connected) is caught and re-raised with a dependency-naming message so
    both fail-loud paths are symmetric.
    """
    from cognic_agentos.sandbox.checkpoint_store import CheckpointStore

    if adapters.object_store is None:
        raise RuntimeError(
            "sandbox_reaper_enabled=true but no object-store adapter is "
            "configured — the checkpoint reaper cannot run without "
            "persistent checkpoint storage."
        )
    try:
        engine = adapters.relational.engine
    except RuntimeError as exc:
        raise RuntimeError(
            "sandbox_reaper_enabled=true but the relational adapter "
            "engine is unavailable — the checkpoint reaper cannot run "
            "without a database connection."
        ) from exc
    return CheckpointStore(
        object_store=adapters.object_store,
        audit_store=AuditStore(engine),
        decision_history_store=DecisionHistoryStore(engine),
        settings=settings,
    )


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
    model_registry_store: ModelRecordStore | None = None,
    model_trust_gate: ModelTrustGate | None = None,
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
    # Sprint 11.5b T7: optional memory tombstone-reaper wiring seam. When
    # a MemoryTombstoneReaper is provided, the FastAPI lifespan starts a
    # single-instance background task (tombstone retention-floor enforcement
    # per ADR-019) and cancels it on shutdown. When None — the dev / test
    # / pack-only default — NO memory-reaper task is created and startup
    # is SILENT (pack-only deployments without long-term memory are legit).
    # Mirrors the checkpoint_store opt-in pattern exactly.
    memory_reaper: MemoryTombstoneReaper | None = None,
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
        # Sprint-7B.4 T6 + #489: lifespan-managed background tasks. All
        # synchronous-object state attaches (gateway_ledger,
        # plugin_registry, actor_binder, pack_record_store, trust_gate,
        # trust_root_resolver, decision_history_store, audit_store,
        # ui_event_emitter, ui_event_broker) happen at module level right
        # after `app = FastAPI(...)` below. The SSE reap_task + the
        # checkpoint reaper_task belong in lifespan because they need an
        # asyncio event loop + clean cancellation on shutdown.
        #
        # #489: reap_task + reaper_task + memory_reaper_task are declared AND
        # the outer try/finally cleanup envelope is opened BEFORE any
        # background task is created or any fail-loud check runs — so a
        # startup failure (e.g. the setting-driven fail-loud raise) can never
        # leak a created task.
        reap_task: asyncio.Task[None] | None = None
        reaper_task: asyncio.Task[None] | None = None
        memory_reaper_task: asyncio.Task[None] | None = None

        async def _shutdown_checkpoint_reaper() -> None:
            # cancel() then await so CancelledError propagates cleanly to
            # the task boundary — the reaper re-raises it out of
            # run_forever (it NEVER swallows cancellation). Idempotent via
            # the done() guard so the inner + outer finally can both call
            # it safely.
            if reaper_task is not None and not reaper_task.done():
                reaper_task.cancel()
                with suppress(asyncio.CancelledError):
                    await reaper_task

        def _start_checkpoint_reaper(store: CheckpointStore) -> asyncio.Task[None]:
            # Local import keeps the portal import graph sandbox-free until
            # a reaper is actually wired (Sprint 8.5 T10 doctrine).
            from cognic_agentos.sandbox.reaper import CheckpointReaper

            reaper = CheckpointReaper(checkpoint_store=store, settings=settings)
            return asyncio.create_task(reaper.run_forever())

        async def _shutdown_memory_reaper() -> None:
            # cancel() then await so CancelledError propagates cleanly to
            # the task boundary — the reaper re-raises it out of
            # run_forever (it NEVER swallows cancellation). Idempotent via
            # the done() guard so the inner + outer finally can both call
            # it safely. Mirrors _shutdown_checkpoint_reaper exactly.
            if memory_reaper_task is not None and not memory_reaper_task.done():
                memory_reaper_task.cancel()
                with suppress(asyncio.CancelledError):
                    await memory_reaper_task

        try:
            # Sprint-7B.4 T6: SSE-subscriber reap task.
            broker_for_lifespan = app.state.ui_event_broker
            if broker_for_lifespan is not None and settings is not None:
                _idle_s = settings.ui_event_stream_idle_timeout_s

                async def _reap_loop() -> None:
                    """Periodic SSE-subscriber reaper. Runs at 1/3 the idle
                    timeout so a stale subscriber is detected within one
                    reap window; logs + swallows any per-iteration
                    exception so a single failure does NOT kill the loop
                    for the entire process lifetime."""
                    while True:
                        await asyncio.sleep(_idle_s / 3)
                        try:
                            broker_for_lifespan.reap_idle(datetime.now(UTC))
                        except Exception:
                            logger.exception("ui.broker.reap_idle_failed")

                reap_task = asyncio.create_task(_reap_loop())

            # --- Memory tombstone reaper (Sprint 11.5b T7) ------------------
            # Opt-in only: when create_app(memory_reaper=...) is supplied the
            # lifespan starts a single-instance background task that drives
            # MemoryAdapter.purge_expired() on a configurable interval
            # (settings.memory_reaper_interval_s). When None — the dev / test
            # / pack-only default — NO task is created and startup is SILENT
            # (pack-only deployments are legitimate). Cancelled BEFORE the
            # adapter/relational shutdown in the finally so the reaper never
            # runs a sweep against a closing DB connection.
            if memory_reaper is not None:
                # The reaper is passed in PRE-CONSTRUCTED (with its adapter +
                # settings); there is NO runtime import of the memory package
                # here. The portal import graph stays memory-free via the
                # TYPE_CHECKING-only create_app annotation ref. (The checkpoint
                # reaper differs: it local-imports + constructs its reaper from
                # the store inside _start_checkpoint_reaper.)
                memory_reaper_task = asyncio.create_task(memory_reaper.run_forever())
                app.state.memory_reaper_task = memory_reaper_task
                logger.info(
                    "memory.reaper.started",
                    extra={"source": "explicit_injection"},
                )

            # --- Checkpoint reaper (Sprint 8.5 T10 + #489) -----------------
            # Precedence: an explicit create_app(checkpoint_store=...)
            # injection wins and needs NO adapter pool (preserves the
            # Sprint 8.5 T10 test seam, incl. the adapter_registry-None
            # path). Otherwise the #489 setting-driven path builds the
            # store from the live adapter pool AFTER open_all().
            injected_store = app.state.checkpoint_store
            setting_driven_reaper = injected_store is None and settings.sandbox_reaper_enabled

            # #489 spec §4.3.2 — fail loud. An operator who set
            # sandbox_reaper_enabled=true on a deployment with no adapter
            # pool gets a startup failure, never a silent no-op. The raise
            # is INSIDE this outer try so the cleanup envelope cancels any
            # background task already created above. Scoped to the
            # setting-driven path only — the explicit-injection path never
            # reaches here, so injecting a store never fails for adapter
            # reasons.
            if setting_driven_reaper and adapter_registry is None:
                raise RuntimeError(
                    "sandbox_reaper_enabled=true but no adapter registry "
                    "is configured. The setting-driven checkpoint reaper "
                    "requires the production adapter pool — launch via "
                    "create_prod_app, or inject "
                    "create_app(checkpoint_store=...)."
                )

            # Explicit-injection reaper starts immediately — the injected
            # store is self-contained (its own engine + object store); no
            # adapter pool needed, so this path works on the
            # adapter_registry-None branch too.
            if injected_store is not None:
                reaper_task = _start_checkpoint_reaper(injected_store)
                app.state.reaper_task = reaper_task
                logger.info(
                    "sandbox.reaper.started",
                    extra={"source": "explicit_injection"},
                )

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
                # #489 — setting-driven reaper: build the CheckpointStore
                # from the live adapter pool AFTER open_all() so the
                # relational adapter's engine is connected. This build is
                # INSIDE the inner try so a builder fail-loud still runs
                # close_all() + clears app.state.adapters.
                if setting_driven_reaper:
                    store = _build_checkpoint_store_from_adapters(adapters, settings)
                    reaper_task = _start_checkpoint_reaper(store)
                    app.state.reaper_task = reaper_task
                    logger.info(
                        "sandbox.reaper.started",
                        extra={
                            "source": "settings",
                            "interval_s": settings.sandbox_reaper_interval_s,
                        },
                    )
                elif injected_store is None:
                    # Default posture — no reaper. Loud log so an operator
                    # who never enabled it sees why checkpoint retention
                    # is not sweeping.
                    logger.info(
                        "sandbox.reaper.disabled",
                        extra={
                            "remediation": (
                                "set sandbox_reaper_enabled=true on "
                                "EXACTLY ONE instance to run the "
                                "resumable-session retention sweep "
                                "(single-instance posture per spec §13; "
                                "Sprint 10.5 adds leader election)"
                            ),
                        },
                    )

                yield
            finally:
                # Cancel reapers BEFORE close_all() so the shared
                # adapter-owned engine is never disposed under an
                # in-flight sweep. Memory reaper first (Sprint 11.5b T7),
                # then checkpoint reaper (#489 ordering preserved).
                await _shutdown_memory_reaper()
                await _shutdown_checkpoint_reaper()
                await adapters.close_all()
                app.state.adapters = None
        finally:
            # All background tasks created above are cancelled here. This
            # envelope opened BEFORE any task creation, so a startup
            # failure (e.g. the setting-driven fail-loud raise) can never
            # leak the SSE reap task, the checkpoint reaper, or the memory
            # reaper.
            if reap_task is not None:
                reap_task.cancel()
                with suppress(asyncio.CancelledError):
                    await reap_task
            await _shutdown_checkpoint_reaper()
            await _shutdown_memory_reaper()

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
    # Sprint 11.5b T7: memory tombstone-reaper wiring seam. ``memory_reaper``
    # is stored for lifespan introspection; ``memory_reaper_task`` is
    # pre-seeded to None so pre-startup introspection sees a defined
    # attribute (mirrors the reaper_task pattern above).
    app.state.memory_reaper = memory_reaper
    app.state.memory_reaper_task = None

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

    # ──────────────────────────────────────────────────────────────────
    # Sprint 9.5 B5 — Model Registry router mount (ADR-013).
    #
    # Gated on all three deps being supplied: ``actor_binder`` (any
    # portal-API enforcement needs a source of Actor identity) +
    # ``model_registry_store`` (the storage primitive) +
    # ``model_trust_gate`` (cosign verifier for promote_eval_passed).
    # ``app.state.models_router_mounted`` is the introspection flag
    # tests use to assert mount/no-mount decision; matches the
    # ``pack_router_mounted`` pattern above. Partial config (one or
    # both model deps supplied but the trio is incomplete) emits a
    # single structured warning so operators see the misconfig at
    # startup rather than at first-request 404.
    # ──────────────────────────────────────────────────────────────────
    app.state.models_router_mounted = False
    _model_deps_supplied = (model_registry_store is not None) + (model_trust_gate is not None)
    if (
        actor_binder is not None
        and model_registry_store is not None
        and model_trust_gate is not None
    ):
        app.state.model_registry_store = model_registry_store
        app.state.model_trust_gate = model_trust_gate
        # Sprint 9.5b C3 — thread the existing ``gateway_ledger`` kwarg
        # (already constructed by the create_app caller for the Sprint 3
        # T9 ``/effective-routing`` surface, attached at
        # ``app.state.gateway_ledger`` below) into the models router.
        # The same ``GatewayCallLedger`` instance now feeds BOTH
        # ``/effective-routing`` AND the new ``/usage``; NO new
        # construction. ``gateway_ledger`` may be None — see the
        # 4-state warning immediately below.
        app.include_router(
            build_models_router(
                store=model_registry_store,
                trust_gate=model_trust_gate,
                settings=settings,
                ledger=gateway_ledger,
            )
        )
        app.state.models_router_mounted = True
        # Sprint 9.5b C3 + PR #35 R2 plan-patch D7 — 4-state mount
        # warning. The models router is mounted (3 deps present) but
        # the gateway_ledger backend is missing. Operators see the
        # partial 9.5b config at startup, not only at first /usage
        # call (which surfaces as 503 gateway_ledger_not_configured).
        # The warning does NOT block the mount — the 5 other model
        # endpoints (register, promote, retire, list, detail, audit)
        # work fine without the ledger; only /usage is affected.
        if gateway_ledger is None:
            logger.warning(
                "portal.models.gateway_ledger_not_wired_partial_9_5b_config",
                extra={
                    "reason": "gateway_ledger_not_configured",
                    "endpoints_returning_503": ["/api/v1/models/{model_id}/usage"],
                    "note": (
                        "models router mounted with model deps; "
                        "gateway_ledger missing — /usage will return "
                        "503 until the ledger is wired."
                    ),
                },
            )
    elif _model_deps_supplied > 0:
        # Partial config — at least one model dep supplied, but the
        # trio is incomplete. Emit a single structured warning so
        # operator-bootstrap miss is visible at startup, NOT silently
        # no-mount. Pack-only deployments (zero model deps) skip this
        # branch and stay quiet per the user invariant.
        logger.warning(
            "portal.models_router_unmounted_partial_config",
            extra={
                "reason": "models_router_partial_config",
                "actor_binder_supplied": actor_binder is not None,
                "model_registry_store_supplied": model_registry_store is not None,
                "model_trust_gate_supplied": model_trust_gate is not None,
                "remediation": (
                    "Wave-1 model registry needs all three of: "
                    "actor_binder + model_registry_store + "
                    "model_trust_gate. Supply all three at create_app "
                    "to mount the /api/v1/models router; the partial "
                    "set leaves the router unmounted and every "
                    "/api/v1/models/* request would 404 at the FastAPI "
                    "level. The warning fires once at startup so the "
                    "wiring miss is visible immediately."
                ),
            },
        )

    # Sprint 9 T6: compliance route-package mount (ADR-006). Gated on
    # ``actor_binder is not None`` — the examiner evidence-pack / trace
    # endpoints declare per-route ``RequireScope(...)`` deps that need a
    # bound Actor identity; no ``pack_record_store`` dependency (the
    # compliance surface reads governance chains via the adapter pool,
    # not the pack store).
    if actor_binder is not None:
        from cognic_agentos.portal.api.compliance.router import build_compliance_routes

        app.include_router(build_compliance_routes(settings=settings))

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
