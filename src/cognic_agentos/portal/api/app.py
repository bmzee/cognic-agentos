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

import httpx
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
    build_adapters_async,
    bundled_registry,
    load_bundled_adapters,
)
from cognic_agentos.harness.sandbox import is_sandbox_available
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
from cognic_agentos.portal.api.approvals.routes import build_approval_routes
from cognic_agentos.portal.api.config_overlay.routes import build_config_overlay_routes
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
    # Sprint 11.5c T5: type-only ref for the ``memory_api_factory`` kwarg.
    # There is NO runtime import of the memory package in app.py — the factory
    # is supplied PRE-CONSTRUCTED by the caller (or None for pack-only
    # deployments). The lazy import of ``build_memory_routes`` inside the
    # conditional mount block keeps the portal import graph free of the memory
    # routes package when no factory is wired.
    # Sprint 13.5b1 (ADR-014): type-only refs for the create_app approval
    # kwargs (mirrors the config-overlay pattern below — the route factory
    # ``build_approval_routes`` is imported at runtime; the store + engine are
    # supplied PRE-CONSTRUCTED by build_runtime / the deploy entrypoint).
    from cognic_agentos.core.approval.engine import ApprovalEngine
    from cognic_agentos.core.approval.storage import ApprovalRequestStore

    # ADR-023 (Wave-2): type-only refs for the create_app config-overlay
    # kwargs. The route factory ``build_config_overlay_routes`` is imported at
    # runtime below (it pulls only already-imported core/rbac deps); the store +
    # resolver types are annotation-only here.
    from cognic_agentos.core.config_overlay.resolver import TenantConfigResolver
    from cognic_agentos.core.config_overlay.storage import TenantConfigOverlayStore

    # Sprint 13.6 (ADR-018): type-only ref for the create_app ``emergency_engine``
    # kwarg (mirrors the approval pattern — the route factory
    # ``build_emergency_routes`` is imported at runtime inside the mount block;
    # the engine is supplied PRE-CONSTRUCTED by build_runtime / the deploy
    # entrypoint). TYPE_CHECKING keeps the core/emergency module out of the
    # portal import graph for callers that don't wire emergency controls.
    from cognic_agentos.core.emergency.kill_switches import KillSwitchEngine
    from cognic_agentos.core.emergency.quotas import QuotaEngine
    from cognic_agentos.core.memory.api import MemoryApiFactory
    from cognic_agentos.core.memory.reaper import MemoryTombstoneReaper
    from cognic_agentos.core.policy.engine import OPAEngine

    # Harness Injection T8: type-only ref for the create_app ``llm_gateway``
    # kwarg (built by build_runtime in the lifespan, or injected on the
    # test/injection path); types the kwarg without pulling the gateway
    # module into the portal import graph.
    from cognic_agentos.llm.gateway import LLMGateway

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
    # ADR-023 (Wave-2): optional per-tenant config-overlay router deps. When
    # BOTH are wired, create_app mounts the operator-administered overlay router
    # under /api/v1 + sets app.state.config_overlay_router_mounted. Same opt-in
    # None-default pattern as pack_record_store. The composition root
    # (build_runtime) constructs them; a bank-overlay caller threads them here.
    config_overlay_store: TenantConfigOverlayStore | None = None,
    config_overlay_resolver: TenantConfigResolver | None = None,
    # ADR-014 (Sprint 13.5b1): optional approval-router deps. When BOTH are
    # wired, create_app mounts the approval router (queue/detail/grant/
    # grant-second/deny) + sets app.state.approval_router_mounted. Same opt-in
    # None-default pattern as config_overlay_store/_resolver — build_runtime
    # constructs the pair; the deploy entrypoint threads them here. The SAME
    # engine instance is reused by 13.5b2's MCP-host seam.
    approval_store: ApprovalRequestStore | None = None,
    approval_engine: ApprovalEngine | None = None,
    # ADR-018 (Sprint 13.6a): optional emergency kill-switch engine. When wired
    # ALONGSIDE decision_history_store, create_app mounts the emergency router
    # (kill-switches list/flip/revert + audit) + sets
    # app.state.emergency_router_mounted. Same opt-in injection-seam posture as
    # approval_store/_engine (13.5b1) — build_runtime constructs the engine
    # (its gateway + memory enforcement are production-wired); the deploy
    # entrypoint threads this instance here for the operator surface.
    emergency_engine: KillSwitchEngine | None = None,
    # ADR-018 (Sprint 13.6b): optional quota engine. When wired, create_app
    # mounts the read-only quota router (GET /api/v1/emergency/quotas) + sets
    # app.state.quota_router_mounted. Same opt-in injection-seam posture as
    # emergency_engine — build_runtime constructs it (its gateway enforcement
    # is production-wired); the deploy entrypoint threads this instance here.
    quota_engine: QuotaEngine | None = None,
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
    # Sprint 11.5c T5: optional /memory router wiring seam. When a
    # MemoryApiFactory is provided, the portal mounts the 4-endpoint
    # /api/v1/memory router (list_records / forget / redact / export).
    # When None — the dev / test / pack-only default — NO memory routes
    # are mounted and startup is SILENT (pack-only deployments without a
    # memory backend are legit). Same opt-in None-default pattern as
    # every other optional dependency on this factory. The lazy import of
    # build_memory_routes inside the conditional block keeps the portal
    # import graph free of the memory package when no factory is wired.
    memory_api_factory: MemoryApiFactory | None = None,
    # Harness Injection T8: the constructed kernel runtime's LLMGateway. On the
    # adapter path the lifespan's build_runtime overwrites app.state.llm_gateway
    # with the real gateway; this kwarg is the test / injection seam (None = the
    # default, pack-only / dev path).
    llm_gateway: LLMGateway | None = None,
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
        # Sprint 13.8 (ADR-002): predeclare BEFORE the inner try whose finally
        # closes it — a build_runtime failure before assignment must not leave
        # this name unbound when the finally runs.
        mcp_http_client: httpx.AsyncClient | None = None
        # Sprint 4 (ADR-003): the lifespan owns the A2A AgentCard-verifier httpx
        # client; predeclare BEFORE the inner try whose finally closes it (mirrors
        # mcp_http_client) so an early build_runtime failure never leaves it unbound.
        a2a_http_client: httpx.AsyncClient | None = None
        # Sprint 14A-A (ADR-004): the lifespan owns the sandbox docker client;
        # predeclare so the finally can close it even if construction failed early.
        sandbox_docker_client: Any | None = None

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
                # Sprint 4 (ADR-002/003/016): no adapter pool → no boot
                # discovery. Expose the injected registry (if any) so the
                # /api/v1/system/plugins honesty surface + non-adapter callers
                # still read it. The unification moved the eager body attach into
                # the lifespan; the shared-registry build (adapter path below)
                # needs the adapter pool, so the non-adapter path threads the
                # create_app kwarg as-is (None when not injected).
                app.state.plugin_registry = plugin_registry
                yield
                return

            # Trigger bundled-adapter registration side-effects. In the
            # default-adapters image this loads all five drivers; in the
            # kernel image (no `adapters` extras installed) every module
            # ImportErrors quietly per its allowlist and any configured
            # driver fails fast at build_adapters().
            if adapter_registry is bundled_registry:
                load_bundled_adapters()

            adapters = await build_adapters_async(settings, registry=adapter_registry)
            await adapters.open_all()
            app.state.adapters = adapters
            try:
                # Harness Injection T8: build the kernel runtime from the live
                # adapter pool (LLMGateway + governed-memory factory). Lazy
                # import keeps the harness out of the portal import graph until
                # the adapter path actually runs. INSIDE this inner try so a
                # build_runtime failure flows through the finally's close_all
                # (the runtime owns an http client that must not leak). Fail-loud
                # — a misconfigured gateway/memory aborts startup, never degrades.
                from cognic_agentos.harness import build_runtime

                runtime = await build_runtime(settings, adapters)
                app.state.runtime = runtime
                app.state.llm_gateway = runtime.llm_gateway
                app.state.memory_api_factory = runtime.memory_api_factory
                # Sprint 13.6 (ADR-018) — expose the kill-switch engine for
                # parity + introspection (enforcement is already production-
                # wired into the gateway + memory conformer build_runtime
                # constructed). The portal operator router mounts from the
                # create_app kwarg (approval 13.5b1 injection-seam posture).
                app.state.kill_switch_engine = runtime.kill_switch_engine
                # Sprint 13.6b (ADR-018) — expose the quota engine for parity +
                # introspection (the gateway quota gate is already production-
                # wired). The portal quota router mounts from the create_app
                # kwarg (the same injection-seam posture).
                app.state.quota_engine = runtime.quota_engine
                # Sprint 13.7 (ADR-022) — expose the scheduler for the 14A
                # managed-runtime path + introspection. None on the gateway-only
                # path (cache-conditional construction). NO router mount + NO
                # create_app kwarg in 13.7 (Fork D — construct + expose only).
                app.state.scheduler = runtime.scheduler

                # Sprint 4 (ADR-002/003/016) — ONE shared PluginRegistry feeds
                # BOTH the MCP host and the A2A endpoint (replacing the two
                # separate empty PluginRegistry(...) each surface built before).
                # The injected create_app kwarg wins (the caller owns
                # pre-population; NO discovery). Otherwise the off-gate
                # boot-builder discovers + trust-registers every installed pack
                # and returns ONE populated registry; it builds its OWN
                # registration_trust_gate (the §4 trapdoor — we pass NO
                # trust_gate). The boot is SDK-FREE (it runs whenever the adapter
                # pool is up). A RegistryBootError (broken
                # <trust_root_prefix>/_default/cosign.pub or a malformed
                # allow-list) is fail-closed: registry → None → BOTH surfaces
                # skip construction → their routes 503. The benign unset-root
                # path returns a real EMPTY registry (never None) → both surfaces
                # reachable-but-empty.
                registry: PluginRegistry | None = plugin_registry
                if registry is None:
                    from cognic_agentos.harness.registry_boot import (
                        RegistryBootError,
                        build_and_populate_registry,
                    )
                    from cognic_agentos.protocol.supply_chain import SupplyChainPipeline

                    object_store = adapters.object_store
                    if object_store is None:
                        # No object-store sink for the Sigstore-bundle evidence
                        # the trust pipeline persists → cannot trust-register.
                        # Treat like the unset-root posture (reachable-but-empty),
                        # NOT fail-closed-None: a missing optional adapter is not a
                        # misconfiguration the boot must refuse.
                        logger.warning("registry.boot_skipped_no_object_store")
                        registry = PluginRegistry(audit_store=runtime.audit_store)
                    else:
                        # mcp_admission is SDK-FREE to assemble (MCPAuthzClient +
                        # MCPAdmissionDeps carry no require_mcp()), so an MCP pack
                        # is ADMITTABLE on the kernel image; only RUNTIME serving
                        # (the MCPHost below) is SDK-gated. opa_engine=None keeps
                        # the boot off the OPA-binary path: a sampling-requiring
                        # MCP pack default-denies (mcp_sampling_default_denied) per
                        # the Sprint-4 default-deny doctrine; non-sampling MCP
                        # packs (the common case) admit. The probe-factory's
                        # MCPAuthzClient instances share a boot-owned httpx client
                        # closed in this block's finally (token-cache isolation is
                        # per-instance; the HTTP transport may be shared).
                        from cognic_agentos.protocol.mcp_authz import MCPAuthzClient
                        from cognic_agentos.protocol.plugin_registry import MCPAdmissionDeps

                        boot_http_client = httpx.AsyncClient()
                        try:
                            mcp_admission = MCPAdmissionDeps(
                                settings=settings,
                                vault_client=adapters.secret,
                                opa_engine=None,
                                make_authz_client_for_probe=lambda: MCPAuthzClient(
                                    settings=settings,
                                    vault_client=adapters.secret,
                                    http_client=boot_http_client,
                                    audit_store=runtime.audit_store,
                                    decision_history_store=runtime.decision_history_store,
                                ),
                            )
                            registry = await build_and_populate_registry(
                                settings=settings,
                                audit_store=runtime.audit_store,
                                supply_chain=SupplyChainPipeline(settings=settings),
                                object_store=object_store,
                                mcp_admission=mcp_admission,
                            )
                        except RegistryBootError as exc:
                            logger.error(
                                "registry.boot_failed_fail_closed",
                                extra={"reason": exc.reason},
                            )
                            registry = None
                        finally:
                            await boot_http_client.aclose()
                app.state.plugin_registry = registry
                if registry is None:
                    # Fail-closed (RegistryBootError): both protocol surfaces
                    # stay None below → their routes 503.
                    logger.error("protocol.registry_boot_failed_surfaces_unavailable")

                # Sprint 13.8 (ADR-002) — MCP host production construction,
                # SDK-gated (the mcp SDK is an optional `adapters` extra; the
                # kernel image lacks it). Constructed HERE in the lifespan (NOT
                # build_runtime, which stays SDK-free) because the host needs
                # runtime.audit_store / decision_history_store / approval_engine.
                # Dormant until a caller invokes call_tool (Fork D). Fail-soft:
                # a construction failure leaves app.state.mcp_host None + ERROR
                # log + the app still boots. mcp_http_client is predeclared above.
                if registry is not None and is_mcp_available():
                    from cognic_agentos.harness.mcp_host import build_mcp_host

                    mcp_http_client = httpx.AsyncClient()
                    try:
                        # Sprint 4: thread the SHARED registry (the same object
                        # the A2A endpoint receives below) — no per-surface empty
                        # PluginRegistry() fallback.
                        app.state.mcp_host = build_mcp_host(
                            registry=registry,
                            runtime=runtime,
                            settings=settings,
                            http_client=mcp_http_client,
                            vault_client=adapters.secret,
                        )
                    except Exception:
                        logger.error("mcp.host_construction_failed", exc_info=True)
                        await mcp_http_client.aclose()
                        mcp_http_client = None
                        app.state.mcp_host = None
                elif registry is not None:
                    logger.warning("mcp.host_unavailable_in_image", extra={"missing_module": "mcp"})

                # Sprint 4 (ADR-003) — A2A inbound endpoint production
                # construction, SDK-gated (the a2a SDK is an optional `adapters`
                # extra; the kernel image lacks it). Constructed HERE in the
                # lifespan (NOT build_runtime, which stays SDK-free) because the
                # endpoint needs runtime.audit_store / decision_history_store + the
                # live SecretAdapter (adapters.secret). Mirrors the MCP-host block
                # above: function-local imports, fail-soft (a construction failure
                # leaves app.state.a2a_endpoint None + ERROR log + the app still
                # boots), a2a_http_client predeclared above so the finally can close
                # it. The unconditionally-mounted /api/v1/a2a route 503s until this
                # populates app.state.a2a_endpoint.
                if registry is not None and is_a2a_available():
                    from cognic_agentos.protocol.a2a_agent_cards import A2AAgentCardVerifier
                    from cognic_agentos.protocol.a2a_authz import A2AAuthzClient
                    from cognic_agentos.protocol.a2a_endpoint import A2AEndpoint
                    from cognic_agentos.protocol.trust_gate import TrustGate

                    # Sprint 4: the SHARED `registry` (the same object the MCP host
                    # received above) feeds plugin_registry below. The endpoint
                    # keeps its OWN `a2a_trust_gate` — DISTINCT from the boot's
                    # registration_trust_gate (the §4 trapdoor). The card verifier's
                    # TrustGate verifies AgentCard JWS against the per-tenant trust
                    # root read through adapters.secret; it does NOT read
                    # signature_root_path (which the boot's gate overrides), so the
                    # two gates correctly stay distinct objects.
                    a2a_trust_gate = trust_gate or TrustGate(
                        settings=settings,
                        audit_store=runtime.audit_store,
                        secret_adapter=adapters.secret,
                    )
                    a2a_http_client = httpx.AsyncClient()
                    try:
                        a2a_authz = A2AAuthzClient(
                            settings=settings,
                            vault_client=adapters.secret,
                            audit_store=runtime.audit_store,
                            decision_history_store=runtime.decision_history_store,
                        )
                        a2a_cards = A2AAgentCardVerifier(
                            settings=settings,
                            trust_gate=a2a_trust_gate,
                            audit_store=runtime.audit_store,
                            decision_history_store=runtime.decision_history_store,
                            http_client=a2a_http_client,
                        )
                        app.state.a2a_endpoint = A2AEndpoint(
                            settings=settings,
                            plugin_registry=registry,
                            authz_client=a2a_authz,
                            agent_card_verifier=a2a_cards,
                            audit_store=runtime.audit_store,
                            decision_history_store=runtime.decision_history_store,
                        )
                    except Exception:
                        logger.error("a2a.endpoint_construction_failed", exc_info=True)
                        await a2a_http_client.aclose()
                        a2a_http_client = None
                        app.state.a2a_endpoint = None
                elif registry is not None:
                    logger.warning(
                        "a2a.endpoint_unavailable_in_image",
                        extra={"missing_module": "a2a"},
                    )

                # Sprint 14A-A (ADR-004/022): SDK-gated managed-run sandbox
                # backend + executor construction. DockerSibling-only; fail-soft.
                # build_runtime stays SDK-free; this is the lifespan's job (the
                # backend needs aiodocker + Vault + OPA + a real scheduler).
                # sandbox_docker_client is predeclared above so the finally can
                # close it even if construction raised early.
                if (
                    is_sandbox_available(settings)
                    and settings.sandbox_runtime_enabled
                    and runtime.scheduler is not None
                ):
                    from cognic_agentos.core.run.executor import ManagedRunExecutor
                    from cognic_agentos.core.run.storage import RunRecordStore
                    from cognic_agentos.harness.sandbox import (
                        PackRecordStoreLoader,
                        build_sandbox_backend,
                    )

                    try:
                        # Sprint 14A-A3b — resolve the CheckpointStore INSIDE the
                        # try + thread it into BOTH the backend (so suspend()'s
                        # final checkpoint persists) AND the executor (so the
                        # suspend branch can load_latest the checkpoint metadata).
                        # An explicit create_app(checkpoint_store=...) injection
                        # wins; else build from the live adapter pool. Share the
                        # resolved store onto app.state so the setting-driven reaper
                        # block below reuses the SAME instance (one CheckpointStore
                        # across the sandbox runtime + the retention reaper — the
                        # early injected_store capture at construction predates this
                        # block).
                        checkpoint_store = (
                            app.state.checkpoint_store
                            or _build_checkpoint_store_from_adapters(adapters, settings)
                        )
                        app.state.checkpoint_store = checkpoint_store
                        backend, sandbox_docker_client = await build_sandbox_backend(
                            settings=settings,
                            runtime=runtime,
                            checkpoint_store=checkpoint_store,
                        )
                        app.state.sandbox_backend = backend
                        run_record_store = RunRecordStore(adapters.relational.engine)
                        app.state.managed_run_executor = ManagedRunExecutor(
                            scheduler=runtime.scheduler,
                            sandbox_backend=backend,
                            pack_loader=PackRecordStoreLoader(
                                store=PackRecordStore(adapters.relational.engine)
                            ),
                            decision_history_store=runtime.decision_history_store,
                            settings=settings,
                            run_record_store=run_record_store,
                            checkpoint_store=checkpoint_store,
                        )
                        # 2026-06-20 (ADR-005, Fork B) — publish the SAME run-record
                        # store the executor uses so POST /api/v1/subagents can
                        # resolve parent_run_id -> task_id (tenant-scoped). Co-populated
                        # with the spawner; the route's combined 503 dep covers either.
                        app.state.run_record_store = run_record_store
                        # 2026-06-20 (ADR-005) — compose the live SubAgentSpawner
                        # off the SAME runtime + engine. WIRED-but-DORMANT: no
                        # route/caller consumes app.state.subagent_spawner yet
                        # (mirrors the 13.7 scheduler / 13.8 MCP-host posture).
                        from cognic_agentos.harness.sandbox import build_subagent_spawner

                        app.state.subagent_spawner = build_subagent_spawner(
                            runtime=runtime,
                            managed_run_executor=app.state.managed_run_executor,
                            engine=adapters.relational.engine,
                            settings=settings,
                        )
                    except Exception:
                        logger.error("sandbox.runtime_construction_failed", exc_info=True)
                        if sandbox_docker_client is not None:
                            await sandbox_docker_client.close()
                        sandbox_docker_client = None
                        app.state.sandbox_backend = None
                        app.state.managed_run_executor = None
                        app.state.subagent_spawner = None
                        app.state.run_record_store = None
                elif settings.sandbox_runtime_enabled:
                    logger.warning(
                        "sandbox.runtime_unavailable_or_disabled",
                        extra={
                            "sandbox_backend": settings.sandbox_backend,
                            "scheduler_present": runtime.scheduler is not None,
                        },
                    )

                # #489 — setting-driven reaper: build the CheckpointStore
                # from the live adapter pool AFTER open_all() so the
                # relational adapter's engine is connected. This build is
                # INSIDE the inner try so a builder fail-loud still runs
                # close_all() + clears app.state.adapters.
                if setting_driven_reaper:
                    # Sprint 14A-A3b — reuse the CheckpointStore the sandbox block
                    # above resolved onto app.state (one store across the sandbox
                    # runtime + the reaper); else build our own (sandbox disabled /
                    # unavailable path). Still fail-louds per #489 §4.3.2 if the
                    # build raises.
                    store = app.state.checkpoint_store or _build_checkpoint_store_from_adapters(
                        adapters, settings
                    )
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
                # Harness Injection T8: close the runtime BEFORE the adapter pool
                # (user-locked runtime-first ordering). Today the runtime owns
                # only the gateway's HTTP client, but its memory_api_factory
                # closes over adapter-backed clients (engine, cache) — close it
                # first in case a future runtime resource depends on them.
                # getattr-guarded so a build_runtime failure (runtime never set)
                # does not AttributeError here; T6's leak-fix guarantees no http
                # client was allocated if build_runtime raised before Runtime
                # existed.
                _runtime = getattr(app.state, "runtime", None)
                if _runtime is not None:
                    await _runtime.aclose()
                await adapters.close_all()
                app.state.adapters = None
                # Sprint 13.8 (ADR-002): close the lifespan-owned MCP authz
                # httpx client. Bound (predeclared) even if build_runtime raised,
                # so this never UnboundLocalErrors; None unless the host was
                # constructed on the SDK-present path.
                if mcp_http_client is not None:
                    await mcp_http_client.aclose()
                # Sprint 4 (ADR-003): close the lifespan-owned A2A AgentCard-verifier
                # httpx client. Bound (predeclared) even if build_runtime raised, so
                # this never UnboundLocalErrors; None unless the endpoint was
                # constructed on the SDK-present path.
                if a2a_http_client is not None:
                    await a2a_http_client.aclose()
                # Sprint 14A-A (ADR-004): close the lifespan-owned sandbox docker
                # client. Predeclared above, so this never UnboundLocalErrors;
                # None unless the backend was constructed on the SDK-present path.
                if sandbox_docker_client is not None:
                    await sandbox_docker_client.close()
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

    # Sprint 11.5c T5 + Harness-Injection T7: memory API factory wiring seam.
    # Stored on app.state because the route handlers resolve it from
    # app.state.memory_api_factory at REQUEST time (T7 — no longer closure-
    # captured), so the lifespan's build_runtime can populate it late.
    app.state.memory_api_factory = memory_api_factory

    # Harness Injection T8: gateway + runtime state seams. ``llm_gateway`` holds
    # the kwarg value at construction (None in prod; the lifespan's build_runtime
    # overwrites it with the real gateway on the adapter path). ``runtime`` is
    # pre-seeded None so pre-startup introspection AND the lifespan finally's
    # getattr guard see a defined attribute (mirrors ``reaper_task = None``).
    app.state.llm_gateway = llm_gateway
    app.state.runtime = None
    # Sprint 13.6 (ADR-018): kill-switch engine introspection seam. Pre-seeded
    # None so pre-startup introspection sees a defined attribute; the lifespan's
    # build_runtime populates it on the adapter path (None on the gateway-only
    # path — no cache → no engine).
    app.state.kill_switch_engine = None
    app.state.quota_engine = None  # Sprint 13.6b — same introspection seam.
    app.state.scheduler = None  # Sprint 13.7 (ADR-022) — same introspection seam.
    # Sprint 4 (ADR-002/003/016) — ONE shared PluginRegistry feeds both the MCP
    # host + the A2A endpoint. Predeclared None (alongside mcp_host/a2a_endpoint);
    # the lifespan populates it with the injected-or-discovered registry.
    app.state.plugin_registry = None
    app.state.mcp_host = None  # Sprint 13.8 (ADR-002) — SDK-gated; lifespan populates.
    app.state.a2a_endpoint = None  # Sprint 4 (ADR-003) — SDK-gated; lifespan populates.
    app.state.sandbox_backend = None  # Sprint 14A-A (ADR-004) — SDK-gated; lifespan populates.
    app.state.managed_run_executor = None  # Sprint 14A-A (ADR-022) — lifespan populates.
    app.state.subagent_spawner = None  # 2026-06-20 sub-agent dispatch — lifespan populates.
    app.state.run_record_store = None  # 2026-06-20 (ADR-005) — lifespan publishes; route resolves.

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
                # Wave-1 T6 — thread the operator-configured adversarial
                # pass-rate floor from the captured ``settings`` (NOT
                # ``get_settings()``) through to the approve handler's gate-3.
                adversarial_pass_rate_floor=settings.adversarial_pass_rate_floor,
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
    # ADR-023 (Wave-2) — per-tenant config-overlay router mount.
    #
    # 3-state mount mirroring the packs router: BOTH store + resolver
    # supplied -> mount the operator-administered overlay router under
    # ``/api/v1`` + set the introspection flag; partial config (exactly
    # one supplied) -> a single structured fail-loud warning so operators
    # see the misconfig at startup; neither -> no mount (silent — the
    # overlay is an opt-in surface). There is deliberately NO actor_binder
    # gate at the mount boundary: the routes read the binder from
    # ``app.state`` at REQUEST time and the KernelDefaultActorBinder fails
    # loud there, so a binder-less mount surfaces a clear 500 rather than a
    # confusing 404.
    # ──────────────────────────────────────────────────────────────────
    app.state.config_overlay_router_mounted = False
    if config_overlay_store is not None and config_overlay_resolver is not None:
        app.include_router(
            build_config_overlay_routes(
                store=config_overlay_store,
                resolver=config_overlay_resolver,
                settings=settings,
            ),
            prefix="/api/v1",
        )
        app.state.config_overlay_router_mounted = True
    elif config_overlay_store is not None or config_overlay_resolver is not None:
        logger.warning(
            "portal.config_overlay_router_unmounted_partial_config",
            extra={
                "reason": "config_overlay_store_and_resolver_both_required",
                "remediation": (
                    "create_app(config_overlay_store=<store>, "
                    "config_overlay_resolver=<resolver>) wires the "
                    "config-overlay router; BOTH are required. The "
                    "composition root build_runtime constructs them as a "
                    "pair, so a partial config indicates a hand-wired caller "
                    "missing one half."
                ),
            },
        )

    # ──────────────────────────────────────────────────────────────────
    # Sprint 13.5b1 — approval router mount (ADR-014).
    #
    # Mirrors the config-overlay 3-state mount above: BOTH deps -> mount
    # under /api/v1/approvals (the router carries its own prefix) + set
    # the introspection flag; partial config -> a single structured
    # fail-loud warning; neither -> no mount (opt-in surface). No
    # actor_binder gate at the mount boundary for the same reason as the
    # overlay block: the routes read the binder from app.state at
    # REQUEST time and fail loud there. The ENGINE stays authoritative
    # for every approval decision (spec §5) — this block only wires it.
    # ──────────────────────────────────────────────────────────────────
    app.state.approval_router_mounted = False
    if approval_store is not None and approval_engine is not None:
        app.include_router(build_approval_routes(store=approval_store, engine=approval_engine))
        app.state.approval_router_mounted = True
    elif approval_store is not None or approval_engine is not None:
        logger.warning(
            "portal.approval_router_unmounted_partial_config",
            extra={
                "reason": "approval_store_and_engine_both_required",
                "remediation": (
                    "create_app(approval_store=<store>, approval_engine=<engine>) "
                    "wires the approval router; BOTH are required. The "
                    "composition root build_runtime constructs them as a "
                    "pair, so a partial config indicates a hand-wired caller "
                    "missing one half."
                ),
            },
        )

    # ──────────────────────────────────────────────────────────────────
    # Sprint 13.6a — emergency kill-switch router mount (ADR-018).
    #
    # Mirrors the approval 3-state mount above: emergency_engine +
    # decision_history_store both present -> mount under /api/v1/emergency
    # (the router carries its own prefix) + set the introspection flag;
    # emergency_engine present but decision_history_store absent -> a single
    # structured fail-loud warning (the GET /audit endpoint reads the DH
    # store, so BOTH are required); neither -> no mount (opt-in operator
    # surface). No actor_binder gate at the mount boundary for the same
    # reason as the approval block: the routes read the binder from app.state
    # at REQUEST time and fail loud there. The ENGINE owns the brake + the
    # chain evidence; this block only wires the operator surface.
    # ──────────────────────────────────────────────────────────────────
    app.state.emergency_router_mounted = False
    if emergency_engine is not None and decision_history_store is not None:
        from cognic_agentos.portal.api.emergency.routes import build_emergency_routes

        app.include_router(
            build_emergency_routes(
                engine=emergency_engine,
                decision_history_store=decision_history_store,
            )
        )
        app.state.emergency_router_mounted = True
    elif emergency_engine is not None and decision_history_store is None:
        logger.warning(
            "portal.emergency_router_unmounted_partial_config",
            extra={
                "reason": "emergency_engine_and_decision_history_store_both_required",
                "remediation": (
                    "create_app(emergency_engine=<engine>, "
                    "decision_history_store=<store>) wires the emergency router; "
                    "the GET /audit endpoint reads the decision_history store, so "
                    "BOTH are required. The composition root build_runtime "
                    "constructs the engine over the relational engine's DH store."
                ),
            },
        )

    # ──────────────────────────────────────────────────────────────────
    # Sprint 13.6b — read-only quota router mount (ADR-018).
    #
    # Single-dep mount (the read surface needs only the QuotaEngine + the
    # global Settings, which is always resolved): wired → mount under
    # /api/v1/emergency (the router carries its own prefix) + set the
    # introspection flag; unwired → no mount (opt-in operator surface,
    # the emergency injection-seam posture). The QuotaEngine's gateway
    # enforcement is production-wired via build_runtime; this is the
    # read-only operator surface.
    # ──────────────────────────────────────────────────────────────────
    app.state.quota_router_mounted = False
    if quota_engine is not None:
        from cognic_agentos.portal.api.emergency.quota_routes import build_quota_routes

        # ``settings`` is the create_app-local resolved Settings (line 435:
        # ``settings or get_settings()``) — always non-None here.
        app.include_router(build_quota_routes(quota_engine=quota_engine, settings=settings))
        app.state.quota_router_mounted = True

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

    # Sprint 11.5c T5 + Harness-Injection T8: memory router mount (ADR-019).
    #
    # Mounted at CONSTRUCTION time when EITHER a factory is injected (test
    # path) OR cache_driver != "none" (prod — the lifespan's build_runtime
    # populates app.state.memory_api_factory after open_all; a request before
    # then fails closed 503 per T7). cache_driver="none" with no injected
    # factory mounts NOTHING — pack-only deployments stay silent. The lazy
    # import of ``build_memory_routes`` keeps the portal import graph free of
    # the memory package when the router is not mounted.
    app.state.memory_router_mounted = False
    if memory_api_factory is not None or settings.cache_driver != "none":
        from cognic_agentos.portal.api.memory import build_memory_routes

        app.include_router(
            build_memory_routes(),
            prefix="/api/v1/memory",
            tags=["memory"],
        )
        app.state.memory_router_mounted = True

    # Eval judge surface (ADR-010 — first gateway consumer). Unconditional:
    # the gateway is always built by build_runtime; the route's DI fails closed
    # 503 until app.state.llm_gateway is populated. Lazy import.
    from cognic_agentos.portal.api.evaluation.routes import build_eval_routes

    app.include_router(
        build_eval_routes(eval_judge_tier=settings.eval_judge_tier),
        prefix="/api/v1/eval",
        tags=["eval"],
    )

    # Managed-run surface (ADR-022 — POST /api/v1/runs). Unconditional mount: the
    # executor is populated by the lifespan only when sandbox_runtime_enabled +
    # is_sandbox_available; the route's request-time dep returns 503
    # sandbox_runtime_unavailable until then. Lazy import.
    from cognic_agentos.portal.api.runs.routes import build_run_routes

    app.include_router(
        build_run_routes(),
        prefix="/api/v1/runs",
        tags=["runs"],
    )

    from cognic_agentos.portal.api.subagents import build_subagent_routes

    app.include_router(
        build_subagent_routes(),
        prefix="/api/v1/subagents",
        tags=["subagents"],
    )

    # A2A inbound receiver surface (ADR-003 — POST /api/v1/a2a/{target_agent}).
    # Unconditional mount: the endpoint is populated by the lifespan only when
    # is_a2a_available() (the a2a SDK is an optional `adapters` extra); the route's
    # request-time dep returns 503 a2a_endpoint_unavailable until then. Lazy import
    # (the route module is SDK-free, so this is safe in the kernel image).
    from cognic_agentos.portal.api.a2a import build_a2a_routes

    app.include_router(
        build_a2a_routes(),
        prefix="/api/v1/a2a",
        tags=["a2a"],
    )

    # MCP tool-invocation surface (ADR-002 "Fork D"). Unconditional mount: the
    # host is populated by the lifespan only when is_mcp_available(); the route's
    # request-time dep returns 503 mcp_host_unavailable until then. Lazy import
    # (the module is SDK-free, so this is safe in the kernel image).
    from cognic_agentos.portal.api.mcp.routes import build_mcp_routes

    app.include_router(
        build_mcp_routes(),
        prefix="/api/v1/mcp",
        tags=["mcp"],
    )

    from cognic_agentos.portal.api.evaluation.bulk_routes import build_eval_bulk_routes

    app.include_router(
        build_eval_bulk_routes(
            max_cases=settings.eval_bulk_max_cases,
            max_raw_output_chars=settings.eval_bulk_max_raw_output_chars,
            target_tier=settings.eval_bulk_target_tier,
            judge_tier=settings.eval_judge_tier,
        ),
        prefix="/api/v1/eval",
        tags=["eval"],
    )

    from cognic_agentos.portal.api.evaluation.replay_routes import build_eval_replay_routes

    app.include_router(
        build_eval_replay_routes(
            max_cases=settings.eval_bulk_max_cases,
            max_raw_output_chars=settings.eval_bulk_max_raw_output_chars,
            target_tier=settings.eval_bulk_target_tier,
            judge_tier=settings.eval_judge_tier,
        ),
        prefix="/api/v1/eval",
        tags=["eval"],
    )

    from cognic_agentos.portal.api.evaluation.adversarial_routes import (
        build_eval_adversarial_routes,
    )

    app.include_router(
        build_eval_adversarial_routes(
            max_cases=settings.eval_bulk_max_cases,
            max_raw_output_chars=settings.eval_bulk_max_raw_output_chars,
            target_tier=settings.eval_bulk_target_tier,
            judge_tier=settings.eval_judge_tier,
        ),
        prefix="/api/v1/eval",
        tags=["eval"],
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

    The actual ``MCPHost`` wiring landed in Sprint 13.8 (the long-deferred
    "Sprint-5 T9") — but in the ``create_app`` LIFESPAN (after ``build_runtime``,
    where ``runtime.audit_store`` / ``approval_engine`` exist), NOT here.
    ``create_prod_app`` remains availability-LOG-only: it logs SDK presence /
    absence but does not construct the host. ``create_app`` pre-seeds
    ``app.state.mcp_host = None`` at construction; the lifespan replaces it with
    the real host on the SDK-present path.
    """

    app = create_app(adapter_registry=bundled_registry)
    if is_mcp_available():
        # Sprint-5 T2: log SDK presence. SUPERSEDED by Sprint 13.8 — the actual
        # MCPHost construction lands in the create_app LIFESPAN (after
        # build_runtime, where runtime.audit_store/approval_engine exist), NOT
        # here in create_prod_app (pre-lifespan). This branch stays a
        # startup-presence log only.
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

    # A2A SDK presence check — create_prod_app() LOG ONLY. Mirrors the MCP
    # branch above (same R3 P1 doctrine: kernel image stays SDK-free;
    # default-adapters image carries the SDK). As of the ADR-003 A2A
    # inbound-reachability slice (2026-06-21) the receiver ROUTE is mounted
    # UNCONDITIONALLY and the `A2AEndpoint` is constructed in create_app()'s
    # lifespan — this factory only LOGS presence (the dual-location pattern
    # MCPHost already uses: the presence-log lives here; the real wiring
    # lives in create_app). Still deferred to their own follow-on slices:
    #   - the auxiliary A2A surfaces — capabilities / cancellation / artifacts
    #   - the T12 UI-event emit hooks (NO HTTP route; ADR-020 SSE)
    if is_a2a_available():
        logger.info("a2a.sdk_present_at_startup", extra={"image": "default-adapters"})
    else:
        # Kernel image (or any venv missing `a2a-sdk`). Admission-side
        # A2A modules (a2a_authz, a2a_agent_cards, a2a_schema,
        # a2a_version) import + construct without the SDK installed
        # (per Sprint-5 R3 P1 + Sprint-6 same doctrine — SDK-free);
        # the receiver route still 503s (create_app's lifespan leaves
        # app.state.a2a_endpoint None without the SDK).
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
