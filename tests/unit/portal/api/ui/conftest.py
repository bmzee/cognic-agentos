"""Sprint 7B.4 T6 — pytest fixtures for the SSE / action / well-known
test suite.

Plain helpers live in `sse_test_helpers.py` (test files import them
explicitly per pytest's plain-callable-no-auto-inject contract); this
module holds ONLY fixtures that pytest auto-discovers under the
directory tree.

Skeleton ships at T6 so the T6 RBAC tests' cross-directory import of
the helpers resolves. T10 may add SSE-specific fixtures (per-test
broker-tear-down hooks, etc.) but the foundational fixtures are
locked here.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.protocol.ui_events import UIEventBroker, UIEventEmitter
from tests.unit.portal.api.ui.sse_test_helpers import _FixtureActorBinder


@pytest.fixture
async def sqlite_engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    """Per-test sqlite-aiosqlite engine with both chain heads seeded."""
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'ui_test.db'}")
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id,
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=datetime.now(UTC),
                )
            )
    yield eng
    await eng.dispose()


@pytest.fixture
def settings() -> Settings:
    """Test-default Settings with SHORT SSE heartbeat + send_timeout
    so streaming-test ``async with c.stream(...)`` blocks unwind
    quickly on client disconnect (production defaults: heartbeat=15s
    + send_timeout=30s; tests can't wait that long per iteration).

    The minimum Pydantic-validated bound is 1s on both fields; tests
    that need sub-second cadence (``test_broker_emits_keepalive_every_n_seconds``)
    monkey-patch ``broker._settings.ui_event_stream_heartbeat_interval_s``
    directly, bypassing Pydantic validation."""
    return Settings(
        ui_event_stream_heartbeat_interval_s=1,
        ui_event_stream_send_timeout_s=2,
    )


# Backward-compat hook for the original T6-shipped `settings` fixture:
# the unit suite predating T10 expects ``settings`` to return production
# defaults. T10 overrode the base fixture above with short cadences
# because every T10 streaming test depends on ``settings`` indirectly
# via the ``broker`` + ``app`` fixtures. Pre-T10 callers that need
# production defaults can request ``settings_production_defaults``.
@pytest.fixture
def settings_production_defaults() -> Settings:
    return Settings()


@pytest.fixture
def settings_low_cap() -> Settings:
    """Settings with per-tenant cap = 1 for the cap-exceeded regression."""
    return Settings(ui_event_stream_per_tenant_cap=1)


@pytest.fixture
def settings_short_send_timeout() -> Settings:
    """Settings with send_timeout = 1s for the half-open-cleanup regression."""
    return Settings(ui_event_stream_send_timeout_s=1)


@pytest.fixture
async def audit_store(sqlite_engine: AsyncEngine) -> AuditStore:
    return AuditStore(sqlite_engine)


@pytest.fixture
async def decision_history_store(sqlite_engine: AsyncEngine) -> DecisionHistoryStore:
    return DecisionHistoryStore(sqlite_engine)


@pytest.fixture
async def ui_event_emitter(
    audit_store: AuditStore,
    decision_history_store: DecisionHistoryStore,
) -> UIEventEmitter:
    return UIEventEmitter(
        audit_store=audit_store,
        decision_history_store=decision_history_store,
    )


@pytest.fixture
async def broker(
    decision_history_store: DecisionHistoryStore,
    ui_event_emitter: UIEventEmitter,
    settings: Settings,
) -> UIEventBroker:
    b = UIEventBroker(decision_history_store=decision_history_store, settings=settings)
    b.register_with_emitter(ui_event_emitter)
    return b


@pytest.fixture
def actor_t1() -> Actor:
    """UI-test actor: tenant t1; holds all 8 UI scopes."""
    return Actor(
        subject="u1",
        tenant_id="t1",
        actor_type="human",
        scopes=frozenset(
            {
                "ui.run_stream",
                "ui.tenant_stream",
                "ui.action.approve",
                "ui.action.deny",
                "ui.action.cancel_run",
                "ui.action.interrupt",
                "ui.action.resume",
                "ui.action.submit_elicitation",
            }
        ),
    )


@pytest.fixture
async def app_with_broker(
    broker: UIEventBroker,
    decision_history_store: DecisionHistoryStore,
    audit_store: AuditStore,
    ui_event_emitter: UIEventEmitter,
    settings: Settings,
    actor_t1: Actor,
) -> FastAPI:
    """UI-test app: broker wired via create_app; actor binder mocked to
    actor_t1. Used by tests that exercise non-UI routes (pack routes for
    RBAC denial flows in T6; the alias `app` below adds UI routes once
    T10 ships)."""
    from cognic_agentos.portal.api.app import create_app

    return create_app(
        settings=settings,
        decision_history_store=decision_history_store,
        audit_store=audit_store,
        ui_event_emitter=ui_event_emitter,
        actor_binder=_FixtureActorBinder(actor_t1),
    )


@pytest.fixture
async def app(
    app_with_broker: FastAPI,
    broker: UIEventBroker,
    settings: Settings,
    decision_history_store: DecisionHistoryStore,
) -> FastAPI:
    """UI-routes-mounted app fixture.

    Wraps `app_with_broker` and includes the T10 SSE stream router via
    lazy import. The lazy import lets this fixture coexist in the T6
    conftest WITHOUT breaking T6's RBAC test collection — T6 RBAC tests
    use `app_with_broker` directly (no UI routes needed); the import
    only fires when a test requests `app` (T10+ SSE tests).

    T10 plan-vs-reality drift #1: ``build_stream_routes`` takes
    ``settings`` + ``decision_history_store`` via closure-capture
    (NOT ``request.app.state.settings``) because ``create_app``
    populates ``app.state.decision_history_store`` but NOT
    ``app.state.settings``. Closure-capture keeps ``create_app``
    untouched (avoids a CC-ADJ to portal/api/app.py) and matches
    the existing ``broker=`` capture pattern.

    Production-grade: NO silent fallback. If a test requests `app` and
    the stream_routes module is missing (e.g. running T10 tests before
    T10 ships the module), the lazy import raises ImportError — that
    IS the TDD RED for those tests."""
    # Lazy import. At T6 time stream_routes didn't exist; ``# type: ignore
    # [import-untyped]`` was needed. T10 shipped the module so the ignore
    # is unused now; left in place as a runtime-import-only convention.
    from cognic_agentos.portal.api.ui.stream_routes import build_stream_routes

    app_with_broker.include_router(
        build_stream_routes(
            broker=broker,
            settings=settings,
            decision_history_store=decision_history_store,
        ),
        prefix="/api/v1/ui",
    )
    return app_with_broker


# ---------------------------------------------------------------------------
# T10 SSE-test fixture extensions (per plan §1129 — "T10 may extend").
# ---------------------------------------------------------------------------
#
# The cap-exceeded + half-open-cleanup regressions need a BROKER built
# from `settings_low_cap` / `settings_short_send_timeout` respectively
# (not the default `settings` cap=50 / timeout=30). Per plan §3475-3479:
# pairing the broker with its scoped settings is load-bearing — using
# default `settings_low_cap` alone wouldn't fire the cap because the
# `app` fixture's broker was constructed from DEFAULT settings.


@pytest.fixture
async def broker_low_cap(
    decision_history_store: DecisionHistoryStore,
    ui_event_emitter: UIEventEmitter,
    settings_low_cap: Settings,
) -> UIEventBroker:
    """Broker variant wired with cap=1 settings — used by the
    `TestTenantConnectionCapExceeded` regression in T10's
    test_stream_routes.py (plan §3472)."""
    b = UIEventBroker(
        decision_history_store=decision_history_store,
        settings=settings_low_cap,
    )
    b.register_with_emitter(ui_event_emitter)
    return b


@pytest.fixture
async def app_low_cap(
    broker_low_cap: UIEventBroker,
    decision_history_store: DecisionHistoryStore,
    audit_store: AuditStore,
    ui_event_emitter: UIEventEmitter,
    settings_low_cap: Settings,
    actor_t1: Actor,
) -> FastAPI:
    """App variant with broker built from `settings_low_cap` (cap=1).

    Per plan §3475-3479: re-roots both `create_app` AND
    `build_stream_routes(broker=, settings=)` at `settings_low_cap` so
    the second SSE connect on the same tenant actually hits the cap.
    The `app` fixture would NOT fire 429 because its broker carries
    default cap=50."""
    from cognic_agentos.portal.api.app import create_app
    from cognic_agentos.portal.api.ui.stream_routes import build_stream_routes

    application = create_app(
        settings=settings_low_cap,
        decision_history_store=decision_history_store,
        audit_store=audit_store,
        ui_event_emitter=ui_event_emitter,
        actor_binder=_FixtureActorBinder(actor_t1),
    )
    application.include_router(
        build_stream_routes(
            broker=broker_low_cap,
            settings=settings_low_cap,
            decision_history_store=decision_history_store,
        ),
        prefix="/api/v1/ui",
    )
    return application


@pytest.fixture
async def broker_short_send_timeout(
    decision_history_store: DecisionHistoryStore,
    ui_event_emitter: UIEventEmitter,
    settings_short_send_timeout: Settings,
) -> UIEventBroker:
    """Broker variant wired with send_timeout=1s settings — used by the
    `TestSendTimeoutCleansUpHalfOpenClient` regression (plan §3711)."""
    b = UIEventBroker(
        decision_history_store=decision_history_store,
        settings=settings_short_send_timeout,
    )
    b.register_with_emitter(ui_event_emitter)
    return b


@pytest.fixture
async def app_short_send_timeout(
    broker_short_send_timeout: UIEventBroker,
    decision_history_store: DecisionHistoryStore,
    audit_store: AuditStore,
    ui_event_emitter: UIEventEmitter,
    settings_short_send_timeout: Settings,
    actor_t1: Actor,
) -> FastAPI:
    """App variant whose broker + EventSourceResponse use the
    short-send-timeout settings (per plan §3714-3717)."""
    from cognic_agentos.portal.api.app import create_app
    from cognic_agentos.portal.api.ui.stream_routes import build_stream_routes

    application = create_app(
        settings=settings_short_send_timeout,
        decision_history_store=decision_history_store,
        audit_store=audit_store,
        ui_event_emitter=ui_event_emitter,
        actor_binder=_FixtureActorBinder(actor_t1),
    )
    application.include_router(
        build_stream_routes(
            broker=broker_short_send_timeout,
            settings=settings_short_send_timeout,
            decision_history_store=decision_history_store,
        ),
        prefix="/api/v1/ui",
    )
    return application


# ---------------------------------------------------------------------------
# Uvicorn-in-thread fixture for SSE streaming tests
# (per T10 user-locked test-strategy doctrine, 2026-05-16)
# ---------------------------------------------------------------------------
#
# httpx 0.28.1's ``ASGITransport.handle_async_request`` buffers the
# entire response body before returning (``body_parts: list = []``;
# ``await self.app(scope, receive, send)`` only returns after
# ``more_body=False`` is sent). For infinite SSE responses ``app()``
# never returns → ``c.stream(...).__aenter__()`` never returns → tests
# hang. Additionally ``ASGITransport.receive()`` only returns
# ``http.disconnect`` AFTER ``response_complete.set()``, so sse-
# starlette's ``_listen_for_disconnect`` cannot propagate close.
#
# The user-locked Hybrid test strategy splits SSE tests into:
#
#   - ASGITransport (``_async_client``) for refusal tests that return
#     a complete response synchronously (RBAC 403, cross-tenant 404,
#     malformed-cursor 422, etc.)
#   - Real uvicorn-in-thread (``uvicorn_app_factory`` + ``_real_client``)
#     for tests that open a streaming response and consume body chunks
#     (live SSE, replay-then-live, Last-Event-ID reconnect, dedup,
#     heartbeat cadence, send_timeout cleanup, connection cap)
#   - Direct-generator drive for cleanup/finally behavior + supplemental
#     edge cases (NOT a substitute for the through-the-stack proof)
#
# ``uvicorn_app_factory`` is **function-scoped** (per-test). Per-test
# fresh sqlite + broker requires per-test fresh app; sharing a
# session-scoped server would break test isolation. Uvicorn startup
# is ~50-100ms; cheap enough for ~12 streaming tests.


def _allocate_free_port() -> int:
    """Bind a transient socket to port 0; OS picks a free ephemeral
    port; close socket; return the port. Standard idiom; small window
    of port-stealing race between close() and uvicorn bind() is
    acceptable for test infra."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
    finally:
        s.close()


@pytest.fixture
async def uvicorn_app_factory() -> AsyncIterator[
    Callable[[FastAPI], contextlib.AbstractAsyncContextManager[str]]
]:
    """Returns an async context manager factory that spins up uvicorn
    on a free localhost port hosting the caller-provided FastAPI app
    and yields the base URL. Tears the server down on exit.

    Usage::

        async def test_streaming(uvicorn_app_factory, app, broker):
            async with uvicorn_app_factory(app) as base_url:
                async with _real_client(base_url) as c:
                    async with c.stream("GET", "/api/v1/ui/...") as r:
                        ...

    **Cross-test isolation contract:** uvicorn runs on pytest's
    per-test event loop (``asyncio.create_task(server.serve())``).
    The factory body explicitly resets
    :class:`sse_starlette.sse.AppStatus`'s class-level state
    (``should_exit`` + ``should_exit_event``) at fixture entry —
    without this reset, the SECOND uvicorn run per pytest process
    sees ``should_exit=True`` from the previous test's teardown,
    ``_listen_for_exit_signal`` returns immediately, and
    sse-starlette's ``cancel_on_finish`` cancels the entire
    streaming-response task group, producing 200 OK + an EMPTY
    body. (Root-cause diagnosed during T10 — the symptom is
    "SSE stream ended without an event" on the second-running test.)

    Threading-based uvicorn was rejected because the SQLAlchemy
    AsyncEngine bound to pytest's loop cannot be safely read from a
    uvicorn-thread loop (cross-loop aiosqlite usage).

    Per-test scope so fresh sqlite + broker state stays isolated
    per test.
    """
    spawned: list[tuple[uvicorn.Server, asyncio.Task[None]]] = []

    @contextlib.asynccontextmanager
    async def factory(app: FastAPI) -> AsyncIterator[str]:
        # ``sse_starlette.sse.AppStatus`` is a CLASS with class-level
        # attributes ``should_exit`` and ``should_exit_event`` that
        # persist across uvicorn lifecycles in the same Python
        # process. Once uvicorn signals exit on test N, the next
        # uvicorn start on test N+1 sees ``should_exit=True`` and
        # ``_listen_for_exit_signal`` returns immediately —
        # sse-starlette's ``cancel_on_finish`` then cancels the
        # ENTIRE streaming-response task group, producing 200 OK +
        # an EMPTY body. (Root-cause diagnostic in T10 work;
        # symptom: "SSE stream ended without an event" on the
        # second-running test per pytest process.)
        from sse_starlette.sse import AppStatus

        AppStatus.should_exit = False
        AppStatus.should_exit_event = None

        port = _allocate_free_port()
        config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="warning",
            access_log=False,
            lifespan="on",
        )
        server = uvicorn.Server(config)
        # ``server.serve()`` runs the HTTP server on the calling
        # event loop; spawn as a task so the test body can issue
        # real HTTP requests while uvicorn accepts connections.
        task = asyncio.create_task(server.serve())
        spawned.append((server, task))
        # Wait for the server to be ready (default startup is <100ms;
        # the explicit poll avoids racing the first request).
        for _ in range(200):
            if server.started:
                break
            await asyncio.sleep(0.01)
        else:
            raise RuntimeError(f"uvicorn server did not start within 2s on port {port}")
        try:
            yield f"http://127.0.0.1:{port}"
        finally:
            # Graceful shutdown so uvicorn's lifespan cleanup
            # (broker reap-task cancellation, etc.) runs before
            # the next test inherits the same loop.
            server.should_exit = True
            try:
                await asyncio.wait_for(task, timeout=5.0)
            except TimeoutError:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task

    try:
        yield factory
    finally:
        # Defensive cleanup — any factory invocations that escaped
        # their ``async with`` (test body raised) get reaped here.
        for server, task in spawned:
            if not task.done():
                server.should_exit = True
                try:
                    await asyncio.wait_for(task, timeout=2.0)
                except (TimeoutError, Exception):
                    task.cancel()
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await task


# ---------------------------------------------------------------------------
# Sprint 7B.4 T11 fixtures — POST /api/v1/ui/actions
# ---------------------------------------------------------------------------
#
# Per the user-locked decision (2026-05-16 T11): these fixtures live in
# conftest.py NOT in ``test_action_routes.py`` because the correlation-
# latency test in the sibling file ``test_action_routes_correlation_latency.py``
# requests ``app_with_scopes_and_broker`` — pytest fixtures defined in a
# test module are only visible WITHIN that module, so cross-file sharing
# requires conftest. The fixture names are T11-specific
# (``app_with_scopes`` / ``app_with_only_approve`` / ``app_no_adapter`` /
# ``app_with_scopes_and_broker``) so they don't collide with the T10-shipped
# ``app`` / ``app_with_broker`` / ``app_low_cap`` / ``app_short_send_timeout``
# fixtures; T10 tests don't reference the T11 names → no fixture-discovery
# pollution.


@pytest.fixture
def actor_t1_all_ui_scopes() -> Actor:
    """T11: Actor holding ALL 8 UI scopes (2 stream + 6 action).

    Matches the value-set of the T6-shipped ``actor_t1`` but declared
    locally here so the T11 app builders don't transitively depend on
    the T6 actor's exact subject/tenant_id (decouples T10 vs T11 actor
    contracts)."""
    return Actor(
        subject="u1",
        tenant_id="t1",
        actor_type="human",
        scopes=frozenset(
            {
                "ui.run_stream",
                "ui.tenant_stream",
                "ui.action.approve",
                "ui.action.deny",
                "ui.action.cancel_run",
                "ui.action.interrupt",
                "ui.action.resume",
                "ui.action.submit_elicitation",
            }
        ),
    )


@pytest.fixture
def actor_t1_only_approve() -> Actor:
    """T11: Actor with ONLY ``ui.action.approve`` — drives the
    per-class scope-enforcement test (deny POST must 403)."""
    return Actor(
        subject="u1",
        tenant_id="t1",
        actor_type="human",
        scopes=frozenset({"ui.action.approve"}),
    )


class _StubElicitationAdapter:
    """T11: Stub satisfying the ``ElicitationAdapter`` Protocol via
    duck-typing (NOT ``isinstance`` / inheritance — Protocol is
    ``@runtime_checkable`` but isinstance only checks method-presence,
    not signature/asyncness; the authoritative shape check is at the
    ``await adapter.handle_submission(...)`` call site per the T7
    forward watchpoint)."""

    async def get_context(
        self, *, elicitation_id: str, tenant_id: str
    ) -> Any:  # -> ElicitationContext | None (lazy import below)
        import uuid

        from cognic_agentos.protocol.elicitation_adapter import ElicitationContext

        return ElicitationContext(
            elicitation_id=elicitation_id,
            tenant_id=tenant_id,
            originating_pack_id="pack-test",
            originating_decision_record_id=uuid.UUID(int=0),
            elicitation_modes=("url", "form"),
            data_classes=(),
            expires_at=None,
        )

    async def handle_submission(
        self, *, ctx: Any, mode: Any, payload: dict[str, Any]
    ) -> Any:  # -> ElicitationResult (lazy import below)
        from cognic_agentos.protocol.elicitation_adapter import ElicitationResult

        return ElicitationResult(
            delivered_at=datetime.now(UTC),
            backend_correlation_id=f"stub-backend-{ctx.elicitation_id}",
        )


def _build_t11_app(
    *,
    settings: Settings,
    decision_history_store: DecisionHistoryStore,
    audit_store: AuditStore,
    ui_event_emitter: UIEventEmitter,
    broker: UIEventBroker,
    actor: Actor,
    elicitation_adapter: Any,
) -> FastAPI:
    """T11: Build an app with the action router mounted.

    Wraps ``create_app`` (which wires broker + stores + emitter +
    actor_binder) and includes the action router via lazy import so
    this fixture file imports cleanly BEFORE T11 ships
    ``action_routes.py`` — the ImportError IS the TDD RED for T11."""
    from cognic_agentos.portal.api.app import create_app
    from cognic_agentos.portal.api.ui.action_routes import build_action_routes

    application = create_app(
        settings=settings,
        decision_history_store=decision_history_store,
        audit_store=audit_store,
        ui_event_emitter=ui_event_emitter,
        actor_binder=_FixtureActorBinder(actor),
    )
    application.include_router(
        build_action_routes(broker=broker, elicitation_adapter=elicitation_adapter),
        prefix="/api/v1/ui",
    )
    return application


@pytest.fixture
async def app_with_scopes(
    settings: Settings,
    decision_history_store: DecisionHistoryStore,
    audit_store: AuditStore,
    ui_event_emitter: UIEventEmitter,
    broker: UIEventBroker,
    actor_t1_all_ui_scopes: Actor,
) -> FastAPI:
    return _build_t11_app(
        settings=settings,
        decision_history_store=decision_history_store,
        audit_store=audit_store,
        ui_event_emitter=ui_event_emitter,
        broker=broker,
        actor=actor_t1_all_ui_scopes,
        elicitation_adapter=_StubElicitationAdapter(),
    )


@pytest.fixture
async def app_with_only_approve(
    settings: Settings,
    decision_history_store: DecisionHistoryStore,
    audit_store: AuditStore,
    ui_event_emitter: UIEventEmitter,
    broker: UIEventBroker,
    actor_t1_only_approve: Actor,
) -> FastAPI:
    return _build_t11_app(
        settings=settings,
        decision_history_store=decision_history_store,
        audit_store=audit_store,
        ui_event_emitter=ui_event_emitter,
        broker=broker,
        actor=actor_t1_only_approve,
        elicitation_adapter=_StubElicitationAdapter(),
    )


@pytest.fixture
async def app_no_adapter(
    settings: Settings,
    decision_history_store: DecisionHistoryStore,
    audit_store: AuditStore,
    ui_event_emitter: UIEventEmitter,
    broker: UIEventBroker,
    actor_t1_all_ui_scopes: Actor,
) -> FastAPI:
    """T11: ``elicitation_adapter=None`` — exercises the
    ``elicitation_backend_unwired`` path per spec §5.5."""
    return _build_t11_app(
        settings=settings,
        decision_history_store=decision_history_store,
        audit_store=audit_store,
        ui_event_emitter=ui_event_emitter,
        broker=broker,
        actor=actor_t1_all_ui_scopes,
        elicitation_adapter=None,
    )


@pytest.fixture
async def app_with_scopes_and_broker(
    settings: Settings,
    decision_history_store: DecisionHistoryStore,
    audit_store: AuditStore,
    ui_event_emitter: UIEventEmitter,
    broker: UIEventBroker,
    actor_t1_all_ui_scopes: Actor,
) -> FastAPI:
    """T11: Same as ``app_with_scopes`` but ALSO mounts the T10 stream
    router so the correlation-latency test can subscribe to the SSE
    feed + post an action against the SAME broker instance."""
    from cognic_agentos.portal.api.ui.stream_routes import build_stream_routes

    application = _build_t11_app(
        settings=settings,
        decision_history_store=decision_history_store,
        audit_store=audit_store,
        ui_event_emitter=ui_event_emitter,
        broker=broker,
        actor=actor_t1_all_ui_scopes,
        elicitation_adapter=_StubElicitationAdapter(),
    )
    application.include_router(
        build_stream_routes(
            broker=broker,
            settings=settings,
            decision_history_store=decision_history_store,
        ),
        prefix="/api/v1/ui",
    )
    return application


# ---------------------------------------------------------------------------
# Sprint 7B.4 T11 R3 P1 #1 — submit_elicitation green-path fixture
# ---------------------------------------------------------------------------
#
# R3 P1 #1: T11's original test set only covered the
# ``elicitation_backend_unwired`` path (Step 1 gate refusal on
# adapter=None). The gate-green → adapter.handle_submission →
# frontend_action.accepted path was untested; a regression that skipped
# backend dispatch or stopped emitting accepted rows would still pass.
# This fixture wires an _AlwaysAllowRegoEngine so the T8 gate's Step 5
# resolves to allow=True, exercising the green-path adapter call.


class _AlwaysAllowRegoEngine:
    """Stub satisfying the duck-typed contract the T8 gate calls:
    ``await rego_engine.evaluate(decision_point=..., input=...)``
    returning an object with a ``.allow == True`` attribute.

    Returns a real :class:`cognic_agentos.core.policy.engine.Decision`
    dataclass instance (NOT a SimpleNamespace) so the gate's narrowing
    behavior + the dataclass's frozen contract are exercised under
    test the same way they are under production OPA evaluation."""

    async def evaluate(self, *, decision_point: str, input: dict[str, Any]) -> Any:  # -> Decision
        from cognic_agentos.core.policy.engine import Decision

        return Decision(
            allow=True,
            rule_matched="cognic.ui.elicitation_submit.allow",
            reasoning="stub: always allow",
            decision_data=None,
        )


@pytest.fixture
async def app_with_scopes_and_allow_rego(
    settings: Settings,
    decision_history_store: DecisionHistoryStore,
    audit_store: AuditStore,
    ui_event_emitter: UIEventEmitter,
    broker: UIEventBroker,
    actor_t1_all_ui_scopes: Actor,
) -> FastAPI:
    """T11 R3 P1 #1: app wired with BOTH a stub elicitation adapter AND
    an always-allow rego engine — exercises the gate-green path through
    ``adapter.handle_submission`` + ``frontend_action.accepted`` emit.

    Different from ``app_with_scopes`` (which has adapter but
    ``rego_engine=None`` → gate Step 5 fires ``elicitation_unwired_evaluator``
    on every submit_elicitation request, never reaching the adapter)."""
    from cognic_agentos.portal.api.app import create_app
    from cognic_agentos.portal.api.ui.action_routes import build_action_routes

    application = create_app(
        settings=settings,
        decision_history_store=decision_history_store,
        audit_store=audit_store,
        ui_event_emitter=ui_event_emitter,
        actor_binder=_FixtureActorBinder(actor_t1_all_ui_scopes),
    )
    application.include_router(
        build_action_routes(
            broker=broker,
            elicitation_adapter=_StubElicitationAdapter(),
            # mypy: _AlwaysAllowRegoEngine is duck-typed against the
            # T8 gate's narrow `.evaluate(...)` call surface, NOT a
            # full OPAEngine subclass. The cast keeps build_action_routes'
            # production-strict parameter type (`OPAEngine | None`) while
            # letting tests inject a stub. Test-only divergence.
            rego_engine=_AlwaysAllowRegoEngine(),  # type: ignore[arg-type]
        ),
        prefix="/api/v1/ui",
    )
    return application
