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
