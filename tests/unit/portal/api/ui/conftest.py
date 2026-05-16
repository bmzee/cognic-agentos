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

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
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
async def app(app_with_broker: FastAPI, broker: UIEventBroker) -> FastAPI:
    """UI-routes-mounted app fixture.

    Wraps `app_with_broker` and includes the T10 SSE stream router via
    lazy import. The lazy import lets this fixture coexist in the T6
    conftest WITHOUT breaking T6's RBAC test collection — T6 RBAC tests
    use `app_with_broker` directly (no UI routes needed); the import
    only fires when a test requests `app` (T10+ SSE tests).

    Production-grade: NO silent fallback. If a test requests `app` and
    the stream_routes module is missing (e.g. running T10 tests before
    T10 ships the module), the lazy import raises ImportError — that
    IS the TDD RED for those tests."""
    # Lazy import — stream_routes ships at T10. mypy can't resolve the
    # module at T6 time; ignore the import-untyped error (the runtime
    # ImportError on missing module IS the TDD RED for T10 tests).
    from cognic_agentos.portal.api.ui.stream_routes import (  # type: ignore[import-untyped]
        build_stream_routes,
    )

    app_with_broker.include_router(
        build_stream_routes(broker=broker),
        prefix="/api/v1/ui",
    )
    return app_with_broker
