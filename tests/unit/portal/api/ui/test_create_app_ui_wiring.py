"""Sprint 7B.4 T12 — ``create_app`` UI-wiring regressions.

T12 extends ``create_app`` with:

  - 3 new optional kwargs: ``elicitation_adapter``, ``rego_engine``,
    ``broker``.
  - Automatic UI-router mount (``/api/v1/ui/*``) + .well-known
    registration when the broker is wired (either pre-built and
    passed via ``broker=`` or auto-built from
    ``decision_history_store + ui_event_emitter + settings``).

Backward-compat invariants pinned:

  - Pack-only callers (settings only, no UI deps) still construct a
    valid FastAPI app with NO UI routes mounted + NO .well-known
    endpoint exposed.
  - UI-wired callers (T6 deps) auto-mount UI routes + the .well-known
    endpoint via create_app — tests need NOT manually include the
    sub-routers.
  - Test fixtures can inject a pre-built broker via the new
    ``broker=`` kwarg so the route's broker matches the fixture's
    broker (subscriber-state parity)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from cognic_agentos.core.config import Settings
from cognic_agentos.portal.api.app import create_app

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine


class TestCreateAppPackOnlyDeploymentStillWorks:
    """R3 #3 backward-compat — existing pack-only callers omit T6+T12
    UI deps; create_app must still build a valid app with NO UI
    routes mounted."""

    def test_pack_only_app_omits_ui_routes(self) -> None:
        app = create_app(settings=Settings())
        paths = [r.path for r in app.routes if hasattr(r, "path")]
        # UI routes must NOT mount when broker isn't wired
        assert not any(p.startswith("/api/v1/ui/") for p in paths)
        # .well-known is gated on the broker being wired (UI surface)
        assert "/.well-known/cognic-ui-events.json" not in paths
        # app.state.ui_event_broker stays None
        assert app.state.ui_event_broker is None


class TestCreateAppWithUIDepsMountsUIRoutes:
    """T12 — when the broker is wired (auto-built from T6 deps OR
    pre-injected), create_app mounts:
      - /api/v1/ui/runs/{run_id}/events (stream)
      - /api/v1/ui/tenants/{tenant_id}/events (stream)
      - /api/v1/ui/events/since/{event_id} (stream)
      - /api/v1/ui/actions (action POST)
      - /.well-known/cognic-ui-events.json (schema publication, root)
    """

    @pytest.mark.asyncio
    async def test_full_ui_app_mounts_ui_routes(self, sqlite_engine: AsyncEngine) -> None:
        from cognic_agentos.core.audit import AuditStore
        from cognic_agentos.core.decision_history import DecisionHistoryStore
        from cognic_agentos.protocol.ui_events import UIEventEmitter

        audit = AuditStore(sqlite_engine)
        dh = DecisionHistoryStore(sqlite_engine)
        emitter = UIEventEmitter(audit_store=audit, decision_history_store=dh)
        app = create_app(
            settings=Settings(),
            decision_history_store=dh,
            audit_store=audit,
            ui_event_emitter=emitter,
        )
        paths = [r.path for r in app.routes if hasattr(r, "path")]
        # UI sub-router routes mounted
        assert any(p.startswith("/api/v1/ui/") for p in paths)
        # .well-known mounted at root (NOT under /api/v1/ui/)
        assert "/.well-known/cognic-ui-events.json" in paths
        # app.state.ui_event_broker now non-None (auto-built)
        assert app.state.ui_event_broker is not None


class TestCreateAppAcceptsPreBuiltBroker:
    """T12 + plan-vs-reality drift fix — test fixtures pre-build their
    own broker (via the ``broker`` fixture) so they can directly emit
    + assert on subscriber state. Without a ``broker=`` kwarg,
    create_app would build an INTERNAL broker that the UI routes use
    — DIFFERENT from the fixture's broker. The two brokers share
    emit state (via the emitter's hook chain) but have SEPARATE
    subscriber lists, breaking tests that inspect ``broker._subscribers``.

    The ``broker=`` kwarg lets tests inject the fixture broker so the
    route's subscriber list IS the fixture broker's subscriber list."""

    @pytest.mark.asyncio
    async def test_broker_kwarg_overrides_internal_construction(
        self, sqlite_engine: AsyncEngine
    ) -> None:
        from cognic_agentos.core.audit import AuditStore
        from cognic_agentos.core.decision_history import DecisionHistoryStore
        from cognic_agentos.protocol.ui_events import (
            UIEventBroker,
            UIEventEmitter,
        )

        settings = Settings()
        audit = AuditStore(sqlite_engine)
        dh = DecisionHistoryStore(sqlite_engine)
        emitter = UIEventEmitter(audit_store=audit, decision_history_store=dh)
        pre_built = UIEventBroker(decision_history_store=dh, settings=settings)
        pre_built.register_with_emitter(emitter)

        app = create_app(
            settings=settings,
            decision_history_store=dh,
            audit_store=audit,
            ui_event_emitter=emitter,
            broker=pre_built,
        )
        # The injected broker IS the one create_app attached
        assert app.state.ui_event_broker is pre_built
