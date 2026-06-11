"""Sprint 13.5b1 (ADR-014) — approval router mount in create_app.

3-state mount mirroring the config-overlay router (test_app_config_overlay_mount.py):
store + engine present -> mount build_approval_routes + set
app.state.approval_router_mounted = True; partial config -> fail-loud warning +
flag stays False; neither -> no mount (silent — opt-in surface).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.approval.engine import ApprovalEngine
from cognic_agentos.core.approval.storage import ApprovalRequestStore
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.portal.api.app import create_app

_QUEUE_PATH = "/api/v1/approvals/"
_GRANT_PATH = "/api/v1/approvals/{request_id}/grant"


class _StubPolicy:
    async def classify(self, *, risk_tier: str) -> str:
        return "require_single_approval"


def _store_and_engine() -> tuple[ApprovalRequestStore, ApprovalEngine]:
    engine = create_async_engine("sqlite+aiosqlite://")  # lazy pool — never connected here
    store = ApprovalRequestStore(DecisionHistoryStore(engine))
    approval_engine = ApprovalEngine(
        policy=_StubPolicy(),
        store=store,
        settings=build_settings_without_env_file(),
        clock=lambda: datetime.now(UTC),
    )
    return store, approval_engine


def _paths(app: object) -> set[str]:
    return {getattr(r, "path", "") for r in app.routes}  # type: ignore[attr-defined]


def test_approval_router_mounted_when_store_and_engine_present() -> None:
    store, engine = _store_and_engine()
    app = create_app(
        build_settings_without_env_file(),
        approval_store=store,
        approval_engine=engine,
    )
    assert app.state.approval_router_mounted is True
    assert _QUEUE_PATH in _paths(app)
    assert _GRANT_PATH in _paths(app)


def test_approval_router_not_mounted_without_deps() -> None:
    app = create_app(build_settings_without_env_file())
    assert app.state.approval_router_mounted is False
    assert not any(p.startswith("/api/v1/approvals") for p in _paths(app))


def _assert_partial_warning(caplog: pytest.LogCaptureFixture) -> None:
    # The fail-loud startup misconfig contract: EXACTLY one structured warning
    # with the closed-enum reason — not just "route absent".
    warnings = [
        rec
        for rec in caplog.records
        if rec.getMessage() == "portal.approval_router_unmounted_partial_config"
    ]
    assert len(warnings) == 1
    assert getattr(warnings[0], "reason", None) == "approval_store_and_engine_both_required"


def test_approval_router_partial_store_only_fails_loud(
    caplog: pytest.LogCaptureFixture,
) -> None:
    store, _ = _store_and_engine()
    with caplog.at_level(logging.WARNING, logger="cognic_agentos.portal.api.app"):
        app = create_app(build_settings_without_env_file(), approval_store=store)
    assert app.state.approval_router_mounted is False
    assert not any(p.startswith("/api/v1/approvals") for p in _paths(app))
    _assert_partial_warning(caplog)


def test_approval_router_partial_engine_only_fails_loud(
    caplog: pytest.LogCaptureFixture,
) -> None:
    _, engine = _store_and_engine()
    with caplog.at_level(logging.WARNING, logger="cognic_agentos.portal.api.app"):
        app = create_app(build_settings_without_env_file(), approval_engine=engine)
    assert app.state.approval_router_mounted is False
    assert not any(p.startswith("/api/v1/approvals") for p in _paths(app))
    _assert_partial_warning(caplog)
