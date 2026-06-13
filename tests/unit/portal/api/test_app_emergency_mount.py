"""Sprint 13.6 T7 (ADR-018) — emergency router mount in create_app.

3-state mount mirroring the approval router (test_app_approval_mount.py):
emergency_engine + decision_history_store present -> mount
build_emergency_routes + set app.state.emergency_router_mounted = True;
emergency_engine present but decision_history_store absent -> fail-loud
warning + flag stays False (the GET /audit endpoint reads the DH store, so
both are required); emergency_engine absent -> no mount (silent — opt-in
operator surface, the approval 13.5b1 injection-seam posture).
"""

from __future__ import annotations

import logging

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.core.emergency.kill_switches import KillSwitchEngine
from cognic_agentos.portal.api.app import create_app

_KILL_SWITCHES_PATH = "/api/v1/emergency/kill-switches"
_AUDIT_PATH = "/api/v1/emergency/audit"


class _FakeRedis:
    async def get(self, key: str) -> object:
        return None

    async def set(self, key: str, value: object, **kwargs: object) -> object:
        return None


def _engine_and_store() -> tuple[KillSwitchEngine, DecisionHistoryStore]:
    sa_engine = create_async_engine("sqlite+aiosqlite://")  # lazy pool — never connected here
    dh = DecisionHistoryStore(sa_engine)
    engine = KillSwitchEngine(redis_client=_FakeRedis(), cache_ttl_s=60, decision_history=dh)
    return engine, dh


def _paths(app: object) -> set[str]:
    return {getattr(r, "path", "") for r in app.routes}  # type: ignore[attr-defined]


def test_emergency_router_mounted_when_engine_and_dh_store_present() -> None:
    engine, dh = _engine_and_store()
    app = create_app(
        build_settings_without_env_file(),
        emergency_engine=engine,
        decision_history_store=dh,
    )
    assert app.state.emergency_router_mounted is True
    assert _KILL_SWITCHES_PATH in _paths(app)
    assert _AUDIT_PATH in _paths(app)


def test_emergency_router_not_mounted_without_engine() -> None:
    app = create_app(build_settings_without_env_file())
    assert app.state.emergency_router_mounted is False
    assert not any(p.startswith("/api/v1/emergency") for p in _paths(app))


def test_emergency_router_engine_without_dh_store_fails_loud(
    caplog: pytest.LogCaptureFixture,
) -> None:
    engine, _ = _engine_and_store()
    with caplog.at_level(logging.WARNING, logger="cognic_agentos.portal.api.app"):
        app = create_app(build_settings_without_env_file(), emergency_engine=engine)
    assert app.state.emergency_router_mounted is False
    assert not any(p.startswith("/api/v1/emergency") for p in _paths(app))
    warnings = [
        rec
        for rec in caplog.records
        if rec.getMessage() == "portal.emergency_router_unmounted_partial_config"
    ]
    assert len(warnings) == 1
    assert (
        getattr(warnings[0], "reason", None)
        == "emergency_engine_and_decision_history_store_both_required"
    )
