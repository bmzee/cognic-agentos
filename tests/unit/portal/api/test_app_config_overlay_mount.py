"""ADR-023 Task 10 — config-overlay router mount in create_app.

3-state mount mirroring the packs router: store + resolver present -> mount the
router under /api/v1 + set app.state.config_overlay_router_mounted = True;
partial config -> fail-loud warning + flag stays False; neither -> no mount.
"""

from __future__ import annotations

import logging

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.config_overlay.resolver import TenantConfigResolver
from cognic_agentos.core.config_overlay.storage import TenantConfigOverlayStore
from cognic_agentos.portal.api.app import create_app

_OVERLAY_PATH = "/api/v1/tenants/{tenant_id}/config-overlay/{field_key}"


def _store_and_resolver() -> tuple[TenantConfigOverlayStore, TenantConfigResolver]:
    settings = build_settings_without_env_file()
    engine = create_async_engine("sqlite+aiosqlite://")  # lazy pool — never connected here
    store = TenantConfigOverlayStore(engine)
    resolver = TenantConfigResolver(
        store=store,
        base=settings,
        audit=AuditStore(engine),
        throttle_s=settings.config_overlay_invalid_at_read_throttle_s,
    )
    return store, resolver


def test_config_overlay_router_mounted_when_store_and_resolver_present() -> None:
    store, resolver = _store_and_resolver()
    app = create_app(
        build_settings_without_env_file(),
        config_overlay_store=store,
        config_overlay_resolver=resolver,
    )
    assert app.state.config_overlay_router_mounted is True
    assert any(getattr(r, "path", "") == _OVERLAY_PATH for r in app.routes)


def test_config_overlay_router_not_mounted_without_store() -> None:
    app = create_app(build_settings_without_env_file())
    assert app.state.config_overlay_router_mounted is False
    assert not any(getattr(r, "path", "") == _OVERLAY_PATH for r in app.routes)


def _assert_partial_warning(caplog: pytest.LogCaptureFixture) -> None:
    # The fail-loud startup misconfig contract: EXACTLY one structured warning
    # with the closed-enum reason — not just "route absent".
    warnings = [
        rec
        for rec in caplog.records
        if rec.getMessage() == "portal.config_overlay_router_unmounted_partial_config"
    ]
    assert len(warnings) == 1
    # ``reason`` is injected via logger.warning(..., extra={"reason": ...}); it is
    # not a static LogRecord attribute, so read it via getattr.
    assert getattr(warnings[0], "reason", None) == "config_overlay_store_and_resolver_both_required"


def test_config_overlay_router_partial_store_only_fails_loud(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Partial config (store, no resolver) -> no mount + fail-loud warning.
    store, _ = _store_and_resolver()
    with caplog.at_level(logging.WARNING, logger="cognic_agentos.portal.api.app"):
        app = create_app(build_settings_without_env_file(), config_overlay_store=store)
    assert app.state.config_overlay_router_mounted is False
    assert not any(getattr(r, "path", "") == _OVERLAY_PATH for r in app.routes)
    _assert_partial_warning(caplog)


def test_config_overlay_router_partial_resolver_only_fails_loud(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # The symmetric partial shape (resolver, no store) -> same fail-loud warning.
    _, resolver = _store_and_resolver()
    with caplog.at_level(logging.WARNING, logger="cognic_agentos.portal.api.app"):
        app = create_app(build_settings_without_env_file(), config_overlay_resolver=resolver)
    assert app.state.config_overlay_router_mounted is False
    assert not any(getattr(r, "path", "") == _OVERLAY_PATH for r in app.routes)
    _assert_partial_warning(caplog)
