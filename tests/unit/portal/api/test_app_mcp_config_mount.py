"""PR-2b-1 (ADR-002 amendment) — MCP operator override + internal-host allow-list
router mount in create_app.

3-state mount mirroring the config-overlay block, gated on the PAIR of stores
(build_runtime constructs them together): BOTH supplied -> mount the override +
allow-list operator routers under /api/v1 + set both
app.state.mcp_*_router_mounted flags True; partial config (exactly one) ->
no mount + EXACTLY ONE fail-loud warning + both flags False; neither -> no mount,
both flags False, and STAY QUIET (pack-only deployments without an internal MCP
Service are legitimate — no warning).
"""

from __future__ import annotations

import logging

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.mcp_config.storage import (
    MCPInternalHostAllowlistStore,
    MCPServerUrlOverrideStore,
)
from cognic_agentos.portal.api.app import create_app

_OVERRIDE_PATH = "/api/v1/tenants/{tenant_id}/mcp-overrides/{pack_id}"
_ALLOWLIST_PATH = "/api/v1/tenants/{tenant_id}/mcp-allowlist"
_PARTIAL_WARNING = "portal.mcp_config_router_unmounted_partial_config"
_PARTIAL_REASON = "mcp_override_store_and_allowlist_store_both_required"


def _stores() -> tuple[MCPServerUrlOverrideStore, MCPInternalHostAllowlistStore]:
    # Lazy pool — never connected here (mount is a pure route-registration step).
    engine = create_async_engine("sqlite+aiosqlite://")
    return MCPServerUrlOverrideStore(engine), MCPInternalHostAllowlistStore(engine)


def _has(app: object, path: str) -> bool:
    return any(getattr(r, "path", "") == path for r in app.routes)  # type: ignore[attr-defined]


def _assert_partial_warning(caplog: pytest.LogCaptureFixture) -> None:
    # The fail-loud startup-misconfig contract: EXACTLY one structured warning
    # with the closed-enum reason — not just "route absent".
    warnings = [r for r in caplog.records if r.getMessage() == _PARTIAL_WARNING]
    assert len(warnings) == 1
    assert getattr(warnings[0], "reason", None) == _PARTIAL_REASON


def test_mcp_config_routers_mounted_when_both_stores_present() -> None:
    override_store, allowlist_store = _stores()
    app = create_app(
        build_settings_without_env_file(),
        mcp_override_store=override_store,
        mcp_internal_host_allowlist_store=allowlist_store,
    )
    assert app.state.mcp_override_router_mounted is True
    assert app.state.mcp_allowlist_router_mounted is True
    assert _has(app, _OVERRIDE_PATH)
    assert _has(app, _ALLOWLIST_PATH)


def test_mcp_config_routers_silent_on_zero(caplog: pytest.LogCaptureFixture) -> None:
    # ZERO stores -> no mount, both flags False, route table untouched, and STAY
    # QUIET: a pack-only deploy without an internal MCP Service is legitimate, so
    # it must emit NO partial-config warning.
    with caplog.at_level(logging.WARNING, logger="cognic_agentos.portal.api.app"):
        app = create_app(build_settings_without_env_file())
    assert app.state.mcp_override_router_mounted is False
    assert app.state.mcp_allowlist_router_mounted is False
    assert not _has(app, _OVERRIDE_PATH)
    assert not _has(app, _ALLOWLIST_PATH)
    assert not [r for r in caplog.records if r.getMessage() == _PARTIAL_WARNING]


def test_mcp_config_routers_partial_override_only_fails_loud(
    caplog: pytest.LogCaptureFixture,
) -> None:
    override_store, _ = _stores()
    with caplog.at_level(logging.WARNING, logger="cognic_agentos.portal.api.app"):
        app = create_app(build_settings_without_env_file(), mcp_override_store=override_store)
    assert app.state.mcp_override_router_mounted is False
    assert app.state.mcp_allowlist_router_mounted is False
    assert not _has(app, _OVERRIDE_PATH)
    assert not _has(app, _ALLOWLIST_PATH)
    _assert_partial_warning(caplog)


def test_mcp_config_routers_partial_allowlist_only_fails_loud(
    caplog: pytest.LogCaptureFixture,
) -> None:
    _, allowlist_store = _stores()
    with caplog.at_level(logging.WARNING, logger="cognic_agentos.portal.api.app"):
        app = create_app(
            build_settings_without_env_file(),
            mcp_internal_host_allowlist_store=allowlist_store,
        )
    assert app.state.mcp_override_router_mounted is False
    assert app.state.mcp_allowlist_router_mounted is False
    assert not _has(app, _OVERRIDE_PATH)
    assert not _has(app, _ALLOWLIST_PATH)
    _assert_partial_warning(caplog)
