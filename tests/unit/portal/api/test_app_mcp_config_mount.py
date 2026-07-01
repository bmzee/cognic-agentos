"""ADR-026 D7 (M4 Task 7) — the PR-2b-1 standalone MCP override + internal-host
allow-list WRITE routes are SUPERSEDED and are NO LONGER MOUNTED by create_app.

Under M4 the ``RuntimeConfigMaterializer`` is the SOLE writer of the derived
override / allow-list carve-out rows (projected from the operator-authored
DESIRED runtime-config record by the install/disable/revoke saga). A second
direct-write path would let an operator drift the derived rows out from under the
desired-config record (two sources of truth), so the standalone write routes are
gone.

This file pins the supersession: even when BOTH stores are supplied the
standalone write routes are absent from ``app.routes``, both introspection flags
stay ``False``, and the old 3-state partial-config warning is never emitted (the
mount block that carried it is removed). The route FACTORIES themselves still
exist + are unit-tested in ``tests/unit/portal/api/mcp_config/test_routes.py`` —
they are simply not wired into the app.
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


def _stores() -> tuple[MCPServerUrlOverrideStore, MCPInternalHostAllowlistStore]:
    # Lazy pool — never connected here (mount is a pure route-registration step).
    engine = create_async_engine("sqlite+aiosqlite://")
    return MCPServerUrlOverrideStore(engine), MCPInternalHostAllowlistStore(engine)


def _has(app: object, path: str) -> bool:
    return any(getattr(r, "path", "") == path for r in app.routes)  # type: ignore[attr-defined]


def _assert_superseded(app: object) -> None:
    """D7 invariant: both flags False + neither standalone write path present."""
    assert app.state.mcp_override_router_mounted is False  # type: ignore[attr-defined]
    assert app.state.mcp_allowlist_router_mounted is False  # type: ignore[attr-defined]
    assert not _has(app, _OVERRIDE_PATH)
    assert not _has(app, _ALLOWLIST_PATH)


def test_standalone_mcp_write_routes_not_mounted_even_with_both_stores(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """D7 — even when BOTH stores are supplied the standalone override +
    allow-list WRITE routes are NOT mounted (the materializer is the sole
    writer), both flags stay False, and the removed 3-state partial warning is
    never emitted. (Pre-D7 this exact call mounted both routes + set the flags
    True — the threat-model-revert pin for D7.)"""
    override_store, allowlist_store = _stores()
    with caplog.at_level(logging.WARNING, logger="cognic_agentos.portal.api.app"):
        app = create_app(
            build_settings_without_env_file(),
            mcp_override_store=override_store,
            mcp_internal_host_allowlist_store=allowlist_store,
        )
    _assert_superseded(app)
    assert not [r for r in caplog.records if r.getMessage() == _PARTIAL_WARNING]


def test_standalone_mcp_write_routes_absent_with_no_stores(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """No stores → routes absent, flags False, quiet (posture unchanged vs
    pre-D7 for the zero-store case; only the both-stores case changed)."""
    with caplog.at_level(logging.WARNING, logger="cognic_agentos.portal.api.app"):
        app = create_app(build_settings_without_env_file())
    _assert_superseded(app)
    assert not [r for r in caplog.records if r.getMessage() == _PARTIAL_WARNING]


def test_standalone_mcp_write_route_partial_store_no_longer_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A partial store config (exactly one) is now INERT for routing — D7 removed
    the 3-state mount, so it neither mounts nor emits the old partial-config
    warning. Pins that the warning was removed WITH the mount (not left
    dangling on a now-unreachable branch)."""
    override_store, _ = _stores()
    with caplog.at_level(logging.WARNING, logger="cognic_agentos.portal.api.app"):
        app = create_app(build_settings_without_env_file(), mcp_override_store=override_store)
    _assert_superseded(app)
    assert not [r for r in caplog.records if r.getMessage() == _PARTIAL_WARNING]
