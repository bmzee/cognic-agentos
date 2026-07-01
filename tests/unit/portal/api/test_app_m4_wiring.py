"""M4 (ADR-026, Task 7) — composition-root wiring in create_app.

Pins the create_app-level M4 wiring (distinct from the operator-route saga
behavior in ``test_operator_routes_m4.py`` + the D7 supersession in
``test_app_mcp_config_mount.py``):

- the configure surface (``/api/v1/packs/{pack_id}/runtime-config``) mounts ONLY
  when pack_record_store + actor_binder + runtime_config_store are ALL present;
- app.state carries the runtime-config store + materializer (injection-seam
  kwargs — introspection parity with pack_record_store);
- a PARTIAL body-time M4 wiring (materializer XOR runtime_config_store, with the
  packs router mounted) raises at construction via build_operator_routes'
  all-2-or-none ValueError — create_app does NOT swallow it;
- the standalone MCP write routes stay unmounted (D7 cross-check).

These are pure route-registration / app.state assertions — create_app is called
WITHOUT a TestClient (no lifespan, no adapter pool, no DB connect); the lazy
engines are never opened.
"""

from __future__ import annotations

import pytest
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.mcp_config.materializer import RuntimeConfigMaterializer
from cognic_agentos.core.mcp_config.runtime_config import PackRuntimeConfigStore
from cognic_agentos.core.mcp_config.storage import (
    MCPInternalHostAllowlistStore,
    MCPServerUrlOverrideStore,
)
from cognic_agentos.packs.storage import PackRecordStore
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.rbac.actor import Actor

_CONFIGURE_PATH = "/api/v1/packs/{pack_id}/runtime-config"
_OVERRIDE_PATH = "/api/v1/tenants/{tenant_id}/mcp-overrides/{pack_id}"
_ALLOWLIST_PATH = "/api/v1/tenants/{tenant_id}/mcp-allowlist"


class _StubBinder:
    """Minimal ActorBinder — never called in these mount-only tests (create_app
    reads it from app.state at REQUEST time, and we fire no requests)."""

    def bind(self, *, request: Request) -> Actor:  # pragma: no cover - not exercised
        raise NotImplementedError


class _StubVault:
    """Minimal VaultReader — the materializer is never invoked in mount tests."""

    async def read(self, path: str) -> None:  # pragma: no cover - not exercised
        return None


def _lazy_engine() -> AsyncEngine:
    # Lazy pool — never connected (mount is a pure route-registration step).
    return create_async_engine("sqlite+aiosqlite://")


def _pack_store() -> PackRecordStore:
    return PackRecordStore(_lazy_engine())


def _config_store() -> PackRuntimeConfigStore:
    return PackRuntimeConfigStore(_lazy_engine())


def _materializer(config_store: PackRuntimeConfigStore) -> RuntimeConfigMaterializer:
    engine = _lazy_engine()
    return RuntimeConfigMaterializer(
        override_store=MCPServerUrlOverrideStore(engine),
        allowlist_store=MCPInternalHostAllowlistStore(engine),
        config_store=config_store,
        vault_reader=_StubVault(),
    )


def _has(app: object, path: str) -> bool:
    return any(getattr(r, "path", "") == path for r in app.routes)  # type: ignore[attr-defined]


def test_configure_router_mounted_with_full_deps() -> None:
    """pack_record_store + actor_binder + runtime_config_store ALL present → the
    configure router mounts at ``/api/v1/packs/{pack_id}/runtime-config`` + the
    introspection flag is True."""
    config_store = _config_store()
    app = create_app(
        build_settings_without_env_file(),
        actor_binder=_StubBinder(),
        pack_record_store=_pack_store(),
        runtime_config_store=config_store,
        runtime_config_materializer=_materializer(config_store),
    )
    assert app.state.configure_router_mounted is True
    assert _has(app, _CONFIGURE_PATH)


def test_configure_router_not_mounted_without_runtime_config_store() -> None:
    """pack_record_store + actor_binder present but NO runtime_config_store (and
    no materializer → M4 off, so no all-2-or-none ValueError) → the configure
    router is NOT mounted + the flag is False."""
    app = create_app(
        build_settings_without_env_file(),
        actor_binder=_StubBinder(),
        pack_record_store=_pack_store(),
    )
    assert app.state.configure_router_mounted is False
    assert not _has(app, _CONFIGURE_PATH)


def test_configure_router_not_mounted_without_actor_binder() -> None:
    """runtime_config_store (+ materializer, a valid 2/2 body wiring) present but
    NO actor_binder → the configure router's RequireTenantOwnership /
    RequireScope deps would have no Actor source, so it is NOT mounted (flag
    False). The packs router is likewise unmounted (no binder), so the 2/2 M4
    deps never reach build_operator_routes."""
    config_store = _config_store()
    app = create_app(
        build_settings_without_env_file(),
        pack_record_store=_pack_store(),
        runtime_config_store=config_store,
        runtime_config_materializer=_materializer(config_store),
    )
    assert app.state.configure_router_mounted is False
    assert not _has(app, _CONFIGURE_PATH)


def test_app_state_carries_runtime_config_collaborators() -> None:
    """app.state carries the runtime-config store + materializer passed via the
    injection-seam kwargs (introspection parity with pack_record_store), by
    IDENTITY (the exact instances)."""
    config_store = _config_store()
    materializer = _materializer(config_store)
    app = create_app(
        build_settings_without_env_file(),
        runtime_config_store=config_store,
        runtime_config_materializer=materializer,
    )
    assert app.state.runtime_config_store is config_store
    assert app.state.runtime_config_materializer is materializer


def test_partial_m4_body_wiring_raises_at_construction() -> None:
    """A PARTIAL body-time M4 wiring — materializer present, runtime_config_store
    ABSENT, WITH the packs router mounted (pack_record_store + actor_binder) —
    reaches build_operator_routes' all-2-or-none guard, which raises ValueError.
    create_app does NOT swallow it (fail-fast at construction, not a silent
    pre-M4 downgrade of the hardened install route)."""
    config_store = _config_store()
    with pytest.raises(ValueError, match="BOTH wired or BOTH absent"):
        create_app(
            build_settings_without_env_file(),
            actor_binder=_StubBinder(),
            pack_record_store=_pack_store(),
            runtime_config_materializer=_materializer(config_store),
            # runtime_config_store deliberately OMITTED → 1/2 → ValueError.
        )


def test_standalone_mcp_write_routes_unmounted_d7_crosscheck() -> None:
    """D7 cross-check at the wiring level — the standalone override / allow-list
    write routes are unmounted even with the FULL M4 wiring present (the
    materializer is the sole writer of the derived rows)."""
    config_store = _config_store()
    app = create_app(
        build_settings_without_env_file(),
        actor_binder=_StubBinder(),
        pack_record_store=_pack_store(),
        runtime_config_store=config_store,
        runtime_config_materializer=_materializer(config_store),
    )
    assert app.state.mcp_override_router_mounted is False
    assert app.state.mcp_allowlist_router_mounted is False
    assert not _has(app, _OVERRIDE_PATH)
    assert not _has(app, _ALLOWLIST_PATH)
