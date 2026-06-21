"""Sprint 4 (ADR-002 + ADR-003 + ADR-016) — ONE shared PluginRegistry feeds
BOTH the MCP host and the A2A endpoint.

Before this slice the lifespan built two SEPARATE empty ``PluginRegistry(...)``
(one per surface). Sprint 4 wires the off-gate boot-builder
``harness/registry_boot.build_and_populate_registry`` into the lifespan so a
SINGLE discovered + trust-registered registry is threaded into
``build_mcp_host(registry=...)`` AND ``A2AEndpoint(plugin_registry=...)``.

Behaviour pinned here:
  * ``app.state.plugin_registry`` predeclared ``None`` (populated in lifespan).
  * One registry object reaches BOTH surfaces.
  * An injected ``create_app(plugin_registry=...)`` SKIPS discovery (the caller
    owns pre-population).
  * Unset ``pack_attestation_root_path`` → the boot returns an EMPTY (non-None)
    registry → both surfaces are still constructed (reachable-but-empty).
  * A ``RegistryBootError`` (broken cosign.pub / malformed allow-list) →
    ``app.state.plugin_registry is None`` → BOTH surfaces stay None (their
    routes 503).
  * The §4 trapdoor: the boot is handed NO ``trust_gate`` (it builds its own
    ``registration_trust_gate``); the A2A endpoint keeps its own
    ``a2a_trust_gate``.

The SDK-gated MCP/A2A constructors (``build_mcp_host`` / ``A2AEndpoint``) are
spied so the tests are deterministic regardless of which optional adapter
extras are installed; ``is_mcp_available`` / ``is_a2a_available`` are forced
True so both blocks run.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cognic_agentos.harness.registry_boot import RegistryBootError
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.protocol.plugin_registry import MCPAdmissionDeps, PluginRegistry

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

    from cognic_agentos.core.config import Settings
    from cognic_agentos.db.adapters import AdapterRegistry


def _litellm_yaml(tmp_path: Path) -> Path:
    """Minimal LiteLLM config (mirrors tests/unit/portal/api/test_app_mcp_host_state.py)."""
    cfg = tmp_path / "litellm.yaml"
    cfg.write_text(
        "model_list:\n"
        "  - model_name: cognic-tier1-dev\n"
        "    litellm_params:\n"
        "      model: ollama/qwen\n"
        "      api_base: http://localhost:11434\n"
    )
    return cfg


def _adapter_settings(memory_settings: Settings, tmp_path: Path) -> Settings:
    """memory_settings + a litellm config + memory cache so build_runtime (and
    therefore the scheduler) constructs on the adapter path."""
    return memory_settings.model_copy(
        update={"litellm_config_path": _litellm_yaml(tmp_path), "cache_driver": "memory"}
    )


def _force_sdk_available(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("cognic_agentos.portal.api.app.is_mcp_available", lambda: True)
    monkeypatch.setattr("cognic_agentos.portal.api.app.is_a2a_available", lambda: True)


def _spy_surfaces(monkeypatch: pytest.MonkeyPatch, captured: dict[str, Any]) -> None:
    """Replace the two SDK-gated constructors with identity-capturing spies.

    ``build_mcp_host(registry=...)`` and ``A2AEndpoint(plugin_registry=...)`` are
    the ONLY consumers of the shared registry; capturing their kwarg by identity
    is how we prove the SAME object reaches both. Each returns a unique sentinel
    so ``app.state.mcp_host`` / ``app.state.a2a_endpoint`` read non-None (i.e.
    "constructed", not skipped)."""

    def _spy_build_mcp_host(**kwargs: Any) -> object:
        captured["mcp_registry"] = kwargs["registry"]
        captured["mcp_host"] = object()
        return captured["mcp_host"]

    def _spy_a2a_endpoint(**kwargs: Any) -> object:
        captured["a2a_registry"] = kwargs["plugin_registry"]
        captured["a2a_endpoint"] = object()
        return captured["a2a_endpoint"]

    monkeypatch.setattr("cognic_agentos.harness.mcp_host.build_mcp_host", _spy_build_mcp_host)
    monkeypatch.setattr("cognic_agentos.protocol.a2a_endpoint.A2AEndpoint", _spy_a2a_endpoint)


# ---------------------------------------------------------------------------
# Predeclare
# ---------------------------------------------------------------------------


def test_app_state_plugin_registry_predeclared_none() -> None:
    """The attribute is predeclared so pre-lifespan introspection sees a defined
    value (mirrors app.state.mcp_host / a2a_endpoint)."""
    assert create_app().state.plugin_registry is None


# ---------------------------------------------------------------------------
# One registry feeds both surfaces
# ---------------------------------------------------------------------------


async def test_one_registry_feeds_both_surfaces(
    memory_settings: Settings,
    memory_registry: AdapterRegistry,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # identity-only sentinel — never exercised as a real registry:
    sentinel = PluginRegistry.__new__(PluginRegistry)

    captured: dict[str, Any] = {}

    async def _stub_boot(**kwargs: Any) -> object:
        captured["boot_called"] = True
        return sentinel

    monkeypatch.setattr(
        "cognic_agentos.harness.registry_boot.build_and_populate_registry", _stub_boot
    )
    _force_sdk_available(monkeypatch)
    _spy_surfaces(monkeypatch, captured)

    app = create_app(_adapter_settings(memory_settings, tmp_path), adapter_registry=memory_registry)
    async with app.router.lifespan_context(app):
        assert captured["boot_called"] is True
        # the SAME object reaches app.state AND both surfaces:
        assert app.state.plugin_registry is sentinel
        assert captured["mcp_registry"] is sentinel
        assert captured["a2a_registry"] is sentinel
        # both surfaces constructed (non-None) from that one registry:
        assert app.state.mcp_host is captured["mcp_host"]
        assert app.state.a2a_endpoint is captured["a2a_endpoint"]


# ---------------------------------------------------------------------------
# Injected registry skips discovery
# ---------------------------------------------------------------------------


async def test_injected_registry_skips_discovery(
    memory_settings: Settings,
    memory_registry: AdapterRegistry,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    injected = PluginRegistry.__new__(PluginRegistry)  # identity-only sentinel

    captured: dict[str, Any] = {"boot_called": False}

    async def _stub_boot(**kwargs: Any) -> object:
        captured["boot_called"] = True
        return PluginRegistry.__new__(PluginRegistry)

    monkeypatch.setattr(
        "cognic_agentos.harness.registry_boot.build_and_populate_registry", _stub_boot
    )
    _force_sdk_available(monkeypatch)
    _spy_surfaces(monkeypatch, captured)

    app = create_app(
        _adapter_settings(memory_settings, tmp_path),
        adapter_registry=memory_registry,
        plugin_registry=injected,
    )
    async with app.router.lifespan_context(app):
        # the injected registry wins — NO discovery:
        assert captured["boot_called"] is False
        assert app.state.plugin_registry is injected
        assert captured["mcp_registry"] is injected
        assert captured["a2a_registry"] is injected


# ---------------------------------------------------------------------------
# Unset attestation root → empty (non-None) registry → both reachable
# ---------------------------------------------------------------------------


async def test_unset_root_empty_registry_both_reachable(
    memory_settings: Settings,
    memory_registry: AdapterRegistry,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # NO stub on build_and_populate_registry — the REAL boot runs. memory_settings
    # leaves pack_attestation_root_path unset → the boot returns a fresh EMPTY
    # PluginRegistry (no discovery, no trust gate built) and NEVER raises.
    assert memory_settings.pack_attestation_root_path is None

    captured: dict[str, Any] = {}
    _force_sdk_available(monkeypatch)
    _spy_surfaces(monkeypatch, captured)

    app = create_app(_adapter_settings(memory_settings, tmp_path), adapter_registry=memory_registry)
    async with app.router.lifespan_context(app):
        # a REAL, non-None, empty registry:
        assert isinstance(app.state.plugin_registry, PluginRegistry)
        # both surfaces are CONSTRUCTED (reachable), not skipped:
        assert app.state.mcp_host is captured["mcp_host"]
        assert app.state.a2a_endpoint is captured["a2a_endpoint"]
        # and they share the ONE registry:
        assert captured["mcp_registry"] is app.state.plugin_registry
        assert captured["a2a_registry"] is app.state.plugin_registry


# ---------------------------------------------------------------------------
# RegistryBootError → registry None → both surfaces 503 (both None)
# ---------------------------------------------------------------------------


async def test_allowlist_failure_registry_none_both_503(
    memory_settings: Settings,
    memory_registry: AdapterRegistry,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {"mcp_called": False, "a2a_called": False}

    async def _boot_raises(**kwargs: Any) -> object:
        raise RegistryBootError("tenant_allowlist_default_key_missing")

    def _spy_build_mcp_host(**kwargs: Any) -> object:
        captured["mcp_called"] = True
        return object()

    def _spy_a2a_endpoint(**kwargs: Any) -> object:
        captured["a2a_called"] = True
        return object()

    monkeypatch.setattr(
        "cognic_agentos.harness.registry_boot.build_and_populate_registry", _boot_raises
    )
    monkeypatch.setattr("cognic_agentos.harness.mcp_host.build_mcp_host", _spy_build_mcp_host)
    monkeypatch.setattr("cognic_agentos.protocol.a2a_endpoint.A2AEndpoint", _spy_a2a_endpoint)
    _force_sdk_available(monkeypatch)

    app = create_app(_adapter_settings(memory_settings, tmp_path), adapter_registry=memory_registry)
    async with app.router.lifespan_context(app):
        # fail-closed: no registry → both surfaces stay None → their routes 503:
        assert app.state.plugin_registry is None
        assert app.state.mcp_host is None
        assert app.state.a2a_endpoint is None
        # and neither constructor was even reached:
        assert captured["mcp_called"] is False
        assert captured["a2a_called"] is False


# ---------------------------------------------------------------------------
# §4 trapdoor — the boot is never handed a trust_gate
# ---------------------------------------------------------------------------


async def test_a2a_trust_gate_is_not_the_boot_registration_trust_gate(
    memory_settings: Settings,
    memory_registry: AdapterRegistry,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    async def _capture_boot(**kwargs: Any) -> object:
        captured["boot_kwargs"] = kwargs
        return PluginRegistry.__new__(PluginRegistry)

    monkeypatch.setattr(
        "cognic_agentos.harness.registry_boot.build_and_populate_registry", _capture_boot
    )
    _force_sdk_available(monkeypatch)
    _spy_surfaces(monkeypatch, captured)

    app = create_app(_adapter_settings(memory_settings, tmp_path), adapter_registry=memory_registry)
    async with app.router.lifespan_context(app):
        # the boot builds its OWN registration_trust_gate — a caller must NEVER be
        # able to hand it the A2A (or any) trust gate:
        assert "trust_gate" not in captured["boot_kwargs"]


# ---------------------------------------------------------------------------
# (b) — the lifespan builds + threads MCPAdmissionDeps into the boot
# ---------------------------------------------------------------------------


async def test_boot_receives_mcp_admission_deps(
    memory_settings: Settings,
    memory_registry: AdapterRegistry,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The (b) expansion: the lifespan BUILDS + THREADS an ``MCPAdmissionDeps``
    into the boot so a ``[tool.cognic.mcp]`` pack is admittable (no
    ``mcp_admission_deps_required``). Pins the intended shape — incl. the accepted
    Sprint-4 ``opa_engine=None`` posture (sampling-capable packs default-deny). A
    regression that drops the wiring (back to the kernel-image default) would
    silently re-empty the MCP catalog while the other unification tests still
    pass — this is the guard against that."""
    settings_obj = _adapter_settings(memory_settings, tmp_path)
    captured: dict[str, Any] = {}

    async def _capture_boot(**kwargs: Any) -> object:
        captured["boot_kwargs"] = kwargs
        return PluginRegistry.__new__(PluginRegistry)

    monkeypatch.setattr(
        "cognic_agentos.harness.registry_boot.build_and_populate_registry", _capture_boot
    )
    _force_sdk_available(monkeypatch)
    _spy_surfaces(monkeypatch, captured)

    app = create_app(settings_obj, adapter_registry=memory_registry)
    async with app.router.lifespan_context(app):
        mcp_admission = captured["boot_kwargs"]["mcp_admission"]
        assert isinstance(mcp_admission, MCPAdmissionDeps)
        assert mcp_admission.settings is settings_obj
        # the accepted Sprint-4 posture (plan AS-BUILT): sampling-capable packs
        # default-deny — wiring a real sampling OPAEngine is a documented extension.
        assert mcp_admission.opa_engine is None
        assert callable(mcp_admission.make_authz_client_for_probe)
        assert mcp_admission.vault_client is not None
