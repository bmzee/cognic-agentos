"""Sprint 13.8 (ADR-002) — app.state.mcp_host SDK-gated lifespan construction.

The MCP host is production-constructed in the lifespan (after build_runtime),
gated on is_mcp_available() (the mcp SDK is an optional `adapters` extra). The
host is exposed on app.state.mcp_host but has NO caller — the approval seam is
wired but dormant (the 13.7 honesty pattern).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cognic_agentos.portal.api.app import create_app

if TYPE_CHECKING:
    from pathlib import Path


def _litellm_yaml(tmp_path: Path) -> Path:
    """Minimal LiteLLM config (mirrors tests/unit/harness/test_runtime.py)."""
    cfg = tmp_path / "litellm.yaml"
    cfg.write_text(
        "model_list:\n"
        "  - model_name: cognic-tier1-dev\n"
        "    litellm_params:\n"
        "      model: ollama/qwen\n"
        "      api_base: http://localhost:11434\n"
    )
    return cfg


def test_mcp_host_preseeded_none_before_lifespan(memory_settings, memory_registry, tmp_path):
    s = memory_settings.model_copy(
        update={"litellm_config_path": _litellm_yaml(tmp_path), "cache_driver": "memory"}
    )
    app = create_app(s, adapter_registry=memory_registry)
    assert app.state.mcp_host is None  # pre-seed; population happens IN the lifespan


async def test_mcp_host_none_when_sdk_absent(
    memory_settings, memory_registry, tmp_path, monkeypatch
):
    # SDK-absent branch via monkeypatch (no venv change) → None + warning, app boots.
    monkeypatch.setattr("cognic_agentos.portal.api.app.is_mcp_available", lambda: False)
    s = memory_settings.model_copy(
        update={"litellm_config_path": _litellm_yaml(tmp_path), "cache_driver": "memory"}
    )
    app = create_app(s, adapter_registry=memory_registry)
    async with app.router.lifespan_context(app):
        assert app.state.mcp_host is None


async def test_mcp_host_constructed_when_sdk_present(memory_settings, memory_registry, tmp_path):
    # the mcp SDK IS present in the uv venv → the lifespan constructs the host
    # over a default (empty) PluginRegistry; the approval seam is WIRED.
    s = memory_settings.model_copy(
        update={"litellm_config_path": _litellm_yaml(tmp_path), "cache_driver": "memory"}
    )
    app = create_app(s, adapter_registry=memory_registry)
    async with app.router.lifespan_context(app):
        from cognic_agentos.protocol.mcp_host import MCPHost

        assert isinstance(app.state.mcp_host, MCPHost)
        assert app.state.mcp_host._approval_engine is app.state.runtime.approval_engine
    # lifespan exited clean (the lifespan-owned httpx client closed on shutdown).
