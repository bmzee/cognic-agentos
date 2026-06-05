"""Harness Injection T8 — create_app gateway kwarg + construction-time /memory
mount gate.

The lifespan ``build_runtime`` wiring (which populates ``app.state.runtime`` /
``llm_gateway`` / ``memory_api_factory`` on the adapter path) is exercised by the
reaper-lifespan slice (``test_reaper_prod_wiring.py``) + the full suite, NOT here
— these unit tests cover only the construction-time surface (the kwarg-on-state
and the two mount-gate branches), which needs no adapter pool.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.portal.api.app import create_app

if TYPE_CHECKING:
    from pathlib import Path

    from fastapi import FastAPI

    from cognic_agentos.core.config import Settings
    from cognic_agentos.db.adapters.registry import AdapterRegistry


def _compiled_paths(app: FastAPI) -> set[str | None]:
    return {getattr(r, "path", None) for r in app.routes}


def _litellm_yaml(tmp_path: Path) -> Path:
    """Minimal LiteLLM config so build_runtime's PreflightResolver.from_yaml has
    a real file to read (mirrors tests/unit/harness/test_runtime.py)."""
    cfg = tmp_path / "litellm.yaml"
    cfg.write_text(
        "model_list:\n"
        "  - model_name: cognic-tier1-dev\n"
        "    litellm_params:\n"
        "      model: ollama/qwen\n"
        "      api_base: http://localhost:11434\n"
    )
    return cfg


def test_llm_gateway_kwarg_stored_on_state() -> None:
    """The ``llm_gateway`` kwarg is attached to ``app.state`` at construction.
    On the adapter path the lifespan overwrites it with the ``build_runtime``
    gateway; this kwarg is the test / injection seam."""
    sentinel = object()
    app = create_app(llm_gateway=sentinel)  # type: ignore[arg-type]
    assert app.state.llm_gateway is sentinel


def test_memory_router_mounted_when_cache_configured() -> None:
    """``cache_driver != "none"`` mounts /memory at CONSTRUCTION time — no
    factory needed (the lifespan populates it later; an unwired request fails
    closed 503 per T7). This is the gate that lets build_runtime supply the
    factory late in the lifespan."""
    s = build_settings_without_env_file().model_copy(
        update={"cache_driver": "redis", "redis_url": "redis://x:6379/0"}
    )
    app = create_app(s)
    assert any(p and p.startswith("/api/v1/memory") for p in _compiled_paths(app))
    assert app.state.memory_router_mounted is True


def test_memory_router_absent_when_cache_none() -> None:
    """``cache_driver="none"`` (the pack-only default) with no injected factory
    mounts NO /memory routes — startup stays silent for pack-only deploys."""
    s = build_settings_without_env_file().model_copy(update={"cache_driver": "none"})
    app = create_app(s)
    assert not any(p and p.startswith("/api/v1/memory") for p in _compiled_paths(app))
    assert app.state.memory_router_mounted is False


async def test_lifespan_build_runtime_populates_state(
    memory_registry: AdapterRegistry, memory_settings: Settings, tmp_path: Path
) -> None:
    """The lifespan's build_runtime populates app.state.{runtime, llm_gateway,
    memory_api_factory} on the adapter path.

    ``cache_driver="none"`` → build_runtime takes its gateway-only branch
    (memory_api_factory stays None); the runtime + gateway ARE populated. The
    pre-startup ``app.state.runtime is None`` pre-seed confirms the LIFESPAN —
    not construction — does the population. A clean lifespan exit (no raise)
    exercises the runtime-first aclose() in the finally."""
    s = memory_settings.model_copy(
        update={"litellm_config_path": _litellm_yaml(tmp_path), "cache_driver": "none"}
    )
    app = create_app(s, adapter_registry=memory_registry)
    assert app.state.runtime is None  # pre-seed; population happens IN the lifespan
    async with app.router.lifespan_context(app):
        assert app.state.runtime is not None
        assert app.state.llm_gateway is app.state.runtime.llm_gateway
        assert app.state.memory_api_factory is None  # cache_driver=none → no memory branch
