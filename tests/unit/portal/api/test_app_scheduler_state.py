"""Sprint 13.7 (ADR-022) — app.state.scheduler introspection-seam exposure.

The scheduler is production-constructed by ``build_runtime`` (cache-conditional)
and exposed on ``app.state.scheduler`` via the lifespan, mirroring the
``app.state.kill_switch_engine`` / ``quota_engine`` introspection seams. There
is NO ``create_app`` kwarg and NO router mount in 13.7 (Fork D — construct +
expose only; 14A owns the submit -> execute caller).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cognic_agentos.portal.api.app import create_app

if TYPE_CHECKING:
    from pathlib import Path


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


def test_scheduler_preseeded_none_before_lifespan(memory_settings, memory_registry, tmp_path):
    """``app.state.scheduler`` is pre-seeded None at construction; population
    happens IN the lifespan (mirrors the app.state.runtime pre-seed)."""
    s = memory_settings.model_copy(
        update={"litellm_config_path": _litellm_yaml(tmp_path), "cache_driver": "memory"}
    )
    app = create_app(s, adapter_registry=memory_registry)
    assert app.state.scheduler is None


async def test_scheduler_threaded_from_runtime_after_lifespan(
    memory_settings, memory_registry, tmp_path
):
    """The lifespan overwrites app.state.scheduler with the build_runtime
    scheduler. Same-object identity pin against app.state.runtime.scheduler
    (set at app.py:601); cache present → a real (non-None) SchedulerEngine."""
    s = memory_settings.model_copy(
        update={"litellm_config_path": _litellm_yaml(tmp_path), "cache_driver": "memory"}
    )
    app = create_app(s, adapter_registry=memory_registry)
    assert app.state.scheduler is None  # pre-seed; lifespan populates
    async with app.router.lifespan_context(app):
        assert app.state.runtime is not None
        assert app.state.scheduler is app.state.runtime.scheduler
        assert app.state.scheduler is not None  # cache present → real scheduler
