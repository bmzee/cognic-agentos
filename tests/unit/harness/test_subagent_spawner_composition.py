"""2026-06-20 (ADR-005) — harness build_subagent_spawner composition.

WIRED-but-DORMANT: asserts the lifespan builder composes a live SubAgentSpawner
whose child runner is the ManagedRunChildRunner (child-is-a-managed-run). Mirrors
test_mcp_host_builder.py's real build_runtime-over-memory-adapters convention; the
engine threaded into the builder is `adapters.relational.engine` (the SAME seam the
portal lifespan passes). Construction does no DB I/O, so a stub executor + the
in-memory sqlite engine suffice. (asyncio_mode=auto, so no module-level marker.)
"""

from pathlib import Path

from cognic_agentos.core.run.executor import RunRequest, RunResult
from cognic_agentos.db.adapters.factory import build_adapters
from cognic_agentos.harness import build_runtime
from cognic_agentos.harness.sandbox import build_subagent_spawner
from cognic_agentos.subagent.managed_run_runner import ManagedRunChildRunner
from cognic_agentos.subagent.spawn import SubAgentSpawner


def _litellm_yaml(tmp_path: Path) -> Path:
    """Minimal LiteLLM config (mirrors tests/unit/harness/test_mcp_host_builder.py)."""
    cfg = tmp_path / "litellm.yaml"
    cfg.write_text(
        "model_list:\n"
        "  - model_name: cognic-tier1-dev\n"
        "    litellm_params:\n"
        "      model: ollama/qwen\n"
        "      api_base: http://localhost:11434\n"
    )
    return cfg


class _StubExecutor:
    """Duck-typed managed-run executor (the builder passes it through to the
    ManagedRunChildRunner seam; the spawner construction never calls run())."""

    async def run(self, request: RunRequest) -> RunResult:  # pragma: no cover - never called
        raise NotImplementedError


async def test_build_subagent_spawner_wires_managed_run_runner(
    memory_registry, memory_settings, tmp_path
):
    s = memory_settings.model_copy(
        update={"litellm_config_path": _litellm_yaml(tmp_path), "cache_driver": "memory"}
    )
    adapters = build_adapters(s, registry=memory_registry)
    await adapters.open_all()
    runtime = await build_runtime(s, adapters)
    try:
        spawner = build_subagent_spawner(
            runtime=runtime,
            managed_run_executor=_StubExecutor(),  # any object with async run()
            engine=adapters.relational.engine,  # the in-memory AsyncEngine
            settings=s,  # has subagent_max_recursion_depth
        )
        assert isinstance(spawner, SubAgentSpawner)
        assert isinstance(spawner._runner, ManagedRunChildRunner)  # composition assert
    finally:
        await runtime.aclose()
        await adapters.close_all()
