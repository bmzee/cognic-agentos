"""Sprint 13.5b1 (ADR-014) — build_runtime wires the approval store + engine.

The approval trio (ApprovalRequestStore + ApprovalPolicy/OPAEngine +
ApprovalEngine) is built UNCONDITIONALLY (mirrors the ADR-023 config-overlay
posture — independent of memory/cache), so it is present even on the
gateway-only path. OPAEngine.create emits ``policy.bundle_loaded`` into
decision history at startup; the in-memory relational test adapter provides
the chain schema at connect() (tests/support/adapter_fixtures.py).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cognic_agentos.core.approval.engine import ApprovalEngine
from cognic_agentos.core.approval.policy import ApprovalPolicy
from cognic_agentos.core.approval.storage import ApprovalRequestStore
from cognic_agentos.db.adapters.factory import build_adapters

if TYPE_CHECKING:
    from pathlib import Path

    from cognic_agentos.core.config import Settings
    from cognic_agentos.db.adapters.registry import AdapterRegistry


def _litellm_yaml(tmp_path: Path) -> Path:
    cfg = tmp_path / "litellm.yaml"
    cfg.write_text(
        "model_list:\n"
        "  - model_name: cognic-tier1-dev\n"
        "    litellm_params:\n"
        "      model: ollama/qwen\n"
        "      api_base: http://localhost:11434\n"
    )
    return cfg


async def test_build_runtime_wires_approval_store_and_engine(
    memory_registry: AdapterRegistry, memory_settings: Settings, tmp_path: Path
) -> None:
    from cognic_agentos.harness import build_runtime

    s = memory_settings.model_copy(
        update={"litellm_config_path": _litellm_yaml(tmp_path), "cache_driver": "none"}
    )
    adapters = build_adapters(s, registry=memory_registry)
    await adapters.open_all()
    try:
        runtime = await build_runtime(s, adapters)
        assert isinstance(runtime.approval_store, ApprovalRequestStore)
        assert isinstance(runtime.approval_engine, ApprovalEngine)
        # The engine's policy is the Rego-backed ApprovalPolicy pointed at the
        # tools bundle from the NEW tools_policy_bundle Setting (identity pin —
        # mirrors test_runtime.py's resolver identity assertions).
        policy = runtime.approval_engine._policy
        assert isinstance(policy, ApprovalPolicy)
        assert policy._opa_engine._bundle_path == s.tools_policy_bundle
        await runtime.aclose()
    finally:
        await adapters.close_all()
