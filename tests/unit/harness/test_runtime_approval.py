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

from cognic_agentos.core.approval._types import ApprovalActor, ApprovalEnvelope
from cognic_agentos.core.approval.assignments import ApprovalAssignmentStore
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


async def test_build_runtime_assignment_changes_the_mint_flow(
    memory_registry: AdapterRegistry, memory_settings: Settings, tmp_path: Path
) -> None:
    """The production mint engine must consume the store built beside it."""

    from cognic_agentos.harness import build_runtime

    s = memory_settings.model_copy(
        update={"litellm_config_path": _litellm_yaml(tmp_path), "cache_driver": "none"}
    )
    adapters = build_adapters(s, registry=memory_registry)
    await adapters.open_all()
    try:
        runtime = await build_runtime(s, adapters)
        assert isinstance(runtime.approval_assignment_store, ApprovalAssignmentStore)
        await runtime.approval_assignment_store.assign(
            tenant_id="tenant-runtime",
            tool_identity="mcp:approval-probe/probe_write",
            approver_subjects=("dana", "erin", "fiona"),
            actor=ApprovalActor(
                subject="omar",
                tenant_id="tenant-runtime",
                scopes=frozenset({"tool.approve.assign"}),
                actor_type="human",
            ),
            request_request_id="assignment-runtime-regression",
        )

        request = await runtime.approval_engine.create_request(
            envelope=ApprovalEnvelope(
                risk_tier="read_only",
                tool_identity="mcp:approval-probe/probe_write",
                originator_subject="amir",
                tenant_id="tenant-runtime",
                data_classes=("internal",),
                args_digest=b"\x42" * 32,
                redacted_context="composition-root assignment regression",
                required_refs={},
            )
        )
        assert request.flow == "require_assigned"
        projected = await runtime.approval_engine.check(
            request_id=request.request_id,
            tenant_id="tenant-runtime",
        )
        assert projected.required_count == 3
        assert projected.decisions_recorded == 0
        await runtime.aclose()
    finally:
        await adapters.close_all()
