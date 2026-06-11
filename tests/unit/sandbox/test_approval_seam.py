"""Sprint 13.5c1 (ADR-014) — sandbox approval seam cutover tests."""

from __future__ import annotations

import typing


def test_refusal_vocabulary_carries_the_five_approval_values() -> None:
    # Wire-protocol-public (spec §4). The +5 join the Literal; the engine-absent
    # fallback value is KEPT.
    from cognic_agentos.sandbox.protocol import SandboxRefusalReason

    values = set(typing.get_args(SandboxRefusalReason))
    assert {
        "sandbox_approval_pending",
        "sandbox_approval_denied",
        "sandbox_approval_expired",
        "sandbox_approval_binding_mismatch",
        "sandbox_approval_request_not_found",
    } <= values
    assert "sandbox_high_risk_tier_refused_pre_13_5" in values  # fallback kept


def test_lifecycle_refused_carries_optional_approval_request_id() -> None:
    from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

    bare = SandboxLifecycleRefused("sandbox_approval_pending", detail="d")
    assert bare.approval_request_id is None  # additive default — old sites unchanged
    rich = SandboxLifecycleRefused(
        "sandbox_approval_pending", detail="d", approval_request_id="abc"
    )
    assert rich.approval_request_id == "abc"


def test_pack_admission_context_carries_data_classes_with_empty_default() -> None:
    # Spec §3.4: the MCPServerEntry.data_classes pattern — harness populates
    # from the manifest [data_governance].data_classes; default keeps every
    # existing constructor green.
    from cognic_agentos.sandbox.policy import PackAdmissionContext

    base: dict[str, object] = dict(
        pack_id="cognic.test_pack",
        pack_version="v1.0.0",
        pack_artifact_digest="sha256:" + "a" * 64,
        risk_tier="internal_write",
        declares_dynamic_install=False,
        profile="production",
    )
    assert PackAdmissionContext(**base).data_classes == ()  # type: ignore[arg-type]
    ctx = PackAdmissionContext(**base, data_classes=("customer_pii",))  # type: ignore[arg-type]
    assert ctx.data_classes == ("customer_pii",)
