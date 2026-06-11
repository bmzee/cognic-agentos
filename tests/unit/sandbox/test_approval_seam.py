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


def test_canonical_sandbox_identity_shape_and_collision_proofing() -> None:
    from cognic_agentos.sandbox.admission import _canonical_sandbox_identity

    ident = _canonical_sandbox_identity(
        pack_id="cognic.test_pack", pack_artifact_digest="sha256:" + "a" * 64
    )
    assert ident.startswith("sandbox:")
    assert len(ident) == 8 + 64  # "sandbox:" + hexdigest — fits String(256)
    assert ident == _canonical_sandbox_identity(
        pack_id="cognic.test_pack", pack_artifact_digest="sha256:" + "a" * 64
    )
    # Collision-proofing (the F4 doctrine): separator content cannot alias.
    a = _canonical_sandbox_identity(pack_id="a:b", pack_artifact_digest="c")
    b = _canonical_sandbox_identity(pack_id="a", pack_artifact_digest="b:c")
    assert a != b


def test_policy_binding_projection_covers_every_field_except_warm_pool_key() -> None:
    # Spec §3.3: the GRANT must bind every security-load-bearing SandboxPolicy
    # field; warm_pool_key (internal pooling hint) is the ONLY exclusion.
    # Drift-pinned via dataclasses.fields so a future SandboxPolicy field
    # FAILS here until the projection decision is made explicitly.
    import dataclasses

    from cognic_agentos.sandbox.admission import _policy_binding_projection
    from cognic_agentos.sandbox.policy import SandboxPolicy, WritableMount

    policy = SandboxPolicy(
        cpu_cores=1.0,
        cpu_time_budget_s=2.0,
        memory_mb=256,
        walltime_s=30.0,
        runtime_image="ghcr.io/cognic/sandbox-runtime-python@sha256:" + "b" * 64,
        egress_allow_list=("api.example.com",),
        vault_path="secret/x",
        read_only_root=False,
        writable_mounts=(WritableMount(host_path="/h", container_path="/c"),),
        warm_pool_key="ignored",
    )
    proj = _policy_binding_projection(policy)
    field_names = {f.name for f in dataclasses.fields(SandboxPolicy)}
    assert set(proj.keys()) == field_names - {"warm_pool_key"}
    # canonical-form no-tuples doctrine: lists + dicts only.
    assert proj["egress_allow_list"] == ["api.example.com"]
    assert proj["writable_mounts"] == [
        {"host_path": "/h", "container_path": "/c", "read_only": False}
    ]
    # The projection is canonical_bytes-clean (would raise on tuples).
    from cognic_agentos.core.canonical import canonical_bytes

    canonical_bytes(proj)


def test_binding_projection_distinguishes_runtime_image_and_root_flag() -> None:
    # The Step-9 Rego policy projection omits runtime_image/read_only_root/
    # writable_mounts; the BINDING projection must distinguish them (an image
    # swap or root-fs flip between grant and re-admit MUST change the digest).
    from cognic_agentos.sandbox.admission import _policy_binding_projection
    from cognic_agentos.sandbox.policy import SandboxPolicy

    base: dict[str, object] = dict(
        cpu_cores=1.0,
        cpu_time_budget_s=None,
        memory_mb=256,
        walltime_s=30.0,
        runtime_image="img-a",
        egress_allow_list=(),
        vault_path=None,
    )
    a = _policy_binding_projection(SandboxPolicy(**base))  # type: ignore[arg-type]
    b = _policy_binding_projection(
        SandboxPolicy(**{**base, "runtime_image": "img-b"})  # type: ignore[arg-type]
    )
    c = _policy_binding_projection(
        SandboxPolicy(**{**base, "read_only_root": False})  # type: ignore[arg-type]
    )
    assert a != b and a != c


# ---------------------------------------------------------------------------
# T4+ admission fixtures (mirror test_admission_pipeline.py:85-176)
# ---------------------------------------------------------------------------

_VALID_IMAGE_REF = "ghcr.io/cognic/sandbox-runtime-python@sha256:" + "c" * 64


def _valid_policy(**overrides: object) -> object:
    from cognic_agentos.sandbox.policy import SandboxPolicy

    base: dict[str, object] = {
        "cpu_cores": 1.0,
        "cpu_time_budget_s": None,
        "memory_mb": 256,
        "walltime_s": 30.0,
        "runtime_image": _VALID_IMAGE_REF,
        "egress_allow_list": ("api.example.com",),
        "vault_path": None,
    }
    base.update(overrides)
    return SandboxPolicy(**base)  # type: ignore[arg-type]


def _valid_pack_context(**overrides: object) -> object:
    from cognic_agentos.sandbox.policy import PackAdmissionContext

    base: dict[str, object] = {
        "pack_id": "cognic.test_pack",
        "pack_version": "v1.0.0",
        "pack_artifact_digest": "sha256:" + "a" * 64,
        "risk_tier": "internal_write",
        "declares_dynamic_install": False,
        "profile": "production",
    }
    base.update(overrides)
    return PackAdmissionContext(**base)  # type: ignore[arg-type]


def _passing_settings() -> object:
    from unittest.mock import MagicMock

    return MagicMock(
        sandbox_per_tenant_max_cpu=4.0,
        sandbox_per_tenant_max_memory=1024,
        sandbox_per_tenant_max_walltime=300.0,
        sandbox_kernel_default_max_credential_ttl_s=900,
    )


async def test_step9_input_always_carries_approval_verified_false_unwired() -> None:
    # Input-contract completeness (precomputed-bool precedent): the key is
    # ALWAYS threaded; engine-absent admissions send False.
    from unittest.mock import AsyncMock, MagicMock

    from cognic_agentos.core.policy.engine import Decision
    from cognic_agentos.sandbox.admission import KernelDefaultCredentialAdapter, admit_policy

    rego = MagicMock()
    rego.evaluate = AsyncMock(
        return_value=Decision(
            allow=True,
            rule_matched="data.cognic.sandbox.admit.allow",
            reasoning="ok",
            decision_data=None,
        )
    )
    catalog = MagicMock()
    catalog.is_canonical.return_value = True
    catalog.is_tenant_allow_listed.return_value = True
    catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
    catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
    await admit_policy(
        _valid_policy(),  # type: ignore[arg-type]
        tenant_id="t-1",
        actor=MagicMock(),
        pack_context=_valid_pack_context(),  # type: ignore[arg-type]
        catalog=catalog,
        credential_adapter=KernelDefaultCredentialAdapter(),
        rego_engine=rego,
        settings=_passing_settings(),  # type: ignore[arg-type]
    )
    sent = rego.evaluate.await_args.kwargs["input"]
    assert sent["approval_verified"] is False
