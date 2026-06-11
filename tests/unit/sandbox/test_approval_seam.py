"""Sprint 13.5c1 (ADR-014) — sandbox approval seam cutover tests."""

from __future__ import annotations

import typing

import pytest


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


# ---------------------------------------------------------------------------
# T5+ engine fixtures (mirror 13.5b2's test_mcp_approval_seam.py shapes)
# ---------------------------------------------------------------------------


class _MutableClock:
    """Advanceable engine clock (the expired-readmission test moves time past
    the flow TTL; everything else uses the fixed default)."""

    def __init__(self) -> None:
        from datetime import UTC, datetime

        self.now = datetime(2026, 6, 11, 12, 0, tzinfo=UTC)

    def __call__(self) -> object:
        return self.now


class _StubApprovalPolicy:
    """Fixed-flow classifier (OPA-free; mirrors test_routes.py::_StubPolicy)."""

    def __init__(self, flow: str = "require_single_approval") -> None:
        self._flow = flow

    async def classify(self, *, risk_tier: str) -> str:
        return self._flow


async def _mk_approval_store(tmp_path: object) -> object:
    import asyncio as _asyncio

    from alembic import command
    from sqlalchemy.ext.asyncio import create_async_engine

    from cognic_agentos.core.approval.storage import ApprovalRequestStore
    from cognic_agentos.core.decision_history import DecisionHistoryStore
    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path}/sandbox-seam.db"
    cfg = make_alembic_config(url)
    await _asyncio.to_thread(command.upgrade, cfg, "head")
    return ApprovalRequestStore(DecisionHistoryStore(create_async_engine(url)))


def _mk_approval_engine(store: object, *, flow: str, clock: object = None) -> object:
    from datetime import UTC, datetime

    from cognic_agentos.core.approval.engine import ApprovalEngine
    from cognic_agentos.core.config import build_settings_without_env_file

    return ApprovalEngine(
        policy=_StubApprovalPolicy(flow),
        store=store,  # type: ignore[arg-type]
        settings=build_settings_without_env_file(),
        clock=clock or (lambda: datetime(2026, 6, 11, 12, 0, tzinfo=UTC)),  # type: ignore[arg-type]
    )


def _admit_kwargs(**overrides: object) -> dict[str, object]:
    """All-green admit_policy kwargs (mirrors test_admission_pipeline fixtures);
    actor carries a REAL str subject — the envelope digests it."""
    from unittest.mock import AsyncMock, MagicMock

    from cognic_agentos.core.policy.engine import Decision
    from cognic_agentos.sandbox.admission import KernelDefaultCredentialAdapter

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
    base: dict[str, object] = dict(
        tenant_id="t-1",
        actor=MagicMock(subject="agent-1"),
        pack_context=_valid_pack_context(
            risk_tier="payment_action", data_classes=("payment_data",)
        ),
        catalog=catalog,
        credential_adapter=KernelDefaultCredentialAdapter(),
        rego_engine=rego,
        settings=_passing_settings(),
    )
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# T5 — wired first-admission path
# ---------------------------------------------------------------------------


class TestWiredFirstAdmission:
    async def test_high_tier_first_admission_refuses_pending_with_correlator(
        self, tmp_path: object
    ) -> None:
        import uuid as _uuid

        from cognic_agentos.sandbox.admission import admit_policy
        from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

        store = await _mk_approval_store(tmp_path)
        engine = _mk_approval_engine(store, flow="require_4_eyes")
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(),  # type: ignore[arg-type]
                **_admit_kwargs(),  # type: ignore[arg-type]
                approval_engine=engine,  # type: ignore[arg-type]
            )
        assert exc.value.reason == "sandbox_approval_pending"
        assert exc.value.approval_request_id is not None
        rid = _uuid.UUID(exc.value.approval_request_id)  # parseable correlator attr
        detail = await store.load_detail(request_id=rid, tenant_id="t-1")  # type: ignore[attr-defined]
        assert detail is not None and detail.state == "pending"
        # Envelope-sourcing pins (spec §3.3/§3.4):
        assert detail.tool_identity.startswith("sandbox:")
        assert detail.redacted_context.startswith("sandbox_admission pack_id=")
        assert "cognic.test_pack" in detail.redacted_context
        assert detail.data_classes == ("payment_data",)

    async def test_auto_flow_proceeds_without_approval_row(self, tmp_path: object) -> None:
        # F2=B direction 1: engine classified auto_run -> admission proceeds
        # (high DECLARED tier; static set bypassed on the wired path).
        from cognic_agentos.sandbox.admission import admit_policy

        store = await _mk_approval_store(tmp_path)
        engine = _mk_approval_engine(store, flow="auto_run")
        kwargs = _admit_kwargs()
        await admit_policy(
            _valid_policy(),  # type: ignore[arg-type]
            **kwargs,  # type: ignore[arg-type]
            approval_engine=engine,  # type: ignore[arg-type]
        )
        assert await store.list_pending("t-1") == []  # type: ignore[attr-defined]
        # ...and approval_verified stays False on the auto path:
        sent = kwargs["rego_engine"].evaluate.await_args.kwargs["input"]  # type: ignore[attr-defined]
        assert sent["approval_verified"] is False

    async def test_tightened_safe_tier_requires_approval(self, tmp_path: object) -> None:
        # F2=B direction 2: overlay-tightened tools.rego on a safe tier.
        from cognic_agentos.sandbox.admission import admit_policy
        from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

        store = await _mk_approval_store(tmp_path)
        engine = _mk_approval_engine(store, flow="require_single_approval")
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(),  # type: ignore[arg-type]
                **_admit_kwargs(pack_context=_valid_pack_context(risk_tier="internal_write")),  # type: ignore[arg-type]
                approval_engine=engine,  # type: ignore[arg-type]
            )
        assert exc.value.reason == "sandbox_approval_pending"

    async def test_regulator_tier_required_refs_carries_admission_correlator(
        self, tmp_path: object
    ) -> None:
        import uuid as _uuid

        from cognic_agentos.sandbox.admission import admit_policy
        from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

        store = await _mk_approval_store(tmp_path)
        engine = _mk_approval_engine(store, flow="require_4_eyes")
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(),  # type: ignore[arg-type]
                **_admit_kwargs(
                    pack_context=_valid_pack_context(risk_tier="regulator_communication")
                ),  # type: ignore[arg-type]
                approval_engine=engine,  # type: ignore[arg-type]
            )
        assert exc.value.approval_request_id is not None
        rid = _uuid.UUID(exc.value.approval_request_id)
        detail = await store.load_detail(request_id=rid, tenant_id="t-1")  # type: ignore[attr-defined]
        assert detail is not None
        ref = detail.required_refs["audit_record_ref"]
        assert ref.startswith("sandbox-admit-")  # §3.5 seam-minted correlator
        assert ref in exc.value.detail  # examiner-followable from the refusal

    async def test_engine_absent_fallback_byte_compat(self) -> None:
        from cognic_agentos.sandbox.admission import admit_policy
        from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(),  # type: ignore[arg-type]
                **_admit_kwargs(),  # type: ignore[arg-type]
            )
        assert exc.value.reason == "sandbox_high_risk_tier_refused_pre_13_5"
        assert exc.value.approval_request_id is None

    async def test_engine_absent_ignores_supplied_approval_request_id_fallback(self) -> None:
        # PINNED CHOICE (plan review): engine-absent is byte-for-byte (§2) —
        # a dangling correlator on the unwired path is INERT, never a new
        # fail-loud branch. The fallback refusal fires identically and the
        # exception carries NO correlator (the param was never read).
        import uuid as _uuid

        from cognic_agentos.sandbox.admission import admit_policy
        from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

        with pytest.raises(SandboxLifecycleRefused) as exc:
            await admit_policy(
                _valid_policy(),  # type: ignore[arg-type]
                **_admit_kwargs(),  # type: ignore[arg-type]
                approval_request_id=_uuid.uuid4(),
            )
        assert exc.value.reason == "sandbox_high_risk_tier_refused_pre_13_5"
        assert exc.value.approval_request_id is None
