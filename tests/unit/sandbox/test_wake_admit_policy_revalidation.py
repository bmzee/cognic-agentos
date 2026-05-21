"""Sprint 8.5 T6 — wake-time admit_policy revalidation per spec §3.2
step 4 + Q3 lock.

Pins: every Sprint-8A admit_policy refusal class re-wraps at wake as
``sandbox_wake_policy_revalidation_failed`` with the ORIGINAL 8A
reason in ``detail``. Per spec §6.1 there are 10 admit_policy refusal
sites:

  3.  ``sandbox_credential_adapter_not_configured`` (vault_path set
      + KernelDefaultCredentialAdapter wired)
  3a. ``sandbox_runtime_deps_unsupported_in_production``
  4.  ``sandbox_high_risk_tier_refused_pre_13_5``
  5.  ``sandbox_policy_exceeds_tenant_max_cpu`` /
      ``_memory`` / ``_walltime`` (three axes)
  6.  ``sandbox_image_digest_not_in_canonical_catalog``
  7.  ``sandbox_image_cosign_verification_failed``
  8.  ``sandbox_image_sbom_check_failed``
  9.  ``sandbox_policy_rego_denied``

The wake-time taxonomy (``sandbox_wake_*``) is wake-specific per
spec §2.3; the wake() seam re-wraps ALL of these as
``sandbox_wake_policy_revalidation_failed`` so a forensic examiner
can distinguish a wake-time refusal from a create-time refusal. The
original reason lives in ``detail`` for traceability.

Strategy: parametrise across the refusal class; tighten the
catalog/Rego/settings/credential surface to make admit_policy refuse
on that arm at wake-time; assert the wake() seam re-wraps correctly.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

pytest.importorskip("aiodocker")

from cognic_agentos.core.audit import AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.db.adapters.local_object_store_adapter import (
    LocalObjectStoreAdapter,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox import KernelDefaultCredentialAdapter
from cognic_agentos.sandbox.backends.docker_sibling import (
    DockerSiblingSandboxBackend,
)
from cognic_agentos.sandbox.checkpoint_store import CheckpointStore
from cognic_agentos.sandbox.policy import PackAdmissionContext, SandboxPolicy
from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused


@dataclass
class _StubSettings:
    sandbox_per_tenant_max_cpu: float = 4.0
    sandbox_per_tenant_max_memory: int = 4096
    sandbox_per_tenant_max_walltime: float = 300.0
    sandbox_checkpoint_retention_s: int = 86_400
    sandbox_max_checkpoints_per_session: int = 10
    sandbox_reaper_interval_s: int = 300


def _policy() -> SandboxPolicy:
    return SandboxPolicy(
        cpu_cores=0.5,
        cpu_time_budget_s=None,
        memory_mb=256,
        walltime_s=30.0,
        runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
        egress_allow_list=("api.example.com",),
        vault_path=None,
    )


def _pack_ctx() -> PackAdmissionContext:
    return PackAdmissionContext(
        pack_id="cognic.t",
        pack_version="v1.0.0",
        pack_artifact_digest="sha256:" + "1" * 64,
        risk_tier="internal_write",
        declares_dynamic_install=False,
        profile="production",
    )


_ACTOR = Actor(
    subject="alice@bank",
    tenant_id="t-1",
    scopes=frozenset(),
    actor_type="human",
)


@pytest_asyncio.fixture
async def engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    url = f"sqlite+aiosqlite:///{tmp_path / 'dh.db'}"
    eng = create_async_engine(url)
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="audit_event",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=datetime.now(UTC),
            )
        )
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="decision_history",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=datetime.now(UTC),
            )
        )
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def store(tmp_path: Path, engine: AsyncEngine) -> CheckpointStore:
    return CheckpointStore(
        object_store=LocalObjectStoreAdapter(root=tmp_path / "objects"),
        audit_store=AuditStore(engine),
        decision_history_store=DecisionHistoryStore(engine),
        settings=_StubSettings(),
    )


def _make_backend(
    store: CheckpointStore,
    *,
    catalog: MagicMock | None = None,
    rego_decision: MagicMock | None = None,
    settings: _StubSettings | None = None,
) -> DockerSiblingSandboxBackend:
    if catalog is None:
        catalog = MagicMock()
        catalog.is_canonical.return_value = True
        catalog.is_tenant_allow_listed.return_value = False
        catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
        catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)

    rego = MagicMock()
    if rego_decision is None:
        rego_decision = MagicMock(allow=True, reasoning="")
    rego.evaluate = AsyncMock(return_value=rego_decision)

    return DockerSiblingSandboxBackend(
        docker_client=MagicMock(),
        image_catalog=catalog,
        credential_adapter=KernelDefaultCredentialAdapter(),
        rego_engine=rego,
        audit_store=store._audit_store,
        decision_history_store=store._dh_store,
        settings=settings or _StubSettings(),  # type: ignore[arg-type]
        warm_pool=None,
        checkpoint_store=store,
    )


async def _persist_checkpoint_with_policy(
    store: CheckpointStore,
    *,
    session_id: str,
    policy: SandboxPolicy | None = None,
    pack_context: PackAdmissionContext | None = None,
) -> str:
    """Persist a checkpoint then surgically replace the persisted
    policy/pack_context blob on disk so wake-time admit_policy can
    refuse against it.

    P2.r2 fixture parity: ALSO writes the
    ``<tenant>/<session>/<checkpoint>.suspend_event_id`` side-blob
    with a parseable UUID so wake() Step 5 (suspend-linkage read)
    cannot refuse with ``sandbox_wake_checkpoint_corrupt`` and the
    tests reach Step 4 (admit_policy revalidate) — which is the only
    thing these tests assert.

    SCOPE NOTE (P2.r3 honesty): the random UUID here pins ONLY the
    T6 wake-linkage SHAPE requirement (parseable bytes at the
    expected key) — it is NOT the record_id of a real
    ``sandbox.lifecycle.suspended`` chain row. The T8 chain-verifier
    relationship (Sprint 8.5 T8) — verifying that the side-blob UUID
    cross-references a real suspended-event record_id — is out of
    scope for these admit_policy revalidation tests. Tests that
    need the chain-verifier semantic linkage will live alongside T8
    and emit a real suspended row to seed their fixture.
    """
    cid = await store.persist(
        session_id=session_id,
        tenant_id="t-1",
        label="cp",
        snapshot_bytes=b"snap",
        policy=_policy(),
        pack_context=_pack_ctx(),
        vault_lease_refs=(),
    )
    # P2.r2 — write a valid suspend_event_id side-blob mirroring what
    # _do_suspend()'s Step 4 writes in production. Without this, the
    # test only reaches Step 4 admit_policy because wake() currently
    # runs admit_policy BEFORE the linkage read; a future reorder
    # would silently flip the refusal class to checkpoint_corrupt.
    await store._object_store.put(
        "sandbox-checkpoints",
        f"t-1/{session_id}/{cid}.suspend_event_id",
        str(uuid.uuid4()).encode("utf-8"),
        retention_seconds=None,
    )
    if policy is None and pack_context is None:
        return cid

    # Surgically smuggle the desired tightening into the persisted
    # metadata so wake() reads what we want admit_policy to refuse.
    key = f"t-1/{session_id}/{cid}.metadata.json"
    raw = await store._object_store.get("sandbox-checkpoints", key)
    meta = json.loads(raw)
    if policy is not None:
        meta["policy"] = {
            "cpu_cores": policy.cpu_cores,
            "cpu_time_budget_s": policy.cpu_time_budget_s,
            "memory_mb": policy.memory_mb,
            "walltime_s": policy.walltime_s,
            "runtime_image": policy.runtime_image,
            "egress_allow_list": list(policy.egress_allow_list),
            "vault_path": policy.vault_path,
            "read_only_root": policy.read_only_root,
            "writable_mounts": [
                {
                    "host_path": m.host_path,
                    "container_path": m.container_path,
                    "read_only": m.read_only,
                }
                for m in policy.writable_mounts
            ],
            "warm_pool_key": policy.warm_pool_key,
        }
    if pack_context is not None:
        meta["pack_context"] = {
            "pack_id": pack_context.pack_id,
            "pack_version": pack_context.pack_version,
            "pack_artifact_digest": pack_context.pack_artifact_digest,
            "risk_tier": pack_context.risk_tier,
            "declares_dynamic_install": pack_context.declares_dynamic_install,
            "profile": pack_context.profile,
        }
    await store._object_store.put(
        "sandbox-checkpoints",
        key,
        json.dumps(meta).encode("utf-8"),
        retention_seconds=None,
    )
    return cid


# ---------------------------------------------------------------------------
# Tests — parametrized per admission refusal class
# ---------------------------------------------------------------------------


class TestAdmitPolicyRefusalsRewrapAtWakeTime:
    @pytest.mark.asyncio
    async def test_credential_adapter_not_configured_rewraps(self, store: CheckpointStore) -> None:
        """admit_policy step 3 — vault_path set + KernelDefault adapter."""
        vault_policy = SandboxPolicy(
            cpu_cores=0.5,
            cpu_time_budget_s=None,
            memory_mb=256,
            walltime_s=30.0,
            runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
            egress_allow_list=("api.example.com",),
            vault_path="secret/data/bank/key",
        )
        await _persist_checkpoint_with_policy(store, session_id="sess-cred", policy=vault_policy)
        backend = _make_backend(store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-cred", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_policy_revalidation_failed"
        assert "sandbox_credential_adapter_not_configured" in exc.value.detail

    @pytest.mark.asyncio
    async def test_dynamic_install_in_production_rewraps(self, store: CheckpointStore) -> None:
        """admit_policy step 3a — declares_dynamic_install + production."""
        ctx = PackAdmissionContext(
            pack_id="cognic.t",
            pack_version="v1.0.0",
            pack_artifact_digest="sha256:" + "1" * 64,
            risk_tier="internal_write",
            declares_dynamic_install=True,
            profile="production",
        )
        await _persist_checkpoint_with_policy(store, session_id="sess-dyn", pack_context=ctx)
        backend = _make_backend(store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-dyn", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_policy_revalidation_failed"
        assert "sandbox_runtime_deps_unsupported_in_production" in exc.value.detail

    @pytest.mark.asyncio
    async def test_high_risk_tier_pre_13_5_rewraps(self, store: CheckpointStore) -> None:
        """admit_policy step 4 — risk_tier in the 6-high-risk set."""
        ctx = PackAdmissionContext(
            pack_id="cognic.t",
            pack_version="v1.0.0",
            pack_artifact_digest="sha256:" + "1" * 64,
            risk_tier="payment_action",
            declares_dynamic_install=False,
            profile="production",
        )
        await _persist_checkpoint_with_policy(store, session_id="sess-hr", pack_context=ctx)
        backend = _make_backend(store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-hr", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_policy_revalidation_failed"
        assert "sandbox_high_risk_tier_refused_pre_13_5" in exc.value.detail

    @pytest.mark.asyncio
    async def test_tenant_max_cpu_exceeded_rewraps(self, store: CheckpointStore) -> None:
        """admit_policy step 5 — cpu_cores > sandbox_per_tenant_max_cpu."""
        big_cpu = SandboxPolicy(
            cpu_cores=99.0,  # exceeds default 4.0
            cpu_time_budget_s=None,
            memory_mb=256,
            walltime_s=30.0,
            runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
            egress_allow_list=("api.example.com",),
            vault_path=None,
        )
        await _persist_checkpoint_with_policy(store, session_id="sess-cpu", policy=big_cpu)
        backend = _make_backend(store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-cpu", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_policy_revalidation_failed"
        assert "sandbox_policy_exceeds_tenant_max_cpu" in exc.value.detail

    @pytest.mark.asyncio
    async def test_tenant_max_memory_exceeded_rewraps(self, store: CheckpointStore) -> None:
        big_mem = SandboxPolicy(
            cpu_cores=0.5,
            cpu_time_budget_s=None,
            memory_mb=999_999,  # exceeds default 4096
            walltime_s=30.0,
            runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
            egress_allow_list=("api.example.com",),
            vault_path=None,
        )
        await _persist_checkpoint_with_policy(store, session_id="sess-mem", policy=big_mem)
        backend = _make_backend(store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-mem", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_policy_revalidation_failed"
        assert "sandbox_policy_exceeds_tenant_max_memory" in exc.value.detail

    @pytest.mark.asyncio
    async def test_tenant_max_walltime_exceeded_rewraps(self, store: CheckpointStore) -> None:
        big_wt = SandboxPolicy(
            cpu_cores=0.5,
            cpu_time_budget_s=None,
            memory_mb=256,
            walltime_s=99_999.0,  # exceeds default 300.0
            runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
            egress_allow_list=("api.example.com",),
            vault_path=None,
        )
        await _persist_checkpoint_with_policy(store, session_id="sess-wt", policy=big_wt)
        backend = _make_backend(store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-wt", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_policy_revalidation_failed"
        assert "sandbox_policy_exceeds_tenant_max_walltime" in exc.value.detail

    @pytest.mark.asyncio
    async def test_catalog_membership_refused_rewraps(self, store: CheckpointStore) -> None:
        """admit_policy step 6 — image not in canonical catalog AND
        not in tenant allow-list."""
        await _persist_checkpoint_with_policy(store, session_id="sess-cat")
        catalog = MagicMock()
        catalog.is_canonical.return_value = False
        catalog.is_tenant_allow_listed.return_value = False
        catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
        catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
        backend = _make_backend(store, catalog=catalog)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-cat", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_policy_revalidation_failed"
        assert "sandbox_image_digest_not_in_canonical_catalog" in exc.value.detail

    @pytest.mark.asyncio
    async def test_cosign_verification_failed_rewraps(self, store: CheckpointStore) -> None:
        """admit_policy step 7 — cosign refuse from catalog."""
        await _persist_checkpoint_with_policy(store, session_id="sess-cos")
        catalog = MagicMock()
        catalog.is_canonical.return_value = True
        catalog.is_tenant_allow_listed.return_value = False
        catalog.verify_cosign_or_refuse = AsyncMock(
            side_effect=SandboxLifecycleRefused(
                "sandbox_image_cosign_verification_failed",
                detail="bad signature",
            )
        )
        catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
        backend = _make_backend(store, catalog=catalog)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-cos", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_policy_revalidation_failed"
        assert "sandbox_image_cosign_verification_failed" in exc.value.detail

    @pytest.mark.asyncio
    async def test_sbom_check_failed_rewraps(self, store: CheckpointStore) -> None:
        """admit_policy step 8 — SBOM refuse from catalog."""
        await _persist_checkpoint_with_policy(store, session_id="sess-sbom")
        catalog = MagicMock()
        catalog.is_canonical.return_value = True
        catalog.is_tenant_allow_listed.return_value = False
        catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
        catalog.verify_sbom_policy_or_refuse = AsyncMock(
            side_effect=SandboxLifecycleRefused(
                "sandbox_image_sbom_check_failed",
                detail="GPL-3.0 detected",
            )
        )
        backend = _make_backend(store, catalog=catalog)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-sbom", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_policy_revalidation_failed"
        assert "sandbox_image_sbom_check_failed" in exc.value.detail

    @pytest.mark.asyncio
    async def test_rego_denied_rewraps(self, store: CheckpointStore) -> None:
        """admit_policy step 9 — Rego decision.allow=False."""
        await _persist_checkpoint_with_policy(store, session_id="sess-rego")
        rego_dec = MagicMock(allow=False, reasoning="bundle denies")
        backend = _make_backend(store, rego_decision=rego_dec)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-rego", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_policy_revalidation_failed"
        assert "sandbox_policy_rego_denied" in exc.value.detail


class TestOriginalReasonInDetailFormat:
    """The wake re-wrap MUST include the original Sprint-8A reason in
    ``detail`` so examiners can trace what triggered the wake-time
    refusal (per spec §2.3). The format is
    ``original=<8a_reason>: <8a_detail>``."""

    @pytest.mark.asyncio
    async def test_detail_format_carries_both_reason_and_detail(
        self, store: CheckpointStore
    ) -> None:
        await _persist_checkpoint_with_policy(store, session_id="sess-fmt")
        catalog = MagicMock()
        catalog.is_canonical.return_value = True
        catalog.is_tenant_allow_listed.return_value = False
        catalog.verify_cosign_or_refuse = AsyncMock(
            side_effect=SandboxLifecycleRefused(
                "sandbox_image_cosign_verification_failed",
                detail="signer mismatch",
            )
        )
        catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
        backend = _make_backend(store, catalog=catalog)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-fmt", actor=_ACTOR, tenant_id="t-1")
        # Detail format: "original=<8a_reason>: <8a_detail>"
        assert "original=" in exc.value.detail
        assert "sandbox_image_cosign_verification_failed" in exc.value.detail
        assert "signer mismatch" in exc.value.detail
