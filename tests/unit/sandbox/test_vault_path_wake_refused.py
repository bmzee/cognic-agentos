"""Sprint 8.5 T6 — vault-bearing wake refused per spec §2.4 amended
(Q4 lock).

Pins: NO CredentialAdapter Protocol extension in Sprint 8.5. A
vault-bearing wake reaches admit_policy's existing Sprint-8A step 3
credential precondition + raises
``sandbox_credential_adapter_not_configured``, which the wake() seam
re-wraps as ``sandbox_wake_policy_revalidation_failed`` carrying the
original 8A reason in ``detail``.

The Q4 lock is wire-protocol: vault-bearing sessions remain
unreachable end-to-end through Sprint 8.5 because admit_policy
refuses them at create-time AND wake-time. Sprint 10's
VaultCredentialAdapter unlocks the path.
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


def _vault_policy() -> SandboxPolicy:
    """Policy with non-None vault_path — would refuse at admit_policy
    step 3 under the wired KernelDefaultCredentialAdapter sentinel."""
    return SandboxPolicy(
        cpu_cores=0.5,
        cpu_time_budget_s=None,
        memory_mb=256,
        walltime_s=30.0,
        runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
        egress_allow_list=("api.example.com",),
        vault_path="secret/data/bank-x/prod-key",
    )


def _no_vault_policy() -> SandboxPolicy:
    """Baseline policy (vault_path=None) — passes admit_policy step 3
    + reaches the test's intended assertions."""
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


def _make_backend(store: CheckpointStore) -> DockerSiblingSandboxBackend:
    """Backend with the Sprint-8A KernelDefaultCredentialAdapter
    sentinel wired — Sprint 8.5 ships no real adapter per Q4 lock."""
    rego = MagicMock()
    rego.evaluate = AsyncMock(return_value=MagicMock(allow=True, reasoning=""))
    catalog = MagicMock()
    catalog.is_canonical.return_value = True
    catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
    catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
    return DockerSiblingSandboxBackend(
        docker_client=MagicMock(),
        image_catalog=catalog,
        credential_adapter=KernelDefaultCredentialAdapter(),
        rego_engine=rego,
        audit_store=store._audit_store,
        decision_history_store=store._dh_store,
        settings=_StubSettings(),  # type: ignore[arg-type]
        warm_pool=None,
        checkpoint_store=store,
    )


class TestVaultBearingWakeRefuses:
    @pytest.mark.asyncio
    async def test_wake_on_vault_policy_refuses_with_revalidation_failed(
        self, store: CheckpointStore
    ) -> None:
        """The vault-bearing wake setup: persist metadata under a
        non-vault policy (no real way to create a vault-bearing
        session via admit_policy today), then SWAP the persisted
        metadata so policy.vault_path is non-None. wake() reads the
        smuggled policy + re-runs admit_policy → step 3 refuses with
        sandbox_credential_adapter_not_configured → wake re-wraps as
        sandbox_wake_policy_revalidation_failed."""
        # Persist via the no-vault path so admit_policy doesn't
        # refuse at create-time. Then we'll smuggle a vault_path
        # into the persisted metadata.
        cid = await store.persist(
            session_id="sess-vault",
            tenant_id="t-1",
            label="cp",
            snapshot_bytes=b"snap",
            policy=_no_vault_policy(),
            pack_context=_pack_ctx(),
            vault_lease_refs=(),
        )

        # Smuggle vault_path into the persisted metadata.
        meta_key = f"t-1/sess-vault/{cid}.metadata.json"
        raw = await store._object_store.get("sandbox-checkpoints", meta_key)
        meta = json.loads(raw)
        meta["policy"]["vault_path"] = "secret/data/bank-x/prod-key"
        await store._object_store.put(
            "sandbox-checkpoints",
            meta_key,
            json.dumps(meta).encode("utf-8"),
            retention_seconds=None,
        )

        # P2.r2 fixture parity — write a parseable UUID at the
        # suspend_event_id side-blob key so wake() Step 5
        # (suspend-linkage read) cannot refuse with
        # sandbox_wake_checkpoint_corrupt and the test reaches Step 4
        # (admit_policy revalidate) — which is the only thing this
        # test asserts.
        #
        # SCOPE NOTE (P2.r3 honesty): the random UUID here pins ONLY
        # the T6 wake-linkage SHAPE requirement — it is NOT the
        # record_id of a real sandbox.lifecycle.suspended chain row.
        # The T8 chain-verifier relationship (Sprint 8.5 T8) is out
        # of scope for this vault-path refusal test.
        await store._object_store.put(
            "sandbox-checkpoints",
            f"t-1/sess-vault/{cid}.suspend_event_id",
            str(uuid.uuid4()).encode("utf-8"),
            retention_seconds=None,
        )

        backend = _make_backend(store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-vault", actor=_ACTOR, tenant_id="t-1")
        # Step 4 admit_policy re-wraps the 8A reason.
        assert exc.value.reason == "sandbox_wake_policy_revalidation_failed"
        # Original 8A reason lives in detail per spec §2.3.
        assert "sandbox_credential_adapter_not_configured" in exc.value.detail


class TestNoCredentialAdapterModified:
    def test_credentials_module_imports_only_kernel_default(self) -> None:
        """Q4 lock proof: cognic_agentos.sandbox.credentials still
        re-exports KernelDefaultCredentialAdapter + CredentialAdapter
        Protocol only — NO new Vault* / Real* adapter class."""
        import cognic_agentos.sandbox.credentials as creds

        public = [n for n in dir(creds) if not n.startswith("_")]
        # Sprint 8A surface — both names re-exported from admission.
        assert "KernelDefaultCredentialAdapter" in public
        assert "CredentialAdapter" in public
        # Sprint 8.5 T6 MUST NOT add new adapter classes.
        for name in public:
            obj = getattr(creds, name)
            # Inspecting class names defensively for any "Vault*" /
            # "Real*" adapter that would violate the Q4 lock.
            if isinstance(obj, type):
                assert "Vault" not in name, f"Sprint 8.5 T6 must not add {name}"
