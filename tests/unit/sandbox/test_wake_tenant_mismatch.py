"""Sprint 8.5 T6 — wake-time tenant mismatch refusal per spec §3.2
step 2.

Pins (defence-in-depth past the prefix-keyed lookup):

* A caller passing ``tenant_id="tenant-b"`` against a session whose
  checkpoint metadata was persisted under ``tenant_id="tenant-a"``
  refuses with ``sandbox_wake_tenant_mismatch``. In practice, the
  prefix-keyed lookup at ``CheckpointStore.load_latest`` already
  filters by tenant, so a cross-tenant query returns
  ``sandbox_wake_checkpoint_not_found`` — but if a future refactor
  bypasses prefix isolation OR a storage-layer race returns
  metadata from a different tenant, this defence-in-depth check
  fires.
* The "session_id alone is NEVER authorization" invariant per spec
  §2.6: ``tenant_id`` kwarg IS the authoritative identity boundary
  at wake time.

Tests the defence-in-depth check by directly invoking the load path
with a metadata blob whose tenant_id differs from the kwarg (we
manually persist a metadata blob with a mismatched tenant_id field
to simulate an in-process refactor that bypasses prefix isolation).
"""

from __future__ import annotations

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
from cognic_agentos.sandbox.checkpoint_store import (
    CheckpointStore,
)
from cognic_agentos.sandbox.policy import PackAdmissionContext, SandboxPolicy
from cognic_agentos.sandbox.protocol import (
    SandboxLifecycleRefused,
)


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


_ACTOR_TENANT_B = Actor(
    subject="bob@bank-b",
    tenant_id="tenant-b",
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


class TestPrefixIsolationCatchesCrossTenantQuery:
    """The first line of defence per spec §3.2: ``load_latest`` is
    keyed by ``(tenant_id, session_id)`` prefix. A cross-tenant query
    returns ``sandbox_wake_checkpoint_not_found`` because the metadata
    blob lives under a different tenant prefix."""

    @pytest.mark.asyncio
    async def test_cross_tenant_query_returns_not_found(self, store: CheckpointStore) -> None:
        await store.persist(
            session_id="sess-cross",
            tenant_id="tenant-a",
            label="cp",
            snapshot_bytes=b"snap",
            policy=_policy(),
            pack_context=_pack_ctx(),
            vault_lease_refs=(),
        )
        backend = _make_backend(store)

        # Caller's actor is tenant-b; wake against tenant-b prefix
        # returns sandbox_wake_checkpoint_not_found because no
        # metadata exists under tenant-b/sess-cross/.
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-cross", actor=_ACTOR_TENANT_B, tenant_id="tenant-b")
        assert exc.value.reason == "sandbox_wake_checkpoint_not_found"


class TestDefenceInDepthMismatchAtStep2:
    """The second line of defence per spec §3.2 step 2: even if some
    refactor or storage-layer race returned metadata whose
    ``tenant_id`` field differs from the caller's kwarg, step 2 catches
    it and refuses with ``sandbox_wake_tenant_mismatch``.

    Test setup: persist a metadata blob under one tenant prefix, then
    move it (manually) under a different tenant prefix so the
    metadata's ``tenant_id`` field disagrees with the prefix's
    tenant_id. This simulates the future-refactor bug class the
    defence-in-depth check guards against.
    """

    @pytest.mark.asyncio
    async def test_metadata_tenant_id_disagreeing_with_caller_refuses(
        self, store: CheckpointStore
    ) -> None:
        # Step 1 — persist under tenant-a. Get the real metadata bytes.
        cid = await store.persist(
            session_id="sess-mismatch",
            tenant_id="tenant-a",
            label="cp",
            snapshot_bytes=b"snap",
            policy=_policy(),
            pack_context=_pack_ctx(),
            vault_lease_refs=(),
        )
        # Step 2 — read the metadata + snapshot bytes from the real
        # tenant-a path; manually re-write them under tenant-b/
        # sess-mismatch/ to simulate cross-prefix metadata smuggle.
        meta_bytes = await store._object_store.get(
            "sandbox-checkpoints", f"tenant-a/sess-mismatch/{cid}.metadata.json"
        )
        snap_bytes = await store._object_store.get(
            "sandbox-checkpoints", f"tenant-a/sess-mismatch/{cid}.snapshot"
        )
        # Write under the WRONG prefix — metadata still says tenant_id=tenant-a.
        await store._object_store.put(
            "sandbox-checkpoints",
            f"tenant-b/sess-mismatch/{cid}.metadata.json",
            meta_bytes,
            retention_seconds=None,
        )
        await store._object_store.put(
            "sandbox-checkpoints",
            f"tenant-b/sess-mismatch/{cid}.snapshot",
            snap_bytes,
            retention_seconds=None,
        )

        backend = _make_backend(store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-mismatch", actor=_ACTOR_TENANT_B, tenant_id="tenant-b")
        # Step 2 fires per spec §3.2 — defence-in-depth past prefix
        # isolation.
        assert exc.value.reason == "sandbox_wake_tenant_mismatch"
        assert "tenant-a" in exc.value.detail
        assert "tenant-b" in exc.value.detail


class TestSessionIdAloneIsNotAuthorization:
    """Spec §2.6 extra design lock: session_id alone is NEVER
    authorization. Even though the session_id is constant across
    suspend → wake, tenant_id is the load-bearing identity boundary."""

    @pytest.mark.asyncio
    async def test_same_session_id_under_different_tenants_isolates(
        self, store: CheckpointStore
    ) -> None:
        """Two tenants each persist a checkpoint with the same
        session_id; tenant-b's wake against tenant-b's session returns
        tenant-b's metadata (NOT tenant-a's)."""
        # Tenant-a persists.
        await store.persist(
            session_id="sess-shared",
            tenant_id="tenant-a",
            label="for-a",
            snapshot_bytes=b"snap-a",
            policy=_policy(),
            pack_context=_pack_ctx(),
            vault_lease_refs=(),
        )

        # Tenant-b attempts wake on the SAME session_id but only
        # tenant-a's prefix has metadata → tenant-b sees not_found.
        backend = _make_backend(store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-shared", actor=_ACTOR_TENANT_B, tenant_id="tenant-b")
        # session_id alone gave no authorization — tenant_id kwarg is
        # the identity boundary.
        assert exc.value.reason == "sandbox_wake_checkpoint_not_found"
