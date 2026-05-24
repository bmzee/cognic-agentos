"""Sprint 8.5 T7 — KubernetesPod wake() / checkpoint() / suspend() /
destroy()-tombstone unit-level regressions.

Pins (LOAD-BEARING — drift = cross-backend parity regression):

* **Tombstone-first ordering** — wake() against a tombstoned session
  refuses ``sandbox_wake_session_tombstoned`` BEFORE load_latest fires
  (a tombstoned session whose checkpoint metadata is still on disk
  MUST surface tombstoned, NOT restorable).
* **P1.r6 fail-closed** — corrupt ``_tombstoned.json`` plus valid
  checkpoint metadata both on disk → wake() refuses NOT restore. Maps
  ``TombstoneCorruptError`` → ``sandbox_wake_session_tombstoned``
  fail-closed.
* **Closed-enum refusals across the wake pipeline** — not_found /
  corrupt-metadata / corrupt-side-blob / tenant_mismatch /
  retention_expired / policy_revalidation_failed (vault-bearing).
* **Q4 lock preserved** — vault-bearing wake re-wraps the 8A reason
  ``sandbox_credential_adapter_not_configured`` inside
  ``sandbox_wake_policy_revalidation_failed`` per spec §2.4 amended.
* **P2.r2 suspend ordering** — teardown raises BEFORE audit row →
  ZERO suspended chain rows + session._suspended remains False +
  side-blob absent.
* **P2.r3 side-blob write failure** — audit row present + side-blob
  absent → subsequent wake() refuses ``sandbox_wake_checkpoint_corrupt``
  via real persisted snapshot/metadata + missing side-blob path.
* **Session lifecycle after suspend** — exec() / checkpoint() on a
  suspended K8s session raise RuntimeError pointing at wake().
* **destroy() tombstone extension** — sessions with persisted
  checkpoints write the tombstone sentinel + the destroyed chain row
  carries ``retained_until`` + ``tombstone_object_key`` payload keys.
  Sessions without checkpoints emit the baseline destroyed event.

These are the K8s-specific mirrors of the T6 unit regressions at
``tests/unit/sandbox/test_*.py`` per the T7 ``Option A`` plan choice —
the existing T6 files import ``aiodocker`` + the ``DockerSiblingSandboxBackend``
directly, so cross-backend coverage at the unit level lands in this
new file. Cross-backend parity at the conformance level is pinned by
T9's ``test_wake_session_tombstoned_conformance.py``.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

pytest.importorskip("kubernetes_asyncio")

from cognic_agentos.core.audit import AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import (
    DecisionHistoryStore,
    _decision_history,
)
from cognic_agentos.db.adapters.local_object_store_adapter import (
    LocalObjectStoreAdapter,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox import KernelDefaultCredentialAdapter
from cognic_agentos.sandbox.backends.kubernetes_pod import (
    KubernetesPodSandboxBackend,
    KubernetesPodSession,
)
from cognic_agentos.sandbox.checkpoint_store import CheckpointStore
from cognic_agentos.sandbox.policy import PackAdmissionContext, SandboxPolicy
from cognic_agentos.sandbox.protocol import CheckpointId, SandboxLifecycleRefused

_BUCKET = "sandbox-checkpoints"


@dataclass
class _StubSettings:
    sandbox_per_tenant_max_cpu: float = 4.0
    sandbox_per_tenant_max_memory: int = 4096
    sandbox_per_tenant_max_walltime: float = 300.0
    sandbox_checkpoint_retention_s: int = 86_400
    sandbox_max_checkpoints_per_session: int = 10
    sandbox_reaper_interval_s: int = 300
    # Sprint 10 T8 added — admit_policy reads this Setting at Step 9
    # to thread input.kernel_default.max_credential_ttl_s into the
    # Rego input. T9 hardening: this stub MUST carry the field to keep
    # wake-time admit_policy revalidation green.
    sandbox_kernel_default_max_credential_ttl_s: int = 900


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


def _no_vault_policy() -> SandboxPolicy:
    return _policy()


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
async def object_store(tmp_path: Path) -> LocalObjectStoreAdapter:
    return LocalObjectStoreAdapter(root=tmp_path / "objects")


@pytest_asyncio.fixture
async def store(engine: AsyncEngine, object_store: LocalObjectStoreAdapter) -> CheckpointStore:
    return CheckpointStore(
        object_store=object_store,
        audit_store=AuditStore(engine),
        decision_history_store=DecisionHistoryStore(engine),
        settings=_StubSettings(),
    )


def _make_backend(
    store: CheckpointStore, *, settings: _StubSettings | None = None
) -> KubernetesPodSandboxBackend:
    rego = MagicMock()
    decision = MagicMock(allow=True, reasoning="")
    rego.evaluate = AsyncMock(return_value=decision)
    catalog = MagicMock()
    catalog.is_canonical.return_value = True
    catalog.is_tenant_allow_listed.return_value = False
    catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
    catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
    return KubernetesPodSandboxBackend(
        kube_api_client=MagicMock(),
        namespace="test-ns",
        image_catalog=catalog,
        credential_adapter=KernelDefaultCredentialAdapter(),
        rego_engine=rego,
        audit_store=store._audit_store,
        decision_history_store=store._dh_store,
        settings=settings or _StubSettings(),  # type: ignore[arg-type]
        warm_pool=None,
        checkpoint_store=store,
    )


def _make_session(
    backend: KubernetesPodSandboxBackend,
    *,
    session_id: str = "sess-test",
    tenant_id: str = "t-1",
    actor_subject: str = "alice@bank",
) -> KubernetesPodSession:
    return KubernetesPodSession(
        session_id=session_id,
        policy=_policy(),
        tenant_id=tenant_id,
        pack_context=_pack_ctx(),
        created_at=datetime.now(UTC),
        warm_pool_hit=False,
        _backend=backend,
        _pod_name=f"sb-{session_id}",
        _network_policy_name=f"sb-{session_id}",
        _namespace="test-ns",
        _actor_subject=actor_subject,
    )


def _patch_k8s_restore_path(
    backend: KubernetesPodSandboxBackend,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, AsyncMock]:
    """Patch every K8s-touching wake helper.

    Mirrors docker_sibling's ``_patch_docker_restore_path`` at
    test_wake_checkpoint_corrupt.py. Patching all of them makes a
    regression fail as "DID NOT RAISE" instead of failing accidentally
    on a MagicMock-shaped K8s object.
    """
    mocks: dict[str, AsyncMock] = {}
    for method_name in (
        "_create_network_policy",
        "_create_pod",
        "_wait_for_pod_ready",
        "_restore_workspace_tar",
        "_teardown_session_state",
    ):
        mock = AsyncMock()
        monkeypatch.setattr(backend, method_name, mock)
        mocks[method_name] = mock
    return mocks


# ---------------------------------------------------------------------------
# Watchpoint 1 — tombstone-first ordering load-bearing
# ---------------------------------------------------------------------------


class TestWakeRefusesWhenSessionTombstoned:
    """Wake() against a tombstoned session refuses
    ``sandbox_wake_session_tombstoned`` carrying the tombstone metadata
    in ``detail`` per spec §3.2 step 1(a)."""

    @pytest.mark.asyncio
    async def test_wake_refuses_when_session_tombstoned(self, store: CheckpointStore) -> None:
        # Pre-place a checkpoint + tombstone the session.
        await store.persist(
            session_id="sess-tomb",
            tenant_id="t-1",
            label="cp",
            snapshot_bytes=b"snap",
            policy=_policy(),
            pack_context=_pack_ctx(),
            vault_lease_refs=(),
        )
        await store.tombstone_session(
            session_id="sess-tomb",
            tenant_id="t-1",
            tombstoned_by="alice@bank",
        )
        backend = _make_backend(store)

        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-tomb", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_session_tombstoned"
        assert "tombstoned at" in exc.value.detail
        assert "alice@bank" in exc.value.detail
        assert "retained_until" in exc.value.detail

    @pytest.mark.asyncio
    async def test_tombstone_first_ordering_pin(self, store: CheckpointStore) -> None:
        """Order-of-operations: a tombstone PLUS valid metadata + valid
        side-blob → wake() returns sandbox_wake_session_tombstoned (NOT
        a green wake; NOT corrupt; NOT retention_expired).

        TM-revert intent: comment out the tombstone-first block in
        backend.wake() and this test fails.
        """
        # Persist a real checkpoint THEN tombstone — proves the
        # tombstone-first check fires even when load_latest WOULD
        # succeed.
        cid = await store.persist(
            session_id="sess-order",
            tenant_id="t-1",
            label="cp",
            snapshot_bytes=b"snap",
            policy=_policy(),
            pack_context=_pack_ctx(),
            vault_lease_refs=(),
        )
        # Also write a real side-blob so the corrupt-side-blob path
        # cannot accidentally fire instead.
        await store._object_store.put(
            _BUCKET,
            f"t-1/sess-order/{cid}.suspend_event_id",
            str(uuid.uuid4()).encode("utf-8"),
            retention_seconds=None,
        )
        await store.tombstone_session(
            session_id="sess-order",
            tenant_id="t-1",
            tombstoned_by="alice@bank",
        )
        backend = _make_backend(store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-order", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_session_tombstoned"


# ---------------------------------------------------------------------------
# Watchpoint 2 — TombstoneCorruptError → fail-closed (P1.r6)
# ---------------------------------------------------------------------------


class TestWakeRefusesOnTombstoneCorruptWithValidMetadataPresent:
    """**LOAD-BEARING P1.r6 fail-closed regression**. A malformed
    ``_tombstoned.json`` MUST surface as
    ``sandbox_wake_session_tombstoned`` even though valid checkpoint
    metadata exists on disk."""

    @pytest.mark.asyncio
    async def test_corrupt_tombstone_plus_valid_metadata_refuses_wake(
        self, store: CheckpointStore
    ) -> None:
        await store.persist(
            session_id="sess-corrupt-tomb",
            tenant_id="t-1",
            label="cp",
            snapshot_bytes=b"snap",
            policy=_policy(),
            pack_context=_pack_ctx(),
            vault_lease_refs=(),
        )
        # Overwrite the tombstone sentinel with malformed JSON.
        await store._object_store.put(
            _BUCKET,
            "t-1/sess-corrupt-tomb/_tombstoned.json",
            b"{not valid json",
            retention_seconds=None,
        )

        backend = _make_backend(store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-corrupt-tomb", actor=_ACTOR, tenant_id="t-1")
        # SAME closed-enum value as the well-formed tombstone path.
        assert exc.value.reason == "sandbox_wake_session_tombstoned"
        assert "corrupt" in exc.value.detail.lower()


# ---------------------------------------------------------------------------
# Watchpoint — checkpoint_not_found / checkpoint_corrupt paths
# ---------------------------------------------------------------------------


class TestWakeRefusesCheckpointNotFound:
    @pytest.mark.asyncio
    async def test_wake_refuses_checkpoint_not_found(self, store: CheckpointStore) -> None:
        """No metadata under the prefix → load_latest raises
        sandbox_wake_checkpoint_not_found per spec §4.1 — propagated
        AS-IS by wake()."""
        backend = _make_backend(store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-empty", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_checkpoint_not_found"


class TestWakeRefusesCheckpointCorruptOnMalformedMetadata:
    @pytest.mark.asyncio
    async def test_wake_refuses_corrupt_metadata_invalid_json(self, store: CheckpointStore) -> None:
        """Malformed metadata on disk → ValueError from
        ``from_storage_payload`` → wake re-raises as
        ``sandbox_wake_checkpoint_corrupt``."""
        cid = "f" * 32
        key = f"t-1/sess-bad/{cid}.metadata.json"
        await store._object_store.put(_BUCKET, key, b"{not valid json", retention_seconds=None)
        backend = _make_backend(store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-bad", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_checkpoint_corrupt"


# ---------------------------------------------------------------------------
# Watchpoint 4 — P2.r3 side-blob missing → corrupt at wake-time
# ---------------------------------------------------------------------------


class TestWakeRefusesCheckpointCorruptOnMissingSideBlob:
    """P2.r3 strengthening: persist real checkpoint metadata + omit
    the side-blob; wake() reaches Step 5 (suspend_event_id read) and
    refuses ``sandbox_wake_checkpoint_corrupt`` BEFORE any K8s
    resources are created."""

    @pytest.mark.asyncio
    async def test_missing_side_blob_refuses_before_k8s_resources(
        self,
        store: CheckpointStore,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await store.persist(
            session_id="sess-missing-side-blob",
            tenant_id="t-1",
            label="cp",
            snapshot_bytes=b"snap",
            policy=_policy(),
            pack_context=_pack_ctx(),
            vault_lease_refs=(),
        )
        backend = _make_backend(store)
        k8s_mocks = _patch_k8s_restore_path(backend, monkeypatch)

        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-missing-side-blob", actor=_ACTOR, tenant_id="t-1")

        assert exc.value.reason == "sandbox_wake_checkpoint_corrupt"
        detail = exc.value.detail.lower()
        assert "suspend_event_id" in detail
        assert "missing" in detail
        # No K8s resources were created on the refusal path.
        for name, mock in k8s_mocks.items():
            if name == "_teardown_session_state":
                continue  # may or may not run on the refusal path
            mock.assert_not_awaited()


class TestWakeRefusesCheckpointCorruptOnMalformedSideBlob:
    @pytest.mark.asyncio
    async def test_malformed_side_blob_refuses_before_k8s_resources(
        self,
        store: CheckpointStore,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cid = await store.persist(
            session_id="sess-bad-blob",
            tenant_id="t-1",
            label="cp",
            snapshot_bytes=b"snap",
            policy=_policy(),
            pack_context=_pack_ctx(),
            vault_lease_refs=(),
        )
        await store._object_store.put(
            _BUCKET,
            f"t-1/sess-bad-blob/{cid}.suspend_event_id",
            b"not-a-uuid",
            retention_seconds=None,
        )
        backend = _make_backend(store)
        k8s_mocks = _patch_k8s_restore_path(backend, monkeypatch)

        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-bad-blob", actor=_ACTOR, tenant_id="t-1")

        assert exc.value.reason == "sandbox_wake_checkpoint_corrupt"
        detail = exc.value.detail.lower()
        assert "suspend_event_id" in detail
        assert "not a uuid" in detail
        for name, mock in k8s_mocks.items():
            if name == "_teardown_session_state":
                continue
            mock.assert_not_awaited()


# ---------------------------------------------------------------------------
# Watchpoint 6 — tenant cross-check defence-in-depth
# ---------------------------------------------------------------------------


class TestWakeRefusesTenantMismatch:
    @pytest.mark.asyncio
    async def test_cross_tenant_query_returns_not_found(self, store: CheckpointStore) -> None:
        """First-line defence: load_latest prefix isolation returns
        not_found on cross-tenant queries."""
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
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-cross", actor=_ACTOR_TENANT_B, tenant_id="tenant-b")
        assert exc.value.reason == "sandbox_wake_checkpoint_not_found"

    @pytest.mark.asyncio
    async def test_metadata_tenant_id_disagreeing_with_caller_refuses(
        self, store: CheckpointStore
    ) -> None:
        """Second-line defence: metadata smuggled into the wrong tenant
        prefix → step 2 tenant cross-check refuses
        ``sandbox_wake_tenant_mismatch``."""
        cid = await store.persist(
            session_id="sess-mismatch",
            tenant_id="tenant-a",
            label="cp",
            snapshot_bytes=b"snap",
            policy=_policy(),
            pack_context=_pack_ctx(),
            vault_lease_refs=(),
        )
        meta_bytes = await store._object_store.get(
            _BUCKET, f"tenant-a/sess-mismatch/{cid}.metadata.json"
        )
        snap_bytes = await store._object_store.get(
            _BUCKET, f"tenant-a/sess-mismatch/{cid}.snapshot"
        )
        await store._object_store.put(
            _BUCKET,
            f"tenant-b/sess-mismatch/{cid}.metadata.json",
            meta_bytes,
            retention_seconds=None,
        )
        await store._object_store.put(
            _BUCKET,
            f"tenant-b/sess-mismatch/{cid}.snapshot",
            snap_bytes,
            retention_seconds=None,
        )

        backend = _make_backend(store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-mismatch", actor=_ACTOR_TENANT_B, tenant_id="tenant-b")
        assert exc.value.reason == "sandbox_wake_tenant_mismatch"
        assert "tenant-a" in exc.value.detail
        assert "tenant-b" in exc.value.detail


# ---------------------------------------------------------------------------
# Watchpoint — retention-expired refusal
# ---------------------------------------------------------------------------


class TestWakeRefusesRetentionExpired:
    @pytest.mark.asyncio
    async def test_retention_expired_refuses(self, store: CheckpointStore) -> None:
        """Step 3 retention-floor: a checkpoint older than the
        per-session retention window refuses
        ``sandbox_wake_checkpoint_retention_expired`` independently of
        reaper progress."""
        # Persist with a 1-second retention window so we can exercise
        # the expired path without sleeping.
        settings = _StubSettings()
        settings.sandbox_checkpoint_retention_s = 1
        store._settings = settings

        cid = await store.persist(
            session_id="sess-old",
            tenant_id="t-1",
            label="cp",
            snapshot_bytes=b"snap",
            policy=_policy(),
            pack_context=_pack_ctx(),
            vault_lease_refs=(),
        )
        # Surgically rewrite created_at to the past so the retention
        # check fires deterministically.
        import json as _json

        key = f"t-1/sess-old/{cid}.metadata.json"
        raw = await store._object_store.get(_BUCKET, key)
        meta = _json.loads(raw)
        old_dt = (datetime.now(UTC) - timedelta(seconds=10)).isoformat()
        meta["created_at"] = old_dt
        await store._object_store.put(
            _BUCKET, key, _json.dumps(meta).encode("utf-8"), retention_seconds=None
        )

        backend = _make_backend(store, settings=settings)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-old", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_checkpoint_retention_expired"


# ---------------------------------------------------------------------------
# Watchpoint 5 — Q4 lock: vault-bearing wake refused via admit_policy
# ---------------------------------------------------------------------------


class TestWakeRefusesPolicyRevalidationFailedForCredentialAdapter:
    @pytest.mark.asyncio
    async def test_vault_path_wake_refused_under_kernel_default_adapter(
        self, store: CheckpointStore
    ) -> None:
        """Q4 LOCK pin: vault-bearing wake re-wraps the 8A reason
        ``sandbox_credential_adapter_not_configured`` inside
        ``sandbox_wake_policy_revalidation_failed`` — no
        CredentialAdapter Protocol extension."""
        import json as _json

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
        raw = await store._object_store.get(_BUCKET, meta_key)
        meta = _json.loads(raw)
        meta["policy"]["vault_path"] = "secret/data/bank-x/prod-key"
        await store._object_store.put(
            _BUCKET, meta_key, _json.dumps(meta).encode("utf-8"), retention_seconds=None
        )
        # Side-blob shape parity per T6 fixture — so Step 5 doesn't
        # accidentally fire before Step 4.
        await store._object_store.put(
            _BUCKET,
            f"t-1/sess-vault/{cid}.suspend_event_id",
            str(uuid.uuid4()).encode("utf-8"),
            retention_seconds=None,
        )

        backend = _make_backend(store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-vault", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_policy_revalidation_failed"
        assert "sandbox_credential_adapter_not_configured" in exc.value.detail


# ---------------------------------------------------------------------------
# Watchpoint 3 — P2.r2 suspend reorder: teardown before audit row
# ---------------------------------------------------------------------------


async def _read_suspended_chain_rows(engine: AsyncEngine) -> list[dict[str, Any]]:
    async with engine.connect() as conn:
        result = await conn.execute(
            select(_decision_history).where(
                _decision_history.c.event_type == "sandbox.lifecycle.suspended"
            )
        )
        return [dict(r._mapping) for r in result.fetchall()]


class TestSuspendOrdersTeardownBeforeAuditRow:
    """**P2.r2 ordering pin** — teardown raises BEFORE audit emit ⇒
    NO suspended chain row + session._suspended remains False +
    side-blob absent. Mirrors T6's
    ``test_suspend_partial_failure_semantics::test_audit_row_not_emitted_when_teardown_fails``
    against the K8s backend.

    TM-revert: a regression that re-orders audit emit ahead of
    teardown would find 1 suspended row instead of 0."""

    @pytest.mark.asyncio
    async def test_audit_row_not_emitted_when_teardown_fails(
        self,
        store: CheckpointStore,
        object_store: LocalObjectStoreAdapter,
        engine: AsyncEngine,
    ) -> None:
        backend = _make_backend(store)
        session = _make_session(backend, session_id="sess-suspend", tenant_id="tenant-a")

        fake_cid = CheckpointId("a" * 32)
        backend._do_checkpoint = AsyncMock(return_value=fake_cid)  # type: ignore[method-assign]
        backend._teardown_session_state = AsyncMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("teardown blew up")
        )
        write_blob_spy = AsyncMock()
        backend._write_suspend_event_id = write_blob_spy  # type: ignore[method-assign]

        with pytest.raises(RuntimeError, match="teardown blew up"):
            await session.suspend()

        rows = await _read_suspended_chain_rows(engine)
        assert rows == [], (
            f"P2.r2 violation: teardown failed but suspended audit row was "
            f"still emitted — chain over-states reality. rows={rows}"
        )
        assert session._suspended is False
        write_blob_spy.assert_not_awaited()

        with pytest.raises(FileNotFoundError):
            await object_store.get(_BUCKET, f"tenant-a/sess-suspend/{fake_cid}.suspend_event_id")


class TestSuspendWritesSideBlobAfterAuditRow:
    """**P2.r3 strengthening** — side-blob write failure leaves audit
    row + side-blob absent; subsequent wake refuses
    ``sandbox_wake_checkpoint_corrupt`` with ``missing
    suspend_event_id side-blob`` in detail. Real persisted metadata
    via ``CheckpointStore.persist()`` (NOT a mock that returns a
    checkpoint_id without bytes)."""

    @pytest.mark.asyncio
    async def test_side_blob_write_failure_subsequent_wake_corrupt(
        self,
        store: CheckpointStore,
        object_store: LocalObjectStoreAdapter,
        engine: AsyncEngine,
    ) -> None:
        backend = _make_backend(store)
        session = _make_session(backend, session_id="sess-blob-fail", tenant_id="tenant-a")

        async def _persist_real_checkpoint(
            session: KubernetesPodSession, label: str
        ) -> CheckpointId:
            return await store.persist(
                session_id=session.session_id,
                tenant_id=session.tenant_id,
                label=label,
                snapshot_bytes=b"snap",
                policy=session.policy,
                pack_context=session.pack_context,
                vault_lease_refs=(),
            )

        backend._do_checkpoint = _persist_real_checkpoint  # type: ignore[method-assign]
        teardown_spy = AsyncMock()
        backend._teardown_session_state = teardown_spy  # type: ignore[method-assign]
        backend._write_suspend_event_id = AsyncMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("side-blob write blew up")
        )

        with pytest.raises(RuntimeError, match="side-blob write blew up"):
            await session.suspend()

        teardown_spy.assert_awaited_once()
        rows = await _read_suspended_chain_rows(engine)
        assert len(rows) == 1, f"expected exactly one suspended chain row; got {len(rows)}: {rows}"

        # Subsequent wake reaches Step 5 + refuses corrupt-side-blob.
        actor = Actor(
            subject="alice@bank",
            tenant_id=session.tenant_id,
            scopes=frozenset(),
            actor_type="human",
        )
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake(
                session.session_id,
                actor=actor,
                tenant_id=session.tenant_id,
            )
        assert exc.value.reason == "sandbox_wake_checkpoint_corrupt"
        assert "missing suspend_event_id side-blob" in exc.value.detail
        assert session._suspended is False


# ---------------------------------------------------------------------------
# Session lifecycle after suspend
# ---------------------------------------------------------------------------


class TestSessionLifecycleAfterSuspend:
    """Mirror of T6's ``test_session_lifecycle_after_suspend.py`` —
    exec() / checkpoint() on a suspended K8s session raise
    RuntimeError pointing at wake()."""

    def _suspended_session(self) -> KubernetesPodSession:
        return KubernetesPodSession(
            session_id="suspended-sess",
            policy=_policy(),
            tenant_id="t-1",
            pack_context=_pack_ctx(),
            created_at=datetime.now(UTC),
            warm_pool_hit=False,
            _backend=MagicMock(),
            _pod_name="sb-suspended-sess",
            _network_policy_name="sb-suspended-sess",
            _namespace="test-ns",
            _actor_subject="actor-1",
            _suspended=True,
        )

    @pytest.mark.asyncio
    async def test_exec_on_suspended_session_raises_with_wake_pointer(self) -> None:
        session = self._suspended_session()
        with pytest.raises(RuntimeError) as exc:
            await session.exec(["echo", "hello"])
        assert "wake" in str(exc.value).lower()
        assert session.session_id in str(exc.value)

    @pytest.mark.asyncio
    async def test_checkpoint_on_suspended_session_raises_with_wake_pointer(
        self, store: CheckpointStore
    ) -> None:
        session = self._suspended_session()
        real_backend = _make_backend(store)
        session._backend = real_backend
        with pytest.raises(RuntimeError) as exc:
            await session.checkpoint("test-label")
        assert "wake" in str(exc.value).lower()

    @pytest.mark.asyncio
    async def test_double_suspend_raises(self, store: CheckpointStore) -> None:
        session = self._suspended_session()
        real_backend = _make_backend(store)
        session._backend = real_backend
        with pytest.raises(RuntimeError):
            await session.suspend()


# ---------------------------------------------------------------------------
# destroy() — tombstone extension
# ---------------------------------------------------------------------------


async def _read_all_chain_rows(engine: AsyncEngine) -> list[dict[str, Any]]:
    async with engine.connect() as conn:
        result = await conn.execute(
            select(_decision_history).order_by(_decision_history.c.sequence.asc())
        )
        return [dict(r._mapping) for r in result.fetchall()]


class TestDestroyTombstonesSessionWithPersistedCheckpoints:
    """Sessions with persisted checkpoints write the tombstone sentinel
    + the destroyed chain row carries ``retained_until`` +
    ``tombstone_object_key`` payload keys. Mirrors T6's
    ``test_destroy_tombstones_session``."""

    @pytest.mark.asyncio
    async def test_destroy_with_checkpoint_writes_tombstone_and_extends_payload(
        self,
        store: CheckpointStore,
        engine: AsyncEngine,
    ) -> None:
        await store.persist(
            session_id="sess-tombstone",
            tenant_id="tenant-a",
            label="test-cp",
            snapshot_bytes=b"snap",
            policy=_policy(),
            pack_context=_pack_ctx(),
            vault_lease_refs=(),
        )

        backend = _make_backend(store)
        backend._teardown_session_state = AsyncMock()  # type: ignore[method-assign]
        session = _make_session(
            backend,
            session_id="sess-tombstone",
            tenant_id="tenant-a",
            actor_subject="alice@bank",
        )

        await backend.destroy(session)

        tombstone_key = "tenant-a/sess-tombstone/_tombstoned.json"
        tombstone_bytes = await store._object_store.get(_BUCKET, tombstone_key)
        assert tombstone_bytes

        rows = await _read_all_chain_rows(engine)
        destroyed_rows = [r for r in rows if r["event_type"] == "sandbox.lifecycle.destroyed"]
        assert len(destroyed_rows) == 1
        payload = destroyed_rows[0]["payload"]
        assert "duration_s" in payload
        assert "retained_until" in payload
        retained = datetime.fromisoformat(payload["retained_until"])
        assert retained.tzinfo is not None
        assert payload["tombstone_object_key"] == tombstone_key


class TestDestroySkipsTombstoneWhenNoCheckpoints:
    """Sessions with NO checkpoints emit the Sprint-8A baseline
    destroyed event WITHOUT the new payload keys."""

    @pytest.mark.asyncio
    async def test_no_checkpoints_means_no_tombstone_keys(
        self,
        store: CheckpointStore,
        engine: AsyncEngine,
    ) -> None:
        backend = _make_backend(store)
        backend._teardown_session_state = AsyncMock()  # type: ignore[method-assign]
        session = _make_session(backend)

        await backend.destroy(session)

        rows = await _read_all_chain_rows(engine)
        destroyed_rows = [r for r in rows if r["event_type"] == "sandbox.lifecycle.destroyed"]
        assert len(destroyed_rows) == 1
        payload = destroyed_rows[0]["payload"]
        assert "duration_s" in payload
        assert "retained_until" not in payload
        assert "tombstone_object_key" not in payload
        assert session._destroyed is True

        # No tombstone sentinel either.
        keys_found: list[str] = []
        async for key in store._object_store.list_prefix(_BUCKET, "t-1/sess-test/"):
            keys_found.append(key)
        assert keys_found == []


__all__: list[str] = []
