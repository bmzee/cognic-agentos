"""Sprint 8.5 T6 — wake() against tombstoned session per spec §3.2
step 1(a) + P1.r4 tombstone redesign + P1.r6 fail-closed correction.

Pins (LOAD-BEARING — drift = wake-pipeline ordering regression):

* wake() against a tombstoned session refuses with
  ``SandboxLifecycleRefused("sandbox_wake_session_tombstoned")``
  carrying the tombstone metadata (tombstoned_at / tombstoned_by /
  retained_until) in ``detail``.
* **P1.r6 fail-closed regression** (LOAD-BEARING): malformed
  ``_tombstoned.json`` AND valid checkpoint metadata both on disk →
  wake() refuses NOT restore. Proves the
  ``TombstoneCorruptError`` → ``sandbox_wake_session_tombstoned``
  fail-closed mapping is wired correctly. Without this, a corrupt
  tombstone would let wake() proceed to load_latest() and restore a
  session the operator INTENDED to destroy.
* Order-of-operations pin: tombstone check fires BEFORE not_found
  check AND BEFORE corrupt-metadata check. A tombstoned session with
  no metadata on disk still surfaces as tombstoned (NOT not_found);
  a tombstoned session with corrupt metadata still surfaces as
  tombstoned (NOT corrupt).
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


def _make_backend(store: CheckpointStore) -> DockerSiblingSandboxBackend:
    rego = MagicMock()
    decision = MagicMock(allow=True, reasoning="")
    rego.evaluate = AsyncMock(return_value=decision)
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


class TestWakeRefusesOnWellFormedTombstone:
    @pytest.mark.asyncio
    async def test_wake_against_tombstoned_session_refuses(self, store: CheckpointStore) -> None:
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
            session_id="sess-tomb", tenant_id="t-1", tombstoned_by="alice@bank"
        )
        backend = _make_backend(store)

        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-tomb", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_session_tombstoned"
        # Tombstone metadata in detail per spec §3.2 step 1(a).
        assert "tombstoned at" in exc.value.detail
        assert "alice@bank" in exc.value.detail
        assert "retained_until" in exc.value.detail


class TestP1R6FailClosedCorruptTombstone:
    """**LOAD-BEARING P1.r6 fail-closed regression** per spec §3.2 step
    1(a-prime). A malformed ``_tombstoned.json`` MUST surface as
    ``sandbox_wake_session_tombstoned`` — operator destroy() intent
    survives tampering.

    The test pre-places BOTH a corrupt tombstone AND a valid checkpoint
    metadata blob, then asserts wake() refuses NOT restores. If
    load_tombstone()'s ``TombstoneCorruptError`` were silently
    swallowed (the fail-OPEN bug class), wake() would proceed to
    load_latest() and successfully restore the session.
    """

    @pytest.mark.asyncio
    async def test_corrupt_tombstone_plus_valid_metadata_refuses_wake(
        self, store: CheckpointStore, tmp_path: Path
    ) -> None:
        # Pre-place a valid checkpoint (real metadata + snapshot).
        await store.persist(
            session_id="sess-corrupt-tomb",
            tenant_id="t-1",
            label="cp",
            snapshot_bytes=b"snap",
            policy=_policy(),
            pack_context=_pack_ctx(),
            vault_lease_refs=(),
        )
        # Now overwrite the tombstone sentinel with malformed JSON.
        # load_tombstone() raises TombstoneCorruptError; wake() MUST
        # map to sandbox_wake_session_tombstoned (NOT proceed to
        # load_latest()).
        await store._object_store.put(
            "sandbox-checkpoints",
            "t-1/sess-corrupt-tomb/_tombstoned.json",
            b"{not valid json",
            retention_seconds=None,
        )

        backend = _make_backend(store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-corrupt-tomb", actor=_ACTOR, tenant_id="t-1")
        # SAME closed-enum value as the well-formed tombstone path per
        # P1.r6 — operator intent survives degradation.
        assert exc.value.reason == "sandbox_wake_session_tombstoned"
        # The corrupt-exception message lives in `detail` for
        # incident-response traceability.
        assert "corrupt" in exc.value.detail.lower()

    @pytest.mark.asyncio
    async def test_tombstone_with_missing_required_keys_refuses_wake(
        self, store: CheckpointStore
    ) -> None:
        """TombstoneRecord requires {tombstoned_at, tombstoned_by,
        retained_until}; a sentinel missing any of these raises
        TombstoneCorruptError → maps to sandbox_wake_session_tombstoned."""
        await store.persist(
            session_id="sess-missing",
            tenant_id="t-1",
            label="cp",
            snapshot_bytes=b"snap",
            policy=_policy(),
            pack_context=_pack_ctx(),
            vault_lease_refs=(),
        )
        # Sentinel that's valid JSON but missing required keys.
        await store._object_store.put(
            "sandbox-checkpoints",
            "t-1/sess-missing/_tombstoned.json",
            b'{"tombstoned_at": "incomplete"}',
            retention_seconds=None,
        )
        backend = _make_backend(store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-missing", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_session_tombstoned"


class TestTombstoneCheckRunsBeforeNotFoundCheck:
    """Order-of-operations pin per spec §3.2 step ordering: tombstone
    check fires BEFORE the load_latest() not-found check. A tombstoned
    session with NO surviving metadata MUST surface as tombstoned (NOT
    sandbox_wake_checkpoint_not_found)."""

    @pytest.mark.asyncio
    async def test_tombstone_without_metadata_surfaces_as_tombstoned(
        self, store: CheckpointStore
    ) -> None:
        # Write tombstone ONLY — no checkpoint metadata.
        await store.tombstone_session(
            session_id="sess-only-tomb", tenant_id="t-1", tombstoned_by="bob"
        )
        backend = _make_backend(store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-only-tomb", actor=_ACTOR, tenant_id="t-1")
        # MUST be tombstoned (NOT not_found) per spec §3.2 ordering.
        assert exc.value.reason == "sandbox_wake_session_tombstoned"


class TestTombstoneFirstOrderingPin:
    """Explicit order-of-operations pin: tombstone check is THE FIRST
    step in wake(). TM-revert proof — swap step 1 to load_latest first
    and this test fails. Keep this regression aligned with spec §3.2
    step ordering."""

    @pytest.mark.asyncio
    async def test_tombstone_first_ordering(self, store: CheckpointStore) -> None:
        """Order-of-operations: a tombstone + valid metadata + retention
        not yet expired → wake() returns sandbox_wake_session_tombstoned
        (NOT a green wake; NOT corrupt; NOT retention_expired).

        TM-revert intent: comment out the tombstone-first block in
        backend.wake() and this test fails — wake() would proceed to
        load_latest + admit_policy + create.
        """
        await store.persist(
            session_id="sess-order",
            tenant_id="t-1",
            label="cp",
            snapshot_bytes=b"snap",
            policy=_policy(),
            pack_context=_pack_ctx(),
            vault_lease_refs=(),
        )
        await store.tombstone_session(
            session_id="sess-order", tenant_id="t-1", tombstoned_by="alice"
        )
        backend = _make_backend(store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-order", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_session_tombstoned"
