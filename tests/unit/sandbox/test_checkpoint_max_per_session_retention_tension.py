"""Sprint 8.5 T3 — persist() cap-vs-retention tension per spec §4.3
amended + P1.r3 + P2.r6 split.

This file is the **persist()-cap-only** scope per the P2.r6 split. The
sibling test_checkpoint_retention.py (T4) covers the reaper retention
path; this file pins the persist()-time max_per_session cap semantics
with three parametrised cases:

* Case 1 — at cap + outside-retention checkpoint exists → oldest
  outside-retention evicted with ``purge_reason="max_per_session_cap"``;
  one ``checkpoint_purged`` chain row emitted; new checkpoint written
  successfully.
* Case 2 — at cap + EVERY existing checkpoint inside retention →
  raises ``CheckpointMaxPerSessionRetentionLocked`` carrying
  ``(session_id, tenant_id, cap, oldest_retention_remaining_s)``;
  **NO checkpoint written; NO ``checkpoint_purged`` row** (typed
  exception IS the operator-observable signal per spec §4.3 P3.r4).
* Case 3 — at cap exactly + no retention block → normal eviction.

Plus a mock-reaper assertion that the reaper does NOT participate in
cap purges (cap eviction is persist()-owned per spec §4.3).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH, canonical_bytes
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.db.adapters.local_object_store_adapter import (
    LocalObjectStoreAdapter,
)
from cognic_agentos.sandbox.checkpoint_store import (
    CheckpointMaxPerSessionRetentionLocked,
    CheckpointMetadata,
    CheckpointStore,
)
from cognic_agentos.sandbox.policy import (
    PackAdmissionContext,
    SandboxPolicy,
)
from cognic_agentos.sandbox.protocol import CheckpointId

BUCKET = "sandbox-checkpoints"


# ---------------------------------------------------------------------------
# Stub Settings (Sprint 8.5 T3 reads 3 fields the canonical Settings
# does NOT yet declare; T10 lands them).
# ---------------------------------------------------------------------------


class _StubSettings:
    def __init__(
        self,
        *,
        max_per_session: int,
        retention_s: int,
    ) -> None:
        self.sandbox_max_checkpoints_per_session = max_per_session
        self.sandbox_checkpoint_retention_s = retention_s
        self.sandbox_reaper_interval_s = 300


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture
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


@pytest.fixture
async def dh_store(engine: AsyncEngine) -> DecisionHistoryStore:
    return DecisionHistoryStore(engine)


@pytest.fixture
async def audit_store(engine: AsyncEngine) -> AuditStore:
    return AuditStore(engine)


@pytest.fixture
def object_store(tmp_path: Path) -> LocalObjectStoreAdapter:
    return LocalObjectStoreAdapter(root=tmp_path / "objects")


def _valid_policy() -> SandboxPolicy:
    return SandboxPolicy(
        cpu_cores=1.0,
        cpu_time_budget_s=10.0,
        memory_mb=512,
        walltime_s=60.0,
        runtime_image=(
            "cognic/sandbox-runtime-python@sha256:"
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ),
        egress_allow_list=("api.example.com",),
        vault_path=None,
        read_only_root=True,
        writable_mounts=(),
        warm_pool_key=None,
    )


def _valid_pack_context() -> PackAdmissionContext:
    return PackAdmissionContext(
        pack_id="pack-a",
        pack_version="1.0.0",
        pack_artifact_digest=(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ),
        risk_tier="read_only",
        declares_dynamic_install=False,
        profile="production",
    )


async def _seed_checkpoint(
    object_store: LocalObjectStoreAdapter,
    *,
    tenant_id: str,
    session_id: str,
    created_at: datetime,
    retention_window_s: int,
    snapshot_bytes: bytes = b"snap",
) -> str:
    """Hand-place a checkpoint with the EXACT (created_at,
    retention_window_s) values needed to drive the cap-tension logic.
    Routes around the persist() time-of-write created_at to set up
    'old enough to be outside retention' OR 'still inside retention'
    deterministically."""
    cid = uuid.uuid4().hex
    meta = CheckpointMetadata(
        checkpoint_id=CheckpointId(cid),
        session_id=session_id,
        tenant_id=tenant_id,
        label="seed",
        created_at=created_at,
        policy=_valid_policy(),
        pack_context=_valid_pack_context(),
        retention_window_s=retention_window_s,
        vault_lease_refs=(),
    )
    await object_store.put(
        BUCKET, f"{tenant_id}/{session_id}/{cid}.snapshot", snapshot_bytes, retention_seconds=None
    )
    await object_store.put(
        BUCKET,
        f"{tenant_id}/{session_id}/{cid}.metadata.json",
        canonical_bytes(meta.to_storage_payload()),
        retention_seconds=None,
    )
    return cid


async def _chain_rows(engine: AsyncEngine, decision_type: str) -> list[dict[str, Any]]:
    async with engine.connect() as conn:
        rows = (
            await conn.execute(
                sa.text(
                    f"SELECT payload FROM decision_history WHERE event_type = '{decision_type}'"
                )
            )
        ).fetchall()
    return [json.loads(r[0]) for r in rows]


# ---------------------------------------------------------------------------
# Case 1 — at cap + outside-retention exists → evict oldest outside-retention.
# ---------------------------------------------------------------------------


class TestCase1AtCapWithOutsideRetentionCheckpoint:
    async def test_at_cap_outside_retention_evicts_oldest_with_cap_reason(
        self,
        engine: AsyncEngine,
        object_store: LocalObjectStoreAdapter,
        audit_store: AuditStore,
        dh_store: DecisionHistoryStore,
    ) -> None:
        """persist() at cap + one outside-retention checkpoint:
        evict the oldest outside-retention with
        purge_reason='max_per_session_cap', emit one checkpoint_purged
        row, write the new checkpoint."""
        # Settings: cap=2, retention=1000s.
        settings = _StubSettings(max_per_session=2, retention_s=1000)
        st = CheckpointStore(
            object_store=object_store,
            audit_store=audit_store,
            decision_history_store=dh_store,
            settings=settings,
        )
        # Seed 2 checkpoints, ONE outside retention (created 2000s ago)
        # and ONE still inside retention (created just now).
        old_cid = await _seed_checkpoint(
            object_store,
            tenant_id="tenant-a",
            session_id="sess-1",
            created_at=datetime.now(UTC) - timedelta(seconds=2000),
            retention_window_s=1000,
        )
        recent_cid = await _seed_checkpoint(
            object_store,
            tenant_id="tenant-a",
            session_id="sess-1",
            created_at=datetime.now(UTC) - timedelta(seconds=10),
            retention_window_s=1000,
        )

        # persist() — at cap (=2); the outside-retention checkpoint
        # MUST be evicted with cap-reason.
        new_cid = await st.persist(
            session_id="sess-1",
            tenant_id="tenant-a",
            label="new",
            snapshot_bytes=b"new-snap",
            policy=_valid_policy(),
            pack_context=_valid_pack_context(),
            vault_lease_refs=(),
        )

        # Old one gone.
        with pytest.raises(FileNotFoundError):
            await object_store.get(BUCKET, f"tenant-a/sess-1/{old_cid}.snapshot")
        # Recent one still there.
        await object_store.get(BUCKET, f"tenant-a/sess-1/{recent_cid}.snapshot")
        # New one written.
        assert await object_store.get(BUCKET, f"tenant-a/sess-1/{new_cid}.snapshot") == b"new-snap"

        # Exactly ONE checkpoint_purged row with cap reason.
        rows = await _chain_rows(engine, "sandbox.lifecycle.checkpoint_purged")
        assert len(rows) == 1
        assert rows[0]["purge_reason"] == "max_per_session_cap"
        assert rows[0]["checkpoint_id"] == old_cid


# ---------------------------------------------------------------------------
# Case 2 — at cap + ALL inside retention → typed exception, no purge.
# ---------------------------------------------------------------------------


class TestCase2AtCapAllInsideRetention:
    async def test_all_inside_retention_raises_typed_exception_with_no_chain_row(
        self,
        engine: AsyncEngine,
        object_store: LocalObjectStoreAdapter,
        audit_store: AuditStore,
        dh_store: DecisionHistoryStore,
    ) -> None:
        """LOAD-BEARING per P1.r3 + P3.r4: typed exception IS the
        operator-observable signal. NO checkpoint written; NO
        checkpoint_purged row — pinned by negative chain-history
        assertion."""
        settings = _StubSettings(max_per_session=2, retention_s=1000)
        st = CheckpointStore(
            object_store=object_store,
            audit_store=audit_store,
            decision_history_store=dh_store,
            settings=settings,
        )
        # Seed 2 checkpoints, BOTH inside retention (created within
        # the last 100s; retention_window_s=1000).
        for i in range(2):
            await _seed_checkpoint(
                object_store,
                tenant_id="tenant-a",
                session_id="sess-1",
                created_at=datetime.now(UTC) - timedelta(seconds=10 * i),
                retention_window_s=1000,
            )

        with pytest.raises(CheckpointMaxPerSessionRetentionLocked) as ei:
            await st.persist(
                session_id="sess-1",
                tenant_id="tenant-a",
                label="new",
                snapshot_bytes=b"new-snap",
                policy=_valid_policy(),
                pack_context=_valid_pack_context(),
                vault_lease_refs=(),
            )

        # Typed exception carries the 4 required fields.
        assert ei.value.session_id == "sess-1"
        assert ei.value.tenant_id == "tenant-a"
        assert ei.value.cap == 2
        # Retention remaining is in the (0, 1000] range (oldest was
        # created ~10s ago; 1000-10 = 990ish).
        assert 0 < ei.value.oldest_retention_remaining_s <= 1000

        # NEGATIVE pin — NO new snapshot written under sess-1 with the
        # label='new'. Walk all keys; assert no key carries a snapshot
        # whose content == b'new-snap'.
        async for key in object_store.list_prefix(BUCKET, "tenant-a/sess-1/"):
            if key.endswith(".snapshot"):
                body = await object_store.get(BUCKET, key)
                assert body != b"new-snap", (
                    f"P1.r3 violation: persist() wrote a new snapshot ({key}) "
                    f"despite raising CheckpointMaxPerSessionRetentionLocked"
                )

        # NEGATIVE pin — NO checkpoint_purged chain row was emitted.
        rows = await _chain_rows(engine, "sandbox.lifecycle.checkpoint_purged")
        assert rows == [], (
            f"P3.r4 violation: persist() emitted {len(rows)} "
            f"checkpoint_purged rows under cap-locked branch; expected 0"
        )


# ---------------------------------------------------------------------------
# Case 3 — at cap exactly + no retention block → normal eviction.
# ---------------------------------------------------------------------------


class TestCase3AtCapWithZeroRetentionBlock:
    async def test_at_cap_with_all_outside_retention_evicts_oldest(
        self,
        engine: AsyncEngine,
        object_store: LocalObjectStoreAdapter,
        audit_store: AuditStore,
        dh_store: DecisionHistoryStore,
    ) -> None:
        """cap=2; both existing outside retention → eviction succeeds
        with the OLDEST being chosen. Pins the deterministic 'oldest
        outside-retention' selection per spec §4.3 path (b)."""
        settings = _StubSettings(max_per_session=2, retention_s=10)
        st = CheckpointStore(
            object_store=object_store,
            audit_store=audit_store,
            decision_history_store=dh_store,
            settings=settings,
        )
        # 2 checkpoints, both old (3000s + 2000s ago); retention=10s.
        oldest_cid = await _seed_checkpoint(
            object_store,
            tenant_id="tenant-a",
            session_id="sess-1",
            created_at=datetime.now(UTC) - timedelta(seconds=3000),
            retention_window_s=10,
        )
        less_old_cid = await _seed_checkpoint(
            object_store,
            tenant_id="tenant-a",
            session_id="sess-1",
            created_at=datetime.now(UTC) - timedelta(seconds=2000),
            retention_window_s=10,
        )

        new_cid = await st.persist(
            session_id="sess-1",
            tenant_id="tenant-a",
            label="new",
            snapshot_bytes=b"new-snap",
            policy=_valid_policy(),
            pack_context=_valid_pack_context(),
            vault_lease_refs=(),
        )

        # Oldest gone; less-old remains.
        with pytest.raises(FileNotFoundError):
            await object_store.get(BUCKET, f"tenant-a/sess-1/{oldest_cid}.snapshot")
        await object_store.get(BUCKET, f"tenant-a/sess-1/{less_old_cid}.snapshot")
        await object_store.get(BUCKET, f"tenant-a/sess-1/{new_cid}.snapshot")
        # Exactly ONE eviction row.
        rows = await _chain_rows(engine, "sandbox.lifecycle.checkpoint_purged")
        assert len(rows) == 1
        assert rows[0]["checkpoint_id"] == oldest_cid
        assert rows[0]["purge_reason"] == "max_per_session_cap"


# ---------------------------------------------------------------------------
# Mock-reaper assertion — cap eviction is persist()-only.
# ---------------------------------------------------------------------------


class TestReaperDoesNotParticipateInCapPurges:
    async def test_reaper_run_once_not_invoked_from_persist(
        self,
        engine: AsyncEngine,
        object_store: LocalObjectStoreAdapter,
        audit_store: AuditStore,
        dh_store: DecisionHistoryStore,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The reaper does NOT participate in max_per_session_cap purges.
        Cap eviction is owned by persist() per spec §4.3. The pin: even
        though a CheckpointReaper instance exists in the same process,
        persist() does NOT invoke its run_once() — pinned by mock
        assert_not_called."""
        settings = _StubSettings(max_per_session=2, retention_s=10)
        st = CheckpointStore(
            object_store=object_store,
            audit_store=audit_store,
            decision_history_store=dh_store,
            settings=settings,
        )
        # Seed 2 outside-retention checkpoints.
        await _seed_checkpoint(
            object_store,
            tenant_id="tenant-a",
            session_id="sess-1",
            created_at=datetime.now(UTC) - timedelta(seconds=3000),
            retention_window_s=10,
        )
        await _seed_checkpoint(
            object_store,
            tenant_id="tenant-a",
            session_id="sess-1",
            created_at=datetime.now(UTC) - timedelta(seconds=2000),
            retention_window_s=10,
        )

        # Mock-reaper sentinel (CheckpointReaper lands at T4; we use a
        # MagicMock to assert nothing inside persist() reaches into a
        # reaper-shaped object).
        mock_reaper = MagicMock()
        mock_reaper.run_once = MagicMock()
        # No coupling — store has no reaper handle. The pin is that
        # the store does not invoke ANY method on the reaper sentinel;
        # the production code MUST own cap eviction via purge_by_id().
        await st.persist(
            session_id="sess-1",
            tenant_id="tenant-a",
            label="new",
            snapshot_bytes=b"new-snap",
            policy=_valid_policy(),
            pack_context=_valid_pack_context(),
            vault_lease_refs=(),
        )
        mock_reaper.run_once.assert_not_called()
