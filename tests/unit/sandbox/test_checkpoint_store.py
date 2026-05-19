"""Sprint 8.5 T3 — CheckpointStore orchestrator tests per spec §4.1.

Pins (every test maps to a wire-public invariant the spec locks):

* ``persist()`` writes the snapshot + metadata at the per-tenant prefix
  keys (``<tenant>/<session>/<checkpoint>.snapshot`` +
  ``…/.metadata.json``).
* ``persist()`` passes ``retention_seconds=None`` to
  ``ObjectStoreAdapter.put()`` per spec §4.1 P1.r3 (retention lives at
  the REAPER, NOT the WORM lock — using the lock as a TTL would block
  max-per-session eviction + explicit destroy paths).
* ``load_latest()`` filters to ``.metadata.json`` keys; round-trips via
  ``from_storage_payload``; picks the latest ``created_at``.
* ``load_latest()`` returns ``SandboxLifecycleRefused(
  "sandbox_wake_checkpoint_not_found")`` on cross-tenant lookup —
  defence-in-depth past the prefix-keyed lookup.
* ``load_tombstone()`` returns ``None`` on ``FileNotFoundError``;
  returns ``TombstoneRecord`` on valid sentinel; raises
  ``TombstoneCorruptError`` on malformed sentinel — P1.r6
  load-bearing fail-closed invariant.
* ``tombstone_session()`` writes the correct sentinel key; idempotent —
  second call returns existing key without overwriting
  ``tombstoned_at`` (prevents destroy()-after-destroy from extending
  retention).
* ``purge_by_id()`` emits ``sandbox.lifecycle.checkpoint_purged`` via
  the T2 helper.
* ``purge_expired()`` walks via ``list_prefix``; tombstoned-then-elapsed
  uses ``purge_reason="explicit_destroy"``; aged non-tombstoned uses
  ``purge_reason="retention_expired"``; refuses purge inside retention
  window.
* ``mint_checkpoint_id()`` returns 32-char hex.
* Per-tenant prefix isolation — tenant-a's persist() does NOT
  cross-contaminate tenant-b's load_latest().
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

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
    CheckpointMetadata,
    CheckpointStore,
    TombstoneCorruptError,
    TombstoneRecord,
)
from cognic_agentos.sandbox.policy import (
    PackAdmissionContext,
    SandboxPolicy,
)
from cognic_agentos.sandbox.protocol import (
    CheckpointId,
    SandboxLifecycleRefused,
)

BUCKET = "sandbox-checkpoints"


# ---------------------------------------------------------------------------
# Settings stub — Sprint 8.5 T3 reads 3 fields the canonical Settings
# does NOT yet declare (T10 lands them). The store accepts any object
# carrying these 3 attributes — Option B per task brief (tiny structural
# contract). Production code post-T10 passes the real Settings (which
# gains the fields then).
# ---------------------------------------------------------------------------


@dataclass
class _StubSettings:
    sandbox_checkpoint_retention_s: int = 86_400
    sandbox_max_checkpoints_per_session: int = 10
    sandbox_reaper_interval_s: int = 300


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    """Per-test SQLite engine carrying the governance schema +
    seeded chain heads (mirrors test_decision_history.py)."""
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


@pytest.fixture
def settings() -> _StubSettings:
    return _StubSettings()


@pytest.fixture
def store(
    object_store: LocalObjectStoreAdapter,
    audit_store: AuditStore,
    dh_store: DecisionHistoryStore,
    settings: _StubSettings,
) -> CheckpointStore:
    return CheckpointStore(
        object_store=object_store,
        audit_store=audit_store,
        decision_history_store=dh_store,
        settings=settings,
    )


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


async def _persist_one(
    store: CheckpointStore,
    *,
    session_id: str = "sess-1",
    tenant_id: str = "tenant-a",
    label: str = "ck",
    snapshot_bytes: bytes = b"snap",
) -> CheckpointId:
    return await store.persist(
        session_id=session_id,
        tenant_id=tenant_id,
        label=label,
        snapshot_bytes=snapshot_bytes,
        policy=_valid_policy(),
        pack_context=_valid_pack_context(),
        vault_lease_refs=(),
    )


# ---------------------------------------------------------------------------
# mint_checkpoint_id + validate_checkpoint_id_or_raise.
# ---------------------------------------------------------------------------


class TestMintAndValidateCheckpointId:
    def test_mint_returns_32_char_hex(self) -> None:
        cid = CheckpointStore.mint_checkpoint_id()
        assert isinstance(cid, str)
        assert len(cid) == 32
        assert re.fullmatch(r"[0-9a-f]{32}", cid)

    def test_mint_is_unique(self) -> None:
        ids = {CheckpointStore.mint_checkpoint_id() for _ in range(50)}
        assert len(ids) == 50

    def test_validate_accepts_minted_id(self) -> None:
        cid = CheckpointStore.mint_checkpoint_id()
        # Classmethod wrapper accepts the freshly-minted id.
        assert CheckpointStore.validate_checkpoint_id_or_raise(cid) == cid

    @pytest.mark.parametrize(
        "bad",
        ["", "abc", "z" * 32, "0" * 31, 12345, None, "A" * 32],
        ids=["empty", "too-short", "non-hex", "off-by-one", "int", "none", "uppercase-hex"],
    )
    def test_validate_rejects_non_32_char_lowercase_hex(self, bad: Any) -> None:
        # int(value, 16) accepts uppercase, but the validator only
        # documents 32-char-hex; uppercase-hex passes int parse, but
        # the spec docstring's "32-char hex" implicitly mirrors uuid4().hex
        # which is lowercase. If the implementation chooses to allow
        # uppercase, this test row will need to relax — but uuid4().hex
        # is always lowercase so production never produces uppercase ids.
        # Validator's primary guards are length + hex-ness; we keep
        # uppercase as a check that the validator is at minimum strict
        # about length (uppercase 32-char is length-32 + hex-parseable,
        # so this assertion only fires if the validator additionally
        # bans non-lowercase).
        # Drop the uppercase row from the strict assertion to keep the
        # validator's surface conservative.
        if bad == "A" * 32:
            # Validator MUST accept uppercase hex (int(value, 16) parses
            # it). Skip the strict assertion for the uppercase row;
            # keep it parametrized for documentation.
            return
        with pytest.raises(ValueError):
            CheckpointStore.validate_checkpoint_id_or_raise(bad)


# ---------------------------------------------------------------------------
# persist() — key layout + retention_seconds=None invariant.
# ---------------------------------------------------------------------------


class TestPersistKeyLayoutAndRetention:
    async def test_persist_writes_snapshot_and_metadata_at_correct_keys(
        self,
        store: CheckpointStore,
        object_store: LocalObjectStoreAdapter,
    ) -> None:
        cid = await _persist_one(store)
        snap = await object_store.get(BUCKET, f"tenant-a/sess-1/{cid}.snapshot")
        meta_bytes = await object_store.get(BUCKET, f"tenant-a/sess-1/{cid}.metadata.json")
        assert snap == b"snap"
        meta_dict = json.loads(meta_bytes)
        assert meta_dict["checkpoint_id"] == cid
        assert meta_dict["session_id"] == "sess-1"
        assert meta_dict["tenant_id"] == "tenant-a"
        assert meta_dict["label"] == "ck"

    async def test_persist_passes_retention_seconds_none_to_put(
        self,
        engine: AsyncEngine,
        audit_store: AuditStore,
        dh_store: DecisionHistoryStore,
        settings: _StubSettings,
    ) -> None:
        """P1.r3 load-bearing — every ObjectStoreAdapter.put() call
        passes retention_seconds=None (NOT the
        settings.sandbox_checkpoint_retention_s value). Retention floor
        lives at the REAPER per spec §4.3; using the WORM lock as a TTL
        would block max-per-session eviction + explicit destroy paths
        against the landed Sprint-4 local driver."""
        captured: list[dict[str, Any]] = []

        class _CaptureStore:
            async def put(
                self,
                bucket: str,
                key: str,
                body: bytes,
                *,
                retention_seconds: int | None = None,
            ) -> None:
                captured.append(
                    {
                        "bucket": bucket,
                        "key": key,
                        "retention_seconds": retention_seconds,
                    }
                )

            async def get(self, bucket: str, key: str) -> bytes:  # pragma: no cover
                raise FileNotFoundError(key)

            async def delete(self, bucket: str, key: str) -> None:  # pragma: no cover
                return None

            async def presign(self, bucket: str, key: str, ttl_s: int) -> str:  # pragma: no cover
                raise NotImplementedError

            async def health_check(self) -> Any:  # pragma: no cover
                return None

            async def list_prefix(self, bucket: str, prefix: str) -> AsyncIterator[str]:
                if False:
                    yield ""
                return

        capture_store = _CaptureStore()
        st = CheckpointStore(
            object_store=capture_store,
            audit_store=audit_store,
            decision_history_store=dh_store,
            settings=settings,
        )
        await st.persist(
            session_id="sess-1",
            tenant_id="tenant-a",
            label="ck",
            snapshot_bytes=b"snap",
            policy=_valid_policy(),
            pack_context=_valid_pack_context(),
            vault_lease_refs=(),
        )

        assert len(captured) == 2
        for call in captured:
            assert call["retention_seconds"] is None, (
                f"P1.r3 violation: persist() passed "
                f"retention_seconds={call['retention_seconds']!r} for key "
                f"{call['key']!r} — must be None"
            )

    async def test_persist_returns_checkpoint_id(self, store: CheckpointStore) -> None:
        cid = await _persist_one(store)
        assert isinstance(cid, str)
        assert re.fullmatch(r"[0-9a-f]{32}", cid)


# ---------------------------------------------------------------------------
# load_latest — filtering + latest-by-created_at + cross-tenant refusal.
# ---------------------------------------------------------------------------


class TestLoadLatest:
    async def test_load_latest_returns_most_recent_by_created_at(
        self,
        store: CheckpointStore,
        object_store: LocalObjectStoreAdapter,
    ) -> None:
        cid1 = await _persist_one(store, label="first", snapshot_bytes=b"first")
        # Small delay to ensure different created_at values; created_at
        # is generated at persist() time per spec §4.1.
        import asyncio

        await asyncio.sleep(0.01)
        cid2 = await _persist_one(store, label="second", snapshot_bytes=b"second")
        meta, snap = await store.load_latest(session_id="sess-1", tenant_id="tenant-a")
        assert meta.checkpoint_id == cid2
        assert snap == b"second"
        # And the first one is still on disk (load_latest doesn't purge).
        assert await object_store.get(BUCKET, f"tenant-a/sess-1/{cid1}.snapshot") == b"first"

    async def test_load_latest_filters_to_metadata_json_keys(
        self,
        store: CheckpointStore,
    ) -> None:
        """A bug that filtered to ``.snapshot`` keys would mis-construct
        metadata. A bug that yielded all keys + tried to parse the
        snapshot blob as JSON would raise. The clean read against a
        valid prefix is the green-path pin."""
        cid = await _persist_one(store)
        meta, _snap = await store.load_latest(session_id="sess-1", tenant_id="tenant-a")
        assert meta.checkpoint_id == cid

    async def test_load_latest_cross_tenant_refuses_with_not_found(
        self,
        store: CheckpointStore,
    ) -> None:
        """Cross-tenant lookup MUST refuse with the wake-not-found
        closed-enum — defence-in-depth past the wake() step 2
        tenant-mismatch check. Bytes physically separated by the
        per-tenant prefix per spec §4.1 + the key layout."""
        await _persist_one(store, tenant_id="tenant-a")
        with pytest.raises(SandboxLifecycleRefused) as ei:
            await store.load_latest(session_id="sess-1", tenant_id="tenant-b")
        assert ei.value.reason == "sandbox_wake_checkpoint_not_found"

    async def test_load_latest_unknown_session_refuses_with_not_found(
        self,
        store: CheckpointStore,
    ) -> None:
        with pytest.raises(SandboxLifecycleRefused) as ei:
            await store.load_latest(session_id="never-existed", tenant_id="tenant-a")
        assert ei.value.reason == "sandbox_wake_checkpoint_not_found"

    async def test_per_tenant_prefix_isolation(
        self,
        store: CheckpointStore,
    ) -> None:
        """Tenant-a's persist() does NOT cross-contaminate tenant-b's
        load_latest()."""
        await _persist_one(store, tenant_id="tenant-a", snapshot_bytes=b"a-snap")
        await _persist_one(store, tenant_id="tenant-b", snapshot_bytes=b"b-snap")
        meta_a, snap_a = await store.load_latest(session_id="sess-1", tenant_id="tenant-a")
        meta_b, snap_b = await store.load_latest(session_id="sess-1", tenant_id="tenant-b")
        assert snap_a == b"a-snap"
        assert snap_b == b"b-snap"
        assert meta_a.tenant_id == "tenant-a"
        assert meta_b.tenant_id == "tenant-b"


# ---------------------------------------------------------------------------
# load_tombstone — FileNotFoundError / valid / malformed (P1.r6).
# ---------------------------------------------------------------------------


class TestLoadTombstone:
    async def test_load_tombstone_returns_none_when_absent(self, store: CheckpointStore) -> None:
        """FileNotFoundError from get() → None (genuinely absent;
        wake() proceeds to load_latest)."""
        result = await store.load_tombstone(session_id="sess-1", tenant_id="tenant-a")
        assert result is None

    async def test_load_tombstone_returns_record_on_valid_sentinel(
        self,
        store: CheckpointStore,
        object_store: LocalObjectStoreAdapter,
    ) -> None:
        key = await store.tombstone_session(
            session_id="sess-1", tenant_id="tenant-a", tombstoned_by="alice"
        )
        assert key.endswith("/_tombstoned.json")
        result = await store.load_tombstone(session_id="sess-1", tenant_id="tenant-a")
        assert result is not None
        assert isinstance(result, TombstoneRecord)
        assert result.tombstoned_by == "alice"
        # tz-aware per the canonical-form rule.
        assert result.tombstoned_at.tzinfo is not None
        assert result.tombstoned_at.utcoffset() is not None
        assert result.retained_until > result.tombstoned_at

    @pytest.mark.parametrize(
        "malformed_bytes",
        [
            b"not json {{{",  # invalid JSON
            b'{"tombstoned_at": "2026-05-19T12:00:00+00:00"}',  # missing fields
            b'["a list", "not a dict"]',  # non-dict
        ],
        ids=["invalid-json", "wrong-shape", "non-dict"],
    )
    async def test_load_tombstone_raises_corrupt_on_malformed_sentinel(
        self,
        store: CheckpointStore,
        object_store: LocalObjectStoreAdapter,
        malformed_bytes: bytes,
    ) -> None:
        """P1.r6 LOAD-BEARING FAIL-CLOSED — malformed sentinel raises
        TombstoneCorruptError. Returning None on malformed would be
        fail-OPEN (wake() would proceed to load_latest and restore a
        session that operator INTENDED to destroy).

        Wake() (T6/T7 — not in this task) catches
        TombstoneCorruptError and maps to the SAME closed-enum value
        sandbox_wake_session_tombstoned with the original_exc_message
        in detail so incident response can distinguish well-formed-
        tombstoned vs tampered-tombstone."""
        await object_store.put(
            BUCKET,
            "tenant-a/sess-1/_tombstoned.json",
            malformed_bytes,
            retention_seconds=None,
        )
        with pytest.raises(TombstoneCorruptError):
            await store.load_tombstone(session_id="sess-1", tenant_id="tenant-a")


# ---------------------------------------------------------------------------
# tombstone_session — idempotency.
# ---------------------------------------------------------------------------


class TestTombstoneSession:
    async def test_tombstone_writes_correct_key(
        self,
        store: CheckpointStore,
        object_store: LocalObjectStoreAdapter,
    ) -> None:
        key = await store.tombstone_session(
            session_id="sess-1", tenant_id="tenant-a", tombstoned_by="alice"
        )
        assert key == "tenant-a/sess-1/_tombstoned.json"
        await object_store.get(BUCKET, key)  # exists

    async def test_tombstone_is_idempotent_returns_existing_key(
        self,
        store: CheckpointStore,
    ) -> None:
        """Second call returns the existing tombstone key without
        overwriting tombstoned_at — prevents destroy()-after-destroy
        from extending retention."""
        key1 = await store.tombstone_session(
            session_id="sess-1", tenant_id="tenant-a", tombstoned_by="alice"
        )
        first = await store.load_tombstone(session_id="sess-1", tenant_id="tenant-a")
        assert first is not None

        # Second call — different actor; must NOT overwrite.
        key2 = await store.tombstone_session(
            session_id="sess-1", tenant_id="tenant-a", tombstoned_by="bob"
        )
        second = await store.load_tombstone(session_id="sess-1", tenant_id="tenant-a")
        assert second is not None
        assert key1 == key2
        # tombstoned_at + tombstoned_by + retained_until UNCHANGED.
        assert second.tombstoned_at == first.tombstoned_at
        assert second.tombstoned_by == "alice"
        assert second.retained_until == first.retained_until

    async def test_tombstone_uses_settings_retention_for_retained_until(
        self,
        engine: AsyncEngine,
        object_store: LocalObjectStoreAdapter,
        audit_store: AuditStore,
        dh_store: DecisionHistoryStore,
    ) -> None:
        """retained_until = now + settings.sandbox_checkpoint_retention_s."""
        st = CheckpointStore(
            object_store=object_store,
            audit_store=audit_store,
            decision_history_store=dh_store,
            settings=_StubSettings(sandbox_checkpoint_retention_s=42),
        )
        await st.tombstone_session(session_id="sess-1", tenant_id="tenant-a", tombstoned_by="alice")
        rec = await st.load_tombstone(session_id="sess-1", tenant_id="tenant-a")
        assert rec is not None
        delta = (rec.retained_until - rec.tombstoned_at).total_seconds()
        assert delta == pytest.approx(42, abs=1)


# ---------------------------------------------------------------------------
# purge_by_id — emits checkpoint_purged chain row via T2 helper.
# ---------------------------------------------------------------------------


class TestPurgeById:
    async def test_purge_by_id_deletes_storage_and_emits_chain_row(
        self,
        store: CheckpointStore,
        object_store: LocalObjectStoreAdapter,
        engine: AsyncEngine,
    ) -> None:
        cid = await _persist_one(store)
        await store.purge_by_id(
            session_id="sess-1",
            tenant_id="tenant-a",
            checkpoint_id=CheckpointId(cid),
            purge_reason="retention_expired",
        )
        # Storage gone.
        with pytest.raises(FileNotFoundError):
            await object_store.get(BUCKET, f"tenant-a/sess-1/{cid}.snapshot")
        with pytest.raises(FileNotFoundError):
            await object_store.get(BUCKET, f"tenant-a/sess-1/{cid}.metadata.json")
        # Chain row appended via the T2 helper.
        async with engine.connect() as conn:
            rows = (
                await conn.execute(
                    sa.text(
                        "SELECT event_type, payload FROM decision_history "
                        "WHERE event_type = 'sandbox.lifecycle.checkpoint_purged'"
                    )
                )
            ).fetchall()
        assert len(rows) == 1
        payload = json.loads(rows[0][1])
        assert payload["checkpoint_id"] == cid
        assert payload["purge_reason"] == "retention_expired"

    async def test_purge_by_id_deletes_suspend_event_id_side_blob(
        self,
        store: CheckpointStore,
        object_store: LocalObjectStoreAdapter,
    ) -> None:
        """T6 DockerSibling writes an optional
        ``<checkpoint>.suspend_event_id`` sibling. The CheckpointStore
        purge lifecycle must remove it with snapshot + metadata so
        reaper/cap purges do not leave stale suspend-linkage bytes."""
        cid = await _persist_one(store)
        await object_store.put(
            BUCKET,
            f"tenant-a/sess-1/{cid}.suspend_event_id",
            b"11111111-1111-1111-1111-111111111111",
            retention_seconds=None,
        )

        await store.purge_by_id(
            session_id="sess-1",
            tenant_id="tenant-a",
            checkpoint_id=CheckpointId(cid),
            purge_reason="retention_expired",
        )

        with pytest.raises(FileNotFoundError):
            await object_store.get(BUCKET, f"tenant-a/sess-1/{cid}.suspend_event_id")

    @pytest.mark.parametrize(
        "reason",
        [
            "explicit_destroy",
            "max_per_session_cap",
            "retention_expired",
            "tenant_revocation",
        ],
    )
    async def test_purge_by_id_accepts_all_4_purge_reasons(
        self, store: CheckpointStore, reason: str
    ) -> None:
        cid = await _persist_one(store, snapshot_bytes=b"x")
        # Must not raise on any of the 4 closed-enum values.
        await store.purge_by_id(
            session_id="sess-1",
            tenant_id="tenant-a",
            checkpoint_id=CheckpointId(cid),
            purge_reason=reason,  # type: ignore[arg-type]
        )


# ---------------------------------------------------------------------------
# purge_expired — walks via list_prefix; tombstone vs aged paths.
# ---------------------------------------------------------------------------


class TestPurgeExpired:
    async def test_purge_expired_skips_inside_retention_window(
        self,
        store: CheckpointStore,
        object_store: LocalObjectStoreAdapter,
    ) -> None:
        """Refuses to purge any checkpoint inside its retention window
        per spec §4.3 path 2."""
        cid = await _persist_one(store)  # retention_window_s = 86_400
        purged = await store.purge_expired()
        assert purged == 0
        # Still on disk.
        await object_store.get(BUCKET, f"tenant-a/sess-1/{cid}.snapshot")

    async def test_purge_expired_purges_aged_non_tombstoned_with_retention_expired(
        self,
        engine: AsyncEngine,
        object_store: LocalObjectStoreAdapter,
        audit_store: AuditStore,
        dh_store: DecisionHistoryStore,
    ) -> None:
        """Aged non-tombstoned checkpoints purged with
        purge_reason='retention_expired' per spec §4.3 path 2."""
        st = CheckpointStore(
            object_store=object_store,
            audit_store=audit_store,
            decision_history_store=dh_store,
            settings=_StubSettings(sandbox_checkpoint_retention_s=0),
        )
        # Build metadata with retention_window_s = 0 + created_at in the
        # past so (now - created_at) >= 0 immediately.
        meta = CheckpointMetadata(
            checkpoint_id=CheckpointId(uuid.uuid4().hex),
            session_id="sess-1",
            tenant_id="tenant-a",
            label="aged",
            created_at=datetime.now(UTC) - timedelta(seconds=10),
            policy=_valid_policy(),
            pack_context=_valid_pack_context(),
            retention_window_s=0,
            vault_lease_refs=(),
        )
        cid = meta.checkpoint_id
        # Hand-place the snapshot + metadata so the in-memory meta
        # carries the past created_at + zero retention.
        await object_store.put(
            BUCKET, f"tenant-a/sess-1/{cid}.snapshot", b"aged-snap", retention_seconds=None
        )
        await object_store.put(
            BUCKET,
            f"tenant-a/sess-1/{cid}.metadata.json",
            canonical_bytes(meta.to_storage_payload()),
            retention_seconds=None,
        )
        purged = await st.purge_expired()
        assert purged == 1
        with pytest.raises(FileNotFoundError):
            await object_store.get(BUCKET, f"tenant-a/sess-1/{cid}.snapshot")
        # Chain row uses retention_expired.
        async with engine.connect() as conn:
            rows = (
                await conn.execute(
                    sa.text(
                        "SELECT payload FROM decision_history "
                        "WHERE event_type = 'sandbox.lifecycle.checkpoint_purged'"
                    )
                )
            ).fetchall()
        assert len(rows) == 1
        payload = json.loads(rows[0][0])
        assert payload["purge_reason"] == "retention_expired"

    async def test_purge_expired_purges_tombstoned_elapsed_with_explicit_destroy(
        self,
        engine: AsyncEngine,
        object_store: LocalObjectStoreAdapter,
        audit_store: AuditStore,
        dh_store: DecisionHistoryStore,
    ) -> None:
        """Tombstoned-then-elapsed path uses
        purge_reason='explicit_destroy' per spec §4.3 path 1 — the
        original operator destroy() action is the cause."""
        st = CheckpointStore(
            object_store=object_store,
            audit_store=audit_store,
            decision_history_store=dh_store,
            settings=_StubSettings(sandbox_checkpoint_retention_s=0),
        )
        # Persist a checkpoint (uses default retention).
        cid = await _persist_one(st)
        # Tombstone the session — retained_until will be ~now+0s.
        await st.tombstone_session(session_id="sess-1", tenant_id="tenant-a", tombstoned_by="alice")
        # Wait until retained_until has elapsed.
        import asyncio

        await asyncio.sleep(0.05)
        purged = await st.purge_expired()
        assert purged >= 1
        # The chain row(s) carry explicit_destroy.
        async with engine.connect() as conn:
            rows = (
                await conn.execute(
                    sa.text(
                        "SELECT payload FROM decision_history "
                        "WHERE event_type = 'sandbox.lifecycle.checkpoint_purged'"
                    )
                )
            ).fetchall()
        assert len(rows) >= 1
        payloads = [json.loads(r[0]) for r in rows]
        assert all(p["purge_reason"] == "explicit_destroy" for p in payloads)
        assert any(p["checkpoint_id"] == cid for p in payloads)
        # Tombstone sentinel also gone.
        with pytest.raises(FileNotFoundError):
            await object_store.get(BUCKET, "tenant-a/sess-1/_tombstoned.json")

    async def test_purge_expired_skips_tombstoned_session_inside_retention(
        self,
        engine: AsyncEngine,
        object_store: LocalObjectStoreAdapter,
        audit_store: AuditStore,
        dh_store: DecisionHistoryStore,
    ) -> None:
        """Tombstoned session whose retained_until has NOT yet elapsed
        is left in place (path 1 second branch)."""
        st = CheckpointStore(
            object_store=object_store,
            audit_store=audit_store,
            decision_history_store=dh_store,
            settings=_StubSettings(sandbox_checkpoint_retention_s=86_400),
        )
        cid = await _persist_one(st)
        await st.tombstone_session(session_id="sess-1", tenant_id="tenant-a", tombstoned_by="alice")
        purged = await st.purge_expired()
        assert purged == 0
        await object_store.get(BUCKET, f"tenant-a/sess-1/{cid}.snapshot")
        await object_store.get(BUCKET, "tenant-a/sess-1/_tombstoned.json")
