"""Sprint 8.5 T12 — focused negative-path coverage for
``sandbox/checkpoint_store.py``.

Same-commit coverage repair landed alongside the T12 critical-controls
gate promotion (71 → 73). The tightening-edit-B check
(`feedback_verify_promotion_meets_floor_at_promotion_time`) found
``checkpoint_store.py`` at 89.90% line / 85.48% branch on fresh
``coverage.json`` — below the 95/90 durable-gate floor. The promotion
MUST NOT land without same-commit repair (Sprint 8B T8B-d precedent).

Every test here pins a NEGATIVE-PATH branch the T3 happy-path suite
(``test_checkpoint_store.py`` + ``test_checkpoint_metadata.py``) left
uncovered — type-validation raise arms, corrupt-blob handling,
reaper-sweep race / corrupt-tombstone skips, and ``load_tombstone``
fail-closed raises. These are exactly the evidence-boundary
negative-path tests `feedback_evidence_boundary_runtime_validation`
mandates: a chain-row materialiser / wake-evidence parser cannot trust
its input types.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.db.adapters.local_object_store_adapter import (
    LocalObjectStoreAdapter,
)
from cognic_agentos.sandbox.checkpoint_store import (
    _BUCKET,
    _METADATA_SUFFIX,
    _TOMBSTONE_BASENAME,
    CheckpointMetadata,
    CheckpointStore,
    TombstoneCorruptError,
)
from cognic_agentos.sandbox.policy import PackAdmissionContext, SandboxPolicy
from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

# ---------------------------------------------------------------------------
# Fixtures — mirror the T3 ``test_checkpoint_store.py`` scaffolding.
# ---------------------------------------------------------------------------


@dataclass
class _StubSettings:
    sandbox_checkpoint_retention_s: int = 86_400
    sandbox_max_checkpoints_per_session: int = 10
    sandbox_reaper_interval_s: int = 300


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    url = f"sqlite+aiosqlite:///{tmp_path / 'dh.db'}"
    eng = create_async_engine(url)
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id,
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=datetime.now(UTC),
                )
            )
    yield eng
    await eng.dispose()


@pytest.fixture
def object_store(tmp_path: Path) -> LocalObjectStoreAdapter:
    return LocalObjectStoreAdapter(root=tmp_path / "objects")


@pytest.fixture
async def store(
    engine: AsyncEngine,
    object_store: LocalObjectStoreAdapter,
) -> CheckpointStore:
    return CheckpointStore(
        object_store=object_store,
        audit_store=AuditStore(engine),
        decision_history_store=DecisionHistoryStore(engine),
        settings=_StubSettings(),
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
) -> str:
    return await store.persist(
        session_id=session_id,
        tenant_id=tenant_id,
        label="ck",
        snapshot_bytes=b"snap",
        policy=_valid_policy(),
        pack_context=_valid_pack_context(),
        vault_lease_refs=(),
    )


async def _valid_payload(
    store: CheckpointStore, object_store: LocalObjectStoreAdapter
) -> dict[str, Any]:
    """Persist a checkpoint + return the parsed metadata payload — the
    exact dict shape ``from_storage_payload`` round-trips. Tests mutate
    one field then assert the matching ``ValueError``."""
    cid = await _persist_one(store)
    raw = await object_store.get(_BUCKET, f"tenant-a/sess-1/{cid}{_METADATA_SUFFIX}")
    payload = json.loads(raw)
    assert isinstance(payload, dict)
    return payload


# ---------------------------------------------------------------------------
# _require_* helper negative paths — reached through from_storage_payload.
# ---------------------------------------------------------------------------


class TestRequireHelperNegativePaths:
    """The numeric / str / list type-validation helpers reject malformed
    wire values BEFORE they reach downstream call sites — pinning the
    raise arms keeps the closed-enum refusal taxonomy intact."""

    async def test_require_str_or_none_rejects_non_str(
        self, store: CheckpointStore, object_store: LocalObjectStoreAdapter
    ) -> None:
        payload = await _valid_payload(store, object_store)
        payload["policy"]["vault_path"] = 123
        with pytest.raises(ValueError, match="vault_path must be str"):
            CheckpointMetadata.from_storage_payload(payload)

    async def test_require_number_or_none_rejects_non_number(
        self, store: CheckpointStore, object_store: LocalObjectStoreAdapter
    ) -> None:
        payload = await _valid_payload(store, object_store)
        payload["policy"]["cpu_time_budget_s"] = "not-a-number"
        with pytest.raises(ValueError, match="cpu_time_budget_s must be number"):
            CheckpointMetadata.from_storage_payload(payload)

    async def test_require_list_of_dict_rejects_tuple(
        self, store: CheckpointStore, object_store: LocalObjectStoreAdapter
    ) -> None:
        # Defence-in-depth: a tuple cannot arrive via json.loads; passing
        # one directly proves the bytes took a non-canonical path.
        payload = await _valid_payload(store, object_store)
        payload["policy"]["writable_mounts"] = ()
        with pytest.raises(ValueError, match="writable_mounts must be list"):
            CheckpointMetadata.from_storage_payload(payload)

    async def test_require_list_of_dict_rejects_non_list(
        self, store: CheckpointStore, object_store: LocalObjectStoreAdapter
    ) -> None:
        payload = await _valid_payload(store, object_store)
        payload["policy"]["writable_mounts"] = "all-of-them"
        with pytest.raises(ValueError, match="writable_mounts must be list"):
            CheckpointMetadata.from_storage_payload(payload)

    async def test_require_list_of_dict_rejects_non_dict_element(
        self, store: CheckpointStore, object_store: LocalObjectStoreAdapter
    ) -> None:
        payload = await _valid_payload(store, object_store)
        payload["policy"]["writable_mounts"] = [123]
        with pytest.raises(ValueError, match=r"writable_mounts\[0\] must be dict"):
            CheckpointMetadata.from_storage_payload(payload)


# ---------------------------------------------------------------------------
# from_storage_payload structural raise arms.
# ---------------------------------------------------------------------------


class TestFromStoragePayloadNegativePaths:
    """``from_storage_payload`` is the wake-time evidence parser — every
    malformed-blob branch routes to ``ValueError`` so the wake() seam
    maps it to ``sandbox_wake_checkpoint_corrupt`` rather than crashing
    with a raw ``TypeError`` / ``KeyError``."""

    def test_rejects_non_dict_payload(self) -> None:
        with pytest.raises(ValueError, match="expects dict"):
            CheckpointMetadata.from_storage_payload("not-a-dict")  # type: ignore[arg-type]

    async def test_rejects_non_str_created_at(
        self, store: CheckpointStore, object_store: LocalObjectStoreAdapter
    ) -> None:
        payload = await _valid_payload(store, object_store)
        payload["created_at"] = 1_700_000_000
        with pytest.raises(ValueError, match="created_at must be ISO string"):
            CheckpointMetadata.from_storage_payload(payload)

    async def test_rejects_unparseable_created_at(
        self, store: CheckpointStore, object_store: LocalObjectStoreAdapter
    ) -> None:
        payload = await _valid_payload(store, object_store)
        payload["created_at"] = "definitely-not-a-datetime"
        with pytest.raises(ValueError, match="not parseable as ISO datetime"):
            CheckpointMetadata.from_storage_payload(payload)

    async def test_rejects_non_dict_policy(
        self, store: CheckpointStore, object_store: LocalObjectStoreAdapter
    ) -> None:
        payload = await _valid_payload(store, object_store)
        payload["policy"] = "not-a-dict"
        with pytest.raises(ValueError, match="policy must be dict"):
            CheckpointMetadata.from_storage_payload(payload)

    async def test_rejects_policy_missing_required_keys(
        self, store: CheckpointStore, object_store: LocalObjectStoreAdapter
    ) -> None:
        payload = await _valid_payload(store, object_store)
        del payload["policy"]["cpu_cores"]
        with pytest.raises(ValueError, match="policy missing required keys"):
            CheckpointMetadata.from_storage_payload(payload)

    async def test_read_only_root_defaults_true_when_absent(
        self, store: CheckpointStore, object_store: LocalObjectStoreAdapter
    ) -> None:
        # Optional field — absence takes the default-True else branch.
        payload = await _valid_payload(store, object_store)
        payload["policy"].pop("read_only_root", None)
        meta = CheckpointMetadata.from_storage_payload(payload)
        assert meta.policy.read_only_root is True

    async def test_rejects_non_dict_pack_context(
        self, store: CheckpointStore, object_store: LocalObjectStoreAdapter
    ) -> None:
        payload = await _valid_payload(store, object_store)
        payload["pack_context"] = ["not", "a", "dict"]
        with pytest.raises(ValueError, match="pack_context must be dict"):
            CheckpointMetadata.from_storage_payload(payload)

    async def test_rejects_pack_context_missing_required_keys(
        self, store: CheckpointStore, object_store: LocalObjectStoreAdapter
    ) -> None:
        payload = await _valid_payload(store, object_store)
        del payload["pack_context"]["pack_id"]
        with pytest.raises(ValueError, match="pack_context missing required keys"):
            CheckpointMetadata.from_storage_payload(payload)

    async def test_rejects_non_list_vault_lease_refs(
        self, store: CheckpointStore, object_store: LocalObjectStoreAdapter
    ) -> None:
        payload = await _valid_payload(store, object_store)
        payload["vault_lease_refs"] = "none-of-them"
        with pytest.raises(ValueError, match="vault_lease_refs must be list"):
            CheckpointMetadata.from_storage_payload(payload)


# ---------------------------------------------------------------------------
# purge_expired() reaper-sweep edge cases.
# ---------------------------------------------------------------------------


class TestPurgeExpiredEdgeCases:
    """The reaper sweep must survive corrupt blobs + races over a
    multi-million-key tenant — one bad object never aborts the sweep."""

    async def test_skips_keys_with_unexpected_shape(
        self, store: CheckpointStore, object_store: LocalObjectStoreAdapter
    ) -> None:
        # A <3-segment key is not a tenant/session/file checkpoint key.
        await object_store.put(_BUCKET, "orphan-tenant/orphan", b"x", retention_seconds=None)
        assert await store.purge_expired() == 0

    async def test_skips_session_with_corrupt_tombstone(
        self, store: CheckpointStore, object_store: LocalObjectStoreAdapter
    ) -> None:
        # Corrupt tombstone — fail-closed: skip the session sweep so an
        # operator can triage; symmetric to wake()-side P1.r6.
        await object_store.put(
            _BUCKET,
            f"tenant-a/sess-tomb/{_TOMBSTONE_BASENAME}",
            b"{ this is not valid json",
            retention_seconds=None,
        )
        assert await store.purge_expired() == 0

    async def test_skips_session_when_tombstone_lost_to_race(
        self,
        store: CheckpointStore,
        object_store: LocalObjectStoreAdapter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # list_prefix saw the tombstone key; load_tombstone returns None
        # (sentinel removed between list + read). The sweep skips it.
        await object_store.put(
            _BUCKET,
            f"tenant-a/sess-race/{_TOMBSTONE_BASENAME}",
            b"{}",
            retention_seconds=None,
        )

        async def _race_none(**_kwargs: object) -> None:
            return None

        monkeypatch.setattr(store, "load_tombstone", _race_none)
        assert await store.purge_expired() == 0

    async def test_skips_metadata_lost_to_race(
        self,
        store: CheckpointStore,
        object_store: LocalObjectStoreAdapter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Non-tombstoned path — the metadata blob vanishes between
        # list_prefix + get. The sweep skips that checkpoint.
        await _persist_one(store)
        real_get = object_store.get

        async def _get_raising(bucket: str, key: str) -> bytes:
            if key.endswith(_METADATA_SUFFIX):
                raise FileNotFoundError(key)
            return await real_get(bucket, key)

        monkeypatch.setattr(object_store, "get", _get_raising)
        assert await store.purge_expired() == 0

    async def test_skips_corrupt_metadata_blob(
        self, store: CheckpointStore, object_store: LocalObjectStoreAdapter
    ) -> None:
        # Non-tombstoned path — a metadata blob is malformed JSON. The
        # sweep logs + skips it rather than aborting.
        cid = await _persist_one(store)
        await object_store.put(
            _BUCKET,
            f"tenant-a/sess-1/{cid}{_METADATA_SUFFIX}",
            b"{ not valid json at all",
            retention_seconds=None,
        )
        assert await store.purge_expired() == 0


# ---------------------------------------------------------------------------
# load_tombstone() fail-closed corrupt-sentinel raises.
# ---------------------------------------------------------------------------


class TestLoadTombstoneCorruptVariants:
    """``load_tombstone`` raises ``TombstoneCorruptError`` on a malformed
    sentinel — fail-closed per P1.r6 so a tampered tombstone can NEVER
    make a destroyed session look restorable."""

    async def _write_tombstone(
        self, object_store: LocalObjectStoreAdapter, session_id: str, body: dict[str, Any]
    ) -> None:
        await object_store.put(
            _BUCKET,
            f"tenant-a/{session_id}/{_TOMBSTONE_BASENAME}",
            json.dumps(body).encode(),
            retention_seconds=None,
        )

    async def test_rejects_unparseable_datetime(
        self, store: CheckpointStore, object_store: LocalObjectStoreAdapter
    ) -> None:
        await self._write_tombstone(
            object_store,
            "sess-unparse",
            {
                "tombstoned_at": "garbage-not-a-datetime",
                "tombstoned_by": "actor-x",
                "retained_until": "2026-01-01T00:00:00+00:00",
            },
        )
        with pytest.raises(TombstoneCorruptError, match="unparseable datetime"):
            await store.load_tombstone(session_id="sess-unparse", tenant_id="tenant-a")

    async def test_rejects_naive_datetime(
        self, store: CheckpointStore, object_store: LocalObjectStoreAdapter
    ) -> None:
        await self._write_tombstone(
            object_store,
            "sess-naive",
            {
                "tombstoned_at": "2026-01-01T00:00:00",  # no tz offset
                "tombstoned_by": "actor-x",
                "retained_until": "2026-01-01T00:00:00+00:00",
            },
        )
        with pytest.raises(TombstoneCorruptError, match="naive"):
            await store.load_tombstone(session_id="sess-naive", tenant_id="tenant-a")

    async def test_rejects_non_str_tombstoned_by(
        self, store: CheckpointStore, object_store: LocalObjectStoreAdapter
    ) -> None:
        await self._write_tombstone(
            object_store,
            "sess-byint",
            {
                "tombstoned_at": "2026-01-01T00:00:00+00:00",
                "tombstoned_by": 12345,
                "retained_until": "2026-06-01T00:00:00+00:00",
            },
        )
        with pytest.raises(TombstoneCorruptError, match="tombstoned_by must be str"):
            await store.load_tombstone(session_id="sess-byint", tenant_id="tenant-a")


# ---------------------------------------------------------------------------
# _list_session_metadata() race — reached through load_latest().
# ---------------------------------------------------------------------------


class TestListSessionMetadataRace:
    """A metadata blob removed between ``list_prefix`` + ``get`` is
    skipped — the sweep over a session prefix never aborts on one race."""

    async def test_load_latest_skips_metadata_lost_to_race(
        self,
        store: CheckpointStore,
        object_store: LocalObjectStoreAdapter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await _persist_one(store)
        real_get = object_store.get

        async def _get_raising(bucket: str, key: str) -> bytes:
            if key.endswith(_METADATA_SUFFIX):
                raise FileNotFoundError(key)
            return await real_get(bucket, key)

        monkeypatch.setattr(object_store, "get", _get_raising)
        # Every metadata key races away — load_latest sees an empty
        # session and refuses with the not-found closed-enum reason.
        with pytest.raises(SandboxLifecycleRefused) as excinfo:
            await store.load_latest(session_id="sess-1", tenant_id="tenant-a")
        assert excinfo.value.reason == "sandbox_wake_checkpoint_not_found"
