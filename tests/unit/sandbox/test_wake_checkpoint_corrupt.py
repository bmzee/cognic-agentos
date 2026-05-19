"""Sprint 8.5 T6 — wake-time corrupt-metadata refusal per spec §3.2
step 1(c) + P2.r3 fix.

Pins:

* Malformed metadata blob on disk (missing key / tuple smuggled in /
  naive datetime / extra closing brace) → ``from_storage_payload()``
  raises ``ValueError`` → wake() catches and surfaces
  ``SandboxLifecycleRefused("sandbox_wake_checkpoint_corrupt")`` with
  the original ``ValueError`` message in ``detail``.
* Distinct from ``sandbox_wake_checkpoint_not_found`` (missing blob)
  AND ``sandbox_wake_session_tombstoned`` (operator destroy) per
  examiner incident-response paths.
* Wake() does NOT swallow the ValueError — catches it explicitly +
  surfaces fail-loud with the closed-enum reason.
* Missing or malformed ``.suspend_event_id`` side-blob refuses at
  wake-time BEFORE Docker resources are created. T8 chain-verifier
  repeats this as defence-in-depth; it is not the first fail-closed
  seam.
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
from cognic_agentos.sandbox.protocol import CheckpointId, SandboxLifecycleRefused


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


async def _write_corrupt_metadata(
    store: CheckpointStore, *, tenant_id: str, session_id: str, raw_bytes: bytes
) -> None:
    """Place a corrupt metadata blob at the per-tenant prefix. The
    checkpoint_id 32-char-hex shape is enforced by the parser; we use
    a sentinel id so the prefix matches load_latest()'s
    ``.metadata.json`` filter."""
    cid = "f" * 32  # 32-char hex; parses past the id-shape check
    key = f"{tenant_id}/{session_id}/{cid}.metadata.json"
    await store._object_store.put("sandbox-checkpoints", key, raw_bytes, retention_seconds=None)


async def _persist_valid_checkpoint(
    store: CheckpointStore,
    *,
    session_id: str,
    tenant_id: str = "t-1",
) -> CheckpointId:
    return await store.persist(
        session_id=session_id,
        tenant_id=tenant_id,
        label="cp",
        snapshot_bytes=b"snapshot-bytes",
        policy=_policy(),
        pack_context=_pack_ctx(),
        vault_lease_refs=(),
    )


def _patch_docker_restore_path(
    backend: DockerSiblingSandboxBackend,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, AsyncMock]:
    """Patch every Docker-touching wake helper.

    Pre-fix code returned a NIL UUID from the side-blob reader and
    continued into these helpers. Patching all of them makes the
    regression fail as "DID NOT RAISE" instead of failing accidentally
    on a MagicMock-shaped Docker object.
    """
    mocks: dict[str, AsyncMock] = {}
    for method_name in (
        "_create_internal_network",
        "_create_egress_network",
        "_start_proxy_sidecar",
        "_start_sandbox_container",
        "_restore_workspace_tar",
    ):
        mock = AsyncMock()
        monkeypatch.setattr(backend, method_name, mock)
        mocks[method_name] = mock
    return mocks


class TestMalformedJSONSurfacesAsCorrupt:
    @pytest.mark.asyncio
    async def test_invalid_json_raises_corrupt(self, store: CheckpointStore) -> None:
        """A metadata file that's not parseable JSON → ValueError
        propagates through ``_list_session_metadata`` /
        ``from_storage_payload`` → wake catches as corrupt."""
        await _write_corrupt_metadata(
            store,
            tenant_id="t-1",
            session_id="sess-bad-json",
            raw_bytes=b"{not valid json",
        )
        backend = _make_backend(store)
        with pytest.raises(Exception) as exc:
            await backend.wake("sess-bad-json", actor=_ACTOR, tenant_id="t-1")
        # The JSONDecodeError propagates as a ValueError subclass via
        # json.loads — but ``_list_session_metadata`` calls
        # ``json.loads`` first; the JSONDecodeError IS a ValueError
        # subclass so the wake() seam catches it.
        assert isinstance(exc.value, SandboxLifecycleRefused)
        assert exc.value.reason == "sandbox_wake_checkpoint_corrupt"


class TestMissingRequiredKeysSurfacesAsCorrupt:
    @pytest.mark.asyncio
    async def test_metadata_missing_session_id_key_raises_corrupt(
        self, store: CheckpointStore
    ) -> None:
        """Valid JSON missing a required top-level key →
        from_storage_payload raises ValueError → corrupt taxonomy."""
        await _write_corrupt_metadata(
            store,
            tenant_id="t-1",
            session_id="sess-missing-key",
            raw_bytes=b'{"checkpoint_id": "abc"}',  # missing 8 other required keys
        )
        backend = _make_backend(store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-missing-key", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_checkpoint_corrupt"
        detail = exc.value.detail.lower()
        assert "missing" in detail


class TestNaiveDatetimeSurfacesAsCorrupt:
    @pytest.mark.asyncio
    async def test_metadata_with_naive_created_at_raises_corrupt(
        self, store: CheckpointStore
    ) -> None:
        """Per ``feedback_evidence_boundary_runtime_validation``:
        tz-naive datetime is fail-closed at the parser; surfaces as
        corrupt at wake."""
        import json

        # Start from a valid metadata blob + zero out the tzinfo.
        await store.persist(
            session_id="sess-naive-base",
            tenant_id="t-1",
            label="cp",
            snapshot_bytes=b"snap",
            policy=_policy(),
            pack_context=_pack_ctx(),
            vault_lease_refs=(),
        )
        # Read + edit + re-write under a new session prefix.
        # Find the persisted blob.
        async for key in store._object_store.list_prefix(
            "sandbox-checkpoints", "t-1/sess-naive-base/"
        ):
            if key.endswith(".metadata.json"):
                raw = await store._object_store.get("sandbox-checkpoints", key)
                meta = json.loads(raw)
                # Strip timezone — keep ISO string but no tzinfo.
                naive_iso = meta["created_at"].split("+")[0].rstrip("Z")
                meta["created_at"] = naive_iso
                await _write_corrupt_metadata(
                    store,
                    tenant_id="t-1",
                    session_id="sess-naive",
                    raw_bytes=json.dumps(meta).encode("utf-8"),
                )
                break

        backend = _make_backend(store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-naive", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_checkpoint_corrupt"


class TestSuspendEventIdSideBlobSurfacesAsCorrupt:
    @pytest.mark.asyncio
    async def test_missing_suspend_event_id_side_blob_refuses_before_docker(
        self,
        store: CheckpointStore,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A plain checkpoint without suspend linkage is corrupt for
        wake(). The refusal fires before Docker resources are created,
        not later in the T8 chain verifier."""
        await _persist_valid_checkpoint(store, session_id="sess-missing-side-blob")
        backend = _make_backend(store)
        docker_mocks = _patch_docker_restore_path(backend, monkeypatch)

        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-missing-side-blob", actor=_ACTOR, tenant_id="t-1")

        assert exc.value.reason == "sandbox_wake_checkpoint_corrupt"
        detail = exc.value.detail.lower()
        assert "suspend_event_id" in detail
        assert "missing" in detail
        for mock in docker_mocks.values():
            mock.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_malformed_suspend_event_id_side_blob_refuses_before_docker(
        self,
        store: CheckpointStore,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A corrupted side-blob is structurally the same class as
        corrupt metadata: wake refuses closed-enum corrupt and never
        emits a woken row with a NIL UUID placeholder."""
        session_id = "sess-malformed-side-blob"
        checkpoint_id = await _persist_valid_checkpoint(store, session_id=session_id)
        await store._object_store.put(
            "sandbox-checkpoints",
            f"t-1/{session_id}/{checkpoint_id}.suspend_event_id",
            b"not-a-uuid",
            retention_seconds=None,
        )
        backend = _make_backend(store)
        docker_mocks = _patch_docker_restore_path(backend, monkeypatch)

        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake(session_id, actor=_ACTOR, tenant_id="t-1")

        assert exc.value.reason == "sandbox_wake_checkpoint_corrupt"
        detail = exc.value.detail.lower()
        assert "suspend_event_id" in detail
        assert "not a uuid" in detail
        for mock in docker_mocks.values():
            mock.assert_not_awaited()


class TestCorruptIsDistinctFromNotFound:
    @pytest.mark.asyncio
    async def test_no_metadata_surfaces_as_not_found_not_corrupt(
        self, store: CheckpointStore
    ) -> None:
        """No metadata under the prefix → load_latest raises
        sandbox_wake_checkpoint_not_found per spec §4.1 — distinct
        from sandbox_wake_checkpoint_corrupt (which fires only when
        bytes exist on disk but are malformed)."""
        backend = _make_backend(store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("sess-empty", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_checkpoint_not_found"
