"""Sprint 8.5 T6 — destroy() tombstone-extension regression per spec
§3.1 + P1.r4 tombstone redesign.

Pins:

* ``destroy()`` of a session with persisted checkpoints calls
  ``CheckpointStore.tombstone_session(...)`` + the destroyed chain
  row carries TWO new payload keys:
  - ``retained_until`` (ISO string of ``now + retention_window_s``)
  - ``tombstone_object_key`` (``<tenant>/<session>/_tombstoned.json``)
* ``destroy()`` of a session with NO checkpoints emits the destroyed
  event WITHOUT those two keys (Sprint-8A baseline behaviour
  preserved).
* Idempotent tombstone: calling destroy() twice on a session with
  checkpoints leaves the original tombstone in place (CheckpointStore
  guarantees idempotency at the storage layer; the second destroy()
  is a no-op for chain emission per ``session._destroyed`` flag).
* ``tombstoned_by`` is sourced from ``session._actor_subject`` NOT
  from a destroy(actor) kwarg — destroy()'s Sprint-8A Protocol
  signature has no actor kwarg.

Uses a real CheckpointStore wired against ``LocalObjectStoreAdapter``
(filesystem) + an in-memory SQLite decision-history store. Docker
client is mocked since these tests pin tombstone + audit behaviour
NOT real container teardown.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
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
from cognic_agentos.sandbox import KernelDefaultCredentialAdapter
from cognic_agentos.sandbox.backends.docker_sibling import (
    DockerSiblingSandboxBackend,
    DockerSiblingSession,
)
from cognic_agentos.sandbox.checkpoint_store import CheckpointStore
from cognic_agentos.sandbox.policy import PackAdmissionContext, SandboxPolicy


@dataclass
class _StubSettings:
    sandbox_per_tenant_max_cpu: float = 4.0
    sandbox_per_tenant_max_memory: int = 4096
    sandbox_per_tenant_max_walltime: float = 300.0
    sandbox_checkpoint_retention_s: int = 86_400
    sandbox_max_checkpoints_per_session: int = 10
    sandbox_reaper_interval_s: int = 300


def _valid_policy() -> SandboxPolicy:
    return SandboxPolicy(
        cpu_cores=0.5,
        cpu_time_budget_s=None,
        memory_mb=256,
        walltime_s=30.0,
        runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
        egress_allow_list=("api.example.com",),
        vault_path=None,
    )


def _valid_pack_ctx() -> PackAdmissionContext:
    return PackAdmissionContext(
        pack_id="cognic.test_pack",
        pack_version="v1.0.0",
        pack_artifact_digest="sha256:" + "1" * 64,
        risk_tier="internal_write",
        declares_dynamic_install=False,
        profile="production",
    )


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


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
    object_store = LocalObjectStoreAdapter(root=tmp_path / "objects")
    audit_store = AuditStore(engine)
    dh_store = DecisionHistoryStore(engine)
    return CheckpointStore(
        object_store=object_store,
        audit_store=audit_store,
        decision_history_store=dh_store,
        settings=_StubSettings(),
    )


def _make_mock_docker() -> MagicMock:
    """Mock aiodocker client — destroy() teardown path swallows
    DockerError 404 from .get() so the mock raises it consistently."""
    import aiodocker

    docker = MagicMock()
    docker.containers.get = AsyncMock(
        side_effect=aiodocker.exceptions.DockerError(404, "not found")
    )
    docker.networks.get = AsyncMock(side_effect=aiodocker.exceptions.DockerError(404, "not found"))
    return docker


def _make_backend(
    *,
    docker: MagicMock,
    dh_store: DecisionHistoryStore,
    audit_store: AuditStore,
    checkpoint_store: CheckpointStore,
) -> DockerSiblingSandboxBackend:
    rego = MagicMock()
    decision = MagicMock(allow=True, reasoning="")
    rego.evaluate = AsyncMock(return_value=decision)
    catalog = MagicMock()
    catalog.is_canonical.return_value = True
    catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
    catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
    return DockerSiblingSandboxBackend(
        docker_client=docker,
        image_catalog=catalog,
        credential_adapter=KernelDefaultCredentialAdapter(),
        rego_engine=rego,
        audit_store=audit_store,
        decision_history_store=dh_store,
        settings=_StubSettings(),  # type: ignore[arg-type]
        warm_pool=None,
        checkpoint_store=checkpoint_store,
    )


def _make_session(
    backend: DockerSiblingSandboxBackend,
    *,
    session_id: str = "sess-1",
    tenant_id: str = "tenant-a",
    actor_subject: str = "actor-1",
) -> DockerSiblingSession:
    """Construct a DockerSiblingSession bound to ``backend`` so
    session.destroy() routes through the real backend code path."""
    return DockerSiblingSession(
        session_id=session_id,
        policy=_valid_policy(),
        tenant_id=tenant_id,
        pack_context=_valid_pack_ctx(),
        created_at=datetime.now(UTC),
        warm_pool_hit=False,
        _backend=backend,
        _internal_network_name=f"net-{session_id}",
        _sidecar_container_name=f"{session_id}-proxy",
        _actor_subject=actor_subject,
        _egress_network_name=f"egress-{session_id}",
    )


async def _read_latest_chain_row(engine: AsyncEngine) -> dict[str, Any]:
    """Read the most recent decision_history row + return its payload."""
    import sqlalchemy as sa

    from cognic_agentos.core.decision_history import _decision_history

    async with engine.connect() as conn:
        result = await conn.execute(
            sa.select(_decision_history).order_by(_decision_history.c.sequence.desc()).limit(1)
        )
        row = result.first()
        assert row is not None, "expected at least one decision_history row"
        return dict(row._mapping)


async def _read_all_chain_rows(engine: AsyncEngine) -> list[dict[str, Any]]:
    """Read all decision_history rows ordered ASC by sequence."""
    import sqlalchemy as sa

    from cognic_agentos.core.decision_history import _decision_history

    async with engine.connect() as conn:
        result = await conn.execute(
            sa.select(_decision_history).order_by(_decision_history.c.sequence.asc())
        )
        return [dict(r._mapping) for r in result.fetchall()]


# ---------------------------------------------------------------------------
# Tests.
# ---------------------------------------------------------------------------


class TestDestroyWithoutCheckpointsEmitsBaselineDestroyedEvent:
    """Spec §3.1 destroy() extension: sessions with NO persisted
    checkpoints emit the Sprint-8A baseline destroyed event WITHOUT
    the ``retained_until`` + ``tombstone_object_key`` payload keys."""

    @pytest.mark.asyncio
    async def test_no_checkpoints_means_no_tombstone_keys(
        self,
        store: CheckpointStore,
        engine: AsyncEngine,
    ) -> None:
        docker = _make_mock_docker()
        backend = _make_backend(
            docker=docker,
            dh_store=store._dh_store,
            audit_store=store._audit_store,
            checkpoint_store=store,
        )
        session = _make_session(backend)

        await backend.destroy(session)

        # Latest row is the destroyed event; no tombstone keys.
        row = await _read_latest_chain_row(engine)
        assert row["event_type"] == "sandbox.lifecycle.destroyed"
        payload = row["payload"]
        assert "duration_s" in payload
        assert "retained_until" not in payload
        assert "tombstone_object_key" not in payload
        assert session._destroyed is True


class TestDestroyWithCheckpointsTombstonesSession:
    """Spec §3.1 destroy() extension + P1.r4 tombstone redesign:
    sessions with persisted checkpoints write the tombstone sentinel +
    the destroyed event carries the two new payload keys."""

    @pytest.mark.asyncio
    async def test_destroy_with_one_checkpoint_writes_tombstone_and_extends_payload(
        self,
        store: CheckpointStore,
        engine: AsyncEngine,
    ) -> None:
        # Pre-place a checkpoint via the store (NOT via session.checkpoint —
        # that requires a real docker exec).
        cid = await store.persist(
            session_id="sess-tombstone",
            tenant_id="tenant-a",
            label="test-cp",
            snapshot_bytes=b"snap",
            policy=_valid_policy(),
            pack_context=_valid_pack_ctx(),
            vault_lease_refs=(),
        )
        assert isinstance(cid, str)

        docker = _make_mock_docker()
        backend = _make_backend(
            docker=docker,
            dh_store=store._dh_store,
            audit_store=store._audit_store,
            checkpoint_store=store,
        )
        session = _make_session(
            backend,
            session_id="sess-tombstone",
            tenant_id="tenant-a",
            actor_subject="alice@bank",
        )

        await backend.destroy(session)

        # Confirm the tombstone sentinel exists at the expected key.
        tombstone_key = "tenant-a/sess-tombstone/_tombstoned.json"
        tombstone_bytes = await store._object_store.get("sandbox-checkpoints", tombstone_key)
        assert tombstone_bytes  # non-empty

        # The destroyed chain row carries both tombstone payload keys.
        rows = await _read_all_chain_rows(engine)
        destroyed_rows = [r for r in rows if r["event_type"] == "sandbox.lifecycle.destroyed"]
        assert len(destroyed_rows) == 1
        payload = destroyed_rows[0]["payload"]
        assert "duration_s" in payload
        assert "retained_until" in payload
        # retained_until is an ISO string parseable as a tz-aware datetime.
        retained = datetime.fromisoformat(payload["retained_until"])
        assert retained.tzinfo is not None
        assert payload["tombstone_object_key"] == tombstone_key

    @pytest.mark.asyncio
    async def test_tombstoned_by_comes_from_session_actor_subject(
        self,
        store: CheckpointStore,
        engine: AsyncEngine,
    ) -> None:
        """Per spec §3.1: tombstoned_by = session._actor_subject (NOT
        actor.subject — destroy() has no actor kwarg per Sprint-8A
        Protocol)."""
        await store.persist(
            session_id="sess-actor",
            tenant_id="tenant-a",
            label="test",
            snapshot_bytes=b"snap",
            policy=_valid_policy(),
            pack_context=_valid_pack_ctx(),
            vault_lease_refs=(),
        )
        docker = _make_mock_docker()
        backend = _make_backend(
            docker=docker,
            dh_store=store._dh_store,
            audit_store=store._audit_store,
            checkpoint_store=store,
        )
        session = _make_session(
            backend,
            session_id="sess-actor",
            tenant_id="tenant-a",
            actor_subject="bob@bank",
        )

        await backend.destroy(session)

        # Read the tombstone sentinel and confirm tombstoned_by.
        import json

        raw = await store._object_store.get(
            "sandbox-checkpoints", "tenant-a/sess-actor/_tombstoned.json"
        )
        parsed = json.loads(raw)
        assert parsed["tombstoned_by"] == "bob@bank"

    @pytest.mark.asyncio
    async def test_destroy_with_multiple_checkpoints_uses_single_tombstone(
        self,
        store: CheckpointStore,
        engine: AsyncEngine,
    ) -> None:
        """Per CheckpointStore.tombstone_session idempotency: even with
        multiple checkpoints, ONE tombstone sentinel covers the session."""
        for _ in range(3):
            await store.persist(
                session_id="sess-many",
                tenant_id="tenant-a",
                label="cp",
                snapshot_bytes=b"snap",
                policy=_valid_policy(),
                pack_context=_valid_pack_ctx(),
                vault_lease_refs=(),
            )

        docker = _make_mock_docker()
        backend = _make_backend(
            docker=docker,
            dh_store=store._dh_store,
            audit_store=store._audit_store,
            checkpoint_store=store,
        )
        session = _make_session(
            backend,
            session_id="sess-many",
            tenant_id="tenant-a",
        )
        await backend.destroy(session)

        # Only one tombstone sentinel under the session prefix.
        tombstones = []
        async for key in store._object_store.list_prefix(
            "sandbox-checkpoints", "tenant-a/sess-many/"
        ):
            if key.endswith("_tombstoned.json"):
                tombstones.append(key)
        assert len(tombstones) == 1


class TestDestroyIdempotent:
    """Per Sprint-8A: destroy() is idempotent. Sprint 8.5 T6 must
    preserve that: a second destroy() is a no-op for chain emission."""

    @pytest.mark.asyncio
    async def test_second_destroy_emits_no_extra_chain_row(
        self,
        store: CheckpointStore,
        engine: AsyncEngine,
    ) -> None:
        await store.persist(
            session_id="sess-idem",
            tenant_id="tenant-a",
            label="cp",
            snapshot_bytes=b"snap",
            policy=_valid_policy(),
            pack_context=_valid_pack_ctx(),
            vault_lease_refs=(),
        )
        docker = _make_mock_docker()
        backend = _make_backend(
            docker=docker,
            dh_store=store._dh_store,
            audit_store=store._audit_store,
            checkpoint_store=store,
        )
        session = _make_session(backend, session_id="sess-idem", tenant_id="tenant-a")

        await backend.destroy(session)
        before_rows = await _read_all_chain_rows(engine)
        before_count = sum(
            1 for r in before_rows if r["event_type"] == "sandbox.lifecycle.destroyed"
        )
        assert before_count == 1

        await backend.destroy(session)
        after_rows = await _read_all_chain_rows(engine)
        after_count = sum(1 for r in after_rows if r["event_type"] == "sandbox.lifecycle.destroyed")
        # Per spec §5 idempotency contract: second destroy emits 0 new
        # destroyed events.
        assert after_count == 1

    @pytest.mark.asyncio
    async def test_second_destroy_does_not_overwrite_tombstone_at(
        self,
        store: CheckpointStore,
        engine: AsyncEngine,
    ) -> None:
        """Tombstone idempotency per spec §4.1: a second destroy() MUST
        NOT overwrite ``tombstoned_at`` (would extend retention)."""
        import json

        await store.persist(
            session_id="sess-2x",
            tenant_id="tenant-a",
            label="cp",
            snapshot_bytes=b"snap",
            policy=_valid_policy(),
            pack_context=_valid_pack_ctx(),
            vault_lease_refs=(),
        )
        docker = _make_mock_docker()
        backend = _make_backend(
            docker=docker,
            dh_store=store._dh_store,
            audit_store=store._audit_store,
            checkpoint_store=store,
        )
        session = _make_session(backend, session_id="sess-2x", tenant_id="tenant-a")

        await backend.destroy(session)
        raw_first = await store._object_store.get(
            "sandbox-checkpoints", "tenant-a/sess-2x/_tombstoned.json"
        )
        first_tombstoned_at = json.loads(raw_first)["tombstoned_at"]

        # Manual second destroy on a NEW session struct (simulates a
        # cross-process retry attack — same session_id + tenant + has
        # checkpoints → store guarantees no overwrite).
        fresh = _make_session(backend, session_id="sess-2x", tenant_id="tenant-a")
        await backend.destroy(fresh)
        raw_second = await store._object_store.get(
            "sandbox-checkpoints", "tenant-a/sess-2x/_tombstoned.json"
        )
        second_tombstoned_at = json.loads(raw_second)["tombstoned_at"]
        # Idempotent at the storage layer per spec §4.1.
        assert first_tombstoned_at == second_tombstoned_at


__all__: list[str] = []

# Silence unused-import warnings for uuid (kept for parity with sibling
# test files; not used here).
_ = uuid
