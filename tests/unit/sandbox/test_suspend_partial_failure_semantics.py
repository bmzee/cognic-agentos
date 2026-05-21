"""Sprint 8.5 T6 P2.r2 — _do_suspend() partial-failure semantics.

Pins the audit-row vs runtime-state coherence invariant per spec §5.1
+ the T2 ``sandbox_lifecycle_suspended`` helper docstring contract.
Pre-P2.r2 the suspend body emitted the audit row BEFORE teardown +
side-blob write — a chain row could over-state reality (claim
suspended while resources were still running). P2.r2 reorder:

    1. take final checkpoint
    2. teardown container/sidecar/networks
    3. emit sandbox.lifecycle.suspended (captures record_id)
    4. write suspend_event_id side-blob (linkage for wake)
    5. flip session._suspended

This file pins all three failure windows the reorder addresses:

* Step 2 (teardown) fails → NO audit row + NO side-blob +
  session._suspended is False. Chain stays conservative (no false
  claim).
* Step 3 (audit emit) fails → NO audit row + NO side-blob +
  container released (lost-evidence but no false claim).
  *NOT pinned here* because audit-emit failure paths route through
  ``DecisionHistoryStore.append_with_precondition`` which has its
  own failure-mode tests at the Sprint-2 level; the relevant
  invariant for T6 is "no audit ⇒ no side-blob" which is implicit
  from the strict ordering.
* Step 4 (side-blob write) fails → audit row IS emitted +
  side-blob absent → a subsequent ``wake()`` refuses with
  ``sandbox_wake_checkpoint_corrupt`` per the P1.r6 fail-closed
  contract pinned by ``test_wake_checkpoint_corrupt.py``.

A regression that re-orders these steps back to "emit before
teardown" would break ``test_audit_row_not_emitted_when_teardown_fails``
loudly — that's the load-bearing pin.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

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
from cognic_agentos.sandbox.admission import KernelDefaultCredentialAdapter
from cognic_agentos.sandbox.backends.docker_sibling import (
    DockerSiblingSandboxBackend,
    DockerSiblingSession,
)
from cognic_agentos.sandbox.checkpoint_store import CheckpointStore
from cognic_agentos.sandbox.policy import PackAdmissionContext, SandboxPolicy
from cognic_agentos.sandbox.protocol import CheckpointId, SandboxLifecycleRefused

_BUCKET = "sandbox-checkpoints"


class _StubSettings:
    """Module-private structural stub carrying both the
    _CheckpointSettings fields AND the admit_policy-revalidate fields
    consumed by wake() Step 4 (per-tenant max caps). P2.r3 extension —
    pre-fix the stub only carried the checkpoint settings and the
    end-to-end wake() assertion blew up at admit_policy Step 5."""

    # _CheckpointSettings Protocol
    sandbox_checkpoint_retention_s: int = 86_400
    sandbox_max_checkpoints_per_session: int = 10
    sandbox_reaper_interval_s: int = 300

    # admit_policy revalidate (wake Step 4) per-tenant max caps
    sandbox_per_tenant_max_cpu: float = 4.0
    sandbox_per_tenant_max_memory: int = 4096
    sandbox_per_tenant_max_walltime: float = 300.0


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
        pack_id="cognic.t",
        pack_version="v1.0.0",
        pack_artifact_digest="sha256:" + "1" * 64,
        risk_tier="internal_write",
        declares_dynamic_install=False,
        profile="production",
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
    audit_store = AuditStore(engine)
    dh_store = DecisionHistoryStore(engine)
    return CheckpointStore(
        object_store=object_store,
        audit_store=audit_store,
        decision_history_store=dh_store,
        settings=_StubSettings(),
    )


def _make_backend(store: CheckpointStore, engine: AsyncEngine) -> DockerSiblingSandboxBackend:
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
        audit_store=AuditStore(engine),
        decision_history_store=DecisionHistoryStore(engine),
        settings=_StubSettings(),  # type: ignore[arg-type]
        warm_pool=None,
        checkpoint_store=store,
    )


def _make_session(backend: DockerSiblingSandboxBackend) -> DockerSiblingSession:
    return DockerSiblingSession(
        session_id="sess-suspend",
        policy=_valid_policy(),
        tenant_id="tenant-a",
        pack_context=_valid_pack_ctx(),
        created_at=datetime.now(UTC),
        warm_pool_hit=False,
        _backend=backend,
        _internal_network_name="net-sess-suspend",
        _sidecar_container_name="sess-suspend-proxy",
        _actor_subject="actor-1",
        _egress_network_name="egress-sess-suspend",
    )


async def _read_suspended_chain_rows(engine: AsyncEngine) -> list[dict[str, Any]]:
    """Return all chain rows with decision_type='sandbox.lifecycle.suspended'."""
    async with engine.connect() as conn:
        result = await conn.execute(
            select(_decision_history).where(
                _decision_history.c.event_type == "sandbox.lifecycle.suspended"
            )
        )
        return [dict(r._mapping) for r in result.fetchall()]


# ---------------------------------------------------------------------------
# Regression 1 — teardown failure MUST suppress the suspended audit row.
# This is the LOAD-BEARING pin for the P2.r2 reorder: a regression that
# moves the audit emit back ahead of teardown surfaces here.
# ---------------------------------------------------------------------------


class TestAuditRowEmittedOnlyAfterTeardown:
    """Pin spec §5.1 + T2 helper-docstring contract: the suspended chain
    row is emitted AFTER container/Pod release. A teardown failure MUST
    leave the chain unmarked + the session observably unsuspended."""

    @pytest.mark.asyncio
    async def test_audit_row_not_emitted_when_teardown_fails(
        self,
        store: CheckpointStore,
        object_store: LocalObjectStoreAdapter,
        engine: AsyncEngine,
    ) -> None:
        """Teardown raises BEFORE audit emit → NO suspended row in chain,
        session._suspended is False, no side-blob persisted.

        TM-revert pin: a regression that re-orders audit emit ahead of
        teardown (the pre-P2.r2 code path) would let the chain row land
        even though teardown fails — this test would then find 1
        suspended row instead of 0.
        """
        backend = _make_backend(store, engine)
        session = _make_session(backend)

        # Bypass the real _do_checkpoint — the test is about _do_suspend
        # ordering, not workspace-tar mechanics. The fake checkpoint id
        # has the canonical 32-hex shape so it doesn't trip
        # _validate_checkpoint_id_or_raise downstream.
        fake_cid = CheckpointId("a" * 32)
        backend._do_checkpoint = AsyncMock(return_value=fake_cid)  # type: ignore[method-assign]

        # Inject teardown failure.
        backend._teardown_session_state = AsyncMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("teardown blew up")
        )

        # Spy on the audit-emit + side-blob-write seams so we can also
        # assert directly that they were NOT called (the chain query is
        # the primary pin; these are defence-in-depth assertions).
        write_blob_spy = AsyncMock()
        backend._write_suspend_event_id = write_blob_spy  # type: ignore[method-assign]

        # _do_suspend MUST propagate the teardown failure (not swallow).
        with pytest.raises(RuntimeError, match="teardown blew up"):
            await session.suspend()

        # PRIMARY ASSERTION — chain has NO suspended row.
        rows = await _read_suspended_chain_rows(engine)
        assert rows == [], (
            f"P2.r2 violation: teardown failed but suspended audit row was "
            f"still emitted — chain over-states reality. rows={rows}"
        )

        # Defence-in-depth.
        assert session._suspended is False, (
            "session._suspended flipped despite teardown failure — "
            "the flag flip MUST come after the audit row + side-blob "
            "are durable"
        )
        write_blob_spy.assert_not_awaited()

        # No side-blob persisted (cross-checked at storage level).
        with pytest.raises(FileNotFoundError):
            await object_store.get(_BUCKET, f"tenant-a/sess-suspend/{fake_cid}.suspend_event_id")


# ---------------------------------------------------------------------------
# Regression 2 — side-blob write failure AFTER audit emit leaves a known
# partial state that wake() correctly refuses as corrupt.
# ---------------------------------------------------------------------------


class TestSideBlobWriteFailureLeavesCorruptState:
    """Pin the P1.r6 + P2.r2 interaction END-TO-END: when the side-blob
    write fails AFTER the suspended audit row is emitted + teardown
    succeeded, a subsequent ``wake()`` call MUST refuse with
    ``sandbox_wake_checkpoint_corrupt`` per the P1.r6 fail-closed
    contract.

    P2.r3 strengthening: the fake ``_do_checkpoint`` now actually
    persists snapshot + metadata via ``CheckpointStore.persist()``
    (mirrors production Step 1 state) so the downstream ``wake()``
    call traverses Steps 1-4 (tombstone-load → load_latest → tenant
    cross-check → admit_policy revalidate) and reaches Step 5
    (suspend_event_id linkage read) where the corrupt-linkage path
    fires. Pre-P2.r3 the test stopped at "audit row + side-blob
    absent" assertions without proving wake() reads the partial state
    correctly — the regression now drives the full corrupt path.

    This is the 'known partial-failure window' the P2.r2 docstring
    documents as acceptable: conservative chain claim (suspended is
    true; container IS released), wake fail-closed via the corrupt
    taxonomy.
    """

    @pytest.mark.asyncio
    async def test_audit_row_present_but_side_blob_missing_when_write_fails(
        self,
        store: CheckpointStore,
        object_store: LocalObjectStoreAdapter,
        engine: AsyncEngine,
    ) -> None:
        """Teardown succeeds, audit emit succeeds, side-blob write
        raises → chain has 1 suspended row + side-blob absent + a
        subsequent ``wake()`` refuses with
        ``sandbox_wake_checkpoint_corrupt``."""
        backend = _make_backend(store, engine)
        session = _make_session(backend)

        # P2.r3 — fake _do_checkpoint that ACTUALLY persists snapshot +
        # metadata via CheckpointStore.persist() so wake() Steps 1-4
        # succeed before reaching Step 5 (suspend_event_id read). Pre-
        # P2.r3 the mock returned a CheckpointId without persisting any
        # bytes — wake() would have refused with checkpoint_not_found
        # instead of the intended corrupt path.
        async def _persist_real_checkpoint(
            session: DockerSiblingSession, label: str
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

        # Teardown succeeds (default no-op AsyncMock).
        teardown_spy = AsyncMock()
        backend._teardown_session_state = teardown_spy  # type: ignore[method-assign]

        # Inject side-blob-write failure.
        backend._write_suspend_event_id = AsyncMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("side-blob write blew up")
        )

        with pytest.raises(RuntimeError, match="side-blob write blew up"):
            await session.suspend()

        # Teardown DID run + complete before the failure.
        teardown_spy.assert_awaited_once()

        # Chain has exactly 1 suspended row — the audit claim that
        # the container was released is HONEST (teardown completed).
        rows = await _read_suspended_chain_rows(engine)
        assert len(rows) == 1, (
            f"Expected exactly one suspended chain row (audit emit ran + "
            f"completed before the side-blob failure); got {len(rows)}: {rows}"
        )

        # ===== STRENGTHENED P2.r3 END-TO-END ASSERTION =====
        # A subsequent wake() reaches Step 5 (suspend-linkage read)
        # because Steps 1-4 succeed against the persisted snapshot +
        # metadata, and refuses with sandbox_wake_checkpoint_corrupt
        # per the P1.r6 fail-closed contract.
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

        # session._suspended remains False because the flag flip is
        # the LAST step + was not reached. A subsequent destroy() would
        # therefore tombstone normally (treating the session as a
        # live-but-now-released session that still needs operator
        # cleanup of the corrupt linkage).
        assert session._suspended is False
