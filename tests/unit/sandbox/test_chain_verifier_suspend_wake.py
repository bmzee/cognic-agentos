"""Sprint 8.5 T8 — ChainVerifier.verify_suspend_wake_linkage tests.

Verifies the suspend→wake audit-chain linkage assertion per spec §5.2.
``core/chain_verifier.py`` is a Sprint-2 critical-controls module on the
durable 95% line / 90% branch coverage gate — the new assertion code is
held to the same floor.

**Test-real mandate.** Every chain row in these tests is created via the
REAL sandbox lifecycle emitters (``sandbox_lifecycle_suspended`` /
``sandbox_lifecycle_woken`` / ``sandbox_lifecycle_checkpointed``) against
a REAL ``DecisionHistoryStore`` backed by a real aiosqlite engine. Rows
are NEVER hand-constructed dicts and NEVER raw-INSERTed — the explicit
user warning is that "tests construct fake chain rows that pass because
the verifier is too shallow".

The deliberate exception is raw-UPDATE — used ONLY for failure modes the
typed emitters structurally cannot produce, and ONLY on otherwise-real
emitter-produced rows (every row's CONTENT is emitter-written; raw-UPDATE
rewires exactly one field). Four tests use it, each commented inline:
``test_malformed_non_uuid_suspend_event_id_fails_closed`` +
``test_missing_suspend_event_id_key_fails_closed`` +
``test_missing_restored_checkpoint_id_key_fails_closed`` (the typed
emitter always writes well-formed payload keys) and
``test_wake_before_suspend_linkage_fails`` (``record_id`` is
emitter-generated, so a woken row cannot be emitted carrying a
not-yet-emitted suspended row's id — the linkage pointer is rewired
after both real rows exist).

Every negative test asserts the EXACT ``break_kind`` string — a test
that only asserts ``is_clean is False`` is too shallow. Each negative
test also keeps every OTHER linkage dimension matched so the failure
isolates to the one invariant under test (e.g. the cross-tenant test
keeps session_id + checkpoint equal; the ordering test keeps tenant +
session + checkpoint equal).
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.chain_verifier import (
    ChainVerifier,
    SuspendWakeLinkageReport,
    _coerce_record_id,
)
from cognic_agentos.core.decision_history import (
    DecisionHistoryStore,
    _decision_history,
)
from cognic_agentos.sandbox.audit import (
    sandbox_lifecycle_checkpointed,
    sandbox_lifecycle_suspended,
    sandbox_lifecycle_woken,
)
from cognic_agentos.sandbox.protocol import CheckpointId


@pytest.fixture
async def engine(tmp_path: Any) -> Any:
    """Per-test aiosqlite engine with both governance chains seeded.

    Mirrors the fixture pattern at
    ``tests/unit/sandbox/backends/test_kubernetes_pod_checkpoint_unit.py``
    — ``_metadata.create_all`` builds both ``audit_event`` +
    ``decision_history`` tables (they share ``_metadata``) and the
    ``_chain_heads`` rows are seeded for both chains so the
    ``DecisionHistoryStore`` append path's chain-head ``FOR UPDATE``
    lock has a row to lock.
    """

    url = f"sqlite+aiosqlite:///{tmp_path / 'suspend_wake.db'}"
    eng: AsyncEngine = create_async_engine(url)
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
def store(engine: AsyncEngine) -> DecisionHistoryStore:
    return DecisionHistoryStore(engine)


# ---------------------------------------------------------------------------
# Requirement 5 — honest suspend → wake passes verification.
# ---------------------------------------------------------------------------


async def test_honest_suspend_wake_round_trip_is_clean(
    engine: AsyncEngine, store: DecisionHistoryStore
) -> None:
    """Requirement 5: an honest suspend→wake pair verifies clean.

    Emits a real ``sandbox.lifecycle.suspended`` row, captures the
    returned ``record_id``, then emits a real ``sandbox.lifecycle.woken``
    row linking back to it with the SAME ``final_checkpoint_id`` value.
    ``verify_suspend_wake_linkage()`` must return ``is_clean=True``.
    """

    checkpoint_id = CheckpointId("cp-honest-round-trip")
    suspend_record_id, _ = await sandbox_lifecycle_suspended(
        store,
        tenant_id="tenant-a",
        actor_id="actor-1",
        trace_id="trace-suspend",
        session_id="sess-honest",
        final_checkpoint_id=checkpoint_id,
    )

    await sandbox_lifecycle_woken(
        store,
        tenant_id="tenant-a",
        actor_id="actor-1",
        trace_id="trace-wake",
        session_id="sess-honest",
        restored_from_checkpoint_id=checkpoint_id,
        suspend_event_id=suspend_record_id,
    )

    report = await ChainVerifier(engine, "decision_history").verify_suspend_wake_linkage()

    assert isinstance(report, SuspendWakeLinkageReport)
    assert report.is_clean is True
    assert report.chain_id == "decision_history"
    assert report.records_checked == 1
    assert report.break_kind is None
    assert report.first_break_record_id is None
    assert report.detail is None


async def test_multi_pair_honest_chain_is_clean_records_checked_two(
    engine: AsyncEngine, store: DecisionHistoryStore
) -> None:
    """Multi-row clean: TWO honest suspend→wake pairs in one chain.

    Confirms ``records_checked`` counts WOKEN rows (== 2 here), not
    every row in the chain, and that the verifier walks past the first
    clean pair to inspect the second.
    """

    # Pair 1.
    suspend_1, _ = await sandbox_lifecycle_suspended(
        store,
        tenant_id="tenant-a",
        actor_id="actor-1",
        trace_id="trace-s1",
        session_id="sess-1",
        final_checkpoint_id=CheckpointId("cp-1"),
    )
    await sandbox_lifecycle_woken(
        store,
        tenant_id="tenant-a",
        actor_id="actor-1",
        trace_id="trace-w1",
        session_id="sess-1",
        restored_from_checkpoint_id=CheckpointId("cp-1"),
        suspend_event_id=suspend_1,
    )

    # Pair 2 — distinct session + checkpoint.
    suspend_2, _ = await sandbox_lifecycle_suspended(
        store,
        tenant_id="tenant-b",
        actor_id="actor-2",
        trace_id="trace-s2",
        session_id="sess-2",
        final_checkpoint_id=CheckpointId("cp-2"),
    )
    await sandbox_lifecycle_woken(
        store,
        tenant_id="tenant-b",
        actor_id="actor-2",
        trace_id="trace-w2",
        session_id="sess-2",
        restored_from_checkpoint_id=CheckpointId("cp-2"),
        suspend_event_id=suspend_2,
    )

    report = await ChainVerifier(engine, "decision_history").verify_suspend_wake_linkage()

    assert report.is_clean is True
    assert report.records_checked == 2
    assert report.break_kind is None


async def test_empty_chain_with_no_woken_rows_is_clean(
    engine: AsyncEngine, store: DecisionHistoryStore
) -> None:
    """A chain carrying only checkpointed / suspended rows (no woken
    rows) verifies clean with ``records_checked == 0`` — the verifier
    only inspects woken rows.
    """

    await sandbox_lifecycle_checkpointed(
        store,
        tenant_id="tenant-a",
        actor_id="actor-1",
        trace_id="trace-cp",
        session_id="sess-x",
        checkpoint_id=CheckpointId("cp-only"),
        label="manual",
        policy_digest="digest-abc",
    )
    await sandbox_lifecycle_suspended(
        store,
        tenant_id="tenant-a",
        actor_id="actor-1",
        trace_id="trace-s",
        session_id="sess-x",
        final_checkpoint_id=CheckpointId("cp-only"),
    )

    report = await ChainVerifier(engine, "decision_history").verify_suspend_wake_linkage()

    assert report.is_clean is True
    assert report.records_checked == 0


# ---------------------------------------------------------------------------
# Requirement 3 — forged wake (no matching suspend row) fails.
# ---------------------------------------------------------------------------


async def test_forged_wake_no_matching_suspend_row_fails(
    engine: AsyncEngine, store: DecisionHistoryStore
) -> None:
    """Requirement 3: a woken row whose ``suspend_event_id`` is a random
    UUID with NO matching suspend row fails verification with the EXACT
    ``break_kind == "suspend_row_not_found"``.
    """

    forged_suspend_event_id = uuid.uuid4()

    woken_record_id, _ = await sandbox_lifecycle_woken(
        store,
        tenant_id="tenant-a",
        actor_id="actor-1",
        trace_id="trace-wake",
        session_id="sess-forged",
        restored_from_checkpoint_id=CheckpointId("cp-forged"),
        suspend_event_id=forged_suspend_event_id,
    )

    report = await ChainVerifier(engine, "decision_history").verify_suspend_wake_linkage()

    assert report.is_clean is False
    assert report.break_kind == "suspend_row_not_found"
    assert report.records_checked == 1
    assert report.first_break_record_id == woken_record_id
    assert report.detail is not None
    assert str(forged_suspend_event_id) in report.detail


# ---------------------------------------------------------------------------
# Requirement 4 — wrong-checkpoint linkage fails.
# ---------------------------------------------------------------------------


async def test_wrong_checkpoint_linkage_fails(
    engine: AsyncEngine, store: DecisionHistoryStore
) -> None:
    """Requirement 4: a woken row that links to a REAL suspend row but
    claims ``restored_from_checkpoint_id`` of a DIFFERENT checkpoint
    than the suspend row's ``final_checkpoint_id`` fails with the EXACT
    ``break_kind == "checkpoint_id_mismatch"``.
    """

    cp_a = CheckpointId("cp-A-suspend-final")
    cp_b = CheckpointId("cp-B-different")
    assert cp_a != cp_b

    suspend_record_id, _ = await sandbox_lifecycle_suspended(
        store,
        tenant_id="tenant-a",
        actor_id="actor-1",
        trace_id="trace-suspend",
        session_id="sess-mismatch",
        final_checkpoint_id=cp_a,
    )

    woken_record_id, _ = await sandbox_lifecycle_woken(
        store,
        tenant_id="tenant-a",
        actor_id="actor-1",
        trace_id="trace-wake",
        session_id="sess-mismatch",
        restored_from_checkpoint_id=cp_b,
        suspend_event_id=suspend_record_id,
    )

    report = await ChainVerifier(engine, "decision_history").verify_suspend_wake_linkage()

    assert report.is_clean is False
    assert report.break_kind == "checkpoint_id_mismatch"
    assert report.records_checked == 1
    assert report.first_break_record_id == woken_record_id
    assert report.detail is not None
    assert cp_a in report.detail
    assert cp_b in report.detail


# ---------------------------------------------------------------------------
# Requirement: wake points at a non-suspend row.
# ---------------------------------------------------------------------------


async def test_wake_points_at_checkpointed_row_wrong_decision_type(
    engine: AsyncEngine, store: DecisionHistoryStore
) -> None:
    """A woken row whose ``suspend_event_id`` points at a REAL
    ``sandbox.lifecycle.checkpointed`` row (not a suspended row) fails
    with the EXACT ``break_kind == "suspend_event_id_wrong_decision_type"``.
    """

    checkpoint_record_id, _ = await sandbox_lifecycle_checkpointed(
        store,
        tenant_id="tenant-a",
        actor_id="actor-1",
        trace_id="trace-cp",
        session_id="sess-wrong-type",
        checkpoint_id=CheckpointId("cp-wrong-type"),
        label="manual",
        policy_digest="digest-xyz",
    )

    woken_record_id, _ = await sandbox_lifecycle_woken(
        store,
        tenant_id="tenant-a",
        actor_id="actor-1",
        trace_id="trace-wake",
        session_id="sess-wrong-type",
        restored_from_checkpoint_id=CheckpointId("cp-wrong-type"),
        # Points at a checkpointed row, NOT a suspended row.
        suspend_event_id=checkpoint_record_id,
    )

    report = await ChainVerifier(engine, "decision_history").verify_suspend_wake_linkage()

    assert report.is_clean is False
    assert report.break_kind == "suspend_event_id_wrong_decision_type"
    assert report.records_checked == 1
    assert report.first_break_record_id == woken_record_id
    assert report.detail is not None
    assert "sandbox.lifecycle.checkpointed" in report.detail


# ---------------------------------------------------------------------------
# Requirement: session-id mismatch fails.
# ---------------------------------------------------------------------------


async def test_session_id_mismatch_fails(engine: AsyncEngine, store: DecisionHistoryStore) -> None:
    """A woken row that links to a REAL suspend row but carries a
    DIFFERENT ``session_id`` than the suspended row fails with the
    EXACT ``break_kind == "session_id_mismatch"``.

    Confirms Step 4 of the spec §5.2 assertion. ``session_id`` is a
    payload key (NOT a row column) per ``sandbox/audit.py:165`` — both
    rows carry it under ``payload["session_id"]``.
    """

    checkpoint_id = CheckpointId("cp-shared")
    suspend_record_id, _ = await sandbox_lifecycle_suspended(
        store,
        tenant_id="tenant-a",
        actor_id="actor-1",
        trace_id="trace-suspend",
        session_id="sess-A",
        final_checkpoint_id=checkpoint_id,
    )

    woken_record_id, _ = await sandbox_lifecycle_woken(
        store,
        tenant_id="tenant-a",
        actor_id="actor-1",
        trace_id="trace-wake",
        # Different session than the suspend row.
        session_id="sess-B",
        restored_from_checkpoint_id=checkpoint_id,
        suspend_event_id=suspend_record_id,
    )

    report = await ChainVerifier(engine, "decision_history").verify_suspend_wake_linkage()

    assert report.is_clean is False
    assert report.break_kind == "session_id_mismatch"
    assert report.records_checked == 1
    assert report.first_break_record_id == woken_record_id
    assert report.detail is not None
    assert "sess-A" in report.detail
    assert "sess-B" in report.detail


# ---------------------------------------------------------------------------
# Malformed linkage — corrupt-data cases (raw-UPDATE exception; see the
# module docstring — these payload shapes cannot be produced through the
# typed emitter).
# ---------------------------------------------------------------------------


async def test_malformed_non_uuid_suspend_event_id_fails_closed(
    engine: AsyncEngine, store: DecisionHistoryStore
) -> None:
    """A woken row whose ``suspend_event_id`` payload value is not a
    parseable UUID fails closed with the EXACT
    ``break_kind == "woken_missing_suspend_event_id"``.

    DELIBERATE RAW-UPDATE EXCEPTION: the typed emitter
    ``sandbox_lifecycle_woken`` takes ``suspend_event_id: uuid.UUID``
    and serialises ``str(uuid)`` into the payload, so a non-UUID value
    cannot be produced through the emitter. This single corrupt-data
    case emits a REAL woken row via the emitter, then raw-updates ONLY
    the ``payload["suspend_event_id"]`` key to a non-UUID string — the
    minimal mutation needed to exercise the fail-closed UUID-parse path.
    The verifier must NOT crash on the malformed value.
    """

    woken_record_id, _ = await sandbox_lifecycle_woken(
        store,
        tenant_id="tenant-a",
        actor_id="actor-1",
        trace_id="trace-wake",
        session_id="sess-corrupt",
        restored_from_checkpoint_id=CheckpointId("cp-corrupt"),
        suspend_event_id=uuid.uuid4(),
    )

    # Read the real persisted payload back, corrupt ONLY the
    # suspend_event_id key, write it back. Everything else stays as the
    # emitter produced it.
    async with engine.begin() as conn:
        row = (
            await conn.execute(
                _decision_history.select().where(_decision_history.c.record_id == woken_record_id)
            )
        ).one()
        corrupt_payload: dict[str, Any] = dict(row.payload)
        corrupt_payload["suspend_event_id"] = "not-a-uuid"
        await conn.execute(
            update(_decision_history)
            .where(_decision_history.c.record_id == woken_record_id)
            .values(payload=corrupt_payload)
        )

    report = await ChainVerifier(engine, "decision_history").verify_suspend_wake_linkage()

    assert report.is_clean is False
    assert report.break_kind == "woken_missing_suspend_event_id"
    assert report.records_checked == 1
    assert report.first_break_record_id == woken_record_id
    assert report.detail is not None
    assert "not-a-uuid" in report.detail


async def test_missing_suspend_event_id_key_fails_closed(
    engine: AsyncEngine, store: DecisionHistoryStore
) -> None:
    """A woken row with NO ``suspend_event_id`` payload key fails closed
    with the EXACT ``break_kind == "woken_missing_suspend_event_id"``.

    DELIBERATE RAW-UPDATE EXCEPTION (see the malformed-uuid test above):
    the typed emitter always writes ``suspend_event_id``, so the
    key-absent case is produced by deleting the key from a REAL woken
    row's persisted payload.
    """

    woken_record_id, _ = await sandbox_lifecycle_woken(
        store,
        tenant_id="tenant-a",
        actor_id="actor-1",
        trace_id="trace-wake",
        session_id="sess-no-key",
        restored_from_checkpoint_id=CheckpointId("cp-no-key"),
        suspend_event_id=uuid.uuid4(),
    )

    async with engine.begin() as conn:
        row = (
            await conn.execute(
                _decision_history.select().where(_decision_history.c.record_id == woken_record_id)
            )
        ).one()
        payload: dict[str, Any] = dict(row.payload)
        del payload["suspend_event_id"]
        await conn.execute(
            update(_decision_history)
            .where(_decision_history.c.record_id == woken_record_id)
            .values(payload=payload)
        )

    report = await ChainVerifier(engine, "decision_history").verify_suspend_wake_linkage()

    assert report.is_clean is False
    assert report.break_kind == "woken_missing_suspend_event_id"
    assert report.records_checked == 1
    assert report.first_break_record_id == woken_record_id


async def test_missing_restored_checkpoint_id_key_fails_closed(
    engine: AsyncEngine, store: DecisionHistoryStore
) -> None:
    """A woken row with NO ``restored_from_checkpoint_id`` payload key
    fails closed with the EXACT
    ``break_kind == "woken_missing_restored_checkpoint_id"``.

    DELIBERATE RAW-UPDATE EXCEPTION: the typed emitter always writes
    ``restored_from_checkpoint_id``; key-absent is produced by deleting
    it from a REAL woken row's payload. The suspend row is REAL and
    correctly linked so the failure is unambiguously the missing-key
    path (NOT a downstream linkage failure).
    """

    suspend_record_id, _ = await sandbox_lifecycle_suspended(
        store,
        tenant_id="tenant-a",
        actor_id="actor-1",
        trace_id="trace-suspend",
        session_id="sess-no-cp-key",
        final_checkpoint_id=CheckpointId("cp-no-cp-key"),
    )
    woken_record_id, _ = await sandbox_lifecycle_woken(
        store,
        tenant_id="tenant-a",
        actor_id="actor-1",
        trace_id="trace-wake",
        session_id="sess-no-cp-key",
        restored_from_checkpoint_id=CheckpointId("cp-no-cp-key"),
        suspend_event_id=suspend_record_id,
    )

    async with engine.begin() as conn:
        row = (
            await conn.execute(
                _decision_history.select().where(_decision_history.c.record_id == woken_record_id)
            )
        ).one()
        payload: dict[str, Any] = dict(row.payload)
        del payload["restored_from_checkpoint_id"]
        await conn.execute(
            update(_decision_history)
            .where(_decision_history.c.record_id == woken_record_id)
            .values(payload=payload)
        )

    report = await ChainVerifier(engine, "decision_history").verify_suspend_wake_linkage()

    assert report.is_clean is False
    assert report.break_kind == "woken_missing_restored_checkpoint_id"
    assert report.records_checked == 1
    assert report.first_break_record_id == woken_record_id


# ---------------------------------------------------------------------------
# Tenant-isolation parity — cross-tenant linkage must NOT verify clean.
# ---------------------------------------------------------------------------


async def test_cross_tenant_linkage_fails(engine: AsyncEngine, store: DecisionHistoryStore) -> None:
    """A woken row for tenant B that links to a REAL suspended row for
    tenant A fails with the EXACT ``break_kind == "tenant_id_mismatch"``.

    The woken row keeps the SAME ``session_id`` and the SAME checkpoint
    id as the suspended row — so the only thing that differs is the
    row-level ``tenant_id``. Without the invariant-6 parity check the
    verifier would reach step 4 / step 5, see matching session +
    checkpoint strings, and verify CLEAN — a cross-tenant linkage hole
    in a bank evidence verifier.

    ``tenant_id`` is a ``decision_history`` ROW COLUMN (the emitters
    take it as the ``tenant_id=`` kwarg), so this forgery is produced
    entirely through the real emitters — NO raw update needed.
    """

    checkpoint_id = CheckpointId("cp-cross-tenant")
    # Suspended row belongs to tenant-a.
    suspend_record_id, _ = await sandbox_lifecycle_suspended(
        store,
        tenant_id="tenant-a",
        actor_id="actor-1",
        trace_id="trace-suspend",
        session_id="sess-shared",
        final_checkpoint_id=checkpoint_id,
    )

    # Woken row belongs to tenant-b but links at tenant-a's suspend row,
    # with identical session_id + checkpoint id.
    woken_record_id, _ = await sandbox_lifecycle_woken(
        store,
        tenant_id="tenant-b",
        actor_id="actor-2",
        trace_id="trace-wake",
        session_id="sess-shared",
        restored_from_checkpoint_id=checkpoint_id,
        suspend_event_id=suspend_record_id,
    )

    report = await ChainVerifier(engine, "decision_history").verify_suspend_wake_linkage()

    assert report.is_clean is False
    assert report.break_kind == "tenant_id_mismatch"
    assert report.records_checked == 1
    assert report.first_break_record_id == woken_record_id
    assert report.detail is not None
    assert "tenant-a" in report.detail
    assert "tenant-b" in report.detail


# ---------------------------------------------------------------------------
# Causal ordering — wake-before-suspend linkage must NOT verify clean.
# ---------------------------------------------------------------------------


async def test_wake_before_suspend_linkage_fails(
    engine: AsyncEngine, store: DecisionHistoryStore
) -> None:
    """A woken row that links FORWARD to a suspended row appearing
    LATER in the chain fails with the EXACT
    ``break_kind == "suspend_row_not_before_woken_row"``.

    ``suspend_event_id`` is the ``record_id`` returned by an EARLIER
    suspend emit — the suspended row MUST precede the woken row in
    chain sequence. Here the woken row is emitted FIRST (lower
    sequence) and the suspended row SECOND (higher sequence); the woken
    row's ``tenant_id`` + ``session_id`` + checkpoint id all MATCH the
    suspended row, so the failure isolates purely to the ordering
    invariant — it is not masked by a tenant / session / checkpoint
    mismatch.

    DELIBERATE RAW-UPDATE EXCEPTION: ``record_id`` is generated inside
    the append path (uuid4), so a woken row cannot be emitted carrying
    the not-yet-emitted suspended row's real ``record_id``. This test
    emits a REAL woken row first (with a placeholder
    ``suspend_event_id``), emits the REAL suspended row second, then
    raw-updates ONLY the woken row's ``payload["suspend_event_id"]`` to
    the suspended row's real ``record_id``. Same exception class as the
    malformed-linkage tests: the typed emitter cannot produce this
    ordering; every row's CONTENT is emitter-produced — only the
    linkage pointer is rewired.
    """

    checkpoint_id = CheckpointId("cp-ordering")

    # Woken row emitted FIRST → lower sequence. Placeholder linkage.
    woken_record_id, _ = await sandbox_lifecycle_woken(
        store,
        tenant_id="tenant-a",
        actor_id="actor-1",
        trace_id="trace-wake",
        session_id="sess-ordering",
        restored_from_checkpoint_id=checkpoint_id,
        suspend_event_id=uuid.uuid4(),
    )

    # Suspended row emitted SECOND → higher sequence. Matching tenant +
    # session + checkpoint so only the ordering differs.
    suspend_record_id, _ = await sandbox_lifecycle_suspended(
        store,
        tenant_id="tenant-a",
        actor_id="actor-1",
        trace_id="trace-suspend",
        session_id="sess-ordering",
        final_checkpoint_id=checkpoint_id,
    )

    # Rewire ONLY the woken row's suspend_event_id to the real (later)
    # suspended row's record_id.
    async with engine.begin() as conn:
        row = (
            await conn.execute(
                _decision_history.select().where(_decision_history.c.record_id == woken_record_id)
            )
        ).one()
        payload: dict[str, Any] = dict(row.payload)
        payload["suspend_event_id"] = str(suspend_record_id)
        await conn.execute(
            update(_decision_history)
            .where(_decision_history.c.record_id == woken_record_id)
            .values(payload=payload)
        )

    report = await ChainVerifier(engine, "decision_history").verify_suspend_wake_linkage()

    assert report.is_clean is False
    assert report.break_kind == "suspend_row_not_before_woken_row"
    assert report.records_checked == 1
    assert report.first_break_record_id == woken_record_id
    assert report.detail is not None


# ---------------------------------------------------------------------------
# First-break semantics + ordering.
# ---------------------------------------------------------------------------


async def test_first_break_returned_when_second_pair_breaks(
    engine: AsyncEngine, store: DecisionHistoryStore
) -> None:
    """With a clean pair followed by a broken pair, the verifier returns
    the FIRST break (the broken second pair) and ``records_checked``
    counts both woken rows inspected up to and including the broken one.
    """

    # Clean pair 1.
    suspend_1, _ = await sandbox_lifecycle_suspended(
        store,
        tenant_id="tenant-a",
        actor_id="actor-1",
        trace_id="trace-s1",
        session_id="sess-1",
        final_checkpoint_id=CheckpointId("cp-1"),
    )
    await sandbox_lifecycle_woken(
        store,
        tenant_id="tenant-a",
        actor_id="actor-1",
        trace_id="trace-w1",
        session_id="sess-1",
        restored_from_checkpoint_id=CheckpointId("cp-1"),
        suspend_event_id=suspend_1,
    )

    # Broken pair 2 — forged wake.
    broken_woken_id, _ = await sandbox_lifecycle_woken(
        store,
        tenant_id="tenant-a",
        actor_id="actor-1",
        trace_id="trace-w2",
        session_id="sess-2",
        restored_from_checkpoint_id=CheckpointId("cp-2"),
        suspend_event_id=uuid.uuid4(),
    )

    report = await ChainVerifier(engine, "decision_history").verify_suspend_wake_linkage()

    assert report.is_clean is False
    assert report.break_kind == "suspend_row_not_found"
    assert report.records_checked == 2
    assert report.first_break_record_id == broken_woken_id


# ---------------------------------------------------------------------------
# Chain-scope guard.
# ---------------------------------------------------------------------------


async def test_audit_event_chain_scope_rejected(engine: AsyncEngine) -> None:
    """``verify_suspend_wake_linkage`` raises ``ValueError`` when the
    verifier is scoped to the ``audit_event`` chain — suspend / wake
    lifecycle events only ever land in ``decision_history``.
    """

    verifier = ChainVerifier(engine, "audit_event")
    with pytest.raises(ValueError, match="decision_history"):
        await verifier.verify_suspend_wake_linkage()


# ---------------------------------------------------------------------------
# _coerce_record_id — both dialect branches.
# ---------------------------------------------------------------------------


def test_coerce_record_id_passes_through_native_uuid() -> None:
    """``_coerce_record_id`` returns a native ``uuid.UUID`` unchanged.

    The aiosqlite test substrate (and most production dialects)
    round-trips the ``Uuid()`` column as a native ``uuid.UUID`` — this
    is the hot path.
    """

    native = uuid.uuid4()
    coerced = _coerce_record_id(native)
    assert coerced is native


def test_coerce_record_id_parses_string_form() -> None:
    """``_coerce_record_id`` parses a string ``record_id`` to ``UUID``.

    Covers the defence-in-depth branch for dialects (or
    ``Uuid(native_uuid=False)`` configurations) that surface
    ``record_id`` as a raw string — the suspend→wake index keying must
    stay dialect-independent. aiosqlite never exercises this branch, so
    it is pinned by this direct unit test.
    """

    target = uuid.uuid4()
    coerced = _coerce_record_id(str(target))
    assert isinstance(coerced, uuid.UUID)
    assert coerced == target


# ---------------------------------------------------------------------------
# Wire-shape — confirm session_id really lives in payload, not a column.
# ---------------------------------------------------------------------------


async def test_session_id_is_payload_key_not_a_row_column(
    engine: AsyncEngine, store: DecisionHistoryStore
) -> None:
    """Source-grounding regression: the ``_decision_history`` table has
    NO ``session_id`` column; ``emit_sandbox_event`` merges
    ``session_id`` into the ``payload`` JSON column. Step 4 of the §5.2
    assertion therefore compares ``payload["session_id"]``.

    Pins that contract so a future schema migration adding a
    ``session_id`` column does not silently shift Step 4's read site.
    """

    assert "session_id" not in _decision_history.c

    suspend_record_id, _ = await sandbox_lifecycle_suspended(
        store,
        tenant_id="tenant-a",
        actor_id="actor-1",
        trace_id="trace-suspend",
        session_id="sess-payload-check",
        final_checkpoint_id=CheckpointId("cp-payload-check"),
    )

    async with engine.begin() as conn:
        row = (
            await conn.execute(
                _decision_history.select().where(_decision_history.c.record_id == suspend_record_id)
            )
        ).one()

    # session_id is reachable only via the payload JSON dict.
    assert row.payload["session_id"] == "sess-payload-check"
    # The persisted payload round-trips as canonical JSON.
    assert json.loads(json.dumps(row.payload))["session_id"] == "sess-payload-check"
