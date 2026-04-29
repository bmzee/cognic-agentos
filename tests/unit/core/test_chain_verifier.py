"""ChainVerifier — walks audit_event + decision_history chains and
surfaces tamper via a typed TamperReport.

Tests run against SQLite-aiosqlite. The chain math is dialect-
independent; the SQLite quirk (`TIMESTAMP` drops tzinfo on round-
trip) is exercised here because it's the unit-test substrate. PG +
Oracle preserve tzinfo, so the dialect-aware datetime normalisation
in the verifier is a no-op there.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import text, update
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import (
    AuditEvent,
    AuditStore,
    _audit_event,
    _chain_heads,
    _metadata,
)
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.chain_verifier import (
    ChainVerifier,
    TamperReport,
)
from cognic_agentos.core.decision_history import (
    DecisionHistoryStore,
    DecisionRecord,
)


@pytest.fixture
async def engine(tmp_path: Any) -> Any:
    """Per-test SQLite-aiosqlite engine with both chains seeded."""

    url = f"sqlite+aiosqlite:///{tmp_path / 'verifier.db'}"
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


class TestTamperReportDataclass:
    def test_minimum_construction(self) -> None:
        r = TamperReport(chain_id="audit_event", is_clean=True, records_checked=0)
        assert r.chain_id == "audit_event"
        assert r.is_clean is True
        assert r.records_checked == 0
        assert r.first_break_sequence is None
        assert r.break_kind is None
        assert r.detail is None

    def test_full_construction(self) -> None:
        r = TamperReport(
            chain_id="audit_event",
            is_clean=False,
            records_checked=5,
            first_break_sequence=3,
            break_kind="hash_mismatch",
            detail="example",
        )
        assert r.is_clean is False
        assert r.first_break_sequence == 3
        assert r.break_kind == "hash_mismatch"

    def test_frozen(self) -> None:
        import dataclasses

        r = TamperReport(chain_id="audit_event", is_clean=True, records_checked=0)
        with pytest.raises(dataclasses.FrozenInstanceError):
            r.is_clean = False  # type: ignore[misc]


class TestConstruction:
    def test_unsupported_chain_id_raises(self, engine: AsyncEngine) -> None:
        with pytest.raises(ValueError, match="chain_id"):
            ChainVerifier(engine, "nonexistent_chain")

    def test_audit_event_chain_supported(self, engine: AsyncEngine) -> None:
        v = ChainVerifier(engine, "audit_event")
        assert v._chain_id == "audit_event"

    def test_decision_history_chain_supported(self, engine: AsyncEngine) -> None:
        v = ChainVerifier(engine, "decision_history")
        assert v._chain_id == "decision_history"


class TestEmptyChain:
    async def test_walk_empty_chain_is_clean(self, engine: AsyncEngine) -> None:
        v = ChainVerifier(engine, "audit_event")
        report = await v.walk()
        assert report.is_clean is True
        assert report.records_checked == 0
        assert report.chain_id == "audit_event"


class TestCleanChain:
    async def test_walk_ten_record_chain_clean(self, engine: AsyncEngine) -> None:
        store = AuditStore(engine)
        for i in range(10):
            await store.append(AuditEvent(event_type="t", request_id=f"r-{i}", payload={"i": i}))
        report = await ChainVerifier(engine, "audit_event").walk()
        assert report.is_clean is True
        assert report.records_checked == 10
        assert report.first_break_sequence is None
        assert report.break_kind is None

    async def test_walk_decision_history_chain_clean(self, engine: AsyncEngine) -> None:
        store = DecisionHistoryStore(engine)
        for i in range(5):
            await store.append(
                DecisionRecord(decision_type="t", request_id=f"r-{i}", payload={"i": i})
            )
        report = await ChainVerifier(engine, "decision_history").walk()
        assert report.is_clean is True
        assert report.records_checked == 5


class TestHashMismatch:
    async def test_mutated_payload_detected(self, engine: AsyncEngine) -> None:
        store = AuditStore(engine)
        for i in range(5):
            await store.append(AuditEvent(event_type="t", request_id=f"r-{i}", payload={"i": i}))
        # UPDATE bypasses app-level INSERT-only contract; simulates a
        # DBA who corrupted the row content.
        async with engine.begin() as conn:
            await conn.execute(
                update(_audit_event).where(_audit_event.c.sequence == 3).values(payload={"i": 999})
            )
        report = await ChainVerifier(engine, "audit_event").walk()
        assert report.is_clean is False
        assert report.first_break_sequence == 3
        assert report.break_kind == "hash_mismatch"
        assert report.detail is not None
        assert "hash" in report.detail.lower()

    async def test_mutated_event_type_detected(self, engine: AsyncEngine) -> None:
        store = AuditStore(engine)
        for i in range(3):
            await store.append(AuditEvent(event_type="orig", request_id=f"r-{i}", payload={}))
        async with engine.begin() as conn:
            await conn.execute(
                update(_audit_event)
                .where(_audit_event.c.sequence == 2)
                .values(event_type="tampered")
            )
        report = await ChainVerifier(engine, "audit_event").walk()
        assert report.is_clean is False
        assert report.first_break_sequence == 2
        assert report.break_kind == "hash_mismatch"


class TestPrevHashMismatch:
    async def test_corrupted_prev_hash_detected(self, engine: AsyncEngine) -> None:
        store = AuditStore(engine)
        for i in range(5):
            await store.append(AuditEvent(event_type="t", request_id=f"r-{i}", payload={}))
        # Corrupt row 3's prev_hash to something that does NOT match
        # row 2's hash. The verifier must catch this on the linkage
        # check (before reaching the recompute step).
        async with engine.begin() as conn:
            await conn.execute(
                update(_audit_event)
                .where(_audit_event.c.sequence == 3)
                .values(prev_hash=b"\xff" * 32)
            )
        report = await ChainVerifier(engine, "audit_event").walk()
        assert report.is_clean is False
        assert report.first_break_sequence == 3
        assert report.break_kind == "prev_hash_mismatch"


class TestSequenceGap:
    async def test_deleted_row_detected_as_sequence_gap(self, engine: AsyncEngine) -> None:
        # Round-2 P2: records_checked is the count of inspected rows,
        # not a sequence number. After deleting row 3 from a 1,2,4,5
        # chain, the verifier inspects rows 1, 2, 4 (3 rows total)
        # before raising on row 4. records_checked must be 3, not 4
        # (which is the broken sequence — first_break_sequence).
        store = AuditStore(engine)
        for i in range(5):
            await store.append(AuditEvent(event_type="t", request_id=f"r-{i}", payload={}))
        # DELETE row 3 → sequences become 1, 2, 4, 5. The verifier
        # walks 1, 2, then expects 3 but sees 4 → sequence_gap at 4.
        async with engine.begin() as conn:
            await conn.execute(text("DELETE FROM audit_event WHERE sequence = 3"))
        report = await ChainVerifier(engine, "audit_event").walk()
        assert report.is_clean is False
        assert report.first_break_sequence == 4
        assert report.break_kind == "sequence_gap"
        assert report.detail is not None
        assert "expected sequence 3" in report.detail
        # P2 fix: records_checked is the count (3 rows inspected),
        # not the broken sequence (4).
        assert report.records_checked == 3


class TestSingleRecord:
    async def test_single_record_clean(self, engine: AsyncEngine) -> None:
        store = AuditStore(engine)
        await store.append(AuditEvent(event_type="t", request_id="r", payload={}))
        report = await ChainVerifier(engine, "audit_event").walk()
        assert report.is_clean is True
        assert report.records_checked == 1


class TestChainIsolation:
    async def test_tampering_audit_does_not_break_decision_history(
        self, engine: AsyncEngine
    ) -> None:
        # Two independent chains. Corrupting one must not poison the
        # other's verify pass.
        a_store = AuditStore(engine)
        d_store = DecisionHistoryStore(engine)

        for i in range(3):
            await a_store.append(AuditEvent(event_type="t", request_id=f"a-{i}", payload={}))
            await d_store.append(DecisionRecord(decision_type="t", request_id=f"d-{i}", payload={}))

        # Corrupt audit_event row 2.
        async with engine.begin() as conn:
            await conn.execute(
                update(_audit_event)
                .where(_audit_event.c.sequence == 2)
                .values(event_type="tampered")
            )

        audit_report = await ChainVerifier(engine, "audit_event").walk()
        decision_report = await ChainVerifier(engine, "decision_history").walk()

        assert audit_report.is_clean is False
        assert audit_report.break_kind == "hash_mismatch"
        assert decision_report.is_clean is True


class TestVerifyRecord:
    async def test_verify_record_clean(self, engine: AsyncEngine) -> None:
        store = AuditStore(engine)
        record_id, _ = await store.append(AuditEvent(event_type="t", request_id="r", payload={}))
        report = await ChainVerifier(engine, "audit_event").verify_record(record_id)
        assert report.is_clean is True
        assert report.records_checked == 1

    async def test_verify_record_break_before_target_reported(self, engine: AsyncEngine) -> None:
        # Tamper at row 2; verify a later record. The verifier should
        # surface the earlier break, not silently return clean for the
        # target.
        store = AuditStore(engine)
        records: list[uuid.UUID] = []
        for i in range(5):
            rid, _ = await store.append(AuditEvent(event_type="t", request_id=f"r-{i}", payload={}))
            records.append(rid)
        async with engine.begin() as conn:
            await conn.execute(
                update(_audit_event)
                .where(_audit_event.c.sequence == 2)
                .values(event_type="tampered")
            )
        report = await ChainVerifier(engine, "audit_event").verify_record(records[4])
        assert report.is_clean is False
        assert report.first_break_sequence == 2
        assert report.break_kind == "hash_mismatch"

    async def test_verify_record_not_found(self, engine: AsyncEngine) -> None:
        store = AuditStore(engine)
        for i in range(3):
            await store.append(AuditEvent(event_type="t", request_id=f"r-{i}", payload={}))
        bogus_id = uuid.uuid4()
        report = await ChainVerifier(engine, "audit_event").verify_record(bogus_id)
        assert report.is_clean is False
        assert report.break_kind == "record_not_found"
        assert report.detail is not None
        assert str(bogus_id) in report.detail

    async def test_verify_record_in_empty_chain_not_found(self, engine: AsyncEngine) -> None:
        bogus_id = uuid.uuid4()
        report = await ChainVerifier(engine, "audit_event").verify_record(bogus_id)
        assert report.is_clean is False
        assert report.break_kind == "record_not_found"
        assert report.records_checked == 0


class TestRichPayloadRoundTrip:
    """Critical: verifier walks audit/decision rows that contain
    canonically-normalised payloads (datetime → ISO string, etc.). The
    recomputed envelope must match what was hashed pre-insert. SQLite
    drops tzinfo on TIMESTAMP round-trip so the verifier needs dialect-
    aware datetime normalisation."""

    async def test_rich_payload_audit_chain_clean(self, engine: AsyncEngine) -> None:
        from decimal import Decimal

        store = AuditStore(engine)
        await store.append(
            AuditEvent(
                event_type="tx",
                request_id="r-1",
                payload={
                    "ts": datetime(2026, 4, 28, 12, 0, 0, tzinfo=UTC),
                    "price": Decimal("99.99"),
                    "id": uuid.UUID("12345678-1234-5678-1234-567812345678"),
                    "raw": b"\x00\x01\x02\x03",
                },
                tenant_id="bank-acme",
                iso_controls=("A.9.2",),
            )
        )
        report = await ChainVerifier(engine, "audit_event").walk()
        assert report.is_clean is True
        assert report.records_checked == 1

    async def test_decision_history_with_actor_id_clean(self, engine: AsyncEngine) -> None:
        store = DecisionHistoryStore(engine)
        await store.append(
            DecisionRecord(
                decision_type="approved",
                request_id="r-1",
                payload={"reason": "policy ok"},
                actor_id="agent-x",
                tenant_id="bank-acme",
                iso_controls=("A.7.4",),
            )
        )
        report = await ChainVerifier(engine, "decision_history").walk()
        assert report.is_clean is True
        assert report.records_checked == 1


class TestHeadMismatch:
    """Round-2 P1: walk() must verify the governance_chain_heads row
    matches the last evidence row. Without this, a DBA could corrupt
    the mutable head row (latest_sequence + latest_hash) and walk()
    would return clean over broken append-state."""

    async def test_mutated_head_hash_detected(self, engine: AsyncEngine) -> None:
        store = AuditStore(engine)
        for i in range(3):
            await store.append(AuditEvent(event_type="t", request_id=f"r-{i}", payload={}))
        # Tamper head hash without touching the evidence rows.
        async with engine.begin() as conn:
            await conn.execute(
                update(_chain_heads)
                .where(_chain_heads.c.chain_id == "audit_event")
                .values(latest_hash=b"\xff" * 32)
            )
        report = await ChainVerifier(engine, "audit_event").walk()
        assert report.is_clean is False
        assert report.break_kind == "head_mismatch"
        assert report.detail is not None
        assert "chain head" in report.detail.lower()
        # All 3 evidence rows were verified clean before the head check fired.
        assert report.records_checked == 3

    async def test_mutated_head_sequence_detected(self, engine: AsyncEngine) -> None:
        store = AuditStore(engine)
        for i in range(3):
            await store.append(AuditEvent(event_type="t", request_id=f"r-{i}", payload={}))
        # Tamper head sequence (claim chain is at sequence=99 when
        # actually at 3).
        async with engine.begin() as conn:
            await conn.execute(
                update(_chain_heads)
                .where(_chain_heads.c.chain_id == "audit_event")
                .values(latest_sequence=99)
            )
        report = await ChainVerifier(engine, "audit_event").walk()
        assert report.is_clean is False
        assert report.break_kind == "head_mismatch"
        assert report.first_break_sequence == 99
        assert report.records_checked == 3

    async def test_missing_head_row_detected(self, engine: AsyncEngine) -> None:
        store = AuditStore(engine)
        for i in range(2):
            await store.append(AuditEvent(event_type="t", request_id=f"r-{i}", payload={}))
        # Remove the head row entirely.
        async with engine.begin() as conn:
            await conn.execute(
                text("DELETE FROM governance_chain_heads WHERE chain_id='audit_event'")
            )
        report = await ChainVerifier(engine, "audit_event").walk()
        assert report.is_clean is False
        assert report.break_kind == "head_mismatch"
        assert report.detail is not None
        assert "missing" in report.detail.lower()
        assert report.first_break_sequence is None  # head row is gone

    async def test_empty_chain_head_must_be_zero_zero(self, engine: AsyncEngine) -> None:
        # Empty chain. If the head row claims (5, BAD_HASH) instead of
        # (0, ZERO_HASH), the verifier must report head_mismatch.
        async with engine.begin() as conn:
            await conn.execute(
                update(_chain_heads)
                .where(_chain_heads.c.chain_id == "audit_event")
                .values(latest_sequence=5, latest_hash=b"\xab" * 32)
            )
        report = await ChainVerifier(engine, "audit_event").walk()
        assert report.is_clean is False
        assert report.break_kind == "head_mismatch"
        assert report.first_break_sequence == 5
        assert report.records_checked == 0  # no evidence rows existed

    async def test_walk_clean_when_head_matches_evidence(self, engine: AsyncEngine) -> None:
        # Positive control: clean append + clean head → is_clean.
        store = AuditStore(engine)
        for i in range(3):
            await store.append(AuditEvent(event_type="t", request_id=f"r-{i}", payload={}))
        report = await ChainVerifier(engine, "audit_event").walk()
        assert report.is_clean is True
        assert report.records_checked == 3


class TestNullColumnTamper:
    """Round-2 P1: nullable JSON columns (iso_controls, payload) must
    be passed through verbatim to canonical_bytes. Coercing NULL to
    the append-time default ([] / {}) would silently mask a DBA who
    NULLed an originally-empty column. The hash mismatch surfaces
    the tamper instead."""

    async def test_iso_controls_nulled_detected_as_hash_mismatch(self, engine: AsyncEngine) -> None:
        store = AuditStore(engine)
        # Append with empty iso_controls → stored as [] per the
        # AuditStore contract (never NULL).
        await store.append(AuditEvent(event_type="t", request_id="r", payload={}))
        # Tamper: NULL the iso_controls column.
        async with engine.begin() as conn:
            await conn.execute(
                update(_audit_event).where(_audit_event.c.sequence == 1).values(iso_controls=None)
            )
        report = await ChainVerifier(engine, "audit_event").walk()
        assert report.is_clean is False
        assert report.break_kind == "hash_mismatch"
        assert report.first_break_sequence == 1

    async def test_payload_nulled_detected_as_hash_mismatch(self, engine: AsyncEngine) -> None:
        store = AuditStore(engine)
        await store.append(AuditEvent(event_type="t", request_id="r", payload={"k": "v"}))
        # Tamper: NULL the payload column. This would normally violate
        # the NOT NULL schema constraint, but tamper is tamper — the
        # verifier must surface it. (On strict-NOT-NULL dialects the
        # UPDATE would fail; on SQLite it succeeds because the
        # constraint isn't enforced retroactively after schema change.)
        async with engine.begin() as conn:
            try:
                await conn.execute(
                    update(_audit_event).where(_audit_event.c.sequence == 1).values(payload=None)
                )
            except Exception:
                pytest.skip(
                    "dialect rejects NULL update on NOT NULL column; "
                    "tamper case is dialect-specific"
                )
        report = await ChainVerifier(engine, "audit_event").walk()
        assert report.is_clean is False
        assert report.break_kind == "hash_mismatch"


class TestWalkSnapshotSafety:
    """Round-3 P1: walk() must read evidence rows + chain head as a
    snapshot-coherent pair against concurrent appenders. The verifier
    locks the chain-head row with the same FOR UPDATE primitive
    AuditStore.append uses; concurrent appenders block on the lock
    until walk() commits.

    Behavioural concurrency proof requires real PG/Oracle (FOR UPDATE
    is a no-op on SQLite). Task 12's live-DB tests exercise the
    appender + walk concurrency path. At unit-test level we verify:
      - The implementation USES engine.begin() + with_for_update on
        chain_heads (structural assertion).
      - Sequential walk-after-append produces the right state (sanity).
    """

    def test_walk_locks_chain_head_in_transaction(self) -> None:
        # Structural assertion: the implementation must use
        # engine.begin() (transaction) and acquire the chain-head
        # FOR UPDATE lock BEFORE scanning evidence rows. A future
        # refactor that drops either primitive would silently break
        # snapshot safety against concurrent appenders.
        import inspect

        source = inspect.getsource(ChainVerifier._walk)
        assert "engine.begin()" in source, (
            "ChainVerifier._walk must use engine.begin() (transaction) "
            "to wrap evidence-row read + chain-head check together"
        )
        assert "with_for_update" in source, (
            "ChainVerifier._walk must SELECT ... FOR UPDATE on the "
            "chain-head row to serialise against concurrent appenders"
        )
        # The lock must be ACQUIRED BEFORE the evidence-row select
        # is executed. Cheap sanity check via source ordering.
        for_update_idx = source.index("with_for_update")
        order_by_seq_idx = source.index("order_by(self._table.c.sequence")
        assert for_update_idx < order_by_seq_idx, (
            "ChainVerifier._walk must acquire the chain-head FOR UPDATE "
            "lock BEFORE the evidence-row scan, not after"
        )

    async def test_sequential_walk_after_append_clean(self, engine: AsyncEngine) -> None:
        # Sequential sanity: append → walk → append → walk all return
        # clean. Proves the lock acquire + release cycle works under
        # the standard call pattern.
        store = AuditStore(engine)
        await store.append(AuditEvent(event_type="t", request_id="r-1", payload={}))
        report1 = await ChainVerifier(engine, "audit_event").walk()
        assert report1.is_clean is True
        assert report1.records_checked == 1

        await store.append(AuditEvent(event_type="t", request_id="r-2", payload={}))
        report2 = await ChainVerifier(engine, "audit_event").walk()
        assert report2.is_clean is True
        assert report2.records_checked == 2


class TestRecordsCheckedOnBreak:
    """When the verifier hits a break, records_checked reflects the
    sequence of the broken row (so callers can scope remediation)."""

    async def test_records_checked_at_break_sequence(self, engine: AsyncEngine) -> None:
        store = AuditStore(engine)
        for i in range(5):
            await store.append(AuditEvent(event_type="t", request_id=f"r-{i}", payload={}))
        async with engine.begin() as conn:
            await conn.execute(
                update(_audit_event)
                .where(_audit_event.c.sequence == 3)
                .values(event_type="tampered")
            )
        report = await ChainVerifier(engine, "audit_event").walk()
        assert report.is_clean is False
        assert report.records_checked == 3
