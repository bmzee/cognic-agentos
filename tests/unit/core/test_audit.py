"""AuditStore — append-only hash-chained audit table.

Unit tests run against sqlite-aiosqlite (the migration's `_metadata`
creates the same shape on SQLite as on Postgres + Oracle). This file
exercises the SQL shape + envelope wiring + tuple→list conversion +
chain-head update; concurrency correctness is proven separately on
real Postgres + Oracle in Task 12 because SQLite does not honour
SELECT ... FOR UPDATE.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import (
    AuditEvent,
    AuditStore,
    _audit_event,
    _chain_heads,
    _metadata,
)
from cognic_agentos.core.canonical import (
    ZERO_HASH,
    canonical_bytes,
    hash_record,
)


@pytest.fixture
async def engine(tmp_path: Any) -> Any:
    """Per-test SQLite-aiosqlite engine with the governance schema +
    seeded chain heads. Mirrors migration 0001's shape."""

    url = f"sqlite+aiosqlite:///{tmp_path / 'audit.db'}"
    eng: AsyncEngine = create_async_engine(url)
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        # Seed the chain heads exactly like migration 0001 does. The
        # AuditStore.append flow reads from these rows.
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
async def store(engine: AsyncEngine) -> AuditStore:
    return AuditStore(engine)


class TestAuditEventDataclass:
    def test_construct_minimum(self) -> None:
        e = AuditEvent(event_type="t", request_id="r", payload={})
        assert e.event_type == "t"
        assert e.request_id == "r"
        assert e.payload == {}
        assert e.tenant_id is None
        assert e.iso_controls == ()

    def test_construct_full(self) -> None:
        e = AuditEvent(
            event_type="tool_invocation",
            request_id="r-1",
            payload={"tool": "echo"},
            tenant_id="bank-acme",
            trace_id="abc",
            span_id="def",
            langfuse_trace_id="lf-1",
            provider_label="vllm",
            iso_controls=("A.9.2", "A.10.2"),
        )
        assert e.iso_controls == ("A.9.2", "A.10.2")

    def test_frozen(self) -> None:
        import dataclasses

        e = AuditEvent(event_type="t", request_id="r", payload={})
        with pytest.raises(dataclasses.FrozenInstanceError):
            e.event_type = "other"  # type: ignore[misc]


class TestGenesisAppend:
    """The first append against an empty chain reads ZERO_HASH from the
    seeded chain-head row, computes the new hash with that as prev_hash,
    inserts sequence=1, and advances the head."""

    async def test_returns_record_id_and_hash(self, store: AuditStore) -> None:
        record_id, h = await store.append(
            AuditEvent(event_type="tool_invocation", request_id="r-1", payload={})
        )
        assert isinstance(record_id, uuid.UUID)
        assert isinstance(h, bytes)
        assert len(h) == 32

    async def test_row_persisted_with_zero_prev_hash(
        self, store: AuditStore, engine: AsyncEngine
    ) -> None:
        await store.append(AuditEvent(event_type="t", request_id="r-1", payload={}))
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    select(
                        _audit_event.c.sequence,
                        _audit_event.c.prev_hash,
                        _audit_event.c.schema_version,
                    )
                )
            ).one()
        assert row.sequence == 1
        assert bytes(row.prev_hash) == ZERO_HASH
        assert row.schema_version == 1

    async def test_chain_head_advanced(self, store: AuditStore, engine: AsyncEngine) -> None:
        _, h = await store.append(AuditEvent(event_type="t", request_id="r-1", payload={}))
        async with engine.connect() as conn:
            head = (
                await conn.execute(
                    select(
                        _chain_heads.c.latest_sequence,
                        _chain_heads.c.latest_hash,
                    ).where(_chain_heads.c.chain_id == "audit_event")
                )
            ).one()
        assert head.latest_sequence == 1
        assert bytes(head.latest_hash) == h


class TestSequentialAppends:
    async def test_second_appends_links_to_first(
        self, store: AuditStore, engine: AsyncEngine
    ) -> None:
        _, h1 = await store.append(AuditEvent(event_type="t", request_id="r-1", payload={}))
        _, h2 = await store.append(AuditEvent(event_type="t", request_id="r-2", payload={}))
        assert h1 != h2
        async with engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(_audit_event.c.sequence, _audit_event.c.prev_hash).order_by(
                        _audit_event.c.sequence
                    )
                )
            ).all()
        assert [r.sequence for r in rows] == [1, 2]
        assert bytes(rows[0].prev_hash) == ZERO_HASH
        assert bytes(rows[1].prev_hash) == h1  # row 2 links to row 1

    async def test_chain_isolation_from_decision_history(
        self, store: AuditStore, engine: AsyncEngine
    ) -> None:
        # Appending to audit_event must not move the decision_history
        # chain head — the two chains are independent.
        await store.append(AuditEvent(event_type="t", request_id="r", payload={}))
        async with engine.connect() as conn:
            head = (
                await conn.execute(
                    select(_chain_heads.c.latest_sequence).where(
                        _chain_heads.c.chain_id == "decision_history"
                    )
                )
            ).one()
        assert head.latest_sequence == 0


class TestEnvelopeIncludesIdentity:
    """Round-2 amendment #3: the canonical envelope MUST include
    record_id + sequence + schema_version + chain_id + tenant_id +
    created_at, not only payload + metadata. Mutating any of those
    fields after the row is written must break the chain."""

    async def test_record_id_makes_hashes_unique(self, store: AuditStore) -> None:
        # Two appends with byte-identical caller-side data still produce
        # different hashes because record_id (uuid4) participates in the
        # canonical envelope.
        e = AuditEvent(event_type="t", request_id="r", payload={"k": "v"})
        _, h1 = await store.append(e)
        _, h2 = await store.append(e)
        assert h1 != h2

    async def test_persisted_row_recomputes_to_stored_hash(
        self, store: AuditStore, engine: AsyncEngine
    ) -> None:
        # Mini-verifier: read the stored row back, rebuild the canonical
        # envelope per the documented Sprint-2 schema_version=1 rules,
        # recompute the hash, and assert it matches the stored value.
        # This is what core/chain_verifier (Task 8) will do across rows.
        _, h = await store.append(
            AuditEvent(
                event_type="tool_invocation",
                request_id="r-1",
                payload={"tool": "echo"},
                tenant_id="bank-acme",
                trace_id="abc",
                iso_controls=("A.9.2",),
            )
        )
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    select(
                        _audit_event.c.record_id,
                        _audit_event.c.sequence,
                        _audit_event.c.schema_version,
                        _audit_event.c.tenant_id,
                        _audit_event.c.prev_hash,
                        _audit_event.c.created_at,
                        _audit_event.c.event_type,
                        _audit_event.c.request_id,
                        _audit_event.c.trace_id,
                        _audit_event.c.span_id,
                        _audit_event.c.langfuse_trace_id,
                        _audit_event.c.provider_label,
                        _audit_event.c.iso_controls,
                        _audit_event.c.payload,
                    )
                )
            ).one()

        # SQLite drops tzinfo on TIMESTAMP round-trip; Postgres + Oracle
        # preserve it. The chain verifier (Task 8) will need dialect-aware
        # datetime normalization for the SQLite test path. Apply the
        # UTC-defaulting locally here so this round-trip test passes on
        # SQLite — the real-DB integration tests (Task 12) will exercise
        # the no-compensation path.
        created_at = row.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=UTC)

        envelope = {
            "schema_version": int(row.schema_version),
            "chain_id": "audit_event",
            "record_id": str(row.record_id),
            "sequence": int(row.sequence),
            "tenant_id": row.tenant_id,
            "created_at": created_at,
            "event_type": row.event_type,
            "request_id": row.request_id,
            "trace_id": row.trace_id,
            "span_id": row.span_id,
            "langfuse_trace_id": row.langfuse_trace_id,
            "provider_label": row.provider_label,
            "iso_controls": list(row.iso_controls or []),
            "payload": dict(row.payload),
        }
        recomputed = hash_record(canonical_bytes(envelope), bytes(row.prev_hash))
        assert recomputed == h


class TestSchemaVersion:
    async def test_schema_version_is_one(self, store: AuditStore, engine: AsyncEngine) -> None:
        await store.append(AuditEvent(event_type="t", request_id="r", payload={}))
        async with engine.connect() as conn:
            row = (await conn.execute(select(_audit_event.c.schema_version))).one()
        assert row.schema_version == 1


class TestTenantId:
    async def test_tenant_id_persists_when_provided(
        self, store: AuditStore, engine: AsyncEngine
    ) -> None:
        await store.append(
            AuditEvent(event_type="t", request_id="r", payload={}, tenant_id="bank-acme")
        )
        async with engine.connect() as conn:
            row = (await conn.execute(select(_audit_event.c.tenant_id))).one()
        assert row.tenant_id == "bank-acme"

    async def test_tenant_id_null_when_omitted(
        self, store: AuditStore, engine: AsyncEngine
    ) -> None:
        await store.append(AuditEvent(event_type="t", request_id="r", payload={}))
        async with engine.connect() as conn:
            row = (await conn.execute(select(_audit_event.c.tenant_id))).one()
        assert row.tenant_id is None


class TestIsoControlsHandling:
    """Carryover from Task 2 + Round-3: iso_controls arrives as
    tuple[str, ...] but canonical_bytes rejects tuples. AuditStore
    converts to list before passing into canonical_bytes AND before
    storing in the JSON column."""

    async def test_tuple_input_works(self, store: AuditStore, engine: AsyncEngine) -> None:
        await store.append(
            AuditEvent(
                event_type="t",
                request_id="r",
                payload={},
                iso_controls=("A.9.2", "A.10.2"),
            )
        )
        async with engine.connect() as conn:
            row = (await conn.execute(select(_audit_event.c.iso_controls))).one()
        # SQLite's JSON column round-trips as Python list.
        assert row.iso_controls == ["A.9.2", "A.10.2"]

    async def test_empty_iso_controls_persists_as_empty_list(
        self, store: AuditStore, engine: AsyncEngine
    ) -> None:
        await store.append(AuditEvent(event_type="t", request_id="r", payload={}))
        async with engine.connect() as conn:
            row = (await conn.execute(select(_audit_event.c.iso_controls))).one()
        # Always a list (possibly empty), never None — keeps the chain
        # verifier from having to handle two shapes.
        assert row.iso_controls == []


class TestPayloadCanonicalNormalization:
    """Round-3 hardening: payload is normalised through the canonical
    serializer (``json.loads(canonical_bytes(payload))``) before
    hashing and inserting. This guarantees:

      1. Snapshot — independent of the caller's mutable dict reference.
      2. Canonical-form validation at method boundary (rejects tuples,
         NaN/Inf, naive datetimes, etc. early).
      3. Projection onto JSON-native types so the persisted JSON
         column matches the canonical bytes across every dialect —
         critical for chain integrity, since the verifier reads back
         the column and re-canonicalises against it.
      4. No __deepcopy__ side-effects on arbitrary caller objects.
    """

    async def test_datetime_payload_normalized_to_iso_string(
        self, store: AuditStore, engine: AsyncEngine
    ) -> None:
        ts = datetime(2026, 4, 28, 12, 0, 0, tzinfo=UTC)
        await store.append(AuditEvent(event_type="t", request_id="r", payload={"ts": ts}))
        async with engine.connect() as conn:
            row = (await conn.execute(select(_audit_event.c.payload))).one()
        # Stored as ISO 8601 string, not a Python datetime — guarantees
        # uniform binding on every dialect's JSON column.
        assert row.payload == {"ts": "2026-04-28T12:00:00+00:00"}
        assert isinstance(row.payload["ts"], str)

    async def test_uuid_payload_normalized_to_hex_string(
        self, store: AuditStore, engine: AsyncEngine
    ) -> None:
        u = uuid.UUID("12345678-1234-5678-1234-567812345678")
        await store.append(AuditEvent(event_type="t", request_id="r", payload={"id": u}))
        async with engine.connect() as conn:
            row = (await conn.execute(select(_audit_event.c.payload))).one()
        assert row.payload == {"id": "12345678-1234-5678-1234-567812345678"}

    async def test_decimal_payload_normalized_to_string(
        self, store: AuditStore, engine: AsyncEngine
    ) -> None:
        from decimal import Decimal

        await store.append(
            AuditEvent(event_type="t", request_id="r", payload={"price": Decimal("19.99")})
        )
        async with engine.connect() as conn:
            row = (await conn.execute(select(_audit_event.c.payload))).one()
        assert row.payload == {"price": "19.99"}

    async def test_bytes_payload_normalized_to_base64(
        self, store: AuditStore, engine: AsyncEngine
    ) -> None:
        await store.append(
            AuditEvent(event_type="t", request_id="r", payload={"raw": b"\x00\x01\x02\x03"})
        )
        async with engine.connect() as conn:
            row = (await conn.execute(select(_audit_event.c.payload))).one()
        assert row.payload == {"raw": "AAECAw=="}

    async def test_string_enum_payload_normalized_to_value(
        self, store: AuditStore, engine: AsyncEngine
    ) -> None:
        from enum import StrEnum

        class V(StrEnum):
            APPROVED = "approved"

        await store.append(
            AuditEvent(event_type="t", request_id="r", payload={"verdict": V.APPROVED})
        )
        async with engine.connect() as conn:
            row = (await conn.execute(select(_audit_event.c.payload))).one()
        assert row.payload == {"verdict": "approved"}

    async def test_tuple_in_payload_raises_at_method_boundary(self, store: AuditStore) -> None:
        # canonical_bytes rejects tuples (Round-3 of Task 2). Without
        # method-boundary normalisation, this would only surface deep
        # in envelope construction; here it surfaces at the API.
        with pytest.raises(TypeError, match="tuple"):
            await store.append(
                AuditEvent(event_type="t", request_id="r", payload={"items": (1, 2, 3)})
            )

    async def test_nan_in_payload_raises_at_method_boundary(self, store: AuditStore) -> None:
        import math

        with pytest.raises(ValueError, match="non-finite"):
            await store.append(AuditEvent(event_type="t", request_id="r", payload={"x": math.nan}))

    async def test_naive_datetime_in_payload_raises_at_method_boundary(
        self, store: AuditStore
    ) -> None:
        with pytest.raises(ValueError, match="naive datetime"):
            await store.append(
                AuditEvent(
                    event_type="t",
                    request_id="r",
                    payload={"ts": datetime(2026, 4, 28, 12, 0, 0)},  # naive
                )
            )

    async def test_round_trip_with_rich_types_chain_verifies(
        self, store: AuditStore, engine: AsyncEngine
    ) -> None:
        """Critical chain-integrity property: the canonical bytes hashed
        pre-insert must match the canonical bytes the chain verifier
        reads back. Normalisation makes this possible because the JSON
        column round-trips identically once the values are JSON-primitive."""
        from decimal import Decimal

        original: dict[str, Any] = {
            "ts": datetime(2026, 4, 28, 12, 0, 0, tzinfo=UTC),
            "price": Decimal("99.99"),
            "id": uuid.UUID("12345678-1234-5678-1234-567812345678"),
        }
        _, h = await store.append(AuditEvent(event_type="tx", request_id="r-1", payload=original))

        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    select(
                        _audit_event.c.record_id,
                        _audit_event.c.sequence,
                        _audit_event.c.schema_version,
                        _audit_event.c.tenant_id,
                        _audit_event.c.prev_hash,
                        _audit_event.c.created_at,
                        _audit_event.c.event_type,
                        _audit_event.c.request_id,
                        _audit_event.c.trace_id,
                        _audit_event.c.span_id,
                        _audit_event.c.langfuse_trace_id,
                        _audit_event.c.provider_label,
                        _audit_event.c.iso_controls,
                        _audit_event.c.payload,
                    )
                )
            ).one()

        # SQLite tzinfo carryover (same compensation as
        # test_persisted_row_recomputes_to_stored_hash).
        created_at = row.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=UTC)

        envelope = {
            "schema_version": int(row.schema_version),
            "chain_id": "audit_event",
            "record_id": str(row.record_id),
            "sequence": int(row.sequence),
            "tenant_id": row.tenant_id,
            "created_at": created_at,
            "event_type": row.event_type,
            "request_id": row.request_id,
            "trace_id": row.trace_id,
            "span_id": row.span_id,
            "langfuse_trace_id": row.langfuse_trace_id,
            "provider_label": row.provider_label,
            "iso_controls": list(row.iso_controls or []),
            "payload": dict(row.payload),
        }
        recomputed = hash_record(canonical_bytes(envelope), bytes(row.prev_hash))
        assert recomputed == h


class TestPayloadSnapshotIsolation:
    """Round-2 hardening: AuditEvent is frozen-shallow but ``payload`` is
    a mutable dict the caller still references. AuditStore must snapshot
    payload at method boundary BEFORE any await — otherwise a concurrent
    task can mutate the audit evidence between method entry and the
    canonical_bytes serialisation that runs after the SELECT FOR UPDATE
    yield."""

    async def test_caller_mutation_during_append_does_not_affect_persisted_row(
        self, store: AuditStore, engine: AsyncEngine
    ) -> None:
        import asyncio

        # Caller-owned dict. Includes a nested list so we can prove
        # deep-copy (not just shallow).
        payload: dict[str, Any] = {"counter": 1, "items": [1, 2, 3], "meta": {"k": "v"}}
        event = AuditEvent(event_type="t", request_id="r", payload=payload)

        # Schedule append as a task; immediately mutate the caller's
        # dict before the task's await chain completes. The first await
        # in append is the engine.begin() context entry, which yields;
        # so this mutation lands BEFORE the canonical envelope is
        # serialised — UNLESS the snapshot happens at method boundary
        # (which it does).
        task = asyncio.create_task(store.append(event))
        # Yield to let the task progress past method-boundary code.
        await asyncio.sleep(0)
        # Mutate the caller's dict — these MUST NOT affect the audit row.
        payload["counter"] = 999
        payload["items"].append(99)
        payload["meta"]["k"] = "tampered"
        payload["new_key"] = "injected"

        _record_id, h = await task

        # Read back; persisted payload must be the original snapshot.
        async with engine.connect() as conn:
            row = (await conn.execute(select(_audit_event.c.payload))).one()
        assert row.payload == {"counter": 1, "items": [1, 2, 3], "meta": {"k": "v"}}
        assert "new_key" not in row.payload
        # And the hash, which is computed over the canonical envelope,
        # must reflect the SNAPSHOT — verified separately in the
        # round-trip test, but sanity-check here that h is a valid
        # 32-byte hash.
        assert isinstance(h, bytes) and len(h) == 32

    async def test_caller_mutation_after_append_returns_does_not_affect_persisted_row(
        self, store: AuditStore, engine: AsyncEngine
    ) -> None:
        # Even after the append commits, the caller's dict is
        # independent of the persisted row (deepcopy guarantee).
        payload: dict[str, Any] = {"a": 1, "nested": {"b": 2}}
        await store.append(AuditEvent(event_type="t", request_id="r", payload=payload))
        payload["a"] = 999
        payload["nested"]["b"] = 999

        async with engine.connect() as conn:
            row = (await conn.execute(select(_audit_event.c.payload))).one()
        assert row.payload == {"a": 1, "nested": {"b": 2}}


class TestChainHeadCompareAndSet:
    """Round-2 defence-in-depth: the chain-head UPDATE is a compare-and-set
    on the previously-read latest_sequence + latest_hash. Under correct
    FOR UPDATE locking the head cannot drift between SELECT and UPDATE,
    but defence-in-depth catches dialect surprises (a future SQLAlchemy
    version dropping FOR UPDATE on some dialect), out-of-band tampering,
    and migration/dialect-bridge regressions. rowcount != 1 → raise."""

    def test_compare_and_set_predicates_and_rowcount_check_in_source(self) -> None:
        # The rowcount=0 raise path is hard to trigger behaviourally on
        # SQLite (the only unit-test dialect): SQLite's UNIQUE on
        # ``sequence`` catches concurrent appends at INSERT time before
        # the UPDATE's compare-and-set can fire. Real Postgres + Oracle
        # FOR UPDATE prevents the drift in the first place. So the test
        # we CAN write at unit level is structural: prove the
        # implementation includes the latest_sequence + latest_hash
        # WHERE predicates AND the rowcount check. Behavioural
        # exercise lives in Task 12's live-DB concurrency suite.
        import inspect

        source = inspect.getsource(AuditStore.append)
        assert "latest_sequence == prev_sequence" in source, (
            "AuditStore.append's chain-head UPDATE missing compare-and-set "
            "predicate on latest_sequence"
        )
        assert "latest_hash == prev_hash" in source, (
            "AuditStore.append's chain-head UPDATE missing compare-and-set predicate on latest_hash"
        )
        assert "update_result.rowcount" in source and "RuntimeError" in source, (
            "AuditStore.append missing rowcount check + RuntimeError raise after chain-head UPDATE"
        )

    async def test_compare_and_set_raises_on_zero_rowcount(
        self, engine: AsyncEngine, store: AuditStore, monkeypatch: Any
    ) -> None:
        """Behavioural test: force the UPDATE's CursorResult.rowcount to
        0 via a wrapper around AsyncConnection.execute. Verifies that
        AuditStore raises RuntimeError with a clear message rather than
        silently committing an evidence row with a desynced chain head."""

        from sqlalchemy.ext.asyncio import AsyncConnection

        real_execute = AsyncConnection.execute

        class _ZeroRowcountResult:
            """Wraps a real result and forces rowcount=0; passes everything
            else through to the wrapped object."""

            def __init__(self, inner: Any) -> None:
                self._inner = inner

            @property
            def rowcount(self) -> int:
                return 0

            def __getattr__(self, name: str) -> Any:
                return getattr(self._inner, name)

        async def patched_execute(self_conn: Any, statement: Any, *args: Any, **kwargs: Any) -> Any:
            result = await real_execute(self_conn, statement, *args, **kwargs)
            # Detect the chain-head UPDATE by inspecting the compiled SQL.
            # The first argument is a SQL construct (Update/Select/Insert).
            try:
                sql = str(statement)
            except Exception:
                sql = ""
            if "UPDATE governance_chain_heads" in sql:
                return _ZeroRowcountResult(result)
            return result

        monkeypatch.setattr(AsyncConnection, "execute", patched_execute)

        with pytest.raises(RuntimeError, match="compare-and-set"):
            await store.append(AuditEvent(event_type="t", request_id="r", payload={}))


class TestPayloadOrderInvariance:
    """canonical_bytes is dict-key-order independent. So two appends with
    payloads that differ only in dict-key order produce the SAME canonical
    bytes for the payload chunk (and the SAME canonical bytes for the rest
    of the envelope IF record_id/sequence/etc. matched — but those differ
    per row, so the row-level hashes differ. The invariant proven here is
    that the payload column itself is order-stable.)"""

    async def test_dict_order_irrelevant_to_canonical_payload(
        self, store: AuditStore, engine: AsyncEngine
    ) -> None:
        await store.append(AuditEvent(event_type="t", request_id="r-1", payload={"b": 2, "a": 1}))
        await store.append(AuditEvent(event_type="t", request_id="r-2", payload={"a": 1, "b": 2}))
        async with engine.connect() as conn:
            rows = (
                await conn.execute(select(_audit_event.c.payload).order_by(_audit_event.c.sequence))
            ).all()
        # SQLite/PG/Oracle JSON round-trip preserves logical equality
        # regardless of input dict-key order.
        assert rows[0].payload == {"a": 1, "b": 2}
        assert rows[1].payload == {"a": 1, "b": 2}


class TestFailureModes:
    async def test_append_raises_when_table_dropped(
        self, store: AuditStore, engine: AsyncEngine
    ) -> None:
        from sqlalchemy import text
        from sqlalchemy.exc import SQLAlchemyError

        async with engine.begin() as conn:
            await conn.execute(text("DROP TABLE audit_event"))
        # Fail-loud per the Sprint-2 plan: caller decides what to do
        # with a DB outage; AuditStore does not silently buffer.
        with pytest.raises(SQLAlchemyError):
            await store.append(AuditEvent(event_type="t", request_id="r", payload={}))

    async def test_append_raises_when_chain_head_missing(self, engine: AsyncEngine) -> None:
        # Migration 0001 seeds chain_heads; if the row is missing the
        # SELECT FOR UPDATE returns no rows and .one() raises
        # NoResultFound (a subclass of SQLAlchemyError).
        from sqlalchemy import text
        from sqlalchemy.exc import NoResultFound

        async with engine.begin() as conn:
            await conn.execute(
                text("DELETE FROM governance_chain_heads WHERE chain_id='audit_event'")
            )
        store = AuditStore(engine)
        with pytest.raises(NoResultFound):
            await store.append(AuditEvent(event_type="t", request_id="r", payload={}))


class TestModuleLevelTablesExportable:
    """core/chain_verifier (Task 8) and core/decision_history (Task 7)
    must be able to import the shared chain_heads + audit_event Tables
    + the metadata used to create them. Pin the public surface here so
    a future refactor doesn't silently break Task 7/8 consumers."""

    def test_metadata_exported(self) -> None:
        from cognic_agentos.core.audit import _metadata

        assert _metadata is not None

    def test_chain_heads_exported(self) -> None:
        from cognic_agentos.core.audit import _chain_heads

        assert _chain_heads.name == "governance_chain_heads"

    def test_audit_event_exported(self) -> None:
        from cognic_agentos.core.audit import _audit_event

        assert _audit_event.name == "audit_event"
