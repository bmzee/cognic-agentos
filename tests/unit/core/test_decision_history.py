"""DecisionHistoryStore — append-only hash-chained decision-history table.

Mirrors the AuditStore test surface against the parallel chain. Same
risks pinned (genesis, sequential linkage, envelope identity, compare-
and-set, payload normalisation, snapshot isolation, fail-loud); the
chain-isolation test runs the OTHER direction (a decision_history
append must not move the audit_event chain head).

Per Option 2 of the Sprint-2 plan: parallel implementation, no shared
base class. A future refactor may factor out _HashChainedAppendStore;
these tests become the regression baseline for that refactor.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import (
    ZERO_HASH,
    canonical_bytes,
    hash_record,
)
from cognic_agentos.core.decision_history import (
    DecisionHistoryStore,
    DecisionRecord,
    _decision_history,
)


@pytest.fixture
async def engine(tmp_path: Any) -> Any:
    """Per-test SQLite-aiosqlite engine with the governance schema +
    seeded chain heads. Mirrors migration 0001's shape. Imports
    _metadata from core.audit (single shared MetaData; both
    audit_event and decision_history Tables register against it)."""

    url = f"sqlite+aiosqlite:///{tmp_path / 'decision_history.db'}"
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
async def store(engine: AsyncEngine) -> DecisionHistoryStore:
    return DecisionHistoryStore(engine)


class TestDecisionRecordDataclass:
    def test_construct_minimum(self) -> None:
        r = DecisionRecord(decision_type="t", request_id="r", payload={})
        assert r.decision_type == "t"
        assert r.request_id == "r"
        assert r.payload == {}
        assert r.tenant_id is None
        assert r.iso_controls == ()

    def test_construct_full(self) -> None:
        r = DecisionRecord(
            decision_type="tool_call_approved",
            request_id="r-1",
            payload={"tool": "transfer", "amount": "100.00"},
            tenant_id="bank-acme",
            actor_id="agent-onboarding",
            trace_id="abc",
            span_id="def",
            langfuse_trace_id="lf-1",
            provider_label="vllm",
            iso_controls=("A.7.4", "A.10.2"),
        )
        assert r.iso_controls == ("A.7.4", "A.10.2")
        assert r.actor_id == "agent-onboarding"

    def test_frozen(self) -> None:
        import dataclasses

        r = DecisionRecord(decision_type="t", request_id="r", payload={})
        with pytest.raises(dataclasses.FrozenInstanceError):
            r.decision_type = "other"  # type: ignore[misc]


class TestGenesisAppend:
    async def test_returns_record_id_and_hash(self, store: DecisionHistoryStore) -> None:
        record_id, h = await store.append(
            DecisionRecord(decision_type="approved", request_id="r-1", payload={})
        )
        assert isinstance(record_id, uuid.UUID)
        assert isinstance(h, bytes)
        assert len(h) == 32

    async def test_row_persisted_with_zero_prev_hash(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        await store.append(DecisionRecord(decision_type="t", request_id="r-1", payload={}))
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    select(
                        _decision_history.c.sequence,
                        _decision_history.c.prev_hash,
                        _decision_history.c.schema_version,
                    )
                )
            ).one()
        assert row.sequence == 1
        assert bytes(row.prev_hash) == ZERO_HASH
        assert row.schema_version == 1

    async def test_chain_head_advanced(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        _, h = await store.append(DecisionRecord(decision_type="t", request_id="r-1", payload={}))
        async with engine.connect() as conn:
            head = (
                await conn.execute(
                    select(
                        _chain_heads.c.latest_sequence,
                        _chain_heads.c.latest_hash,
                    ).where(_chain_heads.c.chain_id == "decision_history")
                )
            ).one()
        assert head.latest_sequence == 1
        assert bytes(head.latest_hash) == h


class TestSequentialAppends:
    async def test_second_append_links_to_first(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        _, h1 = await store.append(DecisionRecord(decision_type="t", request_id="r-1", payload={}))
        _, h2 = await store.append(DecisionRecord(decision_type="t", request_id="r-2", payload={}))
        assert h1 != h2
        async with engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(_decision_history.c.sequence, _decision_history.c.prev_hash).order_by(
                        _decision_history.c.sequence
                    )
                )
            ).all()
        assert [r.sequence for r in rows] == [1, 2]
        assert bytes(rows[0].prev_hash) == ZERO_HASH
        assert bytes(rows[1].prev_hash) == h1

    async def test_chain_isolation_from_audit_event(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        # Mirror of the audit-side test, reverse direction. Appending to
        # decision_history MUST NOT advance the audit_event chain head.
        await store.append(DecisionRecord(decision_type="t", request_id="r", payload={}))
        async with engine.connect() as conn:
            head = (
                await conn.execute(
                    select(_chain_heads.c.latest_sequence).where(
                        _chain_heads.c.chain_id == "audit_event"
                    )
                )
            ).one()
        assert head.latest_sequence == 0


class TestEnvelopeIncludesIdentity:
    async def test_record_id_makes_hashes_unique(self, store: DecisionHistoryStore) -> None:
        r = DecisionRecord(decision_type="t", request_id="r", payload={"k": "v"})
        _, h1 = await store.append(r)
        _, h2 = await store.append(r)
        assert h1 != h2

    async def test_persisted_row_recomputes_to_stored_hash(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        # actor_id must end up in the persisted payload AND in the
        # canonical envelope used to compute the stored hash. Round-2
        # patch (P1): DecisionHistoryStore.append merges actor_id into
        # payload_snapshot before hashing/insertion.
        _, h = await store.append(
            DecisionRecord(
                decision_type="approved",
                request_id="r-1",
                payload={"reason": "policy ok"},
                actor_id="agent-x",
                tenant_id="bank-acme",
                iso_controls=("A.7.4",),
            )
        )
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    select(
                        _decision_history.c.record_id,
                        _decision_history.c.sequence,
                        _decision_history.c.schema_version,
                        _decision_history.c.tenant_id,
                        _decision_history.c.prev_hash,
                        _decision_history.c.created_at,
                        _decision_history.c.event_type,
                        _decision_history.c.request_id,
                        _decision_history.c.trace_id,
                        _decision_history.c.span_id,
                        _decision_history.c.langfuse_trace_id,
                        _decision_history.c.provider_label,
                        _decision_history.c.iso_controls,
                        _decision_history.c.payload,
                    )
                )
            ).one()

        # SQLite tzinfo carryover (same compensation as audit's round-
        # trip test).
        created_at = row.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=UTC)

        # Pin actor_id explicitly: it must be in the persisted payload
        # column AND it must round-trip through the canonical envelope
        # to recompute the stored hash. Without the Round-2 patch, this
        # assertion would fail (actor_id was silently dropped).
        assert row.payload["actor_id"] == "agent-x"
        assert row.payload["reason"] == "policy ok"

        envelope = {
            "schema_version": int(row.schema_version),
            "chain_id": "decision_history",
            "record_id": str(row.record_id),
            "sequence": int(row.sequence),
            "tenant_id": row.tenant_id,
            "created_at": created_at,
            # NOTE: the migration's column name is event_type and the
            # canonical envelope keeps that key for shape parity with
            # audit_event. DecisionRecord.decision_type maps to it.
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


class TestActorIdMerge:
    """Round-2 P1 patch: DecisionRecord.actor_id is merged into the
    normalised payload before hashing + insertion. Without this, actor
    provenance is silently dropped from the chain — a serious evidence
    gap. Collision with payload['actor_id'] requires equality."""

    async def test_actor_id_persisted_in_payload(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        await store.append(
            DecisionRecord(
                decision_type="approved",
                request_id="r-1",
                payload={"reason": "ok"},
                actor_id="agent-onboarding",
            )
        )
        async with engine.connect() as conn:
            row = (await conn.execute(select(_decision_history.c.payload))).one()
        assert row.payload == {"reason": "ok", "actor_id": "agent-onboarding"}

    async def test_actor_id_round_trip_chain_verifies(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        # Critical: actor_id must be in the canonical envelope used to
        # compute the stored hash. Otherwise the chain verifier would
        # see actor_id in the persisted payload, recompute the envelope
        # WITHOUT it, and report a false tamper.
        _, h = await store.append(
            DecisionRecord(
                decision_type="t",
                request_id="r",
                payload={"x": 1},
                actor_id="agent-x",
            )
        )
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    select(
                        _decision_history.c.record_id,
                        _decision_history.c.sequence,
                        _decision_history.c.schema_version,
                        _decision_history.c.tenant_id,
                        _decision_history.c.prev_hash,
                        _decision_history.c.created_at,
                        _decision_history.c.event_type,
                        _decision_history.c.request_id,
                        _decision_history.c.trace_id,
                        _decision_history.c.span_id,
                        _decision_history.c.langfuse_trace_id,
                        _decision_history.c.provider_label,
                        _decision_history.c.iso_controls,
                        _decision_history.c.payload,
                    )
                )
            ).one()
        created_at = row.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=UTC)
        envelope = {
            "schema_version": int(row.schema_version),
            "chain_id": "decision_history",
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
        # Sanity-pin: the actor_id IS in the payload that was hashed.
        assert envelope["payload"]["actor_id"] == "agent-x"

    async def test_actor_id_omitted_does_not_inject_key(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        # When actor_id=None, the merge is a no-op; existing payload
        # keys are preserved exactly. (Empty payload stays empty.)
        await store.append(DecisionRecord(decision_type="t", request_id="r", payload={"x": 1}))
        async with engine.connect() as conn:
            row = (await conn.execute(select(_decision_history.c.payload))).one()
        assert row.payload == {"x": 1}
        assert "actor_id" not in row.payload

    async def test_payload_actor_id_alone_preserved_when_dataclass_field_none(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        # If the caller put actor_id in payload directly without setting
        # the dataclass field, the merge is a no-op (the dataclass field
        # is None, no merge happens) — the payload keeps its actor_id.
        await store.append(
            DecisionRecord(
                decision_type="t",
                request_id="r",
                payload={"actor_id": "agent-from-payload"},
            )
        )
        async with engine.connect() as conn:
            row = (await conn.execute(select(_decision_history.c.payload))).one()
        assert row.payload == {"actor_id": "agent-from-payload"}

    async def test_actor_id_collision_with_equal_payload_value_succeeds(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        # Both sources agree → no error; persisted payload reflects the
        # (equal) value once.
        await store.append(
            DecisionRecord(
                decision_type="t",
                request_id="r",
                payload={"actor_id": "agent-x", "reason": "ok"},
                actor_id="agent-x",
            )
        )
        async with engine.connect() as conn:
            row = (await conn.execute(select(_decision_history.c.payload))).one()
        assert row.payload == {"actor_id": "agent-x", "reason": "ok"}

    async def test_actor_id_collision_mismatch_raises(self, store: DecisionHistoryStore) -> None:
        # Caller passed inconsistent actor provenance via dataclass +
        # payload. Silent overwrite would let one source override the
        # other (which one?). Raise loudly so the caller fixes the
        # ambiguity.
        with pytest.raises(ValueError, match="actor_id"):
            await store.append(
                DecisionRecord(
                    decision_type="t",
                    request_id="r",
                    payload={"actor_id": "agent-from-payload"},
                    actor_id="agent-from-dataclass",
                )
            )

    async def test_payload_explicit_none_collides_with_dataclass_value(
        self, store: DecisionHistoryStore
    ) -> None:
        # Round-3 P2: ``payload['actor_id'] = None`` is "explicitly
        # no actor" — distinct from "actor_id absent". The collision
        # policy must treat the explicit-None as a value to compare
        # against the dataclass field; otherwise a caller-typo would
        # silently overwrite the explicit None.
        with pytest.raises(ValueError, match="actor_id"):
            await store.append(
                DecisionRecord(
                    decision_type="t",
                    request_id="r",
                    payload={"actor_id": None},
                    actor_id="agent-x",
                )
            )

    async def test_payload_explicit_none_with_no_dataclass_actor_preserved(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        # If both sides agree on "no actor" (dataclass=None, payload
        # explicit None), the merge is a no-op; the explicit None is
        # preserved in the persisted payload.
        await store.append(
            DecisionRecord(
                decision_type="t",
                request_id="r",
                payload={"actor_id": None, "x": 1},
            )
        )
        async with engine.connect() as conn:
            row = (await conn.execute(select(_decision_history.c.payload))).one()
        assert row.payload == {"actor_id": None, "x": 1}

    async def test_non_string_dataclass_actor_id_rejected(
        self, store: DecisionHistoryStore
    ) -> None:
        # Round-3 P2: the annotation says str | None but Python doesn't
        # enforce. UUID / Decimal / int / etc. would bypass the
        # canonical normalisation (which ran on payload, not on the
        # dataclass field) and land non-string actor provenance into
        # the JSON column — bind behaviour diverges by dialect.
        # Reject explicitly.
        with pytest.raises(TypeError, match="actor_id"):
            await store.append(
                DecisionRecord(
                    decision_type="t",
                    request_id="r",
                    payload={},
                    actor_id=uuid.uuid4(),  # type: ignore[arg-type]
                )
            )

    async def test_non_string_payload_actor_id_rejected(self, store: DecisionHistoryStore) -> None:
        # canonical_bytes preserves int / float / bool verbatim — they
        # don't get projected to strings. Reject at the raw boundary
        # so actor_id is always str-or-None in persisted rows.
        with pytest.raises(TypeError, match="actor_id"):
            await store.append(
                DecisionRecord(
                    decision_type="t",
                    request_id="r",
                    payload={"actor_id": 42},  # int — would survive canonical
                )
            )

    async def test_uuid_payload_actor_id_rejected_pre_normalization(
        self, store: DecisionHistoryStore
    ) -> None:
        # Round-4 P2: canonical_bytes auto-promotes UUID to its 36-char
        # hex string. A type check that ran POST-normalisation would
        # see the resulting string and silently pass — contradicting
        # the str|None contract. The raw-payload check rejects at the
        # API boundary BEFORE canonical normalisation runs.
        with pytest.raises(TypeError, match="actor_id"):
            await store.append(
                DecisionRecord(
                    decision_type="t",
                    request_id="r",
                    payload={"actor_id": uuid.uuid4()},
                )
            )

    async def test_decimal_payload_actor_id_rejected_pre_normalization(
        self, store: DecisionHistoryStore
    ) -> None:
        # Same auto-promotion family: canonical_bytes serializes
        # Decimal as str(value).
        from decimal import Decimal

        with pytest.raises(TypeError, match="actor_id"):
            await store.append(
                DecisionRecord(
                    decision_type="t",
                    request_id="r",
                    payload={"actor_id": Decimal("42.0")},
                )
            )

    async def test_bytes_payload_actor_id_rejected_pre_normalization(
        self, store: DecisionHistoryStore
    ) -> None:
        # canonical_bytes serializes bytes as standard base64 ASCII.
        with pytest.raises(TypeError, match="actor_id"):
            await store.append(
                DecisionRecord(
                    decision_type="t",
                    request_id="r",
                    payload={"actor_id": b"agent-x"},
                )
            )

    async def test_regular_enum_payload_actor_id_rejected_pre_normalization(
        self, store: DecisionHistoryStore
    ) -> None:
        # Regular Enum (NOT a StrEnum subclass) is not a str at runtime;
        # canonical_bytes serializes via .value. The raw check rejects
        # because isinstance(Enum.X, str) is False.
        from enum import Enum

        class V(Enum):
            X = "agent-x"

        with pytest.raises(TypeError, match="actor_id"):
            await store.append(
                DecisionRecord(
                    decision_type="t",
                    request_id="r",
                    payload={"actor_id": V.X},
                )
            )

    async def test_strenum_payload_actor_id_accepted(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        # StrEnum members ARE str subclasses at the type level, so
        # ``isinstance(StrEnum.X, str)`` is True. Behaviourally
        # equivalent to passing the .value directly. Allowed.
        from enum import StrEnum

        class Agent(StrEnum):
            X = "agent-x"

        await store.append(
            DecisionRecord(
                decision_type="t",
                request_id="r",
                payload={"actor_id": Agent.X},
            )
        )
        async with engine.connect() as conn:
            row = (await conn.execute(select(_decision_history.c.payload))).one()
        # Persisted as the .value string.
        assert row.payload == {"actor_id": "agent-x"}


class TestSchemaVersion:
    async def test_schema_version_is_one(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        await store.append(DecisionRecord(decision_type="t", request_id="r", payload={}))
        async with engine.connect() as conn:
            row = (await conn.execute(select(_decision_history.c.schema_version))).one()
        assert row.schema_version == 1


class TestTenantId:
    async def test_tenant_id_persists_when_provided(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        await store.append(
            DecisionRecord(decision_type="t", request_id="r", payload={}, tenant_id="bank-acme")
        )
        async with engine.connect() as conn:
            row = (await conn.execute(select(_decision_history.c.tenant_id))).one()
        assert row.tenant_id == "bank-acme"

    async def test_tenant_id_null_when_omitted(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        await store.append(DecisionRecord(decision_type="t", request_id="r", payload={}))
        async with engine.connect() as conn:
            row = (await conn.execute(select(_decision_history.c.tenant_id))).one()
        assert row.tenant_id is None


class TestIsoControlsHandling:
    async def test_tuple_input_works(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        await store.append(
            DecisionRecord(
                decision_type="t",
                request_id="r",
                payload={},
                iso_controls=("A.7.4", "A.10.2"),
            )
        )
        async with engine.connect() as conn:
            row = (await conn.execute(select(_decision_history.c.iso_controls))).one()
        assert row.iso_controls == ["A.7.4", "A.10.2"]

    async def test_empty_iso_controls_persists_as_empty_list(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        await store.append(DecisionRecord(decision_type="t", request_id="r", payload={}))
        async with engine.connect() as conn:
            row = (await conn.execute(select(_decision_history.c.iso_controls))).one()
        assert row.iso_controls == []


class TestPayloadCanonicalNormalization:
    """Same Round-3 hardening as AuditStore: payload normalised via
    json.loads(canonical_bytes(payload)) at method boundary."""

    async def test_datetime_payload_normalized_to_iso_string(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        ts = datetime(2026, 4, 28, 12, 0, 0, tzinfo=UTC)
        await store.append(DecisionRecord(decision_type="t", request_id="r", payload={"ts": ts}))
        async with engine.connect() as conn:
            row = (await conn.execute(select(_decision_history.c.payload))).one()
        assert row.payload == {"ts": "2026-04-28T12:00:00+00:00"}

    async def test_decimal_payload_normalized_to_string(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        from decimal import Decimal

        await store.append(
            DecisionRecord(
                decision_type="approved",
                request_id="r",
                payload={"amount": Decimal("99.99")},
            )
        )
        async with engine.connect() as conn:
            row = (await conn.execute(select(_decision_history.c.payload))).one()
        assert row.payload == {"amount": "99.99"}

    async def test_tuple_in_payload_raises_at_method_boundary(
        self, store: DecisionHistoryStore
    ) -> None:
        with pytest.raises(TypeError, match="tuple"):
            await store.append(
                DecisionRecord(
                    decision_type="t",
                    request_id="r",
                    payload={"items": (1, 2, 3)},
                )
            )

    async def test_naive_datetime_in_payload_raises_at_method_boundary(
        self, store: DecisionHistoryStore
    ) -> None:
        with pytest.raises(ValueError, match="naive datetime"):
            await store.append(
                DecisionRecord(
                    decision_type="t",
                    request_id="r",
                    payload={"ts": datetime(2026, 4, 28, 12, 0, 0)},
                )
            )


class TestPayloadSnapshotIsolation:
    async def test_caller_mutation_after_append_returns_does_not_affect_persisted_row(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        payload: dict[str, Any] = {"a": 1, "nested": {"b": 2}}
        await store.append(DecisionRecord(decision_type="t", request_id="r", payload=payload))
        payload["a"] = 999
        payload["nested"]["b"] = 999
        async with engine.connect() as conn:
            row = (await conn.execute(select(_decision_history.c.payload))).one()
        assert row.payload == {"a": 1, "nested": {"b": 2}}


class TestChainHeadCompareAndSet:
    def test_compare_and_set_predicates_and_rowcount_check_in_source(self) -> None:
        import inspect

        source = inspect.getsource(DecisionHistoryStore.append)
        assert "latest_sequence == prev_sequence" in source
        assert "latest_hash == prev_hash" in source
        assert "update_result.rowcount" in source and "RuntimeError" in source

    async def test_compare_and_set_raises_on_zero_rowcount(
        self, engine: AsyncEngine, store: DecisionHistoryStore, monkeypatch: Any
    ) -> None:
        from sqlalchemy.ext.asyncio import AsyncConnection

        real_execute = AsyncConnection.execute

        class _ZeroRowcountResult:
            def __init__(self, inner: Any) -> None:
                self._inner = inner

            @property
            def rowcount(self) -> int:
                return 0

            def __getattr__(self, name: str) -> Any:
                return getattr(self._inner, name)

        async def patched_execute(self_conn: Any, statement: Any, *args: Any, **kwargs: Any) -> Any:
            result = await real_execute(self_conn, statement, *args, **kwargs)
            try:
                sql = str(statement)
            except Exception:
                sql = ""
            if "UPDATE governance_chain_heads" in sql:
                return _ZeroRowcountResult(result)
            return result

        monkeypatch.setattr(AsyncConnection, "execute", patched_execute)

        with pytest.raises(RuntimeError, match="compare-and-set"):
            await store.append(DecisionRecord(decision_type="t", request_id="r", payload={}))


class TestFailureModes:
    async def test_append_raises_when_table_dropped(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        from sqlalchemy import text
        from sqlalchemy.exc import SQLAlchemyError

        async with engine.begin() as conn:
            await conn.execute(text("DROP TABLE decision_history"))
        with pytest.raises(SQLAlchemyError):
            await store.append(DecisionRecord(decision_type="t", request_id="r", payload={}))

    async def test_append_raises_when_chain_head_missing(self, engine: AsyncEngine) -> None:
        from sqlalchemy import text
        from sqlalchemy.exc import NoResultFound

        async with engine.begin() as conn:
            await conn.execute(
                text("DELETE FROM governance_chain_heads WHERE chain_id='decision_history'")
            )
        store = DecisionHistoryStore(engine)
        with pytest.raises(NoResultFound):
            await store.append(DecisionRecord(decision_type="t", request_id="r", payload={}))


class TestModuleLevelTablesExportable:
    """core/chain_verifier (Task 8) imports _decision_history; pin the
    public surface here so a future refactor doesn't silently break it."""

    def test_decision_history_table_exported(self) -> None:
        from cognic_agentos.core.decision_history import _decision_history

        assert _decision_history.name == "decision_history"

    def test_decision_history_shares_metadata_with_audit_event(self) -> None:
        # Both Tables must register against the same MetaData so a
        # single _metadata.create_all() (or alembic 0001) creates both.
        from cognic_agentos.core.audit import _metadata as audit_metadata
        from cognic_agentos.core.decision_history import _decision_history

        assert _decision_history.metadata is audit_metadata
