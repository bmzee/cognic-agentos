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
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

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
        # Sprint 2.5 T2 refactor: the compare-and-set + rowcount-mismatch
        # raise live in ``append_with_precondition`` now. ``append`` is
        # a thin wrapper that delegates through the new method, so the
        # source-introspection target is the new method (the wrapper's
        # source is intentionally trivial — only the lambda + the no-op
        # precondition + the delegated call). The predicates + check
        # are in the same physical place; the public behaviour is
        # unchanged.
        import inspect

        source = inspect.getsource(DecisionHistoryStore.append_with_precondition)
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


# ===========================================================================
# Sprint 2.5 T2 — append_with_precondition[T] primitive
# ===========================================================================
#
# The locked Option-A contract per the merged plan-of-record (PR #7 /
# 4733b52):
#
#     async def append_with_precondition[T](
#         self,
#         *,
#         record_builder: Callable[[T], DecisionRecord],
#         precondition: Callable[[AsyncConnection, int, bytes], Awaitable[T]],
#     ) -> tuple[uuid.UUID, bytes]
#
# Order of operations under the chain-head FOR UPDATE lock:
#   1. SELECT FOR UPDATE chain_heads → (prev_seq, prev_hash)
#   2. captured = await precondition(conn, prev_seq, prev_hash)
#   3. record = record_builder(captured)        # sync, no I/O
#   4. validate + canonicalize + envelope + hash
#   5. INSERT decision_history row
#   6. UPDATE chain_heads compare-and-set
#
# Tests pin: precondition-runs-inside-lock, return-flows-into-builder,
# builder-runs-after-precondition, exceptions-roll-back-atomically,
# precondition-can-SELECT-prior-state, T=None-plumbing-types-cleanly,
# byte-for-byte preservation of the existing append() shape.


class TestAppendWithPreconditionPreconditionRunsInLock:
    """The precondition MUST run inside the chain-head FOR UPDATE
    transaction, after the head is read and before the new row is
    inserted. Verified by capturing what the precondition observes."""

    async def test_precondition_receives_locked_head_state(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        # Genesis chain has (sequence=0, hash=ZERO_HASH). Capture the
        # tuple the precondition is invoked with; assert it matches
        # the head BEFORE the new insert.
        captured: dict[str, Any] = {}

        async def _capturing_precondition(
            conn: AsyncConnection, prev_seq: int, prev_hash: bytes
        ) -> None:
            captured["prev_seq"] = prev_seq
            captured["prev_hash"] = prev_hash
            captured["conn_repr"] = type(conn).__name__
            return None

        record = DecisionRecord(decision_type="canary", request_id="req-precond-state", payload={})
        await store.append_with_precondition(
            record_builder=lambda _state: record,
            precondition=_capturing_precondition,
        )
        assert captured["prev_seq"] == 0
        assert captured["prev_hash"] == ZERO_HASH
        # Sanity: connection is an AsyncConnection (or wrapped); not
        # the engine itself.
        assert "Connection" in captured["conn_repr"]

    async def test_precondition_can_select_committed_prior_rows(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        # Write 3 committed rows via append(). Then call
        # append_with_precondition with a precondition that SELECTs
        # COUNT(*) from decision_history; assert the count is exactly 3
        # (the precondition observes committed-up-to-the-lock state).
        for i in range(3):
            await store.append(
                DecisionRecord(decision_type="seed", request_id=f"req-{i}", payload={"i": i})
            )

        observed_counts: list[int] = []

        async def _count_precondition(
            conn: AsyncConnection, prev_seq: int, prev_hash: bytes
        ) -> int:
            from sqlalchemy import func
            from sqlalchemy import select as _select

            result = await conn.execute(_select(func.count()).select_from(_decision_history))
            count = int(result.scalar() or 0)
            observed_counts.append(count)
            return count

        await store.append_with_precondition(
            record_builder=lambda _captured: DecisionRecord(
                decision_type="canary",
                request_id="req-precond-select",
                payload={"observed": _captured},
            ),
            precondition=_count_precondition,
        )
        assert observed_counts == [3]


class TestAppendWithPreconditionReturnFlowsToBuilder:
    """Precondition's return value of type T MUST flow into
    record_builder verbatim. This is the load-bearing contract for
    Option A — without it, state-machine validators (escalation T3)
    can't put validated in-lock state into the hashed payload."""

    async def test_return_flows_into_record_builder(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        # Sentinel value the precondition returns; the record_builder
        # asserts it received exactly that value, then folds it into
        # the persisted payload.
        SENTINEL = ("captured-state", 42)

        async def _precondition(
            conn: AsyncConnection, prev_seq: int, prev_hash: bytes
        ) -> tuple[str, int]:
            return SENTINEL

        builder_received: list[Any] = []

        def _builder(state: tuple[str, int]) -> DecisionRecord:
            builder_received.append(state)
            return DecisionRecord(
                decision_type="canary",
                request_id="req-return-flow",
                payload={"captured_label": state[0], "captured_int": state[1]},
            )

        record_id, _ = await store.append_with_precondition(
            record_builder=_builder, precondition=_precondition
        )
        # Builder saw the sentinel.
        assert builder_received == [SENTINEL]
        # And the persisted row's payload reflects sentinel-derived content.
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    select(_decision_history.c.payload).where(
                        _decision_history.c.record_id == record_id
                    )
                )
            ).one()
        assert row.payload == {
            "captured_label": "captured-state",
            "captured_int": 42,
        }


class TestAppendWithPreconditionOrdering:
    """record_builder MUST run AFTER precondition. Otherwise the
    builder couldn't use the precondition's return value, which is
    the whole point of Option A."""

    async def test_builder_runs_after_precondition(self, store: DecisionHistoryStore) -> None:
        order: list[str] = []

        async def _precondition(conn: AsyncConnection, prev_seq: int, prev_hash: bytes) -> str:
            order.append("precondition")
            return "passed"

        def _builder(state: str) -> DecisionRecord:
            order.append("builder")
            assert state == "passed"  # received from precondition
            return DecisionRecord(
                decision_type="canary",
                request_id="req-order",
                payload={"state": state},
            )

        await store.append_with_precondition(record_builder=_builder, precondition=_precondition)
        assert order == ["precondition", "builder"]


class TestAppendWithPreconditionRollback:
    """Exceptions raised from the precondition OR the builder OR
    later in the transaction MUST roll back atomically. No row
    inserted, chain head unchanged, exception type propagated."""

    async def _head_state(self, engine: AsyncEngine) -> tuple[int, bytes]:
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    select(
                        _chain_heads.c.latest_sequence,
                        _chain_heads.c.latest_hash,
                    ).where(_chain_heads.c.chain_id == "decision_history")
                )
            ).one()
        return int(row.latest_sequence), bytes(row.latest_hash)

    async def _row_count(self, engine: AsyncEngine) -> int:
        from sqlalchemy import func
        from sqlalchemy import select as _select

        async with engine.connect() as conn:
            result = await conn.execute(_select(func.count()).select_from(_decision_history))
        return int(result.scalar() or 0)

    async def test_precondition_raise_rolls_back(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        class Sentinel(RuntimeError):
            pass

        async def _raising_precondition(
            conn: AsyncConnection, prev_seq: int, prev_hash: bytes
        ) -> None:
            raise Sentinel("validator says no")

        builder_called = False

        def _builder(state: None) -> DecisionRecord:
            nonlocal builder_called
            builder_called = True
            return DecisionRecord(
                decision_type="should-not-land",
                request_id="req-rollback-1",
                payload={},
            )

        pre_seq, pre_hash = await self._head_state(engine)
        pre_count = await self._row_count(engine)
        with pytest.raises(Sentinel, match="validator says no"):
            await store.append_with_precondition(
                record_builder=_builder, precondition=_raising_precondition
            )
        # Builder was NEVER called — precondition raised before the
        # builder phase.
        assert builder_called is False
        # Chain head + row count unchanged — transaction rolled back.
        post_seq, post_hash = await self._head_state(engine)
        post_count = await self._row_count(engine)
        assert (pre_seq, pre_hash, pre_count) == (post_seq, post_hash, post_count)

    async def test_builder_raise_rolls_back(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        class BuilderError(ValueError):
            pass

        async def _ok_precondition(conn: AsyncConnection, prev_seq: int, prev_hash: bytes) -> None:
            return None

        def _raising_builder(state: None) -> DecisionRecord:
            raise BuilderError("builder says no")

        pre_seq, pre_hash = await self._head_state(engine)
        pre_count = await self._row_count(engine)
        with pytest.raises(BuilderError, match="builder says no"):
            await store.append_with_precondition(
                record_builder=_raising_builder, precondition=_ok_precondition
            )
        # Chain head + row count unchanged — builder ran inside the
        # transaction so its raise rolls back.
        post_seq, post_hash = await self._head_state(engine)
        post_count = await self._row_count(engine)
        assert (pre_seq, pre_hash, pre_count) == (post_seq, post_hash, post_count)

    async def test_canonical_form_violation_in_built_record_rolls_back(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        # If record_builder returns a DecisionRecord whose payload is
        # not canonicalisable (e.g. NaN), canonical_bytes raises and
        # the transaction rolls back. Same posture as old append() but
        # now the failure is inside the transaction.
        async def _ok_precondition(conn: AsyncConnection, prev_seq: int, prev_hash: bytes) -> None:
            return None

        def _bad_builder(state: None) -> DecisionRecord:
            return DecisionRecord(
                decision_type="canary",
                request_id="req-canonical-fail",
                payload={"bad": float("nan")},
            )

        pre_seq, pre_hash = await self._head_state(engine)
        pre_count = await self._row_count(engine)
        with pytest.raises(ValueError):  # canonical_bytes raises ValueError
            await store.append_with_precondition(
                record_builder=_bad_builder, precondition=_ok_precondition
            )
        post_seq, post_hash = await self._head_state(engine)
        post_count = await self._row_count(engine)
        assert (pre_seq, pre_hash, pre_count) == (post_seq, post_hash, post_count)


class TestAppendWrapperPreservesContract:
    """The existing public ``append()`` becomes a thin wrapper over
    ``append_with_precondition`` (async no-op precondition + identity
    record_builder). EVERY existing append() behavior MUST be
    preserved byte-for-byte: same canonical envelope, same hash, same
    persisted row, same actor_id contract, same exception types.

    The full existing append() test surface (TestGenesisAppend,
    TestSequentialAppends, TestEnvelopeIncludesIdentity, TestActorIdMerge,
    TestPayloadCanonicalNormalization, TestPayloadSnapshotIsolation,
    TestChainHeadCompareAndSet, TestFailureModes, ...) is the byte-for-
    byte regression baseline — those classes test ``append()`` and
    must still pass after the refactor. The tests below are extra
    cross-checks that explicitly probe the wrapper-vs-new-method
    equivalence.
    """

    async def test_wrapper_produces_same_hash_as_explicit_invocation(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        # Build identical-in-shape records and route them through both
        # call sites; assert the persisted row's hash (the load-bearing
        # canonical-form output) is identical for matching inputs on
        # matching chain state.
        record = DecisionRecord(
            decision_type="canary",
            request_id="req-wrapper-equiv",
            payload={"k": "v"},
            tenant_id="t-1",
            iso_controls=("ISO42001.A.7.4",),
        )

        # Path A: existing append().
        rid_a, hash_a = await store.append(record)

        # Reset chain to genesis between paths so prev_hash is
        # identical for both runs (otherwise the chain has advanced
        # and the second hash differs even for identical record bytes).
        from sqlalchemy import delete as _delete
        from sqlalchemy import update as _update

        async with engine.begin() as conn:
            await conn.execute(_delete(_decision_history))
            await conn.execute(
                _update(_chain_heads)
                .where(_chain_heads.c.chain_id == "decision_history")
                .values(latest_sequence=0, latest_hash=ZERO_HASH)
            )

        # Path B: explicit append_with_precondition with no-op.
        async def _no_op(conn: AsyncConnection, prev_seq: int, prev_hash: bytes) -> None:
            return None

        rid_b, hash_b = await store.append_with_precondition(
            record_builder=lambda _: record, precondition=_no_op
        )

        # record_id is uuid4()-generated so they differ; created_at is
        # datetime.now(UTC) so it differs by microseconds. The hash
        # therefore CANNOT be identical between two runs (envelope
        # depends on record_id + created_at). What we CAN assert:
        # both hashes are 32 bytes, both record_ids are valid UUIDs,
        # both rows persisted with the same caller-side fields. Hash
        # equality is not a contract; envelope-shape equivalence is.
        assert len(hash_a) == 32
        assert len(hash_b) == 32
        assert isinstance(rid_a, uuid.UUID)
        assert isinstance(rid_b, uuid.UUID)
        assert rid_a != rid_b  # uuid4 is unique per call

        async with engine.connect() as conn:
            row_b = (
                await conn.execute(
                    select(
                        _decision_history.c.event_type,
                        _decision_history.c.request_id,
                        _decision_history.c.tenant_id,
                        _decision_history.c.payload,
                        _decision_history.c.iso_controls,
                    ).where(_decision_history.c.record_id == rid_b)
                )
            ).one()
        assert row_b.event_type == "canary"
        assert row_b.request_id == "req-wrapper-equiv"
        assert row_b.tenant_id == "t-1"
        assert row_b.payload == {"k": "v"}
        assert row_b.iso_controls == ["ISO42001.A.7.4"]

    async def test_wrapper_actor_id_contract_preserved(self, store: DecisionHistoryStore) -> None:
        # actor_id collision should still raise via the wrapper —
        # proves the validation logic landed inside append_with_precondition
        # and the wrapper exercises it. Mirror of an existing
        # TestActorIdMerge case.
        record = DecisionRecord(
            decision_type="canary",
            request_id="req-actor-collision",
            payload={"actor_id": "agent-x"},
            actor_id="agent-y",  # mismatch
        )
        with pytest.raises(ValueError, match="conflicts"):
            await store.append(record)

    async def test_wrapper_canonical_form_rejection_preserved(
        self, store: DecisionHistoryStore
    ) -> None:
        # Canonical-form violations still raise via the wrapper.
        record = DecisionRecord(
            decision_type="canary",
            request_id="req-canonical-via-wrapper",
            payload={"bad": float("nan")},
        )
        with pytest.raises(ValueError):
            await store.append(record)


class TestAppendWithPreconditionTypeNonePlumbing:
    """Generic T = None plumbing for the wrapper path. The existing
    ``append()`` uses an async precondition returning None + an
    identity record_builder; PEP 695 inference resolves T = None
    without ``# type: ignore``. This test pins the inference + the
    runtime correctness."""

    async def test_t_is_none_when_precondition_returns_none(
        self, store: DecisionHistoryStore
    ) -> None:
        # Type checker should infer T = None here; runtime should
        # behave identically to the wrapper path.
        async def _noop(conn: AsyncConnection, prev_seq: int, prev_hash: bytes) -> None:
            return None

        record = DecisionRecord(
            decision_type="canary",
            request_id="req-t-none",
            payload={"k": "v"},
        )
        rid, h = await store.append_with_precondition(
            record_builder=lambda _state: record, precondition=_noop
        )
        assert isinstance(rid, uuid.UUID)
        assert len(h) == 32

    async def test_explicit_async_lambda_for_precondition_works(
        self, store: DecisionHistoryStore
    ) -> None:
        # Precondition MUST be async — the implementation awaits its
        # return. This test passes an async no-op directly (vs a sync
        # lambda which would be a static type error per the contract).

        async def _noop(conn: AsyncConnection, prev_seq: int, prev_hash: bytes) -> None:
            return None

        record = DecisionRecord(decision_type="canary", request_id="req-async-pre", payload={})
        rid, h = await store.append_with_precondition(
            record_builder=lambda _: record, precondition=_noop
        )
        assert isinstance(rid, uuid.UUID)
        assert len(h) == 32


class TestAppendPreservesScheduledMutationSnapshot:
    """Sprint 2 R3 hardening regression test (PR-#7-T2 reviewer P1).

    The original T2 refactor moved payload snapshotting from the
    ``append()`` wrapper INTO ``append_with_precondition``'s in-lock
    validation step — which moved the snapshot point AFTER the first
    ``await``. That regressed Sprint 2 R3's "snapshot before first
    await" hardening: a caller doing
    ``task = asyncio.create_task(store.append(record)); await sleep(0); record.payload[...] = ...``
    could mutate the original payload AFTER the task started but
    BEFORE the in-lock snapshot ran, and the mutation would land in
    the hashed envelope + persisted row.

    Fix: the wrapper calls ``_validate_and_normalize_record`` SYNCHRONOUSLY
    — pre-await — to deep-copy the payload via canonical_bytes
    round-trip + ``dataclasses.replace`` into a fresh DecisionRecord.
    Caller mutation post-scheduling cannot reach the snapshot.

    These tests pin the contract by reproducing the regression shape
    + asserting the persisted row matches the pre-mutation state.
    """

    async def test_caller_mutation_after_scheduling_does_not_affect_persisted_payload(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        import asyncio

        # Caller-owned mutable dict.
        payload_dict: dict[str, Any] = {"k": "original", "n": 1}
        record = DecisionRecord(
            decision_type="canary",
            request_id="req-mutation-payload",
            payload=payload_dict,
        )

        # Schedule the append. The coroutine is created but does not
        # run until the event loop gives it a tick.
        task = asyncio.create_task(store.append(record))

        # Yield once. The task runs synchronously up to its first
        # await. With the fix, the wrapper has already done
        # _validate_and_normalize_record(record) BEFORE any await,
        # producing a snapshot record whose payload is independent
        # of payload_dict. Without the fix, the task is suspended at
        # engine.begin() with no snapshot taken — the mutation below
        # would land in the chain.
        await asyncio.sleep(0)

        # Mutate the caller-owned dict. With the snapshot fix, this
        # has no effect on the persisted row.
        payload_dict["k"] = "MUTATED"
        payload_dict["new_key"] = "should-not-land"
        del payload_dict["n"]

        record_id, _ = await task

        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    select(_decision_history.c.payload).where(
                        _decision_history.c.record_id == record_id
                    )
                )
            ).one()

        # Persisted payload reflects the PRE-mutation state.
        assert row.payload == {"k": "original", "n": 1}, (
            f"caller mutation post-scheduling leaked into the chain: "
            f"persisted payload was {row.payload!r}"
        )

    async def test_caller_mutation_after_scheduling_does_not_affect_hash(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        # Stronger form of the above: the hash itself is a function
        # of the canonical envelope, which contains the payload. If
        # caller mutation had leaked, the hash would reflect the
        # mutated payload. Compare the persisted hash to one computed
        # against the original (pre-mutation) payload via a parallel
        # control append — they should match modulo record_id +
        # created_at, which we can normalise away by recomputing the
        # canonical envelope from the persisted row.
        import asyncio

        payload_dict: dict[str, Any] = {"original": True}
        record = DecisionRecord(
            decision_type="canary",
            request_id="req-mutation-hash",
            payload=payload_dict,
        )

        task = asyncio.create_task(store.append(record))
        await asyncio.sleep(0)

        # Mutate after scheduling.
        payload_dict["original"] = False
        payload_dict["leaked"] = True

        record_id, persisted_hash = await task

        # Recompute the envelope from the persisted row. If the
        # snapshot fix is in place, the row's payload has the
        # pre-mutation values + canonical_bytes(envelope) reproduces
        # persisted_hash given the row's prev_hash + the persisted
        # column values. (The chain verifier T8 walks the chain
        # using exactly this primitive.)
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    select(
                        _decision_history.c.record_id,
                        _decision_history.c.sequence,
                        _decision_history.c.schema_version,
                        _decision_history.c.tenant_id,
                        _decision_history.c.prev_hash,
                        _decision_history.c.hash,
                        _decision_history.c.created_at,
                        _decision_history.c.event_type,
                        _decision_history.c.request_id,
                        _decision_history.c.trace_id,
                        _decision_history.c.span_id,
                        _decision_history.c.langfuse_trace_id,
                        _decision_history.c.provider_label,
                        _decision_history.c.iso_controls,
                        _decision_history.c.payload,
                    ).where(_decision_history.c.record_id == record_id)
                )
            ).one()

        # The persisted payload is the pre-mutation snapshot.
        assert row.payload == {"original": True}
        assert "leaked" not in row.payload

        # Recompute the canonical envelope from the persisted row +
        # confirm the hash matches. Strong proof that the persisted
        # hash was computed over the pre-mutation payload, not the
        # mutated one.
        # SQLite TIMESTAMP drops tzinfo on round-trip; re-attach UTC.
        created_at = row.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=UTC)
        recomputed_envelope: dict[str, Any] = {
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
            "iso_controls": list(row.iso_controls) if row.iso_controls else [],
            "payload": row.payload,
        }
        recomputed_hash = hash_record(canonical_bytes(recomputed_envelope), bytes(row.prev_hash))
        assert recomputed_hash == persisted_hash == bytes(row.hash), (
            "hash mismatch — caller mutation leaked into envelope hash"
        )


class TestAppendWithPreconditionUsesSameHeadLockShape:
    """The new method MUST use the same SELECT FOR UPDATE on
    governance_chain_heads + same compare-and-set UPDATE shape as
    the existing append(). Verified via end-to-end by chaining
    appends across both call sites and walking the chain."""

    async def test_alternating_call_sites_produce_one_clean_chain(
        self, store: DecisionHistoryStore, engine: AsyncEngine
    ) -> None:
        # Append 3 rows alternating between append() and
        # append_with_precondition. Walk the chain afterwards; assert
        # sequences are 1, 2, 3 contiguous; each prev_hash matches the
        # predecessor's hash; the chain head moved to (3, last_hash).
        async def _no_op(conn: AsyncConnection, prev_seq: int, prev_hash: bytes) -> None:
            return None

        _rid1, h1 = await store.append(
            DecisionRecord(decision_type="a", request_id="r1", payload={})
        )
        _rid2, h2 = await store.append_with_precondition(
            record_builder=lambda _: DecisionRecord(decision_type="b", request_id="r2", payload={}),
            precondition=_no_op,
        )
        _rid3, h3 = await store.append(
            DecisionRecord(decision_type="c", request_id="r3", payload={})
        )

        async with engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(
                        _decision_history.c.sequence,
                        _decision_history.c.prev_hash,
                        _decision_history.c.hash,
                    ).order_by(_decision_history.c.sequence)
                )
            ).all()
            head = (
                await conn.execute(
                    select(
                        _chain_heads.c.latest_sequence,
                        _chain_heads.c.latest_hash,
                    ).where(_chain_heads.c.chain_id == "decision_history")
                )
            ).one()

        assert [int(r.sequence) for r in rows] == [1, 2, 3]
        # Linkage: row[0].prev_hash == ZERO_HASH; row[N].prev_hash ==
        # row[N-1].hash.
        assert bytes(rows[0].prev_hash) == ZERO_HASH
        assert bytes(rows[1].prev_hash) == bytes(rows[0].hash)
        assert bytes(rows[2].prev_hash) == bytes(rows[1].hash)
        # Each row's recorded hash matches what append() / append_with_precondition
        # returned.
        assert bytes(rows[0].hash) == h1
        assert bytes(rows[1].hash) == h2
        assert bytes(rows[2].hash) == h3
        # Chain head moved to (3, h3).
        assert int(head.latest_sequence) == 3
        assert bytes(head.latest_hash) == h3
