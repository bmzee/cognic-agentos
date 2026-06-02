"""T6 — redact() op (new sealed version). Sprint 11.5b.

CRITICAL CONTROL — core/ stop-rule per AGENTS.md (Memory governance
enforcement, ADR-019 §"Forget + redact"). Six pins:
  1. happy path: redact returns RedactionReceipt; old row sealed; new active row
     holds the redacted value; redaction_version == 1
  2. invalid path propagates as memory_redaction_path_invalid (op does NOT catch)
  3. sub-agent refusal wins BEFORE any storage access (no new DH rows written)
  4. delegates exactly once to redact_record with correct identity from gate ctx
     (tenant_id / agent_id / actor_id from gate._context, never caller args)
  5. exactly ONE memory.redact chain row; payload carries tenant/agent/actor ids
  6. no extra chain/value logic in the op layer (value-never-in-chain: the
     memory.redact payload carries no raw 'value' key)
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import DecisionHistoryStore, _decision_history
from cognic_agentos.core.memory._context import (
    MemoryCallerContext,
    MemoryWriteRecord,
    RedactionSpan,
)
from cognic_agentos.core.memory.gate import MemoryGate
from cognic_agentos.core.memory.storage import PostgresMemoryAdapter, _memory_records
from cognic_agentos.core.memory.tiers import MemoryOperationRefused, SubjectRef

# --------------------------------------------------------------------------- #
# Test-local DB engine fixture (standalone; mirrors conftest.py + test_forget) #
# --------------------------------------------------------------------------- #


@pytest.fixture
async def _engine(tmp_path):
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'redact.db'}")
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        await conn.run_sync(_memory_records.metadata.create_all)
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
def dh_store(_engine):
    return DecisionHistoryStore(_engine)


@pytest.fixture
def adapter(_engine, dh_store):
    return PostgresMemoryAdapter(engine=_engine, dh_store=dh_store)


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

TENANT = "t1"
AGENT = "kyc"
ACTOR = "svc"
SUBJECT = SubjectRef(kind="human", id="cust-7")


def _make_gate(*, is_subagent: bool, dh_store: DecisionHistoryStore) -> MemoryGate:
    from cognic_agentos.core.dlp.scanner import ChecksumRegexGazetteerScanner
    from cognic_agentos.core.memory.consent import ConsentValidator
    from cognic_agentos.core.memory.gate import MemoryGate

    class _InactiveKS:
        async def is_write_frozen(self, *, tenant_id: str) -> bool:
            return False

    class _AllowAll:
        async def evaluate(self, *, decision_point: str, input: object) -> object:
            from cognic_agentos.core.policy.engine import Decision

            return Decision(
                allow=True,
                rule_matched=decision_point,
                reasoning="test",
                decision_data=None,
            )

    ctx = MemoryCallerContext(
        tenant_id=TENANT,
        agent_id=AGENT,
        actor_id=ACTOR,
        served_subject=SUBJECT,
        is_subagent=is_subagent,
        long_term_writes_allowed=True,
        cross_subject_recall=False,
        memory_read_capabilities=frozenset(
            {"memory_read.scratch", "memory_read.task", "memory_read.long_term"}
        ),
        declared_purposes=frozenset({"customer_support"}),
        declared_data_classes=frozenset({"public", "internal"}),
        risk_tier="read_only",
    )
    return MemoryGate(
        context=ctx,
        dlp=ChecksumRegexGazetteerScanner(),
        consent=ConsentValidator(audit=dh_store),
        policy=_AllowAll(),  # type: ignore[arg-type]
        kill_switch=_InactiveKS(),
    )


async def _seed_struct_record(adapter: PostgresMemoryAdapter) -> uuid.UUID:
    """Insert one task-tier memory record with a dict value and return its UUID."""
    record = MemoryWriteRecord(
        tenant_id=TENANT,
        agent_id=AGENT,
        actor_id=ACTOR,
        subject=SUBJECT,
        tier="task",
        purpose="customer_support",
        data_classes=("public",),
        value={"account": {"number": "1234"}},
        request_id="memory-write-seed-struct",
        key="acct",
    )
    return await adapter.put(record)


async def _read_dh_rows(engine: AsyncEngine) -> list[Any]:
    """Return all decision_history rows ordered by sequence."""
    async with engine.connect() as conn:
        rows = (
            await conn.execute(select(_decision_history).order_by(_decision_history.c.sequence))
        ).all()
    return list(rows)


# --------------------------------------------------------------------------- #
# Tests                                                                        #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_happy_path_redact_returns_receipt_and_new_active_row(adapter, dh_store, _engine):
    """Pin 1: redact on a dict-valued record returns RedactionReceipt;
    old row is sealed (tombstoned); new active row holds redacted value;
    redaction_version == 1."""
    from cognic_agentos.core.memory.redact import redact

    rid = await _seed_struct_record(adapter)
    gate = _make_gate(is_subagent=False, dh_store=dh_store)

    span = RedactionSpan(path=("account", "number"))
    receipt = await redact(rid, span=span, reason="pii_minimization", gate=gate, adapter=adapter)

    assert receipt.record_id == rid
    assert receipt.redaction_version == 1
    assert isinstance(receipt.new_version_id, uuid.UUID)
    assert receipt.new_version_id != rid

    # Old row must be tombstoned (sealed).
    async with _engine.connect() as conn:
        old_row = (
            await conn.execute(select(_memory_records).where(_memory_records.c.record_id == rid))
        ).first()
    assert old_row is not None
    assert old_row.tombstone is not None, "old row must be sealed after redaction"

    # New active row carries the redacted value.
    hit = await adapter.get(
        tenant_id=TENANT,
        agent_id=AGENT,
        subject=SUBJECT,
        tier="task",
        key="acct",
    )
    assert hit is not None, "new active row must be retrievable"
    assert hit.record_id == receipt.new_version_id
    assert hit.value == {"account": {"number": "[REDACTED]"}}


@pytest.mark.asyncio
async def test_invalid_path_propagates_as_memory_redaction_path_invalid(adapter, dh_store):
    """Pin 2: an absent key in the redaction path propagates as
    memory_redaction_path_invalid. The op does NOT catch/translate — storage raises
    it and the op lets it propagate."""
    from cognic_agentos.core.memory.redact import redact

    rid = await _seed_struct_record(adapter)
    gate = _make_gate(is_subagent=False, dh_store=dh_store)

    # 'ssn' key does not exist in {"account": {"number": "1234"}}
    span = RedactionSpan(path=("account", "ssn"))
    with pytest.raises(MemoryOperationRefused) as ei:
        await redact(rid, span=span, reason="pii_minimization", gate=gate, adapter=adapter)

    assert ei.value.reason == "memory_redaction_path_invalid"


@pytest.mark.asyncio
async def test_subagent_refuses_before_any_storage_access(adapter, dh_store, _engine):
    """Pin 3: a sub-agent gate raises memory_subagent_durable_access_refused BEFORE
    any storage access — no new decision_history rows written (gate runs first)."""
    from cognic_agentos.core.memory.redact import redact

    rid = await _seed_struct_record(adapter)
    gate = _make_gate(is_subagent=True, dh_store=dh_store)

    # Capture DH row count BEFORE the call (after seeding: 1 memory.write row).
    pre_rows = await _read_dh_rows(_engine)
    pre_count = len(pre_rows)

    span = RedactionSpan(path=("account", "number"))
    with pytest.raises(MemoryOperationRefused) as ei:
        await redact(rid, span=span, reason="pii_minimization", gate=gate, adapter=adapter)

    assert ei.value.reason == "memory_subagent_durable_access_refused"

    # Exactly the same number of DH rows — storage was never reached.
    post_rows = await _read_dh_rows(_engine)
    assert len(post_rows) == pre_count, (
        "sub-agent refusal must not write any new decision_history rows"
    )


@pytest.mark.asyncio
async def test_delegates_exactly_once_identity_from_gate_context(adapter, dh_store, _engine):
    """Pin 4 + 5: exactly ONE memory.redact chain row; payload carries tenant/agent/actor
    from gate._context (t1/kyc/svc). Proves identity from ctx, not caller args."""
    from cognic_agentos.core.memory.redact import redact

    rid = await _seed_struct_record(adapter)
    gate = _make_gate(is_subagent=False, dh_store=dh_store)

    span = RedactionSpan(path=("account", "number"))
    await redact(rid, span=span, reason="pii_minimization", gate=gate, adapter=adapter)

    rows = await _read_dh_rows(_engine)
    redact_rows = [r for r in rows if r.event_type == "memory.redact"]
    assert len(redact_rows) == 1, f"expected exactly one memory.redact row; got {len(redact_rows)}"

    payload = redact_rows[0].payload
    assert payload["tenant_id"] == TENANT, f"tenant_id={payload['tenant_id']!r}"
    assert payload["agent_id"] == AGENT, f"agent_id={payload['agent_id']!r}"
    assert payload["actor_id"] == ACTOR, f"actor_id={payload['actor_id']!r}"


@pytest.mark.asyncio
async def test_value_never_in_chain_redact(adapter, dh_store, _engine):
    """Pin 6: the memory.redact chain row payload contains NO 'value' key.
    The op adds no chain/value logic — the raw value-never-in-chain invariant
    is enforced at the storage layer and the op does not introduce a raw value."""
    from cognic_agentos.core.memory.redact import redact

    rid = await _seed_struct_record(adapter)
    gate = _make_gate(is_subagent=False, dh_store=dh_store)

    span = RedactionSpan(path=("account", "number"))
    await redact(rid, span=span, reason="pii_minimization", gate=gate, adapter=adapter)

    rows = await _read_dh_rows(_engine)
    redact_rows = [r for r in rows if r.event_type == "memory.redact"]
    assert len(redact_rows) == 1

    payload = redact_rows[0].payload
    assert "value" not in payload, "raw value must never appear in memory.redact chain row"
    # redacted_value_digest IS allowed in the chain (storage emits it); raw value is not.
    assert "value" not in payload


@pytest.mark.asyncio
async def test_redact_record_called_with_correct_kwargs(adapter, dh_store):
    """Optional spy-adapter pin: redact_record is awaited exactly once with the
    correct kwargs (tenant_id / agent_id / actor_id / record_id / span / reason).
    Uses a spy wrapping the real adapter to capture the call kwargs."""
    from cognic_agentos.core.memory.redact import redact

    rid = await _seed_struct_record(adapter)
    gate = _make_gate(is_subagent=False, dh_store=dh_store)
    span = RedactionSpan(path=("account", "number"))

    calls: list[dict[str, object]] = []
    _original_redact_record = adapter.redact_record

    async def _spy_redact_record(**kwargs: object) -> object:
        calls.append(dict(kwargs))
        return await _original_redact_record(**kwargs)

    adapter.redact_record = _spy_redact_record

    await redact(rid, span=span, reason="pii_minimization", gate=gate, adapter=adapter)

    assert len(calls) == 1, f"expected exactly 1 call to redact_record; got {len(calls)}"
    kw = calls[0]
    assert kw["tenant_id"] == TENANT
    assert kw["agent_id"] == AGENT
    assert kw["actor_id"] == ACTOR
    assert kw["record_id"] == rid
    assert kw["span"] is span
    assert kw["reason"] == "pii_minimization"
