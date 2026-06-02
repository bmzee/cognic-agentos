"""T5 — forget() op (soft-delete + regulator-erasure). Sprint 11.5b.

CRITICAL CONTROL — core/ stop-rule per AGENTS.md (Memory governance
enforcement, ADR-019 §"Forget + redact"). Eight pins:
  1. soft forget → tombstone_record; ForgetReceipt(tombstoned=True, purged=False)
  2. regulator_erasure WITHOUT command → memory_regulator_erasure_metadata_required
  3. regulator_erasure with WRONG requester_scope → same refusal
  4. regulator_erasure + CORRECT command → purge_record; ForgetReceipt(purged=True)
  5. sub-agent soft forget → memory_subagent_durable_access_refused (gate FIRST)
  6. sub-agent + regulator_erasure + NO command → subagent refusal WINS
     (check_lifecycle runs before metadata gate)
  7. value-never-in-chain: memory.forget / memory.regulator_erasure payloads
     carry no ``value`` or ``redacted_value_digest``
  8. identity source: chain row records gate context's tenant/agent/actor
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
    RegulatorErasureCommand,
)
from cognic_agentos.core.memory.gate import MemoryGate
from cognic_agentos.core.memory.storage import PostgresMemoryAdapter, _memory_records
from cognic_agentos.core.memory.tiers import MemoryOperationRefused, SubjectRef

# --------------------------------------------------------------------------- #
# Test-local DB engine fixture (mirrors conftest.py but standalone so this     #
# file is independent; re-grounded from conftest.py patterns)                  #
# --------------------------------------------------------------------------- #


@pytest.fixture
async def _engine(tmp_path):
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'forget.db'}")
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


async def _seed_task_record(adapter: PostgresMemoryAdapter) -> uuid.UUID:
    """Insert one task-tier memory record and return its UUID."""
    from cognic_agentos.core.memory._context import MemoryWriteRecord

    record = MemoryWriteRecord(
        tenant_id=TENANT,
        agent_id=AGENT,
        actor_id=ACTOR,
        subject=SUBJECT,
        tier="task",
        purpose="customer_support",
        data_classes=("public",),
        value="hello",
        request_id="memory-write-seed",
        key="greeting",
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
async def test_soft_forget_tombstones_record_and_returns_receipt(adapter, dh_store, _engine):
    """Pin 1: soft forget with reason='user_request' calls tombstone_record and
    returns ForgetReceipt(tombstoned=True, purged=False)."""
    from cognic_agentos.core.memory.forget import forget

    rid = await _seed_task_record(adapter)
    gate = _make_gate(is_subagent=False, dh_store=dh_store)

    receipt = await forget(rid, reason="user_request", gate=gate, adapter=adapter)

    assert receipt.record_id == rid
    assert receipt.tombstoned is True
    assert receipt.purged is False

    # Verify the row was tombstoned in the DB.
    async with _engine.connect() as conn:
        row = (
            await conn.execute(select(_memory_records).where(_memory_records.c.record_id == rid))
        ).first()
    assert row is not None
    assert row.tombstone is not None


@pytest.mark.asyncio
async def test_regulator_erasure_without_command_refuses(adapter, dh_store):
    """Pin 2: regulator_erasure reason with erasure_command=None raises
    memory_regulator_erasure_metadata_required."""
    from cognic_agentos.core.memory.forget import forget

    rid = await _seed_task_record(adapter)
    gate = _make_gate(is_subagent=False, dh_store=dh_store)

    with pytest.raises(MemoryOperationRefused) as ei:
        await forget(
            rid, reason="regulator_erasure", gate=gate, adapter=adapter, erasure_command=None
        )
    assert ei.value.reason == "memory_regulator_erasure_metadata_required"


@pytest.mark.asyncio
async def test_regulator_erasure_with_wrong_scope_refuses(adapter, dh_store):
    """Pin 3: regulator_erasure with requester_scope != 'memory.regulator_erasure'
    raises memory_regulator_erasure_metadata_required."""
    from cognic_agentos.core.memory.forget import forget

    rid = await _seed_task_record(adapter)
    gate = _make_gate(is_subagent=False, dh_store=dh_store)

    bad_cmd = RegulatorErasureCommand(
        regulator_order_id="ORD-1",
        requester_scope="memory.read",  # wrong scope
        subject_id="cust-7",
    )

    with pytest.raises(MemoryOperationRefused) as ei:
        await forget(
            rid, reason="regulator_erasure", gate=gate, adapter=adapter, erasure_command=bad_cmd
        )
    assert ei.value.reason == "memory_regulator_erasure_metadata_required"


@pytest.mark.asyncio
async def test_regulator_erasure_with_correct_command_purges_and_returns_receipt(
    adapter, dh_store, _engine
):
    """Pin 4: regulator_erasure with correct command calls purge_record and returns
    ForgetReceipt(purged=True, tombstoned=True)."""
    from cognic_agentos.core.memory.forget import forget

    rid = await _seed_task_record(adapter)
    gate = _make_gate(is_subagent=False, dh_store=dh_store)

    good_cmd = RegulatorErasureCommand(
        regulator_order_id="ORD-99",
        requester_scope="memory.regulator_erasure",
        subject_id="cust-7",  # matches SUBJECT.id
    )

    receipt = await forget(
        rid, reason="regulator_erasure", gate=gate, adapter=adapter, erasure_command=good_cmd
    )

    assert receipt.record_id == rid
    assert receipt.tombstoned is True
    assert receipt.purged is True

    # The row should be physically deleted.
    async with _engine.connect() as conn:
        row = (
            await conn.execute(select(_memory_records).where(_memory_records.c.record_id == rid))
        ).first()
    assert row is None  # purge_record performs DELETE


@pytest.mark.asyncio
async def test_subagent_soft_forget_refuses_before_any_storage_access(adapter, dh_store, _engine):
    """Pin 5: a sub-agent gate raises memory_subagent_durable_access_refused
    on a soft forget BEFORE any storage access (gate runs first)."""
    from cognic_agentos.core.memory.forget import forget

    rid = await _seed_task_record(adapter)
    gate = _make_gate(is_subagent=True, dh_store=dh_store)

    # Capture DH row count before call to verify no storage mutation occurred.
    pre_rows = await _read_dh_rows(_engine)
    pre_count = len(pre_rows)

    with pytest.raises(MemoryOperationRefused) as ei:
        await forget(rid, reason="user_request", gate=gate, adapter=adapter)

    assert ei.value.reason == "memory_subagent_durable_access_refused"

    # No new DH rows — storage never reached.
    post_rows = await _read_dh_rows(_engine)
    assert len(post_rows) == pre_count  # only the seed's memory.write row


@pytest.mark.asyncio
async def test_subagent_regulator_erasure_without_command_subagent_refusal_wins(adapter, dh_store):
    """Pin 6: sub-agent + reason='regulator_erasure' + NO command →
    memory_subagent_durable_access_refused (check_lifecycle runs BEFORE metadata gate).
    The sub-agent refusal WINS over the missing-metadata check."""
    from cognic_agentos.core.memory.forget import forget

    rid = await _seed_task_record(adapter)
    gate = _make_gate(is_subagent=True, dh_store=dh_store)

    with pytest.raises(MemoryOperationRefused) as ei:
        # erasure_command=None would trigger memory_regulator_erasure_metadata_required,
        # but sub-agent check_lifecycle WINS because it runs first.
        await forget(
            rid, reason="regulator_erasure", gate=gate, adapter=adapter, erasure_command=None
        )

    # MUST be the sub-agent reason, NOT memory_regulator_erasure_metadata_required.
    assert ei.value.reason == "memory_subagent_durable_access_refused"


@pytest.mark.asyncio
async def test_value_never_in_chain_soft_forget(adapter, dh_store, _engine):
    """Pin 7a: the memory.forget chain row payload contains NO 'value' or
    'redacted_value_digest' key — the op layer never leaks raw value."""
    from cognic_agentos.core.memory.forget import forget

    rid = await _seed_task_record(adapter)
    gate = _make_gate(is_subagent=False, dh_store=dh_store)

    await forget(rid, reason="user_request", gate=gate, adapter=adapter)

    rows = await _read_dh_rows(_engine)
    # The _decision_history table stores decision_type as event_type column.
    forget_rows = [r for r in rows if r.event_type == "memory.forget"]
    assert len(forget_rows) == 1, "Expected exactly one memory.forget chain row"

    payload = forget_rows[0].payload
    assert "value" not in payload, "raw value must never appear in memory.forget chain row"
    assert "redacted_value_digest" not in payload, "no digest in memory.forget chain row"


@pytest.mark.asyncio
async def test_value_never_in_chain_regulator_erasure(adapter, dh_store, _engine):
    """Pin 7b: the memory.regulator_erasure chain row payload contains NO 'value'
    or 'redacted_value_digest' key."""
    from cognic_agentos.core.memory.forget import forget

    rid = await _seed_task_record(adapter)
    gate = _make_gate(is_subagent=False, dh_store=dh_store)

    good_cmd = RegulatorErasureCommand(
        regulator_order_id="ORD-42",
        requester_scope="memory.regulator_erasure",
        subject_id="cust-7",
    )
    await forget(
        rid, reason="regulator_erasure", gate=gate, adapter=adapter, erasure_command=good_cmd
    )

    rows = await _read_dh_rows(_engine)
    # The _decision_history table stores decision_type as event_type column.
    erasure_rows = [r for r in rows if r.event_type == "memory.regulator_erasure"]
    assert len(erasure_rows) == 1

    payload = erasure_rows[0].payload
    assert "value" not in payload, "no raw value in memory.regulator_erasure chain row"
    assert "redacted_value_digest" not in payload, "no digest in erasure chain row"


@pytest.mark.asyncio
async def test_identity_source_is_gate_context_not_caller_args(adapter, dh_store, _engine):
    """Pin 8: the memory.forget chain row records the gate context's tenant/agent/actor
    — the op threads ctx.* not any caller-supplied identity."""
    from cognic_agentos.core.memory.forget import forget

    rid = await _seed_task_record(adapter)
    gate = _make_gate(is_subagent=False, dh_store=dh_store)

    await forget(rid, reason="user_request", gate=gate, adapter=adapter)

    rows = await _read_dh_rows(_engine)
    # The _decision_history table stores decision_type as event_type column.
    forget_rows = [r for r in rows if r.event_type == "memory.forget"]
    assert len(forget_rows) == 1

    payload = forget_rows[0].payload
    assert payload["tenant_id"] == TENANT, f"tenant_id={payload['tenant_id']!r}"
    assert payload["agent_id"] == AGENT, f"agent_id={payload['agent_id']!r}"
    # actor_id is merged into payload by DecisionHistoryStore (not a top-level column).
    assert payload["actor_id"] == ACTOR, f"actor_id={payload['actor_id']!r}"
