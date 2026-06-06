"""Sprint 11.5b T4 — storage erasure primitives (tombstone/purge/redact).

Re-grounded fixture names:
  - plan `pg_adapter` → `memory_adapter`  (PostgresMemoryAdapter from conftest)
  - plan `engine`     → `_mem_engine`     (AsyncEngine from conftest)
  - plan `subject_id="c1"` → `"cust-7"`  (matches SUBJECT = SubjectRef(kind="human", id="cust-7"))
  - _task_record() does NOT accept `key`; we use dataclasses.replace where needed.
"""

import dataclasses
import uuid
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.core.decision_history import _decision_history
from cognic_agentos.core.memory._context import (
    MemoryWriteRecord,
    RedactionSpan,
    RegulatorErasureCommand,
)
from cognic_agentos.core.memory.storage import _memory_records
from cognic_agentos.core.memory.tiers import MemoryOperationRefused, SubjectRef
from tests.unit.core.memory._builders import _task_record


async def _events(engine: AsyncEngine, decision_type: str) -> list[Any]:
    """Read decision_history rows of a given type."""
    async with engine.connect() as c:
        rows = (
            await c.execute(
                sa.select(_decision_history).where(_decision_history.c.event_type == decision_type)
            )
        ).all()
    return list(rows)


# --------------------------------------------------------------------------- #
# tombstone_record — soft delete
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_tombstone_record_sets_tombstone_and_emits_memory_forget(memory_adapter, _mem_engine):
    rid = await memory_adapter.put(_task_record(value="v"))
    await memory_adapter.tombstone_record(
        tenant_id="t1",
        agent_id="kyc",
        record_id=rid,
        reason="user_request",
        actor_id="a1",
    )
    async with _mem_engine.connect() as c:
        row = (
            await c.execute(sa.select(_memory_records).where(_memory_records.c.record_id == rid))
        ).first()
    assert row.tombstone is not None
    forget_events = await _events(_mem_engine, "memory.forget")
    assert len(forget_events) == 1  # chain-linked


@pytest.mark.asyncio
async def test_tombstone_missing_raises_not_found_no_event(memory_adapter, _mem_engine):
    with pytest.raises(MemoryOperationRefused) as ei:
        await memory_adapter.tombstone_record(
            tenant_id="t1",
            agent_id="kyc",
            record_id=uuid.uuid4(),
            reason="user_request",
            actor_id="a1",
        )
    assert ei.value.reason == "memory_record_not_found"
    # rolled back: no memory.forget event emitted
    assert await _events(_mem_engine, "memory.forget") == []


@pytest.mark.asyncio
async def test_tombstone_already_tombstoned_raises(memory_adapter):
    rid = await memory_adapter.put(_task_record(value="v"))
    await memory_adapter.tombstone_record(
        tenant_id="t1",
        agent_id="kyc",
        record_id=rid,
        reason="user_request",
        actor_id="a1",
    )
    with pytest.raises(MemoryOperationRefused) as ei:
        await memory_adapter.tombstone_record(
            tenant_id="t1",
            agent_id="kyc",
            record_id=rid,
            reason="user_request",
            actor_id="a1",
        )
    assert ei.value.reason == "memory_record_already_tombstoned"


# --------------------------------------------------------------------------- #
# purge_record — regulator erasure (physical delete + custody chain row)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_purge_record_deletes_row_and_emits_regulator_erasure_with_custody(
    memory_adapter, _mem_engine
):
    # SUBJECT.id == "cust-7"; subject_ref stored as "human:cust-7"
    rid = await memory_adapter.put(_task_record(value="secret"))
    cmd = RegulatorErasureCommand(
        regulator_order_id="ORD-7",
        requester_scope="memory.regulator_erasure",
        subject_id="cust-7",  # matches SUBJECT.id
    )
    await memory_adapter.purge_record(
        tenant_id="t1",
        agent_id="kyc",
        record_id=rid,
        erasure_command=cmd,
        actor_id="a1",
    )
    async with _mem_engine.connect() as c:
        gone = (
            await c.execute(sa.select(_memory_records).where(_memory_records.c.record_id == rid))
        ).first()
    assert gone is None  # row physically deleted
    rows = await _events(_mem_engine, "memory.regulator_erasure")
    assert len(rows) == 1
    payload = rows[0].payload
    assert payload["regulator_order_id"] == "ORD-7"
    assert payload["subject_id"] == "cust-7"
    # value NEVER in chain — neither raw value nor digest
    assert "redacted_value_digest" not in payload
    assert "value" not in payload


@pytest.mark.asyncio
async def test_purge_record_subject_mismatch_refuses_deletes_nothing(memory_adapter, _mem_engine):
    # The row is for SUBJECT = human:cust-7; the command names a different subject.
    # custody subject_id MUST match the row's subject_ref.
    rid = await memory_adapter.put(_task_record(value="secret"))
    bad = RegulatorErasureCommand(
        regulator_order_id="ORD-7",
        requester_scope="memory.regulator_erasure",
        subject_id="OTHER",  # mismatch — row is human:cust-7
    )
    with pytest.raises(MemoryOperationRefused) as ei:
        await memory_adapter.purge_record(
            tenant_id="t1",
            agent_id="kyc",
            record_id=rid,
            erasure_command=bad,
            actor_id="a1",
        )
    assert ei.value.reason == "memory_regulator_erasure_metadata_required"
    async with _mem_engine.connect() as c:
        still = (
            await c.execute(sa.select(_memory_records).where(_memory_records.c.record_id == rid))
        ).first()
    assert still is not None  # nothing deleted (rolled back)
    assert await _events(_mem_engine, "memory.regulator_erasure") == []  # no custody event


# --------------------------------------------------------------------------- #
# Review §4.3 — agent-kind regulator erasure (was silently broken: purge_record
# hardcoded "human:" so every agent-subject erasure failed the subject guard).
# --------------------------------------------------------------------------- #


def _agent_task_record(*, subject_id: str = "agent-9") -> MemoryWriteRecord:
    """A keyed task record owned by an AGENT-kind subject (subject_ref
    ``agent:<id>``). ``_task_record`` only builds the human SUBJECT."""
    return MemoryWriteRecord(
        tenant_id="t1",
        agent_id="kyc",
        actor_id="svc",
        subject=SubjectRef(kind="agent", id=subject_id),
        tier="task",
        purpose="customer_support",
        data_classes=("public",),
        value="agent-secret",
        request_id="memory-write-test",
        key="agent-greeting",
    )


@pytest.mark.asyncio
async def test_purge_record_agent_kind_deletes_and_emits_custody(memory_adapter, _mem_engine):
    rid = await memory_adapter.put(_agent_task_record(subject_id="agent-9"))
    cmd = RegulatorErasureCommand(
        regulator_order_id="ORD-A",
        requester_scope="memory.regulator_erasure",
        subject_id="agent-9",
        subject_kind="agent",  # matches the stored subject_ref "agent:agent-9"
    )
    await memory_adapter.purge_record(
        tenant_id="t1", agent_id="kyc", record_id=rid, erasure_command=cmd, actor_id="a1"
    )
    async with _mem_engine.connect() as c:
        gone = (
            await c.execute(sa.select(_memory_records).where(_memory_records.c.record_id == rid))
        ).first()
    assert gone is None  # agent record physically deleted (the §4.3 fix)
    rows = await _events(_mem_engine, "memory.regulator_erasure")
    assert len(rows) == 1
    assert rows[0].payload["subject_id"] == "agent-9"


@pytest.mark.asyncio
async def test_purge_record_cross_kind_mismatch_refuses(memory_adapter, _mem_engine):
    # Record is agent:agent-9; a command with the same id but the DEFAULT
    # subject_kind ("human") must be refused — kind is part of the subject guard,
    # so a human-kind erasure can never touch an agent record (and vice versa).
    rid = await memory_adapter.put(_agent_task_record(subject_id="agent-9"))
    wrong_kind = RegulatorErasureCommand(
        regulator_order_id="ORD-A",
        requester_scope="memory.regulator_erasure",
        subject_id="agent-9",
        # subject_kind omitted -> defaults "human" -> mismatch with agent:agent-9
    )
    with pytest.raises(MemoryOperationRefused) as ei:
        await memory_adapter.purge_record(
            tenant_id="t1",
            agent_id="kyc",
            record_id=rid,
            erasure_command=wrong_kind,
            actor_id="a1",
        )
    assert ei.value.reason == "memory_regulator_erasure_metadata_required"
    async with _mem_engine.connect() as c:
        still = (
            await c.execute(sa.select(_memory_records).where(_memory_records.c.record_id == rid))
        ).first()
    assert still is not None  # nothing deleted (rolled back)
    assert await _events(_mem_engine, "memory.regulator_erasure") == []


# --------------------------------------------------------------------------- #
# purge_expired — physical housekeeping sweep (no chain row)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_purge_expired_deletes_past_window_and_retention(memory_adapter, _mem_engine):
    from datetime import UTC, datetime, timedelta

    keep = await memory_adapter.put(dataclasses.replace(_task_record(value="keep"), key="k1"))
    old = await memory_adapter.put(dataclasses.replace(_task_record(value="old"), key="k2"))
    # tombstone 'old'
    await memory_adapter.tombstone_record(
        tenant_id="t1",
        agent_id="kyc",
        record_id=old,
        reason="user_request",
        actor_id="a1",
    )
    # backdate the tombstone past the window directly (test seam)
    async with _mem_engine.begin() as c:
        await c.execute(
            sa.update(_memory_records)
            .where(_memory_records.c.record_id == old)
            .values(tombstone=datetime.now(UTC) - timedelta(days=40))
        )
    n = await memory_adapter.purge_expired(tombstone_window_s=2_592_000)  # 30d
    assert n >= 1  # at minimum the old row was deleted
    async with _mem_engine.connect() as c:
        remaining = (await c.execute(sa.select(_memory_records.c.record_id))).all()
    remaining_ids = [r.record_id for r in remaining]
    assert keep in remaining_ids  # fresh row survives
    assert old not in remaining_ids  # past-window row gone


@pytest.mark.asyncio
async def test_purge_expired_leaves_fresh_tombstone(memory_adapter, _mem_engine):
    """A freshly tombstoned row (within the window) must NOT be purged."""
    rid = await memory_adapter.put(_task_record(value="fresh"))
    await memory_adapter.tombstone_record(
        tenant_id="t1",
        agent_id="kyc",
        record_id=rid,
        reason="user_request",
        actor_id="a1",
    )
    # tombstone is fresh — window is 30 days
    n = await memory_adapter.purge_expired(tombstone_window_s=2_592_000)
    assert n == 0
    async with _mem_engine.connect() as c:
        row = (
            await c.execute(sa.select(_memory_records).where(_memory_records.c.record_id == rid))
        ).first()
    assert row is not None  # still there (tombstoned but not purged)


@pytest.mark.asyncio
async def test_purge_expired_no_chain_row_written(memory_adapter, _mem_engine):
    """purge_expired is housekeeping — it emits ZERO chain rows."""
    from datetime import UTC, datetime, timedelta

    rid = await memory_adapter.put(_task_record(value="old"))
    await memory_adapter.tombstone_record(
        tenant_id="t1", agent_id="kyc", record_id=rid, reason="user_request", actor_id="a1"
    )
    async with _mem_engine.begin() as c:
        await c.execute(
            sa.update(_memory_records)
            .where(_memory_records.c.record_id == rid)
            .values(tombstone=datetime.now(UTC) - timedelta(days=40))
        )
    # count chain rows BEFORE purge
    async with _mem_engine.connect() as c:
        before = (await c.execute(sa.select(_decision_history))).all()
    n = await memory_adapter.purge_expired(tombstone_window_s=2_592_000)
    assert n >= 1
    async with _mem_engine.connect() as c:
        after = (await c.execute(sa.select(_decision_history))).all()
    assert len(after) == len(before)  # purge_expired writes NO chain row


# --------------------------------------------------------------------------- #
# redact_record — new sealed version
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_redact_record_new_version_seals_prior_emits_memory_redact(
    memory_adapter, _mem_engine
):
    rid = await memory_adapter.put(_task_record(value={"account": {"number": "1234"}}))
    receipt = await memory_adapter.redact_record(
        tenant_id="t1",
        agent_id="kyc",
        record_id=rid,
        span=RedactionSpan(path=("account", "number")),
        reason="pii_minimization",
        actor_id="a1",
    )
    assert receipt.record_id == rid
    assert receipt.redaction_version == 1
    async with _mem_engine.connect() as c:
        old = (
            await c.execute(sa.select(_memory_records).where(_memory_records.c.record_id == rid))
        ).first()
        new = (
            await c.execute(
                sa.select(_memory_records).where(
                    _memory_records.c.record_id == receipt.new_version_id
                )
            )
        ).first()
    assert old.tombstone is not None  # prior sealed (tombstoned)
    assert new.value == {"account": {"number": "[REDACTED]"}}
    assert new.sealed_prior_version_ref == rid
    assert new.redaction_version == 1
    redact_events = await _events(_mem_engine, "memory.redact")
    assert len(redact_events) == 1


@pytest.mark.asyncio
async def test_redact_invalid_path_refuses_no_version_no_event(memory_adapter, _mem_engine):
    rid = await memory_adapter.put(_task_record(value={"account": {}}))
    with pytest.raises(MemoryOperationRefused) as ei:
        await memory_adapter.redact_record(
            tenant_id="t1",
            agent_id="kyc",
            record_id=rid,
            span=RedactionSpan(path=("account", "number")),  # "number" missing in {}
            reason="correction",
            actor_id="a1",
        )
    assert ei.value.reason == "memory_redaction_path_invalid"
    # rolled back: no new version, no chain row
    assert await _events(_mem_engine, "memory.redact") == []


# --------------------------------------------------------------------------- #
# Composed lifecycle sequences (stateful-review requirement)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_tombstone_then_tombstone_again_refuses(memory_adapter):
    """Composed sequence: tombstone → tombstone same record → refuses (not_found after first)."""
    rid = await memory_adapter.put(_task_record(value="v"))
    await memory_adapter.tombstone_record(
        tenant_id="t1", agent_id="kyc", record_id=rid, reason="user_request", actor_id="a1"
    )
    with pytest.raises(MemoryOperationRefused) as ei:
        await memory_adapter.tombstone_record(
            tenant_id="t1", agent_id="kyc", record_id=rid, reason="user_request", actor_id="a1"
        )
    assert ei.value.reason == "memory_record_already_tombstoned"


@pytest.mark.asyncio
async def test_tombstone_nonexistent_refuses_not_found(memory_adapter):
    """Tombstone of a missing record refuses memory_record_not_found (no chain event)."""
    with pytest.raises(MemoryOperationRefused) as ei:
        await memory_adapter.tombstone_record(
            tenant_id="t1",
            agent_id="kyc",
            record_id=uuid.uuid4(),
            reason="user_request",
            actor_id="a1",
        )
    assert ei.value.reason == "memory_record_not_found"


@pytest.mark.asyncio
async def test_redact_then_new_version_readable(memory_adapter, _mem_engine):
    """Composed sequence: redact → read new version back (not just 'a new row exists')."""
    rid = await memory_adapter.put(_task_record(value={"account": {"number": "1234"}}))
    receipt = await memory_adapter.redact_record(
        tenant_id="t1",
        agent_id="kyc",
        record_id=rid,
        span=RedactionSpan(path=("account", "number")),
        reason="pii_minimization",
        actor_id="a1",
    )
    # Read back the NEW version via get() using new_version_id
    async with _mem_engine.connect() as c:
        new_row = (
            await c.execute(
                sa.select(_memory_records).where(
                    _memory_records.c.record_id == receipt.new_version_id
                )
            )
        ).first()
    # The new version carries the redacted value and has no tombstone
    assert new_row is not None
    assert new_row.value == {"account": {"number": "[REDACTED]"}}
    assert new_row.tombstone is None  # new version is active (not sealed)
    assert new_row.sealed_prior_version_ref == rid


@pytest.mark.asyncio
async def test_purge_regulator_erasure_value_never_in_chain(memory_adapter, _mem_engine):
    """The memory.regulator_erasure payload contains NO value / no redacted_value_digest."""
    rid = await memory_adapter.put(_task_record(value="top-secret"))
    cmd = RegulatorErasureCommand(
        regulator_order_id="ORD-99",
        requester_scope="memory.regulator_erasure",
        subject_id="cust-7",
    )
    await memory_adapter.purge_record(
        tenant_id="t1",
        agent_id="kyc",
        record_id=rid,
        erasure_command=cmd,
        actor_id="a1",
    )
    rows = await _events(_mem_engine, "memory.regulator_erasure")
    assert len(rows) == 1
    payload = rows[0].payload
    # Negative assertion: value-never-in-chain
    assert "value" not in payload
    assert "redacted_value_digest" not in payload
    # Custody fields present
    assert "regulator_order_id" in payload
    assert "subject_id" in payload


# --------------------------------------------------------------------------- #
# Cross-tenant / cross-agent isolation (P1 review fix). A record_id is a PRIMARY
# KEY, not an authorization boundary: every mutator's row-locking SELECT + its
# UPDATE/DELETE are scoped by tenant_id + agent_id. A wrong tenant or agent
# surfaces as memory_record_not_found (NOT subject-mismatch / already-tombstoned),
# mutates nothing, and emits no chain event. The seeded record is owned by
# t1/kyc, subject human:cust-7.
# --------------------------------------------------------------------------- #

_WRONG_SCOPE = [
    pytest.param("OTHER", "kyc", id="cross_tenant"),
    pytest.param("t1", "OTHER", id="cross_agent"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("tenant_id, agent_id", _WRONG_SCOPE)
async def test_tombstone_wrong_scope_refuses_not_found_unchanged_no_event(
    memory_adapter, _mem_engine, tenant_id, agent_id
):
    rid = await memory_adapter.put(_task_record(value="v"))
    with pytest.raises(MemoryOperationRefused) as ei:
        await memory_adapter.tombstone_record(
            tenant_id=tenant_id,
            agent_id=agent_id,
            record_id=rid,
            reason="user_request",
            actor_id="a1",
        )
    assert ei.value.reason == "memory_record_not_found"  # NOT already_tombstoned
    async with _mem_engine.connect() as c:
        row = (
            await c.execute(sa.select(_memory_records).where(_memory_records.c.record_id == rid))
        ).first()
    assert row is not None and row.tombstone is None  # original UNCHANGED
    assert await _events(_mem_engine, "memory.forget") == []  # zero chain events


@pytest.mark.asyncio
@pytest.mark.parametrize("tenant_id, agent_id", _WRONG_SCOPE)
async def test_purge_wrong_scope_refuses_not_found_unchanged_no_event(
    memory_adapter, _mem_engine, tenant_id, agent_id
):
    rid = await memory_adapter.put(_task_record(value="v"))
    # MATCHING subject_id — proves tenant/agent scoping, NOT the subject-mismatch guard.
    cmd = RegulatorErasureCommand(
        regulator_order_id="ORD-7", requester_scope="memory.regulator_erasure", subject_id="cust-7"
    )
    with pytest.raises(MemoryOperationRefused) as ei:
        await memory_adapter.purge_record(
            tenant_id=tenant_id,
            agent_id=agent_id,
            record_id=rid,
            erasure_command=cmd,
            actor_id="a1",
        )
    assert ei.value.reason == "memory_record_not_found"  # NOT regulator_erasure_metadata_required
    async with _mem_engine.connect() as c:
        row = (
            await c.execute(sa.select(_memory_records).where(_memory_records.c.record_id == rid))
        ).first()
    assert row is not None  # original NOT deleted
    assert await _events(_mem_engine, "memory.regulator_erasure") == []  # zero chain events


@pytest.mark.asyncio
@pytest.mark.parametrize("tenant_id, agent_id", _WRONG_SCOPE)
async def test_redact_wrong_scope_refuses_not_found_no_new_version_no_event(
    memory_adapter, _mem_engine, tenant_id, agent_id
):
    rid = await memory_adapter.put(_task_record(value={"account": {"number": "1234"}}))
    with pytest.raises(MemoryOperationRefused) as ei:
        await memory_adapter.redact_record(
            tenant_id=tenant_id,
            agent_id=agent_id,
            record_id=rid,
            span=RedactionSpan(path=("account", "number")),
            reason="pii_minimization",
            actor_id="a1",
        )
    assert ei.value.reason == "memory_record_not_found"  # NOT redaction_path_invalid
    async with _mem_engine.connect() as c:
        rows = (await c.execute(sa.select(_memory_records))).all()
    assert len(rows) == 1  # NO new version inserted
    assert rows[0].record_id == rid and rows[0].tombstone is None  # original unchanged
    assert await _events(_mem_engine, "memory.redact") == []  # zero chain events
