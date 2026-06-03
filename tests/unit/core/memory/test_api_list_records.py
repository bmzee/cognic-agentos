"""Sprint 11.5c T4 — MemoryAPI.list_records (11th op) tests.

CRITICAL CONTROL. Pins five contracts:
  (a) value-free metadata — returns list[MemoryRecordMetadata]; NO ``value`` attr.
  (b) one honest memory.read — exactly one chain row with op="list_records" and
      payload["count"] == len(returned list).
  (c) sub-agent precedence — a sub-agent context → MemoryOperationRefused with
      reason "memory_subagent_durable_access_refused"; NO memory.read emitted.
  (d) scratch-exclusion (authz consistency) — scratch fallback rows returned by
      list_for_subject are excluded; payload["count"] reflects durable count only.
  (e) tenant+agent scoping preserved — a record written under a different agent_id
      is excluded; only the context's own agent records are returned.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from cognic_agentos.core.memory._context import MemoryCallerContext, MemoryRecordMetadata
from cognic_agentos.core.memory.tiers import MemoryOperationRefused

from ._builders import SUBJECT, _long_term_record, _scratch_record, _task_record
from .conftest import _READ_CAPS, _build_api, _ctx

# --------------------------------------------------------------------------- #
# Sub-agent context helper (mirrors test_api_export._subagent_ctx)
# --------------------------------------------------------------------------- #


def _subagent_ctx() -> MemoryCallerContext:
    return MemoryCallerContext(
        tenant_id="t1",
        agent_id="kyc",
        actor_id="svc",
        served_subject=SUBJECT,
        is_subagent=True,  # <-- key difference
        long_term_writes_allowed=False,
        cross_subject_recall=False,
        memory_read_capabilities=_READ_CAPS,
        declared_purposes=frozenset({"customer_support"}),
        declared_data_classes=frozenset({"public"}),
        risk_tier="read_only",
    )


# --------------------------------------------------------------------------- #
# (a) value-free metadata
# --------------------------------------------------------------------------- #


async def test_list_records_returns_memory_record_metadata_instances(memory_adapter, dh_store):
    """list_records returns a list of MemoryRecordMetadata with no value attribute."""
    ctx = _ctx(served_subject=SUBJECT, agent_id="kyc")
    api = _build_api(ctx, memory_adapter, dh_store)

    await memory_adapter.put(_task_record(value="hidden", key="k1"))

    result = await api.list_records(SUBJECT)

    assert isinstance(result, list)
    assert len(result) == 1
    meta = result[0]
    assert isinstance(meta, MemoryRecordMetadata)
    # MemoryRecordMetadata deliberately has NO value field.
    assert not hasattr(meta, "value")


async def test_list_records_metadata_fields_present(memory_adapter, dh_store):
    """Each MemoryRecordMetadata element carries record_id/agent_id/tier/
    data_classes/purpose/created_at/block_kind."""
    ctx = _ctx(served_subject=SUBJECT, agent_id="kyc")
    api = _build_api(ctx, memory_adapter, dh_store)

    await memory_adapter.put(_long_term_record(value="v", purpose="fraud_detection"))

    result = await api.list_records(SUBJECT)

    assert len(result) == 1
    meta = result[0]
    assert meta.agent_id == "kyc"
    assert meta.tier == "long_term"
    assert meta.purpose == "fraud_detection"
    assert isinstance(meta.data_classes, tuple)
    assert meta.created_at is not None
    # block_kind is None for a non-block record
    assert meta.block_kind is None


# --------------------------------------------------------------------------- #
# (b) one honest memory.read chain row
# --------------------------------------------------------------------------- #


async def test_list_records_emits_exactly_one_memory_read_row(
    memory_adapter, dh_store, decision_history_rows
):
    """list_records emits exactly one memory.read chain row with op=list_records."""
    ctx = _ctx(served_subject=SUBJECT, agent_id="kyc")
    api = _build_api(ctx, memory_adapter, dh_store)

    await memory_adapter.put(_task_record(value="x", key="k1"))
    await memory_adapter.put(_long_term_record(value="y"))

    await api.list_records(SUBJECT)

    rows = await decision_history_rows()
    read_rows = [r for r in rows if r.event_type == "memory.read"]
    # Exactly one memory.read — from list_records; the two put() calls emit
    # memory.write rows, not memory.read.
    assert len(read_rows) == 1
    row = read_rows[0]
    assert row.payload["op"] == "list_records"


async def test_list_records_chain_row_count_equals_returned_list_length(
    memory_adapter, dh_store, decision_history_rows
):
    """payload["count"] in the chain row equals len(returned list)."""
    ctx = _ctx(served_subject=SUBJECT, agent_id="kyc")
    api = _build_api(ctx, memory_adapter, dh_store)

    await memory_adapter.put(_task_record(value="x", key="k1"))
    await memory_adapter.put(_long_term_record(value="y"))

    result = await api.list_records(SUBJECT)

    rows = await decision_history_rows()
    read_rows = [r for r in rows if r.event_type == "memory.read"]
    assert len(read_rows) == 1
    assert read_rows[0].payload["count"] == len(result)


async def test_list_records_chain_row_hit_and_tiers(
    memory_adapter, dh_store, decision_history_rows
):
    """payload["hit"] is True when records exist; payload["tiers"] covers the
    enumerate tier set."""
    ctx = _ctx(served_subject=SUBJECT, agent_id="kyc")
    api = _build_api(ctx, memory_adapter, dh_store)

    await memory_adapter.put(_task_record(value="x", key="k1"))

    await api.list_records(SUBJECT)

    rows = await decision_history_rows()
    read_rows = [r for r in rows if r.event_type == "memory.read"]
    assert len(read_rows) == 1
    payload = read_rows[0].payload
    assert payload["hit"] is True
    assert set(payload["tiers"]) == {"task", "long_term"}
    assert payload["subject_ref"] == SUBJECT.canonical


async def test_list_records_hit_false_on_empty(memory_adapter, dh_store, decision_history_rows):
    """payload["hit"] is False and count is 0 when no durable records exist."""
    ctx = _ctx(served_subject=SUBJECT, agent_id="kyc")
    api = _build_api(ctx, memory_adapter, dh_store)

    result = await api.list_records(SUBJECT)

    assert result == []
    rows = await decision_history_rows()
    read_rows = [r for r in rows if r.event_type == "memory.read"]
    assert len(read_rows) == 1
    payload = read_rows[0].payload
    assert payload["hit"] is False
    assert payload["count"] == 0


# --------------------------------------------------------------------------- #
# (c) sub-agent precedence
# --------------------------------------------------------------------------- #


async def test_list_records_refuses_subagent(memory_adapter, dh_store):
    """A sub-agent context → MemoryOperationRefused before any read."""
    api = _build_api(_subagent_ctx(), memory_adapter, dh_store)

    with pytest.raises(MemoryOperationRefused) as exc_info:
        await api.list_records(SUBJECT)

    assert exc_info.value.reason == "memory_subagent_durable_access_refused"


async def test_list_records_subagent_emits_no_memory_read_row(
    memory_adapter, dh_store, decision_history_rows
):
    """A sub-agent refusal must NOT emit a memory.read chain row (gate refuses
    before the read and the audit emit)."""
    api = _build_api(_subagent_ctx(), memory_adapter, dh_store)

    with pytest.raises(MemoryOperationRefused):
        await api.list_records(SUBJECT)

    rows = await decision_history_rows()
    read_rows = [r for r in rows if r.event_type == "memory.read"]
    assert len(read_rows) == 0


# --------------------------------------------------------------------------- #
# (d) scratch-exclusion (authz consistency)
# --------------------------------------------------------------------------- #


async def test_list_records_excludes_scratch_fallback_rows(
    memory_adapter, dh_store, decision_history_rows
):
    """A scratch fallback row (put_scratch_fallback, still within TTL) is excluded
    from list_records — scratch was not capability-checked by check_enumerate.
    payload["count"] reflects the durable count only.

    TM-revert verified load-bearing: removing the _ENUMERATE_TIERS filter in
    MemoryAPI.list_records makes the scratch record appear in the result and
    count == 2 — this test then FAILS."""
    ctx = _ctx(served_subject=SUBJECT, agent_id="kyc")
    api = _build_api(ctx, memory_adapter, dh_store)

    # One durable record (should appear in result) ...
    durable_id = await memory_adapter.put(_long_term_record(value="DURABLE"))
    # ... and one scratch fallback row still within its TTL window.
    await memory_adapter.put_scratch_fallback(
        _scratch_record(value="SCRATCH", key="tmp", agent_id="kyc"),
        retention_until=datetime.now(UTC) + timedelta(hours=1),
    )

    result = await api.list_records(SUBJECT)

    # Only the durable record is returned.
    assert len(result) == 1
    assert result[0].record_id == durable_id
    assert result[0].tier != "scratch"

    # No element with tier == "scratch".
    assert all(m.tier != "scratch" for m in result)

    # The chain row count reflects the durable count only (1, NOT 2).
    rows = await decision_history_rows()
    read_rows = [r for r in rows if r.event_type == "memory.read"]
    assert len(read_rows) == 1
    assert read_rows[0].payload["count"] == 1


# --------------------------------------------------------------------------- #
# (e) tenant+agent scoping preserved
# --------------------------------------------------------------------------- #


async def test_list_records_excludes_other_agent_records(memory_adapter, dh_store):
    """list_records returns ONLY the context agent's records — a record written
    under a different agent_id (same tenant, same subject) is excluded."""
    from cognic_agentos.core.memory._context import MemoryWriteRecord

    ctx = _ctx(served_subject=SUBJECT, agent_id="kyc")
    api = _build_api(ctx, memory_adapter, dh_store)

    # Own record (agent "kyc") — should appear.
    kyc_id = await memory_adapter.put(_long_term_record(value="mine"))

    # Other-agent record — same tenant_id + subject, different agent_id.
    other_record = MemoryWriteRecord(
        tenant_id="t1",
        agent_id="other",
        actor_id="svc",
        subject=SUBJECT,
        tier="long_term",
        purpose="fraud_detection",
        data_classes=("internal",),
        value="theirs",
        request_id="memory-write-test",
        key="other-key",
    )
    await memory_adapter.put(other_record)

    result = await api.list_records(SUBJECT)

    # Only the "kyc" record is returned.
    assert len(result) == 1
    assert result[0].record_id == kyc_id
    assert result[0].agent_id == "kyc"
