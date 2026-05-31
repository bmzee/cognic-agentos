import dataclasses
import hashlib

import pytest

from tests.unit.core.memory._builders import (
    AGENT_SUBJECT,
    _block_record,
    _scratch_record,
    _task_record,
)


async def test_put_emits_memory_write_event_with_digest_not_value(
    memory_adapter, decision_history_rows
):
    rid = await memory_adapter.put(_task_record(value="hello", tenant_id="t1"))
    rows = await decision_history_rows()
    ev = [r for r in rows if r.event_type == "memory.write"][-1]  # raw row column is event_type
    assert ev.payload["redacted_value_digest"] == hashlib.sha256(b'"hello"').hexdigest()
    assert "value" not in ev.payload  # value never enters the chain
    assert tuple(ev.iso_controls) == ("A.7.4", "A.8.2", "A.8.5", "A.10.2")
    assert ev.payload["subject_ref"] == "human:cust-7"
    assert rid is not None


async def test_upsert_block_tombstones_prior_then_inserts_atomically(memory_adapter):
    r1 = await memory_adapter.upsert_block(_block_record(value="v1"))
    r2 = await memory_adapter.upsert_block(_block_record(value="v2"))
    assert r1 != r2
    active = await memory_adapter.get(
        tenant_id="t1", block_kind="persona", subject=AGENT_SUBJECT, tier="long_term"
    )
    assert active.value == "v2"  # singleton: only the new version active


async def test_get_is_tenant_scoped_across_same_subject_and_block(memory_adapter):
    # Same subject + block_kind under two tenants must NOT leak across the tenant
    # boundary: each tenant's get() sees only its own row. The write path already
    # isolates tenants (upsert_block's tombstone WHERE filters tenant_id, so tb's
    # write does not tombstone ta's row), so both rows stay active — without the
    # tenant filter on get() both calls resolve the same arbitrary row and the two
    # assertions below cannot both hold.
    await memory_adapter.upsert_block(dataclasses.replace(_block_record(value="A"), tenant_id="ta"))
    await memory_adapter.upsert_block(dataclasses.replace(_block_record(value="B"), tenant_id="tb"))
    hit_a = await memory_adapter.get(
        tenant_id="ta", block_kind="persona", subject=AGENT_SUBJECT, tier="long_term"
    )
    hit_b = await memory_adapter.get(
        tenant_id="tb", block_kind="persona", subject=AGENT_SUBJECT, tier="long_term"
    )
    assert hit_a is not None and hit_a.value == "A"
    assert hit_b is not None and hit_b.value == "B"


async def test_put_refuses_scratch_tier_and_emits_no_chain_row(
    memory_adapter, decision_history_rows
):
    # PostgresMemoryAdapter persists task/long_term only — a misrouted scratch
    # record must be refused at the persistence boundary (Cut-A: no un-erasable
    # Postgres-scratch path) BEFORE any row or chain event is written.
    with pytest.raises(ValueError):
        await memory_adapter.put(_scratch_record(value="ephemeral"))
    rows = await decision_history_rows()
    assert [r for r in rows if r.event_type == "memory.write"] == []


async def test_upsert_block_refuses_non_long_term_tier_and_emits_no_chain_row(
    memory_adapter, decision_history_rows
):
    # Blocks are long_term-only — a block record with any other tier is refused at
    # the persistence boundary before any row or chain event is written.
    bad = dataclasses.replace(_block_record(value="x"), tier="task")
    with pytest.raises(ValueError):
        await memory_adapter.upsert_block(bad)
    rows = await decision_history_rows()
    assert [r for r in rows if r.event_type == "memory.write"] == []
