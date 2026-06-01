import dataclasses
import hashlib

import pytest

from tests.unit.core.memory._builders import (
    AGENT_SUBJECT,
    SUBJECT,
    _block_record,
    _long_term_record,
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
        tenant_id="t1", agent_id="a", block_kind="persona", subject=AGENT_SUBJECT, tier="long_term"
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
        tenant_id="ta", agent_id="a", block_kind="persona", subject=AGENT_SUBJECT, tier="long_term"
    )
    hit_b = await memory_adapter.get(
        tenant_id="tb", agent_id="a", block_kind="persona", subject=AGENT_SUBJECT, tier="long_term"
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


# --------------------------------------------------------------------------- #
# Sprint 11.5a T10 — list_for_subject (recall enumerate surface).
# --------------------------------------------------------------------------- #


async def test_list_for_subject_returns_active_rows_across_tiers(memory_adapter):
    # A task row + a long_term row + a block, all for SUBJECT/AGENT_SUBJECT.
    await memory_adapter.put(dataclasses.replace(_task_record(value="t1v"), key="k1"))
    await memory_adapter.put(dataclasses.replace(_long_term_record(value="ltv"), key="k2"))
    hits = await memory_adapter.list_for_subject(tenant_id="t1", agent_id="kyc", subject=SUBJECT)
    assert {h.value for h in hits} == {"t1v", "ltv"}
    assert {h.tier for h in hits} == {"task", "long_term"}
    # Field mapping mirrors get(): data_classes is a tuple.
    for h in hits:
        assert isinstance(h.data_classes, tuple)
        assert h.created_at is not None


async def test_list_for_subject_is_tenant_scoped(memory_adapter):
    # Same subject + key under two tenants must not leak across the boundary.
    await memory_adapter.put(dataclasses.replace(_task_record(value="A"), tenant_id="ta", key="k"))
    await memory_adapter.put(dataclasses.replace(_task_record(value="B"), tenant_id="tb", key="k"))
    hits_a = await memory_adapter.list_for_subject(tenant_id="ta", agent_id="kyc", subject=SUBJECT)
    hits_b = await memory_adapter.list_for_subject(tenant_id="tb", agent_id="kyc", subject=SUBJECT)
    assert {h.value for h in hits_a} == {"A"}
    assert {h.value for h in hits_b} == {"B"}


async def test_list_for_subject_excludes_other_subjects(memory_adapter):
    await memory_adapter.put(dataclasses.replace(_task_record(value="mine"), key="k1"))
    await memory_adapter.upsert_block(_block_record(value="block"))  # AGENT_SUBJECT
    hits = await memory_adapter.list_for_subject(tenant_id="t1", agent_id="kyc", subject=SUBJECT)
    assert {h.value for h in hits} == {"mine"}  # the agent-subject block is excluded


async def test_list_for_subject_excludes_tombstoned_blocks(memory_adapter):
    # Two block versions: the first is tombstoned by the second (singleton).
    await memory_adapter.upsert_block(_block_record(value="old"))
    await memory_adapter.upsert_block(_block_record(value="new"))
    hits = await memory_adapter.list_for_subject(
        tenant_id="t1", agent_id="a", subject=AGENT_SUBJECT
    )
    assert [h.value for h in hits] == ["new"]  # only the active version


async def test_list_for_subject_empty_when_no_rows(memory_adapter):
    hits = await memory_adapter.list_for_subject(tenant_id="t1", agent_id="kyc", subject=SUBJECT)
    assert hits == []


# --------------------------------------------------------------------------- #
# Sprint 11.5a T10 — list_blocks (block-ref enumerate surface).
# --------------------------------------------------------------------------- #


async def test_list_blocks_returns_one_ref_per_active_kind(memory_adapter):
    await memory_adapter.upsert_block(_block_record(value="p", kind="persona"))
    await memory_adapter.upsert_block(_block_record(value="n", kind="agent_notes"))
    refs = await memory_adapter.list_blocks(tenant_id="t1", agent_id="a", subject=AGENT_SUBJECT)
    assert {r.kind for r in refs} == {"persona", "agent_notes"}
    assert all(r.subject == AGENT_SUBJECT for r in refs)


async def test_list_blocks_singleton_after_supersede(memory_adapter):
    # Upserting persona twice tombstones the first version; list_blocks returns
    # exactly ONE active persona ref (the COUNT is pinned, not the version value).
    await memory_adapter.upsert_block(_block_record(value="v1", kind="persona"))
    await memory_adapter.upsert_block(_block_record(value="v2", kind="persona"))
    refs = await memory_adapter.list_blocks(tenant_id="t1", agent_id="a", subject=AGENT_SUBJECT)
    persona = [r for r in refs if r.kind == "persona"]
    assert len(persona) == 1  # singleton invariant


async def test_list_blocks_excludes_keyed_rows(memory_adapter):
    # A keyed (non-block) long_term row for AGENT_SUBJECT must not appear.
    await memory_adapter.put(
        dataclasses.replace(
            _long_term_record(value="keyed"), subject=AGENT_SUBJECT, agent_id="a", key="k"
        )
    )
    await memory_adapter.upsert_block(_block_record(value="block", kind="persona"))
    refs = await memory_adapter.list_blocks(tenant_id="t1", agent_id="a", subject=AGENT_SUBJECT)
    assert {r.kind for r in refs} == {"persona"}  # only the block, not the keyed row


async def test_list_blocks_is_tenant_scoped(memory_adapter):
    await memory_adapter.upsert_block(dataclasses.replace(_block_record(value="A"), tenant_id="ta"))
    await memory_adapter.upsert_block(dataclasses.replace(_block_record(value="B"), tenant_id="tb"))
    refs_a = await memory_adapter.list_blocks(tenant_id="ta", agent_id="a", subject=AGENT_SUBJECT)
    refs_b = await memory_adapter.list_blocks(tenant_id="tb", agent_id="a", subject=AGENT_SUBJECT)
    assert len(refs_a) == 1
    assert len(refs_b) == 1


async def test_list_blocks_empty_when_no_blocks(memory_adapter):
    refs = await memory_adapter.list_blocks(tenant_id="t1", agent_id="a", subject=AGENT_SUBJECT)
    assert refs == []


# --------------------------------------------------------------------------- #
# Sprint 11.5a T10 — agent-scope isolation. Block singleton identity is
# (tenant, subject, agent, kind); reads MUST NOT leak across agents in a tenant.
# --------------------------------------------------------------------------- #


async def test_get_is_agent_scoped_across_same_tenant_subject_block(memory_adapter):
    # Two agents in the SAME tenant hold an active persona block for the SAME
    # subject (the singleton index keys on agent_id, so both stay active). get()
    # MUST resolve each agent's own block — without the agent_id filter both calls
    # resolve the same arbitrary row and the two assertions cannot both hold.
    await memory_adapter.upsert_block(_block_record(value="a-own"))  # agent "a"
    await memory_adapter.upsert_block(
        dataclasses.replace(_block_record(value="b-own"), agent_id="b")
    )
    hit_a = await memory_adapter.get(
        tenant_id="t1", agent_id="a", block_kind="persona", subject=AGENT_SUBJECT, tier="long_term"
    )
    hit_b = await memory_adapter.get(
        tenant_id="t1", agent_id="b", block_kind="persona", subject=AGENT_SUBJECT, tier="long_term"
    )
    assert hit_a is not None and hit_a.value == "a-own"
    assert hit_b is not None and hit_b.value == "b-own"


async def test_list_blocks_is_agent_scoped(memory_adapter):
    await memory_adapter.upsert_block(_block_record(value="a-own"))  # agent "a"
    await memory_adapter.upsert_block(
        dataclasses.replace(_block_record(value="b-own"), agent_id="b")
    )
    refs_a = await memory_adapter.list_blocks(tenant_id="t1", agent_id="a", subject=AGENT_SUBJECT)
    refs_b = await memory_adapter.list_blocks(tenant_id="t1", agent_id="b", subject=AGENT_SUBJECT)
    assert [r.kind for r in refs_a] == ["persona"]  # only agent a's block
    assert [r.kind for r in refs_b] == ["persona"]  # only agent b's block
    assert len(refs_a) == 1 and len(refs_b) == 1  # neither sees the other agent's


async def test_list_for_subject_is_agent_scoped(memory_adapter):
    # Two agents write a keyed task record for the SAME subject; each agent's
    # list_for_subject sees only its own row.
    await memory_adapter.put(dataclasses.replace(_task_record(value="a-row"), key="k"))  # agent kyc
    await memory_adapter.put(
        dataclasses.replace(_task_record(value="b-row"), agent_id="other", key="k")
    )
    hits_kyc = await memory_adapter.list_for_subject(
        tenant_id="t1", agent_id="kyc", subject=SUBJECT
    )
    hits_other = await memory_adapter.list_for_subject(
        tenant_id="t1", agent_id="other", subject=SUBJECT
    )
    assert {h.value for h in hits_kyc} == {"a-row"}
    assert {h.value for h in hits_other} == {"b-row"}
