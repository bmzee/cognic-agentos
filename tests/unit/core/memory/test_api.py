"""Sprint 11.5a T10 — MemoryAPI happy-path + memory.read audit wiring.

CRITICAL CONTROL. MemoryAPI is the single Layer-C access path: it wires the
T9 enforcement gate + the T6 adapter into the 6 public ops (remember / recall /
upsert_block / read_block / list_for_subject / list_blocks). These tests pin the
green-path wiring + the ``memory.read`` audit emission contract (keyed reads emit
one row carrying ``hit``; ``list_for_subject`` emits one enumerate row; ``list_blocks``
emits NONE). Refusal precedence is covered by the gate suites
(``test_write_gate.py`` / ``test_recall_gate.py`` / ``test_enumerate_gate.py``).
"""

from __future__ import annotations

import dataclasses

import pytest

from cognic_agentos.core.memory.tiers import MemoryOperationRefused
from tests.unit.core.memory._builders import AGENT_SUBJECT, SUBJECT, _block_record

# --------------------------------------------------------------------------- #
# Keyed roundtrip (remember -> recall).
# --------------------------------------------------------------------------- #


async def test_remember_then_recall_roundtrip_on_served_subject(api):
    rid = await api.remember(
        "greeting", "hi", tier="task", data_classes=["public"], purpose="customer_support"
    )
    hit = await api.recall("greeting", tier="task", purpose="customer_support")
    assert hit is not None
    assert hit.record_id == rid


# --------------------------------------------------------------------------- #
# Block singleton (upsert_block / read_block / list_blocks).
# --------------------------------------------------------------------------- #


async def test_upsert_block_is_singleton(agent_api):
    await agent_api.upsert_block(
        "persona",
        subject=AGENT_SUBJECT,
        value="v1",
        data_classes=["internal"],
        purpose="customer_support",
    )
    await agent_api.upsert_block(
        "persona",
        subject=AGENT_SUBJECT,
        value="v2",
        data_classes=["internal"],
        purpose="customer_support",
    )
    refs = await agent_api.list_blocks(AGENT_SUBJECT)
    persona = [r for r in refs if r.kind == "persona"]
    assert len(persona) == 1  # exactly one active persona block
    read = await agent_api.read_block("persona", subject=AGENT_SUBJECT, purpose="customer_support")
    assert read is not None
    assert read.value == "v2"


# --------------------------------------------------------------------------- #
# memory.read audit emission — keyed reads.
# --------------------------------------------------------------------------- #


async def test_recall_emits_memory_read_on_hit_and_miss(api, decision_history_rows):
    await api.remember(
        "greeting", "hi", tier="task", data_classes=["public"], purpose="customer_support"
    )
    await api.recall("greeting", tier="task", purpose="customer_support")  # hit
    await api.recall("absent", tier="task", purpose="customer_support")  # miss
    rows = await decision_history_rows()
    reads = [r for r in rows if r.event_type == "memory.read"]
    assert {r.payload["hit"] for r in reads} == {True, False}
    assert all(tuple(r.iso_controls) == ("A.7.4", "A.8.2") for r in reads)


async def test_read_block_emits_memory_read(agent_api, decision_history_rows):
    await agent_api.upsert_block(
        "persona",
        subject=AGENT_SUBJECT,
        value="v1",
        data_classes=["internal"],
        purpose="customer_support",
    )
    await agent_api.read_block("persona", subject=AGENT_SUBJECT, purpose="customer_support")
    rows = await decision_history_rows()
    reads = [r for r in rows if r.event_type == "memory.read"]
    assert len(reads) == 1
    assert reads[0].payload["hit"] is True
    assert reads[0].payload["subject_ref"] == AGENT_SUBJECT.canonical


# --------------------------------------------------------------------------- #
# memory.read audit emission — enumerate reads.
# --------------------------------------------------------------------------- #


async def test_list_for_subject_emits_single_enumerate_read(api, decision_history_rows):
    await api.remember("g1", "a", tier="task", data_classes=["public"], purpose="customer_support")
    await api.remember("g2", "b", tier="task", data_classes=["public"], purpose="customer_support")
    rows_before = await decision_history_rows()
    reads_before = [r for r in rows_before if r.event_type == "memory.read"]

    result = await api.list_for_subject(SUBJECT)
    assert len(result) == 2

    rows_after = await decision_history_rows()
    new_reads = [r for r in rows_after if r.event_type == "memory.read"][len(reads_before) :]
    assert len(new_reads) == 1  # exactly one enumerate row
    row = new_reads[0]
    assert row.payload["op"] == "list_for_subject"
    assert row.payload["hit"] is True
    assert row.payload["count"] == 2
    assert row.payload["tiers"] == ["task", "long_term"]
    assert row.payload["subject_ref"] == SUBJECT.canonical
    assert tuple(row.iso_controls) == ("A.7.4", "A.8.2")


async def test_list_for_subject_enumerate_read_records_miss_when_empty(api, decision_history_rows):
    result = await api.list_for_subject(SUBJECT)
    assert result == []
    rows = await decision_history_rows()
    reads = [r for r in rows if r.event_type == "memory.read"]
    assert len(reads) == 1
    assert reads[0].payload["op"] == "list_for_subject"
    assert reads[0].payload["hit"] is False
    assert reads[0].payload["count"] == 0


async def test_list_blocks_emits_no_memory_read(agent_api, decision_history_rows):
    result = await agent_api.list_blocks(AGENT_SUBJECT)  # no blocks yet -> empty
    assert result == []
    rows = await decision_history_rows()
    reads = [r for r in rows if r.event_type == "memory.read"]
    assert reads == []  # list_blocks never emits memory.read


# --------------------------------------------------------------------------- #
# Purpose matrix threads the STORED write purpose (P1). recall / read_block run
# the matrix AFTER the read, against hit.purpose — NOT write_purpose=None. The
# strict_* fixtures use a default-deny matrix (allow iff recall == write); the
# pre-fix code (matrix before the read, write_purpose=None) would have refused
# these same-purpose reads as memory_purpose_mismatch.
# --------------------------------------------------------------------------- #


async def test_recall_threads_stored_write_purpose(strict_purpose_api):
    rid = await strict_purpose_api.remember(
        "k", "v", tier="task", data_classes=["public"], purpose="customer_support"
    )
    # Permitted ONLY because the API threaded hit.purpose="customer_support"
    # into the matrix; write_purpose=None would have been refused.
    hit = await strict_purpose_api.recall("k", tier="task", purpose="customer_support")
    assert hit is not None
    assert hit.record_id == rid


async def test_recall_refuses_purpose_mismatch_against_stored(strict_purpose_api):
    await strict_purpose_api.remember(
        "k", "v", tier="task", data_classes=["public"], purpose="customer_support"
    )
    with pytest.raises(MemoryOperationRefused) as ei:
        # Recall purpose != stored write purpose -> matrix denies.
        await strict_purpose_api.recall("k", tier="task", purpose="fraud_detection")
    assert ei.value.reason == "memory_purpose_mismatch"


async def test_recall_miss_returns_none(strict_purpose_api, decision_history_rows):
    # A miss has no stored write purpose -> the matrix is N/A; the recall returns
    # None (NOT memory_purpose_mismatch) and emits a miss memory.read.
    result = await strict_purpose_api.recall("absent", tier="task", purpose="customer_support")
    assert result is None
    reads = [r for r in await decision_history_rows() if r.event_type == "memory.read"]
    assert len(reads) == 1
    assert reads[0].payload["hit"] is False


async def test_read_block_threads_stored_write_purpose(strict_purpose_agent_api):
    await strict_purpose_agent_api.upsert_block(
        "persona",
        subject=AGENT_SUBJECT,
        value="v1",
        data_classes=["internal"],
        purpose="customer_support",
    )
    read = await strict_purpose_agent_api.read_block(
        "persona", subject=AGENT_SUBJECT, purpose="customer_support"
    )
    assert read is not None
    assert read.value == "v1"


async def test_read_block_refuses_purpose_mismatch_against_stored(strict_purpose_agent_api):
    await strict_purpose_agent_api.upsert_block(
        "persona",
        subject=AGENT_SUBJECT,
        value="v1",
        data_classes=["internal"],
        purpose="customer_support",
    )
    with pytest.raises(MemoryOperationRefused) as ei:
        await strict_purpose_agent_api.read_block(
            "persona", subject=AGENT_SUBJECT, purpose="fraud_detection"
        )
    assert ei.value.reason == "memory_purpose_mismatch"


async def test_read_block_miss_returns_none_and_emits_read(agent_api, decision_history_rows):
    # No block written -> read_block returns None (the hit-is-None branch skips
    # the purpose check) and emits a miss memory.read.
    result = await agent_api.read_block(
        "persona", subject=AGENT_SUBJECT, purpose="customer_support"
    )
    assert result is None
    reads = [r for r in await decision_history_rows() if r.event_type == "memory.read"]
    assert len(reads) == 1
    assert reads[0].payload["hit"] is False


# --------------------------------------------------------------------------- #
# Agent-scope isolation at the API boundary (block identity includes agent_id;
# the API threads ctx.agent_id into the adapter read).
# --------------------------------------------------------------------------- #


async def test_read_block_and_list_blocks_are_agent_scoped_at_api(agent_api, memory_adapter):
    # agent_api serves AGENT_SUBJECT as agent "a". Plant a DIFFERENT agent "b"'s
    # active persona block for the same subject directly via storage; agent "a"'s
    # API reads MUST NOT see it — pre-fix (no agent_id filter) read_block could
    # return "b-secret" and list_blocks would return 2.
    await memory_adapter.upsert_block(
        dataclasses.replace(_block_record(value="b-secret"), agent_id="b")
    )
    await agent_api.upsert_block(
        "persona",
        subject=AGENT_SUBJECT,
        value="a-own",
        data_classes=["internal"],
        purpose="customer_support",
    )
    read = await agent_api.read_block("persona", subject=AGENT_SUBJECT, purpose="customer_support")
    assert read is not None
    assert read.value == "a-own"  # never agent b's "b-secret"
    refs = await agent_api.list_blocks(AGENT_SUBJECT)
    assert len([r for r in refs if r.kind == "persona"]) == 1  # only agent a's block
