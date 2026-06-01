"""Sprint 11.5a T11 — MemoryAPI.recall_episodes (the 7th 11.5a op).

CRITICAL CONTROL. ``recall_episodes`` is the Layer-C entry to the episodic
view: it runs the enumerate gate scoped to ``long_term``, delegates to
``episodes.recall_episodes``, and emits ONE enumerate-shape ``memory.read``
row (``payload["op"] == "recall_episodes"``; ISO controls ``("A.7.4",
"A.8.2")``). Pin-2: ``similarity_threshold > 0.0`` passes the gate then
propagates ``episodes``' ``NotImplementedError`` (no emit).

The ``api`` fixture serves SUBJECT as agent "kyc" with the allow-all policy +
``memory_read.long_term`` capability, so the enumerate gate clears for the
served subject. Records are planted via the real adapter (same pattern as
``test_api.py``).
"""

from __future__ import annotations

import pytest

from tests.unit.core.memory._builders import SUBJECT, _long_term_record


async def test_memory_api_recall_episodes_delegates(api, memory_adapter):
    await memory_adapter.put(_long_term_record(purpose="fraud_detection"))
    eps = await api.recall_episodes(SUBJECT, similarity_threshold=0.0, purpose="fraud_detection")
    assert len(eps) >= 1


async def test_recall_episodes_emits_memory_read(api, memory_adapter, decision_history_rows):
    await memory_adapter.put(_long_term_record(purpose="fraud_detection"))
    await api.recall_episodes(SUBJECT, similarity_threshold=0.0, purpose="fraud_detection")
    rows = await decision_history_rows()
    reads = [r for r in rows if r.event_type == "memory.read"]
    assert len(reads) == 1  # exactly one enumerate-shape read for the recall
    row = reads[0]
    assert tuple(row.iso_controls) == ("A.7.4", "A.8.2")
    assert row.payload["op"] == "recall_episodes"
    assert row.payload["purpose"] == "fraud_detection"
    assert row.payload["subject_ref"] == SUBJECT.canonical
    assert row.payload["hit"] is True
    assert row.payload["count"] >= 1


async def test_api_recall_episodes_fails_loud_on_nonzero_threshold(api):
    with pytest.raises(NotImplementedError):
        await api.recall_episodes(SUBJECT, similarity_threshold=0.5, purpose="fraud_detection")
