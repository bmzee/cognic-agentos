"""Sprint 11.5a T11 — episodes.recall_episodes (the long_term + purpose view).

CRITICAL CONTROL. ``recall_episodes`` is NOT a fourth memory tier — it is a
VIEW over the served-context agent's active ``long_term`` keyed records for a
subject, purpose-filtered, joined to ``decision_history`` for the originating
``trace_id`` (F2=A: read the ``_decision_history`` table through the store's
engine, match ``memory.write`` rows by ``payload["record_id"]``).

Pin-1: the read is agent-scoped (``tenant_id`` + ``agent_id`` threaded into
storage). Pin-2: ``similarity_threshold > 0.0`` FAILS LOUD — vector-ranked
recall is 11.5b; only ``0.0`` is supported in 11.5a.
"""

from __future__ import annotations

import dataclasses
import uuid

import pytest

from cognic_agentos.core.decision_history import DecisionRecord
from cognic_agentos.core.memory import episodes as _episodes
from cognic_agentos.core.memory._context import MemoryWriteRecord
from cognic_agentos.core.memory.storage import PostgresMemoryAdapter
from tests.unit.core.memory._builders import SUBJECT, _long_term_record


class _TracePostgresMemoryAdapter(PostgresMemoryAdapter):
    """Postgres adapter variant that stamps a non-None trace id on writes.

    Production trace context is threaded into the chain row by callers outside
    the memory adapter. This test conformer keeps the storage behavior intact
    while making the T11 decision-history join observable.
    """

    def _build_write_record(self, record: MemoryWriteRecord, rid: uuid.UUID) -> DecisionRecord:
        return dataclasses.replace(
            super()._build_write_record(record, rid), trace_id="trace-memory-1"
        )


async def test_recall_episodes_backed_by_long_term_not_a_fourth_tier(memory_adapter, dh_store):
    await memory_adapter.put(_long_term_record(purpose="fraud_detection"))
    eps = await _episodes.recall_episodes(
        SUBJECT,
        similarity_threshold=0.0,
        purpose="fraud_detection",
        adapter=memory_adapter,
        dh_store=dh_store,
        tenant_id="t1",
        agent_id="kyc",
    )
    assert len(eps) >= 1
    # The backing record really is a long_term record (the view is a slice over
    # long_term, not a new tier): the same record is readable on the long_term
    # tier via the keyed get.
    backing = await memory_adapter.get(
        tenant_id="t1", agent_id="kyc", subject=SUBJECT, tier="long_term", key="case-1"
    )
    assert backing is not None
    assert backing.tier == "long_term"


async def test_recall_episodes_respects_purpose_filter(memory_adapter, dh_store):
    await memory_adapter.put(_long_term_record(purpose="customer_support"))
    eps = await _episodes.recall_episodes(
        SUBJECT,
        similarity_threshold=0.0,
        purpose="fraud_detection",  # != stored purpose
        adapter=memory_adapter,
        dh_store=dh_store,
        tenant_id="t1",
        agent_id="kyc",
    )
    assert eps == []


async def test_recall_episodes_links_originating_decision_trace(_mem_engine, dh_store):
    traced_adapter = _TracePostgresMemoryAdapter(engine=_mem_engine, dh_store=dh_store)
    rid = await traced_adapter.put(_long_term_record(purpose="fraud_detection"))

    eps = await _episodes.recall_episodes(
        SUBJECT,
        similarity_threshold=0.0,
        purpose="fraud_detection",
        adapter=traced_adapter,
        dh_store=dh_store,
        tenant_id="t1",
        agent_id="kyc",
    )

    matched = [ep for ep in eps if ep.record_id == rid]
    assert len(matched) == 1
    assert matched[0].decision_trace_id == "trace-memory-1"


async def test_recall_episodes_fails_loud_on_nonzero_similarity_threshold(memory_adapter, dh_store):
    with pytest.raises(NotImplementedError):
        await _episodes.recall_episodes(
            SUBJECT,
            similarity_threshold=0.5,
            purpose="fraud_detection",
            adapter=memory_adapter,
            dh_store=dh_store,
            tenant_id="t1",
            agent_id="kyc",
        )


async def test_recall_episodes_is_agent_scoped(memory_adapter, dh_store):
    # Plant a long_term record for agent "kyc" AND one for agent "other" on the
    # SAME subject; recall_episodes scoped to "kyc" must return only kyc's.
    await memory_adapter.put(_long_term_record(purpose="fraud_detection"))
    await memory_adapter.put(
        dataclasses.replace(
            _long_term_record(value="other-case", purpose="fraud_detection"), agent_id="other"
        )
    )
    eps = await _episodes.recall_episodes(
        SUBJECT,
        similarity_threshold=0.0,
        purpose="fraud_detection",
        adapter=memory_adapter,
        dh_store=dh_store,
        tenant_id="t1",
        agent_id="kyc",
    )
    summaries = [e.summary for e in eps]
    assert "case" in summaries  # kyc's own record (default value="case")
    assert "other-case" not in summaries  # agent "other"'s record is invisible
