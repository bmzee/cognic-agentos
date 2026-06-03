"""Sprint 11.5c T7 — episodes.recall_episodes (vector path wired).

CRITICAL CONTROL. ``recall_episodes`` is NOT a fourth memory tier — it is a
VIEW over the served-context agent's active ``long_term`` keyed records for a
subject, purpose-filtered, joined to ``decision_history`` for the originating
``trace_id`` (F2=A: read the ``_decision_history`` table through the store's
engine, match ``memory.write`` rows by ``payload["record_id"]``).

Pin-1: the read is agent-scoped (``tenant_id`` + ``agent_id`` threaded into
storage). Pin-2 (11.5a-11.5b): replaced in 11.5c — ``similarity_threshold > 0.0``
with ``query`` + ``vector_index`` now runs the real vector path;
without query or without vector_index it raises ``MemoryOperationRefused``.

Authz invariant: a vector hit whose ``id`` is NOT in the governed
``list_for_subject`` set is DROPPED (the authz-intersection is the security
crux). Score filter: hits below ``similarity_threshold`` are dropped.
"""

from __future__ import annotations

import dataclasses
import uuid

import pytest

from cognic_agentos.core.decision_history import DecisionRecord
from cognic_agentos.core.memory import episodes as _episodes
from cognic_agentos.core.memory._context import MemoryWriteRecord
from cognic_agentos.core.memory.storage import PostgresMemoryAdapter
from cognic_agentos.core.memory.tiers import MemoryOperationRefused
from cognic_agentos.core.memory.vector import MemoryVectorIndex
from cognic_agentos.db.adapters.protocols import VectorHit, VectorItem
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


async def test_recall_episodes_nonzero_threshold_without_query_refused(memory_adapter, dh_store):
    """``similarity_threshold > 0.0`` with ``query=None`` (default) →
    ``MemoryOperationRefused("memory_vector_recall_unavailable")``."""
    with pytest.raises(MemoryOperationRefused) as exc_info:
        await _episodes.recall_episodes(
            SUBJECT,
            similarity_threshold=0.5,
            purpose="fraud_detection",
            adapter=memory_adapter,
            dh_store=dh_store,
            tenant_id="t1",
            agent_id="kyc",
        )
    assert exc_info.value.reason == "memory_vector_recall_unavailable"


async def test_recall_episodes_nonzero_threshold_without_vector_index_refused(
    memory_adapter, dh_store
):
    """``similarity_threshold > 0.0`` with query but ``vector_index=None`` →
    ``MemoryOperationRefused("memory_vector_recall_unavailable")``."""
    with pytest.raises(MemoryOperationRefused) as exc_info:
        await _episodes.recall_episodes(
            SUBJECT,
            similarity_threshold=0.5,
            purpose="fraud_detection",
            adapter=memory_adapter,
            dh_store=dh_store,
            tenant_id="t1",
            agent_id="kyc",
            query="fraud case",
            vector_index=None,
        )
    assert exc_info.value.reason == "memory_vector_recall_unavailable"


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


# --------------------------------------------------------------------------- #
# Sprint 11.5c T7 — vector path (authz intersection + score filter)
# --------------------------------------------------------------------------- #


class _FakeEmbedder:
    """Structural EmbeddingAdapter conformer — returns a deterministic vector."""

    @property
    def dimensions(self) -> int:
        return 3

    async def embed(self, texts: list[str]) -> list[list[float]]:
        return [[float(len(t)), 0.0, 1.0] for t in texts]


class _FakeVectorClientForEpisodes:
    """Structural VectorAdapter conformer that returns a PRE-CONFIGURED hit list,
    regardless of the query vector. Used to inject known hits for authz-intersection
    and score-filter tests."""

    def __init__(self, hits: list[VectorHit]) -> None:
        self._hits = hits

    async def upsert(self, items: list[VectorItem]) -> None:
        pass

    async def search(
        self,
        vector: list[float],
        k: int = 10,
        filter: dict[str, object] | None = None,
    ) -> list[VectorHit]:
        assert filter is None, "filter must be None (client-side filtering)"
        return self._hits[:k]

    async def ensure_collection(self, name: str, dim: int, metric: str = "cosine") -> None:
        pass


def _fake_index(hits: list[VectorHit]) -> MemoryVectorIndex:
    """Build a MemoryVectorIndex backed by a fake client that returns ``hits``."""
    return MemoryVectorIndex(
        embedder=_FakeEmbedder(),  # type: ignore[arg-type]
        client=_FakeVectorClientForEpisodes(hits),  # type: ignore[arg-type]
        collection="memory-episodes",
    )


@pytest.mark.parametrize("blank", ["", "   ", "\t\n"])
async def test_recall_episodes_blank_query_refused(memory_adapter, dh_store, blank):
    """A blank / whitespace-only query is semantically "no query" and is REFUSED
    even with a wired vector_index + a governed record present — it must NOT
    bypass the contract and return governed episodes (P2). TM-revert: a guard
    that only checks ``query is None`` lets the blank query reach search and
    return the governed episode, so this raises nothing → FAIL."""
    rid = await memory_adapter.put(_long_term_record(purpose="fraud_detection"))
    index = _fake_index(
        [VectorHit(id=str(rid), score=0.95, payload={"purpose": "fraud_detection"})]
    )
    with pytest.raises(MemoryOperationRefused) as exc_info:
        await _episodes.recall_episodes(
            SUBJECT,
            similarity_threshold=0.5,
            purpose="fraud_detection",
            query=blank,
            vector_index=index,
            adapter=memory_adapter,
            dh_store=dh_store,
            tenant_id="t1",
            agent_id="kyc",
        )
    assert exc_info.value.reason == "memory_vector_recall_unavailable"


async def test_vector_path_authz_intersection_drops_ungoverned_hits(memory_adapter, dh_store):
    """A vector hit whose id is NOT in the governed ``list_for_subject`` set
    is DROPPED — the authz intersection is the security crux."""
    # Plant ONE governed long_term record (gets a real record_id after put).
    rid = await memory_adapter.put(_long_term_record(purpose="fraud_detection"))
    governed_id = str(rid)

    # The fake index returns the governed id PLUS a non-governed "ghost" id.
    ghost_id = str(uuid.uuid4())
    hits = [
        VectorHit(id=governed_id, score=0.95, payload={"purpose": "fraud_detection"}),
        VectorHit(id=ghost_id, score=0.90, payload={"purpose": "fraud_detection"}),
    ]
    index = _fake_index(hits)

    eps = await _episodes.recall_episodes(
        SUBJECT,
        similarity_threshold=0.5,
        purpose="fraud_detection",
        query="fraud case",
        vector_index=index,
        adapter=memory_adapter,
        dh_store=dh_store,
        tenant_id="t1",
        agent_id="kyc",
    )
    # Only the governed id survives; the ghost is dropped.
    returned_ids = [str(ep.record_id) for ep in eps]
    assert governed_id in returned_ids
    assert ghost_id not in returned_ids


async def test_vector_path_score_filter_drops_below_threshold(memory_adapter, dh_store):
    """Governed hits with ``score < similarity_threshold`` are dropped."""
    # Two governed records
    rid1 = await memory_adapter.put(
        dataclasses.replace(_long_term_record(value="case-a", purpose="fraud_detection"), key="k1")
    )
    rid2 = await memory_adapter.put(
        dataclasses.replace(_long_term_record(value="case-b", purpose="fraud_detection"), key="k2")
    )
    id1, id2 = str(rid1), str(rid2)

    # Fake index returns id1 at score 0.9 (above threshold) and id2 at 0.3 (below).
    hits = [
        VectorHit(id=id1, score=0.9, payload={"purpose": "fraud_detection"}),
        VectorHit(id=id2, score=0.3, payload={"purpose": "fraud_detection"}),
    ]
    index = _fake_index(hits)

    eps = await _episodes.recall_episodes(
        SUBJECT,
        similarity_threshold=0.5,
        purpose="fraud_detection",
        query="fraud",
        vector_index=index,
        adapter=memory_adapter,
        dh_store=dh_store,
        tenant_id="t1",
        agent_id="kyc",
    )
    returned_ids = [str(ep.record_id) for ep in eps]
    assert id1 in returned_ids  # score 0.9 >= 0.5 → kept
    assert id2 not in returned_ids  # score 0.3 < 0.5 → dropped


async def test_vector_path_returns_episodes_in_index_order(memory_adapter, dh_store):
    """Result order follows the vector index's similarity order (not storage order)."""
    rid1 = await memory_adapter.put(
        dataclasses.replace(_long_term_record(value="case-a", purpose="fraud_detection"), key="k1")
    )
    rid2 = await memory_adapter.put(
        dataclasses.replace(_long_term_record(value="case-b", purpose="fraud_detection"), key="k2")
    )
    id1, id2 = str(rid1), str(rid2)

    # Index returns id2 first (higher score), then id1.
    hits = [
        VectorHit(id=id2, score=0.95, payload={"purpose": "fraud_detection"}),
        VectorHit(id=id1, score=0.85, payload={"purpose": "fraud_detection"}),
    ]
    index = _fake_index(hits)

    eps = await _episodes.recall_episodes(
        SUBJECT,
        similarity_threshold=0.5,
        purpose="fraud_detection",
        query="fraud",
        vector_index=index,
        adapter=memory_adapter,
        dh_store=dh_store,
        tenant_id="t1",
        agent_id="kyc",
    )
    returned_ids = [str(ep.record_id) for ep in eps]
    assert returned_ids == [id2, id1], "Episodes must follow the index's similarity order"


async def test_zero_threshold_unchanged_view_query_ignored(memory_adapter, dh_store):
    """``similarity_threshold == 0.0`` → the unchanged long_term + purpose view
    (query and vector_index are ignored; the existing unranked path runs)."""
    await memory_adapter.put(_long_term_record(purpose="fraud_detection"))
    eps = await _episodes.recall_episodes(
        SUBJECT,
        similarity_threshold=0.0,
        purpose="fraud_detection",
        query="this query is ignored",
        vector_index=None,  # None is fine at 0.0 — vector path is skipped
        adapter=memory_adapter,
        dh_store=dh_store,
        tenant_id="t1",
        agent_id="kyc",
    )
    assert len(eps) >= 1  # the long_term + purpose view returns the planted record
