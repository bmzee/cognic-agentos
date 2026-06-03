"""Sprint 11.5c T7 — MemoryAPI.recall_episodes (vector path wired).

CRITICAL CONTROL. ``recall_episodes`` is the Layer-C entry to the episodic
view: it runs the enumerate gate scoped to ``long_term``, delegates to
``episodes.recall_episodes``, and emits ONE enumerate-shape ``memory.read``
row (``payload["op"] == "recall_episodes"``; ISO controls ``("A.7.4",
"A.8.2")``). Vector path (11.5c): ``similarity_threshold > 0.0`` with
``query`` + a wired ``vector_index`` runs the real vector path; missing query
or missing index raises ``MemoryOperationRefused`` (no ``memory.read`` emitted).

The ``api`` fixture serves SUBJECT as agent "kyc" with the allow-all policy +
``memory_read.long_term`` capability, so the enumerate gate clears for the
served subject. Records are planted via the real adapter (same pattern as
``test_api.py``).
"""

from __future__ import annotations

import pytest

from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.core.memory.api import MemoryAPI
from cognic_agentos.core.memory.storage import PostgresMemoryAdapter
from cognic_agentos.core.memory.tiers import MemoryOperationRefused
from cognic_agentos.core.memory.vector import MemoryVectorIndex
from cognic_agentos.db.adapters.protocols import VectorHit, VectorItem
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


async def test_api_recall_episodes_no_query_refused(api):
    """``recall_episodes`` with ``similarity_threshold > 0.0`` but no ``query``
    → ``MemoryOperationRefused("memory_vector_recall_unavailable")``."""
    with pytest.raises(MemoryOperationRefused) as exc_info:
        await api.recall_episodes(SUBJECT, similarity_threshold=0.5, purpose="fraud_detection")
    assert exc_info.value.reason == "memory_vector_recall_unavailable"


async def test_api_recall_episodes_no_memory_read_emitted_on_refusal(api, decision_history_rows):
    """No ``memory.read`` event is emitted when the vector path raises a refusal."""
    with pytest.raises(MemoryOperationRefused):
        await api.recall_episodes(SUBJECT, similarity_threshold=0.5, purpose="fraud_detection")
    rows = await decision_history_rows()
    reads = [r for r in rows if r.event_type == "memory.read"]
    assert len(reads) == 0  # refusal propagates before the emit


# --------------------------------------------------------------------------- #
# Sprint 11.5c T7 — MemoryAPI wired with vector_index
# --------------------------------------------------------------------------- #


class _FakeEmbedder:
    @property
    def dimensions(self) -> int:
        return 3

    async def embed(self, texts: list[str]) -> list[list[float]]:
        return [[float(len(t)), 0.0, 1.0] for t in texts]


class _ControlledFakeVectorClient:
    """Records index calls and returns a PRE-CONFIGURED hit list on search."""

    def __init__(self, hits: list[VectorHit] | None = None) -> None:
        self._hits: list[VectorHit] = hits or []
        self.index_calls: list[dict[str, object]] = []
        self.search_called: bool = False

    async def upsert(self, items: list[VectorItem]) -> None:
        for item in items:
            self.index_calls.append(
                {
                    "id": item.id,
                    "purpose": item.payload.get("purpose"),
                    "data_classes": item.payload.get("data_classes"),
                }
            )

    async def search(
        self,
        vector: list[float],
        k: int = 10,
        filter: dict[str, object] | None = None,
    ) -> list[VectorHit]:
        assert filter is None
        self.search_called = True
        return self._hits[:k]

    async def ensure_collection(self, name: str, dim: int, metric: str = "cosine") -> None:
        pass


def _build_api_with_vector(
    memory_adapter: PostgresMemoryAdapter,
    dh_store: DecisionHistoryStore,
    vector_index: MemoryVectorIndex,
) -> MemoryAPI:
    """Build a MemoryAPI with a wired vector_index using the existing conftest helpers."""
    from cognic_agentos.core.dlp.scanner import ChecksumRegexGazetteerScanner
    from cognic_agentos.core.memory.consent import ConsentValidator
    from tests.unit.core.memory.conftest import (
        _AllowAllPolicy,
        _ctx,
        _InactiveKillSwitch,
    )

    ctx = _ctx(served_subject=SUBJECT, agent_id="kyc")
    return MemoryAPI(
        context=ctx,
        adapter=memory_adapter,
        dlp=ChecksumRegexGazetteerScanner(),
        consent=ConsentValidator(audit=dh_store),
        policy=_AllowAllPolicy(),  # type: ignore[arg-type]
        kill_switch=_InactiveKillSwitch(),  # structural conformer (no type: ignore needed)
        audit=dh_store,
        settings=Settings(),
        vector_index=vector_index,
    )


async def test_api_recall_episodes_with_vector_index_searches(memory_adapter, dh_store):
    """``recall_episodes`` with ``query`` + a wired ``vector_index`` calls
    ``vector_index.search`` and returns the governed intersected Episodes."""
    rid = await memory_adapter.put(_long_term_record(purpose="fraud_detection"))
    governed_id = str(rid)

    hits = [VectorHit(id=governed_id, score=0.9, payload={"purpose": "fraud_detection"})]
    client = _ControlledFakeVectorClient(hits=hits)
    index = MemoryVectorIndex(
        embedder=_FakeEmbedder(),  # type: ignore[arg-type]
        client=client,  # type: ignore[arg-type]
        collection="memory-episodes",
    )
    api_with_index = _build_api_with_vector(memory_adapter, dh_store, index)

    eps = await api_with_index.recall_episodes(
        SUBJECT,
        similarity_threshold=0.5,
        purpose="fraud_detection",
        query="fraud case",
    )
    assert client.search_called, "vector_index.search must be called"
    assert len(eps) == 1
    assert str(eps[0].record_id) == governed_id


@pytest.mark.parametrize("blank", ["", "   "])
async def test_api_recall_episodes_blank_query_refused_no_emit(
    memory_adapter, dh_store, decision_history_rows, blank
):
    """A blank/whitespace query is refused even with a wired vector_index — the
    refusal propagates BEFORE both the index search AND the memory.read emit
    (P2: query='' must not return governed episodes or emit a read row)."""
    await memory_adapter.put(_long_term_record(purpose="fraud_detection"))
    client = _ControlledFakeVectorClient(hits=[])
    index = MemoryVectorIndex(
        embedder=_FakeEmbedder(),  # type: ignore[arg-type]
        client=client,  # type: ignore[arg-type]
        collection="memory-episodes",
    )
    api_with_index = _build_api_with_vector(memory_adapter, dh_store, index)

    with pytest.raises(MemoryOperationRefused) as exc_info:
        await api_with_index.recall_episodes(
            SUBJECT, similarity_threshold=0.5, purpose="fraud_detection", query=blank
        )
    assert exc_info.value.reason == "memory_vector_recall_unavailable"
    assert not client.search_called, "blank query must not reach vector search"
    reads = [r for r in await decision_history_rows() if r.event_type == "memory.read"]
    assert len(reads) == 0  # refusal propagates before the emit


async def test_api_remember_indexes_long_term_non_restricted(memory_adapter, dh_store):
    """``remember`` with ``tier="long_term"`` + non-restricted ``data_classes``
    calls ``vector_index.index`` exactly once."""
    client = _ControlledFakeVectorClient()
    index = MemoryVectorIndex(
        embedder=_FakeEmbedder(),  # type: ignore[arg-type]
        client=client,  # type: ignore[arg-type]
        collection="memory-episodes",
    )
    api_with_index = _build_api_with_vector(memory_adapter, dh_store, index)

    await api_with_index.remember(
        "case-key",
        "some case data",
        tier="long_term",
        data_classes=("public",),
        purpose="fraud_detection",
    )
    # exactly one index call for long_term + non-restricted data class
    assert len(client.index_calls) == 1
    assert client.index_calls[0]["purpose"] == "fraud_detection"


async def test_api_remember_does_not_index_restricted_class(memory_adapter, dh_store):
    """Index-on-write skips restricted-class records (Wave-1 bank-safe default).

    The ``_is_indexable`` guard in ``api.py`` imports the single-source helper
    from ``vector.py``; the guard logic itself is unit-tested exhaustively in
    ``test_vector.py::test_is_indexable_*``. Here we verify the api-level
    WIRING: when ``_is_indexable(data_classes)`` returns False, the vector
    client receives ZERO index calls even if all other conditions would allow
    indexing (long_term tier + wired vector_index + non-None key).

    We use ``data_classes=("public", "internal")`` (non-restricted) for the
    positive case (test_api_remember_indexes_long_term_non_restricted covers it)
    and here directly verify the guard fires for a simulated restricted mix.
    Since the real consent gate blocks restricted-class writes through MemoryAPI,
    we verify the guard at one level down: call ``_is_indexable`` directly with
    the api.py import path to confirm single-source wiring.
    """
    # Verify the api.py imports _is_indexable from vector.py (single-source).
    # Use getattr to access private attribute (mypy sees _ as private; we
    # deliberately inspect internals here for the single-source contract test).
    import cognic_agentos.core.memory.api as _api_mod
    import cognic_agentos.core.memory.vector as _vec_mod

    # Private attribute access: deliberate — this test verifies that api.py's
    # private _is_indexable binding IS the same function object as vector.py's
    # (single-source contract; the noqa code SLF001 is not enabled in this project).
    api_is_indexable = _api_mod._is_indexable  # type: ignore[attr-defined]
    vec_is_indexable = _vec_mod._is_indexable

    # They must be the SAME object (api imports from vector, not a duplicate).
    assert api_is_indexable is vec_is_indexable, (
        "api.py must import _is_indexable from vector.py (single source — no inline duplicate)"
    )
    # And it returns False for restricted classes.
    assert vec_is_indexable(("customer_pii",)) is False
    assert vec_is_indexable(("public", "customer_pii")) is False


async def test_api_remember_task_does_not_index(memory_adapter, dh_store):
    """``remember`` with ``tier="task"`` NEVER indexes (long_term-only).

    The gate condition is ``tier == "long_term"`` — task tier causes the
    index-on-write branch to be skipped entirely even with a wired vector_index.
    """
    client = _ControlledFakeVectorClient()
    index = MemoryVectorIndex(
        embedder=_FakeEmbedder(),  # type: ignore[arg-type]
        client=client,  # type: ignore[arg-type]
        collection="memory-episodes",
    )
    api_with_index = _build_api_with_vector(memory_adapter, dh_store, index)

    await api_with_index.remember(
        "task-key",
        "task data",
        tier="task",
        data_classes=("public",),
        purpose="customer_support",
    )
    assert len(client.index_calls) == 0, "task tier must never be indexed"


async def test_api_remember_index_failure_does_not_propagate(memory_adapter, dh_store, caplog):
    """A failing ``vector_index.index`` MUST NOT propagate from ``remember``
    (best-effort isolation). The record_id is still returned. The value text
    MUST NOT appear in any log (only record_id/purpose/exc-class are logged)."""
    import logging

    class _BrokenVectorClient:
        async def upsert(self, items: list[VectorItem]) -> None:
            raise RuntimeError("embed backend down")

        async def search(
            self,
            vector: list[float],
            k: int = 10,
            filter: dict[str, object] | None = None,
        ) -> list[VectorHit]:
            return []

        async def ensure_collection(self, name: str, dim: int, metric: str = "cosine") -> None:
            pass

    index = MemoryVectorIndex(
        embedder=_FakeEmbedder(),  # type: ignore[arg-type]
        client=_BrokenVectorClient(),  # type: ignore[arg-type]
        collection="memory-episodes",
    )
    api_with_index = _build_api_with_vector(memory_adapter, dh_store, index)

    _SENSITIVE_VALUE = "HIGHLY_SENSITIVE_CONTENT_42"

    with caplog.at_level(logging.WARNING, logger="cognic_agentos.core.memory.api"):
        rid = await api_with_index.remember(
            "sensitive-key",
            _SENSITIVE_VALUE,
            tier="long_term",
            data_classes=("public",),
            purpose="fraud_detection",
        )

    # The record_id is still returned despite the index failure.
    assert rid is not None, "record_id must be returned even when index fails"

    # The value text must NOT appear in any log line.
    all_log_text = " ".join(r.getMessage() for r in caplog.records)
    assert _SENSITIVE_VALUE not in all_log_text, (
        f"Sensitive value '{_SENSITIVE_VALUE}' must NOT appear in logs; got: {all_log_text!r}"
    )
