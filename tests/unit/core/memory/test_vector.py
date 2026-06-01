"""Sprint 11.5a T11 — MemoryVectorIndex (standalone DI-tested primitive).

MemoryVectorIndex consumes the REAL ``db/adapters/protocols`` Protocols
(``EmbeddingAdapter`` BATCH ``embed`` + ``VectorAdapter``). The real
``QdrantAdapter.search`` RAISES on any non-None ``filter``, so the index
calls ``search(..., filter=None)`` and filters by ``purpose`` CLIENT-side in
Python (with over-fetch), then truncates. These fakes conform to the real
Protocol shapes (``VectorItem`` = ``id`` / ``vector`` / ``payload``;
``VectorHit`` = ``id`` / ``score`` / ``payload``) and the search fake ASSERTS
``filter is None`` so a regression that smuggles a server-side filter trips
the fake (mirroring the real adapter's ``NotImplementedError``).

There is NO production caller in 11.5a — this primitive is NOT wired into
``recall_episodes``. Real-qdrant + collection lifecycle land in 11.5b.
"""

from __future__ import annotations

from cognic_agentos.core.memory.vector import MemoryVectorIndex
from cognic_agentos.db.adapters.protocols import VectorHit, VectorItem


class _FakeEmbedder:
    """Structural EmbeddingAdapter conformer — BATCH ``embed`` + sync
    ``dimensions``. Returns a deterministic length-3 vector per text so the
    index wiring is exercised without a real embedding backend."""

    @property
    def dimensions(self) -> int:
        return 3

    async def embed(self, texts: list[str]) -> list[list[float]]:
        return [[float(len(t)), 0.0, 1.0] for t in texts]


class _FakeVectorClient:
    """Structural VectorAdapter conformer. Records every upserted
    ``VectorItem`` and returns them as ``VectorHit``s on search. ``search``
    ASSERTS ``filter is None`` — the real QdrantAdapter raises on a non-None
    filter, so the index MUST filter client-side; this assertion pins it."""

    def __init__(self) -> None:
        self.items: list[VectorItem] = []

    async def upsert(self, items: list[VectorItem]) -> None:
        self.items.extend(items)

    async def search(
        self,
        vector: list[float],
        k: int = 10,
        filter: dict[str, object] | None = None,
    ) -> list[VectorHit]:
        assert filter is None, "MemoryVectorIndex must filter client-side, never server-side"
        return [VectorHit(id=it.id, score=1.0, payload=it.payload) for it in self.items][:k]


def _index(client: _FakeVectorClient) -> MemoryVectorIndex:
    return MemoryVectorIndex(
        embedder=_FakeEmbedder(),  # type: ignore[arg-type]
        client=client,  # type: ignore[arg-type]
        collection="memory-episodes",
    )


async def test_semantic_recall_is_purpose_filtered():
    client = _FakeVectorClient()
    index = _index(client)
    await index.index(
        record_id="r1", text="fraud case 1", purpose="fraud_detection", data_classes=["internal"]
    )
    await index.index(
        record_id="r2", text="support ticket", purpose="customer_support", data_classes=["public"]
    )
    hits = await index.search(text="case", purpose="fraud_detection", limit=10)
    # r2 is excluded CLIENT-side (purpose mismatch); only r1 survives.
    assert [h.payload["record_id"] for h in hits] == ["r1"]


async def test_index_costores_purpose_and_record_id_in_payload():
    client = _FakeVectorClient()
    index = _index(client)
    await index.index(
        record_id="r1", text="fraud case 1", purpose="fraud_detection", data_classes=["internal"]
    )
    assert len(client.items) == 1
    stored = client.items[0]
    assert stored.id == "r1"
    assert stored.payload["record_id"] == "r1"
    assert stored.payload["purpose"] == "fraud_detection"
    assert stored.payload["data_classes"] == ["internal"]
