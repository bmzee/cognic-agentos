"""Sprint 11.5c T7 — MemoryVectorIndex (wired into recall path).

MemoryVectorIndex consumes the REAL ``db/adapters/protocols`` Protocols
(``EmbeddingAdapter`` BATCH ``embed`` + ``VectorAdapter``). The real
``QdrantAdapter.search`` RAISES on any non-None ``filter``, so the index
calls ``search(..., filter=None)`` and filters by ``purpose`` CLIENT-side in
Python (with over-fetch), then truncates. These fakes conform to the real
Protocol shapes (``VectorItem`` = ``id`` / ``vector`` / ``payload``;
``VectorHit`` = ``id`` / ``score`` / ``payload``) and the search fake ASSERTS
``filter is None`` so a regression that smuggles a server-side filter trips
the fake (mirroring the real adapter's ``NotImplementedError``).

Sprint 11.5c wires ``ensure_collection`` (collection lifecycle) and
``_is_indexable`` (restricted-class exclusion) into the recall/write paths.
"""

from __future__ import annotations

from cognic_agentos.core.memory.vector import MemoryVectorIndex, _is_indexable
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
    filter, so the index MUST filter client-side; this assertion pins it.

    Records ``ensure_collection`` calls for the 11.5c lifecycle test."""

    def __init__(self) -> None:
        self.items: list[VectorItem] = []
        self.ensure_collection_calls: list[tuple[str, int, str]] = []

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

    async def ensure_collection(self, name: str, dim: int, metric: str = "cosine") -> None:
        self.ensure_collection_calls.append((name, dim, metric))


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


# --------------------------------------------------------------------------- #
# Sprint 11.5c T7 — ensure_collection + _is_indexable
# --------------------------------------------------------------------------- #


async def test_ensure_collection_calls_client_with_collection_dim_cosine():
    """``ensure_collection`` delegates to ``client.ensure_collection`` with the
    bound collection name, the embedder's dimensions, and metric="cosine"."""
    client = _FakeVectorClient()
    embedder = _FakeEmbedder()  # dimensions == 3
    index = MemoryVectorIndex(
        embedder=embedder,  # type: ignore[arg-type]
        client=client,  # type: ignore[arg-type]
        collection="test-collection",
    )
    await index.ensure_collection()
    assert len(client.ensure_collection_calls) == 1
    name, dim, metric = client.ensure_collection_calls[0]
    assert name == "test-collection"
    assert dim == 3  # _FakeEmbedder.dimensions
    assert metric == "cosine"


async def test_ensure_collection_idempotent_on_second_call():
    """Calling ``ensure_collection`` twice propagates two calls to the client
    (the adapter's ensure_collection is idempotent; the index just delegates)."""
    client = _FakeVectorClient()
    index = _index(client)
    await index.ensure_collection()
    await index.ensure_collection()
    assert len(client.ensure_collection_calls) == 2


def test_is_indexable_public_class_is_indexable():
    """Non-restricted class → indexable."""
    assert _is_indexable(("public",)) is True


def test_is_indexable_internal_class_is_indexable():
    assert _is_indexable(["internal"]) is True


def test_is_indexable_customer_pii_is_not_indexable():
    """``customer_pii`` is a RESTRICTED_DATA_CLASSES member → not indexable."""
    assert _is_indexable(("customer_pii",)) is False


def test_is_indexable_mixed_restricted_not_indexable():
    """Any restricted class in the tuple makes the record non-indexable."""
    assert _is_indexable(("public", "customer_pii")) is False


def test_is_indexable_payment_data_not_indexable():
    assert _is_indexable(("payment_data",)) is False


def test_is_indexable_credentials_not_indexable():
    assert _is_indexable(("credentials",)) is False


def test_is_indexable_regulator_communication_not_indexable():
    assert _is_indexable(("regulator_communication",)) is False


def test_is_indexable_accepts_list_and_tuple():
    """_is_indexable accepts both list and tuple (matches MemoryWriteRecord flexibility)."""
    assert _is_indexable(["public"]) is True
    assert _is_indexable(("public",)) is True
