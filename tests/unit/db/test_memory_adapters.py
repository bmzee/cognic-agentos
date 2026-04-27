"""In-memory adapters — used by tests, never registered as default drivers.

Lives under ``tests/`` per AGENTS.md test-fixture-placement rule."""

from __future__ import annotations

from cognic_agentos.db.adapters import protocols as P
from tests.support.adapter_fixtures import (
    InMemoryEmbeddingAdapter,
    InMemoryObservabilityAdapter,
    InMemoryRelationalAdapter,
    InMemorySecretAdapter,
    InMemoryVectorAdapter,
)


class TestInMemoryRelational:
    async def test_lifecycle(self) -> None:
        a = InMemoryRelationalAdapter()
        await a.connect()
        h = await a.health_check()
        assert h.status == "ok"
        assert h.driver == "memory"
        await a.close()
        h2 = await a.health_check()
        assert h2.status == "unreachable"

    def test_satisfies_protocol(self) -> None:
        assert isinstance(InMemoryRelationalAdapter(), P.RelationalAdapter)


class TestInMemoryVector:
    async def test_upsert_and_search(self) -> None:
        a = InMemoryVectorAdapter()
        await a.ensure_collection("c", dim=3)
        await a.upsert(
            [
                P.VectorItem(id="1", vector=[1.0, 0.0, 0.0], payload={"k": "a"}),
                P.VectorItem(id="2", vector=[0.0, 1.0, 0.0], payload={"k": "b"}),
            ]
        )
        hits = await a.search([1.0, 0.0, 0.0], k=2)
        assert len(hits) == 2
        assert hits[0].id == "1"  # exact match wins on cosine

    async def test_delete(self) -> None:
        a = InMemoryVectorAdapter()
        await a.ensure_collection("c", dim=2)
        await a.upsert([P.VectorItem(id="1", vector=[1.0, 0.0], payload={})])
        await a.delete(["1"])
        hits = await a.search([1.0, 0.0])
        assert hits == []

    async def test_filter_argument_rejected(self) -> None:
        """Mirror QdrantAdapter behaviour: silent-drop on filter is unsafe.
        Sprint 11.5 + ADR-017 will introduce typed filter translation."""

        import pytest

        a = InMemoryVectorAdapter()
        await a.ensure_collection("c", dim=2)
        with pytest.raises(NotImplementedError, match="filter"):
            await a.search([1.0, 0.0], filter={"k": "a"})

    def test_satisfies_protocol(self) -> None:
        assert isinstance(InMemoryVectorAdapter(), P.VectorAdapter)


class TestInMemorySecret:
    async def test_round_trip(self) -> None:
        a = InMemorySecretAdapter()
        await a.write("p/q", {"k": "v"})
        assert await a.read("p/q") == {"k": "v"}

    async def test_lease_and_revoke(self) -> None:
        a = InMemorySecretAdapter()
        await a.write("p/q", {"k": "v"})
        lease = await a.lease("p/q", ttl_s=60)
        assert lease.value == {"k": "v"}
        assert lease.ttl_s == 60
        await a.revoke(lease.lease_id)

    def test_satisfies_protocol(self) -> None:
        assert isinstance(InMemorySecretAdapter(), P.SecretAdapter)


class TestInMemoryEmbedding:
    async def test_deterministic_shape(self) -> None:
        a = InMemoryEmbeddingAdapter(dimensions=8)
        v = await a.embed(["hello", "world"])
        assert len(v) == 2
        assert all(len(row) == 8 for row in v)

    def test_dimensions_property(self) -> None:
        assert InMemoryEmbeddingAdapter(dimensions=4).dimensions == 4

    def test_satisfies_protocol(self) -> None:
        assert isinstance(InMemoryEmbeddingAdapter(), P.EmbeddingAdapter)


class TestInMemoryObservability:
    async def test_records_emissions(self) -> None:
        a = InMemoryObservabilityAdapter()
        await a.emit_trace("t", {"k": 1})
        await a.emit_metric("m", 1.0, {})
        await a.flush()
        assert len(a.traces) == 1
        assert len(a.metrics) == 1

    def test_satisfies_protocol(self) -> None:
        assert isinstance(InMemoryObservabilityAdapter(), P.ObservabilityAdapter)
