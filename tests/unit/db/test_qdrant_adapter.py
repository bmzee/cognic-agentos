"""QdrantAdapter — exercises ``AsyncQdrantClient(":memory:")`` in tests."""

from __future__ import annotations

import pytest

from cognic_agentos.db.adapters import bundled_registry
from cognic_agentos.db.adapters import protocols as P
from cognic_agentos.db.adapters.qdrant_adapter import QdrantAdapter


class TestRegistration:
    def test_qdrant_registered_under_bundled(self) -> None:
        assert bundled_registry.has("vector", "qdrant")
        assert bundled_registry.resolve("vector", "qdrant") is QdrantAdapter


class TestConstruction:
    def test_constructor_refuses_empty_url(self) -> None:
        with pytest.raises(ValueError, match="qdrant_url"):
            QdrantAdapter(None, "col")
        with pytest.raises(ValueError, match="qdrant_url"):
            QdrantAdapter("", "col")


class TestRoundTrip:
    async def test_ensure_upsert_search(self) -> None:
        a = QdrantAdapter(url=":memory:", collection="test_col")
        await a.connect()
        await a.ensure_collection("test_col", dim=4)
        await a.upsert(
            [
                P.VectorItem(id="1", vector=[1.0, 0.0, 0.0, 0.0], payload={"k": "a"}),
                P.VectorItem(id="2", vector=[0.0, 1.0, 0.0, 0.0], payload={"k": "b"}),
            ]
        )
        hits = await a.search([1.0, 0.0, 0.0, 0.0], k=2)
        assert len(hits) == 2
        assert hits[0].id == "1"
        await a.close()

    async def test_health_check(self) -> None:
        a = QdrantAdapter(url=":memory:", collection="test_col")
        await a.connect()
        h = await a.health_check()
        assert h.status == "ok"
        assert h.driver == "qdrant"
        await a.close()

    async def test_unreachable_before_connect(self) -> None:
        a = QdrantAdapter(url=":memory:", collection="test_col")
        h = await a.health_check()
        assert h.status == "unreachable"

    async def test_delete(self) -> None:
        a = QdrantAdapter(url=":memory:", collection="test_col")
        await a.connect()
        await a.ensure_collection("test_col", dim=2)
        await a.upsert([P.VectorItem(id="1", vector=[1.0, 0.0], payload={})])
        await a.delete(["1"])
        hits = await a.search([1.0, 0.0])
        assert hits == []
        await a.close()

    async def test_filter_argument_rejected(self) -> None:
        """Sprint 1C deliberately fails loud on non-None filter — translation
        to qdrant.Filter shape lands with Sprint 11.5 + ADR-017."""

        a = QdrantAdapter(url=":memory:", collection="test_col")
        await a.connect()
        await a.ensure_collection("test_col", dim=2)
        with pytest.raises(NotImplementedError, match="filter translation"):
            await a.search([1.0, 0.0], k=1, filter={"k": "a"})
        await a.close()


class TestSatisfiesProtocol:
    def test_protocol_conformance(self) -> None:
        a = QdrantAdapter(url=":memory:", collection="x")
        assert isinstance(a, P.VectorAdapter)
