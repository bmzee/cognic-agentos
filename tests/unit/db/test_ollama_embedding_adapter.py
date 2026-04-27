"""OllamaEmbeddingAdapter — embed() shape + health_check + graceful degrade."""

from __future__ import annotations

import respx
from httpx import ConnectError, Response

from cognic_agentos.db.adapters import bundled_registry
from cognic_agentos.db.adapters import protocols as P
from cognic_agentos.db.adapters.ollama_embedding_adapter import OllamaEmbeddingAdapter

BASE = "http://ollama.test:11434"


class TestRegistration:
    def test_ollama_registered_under_bundled(self) -> None:
        assert bundled_registry.has("embedding", "ollama")
        assert bundled_registry.resolve("embedding", "ollama") is OllamaEmbeddingAdapter


class TestConstruction:
    def test_constructor_refuses_empty_base_url(self) -> None:
        import pytest

        with pytest.raises(ValueError, match="embedding_base_url"):
            OllamaEmbeddingAdapter(None, model="x", dimensions=4)
        with pytest.raises(ValueError, match="embedding_base_url"):
            OllamaEmbeddingAdapter("", model="x", dimensions=4)


class TestEmbed:
    @respx.mock
    async def test_embed_returns_vectors(self) -> None:
        respx.post(f"{BASE}/api/embed").mock(
            return_value=Response(
                200,
                json={"embeddings": [[0.1, 0.2, 0.3, 0.4], [0.5, 0.6, 0.7, 0.8]]},
            )
        )
        a = OllamaEmbeddingAdapter(BASE, model="qwen3-embedding:8b", dimensions=4)
        v = await a.embed(["a", "b"])
        assert len(v) == 2
        assert len(v[0]) == 4

    def test_dimensions_property(self) -> None:
        a = OllamaEmbeddingAdapter(BASE, model="x", dimensions=512)
        assert a.dimensions == 512


class TestHealth:
    @respx.mock
    async def test_health_ok(self) -> None:
        respx.get(f"{BASE}/api/tags").mock(return_value=Response(200, json={"models": []}))
        a = OllamaEmbeddingAdapter(BASE, model="x", dimensions=8)
        h = await a.health_check()
        assert h.status == "ok"
        assert h.driver == "ollama"
        assert h.latency_ms is not None

    @respx.mock
    async def test_health_unreachable_on_connect_error(self) -> None:
        respx.get(f"{BASE}/api/tags").mock(side_effect=ConnectError("nope"))
        a = OllamaEmbeddingAdapter(BASE, model="x", dimensions=8)
        h = await a.health_check()
        assert h.status == "unreachable"


class TestSatisfiesProtocol:
    def test_protocol_conformance(self) -> None:
        a = OllamaEmbeddingAdapter(BASE, model="x", dimensions=8)
        assert isinstance(a, P.EmbeddingAdapter)
