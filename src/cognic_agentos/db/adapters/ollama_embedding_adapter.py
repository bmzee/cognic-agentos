"""OllamaEmbeddingAdapter — EmbeddingAdapter via Ollama HTTP.

Driver name: ``ollama``. Auto-registers into ``bundled_registry`` on import.

Per ADR-009 this adapter is **dev-only** for production deployment —
production banks set ``embed_driver=openai_compat`` against vLLM/SGLang
in Sprint 1D. The Ollama adapter exists to make local dev workable
without a GPU cluster.
"""

from __future__ import annotations

import time

import httpx

from cognic_agentos.db.adapters.protocols import AdapterHealth
from cognic_agentos.db.adapters.registry import bundled_registry


class OllamaEmbeddingAdapter:
    driver = "ollama"

    def __init__(
        self,
        base_url: str | None,
        model: str,
        dimensions: int,
    ) -> None:
        if not base_url:
            raise ValueError("OllamaEmbeddingAdapter requires embedding_base_url; got empty/None")
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._dimensions = dimensions

    async def embed(self, texts: list[str]) -> list[list[float]]:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self._base_url}/api/embed",
                json={"model": self._model, "input": texts},
            )
            resp.raise_for_status()
            body = resp.json()
        return [list(row) for row in body.get("embeddings", [])]

    @property
    def dimensions(self) -> int:
        return self._dimensions

    async def health_check(self) -> AdapterHealth:
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(f"{self._base_url}/api/tags")
                resp.raise_for_status()
        except Exception as exc:
            return AdapterHealth(
                status="unreachable",
                driver=self.driver,
                detail=type(exc).__name__,
            )
        return AdapterHealth(
            status="ok",
            driver=self.driver,
            latency_ms=(time.perf_counter() - start) * 1000.0,
        )


bundled_registry.register("embedding", "ollama", OllamaEmbeddingAdapter)
