"""OpenAICompatEmbeddingAdapter — EmbeddingAdapter against any
OpenAI-compatible /v1/embeddings endpoint.

Driver name: ``openai_compat``. Auto-registers into ``bundled_registry``
on import.

Per ADR-009 this adapter is the production embedding default for banks
running vLLM/SGLang (no auth), OpenAI/Cohere (Bearer), or Azure-OpenAI
/ Bedrock when fronted by an OpenAI-compat proxy (api-key + extra
headers). Direct Azure-OpenAI URL shape requires a separate Azure-
specific adapter (deferred — see Sprint 1D plan + BUILD_PLAN amendment).

Auth surface:
- ``api_key`` is None → no auth header sent (vLLM/SGLang local default).
- ``api_key_header == "Authorization"`` → ``Authorization: Bearer <key>``
  (OpenAI / Cohere / vLLM-with-auth convention).
- Any other ``api_key_header`` value → ``<header>: <key>`` raw, no
  prefix (e.g. ``api-key`` for Azure-OpenAI proxies).
- ``extra_headers`` carries provider-specific quirks (e.g. Azure's
  ``api-version`` header) and is sent on every /v1/embeddings + /v1/models
  request, including health probes.

Defensive validation on embed() output:
- Response count must match request count (catches providers that drop
  or duplicate rows — would otherwise silently mis-align downstream
  consumers like retrieval upserts).
- Per-row embedding must be a list of numerics with the adapter's
  declared dimensionality (catches operator misconfiguration like
  COGNIC_EMBEDDING_DIMENSIONS not matching the deployed model's actual
  output dim).

The ``provider_label`` is exposed as a property; per-embed audit
emission of the label lands with Sprint 2 ``core/audit`` wiring (Sprint
1D ships storage + plumbing only — see BUILD_PLAN amendment).
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from cognic_agentos.db.adapters.protocols import AdapterHealth
from cognic_agentos.db.adapters.registry import bundled_registry


class OpenAICompatEmbeddingAdapter:
    driver = "openai_compat"

    def __init__(
        self,
        base_url: str | None,
        model: str,
        dimensions: int,
        provider_label: str,
        api_key: str | None = None,
        api_key_header: str = "Authorization",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        if not base_url:
            raise ValueError(
                "OpenAICompatEmbeddingAdapter requires embedding_base_url; got empty/None"
            )
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._dimensions = dimensions
        self._provider_label = provider_label
        self._api_key = api_key
        self._api_key_header = api_key_header
        self._extra_headers = dict(extra_headers or {})

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = dict(self._extra_headers)
        if self._api_key:
            if self._api_key_header == "Authorization":
                # OpenAI / Cohere / vLLM-with-auth convention
                h["Authorization"] = f"Bearer {self._api_key}"
            else:
                # Azure-OpenAI proxy convention: raw key under custom header
                h[self._api_key_header] = self._api_key
        return h

    async def embed(self, texts: list[str]) -> list[list[float]]:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self._base_url}/v1/embeddings",
                headers=self._headers(),
                json={
                    "input": texts,
                    "model": self._model,
                    "encoding_format": "float",
                },
            )
            resp.raise_for_status()
            body = resp.json()
        data: list[dict[str, Any]] = body.get("data", [])

        # Validation: response count must match request count. Out-of-spec
        # providers that drop or duplicate rows would otherwise silently
        # mis-align downstream consumers (e.g. retrieval upserts).
        if len(data) != len(texts):
            raise ValueError(
                f"OpenAI-compat embedding response shape mismatch: requested "
                f"{len(texts)} input(s), got {len(data)} row(s) from "
                f"{self._provider_label!r}"
            )

        # Defensively sort by ``index`` so providers that respond out of
        # order (rare, but spec-permitted) still yield request-order rows.
        data_sorted = sorted(data, key=lambda d: int(d.get("index", 0)))

        out: list[list[float]] = []
        for i, d in enumerate(data_sorted):
            embedding = d.get("embedding")
            # Validation: embedding must be a list of numerics with the
            # adapter's declared dimensionality. A wrong-dim response is
            # almost always a model misconfiguration (operator pointed
            # the adapter at a different model than declared) — fail
            # loudly so retrieval doesn't poison its index with garbage
            # rows.
            if not isinstance(embedding, list):
                raise ValueError(
                    f"OpenAI-compat embedding row {i} from "
                    f"{self._provider_label!r} is not a list: "
                    f"got {type(embedding).__name__}"
                )
            if len(embedding) != self._dimensions:
                raise ValueError(
                    f"OpenAI-compat embedding row {i} from "
                    f"{self._provider_label!r} has dim={len(embedding)}, "
                    f"adapter declared dimensions={self._dimensions}. "
                    f"Likely misconfigured: COGNIC_EMBEDDING_DIMENSIONS "
                    f"must match the deployed model's actual output dim."
                )
            out.append([float(x) for x in embedding])
        return out

    @property
    def dimensions(self) -> int:
        return self._dimensions

    @property
    def provider_label(self) -> str:
        return self._provider_label

    async def health_check(self) -> AdapterHealth:
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(
                    f"{self._base_url}/v1/models",
                    headers=self._headers(),
                )
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


bundled_registry.register("embedding", "openai_compat", OpenAICompatEmbeddingAdapter)
