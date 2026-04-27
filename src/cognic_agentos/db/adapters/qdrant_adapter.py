"""QdrantAdapter — VectorAdapter via qdrant-client (async).

Driver name: ``qdrant``. Auto-registers into ``bundled_registry`` on import.

The ``url`` parameter accepts both ``http://host:6333`` (real server) and
``:memory:`` (qdrant-client embedded mode used in tests).

Per Sprint 1C plan: ``search()`` raises ``NotImplementedError`` on non-None
``filter`` argument. Filter translation to ``qdrant.Filter`` lands with
Sprint 11.5 + ADR-017 governance work.
"""

from __future__ import annotations

import time
from typing import Any
from uuid import NAMESPACE_OID, UUID, uuid5

from qdrant_client import AsyncQdrantClient
from qdrant_client.http import models as qmodels

from cognic_agentos.db.adapters.protocols import AdapterHealth, VectorHit, VectorItem
from cognic_agentos.db.adapters.registry import bundled_registry


def _to_qdrant_id(s: str) -> str:
    """Qdrant accepts UUID or unsigned int IDs; we accept str ids and map
    to a deterministic UUID5 so callers can use natural keys."""

    try:
        return str(UUID(s))
    except ValueError:
        return str(uuid5(NAMESPACE_OID, s))


class QdrantAdapter:
    driver = "qdrant"

    def __init__(self, url: str | None, collection: str) -> None:
        if not url:
            raise ValueError("QdrantAdapter requires qdrant_url; got empty/None")
        self._url = url
        self._default_collection = collection
        self._client: AsyncQdrantClient | None = None

    async def connect(self) -> None:
        # ``location`` is the unified parameter on AsyncQdrantClient that
        # accepts URLs, file paths, or ``:memory:``.
        self._client = AsyncQdrantClient(location=self._url)

    async def ensure_collection(self, name: str, dim: int, metric: str = "cosine") -> None:
        if self._client is None:
            await self.connect()
        assert self._client is not None
        existing = await self._client.get_collections()
        if any(c.name == name for c in existing.collections):
            return
        await self._client.create_collection(
            collection_name=name,
            vectors_config=qmodels.VectorParams(
                size=dim,
                distance=qmodels.Distance.COSINE if metric == "cosine" else qmodels.Distance.EUCLID,
            ),
        )

    async def upsert(self, items: list[VectorItem]) -> None:
        if self._client is None:
            await self.connect()
        assert self._client is not None
        points = [
            qmodels.PointStruct(
                id=_to_qdrant_id(it.id),
                vector=it.vector,
                payload={**it.payload, "_natural_id": it.id},
            )
            for it in items
        ]
        await self._client.upsert(
            collection_name=self._default_collection,
            points=points,
        )

    async def search(
        self,
        vector: list[float],
        k: int = 10,
        filter: dict[str, Any] | None = None,
    ) -> list[VectorHit]:
        if filter is not None:
            # Sprint 1C deliberately refuses to silently drop a filter we
            # cannot translate. Filter shape (data-class / purpose / tenant)
            # is the responsibility of Sprint 11.5 + ADR-017 governance work
            # — that sprint introduces the typed filter vocabulary and the
            # qdrant.Filter translator. Until then, fail loudly so callers
            # cannot believe their predicate ran.
            raise NotImplementedError(
                "QdrantAdapter.search filter translation is deferred to "
                "Sprint 11.5 + ADR-017 (data-governance filtering). "
                "Sprint 1C accepts filter=None only."
            )
        if self._client is None:
            await self.connect()
        assert self._client is not None
        # qdrant-client 1.10+ renamed `search` → `query_points`; the response
        # is a QueryResponse with a `.points` attribute holding ScoredPoint
        # objects (same shape `search` returned directly).
        response = await self._client.query_points(
            collection_name=self._default_collection,
            query=vector,
            limit=k,
        )
        out: list[VectorHit] = []
        for h in response.points:
            payload = dict(h.payload or {})
            natural = payload.pop("_natural_id", str(h.id))
            out.append(VectorHit(id=natural, score=float(h.score), payload=payload))
        return out

    async def delete(self, ids: list[str]) -> None:
        if self._client is None:
            await self.connect()
        assert self._client is not None
        # qmodels.PointIdsList.points is typed list[ExtendedPointId] which
        # is a Union[StrictInt, StrictStr, UUID]; the str values we pass
        # satisfy the StrictStr branch but mypy can't narrow that here.
        await self._client.delete(
            collection_name=self._default_collection,
            points_selector=qmodels.PointIdsList(
                points=[_to_qdrant_id(i) for i in ids],
            ),
        )

    async def close(self) -> None:
        if self._client is not None:
            await self._client.close()
            self._client = None

    async def health_check(self) -> AdapterHealth:
        if self._client is None:
            return AdapterHealth(status="unreachable", driver=self.driver, detail="not connected")
        start = time.perf_counter()
        try:
            await self._client.get_collections()
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


bundled_registry.register("vector", "qdrant", QdrantAdapter)
