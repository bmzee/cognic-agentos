"""Sprint 11.5a T11 — MemoryVectorIndex: a standalone DI-tested vector-index
primitive for governed-memory episodic search (ADR-019).

**Standalone primitive — no production caller in 11.5a.** This class is
exercised only by its DI unit tests; it is deliberately NOT wired into
``recall_episodes`` (the 11.5a episodic-recall view is the ``long_term`` +
purpose slice, with no vector ranking). Real-Qdrant wiring + the collection
lifecycle (``ensure_collection``) land in 11.5b.

**Client-side purpose filter (best-effort over-fetch).** The real
:class:`~cognic_agentos.db.adapters.qdrant_adapter.QdrantAdapter` RAISES
``NotImplementedError`` on any non-None ``filter`` argument — server-side
``qdrant.Filter`` translation is deferred to 11.5b + ADR-017. So
:meth:`search` calls ``client.search(..., filter=None)``, OVER-FETCHES (``k =
max(limit * 5, limit)``) to compensate for the post-filter drop, filters by
``purpose`` in Python, and truncates to ``limit``. This is best-effort: a
purpose with many more than ``limit * 5`` competing results could be
under-returned until the exact server-side filter lands in 11.5b.

**Collection lifecycle is a caller / 11.5b concern.** :meth:`index` and
:meth:`search` ASSUME the ``collection`` already exists; this primitive does
NOT call ``ensure_collection`` — that wiring lands in 11.5b alongside the real
Qdrant client.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cognic_agentos.db.adapters.protocols import VectorItem

if TYPE_CHECKING:
    from cognic_agentos.db.adapters.protocols import (
        EmbeddingAdapter,
        VectorAdapter,
        VectorHit,
    )


class MemoryVectorIndex:
    """Embed-and-index + semantic-search seam over a vector backend.

    Construction binds an :class:`EmbeddingAdapter` (BATCH ``embed``), a
    :class:`VectorAdapter` client, and the target ``collection`` name. A
    standalone DI-tested primitive — see the module docstring for the
    no-production-caller + client-side-filter + collection-lifecycle caveats.
    """

    def __init__(
        self, *, embedder: EmbeddingAdapter, client: VectorAdapter, collection: str
    ) -> None:
        self._embedder = embedder
        self._client = client
        self._collection = collection

    async def index(
        self, *, record_id: str, text: str, purpose: str, data_classes: list[str]
    ) -> None:
        """Embed ``text`` and upsert one point keyed by ``record_id``, co-storing
        ``record_id`` / ``purpose`` / ``data_classes`` in the point payload so a
        later :meth:`search` can filter by purpose client-side. Assumes the
        collection already exists (lifecycle is a 11.5b concern)."""

        vec = (await self._embedder.embed([text]))[0]
        await self._client.upsert(
            [
                VectorItem(
                    id=record_id,
                    vector=vec,
                    payload={
                        "record_id": record_id,
                        "purpose": purpose,
                        "data_classes": list(data_classes),
                    },
                )
            ]
        )

    async def search(self, *, text: str, purpose: str, limit: int) -> list[VectorHit]:
        """Embed ``text`` and return up to ``limit`` hits whose payload
        ``purpose`` matches. Over-fetches then filters CLIENT-side because the
        real :class:`QdrantAdapter` refuses server-side filters; see the module
        docstring for the best-effort caveat."""

        vec = (await self._embedder.embed([text]))[0]
        raw = await self._client.search(vector=vec, k=max(limit * 5, limit), filter=None)
        filtered = [h for h in raw if h.payload.get("purpose") == purpose]
        return filtered[:limit]


__all__ = ("MemoryVectorIndex",)
