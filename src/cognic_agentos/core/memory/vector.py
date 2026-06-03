"""Sprint 11.5c T7 — MemoryVectorIndex: wired into the real recall path
(ADR-019 governed-memory episodic vector search).

**Wired in 11.5c.** :meth:`ensure_collection` is now implemented, but the
COLLECTION LIFECYCLE IS A CALLER / FACTORY CONCERN — whoever wires the
:class:`MemoryVectorIndex` into :class:`~cognic_agentos.core.memory.api.MemoryAPI`
(the app / DI factory) is responsible for calling :meth:`ensure_collection`
before first use. ``MemoryAPI`` itself does NOT call it: it stores the injected
index and delegates ``index`` / ``search`` only. :func:`_is_indexable` is the
SINGLE SOURCE of the restricted-class exclusion rule (``api.py`` imports it; no
inline duplicate). Index-on-write in ``remember`` skips restricted-class
records (Wave-1 bank-safe default; ADR-019).

**Client-side purpose filter (best-effort over-fetch).** The real
:class:`~cognic_agentos.db.adapters.qdrant_adapter.QdrantAdapter` RAISES
``NotImplementedError`` on any non-None ``filter`` argument — server-side
``qdrant.Filter`` translation is deferred to a future sprint per ADR-017. So
:meth:`search` calls ``client.search(..., filter=None)``, OVER-FETCHES (``k =
max(limit * 5, limit)``) to compensate for the post-filter drop, filters by
``purpose`` in Python, and truncates to ``limit``. This is best-effort: a
purpose with many more than ``limit * 5`` competing results could be
under-returned until the exact server-side filter lands in a later sprint.

**Collection lifecycle is a caller concern (wired in 11.5c).** :meth:`index`
and :meth:`search` ASSUME the ``collection`` already exists.
:meth:`ensure_collection` now exists and idempotently creates the backing
collection via ``client.ensure_collection``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cognic_agentos.core.memory.tiers import RESTRICTED_DATA_CLASSES
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
    DI-tested primitive — see the module docstring for the
    caller-owned-collection-lifecycle + client-side-filter caveats.
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
        collection already exists (lifecycle is a caller concern — call
        :meth:`ensure_collection` first)."""

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

    async def ensure_collection(self) -> None:
        """Idempotently create the backing collection (lifecycle is a caller
        concern; wired in 11.5c)."""
        await self._client.ensure_collection(self._collection, self._embedder.dimensions, "cosine")

    async def search(self, *, text: str, purpose: str, limit: int) -> list[VectorHit]:
        """Embed ``text`` and return up to ``limit`` hits whose payload
        ``purpose`` matches. Over-fetches then filters CLIENT-side because the
        real :class:`QdrantAdapter` refuses server-side filters; see the module
        docstring for the best-effort caveat."""

        vec = (await self._embedder.embed([text]))[0]
        raw = await self._client.search(vector=vec, k=max(limit * 5, limit), filter=None)
        filtered = [h for h in raw if h.payload.get("purpose") == purpose]
        return filtered[:limit]


def _is_indexable(data_classes: tuple[str, ...] | list[str]) -> bool:
    """True iff NONE of ``data_classes`` is a restricted class — index-on-write
    skips restricted records (Wave-1 bank-safe default; ADR-019).

    This is the SINGLE SOURCE of the restricted-class exclusion rule.
    ``api.py`` imports this function; the ``isdisjoint`` logic is NOT
    duplicated there.
    """
    return frozenset(data_classes).isdisjoint(RESTRICTED_DATA_CLASSES)


__all__ = ("MemoryVectorIndex", "_is_indexable")
