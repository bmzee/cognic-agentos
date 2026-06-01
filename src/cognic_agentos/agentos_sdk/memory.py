"""Sprint 11.5a T12 — ``MemorySDK``, a thin typed Layer-C facade over ``MemoryAPI``.

This is the ergonomic Layer-C handle a pack author imports to use governed
memory (ADR-019 §7). It wraps an INJECTED :class:`MemoryAPI` and forwards each
of the 7 11.5a ops to the matching ``MemoryAPI`` method, EXACTLY by keyword.

It carries no governance of its own — every write/recall/enumerate still runs
through the bound :class:`~cognic_agentos.core.memory.gate.MemoryGate` inside
``MemoryAPI``; the SDK adds only a typed surface. It imports ONLY ``MemoryAPI``
+ the memory DTO/vocab types, and every one of those imports is annotation-only
(under ``if TYPE_CHECKING:``), so there is ZERO runtime ``core.memory`` import
from this module — never ``core.memory.storage`` / ``gate`` / any adapter. The
no-runtime-storage-import posture is pinned by
``tests/unit/architecture/test_memory_layer_c_no_direct_storage.py`` (which
AST-walks this file as a parametrized case).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cognic_agentos.core.memory._context import BlockRef, Episode, MemoryHit, MemoryRecordId
    from cognic_agentos.core.memory.api import MemoryAPI
    from cognic_agentos.core.memory.consent import ConsentToken
    from cognic_agentos.core.memory.tiers import BlockKind, MemoryTier, SubjectRef


class MemorySDK:
    """Thin typed Layer-C facade over :class:`MemoryAPI`.

    Imports ONLY ``MemoryAPI`` + DTO/vocab types (all annotation-only); never
    storage/gate/adapter. Wraps one injected ``MemoryAPI`` instance bound to a
    single Layer-C caller context by the harness — the SDK never re-binds or
    overrides identity; it only forwards."""

    def __init__(self, api: MemoryAPI) -> None:
        self._api = api

    # -- Write ops ---------------------------------------------------------

    async def remember(
        self,
        key: str,
        value: object,
        *,
        tier: MemoryTier,
        data_classes: tuple[str, ...] | list[str],
        purpose: str,
        consent_token: ConsentToken | None = None,
        retention_window_s: int | None = None,
    ) -> MemoryRecordId:
        """Write a keyed memory under the served subject (forwards to
        :meth:`MemoryAPI.remember`)."""
        return await self._api.remember(
            key,
            value,
            tier=tier,
            data_classes=data_classes,
            purpose=purpose,
            consent_token=consent_token,
            retention_window_s=retention_window_s,
        )

    async def upsert_block(
        self,
        kind: BlockKind,
        *,
        subject: SubjectRef,
        value: object,
        data_classes: tuple[str, ...] | list[str],
        purpose: str,
        consent_token: ConsentToken | None = None,
    ) -> MemoryRecordId:
        """Singleton block upsert (always ``long_term``; forwards to
        :meth:`MemoryAPI.upsert_block`). No retention kwarg."""
        return await self._api.upsert_block(
            kind,
            subject=subject,
            value=value,
            data_classes=data_classes,
            purpose=purpose,
            consent_token=consent_token,
        )

    # -- Keyed reads -------------------------------------------------------

    async def recall(self, key: str, *, tier: MemoryTier, purpose: str) -> MemoryHit | None:
        """Recall a keyed memory (forwards to :meth:`MemoryAPI.recall`)."""
        return await self._api.recall(key, tier=tier, purpose=purpose)

    async def read_block(
        self, kind: BlockKind, *, subject: SubjectRef, purpose: str
    ) -> MemoryHit | None:
        """Read a singleton block (forwards to :meth:`MemoryAPI.read_block`)."""
        return await self._api.read_block(kind, subject=subject, purpose=purpose)

    # -- Enumerate reads ---------------------------------------------------

    async def list_for_subject(self, subject: SubjectRef) -> list[MemoryRecordId]:
        """Enumerate active record ids for ``subject`` (forwards to
        :meth:`MemoryAPI.list_for_subject`)."""
        return await self._api.list_for_subject(subject)

    async def list_blocks(self, subject: SubjectRef) -> list[BlockRef]:
        """Enumerate active block refs for ``subject`` (forwards to
        :meth:`MemoryAPI.list_blocks`)."""
        return await self._api.list_blocks(subject)

    # -- Episodic recall ---------------------------------------------------

    async def recall_episodes(
        self, subject: SubjectRef, *, similarity_threshold: float, purpose: str
    ) -> list[Episode]:
        """Episodic recall (forwards to :meth:`MemoryAPI.recall_episodes`)."""
        return await self._api.recall_episodes(
            subject, similarity_threshold=similarity_threshold, purpose=purpose
        )


__all__ = ("MemorySDK",)
