"""Sprint 11.5b T8 — RoutingMemoryAdapter.

CRITICAL CONTROL (core/ stop-rule per AGENTS.md — Memory governance
enforcement, ADR-019). Routes memory operations to the correct backend:

  * ``scratch`` writes → ``RedisMemoryAdapter`` when available; falls back to
    ``PostgresMemoryAdapter.put_scratch_fallback`` ONLY when Redis is
    *unreachable* (``MemoryBackendUnavailable.unreachable=True``).  A Redis
    write bug (``unreachable=False``) propagates — NO fallback.
  * ``scratch`` reads → Redis-first; if Redis hits, return immediately (Redis
    WINS).  If Redis is unavailable OR returns a miss, consult Postgres for a
    fallback row written during a past outage.  This makes a fallback row
    readable after Redis recovers (read-after-recovery invariant).
  * Non-scratch (``task`` / ``long_term``) → delegate to ``pg_adapter``
    directly for both reads and writes.
  * All seven remaining ``MemoryAdapter`` methods (list_for_subject, list_blocks,
    upsert_block, tombstone_record, purge_record, purge_expired, redact_record)
    → delegate to ``pg_adapter`` (durable rows + scratch-fallback rows live in
    Postgres; Redis TTL handles scratch expiry transparently).

**Cross-tenant / cross-agent / cross-subject isolation** is guaranteed by the
collision-free Redis key schema in ``RedisMemoryAdapter`` —
``memory:scratch:{sha256(canonical_bytes([tenant, agent, subject_canonical,
key]))}`` (a structured-hash, NOT a ``:``-join, so ``:``-bearing IDs/keys
cannot alias across subjects) — and by the standard ``tenant_id + agent_id``
WHERE clauses in ``PostgresMemoryAdapter.get``.

**Scratch enumerate via Redis SCAN** is out of 11.5b scope — durable enumerate
is always PG; ``list_for_subject`` delegates to ``pg_adapter`` and returns
scratch-fallback rows but not TTL'd Redis-only rows.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from cognic_agentos.core.memory._errors import MemoryBackendUnavailable

if TYPE_CHECKING:
    from cognic_agentos.core.memory._context import (
        BlockRef,
        MemoryHit,
        MemoryRecordId,
        MemoryWriteRecord,
        RedactionReceipt,
        RedactionSpan,
        RegulatorErasureCommand,
    )
    from cognic_agentos.core.memory.storage import (
        MemoryAdapter,
        PostgresMemoryAdapter,
    )
    from cognic_agentos.core.memory.tiers import (
        BlockKind,
        ForgetReason,
        MemoryTier,
        RedactionReason,
        SubjectRef,
    )


class RoutingMemoryAdapter:
    """Routes memory operations to Redis (scratch) or Postgres (durable).

    Conforms structurally to :class:`~cognic_agentos.core.memory.storage.MemoryAdapter`
    — all nine Protocol methods are implemented.

    ``redis_adapter`` is typed as :class:`MemoryAdapter` (the structural Protocol)
    so duck-typed stubs can be injected in tests without a hard import of
    ``RedisMemoryAdapter``.  The caller is responsible for ensuring the injected
    adapter only handles ``scratch`` tier operations.
    """

    def __init__(
        self,
        *,
        redis_adapter: MemoryAdapter,
        pg_adapter: PostgresMemoryAdapter,
        scratch_ttl_s: int,
    ) -> None:
        self._redis = redis_adapter
        self._pg = pg_adapter
        self._scratch_ttl_s = scratch_ttl_s

    # -----------------------------------------------------------------------
    # put — the primary routing decision point
    # -----------------------------------------------------------------------

    async def put(self, record: MemoryWriteRecord) -> MemoryRecordId:
        """Route a write to Redis (scratch) or Postgres (durable).

        Scratch write fallback contract (locked design decision #5):
        - Redis available → store transiently under the deterministic key.
        - Redis *unreachable* (``unreachable=True``) → fall back to Postgres
          via ``put_scratch_fallback`` with ``retention_until = now + scratch_ttl_s``.
        - Redis write bug (``unreachable=False``) → propagate — NO fallback.
          A write bug must not silently persist scratch data durably.
        """
        if record.tier == "scratch":
            try:
                return await self._redis.put(record)
            except MemoryBackendUnavailable as exc:
                if exc.unreachable:
                    # Redis is down — durably persist the scratch value so it
                    # survives the outage and is readable after Redis recovers.
                    retention_until = datetime.now(UTC) + timedelta(seconds=self._scratch_ttl_s)
                    return await self._pg.put_scratch_fallback(
                        record, retention_until=retention_until
                    )
                # Redis write bug → propagate, do NOT fall back.
                raise
        # Non-scratch → Postgres directly.
        return await self._pg.put(record)

    # -----------------------------------------------------------------------
    # get — Redis-first for scratch, then PG fallback on miss or unavailable
    # -----------------------------------------------------------------------

    async def get(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        subject: SubjectRef,
        tier: MemoryTier,
        key: str | None = None,
        block_kind: BlockKind | None = None,
    ) -> MemoryHit | None:
        """Read a record from the appropriate backend.

        Scratch read contract:
        1. Try Redis.  On a hit, return IMMEDIATELY (Redis hit wins).
        2. If Redis is *unreachable*, fall through to Postgres (a fallback row
           may have been written during the outage).
        3. If Redis is available but returns a MISS, also consult Postgres
           (read-after-recovery: a past-outage fallback row must stay readable
           until its ``retention_until`` passes).
        4. Return the Postgres result (may be ``None`` if no fallback row).

        Non-scratch → delegate to Postgres directly.
        """
        if tier == "scratch":
            redis_hit: MemoryHit | None = None
            try:
                redis_hit = await self._redis.get(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    subject=subject,
                    tier=tier,
                    key=key,
                    block_kind=block_kind,
                )
            except MemoryBackendUnavailable as exc:
                if not exc.unreachable:
                    raise
                # Redis unreachable — fall through to PG fallback read.

            if redis_hit is not None:
                # Redis hit WINS — PG not consulted.
                return redis_hit

            # Redis available-but-miss OR unavailable → consult PG for a
            # scratch fallback row.  The T4 retention-expiry filter makes
            # expired fallback rows an immediate miss without a reaper sweep.
            return await self._pg.get(
                tenant_id=tenant_id,
                agent_id=agent_id,
                subject=subject,
                tier=tier,
                key=key,
                block_kind=block_kind,
            )

        # Non-scratch → Postgres.
        return await self._pg.get(
            tenant_id=tenant_id,
            agent_id=agent_id,
            subject=subject,
            tier=tier,
            key=key,
            block_kind=block_kind,
        )

    # -----------------------------------------------------------------------
    # Remaining MemoryAdapter methods — delegate to pg_adapter
    # -----------------------------------------------------------------------

    async def list_for_subject(
        self, *, tenant_id: str, agent_id: str, subject: SubjectRef
    ) -> list[MemoryHit]:
        """Enumerate records — delegates to Postgres.

        Returns durable (task/long_term) rows and any surviving scratch-fallback
        rows.  TTL'd Redis-only scratch rows are NOT included (Redis SCAN is
        out of 11.5b scope).
        """
        return await self._pg.list_for_subject(
            tenant_id=tenant_id, agent_id=agent_id, subject=subject
        )

    async def list_blocks(
        self, *, tenant_id: str, agent_id: str, subject: SubjectRef
    ) -> list[BlockRef]:
        return await self._pg.list_blocks(tenant_id=tenant_id, agent_id=agent_id, subject=subject)

    async def upsert_block(self, record: MemoryWriteRecord) -> MemoryRecordId:
        return await self._pg.upsert_block(record)

    async def tombstone_record(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        record_id: MemoryRecordId,
        reason: ForgetReason,
        actor_id: str,
    ) -> None:
        return await self._pg.tombstone_record(
            tenant_id=tenant_id,
            agent_id=agent_id,
            record_id=record_id,
            reason=reason,
            actor_id=actor_id,
        )

    async def purge_record(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        record_id: MemoryRecordId,
        erasure_command: RegulatorErasureCommand,
        actor_id: str,
    ) -> None:
        return await self._pg.purge_record(
            tenant_id=tenant_id,
            agent_id=agent_id,
            record_id=record_id,
            erasure_command=erasure_command,
            actor_id=actor_id,
        )

    async def purge_expired(self, *, tombstone_window_s: int) -> int:
        return await self._pg.purge_expired(tombstone_window_s=tombstone_window_s)

    async def redact_record(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        record_id: MemoryRecordId,
        span: RedactionSpan,
        reason: RedactionReason,
        actor_id: str,
    ) -> RedactionReceipt:
        return await self._pg.redact_record(
            tenant_id=tenant_id,
            agent_id=agent_id,
            record_id=record_id,
            span=span,
            reason=reason,
            actor_id=actor_id,
        )


__all__ = ("RoutingMemoryAdapter",)
