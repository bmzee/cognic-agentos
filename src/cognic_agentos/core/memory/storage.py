"""Governed-memory storage Protocol + relational Table — Sprint 11.5a per ADR-019.

CRITICAL CONTROL (core/ stop-rule per AGENTS.md — Memory governance
enforcement, ADR-019). This module owns the persistence CONTRACT for the
memory substrate:

  * ``MemoryAdapter`` — the structural Protocol every concrete backend
    (PostgresMemoryAdapter / RedisMemoryAdapter) MUST satisfy. Those
    concrete adapters are Task 6 and are NOT in this module — T5 ships
    the contract only.
  * ``_memory_records`` — the in-process SQLAlchemy Table mirroring the
    ``memory_records`` table created by the ``0006`` migration. The Table
    here MUST agree column-for-column (type, length, nullability) with
    ``db/migrations/versions/20260531_0006_memory.py``; drift is pinned
    by ``tests/unit/db/test_migration_20260531_0006.py`` which reflects
    the migrated DB and compiles both for the SQLite dialect.
  * ``MemoryBackendUnavailable`` — an INFRA exception. It is deliberately
    NOT a ``MemoryOperationRefused`` subclass: a backend-down condition is
    not a governance refusal and must not be confused with the wire-public
    closed-enum ``MemoryRefusalReason`` taxonomy.

No concrete adapter implementations live here — no driver imports
(``asyncpg`` / ``redis`` / ``qdrant_client`` / ``hvac``). SQLAlchemy core
is used for the Table + portable column types only.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

import sqlalchemy as sa

from cognic_agentos.core.memory._context import (
    BlockRef,
    MemoryHit,
    MemoryRecordId,
    MemoryWriteRecord,
)
from cognic_agentos.core.memory.tiers import (
    BlockKind,
    MemoryTier,
    SubjectRef,
)
from cognic_agentos.db.types import GovernanceJSON

#: Pin: ``sa.TIMESTAMP(timezone=True)`` — NOT ``sa.DateTime(timezone=True)``.
#: ``sa.DateTime`` compiles to ``DATE`` on Oracle, silently dropping the
#: offset. Mirrors ``SCHEDULER_TS_TYPE`` in the 0005 migration.
MEMORY_TS_TYPE = sa.TIMESTAMP(timezone=True)


@runtime_checkable
class MemoryAdapter(Protocol):
    """Structural contract for governed-memory persistence backends.

    Concrete adapters (Postgres / Redis) land in Task 6 and structurally
    conform to this Protocol — they are NOT defined in this module."""

    async def put(self, record: MemoryWriteRecord) -> MemoryRecordId: ...

    async def get(
        self,
        *,
        subject: SubjectRef,
        tier: MemoryTier,
        key: str | None = None,
        block_kind: BlockKind | None = None,
    ) -> MemoryHit | None: ...

    async def list_for_subject(self, subject: SubjectRef) -> list[MemoryHit]: ...

    async def list_blocks(self, subject: SubjectRef) -> list[BlockRef]: ...

    async def upsert_block(self, record: MemoryWriteRecord) -> MemoryRecordId: ...


class MemoryBackendUnavailable(Exception):
    """Infra failure (backend unreachable / driver error).

    Deliberately a plain ``Exception`` — NOT a ``MemoryOperationRefused``
    subclass. An unreachable backend is not a governance refusal and must
    not be mistaken for the wire-public ``MemoryRefusalReason`` taxonomy."""


_metadata = sa.MetaData()

#: In-process Table mirroring the ``memory_records`` table from the 0006
#: migration. Column type / length / nullability MUST be byte-identical to
#: the migration — pinned by ``test_migration_20260531_0006`` which compiles
#: both for the SQLite dialect and asserts equality.
_memory_records = sa.Table(
    "memory_records",
    _metadata,
    sa.Column("record_id", sa.Uuid(), primary_key=True),
    sa.Column("tenant_id", sa.String(128), nullable=False),
    sa.Column("subject_ref", sa.String(256), nullable=False),
    sa.Column("agent_id", sa.String(128), nullable=False),
    sa.Column("tier", sa.String(16), nullable=False),
    sa.Column("block_kind", sa.String(32), nullable=True),
    sa.Column("key", sa.String(256), nullable=True),
    sa.Column("value", GovernanceJSON(), nullable=False),
    sa.Column("data_classes", GovernanceJSON(), nullable=False),
    sa.Column("purpose", sa.String(64), nullable=False),
    sa.Column("retention_until", MEMORY_TS_TYPE, nullable=True),
    sa.Column("tombstone", MEMORY_TS_TYPE, nullable=True),
    sa.Column("redaction_version", sa.Integer(), nullable=False),
    sa.Column("sealed_prior_version_ref", sa.Uuid(), nullable=True),
    sa.Column("vector_ref", sa.String(256), nullable=True),
    sa.Column("created_at", MEMORY_TS_TYPE, nullable=False),
    sa.CheckConstraint(
        "(key IS NOT NULL AND block_kind IS NULL) OR (key IS NULL AND block_kind IS NOT NULL)",
        name="ck_memory_records_key_xor_block_kind",
    ),
)


__all__: tuple[str, ...] = (
    "MemoryAdapter",
    "MemoryBackendUnavailable",
)
