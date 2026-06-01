from __future__ import annotations

import dataclasses
import uuid
from datetime import datetime

from cognic_agentos.core.memory.tiers import BlockKind, MemoryTier, SubjectRef

MemoryRecordId = uuid.UUID


@dataclasses.dataclass(frozen=True, slots=True)
class MemoryCallerContext:
    tenant_id: str
    agent_id: str
    actor_id: str
    served_subject: SubjectRef
    is_subagent: bool
    long_term_writes_allowed: bool
    cross_subject_recall: bool
    memory_read_capabilities: frozenset[str]
    declared_purposes: frozenset[str]
    declared_data_classes: frozenset[str]
    risk_tier: str


@dataclasses.dataclass(frozen=True, slots=True)
class MemoryHit:
    record_id: MemoryRecordId
    value: object
    tier: MemoryTier
    data_classes: tuple[str, ...]
    purpose: str
    created_at: datetime
    block_kind: BlockKind | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class BlockRef:
    record_id: MemoryRecordId
    kind: BlockKind
    subject: SubjectRef
    version: int


@dataclasses.dataclass(frozen=True, slots=True)
class Episode:
    record_id: MemoryRecordId
    summary: str
    decision_trace_id: str | None
    created_at: datetime


@dataclasses.dataclass(frozen=True, slots=True)
class MemoryWriteRecord:
    """The write payload MemoryAPI builds (from the bound MemoryCallerContext +
    call args) and hands to MemoryAdapter.put / upsert_block."""

    tenant_id: str
    agent_id: str
    actor_id: str
    subject: SubjectRef
    tier: MemoryTier
    purpose: str
    data_classes: tuple[str, ...]
    value: object
    request_id: str
    key: str | None = None
    block_kind: BlockKind | None = None
    retention_until: datetime | None = None
