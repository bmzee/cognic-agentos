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


# --- Sprint 11.5b T1 — erasure / lifecycle DTOs ---


@dataclasses.dataclass(frozen=True, slots=True)
class RedactionSpan:
    """JSON field-path selector for redact() (locked: field-path, NOT byte-span).

    ``path`` walks nested mappings (e.g. ``("account", "number")``); the leaf
    value is replaced by ``replacement``. A missing or non-container path
    refuses with ``memory_redaction_path_invalid``.
    """

    path: tuple[str, ...]
    replacement: object = "[REDACTED]"


@dataclasses.dataclass(frozen=True, slots=True)
class RegulatorErasureCommand:
    """Chain-of-custody metadata REQUIRED for ``forget(reason='regulator_erasure')``.

    Core records all three fields on the ``memory.regulator_erasure`` chain
    event. RBAC enforcement of ``requester_scope`` is the 11.5c portal's job —
    core has no Actor/scope set; it validates ``requester_scope`` equals
    ``"memory.regulator_erasure"`` and refuses with
    ``memory_regulator_erasure_metadata_required`` on mismatch or absence.
    """

    regulator_order_id: str
    requester_scope: str  # must == "memory.regulator_erasure" (validated in forget.py)
    subject_id: str


@dataclasses.dataclass(frozen=True, slots=True)
class ForgetReceipt:
    """Receipt returned by a successful ``forget()`` call."""

    record_id: MemoryRecordId
    tombstoned: bool
    purged: bool  # True only on the regulator_erasure immediate-purge path


@dataclasses.dataclass(frozen=True, slots=True)
class RedactionReceipt:
    """Receipt returned by a successful ``redact()`` call."""

    record_id: MemoryRecordId  # the ORIGINAL record id (now sealed)
    new_version_id: MemoryRecordId
    redaction_version: int


# --- Sprint 11.5c T4 — value-free enumerate metadata ---


@dataclasses.dataclass(frozen=True, slots=True)
class MemoryRecordMetadata:
    """Value-free projection of a MemoryHit for the governed list_records
    enumerate (portal records surface, Sprint 11.5c T4). Deliberately carries
    NO ``value`` — value reads go through the recall purpose-matrix or the
    authorized export path."""

    record_id: MemoryRecordId
    agent_id: str
    tier: MemoryTier
    data_classes: tuple[str, ...]
    purpose: str
    created_at: datetime
    block_kind: BlockKind | None = None


# --- Sprint 11.5c T3 — export receipt ---


@dataclasses.dataclass(frozen=True, slots=True)
class ExportReceipt:
    """Receipt returned by a successful ``export()`` call.

    Carries the object-store key where the archive was persisted, the sha256
    commitment over the archive bytes, and the count of exported records.
    """

    object_key: str
    archive_sha256: str
    record_count: int
