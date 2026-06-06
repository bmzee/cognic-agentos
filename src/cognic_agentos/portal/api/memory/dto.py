"""Sprint 11.5c T5 — Pydantic v2 DTOs for the /api/v1/memory portal surface.

Pure type / shape module — no FastAPI, no Depends, no closure-locals.
``from __future__ import annotations`` IS present here (this is a plain
Pydantic model module, not a closure-factory route module; the PEP 563
standing-offer §30 ban applies ONLY to ``routes.py`` where FastAPI's
``inspect.signature`` must resolve ``Annotated[..., Depends(<closure-local>)]``
annotations eagerly).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

import pydantic

from cognic_agentos.core.memory.tiers import (
    BlockKind,
    ForgetReason,
    MemoryTier,
    RedactionReason,
)


class MemoryRecordMetadataResponse(pydantic.BaseModel):
    """Value-free projection of a MemoryRecordMetadata for the portal records
    surface. Deliberately carries NO ``value`` field — value reads go through
    recall / export, not this enumerate surface."""

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")

    record_id: uuid.UUID
    agent_id: str
    tier: MemoryTier
    data_classes: list[str]
    purpose: str
    created_at: datetime
    block_kind: BlockKind | None = None


class ErasureCommandBody(pydantic.BaseModel):
    """Portal wire-shape for the core ``RegulatorErasureCommand`` (custody metadata)."""

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")

    regulator_order_id: str
    requester_scope: str
    subject_id: str
    # Review §4.3 — the erased subject's kind. Derives
    # expected_subject_ref = f"{subject_kind}:{subject_id}" so agent-kind
    # records can be erased (was hardcoded "human:"). Defaults "human" for
    # backward-compat with existing human-subject erasure clients.
    subject_kind: Literal["human", "agent"] = "human"


class ForgetRequest(pydantic.BaseModel):
    """Request body for ``POST /records/{record_id}/forget``."""

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")

    reason: ForgetReason
    agent_id: str = pydantic.Field(min_length=1)
    subject_kind: Literal["human", "agent"]
    subject_id: str = pydantic.Field(min_length=1)
    erasure_command: ErasureCommandBody | None = None


class RedactRequest(pydantic.BaseModel):
    """Request body for ``POST /records/{record_id}/redact``."""

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")

    span_path: list[str]
    replacement: Any = "[REDACTED]"
    reason: RedactionReason
    agent_id: str = pydantic.Field(min_length=1)
    subject_kind: Literal["human", "agent"]
    subject_id: str = pydantic.Field(min_length=1)


class ExportRequest(pydantic.BaseModel):
    """Request body for ``POST /export``."""

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")

    agent_id: str = pydantic.Field(min_length=1)
    subject_kind: Literal["human", "agent"]
    subject_id: str = pydantic.Field(min_length=1)


class ForgetReceiptResponse(pydantic.BaseModel):
    """Response shape for a successful ``forget()`` call."""

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")

    record_id: uuid.UUID
    tombstoned: bool
    purged: bool


class RedactionReceiptResponse(pydantic.BaseModel):
    """Response shape for a successful ``redact()`` call."""

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")

    record_id: uuid.UUID
    new_version_id: uuid.UUID
    redaction_version: int


class ExportReceiptResponse(pydantic.BaseModel):
    """Response shape for a successful ``export()`` call."""

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")

    object_key: str
    archive_sha256: str
    record_count: int
