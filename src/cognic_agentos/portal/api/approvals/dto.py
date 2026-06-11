"""Sprint 13.5b1 (ADR-014) — portal approval API DTOs. Frozen, extra-forbid,
from_attributes. All digests render as hex strings (never bytes; never raw args)."""

from __future__ import annotations

import uuid

import pydantic

from cognic_agentos.core.approval._types import ApprovalFlow, ApprovalState


class _ApprovalBaseModel(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")


class _ApprovalResponseModel(_ApprovalBaseModel):
    model_config = pydantic.ConfigDict(frozen=True, extra="forbid", from_attributes=True)


class ApprovalSummaryResponse(_ApprovalResponseModel):
    request_id: uuid.UUID
    tenant_id: str
    flow: ApprovalFlow
    risk_tier: str
    tool_identity: str
    originator_subject: str
    state: ApprovalState
    first_approver: str | None
    created_at: str
    expires_at: str


class ApprovalDetailResponse(_ApprovalResponseModel):
    request_id: uuid.UUID
    tenant_id: str
    state: ApprovalState
    flow: ApprovalFlow
    risk_tier: str
    tool_identity: str
    originator_subject: str
    envelope_digest: str  # hex
    args_digest: str  # hex
    data_classes: tuple[str, ...]
    redacted_context: str
    first_approver: str | None
    second_approver: str | None
    denier: str | None
    created_at: str
    expires_at: str


class GrantRequest(_ApprovalBaseModel):
    reason: str | None = None


class DenyRequest(_ApprovalBaseModel):
    reason: str


class ApprovalActionResponse(_ApprovalBaseModel):
    request_id: uuid.UUID
    state: ApprovalState
