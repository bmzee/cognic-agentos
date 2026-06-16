"""Sprint 14A-A2a — POST /api/v1/runs request/response DTOs (ADR-022)."""

from __future__ import annotations

import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

#: argv bounds — non-empty + bounded per-item + bounded count (no shell concat;
#: argv is passed verbatim to session.exec). Empty/oversized -> 422.
_MAX_ARGV_ITEMS = 64
_MAX_ARGV_ITEM_LEN = 4096


class RunSubmitRequest(BaseModel):
    """Body for POST /api/v1/runs. tenant_id + actor come ONLY from the bound
    Actor — this DTO has NO tenant/actor field (extra='forbid' rejects them)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    pack_id: str
    pack_uuid: uuid.UUID
    pack_version: str
    argv: list[str]
    approval_request_id: uuid.UUID | None = None

    @field_validator("argv")
    @classmethod
    def _argv_bounded(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("argv_must_be_non_empty")
        if len(v) > _MAX_ARGV_ITEMS:
            raise ValueError(f"argv_too_many_items_max_{_MAX_ARGV_ITEMS}")
        for item in v:
            if len(item) > _MAX_ARGV_ITEM_LEN:
                raise ValueError(f"argv_item_too_long_max_{_MAX_ARGV_ITEM_LEN}")
        return v


class RunResponse(BaseModel):
    """Returned for every terminal state. Raw stdout/stderr are base64-encoded
    (bytes are not an accidental wire ambiguity); *_bytes are the decoded sizes."""

    model_config = ConfigDict(frozen=True)

    task_id: str | None
    # Sprint 14A-A3b widened the executor's public RunTerminalState with
    # "suspended". The synchronous POST /api/v1/runs caller never sets
    # suspend_after_exec (RunSubmitRequest has no such field), so a route-driven
    # run cannot currently return "suspended" — but the response Literal mirrors
    # the executor's public type so the mapping stays type-exact (the dedicated
    # resume route in a later slice exercises the suspended path).
    terminal_state: Literal["completed", "failed", "refused", "pending_approval", "suspended"]
    exit_code: int | None
    stdout_b64: str
    stderr_b64: str
    stdout_bytes: int
    stderr_bytes: int
    refusal_reason: str | None
    approval_request_id: str | None
