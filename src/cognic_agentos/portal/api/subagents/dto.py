"""POST /api/v1/subagents request/response DTOs (ADR-005)."""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict, field_validator

#: argv bounds — mirror the run route (non-empty, bounded count + per-item length).
_MAX_ARGV_ITEMS = 64
_MAX_ARGV_ITEM_LEN = 4096
#: tool-list bounds — defensive caps on the body-supplied allow-lists.
_MAX_TOOLS = 512
_MAX_TOOL_ID_LEN = 512


def _validate_argv_bounds(v: list[str]) -> list[str]:
    if not v:
        raise ValueError("argv_must_be_non_empty")
    if len(v) > _MAX_ARGV_ITEMS:
        raise ValueError(f"argv_too_many_items_max_{_MAX_ARGV_ITEMS}")
    for item in v:
        if len(item) > _MAX_ARGV_ITEM_LEN:
            raise ValueError(f"argv_item_too_long_max_{_MAX_ARGV_ITEM_LEN}")
    return v


def _validate_tool_list(v: list[str]) -> list[str]:
    if len(v) > _MAX_TOOLS:
        raise ValueError(f"tool_list_too_many_max_{_MAX_TOOLS}")
    for item in v:
        if len(item) > _MAX_TOOL_ID_LEN:
            raise ValueError(f"tool_id_too_long_max_{_MAX_TOOL_ID_LEN}")
    return v


class ManagedRunChildSpecBody(BaseModel):
    """The child's managed-run identity (maps to ManagedRunChildSpec)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    pack_id: str
    pack_version: str
    argv: list[str]

    @field_validator("argv")
    @classmethod
    def _argv_bounded(cls, v: list[str]) -> list[str]:
        return _validate_argv_bounds(v)


class SubAgentSpawnRequestBody(BaseModel):
    """Body for POST /api/v1/subagents. tenant_id + actor come ONLY from the bound
    Actor; current_depth is route-set to 0 (never a body field). Tool lists are
    list[str] for JSON ergonomics (deduped to frozenset when building the spawn
    request); ordering is not semantically meaningful."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    parent_run_id: uuid.UUID
    managed_run: ManagedRunChildSpecBody
    prompt: str
    parent_tool_allow_list: list[str]
    requested_tool_allow_list: list[str]
    requested_estimated_tokens: int
    #: the granted approval id on a pending-child retry (else None); parsed as
    #: uuid.UUID (malformed -> 422), str()'d back into the spawn request at the route.
    approval_request_id: uuid.UUID | None = None

    @field_validator("parent_tool_allow_list", "requested_tool_allow_list")
    @classmethod
    def _tool_list_bounded(cls, v: list[str]) -> list[str]:
        return _validate_tool_list(v)


class ChildResultBody(BaseModel):
    """The coarse child outcome (maps from ChildResult)."""

    model_config = ConfigDict(frozen=True)

    ok: bool
    summary: str
    tokens_used: int
    wall_time_used_s: float
    #: mirrors core/run RunTerminalState (str avoids a core import) so the pending
    #: state is visible in the body alongside the top-level approval_request_id.
    terminal_state: str | None = None


class SubAgentSpawnResponse(BaseModel):
    """200/202 body. spawn_record_id is str(result.spawn_record_id) — the
    audit-correlatable subagent.spawn chain-event id. A pending child surfaces as
    202 + top-level approval_request_id; a failed/refused child rides
    child_result.ok=false + summary inside the 200."""

    model_config = ConfigDict(frozen=True)

    spawn_record_id: str
    child_result: ChildResultBody
    #: set ONLY on the pending-approval path (the granted-id correlator the caller
    #: re-POSTs to retry); None otherwise.
    approval_request_id: str | None = None
