"""MCP tool-invocation route request/response DTOs (ADR-002)."""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CallToolRequest(BaseModel):
    """Body for POST /api/v1/mcp/servers/{server_id}/tools/call. tenant_id +
    originator come ONLY from the bound Actor (extra='forbid' rejects them).
    ``tool_name`` is caller-supplied RAW identity — passed verbatim to
    ``call_tool`` (the host owns audit-canonical raw tool identity); the route
    NEVER sanitizes or path-encodes it. ``arguments`` uses an explicit
    ``default_factory`` (not a bare ``= {}``) per the repo convention."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool_name: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)
    approval_request_id: uuid.UUID | None = None


class CallToolResponse(BaseModel):
    """200 envelope — the ``CallResult`` projection (payload + the correlation
    IDs examiners replay against the audit chain + decision-history rows)."""

    model_config = ConfigDict(frozen=True)

    payload: Any
    request_id: str
    server_id: str
    tool_name: str
    mcp_session_id: str | None
    as_issuer: str
    scopes: list[str]
    client_id: str


class ListToolsResponse(BaseModel):
    """200 envelope for the list route — the flat host-provided tool catalogue
    (already deep-copy-isolated from the host's per-tenant cache)."""

    model_config = ConfigDict(frozen=True)

    tools: list[Any]
