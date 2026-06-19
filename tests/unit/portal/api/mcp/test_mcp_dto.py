"""MCP route DTOs (ADR-002)."""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from cognic_agentos.portal.api.mcp.dto import CallToolRequest


def test_call_request_defaults_empty_arguments() -> None:
    req = CallToolRequest(tool_name="lookup")
    assert req.arguments == {}
    assert req.approval_request_id is None


def test_call_request_parses_approval_request_id_to_uuid() -> None:
    rid = uuid.uuid4()
    # model_validate (runtime parsing) — the wire sends approval_request_id as a
    # str; Pydantic parses it to UUID. (A typed constructor call would fail mypy.)
    req = CallToolRequest.model_validate({"tool_name": "lookup", "approval_request_id": str(rid)})
    assert req.approval_request_id == rid


def test_call_request_rejects_empty_tool_name() -> None:
    with pytest.raises(ValidationError):
        CallToolRequest(tool_name="")


def test_call_request_forbids_extra_fields() -> None:
    # model_validate so mypy doesn't reject the deliberate unknown kwarg; the
    # extra='forbid' rejection is a RUNTIME ValidationError.
    with pytest.raises(ValidationError):
        CallToolRequest.model_validate({"tool_name": "lookup", "tenant_id": "t"})


def test_call_request_preserves_raw_tool_name() -> None:
    # Control chars stay verbatim — the route NEVER sanitizes / path-encodes.
    raw = "look\tup\n; rm -rf"
    assert CallToolRequest(tool_name=raw).tool_name == raw
