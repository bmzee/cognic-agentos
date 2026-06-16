"""Sprint 14A-A3b — focused DTO tests for the resume route's request/response
shapes: the extracted ``_validate_argv_bounds`` helper, ``RunResumeRequest``
(frozen + extra-forbid + bounded argv), and ``RunResponse.run_id`` (new first
field). The HTTP-status mapping is covered by test_run_routes.py."""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from cognic_agentos.portal.api.runs.dto import (
    _MAX_ARGV_ITEM_LEN,
    _MAX_ARGV_ITEMS,
    RunResponse,
    RunResumeRequest,
    RunSubmitRequest,
    _validate_argv_bounds,
)

# --- _validate_argv_bounds (the shared helper) ------------------------------


def test_validate_argv_bounds_passes_a_normal_argv() -> None:
    assert _validate_argv_bounds(["echo", "hi"]) == ["echo", "hi"]


def test_validate_argv_bounds_rejects_empty() -> None:
    with pytest.raises(ValueError, match="argv_must_be_non_empty"):
        _validate_argv_bounds([])


def test_validate_argv_bounds_rejects_too_many_items() -> None:
    with pytest.raises(ValueError, match=f"argv_too_many_items_max_{_MAX_ARGV_ITEMS}"):
        _validate_argv_bounds(["x"] * (_MAX_ARGV_ITEMS + 1))


def test_validate_argv_bounds_rejects_oversized_item() -> None:
    with pytest.raises(ValueError, match=f"argv_item_too_long_max_{_MAX_ARGV_ITEM_LEN}"):
        _validate_argv_bounds(["x" * (_MAX_ARGV_ITEM_LEN + 1)])


# --- RunResumeRequest -------------------------------------------------------


def test_resume_request_accepts_bounded_argv() -> None:
    req = RunResumeRequest(argv=["cont", "go"])
    assert req.argv == ["cont", "go"]


def test_resume_request_is_frozen() -> None:
    req = RunResumeRequest(argv=["go"])
    with pytest.raises(ValidationError):
        req.argv = ["other"]


def test_resume_request_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError):
        RunResumeRequest(argv=["go"], tenant_id="attacker")  # type: ignore[call-arg]


def test_resume_request_rejects_empty_argv() -> None:
    with pytest.raises(ValidationError):
        RunResumeRequest(argv=[])


def test_resume_request_rejects_oversized_argv_item() -> None:
    with pytest.raises(ValidationError):
        RunResumeRequest(argv=["x" * (_MAX_ARGV_ITEM_LEN + 1)])


def test_submit_request_shares_the_same_argv_validator() -> None:
    # both DTOs reject the same out-of-bounds argv (one shared helper).
    with pytest.raises(ValidationError):
        RunSubmitRequest(
            pack_id="p",
            pack_uuid=uuid.UUID("11111111-1111-1111-1111-111111111111"),
            pack_version="1.0.0",
            argv=[],
        )


# --- RunResponse.run_id -----------------------------------------------------


def test_run_response_carries_run_id() -> None:
    resp = RunResponse(
        run_id="rid",
        task_id="tid",
        terminal_state="completed",
        exit_code=0,
        stdout_b64="",
        stderr_b64="",
        stdout_bytes=0,
        stderr_bytes=0,
        refusal_reason=None,
        approval_request_id=None,
    )
    assert resp.run_id == "rid"
