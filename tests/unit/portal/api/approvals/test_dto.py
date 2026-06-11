from __future__ import annotations

import uuid

import pydantic
import pytest

from cognic_agentos.portal.api.approvals.dto import (
    ApprovalActionResponse,
    ApprovalDetailResponse,
    DenyRequest,
    GrantRequest,
)


def test_grant_request_reason_optional() -> None:
    assert GrantRequest().reason is None
    assert GrantRequest(reason="ok").reason == "ok"


def test_deny_request_reason_required() -> None:
    with pytest.raises(pydantic.ValidationError):
        DenyRequest()  # type: ignore[call-arg]


def test_dtos_forbid_extra() -> None:
    with pytest.raises(pydantic.ValidationError):
        ApprovalActionResponse(request_id=uuid.uuid4(), state="granted", boom=1)  # type: ignore[call-arg]


def test_detail_response_digests_are_hex_strings() -> None:
    # args_digest/envelope_digest are str (hex) on the wire, never bytes.
    fields = ApprovalDetailResponse.model_fields
    assert fields["args_digest"].annotation is str
    assert fields["envelope_digest"].annotation is str
