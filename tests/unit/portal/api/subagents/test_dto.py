"""POST /api/v1/subagents DTOs (ADR-005)."""

import uuid
from typing import Any

import pytest
from pydantic import ValidationError

from cognic_agentos.portal.api.subagents.dto import (
    ManagedRunChildSpecBody,
    SubAgentSpawnRequestBody,
)


def _valid_body() -> dict[str, Any]:
    return {
        "parent_run_id": str(uuid.uuid4()),
        "managed_run": {"pack_id": "cognic-tool-x", "pack_version": "1.0.0", "argv": ["--run"]},
        "prompt": "do the thing",
        "parent_tool_allow_list": ["a", "b", "b"],  # dupe is fine — frozenset dedupes
        "requested_tool_allow_list": ["a"],
        "requested_estimated_tokens": 100,
    }


def test_request_body_parses_and_uuid_typed() -> None:
    body = SubAgentSpawnRequestBody.model_validate(_valid_body())
    assert isinstance(body.parent_run_id, uuid.UUID)
    assert body.managed_run.pack_id == "cognic-tool-x"


def test_request_body_forbids_extra_fields() -> None:
    bad = _valid_body() | {"tenant_id": "tenant-evil"}  # tenant comes from the Actor only
    with pytest.raises(ValidationError):
        SubAgentSpawnRequestBody.model_validate(bad)


def test_request_body_forbids_current_depth() -> None:
    bad = _valid_body() | {"current_depth": 5}  # route-set to 0; never a body field
    with pytest.raises(ValidationError):
        SubAgentSpawnRequestBody.model_validate(bad)


def test_malformed_parent_run_id_is_422() -> None:
    bad = _valid_body() | {"parent_run_id": "not-a-uuid"}
    with pytest.raises(ValidationError):
        SubAgentSpawnRequestBody.model_validate(bad)


def test_approval_request_id_absent_defaults_none() -> None:
    body = SubAgentSpawnRequestBody.model_validate(_valid_body())
    assert body.approval_request_id is None


def test_approval_request_id_parses_uuid() -> None:
    grant = uuid.uuid4()
    body = SubAgentSpawnRequestBody.model_validate(
        _valid_body() | {"approval_request_id": str(grant)}
    )
    assert body.approval_request_id == grant


def test_malformed_approval_request_id_is_422() -> None:
    bad = _valid_body() | {"approval_request_id": "not-a-uuid"}
    with pytest.raises(ValidationError):
        SubAgentSpawnRequestBody.model_validate(bad)


def test_managed_run_argv_must_be_non_empty() -> None:
    bad = _valid_body()
    bad["managed_run"] = {"pack_id": "p", "pack_version": "1.0.0", "argv": []}
    with pytest.raises(ValidationError):
        SubAgentSpawnRequestBody.model_validate(bad)


def test_managed_run_child_spec_body_standalone() -> None:
    spec = ManagedRunChildSpecBody.model_validate(
        {"pack_id": "p", "pack_version": "1.0.0", "argv": ["x"]}
    )
    assert spec.argv == ["x"]
