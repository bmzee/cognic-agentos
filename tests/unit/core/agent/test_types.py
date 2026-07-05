"""M8 Task A4 (ADR-027) — closed-enum pins + frozen/slots dataclass behavior
for ``core/agent/_types.py``.

Closed-enum counts via ``typing.get_args`` per
``feedback_count_enum_values_via_ast_not_regex``. These are the ONLY count
pins for ``AgentDispatchRefusalReason`` / ``AgentRunTerminalState`` (the A2
lesson) — keep it that way.
"""

from __future__ import annotations

import dataclasses
from typing import Any, get_args

import pytest

from cognic_agentos.core.agent._types import (
    AgentAskResult,
    AgentDispatchRefusalReason,
    AgentGrantNotRequested,
    AgentRunTerminalState,
    CapabilityRef,
    GrantedCapabilities,
    LoadedAgentRecord,
)


def _record(**overrides: Any) -> LoadedAgentRecord:
    base: dict[str, Any] = {
        "agent_id": "bank-analyst",
        "persona_body": "You are the bank analyst.",
        "persona_sha256": "a" * 64,
        "requested_skills": ("customer-data", "financial-data"),
        "requested_tools": ("cognic-tool-oracle-schema/run_readonly_query",),
        "max_steps": 6,
        "risk_tier": "customer_data_read",
        "pack_version": "0.1.0",
        "signed_artefact_digest": None,
        "registered": True,
    }
    base.update(overrides)
    return LoadedAgentRecord(**base)


# --------------------------------------------------------------------------- #
# Closed-enum pins (the ONLY count pins for these enums)
# --------------------------------------------------------------------------- #


def test_agent_dispatch_refusal_reason_has_exactly_seven_values() -> None:
    values = get_args(AgentDispatchRefusalReason)
    assert len(values) == 7
    assert set(values) == {
        "agent_capability_not_assigned",
        "agent_scope_not_entitled",
        "agent_sql_object_out_of_scope",
        "agent_max_steps_exceeded",
        "agent_tool_dispatch_failed",
        "agent_policy_denied",
        "agent_grant_not_requested",
    }


def test_agent_run_terminal_state_has_exactly_three_values() -> None:
    values = get_args(AgentRunTerminalState)
    assert len(values) == 3
    assert set(values) == {"completed", "refused", "failed"}


# --------------------------------------------------------------------------- #
# Frozen + slots behavior
# --------------------------------------------------------------------------- #


def _instances() -> list[Any]:
    return [
        _record(),
        CapabilityRef(kind="skill", ref="customer-data"),
        AgentAskResult(
            run_id="agent-run-abc",
            terminal_state="completed",
            answer="42",
            steps_used=2,
            refusal_reason=None,
        ),
        GrantedCapabilities(
            skills=frozenset({"customer-data"}),
            tools=frozenset({"cognic-tool-oracle-schema/run_readonly_query"}),
        ),
    ]


@pytest.mark.parametrize("instance", _instances(), ids=lambda i: type(i).__name__)
def test_dataclasses_are_frozen(instance: Any) -> None:
    field_name = dataclasses.fields(instance)[0].name
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(instance, field_name, "tampered")


@pytest.mark.parametrize("instance", _instances(), ids=lambda i: type(i).__name__)
def test_dataclasses_use_slots_no_dict(instance: Any) -> None:
    assert not hasattr(instance, "__dict__")


def test_granted_capabilities_sets_are_frozensets() -> None:
    granted = GrantedCapabilities(skills=frozenset(), tools=frozenset())
    assert isinstance(granted.skills, frozenset)
    assert isinstance(granted.tools, frozenset)


# --------------------------------------------------------------------------- #
# AgentGrantNotRequested
# --------------------------------------------------------------------------- #


def test_agent_grant_not_requested_carries_reason_and_ref() -> None:
    exc = AgentGrantNotRequested(capability_ref="atm-recon", capability_kind="skill")
    assert isinstance(exc, RuntimeError)
    assert exc.reason == "agent_grant_not_requested"
    assert exc.capability_ref == "atm-recon"


def test_agent_grant_not_requested_message_carries_ref_and_kind() -> None:
    exc = AgentGrantNotRequested(capability_ref="atm-recon", capability_kind="skill")
    message = str(exc)
    assert "atm-recon" in message
    assert "skill" in message
