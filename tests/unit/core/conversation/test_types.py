"""ADR-028 M8.5-A — closed-enum + state-machine drift detectors.

Mirrors tests/unit/core/run/test_run_types.py. The ConversationState VOCABULARY
is fixed at 4 values; later slices EXPAND the legal-transition matrix only.
"""

from __future__ import annotations

import dataclasses
import typing
import uuid
from datetime import UTC, datetime

import pytest

from cognic_agentos.core.conversation._types import (
    ConversationNotFound,
    ConversationRecord,
    ConversationState,
    ConversationTransitionRefused,
    ConversationTurnRefusalReason,
    ConversationTurnRefused,
    TurnRecord,
    validate_transition,
)


def test_conversation_state_has_exactly_four_values() -> None:
    assert set(typing.get_args(ConversationState)) == {
        "active",
        "closed",
        "expired",
        "erased",
    }


def test_turn_refusal_reason_has_exactly_five_values() -> None:
    """conversation_turn_claim_stale is the P0 fencing refusal (2026-07-10)."""
    assert set(typing.get_args(ConversationTurnRefusalReason)) == {
        "conversation_not_active",
        "conversation_turn_in_progress",
        "conversation_max_turns_exceeded",
        "conversation_token_budget_exceeded",
        "conversation_turn_claim_stale",
    }


def test_active_to_closed_is_the_only_legal_pair_in_this_slice() -> None:
    validate_transition(from_state="active", to_state="closed")


@pytest.mark.parametrize(
    ("frm", "to"),
    [
        ("active", "expired"),  # reserved — reaper slice
        ("active", "erased"),  # reserved — erasure slice
        ("closed", "active"),  # no reopen in v1 (spec §3)
        ("closed", "closed"),  # no self-loop
        ("erased", "closed"),
        ("expired", "active"),
    ],
)
def test_reserved_pairs_refuse_until_expanded(
    frm: ConversationState, to: ConversationState
) -> None:
    with pytest.raises(ConversationTransitionRefused) as exc:
        validate_transition(from_state=frm, to_state=to)
    assert exc.value.reason == "conversation_transition_invalid_state_pair"


def test_validate_transition_is_keyword_only() -> None:
    with pytest.raises(TypeError):
        validate_transition("active", "closed")  # type: ignore[misc]


def test_turn_refused_carries_reason_and_current_state() -> None:
    exc = ConversationTurnRefused("conversation_not_active", current_state="closed")
    assert exc.reason == "conversation_not_active"
    assert exc.current_state == "closed"


def test_conversation_not_found_is_an_exception() -> None:
    assert issubclass(ConversationNotFound, Exception)


def test_conversation_record_is_frozen() -> None:
    rec = ConversationRecord(
        conversation_id=uuid.uuid4(),
        tenant_id="t1",
        agent_id="a1",
        creator_subject="s1",
        state="active",
        turn_count=0,
        cumulative_tokens=0,
        created_at=datetime.now(UTC),
        last_turn_at=None,
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.state = "closed"  # type: ignore[misc]


def test_turn_record_plaintext_is_nullable_for_erasure() -> None:
    """After erasure the row survives; seq + agent_run_id keep the chain join."""
    rec = TurnRecord(
        turn_id=uuid.uuid4(),
        seq=1,
        user_message=None,
        answer=None,
        agent_run_id="agent-run-1",
        prompt_tokens=0,
        completion_tokens=0,
        created_at=datetime.now(UTC),
    )
    assert rec.user_message is None and rec.answer is None
    assert rec.seq == 1 and rec.agent_run_id == "agent-run-1"
