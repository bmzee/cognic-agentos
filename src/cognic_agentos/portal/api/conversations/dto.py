"""ADR-028 M8.5-C — conversation wire DTOs.

``extra="forbid"`` on every request model is invariant I-1: the turn API has NO
history-accepting field, and a crafted payload attempting one fails closed-enum
validation with a 422. Tenant and subject come from the bound ``Actor`` only --
never from the body.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict, Field

from cognic_agentos.core.agent._types import (
    AgentDispatchRefusalReason,
    AgentRunTerminalState,
)
from cognic_agentos.core.conversation._types import ConversationState


class CreateConversationRequest(BaseModel):
    """The ONLY field is the agent to converse with.

    ``tenant_id`` / ``creator_subject`` are taken from the bound Actor; a body
    that supplies them is refused 422 by ``extra="forbid"``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_id: str = Field(min_length=1, max_length=128)


class PostTurnRequest(BaseModel):
    """The ONLY field is the new message.

    There is deliberately no ``messages`` / ``history`` / ``prior_context`` /
    ``transcript`` field: prior turns come exclusively from the kernel store
    (invariant I-1). ``extra="forbid"`` makes a client-supplied transcript
    unrepresentable on the wire.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    user_message: str = Field(min_length=1, max_length=32_000)


class ConversationResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    conversation_id: uuid.UUID
    agent_id: str
    state: ConversationState
    turn_count: int


class TurnResponse(BaseModel):
    """Carries the answer plaintext. Chain rows carry digests only."""

    model_config = ConfigDict(frozen=True)

    turn_id: uuid.UUID
    seq: int
    answer: str
    agent_run_id: str
    terminal_state: AgentRunTerminalState
    refusal_reason: AgentDispatchRefusalReason | None
