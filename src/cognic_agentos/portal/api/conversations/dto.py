"""ADR-028 M8.5-C — conversation wire DTOs.

``extra="forbid"`` on every request model is invariant I-1: the turn API has NO
history-accepting field, and a crafted payload attempting one fails closed-enum
validation with a 422. Tenant and subject come from the bound ``Actor`` only --
never from the body.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

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
    approval_request_id: str | None = None


class ConversationSummaryResponse(BaseModel):
    """One list row / the transcript header. Curated operational metadata."""

    model_config = ConfigDict(frozen=True)

    conversation_id: uuid.UUID
    agent_id: str
    state: ConversationState
    turn_count: int
    cumulative_tokens: int
    created_at: datetime
    last_turn_at: datetime | None


class ConversationListResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    items: list[ConversationSummaryResponse]
    next_cursor: str | None


class TranscriptTurnResponse(BaseModel):
    """Plaintext + operational metadata. ``user_message`` / ``answer`` are
    None AFTER erasure (the M8.5-F shape — the schema is nullable now, the
    pathway lands at F); digests live on the CHAIN response, not here."""

    model_config = ConfigDict(frozen=True)

    turn_id: uuid.UUID
    seq: int
    user_message: str | None
    answer: str | None
    agent_run_id: str
    prompt_tokens: int
    completion_tokens: int
    created_at: datetime
    erased_at: datetime | None
    approval_request_id: str | None = None
    turn_kind: Literal["exchange", "system"] = "exchange"


class TranscriptResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    conversation: ConversationSummaryResponse
    turns: list[TranscriptTurnResponse]
    watermark: int
    next_cursor: str | None


class TurnCompletedEvidenceResponse(BaseModel):
    """Hop 1 — the digest-only conversation.turn_completed projection.
    Curated per-key; never a raw payload, never a chain hash."""

    model_config = ConfigDict(frozen=True)

    sequence: int
    created_at: datetime
    turn_id: uuid.UUID
    seq: int
    agent_run_id: str
    actor_id: str
    question_sha256: str
    question_bytes: int
    answer_sha256: str
    answer_bytes: int
    prompt_tokens: int
    completion_tokens: int


class RunStartedEvidenceResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    sequence: int
    created_at: datetime
    run_id: str
    agent_id: str
    actor_id: str
    originator_subject: str
    question_sha256: str
    question_bytes: int
    max_steps: int
    token_budget: int
    wall_clock_s: float
    prior_context_turns: int
    prior_context_sha256: str


class RunTerminalEvidenceResponse(BaseModel):
    """``refusal_reason``/``bound`` present on refused runs, ``error_class``
    on failed runs — governed refusals stay visible to the evidence viewer."""

    model_config = ConfigDict(frozen=True)

    sequence: int
    created_at: datetime
    terminal_state: str
    answer_sha256: str
    answer_bytes: int
    steps_used: int
    prompt_tokens_total: int
    completion_tokens_total: int
    refusal_reason: str | None
    bound: str | None
    error_class: str | None


class DispatchEvidenceResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    sequence: int
    step_index: int
    capability_kind: str
    capability_ref: str
    scope_id: str | None
    outcome: str
    refusal_reason: str | None
    args_sha256: str | None
    result_sha256: str | None
    result_bytes: int | None


class TurnChainResponse(BaseModel):
    """The conversation -> agent_run -> dispatch join for ONE turn. The
    turn-2 dispatch count is UNCONSTRAINED semantics: an empty list means
    context reuse and is valid."""

    model_config = ConfigDict(frozen=True)

    turn_completed: TurnCompletedEvidenceResponse
    started: RunStartedEvidenceResponse
    terminal: RunTerminalEvidenceResponse
    dispatches: list[DispatchEvidenceResponse]
