"""M8 Task A13 (ADR-027) — POST /api/v1/agents/{agent_id}/ask request/response
DTOs."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from cognic_agentos.core.agent._types import AgentDispatchRefusalReason, AgentRunTerminalState


class AgentAskRequest(BaseModel):
    """Body for POST /api/v1/agents/{agent_id}/ask. ``agent_id`` is the path
    param; tenant + originator come ONLY from the bound Actor (extra='forbid'
    rejects a tenant/actor field). ``question`` is the single-shot user
    question the governed loop answers — bounded so an oversized body is
    refused at the wire, before any run is minted."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    question: str = Field(min_length=1, max_length=4096)


class AgentAskResponse(BaseModel):
    """One body shape across all outcomes; the HTTP status varies (completed →
    200; refused → 200 — a governed refusal IS a governed answer; failed →
    502). ``answer`` is the ONLY surface carrying the plaintext (the
    ``agent.run.*`` chain rows are digest-only per ADR-027 §f);
    ``refusal_reason`` carries the closed-enum reason on ``refused``."""

    model_config = ConfigDict(frozen=True)

    run_id: str
    terminal_state: AgentRunTerminalState
    answer: str
    steps_used: int
    refusal_reason: AgentDispatchRefusalReason | None
