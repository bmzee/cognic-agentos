"""M6 Task A6 (ADR-025) — POST /api/v1/skills/{skill_id}/invoke request/response
DTOs."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

from cognic_agentos.core.skill._types import SkillInvokeTerminalState


class SkillInvokeRequest(BaseModel):
    """Body for POST /api/v1/skills/{skill_id}/invoke. ``skill_id`` is the path
    param; tenant + actor come ONLY from the bound Actor (extra='forbid' rejects
    a tenant/actor field). ``arguments`` is the deterministic kwargs dict the
    runner passes to the skill action's ``execute(**arguments)``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    arguments: dict[str, Any] = {}


class SkillInvokeResponse(BaseModel):
    """One body shape across all outcomes; the HTTP status varies. ``result`` is
    the runner's fixed-shape result dict on ``completed``; ``None`` otherwise.
    ``refusal_reason`` carries the surfaced reason on ``refused`` / ``failed``
    (a broker passthrough like ``skill_tool_not_declared``, a pre-flight
    ``skill_not_found`` / ``skill_not_registered``, or ``skill_runtime_error``)."""

    model_config = ConfigDict(frozen=True)

    skill_id: str
    terminal_state: SkillInvokeTerminalState
    result: dict[str, Any] | None
    refusal_reason: str | None
