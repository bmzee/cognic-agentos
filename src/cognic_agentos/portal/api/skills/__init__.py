"""M6 Task A6 (ADR-025) — the governed skill-invocation portal surface.

``POST /api/v1/skills/{skill_id}/invoke`` is the deterministic caller that
LIVE-exercises :class:`~cognic_agentos.core.skill.executor.SkillExecutor` (the
LLM agent that reads ``SKILL.md`` and DECIDES to invoke is M8). Mounted
UNCONDITIONALLY; the request-time dep returns 503 until the SDK-gated lifespan
populates ``app.state.skill_executor``.
"""

from cognic_agentos.portal.api.skills.routes import build_skill_routes

__all__ = ["build_skill_routes"]
