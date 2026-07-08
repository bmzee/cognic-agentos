"""M8 Task A13 (ADR-027) — the governed-agent ask portal surface.

``POST /api/v1/agents/{agent_id}/ask`` is the production caller that
LIVE-exercises :class:`~cognic_agentos.core.agent.loop.AgentLoop` (the A11
governed reasoning loop over the A10 dispatch chokepoint). Mounted
UNCONDITIONALLY; the request-time dep returns 503 until the lifespan
populates ``app.state.agent_loop``.
"""

from cognic_agentos.portal.api.agents.routes import build_agent_routes

__all__ = ["build_agent_routes"]
