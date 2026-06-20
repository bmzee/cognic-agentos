"""POST /api/v1/subagents — the portal-trigger surface for the live SubAgentSpawner (ADR-005)."""

from cognic_agentos.portal.api.subagents.routes import build_subagent_routes

__all__ = ["build_subagent_routes"]
