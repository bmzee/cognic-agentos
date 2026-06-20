"""The subagent route mounts UNCONDITIONALLY at /api/v1/subagents (ADR-005)."""

from cognic_agentos.portal.api.app import create_app


def test_subagent_route_is_registered() -> None:
    app = create_app()
    paths = {route.path for route in app.routes}  # type: ignore[attr-defined]
    assert "/api/v1/subagents" in paths
