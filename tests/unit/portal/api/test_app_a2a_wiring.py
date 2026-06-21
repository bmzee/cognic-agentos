"""Sprint 4 (ADR-003) — A2A inbound route wiring.

The receiver mounts UNCONDITIONALLY at /api/v1/a2a/{target_agent}; the
request-time dep returns 503 a2a_endpoint_unavailable until the SDK-gated
lifespan populates app.state.a2a_endpoint. The default create_app() (no
adapter_registry) never constructs the endpoint, so the route 503s — proving
the mount is unconditional (a 404 would mean unmounted). Mirrors the Fork-B
mount test (test_app_subagent_route_mounted.py).
"""

from fastapi.testclient import TestClient

from cognic_agentos.portal.api.app import create_app


def test_a2a_route_mounted_and_503_without_endpoint() -> None:
    app = create_app()  # default: no a2a_endpoint wired (kernel-image / no-SDK path)
    # mounted unconditionally — the route exists in the table:
    paths = {route.path for route in app.routes}  # type: ignore[attr-defined]
    assert "/api/v1/a2a/{target_agent}" in paths
    # ... and 503s (NOT 404) because app.state.a2a_endpoint is unset:
    response = TestClient(app).post(
        "/api/v1/a2a/policy_qa",
        content=b"{}",
        headers={"X-Cognic-Tenant": "bank_a"},
    )
    assert response.status_code == 503
    # the route raises HTTPException(503, detail={"reason": ...}); the default
    # FastAPI handler nests the dict under "detail" (Sprint 3 carry-forward).
    assert response.json()["detail"]["reason"] == "a2a_endpoint_unavailable"
