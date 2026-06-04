"""OpenAPI export contract."""

from __future__ import annotations

from fastapi.testclient import TestClient

from cognic_agentos.portal.api.app import create_app
from tests.support.settings_fixtures import prod_settings


def _client() -> TestClient:
    return TestClient(create_app(prod_settings()))


def test_openapi_endpoint_serves_valid_v3_schema() -> None:
    response = _client().get("/api/v1/openapi.json")
    assert response.status_code == 200
    spec = response.json()

    # OpenAPI 3.x — FastAPI ships 3.1.0 by default.
    assert spec["openapi"].startswith("3."), spec["openapi"]
    assert spec["info"]["title"] == "Cognic AgentOS"
    assert "version" in spec["info"]


def test_openapi_lists_sprint_1a_and_1b_probe_routes() -> None:
    spec = _client().get("/api/v1/openapi.json").json()
    paths = spec["paths"]
    assert "/api/v1/healthz" in paths
    assert "/api/v1/version" in paths
    assert "/api/v1/readyz" in paths


def test_openapi_excludes_metrics_endpoint() -> None:
    spec = _client().get("/api/v1/openapi.json").json()
    assert "/api/v1/metrics" not in spec["paths"]
