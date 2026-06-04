"""Prometheus scrape endpoint contract."""

from __future__ import annotations

from fastapi.testclient import TestClient

from cognic_agentos.portal.api.app import create_app
from tests.support.settings_fixtures import prod_settings


def _client() -> TestClient:
    return TestClient(create_app(prod_settings()))


def test_metrics_endpoint_returns_prometheus_format() -> None:
    client = _client()
    # Prime one labeled request so http_requests_total emits a sample.
    client.get("/api/v1/healthz")
    response = client.get("/api/v1/metrics")

    assert response.status_code == 200
    content_type = response.headers.get("content-type", "")
    assert content_type.startswith("text/plain"), (
        f"Prometheus expects text/plain; got {content_type!r}"
    )
    body = response.text
    assert "# HELP" in body
    assert "# TYPE" in body
    # The instrumentator emits a histogram of HTTP request durations.
    assert "http_request_duration_seconds" in body or "http_requests_total" in body


def test_metrics_endpoint_excluded_from_openapi() -> None:
    response = _client().get("/api/v1/openapi.json")
    assert response.status_code == 200
    paths = response.json()["paths"]
    # /metrics should not pollute the OpenAPI surface (include_in_schema=False).
    assert "/api/v1/metrics" not in paths
