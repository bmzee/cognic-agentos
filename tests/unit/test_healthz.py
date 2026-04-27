"""Liveness probe contract."""

from __future__ import annotations

from fastapi.testclient import TestClient

from cognic_agentos import __version__
from cognic_agentos.core.config import Settings
from cognic_agentos.portal.api.app import create_app


def _client() -> TestClient:
    return TestClient(create_app(Settings()))


def test_healthz_returns_alive_payload() -> None:
    response = _client().get("/api/v1/healthz")
    assert response.status_code == 200
    body = response.json()
    assert body == {"alive": True, "version": __version__}


def test_healthz_does_not_check_dependencies() -> None:
    """``/healthz`` is liveness only — readiness lives at ``/readyz`` (Sprint 1B/1C).

    The endpoint must be a pure function of the running process; if it
    grows dependency probes the test fails so the regression is loud.
    """

    response = _client().get("/api/v1/healthz")
    assert response.status_code == 200
    assert set(response.json().keys()) == {"alive", "version"}
