"""Build-metadata endpoint contract."""

from __future__ import annotations

from fastapi.testclient import TestClient

from cognic_agentos import __version__
from cognic_agentos.core.config import Settings
from cognic_agentos.portal.api.app import create_app


def test_version_endpoint_shape() -> None:
    settings = Settings(build_sha="abc123", build_time="2026-04-27T07:00:00+00:00")
    response = TestClient(create_app(settings)).get("/api/v1/version")
    assert response.status_code == 200
    body = response.json()

    assert body["version"] == __version__
    assert body["build_sha"] == "abc123"
    assert body["build_time"] == "2026-04-27T07:00:00+00:00"
    assert body["runtime_profile"] in {"dev", "stage", "prod"}
    assert body["python_version"].startswith("3.12.")
    assert "platform" in body
    assert set(body.keys()) == {
        "version",
        "build_sha",
        "build_time",
        "python_version",
        "platform",
        "runtime_profile",
    }
