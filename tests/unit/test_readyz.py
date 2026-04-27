"""Readiness-probe contract.

Sprint 1B reports only on internal readiness; Sprint 1C extends with
per-adapter components under the same nested shape so this test pins
the contract that 1C must extend rather than rewrite.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from cognic_agentos.core.config import Settings
from cognic_agentos.portal.api.app import create_app


def _client() -> TestClient:
    return TestClient(create_app(Settings(runtime_profile="prod")))


def test_readyz_returns_200_when_all_components_ok() -> None:
    response = _client().get("/api/v1/readyz")
    assert response.status_code == 200
    body = response.json()

    assert body["ready"] is True
    assert body["runtime_profile"] in {"dev", "stage", "prod"}
    assert isinstance(body["components"], dict)

    # Sprint 1B internal-only components: each is a dict with a "status" key.
    for name in ("settings", "logging", "tracing"):
        assert name in body["components"]
        assert body["components"][name]["status"] == "ok"


def test_readyz_shape_is_extensible_for_sprint_1c() -> None:
    """Lock the per-component **dict** shape so 1C can attach metadata
    (driver name, latency, last-error) without breaking consumers."""

    body = _client().get("/api/v1/readyz").json()
    assert set(body.keys()) == {"ready", "runtime_profile", "components"}
    for name, comp in body["components"].items():
        assert isinstance(comp, dict), f"component {name!r} must be a dict"
        assert "status" in comp, f"component {name!r} must carry a status key"


def test_readyz_returns_503_when_any_component_not_ok(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Inject a failure mode into the readiness components map."""

    from cognic_agentos.portal.api import app as app_module

    def _fake_components(_: object) -> dict[str, dict[str, object]]:
        return {
            "settings": {"status": "ok"},
            "logging": {"status": "FAIL", "reason": "handler missing"},
            "tracing": {"status": "ok"},
        }

    monkeypatch.setattr(app_module, "_readiness_components", _fake_components)

    response = _client().get("/api/v1/readyz")
    assert response.status_code == 503
    body = response.json()
    assert body["ready"] is False
    assert body["components"]["logging"]["status"] == "FAIL"
    assert body["components"]["logging"]["reason"] == "handler missing"


def test_readyz_component_metadata_passes_through(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Sprint 1C precedent: adapter components attach driver + latency."""

    from cognic_agentos.portal.api import app as app_module

    def _components_with_adapter_metadata(_: object) -> dict[str, dict[str, object]]:
        return {
            "settings": {"status": "ok"},
            "logging": {"status": "ok"},
            "tracing": {"status": "ok"},
            "db": {"driver": "postgres", "status": "ok", "latency_ms": 12},
        }

    monkeypatch.setattr(app_module, "_readiness_components", _components_with_adapter_metadata)

    body = _client().get("/api/v1/readyz").json()
    assert body["ready"] is True
    assert body["components"]["db"]["driver"] == "postgres"
    assert body["components"]["db"]["latency_ms"] == 12
