"""Readiness-probe contract.

Sprint 1B reports only on internal readiness; Sprint 1C extends with
adapter-component probes. This test pins the Sprint 1B contract.
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
    assert isinstance(body["components"], dict)
    assert body["components"]["settings_loaded"] == "ok"
    assert body["components"]["logging_configured"] == "ok"
    assert body["components"]["tracing_configured"] == "ok"
    assert body["components"]["runtime_profile"] in {"dev", "stage", "prod"}


def test_readyz_shape_is_stable() -> None:
    """Lock the response shape so Sprint 1C can extend without breakage."""

    body = _client().get("/api/v1/readyz").json()
    assert set(body.keys()) == {"ready", "components"}
    # ``runtime_profile`` is informational; ``ok``-keyed components carry
    # the boolean signal. Sprint 1C must add new ``ok`` keys, not replace
    # the existing ones.
    assert "settings_loaded" in body["components"]


def test_readyz_returns_503_when_any_component_not_ok(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Inject a failure mode into the readiness components map."""

    from cognic_agentos.portal.api import app as app_module

    def _fake_components(_: object) -> dict[str, str]:
        return {
            "settings_loaded": "ok",
            "logging_configured": "FAIL: handler missing",
            "tracing_configured": "ok",
            "runtime_profile": "prod",
        }

    monkeypatch.setattr(app_module, "_readiness_components", _fake_components)

    response = _client().get("/api/v1/readyz")
    assert response.status_code == 503
    body = response.json()
    assert body["ready"] is False
    assert body["components"]["logging_configured"].startswith("FAIL")
