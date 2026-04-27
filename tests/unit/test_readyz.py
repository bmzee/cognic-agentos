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


# ---------------------------------------------------------------------------
# Sprint 1C — /readyz with adapter integration
# ---------------------------------------------------------------------------


class TestReadyzWithAdapters:
    """Lifespan-attached adapters surface in /readyz under per-kind keys.

    Uses the conftest ``memory_registry`` + ``memory_settings`` fixtures so
    the test does not require a live Postgres / Qdrant / Vault / Ollama /
    Langfuse process.
    """

    def test_readyz_reports_per_adapter(self, memory_registry, memory_settings) -> None:  # type: ignore[no-untyped-def]
        from cognic_agentos.portal.api.app import create_app

        app = create_app(memory_settings, adapter_registry=memory_registry)
        with TestClient(app) as client:
            resp = client.get("/api/v1/readyz")

        assert resp.status_code == 200
        body = resp.json()
        assert body["ready"] is True
        comps = body["components"]
        for name in ("relational", "vector", "secret", "embedding", "observability"):
            assert comps[name]["driver"] == "memory"
            assert comps[name]["status"] == "ok"

    def test_readyz_503_when_adapter_unreachable(  # type: ignore[no-untyped-def]
        self, memory_registry, memory_settings, monkeypatch
    ) -> None:
        """Force one adapter's health_check to report unreachable; the
        roll-up must collapse to 503 and the bad component must be
        labelled in the response."""

        from cognic_agentos.db.adapters.protocols import AdapterHealth
        from cognic_agentos.portal.api.app import create_app

        app = create_app(memory_settings, adapter_registry=memory_registry)
        with TestClient(app) as client:
            adapters = app.state.adapters
            assert adapters is not None

            async def fake_health() -> AdapterHealth:
                return AdapterHealth(status="unreachable", driver="memory", detail="forced")

            monkeypatch.setattr(adapters.relational, "health_check", fake_health)
            resp = client.get("/api/v1/readyz")

        assert resp.status_code == 503
        body = resp.json()
        assert body["ready"] is False
        assert body["components"]["relational"]["status"] == "unreachable"
        assert body["components"]["relational"]["detail"] == "forced"

    def test_readyz_without_adapter_registry_keeps_sprint_1b_shape(  # type: ignore[no-untyped-def]
        self, memory_settings
    ) -> None:
        """Backward-compat: when adapter_registry is omitted, /readyz still
        reports only the internal Sprint 1B triplet (no adapter keys)."""

        from cognic_agentos.portal.api.app import create_app

        app = create_app(memory_settings)  # no adapter_registry
        with TestClient(app) as client:
            resp = client.get("/api/v1/readyz")

        assert resp.status_code == 200
        body = resp.json()
        assert set(body["components"].keys()) == {"settings", "logging", "tracing"}
