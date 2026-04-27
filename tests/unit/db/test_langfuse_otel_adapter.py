"""LangfuseOtelAdapter — graceful degrade on host down + flush idempotent."""

from __future__ import annotations

import respx
from httpx import ConnectError, Response

from cognic_agentos.db.adapters import bundled_registry
from cognic_agentos.db.adapters import protocols as P
from cognic_agentos.db.adapters.langfuse_otel_adapter import LangfuseOtelAdapter

HOST = "http://langfuse.test:3000"


class TestRegistration:
    def test_langfuse_otel_registered_under_bundled(self) -> None:
        assert bundled_registry.has("observability", "langfuse_otel")
        assert bundled_registry.resolve("observability", "langfuse_otel") is LangfuseOtelAdapter


class TestConstruction:
    def test_constructor_refuses_empty_host(self) -> None:
        import pytest

        with pytest.raises(ValueError, match="langfuse_host"):
            LangfuseOtelAdapter(None, public_key="pk", secret_key="sk")
        with pytest.raises(ValueError, match="langfuse_host"):
            LangfuseOtelAdapter("", public_key="pk", secret_key="sk")


class TestHealth:
    @respx.mock
    async def test_health_ok_when_langfuse_reachable(self) -> None:
        respx.get(f"{HOST}/api/public/health").mock(
            return_value=Response(200, json={"status": "OK"})
        )
        a = LangfuseOtelAdapter(HOST, public_key="pk", secret_key="sk")
        h = await a.health_check()
        assert h.status == "ok"
        assert h.driver == "langfuse_otel"
        assert h.latency_ms is not None

    @respx.mock
    async def test_health_unreachable_when_host_down(self) -> None:
        """Per BUILD_PLAN Sprint 1C exit criterion: stopping the Langfuse
        container makes /readyz return 503 with ``obs: {driver:
        langfuse_otel, status: unreachable}``. Restart → /readyz flips
        back to 200.

        ``health_check()`` therefore returns ``unreachable`` (not
        ``degraded``) on host outage so the /readyz roll-up collapses
        to 503 as specified."""

        respx.get(f"{HOST}/api/public/health").mock(side_effect=ConnectError("nope"))
        a = LangfuseOtelAdapter(HOST, public_key="pk", secret_key="sk")
        h = await a.health_check()
        assert h.status == "unreachable"

    @respx.mock
    async def test_health_unreachable_on_5xx(self) -> None:
        respx.get(f"{HOST}/api/public/health").mock(return_value=Response(500))
        a = LangfuseOtelAdapter(HOST, public_key="pk", secret_key="sk")
        h = await a.health_check()
        assert h.status == "unreachable"


class TestEmissions:
    async def test_emit_trace_no_raise(self) -> None:
        # OTel span emission is in-process — no HTTP required.
        a = LangfuseOtelAdapter(HOST, public_key="pk", secret_key="sk")
        await a.emit_trace("test_span", {"k": 1, "k2": "v"})

    async def test_emit_metric_no_raise(self) -> None:
        a = LangfuseOtelAdapter(HOST, public_key="pk", secret_key="sk")
        await a.emit_metric("metric_x", 3.14, {"label": "y"})

    @respx.mock
    async def test_flush_swallows_outage(self) -> None:
        # Even if the host is down, flush must not raise — observability
        # outages must not propagate as runtime errors.
        respx.post(f"{HOST}/api/public/ingestion").mock(side_effect=ConnectError("nope"))
        a = LangfuseOtelAdapter(HOST, public_key="pk", secret_key="sk")
        await a.flush()  # idempotent + non-raising


class TestSatisfiesProtocol:
    def test_protocol_conformance(self) -> None:
        a = LangfuseOtelAdapter(HOST, public_key="pk", secret_key="sk")
        assert isinstance(a, P.ObservabilityAdapter)
