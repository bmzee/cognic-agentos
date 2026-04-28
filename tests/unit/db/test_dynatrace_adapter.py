"""DynatraceAdapter — OTel-bridged trace emission + Dynatrace Metric
Ingest API for native custom metrics + HTTP health probe."""

from __future__ import annotations

import respx
from httpx import ConnectError, Response

from cognic_agentos.db.adapters import bundled_registry
from cognic_agentos.db.adapters import protocols as P
from cognic_agentos.db.adapters.dynatrace_adapter import DynatraceAdapter

TENANT = "https://abc12345.live.dynatrace.com"
TOKEN = "dt0c01.test-token"
HEALTH_PATH = "/api/v2/metrics/query"


class TestRegistration:
    def test_dynatrace_registered_under_bundled(self) -> None:
        assert bundled_registry.has("observability", "dynatrace")
        assert bundled_registry.resolve("observability", "dynatrace") is DynatraceAdapter


class TestConstruction:
    def test_constructor_refuses_empty_tenant_url(self) -> None:
        import pytest

        with pytest.raises(ValueError, match="dynatrace_tenant_url"):
            DynatraceAdapter(None, api_token=TOKEN)
        with pytest.raises(ValueError, match="dynatrace_tenant_url"):
            DynatraceAdapter("", api_token=TOKEN)

    def test_constructor_refuses_empty_token(self) -> None:
        import pytest

        with pytest.raises(ValueError, match="dynatrace_api_token"):
            DynatraceAdapter(TENANT, api_token=None)
        with pytest.raises(ValueError, match="dynatrace_api_token"):
            DynatraceAdapter(TENANT, api_token="")


class TestHealth:
    @respx.mock
    async def test_health_ok(self) -> None:
        respx.get(f"{TENANT}{HEALTH_PATH}").mock(
            return_value=Response(200, json={"totalCount": 1, "result": []})
        )
        a = DynatraceAdapter(TENANT, api_token=TOKEN)
        h = await a.health_check()
        assert h.status == "ok"
        assert h.driver == "dynatrace"
        assert h.latency_ms is not None

    @respx.mock
    async def test_health_unreachable_on_connect_error(self) -> None:
        respx.get(f"{TENANT}{HEALTH_PATH}").mock(side_effect=ConnectError("nope"))
        a = DynatraceAdapter(TENANT, api_token=TOKEN)
        h = await a.health_check()
        assert h.status == "unreachable"

    @respx.mock
    async def test_health_unreachable_on_401(self) -> None:
        """Bad / expired API token → 401; surface as unreachable so
        operators see the auth failure in /readyz."""

        respx.get(f"{TENANT}{HEALTH_PATH}").mock(return_value=Response(401))
        a = DynatraceAdapter(TENANT, api_token=TOKEN)
        h = await a.health_check()
        assert h.status == "unreachable"

    @respx.mock
    async def test_health_sends_api_token_header(self) -> None:
        """Dynatrace API expects ``Authorization: Api-Token <value>`` —
        not ``Bearer``. Verify the adapter sends the right shape."""

        route = respx.get(f"{TENANT}{HEALTH_PATH}").mock(
            return_value=Response(200, json={"result": []})
        )
        a = DynatraceAdapter(TENANT, api_token=TOKEN)
        await a.health_check()
        assert route.called
        sent = route.calls.last.request
        assert sent.headers["authorization"] == f"Api-Token {TOKEN}"


class TestEmissions:
    async def test_emit_trace_no_raise(self) -> None:
        """Trace emission rides Sprint 1B's OTel pipeline (configured via
        OTEL_EXPORTER_OTLP_ENDPOINT to point at Dynatrace's OTLP ingest).
        The adapter creates spans; OTel exports."""

        a = DynatraceAdapter(TENANT, api_token=TOKEN)
        await a.emit_trace("test_span", {"k": 1, "k2": "v"})

    @respx.mock
    async def test_emit_metric_posts_line_protocol(self) -> None:
        """Dynatrace Metric Ingest line-protocol shape:
        ``<metric.name>,<dim1>=<v1>,<dim2>=<v2> <value> <ts_ms>``.
        ``ts`` is optional (server uses ingest time)."""

        route = respx.post(f"{TENANT}/api/v2/metrics/ingest").mock(return_value=Response(202))
        a = DynatraceAdapter(TENANT, api_token=TOKEN)
        await a.emit_metric("agentos.test.gauge", 42.0, {"adapter": "dynatrace"})

        assert route.called
        sent = route.calls.last.request
        body = sent.content.decode("utf-8")
        # Line protocol: metric.name + dimensions + value. Values are
        # always quoted + escaped per Dynatrace line-protocol spec so
        # spaces / commas in caller-provided data can't break parsing.
        assert body.startswith("agentos.test.gauge")
        assert 'adapter="dynatrace"' in body
        assert " 42.0" in body or " 42" in body
        # Header: text/plain for line protocol, NOT application/json
        assert sent.headers["content-type"] == "text/plain"
        assert sent.headers["authorization"] == f"Api-Token {TOKEN}"

    @respx.mock
    async def test_emit_metric_no_raise_on_outage(self) -> None:
        """Observability outages must NOT raise into the request path;
        same rule as LangfuseOtelAdapter.flush()."""

        respx.post(f"{TENANT}/api/v2/metrics/ingest").mock(side_effect=ConnectError("nope"))
        a = DynatraceAdapter(TENANT, api_token=TOKEN)
        # Must not raise
        await a.emit_metric("agentos.test.gauge", 1.0, {})

    @respx.mock
    async def test_emit_metric_quotes_dimension_values_with_specials(self) -> None:
        """Dynatrace line protocol uses commas to separate dimensions and
        spaces to separate dimensions from value. A raw dimension value
        containing space/comma/quote would corrupt the line. The adapter
        must quote+escape values so the line stays well-formed."""

        route = respx.post(f"{TENANT}/api/v2/metrics/ingest").mock(return_value=Response(202))
        a = DynatraceAdapter(TENANT, api_token=TOKEN)
        await a.emit_metric(
            "agentos.test.gauge",
            42.0,
            {"adapter": 'with space, and "quote"'},
        )
        assert route.called
        body = route.calls.last.request.content.decode("utf-8")
        # Value must be quoted; embedded quote must be backslash-escaped;
        # the unescaped trailing space-then-value segment must still parse
        # cleanly as the value column.
        assert 'adapter="with space, and \\"quote\\""' in body
        assert body.endswith(" 42.0")

    @respx.mock
    async def test_emit_metric_quotes_dimension_values_with_backslash(self) -> None:
        """Backslashes inside quoted Dynatrace dimension values must be
        escaped (\\\\) so the parser doesn't treat the next char as the
        escape body."""

        route = respx.post(f"{TENANT}/api/v2/metrics/ingest").mock(return_value=Response(202))
        a = DynatraceAdapter(TENANT, api_token=TOKEN)
        await a.emit_metric("agentos.test.gauge", 1.0, {"path": r"C:\Windows\System32"})
        body = route.calls.last.request.content.decode("utf-8")
        assert r'path="C:\\Windows\\System32"' in body

    @respx.mock
    async def test_emit_metric_skips_invalid_dimension_keys(self) -> None:
        """Dimension keys must match Dynatrace's grammar
        (``[a-z][a-z0-9._-]*``). Invalid keys (uppercase, spaces, special
        chars, leading digit, empty) must be silently dropped so the line
        stays well-formed; the metric still emits with the valid
        dimensions only."""

        route = respx.post(f"{TENANT}/api/v2/metrics/ingest").mock(return_value=Response(202))
        a = DynatraceAdapter(TENANT, api_token=TOKEN)
        await a.emit_metric(
            "agentos.test.gauge",
            1.0,
            {
                "good.key": "v1",
                "BadKey": "v2",  # uppercase rejected
                "1leading_digit": "v3",  # leading digit rejected
                "with space": "v4",  # space rejected
                "with,comma": "v5",  # comma rejected
                "": "v6",  # empty rejected
            },
        )
        body = route.calls.last.request.content.decode("utf-8")
        assert "good.key=" in body
        # All invalid keys must be dropped entirely from the line
        for bad in ("BadKey", "1leading_digit", "with space", "with,comma"):
            assert bad not in body

    @respx.mock
    async def test_emit_metric_replaces_newlines_in_value(self) -> None:
        """Dynatrace lines are newline-separated; an unescaped newline in
        a dimension value would terminate the metric line and let the
        rest of the value be parsed as a new line. Replace with space so
        the line stays single-row regardless of provenance."""

        route = respx.post(f"{TENANT}/api/v2/metrics/ingest").mock(return_value=Response(202))
        a = DynatraceAdapter(TENANT, api_token=TOKEN)
        await a.emit_metric("agentos.test.gauge", 1.0, {"msg": "line1\nline2\rline3"})
        body = route.calls.last.request.content.decode("utf-8")
        assert "\n" not in body[: body.rindex(" ")]  # no newlines before value column
        assert "\r" not in body
        assert 'msg="line1 line2 line3"' in body

    @respx.mock
    async def test_emit_metric_logs_and_swallows_non_2xx(self, caplog: object) -> None:
        """A token with metrics.read but missing metrics.ingest causes
        /api/v2/metrics/ingest to return 403. Without raise_for_status()
        /readyz would pass while ingest silently fails — the most
        operator-hostile failure mode for observability. Adapter must
        log and swallow."""

        import logging

        import pytest

        respx.post(f"{TENANT}/api/v2/metrics/ingest").mock(return_value=Response(403))
        a = DynatraceAdapter(TENANT, api_token=TOKEN)
        cl = caplog
        # caplog is a pytest LogCaptureFixture; the param type is widened
        # to ``object`` so the test signature stays self-contained, and
        # an isinstance assertion narrows it for the rest of the body.
        assert isinstance(cl, pytest.LogCaptureFixture)
        with cl.at_level(logging.WARNING, logger="cognic_agentos.db.adapters.dynatrace_adapter"):
            await a.emit_metric("agentos.test.gauge", 1.0, {"adapter": "dynatrace"})

        # Non-2xx must surface as a warning so operators can debug a
        # silently-failing ingest path; must NOT raise.
        warnings = [r for r in cl.records if r.levelno >= logging.WARNING]
        assert any(
            "403" in r.getMessage() or "metric emit failed" in r.getMessage() for r in warnings
        ), [r.getMessage() for r in warnings]

    @respx.mock
    async def test_flush_no_raise(self) -> None:
        """flush is a non-raising best-effort liveness ping."""

        respx.get(f"{TENANT}{HEALTH_PATH}").mock(side_effect=ConnectError("nope"))
        a = DynatraceAdapter(TENANT, api_token=TOKEN)
        await a.flush()


class TestSatisfiesProtocol:
    def test_protocol_conformance(self) -> None:
        a = DynatraceAdapter(TENANT, api_token=TOKEN)
        assert isinstance(a, P.ObservabilityAdapter)
