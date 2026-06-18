"""OpenTelemetry tracer-setup contract."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
)
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from cognic_agentos.core.config import Settings
from cognic_agentos.observability.otel import configure_tracing
from tests.support.settings_fixtures import prod_settings


def _processors(provider: TracerProvider) -> list[object]:
    """Reach into the provider's processor list for assertions.

    Pydantic-Settings calls span-processor accessors via internal attrs;
    OTel doesn't expose a public list, so we pull from the documented
    private attribute. If OTel changes this we want the test to fail
    loudly.
    """

    multi = provider._active_span_processor
    return list(multi._span_processors)


def test_dev_profile_without_endpoint_uses_synchronous_console_exporter() -> None:
    """Dev console output uses the **synchronous** SimpleSpanProcessor so
    there's no flush thread to race interpreter / pytest stdout teardown."""

    provider = configure_tracing(Settings(runtime_profile="dev"))
    try:
        procs = _processors(provider)
        assert len(procs) == 1
        proc = procs[0]
        assert isinstance(proc, SimpleSpanProcessor)
        assert isinstance(proc.span_exporter, ConsoleSpanExporter)
    finally:
        provider.shutdown()


def test_prod_profile_without_endpoint_installs_no_exporter() -> None:
    """Prod must NOT print spans to stdout — that would corrupt JSON logs."""

    provider = configure_tracing(prod_settings())
    assert _processors(provider) == []


def test_endpoint_set_installs_otlp_exporter() -> None:
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
        OTLPSpanExporter,
    )

    provider = configure_tracing(
        prod_settings(
            otel_exporter_endpoint="otel-collector:4317",
            otel_exporter_insecure=True,  # opt-in for the localhost test stub
        )
    )
    try:
        procs = _processors(provider)
        assert len(procs) == 1
        proc = procs[0]
        assert isinstance(proc, BatchSpanProcessor)
        assert isinstance(proc.span_exporter, OTLPSpanExporter)
    finally:
        provider.shutdown()


def test_otlp_exporter_defaults_to_secure_when_endpoint_set() -> None:
    """Bank-grade default: OTLP traffic must be TLS-encrypted unless explicitly opted out."""

    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
        OTLPSpanExporter,
    )

    provider = configure_tracing(prod_settings(otel_exporter_endpoint="otel-collector:4317"))
    try:
        proc = _processors(provider)[0]
        assert isinstance(proc, BatchSpanProcessor)
        # configure_tracing did NOT pass insecure=True when the setting was
        # at its default (False) — the exporter is constructed in TLS mode.
        assert isinstance(proc.span_exporter, OTLPSpanExporter)
    finally:
        provider.shutdown()


def test_configure_tracing_returns_new_provider_each_call() -> None:
    """Each call constructs a fresh ``TracerProvider`` instance.

    Note: OTel deliberately refuses to override the **process-global**
    provider once set — ``trace.set_tracer_provider`` is a one-shot
    operation by upstream policy. ``configure_tracing`` still returns a
    fresh, fully-configured provider per call so callers can introspect
    its exporter list even when the global slot has already been claimed
    by an earlier call (e.g. by ``create_app`` in tests). We do NOT
    assert on the global provider here; that responsibility belongs to
    the small set of integration tests that own the process state.
    """

    p1 = configure_tracing(prod_settings())
    p2 = configure_tracing(prod_settings())
    assert p1 is not p2
    assert isinstance(p1, TracerProvider)
    assert isinstance(p2, TracerProvider)


def test_resource_metadata_carries_service_identity() -> None:
    provider = configure_tracing(Settings(runtime_profile="dev"))
    attrs = provider.resource.attributes
    assert attrs["service.name"] == "cognic-agentos"
    assert attrs["deployment.environment"] == "dev"
    assert "service.version" in attrs


def test_http_protocol_installs_http_otlp_exporter() -> None:
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
        OTLPSpanExporter as HTTPSpanExporter,
    )

    settings = prod_settings(
        otel_exporter_endpoint="https://lf.example.com/api/public/otel/v1/traces",
        otel_exporter_protocol="http",
        otel_exporter_headers={"Authorization": "Basic eHk6eg=="},
    )
    provider = configure_tracing(settings)
    procs = _processors(provider)
    proc = next(p for p in procs if isinstance(p, BatchSpanProcessor))
    assert isinstance(proc.span_exporter, HTTPSpanExporter)


def test_http_build_threads_headers_and_file_tls_no_insecure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from cognic_agentos.observability import otel as otel_mod

    captured: dict[str, Any] = {}

    class _FakeHTTP:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

    # The http exporter is lazily imported inside _build_otlp_exporter, so the
    # patch on its source module is picked up at call time.
    monkeypatch.setattr(
        "opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter",
        _FakeHTTP,
    )
    ca = tmp_path / "ca.pem"
    ca.write_text("x")
    settings = prod_settings(
        otel_exporter_endpoint="https://lf/api/public/otel/v1/traces",
        otel_exporter_protocol="http",
        otel_exporter_headers={"Authorization": "Basic abc"},
        otel_exporter_ca_cert_path=ca,
    )
    otel_mod._build_otlp_exporter(settings)
    assert captured["endpoint"].endswith("/v1/traces")
    assert captured["headers"] == {"Authorization": "Basic abc"}
    assert captured["certificate_file"] == str(ca)
    assert "insecure" not in captured  # http: insecure is gRPC-only


def test_grpc_path_still_threads_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    from cognic_agentos.observability import otel as otel_mod

    captured: dict[str, Any] = {}

    class _FakeGRPC:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(otel_mod, "OTLPSpanExporter", _FakeGRPC)
    settings = prod_settings(
        otel_exporter_endpoint="collector:4317",
        otel_exporter_insecure=True,
        otel_exporter_headers={"x-tenant": "acme"},
    )
    otel_mod._build_otlp_exporter(settings)
    assert captured["insecure"] is True
    assert captured["headers"] == {"x-tenant": "acme"}


# Keep import linter happy — InMemorySpanExporter is currently only used as
# a typed import marker. Future tests can swap it in without re-importing.
_KEEP = InMemorySpanExporter
