"""OpenTelemetry tracer-setup contract."""

from __future__ import annotations

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
)
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from cognic_agentos.core.config import Settings
from cognic_agentos.observability.otel import configure_tracing


def _processors(provider: TracerProvider) -> list[object]:
    """Reach into the provider's processor list for assertions.

    Pydantic-Settings calls span-processor accessors via internal attrs;
    OTel doesn't expose a public list, so we pull from the documented
    private attribute. If OTel changes this we want the test to fail
    loudly.
    """

    multi = provider._active_span_processor
    return list(multi._span_processors)


def test_dev_profile_without_endpoint_uses_console_exporter() -> None:
    provider = configure_tracing(Settings(runtime_profile="dev"))
    try:
        procs = _processors(provider)
        assert len(procs) == 1
        proc = procs[0]
        assert isinstance(proc, BatchSpanProcessor)
        assert isinstance(proc.span_exporter, ConsoleSpanExporter)
    finally:
        # Drain the BatchSpanProcessor before pytest closes stdout, otherwise
        # the background flush thread races teardown and prints a stack trace.
        provider.shutdown()


def test_prod_profile_without_endpoint_installs_no_exporter() -> None:
    """Prod must NOT print spans to stdout — that would corrupt JSON logs."""

    provider = configure_tracing(Settings(runtime_profile="prod"))
    assert _processors(provider) == []


def test_endpoint_set_installs_otlp_exporter() -> None:
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
        OTLPSpanExporter,
    )

    provider = configure_tracing(
        Settings(runtime_profile="prod", otel_exporter_endpoint="http://localhost:4317")
    )
    procs = _processors(provider)
    assert len(procs) == 1
    proc = procs[0]
    assert isinstance(proc, BatchSpanProcessor)
    assert isinstance(proc.span_exporter, OTLPSpanExporter)


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

    p1 = configure_tracing(Settings(runtime_profile="prod"))
    p2 = configure_tracing(Settings(runtime_profile="prod"))
    assert p1 is not p2
    assert isinstance(p1, TracerProvider)
    assert isinstance(p2, TracerProvider)


def test_resource_metadata_carries_service_identity() -> None:
    provider = configure_tracing(Settings(runtime_profile="dev"))
    attrs = provider.resource.attributes
    assert attrs["service.name"] == "cognic-agentos"
    assert attrs["deployment.environment"] == "dev"
    assert "service.version" in attrs


# Keep import linter happy — InMemorySpanExporter is currently only used as
# a typed import marker. Future tests can swap it in without re-importing.
_KEEP = InMemorySpanExporter
