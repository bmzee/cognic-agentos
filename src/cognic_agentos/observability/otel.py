"""OpenTelemetry tracer setup.

Layer classification: **observability**.

Sprint 1B exports traces via OTLP gRPC when ``otel_exporter_endpoint`` is
set. When unset:

- ``dev`` profile: console exporter so local development sees spans on
  stdout (alongside JSON logs).
- ``stage`` / ``prod`` profile: no exporter installed — traces are
  silently dropped rather than printed to stdout (which would corrupt
  the JSON log stream).
"""

from __future__ import annotations

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
)

from cognic_agentos import __version__
from cognic_agentos.core.config import Settings


def _build_processor(settings: Settings) -> SpanProcessor | None:
    if settings.otel_exporter_endpoint:
        return BatchSpanProcessor(
            OTLPSpanExporter(endpoint=settings.otel_exporter_endpoint, insecure=True)
        )
    if settings.runtime_profile == "dev":
        return BatchSpanProcessor(ConsoleSpanExporter())
    return None


def configure_tracing(settings: Settings) -> TracerProvider:
    """Install a process-wide :class:`TracerProvider`.

    Idempotent — repeated calls replace the global provider so tests can
    swap exporters without leaking BatchSpanProcessor threads.
    """

    resource = Resource.create(
        {
            "service.name": "cognic-agentos",
            "service.version": __version__,
            "deployment.environment": settings.runtime_profile,
        }
    )
    provider = TracerProvider(resource=resource)
    processor = _build_processor(settings)
    if processor is not None:
        provider.add_span_processor(processor)
    trace.set_tracer_provider(provider)
    return provider


__all__ = ["configure_tracing"]
