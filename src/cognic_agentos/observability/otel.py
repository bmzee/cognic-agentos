"""OpenTelemetry tracer setup.

Layer classification: **observability**.

Sprint 1B exports traces via OTLP gRPC when ``otel_exporter_endpoint`` is
set. When unset:

- ``dev`` profile: console exporter so local development sees spans on
  stdout (alongside JSON logs).
- ``stage`` / ``prod`` profile: no exporter installed — traces are
  silently dropped rather than printed to stdout (which would corrupt
  the JSON log stream).

OTel global behaviour: ``trace.set_tracer_provider`` is **set-once** per
process by upstream policy. The first call wins the global slot; later
calls log an "Overriding of current TracerProvider is not allowed"
warning and the global stays the original. ``configure_tracing`` still
constructs a fresh, fully-configured provider on every call so callers
can introspect its exporter list and lifecycle, but the global is
immutable after the first call.

Every constructed provider is registered with ``atexit`` so its
``BatchSpanProcessor`` flush thread shuts down cleanly before the
interpreter tears down stdout — this prevents the "I/O operation on
closed file" noise we saw when the flush thread tried to write spans
after pytest closed its captured stdout.
"""

from __future__ import annotations

import atexit
import contextlib
import weakref

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
    SpanExporter,
)

from cognic_agentos import __version__
from cognic_agentos.core.config import Settings

# Track every provider we've constructed so atexit can shut them down
# without holding strong references that would defeat GC.
_LIVE_PROVIDERS: weakref.WeakSet[TracerProvider] = weakref.WeakSet()


def _shutdown_all() -> None:
    for provider in list(_LIVE_PROVIDERS):
        # Best-effort shutdown at exit: any exception here is meaningless
        # because the interpreter is tearing down anyway.
        with contextlib.suppress(Exception):
            provider.shutdown()


atexit.register(_shutdown_all)


def _build_otlp_exporter(settings: Settings) -> SpanExporter:
    """Construct an OTLP exporter for the configured protocol + TLS posture.

    grpc (default): the gRPC exporter with endpoint / insecure / mTLS-credentials.
    http: the OTLP/HTTP exporter with endpoint + file-based TLS (for backends
    like Langfuse that need HTTP + auth headers). Headers thread into both.
    Defaults to **secure** (TLS) on grpc; http security is the endpoint URL scheme.
    """

    headers = dict(settings.otel_exporter_headers) or None

    if settings.otel_exporter_protocol == "http":
        # Lazy import — same opentelemetry-exporter-otlp umbrella as the gRPC
        # exporter; kept off the module's hot import path.
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter as HTTPSpanExporter,
        )

        http_kwargs: dict[str, object] = {"endpoint": settings.otel_exporter_endpoint}
        if headers is not None:
            http_kwargs["headers"] = headers
        # The mTLS triple maps to the http exporter's file-path kwargs; insecure
        # is gRPC-only (http security is the endpoint URL scheme).
        if settings.otel_exporter_ca_cert_path:
            http_kwargs["certificate_file"] = str(settings.otel_exporter_ca_cert_path)
        if settings.otel_exporter_client_cert_path:
            http_kwargs["client_certificate_file"] = str(settings.otel_exporter_client_cert_path)
        if settings.otel_exporter_client_key_path:
            http_kwargs["client_key_file"] = str(settings.otel_exporter_client_key_path)
        return HTTPSpanExporter(**http_kwargs)  # type: ignore[arg-type]

    # grpc (default) — the existing path, now also threading headers.
    kwargs: dict[str, object] = {
        "endpoint": settings.otel_exporter_endpoint,
        "insecure": settings.otel_exporter_insecure,
    }
    if headers is not None:
        kwargs["headers"] = headers
    if settings.otel_exporter_ca_cert_path:
        ca_bytes = settings.otel_exporter_ca_cert_path.read_bytes()
        client_cert = (
            settings.otel_exporter_client_cert_path.read_bytes()
            if settings.otel_exporter_client_cert_path
            else None
        )
        client_key = (
            settings.otel_exporter_client_key_path.read_bytes()
            if settings.otel_exporter_client_key_path
            else None
        )
        import grpc  # type: ignore[import-untyped]

        kwargs["credentials"] = grpc.ssl_channel_credentials(
            root_certificates=ca_bytes,
            private_key=client_key,
            certificate_chain=client_cert,
        )
    return OTLPSpanExporter(**kwargs)  # type: ignore[arg-type]


def _build_processor(settings: Settings) -> SpanProcessor | None:
    if settings.otel_exporter_endpoint:
        # OTLP traffic uses BatchSpanProcessor for throughput in prod; the
        # background flush thread is shut down via the ``atexit`` hook
        # registered above.
        return BatchSpanProcessor(_build_otlp_exporter(settings))
    if settings.runtime_profile == "dev":
        # Synchronous processor for the dev console exporter — no flush
        # thread to race interpreter / pytest teardown of stdout.
        return SimpleSpanProcessor(ConsoleSpanExporter())
    return None


def configure_tracing(settings: Settings) -> TracerProvider:
    """Construct + register a :class:`TracerProvider`.

    Returns a fully-configured provider on every call. The **first** call
    wins the OTel process-global slot; subsequent calls return a new
    provider for inspection but do NOT replace the global (OTel refuses).
    Every constructed provider is shut down via ``atexit``.
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
    _LIVE_PROVIDERS.add(provider)
    trace.set_tracer_provider(provider)
    return provider


__all__ = ["configure_tracing"]
