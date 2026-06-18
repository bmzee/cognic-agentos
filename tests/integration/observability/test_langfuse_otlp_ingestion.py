"""Env-gated live proof: spans INGEST into a real Langfuse via the OTLP/HTTP exporter.

Opt in with COGNIC_RUN_LANGFUSE_OTEL=1 + COGNIC_LANGFUSE_HOST + the keys.
Fail-loud (NOT skip) when opted in but misconfigured — never a silent pass.
"""

from __future__ import annotations

import base64
import os
import time

import pytest

_OPT_IN = os.environ.get("COGNIC_RUN_LANGFUSE_OTEL") == "1"

pytestmark = pytest.mark.skipif(
    not _OPT_IN,
    reason="set COGNIC_RUN_LANGFUSE_OTEL=1 (+ COGNIC_LANGFUSE_HOST + keys) to run",
)


def test_span_ingests_into_langfuse_via_http_otlp() -> None:
    host = os.environ["COGNIC_LANGFUSE_HOST"].rstrip("/")
    public = os.environ["COGNIC_LANGFUSE_PUBLIC_KEY"]
    secret = os.environ["COGNIC_LANGFUSE_SECRET_KEY"]
    token = base64.b64encode(f"{public}:{secret}".encode()).decode()

    from langfuse import Langfuse

    from cognic_agentos.observability.otel import configure_tracing
    from tests.support.settings_fixtures import prod_settings

    # prod_settings(...) supplies the strict-profile-safe fields (G5 embedding,
    # digest-pinned sandbox images); a bare Settings(runtime_profile="prod")
    # fails validation on the dev embedding default.
    settings = prod_settings(
        otel_exporter_endpoint=f"{host}/api/public/otel/v1/traces",
        otel_exporter_protocol="http",
        otel_exporter_headers={
            "Authorization": f"Basic {token}",
            # Langfuse's recommended header for real-time OTLP ingestion
            # visibility (Langfuse OTel docs).
            "x-langfuse-ingestion-version": "4",
        },
    )
    provider = configure_tracing(settings)
    try:
        # Use the provider we just built (NOT trace.get_tracer, which returns a
        # tracer bound to the set-once process-global provider — if an earlier
        # test/app claimed the global slot, the span would emit through the OLD
        # provider while we force_flush this new Langfuse one).
        tracer = provider.get_tracer("cognic_agentos.test")
        with tracer.start_as_current_span("z1bc-otlp-proof") as span:
            trace_id = format(span.get_span_context().trace_id, "032x")
            span.set_attribute("test.marker", "z1bc")
        # force_flush returns True once export() runs — that alone does NOT prove
        # ingestion, so query Langfuse's public API for the trace below.
        assert provider.force_flush(timeout_millis=10_000) is True

        # Source-grounded read: the Langfuse Python SDK's documented
        # `api.observations.get_many(trace_id=...)` (Langfuse maps the OTLP
        # trace_id to its traceId). Bounded retry for ingestion lag; fail-loud.
        client = Langfuse(host=host, public_key=public, secret_key=secret)
        deadline_s, waited_s = 30.0, 0.0
        while True:
            observations = client.api.observations.get_many(trace_id=trace_id)
            if observations.data:
                break
            assert waited_s < deadline_s, (
                f"trace {trace_id} not ingested into Langfuse within {deadline_s:.0f}s"
            )
            time.sleep(2.0)
            waited_s += 2.0
    finally:
        provider.shutdown()
