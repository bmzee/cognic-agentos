"""Observability — structured logs, traces, metrics.

Layer classification: **observability**.

Per ``AGENTS.md`` "Code layers", observability is a peer of platform
primitives, persistence adapters, portal surfaces, and channel adapters —
not "core" and not a plugin. Sprint 1B ships logging + middleware +
OTel; Sprint 1B's portal extension wires Prometheus + the readyz probe.
Sprint 1C onward extends this layer with audit forwarding, SIEM hooks,
and chain-integrity walkers.
"""

from cognic_agentos.observability.logging import (
    REQUEST_ID_CONTEXT,
    bind_request_id,
    configure_logging,
)
from cognic_agentos.observability.middleware import (
    REQUEST_ID_HEADER,
    install_cors_middleware,
    install_otel_instrumentation,
    install_request_id_middleware,
)
from cognic_agentos.observability.otel import configure_tracing

__all__ = [
    "REQUEST_ID_CONTEXT",
    "REQUEST_ID_HEADER",
    "bind_request_id",
    "configure_logging",
    "configure_tracing",
    "install_cors_middleware",
    "install_otel_instrumentation",
    "install_request_id_middleware",
]
