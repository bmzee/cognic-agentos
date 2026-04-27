"""LangfuseOtelAdapter — OTel-bridged observability sink with a Langfuse health probe.

Driver name: ``langfuse_otel``. Auto-registers into ``bundled_registry`` on import.

**Sprint 1C scope (deliberately thin):**

- ``emit_trace`` creates an OpenTelemetry span with the supplied
  attributes. The Sprint 1B OTel pipeline (configured in
  ``cognic_agentos.observability.otel``) handles export.
- ``emit_metric`` is logged at debug level — full metric pipeline ships
  in Sprint 2 alongside ``core/audit``.
- ``flush`` posts an empty ingestion batch to Langfuse as a liveness
  ping; non-raising.
- ``health_check`` does an HTTP GET against ``/api/public/health`` so
  the /readyz roll-up surfaces Langfuse outages.

**Out of scope (Sprint 2/3 work):** real Langfuse SDK trace lifecycle —
parent-child generation records linked to agent invocations, prompt /
response capture, custom scorers, ``workflow_trace_id`` propagation. Those
require ``core/decision_history`` and the LLM gateway, which Sprint 1C
does not ship. This adapter therefore satisfies the ObservabilityAdapter
**contract** without claiming a full Langfuse trace integration.

Per BUILD_PLAN Sprint 1C exit criterion: stopping the Langfuse container
makes /readyz return 503 with ``observability: {driver: langfuse_otel,
status: unreachable}``. ``health_check()`` returns ``unreachable`` on
host outage so the /readyz roll-up collapses to 503 exactly as spec'd.
(The ``observability`` key matches the ``Adapters`` dataclass field name
+ ``AdapterKind`` literal used throughout the codebase.)

emit/flush remain non-raising — losing individual traces is acceptable
runtime behaviour; a sustained outage surfaces via the next /readyz probe,
not via exceptions in the request path.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx
from opentelemetry import trace

from cognic_agentos.db.adapters.protocols import AdapterHealth
from cognic_agentos.db.adapters.registry import bundled_registry

logger = logging.getLogger(__name__)


class LangfuseOtelAdapter:
    driver = "langfuse_otel"

    def __init__(
        self,
        host: str | None,
        public_key: str | None,
        secret_key: str | None,
    ) -> None:
        if not host:
            raise ValueError("LangfuseOtelAdapter requires langfuse_host; got empty/None")
        self._host = host.rstrip("/")
        self._public_key = public_key
        self._secret_key = secret_key
        self._tracer = trace.get_tracer("cognic_agentos.observability")

    async def emit_trace(self, name: str, attributes: dict[str, Any]) -> None:
        # OTel trace emit is in-process and never raises on Langfuse outage.
        with self._tracer.start_as_current_span(name) as span:
            for k, v in attributes.items():
                # OTel span attributes accept str | bool | int | float | sequence;
                # coerce anything else to str so we never crash the request path.
                if isinstance(v, str | bool | int | float):
                    span.set_attribute(k, v)
                else:
                    span.set_attribute(k, str(v))

    async def emit_metric(self, name: str, value: float, attributes: dict[str, Any]) -> None:
        # Sprint 1C ships metric emission as a debug-log fallback;
        # full metric pipeline lands in Sprint 2 alongside core/audit.
        logger.debug("metric %s=%s %s", name, value, attributes)

    async def flush(self) -> None:
        # Best-effort liveness ping. Exceptions are swallowed and logged
        # so observability outages never propagate as runtime errors.
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                await client.post(
                    f"{self._host}/api/public/ingestion",
                    json={"batch": []},
                    auth=httpx.BasicAuth(self._public_key or "", self._secret_key or ""),
                )
        except Exception as exc:
            logger.warning("langfuse flush failed: %s", exc)

    async def health_check(self) -> AdapterHealth:
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(f"{self._host}/api/public/health")
                resp.raise_for_status()
        except Exception as exc:
            return AdapterHealth(
                status="unreachable",
                driver=self.driver,
                detail=type(exc).__name__,
            )
        return AdapterHealth(
            status="ok",
            driver=self.driver,
            latency_ms=(time.perf_counter() - start) * 1000.0,
        )


bundled_registry.register("observability", "langfuse_otel", LangfuseOtelAdapter)
