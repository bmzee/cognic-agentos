"""DynatraceAdapter — OTel-bridged observability sink + Dynatrace Metric
Ingest API for native custom metrics + HTTP health probe.

Driver name: ``dynatrace``. Auto-registers into ``bundled_registry`` on import.

**Sprint 1D scope:**

- ``emit_trace`` creates an in-process OpenTelemetry span. Trace export
  to Dynatrace's OTLP ingest is configured at the OTel-pipeline level
  (Sprint 1B ``observability/otel.py`` reads
  ``COGNIC_OTEL_EXPORTER_ENDPOINT``); the adapter does not duplicate
  that wiring.
- ``emit_metric`` POSTs Dynatrace Metric Ingest line protocol to
  ``/api/v2/metrics/ingest``. Non-raising on outage so observability
  failures never propagate into the request path.
- ``flush`` is a non-raising best-effort liveness ping.
- ``health_check`` GETs ``/api/v2/metrics/query?metricSelector=builtin:host.cpu.usage&pageSize=1``
  with the ``Authorization: Api-Token <value>`` header Dynatrace expects
  (note: ``Api-Token``, not ``Bearer``). The metrics-query endpoint
  validates BOTH connectivity AND token scope — a 200 proves the token
  has the ``metrics.read`` scope and the tenant URL is reachable; a 401
  proves the token is bad; any non-200 → ``unreachable``.

**Required Dynatrace API token scopes** (operator must grant when
provisioning the token in the Dynatrace UI):
  - ``metrics.read`` — for the ``health_check`` probe
  - ``metrics.ingest`` — for ``emit_metric`` POST to ``/api/v2/metrics/ingest``
  - (no ``traces.write`` needed — trace export rides the Sprint 1B OTel
    pipeline configured separately via ``OTEL_EXPORTER_OTLP_ENDPOINT``)

Per BUILD_PLAN Sprint 1D exit criterion: ``COGNIC_OBS_DRIVER=dynatrace``
+ API token resolved by operator (env or secret-mount in Sprint 1D;
native runtime Vault resolution lands in Sprint 10) → ``/readyz`` shows
``observability: {driver: dynatrace, status: ok}``.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

import httpx
from opentelemetry import trace

from cognic_agentos.db.adapters.protocols import AdapterHealth
from cognic_agentos.db.adapters.registry import bundled_registry

logger = logging.getLogger(__name__)

# Token-validating + reachability-validating health probe. Requires the
# metrics.read scope on the API token. Returns 200 with empty/short
# results when the token is valid; 401 when bad; non-200 otherwise.
_HEALTH_PATH = "/api/v2/metrics/query?metricSelector=builtin:host.cpu.usage&pageSize=1"

# Dynatrace metric line-protocol dimension key grammar:
#   - Lowercase letters / digits / dot / hyphen / underscore
#   - Must start with a lowercase letter
#   - Up to 100 chars
# Anything outside this is silently dropped so a stray attribute key
# doesn't corrupt the line — observability outages must not propagate
# into the request path.
_DIM_KEY_RE = re.compile(r"^[a-z][a-z0-9._\-]{0,99}$")


def _sanitize_dim_value(v: Any) -> str:
    """Quote + escape a dimension value for Dynatrace line protocol.

    The line-protocol parser uses commas to separate dimensions and a
    single space to separate the dimension block from the metric value.
    Any of those characters in a raw dimension value would corrupt the
    line. Newlines would terminate the line entirely and let the rest
    parse as a new metric line — same severity.

    Strategy: always quote, always backslash-escape the quote and the
    backslash, replace any newlines/carriage-returns with a single
    space (line protocol forbids them inside quoted values too).
    """

    s = str(v)
    s = s.replace("\\", "\\\\")  # backslash first; downstream escapes layer over this
    s = s.replace('"', '\\"')
    s = s.replace("\n", " ").replace("\r", " ")
    return f'"{s}"'


class DynatraceAdapter:
    driver = "dynatrace"

    def __init__(self, tenant_url: str | None, api_token: str | None) -> None:
        if not tenant_url:
            raise ValueError("DynatraceAdapter requires dynatrace_tenant_url; got empty/None")
        if not api_token:
            raise ValueError("DynatraceAdapter requires dynatrace_api_token; got empty/None")
        self._tenant = tenant_url.rstrip("/")
        self._token = api_token
        self._tracer = trace.get_tracer("cognic_agentos.observability.dynatrace")

    def _headers(self, content_type: str = "application/json") -> dict[str, str]:
        return {
            "Authorization": f"Api-Token {self._token}",
            "Content-Type": content_type,
        }

    async def emit_trace(self, name: str, attributes: dict[str, Any]) -> None:
        # OTel trace emit is in-process and never raises on Dynatrace outage.
        with self._tracer.start_as_current_span(name) as span:
            for k, v in attributes.items():
                if isinstance(v, str | bool | int | float):
                    span.set_attribute(k, v)
                else:
                    span.set_attribute(k, str(v))

    async def emit_metric(self, name: str, value: float, attributes: dict[str, Any]) -> None:
        # Dynatrace Metric Ingest line protocol:
        #   <metric.name>,<dim1>=<v1>,<dim2>=<v2> <value>
        # Keys must match the Dynatrace dimension-key grammar; anything
        # outside it is silently dropped so a stray attribute can't
        # corrupt the line. Values are always quoted + escaped so that
        # spaces / commas / quotes / newlines from caller-controlled
        # data can't break the line-protocol structure.
        dim_parts = [
            f"{k}={_sanitize_dim_value(v)}"
            for k, v in attributes.items()
            if isinstance(k, str) and _DIM_KEY_RE.match(k)
        ]
        dim_block = "," + ",".join(dim_parts) if dim_parts else ""
        line = f"{name}{dim_block} {value}"

        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.post(
                    f"{self._tenant}/api/v2/metrics/ingest",
                    headers=self._headers(content_type="text/plain"),
                    content=line.encode("utf-8"),
                )
                # raise_for_status() inside the try-block: a token with
                # metrics.read (so /readyz passes) but missing
                # metrics.ingest will return 403 here. Without this,
                # /readyz reports observability=ok while every metric
                # write is silently dropped — the most operator-hostile
                # observability failure mode. Logging via the warning
                # path keeps the contract that observability outages
                # never propagate into the request path.
                resp.raise_for_status()
        except Exception as exc:
            # Observability outages must NOT raise into the request path.
            logger.warning("dynatrace metric emit failed: %s", exc)

    async def flush(self) -> None:
        # Best-effort liveness ping. Same non-raising contract as
        # LangfuseOtelAdapter.flush() — observability outages never
        # propagate as runtime errors.
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                await client.get(
                    f"{self._tenant}{_HEALTH_PATH}",
                    headers=self._headers(),
                )
        except Exception as exc:
            logger.warning("dynatrace flush ping failed: %s", exc)

    async def health_check(self) -> AdapterHealth:
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(
                    f"{self._tenant}{_HEALTH_PATH}",
                    headers=self._headers(),
                )
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


bundled_registry.register("observability", "dynatrace", DynatraceAdapter)
