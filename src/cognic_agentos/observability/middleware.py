"""HTTP middleware: request-id, structured access log, CORS allow-list, OTel instrumentation.

Layer classification: **observability**.
"""

from __future__ import annotations

import logging
import time
import uuid

from fastapi import FastAPI, Request, Response
from opentelemetry import trace
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from starlette.middleware.cors import CORSMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from cognic_agentos.core.config import Settings
from cognic_agentos.observability.logging import bind_request_id

REQUEST_ID_HEADER = "X-Request-Id"
"""Inbound + outbound header name. Mixed-case to match common conventions."""

ACCESS_LOGGER_NAME = "cognic_agentos.access"
"""Dedicated logger so operators can route access logs separately if needed."""

# Maximum length of a caller-supplied request id we'll trust verbatim.
# Anything longer or that fails the UUID parse is replaced with a fresh
# UUID4 so an attacker cannot poison logs with arbitrary content.
_REQUEST_ID_MAX_LEN = 128


def _normalise_request_id(raw: str | None) -> str:
    if raw is None:
        return uuid.uuid4().hex
    candidate = raw.strip()
    if not candidate or len(candidate) > _REQUEST_ID_MAX_LEN:
        return uuid.uuid4().hex
    # Best-effort: accept caller-supplied UUIDs; otherwise replace.
    try:
        return uuid.UUID(candidate).hex
    except ValueError:
        return uuid.uuid4().hex


class RequestIdMiddleware:
    """Generate or accept ``X-Request-Id`` and bind it to log context.

    Pure ASGI middleware (not the deprecated ``BaseHTTPMiddleware``) so
    OTel and Prometheus instrumentation see the request id on every span
    + metric label without an extra hop.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        raw_headers: list[tuple[bytes, bytes]] = list(scope.get("headers", []))
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in raw_headers}
        request_id = _normalise_request_id(headers.get(REQUEST_ID_HEADER.lower()))
        bind_request_id(request_id)

        async def send_with_header(message: Message) -> None:
            if message["type"] == "http.response.start":
                response_headers: list[tuple[bytes, bytes]] = list(message.get("headers", []))
                response_headers.append(
                    (REQUEST_ID_HEADER.encode("latin-1"), request_id.encode("latin-1"))
                )
                message["headers"] = response_headers
            await send(message)

        await self.app(scope, receive, send_with_header)


def install_request_id_middleware(app: FastAPI) -> None:
    app.add_middleware(RequestIdMiddleware)


class StructuredAccessLogMiddleware:
    """Emit one JSON access-log line per HTTP request.

    Critical timing: the log line is emitted **inside** the
    ``http.response.start`` ASGI callback, while the OTel span is still
    active. The ``_ContextFilter`` in :mod:`cognic_agentos.observability.logging`
    therefore captures the correct ``trace_id`` / ``span_id`` automatically.

    This middleware replaces uvicorn's default plain-text access log
    (which fires after the response is sent and after the OTel span has
    closed, so it never sees a trace id). The portal app silences
    ``uvicorn.access`` propagation; this middleware is the canonical
    source of HTTP request log lines.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self._logger = logging.getLogger(ACCESS_LOGGER_NAME)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start = time.perf_counter()
        method = str(scope.get("method", "?"))
        path = str(scope.get("path", "?"))
        query_bytes = scope.get("query_string", b"")
        if isinstance(query_bytes, bytes | bytearray):
            query_string = query_bytes.decode("latin-1")
        else:
            query_string = ""
        client = scope.get("client")
        client_addr = client[0] if isinstance(client, list | tuple) and client else "?"
        access_logger = self._logger
        emitted = False

        async def send_wrapper(message: Message) -> None:
            nonlocal emitted
            if message["type"] == "http.response.start" and not emitted:
                emitted = True
                duration_ms = (time.perf_counter() - start) * 1000.0
                access_logger.info(
                    "http_request",
                    extra={
                        "http_method": method,
                        "http_path": path,
                        "http_query": query_string,
                        "http_status_code": int(message.get("status", 0)),
                        "duration_ms": round(duration_ms, 3),
                        "client_addr": client_addr,
                    },
                )
            await send(message)

        await self.app(scope, receive, send_wrapper)


def install_access_log_middleware(app: FastAPI) -> None:
    app.add_middleware(StructuredAccessLogMiddleware)


def silence_uvicorn_access_log() -> None:
    """Suppress uvicorn's built-in plain-text access log.

    AgentOS uses :class:`StructuredAccessLogMiddleware` for the canonical
    JSON access line. Leaving uvicorn's default access logger live would
    duplicate every request line in plain text and corrupt the JSON log
    pipeline.
    """

    uvicorn_access = logging.getLogger("uvicorn.access")
    uvicorn_access.handlers = []
    uvicorn_access.propagate = False
    uvicorn_access.disabled = True


def _capture_trace_context() -> tuple[str | None, str | None]:
    """Return ``(trace_id_hex, span_id_hex)`` for the active OTel span.

    Returned only for tests that want to assert the span context that
    will be observed by the access-log filter at log emission time.
    """

    span = trace.get_current_span()
    if span is None:
        return None, None
    ctx = span.get_span_context()
    if not ctx.is_valid:
        return None, None
    return format(ctx.trace_id, "032x"), format(ctx.span_id, "016x")


def install_cors_middleware(app: FastAPI, settings: Settings) -> None:
    """Mount the CORS middleware with the configured allow-list.

    The allow-list cannot contain ``*`` — that constraint is enforced by
    the field validator on ``Settings.cors_allowed_origins``, so reaching
    this point means the list is already safe.
    """

    if not settings.cors_allowed_origins:
        return  # nothing to allow → no CORS middleware (default-deny)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=[REQUEST_ID_HEADER, "Authorization", "Content-Type"],
    )


def install_otel_instrumentation(app: FastAPI) -> None:
    """Enable OTel auto-instrumentation for FastAPI routes."""

    FastAPIInstrumentor.instrument_app(app)


__all__ = [
    "ACCESS_LOGGER_NAME",
    "REQUEST_ID_HEADER",
    "RequestIdMiddleware",
    "StructuredAccessLogMiddleware",
    "install_access_log_middleware",
    "install_cors_middleware",
    "install_otel_instrumentation",
    "install_request_id_middleware",
    "silence_uvicorn_access_log",
]


# Suppress unused-import lint on Request/Response — re-exported for typing
# convenience in tests that compose middlewares directly.
_RE_EXPORT_FOR_TESTS = (Request, Response)
