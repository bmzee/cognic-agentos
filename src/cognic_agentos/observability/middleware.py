"""HTTP middleware: request-id, CORS allow-list, OTel instrumentation.

Layer classification: **observability**.
"""

from __future__ import annotations

import uuid

from fastapi import FastAPI, Request, Response
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from starlette.middleware.cors import CORSMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from cognic_agentos.core.config import Settings
from cognic_agentos.observability.logging import bind_request_id

REQUEST_ID_HEADER = "X-Request-Id"
"""Inbound + outbound header name. Mixed-case to match common conventions."""

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
    "REQUEST_ID_HEADER",
    "RequestIdMiddleware",
    "install_cors_middleware",
    "install_otel_instrumentation",
    "install_request_id_middleware",
]


# Suppress unused-import lint on Request/Response — re-exported for typing
# convenience in tests that compose middlewares directly.
_RE_EXPORT_FOR_TESTS = (Request, Response)
