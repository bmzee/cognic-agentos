"""Structured logging.

Layer classification: **observability**.

Every log line emitted from AgentOS source carries a ``request_id`` (bound
by :func:`bind_request_id` per request) and an OTel ``trace_id`` (read
from the active span when one exists). The ``json`` formatter is the
production default per the Sprint 1B Phase-1 principle "JSON logs from
request 1"; ``text`` is a developer convenience and is never used in
``stage`` / ``prod``.
"""

from __future__ import annotations

import logging
import sys
from contextvars import ContextVar
from typing import Any

from opentelemetry import trace
from pythonjsonlogger.json import JsonFormatter

from cognic_agentos.core.config import Settings

REQUEST_ID_CONTEXT: ContextVar[str | None] = ContextVar("cognic_request_id", default=None)
"""Holds the per-request UUID set by the request-id middleware."""


def bind_request_id(request_id: str) -> None:
    """Bind ``request_id`` for the current async context.

    The middleware in :mod:`cognic_agentos.observability.middleware` calls
    this on every inbound request after it generates or accepts the
    incoming ``X-Request-Id`` header.
    """

    REQUEST_ID_CONTEXT.set(request_id)


class _ContextFilter(logging.Filter):
    """Inject ``request_id`` + OTel ``trace_id`` into every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = REQUEST_ID_CONTEXT.get()
        span = trace.get_current_span()
        ctx = span.get_span_context() if span else None
        if ctx is not None and ctx.is_valid:
            record.trace_id = format(ctx.trace_id, "032x")
            record.span_id = format(ctx.span_id, "016x")
        else:
            record.trace_id = None
            record.span_id = None
        return True


def _build_json_formatter() -> logging.Formatter:
    # ``%(name)s`` is the logger name; the rest are spec-mandated fields the
    # SIEM pipeline keys off. ``request_id`` / ``trace_id`` come from the
    # context filter above.
    return JsonFormatter(
        "{asctime} {levelname} {name} {message} {request_id} {trace_id} {span_id}",
        style="{",
        rename_fields={"asctime": "ts", "levelname": "level", "name": "logger"},
    )


def _build_text_formatter() -> logging.Formatter:
    return logging.Formatter(
        fmt="{asctime} {levelname:5s} {name} req={request_id} trace={trace_id} | {message}",
        style="{",
    )


def configure_logging(settings: Settings) -> None:
    """Install the JSON (or text) formatter on the root logger.

    Idempotent — re-running replaces the AgentOS-installed handler so test
    fixtures can swap profile/format and immediately observe the change.
    """

    formatter: logging.Formatter
    if settings.log_format == "json":
        formatter = _build_json_formatter()
    else:
        formatter = _build_text_formatter()

    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(formatter)
    handler.addFilter(_ContextFilter())
    handler.set_name("cognic-agentos")

    root = logging.getLogger()
    # Replace any prior AgentOS handler (idempotency for tests / hot-reload).
    for existing in list(root.handlers):
        if existing.get_name() == "cognic-agentos":
            root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(settings.log_level.upper())


def get_logger(name: str) -> logging.Logger:
    """Return a logger; ensures every AgentOS module uses the configured stack."""

    return logging.getLogger(name)


# Re-export for typing convenience in tests.
LogRecord = logging.LogRecord
__all__ = [
    "REQUEST_ID_CONTEXT",
    "LogRecord",
    "bind_request_id",
    "configure_logging",
    "get_logger",
]


# Silence linter on unused private re-export — ``Any`` keeps mypy happy if a
# caller hands us a non-Settings duck-type in tests.
_: Any = None
