"""Structured-logging contract."""

from __future__ import annotations

import io
import json
import logging
from collections.abc import Iterator
from contextlib import contextmanager

from cognic_agentos.core.config import Settings
from cognic_agentos.observability.logging import (
    REQUEST_ID_CONTEXT,
    bind_request_id,
    configure_logging,
)


@contextmanager
def _capture_log_stream() -> Iterator[io.StringIO]:
    """Replace the AgentOS-installed handler's stream with an in-memory buffer."""

    # Install the AgentOS handler first so we know where it lives.
    configure_logging(Settings(log_format="json", log_level="INFO"))
    root = logging.getLogger()
    handler = next(h for h in root.handlers if h.get_name() == "cognic-agentos")
    buffer = io.StringIO()
    original_stream = handler.stream  # type: ignore[attr-defined]
    handler.stream = buffer  # type: ignore[attr-defined]
    try:
        yield buffer
    finally:
        handler.stream = original_stream  # type: ignore[attr-defined]


def test_json_log_carries_request_id_when_bound() -> None:
    with _capture_log_stream() as buffer:
        bind_request_id("abc123")
        logging.getLogger("cognic_agentos.test").info("hello")
    record = json.loads(buffer.getvalue().strip().splitlines()[-1])
    assert record["request_id"] == "abc123"
    assert record["message"] == "hello"
    assert record["level"] == "INFO"


def test_json_log_request_id_is_null_when_unbound() -> None:
    REQUEST_ID_CONTEXT.set(None)
    with _capture_log_stream() as buffer:
        logging.getLogger("cognic_agentos.test").info("anonymous")
    record = json.loads(buffer.getvalue().strip().splitlines()[-1])
    assert record["request_id"] is None


def test_text_format_does_not_emit_json() -> None:
    configure_logging(Settings(log_format="text", log_level="INFO"))
    root = logging.getLogger()
    handler = next(h for h in root.handlers if h.get_name() == "cognic-agentos")
    buffer = io.StringIO()
    original = handler.stream  # type: ignore[attr-defined]
    handler.stream = buffer  # type: ignore[attr-defined]
    try:
        logging.getLogger("cognic_agentos.test").info("plain")
    finally:
        handler.stream = original  # type: ignore[attr-defined]
    line = buffer.getvalue().strip().splitlines()[-1]
    assert not line.startswith("{"), f"text format must not emit JSON, got: {line!r}"
    assert "plain" in line


def test_configure_logging_is_idempotent() -> None:
    """Reinstalling the handler must NOT stack duplicates on the root logger."""

    settings = Settings(log_format="json")
    configure_logging(settings)
    configure_logging(settings)
    configure_logging(settings)
    handlers = [h for h in logging.getLogger().handlers if h.get_name() == "cognic-agentos"]
    assert len(handlers) == 1
