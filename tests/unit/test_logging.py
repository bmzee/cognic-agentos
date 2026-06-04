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
from tests.support.settings_fixtures import prod_settings


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


# --- P0 closure: actual HTTP request emits a JSON access line with request_id + trace_id


def _capture_access_logs() -> tuple[io.StringIO, logging.Handler]:
    """Attach a buffer-backed handler to the access logger; return (buffer, handler).

    The handler carries its own copy of the JSON formatter AND its own
    instance of the context filter (filters do not propagate from the
    root logger to handlers attached lower in the hierarchy, so we must
    install one directly on the buffer handler).
    """

    from cognic_agentos.observability.logging import _ContextFilter
    from cognic_agentos.observability.middleware import ACCESS_LOGGER_NAME

    configure_logging(Settings(log_format="json"))
    buffer = io.StringIO()
    formatter = next(
        h for h in logging.getLogger().handlers if h.get_name() == "cognic-agentos"
    ).formatter
    handler = logging.StreamHandler(buffer)
    handler.setFormatter(formatter)
    handler.addFilter(_ContextFilter())
    access_logger = logging.getLogger(ACCESS_LOGGER_NAME)
    access_logger.addHandler(handler)
    access_logger.setLevel(logging.INFO)
    return buffer, handler


def test_actual_request_emits_json_access_line_with_request_id_and_trace_id() -> None:
    """End-to-end: send a request through the app; the access log line must be
    valid JSON, carry the request id from the response header, and carry an
    OTel trace id captured while the span was still active.

    This is the closure test for the Phase-1 principle "JSON logs from
    request 1" + the BUILD_PLAN.md exit criterion that "JSON log line
    during a request shows request_id + trace_id populated."
    """

    from fastapi.testclient import TestClient

    from cognic_agentos.observability.middleware import REQUEST_ID_HEADER
    from cognic_agentos.portal.api.app import create_app

    buffer, handler = _capture_access_logs()
    try:
        app = create_app(prod_settings(log_format="json"))
        client = TestClient(app)
        response = client.get("/api/v1/healthz")
        assert response.status_code == 200
        observed_request_id = response.headers[REQUEST_ID_HEADER]

        lines = [line for line in buffer.getvalue().splitlines() if line.strip()]
        assert lines, "no access log line emitted"
        access = json.loads(lines[-1])

        assert access["message"] == "http_request"
        assert access["http_method"] == "GET"
        assert access["http_path"] == "/api/v1/healthz"
        assert access["http_status_code"] == 200
        assert isinstance(access["duration_ms"], (int, float))
        assert access["request_id"] == observed_request_id
        # The trace_id must be populated — the access log emits inside the
        # OTel span, so the context filter sees a valid span context.
        assert access["trace_id"] is not None, (
            "trace_id MUST be populated in access log (span is alive at http.response.start)"
        )
        assert isinstance(access["trace_id"], str)
        assert len(access["trace_id"]) == 32, "trace id should be 32-hex chars"
        # Query-string-free request: signals must say so.
        assert access["http_has_query"] is False
        assert access["http_query_param_count"] == 0
    finally:
        from cognic_agentos.observability.middleware import ACCESS_LOGGER_NAME

        logging.getLogger(ACCESS_LOGGER_NAME).removeHandler(handler)


def test_access_log_never_records_query_string_values_or_names() -> None:
    """Bank-grade: query parameters can carry tokens, account numbers, PII,
    regulator IDs. The access log must NEVER log values or names — only
    the boolean ``http_has_query`` and the integer ``http_query_param_count``.

    Sends a request with deliberately sensitive-looking parameter names AND
    values; asserts none of them appear anywhere in the captured log line
    (full-string substring search across the serialized JSON).
    """

    from fastapi.testclient import TestClient

    from cognic_agentos.portal.api.app import create_app

    buffer, handler = _capture_access_logs()
    try:
        app = create_app(prod_settings(log_format="json"))
        client = TestClient(app)
        response = client.get(
            "/api/v1/healthz?token=BEARER-TOPSECRET-9999&account=PK36ABL0000123456789&ssn=000-00-1234"
        )
        assert response.status_code == 200

        lines = [line for line in buffer.getvalue().splitlines() if line.strip()]
        assert lines, "no access log line emitted"
        raw_line = lines[-1]
        access = json.loads(raw_line)

        # Signal-only fields populated correctly.
        assert access["http_has_query"] is True
        assert access["http_query_param_count"] == 3

        # The legacy http_query field MUST be gone.
        assert "http_query" not in access, (
            "http_query field leaks raw query string — must be removed in favour of "
            "http_has_query + http_query_param_count"
        )

        # And critically: no value or name from the query string may appear
        # anywhere in the serialized log line. This is the substring-style
        # check that catches accidental reintroduction via any future field.
        forbidden = (
            "BEARER-TOPSECRET-9999",
            "PK36ABL0000123456789",
            "000-00-1234",
            "token",
            "account",
            "ssn",
        )
        for needle in forbidden:
            assert needle not in raw_line, (
                f"sensitive query content {needle!r} leaked into access log: {raw_line!r}"
            )
    finally:
        from cognic_agentos.observability.middleware import ACCESS_LOGGER_NAME

        logging.getLogger(ACCESS_LOGGER_NAME).removeHandler(handler)


def test_uvicorn_access_logger_silenced_after_create_app() -> None:
    """create_app() must disable uvicorn.access so we don't double-log."""

    from cognic_agentos.portal.api.app import create_app

    create_app(prod_settings())
    uvicorn_access = logging.getLogger("uvicorn.access")
    assert uvicorn_access.disabled is True
    assert uvicorn_access.propagate is False
    assert uvicorn_access.handlers == []
