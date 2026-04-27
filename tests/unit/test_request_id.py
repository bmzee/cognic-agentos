"""Request-ID middleware contract."""

from __future__ import annotations

import re

from fastapi.testclient import TestClient

from cognic_agentos.core.config import Settings
from cognic_agentos.observability.middleware import REQUEST_ID_HEADER
from cognic_agentos.portal.api.app import create_app

_HEX32 = re.compile(r"^[0-9a-f]{32}$")


def _client() -> TestClient:
    return TestClient(create_app(Settings(runtime_profile="prod")))


def test_request_id_generated_when_absent() -> None:
    response = _client().get("/api/v1/healthz")
    assert response.status_code == 200
    rid = response.headers.get(REQUEST_ID_HEADER)
    assert rid is not None
    assert _HEX32.match(rid), f"generated id should be 32-hex UUID, got {rid!r}"


def test_request_id_echoed_when_supplied_as_uuid() -> None:
    incoming = "12345678-1234-5678-1234-567812345678"
    response = _client().get("/api/v1/healthz", headers={REQUEST_ID_HEADER: incoming})
    assert response.status_code == 200
    # Echo is UUID hex (no hyphens) — guarantees the value was parsed.
    assert response.headers[REQUEST_ID_HEADER] == "12345678123456781234567812345678"


def test_request_id_replaces_non_uuid_input() -> None:
    """A non-UUID caller value must NOT poison logs; replace with fresh UUID."""

    response = _client().get(
        "/api/v1/healthz", headers={REQUEST_ID_HEADER: "not-a-uuid; DROP TABLE users;--"}
    )
    rid = response.headers[REQUEST_ID_HEADER]
    assert _HEX32.match(rid)
    assert "DROP" not in rid


def test_request_id_replaces_overlong_input() -> None:
    response = _client().get("/api/v1/healthz", headers={REQUEST_ID_HEADER: "x" * 4096})
    rid = response.headers[REQUEST_ID_HEADER]
    assert _HEX32.match(rid)
