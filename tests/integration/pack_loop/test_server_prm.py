# tests/integration/pack_loop/test_server_prm.py
"""Proof 1a Task 4 — the pack's FastMCP server serves /mcp and auto-publishes PRM.

Uses the session-scoped, managed `pack_server` fixture (conftest.py) — NOT a
per-test daemon thread — so the fixed port 8765 is bound once and torn down at
session end (no port/lifecycle flakes when the pack-loop tests run as a group).
"""

import importlib.util

import httpx
import pytest

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("cognic_tool_search") is None
    or importlib.util.find_spec("mcp") is None,
    reason="cognic-tool-search and the mcp SDK must be installed",
)


def test_server_publishes_prm_with_authorization_server(pack_server: str) -> None:
    # pack_server has started the FastMCP server + waited for port 8765.
    # PRM is auto-served at the RFC 9728 well-known path for resource path /mcp.
    resp = httpx.get("http://127.0.0.1:8765/.well-known/oauth-protected-resource/mcp", timeout=5)
    assert resp.status_code == 200
    body = resp.json()
    # The SDK builds PRM `authorization_servers` from AuthSettings.issuer_url, an
    # `AnyHttpUrl`. pydantic normalizes a host-only URL to its canonical RFC-3986
    # form WITH a trailing slash, so the real served value is
    # "http://127.0.0.1:9000/" (not the slash-less form). What MUST hold is that
    # PRM advertises the Proof 1a local authorization server, which it does.
    assert body["authorization_servers"] == ["http://127.0.0.1:9000/"]

    # The /mcp endpoint requires auth (401 with no bearer) — the runtime PRM probe relies on this.
    unauth = httpx.get("http://127.0.0.1:8765/mcp", timeout=5)
    assert unauth.status_code == 401
