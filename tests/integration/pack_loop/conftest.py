# tests/integration/pack_loop/conftest.py
"""Session-scoped managed servers for the Proof 1a pack-loop tests.

The pack server (127.0.0.1:8765) and local AS (127.0.0.1:9000) bind FIXED ports
(the manifest pins server_url), so they must start ONCE per session with real
teardown — not a daemon thread per test (which collides + leaks)."""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator

import pytest
import uvicorn
from starlette.types import ASGIApp

_AS_ISSUER = "http://127.0.0.1:9000"


def _wait_port(host: str, port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as s:
            s.settimeout(0.25)
            if s.connect_ex((host, port)) == 0:
                return
        time.sleep(0.1)
    raise TimeoutError(f"never came up on {host}:{port}")


def _serve(app: ASGIApp, host: str, port: int) -> tuple[uvicorn.Server, threading.Thread]:
    server = uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    _wait_port(host, port)
    return server, thread


@pytest.fixture(scope="session")
def local_as() -> Iterator[str]:
    # _local_as.py lands in Task 5; resolve it dynamically so this Task-4
    # conftest type-checks under strict mypy. A static `from ..._local_as
    # import build_app` errors import-not-found while the module is absent, and
    # a `# type: ignore[import-not-found]` would become an unused-ignore error
    # (warn_unused_ignores) the moment Task 5 creates the file.
    import importlib

    build_app = importlib.import_module("tests.integration.pack_loop._local_as").build_app

    server, thread = _serve(build_app(), "127.0.0.1", 9000)
    try:
        yield _AS_ISSUER
    finally:
        server.should_exit = True
        thread.join(timeout=5)


@pytest.fixture(scope="session")
def pack_server() -> Iterator[str]:
    # NOTE: independent of `local_as` — the PRM document only ADVERTISES the AS
    # issuer (a string); the server does not call the AS to serve PRM. So Task 4
    # (PRM shape) needs only `pack_server`; Task 5/7 (token acquisition) request
    # BOTH `pack_server` and `local_as`. Keeping pack_server decoupled means it
    # does not import _local_as.py (created later, in Task 5).
    from cognic_tool_search.server import build_server

    mcp = build_server(as_issuer=_AS_ISSUER)
    # FastMCP.streamable_http_app() returns the Starlette ASGI app (serves /mcp + auto-PRM).
    server, thread = _serve(mcp.streamable_http_app(), "127.0.0.1", 8765)
    try:
        yield "http://127.0.0.1:8765/mcp"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
