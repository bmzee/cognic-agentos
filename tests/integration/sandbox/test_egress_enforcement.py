"""T13 — egress-proxy ENFORCEMENT live proof (the empirical denied-CONNECT test).

The T1-T6 shim + T5a log-mapper prove the proxy *records* outcomes; THIS proof
shows tinyproxy actually *enforces* the per-session allow-list against real
traffic, and that the AgentOS backend parser (``_parse_proxy_log_jsonl``) reads
the resulting ``ProxyAccessRecord`` JSONL. The headline (spec §8 G6) is that a
**denied HTTPS CONNECT is BLOCKED live** — empirical, not inferred.

**Hermetic — no public deps.** A throwaway Docker network carries an upstream
echo (HTTP :80 + a plain TCP :443 listener) under the alias ``allowed.test`` (in
the allow-list) and the proxy container with ``ALLOW_LIST=["allowed.test"]``.
``denied.test`` is NOT served — tinyproxy filters it *before* connecting, so it
needs no upstream. The host is the client (via the published proxy port); the
proxy resolves the ``*.test`` aliases on its own network, the host does not.

**Why a plain TCP :443 listener (not a TLS-terminating echo):** per the T1
spike, tinyproxy logs the CONNECT *tunnel establishment* at TCP-connect time,
BEFORE any TLS handshake — so the ``allowed`` + ``method=CONNECT``
``ProxyAccessRecord`` is produced as soon as the tunnel opens. A full TLS echo
would only add a response-body assertion that the access-record already covers
for *enforcement*. The curl TLS handshake then fails against the plain listener
(irrelevant — we assert the access record, not curl's exit).

**Env-gated** on ``COGNIC_RUN_EGRESS_ENFORCEMENT_PROOF=1``. Default ``pytest``
skips the module. When opted in, the fixture **fails LOUD** (``AssertionError``,
not skip) if docker is missing or the proxy image cannot be built/started.
"""

from __future__ import annotations

import os
import socket
import subprocess
import time
from collections.abc import Iterator
from typing import Any

import pytest

# Env-gate FIRST, BEFORE any optional-extra import (Sprint-10.1 Finding #3
# contract): env unset → skip by design via allow_module_level; env SET → the
# plain import below so a missing extra FAILS LOUD, never importorskip's silent
# skip. importorskip("aiodocker") would wrongly skip an opted-in run on a host
# missing the extra.
if os.environ.get("COGNIC_RUN_EGRESS_ENFORCEMENT_PROOF") != "1":
    pytest.skip(
        "egress-proxy enforcement live proof; opt in via "
        "COGNIC_RUN_EGRESS_ENFORCEMENT_PROOF=1 (requires docker)",
        allow_module_level=True,
    )

# Opted in: ``_parse_proxy_log_jsonl`` lives in docker_sibling, which imports
# aiodocker at module load. A missing sandbox-docker extra here is a broken
# opted-in environment → fail LOUD (AssertionError), not a silent skip.
try:
    from cognic_agentos.sandbox.backends.docker_sibling import _parse_proxy_log_jsonl
except ImportError as exc:  # pragma: no cover - opted-in-but-missing-extra path
    raise AssertionError(
        "COGNIC_RUN_EGRESS_ENFORCEMENT_PROOF=1 but importing _parse_proxy_log_jsonl "
        "from sandbox.backends.docker_sibling failed (the sandbox-docker extra / "
        "aiodocker is unavailable) — failing loud rather than skipping."
    ) from exc

_PROXY_IMAGE = "cognic/sandbox-egress-proxy:dev"
_NET = "t30-egress-enforcement-net"
_UPSTREAM = "t30-egress-upstream"
_PROXY = "t30-egress-proxy"
_HOST_PORT = 13131
_SESSION_ID = "egress-proof-sess"

# Upstream echo: HTTP :80 (returns "echo-ok") + a plain TCP :443 listener (the
# CONNECT tunnel target). stdlib-only; runs as root (--user 0) to bind the
# privileged ports. The TCP :443 listener just accepts + drains + closes — it is
# the CONNECT tunnel endpoint, not a TLS server (see module docstring).
_ECHO_SCRIPT = r"""
import http.server, socket, threading
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"echo-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        return
def _http80():
    http.server.HTTPServer(("0.0.0.0", 80), H).serve_forever()
def _tcp443():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 443))
    s.listen(16)
    while True:
        conn, _ = s.accept()
        threading.Thread(
            target=lambda c: (c.recv(4096), c.close()), args=(conn,), daemon=True
        ).start()
threading.Thread(target=_http80, daemon=True).start()
_tcp443()
"""


def _run(args: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(args, check=True, capture_output=True, **kw)


def _curl(host_port: int, url: str, *, extra: list[str] | None = None) -> str:
    """Send ``url`` through the proxy at ``localhost:host_port``; return the HTTP
    code as a string ("000" on a transport failure — expected for the CONNECT
    cases where the plain :443 listener fails the TLS handshake AFTER the tunnel
    is established + logged)."""
    cmd = [
        "curl",
        "-s",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "-m",
        "10",
        "-x",
        f"http://localhost:{host_port}",
        *(extra or []),
        url,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.stdout.strip() or "000"


def _wait_tcp(port: int, *, timeout_s: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("localhost", port), timeout=1.0).close()
            return True
        except OSError:
            time.sleep(0.25)
    return False


def _access_records(proxy_name: str) -> tuple[Any, ...]:
    """docker exec cat the proxy's access.jsonl + parse via the REAL backend
    wire parser (the oracle the production backend uses)."""
    out = subprocess.run(
        ["docker", "exec", proxy_name, "cat", "/var/log/cognic-proxy/access.jsonl"],
        capture_output=True,
        text=True,
    )
    return _parse_proxy_log_jsonl(out.stdout)


@pytest.fixture(scope="module")
def egress_stack() -> Iterator[dict[str, Any]]:
    docker = subprocess.run(["docker", "version"], capture_output=True)
    assert docker.returncode == 0, (
        "docker daemon not reachable; opt-in COGNIC_RUN_EGRESS_ENFORCEMENT_PROOF=1 "
        "implies docker is available — failing loud rather than skipping."
    )
    # Build the proxy image (self-contained — does not depend on a prior T7 run).
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    _proxy_ctx = os.path.join(repo_root, "infra/sandbox/egress-proxy")
    _run(["docker", "build", "-t", _PROXY_IMAGE, _proxy_ctx])

    started: list[str] = []
    try:
        subprocess.run(["docker", "rm", "-f", _UPSTREAM, _PROXY], capture_output=True, check=False)
        subprocess.run(["docker", "network", "rm", _NET], capture_output=True, check=False)
        _run(["docker", "network", "create", _NET])

        # Upstream echo, aliased allowed.test, root to bind :80/:443.
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                _UPSTREAM,
                "--network",
                _NET,
                "--network-alias",
                "allowed.test",
                "--user",
                "0:0",
                "--entrypoint",
                "python3",
                _PROXY_IMAGE,
                "-c",
                _ECHO_SCRIPT,
            ]
        )
        started.append(_UPSTREAM)

        # Proxy: allow-list = allowed.test only; publish 3128 for the host client.
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                _PROXY,
                "--network",
                _NET,
                "-p",
                f"{_HOST_PORT}:3128",
                "-e",
                f"SESSION_ID={_SESSION_ID}",
                "-e",
                'ALLOW_LIST=["allowed.test"]',
                _PROXY_IMAGE,
            ]
        )
        started.append(_PROXY)

        assert _wait_tcp(_HOST_PORT), f"proxy did not bind :{_HOST_PORT}"
        # Wait for the upstream to be reachable THROUGH the proxy (retries cover
        # both the proxy main-loop start + the upstream HTTP server start).
        ready = False
        for _ in range(40):
            if _curl(_HOST_PORT, "http://allowed.test/") == "200":
                ready = True
                break
            time.sleep(0.5)
        assert ready, "upstream allowed.test not reachable through the proxy"

        yield {"host_port": _HOST_PORT, "proxy_name": _PROXY}
    finally:
        subprocess.run(["docker", "rm", "-f", *started], capture_output=True, check=False)
        subprocess.run(["docker", "network", "rm", _NET], capture_output=True, check=False)


def test_egress_enforcement_matrix(egress_stack: dict[str, Any]) -> None:
    port = egress_stack["host_port"]

    # 1. allowed HTTP → forwarded to the real upstream (200 + echo body).
    assert _curl(port, "http://allowed.test/") == "200"
    # 2. denied HTTP → proxy refuses (403), never reaches an upstream.
    assert _curl(port, "http://denied.test/") == "403"
    # 3. allowed HTTPS CONNECT → tunnel established (logged allowed); curl's TLS
    #    then fails against the plain :443 listener (ignored — we assert the record).
    _curl(port, "https://allowed.test/", extra=["-k"])
    # 4. denied HTTPS CONNECT → BLOCKED live (the G6 headline).
    _curl(port, "https://denied.test/", extra=["-k"])
    # 5. CONNECT to a non-allowed port → non_http_connect_target.
    _curl(port, "https://allowed.test:22/", extra=["-k"])

    # Let the proxy's incremental tailer flush the records (0.5s poll cadence).
    records: tuple[Any, ...] = ()
    for _ in range(20):
        records = _access_records(egress_stack["proxy_name"])
        tuples = {(r.host, r.method, r.outcome, r.refusal_reason) for r in records}
        if tuples >= _EXPECTED:
            break
        time.sleep(0.5)

    got = {(r.host, r.method, r.outcome, r.refusal_reason) for r in records}
    missing = _EXPECTED - got
    assert not missing, f"missing enforcement records: {missing}; got: {got}"

    # The denied-CONNECT block is the empirical headline — assert it explicitly.
    assert ("denied.test", "CONNECT", "refused", "not_in_allow_list") in got
    # Every record round-trips through the production wire parser by construction
    # (_access_records used it); re-assert the closed-enum outcome vocabulary.
    assert all(r.outcome in ("allowed", "refused") for r in records)


_EXPECTED = {
    ("allowed.test", "GET", "allowed", None),
    ("allowed.test", "CONNECT", "allowed", None),
    ("denied.test", "GET", "refused", "not_in_allow_list"),
    ("denied.test", "CONNECT", "refused", "not_in_allow_list"),
    ("allowed.test", "CONNECT", "refused", "non_http_connect_target"),
}


def test_malformed_allow_list_denies_all() -> None:
    """A malformed ``ALLOW_LIST`` renders a deny-all filter (the shim's
    fail-closed contract) — even an otherwise-allowed host is refused. Separate
    short-lived proxy (no upstream needed; everything is filtered)."""
    name = "t30-egress-proxy-denyall"
    port = _HOST_PORT + 1
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
    try:
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                name,
                "-p",
                f"{port}:3128",
                "-e",
                f"SESSION_ID={_SESSION_ID}",
                "-e",
                "ALLOW_LIST=this-is-not-json",
                _PROXY_IMAGE,
            ]
        )
        assert _wait_tcp(port), f"deny-all proxy did not bind :{port}"
        # allowed.test would be allowed under a valid list; under deny-all it is
        # refused (filtered) — no upstream is contacted. Retry the curl AND the
        # access.jsonl read together so BOTH the proxy main-loop start and the
        # tailer's 0.5s flush of the refusal record are covered (reading once
        # raced the tailer).
        code = "000"
        got: set[Any] = set()
        for _ in range(30):
            code = _curl(port, "http://allowed.test/")
            records = _access_records(name)
            got = {(r.host, r.outcome, r.refusal_reason) for r in records}
            if code == "403" and ("allowed.test", "refused", "not_in_allow_list") in got:
                break
            time.sleep(0.5)
        assert code == "403", f"deny-all proxy did not refuse (got {code})"
        assert ("allowed.test", "refused", "not_in_allow_list") in got, got
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
