"""M6 Task A3 (ADR-025) — skill-execution broker tests (CRITICAL CONTROLS).

The broker is the load-bearing enforcement point between sandboxed
skill-action code and ``MCPHost.call_tool`` (design spec §5.2). This
suite pins the broker-side §5.4 transport invariants **#1-#8 and #11**
— each as its own threat-model-revert-proven load-bearing test — plus
the green path and the three wire arms:

- #1  per-invocation socket directory is ``0700``;
- #2  socket not world-accessible;
- #3  unguessable (crypto-random) session id in the socket path;
- #4  unauthorized client (wrong / absent / cross-session token)
      refused before any tool-call is processed;
- #5  stale-socket cleanup on success AND failure (finally-guarded);
- #6  broker closes on timeout — a hung client cannot hold the channel;
- #7  malformed frame refused, never reaching the call proxy;
- #8  oversized declared length refused before allocation;
- #11 undeclared ``tool_ref`` refused with ``skill_tool_not_declared``
      BEFORE the call proxy (the load-bearing declared_tools guard).

Invariants #9 (no general network) and #10 (no ambient credentials)
are sandbox-executor policy assertions — owned by Task A5, not here.

Every asyncio wait is bounded (``asyncio.wait_for``) so a regression
hangs a single test, not CI.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, NoReturn, cast

import pytest

from cognic_agentos.core.skill._types import _BrokerHandle
from cognic_agentos.core.skill.broker import SkillBroker
from cognic_agentos.sdk.skill_transport import (
    MAX_FRAME_BYTES,
    decode_frame_async,
    encode_frame,
)

_DECLARED = frozenset({"oracle/list_tables", "oracle/describe_table"})


class _SpyProxy:
    """Spy ``SkillCallProxy`` conformer recording every call."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.result: Any = {"tables": ["EMPLOYEES"]}
        self.exc: Exception | None = None

    async def call(
        self,
        *,
        server_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        request_id: str,
        tenant_id: str,
        originator_subject: str,
    ) -> Any:
        self.calls.append(
            {
                "server_id": server_id,
                "tool_name": tool_name,
                "arguments": arguments,
                "request_id": request_id,
                "tenant_id": tenant_id,
                "originator_subject": originator_subject,
            }
        )
        if self.exc is not None:
            raise self.exc
        return self.result


@pytest.fixture
def spy_proxy() -> _SpyProxy:
    return _SpyProxy()


def _make_broker(spy_proxy: _SpyProxy, *, timeout_s: float = 5.0) -> SkillBroker:
    return SkillBroker(
        declared_tools=_DECLARED,
        tenant_id="tenant-1",
        actor_subject="actor-1",
        request_id_prefix="skill-tool-",
        call_proxy=spy_proxy,
        timeout_s=timeout_s,
    )


@pytest.fixture
def broker(spy_proxy: _SpyProxy) -> SkillBroker:
    return _make_broker(spy_proxy)


@pytest.fixture
def broker_short_timeout(spy_proxy: _SpyProxy) -> SkillBroker:
    return _make_broker(spy_proxy, timeout_s=0.2)


@pytest.fixture
async def serve_handles() -> AsyncIterator[list[_BrokerHandle]]:
    """Track served handles; close() is idempotent so double-close is safe."""
    handles: list[_BrokerHandle] = []
    yield handles
    for handle in handles:
        await handle.close()


async def _rpc_raw(sock_path: str, raw: bytes) -> dict[str, Any]:
    reader, writer = await asyncio.open_unix_connection(sock_path)
    try:
        writer.write(raw)
        await writer.drain()
        return await asyncio.wait_for(
            decode_frame_async(reader, required_keys=("ok",)), timeout=5.0
        )
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def _rpc(sock_path: str, obj: dict[str, Any]) -> dict[str, Any]:
    return await _rpc_raw(sock_path, encode_frame(obj))


async def _wait_for_path_removal(path: str) -> None:
    for _ in range(500):
        if not os.path.exists(path):
            return
        await asyncio.sleep(0.01)
    pytest.fail(f"path {path!r} was not removed within the bounded wait")


# ---------------------------------------------------------------------------
# Invariants #1 + #2 — filesystem posture
# ---------------------------------------------------------------------------


async def _serve_under_permissive_umask(
    broker: SkillBroker, serve_handles: list[_BrokerHandle]
) -> _BrokerHandle:
    # Pin a PERMISSIVE ambient umask (0o022) around serve(): without it
    # a locked-down machine umask (e.g. 0o077) would mask group/other
    # bits by itself and both perms tests would pass VACUOUSLY even if
    # the broker's explicit chmods were removed. The broker — not the
    # ambient umask — must enforce the modes.
    old_umask = os.umask(0o022)
    try:
        h = await broker.serve()
    finally:
        os.umask(old_umask)
    serve_handles.append(h)
    return h


async def test_socket_dir_is_0700(broker: SkillBroker, serve_handles: list[_BrokerHandle]) -> None:
    h = await _serve_under_permissive_umask(broker, serve_handles)
    assert (os.stat(os.path.dirname(h.sock_path)).st_mode & 0o777) == 0o700
    await h.close()


async def test_socket_not_world_accessible(
    broker: SkillBroker, serve_handles: list[_BrokerHandle]
) -> None:
    h = await _serve_under_permissive_umask(broker, serve_handles)
    assert (os.stat(h.sock_path).st_mode & 0o077) == 0  # no group/other bits
    await h.close()


# ---------------------------------------------------------------------------
# Invariant #3 — unguessable session id
# ---------------------------------------------------------------------------


async def test_session_id_is_random_hex(
    broker: SkillBroker, serve_handles: list[_BrokerHandle]
) -> None:
    h1 = await broker.serve()
    serve_handles.append(h1)
    h2 = await broker.serve()
    serve_handles.append(h2)
    assert h1.sock_path != h2.sock_path
    for h in (h1, h2):
        assert re.search(r"[0-9a-f]{32}", h.sock_path)
        # The session token is an independent 32-byte crypto-random secret.
        assert re.fullmatch(r"[0-9a-f]{64}", h.session_token)
    assert h1.session_token != h2.session_token
    await h1.close()
    await h2.close()


# ---------------------------------------------------------------------------
# Invariant #4 — unauthorized client refused before processing
# ---------------------------------------------------------------------------


async def test_unauthorized_wrong_token_refused(
    broker: SkillBroker, spy_proxy: _SpyProxy, serve_handles: list[_BrokerHandle]
) -> None:
    h = await broker.serve()
    serve_handles.append(h)
    resp = await _rpc(
        h.sock_path,
        {"session_token": "WRONG", "tool_ref": "oracle/list_tables", "arguments": {}},
    )
    assert resp["ok"] is False
    assert resp["refused"] is True
    assert resp["reason"] == "skill_broker_unauthorized"
    assert spy_proxy.calls == []
    await h.close()


async def test_unauthorized_absent_token_refused(
    broker: SkillBroker, spy_proxy: _SpyProxy, serve_handles: list[_BrokerHandle]
) -> None:
    h = await broker.serve()
    serve_handles.append(h)
    resp = await _rpc(h.sock_path, {"tool_ref": "oracle/list_tables", "arguments": {}})
    assert resp["ok"] is False
    assert resp["refused"] is True
    assert resp["reason"] == "skill_broker_unauthorized"
    assert spy_proxy.calls == []
    await h.close()


async def test_session_token_bound_to_its_session(
    broker: SkillBroker, spy_proxy: _SpyProxy, serve_handles: list[_BrokerHandle]
) -> None:
    # Invariant #4's parenthetical: the token is bound to the SAME
    # random session id — another live session's token does not open
    # this session.
    h1 = await broker.serve()
    serve_handles.append(h1)
    h2 = await broker.serve()
    serve_handles.append(h2)
    resp = await _rpc(
        h2.sock_path,
        {"session_token": h1.session_token, "tool_ref": "oracle/list_tables", "arguments": {}},
    )
    assert resp["ok"] is False
    assert resp["refused"] is True
    assert resp["reason"] == "skill_broker_unauthorized"
    assert spy_proxy.calls == []
    await h1.close()
    await h2.close()


# ---------------------------------------------------------------------------
# Invariant #5 — stale-socket cleanup on success AND failure
# ---------------------------------------------------------------------------


async def test_cleanup_on_success(broker: SkillBroker, serve_handles: list[_BrokerHandle]) -> None:
    h = await broker.serve()
    serve_handles.append(h)
    sock = h.sock_path
    sock_dir = os.path.dirname(sock)
    assert os.path.exists(sock) and os.path.exists(sock_dir)
    await h.close()
    assert not os.path.exists(sock)
    assert not os.path.exists(sock_dir)


async def test_serve_failure_cleans_up_dir(
    broker: SkillBroker, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A failure mid-serve (bind refused) must not leave the 0700 dir
    # behind — a leftover dir is exactly the stale-socket re-bind
    # surface invariant #5 forbids.
    tmp = Path(tempfile.gettempdir())
    before = {p.name for p in tmp.glob("csk-*")}

    async def _boom(*args: Any, **kwargs: Any) -> NoReturn:
        raise RuntimeError("bind failed")

    monkeypatch.setattr(asyncio, "start_unix_server", _boom)
    with pytest.raises(RuntimeError, match="bind failed"):
        await broker.serve()
    after = {p.name for p in tmp.glob("csk-*")}
    assert after == before


async def test_serve_failure_after_bind_closes_server_and_cleans_up(
    broker: SkillBroker, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Failure AFTER the socket is bound (the socket chmod refuses): the
    # already-started server must be closed and both socket + dir removed.
    tmp = Path(tempfile.gettempdir())
    before = {p.name for p in tmp.glob("csk-*")}
    real_chmod = os.chmod

    def _chmod(path: Any, mode: int, *args: Any, **kwargs: Any) -> None:
        if str(path).endswith("broker.sock"):
            raise PermissionError("chmod denied")
        real_chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(os, "chmod", _chmod)
    with pytest.raises(PermissionError, match="chmod denied"):
        await broker.serve()
    after = {p.name for p in tmp.glob("csk-*")}
    assert after == before


async def test_close_is_finally_guarded(
    broker: SkillBroker,
    serve_handles: list[_BrokerHandle],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An exception during close()'s teardown phase must still unlink
    # the socket + rmdir the 0700 dir (the finally guard).
    h = await broker.serve()
    serve_handles.append(h)
    ctx = cast(Any, h)._closer.__self__  # white-box: the serve context
    assert ctx.server is not None

    async def _boom(self: Any) -> None:
        raise RuntimeError("teardown boom")

    monkeypatch.setattr(type(ctx.server), "wait_closed", _boom)
    with pytest.raises(RuntimeError, match="teardown boom"):
        await h.close()
    assert not os.path.exists(h.sock_path)
    assert not os.path.exists(os.path.dirname(h.sock_path))


async def test_close_is_idempotent(broker: SkillBroker, serve_handles: list[_BrokerHandle]) -> None:
    h = await broker.serve()
    serve_handles.append(h)
    await h.close()
    await h.close()  # second close is a no-op, not an error
    assert not os.path.exists(h.sock_path)


# ---------------------------------------------------------------------------
# Invariant #6 — broker closes on timeout (hung client / action)
# ---------------------------------------------------------------------------


async def test_broker_closes_on_timeout(
    broker_short_timeout: SkillBroker, serve_handles: list[_BrokerHandle]
) -> None:
    h = await broker_short_timeout.serve()
    serve_handles.append(h)
    # A client that connects but never sends: the per-invocation
    # deadline fires, the hung connection is closed (EOF at the client)
    # and the socket + dir are torn down.
    reader, writer = await asyncio.open_unix_connection(h.sock_path)
    try:
        data = await asyncio.wait_for(reader.read(), timeout=5.0)
        assert data == b""
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    await _wait_for_path_removal(h.sock_path)
    assert not os.path.exists(os.path.dirname(h.sock_path))


# ---------------------------------------------------------------------------
# Invariant #7 — malformed frame refused (never reaches the proxy)
# ---------------------------------------------------------------------------


async def test_malformed_frame_refused(
    broker: SkillBroker, spy_proxy: _SpyProxy, serve_handles: list[_BrokerHandle]
) -> None:
    h = await broker.serve()
    serve_handles.append(h)
    resp = await _rpc_raw(h.sock_path, b"\x00\x00\x00\x04nope")
    assert resp["ok"] is False
    assert resp["refused"] is True
    assert resp["reason"] == "skill_broker_malformed_frame"
    assert spy_proxy.calls == []
    await h.close()


async def test_missing_tool_ref_refused_malformed(
    broker: SkillBroker, spy_proxy: _SpyProxy, serve_handles: list[_BrokerHandle]
) -> None:
    h = await broker.serve()
    serve_handles.append(h)
    resp = await _rpc(h.sock_path, {"session_token": h.session_token, "arguments": {}})
    assert resp["ok"] is False
    assert resp["refused"] is True
    assert resp["reason"] == "skill_broker_malformed_frame"
    assert spy_proxy.calls == []
    await h.close()


async def test_non_string_tool_ref_refused_malformed(
    broker: SkillBroker, spy_proxy: _SpyProxy, serve_handles: list[_BrokerHandle]
) -> None:
    h = await broker.serve()
    serve_handles.append(h)
    resp = await _rpc(
        h.sock_path, {"session_token": h.session_token, "tool_ref": 42, "arguments": {}}
    )
    assert resp["ok"] is False
    assert resp["refused"] is True
    assert resp["reason"] == "skill_broker_malformed_frame"
    assert spy_proxy.calls == []
    await h.close()


async def test_non_object_arguments_refused_malformed(
    broker: SkillBroker, spy_proxy: _SpyProxy, serve_handles: list[_BrokerHandle]
) -> None:
    h = await broker.serve()
    serve_handles.append(h)
    resp = await _rpc(
        h.sock_path,
        {"session_token": h.session_token, "tool_ref": "oracle/list_tables", "arguments": [1]},
    )
    assert resp["ok"] is False
    assert resp["refused"] is True
    assert resp["reason"] == "skill_broker_malformed_frame"
    assert spy_proxy.calls == []
    await h.close()


async def test_declared_ref_without_slash_refused_malformed(
    spy_proxy: _SpyProxy, serve_handles: list[_BrokerHandle]
) -> None:
    # Defence-in-depth: even a DECLARED identity that is not a valid
    # ``<server_id>/<tool_name>`` shape never reaches the proxy.
    broker = SkillBroker(
        declared_tools=frozenset({"noslash"}),
        tenant_id="tenant-1",
        actor_subject="actor-1",
        request_id_prefix="skill-tool-",
        call_proxy=spy_proxy,
        timeout_s=5.0,
    )
    h = await broker.serve()
    serve_handles.append(h)
    resp = await _rpc(
        h.sock_path, {"session_token": h.session_token, "tool_ref": "noslash", "arguments": {}}
    )
    assert resp["ok"] is False
    assert resp["refused"] is True
    assert resp["reason"] == "skill_broker_malformed_frame"
    assert spy_proxy.calls == []
    await h.close()


# ---------------------------------------------------------------------------
# Invariant #8 — oversized payload refused before allocation
# ---------------------------------------------------------------------------


async def test_oversized_payload_refused(
    broker: SkillBroker, spy_proxy: _SpyProxy, serve_handles: list[_BrokerHandle]
) -> None:
    h = await broker.serve()
    serve_handles.append(h)
    # ONLY the hostile 4-byte prefix is sent — an implementation that
    # tried to allocate/read the declared body would hang, not respond.
    resp = await _rpc_raw(h.sock_path, (MAX_FRAME_BYTES + 1).to_bytes(4, "big"))
    assert resp["ok"] is False
    assert resp["refused"] is True
    assert resp["reason"] == "skill_broker_oversized_frame"
    assert spy_proxy.calls == []
    await h.close()


# ---------------------------------------------------------------------------
# Invariant #11 — undeclared tool refused BEFORE MCPHost.call_tool
# ---------------------------------------------------------------------------


async def test_undeclared_tool_refused_before_call(
    broker: SkillBroker, spy_proxy: _SpyProxy, serve_handles: list[_BrokerHandle]
) -> None:
    h = await broker.serve()
    serve_handles.append(h)
    resp = await _rpc(
        h.sock_path,
        {
            "session_token": h.session_token,
            "tool_ref": "oracle/get_constraints",
            "arguments": {},
        },
    )
    assert resp["ok"] is False
    assert resp["refused"] is True
    assert resp["reason"] == "skill_tool_not_declared"
    assert spy_proxy.calls == []  # the call proxy is NEVER reached
    await h.close()


# ---------------------------------------------------------------------------
# Green path + the downstream-failure arm
# ---------------------------------------------------------------------------


async def test_declared_tool_routes_through_proxy(
    broker: SkillBroker, spy_proxy: _SpyProxy, serve_handles: list[_BrokerHandle]
) -> None:
    h = await broker.serve()
    serve_handles.append(h)
    resp = await _rpc(
        h.sock_path,
        {
            "session_token": h.session_token,
            "tool_ref": "oracle/list_tables",
            "arguments": {"owner": "COGNIC"},
        },
    )
    assert resp["ok"] is True
    assert resp["result"] == {"tables": ["EMPLOYEES"]}
    c = spy_proxy.calls[0]
    assert c["server_id"] == "oracle"
    assert c["tool_name"] == "list_tables"
    assert c["arguments"] == {"owner": "COGNIC"}
    assert c["tenant_id"] == "tenant-1"
    assert c["originator_subject"] == "actor-1"
    assert c["request_id"].startswith("skill-tool-")
    await h.close()


async def test_fresh_request_id_per_call(
    broker: SkillBroker, spy_proxy: _SpyProxy, serve_handles: list[_BrokerHandle]
) -> None:
    h = await broker.serve()
    serve_handles.append(h)
    request = {
        "session_token": h.session_token,
        "tool_ref": "oracle/list_tables",
        "arguments": {},
    }
    await _rpc(h.sock_path, request)
    await _rpc(h.sock_path, request)
    ids = [c["request_id"] for c in spy_proxy.calls]
    assert len(ids) == 2
    assert ids[0] != ids[1]
    assert all(i.startswith("skill-tool-") for i in ids)
    await h.close()


async def test_proxy_exception_maps_to_invocation_failed(
    broker: SkillBroker, spy_proxy: _SpyProxy, serve_handles: list[_BrokerHandle]
) -> None:
    spy_proxy.exc = RuntimeError("upstream boom")
    h = await broker.serve()
    serve_handles.append(h)
    resp = await _rpc(
        h.sock_path,
        {
            "session_token": h.session_token,
            "tool_ref": "oracle/list_tables",
            "arguments": {},
        },
    )
    assert resp["ok"] is False
    assert resp["refused"] is False  # downstream failure, NOT a broker refusal
    assert resp["reason"] == "skill_tool_invocation_failed"
    assert "RuntimeError" in resp["error"]
    assert "upstream boom" in resp["error"]
    await h.close()


async def test_unframeable_result_maps_to_invocation_failed(
    broker: SkillBroker, spy_proxy: _SpyProxy, serve_handles: list[_BrokerHandle]
) -> None:
    spy_proxy.result = object()  # not JSON-serializable
    h = await broker.serve()
    serve_handles.append(h)
    resp = await _rpc(
        h.sock_path,
        {
            "session_token": h.session_token,
            "tool_ref": "oracle/list_tables",
            "arguments": {},
        },
    )
    assert resp["ok"] is False
    assert resp["refused"] is False
    assert resp["reason"] == "skill_tool_invocation_failed"
    await h.close()


# ---------------------------------------------------------------------------
# Constructor guard
# ---------------------------------------------------------------------------


def test_timeout_s_must_be_positive(spy_proxy: _SpyProxy) -> None:
    # A non-positive deadline would disable invariant #6 silently.
    with pytest.raises(ValueError, match="timeout_s"):
        SkillBroker(
            declared_tools=_DECLARED,
            tenant_id="tenant-1",
            actor_subject="actor-1",
            request_id_prefix="skill-tool-",
            call_proxy=spy_proxy,
            timeout_s=0.0,
        )
