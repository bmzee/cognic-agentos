"""M6 Task A2 (ADR-025) — skill-transport wire-protocol tests.

The transport is the FROZEN wire contract between the in-sandbox
skill-runner and the kernel-side skill-execution broker (design spec
§5.2 + §5.4; ADR-025 §"Security model"). This suite pins:

- the length-framed JSON codec: round-trip, bounded max-frame,
  oversized-prefix refused BEFORE the body read (the codec half of
  invariant #8), malformed-frame refusals (the codec half of
  invariant #7) — sync AND asyncio variants;
- the closed 5-value ``SkillBrokerReason`` vocabulary;
- the sandbox-side ``BrokerToolRegistry`` / ``BrokerTool`` client
  adapters: structural ``sdk.registry.ToolRegistry`` conformance, the
  three wire arms (success → result dict; broker refusal →
  ``SkillToolRefused(reason)``; downstream failure →
  ``SkillToolRefused("skill_tool_invocation_failed")``);
- the SDK-light import fence — the module ships inside the minimal
  sandbox runtime image, so it MUST import stdlib only.
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
import shutil
import sys
import tempfile
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path
from typing import Any, get_args

import pytest

from cognic_agentos.sdk.skill_transport import (
    MAX_FRAME_BYTES,
    BrokerTool,
    BrokerToolRegistry,
    FrameTooLarge,
    MalformedFrame,
    SkillBrokerReason,
    SkillToolRefused,
    decode_frame,
    decode_frame_async,
    encode_frame,
)

_EXPECTED_REASONS = {
    "skill_tool_not_declared",
    "skill_broker_malformed_frame",
    "skill_broker_oversized_frame",
    "skill_broker_unauthorized",
    "skill_tool_invocation_failed",
}


class _BytesReader:
    """Sync reader stub tracking consumed bytes (plan A2 sketch)."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self.bytes_read = 0

    def read(self, n: int) -> bytes:
        chunk = self._data[self.bytes_read : self.bytes_read + n]
        self.bytes_read += len(chunk)
        return chunk


# ---------------------------------------------------------------------------
# Codec — sync
# ---------------------------------------------------------------------------


def test_frame_roundtrip() -> None:
    payload = {"tool_ref": "s/t", "arguments": {"table": "EMPLOYEES"}}
    raw = encode_frame(payload)
    assert decode_frame(_BytesReader(raw)) == payload


def test_encode_frame_refuses_oversized_object() -> None:
    with pytest.raises(FrameTooLarge):
        encode_frame({"tool_ref": "s/t", "blob": "x" * (MAX_FRAME_BYTES + 16)})


def test_oversized_prefix_refused_before_body() -> None:
    # A 4-byte prefix declaring > MAX_FRAME_BYTES must raise WITHOUT
    # reading the body (invariant #8 — no unbounded allocation).
    huge = (MAX_FRAME_BYTES + 1).to_bytes(4, "big")
    reader = _BytesReader(huge)  # body deliberately absent
    with pytest.raises(FrameTooLarge):
        decode_frame(reader)
    assert reader.bytes_read == 4  # only the prefix was consumed


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param(b"\x00\x00", id="truncated-prefix"),
        pytest.param(b"\x00\x00\x00\x02{", id="truncated-body"),
        pytest.param(b"\x00\x00\x00\x04nope", id="non-json"),
        pytest.param(b"\x00\x00\x00\x00", id="zero-length-body"),
        pytest.param(b"\x00\x00\x00\x02\xff\xfe", id="non-utf8-body"),
        pytest.param(len(b"[1, 2]").to_bytes(4, "big") + b"[1, 2]", id="json-non-object"),
        pytest.param(encode_frame({"no": "toolref"}), id="missing-tool-ref"),
    ],
)
def test_malformed_frame_refused(bad: bytes) -> None:
    with pytest.raises(MalformedFrame):
        decode_frame(_BytesReader(bad))


def test_decode_frame_required_keys_override() -> None:
    # A response frame has no tool_ref — required_keys is the caller's
    # contract knob. Absent required key still refuses.
    response = {"ok": True, "result": {"rows": 3}}
    raw = encode_frame(response)
    assert decode_frame(_BytesReader(raw), required_keys=("ok",)) == response
    with pytest.raises(MalformedFrame):
        decode_frame(_BytesReader(raw))  # default requires tool_ref


def test_reason_enum_closed_five() -> None:
    values = get_args(SkillBrokerReason)
    assert len(values) == 5
    assert set(values) == _EXPECTED_REASONS


# ---------------------------------------------------------------------------
# Codec — asyncio variant (the broker + BrokerTool read path)
# ---------------------------------------------------------------------------


def _stream_reader_with(data: bytes, *, eof: bool = True) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    if eof:
        reader.feed_eof()
    return reader


async def test_async_frame_roundtrip() -> None:
    payload = {"tool_ref": "oracle/list_tables", "arguments": {}}
    reader = _stream_reader_with(encode_frame(payload))
    assert await decode_frame_async(reader) == payload


async def test_async_oversized_prefix_refused_without_body_read() -> None:
    # Feed ONLY the oversized prefix and NO EOF: an implementation that
    # tried to read the declared body would block forever — the bounded
    # wait proves the refusal fires on the prefix alone (invariant #8).
    reader = _stream_reader_with((MAX_FRAME_BYTES + 1).to_bytes(4, "big"), eof=False)
    with pytest.raises(FrameTooLarge):
        await asyncio.wait_for(decode_frame_async(reader), timeout=1.0)


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param(b"\x00\x00", id="truncated-prefix"),
        pytest.param(b"\x00\x00\x00\x0a{}", id="truncated-body"),
        pytest.param(b"\x00\x00\x00\x04nope", id="non-json"),
    ],
)
async def test_async_malformed_frame_refused(bad: bytes) -> None:
    reader = _stream_reader_with(bad)
    with pytest.raises(MalformedFrame):
        await asyncio.wait_for(decode_frame_async(reader), timeout=1.0)


# ---------------------------------------------------------------------------
# BrokerTool / BrokerToolRegistry — the sandbox-side client adapters
# ---------------------------------------------------------------------------


@pytest.fixture
def short_sock_dir() -> Iterator[str]:
    # AF_UNIX sun_path is capped (~104 bytes on darwin); pytest tmp_path
    # exceeds it. A short tempfile.mkdtemp dir stays well under the cap.
    d = tempfile.mkdtemp(prefix="csk-a2-")
    yield d
    shutil.rmtree(d, ignore_errors=True)


_Responder = Callable[[dict[str, Any]], dict[str, Any]]


class _StubBrokerServer:
    """Canned-response Unix-socket server capturing client requests."""

    def __init__(self, sock_path: str, responder: _Responder) -> None:
        self.sock_path = sock_path
        self.requests: list[dict[str, Any]] = []
        self._responder = responder
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_unix_server(self._handle, path=self.sock_path)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        frame = await decode_frame_async(reader)
        self.requests.append(frame)
        writer.write(encode_frame(self._responder(frame)))
        await writer.drain()
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()

    async def stop(self) -> None:
        assert self._server is not None
        self._server.close()
        await self._server.wait_closed()


async def _with_stub(
    sock_dir: str,
    responder: _Responder,
    action: Callable[[_StubBrokerServer], Awaitable[None]],
) -> None:
    stub = _StubBrokerServer(str(Path(sock_dir) / "s.sock"), responder)
    await stub.start()
    try:
        await asyncio.wait_for(action(stub), timeout=5.0)
    finally:
        await stub.stop()


async def test_broker_tool_invoke_success_arm(short_sock_dir: str) -> None:
    result = {"tables": ["EMPLOYEES", "DEPARTMENTS"]}

    async def action(stub: _StubBrokerServer) -> None:
        tool = BrokerTool(
            tool_ref="oracle/list_tables", sock_path=stub.sock_path, session_token="tok-1"
        )
        assert await tool.invoke(owner="COGNIC") == result
        # The request frame carries the session token, the tool_ref and
        # the kwargs — the exact broker-side contract.
        assert stub.requests == [
            {
                "session_token": "tok-1",
                "tool_ref": "oracle/list_tables",
                "arguments": {"owner": "COGNIC"},
            }
        ]

    await _with_stub(short_sock_dir, lambda _f: {"ok": True, "result": result}, action)


async def test_broker_tool_invoke_refused_arm_raises(short_sock_dir: str) -> None:
    async def action(stub: _StubBrokerServer) -> None:
        tool = BrokerTool(
            tool_ref="oracle/get_constraints", sock_path=stub.sock_path, session_token="tok-1"
        )
        with pytest.raises(SkillToolRefused) as exc_info:
            await tool.invoke()
        assert exc_info.value.reason == "skill_tool_not_declared"

    await _with_stub(
        short_sock_dir,
        lambda _f: {"ok": False, "refused": True, "reason": "skill_tool_not_declared"},
        action,
    )


async def test_broker_tool_invoke_error_arm_raises(short_sock_dir: str) -> None:
    async def action(stub: _StubBrokerServer) -> None:
        tool = BrokerTool(
            tool_ref="oracle/list_tables", sock_path=stub.sock_path, session_token="tok-1"
        )
        with pytest.raises(SkillToolRefused) as exc_info:
            await tool.invoke()
        assert exc_info.value.reason == "skill_tool_invocation_failed"
        assert exc_info.value.detail is not None
        assert "boom" in exc_info.value.detail

    await _with_stub(
        short_sock_dir,
        lambda _f: {
            "ok": False,
            "refused": False,
            "reason": "skill_tool_invocation_failed",
            "error": "MCPTransportError: boom",
        },
        action,
    )


async def test_broker_tool_invoke_non_object_result_refused(short_sock_dir: str) -> None:
    # A success frame whose result is not a JSON object violates the
    # response contract — the client refuses rather than passing junk
    # into skill code typed to receive a dict.
    async def action(stub: _StubBrokerServer) -> None:
        tool = BrokerTool(
            tool_ref="oracle/list_tables", sock_path=stub.sock_path, session_token="tok-1"
        )
        with pytest.raises(MalformedFrame):
            await tool.invoke()

    await _with_stub(short_sock_dir, lambda _f: {"ok": True, "result": [1, 2]}, action)


def test_registry_lists_declared_identities() -> None:
    declared = ["oracle/list_tables", "oracle/describe_table"]
    registry = BrokerToolRegistry(
        sock_path="/run/x.sock", session_token="tok", declared_tools=declared
    )
    # list_tools() is what Skill.__init__ cross-checks declared_tools
    # against — it MUST return the declared identities unmodified.
    assert registry.list_tools() == declared


def test_registry_get_returns_bound_broker_tool(short_sock_dir: str) -> None:
    registry = BrokerToolRegistry(
        sock_path=str(Path(short_sock_dir) / "s.sock"),
        session_token="tok-9",
        declared_tools=["oracle/list_tables"],
    )
    tool = registry.get("oracle/list_tables")
    assert isinstance(tool, BrokerTool)


def test_registry_get_is_permissive_for_undeclared_names() -> None:
    # Deliberate: the in-sandbox registry is UNTRUSTED client code; the
    # broker is the enforcement point (invariant #11). A local KeyError
    # would hide the governed refusal row — get() must hand back a tool
    # whose invoke() the broker then refuses with skill_tool_not_declared.
    registry = BrokerToolRegistry(
        sock_path="/run/x.sock", session_token="tok", declared_tools=["oracle/list_tables"]
    )
    tool = registry.get("oracle/get_constraints")
    assert isinstance(tool, BrokerTool)


def test_registry_structurally_satisfies_tool_registry_protocol() -> None:
    from cognic_agentos.sdk.registry import ToolRegistry

    registry = BrokerToolRegistry(sock_path="/run/x.sock", session_token="tok", declared_tools=[])
    assert isinstance(registry, ToolRegistry)


# ---------------------------------------------------------------------------
# SDK-light fence — stdlib-only imports (the module ships in the
# minimal sandbox runtime image; a kernel or third-party import here
# would break the image build AND widen the sandbox trust surface)
# ---------------------------------------------------------------------------


def _imported_top_level_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "relative imports forbidden in SDK-light modules"
            assert node.module is not None
            mods.add(node.module.split(".")[0])
    return mods


def test_transport_is_stdlib_only() -> None:
    import cognic_agentos.sdk.skill_transport as skill_transport

    module_path = Path(skill_transport.__file__)
    for mod in _imported_top_level_modules(module_path):
        assert mod in sys.stdlib_module_names, (
            f"non-stdlib import {mod!r} in SDK-light skill_transport (must run "
            "inside the minimal sandbox runtime image)"
        )
