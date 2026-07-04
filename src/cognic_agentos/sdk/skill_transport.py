"""M6 Task A2 (ADR-025) — the FROZEN skill-broker wire protocol + sandbox-side client.

The transport between the in-sandbox skill-runner and the kernel-side
skill-execution broker (design spec §5.2; ADR-025 §"Security model"):
a request/response tool-call RPC over a Unix domain socket, carrying
length-framed JSON — a 4-byte big-endian unsigned length prefix
followed by a UTF-8 JSON object, bounded by ``MAX_FRAME_BYTES``.

Wire arms (spec §5.2):

.. code-block:: text

    request  → { "session_token": "...", "tool_ref": "<server_id>/<tool_name>",
                 "arguments": { ... } }
    response ← { "ok": true,  "result": { ... } }
             | { "ok": false, "refused": true,  "reason": "<SkillBrokerReason>" }
             | { "ok": false, "refused": false, "reason": "skill_tool_invocation_failed",
                 "error": "<mapped detail>" }

SDK-light: this module ships inside the minimal, immutable sandbox
runtime image — it imports **stdlib only** (no kernel modules, no
pydantic, no third-party dependencies). Pinned by the AST fence in
``tests/unit/sdk/test_skill_transport.py``.

The decode path enforces the transport half of two §5.4 invariants:

- invariant #8 — an oversized declared length is refused **before**
  the body is read (no unbounded allocation);
- invariant #7 — a truncated / non-JSON / non-object / missing-key
  frame is refused with :class:`MalformedFrame`.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import Sequence
from typing import Any, Literal, Protocol

#: Bounded maximum frame size (1 MiB). A declared length above this is
#: refused BEFORE the body read — invariant #8 (no memory-exhaustion frame).
MAX_FRAME_BYTES: int = 1_048_576

_PREFIX_LEN = 4

#: Closed refusal vocabulary the broker emits on the wire (spec §5.2 +
#: plan Task A2). Wire-protocol-public — drift breaks every deployed
#: skill-runtime image reading broker responses.
SkillBrokerReason = Literal[
    "skill_tool_not_declared",
    "skill_broker_malformed_frame",
    "skill_broker_oversized_frame",
    "skill_broker_unauthorized",
    "skill_tool_invocation_failed",
]


class FrameTooLarge(Exception):
    """A frame's declared (or encoded) length exceeds ``MAX_FRAME_BYTES``.

    On the decode path this fires after reading ONLY the 4-byte prefix —
    the body is never read, so a hostile length cannot force an
    unbounded allocation (invariant #8).
    """


class MalformedFrame(Exception):
    """The frame is not a well-formed length-framed JSON object.

    Covers: truncated length prefix, truncated body, non-UTF-8 body,
    non-JSON body, a JSON value that is not an object, and a frame
    missing a required key (invariant #7's codec half).
    """


class SkillToolRefused(Exception):
    """The broker refused (or failed to complete) a tool invocation.

    ``reason`` carries the wire reason — one of ``SkillBrokerReason``
    from a conforming broker, but typed ``str`` because this is the
    UNTRUSTED-side client and the wire value is data, not a trusted
    invariant. ``detail`` carries the optional mapped error string from
    the downstream-failure arm.
    """

    def __init__(self, reason: str, *, detail: str | None = None) -> None:
        super().__init__(reason if detail is None else f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


class _SyncReader(Protocol):
    """Minimal blocking-read protocol for :func:`decode_frame`."""

    def read(self, n: int) -> bytes: ...


def encode_frame(obj: dict[str, Any]) -> bytes:
    """Encode ``obj`` as a length-framed UTF-8 JSON frame.

    Raises :class:`FrameTooLarge` if the encoded body exceeds
    ``MAX_FRAME_BYTES`` (the encode-side half of the bound — a
    conforming peer never emits a frame the decode side must refuse).
    """
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_FRAME_BYTES:
        raise FrameTooLarge(
            f"frame body is {len(body)} bytes; the bounded maximum is {MAX_FRAME_BYTES}"
        )
    return len(body).to_bytes(_PREFIX_LEN, "big") + body


def _length_from_prefix(prefix: bytes) -> int:
    """Validate the 4-byte prefix and return the declared body length.

    The ``MAX_FRAME_BYTES`` check happens HERE — before any caller
    reads the body — so the bound holds for every decode variant.
    """
    if len(prefix) < _PREFIX_LEN:
        raise MalformedFrame("truncated length prefix")
    length = int.from_bytes(prefix, "big")
    if length > MAX_FRAME_BYTES:
        raise FrameTooLarge(
            f"frame declares {length} bytes; the bounded maximum is {MAX_FRAME_BYTES}"
        )
    return length


def _object_from_body(
    body: bytes, declared_length: int, required_keys: Sequence[str]
) -> dict[str, Any]:
    if len(body) < declared_length:
        raise MalformedFrame("truncated frame body")
    try:
        decoded = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MalformedFrame(f"frame body is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(decoded, dict):
        raise MalformedFrame("frame body is not a JSON object")
    for key in required_keys:
        if key not in decoded:
            raise MalformedFrame(f"frame is missing required key {key!r}")
    return decoded


def decode_frame(
    reader: _SyncReader, *, required_keys: Sequence[str] = ("tool_ref",)
) -> dict[str, Any]:
    """Decode one frame from a blocking reader.

    Reads the 4-byte prefix, refuses an oversized declared length
    BEFORE reading the body (invariant #8), then reads + parses the
    body. ``required_keys`` defaults to the request-frame contract
    (``tool_ref``); response readers pass their own key set.
    """
    length = _length_from_prefix(reader.read(_PREFIX_LEN))
    return _object_from_body(reader.read(length), length, required_keys)


async def decode_frame_async(
    reader: asyncio.StreamReader, *, required_keys: Sequence[str] = ("tool_ref",)
) -> dict[str, Any]:
    """Decode one frame from an asyncio stream — same invariants as
    :func:`decode_frame` (bound checked on the prefix alone; truncation
    surfaces as :class:`MalformedFrame`)."""
    try:
        prefix = await reader.readexactly(_PREFIX_LEN)
    except asyncio.IncompleteReadError as exc:
        raise MalformedFrame("truncated length prefix") from exc
    length = _length_from_prefix(prefix)
    try:
        body = await reader.readexactly(length)
    except asyncio.IncompleteReadError as exc:
        raise MalformedFrame("truncated frame body") from exc
    return _object_from_body(body, length, required_keys)


class BrokerTool:
    """Sandbox-side tool handle whose ``invoke`` is the broker RPC.

    Pack authors keep writing ``await tool.invoke(**kwargs)`` unchanged
    (the ``sdk.tool.Tool`` calling convention); every call becomes one
    request/response round-trip over the broker socket. One connection
    per invocation — the broker serves one request per connection.
    """

    def __init__(self, *, tool_ref: str, sock_path: str, session_token: str) -> None:
        self._tool_ref = tool_ref
        self._sock_path = sock_path
        self._session_token = session_token

    async def invoke(self, **kwargs: Any) -> dict[str, Any]:
        """Invoke the tool through the broker.

        Returns the ``result`` object on the success arm. Raises
        :class:`SkillToolRefused` carrying the wire ``reason`` on both
        refusal arms, or :class:`MalformedFrame` if the broker's
        response violates the frame contract.
        """
        reader, writer = await asyncio.open_unix_connection(self._sock_path)
        try:
            writer.write(
                encode_frame(
                    {
                        "session_token": self._session_token,
                        "tool_ref": self._tool_ref,
                        "arguments": dict(kwargs),
                    }
                )
            )
            await writer.drain()
            response = await decode_frame_async(reader, required_keys=("ok",))
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
        if response.get("ok") is True:
            result = response.get("result")
            if not isinstance(result, dict):
                raise MalformedFrame("success frame carries a non-object result")
            return result
        reason = response.get("reason")
        if not isinstance(reason, str) or not reason:
            reason = "skill_tool_invocation_failed"
        error = response.get("error")
        raise SkillToolRefused(reason, detail=error if isinstance(error, str) else None)


class BrokerToolRegistry:
    """Sandbox-side ``sdk.registry.ToolRegistry`` conformer backed by the broker.

    ``list_tools()`` returns the declared MCP tool identities the runner
    received from the executor's env — so the existing
    ``Skill.__init__`` ``declared_tools`` cross-check passes unmodified.

    ``get()`` is deliberately PERMISSIVE: it hands back a bound
    :class:`BrokerTool` for any name, declared or not. The in-sandbox
    registry is untrusted client code — enforcement lives broker-side
    (invariant #11), where an undeclared ``tool_ref`` is refused with
    ``skill_tool_not_declared`` and leaves a governed refusal row. A
    local ``KeyError`` would hide that evidence without adding any
    security (hostile code could bypass this class entirely).
    """

    def __init__(
        self, *, sock_path: str, session_token: str, declared_tools: Sequence[str]
    ) -> None:
        self._sock_path = sock_path
        self._session_token = session_token
        self._declared_tools = tuple(declared_tools)

    def list_tools(self) -> list[str]:
        """The declared MCP tool identities (``<server_id>/<tool_name>``)."""
        return list(self._declared_tools)

    def get(self, name: str) -> Any:
        """Return a broker-bound :class:`BrokerTool` for ``name``.

        Typed ``Any`` (not ``sdk.tool.Tool``): the SDK ``Tool`` base
        pulls ``jsonschema`` — a third-party dependency the SDK-light
        sandbox image must not carry. ``BrokerTool`` satisfies the
        call-site contract (``await tool.invoke(**kwargs) -> dict``).
        """
        return BrokerTool(
            tool_ref=name, sock_path=self._sock_path, session_token=self._session_token
        )


__all__ = [
    "MAX_FRAME_BYTES",
    "BrokerTool",
    "BrokerToolRegistry",
    "FrameTooLarge",
    "MalformedFrame",
    "SkillBrokerReason",
    "SkillToolRefused",
    "decode_frame",
    "decode_frame_async",
    "encode_frame",
]
