"""M6 Task A3 (ADR-025) — the skill-execution broker (CRITICAL CONTROLS).

The broker is a NEW TRUST BOUNDARY: it decides which MCP tool calls a
sandboxed skill action may make. A per-invocation asyncio Unix-socket
server enforcing, per connection (design spec §5.2; the §5.4
invariants each pinned by a threat-model-revert-proven test in
``tests/unit/core/skill/test_broker.py``):

- a ``0700`` per-invocation socket directory + a non-world-accessible
  socket (invariants #1 + #2);
- a cryptographically-random session id in the socket path AND an
  independent per-invocation session token every request must present
  (invariants #3 + #4 — wrong/absent token refused before processing);
- bounded, length-framed decode (malformed → refusal, oversized
  declared length → refusal BEFORE allocation; invariants #7 + #8);
- **per-call ``declared_tools`` enforcement** — a ``tool_ref`` outside
  the skill's declared set is refused with ``skill_tool_not_declared``
  and the downstream call proxy is NEVER reached (invariant #11, the
  load-bearing guard);
- a per-invocation deadline that tears the whole session down
  (invariant #6) and finally-guarded stale-socket cleanup on success
  AND failure (invariant #5).

Wire arms (spec §5.2): success ``{"ok": true, "result": ...}``; broker
refusal ``{"ok": false, "refused": true, "reason": <SkillBrokerReason>}``;
downstream failure ``{"ok": false, "refused": false, "reason":
"skill_tool_invocation_failed", "error": <detail>}``.

Layering: imports the FROZEN wire protocol from
``sdk.skill_transport`` (the codec + the closed reason vocabulary) and
the ``SkillCallProxy`` seam from ``core/skill/_types`` — NEVER
``protocol.*`` or ``portal.*``; ``MCPHost`` is reached only through
the seam the Task-A5 executor wires.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import logging
import os
import secrets
import tempfile
import uuid
from pathlib import Path
from typing import Any

from cognic_agentos.core.skill._types import SkillCallProxy, _BrokerHandle
from cognic_agentos.sdk.skill_transport import (
    FrameTooLarge,
    MalformedFrame,
    SkillBrokerReason,
    decode_frame_async,
    encode_frame,
)

__all__ = ["SkillBroker"]

_LOGGER = logging.getLogger(__name__)

#: Socket filename inside the per-invocation 0700 directory. The dir
#: name stays SHORT (``csk-<32 hex>``) so the full path fits the
#: AF_UNIX ``sun_path`` cap (~104 bytes on darwin) under macOS's long
#: ``tempfile.gettempdir()``.
_SOCKET_NAME = "broker.sock"
_DIR_PREFIX = "csk-"


class _ServeContext:
    """Per-``serve()`` state: one socket, one token, one deadline.

    A ``SkillBroker`` instance is pure configuration; every ``serve()``
    call mints an independent context so concurrent invocations never
    share a socket, a token, or teardown state.
    """

    def __init__(self, *, broker_dir: Path, sock_path: Path, session_token: str) -> None:
        self.broker_dir = broker_dir
        self.sock_path = sock_path
        self.session_token = session_token
        self.server: asyncio.AbstractServer | None = None
        self.deadline_task: asyncio.Task[None] | None = None
        self.conn_tasks: set[asyncio.Task[Any]] = set()
        self._closed = False

    async def close(self) -> None:
        """Idempotent teardown — invariant #5.

        Cancels the deadline + every live connection, stops the server,
        and — ``finally``-guarded, so an exception mid-teardown cannot
        skip it — unlinks the socket and removes the ``0700`` dir.
        """
        if self._closed:
            return
        self._closed = True
        try:
            current = asyncio.current_task()
            if self.deadline_task is not None and self.deadline_task is not current:
                self.deadline_task.cancel()
            if self.server is not None:
                self.server.close()
            pending = [task for task in tuple(self.conn_tasks) if task is not current]
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            if self.server is not None:
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self.server.wait_closed(), timeout=5.0)
        finally:
            # Invariant #5 — stale-socket cleanup on success AND failure.
            with contextlib.suppress(OSError):
                self.sock_path.unlink(missing_ok=True)
            with contextlib.suppress(OSError):
                self.broker_dir.rmdir()


class SkillBroker:
    """Kernel-side skill-execution broker (ADR-025 §"Security model").

    Bound at construction to ONE skill invocation's authority: the
    skill's ``declared_tools`` (MCP identities ``<server_id>/<tool_name>``),
    the invoking tenant/actor, and the per-invocation deadline. The
    Task-A5 executor serves it, mounts the socket dir into the sandbox,
    and closes it (both finally-guarded) around the runner exec.
    """

    def __init__(
        self,
        *,
        declared_tools: frozenset[str],
        tenant_id: str,
        actor_subject: str,
        request_id_prefix: str,
        call_proxy: SkillCallProxy,
        timeout_s: float,
    ) -> None:
        if timeout_s <= 0:
            raise ValueError("timeout_s must be > 0 (a non-positive deadline would disable it)")
        self._declared_tools = frozenset(declared_tools)
        self._tenant_id = tenant_id
        self._actor_subject = actor_subject
        self._request_id_prefix = request_id_prefix
        self._call_proxy = call_proxy
        self._timeout_s = timeout_s

    async def serve(self) -> _BrokerHandle:
        """Bind + start serving one per-invocation broker session.

        Creates the ``0700`` directory named by a crypto-random session
        id (invariants #1 + #3 — ``exist_ok=False`` fails closed on a
        pre-created path), binds the Unix socket, chmods it ``0600``
        (invariant #2), mints the session token (invariant #4), and
        arms the per-invocation deadline (invariant #6). Any failure
        mid-serve tears down whatever was created before re-raising.
        """
        session_id = secrets.token_hex(16)
        broker_dir = Path(tempfile.gettempdir()) / f"{_DIR_PREFIX}{session_id}"
        broker_dir.mkdir(mode=0o700, exist_ok=False)
        ctx = _ServeContext(
            broker_dir=broker_dir,
            sock_path=broker_dir / _SOCKET_NAME,
            session_token=secrets.token_hex(32),
        )
        try:
            # mkdir(mode=...) is umask-subtracted; chmod pins 0700
            # deterministically (invariant #1).
            os.chmod(broker_dir, 0o700)
            ctx.server = await asyncio.start_unix_server(
                functools.partial(self._handle_connection, ctx), path=str(ctx.sock_path)
            )
            os.chmod(ctx.sock_path, 0o600)  # invariant #2
            ctx.deadline_task = asyncio.create_task(self._deadline(ctx))
        except BaseException:
            if ctx.server is not None:
                ctx.server.close()
            with contextlib.suppress(OSError):
                ctx.sock_path.unlink(missing_ok=True)
            with contextlib.suppress(OSError):
                broker_dir.rmdir()
            raise
        return _BrokerHandle(
            sock_path=str(ctx.sock_path),
            session_token=ctx.session_token,
            _closer=ctx.close,
        )

    async def _deadline(self, ctx: _ServeContext) -> None:
        """Invariant #6 — the per-invocation deadline tears the session down."""
        await asyncio.sleep(self._timeout_s)
        _LOGGER.warning(
            "skill broker per-invocation deadline (%.1fs) fired; tearing down session "
            "tenant_id=%s actor_subject=%s",
            self._timeout_s,
            self._tenant_id,
            self._actor_subject,
        )
        await ctx.close()

    async def _handle_connection(
        self, ctx: _ServeContext, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.current_task()
        assert task is not None  # start_unix_server always runs the callback in a task
        ctx.conn_tasks.add(task)
        try:
            await self._serve_one_request(ctx, reader, writer)
        except Exception:
            # Refusal paths respond in-band; anything else must not
            # kill the loop's exception handler silently.
            _LOGGER.exception("skill broker connection handler failed")
        finally:
            ctx.conn_tasks.discard(task)
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    async def _serve_one_request(
        self, ctx: _ServeContext, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """One request/response exchange — the enforcement pipeline.

        Order: transport (oversized / malformed) → session-token auth →
        request-shape checks → ``declared_tools`` (invariant #11) → the
        governed call proxy. Every refusal responds in-band with the
        closed-enum reason and never reaches the proxy.
        """
        try:
            frame = await decode_frame_async(reader)  # requires tool_ref (invariant #7)
        except FrameTooLarge:
            # Invariant #8 — the declared length was refused BEFORE any
            # body read; nothing was allocated.
            await self._respond_refusal(writer, "skill_broker_oversized_frame")
            return
        except MalformedFrame:
            await self._respond_refusal(writer, "skill_broker_malformed_frame")
            return

        token = frame.get("session_token")
        if not isinstance(token, str) or not secrets.compare_digest(
            token.encode("utf-8"), ctx.session_token.encode("utf-8")
        ):
            # Invariant #4 — refused before ANY processing of the request.
            _LOGGER.warning(
                "skill broker refused unauthorized client tenant_id=%s", self._tenant_id
            )
            await self._respond_refusal(writer, "skill_broker_unauthorized")
            return

        tool_ref = frame.get("tool_ref")
        if not isinstance(tool_ref, str):
            await self._respond_refusal(writer, "skill_broker_malformed_frame")
            return
        arguments = frame.get("arguments", {})
        if not isinstance(arguments, dict):
            await self._respond_refusal(writer, "skill_broker_malformed_frame")
            return

        if tool_ref not in self._declared_tools:
            # Invariant #11 — THE load-bearing guard: refused before the
            # proxy, so no token is minted and no external tool is touched.
            _LOGGER.warning(
                "skill broker refused undeclared tool_ref=%s tenant_id=%s actor_subject=%s",
                tool_ref,
                self._tenant_id,
                self._actor_subject,
            )
            await self._respond_refusal(writer, "skill_tool_not_declared")
            return

        server_id, _, tool_name = tool_ref.partition("/")
        if not server_id or not tool_name:
            # Defence-in-depth: a declared-but-malformed identity (no
            # ``<server_id>/<tool_name>`` shape) never reaches the proxy.
            await self._respond_refusal(writer, "skill_broker_malformed_frame")
            return

        request_id = f"{self._request_id_prefix}{uuid.uuid4().hex}"
        try:
            result = await self._call_proxy.call(
                server_id=server_id,
                tool_name=tool_name,
                arguments=arguments,
                request_id=request_id,
                tenant_id=self._tenant_id,
                originator_subject=self._actor_subject,
            )
        except Exception as exc:
            # The downstream-failure arm: refused=false distinguishes
            # "the governed call failed" from a broker-side refusal.
            await self._respond(
                writer,
                {
                    "ok": False,
                    "refused": False,
                    "reason": "skill_tool_invocation_failed",
                    "error": f"{type(exc).__name__}: {exc}",
                },
            )
            return

        try:
            payload = encode_frame({"ok": True, "result": result})
        except (FrameTooLarge, TypeError, ValueError) as exc:
            await self._respond(
                writer,
                {
                    "ok": False,
                    "refused": False,
                    "reason": "skill_tool_invocation_failed",
                    "error": f"tool result not frameable: {type(exc).__name__}",
                },
            )
            return
        with contextlib.suppress(OSError):
            writer.write(payload)
            await writer.drain()

    async def _respond_refusal(
        self, writer: asyncio.StreamWriter, reason: SkillBrokerReason
    ) -> None:
        await self._respond(writer, {"ok": False, "refused": True, "reason": reason})

    async def _respond(self, writer: asyncio.StreamWriter, obj: dict[str, Any]) -> None:
        # The client may already be gone (half-closed / vanished) — a
        # failed response write must not crash the handler.
        with contextlib.suppress(OSError):
            writer.write(encode_frame(obj))
            await writer.drain()
