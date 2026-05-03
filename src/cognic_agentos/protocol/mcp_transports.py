"""MCP transport implementations for Sprint-5 runtime traffic.

Critical-controls module per AGENTS.md. This module is runtime-side
for Streamable HTTP: importing it stays SDK-free, but constructing
``StreamableHTTPTransport`` calls :func:`require_mcp` because the class
uses the official ``mcp`` SDK to open sessions.

T7 lands only the Streamable HTTP transport. T8 adds the non-launching
``StdioTransport`` refusal stub; STDIO pack refusal itself already lives
in the T6 capability validator + registry admission path.
"""

from __future__ import annotations

import asyncio
import dataclasses
import inspect
import time
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager, AsyncExitStack
from datetime import timedelta
from importlib import import_module
from typing import Any, Literal, Protocol, cast

import httpx

from cognic_agentos.core.config import Settings
from cognic_agentos.protocol import require_mcp
from cognic_agentos.protocol.mcp_authz import MCPAuthzClient, Token

MCPTransportReason = Literal[
    "mcp_session_open_timeout",
    "mcp_session_open_failed",
    "mcp_call_tool_timeout",
    "mcp_transport_send_failed",
    "mcp_session_close_failed",
    "mcp_session_closed",
]

MCPTransportEventType = Literal["session_open", "session_close", "send_error"]

_SessionStreams = tuple[Any, Any, Callable[[], str | None]]


class MCPTransportError(Exception):
    """Closed-enum transport failure with token-free structured payload."""

    def __init__(
        self,
        reason: MCPTransportReason,
        message: str = "",
        **payload: Any,
    ) -> None:
        self.reason = reason
        self.payload = payload
        super().__init__(f"{reason}: {message}" if message else reason)


@dataclasses.dataclass(frozen=True, slots=True)
class MCPTransportEvent:
    """Token-free event payload that MCPHost can append to audit later."""

    event_type: MCPTransportEventType
    server_url: str
    session_id: str | None = None
    reason: MCPTransportReason | None = None
    payload: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True, slots=True)
class MCPToolCallRequest:
    """Tool-call request carried over an open MCP session."""

    name: str
    arguments: dict[str, Any] | None = None
    meta: dict[str, Any] | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class MCPSDKRequest:
    """Generic SDK request escape hatch for host-level protocol methods."""

    payload: Any
    result_type: type[Any]


@dataclasses.dataclass(slots=True)
class MCPSession:
    """Open SDK session plus the cleanup stack that owns its resources."""

    server_url: str
    sdk_session: Any
    exit_stack: AsyncExitStack
    get_session_id: Callable[[], str | None]
    token_scopes: tuple[str, ...]
    token_client_id: str
    opened_at: float = dataclasses.field(default_factory=time.time)
    closed: bool = False

    @property
    def session_id(self) -> str | None:
        """Return the SDK session id, if the server has assigned one."""
        return self.get_session_id()


class MCPTransport(Protocol):
    """Common async transport surface consumed by the future MCPHost.

    ``open_session`` is **keyword-only** per plan §T9 spec: forcing
    the call site to spell both ``server_url=`` and ``token=``
    eliminates the class of bug where a future MCPHost edit swaps
    argument order and silently sends the wrong token to the wrong
    server. ``close_session`` and ``send`` are positional because
    they take a single ``MCPSession`` (and a request, for ``send``)
    that was already explicitly constructed by the caller — there's
    no order-confusion risk.
    """

    async def open_session(self, *, server_url: str, token: Token) -> MCPSession:
        """Open an MCP session for ``server_url`` using ``token``."""

    async def close_session(self, session: MCPSession) -> None:
        """Close a previously-opened session."""

    async def send(self, session: MCPSession, request: MCPToolCallRequest | MCPSDKRequest) -> Any:
        """Send a request over ``session`` and return the SDK response."""


TransportEventHook = Callable[[MCPTransportEvent], object]


def _streamable_http_client_context(
    *,
    url: str,
    http_client: httpx.AsyncClient,
    terminate_on_close: bool,
) -> AbstractAsyncContextManager[_SessionStreams]:
    """Load the official MCP Streamable HTTP client lazily.

    The import stays inside the helper so module import remains clean on
    kernel-image-equivalent venvs that do not install the ``mcp`` SDK.
    """
    module = import_module("mcp.client.streamable_http")
    factory = cast(
        Callable[..., AbstractAsyncContextManager[_SessionStreams]], module.streamable_http_client
    )
    return factory(
        url=url,
        http_client=http_client,
        terminate_on_close=terminate_on_close,
    )


def _load_client_session_cls() -> type[Any]:
    """Load the SDK ClientSession class lazily."""
    module = import_module("mcp.client.session")
    return cast(type[Any], module.ClientSession)


class StreamableHTTPTransport:
    """Production-default Streamable HTTP transport backed by the MCP SDK."""

    def __init__(
        self,
        *,
        authz: MCPAuthzClient,
        settings: Settings,
        event_hook: TransportEventHook | None = None,
    ) -> None:
        """Construct a Streamable HTTP MCP transport.

        Per Sprint-5 R3 P1 doctrine, ``require_mcp()`` is called at
        construction time — :class:`StreamableHTTPTransport` is a
        runtime-side class that genuinely uses the ``mcp`` SDK to
        open sessions. Construction on a kernel-image-equivalent
        venv (no SDK) raises :class:`MCPNotAvailableError`.

        :param authz: The Sprint-5 :class:`MCPAuthzClient` instance
            this transport will use for token-related operations.
            Sprint-5 T7 stores it but does NOT consume it directly:
            the bearer token is passed in by the caller (T9's
            :class:`MCPHost.call_tool`) via the ``token`` argument
            to :meth:`open_session`. The ``authz`` reference is
            wired here so that when T9 lands runtime step-up
            handling (per the 401-vs-403 retry semantics in plan
            §T9), the transport can call ``authz.step_up_token(...)``
            without having to plumb it through every send call.
            Documented as load-bearing: even though Sprint-5 T7
            doesn't *call* methods on it, the parameter is part of
            the dependency graph that T9 will consume.
        :param settings: Process-wide :class:`Settings`. Reads
            ``mcp_oauth_request_timeout_s`` (session-open) and
            ``mcp_call_tool_timeout_s`` (per-call read).
        :param event_hook: Optional callable that receives every
            session/send transport event for audit emission via
            T9's :class:`MCPHost`. Sync and async callables both
            supported. Token-free payloads — see
            :class:`MCPTransportEvent`.
        """
        require_mcp()
        self._settings = settings
        self._authz = authz
        self._event_hook = event_hook
        self._open_timeout_s = self._positive_timeout(
            settings.mcp_oauth_request_timeout_s,
            "mcp_oauth_request_timeout_s",
        )
        self._call_timeout_s = self._positive_timeout(
            settings.mcp_call_tool_timeout_s,
            "mcp_call_tool_timeout_s",
        )

    async def open_session(self, *, server_url: str, token: Token) -> MCPSession:
        """Open and initialize an SDK session with a bearer token header.

        Keyword-only signature per :class:`MCPTransport` Protocol spec —
        forces the call site to name both arguments so ``server_url``
        and ``token`` can never be silently swapped by a refactor.
        """
        stack = AsyncExitStack()
        try:
            session = await asyncio.wait_for(
                self._open_session_with_stack(server_url=server_url, token=token, stack=stack),
                timeout=self._open_timeout_s,
            )
        except TimeoutError as exc:
            await stack.aclose()
            raise MCPTransportError(
                "mcp_session_open_timeout",
                "opening Streamable HTTP MCP session timed out",
                server_url=server_url,
                timeout_s=self._open_timeout_s,
            ) from exc
        except Exception as exc:
            await stack.aclose()
            raise MCPTransportError(
                "mcp_session_open_failed",
                "opening Streamable HTTP MCP session failed",
                server_url=server_url,
                error_type=type(exc).__name__,
            ) from exc

        await self._emit_event(
            MCPTransportEvent(
                event_type="session_open",
                server_url=server_url,
                session_id=session.session_id,
                payload={
                    "client_id": token.client_id,
                    "scopes": list(token.scopes),
                },
            )
        )
        return session

    async def close_session(self, session: MCPSession) -> None:
        """Close the SDK session and emit one close event."""
        if session.closed:
            return

        try:
            await asyncio.wait_for(session.exit_stack.aclose(), timeout=self._open_timeout_s)
        except TimeoutError as exc:
            raise MCPTransportError(
                "mcp_session_close_failed",
                "closing Streamable HTTP MCP session timed out",
                server_url=session.server_url,
                session_id=session.session_id,
                timeout_s=self._open_timeout_s,
            ) from exc
        except Exception as exc:
            raise MCPTransportError(
                "mcp_session_close_failed",
                "closing Streamable HTTP MCP session failed",
                server_url=session.server_url,
                session_id=session.session_id,
                error_type=type(exc).__name__,
            ) from exc

        session.closed = True
        await self._emit_event(
            MCPTransportEvent(
                event_type="session_close",
                server_url=session.server_url,
                session_id=session.session_id,
                payload={
                    "client_id": session.token_client_id,
                    "scopes": list(session.token_scopes),
                },
            )
        )

    async def send(self, session: MCPSession, request: MCPToolCallRequest | MCPSDKRequest) -> Any:
        """Send a tool-call or generic SDK request over an open session."""
        if session.closed:
            raise MCPTransportError(
                "mcp_session_closed",
                "cannot send over a closed MCP session",
                server_url=session.server_url,
                session_id=session.session_id,
            )

        try:
            return await asyncio.wait_for(
                self._send_without_timeout(session=session, request=request),
                timeout=self._call_timeout_s,
            )
        except TimeoutError as exc:
            await self._emit_send_error(
                session=session,
                reason="mcp_call_tool_timeout",
                payload={"timeout_s": self._call_timeout_s},
            )
            raise MCPTransportError(
                "mcp_call_tool_timeout",
                "MCP transport send timed out",
                server_url=session.server_url,
                session_id=session.session_id,
                timeout_s=self._call_timeout_s,
            ) from exc
        except Exception as exc:
            await self._emit_send_error(
                session=session,
                reason="mcp_transport_send_failed",
                payload={"error_type": type(exc).__name__},
            )
            raise MCPTransportError(
                "mcp_transport_send_failed",
                "MCP transport send failed",
                server_url=session.server_url,
                session_id=session.session_id,
                error_type=type(exc).__name__,
            ) from exc

    async def _open_session_with_stack(
        self,
        *,
        server_url: str,
        token: Token,
        stack: AsyncExitStack,
    ) -> MCPSession:
        timeout = httpx.Timeout(
            self._open_timeout_s,
            read=self._call_timeout_s,
        )
        http_client = await stack.enter_async_context(
            httpx.AsyncClient(
                headers={"Authorization": f"Bearer {token.value}"},
                timeout=timeout,
            )
        )
        read_stream, write_stream, get_session_id = await stack.enter_async_context(
            _streamable_http_client_context(
                url=server_url,
                http_client=http_client,
                terminate_on_close=True,
            )
        )
        client_session_cls = _load_client_session_cls()
        sdk_session = await stack.enter_async_context(
            client_session_cls(
                read_stream,
                write_stream,
                read_timeout_seconds=timedelta(seconds=self._call_timeout_s),
            )
        )
        await sdk_session.initialize()
        return MCPSession(
            server_url=server_url,
            sdk_session=sdk_session,
            exit_stack=stack,
            get_session_id=get_session_id,
            token_scopes=token.scopes,
            token_client_id=token.client_id,
        )

    async def _send_without_timeout(
        self,
        *,
        session: MCPSession,
        request: MCPToolCallRequest | MCPSDKRequest,
    ) -> Any:
        if isinstance(request, MCPToolCallRequest):
            return await session.sdk_session.call_tool(
                name=request.name,
                arguments=request.arguments,
                read_timeout_seconds=timedelta(seconds=self._call_timeout_s),
                meta=request.meta,
            )
        return await session.sdk_session.send_request(
            request.payload,
            request.result_type,
            request_read_timeout_seconds=timedelta(seconds=self._call_timeout_s),
        )

    async def _emit_send_error(
        self,
        *,
        session: MCPSession,
        reason: MCPTransportReason,
        payload: dict[str, Any],
    ) -> None:
        await self._emit_event(
            MCPTransportEvent(
                event_type="send_error",
                server_url=session.server_url,
                session_id=session.session_id,
                reason=reason,
                payload=payload,
            )
        )

    async def _emit_event(self, event: MCPTransportEvent) -> None:
        if self._event_hook is None:
            return
        result = self._event_hook(event)
        if inspect.isawaitable(result):
            await result

    @staticmethod
    def _positive_timeout(value: int | float, field_name: str) -> float:
        if value <= 0:
            raise ValueError(f"{field_name} must be > 0")
        return float(value)
