"""Sprint-5 T7 - Streamable HTTP MCP transport contract tests.

Critical-controls module per AGENTS.md: the HTTP transport is the
runtime boundary that turns an OAuth/PRM token into SDK-backed MCP
session traffic. Tests pin the R3 P1 SDK boundary, timeout handling,
bearer-token injection, event hooks, and error taxonomy without
opening a real network connection.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import types
from typing import Any, ClassVar, cast
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.protocol import MCPNotAvailableError
from cognic_agentos.protocol.mcp_authz import Token


def _token(value: str = "secret-token-value") -> Token:
    return Token(
        value=value,
        expires_at=4_100_000_000,
        as_issuer="https://as.example",
        scopes=("mcp:tools",),
        resource_indicator="https://server.example/mcp",
        client_id="client-a",
    )


class _FakeHTTPClient:
    """AsyncClient stand-in that records constructor args + lifecycle."""

    instances: ClassVar[list[_FakeHTTPClient]] = []

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.args = args
        self.kwargs = kwargs
        self.entered = False
        self.exited = False
        _FakeHTTPClient.instances.append(self)

    async def __aenter__(self) -> _FakeHTTPClient:
        self.entered = True
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: object | None,
    ) -> None:
        self.exited = True


class _FakeStreamableContext:
    def __init__(
        self,
        *,
        read_stream: object,
        write_stream: object,
        session_id: str | None = "sdk-session-1",
        enter_error: BaseException | None = None,
    ) -> None:
        self.read_stream = read_stream
        self.write_stream = write_stream
        self.session_id = session_id
        self.enter_error = enter_error
        self.entered = False
        self.exited = False

    async def __aenter__(self) -> tuple[object, object, Any]:
        if self.enter_error is not None:
            raise self.enter_error
        self.entered = True
        return (self.read_stream, self.write_stream, lambda: self.session_id)

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: object | None,
    ) -> None:
        self.exited = True


class _FakeClientSession:
    instances: ClassVar[list[_FakeClientSession]] = []

    def __init__(
        self,
        read_stream: object,
        write_stream: object,
        read_timeout_seconds: dt.timedelta | None = None,
    ) -> None:
        self.read_stream = read_stream
        self.write_stream = write_stream
        self.read_timeout_seconds = read_timeout_seconds
        self.entered = False
        self.exited = False
        self.initialize = AsyncMock(return_value={"initialized": True})
        self.call_tool = AsyncMock(return_value={"content": "ok"})
        self.send_request = AsyncMock(return_value={"generic": "ok"})
        _FakeClientSession.instances.append(self)

    async def __aenter__(self) -> _FakeClientSession:
        self.entered = True
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: object | None,
    ) -> None:
        self.exited = True


@pytest.fixture(autouse=True)
def reset_fakes() -> None:
    _FakeHTTPClient.instances.clear()
    _FakeClientSession.instances.clear()


@pytest.fixture
def settings() -> Any:
    return build_settings_without_env_file().model_copy(
        update={
            "mcp_oauth_request_timeout_s": 7,
            "mcp_call_tool_timeout_s": 13,
        }
    )


@pytest.fixture
def authz() -> MagicMock:
    return MagicMock(name="authz")


@pytest.fixture
def transport_module(monkeypatch: pytest.MonkeyPatch) -> Any:
    from cognic_agentos.protocol import mcp_transports

    monkeypatch.setattr(mcp_transports, "require_mcp", MagicMock())
    monkeypatch.setattr("cognic_agentos.protocol.mcp_transports.httpx.AsyncClient", _FakeHTTPClient)
    monkeypatch.setattr(mcp_transports, "_load_client_session_cls", lambda: _FakeClientSession)
    return mcp_transports


@pytest.fixture
def fake_stream_context(
    transport_module: Any, monkeypatch: pytest.MonkeyPatch
) -> _FakeStreamableContext:
    context = _FakeStreamableContext(read_stream=object(), write_stream=object())
    calls: list[dict[str, Any]] = []

    def _factory(**kwargs: Any) -> _FakeStreamableContext:
        calls.append(kwargs)
        return context

    context.calls = calls  # type: ignore[attr-defined]
    monkeypatch.setattr(transport_module, "_streamable_http_client_context", _factory)
    return context


async def _collecting_hook(events: list[Any], event: Any) -> None:
    events.append(event)


class TestStreamableHTTPConstructor:
    def test_constructor_calls_require_mcp(
        self, transport_module: Any, settings: Any, authz: Any
    ) -> None:
        transport_module.StreamableHTTPTransport(authz=authz, settings=settings)
        transport_module.require_mcp.assert_called_once_with()

    def test_constructor_propagates_missing_sdk(
        self, transport_module: Any, monkeypatch: pytest.MonkeyPatch, settings: Any, authz: Any
    ) -> None:
        monkeypatch.setattr(
            transport_module,
            "require_mcp",
            MagicMock(side_effect=MCPNotAvailableError("missing sdk")),
        )
        with pytest.raises(MCPNotAvailableError):
            transport_module.StreamableHTTPTransport(authz=authz, settings=settings)

    def test_constructor_rejects_non_positive_runtime_timeouts(
        self, transport_module: Any, settings: Any, authz: Any
    ) -> None:
        settings.mcp_call_tool_timeout_s = 0
        with pytest.raises(ValueError, match="mcp_call_tool_timeout_s"):
            transport_module.StreamableHTTPTransport(authz=authz, settings=settings)


class TestOpenSession:
    async def test_open_session_injects_bearer_token_and_timeout(
        self,
        transport_module: Any,
        fake_stream_context: _FakeStreamableContext,
        settings: Any,
        authz: Any,
    ) -> None:
        transport = transport_module.StreamableHTTPTransport(authz=authz, settings=settings)
        session = await transport.open_session(
            server_url="https://server.example/mcp",
            token=_token(),
        )

        assert session.server_url == "https://server.example/mcp"
        assert session.session_id == "sdk-session-1"
        client = _FakeHTTPClient.instances[0]
        assert client.entered is True
        assert client.kwargs["headers"] == {"Authorization": "Bearer secret-token-value"}
        timeout = client.kwargs["timeout"]
        assert isinstance(timeout, httpx.Timeout)
        assert timeout.connect == 7
        assert timeout.read == 13
        assert fake_stream_context.calls == [  # type: ignore[attr-defined]
            {
                "url": "https://server.example/mcp",
                "http_client": client,
                "terminate_on_close": True,
            }
        ]

    async def test_open_session_enters_sdk_session_and_initializes(
        self,
        transport_module: Any,
        fake_stream_context: _FakeStreamableContext,
        settings: Any,
        authz: Any,
    ) -> None:
        transport = transport_module.StreamableHTTPTransport(authz=authz, settings=settings)
        session = await transport.open_session(
            server_url="https://server.example/mcp",
            token=_token(),
        )

        sdk_session = _FakeClientSession.instances[0]
        assert sdk_session.entered is True
        assert sdk_session.read_timeout_seconds == dt.timedelta(seconds=13)
        sdk_session.initialize.assert_awaited_once_with()
        assert session.sdk_session is sdk_session

    async def test_open_session_emits_sanitized_event(
        self,
        transport_module: Any,
        fake_stream_context: _FakeStreamableContext,
        settings: Any,
        authz: Any,
    ) -> None:
        events: list[Any] = []
        transport = transport_module.StreamableHTTPTransport(
            authz=authz,
            settings=settings,
            event_hook=lambda event: _collecting_hook(events, event),
        )

        await transport.open_session(server_url="https://server.example/mcp", token=_token())

        assert [event.event_type for event in events] == ["session_open"]
        event = events[0]
        assert event.server_url == "https://server.example/mcp"
        assert event.session_id == "sdk-session-1"
        assert event.payload["client_id"] == "client-a"
        assert "secret-token-value" not in repr(event)
        assert "token" not in event.payload

    async def test_open_session_supports_sync_event_hook(
        self,
        transport_module: Any,
        fake_stream_context: _FakeStreamableContext,
        settings: Any,
        authz: Any,
    ) -> None:
        events: list[Any] = []
        transport = transport_module.StreamableHTTPTransport(
            authz=authz,
            settings=settings,
            event_hook=events.append,
        )

        await transport.open_session(server_url="https://server.example/mcp", token=_token())

        assert [event.event_type for event in events] == ["session_open"]

    async def test_open_session_timeout_closes_partial_stack(
        self,
        transport_module: Any,
        fake_stream_context: _FakeStreamableContext,
        monkeypatch: pytest.MonkeyPatch,
        settings: Any,
        authz: Any,
    ) -> None:
        async def _never_initialize() -> None:
            await asyncio.sleep(60)

        original_init = _FakeClientSession.__init__

        def _init_with_hanging_initialize(
            self: _FakeClientSession,
            read_stream: object,
            write_stream: object,
            read_timeout_seconds: dt.timedelta | None = None,
        ) -> None:
            original_init(self, read_stream, write_stream, read_timeout_seconds)
            self.initialize = AsyncMock(side_effect=_never_initialize)

        monkeypatch.setattr(_FakeClientSession, "__init__", _init_with_hanging_initialize)
        settings.mcp_oauth_request_timeout_s = 0.001
        transport = transport_module.StreamableHTTPTransport(authz=authz, settings=settings)

        with pytest.raises(transport_module.MCPTransportError) as exc:
            await transport.open_session(server_url="https://server.example/mcp", token=_token())

        assert exc.value.reason == "mcp_session_open_timeout"
        assert _FakeHTTPClient.instances[0].exited is True
        assert fake_stream_context.exited is True

    async def test_open_session_failure_raises_sanitized_transport_error(
        self,
        transport_module: Any,
        monkeypatch: pytest.MonkeyPatch,
        settings: Any,
        authz: Any,
    ) -> None:
        context = _FakeStreamableContext(
            read_stream=object(),
            write_stream=object(),
            enter_error=RuntimeError("server echoed secret-token-value"),
        )
        monkeypatch.setattr(
            transport_module,
            "_streamable_http_client_context",
            lambda **_kwargs: context,
        )
        transport = transport_module.StreamableHTTPTransport(authz=authz, settings=settings)

        with pytest.raises(transport_module.MCPTransportError) as exc:
            await transport.open_session(server_url="https://server.example/mcp", token=_token())

        assert exc.value.reason == "mcp_session_open_failed"
        assert "secret-token-value" not in repr(exc.value.payload)
        assert "server echoed" not in repr(exc.value.payload)


class TestCloseSession:
    async def test_close_session_closes_stack_and_emits_event(
        self,
        transport_module: Any,
        fake_stream_context: _FakeStreamableContext,
        settings: Any,
        authz: Any,
    ) -> None:
        events: list[Any] = []
        transport = transport_module.StreamableHTTPTransport(
            authz=authz,
            settings=settings,
            event_hook=lambda event: _collecting_hook(events, event),
        )
        session = await transport.open_session(
            server_url="https://server.example/mcp", token=_token()
        )

        await transport.close_session(session)

        assert session.closed is True
        assert fake_stream_context.exited is True
        assert _FakeHTTPClient.instances[0].exited is True
        assert [event.event_type for event in events] == ["session_open", "session_close"]

    async def test_close_session_timeout_fails_closed(
        self,
        transport_module: Any,
        fake_stream_context: _FakeStreamableContext,
        settings: Any,
        authz: Any,
    ) -> None:
        class _HangingCloseStack:
            async def aclose(self) -> None:
                await asyncio.sleep(60)

        settings.mcp_oauth_request_timeout_s = 0.001
        transport = transport_module.StreamableHTTPTransport(authz=authz, settings=settings)
        session = await transport.open_session(
            server_url="https://server.example/mcp", token=_token()
        )
        session.exit_stack = _HangingCloseStack()

        with pytest.raises(transport_module.MCPTransportError) as exc:
            await transport.close_session(session)

        assert exc.value.reason == "mcp_session_close_failed"
        assert exc.value.payload["timeout_s"] == 0.001

    async def test_close_session_failure_fails_closed(
        self,
        transport_module: Any,
        fake_stream_context: _FakeStreamableContext,
        settings: Any,
        authz: Any,
    ) -> None:
        class _FailingCloseStack:
            async def aclose(self) -> None:
                raise RuntimeError("server echoed secret-token-value")

        transport = transport_module.StreamableHTTPTransport(authz=authz, settings=settings)
        session = await transport.open_session(
            server_url="https://server.example/mcp", token=_token()
        )
        session.exit_stack = _FailingCloseStack()

        with pytest.raises(transport_module.MCPTransportError) as exc:
            await transport.close_session(session)

        assert exc.value.reason == "mcp_session_close_failed"
        assert exc.value.payload["error_type"] == "RuntimeError"
        assert "secret-token-value" not in repr(exc.value.payload)

    async def test_close_session_is_idempotent(
        self,
        transport_module: Any,
        fake_stream_context: _FakeStreamableContext,
        settings: Any,
        authz: Any,
    ) -> None:
        events: list[Any] = []
        transport = transport_module.StreamableHTTPTransport(
            authz=authz,
            settings=settings,
            event_hook=lambda event: _collecting_hook(events, event),
        )
        session = await transport.open_session(
            server_url="https://server.example/mcp", token=_token()
        )

        await transport.close_session(session)
        await transport.close_session(session)

        assert [event.event_type for event in events] == ["session_open", "session_close"]


class TestSend:
    async def test_send_call_tool_uses_sdk_call_tool_timeout(
        self,
        transport_module: Any,
        fake_stream_context: _FakeStreamableContext,
        settings: Any,
        authz: Any,
    ) -> None:
        transport = transport_module.StreamableHTTPTransport(authz=authz, settings=settings)
        session = await transport.open_session(
            server_url="https://server.example/mcp", token=_token()
        )
        request = transport_module.MCPToolCallRequest(name="lookup", arguments={"q": "abc"})

        result = await transport.send(session, request)

        assert result == {"content": "ok"}
        _FakeClientSession.instances[0].call_tool.assert_awaited_once_with(
            name="lookup",
            arguments={"q": "abc"},
            read_timeout_seconds=dt.timedelta(seconds=13),
            meta=None,
        )

    async def test_send_generic_request_uses_send_request_timeout(
        self,
        transport_module: Any,
        fake_stream_context: _FakeStreamableContext,
        settings: Any,
        authz: Any,
    ) -> None:
        transport = transport_module.StreamableHTTPTransport(authz=authz, settings=settings)
        session = await transport.open_session(
            server_url="https://server.example/mcp", token=_token()
        )
        request = transport_module.MCPSDKRequest(payload={"jsonrpc": "2.0"}, result_type=dict)

        result = await transport.send(session, request)

        assert result == {"generic": "ok"}
        _FakeClientSession.instances[0].send_request.assert_awaited_once_with(
            {"jsonrpc": "2.0"},
            dict,
            request_read_timeout_seconds=dt.timedelta(seconds=13),
        )

    async def test_send_closed_session_fails_closed(
        self,
        transport_module: Any,
        fake_stream_context: _FakeStreamableContext,
        settings: Any,
        authz: Any,
    ) -> None:
        transport = transport_module.StreamableHTTPTransport(authz=authz, settings=settings)
        session = await transport.open_session(
            server_url="https://server.example/mcp", token=_token()
        )
        await transport.close_session(session)

        with pytest.raises(transport_module.MCPTransportError) as exc:
            await transport.send(session, transport_module.MCPToolCallRequest(name="lookup"))

        assert exc.value.reason == "mcp_session_closed"

    async def test_send_timeout_emits_sanitized_send_error(
        self,
        transport_module: Any,
        fake_stream_context: _FakeStreamableContext,
        monkeypatch: pytest.MonkeyPatch,
        settings: Any,
        authz: Any,
    ) -> None:
        async def _never_call_tool(**_kwargs: Any) -> None:
            await asyncio.sleep(60)

        events: list[Any] = []
        settings.mcp_call_tool_timeout_s = 0.001
        transport = transport_module.StreamableHTTPTransport(
            authz=authz,
            settings=settings,
            event_hook=lambda event: _collecting_hook(events, event),
        )
        session = await transport.open_session(
            server_url="https://server.example/mcp", token=_token()
        )
        session.sdk_session.call_tool = _never_call_tool

        with pytest.raises(transport_module.MCPTransportError) as exc:
            await transport.send(session, transport_module.MCPToolCallRequest(name="lookup"))

        assert exc.value.reason == "mcp_call_tool_timeout"
        assert events[-1].event_type == "send_error"
        assert events[-1].reason == "mcp_call_tool_timeout"
        assert "secret-token-value" not in repr(events[-1])

    async def test_send_failure_emits_sanitized_send_error(
        self,
        transport_module: Any,
        fake_stream_context: _FakeStreamableContext,
        settings: Any,
        authz: Any,
    ) -> None:
        events: list[Any] = []
        transport = transport_module.StreamableHTTPTransport(
            authz=authz,
            settings=settings,
            event_hook=lambda event: _collecting_hook(events, event),
        )
        session = await transport.open_session(
            server_url="https://server.example/mcp", token=_token()
        )
        session.sdk_session.call_tool = AsyncMock(
            side_effect=RuntimeError("server echoed secret-token-value")
        )

        with pytest.raises(transport_module.MCPTransportError) as exc:
            await transport.send(session, transport_module.MCPToolCallRequest(name="lookup"))

        assert exc.value.reason == "mcp_transport_send_failed"
        assert events[-1].event_type == "send_error"
        assert "secret-token-value" not in repr(events[-1])
        assert "server echoed" not in repr(events[-1].payload)


class TestLazySdkLoaders:
    def test_streamable_http_client_context_loads_sdk_lazily(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cognic_agentos.protocol import mcp_transports as transport_module

        context = object()
        calls: list[dict[str, Any]] = []

        def _factory(**kwargs: Any) -> object:
            calls.append(kwargs)
            return context

        monkeypatch.setattr(
            transport_module,
            "import_module",
            lambda name: types.SimpleNamespace(streamable_http_client=_factory),
        )
        http_client = cast(httpx.AsyncClient, object())

        loaded = transport_module._streamable_http_client_context(
            url="https://server.example/mcp",
            http_client=http_client,
            terminate_on_close=True,
        )

        assert loaded is context
        assert calls == [
            {
                "url": "https://server.example/mcp",
                "http_client": http_client,
                "terminate_on_close": True,
            }
        ]

    def test_client_session_cls_loads_sdk_lazily(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cognic_agentos.protocol import mcp_transports as transport_module

        class _SDKClientSession:
            pass

        monkeypatch.setattr(
            transport_module,
            "import_module",
            lambda name: types.SimpleNamespace(ClientSession=_SDKClientSession),
        )

        assert transport_module._load_client_session_cls() is _SDKClientSession


# ---------------------------------------------------------------------------
# MCPTransportReason closed-enum drift detector
# ---------------------------------------------------------------------------


class TestMCPTransportReasonClosedEnum:
    """Pin the runtime-side transport reason vocabulary so additions
    can't drift undetected.

    ``MCPTransportReason`` is the closed-enum the transport raises
    via :class:`MCPTransportError` and emits via
    :class:`MCPTransportEvent.reason`. T9's :class:`MCPHost` will
    consume these reasons in ``audit.tool_invocation_*`` payloads
    and in the per-call decision-history rows; once that surface
    lands, an unrecognized reason would silently fall through audit
    classification logic.

    Mirrors the same drift-detector pattern the Sprint-5 plan
    established for ``AuthzReason`` (`test_mcp_authz.py`),
    ``ValidationReason`` (`test_mcp_capabilities.py`), and
    ``RefusalReason`` (`test_refusal_reason_completeness.py`).
    """

    EXPECTED_REASONS: ClassVar[frozenset[str]] = frozenset(
        {
            "mcp_session_open_timeout",
            "mcp_session_open_failed",
            "mcp_call_tool_timeout",
            "mcp_transport_send_failed",
            "mcp_session_close_failed",
            "mcp_session_closed",
        }
    )

    def test_transport_reason_literal_matches_expected_set(self) -> None:
        """The :data:`MCPTransportReason` ``Literal`` matches the
        documented set exactly. Adding a new value here without
        updating :attr:`EXPECTED_REASONS` (and the corresponding
        T9 audit-mapping arm when that lands) trips this test."""
        from typing import get_args

        from cognic_agentos.protocol.mcp_transports import MCPTransportReason

        actual = frozenset(get_args(MCPTransportReason))
        assert actual == self.EXPECTED_REASONS, (
            f"MCPTransportReason drift detected. "
            f"Added without test arm: {actual - self.EXPECTED_REASONS}; "
            f"Removed without removing arm: "
            f"{self.EXPECTED_REASONS - actual}"
        )

    def test_event_type_literal_matches_expected_set(self) -> None:
        """Companion drift detector for :data:`MCPTransportEventType`
        — the event-type vocabulary T9 will switch on for audit
        emission. Three values: open / close / send-error. Any
        addition here means a new T9 audit-classification branch
        is needed."""
        from typing import get_args

        from cognic_agentos.protocol.mcp_transports import MCPTransportEventType

        actual = frozenset(get_args(MCPTransportEventType))
        expected = frozenset({"session_open", "session_close", "send_error"})
        assert actual == expected, (
            f"MCPTransportEventType drift detected. "
            f"Added: {actual - expected}; Removed: {expected - actual}"
        )

    @pytest.mark.parametrize(
        "reason",
        sorted(EXPECTED_REASONS),
    )
    def test_every_reason_has_a_dedicated_test_arm(self, reason: str) -> None:
        """Every value of :data:`MCPTransportReason` MUST appear in
        a real ``.reason == "<r>"`` assertion target somewhere in
        this test file (i.e., a place where a test is actually
        verifying the transport's closed-enum surfaces that reason).

        R1 P3 fix: the previous implementation counted RAW string
        occurrences anywhere in the file. Because each reason already
        appears in :attr:`EXPECTED_REASONS` AND in this parametrize
        list (the parametrize list is now derived from the set, but
        even before that change the bare-string counter was vulnerable
        to "future reason added to both lists with no actual assertion
        ever made on it"). The tightened pattern below specifically
        looks for the ``.reason ==`` member-access equality form,
        which is unambiguously a test assertion in this codebase
        (declarations use string literals in lists/sets without
        ``.reason ==`` syntax).
        """
        from pathlib import Path

        this_file = Path(__file__)
        text = this_file.read_text(encoding="utf-8")

        # Match the assertion patterns we actually use in this file:
        #   assert exc.value.reason == "<r>"       (MCPTransportError raised)
        #   assert event.reason == "<r>"           (event.reason field)
        #   assert events[-1].reason == "<r>"      (last-event indexing)
        # All three reduce to ``.reason == "<r>"`` after the dot. The
        # comparison-equality form is a strong signal that the test
        # is actually verifying the reason fired, not just declaring
        # it for completeness.
        assertion_pattern = f'.reason == "{reason}"'
        assertion_hits = text.count(assertion_pattern)
        assert assertion_hits >= 1, (
            f'MCPTransportReason {reason!r} has no `.reason == "<r>"` '
            f"assertion in this test file — only declarations in "
            f"EXPECTED_REASONS / parametrize lists. Add a test that "
            f"actually exercises the code path that raises this reason "
            f"OR emits an event with this reason."
        )


# ---------------------------------------------------------------------------
# R1 P2 #1 — open_session resource-cleanup invariant
# (cancellation + hook-failure paths MUST close the partially-built stack)
# ---------------------------------------------------------------------------


class TestOpenSessionCleanupOnPreReturnFailure:
    """Three failure classes during ``open_session`` MUST close the
    partially-built :class:`AsyncExitStack` before propagating:

      1. ``asyncio.CancelledError`` (a ``BaseException`` subclass)
         from caller cancellation — bypasses both ``except``
         clauses; without the outer ``try/finally``, the
         already-entered HTTP client + SDK session contexts leak.
      2. Hook failure during the ``session_open`` audit-event
         emission — the session is fully opened, the stack is
         fully entered, but the audit pipeline can't record it.
         Per AGENTS.md audit-chain doctrine, fail-closed: close
         the session and propagate the hook failure.
      3. (Sanity) the existing TimeoutError + Exception paths still
         clean up — re-asserted in the same shape so a future
         refactor can't regress them.
    """

    async def test_cancellation_during_open_closes_partial_stack(
        self,
        transport_module: Any,
        fake_stream_context: _FakeStreamableContext,
        monkeypatch: pytest.MonkeyPatch,
        settings: Any,
        authz: Any,
    ) -> None:
        """Caller cancels mid-open → ``CancelledError`` propagates AND
        the HTTP client + stream context are closed. Without the R1
        P2 #1 fix, ``CancelledError`` (BaseException) bypassed both
        ``except`` clauses and the stack stayed open for process
        lifetime."""

        # Make initialize() block forever so we can cancel mid-open
        async def _hangs_forever() -> None:
            await asyncio.sleep(60)

        original_init = _FakeClientSession.__init__

        def _init_with_hanging_initialize(
            self: _FakeClientSession,
            read_stream: object,
            write_stream: object,
            read_timeout_seconds: dt.timedelta | None = None,
        ) -> None:
            original_init(self, read_stream, write_stream, read_timeout_seconds)
            self.initialize = AsyncMock(side_effect=_hangs_forever)

        monkeypatch.setattr(_FakeClientSession, "__init__", _init_with_hanging_initialize)

        transport = transport_module.StreamableHTTPTransport(authz=authz, settings=settings)
        task = asyncio.create_task(
            transport.open_session(server_url="https://server.example/mcp", token=_token())
        )
        # Yield control so the task starts the SDK open
        await asyncio.sleep(0)
        # Cancel before the wait_for timeout fires — this would
        # have leaked the stack in the pre-R1-P2-#1 implementation.
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        # The partially-built stack MUST have been closed: the HTTP
        # client + stream context both exited.
        assert _FakeHTTPClient.instances[0].exited is True
        assert fake_stream_context.exited is True

    async def test_hook_failure_during_session_open_closes_session(
        self,
        transport_module: Any,
        fake_stream_context: _FakeStreamableContext,
        settings: Any,
        authz: Any,
    ) -> None:
        """Hook raises during ``session_open`` event emission → the
        already-opened session MUST be closed before the hook
        exception propagates. Per audit-chain fail-closed doctrine:
        a session that the audit pipeline cannot record is NOT
        returned to the caller."""

        class _BrokenAuditHook(Exception):
            pass

        def _broken_hook(_event: Any) -> None:
            raise _BrokenAuditHook("audit pipeline misconfigured")

        transport = transport_module.StreamableHTTPTransport(
            authz=authz,
            settings=settings,
            event_hook=_broken_hook,
        )

        with pytest.raises(_BrokenAuditHook, match="audit pipeline misconfigured"):
            await transport.open_session(
                server_url="https://server.example/mcp",
                token=_token(),
            )

        # Session was opened, then closed when the hook raised.
        # Both the HTTP client and the stream context exited.
        assert _FakeHTTPClient.instances[0].exited is True
        assert fake_stream_context.exited is True
        # No MCPSession returned — caller would have leaked the
        # session if cleanup didn't run; here the assertion is
        # implicit (the raise prevented assignment).

    async def test_nested_mcp_transport_error_is_not_re_wrapped(
        self,
        transport_module: Any,
        fake_stream_context: _FakeStreamableContext,
        monkeypatch: pytest.MonkeyPatch,
        settings: Any,
        authz: Any,
    ) -> None:
        """Defensive branch: if a future refactor adds an
        :class:`MCPTransportError`-raising path inside
        ``_open_session_with_stack`` (e.g., nested transport error
        from a sub-component), the outer ``except MCPTransportError``
        re-raises it UNCHANGED — instead of letting the generic
        ``except Exception`` wrap it as ``mcp_session_open_failed``.
        Without this branch a nested closed-enum reason would be
        swallowed and replaced with a less specific one."""

        async def _raises_typed_error(**_kwargs: Any) -> Any:
            raise transport_module.MCPTransportError(
                "mcp_session_open_failed",
                "nested error from a future sub-component",
                server_url="https://server.example/mcp",
                nested_marker="preserved",
            )

        transport = transport_module.StreamableHTTPTransport(authz=authz, settings=settings)
        monkeypatch.setattr(transport, "_open_session_with_stack", _raises_typed_error)

        with pytest.raises(transport_module.MCPTransportError) as exc:
            await transport.open_session(server_url="https://server.example/mcp", token=_token())

        # The nested-marker payload field proves the original error
        # passed through unchanged (would have been stripped if the
        # generic Exception path wrapped it).
        assert exc.value.payload.get("nested_marker") == "preserved"

    async def test_hook_async_failure_during_session_open_also_closes(
        self,
        transport_module: Any,
        fake_stream_context: _FakeStreamableContext,
        settings: Any,
        authz: Any,
    ) -> None:
        """Async hook raises after `await` — same cleanup path."""

        async def _broken_async_hook(_event: Any) -> None:
            raise RuntimeError("async audit hook failed")

        transport = transport_module.StreamableHTTPTransport(
            authz=authz,
            settings=settings,
            event_hook=_broken_async_hook,
        )

        with pytest.raises(RuntimeError, match="async audit hook failed"):
            await transport.open_session(server_url="https://server.example/mcp", token=_token())

        assert _FakeHTTPClient.instances[0].exited is True
        assert fake_stream_context.exited is True


# ---------------------------------------------------------------------------
# R1 P2 #2 — send-path hook failure MUST NOT mask closed-enum error
# ---------------------------------------------------------------------------


class TestSendHookFailureDoesNotMaskTransportError:
    """When the SDK send raises (timeout OR ordinary exception), the
    audit-event emission for the matching ``send_error`` event runs
    through :meth:`_emit_send_error_safe`, which swallows non-
    cancellation hook exceptions so the closed-enum
    :class:`MCPTransportError` ALWAYS reaches the caller. Without
    the safe-emit wrapper, a broken T9 audit hook would mask the
    primary transport error and the closed-enum reason would never
    reach T9's ``decision_history`` mapping."""

    async def test_hook_failure_during_send_timeout_emit_does_not_mask(
        self,
        transport_module: Any,
        fake_stream_context: _FakeStreamableContext,
        settings: Any,
        authz: Any,
    ) -> None:
        """SDK send times out → hook raises during send-error emission
        → caller MUST still see ``mcp_call_tool_timeout``, NOT the
        hook exception."""

        async def _never_call_tool(**_kwargs: Any) -> None:
            await asyncio.sleep(60)

        def _broken_hook(_event: Any) -> None:
            raise RuntimeError("audit hook misconfigured")

        settings.mcp_call_tool_timeout_s = 0.001
        transport = transport_module.StreamableHTTPTransport(
            authz=authz,
            settings=settings,
            event_hook=_broken_hook,
        )
        # NOTE: open path also uses the hook — but we don't trip it
        # here because the open path is ALSO swallowed via the
        # broken hook; let's give a working hook for open and a
        # broken one for send. Switching mid-flight isn't ergonomic;
        # use a per-event-type hook instead.
        events_seen: list[str] = []

        def _selective_hook(event: Any) -> None:
            events_seen.append(event.event_type)
            if event.event_type == "send_error":
                raise RuntimeError("audit hook misconfigured for send_error")

        transport = transport_module.StreamableHTTPTransport(
            authz=authz,
            settings=settings,
            event_hook=_selective_hook,
        )
        session = await transport.open_session(
            server_url="https://server.example/mcp", token=_token()
        )
        session.sdk_session.call_tool = _never_call_tool

        with pytest.raises(transport_module.MCPTransportError) as exc:
            await transport.send(session, transport_module.MCPToolCallRequest(name="lookup"))

        # Caller sees the closed-enum reason, NOT the hook exception
        assert exc.value.reason == "mcp_call_tool_timeout"
        # The hook was invoked (proves the safe-emit went through it)
        assert "send_error" in events_seen

    async def test_hook_failure_during_send_failure_emit_does_not_mask(
        self,
        transport_module: Any,
        fake_stream_context: _FakeStreamableContext,
        settings: Any,
        authz: Any,
    ) -> None:
        """SDK send raises ordinary exception → hook raises during
        send-error emission → caller MUST still see
        ``mcp_transport_send_failed``."""
        events_seen: list[str] = []

        def _selective_hook(event: Any) -> None:
            events_seen.append(event.event_type)
            if event.event_type == "send_error":
                raise RuntimeError("audit hook misconfigured for send_error")

        transport = transport_module.StreamableHTTPTransport(
            authz=authz,
            settings=settings,
            event_hook=_selective_hook,
        )
        session = await transport.open_session(
            server_url="https://server.example/mcp", token=_token()
        )
        session.sdk_session.call_tool = AsyncMock(
            side_effect=RuntimeError("simulated SDK send failure")
        )

        with pytest.raises(transport_module.MCPTransportError) as exc:
            await transport.send(session, transport_module.MCPToolCallRequest(name="lookup"))

        # Caller sees the closed-enum reason, NOT the hook exception
        assert exc.value.reason == "mcp_transport_send_failed"
        assert "send_error" in events_seen

    async def test_hook_cancellation_during_send_error_propagates(
        self,
        transport_module: Any,
        fake_stream_context: _FakeStreamableContext,
        settings: Any,
        authz: Any,
    ) -> None:
        """Cancellation in the hook (rare — requires the hook to
        await a cancellable) is the ONE exception class that's
        allowed to propagate from the safe-emit wrapper. The
        whole operation is being torn down; the caller's outer
        scope should see the cancellation rather than a transport
        error."""

        async def _hook_that_cancels(_event: Any) -> None:
            raise asyncio.CancelledError()

        transport = transport_module.StreamableHTTPTransport(
            authz=authz,
            settings=settings,
            event_hook=_hook_that_cancels,
        )
        # Open with a working hook by replacing it AFTER open_session
        # — open uses the cancelling hook, which would also propagate
        # CancelledError. So skip the hook for open by giving a
        # benign one first, then swapping.
        events_seen: list[str] = []

        async def _selective_hook(event: Any) -> None:
            events_seen.append(event.event_type)
            if event.event_type == "send_error":
                raise asyncio.CancelledError()

        transport = transport_module.StreamableHTTPTransport(
            authz=authz,
            settings=settings,
            event_hook=_selective_hook,
        )
        session = await transport.open_session(
            server_url="https://server.example/mcp", token=_token()
        )
        session.sdk_session.call_tool = AsyncMock(
            side_effect=RuntimeError("simulated SDK send failure")
        )

        # CancelledError propagates from the hook, NOT swallowed.
        with pytest.raises(asyncio.CancelledError):
            await transport.send(session, transport_module.MCPToolCallRequest(name="lookup"))


# ---------------------------------------------------------------------------
# R2 P2 #1 — cleanup failure during failed open MUST NOT mask original error
# ---------------------------------------------------------------------------


class TestOpenSessionCleanupFailureDoesNotMaskOriginal:
    """When ``open_session`` is failing AND the
    ``finally: stack.aclose()`` cleanup itself raises (e.g., a stuck
    SDK / httpx context manager raises during teardown), the cleanup
    error MUST NOT replace the original failure. Operators see the
    cleanup failure in the warning log; the caller sees the original
    ``MCPTransportError`` / ``CancelledError`` / audit-hook exception
    unchanged.

    Three original-failure classes covered, mirroring the original
    open path:

      1. wait_for timeout → ``mcp_session_open_timeout``
      2. SDK initialize raises → ``mcp_session_open_failed``
      3. caller cancellation → ``CancelledError``

    Plus a token-discipline assertion: the cleanup-failure warning
    contains ``cleanup_error_type`` only — never the cleanup
    exception's message text.
    """

    @staticmethod
    def _make_sdk_aexit_raise(monkeypatch: pytest.MonkeyPatch) -> None:
        """Patch :class:`_FakeClientSession` so its async context-manager
        exit raises during cleanup — simulates an SDK / httpx context
        that itself fails during teardown."""
        original_aexit = _FakeClientSession.__aexit__

        async def _aexit_raises(
            self: _FakeClientSession,
            exc_type: type[BaseException] | None,
            exc: BaseException | None,
            tb: object | None,
        ) -> None:
            await original_aexit(self, exc_type, exc, tb)
            raise RuntimeError("simulated SDK cleanup failure: bearer abc.def.ghi")

        monkeypatch.setattr(_FakeClientSession, "__aexit__", _aexit_raises)

    async def test_cleanup_failure_does_not_mask_session_open_timeout(
        self,
        transport_module: Any,
        fake_stream_context: _FakeStreamableContext,
        monkeypatch: pytest.MonkeyPatch,
        settings: Any,
        authz: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """wait_for timeout fires → cleanup raises during stack.aclose()
        → caller MUST still see ``mcp_session_open_timeout``."""
        import logging

        async def _hangs_forever() -> None:
            await asyncio.sleep(60)

        original_init = _FakeClientSession.__init__

        def _init_with_hanging_initialize(
            self: _FakeClientSession,
            read_stream: object,
            write_stream: object,
            read_timeout_seconds: dt.timedelta | None = None,
        ) -> None:
            original_init(self, read_stream, write_stream, read_timeout_seconds)
            self.initialize = AsyncMock(side_effect=_hangs_forever)

        monkeypatch.setattr(_FakeClientSession, "__init__", _init_with_hanging_initialize)
        self._make_sdk_aexit_raise(monkeypatch)
        settings.mcp_oauth_request_timeout_s = 0.05

        transport = transport_module.StreamableHTTPTransport(authz=authz, settings=settings)

        with (
            caplog.at_level(logging.WARNING, logger="cognic_agentos.protocol.mcp_transports"),
            pytest.raises(transport_module.MCPTransportError) as exc,
        ):
            await transport.open_session(server_url="https://server.example/mcp", token=_token())

        assert exc.value.reason == "mcp_session_open_timeout"
        # Cleanup failure logged token-free with the closed-enum field
        cleanup_warnings = [
            r.getMessage() for r in caplog.records if "cleanup_error_type" in r.getMessage()
        ]
        assert cleanup_warnings, "expected one cleanup-failure warning"
        # The cleanup exception class name appears
        assert any("cleanup_error_type=RuntimeError" in m for m in cleanup_warnings)
        # The cleanup exception MESSAGE text does NOT appear (would
        # leak transcript fragments / tokens / server-side details)
        for msg in cleanup_warnings:
            assert "simulated SDK cleanup failure" not in msg
            assert "bearer abc.def.ghi" not in msg

    async def test_cleanup_failure_does_not_mask_session_open_failed(
        self,
        transport_module: Any,
        fake_stream_context: _FakeStreamableContext,
        monkeypatch: pytest.MonkeyPatch,
        settings: Any,
        authz: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """SDK ``initialize()`` raises a generic Exception → cleanup
        raises during stack.aclose() → caller MUST still see
        ``mcp_session_open_failed``."""
        import logging

        original_init = _FakeClientSession.__init__

        def _init_with_failing_initialize(
            self: _FakeClientSession,
            read_stream: object,
            write_stream: object,
            read_timeout_seconds: dt.timedelta | None = None,
        ) -> None:
            original_init(self, read_stream, write_stream, read_timeout_seconds)
            self.initialize = AsyncMock(side_effect=RuntimeError("simulated initialize failure"))

        monkeypatch.setattr(_FakeClientSession, "__init__", _init_with_failing_initialize)
        self._make_sdk_aexit_raise(monkeypatch)

        transport = transport_module.StreamableHTTPTransport(authz=authz, settings=settings)

        with (
            caplog.at_level(logging.WARNING, logger="cognic_agentos.protocol.mcp_transports"),
            pytest.raises(transport_module.MCPTransportError) as exc,
        ):
            await transport.open_session(server_url="https://server.example/mcp", token=_token())

        # Original error class name preserved in the closed-enum payload
        assert exc.value.reason == "mcp_session_open_failed"
        assert exc.value.payload.get("error_type") == "RuntimeError"
        # Cleanup failure logged token-free
        assert any("cleanup_error_type=RuntimeError" in r.getMessage() for r in caplog.records)

    async def test_cleanup_failure_does_not_mask_cancellation(
        self,
        transport_module: Any,
        fake_stream_context: _FakeStreamableContext,
        monkeypatch: pytest.MonkeyPatch,
        settings: Any,
        authz: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Caller cancels mid-open → cleanup raises during stack.aclose()
        → caller MUST still see ``CancelledError``, NOT the cleanup
        exception. Without R2 P2 #1, the cleanup ``RuntimeError``
        would replace the cancellation that the caller's outer scope
        is waiting for."""
        import logging

        async def _hangs_forever() -> None:
            await asyncio.sleep(60)

        original_init = _FakeClientSession.__init__

        def _init_with_hanging_initialize(
            self: _FakeClientSession,
            read_stream: object,
            write_stream: object,
            read_timeout_seconds: dt.timedelta | None = None,
        ) -> None:
            original_init(self, read_stream, write_stream, read_timeout_seconds)
            self.initialize = AsyncMock(side_effect=_hangs_forever)

        monkeypatch.setattr(_FakeClientSession, "__init__", _init_with_hanging_initialize)
        self._make_sdk_aexit_raise(monkeypatch)

        transport = transport_module.StreamableHTTPTransport(authz=authz, settings=settings)
        task = asyncio.create_task(
            transport.open_session(server_url="https://server.example/mcp", token=_token())
        )
        await asyncio.sleep(0)

        task.cancel()
        with (
            caplog.at_level(logging.WARNING, logger="cognic_agentos.protocol.mcp_transports"),
            pytest.raises(asyncio.CancelledError),
        ):
            await task

        # Cleanup failure logged token-free
        assert any("cleanup_error_type=RuntimeError" in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# R2 P2 #2 — send-error hook log MUST NOT include hook exception text
# ---------------------------------------------------------------------------


class TestSendErrorHookLogNeverIncludesHookExceptionText:
    """The safe-emit wrapper :meth:`_emit_send_error_safe` logs a
    warning when the audit hook raises during send-error emission.
    Per R2 P2 #2, the warning MUST contain only fixed context fields
    + ``hook_error_type=<class name>`` — NEVER the hook exception's
    ``str()``. A broken hook can raise an exception whose message
    contains the original event payload, request details, or a
    copied bearer token; this critical-controls module's discipline
    of never propagating ``str(exc)`` into operator-visible surfaces
    applies to its own warning logs too."""

    async def test_hook_exception_message_text_not_logged_on_send_failure(
        self,
        transport_module: Any,
        fake_stream_context: _FakeStreamableContext,
        settings: Any,
        authz: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Hook raises with a secret-bearing message during send-error
        emission → caller sees ``mcp_transport_send_failed`` AND the
        warning log contains ``hook_error_type=RuntimeError`` only,
        with the secret message text scrubbed."""
        import logging

        # A realistic worst-case: a broken hook that copies the event
        # payload (or a bearer token) into its own exception message
        secret_in_hook_message = "Bearer eyJhbGciOiJIUzI1NiJ9.LEAKED-TOKEN-VALUE.sig"

        def _selective_hook(event: Any) -> None:
            if event.event_type == "send_error":
                raise RuntimeError(f"audit hook captured request payload: {secret_in_hook_message}")

        transport = transport_module.StreamableHTTPTransport(
            authz=authz,
            settings=settings,
            event_hook=_selective_hook,
        )
        session = await transport.open_session(
            server_url="https://server.example/mcp", token=_token()
        )
        session.sdk_session.call_tool = AsyncMock(
            side_effect=RuntimeError("simulated SDK send failure")
        )

        with (
            caplog.at_level(logging.WARNING, logger="cognic_agentos.protocol.mcp_transports"),
            pytest.raises(transport_module.MCPTransportError) as exc,
        ):
            await transport.send(session, transport_module.MCPToolCallRequest(name="lookup"))

        # Caller sees the closed-enum reason
        assert exc.value.reason == "mcp_transport_send_failed"

        # Exactly one warning emitted from the safe-emit wrapper
        send_warnings = [
            r.getMessage() for r in caplog.records if "hook_error_type=" in r.getMessage()
        ]
        assert send_warnings, "expected one hook-failure warning"
        for msg in send_warnings:
            # Class name only
            assert "hook_error_type=RuntimeError" in msg
            # Secret-bearing exception message MUST NOT appear
            assert secret_in_hook_message not in msg
            assert "LEAKED-TOKEN-VALUE" not in msg
            assert "audit hook captured request payload" not in msg

    async def test_hook_exception_message_text_not_logged_on_send_timeout(
        self,
        transport_module: Any,
        fake_stream_context: _FakeStreamableContext,
        settings: Any,
        authz: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Same scrubbing on the timeout path: hook raises with a
        secret message during the ``mcp_call_tool_timeout`` send-error
        emission → warning contains class name only."""
        import logging

        secret_in_hook_message = "internal-stack-trace=/var/secret/path/db.creds"

        async def _never_call_tool(**_kwargs: Any) -> None:
            await asyncio.sleep(60)

        def _selective_hook(event: Any) -> None:
            if event.event_type == "send_error":
                raise RuntimeError(f"hook crashed with: {secret_in_hook_message}")

        settings.mcp_call_tool_timeout_s = 0.001
        transport = transport_module.StreamableHTTPTransport(
            authz=authz,
            settings=settings,
            event_hook=_selective_hook,
        )
        session = await transport.open_session(
            server_url="https://server.example/mcp", token=_token()
        )
        session.sdk_session.call_tool = _never_call_tool

        with (
            caplog.at_level(logging.WARNING, logger="cognic_agentos.protocol.mcp_transports"),
            pytest.raises(transport_module.MCPTransportError) as exc,
        ):
            await transport.send(session, transport_module.MCPToolCallRequest(name="lookup"))

        assert exc.value.reason == "mcp_call_tool_timeout"

        send_warnings = [
            r.getMessage() for r in caplog.records if "hook_error_type=" in r.getMessage()
        ]
        assert send_warnings, "expected one hook-failure warning"
        for msg in send_warnings:
            assert "hook_error_type=RuntimeError" in msg
            assert secret_in_hook_message not in msg
            assert "/var/secret/path/db.creds" not in msg


# ---------------------------------------------------------------------------
# R2 grep-guard: source-level ban on ``%s``-formatting hook_exc / cleanup_exc
# ---------------------------------------------------------------------------


class TestNoExceptionStringInterpolationInWarnings:
    """Regression guard against re-introducing the R2 P2 leaks via a
    refactor that adds back ``%s`` of the hook/cleanup exception. The
    only acceptable interpolation is the class name via
    ``type(exc).__name__``.
    """

    def test_emit_send_error_safe_does_not_log_hook_exc_directly(self) -> None:
        from pathlib import Path

        src = Path("src/cognic_agentos/protocol/mcp_transports.py").read_text(encoding="utf-8")
        # The safe-emit wrapper exists
        assert "_emit_send_error_safe" in src
        # And it does NOT pass ``hook_exc`` itself (only the class
        # name) into the logger format args.
        # We allow ``type(hook_exc).__name__`` but ban bare ``hook_exc,``
        # in argument position.
        assert "type(hook_exc).__name__" in src
        assert "                hook_exc,\n" not in src, (
            "hook_exc passed as a positional logger arg — would leak "
            "the hook exception's message text. Use type(hook_exc).__name__."
        )

    def test_open_session_cleanup_does_not_log_cleanup_exc_directly(self) -> None:
        from pathlib import Path

        src = Path("src/cognic_agentos/protocol/mcp_transports.py").read_text(encoding="utf-8")
        assert "cleanup_error_type=" in src
        assert "type(cleanup_exc).__name__" in src
        assert "                        cleanup_exc,\n" not in src, (
            "cleanup_exc passed as a positional logger arg — would "
            "leak the cleanup exception's message text. Use "
            "type(cleanup_exc).__name__."
        )
