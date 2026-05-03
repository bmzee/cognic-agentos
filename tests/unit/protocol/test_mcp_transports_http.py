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
        sorted(
            {
                "mcp_session_open_timeout",
                "mcp_session_open_failed",
                "mcp_call_tool_timeout",
                "mcp_transport_send_failed",
                "mcp_session_close_failed",
                "mcp_session_closed",
            }
        ),
    )
    def test_every_reason_has_a_dedicated_test_arm(self, reason: str) -> None:
        """Every value of :data:`MCPTransportReason` MUST appear in
        an assertion target somewhere in this test file. The same
        file-walk pattern the cross-sprint
        ``test_refusal_reason_completeness.py`` uses; here scoped
        to just this file because the transport vocabulary is
        runtime-only and not part of the registration RefusalReason
        cross-sprint vocabulary.
        """
        from pathlib import Path

        this_file = Path(__file__)
        text = this_file.read_text(encoding="utf-8")
        # The reason MUST appear at least twice — once in the
        # EXPECTED_REASONS set above (for the literal-match drift
        # detector) AND once in an actual error / event assertion
        # downstream. The 2-hit floor catches "reason added to set
        # but never raised by code under test".
        hits = text.count(f'"{reason}"')
        assert hits >= 2, (
            f"MCPTransportReason {reason!r} appears only {hits} time(s) "
            f"in this test file. Expected at least 2 — once in "
            f"EXPECTED_REASONS and once in an exc.value.reason or "
            f"event.reason assertion that exercises the code path."
        )
