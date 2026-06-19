"""POST/GET /api/v1/mcp routes (ADR-002). Stub host + stub binder on app.state
(after lifespan startup); the route is mounted unconditionally; the request-time
dep returns 503 when the host is absent."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.protocol.mcp_authz import MCPAuthzError
from cognic_agentos.protocol.mcp_host import (
    CallResult,
    MCPToolInvocationRefused,
)
from cognic_agentos.protocol.mcp_transports import MCPTransportError

_SERVER = "pack.demo"


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Any) -> Actor:
        return self._actor


class _StubHost:
    def __init__(
        self, *, call_return: Any = None, raises: Exception | None = None, list_return: Any = None
    ) -> None:
        self._call_return = call_return
        self._raises = raises
        self._list_return = [] if list_return is None else list_return
        self.calls: list[dict[str, Any]] = []

    async def call_tool(self, **kw: Any) -> Any:
        self.calls.append(kw)
        if self._raises is not None:
            raise self._raises
        return self._call_return

    async def list_tools(self, **kw: Any) -> Any:
        self.calls.append({"op": "list", **kw})
        if self._raises is not None:
            raise self._raises
        return self._list_return


def _actor(scopes: frozenset[Any] = frozenset({"mcp.tool.list", "mcp.tool.invoke"})) -> Actor:
    return Actor(subject="svc", tenant_id="t", scopes=scopes, actor_type="service")


def _call_result(tool_name: str = "lookup") -> CallResult:
    return CallResult(
        payload={"content": "ok"},
        request_id="mcp-call-xyz",
        server_id=_SERVER,
        tool_name=tool_name,
        mcp_session_id="sess-1",
        as_issuer="https://as.example",
        scopes=("mcp:tools",),
        client_id="client-a",
    )


def _make_app(memory_settings: Any, memory_registry: Any, tmp_path: Any) -> Any:
    cfg = tmp_path / "litellm.yaml"
    cfg.write_text(
        "model_list:\n  - model_name: cognic-tier1-dev\n"
        "    litellm_params:\n      model: ollama/qwen\n"
        "      api_base: http://localhost:11434\n"
    )
    return create_app(
        memory_settings.model_copy(update={"litellm_config_path": cfg, "cache_driver": "memory"}),
        adapter_registry=memory_registry,
    )


def _call(
    memory_settings: Any,
    memory_registry: Any,
    tmp_path: Any,
    *,
    host: Any,
    actor: Actor | None = None,
    json: dict[str, Any] | None = None,
) -> Any:
    """POST .../tools/call. The stubs are set AFTER lifespan startup (so they
    survive any pre-seed) and the request is made INSIDE the with-block so the
    lifespan shutdown runs cleanly on exit (the test_run_routes.py pattern)."""
    app = _make_app(memory_settings, memory_registry, tmp_path)
    with TestClient(app) as client:
        app.state.actor_binder = _StubBinder(actor if actor is not None else _actor())
        app.state.mcp_host = host
        return client.post(
            f"/api/v1/mcp/servers/{_SERVER}/tools/call", json=json or {"tool_name": "lookup"}
        )


def _list(
    memory_settings: Any,
    memory_registry: Any,
    tmp_path: Any,
    *,
    host: Any,
    actor: Actor | None = None,
) -> Any:
    """GET .../tools — same harness as _call (with-block, clean shutdown)."""
    app = _make_app(memory_settings, memory_registry, tmp_path)
    with TestClient(app) as client:
        app.state.actor_binder = _StubBinder(actor if actor is not None else _actor())
        app.state.mcp_host = host
        return client.get(f"/api/v1/mcp/servers/{_SERVER}/tools")


def test_list_success(memory_settings: Any, memory_registry: Any, tmp_path: Any) -> None:
    host = _StubHost(list_return=[{"name": "lookup"}])
    r = _list(memory_settings, memory_registry, tmp_path, host=host)
    assert r.status_code == 200
    assert r.json() == {"tools": [{"name": "lookup"}]}


def test_call_success(memory_settings: Any, memory_registry: Any, tmp_path: Any) -> None:
    host = _StubHost(call_return=_call_result())
    r = _call(memory_settings, memory_registry, tmp_path, host=host)
    assert r.status_code == 200
    body = r.json()
    assert body["payload"] == {"content": "ok"}
    assert body["server_id"] == _SERVER


def test_call_pending_returns_202_with_approval_request_id(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    rid = str(uuid.uuid4())
    host = _StubHost(
        raises=MCPToolInvocationRefused("tool_approval_pending", approval_request_id=rid)
    )
    r = _call(memory_settings, memory_registry, tmp_path, host=host, json={"tool_name": "pay"})
    assert r.status_code == 202
    assert r.json()["detail"]["reason"] == "tool_approval_pending"
    assert r.json()["detail"]["approval_request_id"] == rid


def test_call_recall_threads_approval_request_id(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    host = _StubHost(call_return=_call_result())
    rid = str(uuid.uuid4())
    r = _call(
        memory_settings,
        memory_registry,
        tmp_path,
        host=host,
        json={"tool_name": "pay", "approval_request_id": rid},
    )
    assert r.status_code == 200
    assert str(host.calls[0]["approval_request_id"]) == rid
    # tenant + originator come from the actor, not the body.
    assert host.calls[0]["tenant_id"] == "t"
    assert host.calls[0]["originator_subject"] == "svc"


@pytest.mark.parametrize(
    ("exc", "status"),
    [
        (MCPToolInvocationRefused("tool_approval_denied"), 403),
        (MCPToolInvocationRefused("tool_approval_engine_not_available"), 403),
        (MCPToolInvocationRefused("tool_approval_expired"), 409),
        (MCPToolInvocationRefused("tool_approval_binding_mismatch"), 409),
        (MCPToolInvocationRefused("tool_approval_request_not_found"), 409),
        (MCPTransportError("mcp_call_tool_timeout"), 504),
        (MCPTransportError("mcp_session_open_timeout"), 504),
        (MCPTransportError("mcp_transport_send_failed"), 502),
        (MCPTransportError("mcp_session_open_failed"), 502),
        (MCPAuthzError("mcp_oauth_request_timeout"), 504),
        (MCPAuthzError("mcp_as_not_allowlisted"), 502),
        (MCPAuthzError("mcp_authorisation_lost"), 502),
        (LookupError("unknown server"), 404),
    ],
)
def test_call_status_mapping(
    memory_settings: Any, memory_registry: Any, tmp_path: Any, exc: Exception, status: int
) -> None:
    r = _call(memory_settings, memory_registry, tmp_path, host=_StubHost(raises=exc))
    assert r.status_code == status


def test_call_generic_exception_maps_502(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    # The catch-all: any non-typed error (here a bare RuntimeError, as call_tool
    # re-raises its generic-Exception path) maps to 502 mcp_orchestrator_error.
    r = _call(
        memory_settings, memory_registry, tmp_path, host=_StubHost(raises=RuntimeError("boom"))
    )
    assert r.status_code == 502
    assert r.json()["detail"]["reason"] == "mcp_orchestrator_error"


@pytest.mark.parametrize(
    ("exc", "status"),
    [
        (LookupError("unknown server"), 404),
        (MCPTransportError("mcp_session_open_timeout"), 504),
        (MCPTransportError("mcp_transport_send_failed"), 502),
        (MCPAuthzError("mcp_as_not_allowlisted"), 502),
        (RuntimeError("boom"), 502),
    ],
)
def test_list_status_mapping(
    memory_settings: Any, memory_registry: Any, tmp_path: Any, exc: Exception, status: int
) -> None:
    # The GET list route maps the same exception classes (no approval path).
    r = _list(memory_settings, memory_registry, tmp_path, host=_StubHost(raises=exc))
    assert r.status_code == status
    if status == 502 and isinstance(exc, RuntimeError):
        assert r.json()["detail"]["reason"] == "mcp_orchestrator_error"


def test_list_scope_miss_returns_403(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    # An actor without mcp.tool.list -> RequireScope refuses 403 on the GET route.
    r = _list(
        memory_settings, memory_registry, tmp_path, host=_StubHost(), actor=_actor(frozenset())
    )
    assert r.status_code == 403


def test_no_host_returns_503(memory_settings: Any, memory_registry: Any, tmp_path: Any) -> None:
    r = _call(memory_settings, memory_registry, tmp_path, host=None)
    assert r.status_code == 503
    assert r.json()["detail"]["reason"] == "mcp_host_unavailable"


def test_scope_miss_returns_403(memory_settings: Any, memory_registry: Any, tmp_path: Any) -> None:
    # An actor without mcp.tool.invoke -> RequireScope refuses 403 on the POST route.
    r = _call(
        memory_settings,
        memory_registry,
        tmp_path,
        host=_StubHost(call_return=_call_result()),
        actor=_actor(frozenset()),
    )
    assert r.status_code == 403


def test_request_id_minted_and_bounded(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    host = _StubHost(call_return=_call_result())
    _call(memory_settings, memory_registry, tmp_path, host=host)
    rid = host.calls[0]["request_id"]
    assert rid.startswith("mcp-call-")
    assert len(rid) <= 64


def test_tool_name_raw_preserved(memory_settings: Any, memory_registry: Any, tmp_path: Any) -> None:
    host = _StubHost(call_return=_call_result())
    raw = "look\tup\n; rm -rf"
    _call(memory_settings, memory_registry, tmp_path, host=host, json={"tool_name": raw})
    assert host.calls[0]["tool_name"] == raw  # never sanitized / path-encoded


def test_timeout_reasons_are_subset_of_live_enums() -> None:
    from typing import get_args

    from cognic_agentos.portal.api.mcp.routes import _TIMEOUT_REASONS
    from cognic_agentos.protocol.mcp_authz import AuthzReason
    from cognic_agentos.protocol.mcp_transports import MCPTransportReason

    live = set(get_args(MCPTransportReason)) | set(get_args(AuthzReason))
    assert _TIMEOUT_REASONS.issubset(live)  # a renamed/removed timeout reason fails here
