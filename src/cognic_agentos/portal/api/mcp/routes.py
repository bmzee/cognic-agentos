"""MCP tool-invocation portal route — the production caller of MCPHost
(ADR-002 "Fork D" + ADR-014). Mounted UNCONDITIONALLY; the request-time
``_require_mcp_host`` dep returns 503 when ``app.state.mcp_host`` is None (the
``mcp`` SDK is absent / construction failed). Live-exercises ``call_tool`` +
``list_tools`` + the approval seam.

``from __future__ import annotations`` is INTENTIONALLY OMITTED so FastAPI can
resolve the closure-local ``Depends(...)`` annotations eagerly. The MCPHost
exception classes import SDK-free (``require_mcp`` is constructor-only), so this
module is kernel-image-clean.
"""

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from cognic_agentos.portal.api.mcp.dto import (
    CallToolRequest,
    CallToolResponse,
    ListToolsResponse,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope
from cognic_agentos.protocol.mcp_authz import MCPAuthzError
from cognic_agentos.protocol.mcp_host import (
    CallResult,
    MCPHost,
    MCPToolInvocationRefused,
)
from cognic_agentos.protocol.mcp_transports import MCPTransportError

#: ``MCPToolInvocationRefused.reason`` -> HTTP status. The 6-value enum is
#: wire-public + drift-pinned at its definition; this map consumes it.
#: 202 = approval pending (the body adds approval_request_id); 403 = terminal
#: forbidden (denied / no-engine); 409 = re-request conflicts.
_REFUSAL_STATUS: dict[str, int] = {
    "tool_approval_pending": 202,
    "tool_approval_denied": 403,
    "tool_approval_engine_not_available": 403,
    "tool_approval_expired": 409,
    "tool_approval_binding_mismatch": 409,
    "tool_approval_request_not_found": 409,
}

#: Transport/authz reasons that map to 504 (gateway timeout). EVERY OTHER
#: MCPTransportError / MCPAuthzError reason maps to 502 (bad gateway) — so a
#: future non-timeout reason is a DELIBERATE 502, never a leaked 500. Pinned
#: against the live MCPTransportReason + AuthzReason enums in the route tests.
_TIMEOUT_REASONS: frozenset[str] = frozenset(
    {"mcp_call_tool_timeout", "mcp_session_open_timeout", "mcp_oauth_request_timeout"}
)

#: Server-minted request-id prefixes. len(prefix) + 32 (uuid4 hex) <= 64 (the
#: decision_history.request_id String(64) cap). Asserted at module foot.
_CALL_REQUEST_ID_PREFIX = "mcp-call-"
_LIST_REQUEST_ID_PREFIX = "mcp-list-"


def _require_mcp_host(request: Request) -> MCPHost:
    host: MCPHost | None = getattr(request.app.state, "mcp_host", None)
    if host is None:
        raise HTTPException(status_code=503, detail={"reason": "mcp_host_unavailable"})
    return host


def _mint_request_id(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex}"


def _transport_status(reason: str) -> int:
    return 504 if reason in _TIMEOUT_REASONS else 502


def _call_result_to_response(result: CallResult) -> CallToolResponse:
    return CallToolResponse(
        payload=result.payload,
        request_id=result.request_id,
        server_id=result.server_id,
        tool_name=result.tool_name,
        mcp_session_id=result.mcp_session_id,
        as_issuer=result.as_issuer,
        scopes=list(result.scopes),
        client_id=result.client_id,
    )


def build_mcp_routes() -> APIRouter:
    router = APIRouter()
    _require_list = RequireScope("mcp.tool.list")
    _require_invoke = RequireScope("mcp.tool.invoke")

    @router.get("/servers/{server_id}/tools", response_model=ListToolsResponse)
    async def list_tools(
        server_id: str,
        actor: Annotated[Actor, Depends(_require_list)],
        host: Annotated[MCPHost, Depends(_require_mcp_host)],
    ) -> ListToolsResponse:
        try:
            tools = await host.list_tools(
                server_id=server_id,
                request_id=_mint_request_id(_LIST_REQUEST_ID_PREFIX),
                tenant_id=actor.tenant_id,
            )
        except LookupError:
            raise HTTPException(status_code=404, detail={"reason": "server_not_found"}) from None
        except (MCPTransportError, MCPAuthzError) as exc:
            raise HTTPException(
                status_code=_transport_status(exc.reason), detail={"reason": exc.reason}
            ) from None
        except Exception:
            # LAST arm (the specific types win first). A generic host-call failure
            # maps to a DELIBERATE 502, never a leaked 500 (the spec's
            # mcp_orchestrator_error row). The repo does not enable ruff BLE001.
            raise HTTPException(
                status_code=502, detail={"reason": "mcp_orchestrator_error"}
            ) from None
        return ListToolsResponse(tools=list(tools))

    @router.post("/servers/{server_id}/tools/call", response_model=CallToolResponse)
    async def call_tool(
        server_id: str,
        body: CallToolRequest,
        response: Response,
        actor: Annotated[Actor, Depends(_require_invoke)],
        host: Annotated[MCPHost, Depends(_require_mcp_host)],
    ) -> CallToolResponse:
        try:
            result = await host.call_tool(
                server_id=server_id,
                tool_name=body.tool_name,
                arguments=body.arguments,
                request_id=_mint_request_id(_CALL_REQUEST_ID_PREFIX),
                tenant_id=actor.tenant_id,
                originator_subject=actor.subject,
                approval_request_id=body.approval_request_id,
            )
        except LookupError:
            raise HTTPException(status_code=404, detail={"reason": "server_not_found"}) from None
        except MCPToolInvocationRefused as exc:
            detail: dict[str, Any] = {"reason": exc.reason}
            if exc.reason == "tool_approval_pending":
                detail["approval_request_id"] = exc.payload.get("approval_request_id")
            raise HTTPException(status_code=_REFUSAL_STATUS[exc.reason], detail=detail) from None
        except (MCPTransportError, MCPAuthzError) as exc:
            raise HTTPException(
                status_code=_transport_status(exc.reason), detail={"reason": exc.reason}
            ) from None
        except Exception:
            # LAST arm — MCPToolInvocationRefused is an Exception subclass, so the
            # specific arms above MUST precede this. call_tool re-raises generic
            # errors after auditing them; map to a DELIBERATE 502, never a leaked
            # 500 (the spec's mcp_orchestrator_error row). Repo has no ruff BLE001.
            raise HTTPException(
                status_code=502, detail={"reason": "mcp_orchestrator_error"}
            ) from None
        return _call_result_to_response(result)

    return router


# Module-foot bounded-request-id invariant (the decision_history.request_id String(64) cap).
assert len(_CALL_REQUEST_ID_PREFIX) + 32 <= 64
assert len(_LIST_REQUEST_ID_PREFIX) + 32 <= 64
