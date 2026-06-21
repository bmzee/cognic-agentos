"""POST /api/v1/a2a/{target_agent} — the A2A inbound receiver (ADR-003).

A dumb raw-body adapter around A2AEndpoint.handle(): the A2A pinned token is
the auth axis (validated inside handle(), NOT portal RBAC). Mounted
UNCONDITIONALLY; the request-time dep returns 503 until the SDK-gated lifespan
populates app.state.a2a_endpoint. `from __future__ import annotations` OMITTED.
"""

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from cognic_agentos.protocol import a2a_errors
from cognic_agentos.protocol.a2a_endpoint import A2AEndpoint, A2AEndpointError

#: Wave-1 tenant source. Host-based tenancy is a later swap of THIS function
#: only (handle()/route contract untouched). The claimed tenant is not trusted:
#: A2AAuthzClient validates the token against it; a forged claim is refused.
_TENANT_HEADER = "X-Cognic-Tenant"
_PARENT_TRACE_HEADER = "X-Cognic-Parent-Trace-Id"


def resolve_a2a_tenant(request: Request) -> str | None:
    return (request.headers.get(_TENANT_HEADER) or "").strip() or None


def _require_a2a_endpoint(request: Request) -> A2AEndpoint:
    endpoint: A2AEndpoint | None = getattr(request.app.state, "a2a_endpoint", None)
    if endpoint is None:
        raise HTTPException(status_code=503, detail={"reason": "a2a_endpoint_unavailable"})
    return endpoint


def build_a2a_routes() -> APIRouter:
    router = APIRouter()

    @router.post("/{target_agent}")
    async def receive_a2a(
        target_agent: str,
        request: Request,
        response: Response,
        endpoint: Annotated[A2AEndpoint, Depends(_require_a2a_endpoint)],
    ) -> dict[str, Any]:
        request_id = uuid.uuid4().hex
        tenant_id = resolve_a2a_tenant(request)
        if tenant_id is None:
            err = a2a_errors.from_policy_reason(
                "tenant_header_missing",
                message="missing or empty X-Cognic-Tenant header",
            )
            response.status_code = err.http_status
            return err.to_jsonrpc(jsonrpc_id=None)
        raw = await request.body()
        try:
            result = await endpoint.handle(
                target_agent=target_agent,
                payload=raw,
                authorization_header=request.headers.get("Authorization"),
                a2a_version_header=request.headers.get("A2A-Version"),
                parent_trace_id=request.headers.get(_PARENT_TRACE_HEADER),
                tenant_id=tenant_id,
                request_id=request_id,
            )
        except A2AEndpointError as exc:
            err = a2a_errors.from_endpoint_error(exc)
            response.status_code = err.http_status
            return err.to_jsonrpc(jsonrpc_id=None)
        response.status_code = 200
        return result

    return router
