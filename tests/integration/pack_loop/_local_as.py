# tests/integration/pack_loop/_local_as.py
"""A tiny localhost OAuth2 client-credentials authorization server for Proof 1a.

Serves exactly what MCPAuthzClient needs:
  - GET /.well-known/oauth-authorization-server -> {"token_endpoint": ".../token"}
  - POST /token (grant_type=client_credentials) -> {"access_token","expires_in","scope"}

The access token is a simple JWT (3-part header.payload.signature) whose payload
carries `aud = <resource>` — the RFC 8707 `resource` form parameter, which is the
MCP `server_url`. The runtime DECODES it and exercises audience validation
(`aud == server_url`). The signature part is decorative: AgentOS does NOT verify
the AS signature here (the AS is trusted via the per-tenant allow-list); it
validates the `aud` claim. The granted scope echoes the requested scope so it is
a subset of the manifest scopes (no overgrant).
"""

from __future__ import annotations

import base64
import json
import os

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

_AS_ISSUER = os.environ.get("COGNIC_PROOF_AS_ISSUER", "http://127.0.0.1:9000")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


async def _metadata(_request: Request) -> JSONResponse:
    return JSONResponse({"token_endpoint": f"{_AS_ISSUER}/token", "issuer": _AS_ISSUER})


async def _token(request: Request) -> JSONResponse:
    form = await request.form()
    requested_scope = str(form.get("scope", "mcp:tools"))
    resource = str(form.get("resource", ""))  # RFC 8707 resource indicator == server_url
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode("utf-8"))
    payload = _b64url(json.dumps({"aud": resource, "scope": requested_scope}).encode("utf-8"))
    access_token = f"{header}.{payload}.sig"
    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": requested_scope,
        }
    )


def build_app() -> Starlette:
    return Starlette(
        routes=[
            Route("/.well-known/oauth-authorization-server", _metadata, methods=["GET"]),
            Route("/token", _token, methods=["POST"]),
        ]
    )


def run_local_as(*, port: int = 9000) -> None:
    uvicorn.run(
        build_app(),
        host=os.environ.get("COGNIC_PROOF_AS_HOST", "127.0.0.1"),
        port=port,
        log_level="warning",
    )


if __name__ == "__main__":
    run_local_as(port=int(os.environ.get("COGNIC_PROOF_AS_PORT", "9000")))
