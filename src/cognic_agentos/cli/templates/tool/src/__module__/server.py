"""Streamable-HTTP MCP server for {{ pack_id }} (FastMCP).

Resource-server OAuth mode: passing `auth` + `token_verifier` makes FastMCP
auto-publish Protected Resource Metadata and wrap /mcp with bearer auth.

AUTHOR-FILL: implement a real JWT/JWKS TokenVerifier (issuer / signature /
expiry / audience / scope) and run with COGNIC_AUTH_MODE=jwt before production.
The shipped DevTokenVerifier is dev-only and fails closed unless
COGNIC_AUTH_MODE=dev_insecure + COGNIC_ENV=dev.
"""

from __future__ import annotations

import os

from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from pydantic import AnyHttpUrl

_HOST = os.environ.get("COGNIC_MCP_HOST", "127.0.0.1")
_PORT = int(os.environ.get("COGNIC_MCP_PORT", "8765"))
_SERVER_URL = os.environ.get("COGNIC_MCP_SERVER_URL", "http://127.0.0.1:8765/mcp")
_REQUIRED_SCOPES = ["mcp:tools"]  # AUTHOR-FILL: your pack's required scopes


class DevTokenVerifier(TokenVerifier):
    """DEV-ONLY verifier — accepts any non-empty bearer and binds it to this
    resource. Reachable ONLY via COGNIC_AUTH_MODE=dev_insecure + COGNIC_ENV=dev
    (see _select_token_verifier). Production packs implement a real JWT/JWKS
    verifier and run with COGNIC_AUTH_MODE=jwt (see the cognic-tool-oracle-schema
    pack for a worked example)."""

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token:
            return None
        return AccessToken(
            token=token,
            client_id="{{ pack_id }}",
            scopes=list(_REQUIRED_SCOPES),
            expires_at=None,
            resource=_SERVER_URL,
        )


def _select_token_verifier() -> TokenVerifier:
    """Fail-closed verifier selection. COGNIC_AUTH_MODE defaults to 'jwt'; the
    scaffold ships NO real jwt verifier, so the default path raises with
    remediation. The permissive DevTokenVerifier is reachable ONLY via
    COGNIC_AUTH_MODE=dev_insecure AND COGNIC_ENV=dev."""
    mode = os.environ.get("COGNIC_AUTH_MODE", "jwt")
    if mode == "dev_insecure":
        if os.environ.get("COGNIC_ENV") != "dev":
            raise RuntimeError(
                "COGNIC_AUTH_MODE=dev_insecure requires COGNIC_ENV=dev; refusing "
                "to start a permissive verifier outside dev."
            )
        return DevTokenVerifier()
    raise RuntimeError(
        "AUTHOR-FILL: implement a real JWT/JWKS TokenVerifier for "
        "COGNIC_AUTH_MODE=jwt (validate issuer / signature / expiry / audience / "
        "scope; see the cognic-tool-oracle-schema pack), or run locally with "
        "COGNIC_AUTH_MODE=dev_insecure COGNIC_ENV=dev."
    )


def build_server(*, as_issuer: str) -> FastMCP:
    mcp = FastMCP(
        "{{ pack_id }}",
        host=_HOST,
        port=_PORT,
        streamable_http_path="/mcp",
        json_response=False,
        stateless_http=False,
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(as_issuer),
            resource_server_url=AnyHttpUrl(_SERVER_URL),
            required_scopes=list(_REQUIRED_SCOPES),
        ),
        token_verifier=_select_token_verifier(),
    )

    @mcp.tool(name="ping", description="AUTHOR-FILL: replace with your tool. Returns 'pong'.")
    def ping() -> str:
        return "pong"

    return mcp


if __name__ == "__main__":
    build_server(
        as_issuer=os.environ.get("COGNIC_MCP_AS_ISSUER", "http://127.0.0.1:9000")
    ).run(transport="streamable-http")
