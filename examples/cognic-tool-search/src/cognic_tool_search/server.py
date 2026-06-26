# examples/cognic-tool-search/src/cognic_tool_search/server.py
"""Streamable-HTTP MCP server for cognic-tool-search (mcp SDK 1.27.0 FastMCP).

Resource-server-only OAuth mode: passing `auth` + `token_verifier` (and no
auth_server_provider) makes FastMCP auto-publish Protected Resource Metadata at
/.well-known/oauth-protected-resource/mcp and wrap /mcp with bearer auth. The
LocalTokenVerifier accepts tokens minted by the Proof 1a local authorization
server; it binds the resource (audience) to server_url and the granted scope to
a subset of {mcp:tools}.
"""

from __future__ import annotations

import os

from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from pydantic import AnyHttpUrl

from cognic_tool_search.corpus_loader import load_corpus, search

_HOST = os.environ.get("COGNIC_PROOF_HOST", "127.0.0.1")
_PORT = 8765
_SERVER_URL = os.environ.get("COGNIC_PROOF_SERVER_URL", "http://127.0.0.1:8765/mcp")
_REQUIRED_SCOPES = ["mcp:tools"]


class LocalTokenVerifier(TokenVerifier):
    """Accepts any non-empty bearer token from the trusted local AS and binds it
    to this resource + the required scopes. The Proof 1a harness is the only
    caller; the AS allow-list + OAuth client creds are enforced upstream by the
    AgentOS MCPAuthzClient before a token ever reaches here."""

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token:
            return None
        return AccessToken(
            token=token,
            client_id="cognic-tool-search-proof",
            scopes=list(_REQUIRED_SCOPES),
            expires_at=None,
            resource=_SERVER_URL,
        )


def build_server(*, as_issuer: str) -> FastMCP:
    mcp = FastMCP(
        "cognic-tool-search",
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
        token_verifier=LocalTokenVerifier(),
    )

    _corpus = load_corpus()

    @mcp.tool(name="search_policy_docs", description="Search the bundled static policy-doc corpus.")
    def search_policy_docs(query: str) -> list[dict[str, str]]:
        return search(_corpus, query)

    return mcp


if __name__ == "__main__":
    import os

    build_server(as_issuer=os.environ.get("COGNIC_PROOF_AS_ISSUER", "http://127.0.0.1:9000")).run(
        transport="streamable-http"
    )
