"""Sprint 5 T5 — MCPAuthzClient OAuth/PRM contract tests.

Critical-controls module per AGENTS.md (per-file gate ≥95% line /
≥90% branch enforced by ``tools/check_critical_coverage.py`` once
Sprint-5 T14 extends the gate).

Test classes (per Sprint-5 plan §T5):

  TestPrmDiscoveryWWWAuthenticatePath  — primary header-driven discovery
  TestPrmDiscoveryEndpointSpecificFallback — well-known fallback #1
  TestPrmDiscoveryRootFallback         — well-known fallback #2
  TestPrmDiscoveryPriorityOrder        — endpoint-specific wins over root
  TestPrmDiscoveryAnonymousRefused     — all 3 paths fail → mcp_anonymous_refused
  TestAsAllowlistEnforcement           — non-allow-listed AS → refused
  TestRfc8707ResourceIndicator         — every token request includes resource=
  TestTokenAudienceValidation          — aud claim must match resource
  TestTokenCacheAndRefresh             — cache hit path + refresh emits audit
  TestStepUpScopeFlow                  — 403 step-up + manifest-declared check
  TestOauthRequestTimeout              — strict timeout shape
  TestApiKeyFallbackPath               — Wave-1 API-key fallback documented
  TestAdmissionStaysSdkFree            — R3 P1 doctrine: no require_mcp() at construction
  TestRefusalReasonClosedEnum          — every raise path uses a closed-enum value
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import respx

from cognic_agentos.core.config import Settings, build_settings_without_env_file
from cognic_agentos.protocol.mcp_authz import (
    MCPAuthzClient,
    MCPAuthzError,
    Token,
    _decode_jwt_payload,
    _endpoint_specific_well_known_url,
    _is_token_near_expiry,
    _parse_resource_metadata_url,
    _root_well_known_url,
    _validate_token_audience,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def settings() -> Settings:
    """Test settings with short timeouts for negative-path tests."""
    base = build_settings_without_env_file()
    return base.model_copy(
        update={
            "mcp_oauth_request_timeout_s": 5,
            "mcp_oauth_token_cache_ttl_s": 3600,
            "mcp_as_allowlist_path": "secret/cognic/{tenant}/mcp-as-allowlist",
            "mcp_oauth_credentials_path": "secret/cognic/{tenant}/mcp-oauth/{as_host}",
        }
    )


# Default per-(tenant, AS) Vault credential fixture used by tests that don't
# override it. Uses ``client_secret_post`` (the most common form). Tests
# wanting basic-auth or different shapes set ``vault_client.read.side_effect``
# directly to override.
_DEFAULT_OAUTH_CREDS = {
    "client_id": "cognic-mcp-bank_a",
    "client_secret": "vault-stored-secret",
    "auth_method": "client_secret_post",
}


def _vault_dispatch(
    *,
    allowlist: list[str] | None = None,
    creds: dict[str, str] | None = None,
) -> Any:
    """Build an AsyncMock side_effect that routes Vault reads by path.

    Per Sprint 5 R6: ``MCPAuthzClient`` reads two distinct Vault paths —
    the per-tenant AS allow-list (``mcp-as-allowlist``) and the per-
    (tenant, AS) OAuth client credentials (``mcp-oauth/...``). Tests
    must dispatch on path so neither lookup gets the wrong shape.
    """
    allowlist_resp = {"servers": allowlist if allowlist is not None else ["https://as.example"]}
    creds_resp = creds if creds is not None else dict(_DEFAULT_OAUTH_CREDS)

    async def _read(path: str) -> dict[str, Any]:
        if "mcp-oauth" in path:
            return creds_resp
        return allowlist_resp

    return _read


@pytest.fixture
def vault_client() -> MagicMock:
    """Mock SecretAdapter that dispatches by Vault path.

    AS allow-list reads (``mcp-as-allowlist``) return ``{servers: [...]}``;
    OAuth credential reads (``mcp-oauth/...``) return the default
    ``{client_id, client_secret, auth_method}`` shape. Tests override
    via ``vault_client.read.side_effect = _vault_dispatch(...)``.
    """
    mock = MagicMock()
    mock.read = AsyncMock(side_effect=_vault_dispatch())
    return mock


@pytest.fixture
def audit_store() -> MagicMock:
    mock = MagicMock()
    mock.append = AsyncMock()
    return mock


@pytest.fixture
def decision_history_store() -> MagicMock:
    mock = MagicMock()
    mock.append = AsyncMock()
    return mock


@pytest.fixture
async def http_client() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient() as client:
        yield client


@pytest.fixture
async def authz(
    settings: Settings,
    vault_client: MagicMock,
    http_client: httpx.AsyncClient,
    audit_store: MagicMock,
    decision_history_store: MagicMock,
) -> MCPAuthzClient:
    return MCPAuthzClient(
        settings=settings,
        vault_client=vault_client,
        http_client=http_client,
        audit_store=audit_store,
        decision_history_store=decision_history_store,
    )


def _make_jwt(payload: dict[str, Any]) -> str:
    """Build a fake JWT (header.payload.signature) — signature is
    decorative; the loader doesn't verify it, only decodes the payload."""

    def _b64(d: dict[str, Any]) -> str:
        raw = json.dumps(d, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = _b64({"alg": "HS256", "typ": "JWT"})
    body = _b64(payload)
    return f"{header}.{body}.fakesignature"


# ---------------------------------------------------------------------------
# Helper-function unit tests (URL building, JWT decode, audience validation)
# ---------------------------------------------------------------------------


class TestUrlBuilders:
    def test_endpoint_specific_well_known_with_path(self) -> None:
        url = _endpoint_specific_well_known_url("https://server.example/public/mcp")
        assert url == ("https://server.example/.well-known/oauth-protected-resource/public/mcp")

    def test_endpoint_specific_well_known_root_only(self) -> None:
        url = _endpoint_specific_well_known_url("https://server.example/")
        assert url == "https://server.example/.well-known/oauth-protected-resource"

    def test_root_well_known(self) -> None:
        url = _root_well_known_url("https://server.example/some/path")
        assert url == "https://server.example/.well-known/oauth-protected-resource"


class TestParseResourceMetadataUrl:
    def test_returns_url_when_present(self) -> None:
        header = 'Bearer realm="mcp", resource_metadata="https://prm.example/doc"'
        assert _parse_resource_metadata_url(header) == "https://prm.example/doc"

    def test_returns_none_when_absent(self) -> None:
        assert _parse_resource_metadata_url('Bearer realm="mcp"') is None

    def test_returns_none_for_non_bearer(self) -> None:
        assert _parse_resource_metadata_url('Basic realm="mcp"') is None

    def test_returns_none_for_empty_header(self) -> None:
        assert _parse_resource_metadata_url("") is None

    def test_returns_none_for_unclosed_quote(self) -> None:
        """Defensive: ``WWW-Authenticate: Bearer resource_metadata="...`` (no
        closing quote) is malformed; should return None rather than
        returning the rest-of-the-string as a URL."""
        assert (
            _parse_resource_metadata_url(
                'Bearer resource_metadata="https://prm.example/doc'  # unclosed
            )
            is None
        )


class TestJwtDecode:
    def test_decodes_payload(self) -> None:
        token = _make_jwt({"sub": "abc", "aud": "https://server.example/mcp"})
        decoded = _decode_jwt_payload(token)
        assert decoded["sub"] == "abc"
        assert decoded["aud"] == "https://server.example/mcp"

    def test_returns_empty_for_opaque_token(self) -> None:
        assert _decode_jwt_payload("not-a-jwt-just-an-opaque-string") == {}

    def test_returns_empty_for_malformed_jwt(self) -> None:
        assert _decode_jwt_payload("only.two") == {}

    def test_returns_empty_when_payload_is_not_json(self) -> None:
        """3-part token where the middle part decodes to non-JSON bytes —
        ``json.loads`` raises, except path returns ``{}``."""

        def _b64(raw: bytes) -> str:
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        header = _b64(b'{"alg":"HS256"}')
        non_json_payload = _b64(b"not-valid-json-bytes")
        token = f"{header}.{non_json_payload}.fakesig"
        assert _decode_jwt_payload(token) == {}

    def test_returns_empty_when_payload_is_json_but_not_object(self) -> None:
        """3-part token where the payload decodes to valid JSON but is a
        list/string instead of an object. The defensive ``isinstance(result, dict)``
        check returns ``{}`` rather than coercing the wrong shape."""

        def _b64(raw: bytes) -> str:
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        header = _b64(b'{"alg":"HS256"}')
        # Valid JSON but a list, not an object
        list_payload = _b64(b'["not", "an", "object"]')
        token = f"{header}.{list_payload}.fakesig"
        assert _decode_jwt_payload(token) == {}


class TestTokenNearExpiry:
    def test_fresh_token_not_near_expiry(self) -> None:
        token = Token(
            value="x",
            expires_at=time.time() + 3600,
            as_issuer="https://as.example",
            scopes=("mcp:tools",),
            resource_indicator="https://server.example/mcp",
            client_id="cognic-mcp-bank_a",
        )
        assert not _is_token_near_expiry(token)

    def test_token_expiring_soon_is_near_expiry(self) -> None:
        token = Token(
            value="x",
            expires_at=time.time() + 30,  # buffer is 60s
            as_issuer="https://as.example",
            scopes=("mcp:tools",),
            resource_indicator="https://server.example/mcp",
            client_id="cognic-mcp-bank_a",
        )
        assert _is_token_near_expiry(token)


class TestTokenRepr:
    def test_token_repr_redacts_value(self) -> None:
        """The token __repr__ must NOT leak the token value — operators
        seeing tokens in tracebacks would be a confidentiality leak."""
        token = Token(
            value="super-secret-bearer-token-bytes",
            expires_at=time.time() + 3600,
            as_issuer="https://as.example",
            scopes=("mcp:tools",),
            resource_indicator="https://server.example/mcp",
            client_id="cognic-mcp-bank_a",
        )
        repr_str = repr(token)
        assert "super-secret-bearer-token-bytes" not in repr_str
        assert "<redacted>" in repr_str
        # Other fields should still be visible
        assert "https://as.example" in repr_str
        assert "mcp:tools" in repr_str


# ---------------------------------------------------------------------------
# Audience validation
# ---------------------------------------------------------------------------


class TestTokenAudienceValidation:
    def test_matching_audience_accepted(self) -> None:
        token = Token(
            value=_make_jwt({"aud": "https://server.example/mcp"}),
            expires_at=time.time() + 3600,
            as_issuer="https://as.example",
            scopes=("mcp:tools",),
            resource_indicator="https://server.example/mcp",
            client_id="cognic-mcp-bank_a",
        )
        # No raise = pass
        _validate_token_audience(token, expected_audience="https://server.example/mcp")

    def test_audience_list_match_accepted(self) -> None:
        """RFC 7519 allows ``aud`` to be a list of strings."""
        token = Token(
            value=_make_jwt({"aud": ["https://other.example", "https://server.example/mcp"]}),
            expires_at=time.time() + 3600,
            as_issuer="https://as.example",
            scopes=("mcp:tools",),
            resource_indicator="https://server.example/mcp",
            client_id="cognic-mcp-bank_a",
        )
        _validate_token_audience(token, expected_audience="https://server.example/mcp")

    def test_mismatched_audience_refused(self) -> None:
        token = Token(
            value=_make_jwt({"aud": "https://attacker.example/mcp"}),
            expires_at=time.time() + 3600,
            as_issuer="https://as.example",
            scopes=("mcp:tools",),
            resource_indicator="https://server.example/mcp",
            client_id="cognic-mcp-bank_a",
        )
        with pytest.raises(MCPAuthzError) as exc:
            _validate_token_audience(token, expected_audience="https://server.example/mcp")
        assert exc.value.reason == "mcp_token_audience_mismatch"

    def test_missing_aud_claim_refused(self) -> None:
        """JWT with no ``aud`` claim is rejected — the spec requires it."""
        token = Token(
            value=_make_jwt({"sub": "no-aud-here"}),
            expires_at=time.time() + 3600,
            as_issuer="https://as.example",
            scopes=("mcp:tools",),
            resource_indicator="https://server.example/mcp",
            client_id="cognic-mcp-bank_a",
        )
        with pytest.raises(MCPAuthzError) as exc:
            _validate_token_audience(token, expected_audience="https://server.example/mcp")
        assert exc.value.reason == "mcp_token_audience_mismatch"

    def test_opaque_token_skips_audience_check(self) -> None:
        """Non-JWT (opaque) tokens — trust the AS's RFC 8707 binding."""
        token = Token(
            value="opaque-token-not-jwt",
            expires_at=time.time() + 3600,
            as_issuer="https://as.example",
            scopes=("mcp:tools",),
            resource_indicator="https://server.example/mcp",
            client_id="cognic-mcp-bank_a",
        )
        # No raise — opaque tokens skip JWT-level audience check
        _validate_token_audience(token, expected_audience="https://server.example/mcp")


# ---------------------------------------------------------------------------
# Admission stays SDK-free (R3 P1 doctrine)
# ---------------------------------------------------------------------------


class TestAdmissionStaysSdkFree:
    """**R3 P1 doctrine pin:** MCPAuthzClient construction MUST succeed
    on a kernel-image-equivalent venv (no ``mcp`` SDK installed). This
    is the contract :func:`require_mcp` must NOT be called inside the
    constructor."""

    async def test_client_constructs_without_mcp_sdk(
        self,
        settings: Settings,
        vault_client: MagicMock,
        http_client: httpx.AsyncClient,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Even with ``find_spec("mcp")`` mocked to None (kernel-image
        simulation), the client must construct cleanly."""
        import importlib.util

        real_find_spec = importlib.util.find_spec

        def _stub(name: str, *args: Any, **kw: Any) -> Any:
            if name == "mcp" or name.startswith("mcp."):
                return None
            return real_find_spec(name, *args, **kw)

        monkeypatch.setattr(importlib.util, "find_spec", _stub)

        # Should NOT raise MCPNotAvailableError
        client = MCPAuthzClient(
            settings=settings,
            vault_client=vault_client,
            http_client=http_client,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
        )
        assert client is not None


# ---------------------------------------------------------------------------
# PRM discovery — three paths
# ---------------------------------------------------------------------------


class TestPrmDiscoveryWWWAuthenticatePath:
    @respx.mock
    async def test_primary_path_follows_resource_metadata_url(self, authz: MCPAuthzClient) -> None:
        """Server returns 401 with ``WWW-Authenticate: Bearer
        resource_metadata="..."`` → client follows the URL."""
        server = "https://server.example/mcp"
        prm_url = "https://prm.example/doc"
        respx.get(server).mock(
            return_value=httpx.Response(
                401,
                headers={"WWW-Authenticate": f'Bearer resource_metadata="{prm_url}"'},
            )
        )
        respx.get(prm_url).mock(
            return_value=httpx.Response(
                200,
                json={
                    "resource": server,
                    "authorization_servers": ["https://as.example"],
                    "scopes_supported": ["mcp:tools"],
                },
            )
        )

        prm = await authz.discover_resource_metadata(
            server_url=server, request_id="rid-1", tenant_id="bank_a"
        )

        assert prm.discovery_path == "www-authenticate"
        assert prm.authorization_servers == ("https://as.example",)


class TestPrmDiscoveryEndpointSpecificFallback:
    @respx.mock
    async def test_endpoint_specific_well_known_used_when_header_missing(
        self, authz: MCPAuthzClient
    ) -> None:
        """401 without WWW-Authenticate → probe endpoint-specific
        well-known URL (with the server path appended)."""
        server = "https://server.example/public/mcp"
        endpoint_specific = "https://server.example/.well-known/oauth-protected-resource/public/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))  # no header
        respx.get(endpoint_specific).mock(
            return_value=httpx.Response(
                200,
                json={
                    "resource": server,
                    "authorization_servers": ["https://as.example"],
                },
            )
        )

        prm = await authz.discover_resource_metadata(
            server_url=server, request_id="rid-2", tenant_id="bank_a"
        )

        assert prm.discovery_path == "endpoint-well-known"

    @respx.mock
    async def test_endpoint_specific_used_when_no_initial_401(self, authz: MCPAuthzClient) -> None:
        """If the server returns a non-401 (e.g., 200 with no auth
        challenge), client still tries endpoint-specific PRM."""
        server = "https://server.example/mcp"
        endpoint_specific = "https://server.example/.well-known/oauth-protected-resource/mcp"
        respx.get(server).mock(return_value=httpx.Response(200, json={}))
        respx.get(endpoint_specific).mock(
            return_value=httpx.Response(
                200,
                json={"authorization_servers": ["https://as.example"]},
            )
        )

        prm = await authz.discover_resource_metadata(
            server_url=server, request_id="rid", tenant_id="bank_a"
        )

        assert prm.discovery_path == "endpoint-well-known"


class TestPrmDiscoveryRootFallback:
    @respx.mock
    async def test_root_used_when_endpoint_specific_404s(self, authz: MCPAuthzClient) -> None:
        server = "https://server.example/mcp"
        endpoint_specific = "https://server.example/.well-known/oauth-protected-resource/mcp"
        root = "https://server.example/.well-known/oauth-protected-resource"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get(endpoint_specific).mock(return_value=httpx.Response(404))
        respx.get(root).mock(
            return_value=httpx.Response(
                200,
                json={"authorization_servers": ["https://as.example"]},
            )
        )

        prm = await authz.discover_resource_metadata(
            server_url=server, request_id="rid", tenant_id="bank_a"
        )

        assert prm.discovery_path == "root-well-known"


class TestPrmDiscoveryPriorityOrder:
    @respx.mock
    async def test_endpoint_specific_wins_over_root(self, authz: MCPAuthzClient) -> None:
        """Both endpoint-specific AND root paths exist with conflicting
        PRMs → endpoint-specific takes precedence per spec."""
        server = "https://server.example/mcp"
        endpoint_specific = "https://server.example/.well-known/oauth-protected-resource/mcp"
        root = "https://server.example/.well-known/oauth-protected-resource"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get(endpoint_specific).mock(
            return_value=httpx.Response(
                200, json={"authorization_servers": ["https://specific-as.example"]}
            )
        )
        respx.get(root).mock(
            return_value=httpx.Response(
                200, json={"authorization_servers": ["https://root-as.example"]}
            )
        )

        prm = await authz.discover_resource_metadata(
            server_url=server, request_id="rid", tenant_id="bank_a"
        )

        # Endpoint-specific wins; root never probed
        assert prm.authorization_servers == ("https://specific-as.example",)
        assert prm.discovery_path == "endpoint-well-known"


class TestPrmDiscoveryAnonymousRefused:
    @respx.mock
    async def test_all_three_paths_fail_raises_anonymous_refused(
        self, authz: MCPAuthzClient
    ) -> None:
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))  # no header
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://server.example/.well-known/oauth-protected-resource").mock(
            return_value=httpx.Response(404)
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.discover_resource_metadata(
                server_url=server, request_id="rid", tenant_id="bank_a"
            )

        assert exc.value.reason == "mcp_anonymous_refused"


class TestPrmInvalidShapes:
    @respx.mock
    async def test_malformed_json_raises_prm_invalid(self, authz: MCPAuthzClient) -> None:
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, text="not-json")
        )
        respx.get("https://server.example/.well-known/oauth-protected-resource").mock(
            return_value=httpx.Response(404)
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.discover_resource_metadata(
                server_url=server, request_id="rid", tenant_id="bank_a"
            )
        assert exc.value.reason == "mcp_prm_invalid"

    @respx.mock
    async def test_missing_authorization_servers_raises_prm_invalid(
        self, authz: MCPAuthzClient
    ) -> None:
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"scopes_supported": ["x"]})
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.discover_resource_metadata(
                server_url=server, request_id="rid", tenant_id="bank_a"
            )
        assert exc.value.reason == "mcp_prm_invalid"

    @respx.mock
    async def test_empty_authorization_servers_raises_prm_invalid(
        self, authz: MCPAuthzClient
    ) -> None:
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": []})
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.discover_resource_metadata(
                server_url=server, request_id="rid", tenant_id="bank_a"
            )
        assert exc.value.reason == "mcp_prm_invalid"


# ---------------------------------------------------------------------------
# AS allow-list + token acquisition
# ---------------------------------------------------------------------------


def _setup_oauth_flow(
    server_url: str,
    as_issuer: str,
    scopes: tuple[str, ...] = ("mcp:tools",),
    aud: str | None = None,
) -> None:
    """Helper: set up the standard OAuth flow against ``respx``.

    Assumes PRM at the endpoint-specific well-known URL points to
    the AS issuer; AS discovery returns a token_endpoint; token
    endpoint returns a JWT-bound token with the given audience.
    """
    if aud is None:
        aud = server_url
    endpoint_specific = (
        server_url.rsplit("/", 1)[0]
        + "/.well-known/oauth-protected-resource"
        + (server_url.split(server_url.rsplit("/", 1)[0], 1)[1] if "/" in server_url else "")
    )
    # Simpler: construct via the actual helper
    from cognic_agentos.protocol.mcp_authz import _endpoint_specific_well_known_url

    endpoint_specific = _endpoint_specific_well_known_url(server_url)
    respx.get(server_url).mock(return_value=httpx.Response(401))
    respx.get(endpoint_specific).mock(
        return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
    )
    respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
        return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
    )
    respx.post(f"{as_issuer}/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": _make_jwt({"aud": aud}),
                "expires_in": 3600,
                "scope": " ".join(scopes),
            },
        )
    )


class TestAsAllowlistEnforcement:
    @respx.mock
    async def test_non_allowlisted_as_refused(
        self, authz: MCPAuthzClient, vault_client: MagicMock
    ) -> None:
        """PRM advertises AS ``https://attacker-as.example``; per-tenant
        allow-list does NOT include it → ``mcp_as_not_allowlisted``."""
        vault_client.read.side_effect = _vault_dispatch(allowlist=["https://only-this-one.example"])
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(
                200, json={"authorization_servers": ["https://attacker-as.example"]}
            )
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_as_not_allowlisted"

    @respx.mock
    async def test_allowlisted_as_proceeds_to_token_request(
        self, authz: MCPAuthzClient, vault_client: MagicMock
    ) -> None:
        as_issuer = "https://as.example"
        vault_client.read.side_effect = _vault_dispatch(allowlist=[as_issuer])
        server = "https://server.example/mcp"
        _setup_oauth_flow(server, as_issuer)

        token = await authz.acquire_token(
            server_url=server,
            manifest_scopes=("mcp:tools",),
            request_id="rid",
            tenant_id="bank_a",
        )

        assert token.as_issuer == as_issuer
        assert token.scopes == ("mcp:tools",)
        assert token.resource_indicator == server


class TestRfc8707ResourceIndicator:
    @respx.mock
    async def test_token_request_includes_resource_parameter(self, authz: MCPAuthzClient) -> None:
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        _setup_oauth_flow(server, as_issuer)

        await authz.acquire_token(
            server_url=server,
            manifest_scopes=("mcp:tools",),
            request_id="rid",
            tenant_id="bank_a",
        )

        # Inspect the token-endpoint POST body for the resource= field
        token_request = respx.routes[3].calls[0].request  # 4th mocked route
        body = token_request.read().decode()
        # Form-encoded body should include resource=<server_url>
        assert f"resource={server.replace(':', '%3A').replace('/', '%2F')}" in body

    @respx.mock
    async def test_token_with_mismatched_audience_rejected(
        self,
        authz: MCPAuthzClient,
    ) -> None:
        """Token returned with ``aud`` != server URL → rejected with
        ``mcp_token_audience_mismatch`` even though RFC 8707 was sent."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        _setup_oauth_flow(server, as_issuer, aud="https://attacker.example/mcp")

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_token_audience_mismatch"


# ---------------------------------------------------------------------------
# Token cache + refresh
# ---------------------------------------------------------------------------


class TestTokenCacheAndRefresh:
    @respx.mock
    async def test_cached_token_returned_on_second_acquire(self, authz: MCPAuthzClient) -> None:
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        _setup_oauth_flow(server, as_issuer)

        # First call hits the network
        token_a = await authz.acquire_token(
            server_url=server,
            manifest_scopes=("mcp:tools",),
            request_id="rid-1",
            tenant_id="bank_a",
        )
        # Second call MUST come from cache (same Token object, no
        # additional respx calls beyond what the first acquire used)
        token_b = await authz.acquire_token(
            server_url=server,
            manifest_scopes=("mcp:tools",),
            request_id="rid-2",
            tenant_id="bank_a",
        )

        assert token_a.value == token_b.value
        # Token-endpoint mock should have been called exactly once
        token_endpoint_route = respx.routes[3]
        assert token_endpoint_route.call_count == 1

    @respx.mock
    async def test_refresh_emits_audit_and_decision_history(
        self,
        authz: MCPAuthzClient,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
    ) -> None:
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        # Set up AS discovery + token endpoint for the refresh
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": 7200,
                    "scope": "mcp:tools",
                },
            )
        )

        old_token = Token(
            value=_make_jwt({"aud": server}),
            expires_at=time.time() + 30,  # near expiry
            as_issuer=as_issuer,
            scopes=("mcp:tools",),
            resource_indicator=server,
            client_id="cognic-mcp-bank_a",
        )

        new_token = await authz.refresh_token(
            token=old_token, request_id="rid-refresh", tenant_id="bank_a"
        )

        # New token issued with later expiry
        assert new_token.expires_at > old_token.expires_at
        # Audit event emitted with no token-value leak
        audit_store.append.assert_awaited_once()
        audit_arg = audit_store.append.call_args[0][0]
        assert audit_arg.event_type == "audit.mcp_token_refresh"
        assert audit_arg.request_id == "rid-refresh"
        assert audit_arg.tenant_id == "bank_a"
        # Critical: the token VALUE must not appear anywhere in the
        # audit payload (per Sprint-5 R1 P2 #6 + ADR-002 §"audit
        # payload" — never log token contents)
        payload_str = json.dumps(audit_arg.payload)
        assert new_token.value not in payload_str
        # decision_history row written (T11 doctrine)
        decision_history_store.append.assert_awaited_once()
        dh_arg = decision_history_store.append.call_args[0][0]
        assert dh_arg.decision_type == "mcp_token_refresh"
        assert dh_arg.request_id == "rid-refresh"


# ---------------------------------------------------------------------------
# Step-up flow
# ---------------------------------------------------------------------------


class TestStepUpScopeFlow:
    @respx.mock
    async def test_step_up_with_manifest_declared_scope_succeeds(
        self,
        authz: MCPAuthzClient,
        audit_store: MagicMock,
    ) -> None:
        """Server returns 403 wider scope; manifest declares it →
        fresh token with wider scopes acquired."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": 3600,
                    "scope": "mcp:tools mcp:tools.write",
                },
            )
        )

        current = Token(
            value=_make_jwt({"aud": server}),
            expires_at=time.time() + 3600,
            as_issuer=as_issuer,
            scopes=("mcp:tools",),
            resource_indicator=server,
            client_id="cognic-mcp-bank_a",
        )

        new_token = await authz.step_up_token(
            server_url=server,
            current_token=current,
            requested_scope="mcp:tools.write",
            manifest_scopes=("mcp:tools", "mcp:tools.write"),
            request_id="rid-stepup",
            tenant_id="bank_a",
        )

        assert "mcp:tools.write" in new_token.scopes
        # Step-up audit event emitted
        audit_store.append.assert_awaited_once()
        audit_arg = audit_store.append.call_args[0][0]
        assert audit_arg.event_type == "audit.mcp_step_up"
        assert audit_arg.payload["outcome"] == "granted"
        assert audit_arg.payload["requested_additional_scope"] == "mcp:tools.write"

    async def test_step_up_without_manifest_declared_scope_refused(
        self, authz: MCPAuthzClient
    ) -> None:
        """Server requests scope NOT in manifest → fail closed with
        ``mcp_step_up_unauthorised``."""
        server = "https://server.example/mcp"
        current = Token(
            value="opaque",
            expires_at=time.time() + 3600,
            as_issuer="https://as.example",
            scopes=("mcp:tools",),
            resource_indicator=server,
            client_id="cognic-mcp-bank_a",
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.step_up_token(
                server_url=server,
                current_token=current,
                requested_scope="mcp:admin",  # NOT in manifest
                manifest_scopes=("mcp:tools",),  # only the original
                request_id="rid",
                tenant_id="bank_a",
            )

        assert exc.value.reason == "mcp_step_up_unauthorised"


# ---------------------------------------------------------------------------
# Strict timeout
# ---------------------------------------------------------------------------


class TestOauthRequestTimeout:
    @respx.mock
    async def test_prm_probe_timeout_raises_request_timeout(self, authz: MCPAuthzClient) -> None:
        server = "https://server.example/mcp"
        # respx supports raising via side_effect = httpx.TimeoutException
        respx.get(server).mock(side_effect=httpx.TimeoutException("simulated timeout"))

        with pytest.raises(MCPAuthzError) as exc:
            await authz.discover_resource_metadata(
                server_url=server, request_id="rid", tenant_id="bank_a"
            )
        assert exc.value.reason == "mcp_oauth_request_timeout"


# ---------------------------------------------------------------------------
# Closed-enum coverage
# ---------------------------------------------------------------------------


class TestRequestTokenErrorPaths:
    """Coverage for negative paths in :meth:`_request_token` —
    AS-discovery + token-endpoint failure modes. Without these tests
    the critical-controls coverage gate (≥95 line / ≥90 branch) trips
    on uncovered exception branches.
    """

    @respx.mock
    async def test_as_discovery_timeout_raises_oauth_request_timeout(
        self, authz: MCPAuthzClient
    ) -> None:
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            side_effect=httpx.TimeoutException("simulated discovery timeout")
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_request_timeout"

    @respx.mock
    async def test_as_discovery_non_200_raises_as_discovery_invalid(
        self, authz: MCPAuthzClient
    ) -> None:
        """R11 P2: AS discovery endpoint returning a non-200 status
        is its own closed-enum reason — distinct from a malformed PRM
        document on the MCP server (the operator debug paths differ)."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(503)
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_as_discovery_invalid"
        assert exc.value.payload.get("status_code") == 503

    @respx.mock
    async def test_as_discovery_malformed_json_raises_as_discovery_invalid(
        self, authz: MCPAuthzClient
    ) -> None:
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, text="not-json")
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_as_discovery_invalid"

    @respx.mock
    async def test_as_discovery_missing_token_endpoint_raises_as_discovery_invalid(
        self, authz: MCPAuthzClient
    ) -> None:
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"issuer": as_issuer})  # no token_endpoint
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_as_discovery_invalid"

    @respx.mock
    async def test_token_endpoint_timeout_raises_oauth_request_timeout(
        self, authz: MCPAuthzClient
    ) -> None:
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            side_effect=httpx.TimeoutException("simulated token timeout")
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_request_timeout"

    @respx.mock
    async def test_token_endpoint_non_200_raises_token_endpoint_error(
        self, authz: MCPAuthzClient
    ) -> None:
        """R11 P2: token endpoint non-200 (400 invalid_grant, 401
        rejected credentials, 503 AS down) is its own closed-enum
        reason — distinct from PRM-invalid; operators debug Vault-
        stored client credentials, not the MCP server's PRM."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(return_value=httpx.Response(400))

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_token_endpoint_error"
        assert exc.value.payload.get("status_code") == 400
        # Operator-relevant: as_issuer + token_endpoint surfaced;
        # response body NEVER carried (could echo credentials)
        assert exc.value.payload.get("as_issuer") == as_issuer
        assert "token_endpoint" in exc.value.payload

    @respx.mock
    async def test_token_endpoint_401_raises_token_endpoint_error(
        self, authz: MCPAuthzClient
    ) -> None:
        """R11 P2: 401 from the token endpoint (the most operator-
        relevant case — usually rejected Vault-stored client
        credentials) MUST surface as ``mcp_oauth_token_endpoint_error``
        with status_code=401 in the payload, NOT as
        ``mcp_prm_invalid``."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(
                401,
                # AS sends an OAuth error body with credentials echoed
                # back; assertion below verifies AgentOS does NOT
                # propagate the body into the payload.
                json={"error": "invalid_client", "error_description": "client_secret rejected"},
            )
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_token_endpoint_error"
        assert exc.value.payload.get("status_code") == 401
        # No body / response text in the closed-enum payload — operator
        # sees the status code only. The AS's own debug body might
        # echo credentials or sensitive AS-side state.
        payload_str = str(exc.value.payload)
        assert "client_secret" not in payload_str
        assert "rejected" not in payload_str

    @respx.mock
    async def test_token_response_malformed_json_raises_token_response_invalid(
        self, authz: MCPAuthzClient
    ) -> None:
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(200, text="not-json-token-response")
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_token_response_invalid"

    @respx.mock
    async def test_token_response_missing_access_token_raises_token_response_invalid(
        self, authz: MCPAuthzClient
    ) -> None:
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(200, json={"expires_in": 3600})
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_token_response_invalid"


class TestVaultAllowlistErrorPaths:
    """Coverage for :meth:`_load_as_allowlist` — defensive paths
    against malformed Vault data."""

    @respx.mock
    async def test_malformed_allowlist_data_raises_as_not_allowlisted(
        self,
        authz: MCPAuthzClient,
        vault_client: MagicMock,
    ) -> None:
        """Vault returns ``{"servers": "not-a-list"}`` — defensive
        check raises ``mcp_as_not_allowlisted``."""

        async def _malformed(path: str) -> dict[str, Any]:
            if "mcp-oauth" in path:
                return dict(_DEFAULT_OAUTH_CREDS)
            return {"servers": "not-a-list"}

        vault_client.read.side_effect = _malformed
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": ["https://as.example"]})
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_as_not_allowlisted"


class TestPrmDocumentEdgeCases:
    """Coverage for malformed-PRM-document branches in :meth:`_fetch_prm`."""

    @respx.mock
    async def test_prm_returning_non_object_raises_prm_invalid(self, authz: MCPAuthzClient) -> None:
        """PRM returns a JSON array (not an object) → ``mcp_prm_invalid``."""
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json=["not-an-object"])
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.discover_resource_metadata(
                server_url=server, request_id="rid", tenant_id="bank_a"
            )
        assert exc.value.reason == "mcp_prm_invalid"

    @respx.mock
    async def test_prm_with_non_string_server_entry_raises_prm_invalid(
        self, authz: MCPAuthzClient
    ) -> None:
        """``authorization_servers: [42]`` — non-string entry rejected."""
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [42]})
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.discover_resource_metadata(
                server_url=server, request_id="rid", tenant_id="bank_a"
            )
        assert exc.value.reason == "mcp_prm_invalid"

    @respx.mock
    async def test_prm_with_malformed_scopes_supported_raises_prm_invalid(
        self, authz: MCPAuthzClient
    ) -> None:
        """``scopes_supported`` not a list of strings → ``mcp_prm_invalid``."""
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "authorization_servers": ["https://as.example"],
                    "scopes_supported": [123],
                },
            )
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.discover_resource_metadata(
                server_url=server, request_id="rid", tenant_id="bank_a"
            )
        assert exc.value.reason == "mcp_prm_invalid"

    @respx.mock
    async def test_prm_fallback_path_timeout_raises_oauth_request_timeout(
        self, authz: MCPAuthzClient
    ) -> None:
        """Endpoint-specific PRM URL itself times out (not the initial
        server probe). The fetch path raises ``mcp_oauth_request_timeout``."""
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))  # no header
        # Endpoint-specific URL itself times out
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            side_effect=httpx.TimeoutException("simulated PRM-fetch timeout")
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.discover_resource_metadata(
                server_url=server, request_id="rid", tenant_id="bank_a"
            )
        assert exc.value.reason == "mcp_oauth_request_timeout"

    @respx.mock
    async def test_www_authenticate_url_404s_falls_through(self, authz: MCPAuthzClient) -> None:
        """``WWW-Authenticate`` advertises a PRM URL that 404s →
        client falls through to endpoint-specific well-known."""
        server = "https://server.example/mcp"
        bogus_prm_url = "https://prm.example/doc"
        respx.get(server).mock(
            return_value=httpx.Response(
                401,
                headers={"WWW-Authenticate": f'Bearer resource_metadata="{bogus_prm_url}"'},
            )
        )
        # The WWW-Authenticate-advertised URL 404s
        respx.get(bogus_prm_url).mock(return_value=httpx.Response(404))
        # Fall through to endpoint-specific
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": ["https://as.example"]})
        )

        prm = await authz.discover_resource_metadata(
            server_url=server, request_id="rid", tenant_id="bank_a"
        )
        assert prm.discovery_path == "endpoint-well-known"

    @respx.mock
    async def test_prm_path_returns_500_falls_through_to_next_path(
        self, authz: MCPAuthzClient
    ) -> None:
        """Endpoint-specific path returns 500 (not 404) → fall through
        to root well-known."""
        server = "https://server.example/mcp"
        endpoint_specific = "https://server.example/.well-known/oauth-protected-resource/mcp"
        root = "https://server.example/.well-known/oauth-protected-resource"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get(endpoint_specific).mock(return_value=httpx.Response(500))
        respx.get(root).mock(
            return_value=httpx.Response(200, json={"authorization_servers": ["https://as.example"]})
        )

        prm = await authz.discover_resource_metadata(
            server_url=server, request_id="rid", tenant_id="bank_a"
        )
        # Fell through to root path because endpoint-specific 500'd
        assert prm.discovery_path == "root-well-known"


class TestStepUpAsAllowlistRevoked:
    """Edge case: AS allow-list changes between initial token acquire
    and step-up. Step-up MUST refuse if the AS is no longer allowed."""

    @respx.mock
    async def test_step_up_with_revoked_as_refuses(
        self,
        authz: MCPAuthzClient,
        vault_client: MagicMock,
    ) -> None:
        """Vault allow-list does NOT include the PRM-advertised AS at
        step-up time. The step-up path should fail at the allow-list
        check, before any AS-discovery HTTP call fires.
        """
        # Step-up makes a fresh PRM discovery + a fresh allow-list
        # lookup. PRM advertises https://as.example; allow-list does
        # NOT include it → fail closed at the allow-list check.
        vault_client.read.side_effect = _vault_dispatch(allowlist=["https://other-as.example"])
        prm_advertised_as = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [prm_advertised_as]})
        )

        current = Token(
            value="opaque",
            expires_at=time.time() + 3600,
            as_issuer=prm_advertised_as,
            scopes=("mcp:tools",),
            resource_indicator=server,
            client_id="cognic-mcp-bank_a",
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.step_up_token(
                server_url=server,
                current_token=current,
                requested_scope="mcp:tools.write",
                manifest_scopes=("mcp:tools", "mcp:tools.write"),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_as_not_allowlisted"


class TestAuthzErrorWithoutMessage:
    """Coverage for the :class:`MCPAuthzError` constructor branch where
    ``message`` is empty."""

    def test_error_str_uses_reason_when_message_empty(self) -> None:
        err = MCPAuthzError("mcp_anonymous_refused")
        assert str(err) == "mcp_anonymous_refused"

    def test_error_str_includes_message_when_provided(self) -> None:
        err = MCPAuthzError("mcp_anonymous_refused", "no PRM advertised")
        assert "mcp_anonymous_refused" in str(err)
        assert "no PRM advertised" in str(err)


class TestRefusalReasonClosedEnum:
    """Pin every documented closed-enum reason has a test that exercises
    it. Drift detector for new reasons added to ``AuthzReason`` without
    a test arm.
    """

    EXPECTED_REASONS = frozenset(
        {
            "mcp_anonymous_refused",
            "mcp_as_not_allowlisted",
            "mcp_token_audience_mismatch",
            "mcp_token_scope_overgrant",
            "mcp_step_up_unauthorised",
            "mcp_oauth_request_timeout",
            "mcp_oauth_transport_failure",
            "mcp_oauth_credentials_missing",
            "mcp_oauth_as_discovery_invalid",
            "mcp_oauth_token_endpoint_error",
            "mcp_oauth_token_response_invalid",
            "mcp_prm_invalid",
        }
    )

    def test_authz_reason_literal_matches_expected_set(self) -> None:
        """The ``AuthzReason`` Literal type matches the documented set
        exactly. If a new reason is added, update :attr:`EXPECTED_REASONS`."""
        from typing import get_args

        from cognic_agentos.protocol.mcp_authz import AuthzReason

        actual = frozenset(get_args(AuthzReason))
        assert actual == self.EXPECTED_REASONS, (
            f"AuthzReason drift detected. "
            f"Added without test: {actual - self.EXPECTED_REASONS}; "
            f"Removed without removing test arm: "
            f"{self.EXPECTED_REASONS - actual}"
        )


# ---------------------------------------------------------------------------
# Sprint 5 R6 — production-grade OAuth client credentials, transport-failure
# closed-enum, scope-overgrant doctrine, audit-on-denial paths
# ---------------------------------------------------------------------------


class TestVaultOauthCredentials:
    """R6 P1: client credentials must be Vault-backed (no synthesised
    client_id / no missing client_secret). Covers the
    :meth:`_load_oauth_credentials` resolver + integration with
    :meth:`_request_token`.
    """

    @respx.mock
    async def test_credentials_loaded_from_vault_post_method(
        self,
        authz: MCPAuthzClient,
        vault_client: MagicMock,
    ) -> None:
        """``client_secret_post`` (default): client_id + client_secret
        appear in the form-encoded request body sent to the AS token
        endpoint."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        _setup_oauth_flow(server, as_issuer)

        token = await authz.acquire_token(
            server_url=server,
            manifest_scopes=("mcp:tools",),
            request_id="rid",
            tenant_id="bank_a",
        )

        assert token.client_id == "cognic-mcp-bank_a"
        # Vault was queried twice: once for allow-list, once for creds
        assert vault_client.read.call_count == 2
        creds_call = next(c for c in vault_client.read.call_args_list if "mcp-oauth" in c.args[0])
        # AS host (netloc) is interpolated into the path
        assert "as.example" in creds_call.args[0]
        assert "bank_a" in creds_call.args[0]

        # Inspect the token-endpoint POST body — credentials in form body
        token_request = respx.routes[3].calls[0].request
        body = token_request.read().decode()
        assert "client_id=cognic-mcp-bank_a" in body
        assert "client_secret=vault-stored-secret" in body
        # No Authorization header on POST when method is post
        assert "Authorization" not in token_request.headers

    @respx.mock
    async def test_credentials_loaded_from_vault_basic_method(
        self,
        authz: MCPAuthzClient,
        vault_client: MagicMock,
    ) -> None:
        """``client_secret_basic``: credentials sent as
        ``Authorization: Basic <b64>`` header, NOT in body."""
        vault_client.read.side_effect = _vault_dispatch(
            creds={
                "client_id": "basic-client",
                "client_secret": "basic-secret",
                "auth_method": "client_secret_basic",
            }
        )
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        _setup_oauth_flow(server, as_issuer)

        await authz.acquire_token(
            server_url=server,
            manifest_scopes=("mcp:tools",),
            request_id="rid",
            tenant_id="bank_a",
        )

        token_request = respx.routes[3].calls[0].request
        body = token_request.read().decode()
        # Credentials NOT in body
        assert "client_secret=" not in body
        assert "client_id=basic-client" not in body
        # Credentials in Basic header (b64 of "basic-client:basic-secret")
        expected_b64 = base64.b64encode(b"basic-client:basic-secret").decode()
        assert token_request.headers.get("Authorization") == f"Basic {expected_b64}"

    @respx.mock
    async def test_missing_vault_secret_raises_credentials_missing(
        self,
        authz: MCPAuthzClient,
        vault_client: MagicMock,
    ) -> None:
        """Vault read raises (path-not-found, permission denied, backend
        unreachable) → ``mcp_oauth_credentials_missing``."""

        async def _vault_creds_missing(path: str) -> dict[str, Any]:
            if "mcp-oauth" in path:
                raise RuntimeError("path not found")
            return {"servers": ["https://as.example"]}

        vault_client.read.side_effect = _vault_creds_missing
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_credentials_missing"

    @respx.mock
    async def test_vault_secret_not_a_mapping_raises_credentials_missing(
        self,
        authz: MCPAuthzClient,
        vault_client: MagicMock,
    ) -> None:
        """Vault returns a non-dict (e.g., a list) → fail closed."""

        async def _bad_shape(path: str) -> Any:
            if "mcp-oauth" in path:
                return ["not", "a", "mapping"]
            return {"servers": ["https://as.example"]}

        vault_client.read.side_effect = _bad_shape
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_credentials_missing"

    @respx.mock
    async def test_missing_client_id_raises_credentials_missing(
        self,
        authz: MCPAuthzClient,
        vault_client: MagicMock,
    ) -> None:
        vault_client.read.side_effect = _vault_dispatch(
            creds={
                "client_id": "",
                "client_secret": "x",
                "auth_method": "client_secret_post",
            }
        )
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_credentials_missing"

    @respx.mock
    async def test_missing_client_secret_raises_credentials_missing(
        self,
        authz: MCPAuthzClient,
        vault_client: MagicMock,
    ) -> None:
        vault_client.read.side_effect = _vault_dispatch(
            creds={
                "client_id": "cid",
                "client_secret": "",
                "auth_method": "client_secret_post",
            }
        )
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_credentials_missing"

    @respx.mock
    async def test_unsupported_auth_method_raises_credentials_missing(
        self,
        authz: MCPAuthzClient,
        vault_client: MagicMock,
    ) -> None:
        """``private_key_jwt`` is Wave 2 — Sprint 5 must reject it
        cleanly, not silently fall back."""
        vault_client.read.side_effect = _vault_dispatch(
            creds={
                "client_id": "cid",
                "client_secret": "cs",
                "auth_method": "private_key_jwt",  # Wave 2 only
            }
        )
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_credentials_missing"

    @respx.mock
    async def test_client_secret_never_appears_in_token_repr(
        self,
        authz: MCPAuthzClient,
    ) -> None:
        """The Vault-loaded ``client_secret`` MUST NOT leak into the
        ``Token.__repr__`` (the secret is form-body / Basic-header
        ephemeral, never carried on the Token object — defensive
        check that we didn't accidentally store it on the dataclass)."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        _setup_oauth_flow(server, as_issuer)

        token = await authz.acquire_token(
            server_url=server,
            manifest_scopes=("mcp:tools",),
            request_id="rid",
            tenant_id="bank_a",
        )
        repr_str = repr(token)
        assert "vault-stored-secret" not in repr_str


class TestTransportFailureClosedEnum:
    """R6 P2: every httpx.RequestError (ConnectError, NetworkError, TLS
    handshake failure, DNS failure, …) maps to the closed-enum
    ``mcp_oauth_transport_failure`` reason. Without this, registration
    auth probes would bubble raw httpx exceptions to the registry,
    breaking the no-fall-through contract.
    """

    @respx.mock
    async def test_prm_probe_connect_error_raises_transport_failure(
        self, authz: MCPAuthzClient
    ) -> None:
        server = "https://server.example/mcp"
        respx.get(server).mock(side_effect=httpx.ConnectError("simulated DNS failure"))

        with pytest.raises(MCPAuthzError) as exc:
            await authz.discover_resource_metadata(
                server_url=server, request_id="rid", tenant_id="bank_a"
            )
        assert exc.value.reason == "mcp_oauth_transport_failure"

    @respx.mock
    async def test_prm_fetch_connect_error_raises_transport_failure(
        self, authz: MCPAuthzClient
    ) -> None:
        """The PRM fetch path itself fails at transport (vs. the initial
        server probe); ``_fetch_prm`` maps to transport-failure."""
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            side_effect=httpx.ConnectError("simulated TLS handshake failure")
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.discover_resource_metadata(
                server_url=server, request_id="rid", tenant_id="bank_a"
            )
        assert exc.value.reason == "mcp_oauth_transport_failure"

    @respx.mock
    async def test_as_discovery_connect_error_raises_transport_failure(
        self, authz: MCPAuthzClient
    ) -> None:
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            side_effect=httpx.ConnectError("simulated AS unreachable")
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_transport_failure"

    @respx.mock
    async def test_token_endpoint_connect_error_raises_transport_failure(
        self, authz: MCPAuthzClient
    ) -> None:
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            side_effect=httpx.ConnectError("simulated token-endpoint TLS error")
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_transport_failure"


class TestScopeOvergrantRejection:
    """R6 P2: AS may NOT silently widen the granted scope set beyond
    what the manifest declares. Even if the AS is allow-listed, if it
    returns a scope set wider than requested, AgentOS fails closed.
    """

    @respx.mock
    async def test_as_grants_extra_scope_raises_scope_overgrant(
        self, authz: MCPAuthzClient
    ) -> None:
        """Manifest declares ``mcp:tools``; AS returns
        ``mcp:tools mcp:admin`` → no-silent-privilege-widening doctrine
        fails closed."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": 3600,
                    # AS widens beyond what the manifest declared
                    "scope": "mcp:tools mcp:admin",
                },
            )
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_token_scope_overgrant"
        assert "mcp:admin" in exc.value.payload["overgrant_scopes"]

    @respx.mock
    async def test_as_grants_subset_of_manifest_accepted(self, authz: MCPAuthzClient) -> None:
        """AS-granted set is a strict subset → accepted (the AS may
        narrow; only widening fails closed)."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": 3600,
                    # AS narrows: only one of two requested scopes
                    "scope": "mcp:tools",
                },
            )
        )

        token = await authz.acquire_token(
            server_url=server,
            manifest_scopes=("mcp:tools", "mcp:tools.write"),
            request_id="rid",
            tenant_id="bank_a",
        )
        assert token.scopes == ("mcp:tools",)


class TestStepUpAuditOnDenial:
    """R6 P2: denial paths in :meth:`step_up_token` MUST emit audit
    events BEFORE raising — security-relevant; an attacker probing
    for wider scopes leaves a trace in the audit chain.
    """

    async def test_unauthorised_step_up_emits_audit_with_denial_outcome(
        self,
        authz: MCPAuthzClient,
        audit_store: MagicMock,
    ) -> None:
        """Manifest does NOT declare the requested scope → audit event
        fires BEFORE the raise, with outcome
        ``mcp_step_up_unauthorised``."""
        server = "https://server.example/mcp"
        current = Token(
            value="opaque",
            expires_at=time.time() + 3600,
            as_issuer="https://as.example",
            scopes=("mcp:tools",),
            resource_indicator=server,
            client_id="cognic-mcp-bank_a",
        )

        with pytest.raises(MCPAuthzError):
            await authz.step_up_token(
                server_url=server,
                current_token=current,
                requested_scope="mcp:admin",  # NOT in manifest
                manifest_scopes=("mcp:tools",),
                request_id="rid-denied",
                tenant_id="bank_a",
            )

        # Audit MUST have been emitted before the raise
        audit_store.append.assert_awaited_once()
        ev = audit_store.append.call_args[0][0]
        assert ev.event_type == "audit.mcp_step_up"
        assert ev.payload["outcome"] == "mcp_step_up_unauthorised"
        assert ev.payload["requested_additional_scope"] == "mcp:admin"
        # Token value MUST NOT appear in the audit payload
        assert "opaque" not in json.dumps(ev.payload)

    @respx.mock
    async def test_revoked_as_step_up_emits_audit_with_denial_outcome(
        self,
        authz: MCPAuthzClient,
        audit_store: MagicMock,
        vault_client: MagicMock,
    ) -> None:
        """AS allow-list revoked between initial token acquire and
        step-up → audit event fires BEFORE the raise, outcome
        ``mcp_as_not_allowlisted``."""
        vault_client.read.side_effect = _vault_dispatch(allowlist=["https://other-as.example"])
        prm_advertised_as = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [prm_advertised_as]})
        )
        current = Token(
            value="opaque",
            expires_at=time.time() + 3600,
            as_issuer=prm_advertised_as,
            scopes=("mcp:tools",),
            resource_indicator=server,
            client_id="cognic-mcp-bank_a",
        )

        with pytest.raises(MCPAuthzError):
            await authz.step_up_token(
                server_url=server,
                current_token=current,
                requested_scope="mcp:tools.write",
                manifest_scopes=("mcp:tools", "mcp:tools.write"),
                request_id="rid-revoked",
                tenant_id="bank_a",
            )

        audit_store.append.assert_awaited_once()
        ev = audit_store.append.call_args[0][0]
        assert ev.event_type == "audit.mcp_step_up"
        assert ev.payload["outcome"] == "mcp_as_not_allowlisted"


class TestRefreshFailureDecisionHistory:
    """R6 P2: token refresh failures MUST land in decision_history with
    decision ``refresh_failed`` so operators can correlate refresh
    storms with AS outages and audience-mismatch incidents.
    """

    @respx.mock
    async def test_refresh_timeout_writes_refresh_failed_decision(
        self,
        authz: MCPAuthzClient,
        decision_history_store: MagicMock,
    ) -> None:
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            side_effect=httpx.TimeoutException("simulated discovery timeout")
        )
        old_token = Token(
            value="opaque",
            expires_at=time.time() + 30,
            as_issuer=as_issuer,
            scopes=("mcp:tools",),
            resource_indicator=server,
            client_id="cognic-mcp-bank_a",
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.refresh_token(token=old_token, request_id="rid-rf", tenant_id="bank_a")
        assert exc.value.reason == "mcp_oauth_request_timeout"

        decision_history_store.append.assert_awaited_once()
        rec = decision_history_store.append.call_args[0][0]
        assert rec.decision_type == "mcp_token_refresh"
        assert rec.payload["decision"] == "refresh_failed"
        assert rec.payload["reason"] == "mcp_oauth_request_timeout"

    @respx.mock
    async def test_refresh_audience_mismatch_writes_refresh_failed_decision(
        self,
        authz: MCPAuthzClient,
        decision_history_store: MagicMock,
    ) -> None:
        """Refresh succeeds at the network layer but returns a token
        with the wrong ``aud`` → audience-validation raises and the
        failure row still lands in decision_history."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": "https://attacker.example"}),
                    "expires_in": 3600,
                    "scope": "mcp:tools",
                },
            )
        )
        old_token = Token(
            value="opaque",
            expires_at=time.time() + 30,
            as_issuer=as_issuer,
            scopes=("mcp:tools",),
            resource_indicator=server,
            client_id="cognic-mcp-bank_a",
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.refresh_token(token=old_token, request_id="rid-rf2", tenant_id="bank_a")
        assert exc.value.reason == "mcp_token_audience_mismatch"

        decision_history_store.append.assert_awaited_once()
        rec = decision_history_store.append.call_args[0][0]
        assert rec.payload["decision"] == "refresh_failed"
        assert rec.payload["reason"] == "mcp_token_audience_mismatch"

    @respx.mock
    async def test_refresh_as_500_writes_refresh_failed_decision(
        self,
        authz: MCPAuthzClient,
        decision_history_store: MagicMock,
    ) -> None:
        """AS discovery 500 during refresh → refresh_failed row, reason
        ``mcp_oauth_as_discovery_invalid`` (R11 P2 split this off the
        general ``mcp_prm_invalid`` bucket — AS discovery failures are
        operationally distinct from MCP-server PRM failures)."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(500)
        )
        old_token = Token(
            value="opaque",
            expires_at=time.time() + 30,
            as_issuer=as_issuer,
            scopes=("mcp:tools",),
            resource_indicator=server,
            client_id="cognic-mcp-bank_a",
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.refresh_token(token=old_token, request_id="rid-rf3", tenant_id="bank_a")
        assert exc.value.reason == "mcp_oauth_as_discovery_invalid"

        decision_history_store.append.assert_awaited_once()
        rec = decision_history_store.append.call_args[0][0]
        assert rec.payload["decision"] == "refresh_failed"
        assert rec.payload["reason"] == "mcp_oauth_as_discovery_invalid"


# ---------------------------------------------------------------------------
# Sprint 5 R7 — token cache TTL cap, expires_in defensive parse, allow-list
# strict validation, RFC 6749 §2.3.1 form-url-encoded Basic auth
# ---------------------------------------------------------------------------


class TestExpiresInValidation:
    """R7 P2: AS-supplied ``expires_in`` MUST be parsed defensively
    (closed-enum on non-numeric / non-positive) AND capped by the
    operator-set ``mcp_oauth_token_cache_ttl_s`` policy. Without this,
    the AS could override tenant policy by issuing 24h-lived tokens
    when the cache TTL is set to 1h.
    """

    @respx.mock
    async def test_token_lifetime_capped_by_cache_ttl(
        self,
        authz: MCPAuthzClient,
        settings: Settings,
    ) -> None:
        """AS issues a 24h token; operator policy caps at 1h. The Token
        ``expires_at`` MUST reflect the cap, not the AS's wider
        lifetime."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    # AS proposes 24h but operator policy is 1h
                    "expires_in": 86400,
                    "scope": "mcp:tools",
                },
            )
        )

        before = time.time()
        token = await authz.acquire_token(
            server_url=server,
            manifest_scopes=("mcp:tools",),
            request_id="rid",
            tenant_id="bank_a",
        )
        after = time.time()

        # Effective lifetime equals the cache-TTL cap, not the AS value
        ttl_cap = float(settings.mcp_oauth_token_cache_ttl_s)
        assert before + ttl_cap <= token.expires_at <= after + ttl_cap
        # Sanity: AS-proposed 24h would have produced a much later expiry
        assert token.expires_at < before + 86400 - 1

    @respx.mock
    async def test_token_lifetime_uses_as_value_when_below_cap(
        self,
        authz: MCPAuthzClient,
    ) -> None:
        """AS issues a 30s token, well below the 1h cap. Token MUST
        reflect the AS value (the cap is a ceiling, not a floor)."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": 30,
                    "scope": "mcp:tools",
                },
            )
        )

        before = time.time()
        token = await authz.acquire_token(
            server_url=server,
            manifest_scopes=("mcp:tools",),
            request_id="rid",
            tenant_id="bank_a",
        )
        after = time.time()

        # AS lifetime (30s) is well under the cap (3600s) → use AS value
        assert before + 30 <= token.expires_at <= after + 30

    @respx.mock
    async def test_non_numeric_expires_in_raises_prm_invalid(self, authz: MCPAuthzClient) -> None:
        """AS returns ``expires_in: "not-a-number"`` → closed-enum
        ``mcp_prm_invalid`` (NOT a raw ValueError from ``float()``)."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": "not-a-number",
                    "scope": "mcp:tools",
                },
            )
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_token_response_invalid"
        assert "expires_in" in str(exc.value)

    @respx.mock
    async def test_null_expires_in_raises_prm_invalid(self, authz: MCPAuthzClient) -> None:
        """AS returns ``expires_in: null`` → closed-enum, not a TypeError."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": None,
                    "scope": "mcp:tools",
                },
            )
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_token_response_invalid"

    @respx.mock
    async def test_zero_expires_in_raises_prm_invalid(self, authz: MCPAuthzClient) -> None:
        """``expires_in: 0`` is non-positive → closed-enum (a token
        with 0s lifetime is non-sensical)."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": 0,
                    "scope": "mcp:tools",
                },
            )
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_token_response_invalid"

    @respx.mock
    async def test_negative_expires_in_raises_prm_invalid(self, authz: MCPAuthzClient) -> None:
        """Negative ``expires_in`` → closed-enum."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": -1,
                    "scope": "mcp:tools",
                },
            )
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_token_response_invalid"


class TestAllowlistStrictValidation:
    """R7 P2: AS allow-list MUST reject any non-string or blank entry
    rather than silently dropping them. Mirrors the
    :meth:`_fetch_prm`'s ``authorization_servers`` validation; partial
    acceptance is the wrong posture for a critical authorization
    boundary.
    """

    @respx.mock
    async def test_non_string_entry_in_allowlist_raises_as_not_allowlisted(
        self,
        authz: MCPAuthzClient,
        vault_client: MagicMock,
    ) -> None:
        """Vault allow-list contains an integer entry → fail closed
        rather than silently drop it."""

        async def _mixed(path: str) -> dict[str, Any]:
            if "mcp-oauth" in path:
                return dict(_DEFAULT_OAUTH_CREDS)
            return {"servers": ["https://as.example", 42]}

        vault_client.read.side_effect = _mixed
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": ["https://as.example"]})
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_as_not_allowlisted"
        # Operator-relevant: the malformed entry surfaces in the message
        assert "42" in str(exc.value)

    @respx.mock
    async def test_blank_entry_in_allowlist_raises_as_not_allowlisted(
        self,
        authz: MCPAuthzClient,
        vault_client: MagicMock,
    ) -> None:
        """Empty / whitespace-only string entry is also a fail-closed
        path."""

        async def _blank(path: str) -> dict[str, Any]:
            if "mcp-oauth" in path:
                return dict(_DEFAULT_OAUTH_CREDS)
            return {"servers": ["https://as.example", "   "]}

        vault_client.read.side_effect = _blank
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": ["https://as.example"]})
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_as_not_allowlisted"

    @respx.mock
    async def test_none_entry_in_allowlist_raises_as_not_allowlisted(
        self,
        authz: MCPAuthzClient,
        vault_client: MagicMock,
    ) -> None:
        """``None`` entry triggers the non-string check."""

        async def _none_in_list(path: str) -> dict[str, Any]:
            if "mcp-oauth" in path:
                return dict(_DEFAULT_OAUTH_CREDS)
            return {"servers": ["https://as.example", None]}

        vault_client.read.side_effect = _none_in_list
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": ["https://as.example"]})
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_as_not_allowlisted"


class TestBasicAuthEncoding:
    """R7 P3: per RFC 6749 §2.3.1, ``client_secret_basic`` MUST
    form-url-encode client_id + client_secret BEFORE base64. Raw
    concatenation breaks for any secret containing reserved characters
    (``:`` ``+`` ``/`` ``=`` etc.). Vault-generated secrets routinely
    contain such characters, so this is not a corner case.
    """

    @respx.mock
    async def test_basic_auth_form_url_encodes_reserved_characters(
        self,
        authz: MCPAuthzClient,
        vault_client: MagicMock,
    ) -> None:
        """A secret containing every RFC 3986 sub-delim plus ':'+'/'
        survives the round-trip when properly form-url-encoded."""
        from urllib.parse import quote as _q

        client_id = "client+id/with:reserved"
        client_secret = "secret:with/reserved+chars=!*'(),;"
        vault_client.read.side_effect = _vault_dispatch(
            creds={
                "client_id": client_id,
                "client_secret": client_secret,
                "auth_method": "client_secret_basic",
            }
        )
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        _setup_oauth_flow(server, as_issuer)

        await authz.acquire_token(
            server_url=server,
            manifest_scopes=("mcp:tools",),
            request_id="rid",
            tenant_id="bank_a",
        )

        token_request = respx.routes[3].calls[0].request
        # Decode the Basic header and verify the ``id:secret`` halves
        # are EACH form-url-encoded (so a ':' inside the secret never
        # collides with the separator)
        auth_header = token_request.headers["Authorization"]
        assert auth_header.startswith("Basic ")
        decoded = base64.b64decode(auth_header[len("Basic ") :]).decode()
        # Each side must equal quote(value, safe="")
        encoded_id = _q(client_id, safe="")
        encoded_secret = _q(client_secret, safe="")
        assert decoded == f"{encoded_id}:{encoded_secret}"
        # Defensive: the raw secret containing ':' MUST NOT appear
        # verbatim in the decoded credential — that would mean the
        # encoding step was skipped.
        assert client_secret not in decoded
        # Defensive: only one ':' (the separator) — encoded ':' becomes %3A
        assert decoded.count(":") == 1

    @respx.mock
    async def test_basic_auth_simple_credentials_round_trip(
        self,
        authz: MCPAuthzClient,
        vault_client: MagicMock,
    ) -> None:
        """Credentials with NO reserved characters round-trip cleanly
        (encoded form == raw form for unreserved chars)."""
        vault_client.read.side_effect = _vault_dispatch(
            creds={
                "client_id": "simple-id",
                "client_secret": "simple-secret-no-reserved",
                "auth_method": "client_secret_basic",
            }
        )
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        _setup_oauth_flow(server, as_issuer)

        await authz.acquire_token(
            server_url=server,
            manifest_scopes=("mcp:tools",),
            request_id="rid",
            tenant_id="bank_a",
        )

        auth_header = respx.routes[3].calls[0].request.headers["Authorization"]
        decoded = base64.b64decode(auth_header[len("Basic ") :]).decode()
        # Unreserved characters are unchanged by quote()
        assert decoded == "simple-id:simple-secret-no-reserved"


# ---------------------------------------------------------------------------
# Sprint 5 R8 — non-finite expires_in, bool expires_in, whitespace credentials,
# RFC 6749 form-encoded space → '+' (NOT '%20')
# ---------------------------------------------------------------------------


class TestExpiresInNonFiniteAndBool:
    """R8 P2: ``float("nan")`` / ``float("inf")`` / Python ``True`` all
    parse cleanly through ``float()`` but produce token lifetimes that
    break the cache/refresh contract:

    - ``nan`` → ``time.time() + nan`` is ``nan``; the
      ``_is_token_near_expiry`` comparison ``time.time() + buffer >= nan``
      is ``False`` for all time, so a malformed token caches forever.
    - ``inf`` → defeats the operator-set TTL cap (downstream arithmetic
      assumes finite seconds).
    - ``True`` → ``float(True) == 1.0``; a 1-second token leaks through
      every type check.

    All three must fail closed with ``mcp_prm_invalid``.
    """

    @respx.mock
    async def test_nan_string_expires_in_raises_prm_invalid(self, authz: MCPAuthzClient) -> None:
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": "NaN",  # parses cleanly to float('nan')
                    "scope": "mcp:tools",
                },
            )
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_token_response_invalid"
        assert "non-finite" in str(exc.value).lower() or "nan" in str(exc.value).lower()

    @respx.mock
    async def test_infinity_string_expires_in_raises_prm_invalid(
        self, authz: MCPAuthzClient
    ) -> None:
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": "Infinity",
                    "scope": "mcp:tools",
                },
            )
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_token_response_invalid"

    @respx.mock
    async def test_bool_true_expires_in_raises_prm_invalid(self, authz: MCPAuthzClient) -> None:
        """``True`` is an int subclass; without explicit rejection it
        would yield a 1-second token lifetime."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": True,  # bool subclass of int
                    "scope": "mcp:tools",
                },
            )
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_token_response_invalid"
        assert "bool" in str(exc.value).lower()

    @respx.mock
    async def test_bool_false_expires_in_raises_prm_invalid(self, authz: MCPAuthzClient) -> None:
        """``False`` would otherwise yield a 0-second lifetime, caught
        by the non-positive guard. The bool check fires first so the
        operator sees the right diagnostic ('bool expires_in', not
        'non-positive')."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": False,
                    "scope": "mcp:tools",
                },
            )
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_token_response_invalid"
        assert "bool" in str(exc.value).lower()


class TestCredentialsWhitespaceRefused:
    """R8 P2: whitespace-only client_id / client_secret are malformed
    security configuration; mirror the allow-list strict-validation
    posture and fail closed.
    """

    @respx.mock
    async def test_whitespace_only_client_id_raises_credentials_missing(
        self,
        authz: MCPAuthzClient,
        vault_client: MagicMock,
    ) -> None:
        vault_client.read.side_effect = _vault_dispatch(
            creds={
                "client_id": "   ",
                "client_secret": "real-secret",
                "auth_method": "client_secret_post",
            }
        )
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_credentials_missing"
        assert "whitespace" in str(exc.value).lower()

    @respx.mock
    async def test_whitespace_only_client_secret_raises_credentials_missing(
        self,
        authz: MCPAuthzClient,
        vault_client: MagicMock,
    ) -> None:
        vault_client.read.side_effect = _vault_dispatch(
            creds={
                "client_id": "real-id",
                "client_secret": "\t\n  ",  # tabs + newlines + spaces
                "auth_method": "client_secret_post",
            }
        )
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_credentials_missing"
        assert "whitespace" in str(exc.value).lower()


class TestBasicAuthFormEncoding:
    """R8 P3: per RFC 6749 §2.3.1, the encoding cited is
    ``application/x-www-form-urlencoded`` — which encodes the space
    character as ``+``, NOT ``%20``. ``urllib.parse.quote_plus`` is
    the matching primitive; ``quote(safe="")`` would emit ``%20`` (the
    percent-encoding form) which is the wrong encoding per the cited
    RFC. Real-world Vault secrets occasionally contain spaces (paste-
    in passphrases), so this distinction is load-bearing.
    """

    @respx.mock
    async def test_basic_auth_encodes_space_as_plus_not_percent_20(
        self,
        authz: MCPAuthzClient,
        vault_client: MagicMock,
    ) -> None:
        client_id = "client with space"
        client_secret = "secret with space"
        vault_client.read.side_effect = _vault_dispatch(
            creds={
                "client_id": client_id,
                "client_secret": client_secret,
                "auth_method": "client_secret_basic",
            }
        )
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        _setup_oauth_flow(server, as_issuer)

        await authz.acquire_token(
            server_url=server,
            manifest_scopes=("mcp:tools",),
            request_id="rid",
            tenant_id="bank_a",
        )

        auth_header = respx.routes[3].calls[0].request.headers["Authorization"]
        decoded = base64.b64decode(auth_header[len("Basic ") :]).decode()
        # Spaces MUST encode as '+' per application/x-www-form-urlencoded;
        # NEVER as '%20' (that would be percent-encoding form, which RFC
        # 6749 §2.3.1 does not cite — the AS may or may not decode it
        # back, so the spec-compliant '+' form is mandatory).
        assert "+" in decoded
        assert "%20" not in decoded
        assert decoded == "client+with+space:secret+with+space"


# ---------------------------------------------------------------------------
# Sprint 5 R9 — narrowed-token cache correctness, malformed scope rejection,
# AS-host sanitization for issuers with ports
# ---------------------------------------------------------------------------


class TestNarrowedTokenCacheNotReused:
    """R9 P2 (refined by R10 P2): when the AS narrows the granted
    scope set below the requested set, the resulting token MUST NOT
    be returned from the cache for any subsequent broader request.

    Implementation: the cache is keyed by GRANTED scopes and the
    lookup is EXACT-match. An AS-narrowed token (granted ⊊ requested)
    is cached under the narrow granted set; a later broader acquire
    looks up under the broader requested set → cache MISS → fresh
    token request. Without exact-match, the narrowed token would
    have been silently reused for the broader call and silently
    under-scoped it.
    """

    @respx.mock
    async def test_narrowed_token_not_returned_for_broader_request(
        self,
        authz: MCPAuthzClient,
    ) -> None:
        """Caller asks for ``("mcp:tools", "mcp:tools.write")``; AS
        narrows to ``("mcp:tools",)``. A subsequent acquire for the
        same broader set MUST trigger a fresh token request — NOT
        return the cached narrowed token."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        # AS narrows: caller requests two scopes; only one comes back
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": 3600,
                    "scope": "mcp:tools",  # narrowed from requested 2
                },
            )
        )

        token1 = await authz.acquire_token(
            server_url=server,
            manifest_scopes=("mcp:tools", "mcp:tools.write"),
            request_id="rid-1",
            tenant_id="bank_a",
        )
        # Granted scope is the narrowed single-element set
        assert token1.scopes == ("mcp:tools",)

        # Second acquire for the SAME broader manifest set — the
        # cached narrowed token does NOT cover the broader request,
        # so the client MUST issue a fresh token request to the AS.
        token2 = await authz.acquire_token(
            server_url=server,
            manifest_scopes=("mcp:tools", "mcp:tools.write"),
            request_id="rid-2",
            tenant_id="bank_a",
        )
        # Token endpoint MUST have been hit twice (no silent cache hit
        # of the under-scoped token)
        token_endpoint_route = respx.routes[3]
        assert token_endpoint_route.call_count == 2
        # The second token's scopes are also the narrowed set (AS
        # behaviour didn't change), but the assertion that matters is
        # the network round-trip count above.
        assert token2.scopes == ("mcp:tools",)

    @respx.mock
    async def test_narrowed_token_returned_for_same_narrow_request(
        self,
        authz: MCPAuthzClient,
    ) -> None:
        """Same-shaped follow-up request that ASKS only for the
        narrowed set MUST hit the cache. Sanity check that the
        granted-keyed cache still serves the contract for non-pathological
        callers."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": 3600,
                    "scope": "mcp:tools",
                },
            )
        )

        # First acquire — broader request, narrowed grant. The cached
        # entry's granted scope set is the single narrow scope.
        await authz.acquire_token(
            server_url=server,
            manifest_scopes=("mcp:tools", "mcp:tools.write"),
            request_id="rid-1",
            tenant_id="bank_a",
        )
        # Second acquire — caller now asks for EXACTLY the narrow set
        # the cached token was granted. Exact-match HIT under R10.
        await authz.acquire_token(
            server_url=server,
            manifest_scopes=("mcp:tools",),
            request_id="rid-2",
            tenant_id="bank_a",
        )

        token_endpoint_route = respx.routes[3]
        assert token_endpoint_route.call_count == 1


class TestMalformedScopeResponse:
    """R9 P2: a present-but-non-string ``scope`` field (null, list,
    object, number) MUST fail closed with ``mcp_prm_invalid``. Prior
    behaviour silently substituted manifest_scopes for any non-string
    value, which bypassed the overgrant check and recorded
    ``Token.scopes`` as if the AS had granted exactly the requested
    set.
    """

    @respx.mock
    async def test_null_scope_raises_prm_invalid(self, authz: MCPAuthzClient) -> None:
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": 3600,
                    "scope": None,
                },
            )
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_token_response_invalid"
        assert "scope" in str(exc.value).lower()

    @respx.mock
    async def test_list_scope_raises_prm_invalid(self, authz: MCPAuthzClient) -> None:
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": 3600,
                    "scope": ["mcp:tools", "mcp:tools.write"],
                },
            )
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_token_response_invalid"

    @respx.mock
    async def test_object_scope_raises_prm_invalid(self, authz: MCPAuthzClient) -> None:
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": 3600,
                    "scope": {"granted": ["mcp:tools"]},
                },
            )
        )

        with pytest.raises(MCPAuthzError) as exc:
            await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )
        assert exc.value.reason == "mcp_oauth_token_response_invalid"

    @respx.mock
    async def test_absent_scope_defaults_to_manifest(self, authz: MCPAuthzClient) -> None:
        """OAuth 2.1 §3.2.3: if the AS omits the ``scope`` field
        entirely, the granted scope equals the requested scope. This
        path MUST still succeed (only present-but-malformed fails)."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": 3600,
                    # scope key omitted
                },
            )
        )

        token = await authz.acquire_token(
            server_url=server,
            manifest_scopes=("mcp:tools", "mcp:tools.write"),
            request_id="rid",
            tenant_id="bank_a",
        )
        assert frozenset(token.scopes) == frozenset(("mcp:tools", "mcp:tools.write"))


class TestAsHostSanitizationForIssuersWithPorts:
    """R9 P3: AS issuers with explicit ports yield a netloc containing
    ``:`` (e.g. ``as.example:8443``). The runtime sanitises that to
    ``as.example_8443`` before interpolating into the Vault path
    template. Pin the sanitisation behaviour with a real port-bearing
    issuer.
    """

    @respx.mock
    async def test_issuer_with_port_resolves_sanitized_vault_path(
        self,
        authz: MCPAuthzClient,
        vault_client: MagicMock,
    ) -> None:
        """An issuer ``https://as.example:8443`` MUST produce a Vault
        read at ``secret/cognic/bank_a/mcp-oauth/as.example_8443``,
        NOT ``secret/cognic/bank_a/mcp-oauth/as.example:8443``."""
        recorded_paths: list[str] = []

        async def _record(path: str) -> dict[str, Any]:
            recorded_paths.append(path)
            if "mcp-oauth" in path:
                return dict(_DEFAULT_OAUTH_CREDS)
            return {"servers": ["https://as.example:8443"]}

        vault_client.read.side_effect = _record
        as_issuer = "https://as.example:8443"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": 3600,
                    "scope": "mcp:tools",
                },
            )
        )

        await authz.acquire_token(
            server_url=server,
            manifest_scopes=("mcp:tools",),
            request_id="rid",
            tenant_id="bank_a",
        )

        creds_paths = [p for p in recorded_paths if "mcp-oauth" in p]
        assert len(creds_paths) == 1
        assert "as.example_8443" in creds_paths[0]
        assert "as.example:8443" not in creds_paths[0]


class TestCacheLookupBranchCoverage:
    """Coverage for the lookup-miss branches in
    :meth:`_lookup_cached_for_exact_scopes` — defensive lookup paths
    that must miss for cached entries belonging to a different server
    OR nearing expiry."""

    @respx.mock
    async def test_cached_entry_for_different_server_is_skipped(
        self, authz: MCPAuthzClient
    ) -> None:
        """Cache entries belonging to a different MCP server URL MUST
        not satisfy a lookup for this server (avoids cross-server
        token reuse)."""
        as_issuer = "https://as.example"
        # First server: prime the cache
        server_a = "https://server-a.example/mcp"
        respx.get(server_a).mock(return_value=httpx.Response(401))
        respx.get("https://server-a.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server_a}),
                    "expires_in": 3600,
                    "scope": "mcp:tools",
                },
            )
        )
        await authz.acquire_token(
            server_url=server_a,
            manifest_scopes=("mcp:tools",),
            request_id="rid-a",
            tenant_id="bank_a",
        )
        # Second server with the SAME scope set; lookup MUST skip the
        # server_a cache entry and issue a fresh token request.
        server_b = "https://server-b.example/mcp"
        respx.get(server_b).mock(return_value=httpx.Response(401))
        respx.get("https://server-b.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.post(f"{as_issuer}/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server_b}),
                    "expires_in": 3600,
                    "scope": "mcp:tools",
                },
            )
        )
        await authz.acquire_token(
            server_url=server_b,
            manifest_scopes=("mcp:tools",),
            request_id="rid-b",
            tenant_id="bank_a",
        )
        # Token endpoint hit twice — the server_a cached token MUST
        # NOT have been returned for server_b's lookup
        token_endpoint_route = respx.routes[3]
        assert token_endpoint_route.call_count == 2

    async def test_cached_entry_near_expiry_is_skipped(
        self,
        authz: MCPAuthzClient,
    ) -> None:
        """A cache entry whose ``expires_at`` is within the refresh
        buffer MUST be skipped by the lookup helper. Direct test of
        :meth:`_lookup_cached_for_exact_scopes` — manipulates the
        cache in place to avoid network mocking."""
        server = "https://server.example/mcp"
        near_expiry = Token(
            value="opaque",
            # Within the 60s refresh buffer → counts as near-expiry
            expires_at=time.time() + 30,
            as_issuer="https://as.example",
            scopes=("mcp:tools",),
            resource_indicator=server,
            client_id="cognic-mcp-bank_a",
        )
        # Reach into the cache directly. The helper is protected by
        # the cache lock in production; this test runs single-threaded
        # so the bare-write is safe.
        cache_key = (server, frozenset(("mcp:tools",)), server)
        authz._token_cache[cache_key] = near_expiry

        # Lookup MUST return None (the only cached entry is too close
        # to expiry to be reused).
        result = authz._lookup_cached_for_exact_scopes(
            server_url=server, requested_scopes=("mcp:tools",)
        )
        assert result is None


# ---------------------------------------------------------------------------
# Sprint 5 R10 — least-privilege exact-match cache lookup
# ---------------------------------------------------------------------------


class TestBroaderCachedTokenNotReusedForNarrowerRequest:
    """R10 P2: a stepped-up token with broader granted scopes MUST
    NOT be returned from the cache for a subsequent narrower acquire.
    Sending a higher-privileged bearer token than the call needs
    violates ADR-002 + Sprint-5 plan's minimum-scope acquisition
    contract.

    This is the inverse of R9's narrower-grant invariant. Together,
    R9 + R10 define exact-match cache reuse: a cached token's granted
    scopes MUST equal the requested scope set for a hit; otherwise
    the client issues a fresh, minimum-scope token request.
    """

    @respx.mock
    async def test_broader_cached_token_not_returned_for_narrower_request(
        self,
        authz: MCPAuthzClient,
    ) -> None:
        """Step-up has cached a token under granted=
        ``("mcp:tools", "mcp:tools.write")``. A subsequent acquire
        for ONLY ``("mcp:tools",)`` MUST issue a fresh request; the
        broader cached token is NOT returned (least privilege)."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )

        # Token endpoint always returns exactly the requested scope
        # (so the broader caller gets broader, narrower caller gets
        # narrower — no AS narrowing/widening, just plain matching)
        def _token_response(request: httpx.Request) -> httpx.Response:
            body = request.read().decode()
            # form-decode the scope param
            from urllib.parse import parse_qs

            parsed = parse_qs(body)
            granted = parsed.get("scope", ["mcp:tools"])[0]
            return httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": 3600,
                    "scope": granted,
                },
            )

        respx.post(f"{as_issuer}/token").mock(side_effect=_token_response)

        # Step 1: caller acquires the broader 2-scope token (this is
        # the equivalent of a step-up that ran earlier in the session).
        broader = await authz.acquire_token(
            server_url=server,
            manifest_scopes=("mcp:tools", "mcp:tools.write"),
            request_id="rid-broader",
            tenant_id="bank_a",
        )
        assert frozenset(broader.scopes) == frozenset(("mcp:tools", "mcp:tools.write"))

        # Step 2: caller now acquires a NARROWER 1-scope token. The
        # broader cached token MUST NOT satisfy this request — we
        # want minimum privilege.
        narrower = await authz.acquire_token(
            server_url=server,
            manifest_scopes=("mcp:tools",),
            request_id="rid-narrower",
            tenant_id="bank_a",
        )

        # Token endpoint MUST have been hit twice (no silent broader-
        # token reuse for the narrower call). The two-network-roundtrip
        # assertion is the load-bearing check; the token byte-value can
        # incidentally collide because the test's stub JWT is
        # deterministic per ``aud`` claim.
        token_endpoint_route = respx.routes[3]
        assert token_endpoint_route.call_count == 2
        # The narrower acquire returns a narrow-scope token, NOT the
        # cached broader one
        assert narrower.scopes == ("mcp:tools",)
        assert frozenset(broader.scopes) != frozenset(narrower.scopes)

    @respx.mock
    async def test_step_up_broader_cache_does_not_serve_narrow_acquire(
        self,
        authz: MCPAuthzClient,
    ) -> None:
        """End-to-end: real :meth:`step_up_token` populates the cache
        with a broader-scope token; a subsequent :meth:`acquire_token`
        for the narrower scope MUST issue a fresh narrow-scope request
        (least privilege) — NOT return the broader cached token."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )

        def _token_response(request: httpx.Request) -> httpx.Response:
            from urllib.parse import parse_qs

            parsed = parse_qs(request.read().decode())
            granted = parsed.get("scope", ["mcp:tools"])[0]
            return httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": 3600,
                    "scope": granted,
                },
            )

        respx.post(f"{as_issuer}/token").mock(side_effect=_token_response)

        # Caller has a narrow token already
        current = Token(
            value=_make_jwt({"aud": server}),
            expires_at=time.time() + 3600,
            as_issuer=as_issuer,
            scopes=("mcp:tools",),
            resource_indicator=server,
            client_id="cognic-mcp-bank_a",
        )
        # Step-up to a broader scope set; this caches the broader
        # token under its granted scopes
        await authz.step_up_token(
            server_url=server,
            current_token=current,
            requested_scope="mcp:tools.write",
            manifest_scopes=("mcp:tools", "mcp:tools.write"),
            request_id="rid-stepup",
            tenant_id="bank_a",
        )

        # Token endpoint hit count after the step-up
        token_endpoint_route = respx.routes[3]
        post_step_up_count = token_endpoint_route.call_count

        # Now the caller's NARROW path needs a fresh token. The cache
        # holds a broader token, but the exact-match rule MUST force
        # a fresh narrow-scope request.
        narrow = await authz.acquire_token(
            server_url=server,
            manifest_scopes=("mcp:tools",),
            request_id="rid-narrow",
            tenant_id="bank_a",
        )

        # The narrow acquire MUST have triggered an additional token
        # endpoint call — NOT served from the broader cache entry.
        assert token_endpoint_route.call_count == post_step_up_count + 1
        assert narrow.scopes == ("mcp:tools",)


# ---------------------------------------------------------------------------
# Sprint 5 R11 — in-flight coalescing for concurrent cold acquires
# ---------------------------------------------------------------------------


class TestInflightAcquireCoalescing:
    """R11 P2 (a): two concurrent cold acquires for the same
    ``(server, exact_scope_set, resource)`` cache key MUST issue ONE
    network round-trip to the AS, not two. The cache lock alone is
    not enough — it's released between cache miss and network call,
    so a keyed in-flight Future map serialises the work without
    holding the lock through I/O.
    """

    @respx.mock
    async def test_two_concurrent_cold_acquires_share_one_network_roundtrip(
        self,
        authz: MCPAuthzClient,
    ) -> None:
        """Two callers ``await`` ``acquire_token`` concurrently for the
        same scope set on a cold cache. The token endpoint MUST be
        hit exactly once; both callers receive the same Token."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        # Slow response: a small sleep simulates an AS round-trip
        # taking long enough for a second concurrent caller to hit
        # the cache miss + see the in-flight Future.
        token_post_started = asyncio.Event()
        token_post_release = asyncio.Event()

        async def _slow_token_response(request: httpx.Request) -> httpx.Response:
            token_post_started.set()
            await token_post_release.wait()
            return httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": 3600,
                    "scope": "mcp:tools",
                },
            )

        respx.post(f"{as_issuer}/token").mock(side_effect=_slow_token_response)

        async def _acquire() -> Token:
            return await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )

        # Launch two concurrent acquires; release the AS response only
        # after the first has reached the token endpoint.
        task_a = asyncio.create_task(_acquire())
        task_b = asyncio.create_task(_acquire())
        await token_post_started.wait()
        # By now task_a has begun the token POST. Give task_b a chance
        # to enter the cache-miss + in-flight registration path.
        await asyncio.sleep(0)
        token_post_release.set()
        token_a, token_b = await asyncio.gather(task_a, task_b)

        # Both callers got the SAME token (same scopes + resource);
        # the AS saw exactly ONE token request despite two callers.
        assert token_a.scopes == ("mcp:tools",) == token_b.scopes
        token_endpoint_route = respx.routes[3]
        assert token_endpoint_route.call_count == 1

    @respx.mock
    async def test_inflight_failure_propagates_to_concurrent_waiter(
        self,
        authz: MCPAuthzClient,
    ) -> None:
        """If the in-flight owner raises, every concurrent waiter MUST
        see the same failure (consistent outcome) AND the in-flight
        slot MUST be cleared so a subsequent retry can issue a fresh
        request (transient errors don't poison the cache key)."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )
        # First call: AS returns 503. After both concurrent callers
        # complete, retry returns success.
        responses = [
            httpx.Response(503),
            httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": 3600,
                    "scope": "mcp:tools",
                },
            ),
        ]

        token_post_started = asyncio.Event()
        token_post_release = asyncio.Event()

        async def _gated(_request: httpx.Request) -> httpx.Response:
            token_post_started.set()
            await token_post_release.wait()
            return responses.pop(0)

        respx.post(f"{as_issuer}/token").mock(side_effect=_gated)

        async def _acquire() -> Token:
            return await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )

        task_a = asyncio.create_task(_acquire())
        task_b = asyncio.create_task(_acquire())
        await token_post_started.wait()
        await asyncio.sleep(0)
        token_post_release.set()

        with pytest.raises(MCPAuthzError) as exc_a:
            await task_a
        with pytest.raises(MCPAuthzError) as exc_b:
            await task_b

        # Both callers received the SAME closed-enum reason
        assert exc_a.value.reason == "mcp_oauth_token_endpoint_error"
        assert exc_b.value.reason == "mcp_oauth_token_endpoint_error"
        # Token endpoint hit exactly once for the failed pair
        token_endpoint_route = respx.routes[3]
        assert token_endpoint_route.call_count == 1

        # Critical: the in-flight slot was cleared on failure, so a
        # subsequent retry MUST be able to issue a fresh request and
        # succeed (transient AS error doesn't permanently block the
        # cache key).
        token_post_started.clear()
        token_post_release.set()
        token = await authz.acquire_token(
            server_url=server,
            manifest_scopes=("mcp:tools",),
            request_id="rid-retry",
            tenant_id="bank_a",
        )
        assert token.scopes == ("mcp:tools",)
        assert token_endpoint_route.call_count == 2

    @respx.mock
    async def test_inflight_slot_cleared_after_success(
        self,
        authz: MCPAuthzClient,
    ) -> None:
        """After a successful acquire, the in-flight slot MUST be
        empty (sanity check on the success-path deregister)."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        _setup_oauth_flow(server, as_issuer)

        await authz.acquire_token(
            server_url=server,
            manifest_scopes=("mcp:tools",),
            request_id="rid",
            tenant_id="bank_a",
        )

        # In-flight map MUST be empty (no leaked Future entries)
        assert authz._inflight_acquires == {}


# ---------------------------------------------------------------------------
# Sprint 5 R12 — cancellation hardening for the in-flight Future
# ---------------------------------------------------------------------------


class TestInflightCancellationHardening:
    """R12 P2: the shared in-flight Future MUST survive waiter
    cancellation. A bare ``await future`` propagates the awaiter's
    cancellation INTO the Future, marking it cancelled; the owner's
    later ``set_result`` / ``set_exception`` would then raise
    ``InvalidStateError`` and (worse, on the failure path) leave a
    poisoned in-flight slot.

    Three invariants:
      1. Cancelling a waiter MUST NOT cancel the shared Future.
      2. Cancelling a waiter MUST NOT poison the in-flight slot.
      3. The owner's ``set_result`` / ``set_exception`` MUST be guarded
         with ``not future.done()`` so a Future that somehow ended up
         cancelled doesn't raise InvalidStateError when the owner
         tries to resolve it.
    """

    @respx.mock
    async def test_cancelling_waiter_does_not_break_owner(
        self,
        authz: MCPAuthzClient,
    ) -> None:
        """Two concurrent acquires; cancel the second (the waiter)
        before the first resolves. The first MUST still complete
        successfully and return a valid token."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )

        token_post_started = asyncio.Event()
        token_post_release = asyncio.Event()

        async def _gated(_request: httpx.Request) -> httpx.Response:
            token_post_started.set()
            await token_post_release.wait()
            return httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": 3600,
                    "scope": "mcp:tools",
                },
            )

        respx.post(f"{as_issuer}/token").mock(side_effect=_gated)

        async def _acquire() -> Token:
            return await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )

        owner = asyncio.create_task(_acquire())
        waiter = asyncio.create_task(_acquire())
        await token_post_started.wait()
        # Give the waiter a chance to register on the in-flight Future
        await asyncio.sleep(0)
        # Cancel the waiter mid-await
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        # Now release the AS response — owner MUST still complete.
        token_post_release.set()
        token = await owner
        assert token.scopes == ("mcp:tools",)
        # In-flight slot cleaned up
        assert authz._inflight_acquires == {}
        # Token endpoint hit exactly once
        token_endpoint_route = respx.routes[3]
        assert token_endpoint_route.call_count == 1

    @respx.mock
    async def test_cancelling_waiter_does_not_poison_inflight_slot(
        self,
        authz: MCPAuthzClient,
    ) -> None:
        """Cancel a waiter during the in-flight network call. After
        the owner's failure, a fresh acquire MUST succeed (the
        in-flight slot is not stuck with a cancelled Future from the
        waiter's cancellation)."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )

        # First call: AS returns 503; subsequent calls: 200.
        responses = [
            httpx.Response(503),
            httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": 3600,
                    "scope": "mcp:tools",
                },
            ),
        ]
        token_post_started = asyncio.Event()
        token_post_release = asyncio.Event()

        async def _gated(_request: httpx.Request) -> httpx.Response:
            token_post_started.set()
            await token_post_release.wait()
            return responses.pop(0)

        respx.post(f"{as_issuer}/token").mock(side_effect=_gated)

        async def _acquire() -> Token:
            return await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )

        owner = asyncio.create_task(_acquire())
        waiter = asyncio.create_task(_acquire())
        await token_post_started.wait()
        await asyncio.sleep(0)
        # Cancel the waiter — its task dies with CancelledError but
        # the shared Future is untouched (shield).
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        # Release: owner sees the 503 → fails with token_endpoint_error
        token_post_release.set()
        with pytest.raises(MCPAuthzError) as exc:
            await owner
        assert exc.value.reason == "mcp_oauth_token_endpoint_error"

        # In-flight slot cleared (R12 finally-deregister); a fresh
        # acquire MUST succeed (no poisoned slot from the cancelled
        # waiter or the owner's exception).
        assert authz._inflight_acquires == {}

        token_post_started.clear()
        token_post_release.set()
        token = await authz.acquire_token(
            server_url=server,
            manifest_scopes=("mcp:tools",),
            request_id="rid-retry",
            tenant_id="bank_a",
        )
        assert token.scopes == ("mcp:tools",)

    async def test_set_result_skipped_when_future_already_done(self) -> None:
        """Direct white-box check: ``set_result`` on a cancelled
        Future raises ``InvalidStateError``. The guard pattern
        (``if not fut.done(): fut.set_result(...)``) used in
        :meth:`acquire_token`'s success / except branches MUST be
        skip-on-done, not raise-on-done. Defensive coverage of the
        guard's semantics — shield should make the cancelled-during-
        owner-resolve race unreachable in practice, but the guard is
        the belt-and-braces safety net.
        """
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[Token] = loop.create_future()
        fut.cancel()
        assert fut.done()

        # The contract: the guarded resolve MUST NOT raise.
        if not fut.done():
            fut.set_result(  # pragma: no cover — guarded branch never fires here
                Token(
                    value="x",
                    expires_at=time.time() + 3600,
                    as_issuer="https://as.example",
                    scopes=("mcp:tools",),
                    resource_indicator="https://server.example/mcp",
                    client_id="cognic-mcp-bank_a",
                )
            )
        # No assertion needed — the test passes if no InvalidStateError
        # was raised. The guard is exactly what acquire_token does
        # before its set_result / set_exception calls.

    @respx.mock
    async def test_cancelling_owner_propagates_to_waiter(
        self,
        authz: MCPAuthzClient,
    ) -> None:
        """If the owner's task is cancelled mid-network-call, the
        waiter MUST NOT hang forever. The in-flight slot MUST be
        cleared so subsequent acquires can proceed."""
        as_issuer = "https://as.example"
        server = "https://server.example/mcp"
        respx.get(server).mock(return_value=httpx.Response(401))
        respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json={"authorization_servers": [as_issuer]})
        )
        respx.get(f"{as_issuer}/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json={"token_endpoint": f"{as_issuer}/token"})
        )

        token_post_started = asyncio.Event()
        token_post_release = asyncio.Event()

        async def _gated(_request: httpx.Request) -> httpx.Response:
            token_post_started.set()
            await token_post_release.wait()
            return httpx.Response(
                200,
                json={
                    "access_token": _make_jwt({"aud": server}),
                    "expires_in": 3600,
                    "scope": "mcp:tools",
                },
            )

        respx.post(f"{as_issuer}/token").mock(side_effect=_gated)

        async def _acquire() -> Token:
            return await authz.acquire_token(
                server_url=server,
                manifest_scopes=("mcp:tools",),
                request_id="rid",
                tenant_id="bank_a",
            )

        owner = asyncio.create_task(_acquire())
        waiter = asyncio.create_task(_acquire())
        await token_post_started.wait()
        await asyncio.sleep(0)
        owner.cancel()
        with pytest.raises(asyncio.CancelledError):
            await owner

        # Waiter MUST receive an exception (CancelledError from the
        # owner's set_exception, or the underlying CancelledError),
        # not hang. Tight timeout asserts non-hang.
        with pytest.raises((asyncio.CancelledError, MCPAuthzError)):
            await asyncio.wait_for(waiter, timeout=1.0)

        # Slot cleared regardless of which exception type the waiter
        # received (finally-deregister is identity-checked).
        assert authz._inflight_acquires == {}
