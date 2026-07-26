"""D2 regressions for tenant-isolated MCP OAuth token caching.

These tests pin the two tenant boundaries independently:

* a warm token cache entry cannot cross tenants; and
* an in-flight acquisition cannot coalesce callers from different tenants.

They also pin the deliberate bounded-staleness posture for same-tenant cache
hits: Vault is not re-read on a hit, while the cached token's effective
expiry remains capped by the configured cache TTL.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import json
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import respx

from cognic_agentos.core.config import Settings, build_settings_without_env_file
from cognic_agentos.protocol.mcp_authz import (
    MCPAuthzClient,
    MCPAuthzError,
    ResourceMetadata,
    Token,
)

_SERVER = "https://server.example/mcp"
_AS_ISSUER = "https://as.example"
_SCOPES = ("mcp:tools",)


def _settings(*, cache_ttl_s: int = 3600) -> Settings:
    return build_settings_without_env_file().model_copy(
        update={
            "mcp_oauth_request_timeout_s": 5,
            "mcp_oauth_token_cache_ttl_s": cache_ttl_s,
            "mcp_as_allowlist_path": "secret/cognic/{tenant}/mcp-as-allowlist",
            "mcp_oauth_credentials_path": "secret/cognic/{tenant}/mcp-oauth/{as_host}",
        }
    )


def _client(
    *,
    http_client: httpx.AsyncClient,
    settings: Settings | None = None,
    vault_read: AsyncMock | None = None,
) -> MCPAuthzClient:
    vault = MagicMock()
    vault.read = vault_read or AsyncMock()
    audit = MagicMock()
    audit.append = AsyncMock()
    decisions = MagicMock()
    decisions.append = AsyncMock()
    return MCPAuthzClient(
        settings=settings or _settings(),
        vault_client=vault,
        http_client=http_client,
        audit_store=audit,
        decision_history_store=decisions,
    )


def _metadata() -> ResourceMetadata:
    return ResourceMetadata(
        resource=_SERVER,
        authorization_servers=(_AS_ISSUER,),
        scopes_supported=_SCOPES,
        discovery_path="endpoint-well-known",
    )


def _token(tenant_id: str) -> Token:
    return Token(
        value=f"token-for-{tenant_id}",
        expires_at=time.time() + 3600,
        as_issuer=_AS_ISSUER,
        scopes=_SCOPES,
        resource_indicator=_SERVER,
        client_id=f"client-for-{tenant_id}",
    )


def _jwt(payload: dict[str, Any]) -> str:
    def _part(value: dict[str, Any]) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{_part({'alg': 'HS256', 'typ': 'JWT'})}.{_part(payload)}.signature"


async def _yield_to_peer() -> None:
    """Give a newly-created task enough loop turns to reach the in-flight map."""
    for _ in range(3):
        await asyncio.sleep(0)


async def test_warm_cache_cannot_bypass_another_tenants_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tenant B must discover and consult its own policy despite A's warm cache."""
    async with httpx.AsyncClient() as http_client:
        client = _client(http_client=http_client)

        discovery_tenants: list[str] = []
        allowlist_tenants: list[str] = []
        request_tenants: list[str] = []

        async def _discover(**kwargs: Any) -> ResourceMetadata:
            discovery_tenants.append(kwargs["tenant_id"])
            return _metadata()

        async def _allowlist(tenant_id: str) -> frozenset[str]:
            allowlist_tenants.append(tenant_id)
            if tenant_id == "tenant-a":
                return frozenset({_AS_ISSUER})
            return frozenset()

        async def _request(**kwargs: Any) -> Token:
            tenant_id = kwargs["tenant_id"]
            request_tenants.append(tenant_id)
            return _token(tenant_id)

        monkeypatch.setattr(client, "discover_resource_metadata", _discover)
        monkeypatch.setattr(client, "_load_as_allowlist", _allowlist)
        monkeypatch.setattr(client, "_request_token", _request)

        token_a = await client.acquire_token(
            server_url=_SERVER,
            manifest_scopes=_SCOPES,
            request_id="request-a",
            tenant_id="tenant-a",
        )

        with pytest.raises(MCPAuthzError) as exc:
            await client.acquire_token(
                server_url=_SERVER,
                manifest_scopes=_SCOPES,
                request_id="request-b",
                tenant_id="tenant-b",
            )

    assert token_a.value == "token-for-tenant-a"
    assert exc.value.reason == "mcp_as_not_allowlisted"
    assert discovery_tenants == ["tenant-a", "tenant-b"]
    assert allowlist_tenants == ["tenant-a", "tenant-b"]
    assert request_tenants == ["tenant-a"]


async def test_different_tenants_do_not_share_an_inflight_acquisition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cold concurrent calls for different tenants must each own their work."""
    async with httpx.AsyncClient() as http_client:
        client = _client(http_client=http_client)

        request_tenants: list[str] = []
        first_request_started = asyncio.Event()
        release_requests = asyncio.Event()

        async def _discover(**_kwargs: Any) -> ResourceMetadata:
            return _metadata()

        async def _allowlist(_tenant_id: str) -> frozenset[str]:
            return frozenset({_AS_ISSUER})

        async def _request(**kwargs: Any) -> Token:
            tenant_id = kwargs["tenant_id"]
            request_tenants.append(tenant_id)
            first_request_started.set()
            await release_requests.wait()
            return _token(tenant_id)

        monkeypatch.setattr(client, "discover_resource_metadata", _discover)
        monkeypatch.setattr(client, "_load_as_allowlist", _allowlist)
        monkeypatch.setattr(client, "_request_token", _request)

        async def _acquire(tenant_id: str) -> Token:
            return await client.acquire_token(
                server_url=_SERVER,
                manifest_scopes=_SCOPES,
                request_id=f"request-{tenant_id}",
                tenant_id=tenant_id,
            )

        task_a = asyncio.create_task(_acquire("tenant-a"))
        await first_request_started.wait()
        task_b = asyncio.create_task(_acquire("tenant-b"))
        await _yield_to_peer()
        release_requests.set()
        token_a, token_b = await asyncio.gather(task_a, task_b)

    assert request_tenants == ["tenant-a", "tenant-b"]
    assert token_a.value == "token-for-tenant-a"
    assert token_b.value == "token-for-tenant-b"
    assert client._inflight_acquires == {}


@respx.mock
async def test_same_tenant_hit_uses_ttl_bound_without_vault_recheck() -> None:
    """The expensive Vault allow-list read is skipped only within the TTL bound."""
    cache_ttl_s = 120

    async def _read(path: str) -> dict[str, Any]:
        if "mcp-oauth" in path:
            return {
                "client_id": "tenant-a-client",
                "client_secret": "vault-secret",
                "auth_method": "client_secret_post",
            }
        return {"servers": [_AS_ISSUER]}

    vault_read = AsyncMock(side_effect=_read)
    respx.get(_SERVER).mock(return_value=httpx.Response(401))
    respx.get("https://server.example/.well-known/oauth-protected-resource/mcp").mock(
        return_value=httpx.Response(200, json={"authorization_servers": [_AS_ISSUER]})
    )
    respx.get(f"{_AS_ISSUER}/.well-known/oauth-authorization-server").mock(
        return_value=httpx.Response(200, json={"token_endpoint": f"{_AS_ISSUER}/token"})
    )
    token_route = respx.post(f"{_AS_ISSUER}/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": _jwt({"aud": _SERVER}),
                "expires_in": 3600,
                "scope": "mcp:tools",
            },
        )
    )

    async with httpx.AsyncClient() as http_client:
        client = _client(
            http_client=http_client,
            settings=_settings(cache_ttl_s=cache_ttl_s),
            vault_read=vault_read,
        )
        before = time.time()
        first = await client.acquire_token(
            server_url=_SERVER,
            manifest_scopes=_SCOPES,
            request_id="request-1",
            tenant_id="tenant-a",
        )
        vault_reads_after_fill = vault_read.await_count

        second = await client.acquire_token(
            server_url=_SERVER,
            manifest_scopes=_SCOPES,
            request_id="request-2",
            tenant_id="tenant-a",
        )

        assert second is first
        assert vault_read.await_count == vault_reads_after_fill == 2
        assert token_route.call_count == 1
        assert first.expires_at <= before + cache_ttl_s + 1

        async def _read_after_delisting(path: str) -> dict[str, Any]:
            if "mcp-oauth" in path:
                return {
                    "client_id": "tenant-a-client",
                    "client_secret": "vault-secret",
                    "auth_method": "client_secret_post",
                }
            return {"servers": []}

        vault_read.side_effect = _read_after_delisting
        cache_key = next(iter(client._token_cache))
        client._token_cache[cache_key] = dataclasses.replace(first, expires_at=time.time() + 30)

        with pytest.raises(MCPAuthzError) as exc:
            await client.acquire_token(
                server_url=_SERVER,
                manifest_scopes=_SCOPES,
                request_id="request-3",
                tenant_id="tenant-a",
            )

    assert exc.value.reason == "mcp_as_not_allowlisted"
    assert vault_read.await_count == vault_reads_after_fill + 1
    assert token_route.call_count == 1
