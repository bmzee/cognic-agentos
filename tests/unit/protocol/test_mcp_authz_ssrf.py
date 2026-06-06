"""MCP SSRF guard — remediation §4.1 (multi-agent review 2026-06-06).

OAuth/PRM discovery fetches must refuse non-http(s) schemes and, in the
stage/prod (strict) profile, hosts that resolve to private / loopback /
link-local / reserved addresses — BEFORE any network I/O — at BOTH fetch
surfaces (``discover_resource_metadata`` for ``server_url`` and ``_fetch_prm``
for the server-controlled ``WWW-Authenticate`` PRM URL). Rejection payloads
identify the refused component CLASS only and NEVER echo the raw URL
(credential-leak doctrine, mirrors ``a2a_agent_cards``).

Hermetic: IP-literal hosts exercise the range check with no real DNS; the
hostname→internal path monkeypatches the module-level resolver seam.
"""

from __future__ import annotations

from typing import cast
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.protocol import mcp_authz
from cognic_agentos.protocol.mcp_authz import MCPAuthzClient, MCPAuthzError


class _StubHttp:
    """Records GET URLs; optionally raises if called (to prove the guard
    short-circuits before any network I/O)."""

    def __init__(
        self, *, fail_if_called: bool = False, responses: dict[str, httpx.Response] | None = None
    ) -> None:
        self.fail_if_called = fail_if_called
        self._responses = responses or {}
        self.gets: list[str] = []

    async def get(self, url: str, timeout: float | None = None) -> httpx.Response:
        if self.fail_if_called:
            raise AssertionError(f"SSRF guard should have refused before GET {url!r}")
        self.gets.append(url)
        resp = self._responses.get(url)
        if resp is None:
            return httpx.Response(404, request=httpx.Request("GET", url))
        return resp


def _client(http: _StubHttp, *, profile: str) -> MCPAuthzClient:
    settings = build_settings_without_env_file().model_copy(update={"runtime_profile": profile})
    audit = MagicMock()
    audit.append = AsyncMock()
    return MCPAuthzClient(
        settings=settings,
        vault_client=MagicMock(),
        http_client=cast(httpx.AsyncClient, http),
        audit_store=audit,
        decision_history_store=MagicMock(),
    )


async def _discover(client: MCPAuthzClient, url: str) -> object:
    return await client.discover_resource_metadata(server_url=url, request_id="r1", tenant_id="t1")


async def test_non_http_scheme_refused_before_fetch() -> None:
    http = _StubHttp(fail_if_called=True)
    with pytest.raises(MCPAuthzError) as e:
        await _discover(_client(http, profile="prod"), "file:///etc/passwd")
    assert e.value.reason == "mcp_discovery_url_refused"
    assert e.value.payload.get("refused_component") == "scheme"
    assert http.gets == []
    assert "etc/passwd" not in repr(e.value.payload)  # no raw-URL echo


async def test_metadata_ip_literal_refused_in_strict() -> None:
    http = _StubHttp(fail_if_called=True)
    with pytest.raises(MCPAuthzError) as e:
        await _discover(_client(http, profile="prod"), "http://169.254.169.254/latest/meta-data/")
    assert e.value.reason == "mcp_discovery_url_refused"
    assert e.value.payload.get("refused_component") == "host_address"
    assert http.gets == []


async def test_loopback_ip_literal_refused_in_strict() -> None:
    http = _StubHttp(fail_if_called=True)
    with pytest.raises(MCPAuthzError) as e:
        await _discover(_client(http, profile="prod"), "http://127.0.0.1:8080/mcp")
    assert e.value.reason == "mcp_discovery_url_refused"


async def test_rfc1918_ip_literal_refused_in_strict() -> None:
    http = _StubHttp(fail_if_called=True)
    with pytest.raises(MCPAuthzError) as e:
        await _discover(_client(http, profile="prod"), "http://10.0.0.5/mcp")
    assert e.value.reason == "mcp_discovery_url_refused"


async def test_hostname_resolving_to_internal_refused_in_strict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fake_resolve(host: str) -> list[str]:
        return ["169.254.169.254"]

    monkeypatch.setattr(mcp_authz, "_resolve_host_addresses", _fake_resolve)
    http = _StubHttp(fail_if_called=True)
    with pytest.raises(MCPAuthzError) as e:
        await _discover(_client(http, profile="prod"), "https://metadata.evil.example/")
    assert e.value.reason == "mcp_discovery_url_refused"
    assert e.value.payload.get("refused_component") == "host_address"


async def test_loopback_allowed_in_dev_profile() -> None:
    # dev profile: the IP-range gate does not apply; a localhost MCP server is legit.
    http = _StubHttp()  # all 404 -> falls through to anonymous
    with pytest.raises(MCPAuthzError) as e:
        await _discover(_client(http, profile="dev"), "http://127.0.0.1:9000/mcp")
    assert e.value.reason != "mcp_discovery_url_refused"  # guard does not block in dev
    assert http.gets  # the fetch proceeded


async def test_www_authenticate_internal_prm_url_refused() -> None:
    # public server_url passes, but its 401 WWW-Authenticate points the PRM fetch
    # at the cloud-metadata IP — the _fetch_prm guard must refuse it.
    www = 'Bearer resource_metadata="http://169.254.169.254/latest/meta-data/"'
    http = _StubHttp(
        responses={
            "https://8.8.8.8/": httpx.Response(
                401,
                headers={"WWW-Authenticate": www},
                request=httpx.Request("GET", "https://8.8.8.8/"),
            )
        }
    )
    with pytest.raises(MCPAuthzError) as e:
        await _discover(_client(http, profile="prod"), "https://8.8.8.8/")
    assert e.value.reason == "mcp_discovery_url_refused"
    assert e.value.payload.get("refused_component") == "host_address"
    assert "https://8.8.8.8/" in http.gets  # public server WAS fetched
    assert all("169.254" not in u for u in http.gets)  # internal PRM URL was NOT


async def test_public_ip_literal_passes_guard() -> None:
    http = _StubHttp()  # 404 on all 3 paths -> anonymous_refused (guard passed)
    with pytest.raises(MCPAuthzError) as e:
        await _discover(_client(http, profile="prod"), "https://8.8.8.8/")
    assert e.value.reason == "mcp_anonymous_refused"
    assert http.gets  # fetched (guard allowed the public host)
