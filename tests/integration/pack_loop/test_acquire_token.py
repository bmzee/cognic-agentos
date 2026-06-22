# tests/integration/pack_loop/test_acquire_token.py
"""Proof 1a Task 5 — MCPAuthzClient.acquire_token succeeds against the live local
AS + the live pack server + a seeded in-memory secret adapter.

This is the trickiest harness piece: it exercises the REAL runtime OAuth/PRM path
(PRM discovery -> per-tenant AS allow-list -> token request -> resource binding).
"""

import datetime as dt
import importlib.util
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import AuditStore, _audit_event, _chain_heads
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.db.adapters.protocols import AdapterHealth, SecretLease

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("cognic_tool_search") is None
    or importlib.util.find_spec("mcp") is None,
    reason="cognic-tool-search and the mcp SDK must be installed",
)

_TENANT = "proof_tenant"
# The PRM advertises the AS issuer in pydantic-normalized form WITH a trailing
# slash (Task 4 finding), and the runtime AS allow-list check is exact-string
# membership — so the allow-list seed MUST use the slash form.
_AS_ISSUER_ADVERTISED = "http://127.0.0.1:9000/"
_AS_HOST_KEY = "127.0.0.1_9000"  # urlparse(issuer).netloc, ':'->'_' (slash irrelevant)
_SERVER_URL = "http://127.0.0.1:8765/mcp"


class _SeededSecretAdapter:
    """Seeded SecretAdapter stub — only ``read`` is exercised by the authz path.

    Implements the full SecretAdapter Protocol surface so it satisfies
    MCPAuthzClient's concrete ``vault_client: SecretAdapter`` parameter under
    strict mypy. The four unexercised methods raise NotImplementedError
    (fail-loud — they must never be hit on the acquire_token success path).
    """

    def __init__(self, secrets: dict[str, dict[str, Any]]) -> None:
        self._secrets = secrets

    async def read(self, path: str) -> dict[str, Any]:
        return self._secrets[path]

    async def write(self, path: str, value: dict[str, Any]) -> None:
        raise NotImplementedError("Proof 1a authz path never writes secrets")

    async def lease(self, path: str, ttl_s: int) -> SecretLease:
        raise NotImplementedError("Proof 1a authz path never leases secrets")

    async def revoke(self, lease_id: str) -> None:
        raise NotImplementedError("Proof 1a authz path never revokes leases")

    async def health_check(self) -> AdapterHealth:
        raise NotImplementedError("Proof 1a authz path never health-checks vault")


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    # Real in-memory governance stores satisfy MCPAuthzClient's concrete
    # AuditStore / DecisionHistoryStore constructor types under strict mypy.
    # The acquire_token SUCCESS path never appends (audit/decision-history fire
    # only on step-up / refresh), but constructing the real tables + seeding
    # both chain heads keeps the harness robust if an append ever lands here.
    url = f"sqlite+aiosqlite:///{tmp_path / 'pack_loop_acquire.db'}"
    eng = create_async_engine(url)
    async with eng.begin() as conn:
        await conn.run_sync(_audit_event.metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id,
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=dt.datetime.now(dt.UTC),
                )
            )
    yield eng
    await eng.dispose()


@pytest.mark.asyncio
async def test_acquire_token_succeeds_end_to_end(
    pack_server: str, local_as: str, engine: AsyncEngine
) -> None:
    # The `pack_server` (127.0.0.1:8765) and `local_as` (127.0.0.1:9000) fixtures
    # (conftest.py) have started both servers once + waited for their ports.
    from cognic_agentos.core.config import build_settings_without_env_file
    from cognic_agentos.protocol.mcp_authz import MCPAuthzClient

    secret = _SeededSecretAdapter(
        {
            f"secret/cognic/{_TENANT}/mcp-as-allowlist": {"servers": [_AS_ISSUER_ADVERTISED]},
            f"secret/cognic/{_TENANT}/mcp-oauth/{_AS_HOST_KEY}": {
                "client_id": "cognic-mcp-proof",
                "client_secret": "proof-secret",
                "auth_method": "client_secret_post",
            },
        }
    )

    settings = build_settings_without_env_file()  # runtime_profile defaults to "dev"
    assert settings.runtime_profile == "dev"  # loopback SSRF guard is off in dev

    async with httpx.AsyncClient() as http_client:
        authz = MCPAuthzClient(
            settings=settings,
            vault_client=secret,
            http_client=http_client,
            audit_store=AuditStore(engine),
            decision_history_store=DecisionHistoryStore(engine),
        )
        token = await authz.acquire_token(
            server_url=_SERVER_URL,
            manifest_scopes=("mcp:tools",),
            request_id="proof-rid",
            tenant_id=_TENANT,
        )

    assert token.value
    assert token.resource_indicator == _SERVER_URL
    assert set(token.scopes) <= {"mcp:tools"}
