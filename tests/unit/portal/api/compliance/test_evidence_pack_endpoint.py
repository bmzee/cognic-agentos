"""Sprint 9 T6 — evidence-pack endpoint: RBAC, tenant isolation, 503."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from cognic_agentos.core.config import Settings
from cognic_agentos.db.adapters import AdapterRegistry
from cognic_agentos.db.adapters.local_object_store_adapter import LocalObjectStoreAdapter
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.scopes import (
    ComplianceRBACScope,
    PackRBACScope,
    UIRBACScope,
)
from tests.support.adapter_fixtures import (
    InMemoryEmbeddingAdapter,
    InMemoryObservabilityAdapter,
    InMemoryRelationalAdapter,
    InMemorySecretAdapter,
    InMemoryVectorAdapter,
)

_PARAMS = {"from": "2026-01-01T00:00:00Z", "to": "2026-12-31T00:00:00Z", "scope": "t-1"}

#: The externally visible evidence-pack route path (Pin 1 / Pin 2 contract).
_ROUTE = "/api/v1/compliance/evidence-pack"

_Scope = PackRBACScope | UIRBACScope | ComplianceRBACScope


class _StubBinder:
    """Test ActorBinder — bind(*, request) is sync per the protocol."""

    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: object) -> Actor:
        return self._actor


def _examiner(*, scopes: frozenset[_Scope], tenant_id: str = "t-1") -> Actor:
    return Actor(subject="examiner@bank", tenant_id=tenant_id, scopes=scopes, actor_type="human")


def _memory_registry() -> AdapterRegistry:
    r = AdapterRegistry()
    r.register("relational", "memory", InMemoryRelationalAdapter)
    r.register("vector", "memory", InMemoryVectorAdapter)
    r.register("secret", "memory", InMemorySecretAdapter)
    r.register("embedding", "memory", InMemoryEmbeddingAdapter)
    r.register("observability", "memory", InMemoryObservabilityAdapter)
    r.register("object_store", "local_fs", LocalObjectStoreAdapter)
    return r


def _settings(tmp_path: Path, *, signing_key_path: str | None = None) -> Settings:
    return Settings(  # type: ignore[call-arg]
        _env_file=None,
        db_driver="memory",
        vector_driver="memory",
        secret_driver="memory",
        embed_driver="memory",
        obs_driver="memory",
        database_url=None,
        qdrant_url=None,
        vault_addr=None,
        embedding_base_url=None,
        langfuse_host=None,
        object_store_driver="local_fs",
        local_object_store_root=tmp_path,
        evidence_pack_signing_key_path=signing_key_path,
    )


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


def _route_paths(app: FastAPI) -> set[str]:
    return {getattr(route, "path", "") for route in app.routes}


async def test_evidence_pack_endpoint_200_threads_engine_and_secret_adapter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pin 1 — 200 path externally visible contract: route path, gzip
    content-type, attachment Content-Disposition, AND the route threads
    the configured signing key + a live SecretAdapter + engine + tenant
    into the exporter (a vault:// key cannot resolve without the
    SecretAdapter; the captured kwargs fail the test if the route ever
    drops one)."""
    captured: dict[str, object] = {}

    async def _fake_export(**kwargs: object) -> bytes:
        captured.update(kwargs)
        return b"FAKE-TARBALL"

    monkeypatch.setattr(
        "cognic_agentos.portal.api.compliance.evidence_pack_routes.export_evidence_pack",
        _fake_export,
    )
    actor = _examiner(scopes=frozenset({"compliance.evidence_pack.read"}))
    app = create_app(
        _settings(tmp_path, signing_key_path="vault://secret/evidence-key"),
        adapter_registry=_memory_registry(),
        actor_binder=_StubBinder(actor),
    )
    assert _ROUTE in _route_paths(app)
    async with app.router.lifespan_context(app), _client(app) as client:
        resp = await client.get(_ROUTE, params=_PARAMS)
    assert resp.status_code == 200
    assert resp.content == b"FAKE-TARBALL"
    assert resp.headers["content-type"] == "application/gzip"
    assert resp.headers["content-disposition"] == 'attachment; filename="evidence-pack-t-1.tar.gz"'
    assert captured["tenant_id"] == "t-1"
    assert captured["engine"] is not None
    assert captured["secret_adapter"] is not None
    assert captured["signing_key_path"] == "vault://secret/evidence-key"


async def test_evidence_pack_endpoint_500_on_signing_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fail-loud signing error (e.g. unset/missing key) surfaces as a
    500 with the closed-enum reason — never a silent unsigned pack."""
    from cognic_agentos.compliance.iso42001.signing import EvidencePackSigningError

    async def _boom_export(**kwargs: object) -> bytes:
        raise EvidencePackSigningError("evidence_pack_signing_key_path is unset")

    monkeypatch.setattr(
        "cognic_agentos.portal.api.compliance.evidence_pack_routes.export_evidence_pack",
        _boom_export,
    )
    actor = _examiner(scopes=frozenset({"compliance.evidence_pack.read"}))
    app = create_app(
        _settings(tmp_path),
        adapter_registry=_memory_registry(),
        actor_binder=_StubBinder(actor),
    )
    async with app.router.lifespan_context(app), _client(app) as client:
        resp = await client.get(_ROUTE, params=_PARAMS)
    assert resp.status_code == 500
    assert resp.json()["detail"]["reason"] == "evidence_pack_signing_failed"


async def test_evidence_pack_endpoint_403_without_scope(tmp_path: Path) -> None:
    actor = _examiner(scopes=frozenset())  # no compliance scope held
    app = create_app(
        _settings(tmp_path),
        adapter_registry=_memory_registry(),
        actor_binder=_StubBinder(actor),
    )
    async with app.router.lifespan_context(app), _client(app) as client:
        resp = await client.get(_ROUTE, params=_PARAMS)
    assert resp.status_code == 403
    detail = resp.json()["detail"]
    assert detail["reason"] == "scope_not_held"
    assert detail["required_scope"] == "compliance.evidence_pack.read"


async def test_evidence_pack_endpoint_404_cross_tenant(tmp_path: Path) -> None:
    actor = _examiner(scopes=frozenset({"compliance.evidence_pack.read"}), tenant_id="t-1")
    app = create_app(
        _settings(tmp_path),
        adapter_registry=_memory_registry(),
        actor_binder=_StubBinder(actor),
    )
    async with app.router.lifespan_context(app), _client(app) as client:
        resp = await client.get(_ROUTE, params={**_PARAMS, "scope": "t-2"})
    assert resp.status_code == 404  # cross-tenant — never a 403 hint
    assert resp.json()["detail"]["reason"] == "evidence_pack_not_found"


async def test_evidence_pack_endpoint_503_when_adapters_unavailable(
    tmp_path: Path,
) -> None:
    actor = _examiner(scopes=frozenset({"compliance.evidence_pack.read"}))
    # No adapter_registry => the lifespan sets app.state.adapters = None.
    app = create_app(_settings(tmp_path), actor_binder=_StubBinder(actor))
    async with app.router.lifespan_context(app), _client(app) as client:
        resp = await client.get(_ROUTE, params=_PARAMS)
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "compliance_adapters_unavailable"


def test_compliance_router_not_mounted_without_actor_binder(tmp_path: Path) -> None:
    """Pin 2 — the mount boundary. create_app WITHOUT an actor_binder
    must NOT mount the compliance router: the route is absent from the
    table entirely. A structural route-table check — a request-level 404
    could not distinguish 'not mounted' from 'mounted, path mismatch'."""
    app = create_app(_settings(tmp_path), adapter_registry=_memory_registry())
    assert _ROUTE not in _route_paths(app)
