"""Sprint 9 T7 — trace explorer: walk_trace data behaviour + endpoint wiring."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import AuditEvent, AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.db.adapters import AdapterRegistry
from cognic_agentos.db.adapters.local_object_store_adapter import LocalObjectStoreAdapter
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.api.compliance.trace_routes import walk_trace
from cognic_agentos.portal.rbac.actor import Actor
from tests.support.adapter_fixtures import (
    InMemoryEmbeddingAdapter,
    InMemoryObservabilityAdapter,
    InMemoryRelationalAdapter,
    InMemorySecretAdapter,
    InMemoryVectorAdapter,
)

#: The trace-explorer route-table path — carries the {trace_id} path-param
#: placeholder, distinct from a concrete request path like /traces/trace-x.
_TRACE_ROUTE = "/api/v1/traces/{trace_id}"

# --- walk_trace data behaviour (file-backed engine, real seeded rows) ---


async def _seeded(
    tmp_path: Path,
) -> tuple[AsyncEngine, AuditStore, DecisionHistoryStore]:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'tr.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id,
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=datetime.now(UTC),
                )
            )
    return engine, AuditStore(engine), DecisionHistoryStore(engine)


async def test_walk_trace_returns_ordered_timeline(tmp_path: Path) -> None:
    engine, audit, dh = await _seeded(tmp_path)
    await audit.append(
        AuditEvent(
            event_type="a1", request_id="r1", payload={}, tenant_id="t-1", trace_id="trace-x"
        )
    )
    await dh.append(
        DecisionRecord(
            decision_type="d1", request_id="r2", payload={}, tenant_id="t-1", trace_id="trace-x"
        )
    )
    await audit.append(
        AuditEvent(
            event_type="a2", request_id="r3", payload={}, tenant_id="t-1", trace_id="trace-x"
        )
    )
    events = await walk_trace(engine, trace_id="trace-x", tenant_id="t-1")
    assert len(events) == 3
    assert events == sorted(
        events, key=lambda e: (e["created_at"], e["source_chain"], e["sequence"])
    )
    assert {e["event_type"] for e in events} == {"a1", "a2", "d1"}
    assert all("record_id" in e for e in events)  # provenance preserved
    # Hash-chain linkage is exposed, hex-encoded (spec §6.2.1 shape) — an
    # examiner can verify the chain walk, not just read a sorted list.
    for e in events:
        assert len(e["hash"]) == 64 and len(e["prev_hash"]) == 64
        bytes.fromhex(e["hash"])  # valid hex — raises otherwise
        bytes.fromhex(e["prev_hash"])


async def test_walk_trace_excludes_other_tenant_rows(tmp_path: Path) -> None:
    engine, audit, _dh = await _seeded(tmp_path)
    await audit.append(
        AuditEvent(
            event_type="mine", request_id="r1", payload={}, tenant_id="t-1", trace_id="shared"
        )
    )
    await audit.append(
        AuditEvent(
            event_type="theirs", request_id="r2", payload={}, tenant_id="t-2", trace_id="shared"
        )
    )
    events = await walk_trace(engine, trace_id="shared", tenant_id="t-1")
    assert [e["event_type"] for e in events] == ["mine"]


async def test_walk_trace_empty_for_trace_in_other_tenant(tmp_path: Path) -> None:
    engine, audit, _dh = await _seeded(tmp_path)
    await audit.append(
        AuditEvent(event_type="x", request_id="r1", payload={}, tenant_id="t-2", trace_id="only-t2")
    )
    # A t-1 examiner asking for a trace that lives only under t-2 sees
    # nothing — cross-tenant invisible.
    assert await walk_trace(engine, trace_id="only-t2", tenant_id="t-1") == []


# --- endpoint wiring (walk_trace monkeypatched — :memory: isolation) ---


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: object) -> Actor:
        return self._actor


def _memory_registry() -> AdapterRegistry:
    r = AdapterRegistry()
    r.register("relational", "memory", InMemoryRelationalAdapter)
    r.register("vector", "memory", InMemoryVectorAdapter)
    r.register("secret", "memory", InMemorySecretAdapter)
    r.register("embedding", "memory", InMemoryEmbeddingAdapter)
    r.register("observability", "memory", InMemoryObservabilityAdapter)
    r.register("object_store", "local_fs", LocalObjectStoreAdapter)
    return r


def _settings(tmp_path: Path) -> Settings:
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
    )


def _route_paths(app: FastAPI) -> set[str]:
    return {getattr(route, "path", "") for route in app.routes}


async def test_trace_endpoint_200_with_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """200 path — route path pinned AND the route threads the path-param
    trace_id + the AUTHENTICATED actor's tenant + the live engine into
    walk_trace. The captured kwargs fail the test if the route ever
    swaps actor.tenant_id for client-supplied input (the tenant-
    isolation contract) or drops the engine."""
    captured: dict[str, object] = {}

    async def _fake_walk(
        engine: object, *, trace_id: str, tenant_id: str
    ) -> list[dict[str, object]]:
        captured["engine"] = engine
        captured["trace_id"] = trace_id
        captured["tenant_id"] = tenant_id
        return [
            {
                "source_chain": "audit_event",
                "event_type": "x",
                "sequence": 1,
                "record_id": "rid",
                "created_at": "2026-01-01T00:00:00+00:00",
                "request_id": "r1",
                "prev_hash": "00" * 32,
                "hash": "11" * 32,
                "iso_controls": [],
            }
        ]

    monkeypatch.setattr("cognic_agentos.portal.api.compliance.trace_routes.walk_trace", _fake_walk)
    actor = Actor(
        subject="e",
        tenant_id="t-1",
        scopes=frozenset({"compliance.trace.read"}),
        actor_type="human",
    )
    app = create_app(
        _settings(tmp_path),
        adapter_registry=_memory_registry(),
        actor_binder=_StubBinder(actor),
    )
    assert _TRACE_ROUTE in _route_paths(app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        resp = await client.get("/api/v1/traces/trace-x")
    assert resp.status_code == 200
    body = resp.json()
    assert body["trace_id"] == "trace-x"
    assert body["tenant_id"] == "t-1"
    assert len(body["events"]) == 1
    # Response-field contract: exactly the 3 top-level keys, and each
    # event carries the full 9-field walk_trace record shape verbatim
    # (the route passes walk_trace's output through unreshaped).
    assert set(body) == {"trace_id", "tenant_id", "events"}
    assert set(body["events"][0]) == {
        "source_chain",
        "sequence",
        "record_id",
        "created_at",
        "event_type",
        "request_id",
        "prev_hash",
        "hash",
        "iso_controls",
    }
    # Chain-link values survive the route verbatim — prev_hash / hash are
    # the examiner-critical hash-chain linkage.
    event = body["events"][0]
    assert event["prev_hash"] == "00" * 32
    assert event["hash"] == "11" * 32
    # walk_trace call contract: path-param trace_id, the authenticated
    # actor's tenant (NOT client input), and the live engine.
    assert captured["trace_id"] == "trace-x"
    assert captured["tenant_id"] == "t-1"
    assert captured["engine"] is not None


async def test_trace_endpoint_403_without_scope(tmp_path: Path) -> None:
    actor = Actor(subject="e", tenant_id="t-1", scopes=frozenset(), actor_type="human")
    app = create_app(
        _settings(tmp_path),
        adapter_registry=_memory_registry(),
        actor_binder=_StubBinder(actor),
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        resp = await client.get("/api/v1/traces/trace-x")
    assert resp.status_code == 403
    detail = resp.json()["detail"]
    assert detail["reason"] == "scope_not_held"
    assert detail["required_scope"] == "compliance.trace.read"


async def test_trace_endpoint_503_when_adapters_unavailable(tmp_path: Path) -> None:
    actor = Actor(
        subject="e",
        tenant_id="t-1",
        scopes=frozenset({"compliance.trace.read"}),
        actor_type="human",
    )
    app = create_app(_settings(tmp_path), actor_binder=_StubBinder(actor))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        resp = await client.get("/api/v1/traces/trace-x")
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "compliance_adapters_unavailable"


def test_trace_router_not_mounted_without_actor_binder(tmp_path: Path) -> None:
    """Mount boundary — create_app WITHOUT an actor_binder must NOT mount
    the compliance router, so the trace route is structurally absent from
    the route table (mirrors the T6 evidence-pack mount-boundary pin)."""
    app = create_app(_settings(tmp_path), adapter_registry=_memory_registry())
    assert _TRACE_ROUTE not in _route_paths(app)
