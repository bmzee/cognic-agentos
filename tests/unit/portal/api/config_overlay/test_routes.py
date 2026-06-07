"""ADR-023 Task 6 — operator-administered, human-only config-overlay endpoints.

Five pins + DELETE + GET + the no-``RequireTenantOwnership`` AST supplement +
the no-future-import PEP-563 guard + an unknown-field-key registry-gate pin.

The endpoint is OPERATOR-ADMINISTERED: an operator sets config FOR a tenant,
so there is deliberately NO ``RequireTenantOwnership`` gate (a cross-tenant
operator holding the write scope succeeds). The mutation surface
(PUT/DELETE) is additionally human-only via ``RequireHumanActor``; GET is
read-only and permits service actors.
"""

import ast
import inspect
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.config import Settings
from cognic_agentos.core.config_overlay.resolver import TenantConfigResolver
from cognic_agentos.core.config_overlay.storage import (
    TenantConfigOverlayStore,
    _tenant_config_overlay,
)
from cognic_agentos.core.decision_history import _decision_history
from cognic_agentos.portal.api.config_overlay import routes as routes_mod
from cognic_agentos.portal.api.config_overlay.routes import build_config_overlay_routes
from cognic_agentos.portal.rbac.actor import Actor, ActorType
from cognic_agentos.portal.rbac.scopes import ConfigOverlayRBACScope


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


def _actor(
    *,
    scopes: set[ConfigOverlayRBACScope],
    actor_type: ActorType = "human",
    tenant_id: str = "t1",
) -> Actor:
    return Actor(
        subject="op@bank",
        tenant_id=tenant_id,
        scopes=frozenset(scopes),
        actor_type=actor_type,
    )


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'ovl.db'}")
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="decision_history",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=datetime.now(UTC),
            )
        )
    yield eng
    await eng.dispose()


def _app(engine: AsyncEngine, actor: Actor) -> tuple[FastAPI, Settings]:
    settings = Settings(runtime_profile="dev")
    store = TenantConfigOverlayStore(engine)
    resolver = TenantConfigResolver(
        store=store,
        base=settings,
        audit=AuditStore(engine),
        throttle_s=settings.config_overlay_invalid_at_read_throttle_s,
    )
    app = FastAPI()
    app.state.actor_binder = _StubBinder(actor)
    app.include_router(
        build_config_overlay_routes(store=store, resolver=resolver, settings=settings),
        prefix="/api/v1",
    )
    return app, settings


async def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://x")


async def _put(app: FastAPI, tenant: str, field: str, value: float | int) -> httpx.Response:
    async with await _client(app) as c:
        return await c.put(
            f"/api/v1/tenants/{tenant}/config-overlay/{field}", json={"value": value}
        )


# PIN 1 — human-only guard fires BEFORE any mutation (zero chain rows).
async def test_service_actor_refused_before_mutation(engine: AsyncEngine) -> None:
    app, _ = _app(engine, _actor(scopes={"config.tenant_overlay.write"}, actor_type="service"))
    resp = await _put(app, "t1", "sandbox_per_tenant_max_cpu", 2.0)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "actor_type_must_be_human"
    async with engine.connect() as conn:
        assert list((await conn.execute(select(_decision_history))).fetchall()) == []


# PIN 2 — operator-administered: a cross-tenant operator with the write scope
# succeeds (NO tenant-ownership gate). Behaviour proof for the AST supplement.
async def test_cross_tenant_operator_with_scope_succeeds(engine: AsyncEngine) -> None:
    app, _ = _app(engine, _actor(scopes={"config.tenant_overlay.write"}, tenant_id="OTHER"))
    assert (await _put(app, "t1", "sandbox_per_tenant_max_cpu", 2.0)).status_code == 200


async def test_actor_without_scope_refused(engine: AsyncEngine) -> None:
    app, _ = _app(engine, _actor(scopes=set()))
    resp = await _put(app, "t1", "sandbox_per_tenant_max_cpu", 2.0)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "scope_not_held"


def test_routes_do_not_use_require_tenant_ownership() -> None:
    # AST supplement to the behaviour proof: the module must not reference
    # RequireTenantOwnership at all (operator-administered: no tenant gate).
    src = inspect.getsource(routes_mod)
    names = {n.id for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Name)}
    assert "RequireTenantOwnership" not in names


# PIN 3 — a loosening write is refused 422 and writes zero chain rows.
async def test_loosening_write_refused_zero_chain(engine: AsyncEngine) -> None:
    app, settings = _app(engine, _actor(scopes={"config.tenant_overlay.write"}))
    resp = await _put(
        app, "t1", "sandbox_per_tenant_max_cpu", settings.sandbox_per_tenant_max_cpu + 10
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["reason"] == "tenant_overlay_loosens_ceiling"
    async with engine.connect() as conn:
        assert list((await conn.execute(select(_decision_history))).fetchall()) == []


# PIN 4 — an accepted write emits exactly one config.tenant_overlay.set chain
# row carrying the actor_type provenance.
async def test_accepted_write_emits_chain(engine: AsyncEngine) -> None:
    app, _ = _app(engine, _actor(scopes={"config.tenant_overlay.write"}))
    assert (await _put(app, "t1", "sandbox_per_tenant_max_cpu", 2.0)).status_code == 200
    async with engine.connect() as conn:
        chain = list(
            (
                await conn.execute(
                    select(_decision_history).where(
                        _decision_history.c.event_type == "config.tenant_overlay.set"
                    )
                )
            ).fetchall()
        )
    assert len(chain) == 1
    assert chain[0].payload["actor_type"] == "human"


# DELETE — clears the overlay row and emits config.tenant_overlay.cleared.
async def test_delete_clears_and_emits_cleared(engine: AsyncEngine) -> None:
    app, _ = _app(engine, _actor(scopes={"config.tenant_overlay.write"}))
    await _put(app, "t1", "sandbox_per_tenant_max_cpu", 2.0)
    async with await _client(app) as c:
        resp = await c.delete("/api/v1/tenants/t1/config-overlay/sandbox_per_tenant_max_cpu")
    assert resp.status_code == 204
    async with engine.connect() as conn:
        rows = list((await conn.execute(select(_tenant_config_overlay))).fetchall())
        cleared = list(
            (
                await conn.execute(
                    select(_decision_history).where(
                        _decision_history.c.event_type == "config.tenant_overlay.cleared"
                    )
                )
            ).fetchall()
        )
    assert rows == []
    assert len(cleared) == 1


async def test_delete_requires_human(engine: AsyncEngine) -> None:
    app, _ = _app(engine, _actor(scopes={"config.tenant_overlay.write"}, actor_type="service"))
    async with await _client(app) as c:
        resp = await c.delete("/api/v1/tenants/t1/config-overlay/sandbox_per_tenant_max_cpu")
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "actor_type_must_be_human"


# GET — read scope, service actors permitted, no human gate.
async def test_get_lists_overlays_read_scope_no_human(engine: AsyncEngine) -> None:
    app, _ = _app(engine, _actor(scopes={"config.tenant_overlay.write"}))
    await _put(app, "t1", "sandbox_per_tenant_max_cpu", 2.0)
    app_read, _ = _app(engine, _actor(scopes={"config.tenant_overlay.read"}, actor_type="service"))
    async with await _client(app_read) as c:  # service actor OK for read
        resp = await c.get("/api/v1/tenants/t1/config-overlay")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["field_key"] == "sandbox_per_tenant_max_cpu"


async def test_get_refused_without_read_scope(engine: AsyncEngine) -> None:
    app, _ = _app(engine, _actor(scopes=set()))
    async with await _client(app) as c:
        resp = await c.get("/api/v1/tenants/t1/config-overlay")
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "scope_not_held"


# Registry-gate pin: an unknown / non-overridable field_key is refused 422
# BEFORE getattr(settings, field_key) can read an arbitrary Setting.
async def test_unknown_field_key_refused_422(engine: AsyncEngine) -> None:
    app, _ = _app(engine, _actor(scopes={"config.tenant_overlay.write"}))
    resp = await _put(app, "t1", "require_cosign", 1)
    assert resp.status_code == 422
    assert resp.json()["detail"]["reason"] == "tenant_overlay_field_not_overridable"
    async with engine.connect() as conn:
        assert list((await conn.execute(select(_decision_history))).fetchall()) == []


# Symmetric registry-gate on DELETE — clear_overlay() also refuses an
# unknown / non-overridable field_key with 422 + zero chain rows.
async def test_delete_unknown_field_key_refused_422(engine: AsyncEngine) -> None:
    app, _ = _app(engine, _actor(scopes={"config.tenant_overlay.write"}))
    async with await _client(app) as c:
        resp = await c.delete("/api/v1/tenants/t1/config-overlay/require_cosign")
    assert resp.status_code == 422
    assert resp.json()["detail"]["reason"] == "tenant_overlay_field_not_overridable"
    async with engine.connect() as conn:
        assert list((await conn.execute(select(_decision_history))).fetchall()) == []


# P1 (reviewer) — JSON-number-only wire contract. A lax ``float | int`` DTO
# would coerce JSON true -> 1.0 before the registry bool-guard runs, bypassing
# the Task-1 "bool is never accepted as numeric config" invariant. The strict
# DTO rejects bool at the request boundary with a 422 + zero chain rows.
async def test_bool_value_refused_422_zero_chain(engine: AsyncEngine) -> None:
    app, _ = _app(engine, _actor(scopes={"config.tenant_overlay.write"}))
    async with await _client(app) as c:
        resp = await c.put(
            "/api/v1/tenants/t1/config-overlay/sandbox_per_tenant_max_cpu",
            json={"value": True},
        )
    assert resp.status_code == 422  # Pydantic request-validation, NOT registry 422
    async with engine.connect() as conn:
        assert list((await conn.execute(select(_decision_history))).fetchall()) == []


# P1 (reviewer) — the wire contract is "JSON number only", NOT string coercion:
# a JSON string "2" must be refused (a lax DTO would coerce it to 2.0).
async def test_string_value_refused_422_zero_chain(engine: AsyncEngine) -> None:
    app, _ = _app(engine, _actor(scopes={"config.tenant_overlay.write"}))
    async with await _client(app) as c:
        resp = await c.put(
            "/api/v1/tenants/t1/config-overlay/sandbox_per_tenant_max_cpu",
            json={"value": "2"},
        )
    assert resp.status_code == 422
    async with engine.connect() as conn:
        assert list((await conn.execute(select(_decision_history))).fetchall()) == []


def test_no_future_import() -> None:
    # PEP 563 invariant guard (AST-based, mirrors the repo pattern at
    # tests/unit/portal/api/packs/test_operator_routes.py): the module MUST
    # OMIT ``from __future__ import annotations`` — string-deferred annotations
    # break FastAPI's get_type_hints() resolution of the closure-local
    # ``Annotated[..., Depends(<closure-local>)]`` deps. AST (not substring) so
    # the module docstring may still explain WHY the import is omitted.
    tree = ast.parse(Path(routes_mod.__file__).read_text())
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            for alias_node in node.names:
                assert alias_node.name != "annotations", (
                    "config_overlay/routes.py MUST OMIT "
                    "`from __future__ import annotations` — PEP 563 breaks the "
                    "FastAPI closure-local Depends resolution in "
                    "build_config_overlay_routes's inner handlers."
                )
