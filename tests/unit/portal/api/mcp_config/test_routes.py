"""PR-2b-1 Task 6 — operator MCP ``server_url`` override + per-tenant exact-IP
internal-host allow-list write/read endpoints.

Mirrors ``tests/unit/portal/api/config_overlay/test_routes.py``. The endpoints
are OPERATOR-ADMINISTERED (an operator sets MCP config FOR a tenant) so there is
deliberately NO ``RequireTenantOwnership`` gate — the scope IS the boundary. Both
write surfaces (override PUT/DELETE; allow-list add/remove) are human-only via
``RequireHumanActor``; the GET reads permit service actors.

The HARD BARs pinned here:

1. **HumanActor refusal on writes** — a service-token actor holding the write
   scope is refused 403 BEFORE the handler body (override PUT/DELETE; allow-list
   add/remove), and ZERO chain rows are written.
2. **Read/write scope separation** — writes require ``mcp.*.write``; reads
   require ``mcp.*.read``; a read-scope actor cannot write; a SERVICE actor CAN
   read.
3. **Closed-enum ``MCPConfigRejected`` → 422** — each refusal surface (override
   non-http / hostname / public-ip; allow-list malformed / broad-CIDR / metadata)
   returns 422 carrying the closed-enum reason. The allow-list ADD carries the IP
   in the BODY precisely so a broad CIDR (``10.0.0.0/8`` — whose ``/`` would break
   a path-param route) still reaches the store and surfaces
   ``allowlist_ip_not_exact``.
4. **Mutually-exclusive logs** — a service-actor write refusal emits ZERO
   ``portal.mcp_config.*`` logs (the human-actor refusal fires in the dep chain
   before the handler body); a green write emits exactly one accepted log; a
   store-refusal (422) emits exactly one ``_refused`` log + zero accepted.
5. **No broad write path around the audited stores** — AST guard: the route
   module imports no SQLAlchemy / engine plumbing; every mutation goes through the
   injected store mutators.
6. **``from __future__ import annotations`` OMITTED** — PEP-563 string-deferred
   annotations break FastAPI's closure-local ``Depends`` resolution.
"""

import ast
import inspect
import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import _decision_history
from cognic_agentos.core.mcp_config.storage import (
    MCPInternalHostAllowlistStore,
    MCPServerUrlOverrideStore,
)
from cognic_agentos.portal.api.mcp_config import routes as routes_mod
from cognic_agentos.portal.api.mcp_config.routes import (
    build_mcp_allowlist_routes,
    build_mcp_override_routes,
)
from cognic_agentos.portal.rbac.actor import Actor, ActorType
from cognic_agentos.portal.rbac.scopes import MCPInternalAccessRBACScope

#: The module logger name the route emits its accepted / refused logs under.
_MOD_LOGGER = "cognic_agentos.portal.api.mcp_config"
#: The human-actor denial log message emitted (by the shared rbac helper) when a
#: service actor is refused at the dep chain.
_HUMAN_DENIAL_MSG = "portal.rbac.actor_type_must_be_human"


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


def _actor(
    *,
    scopes: set[MCPInternalAccessRBACScope],
    actor_type: ActorType = "human",
    tenant_id: str = "t1",
    subject: str = "op@bank",
) -> Actor:
    return Actor(
        subject=subject,
        tenant_id=tenant_id,
        scopes=frozenset(scopes),
        actor_type=actor_type,
    )


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'mcpcfg.db'}")
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


def _app(engine: AsyncEngine, actor: Actor) -> FastAPI:
    app = FastAPI()
    app.state.actor_binder = _StubBinder(actor)
    app.include_router(
        build_mcp_override_routes(store=MCPServerUrlOverrideStore(engine)),
        prefix="/api/v1",
    )
    app.include_router(
        build_mcp_allowlist_routes(store=MCPInternalHostAllowlistStore(engine)),
        prefix="/api/v1",
    )
    return app


async def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://x")


async def _put_override(app: FastAPI, tenant: str, pack: str, server_url: object) -> httpx.Response:
    async with await _client(app) as c:
        return await c.put(
            f"/api/v1/tenants/{tenant}/mcp-overrides/{pack}",
            json={"server_url": server_url},
        )


async def _add_ip(app: FastAPI, tenant: str, ip: object) -> httpx.Response:
    async with await _client(app) as c:
        return await c.put(f"/api/v1/tenants/{tenant}/mcp-allowlist", json={"ip": ip})


def _mcp_config_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == _MOD_LOGGER]


async def _chain_rows(engine: AsyncEngine, event_type: str | None = None) -> list[Any]:
    async with engine.connect() as conn:
        stmt = select(_decision_history)
        if event_type is not None:
            stmt = stmt.where(_decision_history.c.event_type == event_type)
        return list((await conn.execute(stmt)).fetchall())


# =====================================================================
# Override — PUT (write, human-only)
# =====================================================================


# HARD BAR 1 (write green) + 4 (exactly one accepted log) + chain evidence.
async def test_override_put_human_sets_override_and_logs_once(
    engine: AsyncEngine, caplog: pytest.LogCaptureFixture
) -> None:
    app = _app(engine, _actor(scopes={"mcp.override.write"}))
    with caplog.at_level(logging.WARNING):
        resp = await _put_override(app, "t1", "pack-a", "http://10.42.0.7:8080/mcp")
    assert resp.status_code == 200
    assert resp.json()["server_url"] == "http://10.42.0.7:8080/mcp"
    # store-of-record is the audited store
    assert (
        await MCPServerUrlOverrideStore(engine).get(tenant_id="t1", pack_id="pack-a")
        == "http://10.42.0.7:8080/mcp"
    )
    # exactly one accepted log, zero refused
    msgs = [r.getMessage() for r in _mcp_config_records(caplog)]
    assert msgs == ["portal.mcp_config.override_set"]
    # chain row carries actor_type provenance
    rows = await _chain_rows(engine, "mcp.override.set")
    assert len(rows) == 1
    assert rows[0].payload["actor_type"] == "human"


# HARD BAR 1 + 4: service actor with the write scope → 403 BEFORE the body;
# ZERO mcp_config logs; exactly one human-actor denial log; zero chain rows.
async def test_override_put_service_refused_human_only_mutually_exclusive(
    engine: AsyncEngine, caplog: pytest.LogCaptureFixture
) -> None:
    app = _app(engine, _actor(scopes={"mcp.override.write"}, actor_type="service"))
    with caplog.at_level(logging.WARNING):
        resp = await _put_override(app, "t1", "pack-a", "http://10.42.0.7/mcp")
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "actor_type_must_be_human"
    # mutually-exclusive: ZERO portal.mcp_config.* logs (handler body never ran)
    assert _mcp_config_records(caplog) == []
    # exactly one human-actor denial log from the dep chain
    assert [r.getMessage() for r in caplog.records].count(_HUMAN_DENIAL_MSG) == 1
    # zero chain rows
    assert await _chain_rows(engine) == []


# HARD BAR 2: an actor without the write scope is refused scope_not_held.
async def test_override_put_without_write_scope_refused(engine: AsyncEngine) -> None:
    app = _app(engine, _actor(scopes=set()))
    resp = await _put_override(app, "t1", "pack-a", "http://10.42.0.7/mcp")
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "scope_not_held"


# HARD BAR 2: a read-scope-only actor CANNOT write.
async def test_override_read_scope_actor_cannot_write(engine: AsyncEngine) -> None:
    app = _app(engine, _actor(scopes={"mcp.override.read"}))
    resp = await _put_override(app, "t1", "pack-a", "http://10.42.0.7/mcp")
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "scope_not_held"


# HARD BAR 3 + 4: internal HTTPS override → 422 override_url_not_http; exactly one
# refused log, zero accepted; zero chain rows.
async def test_override_put_https_refused_422(
    engine: AsyncEngine, caplog: pytest.LogCaptureFixture
) -> None:
    app = _app(engine, _actor(scopes={"mcp.override.write"}))
    with caplog.at_level(logging.WARNING):
        resp = await _put_override(app, "t1", "pack-a", "https://10.42.0.7")
    assert resp.status_code == 422
    assert resp.json()["detail"]["reason"] == "override_url_not_http"
    msgs = [r.getMessage() for r in _mcp_config_records(caplog)]
    assert msgs == ["portal.mcp_config.override_set_refused"]
    assert await _chain_rows(engine) == []


# HARD BAR 3: a hostname override → 422 override_url_host_not_ip_literal.
async def test_override_put_hostname_refused_422(engine: AsyncEngine) -> None:
    app = _app(engine, _actor(scopes={"mcp.override.write"}))
    resp = await _put_override(app, "t1", "pack-a", "http://svc.ns.svc.cluster.local")
    assert resp.status_code == 422
    assert resp.json()["detail"]["reason"] == "override_url_host_not_ip_literal"


# HARD BAR 3: a public-IP override → 422 override_url_host_not_internal.
async def test_override_put_public_ip_refused_422(engine: AsyncEngine) -> None:
    app = _app(engine, _actor(scopes={"mcp.override.write"}))
    resp = await _put_override(app, "t1", "pack-a", "http://8.8.8.8")
    assert resp.status_code == 422
    assert resp.json()["detail"]["reason"] == "override_url_host_not_internal"


# Strict-string DTO: a non-string body → 422 at the request boundary (the store's
# override_url_not_string is unreachable via the route — the DTO catches it first).
async def test_override_put_non_string_refused_422_zero_chain(engine: AsyncEngine) -> None:
    app = _app(engine, _actor(scopes={"mcp.override.write"}))
    resp = await _put_override(app, "t1", "pack-a", 123)
    assert resp.status_code == 422
    assert await _chain_rows(engine) == []


# =====================================================================
# Override — DELETE (write, human-only) + GET (read, service permitted)
# =====================================================================


async def test_override_delete_human_clears_and_emits_cleared(
    engine: AsyncEngine, caplog: pytest.LogCaptureFixture
) -> None:
    app = _app(engine, _actor(scopes={"mcp.override.write"}))
    await _put_override(app, "t1", "pack-a", "http://10.42.0.7/mcp")
    caplog.clear()  # drop the setup-PUT's accepted log; isolate the DELETE's logs
    with caplog.at_level(logging.WARNING):
        async with await _client(app) as c:
            resp = await c.delete("/api/v1/tenants/t1/mcp-overrides/pack-a")
    assert resp.status_code == 204
    assert await MCPServerUrlOverrideStore(engine).get(tenant_id="t1", pack_id="pack-a") is None
    assert [r.getMessage() for r in _mcp_config_records(caplog)] == [
        "portal.mcp_config.override_cleared"
    ]
    assert len(await _chain_rows(engine, "mcp.override.cleared")) == 1


async def test_override_delete_service_refused_human_only(engine: AsyncEngine) -> None:
    app = _app(engine, _actor(scopes={"mcp.override.write"}, actor_type="service"))
    async with await _client(app) as c:
        resp = await c.delete("/api/v1/tenants/t1/mcp-overrides/pack-a")
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "actor_type_must_be_human"


# HARD BAR 2: a SERVICE actor with the read scope CAN read.
async def test_override_get_read_scope_service_ok(engine: AsyncEngine) -> None:
    writer = _app(engine, _actor(scopes={"mcp.override.write"}))
    await _put_override(writer, "t1", "pack-a", "http://10.42.0.7/mcp")
    reader = _app(engine, _actor(scopes={"mcp.override.read"}, actor_type="service"))
    async with await _client(reader) as c:
        resp = await c.get("/api/v1/tenants/t1/mcp-overrides/pack-a")
    assert resp.status_code == 200
    assert resp.json()["server_url"] == "http://10.42.0.7/mcp"


async def test_override_get_returns_null_when_absent(engine: AsyncEngine) -> None:
    app = _app(engine, _actor(scopes={"mcp.override.read"}))
    async with await _client(app) as c:
        resp = await c.get("/api/v1/tenants/t1/mcp-overrides/pack-absent")
    assert resp.status_code == 200
    assert resp.json()["server_url"] is None


async def test_override_get_refused_without_read_scope(engine: AsyncEngine) -> None:
    app = _app(engine, _actor(scopes=set()))
    async with await _client(app) as c:
        resp = await c.get("/api/v1/tenants/t1/mcp-overrides/pack-a")
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "scope_not_held"


# Tenant isolation: an override set by tenant t1 is INVISIBLE to tenant t2's read.
async def test_override_get_is_tenant_scoped(engine: AsyncEngine) -> None:
    writer = _app(engine, _actor(scopes={"mcp.override.write"}, tenant_id="t1"))
    await _put_override(writer, "t1", "pack-a", "http://10.42.0.7/mcp")
    reader = _app(engine, _actor(scopes={"mcp.override.read"}, tenant_id="t2"))
    async with await _client(reader) as c:
        resp = await c.get("/api/v1/tenants/t2/mcp-overrides/pack-a")
    assert resp.status_code == 200
    assert resp.json()["server_url"] is None


# =====================================================================
# Allow-list — PUT add (write, human-only)
# =====================================================================


async def test_allowlist_add_human_ok_and_logs_once(
    engine: AsyncEngine, caplog: pytest.LogCaptureFixture
) -> None:
    app = _app(engine, _actor(scopes={"mcp.allowlist.write"}))
    with caplog.at_level(logging.WARNING):
        resp = await _add_ip(app, "t1", "10.42.0.7")
    assert resp.status_code == 200
    assert {row["ip"] for row in resp.json()} == {"10.42.0.7"}
    assert await MCPInternalHostAllowlistStore(engine).get_allowlist(tenant_id="t1") == frozenset(
        {"10.42.0.7"}
    )
    assert [r.getMessage() for r in _mcp_config_records(caplog)] == [
        "portal.mcp_config.allowlist_add"
    ]
    rows = await _chain_rows(engine, "mcp.allowlist.add")
    assert len(rows) == 1
    assert rows[0].payload["actor_type"] == "human"


async def test_allowlist_add_service_refused_human_only_mutually_exclusive(
    engine: AsyncEngine, caplog: pytest.LogCaptureFixture
) -> None:
    app = _app(engine, _actor(scopes={"mcp.allowlist.write"}, actor_type="service"))
    with caplog.at_level(logging.WARNING):
        resp = await _add_ip(app, "t1", "10.42.0.7")
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "actor_type_must_be_human"
    assert _mcp_config_records(caplog) == []
    assert [r.getMessage() for r in caplog.records].count(_HUMAN_DENIAL_MSG) == 1
    assert await _chain_rows(engine) == []


# HARD BAR 3: the BROAD-CIDR refusal surface — deliverable ONLY because the IP
# rides the body. A CIDR via a path param would 404 (the "/" breaks routing); the
# body delivers it to the store, which raises allowlist_ip_not_exact → 422.
async def test_allowlist_add_broad_cidr_refused_422(
    engine: AsyncEngine, caplog: pytest.LogCaptureFixture
) -> None:
    app = _app(engine, _actor(scopes={"mcp.allowlist.write"}))
    with caplog.at_level(logging.WARNING):
        resp = await _add_ip(app, "t1", "10.0.0.0/8")
    assert resp.status_code == 422
    assert resp.json()["detail"]["reason"] == "allowlist_ip_not_exact"
    assert [r.getMessage() for r in _mcp_config_records(caplog)] == [
        "portal.mcp_config.allowlist_add_refused"
    ]
    assert await _chain_rows(engine) == []


# HARD BAR 3: malformed (FQDN / wildcard) → 422 allowlist_ip_malformed.
async def test_allowlist_add_malformed_refused_422(engine: AsyncEngine) -> None:
    app = _app(engine, _actor(scopes={"mcp.allowlist.write"}))
    resp = await _add_ip(app, "t1", "*.svc.cluster.local")
    assert resp.status_code == 422
    assert resp.json()["detail"]["reason"] == "allowlist_ip_malformed"


# HARD BAR 3: metadata / hard-blocked IP → 422 allowlist_ip_hard_blocked.
async def test_allowlist_add_metadata_refused_422(engine: AsyncEngine) -> None:
    app = _app(engine, _actor(scopes={"mcp.allowlist.write"}))
    resp = await _add_ip(app, "t1", "169.254.169.254")
    assert resp.status_code == 422
    assert resp.json()["detail"]["reason"] == "allowlist_ip_hard_blocked"


async def test_allowlist_add_non_string_refused_422_zero_chain(engine: AsyncEngine) -> None:
    app = _app(engine, _actor(scopes={"mcp.allowlist.write"}))
    resp = await _add_ip(app, "t1", 123)
    assert resp.status_code == 422
    assert await _chain_rows(engine) == []


# HARD BAR 2: a read-scope-only actor CANNOT add.
async def test_allowlist_add_read_scope_actor_cannot_write(engine: AsyncEngine) -> None:
    app = _app(engine, _actor(scopes={"mcp.allowlist.read"}))
    resp = await _add_ip(app, "t1", "10.42.0.7")
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "scope_not_held"


# =====================================================================
# Allow-list — DELETE remove (write, human-only) + GET list (read, service ok)
# =====================================================================


async def test_allowlist_remove_human_ok_and_emits_remove(
    engine: AsyncEngine, caplog: pytest.LogCaptureFixture
) -> None:
    app = _app(engine, _actor(scopes={"mcp.allowlist.write"}))
    await _add_ip(app, "t1", "10.42.0.7")
    caplog.clear()  # drop the setup-ADD's accepted log; isolate the DELETE's logs
    with caplog.at_level(logging.WARNING):
        async with await _client(app) as c:
            resp = await c.delete("/api/v1/tenants/t1/mcp-allowlist/10.42.0.7")
    assert resp.status_code == 204
    assert await MCPInternalHostAllowlistStore(engine).get_allowlist(tenant_id="t1") == frozenset()
    assert [r.getMessage() for r in _mcp_config_records(caplog)] == [
        "portal.mcp_config.allowlist_remove"
    ]
    assert len(await _chain_rows(engine, "mcp.allowlist.remove")) == 1


async def test_allowlist_remove_service_refused_human_only(engine: AsyncEngine) -> None:
    app = _app(engine, _actor(scopes={"mcp.allowlist.write"}, actor_type="service"))
    async with await _client(app) as c:
        resp = await c.delete("/api/v1/tenants/t1/mcp-allowlist/10.42.0.7")
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "actor_type_must_be_human"


# DELETE also validates the IP grammar in the store (remove_ip calls the
# validator), so a malformed path-IP → 422 allowlist_ip_malformed + a refused log.
async def test_allowlist_remove_malformed_refused_422(
    engine: AsyncEngine, caplog: pytest.LogCaptureFixture
) -> None:
    app = _app(engine, _actor(scopes={"mcp.allowlist.write"}))
    with caplog.at_level(logging.WARNING):
        async with await _client(app) as c:
            resp = await c.delete("/api/v1/tenants/t1/mcp-allowlist/my-host")
    assert resp.status_code == 422
    assert resp.json()["detail"]["reason"] == "allowlist_ip_malformed"
    assert [r.getMessage() for r in _mcp_config_records(caplog)] == [
        "portal.mcp_config.allowlist_remove_refused"
    ]


# HARD BAR 2: a SERVICE actor with the read scope CAN list the allow-list.
async def test_allowlist_get_read_scope_service_ok(engine: AsyncEngine) -> None:
    writer = _app(engine, _actor(scopes={"mcp.allowlist.write"}))
    await _add_ip(writer, "t1", "10.42.0.7")
    reader = _app(engine, _actor(scopes={"mcp.allowlist.read"}, actor_type="service"))
    async with await _client(reader) as c:
        resp = await c.get("/api/v1/tenants/t1/mcp-allowlist")
    assert resp.status_code == 200
    assert {row["ip"] for row in resp.json()} == {"10.42.0.7"}


async def test_allowlist_get_refused_without_read_scope(engine: AsyncEngine) -> None:
    app = _app(engine, _actor(scopes=set()))
    async with await _client(app) as c:
        resp = await c.get("/api/v1/tenants/t1/mcp-allowlist")
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "scope_not_held"


# Tenant isolation: t1's allow-list entry is invisible to t2's list.
async def test_allowlist_get_is_tenant_scoped(engine: AsyncEngine) -> None:
    writer = _app(engine, _actor(scopes={"mcp.allowlist.write"}, tenant_id="t1"))
    await _add_ip(writer, "t1", "10.42.0.7")
    reader = _app(engine, _actor(scopes={"mcp.allowlist.read"}, tenant_id="t2"))
    async with await _client(reader) as c:
        resp = await c.get("/api/v1/tenants/t2/mcp-allowlist")
    assert resp.status_code == 200
    assert resp.json() == []


# =====================================================================
# Structural invariants
# =====================================================================


def test_no_future_import() -> None:
    """PEP 563 invariant guard (AST-based, mirrors the repo pattern): the module
    MUST OMIT ``from __future__ import annotations`` — string-deferred annotations
    break FastAPI's get_type_hints() resolution of the closure-local
    ``Annotated[..., Depends(<closure-local>)]`` deps."""
    tree = ast.parse(Path(routes_mod.__file__).read_text())
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            for alias_node in node.names:
                assert alias_node.name != "annotations", (
                    "mcp_config/routes.py MUST OMIT `from __future__ import "
                    "annotations` — PEP 563 breaks the FastAPI closure-local "
                    "Depends resolution in the build_* factories' inner handlers."
                )


def test_routes_do_not_use_require_tenant_ownership() -> None:
    """Operator-administered: no tenant-ownership gate (the scope IS the
    boundary). The module must not reference RequireTenantOwnership at all."""
    tree = ast.parse(inspect.getsource(routes_mod))
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    assert "RequireTenantOwnership" not in names


def test_routes_have_no_direct_db_access() -> None:
    """HARD BAR 5 — no broad write path around the audited stores: the route
    module imports no SQLAlchemy / engine plumbing; every mutation goes through
    the injected store mutators (set_override / clear_override / add_ip /
    remove_ip), which audit via append_with_precondition."""
    tree = ast.parse(inspect.getsource(routes_mod))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module)
    assert not any("sqlalchemy" in mod for mod in imported), (
        "route module must not import sqlalchemy — mutations go through the store"
    )
    src = inspect.getsource(routes_mod)
    for forbidden in ("create_async_engine", "AsyncEngine", ".execute(", "_metadata"):
        assert forbidden not in src, f"route module must not touch the DB directly ({forbidden!r})"
