"""M4 Task 3 — operator runtime-config write/read endpoints (configure step).

Pins the two endpoints behind ``/api/v1/packs``:

- ``PUT  /api/v1/packs/{pack_id}/runtime-config`` — writes the per-``(tenant,
  pack)`` DESIRED runtime-config record (operator-pre-provisioned MCP override +
  internal-host allow-list + OAuth/AS Vault *references*). Human-only per ADR-026
  D4 (a service-token actor holding ``pack.configure`` is refused at the
  :class:`RequireHumanActor` dep BEFORE the handler body).
- ``GET  /api/v1/packs/{pack_id}/runtime-config`` — reads it. Service actors
  PERMITTED (no :class:`RequireHumanActor` on the read, mirroring the
  ``mcp_config`` read endpoints).

The HARD BARs pinned here:

1. **Existence + tenant ownership** via :class:`RequireTenantOwnership` —
   cross-tenant / unknown / malformed pack UUID → 404 (the
   :data:`TenantIsolationFailure` closed-enum body).
2. **Human-only write** — a service-token actor with ``pack.configure`` →
   403 ``actor_type_must_be_human``; the GET permits service actors.
3. **Grammar refusal → 422** — a bad ``server_url_override`` reaches the store's
   :func:`validate_override_url` grammar and surfaces the closed-enum
   :class:`MCPConfigRejected` reason (e.g. ``override_url_host_not_internal`` for a
   public IP, ``override_url_not_http`` for an https override).
4. **Opaque-ref shape refusal → 422** — an empty ``oauth_credential_ref`` →
   422 ``runtime_config_oauth_credential_ref_malformed`` (the store's own
   :class:`RuntimeConfigRejected` taxonomy).
5. **Reconfigure-while-active → 409** (NOT 422) — the state-conflict reason
   ``runtime_config_reconfigure_while_active`` maps to 409; every other
   :class:`RuntimeConfigRejected` (incl. terminal
   ``runtime_config_reconfigure_while_revoked``) maps to 422.
6. **GET-absent → 404 ``runtime_config_not_found``** — a read with no record.
7. **``from __future__ import annotations`` OMITTED** — PEP-563 string-deferred
   annotations break FastAPI's closure-local ``Depends`` resolution.

Task 3 does NOT materialize anything (that is Task 4) and adds NO lifecycle-state
gate (existence + tenant via the dep + the store's active-reconfigure refusal are
the only gates).
"""

import ast
import logging
import pathlib
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.mcp_config.runtime_config import PackRuntimeConfigStore
from cognic_agentos.packs.storage import PackRecord, PackRecordStore
from cognic_agentos.portal.api.packs import configure_routes
from cognic_agentos.portal.api.packs.configure_routes import build_configure_routes
from cognic_agentos.portal.rbac.actor import Actor

#: The module logger the route emits its accepted / refused logs under.
_MOD_LOGGER = "cognic_agentos.portal.api.packs.configure_routes"
#: The human-actor denial log message emitted (by the shared rbac helper) when a
#: service actor is refused at the dep chain.
_HUMAN_DENIAL_MSG = "portal.rbac.actor_type_must_be_human"


# ---------------------------------------------------------------------------
# Stub actor binder + fixtures (mirrors test_operator_routes.py + mcp_config)
# ---------------------------------------------------------------------------


class _StubBinder:
    """Test-only :class:`ActorBinder` returning a configured actor."""

    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


def _make_actor(
    *,
    subject: str = "operator@bank.example",
    tenant_id: str = "t1",
    scopes: frozenset[str] | None = None,
    actor_type: str = "human",
) -> Actor:
    """Build a fixture :class:`Actor` carrying the ``pack.configure`` scope by
    default. Override ``actor_type="service"`` for the human-only refusal test;
    override ``scopes=frozenset()`` for the scope-not-held test."""
    if scopes is None:
        scopes = frozenset({"pack.configure"})
    return Actor(
        subject=subject,
        tenant_id=tenant_id,
        scopes=scopes,  # type: ignore[arg-type]
        actor_type=actor_type,  # type: ignore[arg-type]
    )


@pytest.fixture
async def engine(tmp_path: Any) -> AsyncIterator[AsyncEngine]:
    """SQLite engine seeded with governance schema + both chain heads."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'configure_routes.db'}"
    eng: AsyncEngine = create_async_engine(url)
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="audit_event",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=datetime.now(UTC),
            )
        )
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


@pytest.fixture
async def pack_store(engine: AsyncEngine) -> PackRecordStore:
    return PackRecordStore(engine)


@pytest.fixture
async def config_store(engine: AsyncEngine) -> PackRuntimeConfigStore:
    return PackRuntimeConfigStore(engine)


def _build_app(
    *,
    actor: Actor,
    pack_store: PackRecordStore,
    config_store: PackRuntimeConfigStore,
) -> FastAPI:
    """Build a raw FastAPI app with the configure sub-router mounted under
    ``/api/v1/packs`` (the prefix Task 7 will mount it under in production).

    ``app.state.actor_binder`` powers ``RequireScope`` / ``RequireHumanActor``;
    ``app.state.pack_record_store`` is what :class:`RequireTenantOwnership` pulls
    the :class:`PackRecord` from itself (so the factory takes only the
    runtime-config store)."""
    app = FastAPI()
    app.state.actor_binder = _StubBinder(actor)
    app.state.pack_record_store = pack_store
    app.include_router(
        build_configure_routes(store=config_store),
        prefix="/api/v1/packs",
    )
    return app


async def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://x")


async def _seed_pack(
    pack_store: PackRecordStore,
    *,
    tenant_id: str = "t1",
    created_by: str = "alice@bank.example",
) -> PackRecord:
    """Save a draft pack at ``tenant_id`` — Task 3 adds NO lifecycle-state gate,
    so a draft pack is a valid configure target (existence + tenant ownership are
    the only gates ``RequireTenantOwnership`` enforces)."""
    now = datetime.now(UTC)
    record = PackRecord(
        id=uuid.uuid4(),
        kind="tool",
        pack_id=f"cognic-tool-{uuid.uuid4().hex[:8]}",
        display_name="Seed Pack",
        state="draft",
        manifest_digest=b"\x01" * 32,
        signed_artefact_digest=b"\x02" * 32,
        sbom_pointer=None,
        tenant_id=tenant_id,
        created_by=created_by,
        last_actor=created_by,
        created_at=now,
        updated_at=now,
    )
    await pack_store.save_draft(record)
    return record


def _config_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == _MOD_LOGGER]


def _assert_single_refused_log(caplog: pytest.LogCaptureFixture) -> None:
    """Exactly one ``portal.packs.configure_set_refused`` log + zero accepted."""
    assert [r.getMessage() for r in _config_records(caplog)] == [
        "portal.packs.configure_set_refused"
    ]


# A full valid config body (every field provisioned). The override is an
# internal http IP-literal so the grammar admits it; the refs are non-empty
# opaque strings so the shape check admits them.
_FULL_BODY: dict[str, Any] = {
    "server_url_override": "http://10.42.0.7:8080/mcp",
    "internal_host_allowlist": ["10.42.0.7"],
    "oauth_credential_ref": "vault://secret/data/mcp/oauth",
    "as_allowlist_ref": "vault://secret/data/mcp/as",
}


async def _put_config(app: FastAPI, pack_id: object, body: dict[str, Any]) -> httpx.Response:
    async with await _client(app) as c:
        return await c.put(f"/api/v1/packs/{pack_id}/runtime-config", json=body)


async def _get_config(app: FastAPI, pack_id: object) -> httpx.Response:
    async with await _client(app) as c:
        return await c.get(f"/api/v1/packs/{pack_id}/runtime-config")


# =====================================================================
# PUT (write, human-only) — green paths
# =====================================================================


# HARD BAR (write green) + read-back round-trip.
async def test_put_full_config_then_get_reads_back(
    pack_store: PackRecordStore,
    config_store: PackRuntimeConfigStore,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A human actor with ``pack.configure`` + matching tenant writes a full
    config → 200; the response + a subsequent GET reflect
    ``activation_status == "configured"`` + ``generation == 1``."""
    record = await _seed_pack(pack_store, tenant_id="t1")
    actor = _make_actor(tenant_id="t1", actor_type="human")
    app = _build_app(actor=actor, pack_store=pack_store, config_store=config_store)

    with caplog.at_level(logging.WARNING, logger=_MOD_LOGGER):
        put_resp = await _put_config(app, record.id, _FULL_BODY)
    assert put_resp.status_code == 200, put_resp.text
    put_body = put_resp.json()
    assert put_body["tenant_id"] == "t1"
    assert put_body["pack_id"] == str(record.id)
    assert put_body["server_url_override"] == "http://10.42.0.7:8080/mcp"
    assert put_body["internal_host_allowlist"] == ["10.42.0.7"]
    assert put_body["oauth_credential_ref"] == "vault://secret/data/mcp/oauth"
    assert put_body["as_allowlist_ref"] == "vault://secret/data/mcp/as"
    assert put_body["activation_status"] == "configured"
    assert put_body["generation"] == 1

    # exactly one accepted log, zero refused
    assert [r.getMessage() for r in _config_records(caplog)] == ["portal.packs.configure_set"]

    # GET reads it back
    get_resp = await _get_config(app, record.id)
    assert get_resp.status_code == 200, get_resp.text
    get_body = get_resp.json()
    assert get_body["activation_status"] == "configured"
    assert get_body["generation"] == 1
    assert get_body["server_url_override"] == "http://10.42.0.7:8080/mcp"

    # store-of-record carries the desired config
    persisted = await config_store.get(tenant_id="t1", pack_id=str(record.id))
    assert persisted is not None
    assert persisted.server_url_override == "http://10.42.0.7:8080/mcp"
    assert persisted.internal_host_allowlist == ("10.42.0.7",)
    assert persisted.oauth_credential_ref == "vault://secret/data/mcp/oauth"


async def test_put_partial_config_no_override_empty_allowlist_no_refs(
    pack_store: PackRecordStore,
    config_store: PackRuntimeConfigStore,
) -> None:
    """A partial desired record (no override, empty allow-list, no refs) is
    VALID — the store + install-time own completeness, not the write."""
    record = await _seed_pack(pack_store, tenant_id="t1")
    actor = _make_actor(tenant_id="t1", actor_type="human")
    app = _build_app(actor=actor, pack_store=pack_store, config_store=config_store)

    resp = await _put_config(app, record.id, {})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["server_url_override"] is None
    assert body["internal_host_allowlist"] == []
    assert body["oauth_credential_ref"] is None
    assert body["as_allowlist_ref"] is None
    assert body["activation_status"] == "configured"
    assert body["generation"] == 1


# =====================================================================
# PUT — human-only refusal (service actor) + scope/tenant siblings
# =====================================================================


# HARD BAR 2 + mutually-exclusive logs: a service actor with the configure scope
# → 403 BEFORE the body; ZERO configure_routes logs; one human-actor denial log.
async def test_put_service_actor_refused_human_only_mutually_exclusive(
    pack_store: PackRecordStore,
    config_store: PackRuntimeConfigStore,
    caplog: pytest.LogCaptureFixture,
) -> None:
    record = await _seed_pack(pack_store, tenant_id="t1")
    actor = _make_actor(tenant_id="t1", actor_type="service")
    app = _build_app(actor=actor, pack_store=pack_store, config_store=config_store)

    with caplog.at_level(logging.WARNING):
        resp = await _put_config(app, record.id, _FULL_BODY)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "actor_type_must_be_human"

    # mutually-exclusive: ZERO portal.packs.configure_* logs (body never ran)
    assert _config_records(caplog) == []
    # exactly one human-actor denial log from the dep chain
    assert [r.getMessage() for r in caplog.records].count(_HUMAN_DENIAL_MSG) == 1

    # no record written
    assert await config_store.get(tenant_id="t1", pack_id=str(record.id)) is None


async def test_put_refuses_when_scope_missing(
    pack_store: PackRecordStore,
    config_store: PackRuntimeConfigStore,
) -> None:
    """An actor without ``pack.configure`` → 403 ``scope_not_held``."""
    record = await _seed_pack(pack_store, tenant_id="t1")
    actor = _make_actor(tenant_id="t1", actor_type="human", scopes=frozenset())
    app = _build_app(actor=actor, pack_store=pack_store, config_store=config_store)

    resp = await _put_config(app, record.id, _FULL_BODY)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "scope_not_held"


async def test_put_refuses_cross_tenant_with_404(
    pack_store: PackRecordStore,
    config_store: PackRuntimeConfigStore,
) -> None:
    """HARD BAR 1 — a pack at t1 is INVISIBLE to a t2 actor: cross-tenant →
    404 ``tenant_id_mismatch`` at :class:`RequireTenantOwnership`."""
    record = await _seed_pack(pack_store, tenant_id="t1")
    actor = _make_actor(tenant_id="t2", actor_type="human")
    app = _build_app(actor=actor, pack_store=pack_store, config_store=config_store)

    resp = await _put_config(app, record.id, _FULL_BODY)
    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "tenant_id_mismatch"


async def test_put_refuses_unknown_pack_with_404(
    pack_store: PackRecordStore,
    config_store: PackRuntimeConfigStore,
) -> None:
    """HARD BAR 1 — an unknown pack UUID → 404 ``pack_not_found``."""
    actor = _make_actor(tenant_id="t1", actor_type="human")
    app = _build_app(actor=actor, pack_store=pack_store, config_store=config_store)

    resp = await _put_config(app, uuid.uuid4(), _FULL_BODY)
    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "pack_not_found"


# =====================================================================
# PUT — store refusals (grammar 422, opaque-ref 422, active-reconfigure 409)
# =====================================================================


# HARD BAR 3 — a public-IP override reaches the store's grammar → 422
# override_url_host_not_internal; exactly one refused log, zero accepted.
async def test_put_public_ip_override_refused_422(
    pack_store: PackRecordStore,
    config_store: PackRuntimeConfigStore,
    caplog: pytest.LogCaptureFixture,
) -> None:
    record = await _seed_pack(pack_store, tenant_id="t1")
    actor = _make_actor(tenant_id="t1", actor_type="human")
    app = _build_app(actor=actor, pack_store=pack_store, config_store=config_store)

    body = {**_FULL_BODY, "server_url_override": "http://8.8.8.8"}
    with caplog.at_level(logging.WARNING, logger=_MOD_LOGGER):
        resp = await _put_config(app, record.id, body)
    assert resp.status_code == 422
    assert resp.json()["detail"]["reason"] == "override_url_host_not_internal"
    _assert_single_refused_log(caplog)
    # the refusal rolled back — no record persisted
    assert await config_store.get(tenant_id="t1", pack_id=str(record.id)) is None


# HARD BAR 3 — an internal HTTPS override → 422 override_url_not_http.
async def test_put_https_override_refused_422(
    pack_store: PackRecordStore,
    config_store: PackRuntimeConfigStore,
) -> None:
    record = await _seed_pack(pack_store, tenant_id="t1")
    actor = _make_actor(tenant_id="t1", actor_type="human")
    app = _build_app(actor=actor, pack_store=pack_store, config_store=config_store)

    body = {**_FULL_BODY, "server_url_override": "https://10.0.0.5"}
    resp = await _put_config(app, record.id, body)
    assert resp.status_code == 422
    assert resp.json()["detail"]["reason"] == "override_url_not_http"


# HARD BAR 4 — an empty oauth_credential_ref → 422
# runtime_config_oauth_credential_ref_malformed (the store's own taxonomy, NOT
# MCPConfigRejected). No override so the grammar gate passes first.
async def test_put_empty_oauth_ref_refused_422(
    pack_store: PackRecordStore,
    config_store: PackRuntimeConfigStore,
    caplog: pytest.LogCaptureFixture,
) -> None:
    record = await _seed_pack(pack_store, tenant_id="t1")
    actor = _make_actor(tenant_id="t1", actor_type="human")
    app = _build_app(actor=actor, pack_store=pack_store, config_store=config_store)

    body: dict[str, Any] = {
        "server_url_override": None,
        "internal_host_allowlist": [],
        "oauth_credential_ref": "",
        "as_allowlist_ref": None,
    }
    with caplog.at_level(logging.WARNING, logger=_MOD_LOGGER):
        resp = await _put_config(app, record.id, body)
    assert resp.status_code == 422
    assert resp.json()["detail"]["reason"] == "runtime_config_oauth_credential_ref_malformed"
    _assert_single_refused_log(caplog)
    assert await config_store.get(tenant_id="t1", pack_id=str(record.id)) is None


# HARD BAR 5 — reconfigure while the record is ``active`` → 409 (NOT 422).
async def test_put_reconfigure_while_active_refused_409(
    pack_store: PackRecordStore,
    config_store: PackRuntimeConfigStore,
    caplog: pytest.LogCaptureFixture,
) -> None:
    record = await _seed_pack(pack_store, tenant_id="t1")
    actor = _make_actor(tenant_id="t1", actor_type="human")
    app = _build_app(actor=actor, pack_store=pack_store, config_store=config_store)

    # First configure (generation 1, status configured), then drive it active
    # directly via the store (simulating Task 6 install materialization).
    await config_store.set_config(
        tenant_id="t1",
        pack_id=str(record.id),
        server_url_override=None,
        internal_host_allowlist=[],
        oauth_credential_ref=None,
        as_allowlist_ref=None,
        actor_subject="operator@bank.example",
        actor_type="human",
        request_id="cfg-seed-001",
    )
    await config_store.set_activation_status(
        tenant_id="t1",
        pack_id=str(record.id),
        status="active",
        actor_subject="operator@bank.example",
        actor_type="human",
        request_id="act-seed-001",
    )

    with caplog.at_level(logging.WARNING, logger=_MOD_LOGGER):
        resp = await _put_config(app, record.id, _FULL_BODY)
    assert resp.status_code == 409, resp.text
    assert resp.json()["detail"]["reason"] == "runtime_config_reconfigure_while_active"
    _assert_single_refused_log(caplog)

    # the active record is unchanged (still no override from the seed config)
    persisted = await config_store.get(tenant_id="t1", pack_id=str(record.id))
    assert persisted is not None
    assert persisted.activation_status == "active"
    assert persisted.server_url_override is None


# HARD BAR 5b — reconfigure while the record is terminal ``revoked`` → 422 (NOT
# 409). revoke is terminal; the store's ``runtime_config_reconfigure_while_revoked``
# is NOT the active state-conflict reason, so the route's else-arm maps it to 422.
# Pins that the 409 is SPECIFIC to the active reason (the 409/422 split is real).
async def test_put_reconfigure_while_revoked_refused_422(
    pack_store: PackRecordStore,
    config_store: PackRuntimeConfigStore,
    caplog: pytest.LogCaptureFixture,
) -> None:
    record = await _seed_pack(pack_store, tenant_id="t1")
    actor = _make_actor(tenant_id="t1", actor_type="human")
    app = _build_app(actor=actor, pack_store=pack_store, config_store=config_store)

    # Seed a config (generation 1), then drive it terminal-revoked directly via
    # the store (simulating a Task 6 revoke retraction).
    await config_store.set_config(
        tenant_id="t1",
        pack_id=str(record.id),
        server_url_override=None,
        internal_host_allowlist=[],
        oauth_credential_ref=None,
        as_allowlist_ref=None,
        actor_subject="operator@bank.example",
        actor_type="human",
        request_id="cfg-rev-seed-001",
    )
    await config_store.set_activation_status(
        tenant_id="t1",
        pack_id=str(record.id),
        status="revoked",
        actor_subject="operator@bank.example",
        actor_type="human",
        request_id="act-rev-seed-001",
    )

    with caplog.at_level(logging.WARNING, logger=_MOD_LOGGER):
        resp = await _put_config(app, record.id, _FULL_BODY)
    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"]["reason"] == "runtime_config_reconfigure_while_revoked"
    _assert_single_refused_log(caplog)

    # the revoked record is unchanged (still no override from the seed config)
    persisted = await config_store.get(tenant_id="t1", pack_id=str(record.id))
    assert persisted is not None
    assert persisted.activation_status == "revoked"
    assert persisted.server_url_override is None


# =====================================================================
# GET (read, service permitted) — present, absent, scope, cross-tenant
# =====================================================================


# HARD BAR 2 — a SERVICE actor with the configure scope CAN read.
async def test_get_service_actor_permitted(
    pack_store: PackRecordStore,
    config_store: PackRuntimeConfigStore,
) -> None:
    record = await _seed_pack(pack_store, tenant_id="t1")
    # write with a human actor, read with a service actor
    writer = _make_actor(tenant_id="t1", actor_type="human")
    writer_app = _build_app(actor=writer, pack_store=pack_store, config_store=config_store)
    put_resp = await _put_config(writer_app, record.id, _FULL_BODY)
    assert put_resp.status_code == 200

    reader = _make_actor(subject="ci@bank.example", tenant_id="t1", actor_type="service")
    reader_app = _build_app(actor=reader, pack_store=pack_store, config_store=config_store)
    get_resp = await _get_config(reader_app, record.id)
    assert get_resp.status_code == 200, get_resp.text
    assert get_resp.json()["server_url_override"] == "http://10.42.0.7:8080/mcp"


# HARD BAR 6 — GET when no record exists → 404 runtime_config_not_found.
async def test_get_absent_returns_404_runtime_config_not_found(
    pack_store: PackRecordStore,
    config_store: PackRuntimeConfigStore,
) -> None:
    record = await _seed_pack(pack_store, tenant_id="t1")  # pack exists, no config
    actor = _make_actor(tenant_id="t1", actor_type="human")
    app = _build_app(actor=actor, pack_store=pack_store, config_store=config_store)

    resp = await _get_config(app, record.id)
    assert resp.status_code == 404, resp.text
    assert resp.json()["detail"]["reason"] == "runtime_config_not_found"


async def test_get_refuses_when_scope_missing(
    pack_store: PackRecordStore,
    config_store: PackRuntimeConfigStore,
) -> None:
    """A read also requires ``pack.configure`` — no scope → 403 ``scope_not_held``."""
    record = await _seed_pack(pack_store, tenant_id="t1")
    actor = _make_actor(tenant_id="t1", actor_type="human", scopes=frozenset())
    app = _build_app(actor=actor, pack_store=pack_store, config_store=config_store)

    resp = await _get_config(app, record.id)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "scope_not_held"


async def test_get_refuses_cross_tenant_with_404(
    pack_store: PackRecordStore,
    config_store: PackRuntimeConfigStore,
) -> None:
    """HARD BAR 1 — cross-tenant read → 404 ``tenant_id_mismatch`` (the config
    is invisible across tenants because the pack itself is)."""
    record = await _seed_pack(pack_store, tenant_id="t1")
    # seed a config so the only failure axis is the cross-tenant gate
    writer = _make_actor(tenant_id="t1", actor_type="human")
    writer_app = _build_app(actor=writer, pack_store=pack_store, config_store=config_store)
    await _put_config(writer_app, record.id, _FULL_BODY)

    reader = _make_actor(tenant_id="t2", actor_type="human")
    reader_app = _build_app(actor=reader, pack_store=pack_store, config_store=config_store)
    resp = await _get_config(reader_app, record.id)
    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "tenant_id_mismatch"


# =====================================================================
# Structural invariants
# =====================================================================


def test_no_future_import() -> None:
    """Standing-offer §30 — AST self-test pinning the no-future-import invariant.

    ``configure_routes.py`` MUST OMIT ``from __future__ import annotations``.
    PEP 563 string-deferred annotations would prevent FastAPI's
    ``inspect.signature()`` / ``typing.get_type_hints()`` from resolving
    ``Annotated[..., Depends(<closure-local>)]`` in the inner endpoint handlers
    (the shared dependency instances are LOCAL variables inside
    :func:`build_configure_routes`, NOT module globals) — silently demoting
    handler params to query params. Mirrors ``mcp_config/routes.py`` +
    ``operator_routes.py``."""
    tree = ast.parse(pathlib.Path(configure_routes.__file__).read_text())
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            for alias_node in node.names:
                assert alias_node.name != "annotations", (
                    "configure_routes.py MUST OMIT `from __future__ import "
                    "annotations` — PEP 563 breaks the FastAPI closure-local "
                    "Depends resolution in build_configure_routes's inner handlers."
                )


def test_request_id_prefix_bounded_to_64_chars() -> None:
    """The configure request-id prefix MUST satisfy ``len(prefix) + 32 <= 64`` so
    the minted request_id fits the ``decision_history.request_id`` String(64)
    column cap. Module-foot build-time assert pins this at import; this test pins
    it in test surface too."""
    prefix = configure_routes._PACK_CONFIGURE_SET_PREFIX
    assert len(prefix) + 32 <= 64, (
        f"configure request-id prefix {prefix!r} ({len(prefix)} chars) + "
        f"uuid4().hex (32 chars) = {len(prefix) + 32} > 64; would overflow "
        "decision_history.request_id String(64) column cap"
    )
