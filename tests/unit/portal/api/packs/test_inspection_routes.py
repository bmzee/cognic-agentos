"""Sprint 7B.2 T7 — inspection_routes.py route-table + dependency-wiring pins.

Plan §958-1018 — T7 inspection surface ships 4 endpoints behind
``/api/v1/packs``:

- ``GET /api/v1/packs`` — list scoped to ``actor.tenant_id``
- ``GET /api/v1/packs/{pack_id}`` — pack detail + lifecycle history
- ``GET /api/v1/packs/{pack_id}/audit`` — hash-chained audit events
- ``GET /api/v1/packs/{pack_id}/invocations?from&to`` — audit-derived
  invocations

The list endpoint is the critical one because it's the ONLY
inspection endpoint without a ``{pack_id}`` path-param, so
``RequireTenantOwnership`` cannot enforce row-level filtering —
server-side WHERE clause in ``store.list_for_tenant`` IS the
authoritative tenant boundary, and route-level
``actor_tenant_id_missing`` preflight (per plan R20 P2 #2 + R21 P2 #1)
must explicitly emit the same structured log + 500 the
``RequireTenantOwnership`` dep emits on the other 3 endpoints.

**Route-shape split** (R33 P2 doctrine decision) — the bare list
endpoint is registered DIRECTLY on the parent router via
:func:`register_inspection_list` (path ``""`` + parent prefix
``/api/v1/packs`` yields the exact wire-protocol path
``/api/v1/packs`` with no trailing slash; matches plan §997 +
ADR-012 §75). The three ``{pack_id}`` sub-handlers live on a
sub-router returned by :func:`build_inspection_routes`. The split
is required because FastAPI's ``include_router`` rejects an
empty-prefix include of a sub-router with an empty-path route.

Pins exercised in this module:

1. Sub-router shape — :func:`build_inspection_routes` returns an
   :class:`APIRouter`, keyword-only ``store`` kwarg, carries the
   three ``{pack_id}`` endpoints (detail / audit / invocations).
2. Path-param convention — each ``{pack_id}`` endpoint uses
   ``{pack_id}`` (NOT ``{id}``) so the shared
   ``RequireTenantOwnership(pack_id_param="pack_id")`` dependency
   can pull the UUID from ``request.path_params["pack_id"]``.
3. List endpoint scope gate — ``RequireScope("pack.audit.read")``
   refuses missing-scope with 403 ``scope_not_held``.
4. List endpoint happy path + cross-tenant absence — invokes
   ``store.list_for_tenant(actor.tenant_id, ...)`` and returns
   ONLY tenant-scoped rows (server-side WHERE filter is the
   authoritative boundary).
5. List endpoint ``actor_tenant_id_missing`` preflight — empty
   ``actor.tenant_id`` (the only reachable falsy case under live
   ``Actor.tenant_id: str`` schema per plan R21 P2 #1) returns 500
   with closed-enum ``reason="actor_tenant_id_missing"`` AND emits
   the same ``portal.rbac.tenant_isolation_failed`` log the
   ``RequireTenantOwnership`` dep emits on the other 3 endpoints,
   with ``pack_id == "<list>"`` sentinel per plan R21 P2 #1.
6. Detail / audit / invocations — happy path response shape,
   scope refusal, cross-tenant 404 ``tenant_id_mismatch`` (via the
   shared ``_require_tenant_ownership`` dep), and the
   ``pack.invocation.read`` scope distinction for the invocations
   endpoint (``pack.audit.read`` alone is NOT sufficient).
7. Production wiring — the actual :func:`build_packs_router`
   factory output includes BOTH the T5 review-queue path AND the
   T7 inspection-list path AND the T7 ``{pack_id}`` sub-paths;
   neither shadows the other (T5/T7 collision split honored per
   plan §1010).

Halt-before-commit per T7 §1012 — CC-ADJ task class; list endpoint
is the authoritative tenant-isolation boundary for any inspection
without a ``{pack_id}`` path-param.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any, ClassVar

import pytest
from fastapi import APIRouter, FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.packs.storage import PackRecord, PackRecordStore
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.api.packs import build_packs_router
from cognic_agentos.portal.api.packs.inspection_routes import build_inspection_routes
from cognic_agentos.portal.rbac.actor import Actor


class _StubStore:
    """Test-only :class:`PackRecordStore` stand-in for the route-shell
    smoke tests (route-table assertions don't invoke store methods).
    Behavioral tests use a real SQLite-backed store via the ``store``
    fixture below."""


# ---------------------------------------------------------------------------
# Fixtures (mirrors test_review_routes.py:103-142 + test_operator_routes.py)
# ---------------------------------------------------------------------------


class _StubBinder:
    """Test-only :class:`ActorBinder` returning a configured actor.
    Mirrors ``test_review_routes.py::_StubBinder``."""

    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


def _make_actor(
    *,
    subject: str = "examiner@bank.example",
    tenant_id: str = "t1",
    scopes: frozenset[str] = frozenset({"pack.audit.read"}),
    actor_type: str = "human",
) -> Actor:
    """Build a fixture :class:`Actor`. Defaults to an examiner with
    ``pack.audit.read`` scope so happy-path inspection reads work.
    Override ``scopes`` to ``frozenset()`` to trigger the
    ``scope_not_held`` 403; override ``tenant_id`` to ``""`` to
    trigger the ``actor_tenant_id_missing`` 500 preflight.

    Per plan R21 P2 #1 — ``Actor.tenant_id: str`` (NOT Optional);
    the only reachable falsy case under live Pydantic validation is
    the empty string ``""``.
    """
    return Actor(
        subject=subject,
        tenant_id=tenant_id,
        scopes=scopes,  # type: ignore[arg-type]
        actor_type=actor_type,  # type: ignore[arg-type]
    )


@pytest.fixture
async def engine(tmp_path: Any) -> AsyncIterator[AsyncEngine]:
    """SQLite engine seeded with governance schema + chain heads —
    mirrors ``test_review_routes.py::engine``."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'inspection_routes.db'}"
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
async def store(engine: AsyncEngine) -> PackRecordStore:
    return PackRecordStore(engine)


def _build_app(*, actor: Actor, store: PackRecordStore) -> FastAPI:
    """Build a portal app via :func:`create_app` with the given
    binder + store; mirrors ``test_review_routes.py::_build_app``.

    Per plan handling-notes — tests use ``with TestClient(app) as
    client:`` (context-manager form) because the inspection routes
    depend on lifespan-populated ``app.state.pack_record_store``.
    """
    return create_app(
        actor_binder=_StubBinder(actor),
        pack_record_store=store,
    )


async def _seed_pack(
    store: PackRecordStore,
    *,
    pack_id: str | None = None,
    tenant_id: str = "t1",
    state_after_seed: str = "draft",
    created_by: str = "bob@bank.example",
) -> PackRecord:
    """Seed a single pack at a chosen lifecycle state. Default leaves
    the pack in ``draft``; pass ``state_after_seed="submitted"`` to
    submit it via ``store.transition("submit", ...)``."""
    now = datetime.now(UTC)
    record = PackRecord(
        id=uuid.uuid4(),
        kind="tool",
        pack_id=pack_id or f"cognic-tool-{uuid.uuid4().hex[:8]}",
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
    await store.save_draft(record)
    if state_after_seed == "submitted":
        await store.transition(
            pack_id=record.id,
            transition="submit",
            actor_id=created_by,
            tenant_id=tenant_id,
            evidence_pointer=None,
            request_id=f"submit-seed-{record.id.hex[:8]}",
        )
    return record


# ---------------------------------------------------------------------------
# Router-shape tests (no app, no TestClient)
# ---------------------------------------------------------------------------


class TestSprint7B2InspectionRouterShape:
    """Defensive type pins on :func:`build_inspection_routes` —
    mirrors the T5/T6 route-shell smoke tests at
    ``test_review_routes.py:373-399`` + ``test_operator_routes.py``."""

    def test_build_inspection_routes_returns_apirouter(self) -> None:
        """Factory returns an :class:`APIRouter` — defensive type
        pin so a future signature drift cannot silently shift the
        return type."""
        router = build_inspection_routes(store=_StubStore())  # type: ignore[arg-type]
        assert isinstance(router, APIRouter)

    def test_build_inspection_routes_requires_keyword_only_store(self) -> None:
        """Defence-in-depth — ``store`` is keyword-only (mirrors
        ``build_review_routes`` + ``build_packs_router`` conventions)."""
        with pytest.raises(TypeError):
            build_inspection_routes(_StubStore())  # type: ignore[arg-type,misc]


# ---------------------------------------------------------------------------
# List endpoint behavioral tests
# (Plan §966 + §1004-1010 + §1012-1017)
# ---------------------------------------------------------------------------


class TestSprint7B2InspectionListEndpoint:
    """``GET /api/v1/packs`` — list scoped to ``actor.tenant_id``.

    Dependency chain:

    1. :class:`RequireScope("pack.audit.read")` — 403
       ``scope_not_held`` for missing scope; emits
       ``portal.rbac.denied`` log.
    2. Route-body preflight (plan R20 P2 #2 + R21 P2 #1) — empty
       ``actor.tenant_id`` (only reachable falsy case under live
       ``Actor.tenant_id: str`` schema) returns 500
       ``actor_tenant_id_missing`` + emits
       ``portal.rbac.tenant_isolation_failed`` log with
       ``pack_id == "<list>"`` sentinel.
    3. Happy path — invokes ``store.list_for_tenant(actor.tenant_id,
       limit=…, cursor=…)`` and returns tenant-scoped rows as
       :class:`PackResponse` instances.
    """

    async def test_list_happy_path_returns_tenant_scoped_rows(
        self,
        store: PackRecordStore,
    ) -> None:
        """Examiner with ``pack.audit.read`` scope + tenant ``t1``
        gets back the 2 packs in ``t1``; the 1 pack in ``t2`` is
        ABSENT from the response (server-side WHERE-clause filter is
        the authoritative tenant boundary)."""
        # Seed: 2 packs in t1 + 1 pack in t2.
        pack_a1 = await _seed_pack(store, tenant_id="t1", pack_id="cognic-tool-a1")
        pack_a2 = await _seed_pack(store, tenant_id="t1", pack_id="cognic-tool-a2")
        await _seed_pack(store, tenant_id="t2", pack_id="cognic-tool-b1")

        actor = _make_actor(tenant_id="t1", scopes=frozenset({"pack.audit.read"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get("/api/v1/packs")

        assert response.status_code == 200, response.text
        body = response.json()
        # Response shape: list of PackResponse dicts.
        assert isinstance(body, list)
        returned_pack_ids = {row["pack_id"] for row in body}
        assert returned_pack_ids == {pack_a1.pack_id, pack_a2.pack_id}, (
            f"expected exactly the 2 t1 packs; got {returned_pack_ids}"
        )

    async def test_list_excludes_cross_tenant_rows(
        self,
        store: PackRecordStore,
    ) -> None:
        """Tenant-isolation regression — even when a t1 actor lists
        and t2 has matching-state packs, the response contains ZERO
        t2 rows. Mirrors the
        ``test_storage_list_for_tenant.py::test_list_for_tenant_returns_only_matching_tenant_rows``
        storage-layer assertion but at the route layer (defence-in-
        depth — both layers MUST enforce the boundary)."""
        # Seed: 1 pack in t1 + 3 packs in t2.
        pack_t1 = await _seed_pack(store, tenant_id="t1", pack_id="cognic-tool-t1-only")
        for i in range(3):
            await _seed_pack(store, tenant_id="t2", pack_id=f"cognic-tool-t2-{i}")

        actor = _make_actor(tenant_id="t1", scopes=frozenset({"pack.audit.read"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get("/api/v1/packs")

        assert response.status_code == 200
        body = response.json()
        returned_pack_ids = {row["pack_id"] for row in body}
        # ONLY the t1 pack — t2 packs are absent.
        assert returned_pack_ids == {pack_t1.pack_id}
        # Defensive: explicitly assert no t2 pack-id strings appear.
        for row in body:
            assert not row["pack_id"].startswith("cognic-tool-t2-"), (
                f"cross-tenant pack leaked into list response: {row}"
            )

    async def test_list_refuses_when_scope_missing(
        self,
        store: PackRecordStore,
    ) -> None:
        """Actor without ``pack.audit.read`` scope → 403
        ``scope_not_held``; handler never runs; ``store.list_for_tenant``
        is never invoked. Mirrors the T5/T6 scope-not-held pattern."""
        await _seed_pack(store, tenant_id="t1")
        actor = _make_actor(tenant_id="t1", scopes=frozenset())
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get("/api/v1/packs")

        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "scope_not_held"

    async def test_list_returns_500_when_actor_tenant_id_missing(
        self,
        store: PackRecordStore,
    ) -> None:
        """Plan R20 P2 #2 + R21 P2 #1 — kernel binder misconfig
        (actor with empty ``tenant_id`` reaching the route) MUST
        surface as 500 ``actor_tenant_id_missing``, NOT silently
        mask as a 200 empty-list response.

        ``Actor.tenant_id: str`` per ``actor.py:71`` — the only
        reachable falsy case under live Pydantic validation is the
        empty string. The list endpoint bypasses
        ``RequireTenantOwnership`` (no ``{pack_id}`` path-param) so
        the route handler MUST run an explicit preflight that
        emits the SAME structured log + 500 the dependency emits on
        the other 3 inspection endpoints.
        """
        await _seed_pack(store, tenant_id="t1")
        actor = _make_actor(tenant_id="", scopes=frozenset({"pack.audit.read"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get("/api/v1/packs")

        assert response.status_code == 500
        assert response.json()["detail"]["reason"] == "actor_tenant_id_missing"

    async def test_list_emits_actor_tenant_id_missing_log_with_pack_id_sentinel(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Sprint-7B.4 T6 wire-shape: the preflight now routes through
        the shared ``_emit_denial_or_500`` helper (in enforcement.py)
        instead of the per-module ``_emit_isolation_log``. The logger
        source moves to ``cognic_agentos.portal.rbac.enforcement`` and
        the message becomes ``portal.rbac.actor_tenant_id_missing``.
        Structured ``reason`` / ``actor_subject`` / ``pack_id`` fields
        unchanged — ``pack_id == "<list>"`` sentinel remains the
        wire-protocol contract for log-aggregator bucketing.
        """
        caplog.set_level(
            logging.WARNING,
            logger="cognic_agentos.portal.rbac.enforcement",
        )

        actor = _make_actor(tenant_id="", scopes=frozenset({"pack.audit.read"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get("/api/v1/packs")
        assert response.status_code == 500

        isolation_records = [
            r
            for r in caplog.records
            if r.name == "cognic_agentos.portal.rbac.enforcement"
            and r.message == "portal.rbac.actor_tenant_id_missing"
        ]
        assert len(isolation_records) == 1, (
            f"expected EXACTLY 1 portal.rbac.actor_tenant_id_missing record on "
            f"missing-tenant-id preflight; got {len(isolation_records)}"
        )
        emitted = isolation_records[0]
        assert emitted.levelno == logging.WARNING
        assert emitted.reason == "actor_tenant_id_missing"  # type: ignore[attr-defined]
        assert emitted.actor_subject == "examiner@bank.example"  # type: ignore[attr-defined]
        # Plan R21 P2 #1 — pack_id="<list>" sentinel (NOT None — the
        # shared helper still accepts pack_id as positional str kwarg).
        assert emitted.pack_id == "<list>", (  # type: ignore[attr-defined]
            f"pack_id sentinel must be '<list>' per plan R21 P2 #1; got {emitted.pack_id!r}"  # type: ignore[attr-defined]
        )


# ---------------------------------------------------------------------------
# Production-wiring + T5/T7 collision-split composition test
# (Plan §1010 — `test_review_queue_and_inspection_list_both_reachable`)
# ---------------------------------------------------------------------------


class TestSprint7B2InspectionRoutesProductionWiring:
    """Plan §1010 — once :mod:`inspection_routes` exists, assert the
    fully-composed :func:`build_packs_router` route table contains
    BOTH ``GET /api/v1/packs/review-queue`` (T5 reviewer queue;
    ``pack.review.claim`` dependency) AND ``GET /api/v1/packs``
    (T7 examiner list; ``pack.audit.read`` dependency). Walks
    ``app.routes`` after mounting ``build_packs_router`` on a fresh
    :class:`FastAPI` test app; asserts both :class:`Route` objects
    exist + their distinct ``methods={"GET"}`` + path + neither
    shadows the other after BOTH sub-routers register.

    T5/T7 collision split (R13 P2 #1 + R15 P2 #2) — T5 review-queue
    is at ``/review-queue`` path (moved off the ``?status=submitted``
    query collision); T7 examiner list is at the bare ``/api/v1/packs``.
    Both compile to distinct FastAPI route entries; neither matches
    the other's URL pattern.
    """

    def test_review_queue_and_inspection_list_both_reachable(self) -> None:
        """Fully-composed ``build_packs_router`` route table contains
        BOTH ``GET /api/v1/packs/review-queue`` (T5) AND
        ``GET /api/v1/packs`` (T7).

        Plan §1010 + R33 P2 — neither path shadows the other. The
        T7 list endpoint is registered DIRECTLY on the parent router
        with path ``""`` so the compiled path is exactly
        ``/api/v1/packs`` (no trailing slash); the wire-protocol
        contract per plan §997 + ADR-012 §75 is the slashless form,
        not the resource-root-trailing-slash form an earlier draft
        used. The T5/T7 collision split is honored because the
        review-queue path contains the ``/review-queue`` sub-segment
        while the T7 list path is the bare parent root.
        """
        router = build_packs_router(store=_StubStore())  # type: ignore[arg-type]
        app = FastAPI()
        app.include_router(router)

        # Collect (path, methods) tuples for every GET route.
        get_routes: list[tuple[str, frozenset[str]]] = []
        for route in app.routes:
            path = getattr(route, "path", "")
            methods = getattr(route, "methods", None)
            if methods and "GET" in methods:
                get_routes.append((path, frozenset(methods)))

        compiled_paths = {p for p, _ in get_routes}

        # T5 review-queue path is present.
        assert "/api/v1/packs/review-queue" in compiled_paths, (
            f"T5 review-queue path missing from composed router; "
            f"got GET routes: {sorted(compiled_paths)}"
        )
        # T7 inspection list path is present (EXACT no-trailing-slash
        # form per R33 P2 doctrine decision; the slashless form IS
        # the wire-protocol contract, not a 307-redirect target).
        assert "/api/v1/packs" in compiled_paths, (
            f"T7 examiner-list path missing from composed router; "
            f"got GET routes: {sorted(compiled_paths)}"
        )
        # Defensive — the trailing-slash form must NOT be registered.
        # An earlier draft used ``@router.get("/")`` on a sub-router
        # which produced ``/api/v1/packs/`` + 307 redirect; R33 P2
        # rejected that in favour of the exact slashless path. This
        # regression pin catches a future revert.
        assert "/api/v1/packs/" not in compiled_paths, (
            f"T7 examiner-list path must be the EXACT slashless form "
            f"per R33 P2 (no trailing slash); a trailing-slash route "
            f"would re-introduce the 307-redirect fallback that the "
            f"doctrine decision rejected. Got: {sorted(compiled_paths)}"
        )
        # No shadow — the two are distinct paths, both at GET.
        review_route = next((p, m) for p, m in get_routes if p == "/api/v1/packs/review-queue")
        list_route = next((p, m) for p, m in get_routes if p == "/api/v1/packs")
        assert review_route[1] == {"GET"}
        assert list_route[1] == {"GET"}
        assert review_route[0] != list_route[0], (
            "T5/T7 collision split honored — distinct paths required"
        )

    def test_build_packs_router_includes_inspection_routes(self) -> None:
        """Production-wiring regression mirroring the T5/T6 R16/R18
        pattern — the actual :func:`build_packs_router` factory output
        MUST include the T7 inspection paths. Without this, a
        regression that creates ``inspection_routes.py`` but never
        wires it into the parent router would silently ship a
        half-wired inspection surface."""
        router = build_packs_router(store=_StubStore())  # type: ignore[arg-type]
        app = FastAPI()
        app.include_router(router)
        compiled_paths = {getattr(route, "path", "") for route in app.routes}

        # T7 list path lands at the EXACT slashless wire-protocol path
        # per R33 P2 doctrine (list endpoint registered directly on
        # the parent router via ``register_inspection_list`` with
        # path="").
        assert "/api/v1/packs" in compiled_paths, (
            f"T7 inspection-list path not wired into production "
            f"build_packs_router — got {sorted(compiled_paths)}"
        )
        # T5 + T4 paths remain (no regression in router wiring).
        assert "/api/v1/packs/review-queue" in compiled_paths, (
            f"T5 review-queue path lost — regression in router wiring; got {sorted(compiled_paths)}"
        )
        assert "/api/v1/packs/drafts" in compiled_paths, (
            f"T4 author-drafts path lost — regression in router wiring; "
            f"got {sorted(compiled_paths)}"
        )


# ===========================================================================
# {pack_id} endpoints — detail / audit / invocations
# (Plan §995-1000 endpoint table rows 2/3/4 + §1006-1009 tenant-isolation)
# ===========================================================================


# ---------------------------------------------------------------------------
# Path-param convention regression — mirrors test_review_routes.py:321-365
# (Plan §1010 — T7 + T6 mirror T5's `{pack_id}` convention)
# ---------------------------------------------------------------------------


class TestSprint7B2InspectionRoutesPathParamConvention:
    """Each inspection endpoint with a path UUID MUST use ``{pack_id}``
    (NOT ``{id}``) so the shared
    :func:`RequireTenantOwnership(pack_id_param="pack_id")` dependency
    can pull the UUID from ``request.path_params["pack_id"]``. A
    regression to ``{id}`` would land 500s on every request because
    ``RequireTenantOwnership`` raises ``RuntimeError`` when its
    declared kwarg name is absent from ``request.path_params`` (per
    ``tenant_isolation.py:122-129``).
    """

    @pytest.mark.parametrize(
        "expected_path",
        [
            "/api/v1/packs/{pack_id}",
            "/api/v1/packs/{pack_id}/audit",
            "/api/v1/packs/{pack_id}/invocations",
        ],
    )
    def test_inspection_route_uses_pack_id_path_param(
        self,
        expected_path: str,
    ) -> None:
        """Each inspection endpoint with a path UUID compiles to a
        path containing ``{pack_id}``."""
        router = build_packs_router(store=_StubStore())  # type: ignore[arg-type]
        app = FastAPI()
        app.include_router(router)
        compiled_paths = {getattr(route, "path", "") for route in app.routes}

        assert expected_path in compiled_paths, (
            f"expected inspection endpoint at {expected_path} but got: {sorted(compiled_paths)}"
        )

    def test_inspection_endpoints_do_not_use_id_path_param(self) -> None:
        """Defensive — no inspection endpoint uses the legacy ``{id}``
        path-param convention."""
        router = build_packs_router(store=_StubStore())  # type: ignore[arg-type]
        app = FastAPI()
        app.include_router(router)
        compiled_paths = {getattr(route, "path", "") for route in app.routes}

        bad_paths = {p for p in compiled_paths if "{id}" in p}
        assert not bad_paths, (
            f"inspection routes must use {{pack_id}} not {{id}} — got bad paths: {bad_paths}"
        )


# ---------------------------------------------------------------------------
# Detail endpoint (Plan §998)
# GET /api/v1/packs/{pack_id} — pack.audit.read + RequireTenantOwnership
# Returns pack detail INCL. lifecycle history (composite response)
# ---------------------------------------------------------------------------


class TestSprint7B2InspectionDetailEndpoint:
    """``GET /api/v1/packs/{pack_id}`` — pack detail incl. lifecycle
    history per plan §998.

    Dependency chain:

    1. :class:`RequireScope("pack.audit.read")` — 403 ``scope_not_held``
       for missing scope.
    2. :class:`RequireTenantOwnership(pack_id_param="pack_id")` — 404
       ``tenant_id_mismatch`` for cross-tenant (info-leak prevention);
       404 ``pack_not_found`` for unknown UUID.

    Response shape: JSON object with two top-level keys ``pack`` (the
    :class:`PackResponse` projection) and ``history`` (list of
    lifecycle-event dicts projected through
    :class:`PackLifecycleEventResponse`).
    """

    async def test_detail_happy_path_returns_pack_and_history(
        self,
        store: PackRecordStore,
    ) -> None:
        """Examiner with ``pack.audit.read`` + tenant ``t1`` GETs the
        ``t1`` pack and receives BOTH the :class:`PackResponse`-shaped
        projection AND the lifecycle history (at least the ``submit``
        chain row emitted by the seed helper)."""
        record = await _seed_pack(
            store,
            tenant_id="t1",
            state_after_seed="submitted",
        )
        actor = _make_actor(
            tenant_id="t1",
            scopes=frozenset({"pack.audit.read"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get(f"/api/v1/packs/{record.id}")

        assert response.status_code == 200, response.text
        body = response.json()
        assert isinstance(body, dict), f"detail response must be a dict; got {type(body).__name__}"
        assert "pack" in body, f"detail response missing 'pack' key; got {body}"
        assert "history" in body, f"detail response missing 'history' key; got {body}"

        # `pack` carries the PackResponse projection.
        pack_body = body["pack"]
        assert pack_body["pack_id"] == record.pack_id
        assert pack_body["state"] == "submitted"

        # `history` is a list with at least the submit chain row.
        history = body["history"]
        assert isinstance(history, list)
        assert len(history) >= 1, (
            f"history must contain at least the submit chain row; got {history}"
        )
        # Each row has at minimum decision_type. (``sequence`` is the
        # chain ordering column at the DB layer — selected for ORDER BY
        # in :meth:`PackRecordStore.load_lifecycle_history` but NOT
        # carried on :class:`DecisionRecord` per the live schema at
        # ``core/decision_history.py:240-249``. Surfacing it on the
        # wire is an explicit CC-ADJ extension on the canonical
        # decision-history dataclass — out of T7 scope.)
        for event in history:
            assert "decision_type" in event

        # The submit row is tagged ``pack.lifecycle.submitted`` per
        # ``packs/storage.py:866`` (target-state event-type namespace).
        decision_types = {event["decision_type"] for event in history}
        assert "pack.lifecycle.submitted" in decision_types, (
            f"submit chain row missing from history; got {decision_types}"
        )

    async def test_detail_refuses_when_scope_missing(
        self,
        store: PackRecordStore,
    ) -> None:
        """Actor without ``pack.audit.read`` → 403 ``scope_not_held``."""
        record = await _seed_pack(store, tenant_id="t1")
        actor = _make_actor(tenant_id="t1", scopes=frozenset())
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get(f"/api/v1/packs/{record.id}")

        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "scope_not_held"

    async def test_detail_refuses_cross_tenant_with_404(
        self,
        store: PackRecordStore,
    ) -> None:
        """Actor in tenant ``t1`` attempts to GET a pack belonging to
        tenant ``t2`` → 404 ``tenant_id_mismatch`` (info-leak
        prevention; the cross-tenant request MUST NOT distinguish
        between "pack exists but in another tenant" and "pack does
        not exist")."""
        record = await _seed_pack(store, tenant_id="t2")
        actor = _make_actor(
            tenant_id="t1",
            scopes=frozenset({"pack.audit.read"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get(f"/api/v1/packs/{record.id}")

        assert response.status_code == 404
        assert response.json()["detail"]["reason"] == "tenant_id_mismatch"

    async def test_detail_returns_pack_not_found_for_unknown_id(
        self,
        store: PackRecordStore,
    ) -> None:
        """Unknown UUID (no row in ``packs`` table) → 404
        ``pack_not_found`` (RequireTenantOwnership surfaces this
        before the handler body runs)."""
        unknown_id = uuid.uuid4()
        actor = _make_actor(
            tenant_id="t1",
            scopes=frozenset({"pack.audit.read"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get(f"/api/v1/packs/{unknown_id}")

        assert response.status_code == 404
        assert response.json()["detail"]["reason"] == "pack_not_found"


# ---------------------------------------------------------------------------
# Audit endpoint (Plan §999)
# GET /api/v1/packs/{pack_id}/audit — pack.audit.read + RequireTenantOwnership
# Returns hash-chained audit events for this pack
# ---------------------------------------------------------------------------


class TestSprint7B2InspectionAuditEndpoint:
    """``GET /api/v1/packs/{pack_id}/audit`` — hash-chained audit
    events per plan §999. Reads via :meth:`PackRecordStore.load_pack_audit_events`
    (lifecycle + ``pack.approval_override`` union per review §4.4 C-narrow;
    filtered to ``payload['pack_id'] == str(pack_id)`` at the storage seam —
    in the storage CC surface and dialect-portable across PG / Oracle / SQLite).
    Override-visibility + evidence-read-deferral pins live in
    :class:`TestReviewS44AuditOverrideVisibility` below.

    Dependency chain identical to detail endpoint above:
    ``pack.audit.read`` + ``RequireTenantOwnership``.

    Response shape (locked here): a JSON list of audit-event dicts
    with at minimum ``decision_type`` + ``sequence`` + ``payload``.
    The handler MUST filter cross-pack rows out at the storage seam
    (other packs in the same tenant emit chain rows under different
    ``payload.pack_id`` values; the storage walker already filters
    them).
    """

    async def test_audit_happy_path_returns_chain_rows(
        self,
        store: PackRecordStore,
    ) -> None:
        """GET ``/{pack_id}/audit`` for a submitted pack returns at
        least one audit-event row (the submit chain row)."""
        record = await _seed_pack(
            store,
            tenant_id="t1",
            state_after_seed="submitted",
        )
        actor = _make_actor(
            tenant_id="t1",
            scopes=frozenset({"pack.audit.read"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get(f"/api/v1/packs/{record.id}/audit")

        assert response.status_code == 200, response.text
        body = response.json()
        assert isinstance(body, list), f"audit response must be a list; got {type(body).__name__}"
        assert len(body) >= 1, f"audit must contain at least the submit chain row; got {body}"
        # Each row has at minimum decision_type + payload. (See the
        # detail-endpoint test above for the rationale on omitting the
        # ``sequence`` assertion — DecisionRecord doesn't carry it.)
        for event in body:
            assert "decision_type" in event
            assert "payload" in event

        decision_types = {event["decision_type"] for event in body}
        assert "pack.lifecycle.submitted" in decision_types

    async def test_audit_filters_to_pack_id(
        self,
        store: PackRecordStore,
    ) -> None:
        """The audit endpoint MUST filter rows to ONLY this pack's
        chain rows — other packs in the same tenant emit chain rows
        under their own ``payload.pack_id`` and MUST be absent."""
        # Seed TWO submitted packs in the same tenant.
        record_a = await _seed_pack(
            store,
            tenant_id="t1",
            pack_id="cognic-tool-pack-a",
            state_after_seed="submitted",
        )
        record_b = await _seed_pack(
            store,
            tenant_id="t1",
            pack_id="cognic-tool-pack-b",
            state_after_seed="submitted",
        )

        actor = _make_actor(
            tenant_id="t1",
            scopes=frozenset({"pack.audit.read"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response_a = client.get(f"/api/v1/packs/{record_a.id}/audit")
            response_b = client.get(f"/api/v1/packs/{record_b.id}/audit")

        assert response_a.status_code == 200, response_a.text
        assert response_b.status_code == 200, response_b.text

        body_a = response_a.json()
        body_b = response_b.json()

        # Each audit row's payload.pack_id MUST match the requested pack.
        for event in body_a:
            assert event["payload"]["pack_id"] == str(record_a.id), (
                f"audit for pack_a leaked a row from another pack: {event}"
            )
        for event in body_b:
            assert event["payload"]["pack_id"] == str(record_b.id), (
                f"audit for pack_b leaked a row from another pack: {event}"
            )

    async def test_audit_refuses_when_scope_missing(
        self,
        store: PackRecordStore,
    ) -> None:
        """Actor without ``pack.audit.read`` → 403 ``scope_not_held``."""
        record = await _seed_pack(store, tenant_id="t1")
        actor = _make_actor(tenant_id="t1", scopes=frozenset())
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get(f"/api/v1/packs/{record.id}/audit")

        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "scope_not_held"

    async def test_audit_refuses_cross_tenant_with_404(
        self,
        store: PackRecordStore,
    ) -> None:
        """Cross-tenant audit read → 404 ``tenant_id_mismatch``."""
        record = await _seed_pack(
            store,
            tenant_id="t2",
            state_after_seed="submitted",
        )
        actor = _make_actor(
            tenant_id="t1",
            scopes=frozenset({"pack.audit.read"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get(f"/api/v1/packs/{record.id}/audit")

        assert response.status_code == 404
        assert response.json()["detail"]["reason"] == "tenant_id_mismatch"


# ---------------------------------------------------------------------------
# Invocations endpoint (Plan §1000)
# GET /api/v1/packs/{pack_id}/invocations?from&to
# pack.invocation.read + RequireTenantOwnership
# ---------------------------------------------------------------------------


class TestSprint7B2InspectionInvocationsEndpoint:
    """``GET /api/v1/packs/{pack_id}/invocations?from&to`` — pack
    invocation history per plan §1000.

    Dependency chain — DIFFERENT scope from detail/audit:
    ``pack.invocation.read`` + ``RequireTenantOwnership(pack_id_param=
    "pack_id")``. A request bearing ``pack.audit.read`` but NOT
    ``pack.invocation.read`` MUST receive 403 — the closed-enum scope
    vocabulary at ``portal/rbac/scopes.py`` lists these as distinct
    grants.

    Sprint 7B.2 scope per plan §1000: returns audit-derived
    invocation events only; deeper analytics deferred. The response
    is a JSON list (possibly empty when no invocation events exist
    yet). ``from`` and ``to`` query params (ISO-8601 datetime
    strings) narrow the window when provided.
    """

    async def test_invocations_happy_path_returns_list(
        self,
        store: PackRecordStore,
    ) -> None:
        """Examiner with ``pack.invocation.read`` + tenant ``t1`` GETs
        invocations for a ``t1`` pack and receives 200 + a list (may
        be empty in Sprint 7B.2)."""
        record = await _seed_pack(
            store,
            tenant_id="t1",
            state_after_seed="submitted",
        )
        actor = _make_actor(
            tenant_id="t1",
            scopes=frozenset({"pack.invocation.read"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get(f"/api/v1/packs/{record.id}/invocations")

        assert response.status_code == 200, response.text
        body = response.json()
        assert isinstance(body, list), (
            f"invocations response must be a list; got {type(body).__name__}"
        )

    async def test_invocations_accepts_from_and_to_query_params(
        self,
        store: PackRecordStore,
    ) -> None:
        """The endpoint accepts ``?from=<iso-datetime>&to=<iso-datetime>``
        query params per plan §1000 endpoint table row 4. Sprint 7B.2
        scope: shape only — the endpoint must not 422-error on these
        params; window-narrowing semantics are deferred until the
        invocation-event-type vocabulary lands. ISO-8601 strings are
        the canonical wire format."""
        record = await _seed_pack(
            store,
            tenant_id="t1",
            state_after_seed="submitted",
        )
        actor = _make_actor(
            tenant_id="t1",
            scopes=frozenset({"pack.invocation.read"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get(
                f"/api/v1/packs/{record.id}/invocations",
                params={
                    "from": "2026-05-01T00:00:00+00:00",
                    "to": "2026-05-31T23:59:59+00:00",
                },
            )

        # 200 (handler runs; even if window-narrowing returns [])
        # vs 422 (FastAPI param-validation refusal — the shape pin).
        assert response.status_code == 200, response.text
        body = response.json()
        assert isinstance(body, list)

    async def test_invocations_refuses_when_scope_missing(
        self,
        store: PackRecordStore,
    ) -> None:
        """Actor without ``pack.invocation.read`` (specifically — NOT
        ``pack.audit.read``) → 403 ``scope_not_held``. The two scopes
        are DISTINCT grants per ``portal/rbac/scopes.py:52-53``;
        invocations is a separate examiner concern from generic audit
        history."""
        record = await _seed_pack(store, tenant_id="t1")
        # Explicitly grant pack.audit.read BUT NOT pack.invocation.read —
        # the invocations endpoint must refuse despite the actor's
        # audit-read grant. Pins the scope-separation invariant.
        actor = _make_actor(
            tenant_id="t1",
            scopes=frozenset({"pack.audit.read"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get(f"/api/v1/packs/{record.id}/invocations")

        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "scope_not_held"

    async def test_invocations_refuses_cross_tenant_with_404(
        self,
        store: PackRecordStore,
    ) -> None:
        """Cross-tenant invocations read → 404 ``tenant_id_mismatch``."""
        record = await _seed_pack(
            store,
            tenant_id="t2",
            state_after_seed="submitted",
        )
        actor = _make_actor(
            tenant_id="t1",
            scopes=frozenset({"pack.invocation.read"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get(f"/api/v1/packs/{record.id}/invocations")

        assert response.status_code == 404
        assert response.json()["detail"]["reason"] == "tenant_id_mismatch"


# ---------------------------------------------------------------------------
# Review §4.4 (C-narrow) — force-approve authorisations visible at /audit
# ---------------------------------------------------------------------------


class TestReviewS44AuditOverrideVisibility:
    """Review §4.4 (C-narrow): the examiner-facing ``GET /{pack_id}/audit``
    endpoint MUST surface ``pack.approval_override`` force-approve
    authorisations (ADR-012 §107), while ``GET /{pack_id}`` detail stays
    lifecycle-only. ``pack.evidence_read.*`` is deliberately deferred."""

    _SNAPSHOT: ClassVar[dict[str, Any]] = {"pack_kind": "tool", "all_green": False, "gates": []}

    async def _seed_with_override(
        self, store: PackRecordStore, *, tenant_id: str = "t1"
    ) -> PackRecord:
        record = await _seed_pack(store, tenant_id=tenant_id, state_after_seed="submitted")
        await store.append_override_event(
            pack_id=record.id,
            override_actor_subject="alice@bank.example",
            override_reason="security_exception",
            gate_composition_snapshot=self._SNAPSHOT,
            request_id=f"override-seed-{record.id.hex[:8]}",
        )
        return record

    async def test_audit_includes_pack_approval_override(self, store: PackRecordStore) -> None:
        # pin #3
        record = await self._seed_with_override(store)
        actor = _make_actor(tenant_id="t1", scopes=frozenset({"pack.audit.read"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get(f"/api/v1/packs/{record.id}/audit")

        assert response.status_code == 200, response.text
        decision_types = {event["decision_type"] for event in response.json()}
        assert "pack.lifecycle.submitted" in decision_types
        assert "pack.approval_override" in decision_types

    async def test_detail_still_excludes_pack_approval_override(
        self, store: PackRecordStore
    ) -> None:
        # pin #4
        record = await self._seed_with_override(store)
        actor = _make_actor(tenant_id="t1", scopes=frozenset({"pack.audit.read"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get(f"/api/v1/packs/{record.id}")

        assert response.status_code == 200, response.text
        decision_types = {event["decision_type"] for event in response.json()["history"]}
        assert "pack.lifecycle.submitted" in decision_types
        assert "pack.approval_override" not in decision_types

    async def test_audit_excludes_evidence_read_events(self, store: PackRecordStore) -> None:
        # pin #6 (route level) — evidence_read deferred (§4.4 C-narrow).
        record = await self._seed_with_override(store)
        await store.append_evidence_read_event(
            pack_id=record.id,
            actor_subject="reviewer-alice",
            panel_name="data_governance",
            tenant_id="t1",
            request_id=f"evread-seed-{record.id.hex[:8]}",
        )
        actor = _make_actor(tenant_id="t1", scopes=frozenset({"pack.audit.read"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get(f"/api/v1/packs/{record.id}/audit")

        assert response.status_code == 200, response.text
        decision_types = {event["decision_type"] for event in response.json()}
        assert "pack.approval_override" in decision_types
        assert not any(dt.startswith("pack.evidence_read") for dt in decision_types)

    async def test_audit_cross_tenant_override_not_leaked(self, store: PackRecordStore) -> None:
        # pin #5 (route level) — pack B's override never appears in pack A's
        # audit, even when both share a tenant.
        record_a = await self._seed_with_override(store, tenant_id="t1")
        record_b = await self._seed_with_override(store, tenant_id="t1")
        actor = _make_actor(tenant_id="t1", scopes=frozenset({"pack.audit.read"}))
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get(f"/api/v1/packs/{record_a.id}/audit")

        assert response.status_code == 200, response.text
        pack_ids = {event["payload"]["pack_id"] for event in response.json()}
        assert pack_ids == {str(record_a.id)}, (
            f"pack_a audit leaked rows from other packs: {pack_ids}"
        )
        # record_b's override (same tenant) MUST NOT appear in pack_a's audit.
        assert str(record_b.id) not in pack_ids
