"""Sprint 7B.2 T5 — review_routes.py route-table + dependency-wiring pins.

Plan Round 11 P2 #4 / Round 12 P2 #1 / Round 13 P2 #1 / Round 16 P2 #1 /
Round 17 P2 #1 — the T5 review surface ships 5 endpoints behind
``/api/v1/packs``:

- ``GET  /api/v1/packs/review-queue`` (Round 12 P2 #1 — moved off the
  ``?status=submitted`` query collision with T7's ``GET /api/v1/packs``)
- ``POST /api/v1/packs/{pack_id}/claim``
- ``POST /api/v1/packs/{pack_id}/approve`` (Sprint 7B.3 T9 wired the
  ADR-012 §41 five-gate composer + override path — replacing the T5
  fail-loud 503 stub; the obsolete ``TestSprint7B2ApproveFailLoud``
  class was removed at T9. Approve-endpoint regressions now live in
  ``test_review_approve_5_gate.py`` + ``test_review_approve_override.py``
  + ``test_review_routes_trust_gate_wiring.py``.)
- ``POST /api/v1/packs/{pack_id}/reject``
- ``GET  /api/v1/packs/{pack_id}/evidence``

**T5-deliverable-4 slice: route-table + dependency wiring only.** Per
the user's bones-first sequencing direction, this slice pins the route
shape + production wiring before handler behavior. Handler-behavior
regressions (RBAC denial / tenant isolation / role-separation /
PackNotFound race / structured-log emission / 4-axis approve matrix /
reviewer-queue tenant-filter / evidence read path) land in subsequent
RED→GREEN cycles within the same T5 commit.

Pins exercised in this slice:

1. ``test_review_routes_does_not_register_inspection_list_path``
   (R13 P2 #1 + R15 P2 #2 mount-prefix correction) — review-only
   sub-router exposes ``/review-queue`` but NOT ``/api/v1/packs``
   (T7 examiner-list path stays unregistered at T5).
2. ``test_build_packs_router_includes_review_routes`` (R16 P2 #1
   production-wiring regression) — the actual production
   ``build_packs_router`` factory output includes BOTH the T4 author
   paths AND the T5 review paths.
3. ``test_review_routes_path_param_name_matches_dependency`` (R17 P2 #1
   path-shell half) — the 4 endpoints with a path UUID use
   ``{pack_id}`` (NOT ``{id}``) matching T4's convention + the shared
   ``RequireTenantOwnership(pack_id_param="pack_id")`` dependency.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import APIRouter, FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.packs.storage import PackNotFound, PackRecord, PackRecordStore
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.api.packs import build_packs_router
from cognic_agentos.portal.api.packs.review_routes import build_review_routes
from cognic_agentos.portal.rbac.actor import Actor


class _StubStore:
    """Test-only :class:`PackRecordStore` stand-in for the route-shell
    smoke tests (route-table assertions don't invoke store methods).
    Slice 2a uses real SQLite-backed :class:`PackRecordStore` via the
    ``store`` fixture below; one stub-store test pins the
    ``PackNotFound`` race translation per Round 16 P2 #2."""


# ---------------------------------------------------------------------------
# Slice 2a fixtures (mirrors test_author_routes.py:67-168)
# ---------------------------------------------------------------------------


class _StubBinder:
    """Test-only :class:`ActorBinder` returning a configured actor.
    Mirrors ``test_author_routes.py::_StubBinder``."""

    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


def _make_actor(
    *,
    subject: str = "alice@bank.example",
    tenant_id: str = "t1",
    scopes: frozenset[str] = frozenset({"pack.review.claim"}),
    actor_type: str = "human",
) -> Actor:
    """Build a fixture :class:`Actor`. Defaults to ``alice`` (the
    reviewer) with ``pack.review.claim`` scope so happy-path claims
    work; override ``subject`` to ``bob@bank.example`` to trigger the
    role-separation refusal (matches the canonical author below)."""
    return Actor(
        subject=subject,
        tenant_id=tenant_id,
        scopes=scopes,  # type: ignore[arg-type]
        actor_type=actor_type,  # type: ignore[arg-type]
    )


@pytest.fixture
async def engine(tmp_path: Any) -> AsyncIterator[AsyncEngine]:
    """SQLite engine seeded with governance schema + chain heads —
    mirrors ``test_author_routes.py::engine``."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'review_routes.db'}"
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
    binder + store; mirrors ``test_author_routes.py::_build_app``."""
    return create_app(
        actor_binder=_StubBinder(actor),
        pack_record_store=store,
    )


async def _seed_submitted_pack(
    store: PackRecordStore,
    *,
    tenant_id: str = "t1",
    created_by: str = "bob@bank.example",
) -> PackRecord:
    """Save a draft + transition to submitted. The reviewer (``alice``)
    will claim this; the author (``bob``) is intentionally a different
    subject so the role-separation guard ADMITS rather than refuses."""
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
    await store.save_draft(record)
    await store.transition(
        pack_id=record.id,
        transition="submit",
        actor_id=created_by,
        tenant_id=tenant_id,
        evidence_pointer=None,
        request_id=f"submit-seed-{record.id.hex[:8]}",
    )
    # Return the in-memory record but with state="submitted" so callers
    # can assert against it; real store row reflects the same.
    return record.model_copy(update={"state": "submitted"})


async def _seed_draft_pack(
    store: PackRecordStore,
    *,
    tenant_id: str = "t1",
    created_by: str = "bob@bank.example",
) -> PackRecord:
    """Save a draft and leave it in draft state — for the
    state-machine-refusal test (claim on draft is illegal)."""
    now = datetime.now(UTC)
    record = PackRecord(
        id=uuid.uuid4(),
        kind="tool",
        pack_id=f"cognic-tool-{uuid.uuid4().hex[:8]}",
        display_name="Draft Pack",
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
    return record


async def _seed_under_review_pack(
    store: PackRecordStore,
    *,
    tenant_id: str = "t1",
    created_by: str = "bob@bank.example",
    claimed_by: str = "carol@bank.example",
) -> PackRecord:
    """Save a draft → submit → claim, leaving the pack in
    ``under_review`` state for the reject happy-path test.

    Note: ``claimed_by`` is intentionally distinct from ``created_by``
    + the reviewer we'll use for the actual reject — the role-separation
    guard fires on ``actor.subject == record.created_by``, not on the
    claimer. The reject reviewer (``alice``) will be a third actor."""
    record = await _seed_submitted_pack(store, tenant_id=tenant_id, created_by=created_by)
    await store.transition(
        pack_id=record.id,
        transition="claim",
        actor_id=claimed_by,
        tenant_id=tenant_id,
        evidence_pointer=None,
        request_id=f"claim-seed-{record.id.hex[:8]}",
    )
    return record.model_copy(update={"state": "under_review"})


# ---------------------------------------------------------------------------
# T5-narrow route-ownership proof (R13 P2 #1 + R15 P2 #2)
# ---------------------------------------------------------------------------


class TestSprint7B2ReviewRouteOwnership:
    """Plan R13 P2 #1 + R15 P2 #2 — narrow proof at T5-execution time
    (before ``inspection_routes.py`` exists at T7): the review sub-router
    carries ``/review-queue`` BUT does NOT register ``/api/v1/packs``
    (the T7 examiner-list path).

    R15 P2 #2 — Shape A (mount under a test parent) — un-mounted
    APIRouter routes carry relative paths only, so we mount the
    review sub-router under a fresh parent at ``/api/v1/packs`` to
    exercise the actually-deployed compiled-path shape.
    """

    def test_review_routes_does_not_register_inspection_list_path(self) -> None:
        """Review sub-router mounted under test parent at
        ``/api/v1/packs`` exposes compiled path
        ``GET /api/v1/packs/review-queue`` but does NOT expose the T7
        examiner-list path ``GET /api/v1/packs``.
        """
        review_router = build_review_routes(store=_StubStore())  # type: ignore[arg-type]
        parent = APIRouter(prefix="/api/v1/packs")
        parent.include_router(review_router)
        app = FastAPI()
        app.include_router(parent)

        compiled_paths = {getattr(route, "path", "") for route in app.routes}

        assert "/api/v1/packs/review-queue" in compiled_paths, (
            f"review-queue path must be reachable; got {compiled_paths}"
        )
        assert "/api/v1/packs" not in compiled_paths, (
            "review sub-router must NOT register the T7 examiner-list path "
            "/api/v1/packs (R12 P2 #1 — T5 owns review-queue; T7 will own /packs); "
            f"got {compiled_paths}"
        )


# ---------------------------------------------------------------------------
# Production-wiring regression (R16 P2 #1)
# ---------------------------------------------------------------------------


class TestSprint7B2ReviewRoutesProductionWiring:
    """Plan R16 P2 #1 — the actual production ``build_packs_router``
    factory output MUST include the T5 review paths. Without this
    test, a regression that creates ``review_routes.py`` but never
    wires it into the parent router would silently ship a half-wired
    review surface (manual-mount test passes; production missing
    review endpoints).
    """

    def test_build_packs_router_includes_review_routes(self) -> None:
        """``build_packs_router(store=stub)`` produces a router whose
        compiled ``app.routes`` includes the T5 review-queue path AND
        the T4 author-drafts path AND the T7 examiner-list path.

        **Sprint 7B.2 T7 carry-forward** — the original T5 assertion
        was a TEMPORAL negative pin ("T7 not yet wired") which was
        load-bearing only between T5 and T7 landing. T7 wires the
        inspection list endpoint into :func:`build_packs_router` at
        EXACTLY ``/api/v1/packs`` (no trailing slash, per R33 P2
        doctrine — the list endpoint is registered directly on the
        parent router via ``register_inspection_list`` so path ``""``
        + parent prefix yields the slashless wire-protocol path per
        plan §997 + ADR-012 §75). The negative assertion is flipped
        to a positive "BOTH T5 review-queue AND T7 inspection-list
        are reachable post-T7-wire" — composition regression pinning
        that neither shadows the other. The T5/T7 collision split
        (review queue at ``/review-queue``; inspection list at the
        bare parent root) means the two paths are textually distinct
        in the compiled route table.

        The narrow ``review_routes`` half — that the T5 sub-router
        ALONE does NOT register the inspection path — is pinned
        SEPARATELY by ``test_review_routes_does_not_register_inspection_list_path``
        (the regression isolated to the T5 sub-router output, not
        the fully-composed parent router output).
        """
        router = build_packs_router(store=_StubStore())  # type: ignore[arg-type]
        app = FastAPI()
        app.include_router(router)
        compiled_paths = {getattr(route, "path", "") for route in app.routes}

        assert "/api/v1/packs/review-queue" in compiled_paths, (
            "T5 review-queue path not wired into production build_packs_router "
            f"— got {compiled_paths}"
        )
        assert "/api/v1/packs/drafts" in compiled_paths, (
            f"T4 author-drafts path lost — regression in router wiring; got {compiled_paths}"
        )
        # T7 carry-forward — inspection list at EXACTLY
        # ``/api/v1/packs`` (no trailing slash per R33 P2 doctrine —
        # the slashless form IS the wire-protocol contract per plan
        # §997, not a 307-redirect target). Was a negative "not yet
        # wired" assertion pre-T7; flipped to a positive presence
        # assertion now.
        assert "/api/v1/packs" in compiled_paths, (
            f"T7 examiner-list path missing from composed build_packs_router — got {compiled_paths}"
        )


# ---------------------------------------------------------------------------
# Path-param-name convention regression (R17 P2 #1 — path-shell half)
# ---------------------------------------------------------------------------


class TestSprint7B2ReviewRoutesPathParamConvention:
    """Plan R17 P2 #1 — the 4 review endpoints with a path UUID MUST
    use ``{pack_id}`` (NOT ``{id}``) matching T4's convention + the
    shared ``RequireTenantOwnership(pack_id_param="pack_id")``
    dependency. Path-shell half of the regression; the full malformed-
    UUID → 404 vs 500 fingerprint check lands once handler bodies +
    dependencies are wired in subsequent slices.
    """

    @pytest.mark.parametrize(
        "expected_path",
        [
            "/api/v1/packs/{pack_id}/claim",
            "/api/v1/packs/{pack_id}/approve",
            "/api/v1/packs/{pack_id}/reject",
            "/api/v1/packs/{pack_id}/evidence",
        ],
    )
    def test_review_route_uses_pack_id_path_param(self, expected_path: str) -> None:
        """Each review endpoint with a path UUID compiles to a path
        containing ``{pack_id}``. T7 + T6 mirror this convention."""
        router = build_packs_router(store=_StubStore())  # type: ignore[arg-type]
        app = FastAPI()
        app.include_router(router)
        compiled_paths = {getattr(route, "path", "") for route in app.routes}

        assert expected_path in compiled_paths, (
            f"expected review endpoint at {expected_path} but got: {sorted(compiled_paths)}"
        )

    def test_review_endpoints_do_not_use_id_path_param(self) -> None:
        """Defensive — no review endpoint uses the legacy ``{id}``
        path param convention. A regression here would land 500s on
        malformed UUIDs (the ``RequireTenantOwnership`` dependency
        raises RuntimeError when ``request.path_params["pack_id"]`` is
        absent)."""
        router = build_packs_router(store=_StubStore())  # type: ignore[arg-type]
        app = FastAPI()
        app.include_router(router)
        compiled_paths = {getattr(route, "path", "") for route in app.routes}

        bad_paths = {p for p in compiled_paths if "{id}" in p}
        assert not bad_paths, (
            f"review routes must use {{pack_id}} not {{id}} — got bad paths: {bad_paths}"
        )


# ---------------------------------------------------------------------------
# Defensive — review router builds without raising (basic smoke)
# ---------------------------------------------------------------------------


def test_build_review_routes_returns_apirouter() -> None:
    """The factory returns an :class:`APIRouter` instance — defensive
    type pin so a future signature drift cannot silently shift the
    return type."""
    router = build_review_routes(store=_StubStore())  # type: ignore[arg-type]
    assert isinstance(router, APIRouter)


def test_build_review_routes_requires_keyword_only_store() -> None:
    """Defence-in-depth — ``store`` is keyword-only (mirrors
    ``build_author_routes`` + ``build_packs_router`` conventions)."""
    with pytest.raises(TypeError):
        build_review_routes(_StubStore())  # type: ignore[arg-type,misc]


def test_review_router_registers_exactly_five_endpoints() -> None:
    """Plan §T5 endpoint table — 5 review endpoints land:
    review-queue + claim + approve + reject + evidence. A regression
    that adds a 6th or drops one would change the surface inventory.
    """
    review_router = build_review_routes(store=_StubStore())  # type: ignore[arg-type]
    # Filter to APIRoute instances (FastAPI auto-registers nothing on a
    # bare APIRouter; every route here is one we declared).
    route_paths = sorted({getattr(r, "path", "") for r in review_router.routes})
    assert len(route_paths) == 5, (
        f"expected exactly 5 review endpoints; got {len(route_paths)}: {route_paths}"
    )


# ===========================================================================
# Slice 2a — POST /api/v1/packs/{pack_id}/claim handler behavior
# (Plan §T5 endpoint table row 2 + R14 P2 #3 + R16 P2 #2 + R17 P2 #2)
# ===========================================================================


class TestSprint7B2ClaimEndpoint:
    """``POST /api/v1/packs/{pack_id}/claim`` — transition
    ``submitted → under_review`` via ``store.transition("claim", ...)``.

    Dependency chain (per R14 P2 #3 + R11 P2 #4):
    1. ``RequireScope("pack.review.claim")`` — 403 ``scope_not_held``
    2. ``RequireTenantOwnership(pack_id_param="pack_id")`` — 404
       ``tenant_id_mismatch`` for cross-tenant
    3. ``RequireDifferentActorThanCreator(tenant_ownership=...)`` —
       403 ``actor_cannot_review_own_pack`` when subject == created_by

    Handler-body refusals:
    - ``PackNotFound`` race (R16 P2 #2) → 404 ``pack_not_found``
    - ``LifecycleTransitionRefused`` → 409 + closed-enum reason

    Structured-log contract (R17 P2 #2): ``portal.packs.claim_refused``
    event fires on every refusal path that reaches the handler.

    Request-id minter (R14 P2 #2): ``_mint_request_id(
    _PACK_CLAIM_REQUEST_ID_PREFIX)`` returns ≤64 chars per the
    ``decision_history.request_id`` String(64) cap.
    """

    async def test_claim_happy_path_advances_state_to_under_review(
        self,
        store: PackRecordStore,
    ) -> None:
        """Reviewer (alice) claims a submitted pack created by bob;
        subjects differ → admits; state advances to ``under_review``;
        chain row emitted with ``last_actor=alice`` + the
        ``pack-claim--`` request-id prefix."""
        record = await _seed_submitted_pack(store, created_by="bob@bank.example")
        actor = _make_actor(
            subject="alice@bank.example",
            scopes=frozenset({"pack.review.claim"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/claim")

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["state"] == "under_review"
        assert body["last_actor"] == "alice@bank.example"
        # Original author preserved (immutable per Sprint 7B.1 contract)
        assert body["created_by"] == "bob@bank.example"

        # Persisted state matches the response
        loaded = await store.load(record.id)
        assert loaded is not None
        assert loaded.state == "under_review"

    async def test_claim_refuses_when_scope_missing(
        self,
        store: PackRecordStore,
    ) -> None:
        """Actor without ``pack.review.claim`` scope → 403
        ``scope_not_held``; handler never runs; state unchanged."""
        record = await _seed_submitted_pack(store, created_by="bob@bank.example")
        actor = _make_actor(subject="alice@bank.example", scopes=frozenset())
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/claim")

        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "scope_not_held"
        loaded = await store.load(record.id)
        assert loaded is not None
        assert loaded.state == "submitted"  # unchanged

    async def test_claim_refuses_cross_tenant_with_404(
        self,
        store: PackRecordStore,
    ) -> None:
        """Actor in tenant t1 attempts to claim a pack in tenant t2 →
        404 ``tenant_id_mismatch`` (info-leak prevention)."""
        record = await _seed_submitted_pack(
            store,
            tenant_id="t2",  # pack lives in t2
            created_by="bob@bank.example",
        )
        actor = _make_actor(
            subject="alice@bank.example",
            tenant_id="t1",  # actor lives in t1
            scopes=frozenset({"pack.review.claim"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/claim")

        assert response.status_code == 404
        assert response.json()["detail"]["reason"] == "tenant_id_mismatch"
        loaded = await store.load(record.id)
        assert loaded is not None
        assert loaded.state == "submitted"

    async def test_claim_refuses_when_actor_is_creator(
        self,
        store: PackRecordStore,
    ) -> None:
        """Plan R11 P2 #4 + ADR-012 §17 — same human cannot both
        submit AND review their own pack. Bob created the pack; Bob
        attempting to claim it → 403 ``actor_cannot_review_own_pack``."""
        record = await _seed_submitted_pack(store, created_by="bob@bank.example")
        actor = _make_actor(
            subject="bob@bank.example",  # SAME as created_by
            scopes=frozenset({"pack.review.claim"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/claim")

        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "actor_cannot_review_own_pack"
        loaded = await store.load(record.id)
        assert loaded is not None
        assert loaded.state == "submitted"

    async def test_claim_refuses_when_pack_not_submitted(
        self,
        store: PackRecordStore,
    ) -> None:
        """Plan T5 watchpoint (a) — claim on a draft-state pack →
        409 ``lifecycle_transition_invalid_state_pair`` (the
        ``_VALID_TRANSITIONS`` map only admits ``submitted →
        under_review`` for the claim transition)."""
        record = await _seed_draft_pack(store, created_by="bob@bank.example")
        actor = _make_actor(
            subject="alice@bank.example",
            scopes=frozenset({"pack.review.claim"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/claim")

        assert response.status_code == 409
        assert response.json()["detail"]["reason"] == "lifecycle_transition_invalid_state_pair"

    def test_claim_handles_pack_not_found_race(self) -> None:
        """Plan R16 P2 #2 — concurrent delete between
        :func:`RequireTenantOwnership` preload + ``store.transition()``
        SELECT FOR UPDATE raises :class:`PackNotFound` inside the
        storage precondition; handler MUST translate to 404
        ``pack_not_found`` (NOT 500). Pinned via a stub store whose
        ``transition()`` raises :class:`PackNotFound` regardless of
        input."""

        class _RaceStore:
            """Stub store: ``load()`` returns a valid PackRecord (so
            the tenant-ownership preload succeeds) but ``transition()``
            raises :class:`PackNotFound` (simulating the race)."""

            def __init__(self, record: PackRecord) -> None:
                self._record = record

            async def load(self, pack_id: uuid.UUID) -> PackRecord | None:
                if pack_id == self._record.id:
                    return self._record
                return None

            async def transition(self, **kwargs: Any) -> tuple[uuid.UUID, bytes]:
                raise PackNotFound(self._record.id)

        record = PackRecord(
            id=uuid.uuid4(),
            kind="tool",
            pack_id="cognic-tool-race",
            display_name="Race Pack",
            state="submitted",
            manifest_digest=b"\x01" * 32,
            signed_artefact_digest=b"\x02" * 32,
            sbom_pointer=None,
            tenant_id="t1",
            created_by="bob@bank.example",
            last_actor="bob@bank.example",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        race_store: PackRecordStore = _RaceStore(record)  # type: ignore[assignment]
        actor = _make_actor(
            subject="alice@bank.example",
            scopes=frozenset({"pack.review.claim"}),
        )
        app = _build_app(actor=actor, store=race_store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/claim")

        # Race produces structured 404 (not 500); the wire-protocol
        # contract pins this as identical to the tenant-isolation
        # `pack_not_found` reason.
        assert response.status_code == 404, response.text
        assert response.json()["detail"]["reason"] == "pack_not_found"

    async def test_claim_request_id_bounded_to_64_chars(
        self,
        store: PackRecordStore,
    ) -> None:
        """Plan R14 P2 #2 — the request_id minted via
        ``_mint_request_id(_PACK_CLAIM_REQUEST_ID_PREFIX)`` MUST fit
        under the ``decision_history.request_id`` String(64) cap.
        Inspects the actual chain row's ``request_id`` field via
        :meth:`PackRecordStore.load_lifecycle_history`."""
        record = await _seed_submitted_pack(store, created_by="bob@bank.example")
        actor = _make_actor(
            subject="alice@bank.example",
            scopes=frozenset({"pack.review.claim"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/claim")
        assert response.status_code == 200

        history = await store.load_lifecycle_history(record.id)
        claim_rows = [r for r in history if r.decision_type == "pack.lifecycle.under_review"]
        assert len(claim_rows) == 1, f"expected exactly 1 claim row, got {len(claim_rows)}"
        request_id = claim_rows[0].request_id
        assert len(request_id) <= 64, (
            f"claim request_id exceeds String(64) cap: len={len(request_id)}, value={request_id!r}"
        )
        assert request_id.startswith("pack-claim--"), (
            f"claim request_id must use _PACK_CLAIM_REQUEST_ID_PREFIX; got {request_id!r}"
        )

    async def test_claim_refused_emits_structured_log(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Plan R17 P2 #2 — refusal paths emit a
        ``portal.packs.claim_refused`` structured log record with
        closed-enum reason + actor_subject + pack_id + from_state.

        Exercises the state-machine-refusal axis (claim on draft pack);
        the role-separation / tenant / RBAC axes emit their own
        sibling-guard logs per the R19 P2 #1 ordering + R19 P2 #2
        operator-vocab discipline.
        """
        caplog.set_level(
            logging.WARNING,
            logger="cognic_agentos.portal.api.packs.review_routes",
        )
        record = await _seed_draft_pack(store, created_by="bob@bank.example")
        actor = _make_actor(
            subject="alice@bank.example",
            scopes=frozenset({"pack.review.claim"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/claim")
        assert response.status_code == 409

        claim_refused_records = [
            r
            for r in caplog.records
            if r.name == "cognic_agentos.portal.api.packs.review_routes"
            and r.message == "portal.packs.claim_refused"
        ]
        assert len(claim_refused_records) == 1, (
            f"expected exactly 1 portal.packs.claim_refused record on refusal; "
            f"got {len(claim_refused_records)}"
        )
        emitted = claim_refused_records[0]
        assert emitted.levelno == logging.WARNING
        assert emitted.reason == "lifecycle_transition_invalid_state_pair"  # type: ignore[attr-defined]
        assert emitted.actor_subject == "alice@bank.example"  # type: ignore[attr-defined]
        assert emitted.pack_id == str(record.id)  # type: ignore[attr-defined]
        assert emitted.from_state == "draft"  # type: ignore[attr-defined]


# ===========================================================================
# Slice 2b — POST /api/v1/packs/{pack_id}/reject handler behavior
# (Plan §T5 endpoint table row 4 + R11 P2 #2 + R11 P2 #3 + R18 P2 #2)
# ===========================================================================


class TestSprint7B2RejectEndpoint:
    """``POST /api/v1/packs/{pack_id}/reject`` — transition
    ``under_review → rejected`` via ``store.transition("reject", ...)``.

    Body schema (R11 P2 #2 — DTO landed at deliverable #3):
    :class:`RejectDraftRequest` — ``reason`` (7-value closed-enum
    :data:`RejectionReason`) + ``comments`` (required non-empty str).

    T5 → T9 history: T5 (R11 P2 #3) shipped the bare reject
    transition with categorised reason + comments emitted via
    structured log ONLY.  Sprint 7B.2 T9 Slice 3 has now extended the
    handler to ALSO attach ``{"rejection_reason": …,
    "reviewer_comments": …}`` to the chain row's
    ``payload["evidence_attachments"]`` via the third
    ``transition()`` kwarg per plan §1086-1088.  The structured log
    remains the operations surface; the chain row is the
    authoritative examiner surface per ADR-006 (defence-in-depth
    dual emission).

    Structured-log contract (R17 P2 #2 + R18 P2 #2 per-event-type
    table):
    - Reject accepted (green) → EXACTLY ONE
      ``portal.packs.review.reject`` record (load-bearing T5 evidence
      surface for categorised reason); NO ``*_refused`` event.
    - Reject refused (state-machine OR PackNotFound race) → EXACTLY
      ONE ``portal.packs.reject_refused`` record; NO accepted log.

    Mutually-exclusive event firing pinned by the test suite.
    """

    async def test_reject_happy_path_advances_state_to_rejected(
        self,
        store: PackRecordStore,
    ) -> None:
        """Reviewer (alice) rejects an under-review pack created by
        bob; subjects differ → admits; state advances to ``rejected``;
        chain row emitted with ``last_actor=alice`` + the
        ``pack-reject-`` request-id prefix."""
        record = await _seed_under_review_pack(
            store,
            created_by="bob@bank.example",
            claimed_by="carol@bank.example",
        )
        actor = _make_actor(
            subject="alice@bank.example",
            scopes=frozenset({"pack.review.reject"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(
                f"/api/v1/packs/{record.id}/reject",
                json={
                    "reason": "signature_invalid",
                    "comments": "cosign signature failed to verify",
                },
            )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["state"] == "rejected"
        assert body["last_actor"] == "alice@bank.example"
        assert body["created_by"] == "bob@bank.example"

        loaded = await store.load(record.id)
        assert loaded is not None
        assert loaded.state == "rejected"

    async def test_reject_refuses_when_scope_missing(
        self,
        store: PackRecordStore,
    ) -> None:
        """Actor without ``pack.review.reject`` scope → 403
        ``scope_not_held``; state unchanged."""
        record = await _seed_under_review_pack(store)
        actor = _make_actor(subject="alice@bank.example", scopes=frozenset())
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(
                f"/api/v1/packs/{record.id}/reject",
                json={"reason": "signature_invalid", "comments": "x"},
            )

        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "scope_not_held"

    async def test_reject_refuses_cross_tenant_with_404(
        self,
        store: PackRecordStore,
    ) -> None:
        """Cross-tenant actor → 404 ``tenant_id_mismatch``."""
        record = await _seed_under_review_pack(store, tenant_id="t2")
        actor = _make_actor(
            subject="alice@bank.example",
            tenant_id="t1",
            scopes=frozenset({"pack.review.reject"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(
                f"/api/v1/packs/{record.id}/reject",
                json={"reason": "signature_invalid", "comments": "x"},
            )

        assert response.status_code == 404
        assert response.json()["detail"]["reason"] == "tenant_id_mismatch"

    async def test_reject_refuses_when_actor_is_creator(
        self,
        store: PackRecordStore,
    ) -> None:
        """Plan R11 P2 #4 + ADR-012 §17 — author cannot reject their
        own pack → 403 ``actor_cannot_review_own_pack``."""
        record = await _seed_under_review_pack(store, created_by="bob@bank.example")
        actor = _make_actor(
            subject="bob@bank.example",  # SAME as created_by
            scopes=frozenset({"pack.review.reject"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(
                f"/api/v1/packs/{record.id}/reject",
                json={"reason": "signature_invalid", "comments": "x"},
            )

        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "actor_cannot_review_own_pack"

    async def test_reject_refuses_when_pack_not_under_review(
        self,
        store: PackRecordStore,
    ) -> None:
        """Reject on a submitted-state pack (not yet claimed) →
        409 ``lifecycle_transition_invalid_state_pair``. The
        ``_VALID_TRANSITIONS`` map only admits ``under_review →
        rejected`` for the reject transition."""
        record = await _seed_submitted_pack(store, created_by="bob@bank.example")
        actor = _make_actor(
            subject="alice@bank.example",
            scopes=frozenset({"pack.review.reject"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(
                f"/api/v1/packs/{record.id}/reject",
                json={"reason": "signature_invalid", "comments": "x"},
            )

        assert response.status_code == 409
        assert response.json()["detail"]["reason"] == "lifecycle_transition_invalid_state_pair"

    def test_reject_handles_pack_not_found_race(self) -> None:
        """Plan R16 P2 #2 — concurrent delete between tenant-isolation
        preload + ``store.transition()`` → 404 ``pack_not_found``."""

        class _RaceStore:
            def __init__(self, record: PackRecord) -> None:
                self._record = record

            async def load(self, pack_id: uuid.UUID) -> PackRecord | None:
                if pack_id == self._record.id:
                    return self._record
                return None

            async def transition(self, **kwargs: Any) -> tuple[uuid.UUID, bytes]:
                raise PackNotFound(self._record.id)

        record = PackRecord(
            id=uuid.uuid4(),
            kind="tool",
            pack_id="cognic-tool-race",
            display_name="Race Pack",
            state="under_review",
            manifest_digest=b"\x01" * 32,
            signed_artefact_digest=b"\x02" * 32,
            sbom_pointer=None,
            tenant_id="t1",
            created_by="bob@bank.example",
            last_actor="carol@bank.example",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        race_store: PackRecordStore = _RaceStore(record)  # type: ignore[assignment]
        actor = _make_actor(
            subject="alice@bank.example",
            scopes=frozenset({"pack.review.reject"}),
        )
        app = _build_app(actor=actor, store=race_store)

        with TestClient(app) as client:
            response = client.post(
                f"/api/v1/packs/{record.id}/reject",
                json={"reason": "signature_invalid", "comments": "x"},
            )

        assert response.status_code == 404
        assert response.json()["detail"]["reason"] == "pack_not_found"

    async def test_reject_refuses_invalid_reason_with_422(
        self,
        store: PackRecordStore,
    ) -> None:
        """Out-of-vocab :data:`RejectionReason` value → 422 from
        Pydantic body validation (closed-enum wire-protocol)."""
        record = await _seed_under_review_pack(store)
        actor = _make_actor(
            subject="alice@bank.example",
            scopes=frozenset({"pack.review.reject"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(
                f"/api/v1/packs/{record.id}/reject",
                json={"reason": "not_a_real_reason", "comments": "x"},
            )

        assert response.status_code == 422

    async def test_reject_refuses_empty_comments_with_422(
        self,
        store: PackRecordStore,
    ) -> None:
        """Empty ``comments`` → 422 from :class:`RejectDraftRequest`'s
        ``Field(min_length=1)`` constraint. The categorised log MUST
        carry a non-empty diagnostic per ADR-012 §42."""
        record = await _seed_under_review_pack(store)
        actor = _make_actor(
            subject="alice@bank.example",
            scopes=frozenset({"pack.review.reject"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(
                f"/api/v1/packs/{record.id}/reject",
                json={"reason": "signature_invalid", "comments": ""},
            )

        assert response.status_code == 422

    async def test_reject_request_id_bounded_to_64_chars_with_prefix(
        self,
        store: PackRecordStore,
    ) -> None:
        """Plan R14 P2 #2 — request_id minted via
        ``_mint_request_id(_PACK_REJECT_REQUEST_ID_PREFIX)`` MUST fit
        under String(64) AND start with ``pack-reject-``."""
        record = await _seed_under_review_pack(store)
        actor = _make_actor(
            subject="alice@bank.example",
            scopes=frozenset({"pack.review.reject"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(
                f"/api/v1/packs/{record.id}/reject",
                json={
                    "reason": "documentation_incomplete",
                    "comments": "manifest fields incomplete",
                },
            )
        assert response.status_code == 200

        history = await store.load_lifecycle_history(record.id)
        reject_rows = [r for r in history if r.decision_type == "pack.lifecycle.rejected"]
        assert len(reject_rows) == 1
        request_id = reject_rows[0].request_id
        assert len(request_id) <= 64
        assert request_id.startswith("pack-reject-")

    async def test_reject_accepted_emits_evidence_log_only(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Plan R18 P2 #2 caplog table — accepted reject (green path)
        emits EXACTLY ONE ``portal.packs.review.reject`` record
        carrying reason + comments + actor_subject + pack_id (the
        operations-surface log per R11 P2 #3 + R18 P2 #2 mutually-
        exclusive emission contract). NO ``portal.packs.reject_refused``
        record fires on the green path.

        This test pins the log surface specifically.  The chain-row /
        ``payload["evidence_attachments"]`` examiner surface (added
        at T9 Slice 3 per plan §1086-1088) is pinned by
        :meth:`test_reject_chain_row_carries_evidence_attachments_post_t9`
        + :meth:`test_reject_accepted_emits_evidence_log_and_persists_post_t9`
        (dual-surface defence-in-depth)."""
        caplog.set_level(
            logging.WARNING,
            logger="cognic_agentos.portal.api.packs.review_routes",
        )
        record = await _seed_under_review_pack(store, created_by="bob@bank.example")
        actor = _make_actor(
            subject="alice@bank.example",
            scopes=frozenset({"pack.review.reject"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(
                f"/api/v1/packs/{record.id}/reject",
                json={
                    "reason": "owasp_conformance_red",
                    "comments": "OWASP gate 4 (memory poisoning) flagged",
                },
            )
        assert response.status_code == 200

        review_routes_records = [
            r for r in caplog.records if r.name == "cognic_agentos.portal.api.packs.review_routes"
        ]
        accepted = [r for r in review_routes_records if r.message == "portal.packs.review.reject"]
        refused = [r for r in review_routes_records if r.message == "portal.packs.reject_refused"]
        assert len(accepted) == 1, (
            f"expected EXACTLY ONE portal.packs.review.reject record on green path; "
            f"got {len(accepted)}"
        )
        assert len(refused) == 0, (
            f"green path MUST NOT emit portal.packs.reject_refused; got {len(refused)}"
        )

        emitted = accepted[0]
        assert emitted.reason == "owasp_conformance_red"  # type: ignore[attr-defined]
        assert emitted.comments == "OWASP gate 4 (memory poisoning) flagged"  # type: ignore[attr-defined]
        assert emitted.actor_subject == "alice@bank.example"  # type: ignore[attr-defined]
        assert emitted.pack_id == str(record.id)  # type: ignore[attr-defined]

    async def test_reject_refused_emits_refused_log_only(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Plan R18 P2 #2 caplog table — refused reject (state-machine
        refusal axis) emits EXACTLY ONE ``portal.packs.reject_refused``
        record; NO ``portal.packs.review.reject`` accepted log
        (mutually-exclusive events per R18 P2 #2)."""
        caplog.set_level(
            logging.WARNING,
            logger="cognic_agentos.portal.api.packs.review_routes",
        )
        # Submitted (not yet claimed) → reject is illegal state-pair
        record = await _seed_submitted_pack(store, created_by="bob@bank.example")
        actor = _make_actor(
            subject="alice@bank.example",
            scopes=frozenset({"pack.review.reject"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(
                f"/api/v1/packs/{record.id}/reject",
                json={
                    "reason": "signature_invalid",
                    "comments": "diagnostic",
                },
            )
        assert response.status_code == 409

        review_routes_records = [
            r for r in caplog.records if r.name == "cognic_agentos.portal.api.packs.review_routes"
        ]
        accepted = [r for r in review_routes_records if r.message == "portal.packs.review.reject"]
        refused = [r for r in review_routes_records if r.message == "portal.packs.reject_refused"]
        assert len(refused) == 1
        assert len(accepted) == 0, (
            "refused path MUST NOT emit the accepted-evidence log "
            "(mutually-exclusive events per R18 P2 #2)"
        )

        emitted = refused[0]
        assert emitted.reason == "lifecycle_transition_invalid_state_pair"  # type: ignore[attr-defined]
        assert emitted.from_state == "submitted"  # type: ignore[attr-defined]

    async def test_reject_chain_row_carries_evidence_attachments_post_t9(
        self,
        store: PackRecordStore,
    ) -> None:
        """Sprint 7B.2 T9 Slice 3 — the reject chain row's
        ``payload["evidence_attachments"]`` carries the categorised
        ``rejection_reason`` + ``reviewer_comments`` after T9 amends
        the handler via the third ``transition()`` kwarg per plan
        §1086-1088 + Round 11 P2 #3.

        **T5 → T9 history (renamed from the original
        ``test_reject_chain_row_does_not_carry_evidence_attachments_in_t5``):**
        T5 shipped the bare reject transition + emitted the categorised
        reason + comments via the ``portal.packs.review.reject``
        structured log ONLY (chain row carried just the bare transition
        payload — ``pack_id`` / ``kind`` / ``from_state`` / ``to_state``
        / ``transition_name`` / ``evidence_pointer`` / ``iso_controls``).
        T9 Slice 3 migrates the categorised pair to the chain row via
        ``evidence_attachments={"rejection_reason": body.reason,
        "reviewer_comments": body.comments}``; the chain payload becomes
        the authoritative examiner surface, while the structured log
        stays as the operations surface (defence-in-depth dual
        emission, per the user-locked Slice 3 contract).

        The dedicated dual-surface log + chain regression lives in
        :meth:`test_reject_accepted_emits_evidence_log_and_persists_post_t9`
        below; this test pins the chain-payload shape specifically."""
        record = await _seed_under_review_pack(store, created_by="bob@bank.example")
        actor = _make_actor(
            subject="alice@bank.example",
            scopes=frozenset({"pack.review.reject"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(
                f"/api/v1/packs/{record.id}/reject",
                json={
                    "reason": "data_governance_unfit",
                    "comments": "PII purpose mismatch",
                },
            )
        assert response.status_code == 200

        history = await store.load_lifecycle_history(record.id)
        reject_rows = [r for r in history if r.decision_type == "pack.lifecycle.rejected"]
        assert len(reject_rows) == 1
        payload = reject_rows[0].payload

        # T9 contract: evidence_attachments key carries exactly the
        # categorised pair per plan §1086-1088.
        assert "evidence_attachments" in payload, (
            "T9-extended reject chain row MUST carry evidence_attachments; "
            "structured log remains as the ops surface, but the chain row "
            "is the authoritative examiner surface"
        )
        assert payload["evidence_attachments"] == {
            "rejection_reason": "data_governance_unfit",
            "reviewer_comments": "PII purpose mismatch",
        }
        # Closed-set keys — storage stays a thin passthrough but the
        # route MUST emit exactly {rejection_reason, reviewer_comments};
        # any added top-level key here is a route-side contract drift.
        assert set(payload["evidence_attachments"].keys()) == {
            "rejection_reason",
            "reviewer_comments",
        }
        # T5 still emits the log; the chain row gains the new key. The
        # categorised pair MUST NOT be promoted to a top-level key on
        # payload itself — only nested inside evidence_attachments.
        assert "rejection_reason" not in payload
        assert "reviewer_comments" not in payload

    async def test_reject_accepted_emits_evidence_log_and_persists_post_t9(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Sprint 7B.2 T9 Slice 3 dual-surface contract — the
        categorised reject pair lands on BOTH the structured log
        (operations surface, T5 carry-forward) AND the chain payload
        (examiner surface, new at T9).  Defence-in-depth: a future
        change that drops one surface fails this test."""
        import logging

        record = await _seed_under_review_pack(store, created_by="bob@bank.example")
        actor = _make_actor(
            subject="alice@bank.example",
            scopes=frozenset({"pack.review.reject"}),
        )
        app = _build_app(actor=actor, store=store)

        with (
            caplog.at_level(
                logging.WARNING,
                logger="cognic_agentos.portal.api.packs.review_routes",
            ),
            TestClient(app) as client,
        ):
            response = client.post(
                f"/api/v1/packs/{record.id}/reject",
                json={
                    "reason": "signature_invalid",
                    "comments": "cosign signature missing",
                },
            )
        assert response.status_code == 200

        # (1) Ops surface — exactly 1 portal.packs.review.reject log
        review_records = [r for r in caplog.records if r.message == "portal.packs.review.reject"]
        assert len(review_records) == 1
        log_record = review_records[0]
        assert log_record.reason == "signature_invalid"  # type: ignore[attr-defined]
        assert log_record.comments == "cosign signature missing"  # type: ignore[attr-defined]

        # (2) Examiner surface — chain row payload.evidence_attachments
        history = await store.load_lifecycle_history(record.id)
        reject_rows = [r for r in history if r.decision_type == "pack.lifecycle.rejected"]
        assert len(reject_rows) == 1
        assert reject_rows[0].payload["evidence_attachments"] == {
            "rejection_reason": "signature_invalid",
            "reviewer_comments": "cosign signature missing",
        }

    async def test_reject_state_machine_refusal_emits_exactly_one_refused_log_post_t9(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """T9 caplog parity carry-forward — state-machine refusal path
        (LifecycleTransitionRefused from an invalid-state submission)
        still emits EXACTLY ONE ``portal.packs.reject_refused`` log per
        R18 P2 #2 mutually-exclusive emission.  No
        ``portal.packs.review.reject`` accepted log fires on the
        refusal path.  T9's evidence-attachments threading does NOT
        change the refusal-axis log emission shape."""
        import logging

        # Seed a SUBMITTED pack (not under_review) — reject from this
        # state triggers lifecycle_transition_invalid_state_pair.
        record = await _seed_submitted_pack(store, created_by="bob@bank.example")
        actor = _make_actor(
            subject="alice@bank.example",
            scopes=frozenset({"pack.review.reject"}),
        )
        app = _build_app(actor=actor, store=store)

        with (
            caplog.at_level(
                logging.WARNING,
                logger="cognic_agentos.portal.api.packs.review_routes",
            ),
            TestClient(app) as client,
        ):
            response = client.post(
                f"/api/v1/packs/{record.id}/reject",
                json={
                    "reason": "evaluation_pass_rate_below_threshold",
                    "comments": "out of vocab; from submitted state",
                },
            )
        assert response.status_code == 409

        refused = [r for r in caplog.records if r.message == "portal.packs.reject_refused"]
        accepted = [r for r in caplog.records if r.message == "portal.packs.review.reject"]
        assert len(refused) == 1, (
            f"expected EXACTLY ONE portal.packs.reject_refused on state-machine "
            f"refusal; got {len(refused)}; records={refused!r}"
        )
        assert len(accepted) == 0, (
            f"refusal axis MUST NOT emit portal.packs.review.reject; got {len(accepted)}"
        )

    async def test_reject_rbac_or_tenant_refusal_emits_zero_route_level_logs_post_t9(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """T9 caplog parity carry-forward — sibling-gate refusals
        (RBAC / tenant-isolation) refuse at the dep chain BEFORE the
        handler body runs, so the route-level
        ``portal.packs.review.reject`` and ``portal.packs.reject_refused``
        log records MUST both fire ZERO times.  RBAC/tenant gates emit
        their OWN logs (``portal.rbac.*`` / ``portal.tenant_isolation.*``)
        — the route handler logs are mutually exclusive with those."""
        import logging

        record = await _seed_under_review_pack(store, created_by="bob@bank.example")
        # Cross-tenant actor — tenant-isolation gate refuses before
        # the handler body runs.
        actor = _make_actor(
            subject="alice@otherbank.example",
            tenant_id="t2",
            scopes=frozenset({"pack.review.reject"}),
        )
        app = _build_app(actor=actor, store=store)

        with (
            caplog.at_level(
                logging.WARNING,
                logger="cognic_agentos.portal.api.packs.review_routes",
            ),
            TestClient(app) as client,
        ):
            response = client.post(
                f"/api/v1/packs/{record.id}/reject",
                json={"reason": "evaluation_pass_rate_below_threshold", "comments": "x"},
            )
        assert response.status_code == 404

        # Route-level handler logs MUST be ZERO on sibling-gate refusal.
        review_records = [
            r
            for r in caplog.records
            if r.message in {"portal.packs.review.reject", "portal.packs.reject_refused"}
        ]
        assert len(review_records) == 0, (
            f"sibling-gate (RBAC/tenant) refusal MUST NOT emit route-level "
            f"reject logs; got {len(review_records)}; records={review_records!r}"
        )

    async def test_reject_request_id_reuses_t5_prefix_no_new_t9_prefix(
        self,
        store: PackRecordStore,
    ) -> None:
        """Sprint 7B.2 T9 user-locked carry-forward — the T9 amendment
        REUSES the T5-owned ``_PACK_REJECT_REQUEST_ID_PREFIX``
        (``"pack-reject-"``) for the reject handler's request_id;
        T9 introduces NO new prefix per plan §1177 + Round 14 P2 #2.

        Pin via the chain row's persisted request_id — must start with
        ``"pack-reject-"`` AND fit the 64-char column cap."""
        from sqlalchemy import select

        from cognic_agentos.core.decision_history import _decision_history

        record = await _seed_under_review_pack(store, created_by="bob@bank.example")
        actor = _make_actor(
            subject="alice@bank.example",
            scopes=frozenset({"pack.review.reject"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(
                f"/api/v1/packs/{record.id}/reject",
                json={
                    "reason": "evaluation_pass_rate_below_threshold",
                    "comments": "T9 prefix-reuse regression",
                },
            )
        assert response.status_code == 200, response.text

        async with store._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(_decision_history.c.request_id)
                    .where(_decision_history.c.event_type == "pack.lifecycle.rejected")
                    .order_by(_decision_history.c.sequence.desc())
                )
            ).first()
        assert row is not None
        request_id = row.request_id
        assert len(request_id) <= 64, (
            f"request_id={request_id!r} is {len(request_id)} chars > 64 cap"
        )
        assert request_id.startswith("pack-reject-"), (
            f"request_id={request_id!r} missing 'pack-reject-' prefix — "
            f"T9 must reuse the T5-owned prefix, not introduce a new one"
        )


# ===========================================================================
# Slice 2d — GET /api/v1/packs/review-queue handler behavior
# (Plan §T5 endpoint table row 1 + R2 P3 #8 + R11 P2 #1 + R12 P2 #1)
# ===========================================================================


class TestSprint7B2ReviewQueueEndpoint:
    """``GET /api/v1/packs/review-queue`` — reviewer queue scoped to
    ``actor.tenant_id``.

    Plan R2 P3 #8 — gated by ``pack.review.claim`` (NOT examiner-facing
    ``pack.audit.read`` which would lock reviewers out).

    Plan R11 P2 #1 + R12 P2 #1 — handler calls
    ``store.list_by_status("submitted", tenant_id=actor.tenant_id,
    limit=..., cursor=...)`` so the tenant filter applies SERVER-SIDE
    (via the ``ix_packs_tenant_state`` composite index per migration
    L129). No per-pack ``RequireTenantOwnership`` dependency because
    there is no ``{pack_id}`` path param — the storage WHERE clause IS
    the authoritative tenant boundary.

    Plan R12 P2 #1 — path is ``/api/v1/packs/review-queue`` (distinct
    from ADR-012 §62's sketch ``?status=submitted`` query param that
    would have collided with T7's ``GET /api/v1/packs``).
    """

    async def test_review_queue_returns_submitted_packs_in_actor_tenant(
        self,
        store: PackRecordStore,
    ) -> None:
        """Happy path — actor with ``pack.review.claim`` in tenant t1
        sees submitted packs in t1."""
        rec_a = await _seed_submitted_pack(store, tenant_id="t1", created_by="bob@bank.example")
        rec_b = await _seed_submitted_pack(store, tenant_id="t1", created_by="bob@bank.example")
        actor = _make_actor(
            subject="alice@bank.example",
            tenant_id="t1",
            scopes=frozenset({"pack.review.claim"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get("/api/v1/packs/review-queue")

        assert response.status_code == 200, response.text
        body = response.json()
        assert isinstance(body, list)
        returned_ids = {item["id"] for item in body}
        assert returned_ids == {str(rec_a.id), str(rec_b.id)}
        # Each item is a PackResponse — no digest fields surfaced.
        for item in body:
            assert "manifest_digest" not in item
            assert "signed_artefact_digest" not in item

    async def test_review_queue_filters_by_tenant_id(
        self,
        store: PackRecordStore,
    ) -> None:
        """Plan R11 P2 #1 — reviewer queue MUST return ONLY rows
        whose ``tenant_id`` matches ``actor.tenant_id``. Cross-tenant
        rows in ``submitted`` state stay hidden (server-side
        ``list_by_status(..., tenant_id=...)`` filter is authoritative;
        no in-handler filtering)."""
        rec_t1 = await _seed_submitted_pack(store, tenant_id="t1")
        rec_t2 = await _seed_submitted_pack(store, tenant_id="t2")  # other tenant
        actor = _make_actor(
            subject="alice@bank.example",
            tenant_id="t1",
            scopes=frozenset({"pack.review.claim"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get("/api/v1/packs/review-queue")

        assert response.status_code == 200
        returned_ids = {item["id"] for item in response.json()}
        assert returned_ids == {str(rec_t1.id)}
        assert str(rec_t2.id) not in returned_ids, (
            "cross-tenant row leaked into the reviewer queue — "
            "server-side WHERE clause must be the authoritative tenant filter"
        )

    async def test_review_queue_refuses_when_scope_missing(
        self,
        store: PackRecordStore,
    ) -> None:
        """Plan R2 P3 #8 — actor without ``pack.review.claim`` scope
        → 403 ``scope_not_held``. The reviewer queue is reviewer-
        facing (NOT examiner ``pack.audit.read``)."""
        actor = _make_actor(subject="alice@bank.example", scopes=frozenset())
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get("/api/v1/packs/review-queue")

        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "scope_not_held"

    async def test_review_queue_excludes_non_submitted_states(
        self,
        store: PackRecordStore,
    ) -> None:
        """Only ``submitted``-state packs appear in the queue. Draft +
        approved + under-review packs (etc.) are NOT in the reviewer
        queue (they live in operator / inspection surfaces)."""
        submitted = await _seed_submitted_pack(store, tenant_id="t1")
        draft = await _seed_draft_pack(store, tenant_id="t1")
        under_review = await _seed_under_review_pack(store, tenant_id="t1")
        actor = _make_actor(
            subject="alice@bank.example",
            tenant_id="t1",
            scopes=frozenset({"pack.review.claim"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get("/api/v1/packs/review-queue")

        assert response.status_code == 200
        returned_ids = {item["id"] for item in response.json()}
        assert returned_ids == {str(submitted.id)}
        assert str(draft.id) not in returned_ids
        assert str(under_review.id) not in returned_ids

    async def test_review_queue_returns_empty_list_when_no_submitted_packs(
        self,
        store: PackRecordStore,
    ) -> None:
        """Empty queue → empty JSON list (NOT 404). Confirms the
        endpoint returns ``[]`` cleanly when no submitted packs exist
        in the actor's tenant."""
        # No seeded packs.
        actor = _make_actor(
            subject="alice@bank.example",
            tenant_id="t1",
            scopes=frozenset({"pack.review.claim"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get("/api/v1/packs/review-queue")

        assert response.status_code == 200
        assert response.json() == []

    async def test_review_queue_returns_500_when_actor_tenant_id_missing(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Plan R23 P2 #1 — route-level ``actor_tenant_id_missing``
        preflight guard. The review-queue endpoint bypasses
        ``RequireTenantOwnership`` (no ``{pack_id}`` path-param) which
        means it ALSO bypasses the existing 500
        ``actor_tenant_id_missing`` emission at
        ``tenant_isolation.py:144-152``. An actor with empty
        ``tenant_id`` + scope held would otherwise receive 200 [] —
        silently hiding a kernel binder misconfig that path-param
        endpoints fail-loud-500 on. Mirrors the T7 inspection-list
        preflight pattern (plan R20 P2 #2 + R21 P2 #1 type-corrected).

        Type-correctness (R21 P2 #1): ``Actor.tenant_id`` is typed
        ``str`` (not ``str | None``) so the only reachable falsy case
        under live Pydantic validation is the empty string. The
        ``_emit_isolation_log(pack_id: str)`` helper requires ``str``;
        the handler passes the sentinel ``"<review-queue>"``.
        """
        caplog.set_level(
            logging.WARNING,
            logger="cognic_agentos.portal.rbac.tenant_isolation",
        )
        actor = _make_actor(
            subject="alice@bank.example",
            tenant_id="",  # empty string; constructible under live Actor schema
            scopes=frozenset({"pack.review.claim"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get("/api/v1/packs/review-queue")

        assert response.status_code == 500, response.text
        assert response.json() == {"detail": {"reason": "actor_tenant_id_missing"}}

        # Structured-log emission on the tenant-isolation logger
        isolation_records = [
            r for r in caplog.records if r.name == "cognic_agentos.portal.rbac.tenant_isolation"
        ]
        assert len(isolation_records) == 1, (
            f"expected exactly one tenant-isolation log record on the "
            f"actor_tenant_id_missing route-level preflight; got {len(isolation_records)}"
        )
        emitted = isolation_records[0]
        assert emitted.reason == "actor_tenant_id_missing"  # type: ignore[attr-defined]
        assert emitted.actor_subject == "alice@bank.example"  # type: ignore[attr-defined]
        # Sentinel pack_id per R21 P2 #1 — keeps the log-aggregator
        # bucket discoverable AND satisfies the helper's `pack_id: str`
        # type contract (no None pack_id slips through).
        assert emitted.pack_id == "<review-queue>"  # type: ignore[attr-defined]


# ===========================================================================
# Slice 2e — GET /api/v1/packs/{pack_id}/evidence handler behavior
# (Plan §T5 endpoint table row 5 + R11 P3 #5 + T5 caveat)
# ===========================================================================


class TestSprint7B2EvidenceEndpoint:
    """``GET /api/v1/packs/{pack_id}/evidence`` — read the conformance
    evidence attached by T9's auto-run-on-submit wire (read from the
    most-recent submit chain row's ``payload.conformance``).

    Plan R11 P3 #5 response shape — :class:`PackEvidenceResponse`:
    ``{conformance: dict[str, Any] | None, reviewer_evidence_panels: None}``.

    Sprint 7B.2 T9 Slice 2 wired auto-run-on-submit, so submit chain
    rows produced from T9 onward carry the OWASP conformance suite
    result under ``payload.conformance``.  Pre-T9 / historical submit
    chain rows (fixtures or rows created by the T5-era submit handler
    before T9 Slice 2 landed) have no ``conformance`` key — both
    shapes coexist via the same response schema, with ``None``
    surfaced for the no-key path (NOT 500).  Both pre-T9 (null) and
    post-T9 (populated) paths are pinned here.  ``reviewer_evidence_panels``
    remains always-null in 7B.2; 7B.3 fills it with the 5-gate
    evidence-panel object.
    """

    async def test_evidence_returns_null_for_historical_pre_t9_row(
        self,
        store: PackRecordStore,
    ) -> None:
        """Plan R11 P3 #5 — submitted pack with no conformance key on
        its submit chain row (historical / pre-T9 shape) → endpoint
        returns ``{"conformance": null, "reviewer_evidence_panels":
        null}``.

        Sprint 7B.2 T9 Slice 2 wired auto-run-on-submit so T9-era
        submits DO carry ``payload.conformance``; this test pins the
        historical-compatibility path where the chain row was created
        before T9 (or by a fixture that bypasses the route handler).
        The endpoint MUST handle the no-key case gracefully (NOT
        500) so production chain rows from both eras read uniformly."""
        record = await _seed_submitted_pack(store, created_by="bob@bank.example")
        actor = _make_actor(
            subject="alice@bank.example",
            scopes=frozenset({"pack.audit.read"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get(f"/api/v1/packs/{record.id}/evidence")

        assert response.status_code == 200, response.text
        body = response.json()
        assert body == {"conformance": None, "reviewer_evidence_panels": None}

    def test_evidence_surfaces_payload_conformance_post_t9_fixture(self) -> None:
        """T9-era submit chain rows carry a top-level
        ``conformance: dict[str, Any]`` key on the ``payload`` (Sprint
        7B.2 T9 Slice 2 wired auto-run-on-submit per
        :func:`run_owasp_conformance_for_chain_payload`).  This test
        exercises the evidence endpoint's READ-PATH logic against a
        hand-built T9-era chain row via a stub store — a focused
        read-path fixture isolated from the submit handler's write
        path (the dual-surface integration is pinned by
        ``test_submit_writes_payload_conformance_to_chain_row`` in
        ``test_author_routes.py``; this test pins only the evidence
        endpoint's read-side dict-surfacing).

        Stub-store shape: ``load_lifecycle_history`` returns a list
        with ONE :class:`DecisionRecord` whose ``payload`` carries the
        T9-era ``conformance`` key.
        """
        from cognic_agentos.core.decision_history import DecisionRecord

        pack_id = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        post_t9_conformance = {
            "status": "green",
            "checks": [
                {"category": "owasp_a01_broken_access_control", "result": "pass"},
                {"category": "owasp_a02_cryptographic_failures", "result": "pass"},
            ],
        }
        submit_row = DecisionRecord(
            decision_type="pack.lifecycle.submitted",
            request_id="submit-fixture-row",
            payload={
                "pack_id": str(pack_id),
                "kind": "tool",
                "from_state": "draft",
                "to_state": "submitted",
                "transition_name": "submit",
                "evidence_pointer": None,
                "iso_controls": ["A.5.31"],
                "conformance": post_t9_conformance,  # T9 forward-looking key
            },
            actor_id="bob@bank.example",
            tenant_id="t1",
            iso_controls=("A.5.31",),
        )
        record = PackRecord(
            id=pack_id,
            kind="tool",
            pack_id="cognic-tool-fixture",
            display_name="Fixture",
            state="submitted",
            manifest_digest=b"\x01" * 32,
            signed_artefact_digest=b"\x02" * 32,
            sbom_pointer=None,
            tenant_id="t1",
            created_by="bob@bank.example",
            last_actor="bob@bank.example",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        class _T9FixtureStore:
            """Stub store whose ``load_lifecycle_history`` returns the
            hand-built post-T9-schema chain row. The ``load`` method
            returns the pack record so :func:`RequireTenantOwnership`
            preload succeeds."""

            async def load(self, _pack_id: uuid.UUID) -> PackRecord | None:
                return record if _pack_id == record.id else None

            async def load_lifecycle_history(self, _pack_id: uuid.UUID) -> list[DecisionRecord]:
                return [submit_row] if _pack_id == record.id else []

        stub_store: PackRecordStore = _T9FixtureStore()  # type: ignore[assignment]
        actor = _make_actor(
            subject="alice@bank.example",
            scopes=frozenset({"pack.audit.read"}),
        )
        app = _build_app(actor=actor, store=stub_store)

        with TestClient(app) as client:
            response = client.get(f"/api/v1/packs/{record.id}/evidence")

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["conformance"] == post_t9_conformance
        assert body["reviewer_evidence_panels"] is None

    async def test_evidence_refuses_when_scope_missing(
        self,
        store: PackRecordStore,
    ) -> None:
        """Actor without ``pack.audit.read`` scope → 403
        ``scope_not_held``."""
        record = await _seed_submitted_pack(store)
        actor = _make_actor(subject="alice@bank.example", scopes=frozenset())
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get(f"/api/v1/packs/{record.id}/evidence")

        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "scope_not_held"

    async def test_evidence_refuses_cross_tenant_with_404(
        self,
        store: PackRecordStore,
    ) -> None:
        """Cross-tenant actor → 404 ``tenant_id_mismatch``."""
        record = await _seed_submitted_pack(store, tenant_id="t2")
        actor = _make_actor(
            subject="alice@bank.example",
            tenant_id="t1",
            scopes=frozenset({"pack.audit.read"}),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.get(f"/api/v1/packs/{record.id}/evidence")

        assert response.status_code == 404
        assert response.json()["detail"]["reason"] == "tenant_id_mismatch"

    async def test_evidence_returns_null_when_no_submit_row_in_history(
        self,
        store: PackRecordStore,
    ) -> None:
        """A pack with NO submit chain row in its lifecycle history
        (e.g. a pack that's somehow in ``submitted`` state without a
        recorded submit transition — exercises the defensive ``None``
        path of the handler's row-finder). Returns null conformance
        gracefully (NOT 500)."""
        # Use a stub store that returns a submitted pack record but
        # an EMPTY lifecycle history.
        pack_id = uuid.UUID("cccccccc-dddd-eeee-ffff-000000000000")
        record = PackRecord(
            id=pack_id,
            kind="tool",
            pack_id="cognic-tool-no-history",
            display_name="No-History Pack",
            state="submitted",
            manifest_digest=b"\x01" * 32,
            signed_artefact_digest=b"\x02" * 32,
            sbom_pointer=None,
            tenant_id="t1",
            created_by="bob@bank.example",
            last_actor="bob@bank.example",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        class _EmptyHistoryStore:
            async def load(self, _pack_id: uuid.UUID) -> PackRecord | None:
                return record if _pack_id == record.id else None

            async def load_lifecycle_history(self, _pack_id: uuid.UUID) -> list[Any]:
                return []

        stub_store: PackRecordStore = _EmptyHistoryStore()  # type: ignore[assignment]
        actor = _make_actor(
            subject="alice@bank.example",
            scopes=frozenset({"pack.audit.read"}),
        )
        app = _build_app(actor=actor, store=stub_store)

        with TestClient(app) as client:
            response = client.get(f"/api/v1/packs/{record.id}/evidence")

        assert response.status_code == 200
        body = response.json()
        assert body == {"conformance": None, "reviewer_evidence_panels": None}

    def test_evidence_skips_newer_non_submit_rows_and_returns_submit_conformance(
        self,
    ) -> None:
        """Plan R23 P2 #2 branch-coverage closer — the evidence loop
        iterates the lifecycle history in reverse looking for the
        most-recent ``pack.lifecycle.submitted`` row. If a NEWER
        non-submit row (e.g. ``pack.lifecycle.under_review`` from a
        claim transition) sits between the submit row and the tail
        of the history, the loop MUST skip past it and continue
        scanning to find the submit row.

        Without this test the "skip + continue" branch at the
        ``if row.decision_type == "pack.lifecycle.submitted"``
        condition is not exercised — the existing tests all either
        find the submit row on the first iteration (single-row
        history) OR fail to find one (empty history). This pins the
        intermediate "iterate past a non-submit row" branch.
        """
        from cognic_agentos.core.decision_history import DecisionRecord

        pack_id = uuid.UUID("11111111-2222-3333-4444-555555555555")
        post_t9_conformance = {"status": "green", "checks": []}
        # History order: submit row FIRST (older, sequence-asc), then
        # a non-submit row (newer). Iterating reversed produces the
        # non-submit row FIRST (which must be skipped), then the
        # submit row (which provides the conformance).
        submit_row = DecisionRecord(
            decision_type="pack.lifecycle.submitted",
            request_id="submit-fixture-newer",
            payload={
                "pack_id": str(pack_id),
                "kind": "tool",
                "from_state": "draft",
                "to_state": "submitted",
                "transition_name": "submit",
                "evidence_pointer": None,
                "iso_controls": ["A.5.31"],
                "conformance": post_t9_conformance,
            },
            actor_id="bob@bank.example",
            tenant_id="t1",
            iso_controls=("A.5.31",),
        )
        under_review_row = DecisionRecord(
            decision_type="pack.lifecycle.under_review",
            request_id="claim-fixture-newer",
            payload={
                "pack_id": str(pack_id),
                "kind": "tool",
                "from_state": "submitted",
                "to_state": "under_review",
                "transition_name": "claim",
                "evidence_pointer": None,
                "iso_controls": ["A.5.31"],
                # No conformance key on this row — it's a claim row,
                # not a submit row.
            },
            actor_id="carol@bank.example",
            tenant_id="t1",
            iso_controls=("A.5.31",),
        )
        record = PackRecord(
            id=pack_id,
            kind="tool",
            pack_id="cognic-tool-newer-claim",
            display_name="Newer-Claim Pack",
            state="under_review",
            manifest_digest=b"\x01" * 32,
            signed_artefact_digest=b"\x02" * 32,
            sbom_pointer=None,
            tenant_id="t1",
            created_by="bob@bank.example",
            last_actor="carol@bank.example",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        class _OrderedHistoryStore:
            """Returns history in sequence-asc order with a non-submit
            row newer than the submit row. The handler iterates
            reversed so the newer non-submit row is seen FIRST and
            MUST be skipped per the read-path contract."""

            async def load(self, _pack_id: uuid.UUID) -> PackRecord | None:
                return record if _pack_id == record.id else None

            async def load_lifecycle_history(self, _pack_id: uuid.UUID) -> list[DecisionRecord]:
                return [submit_row, under_review_row] if _pack_id == record.id else []

        stub_store: PackRecordStore = _OrderedHistoryStore()  # type: ignore[assignment]
        actor = _make_actor(
            subject="alice@bank.example",
            scopes=frozenset({"pack.audit.read"}),
        )
        app = _build_app(actor=actor, store=stub_store)

        with TestClient(app) as client:
            response = client.get(f"/api/v1/packs/{record.id}/evidence")

        assert response.status_code == 200, response.text
        body = response.json()
        # The non-submit row was skipped; the submit row's conformance
        # surfaced (proves the "continue past non-submit" branch).
        assert body["conformance"] == post_t9_conformance
        assert body["reviewer_evidence_panels"] is None
