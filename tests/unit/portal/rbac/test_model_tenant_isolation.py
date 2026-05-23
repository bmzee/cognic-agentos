"""Sprint 9.5 B2 — :func:`RequireModelTenantOwnership` regressions.

Pins the user-locked B2 invariants:

1. mirror :func:`RequireTenantOwnership` shape but use
   :meth:`ModelRecordStore.load_by_model_id` (natural-key string, NOT UUID)
2. **cross-tenant + unknown indistinguishable at HTTP boundary** — same
   404 body shape ``{"reason": "model_not_found"}`` regardless of
   whether the row genuinely does not exist OR exists in another tenant
3. pin the closed refusal vocabulary exactly — 4-value internal
   ``ModelTenantIsolationFailure`` + 3-value wire-public
   ``ModelTenantIsolationWireReason`` (the asymmetry IS the
   wire-body-collapse contract)
4. tests cover owner-allowed / non-owner-invisible / unknown-invisible /
   missing-actor-tenant / store-returning-None (5 substantive branches +
   the wire-shape parity pin)
5. no broad RBAC refactor while touching ``portal/rbac/`` — pack
   equivalent ``RequireTenantOwnership`` is UNCHANGED by this task
   (its tests at ``test_tenant_isolation.py`` remain green; no
   regression on the pack wire contract)
6. structured-log-only Wave-1 emission — no ``UIEventBroker`` chain row

The wire-shape parity pin (cross-tenant 404 body == unknown 404 body)
is the load-bearing test for invariant #2 — a regression that re-leaks
``tenant_id_mismatch`` to the wire would surface here.

Standing-offer §30 invariant — ``from __future__ import annotations`` is
INTENTIONALLY OMITTED. The fixture's probe route ``_probe`` is defined
INSIDE the ``_build`` closure factory and its ``record:
Annotated[ModelRecord, Depends(dep)]`` annotation references ``dep`` as
a closure-local. PEP 563 string-deferred annotations would break
FastAPI's ``inspect.signature()`` / ``typing.get_type_hints()``
resolution on the closure-local ``dep`` (no module-global to resolve
against), surfacing as a 422 ``Unprocessable Entity`` (FastAPI falls
back to treating the param as a query string). Matches the pack-route
operator_routes.py / inspection_routes.py omission per the AGENTS.md
"Authoring — Portal pack API (Sprint 7B.2)" entry.
"""

import logging
import uuid
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, get_args

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.models.storage import ModelRecord, ModelRecordStore
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.model_tenant_isolation import (
    ModelTenantIsolationFailure,
    ModelTenantIsolationWireReason,
    RequireModelTenantOwnership,
)

# ──────────────────────────────────────────────────────────────────────
# Closed-enum vocabulary pins
# ──────────────────────────────────────────────────────────────────────


class TestModelTenantIsolationVocabulary:
    """The 4-value internal categorization + 3-value wire-public
    asymmetry IS the cross-tenant invisibility contract. Drift in
    either Literal is a wire-protocol break."""

    def test_failure_literal_has_exactly_four_pinned_values(self) -> None:
        assert set(get_args(ModelTenantIsolationFailure)) == {
            "model_not_found",
            "tenant_id_mismatch",
            "actor_tenant_id_missing",
            "model_store_not_configured",
        }

    def test_wire_reason_literal_has_exactly_three_pinned_values(self) -> None:
        """``tenant_id_mismatch`` is DELIBERATELY ABSENT from the
        wire-public set — it collapses to ``model_not_found`` at the
        wire per the cross-tenant invisibility rule."""
        assert set(get_args(ModelTenantIsolationWireReason)) == {
            "model_not_found",
            "actor_tenant_id_missing",
            "model_store_not_configured",
        }

    def test_wire_reason_is_strict_subset_of_failure(self) -> None:
        """Every wire-public reason MUST appear in the internal
        categorization vocabulary (wire is a projection of internal,
        not a parallel ontology)."""
        assert set(get_args(ModelTenantIsolationWireReason)) < set(
            get_args(ModelTenantIsolationFailure)
        )

    def test_tenant_id_mismatch_only_in_internal_vocab(self) -> None:
        """The asymmetry IS the contract — ``tenant_id_mismatch``
        appears ONLY in the internal log vocabulary, NEVER on the wire.
        Pinned explicitly so a future regression that adds it to the
        wire-public Literal trips this test BEFORE the change reaches
        a deployed wire response."""
        assert "tenant_id_mismatch" in get_args(ModelTenantIsolationFailure)
        assert "tenant_id_mismatch" not in get_args(ModelTenantIsolationWireReason)


# ──────────────────────────────────────────────────────────────────────
# Test fixtures — minimal FastAPI app + ModelRecordStore + stub binder
# ──────────────────────────────────────────────────────────────────────


def _make_record(model_id: str, tenant_id: str = "tenant-a") -> ModelRecord:
    """Minimal :class:`ModelRecord` for B2 tests. Per
    :file:`AGENTS.md` test-fixture-placement rule, lives in the test
    module — no production-path fixture."""
    now = datetime.now(UTC)
    return ModelRecord(
        id=uuid.uuid4(),
        model_id=model_id,
        tenant_id=tenant_id,
        base_model="cognic/foundation-12b",
        version="1.0.0",
        kind="foundation",
        recipe_hash=None,
        training_data_fingerprint=None,
        eval_results_ref=None,
        adversarial_pass_rate=None,
        signature_digest=None,
        signed_artifact_ref=None,
        sigstore_bundle_ref=None,
        serving_endpoint=None,
        lifecycle_state="proposed",
        last_actor="forge-bot",
        created_at=now,
        updated_at=now,
    )


class _StubBinder:
    """Test-only binder that returns a fixed Actor (matches the
    SYNC ``ActorBinder.bind`` Protocol contract)."""

    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Any) -> Actor:
        return self._actor


@pytest.fixture
async def store_and_app_factory(
    tmp_path: Path,
) -> AsyncIterator[tuple[ModelRecordStore, Callable[..., FastAPI]]]:
    """Per-test sqlite engine + ModelRecordStore + factory that builds
    a minimal FastAPI app with the RequireModelTenantOwnership dep on
    a probe route at ``GET /m/{model_id}`` — returns ``{"model_id":
    ..., "tenant_id": ...}`` on success so tests can assert the
    happy-path payload as well as the refusal bodies.

    The factory takes ``actor`` (bound by ``_StubBinder``) and an
    optional ``store_override`` so the ``model_store_not_configured``
    test can pass ``store_override=None`` to simulate a route mounted
    without a wired store.
    """
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'b2.db'}")
    async with eng.begin() as conn:
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
    store = ModelRecordStore(eng)

    def _build(
        actor: Actor,
        *,
        store_override: ModelRecordStore | None | object = _UNSET,
    ) -> FastAPI:
        app = FastAPI()
        # Default = wire the real store; pass store_override=None to
        # simulate the model_store_not_configured kernel-misconfig
        # branch (a route mounted with a binder but no store).
        app.state.model_registry_store = store if store_override is _UNSET else store_override
        app.state.actor_binder = _StubBinder(actor)
        dep = RequireModelTenantOwnership(model_id_param="model_id")

        @app.get("/m/{model_id}")
        async def _probe(
            record: Annotated[ModelRecord, Depends(dep)],
        ) -> dict[str, str]:
            return {"model_id": record.model_id, "tenant_id": record.tenant_id}

        return app

    yield store, _build
    await eng.dispose()


#: Sentinel for the ``store_override`` kwarg — distinguishes "not
#: provided" (use the default real store) from "explicitly None"
#: (simulate the kernel-misconfig branch).
_UNSET: Any = object()


# ──────────────────────────────────────────────────────────────────────
# Substantive branch tests — 5 paths + wire-shape parity pin
# ──────────────────────────────────────────────────────────────────────


class TestSameTenantOwnerAllowed:
    """Happy path — owner reads their own model."""

    async def test_same_tenant_returns_200_with_record(
        self,
        store_and_app_factory: tuple[ModelRecordStore, Callable[..., FastAPI]],
    ) -> None:
        store, build = store_and_app_factory
        rec = _make_record("m-mine", tenant_id="tenant-a")
        await store.register(rec, request_id="r1", actor_id="forge-bot", actor_type="service")
        owner = Actor(
            subject="alice",
            tenant_id="tenant-a",
            scopes=frozenset(),
            actor_type="human",
        )
        async with AsyncClient(
            transport=ASGITransport(app=build(owner)), base_url="http://test"
        ) as client:
            response = await client.get("/m/m-mine")
        assert response.status_code == 200
        assert response.json() == {"model_id": "m-mine", "tenant_id": "tenant-a"}


class TestCrossTenantInvisibleAtWire:
    """User-locked B2 invariant #2 — non-owner sees the same wire
    shape as an unknown model. The wire-body collapse is the
    load-bearing pin."""

    async def test_cross_tenant_returns_404_with_model_not_found_body(
        self,
        store_and_app_factory: tuple[ModelRecordStore, Callable[..., FastAPI]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        store, build = store_and_app_factory
        # Seed a model owned by tenant-a.
        rec = _make_record("m-secret", tenant_id="tenant-a")
        await store.register(rec, request_id="r1", actor_id="forge-bot", actor_type="service")
        # Request from tenant-b — must look identical to "no such model".
        intruder = Actor(
            subject="bob-cross-tenant",
            tenant_id="tenant-b",
            scopes=frozenset(),
            actor_type="human",
        )
        async with AsyncClient(
            transport=ASGITransport(app=build(intruder)), base_url="http://test"
        ) as client:
            with caplog.at_level(
                logging.WARNING,
                logger="cognic_agentos.portal.rbac.model_tenant_isolation",
            ):
                response = await client.get("/m/m-secret")
        # Wire body collapses to model_not_found — NOT tenant_id_mismatch.
        assert response.status_code == 404
        body = response.json()
        assert body == {"detail": {"reason": "model_not_found"}}, (
            f"cross-tenant access leaked tenant_id_mismatch to the wire; got {body!r}"
        )
        # Internal log retains tenant_id_mismatch for ops visibility.
        cross_tenant_log = [
            r for r in caplog.records if r.getMessage() == "portal.models.tenant_id_mismatch"
        ]
        assert len(cross_tenant_log) == 1
        assert cross_tenant_log[0].reason == "tenant_id_mismatch"  # type: ignore[attr-defined]
        assert cross_tenant_log[0].actor_subject == "bob-cross-tenant"  # type: ignore[attr-defined]
        assert cross_tenant_log[0].actor_tenant == "tenant-b"  # type: ignore[attr-defined]
        assert cross_tenant_log[0].model_id == "m-secret"  # type: ignore[attr-defined]


class TestUnknownModelInvisibleAtWire:
    """User-locked B2 invariant #2 — unknown model returns the
    canonical 404 body. Same shape as cross-tenant (pinned together
    in :class:`TestWireShapeParityPin` below)."""

    async def test_unknown_model_returns_404_with_model_not_found_body(
        self,
        store_and_app_factory: tuple[ModelRecordStore, Callable[..., FastAPI]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        _store, build = store_and_app_factory
        owner = Actor(
            subject="alice",
            tenant_id="tenant-a",
            scopes=frozenset(),
            actor_type="human",
        )
        async with AsyncClient(
            transport=ASGITransport(app=build(owner)), base_url="http://test"
        ) as client:
            with caplog.at_level(
                logging.WARNING,
                logger="cognic_agentos.portal.rbac.model_tenant_isolation",
            ):
                response = await client.get("/m/no-such-model")
        assert response.status_code == 404
        assert response.json() == {"detail": {"reason": "model_not_found"}}
        # Internal log: model_not_found (not tenant_id_mismatch).
        unknown_log = [
            r for r in caplog.records if r.getMessage() == "portal.models.model_not_found"
        ]
        assert len(unknown_log) == 1


class TestWireShapeParityPin:
    """**User-locked B2 invariant #2 load-bearing pin.** Cross-tenant
    and unknown-model responses MUST be byte-identical at the HTTP
    wire — a probe reading just the response (status + body) cannot
    distinguish "model exists in another tenant" from "no such model".
    """

    async def test_cross_tenant_and_unknown_produce_identical_wire_response(
        self,
        store_and_app_factory: tuple[ModelRecordStore, Callable[..., FastAPI]],
    ) -> None:
        store, build = store_and_app_factory
        # Seed a model in tenant-a that we will probe from tenant-b.
        rec = _make_record("m-real", tenant_id="tenant-a")
        await store.register(rec, request_id="r1", actor_id="forge-bot", actor_type="service")
        intruder = Actor(
            subject="bob",
            tenant_id="tenant-b",
            scopes=frozenset(),
            actor_type="human",
        )
        async with AsyncClient(
            transport=ASGITransport(app=build(intruder)), base_url="http://test"
        ) as client:
            cross_tenant_response = await client.get("/m/m-real")
            unknown_response = await client.get("/m/no-such-model")
        # Byte-for-byte identical wire response.
        assert cross_tenant_response.status_code == unknown_response.status_code == 404
        assert cross_tenant_response.json() == unknown_response.json(), (
            f"cross-tenant and unknown responses differ at the wire — "
            f"cross-tenant={cross_tenant_response.json()!r}, "
            f"unknown={unknown_response.json()!r}"
        )


class TestActorTenantIdMissing:
    """User-locked B2 invariant #4 — missing actor tenant is a 500
    with the closed-enum reason (kernel-misconfig, NOT a client error)."""

    async def test_empty_actor_tenant_id_returns_500(
        self,
        store_and_app_factory: tuple[ModelRecordStore, Callable[..., FastAPI]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        store, build = store_and_app_factory
        # Seed a model so the dep gets past the lookup path.
        rec = _make_record("m-target", tenant_id="tenant-a")
        await store.register(rec, request_id="r1", actor_id="forge-bot", actor_type="service")
        unbound = Actor(
            subject="alice",
            tenant_id="",  # only Pydantic-reachable falsy case
            scopes=frozenset(),
            actor_type="human",
        )
        async with AsyncClient(
            transport=ASGITransport(app=build(unbound)), base_url="http://test"
        ) as client:
            with caplog.at_level(
                logging.WARNING,
                logger="cognic_agentos.portal.rbac.model_tenant_isolation",
            ):
                response = await client.get("/m/m-target")
        assert response.status_code == 500
        assert response.json() == {"detail": {"reason": "actor_tenant_id_missing"}}
        assert any(
            r.getMessage() == "portal.models.actor_tenant_id_missing" for r in caplog.records
        )


class TestModelStoreNotConfigured:
    """User-locked B2 invariant #4 — "store returning None" = the
    ``app.state.model_registry_store`` attribute is None (kernel
    misconfig at app-bootstrap time). Distinct closed-enum reason so
    operators can fingerprint WHICH wiring step the overlay bootstrap
    missed — vs ``actor_binder_not_configured`` which is the binder-
    wiring miss.
    """

    async def test_store_none_returns_500_with_closed_enum_reason(
        self,
        store_and_app_factory: tuple[ModelRecordStore, Callable[..., FastAPI]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        _store, build = store_and_app_factory
        owner = Actor(
            subject="alice",
            tenant_id="tenant-a",
            scopes=frozenset(),
            actor_type="human",
        )
        # store_override=None simulates the configuration regression
        # where the actor_binder is wired but the model_registry_store
        # is not.
        app = build(owner, store_override=None)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            with caplog.at_level(
                logging.WARNING,
                logger="cognic_agentos.portal.rbac.model_tenant_isolation",
            ):
                response = await client.get("/m/m-mine")
        assert response.status_code == 500
        assert response.json() == {"detail": {"reason": "model_store_not_configured"}}
        assert any(
            r.getMessage() == "portal.models.model_store_not_configured" for r in caplog.records
        )


# ──────────────────────────────────────────────────────────────────────
# Defence-in-depth pins
# ──────────────────────────────────────────────────────────────────────


class TestKernelMisconfigGuards:
    """The ``model_id_param`` factory argument MUST match the actual
    FastAPI route's path-param name; a mismatch is a kernel routing
    bug, not a client error."""

    async def test_path_param_name_mismatch_raises_runtime_error(
        self,
        store_and_app_factory: tuple[ModelRecordStore, Callable[..., FastAPI]],
    ) -> None:
        store, _ = store_and_app_factory
        # Build an app where the dep expects ``model_id_param="model_id"``
        # but the route uses ``{wrong_name}`` — first hit triggers
        # RuntimeError inside the dependency (kernel routing bug).
        app = FastAPI()
        app.state.model_registry_store = store
        app.state.actor_binder = _StubBinder(
            Actor(
                subject="alice",
                tenant_id="tenant-a",
                scopes=frozenset(),
                actor_type="human",
            )
        )
        dep = RequireModelTenantOwnership(model_id_param="model_id")  # expects 'model_id'

        @app.get("/m/{wrong_name}")
        async def _probe(
            record: Annotated[ModelRecord, Depends(dep)],
        ) -> dict[str, str]:
            return {}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # FastAPI surfaces unhandled RuntimeError from a dep as a 500;
            # the absent client body is the test signal that we hit the
            # kernel-misconfig branch (not a client-triggerable path).
            with pytest.raises(RuntimeError, match="path-param mismatch"):
                await client.get("/m/anything")
