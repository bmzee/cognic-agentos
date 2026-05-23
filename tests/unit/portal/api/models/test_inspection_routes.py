"""Sprint 9.5 B5 — inspection routes: list / detail / audit.

NOT-CC at the critical-controls floor — pure-read endpoints; no
``store.transition()`` calls; no Human-only-decision enforcement; no
cosign verification. Halt-before-commit discipline applied per user
direction.

Per the user-locked B5 invariants:

1. List endpoint is tenant-scoped by ``actor.tenant_id``; NO
   client-controlled tenant filter (query param ``tenant_id=...`` is
   not honored, and the storage call uses ``actor.tenant_id`` as the
   only tenant input).
2. Detail/audit use ``RequireModelTenantOwnership`` and preserve B2's
   ``model_not_found`` wire-body collapse (cross-tenant + unknown
   indistinguishable at the wire).
3. Audit history is oldest-first AND does not leak another model's
   chain rows (per the A5 ``load_lifecycle_history`` exact-match
   filter on ``payload["model_id"]``).
4. ``create_app`` mount is additive and disabled unless all three
   required model dependencies (``actor_binder`` +
   ``model_registry_store`` + ``model_trust_gate``) are supplied.
   Partial config emits a structured warning log + the
   ``app.state.models_router_mounted`` flag reflects the decision.
5. NO ``/usage`` endpoint in B5 (deferred to Block C, which has not
   yet been authorised).

Standing-offer §30 invariant: ``from __future__ import annotations``
is safe here — the conftest fixtures and these test functions do
NOT define FastAPI routes with closure-local ``Depends`` references;
they invoke routes via httpx only.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from cognic_agentos.models.storage import ModelRecordStore

# ──────────────────────────────────────────────────────────────────────
# Shared register payload — byte-coupled to the conftest's bundle
# fixture per [[feedback_test_fixture_byte_coupling_for_crypto_claims]].
# ──────────────────────────────────────────────────────────────────────


_BUNDLE_CONTENT = b"BUNDLE\n"
_BUNDLE_DIGEST = hashlib.sha256(_BUNDLE_CONTENT).hexdigest()


def _payload(model_id: str = "m-default") -> dict[str, Any]:
    """Minimal valid register payload for the inspection-test seed
    step. Mirrors the lifecycle-test canonical payload but lets each
    test override the model_id without redefining the dict."""
    return {
        "model_id": model_id,
        "base_model": "qwen3-8b-instruct",
        "version": "1.0.0",
        "kind": "fine_tune",
        "signature_digest": _BUNDLE_DIGEST,
        "signed_artifact_ref": "artefact.bin",
        "sigstore_bundle_ref": "bundle.sigstore",
    }


# ──────────────────────────────────────────────────────────────────────
# 1. List endpoint — tenant-scoped by actor.tenant_id
# ──────────────────────────────────────────────────────────────────────


class TestInspectionListEndpoint:
    """GET ``/api/v1/models`` — tenant-scoped list (user-locked B5
    invariant #1)."""

    async def test_list_returns_only_actor_tenant_models(
        self, make_app: Callable[..., FastAPI]
    ) -> None:
        """Register two models under tenant-acme + one under
        tenant-other; assert tenant-acme's GET /models returns only
        the acme models, NOT the cross-tenant one.

        User-locked B5 invariant #1: list scope IS the actor's
        tenant_id (the storage WHERE clause is the boundary; no
        actor-side filter)."""
        # Seed two models under tenant-acme.
        acme_app = make_app(scopes=frozenset({"model.register", "model.audit.read"}))
        async with AsyncClient(
            transport=ASGITransport(app=acme_app), base_url="http://test"
        ) as client:
            await client.post("/api/v1/models", json=_payload("m-acme-1"))
            await client.post("/api/v1/models", json=_payload("m-acme-2"))
        # Seed one model under tenant-other.
        other_app = make_app(
            tenant_id="tenant-other",
            scopes=frozenset({"model.register", "model.audit.read"}),
        )
        async with AsyncClient(
            transport=ASGITransport(app=other_app), base_url="http://test"
        ) as client:
            await client.post("/api/v1/models", json=_payload("m-other-1"))
            # Read via tenant-other — must see ONLY m-other-1.
            response = await client.get("/api/v1/models")
        assert response.status_code == 200, response.text
        body = response.json()
        ids = sorted(m["model_id"] for m in body)
        assert ids == ["m-other-1"], f"tenant-other should see only its own models; got {ids!r}"

    async def test_list_for_actor_with_no_models_returns_empty(
        self, make_app: Callable[..., FastAPI]
    ) -> None:
        """A tenant with no registered models gets an empty list, NOT
        a 404 or 500."""
        app = make_app(scopes=frozenset({"model.audit.read"}))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/models")
        assert response.status_code == 200
        assert response.json() == []

    async def test_list_refused_without_scope(self, make_app: Callable[..., FastAPI]) -> None:
        app = make_app(scopes=frozenset())
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/models")
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "scope_not_held"
        assert response.json()["detail"]["required_scope"] == "model.audit.read"

    async def test_list_ignores_client_tenant_id_query_param(
        self,
        make_app: Callable[..., FastAPI],
        client_register: AsyncClient,
    ) -> None:
        """User-locked B5 invariant #1 defence-in-depth — a client
        cannot smuggle a ``tenant_id=...`` query param to cross-tenant.
        The list endpoint takes NO tenant_id parameter; FastAPI's
        Pydantic v2 default + the inspection route signature ignore
        unknown query params silently. The tenant boundary is
        ``actor.tenant_id``, NEVER the client.
        """
        # Seed under tenant-acme.
        await client_register.post("/api/v1/models", json=_payload("m-acme-x"))
        # Read from tenant-other with a smuggled tenant_id=tenant-acme.
        app_other = make_app(
            tenant_id="tenant-other",
            scopes=frozenset({"model.audit.read"}),
        )
        async with AsyncClient(
            transport=ASGITransport(app=app_other), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/models?tenant_id=tenant-acme")
        assert response.status_code == 200
        # tenant-acme's m-acme-x must NOT appear; client-supplied
        # tenant_id query param was ignored.
        ids = [m["model_id"] for m in response.json()]
        assert "m-acme-x" not in ids, (
            f"client-controlled tenant_id query param leaked cross-tenant data; got {ids!r}"
        )

    async def test_list_filters_by_state_query_param(
        self,
        make_app: Callable[..., FastAPI],
        client_register: AsyncClient,
    ) -> None:
        """Spec §6.2 + BUILD_PLAN §789 promise a ``?state=`` filter
        on the list endpoint. Register 2 models that stay at
        ``proposed`` + 1 model promoted to ``eval_passed``; assert
        ``?state=proposed`` returns 2 + ``?state=eval_passed`` returns
        1.
        """
        # Seed 2 models that stay at proposed.
        await client_register.post("/api/v1/models", json=_payload("m-prop-1"))
        await client_register.post("/api/v1/models", json=_payload("m-prop-2"))
        # Seed a third + promote it to eval_passed.
        await client_register.post("/api/v1/models", json=_payload("m-eval-1"))
        promote_app = make_app(scopes=frozenset({"model.promote.eval_passed", "model.audit.read"}))
        async with AsyncClient(
            transport=ASGITransport(app=promote_app), base_url="http://test"
        ) as client:
            r = await client.post(
                "/api/v1/models/m-eval-1/promote",
                json={"target_state": "eval_passed"},
            )
            assert r.status_code == 200, r.text
            # ?state=proposed returns the 2 proposed models only.
            r_proposed = await client.get("/api/v1/models?state=proposed")
            assert r_proposed.status_code == 200
            ids_proposed = sorted(m["model_id"] for m in r_proposed.json())
            assert ids_proposed == ["m-prop-1", "m-prop-2"], (
                f"?state=proposed should return only the 2 proposed; got {ids_proposed!r}"
            )
            # ?state=eval_passed returns the 1 promoted model only.
            r_eval = await client.get("/api/v1/models?state=eval_passed")
            assert r_eval.status_code == 200
            ids_eval = [m["model_id"] for m in r_eval.json()]
            assert ids_eval == ["m-eval-1"], (
                f"?state=eval_passed should return only the 1 promoted; got {ids_eval!r}"
            )
            # Sanity — no state filter returns ALL 3.
            r_all = await client.get("/api/v1/models")
            assert r_all.status_code == 200
            ids_all = sorted(m["model_id"] for m in r_all.json())
            assert ids_all == ["m-eval-1", "m-prop-1", "m-prop-2"]

    async def test_list_with_invalid_state_returns_422(
        self, make_app: Callable[..., FastAPI]
    ) -> None:
        """Pydantic Literal validation on the ``state`` query param
        refuses out-of-vocabulary values with 422 BEFORE the storage
        call runs. The closed-enum :data:`ModelLifecycleState` is the
        wire-protocol contract."""
        app = make_app(scopes=frozenset({"model.audit.read"}))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/models?state=banana")
        assert response.status_code == 422

    async def test_list_path_is_exactly_slashless(self, make_app: Callable[..., FastAPI]) -> None:
        """The bare list endpoint compiles to ``/api/v1/models`` (no
        trailing slash) per the pack inspection_routes precedent —
        register_model_inspection_list on the PARENT router, not a
        sub-router include. A trailing-slash regression would 307
        redirect (sub-optimal) or 404 (broken).
        """
        app = make_app(scopes=frozenset({"model.audit.read"}))
        # Inspect the compiled routes — no `/api/v1/models/` (trailing
        # slash) should appear; only the slashless form.
        compiled_paths = [r.path for r in app.routes]  # type: ignore[attr-defined]
        assert "/api/v1/models" in compiled_paths
        assert "/api/v1/models/" not in compiled_paths


# ──────────────────────────────────────────────────────────────────────
# 2. Detail endpoint — RequireModelTenantOwnership + B2 collapse
# ──────────────────────────────────────────────────────────────────────


class TestInspectionDetailEndpoint:
    """GET ``/api/v1/models/{model_id}`` — record + lifecycle history
    composition. User-locked B5 invariant #2: cross-tenant + unknown
    BOTH collapse to ``model_not_found`` at the wire."""

    async def test_detail_returns_record_and_history(
        self,
        make_app: Callable[..., FastAPI],
        client_register: AsyncClient,
    ) -> None:
        await client_register.post("/api/v1/models", json=_payload("m-detail"))
        app = make_app(scopes=frozenset({"model.audit.read"}))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/models/m-detail")
        assert response.status_code == 200, response.text
        body = response.json()
        # Composition shape: model + history.
        assert set(body.keys()) == {"model", "history"}
        assert body["model"]["model_id"] == "m-detail"
        assert body["model"]["lifecycle_state"] == "proposed"
        # Genesis emits exactly one chain row.
        assert [e["decision_type"] for e in body["history"]] == ["model.lifecycle.proposed"]

    async def test_detail_unknown_returns_404_model_not_found(
        self, make_app: Callable[..., FastAPI]
    ) -> None:
        app = make_app(scopes=frozenset({"model.audit.read"}))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/models/no-such-model")
        assert response.status_code == 404
        assert response.json()["detail"]["reason"] == "model_not_found"

    async def test_detail_cross_tenant_collapses_to_model_not_found(
        self,
        make_app: Callable[..., FastAPI],
        client_register: AsyncClient,
    ) -> None:
        """B2 R1 wire-body-collapse pin — cross-tenant detail renders
        as ``model_not_found`` at the wire (NOT ``tenant_id_mismatch``)
        so a probe cannot distinguish from a genuinely unknown model.
        """
        await client_register.post("/api/v1/models", json=_payload("m-secret"))
        app_other = make_app(
            tenant_id="tenant-other",
            scopes=frozenset({"model.audit.read"}),
        )
        async with AsyncClient(
            transport=ASGITransport(app=app_other), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/models/m-secret")
        assert response.status_code == 404
        assert response.json()["detail"]["reason"] == "model_not_found"

    async def test_detail_refused_without_scope(
        self,
        make_app: Callable[..., FastAPI],
        client_register: AsyncClient,
    ) -> None:
        await client_register.post("/api/v1/models", json=_payload("m-noscope"))
        app = make_app(scopes=frozenset())
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/models/m-noscope")
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "scope_not_held"


# ──────────────────────────────────────────────────────────────────────
# 3. Audit endpoint — oldest-first + per-model isolation
# ──────────────────────────────────────────────────────────────────────


class TestInspectionAuditEndpoint:
    """GET ``/api/v1/models/{model_id}/audit`` — user-locked B5
    invariant #3: oldest-first chain order AND no leak from sibling
    model's chain rows."""

    async def test_audit_returns_chain_events_oldest_first(
        self,
        make_app: Callable[..., FastAPI],
        client_register: AsyncClient,
    ) -> None:
        """Register a model + promote it through eval_passed; assert
        the audit history is [proposed, eval_passed] in that order
        (genesis first; oldest-first per A5 ``load_lifecycle_history``
        sequence-ASC contract)."""
        await client_register.post("/api/v1/models", json=_payload("m-audit"))
        promote_app = make_app(scopes=frozenset({"model.promote.eval_passed", "model.audit.read"}))
        async with AsyncClient(
            transport=ASGITransport(app=promote_app), base_url="http://test"
        ) as client:
            r = await client.post(
                "/api/v1/models/m-audit/promote",
                json={"target_state": "eval_passed"},
            )
            assert r.status_code == 200, r.text
            # Now read the audit chain.
            response = await client.get("/api/v1/models/m-audit/audit")
        assert response.status_code == 200
        events = response.json()
        # Two events: genesis first (oldest), then the promote.
        assert [e["decision_type"] for e in events] == [
            "model.lifecycle.proposed",
            "model.lifecycle.eval_passed",
        ], f"audit history not in oldest-first order; got {[e['decision_type'] for e in events]!r}"

    async def test_audit_isolates_to_one_model_chain(
        self,
        make_app: Callable[..., FastAPI],
        client_register: AsyncClient,
    ) -> None:
        """User-locked B5 invariant #3 (no-leak pin) — register TWO
        distinct models in the same tenant; assert GET /audit for
        ``m-alpha`` returns ONLY ``m-alpha``'s chain rows, not
        ``m-beta``'s. Mirrors the A5
        ``test_load_lifecycle_history_filters_exactly_by_model_id``
        pin but at the route layer."""
        await client_register.post("/api/v1/models", json=_payload("m-alpha"))
        await client_register.post("/api/v1/models", json=_payload("m-beta"))
        app = make_app(scopes=frozenset({"model.audit.read"}))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r_alpha = await client.get("/api/v1/models/m-alpha/audit")
            r_beta = await client.get("/api/v1/models/m-beta/audit")
        assert r_alpha.status_code == 200
        assert r_beta.status_code == 200
        # Each audit response references ONLY its own model_id in
        # every event's payload.
        for event in r_alpha.json():
            assert event["payload"]["model_id"] == "m-alpha", (
                f"alpha audit leaked an event for {event['payload']['model_id']!r}"
            )
        for event in r_beta.json():
            assert event["payload"]["model_id"] == "m-beta", (
                f"beta audit leaked an event for {event['payload']['model_id']!r}"
            )

    async def test_audit_does_not_substring_match(
        self,
        make_app: Callable[..., FastAPI],
        client_register: AsyncClient,
    ) -> None:
        """Defence pin for the A5 substring-defense at the route
        layer — register ``foo`` AND ``foo-long``; audit ``foo`` must
        not return ``foo-long``'s events (exact-match filter, NOT
        LIKE)."""
        await client_register.post("/api/v1/models", json=_payload("foo"))
        await client_register.post("/api/v1/models", json=_payload("foo-long"))
        app = make_app(scopes=frozenset({"model.audit.read"}))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/models/foo/audit")
        assert response.status_code == 200
        events = response.json()
        # Exactly 1 event (genesis), and its payload model_id is "foo".
        assert len(events) == 1
        assert events[0]["payload"]["model_id"] == "foo"

    async def test_audit_cross_tenant_collapses_to_model_not_found(
        self,
        make_app: Callable[..., FastAPI],
        client_register: AsyncClient,
    ) -> None:
        """B2 R1 wire-body-collapse pin — cross-tenant audit renders
        as ``model_not_found``."""
        await client_register.post("/api/v1/models", json=_payload("m-aud-x"))
        app_other = make_app(
            tenant_id="tenant-other",
            scopes=frozenset({"model.audit.read"}),
        )
        async with AsyncClient(
            transport=ASGITransport(app=app_other), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/models/m-aud-x/audit")
        assert response.status_code == 404
        assert response.json()["detail"]["reason"] == "model_not_found"

    async def test_audit_unknown_returns_404(self, make_app: Callable[..., FastAPI]) -> None:
        app = make_app(scopes=frozenset({"model.audit.read"}))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/models/no-such/audit")
        assert response.status_code == 404
        assert response.json()["detail"]["reason"] == "model_not_found"

    async def test_audit_refused_without_scope(
        self,
        make_app: Callable[..., FastAPI],
        client_register: AsyncClient,
    ) -> None:
        await client_register.post("/api/v1/models", json=_payload("m-aud-ns"))
        app = make_app(scopes=frozenset())
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/models/m-aud-ns/audit")
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "scope_not_held"


# ──────────────────────────────────────────────────────────────────────
# 4. B5 deliberately excludes /usage (user-locked invariant #5)
# ──────────────────────────────────────────────────────────────────────


class TestUsageEndpointDeferredToBlockC:
    """User-locked B5 invariant #5 — the ``/usage`` endpoint is
    Block C territory (Task C3 per plan). Pinning its absence at the
    router level so a regression that prematurely lands it in B5
    surfaces here."""

    async def test_usage_endpoint_not_present_in_b5(self, make_app: Callable[..., FastAPI]) -> None:
        app = make_app(scopes=frozenset({"model.audit.read"}))
        # The compiled routes MUST NOT include /api/v1/models/{id}/usage.
        compiled_paths = [r.path for r in app.routes]  # type: ignore[attr-defined]
        usage_paths = [p for p in compiled_paths if p.endswith("/usage")]
        assert usage_paths == [], (
            f"B5 must NOT register the /usage endpoint (deferred to Block C); "
            f"found: {usage_paths!r}"
        )


# ──────────────────────────────────────────────────────────────────────
# 5. create_app mount — additive + conditional + warning on partial
# ──────────────────────────────────────────────────────────────────────


class TestCreateAppMount:
    """User-locked B5 invariant #4 — ``create_app`` mounts the model
    router only when all three required deps (``actor_binder`` +
    ``model_registry_store`` + ``model_trust_gate``) are supplied.
    Partial config emits a structured warning + the
    ``app.state.models_router_mounted`` flag reflects the decision."""

    @pytest.fixture
    def all_three_deps(
        self,
        store: ModelRecordStore,
        artefact_tree: Any,
        make_cosign: Callable[[bool], Any],
    ) -> dict[str, Any]:
        """Build the three model deps + a stub actor binder."""
        from cognic_agentos.core.config import Settings
        from cognic_agentos.models.trust import ModelTrustGate
        from cognic_agentos.portal.rbac.actor import Actor

        settings = Settings(
            model_artifact_root=str(artefact_tree),
            cosign_path=str(make_cosign(True)),
        )
        trust_gate = ModelTrustGate(settings)

        class _Binder:
            def bind(self, *, request: Any) -> Actor:
                return Actor(
                    subject="x",
                    tenant_id="tenant-acme",
                    scopes=frozenset({"model.audit.read"}),
                    actor_type="human",
                )

        return {
            "settings": settings,
            "actor_binder": _Binder(),
            "model_registry_store": store,
            "model_trust_gate": trust_gate,
        }

    def test_mount_active_when_all_three_deps_supplied(
        self, all_three_deps: dict[str, Any]
    ) -> None:
        from cognic_agentos.portal.api.app import create_app

        app = create_app(**all_three_deps)
        assert app.state.models_router_mounted is True
        compiled_paths: list[str] = [
            p for r in app.routes if (p := getattr(r, "path", None)) is not None
        ]
        # The 4 model-registry routes are present:
        #   register (POST), promote (POST), retire (POST), list (GET),
        #   detail (GET), audit (GET).
        # FastAPI dedupes by (path, method); we assert the path set
        # is at minimum the list + a {model_id} pattern.
        model_paths = [p for p in compiled_paths if p.startswith("/api/v1/models")]
        assert "/api/v1/models" in model_paths
        assert any("/api/v1/models/{model_id}" in p for p in model_paths)

    def test_mount_disabled_without_model_registry_store(
        self,
        all_three_deps: dict[str, Any],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        from cognic_agentos.portal.api.app import create_app

        all_three_deps.pop("model_registry_store")
        with caplog.at_level(logging.WARNING):
            app = create_app(**all_three_deps)
        assert app.state.models_router_mounted is False
        compiled_paths: list[str] = [
            p for r in app.routes if (p := getattr(r, "path", None)) is not None
        ]
        assert not any(p.startswith("/api/v1/models") for p in compiled_paths), (
            "model routes leaked despite missing model_registry_store"
        )

    def test_mount_disabled_without_model_trust_gate(
        self,
        all_three_deps: dict[str, Any],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        from cognic_agentos.portal.api.app import create_app

        all_three_deps.pop("model_trust_gate")
        with caplog.at_level(logging.WARNING):
            app = create_app(**all_three_deps)
        assert app.state.models_router_mounted is False
        compiled_paths: list[str] = [
            p for r in app.routes if (p := getattr(r, "path", None)) is not None
        ]
        assert not any(p.startswith("/api/v1/models") for p in compiled_paths)

    def test_mount_disabled_without_actor_binder(
        self,
        all_three_deps: dict[str, Any],
    ) -> None:
        from cognic_agentos.portal.api.app import create_app

        all_three_deps.pop("actor_binder")
        app = create_app(**all_three_deps)
        assert app.state.models_router_mounted is False
        compiled_paths: list[str] = [
            p for r in app.routes if (p := getattr(r, "path", None)) is not None
        ]
        assert not any(p.startswith("/api/v1/models") for p in compiled_paths)

    def test_mount_emits_warning_log_on_partial_config(
        self,
        all_three_deps: dict[str, Any],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Partial config (one of the two model-specific deps
        supplied, the other not) MUST emit a structured warning so
        an operator-bootstrap miss is visible at startup, not
        silently no-mount."""
        from cognic_agentos.portal.api.app import create_app

        # Drop the store but keep the trust_gate — operator bootstrap
        # forgot the store.
        all_three_deps.pop("model_registry_store")
        with caplog.at_level(logging.WARNING):
            create_app(**all_three_deps)
        partial_logs = [
            r for r in caplog.records if "models_router_unmounted_partial_config" in r.getMessage()
        ]
        assert len(partial_logs) >= 1, (
            "expected at least one models_router_unmounted_partial_config "
            f"warning; got log records: "
            f"{[(r.levelname, r.getMessage()) for r in caplog.records]}"
        )

    def test_mount_silent_when_no_model_deps_supplied(
        self,
        all_three_deps: dict[str, Any],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Pack-only deployments (zero model deps) MUST NOT emit the
        partial-config warning — that warning is for the
        SOMETHING-but-not-EVERYTHING case. Pre-9.5 deployments stay
        clean."""
        from cognic_agentos.portal.api.app import create_app

        all_three_deps.pop("model_registry_store")
        all_three_deps.pop("model_trust_gate")
        with caplog.at_level(logging.WARNING):
            create_app(**all_three_deps)
        partial_logs = [
            r for r in caplog.records if "models_router_unmounted_partial_config" in r.getMessage()
        ]
        assert partial_logs == [], (
            "pack-only deployment emitted partial-config warning despite supplying zero model deps"
        )
