"""Sprint 9.5 B4 — register / promote / retire route tests + path-
containment direct-helper tests.

CRITICAL CONTROL — covers the route module's behavioural contract +
the cosign path-containment resolver. Per the user-locked B4 reviewer
bar:

* 3 endpoints (register / promote / retire); RBAC scopes per spec
  §6.2; ``RequireModelTenantOwnership`` on promote + retire; cosign
  verification OUTSIDE the storage transaction with TOCTOU re-check
  inside; body-aware promote scope resolution; 404 + body-aware error
  rendering per the B2 wire-body collapse contract.

User-locked extra pins:

* ``promote → serving`` requires a human actor BEFORE the state
  transition fires; a service actor holding the right
  ``model.promote.serving`` scope still gets 403
  ``actor_type_must_be_human`` AND the model's lifecycle_state stays
  ``tenant_approved`` (proof the gate runs pre-transition).
* Path containment rejects every category: absolute paths /
  ``..``-segments / URI schemes / symlink escapes / wrong-tenant
  symlink crossings / non-existent + non-file targets — pinned for
  BOTH ``signed_artifact_ref`` AND ``sigstore_bundle_ref`` test
  surfaces via direct helper tests.

Standing-offer §30 invariant: ``from __future__ import annotations`` is
safe here because no FastAPI routes are defined inline with
closure-local :func:`Depends` references (tests invoke routes via
httpx only).
"""

from __future__ import annotations

import hashlib
import logging
import re
import sys
from pathlib import Path
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from cognic_agentos.models.storage import ModelRecordStore
from cognic_agentos.portal.api.models.lifecycle_routes import (
    _resolve_under_tenant_root,
)

# ──────────────────────────────────────────────────────────────────────
# Canonical register payload — shared across the route tests.
# ──────────────────────────────────────────────────────────────────────


#: The artefact_tree fixture writes ``"BUNDLE\n"`` to
#: ``<tenant>/bundle.sigstore``. Per the B4 R1 P1 evidence-integrity
#: pin, ``signature_digest`` MUST be the actual SHA-256 of those
#: bytes — otherwise ``_verify_record_signature`` refuses with the
#: ``model_promote_signature_verification_failed`` reason BEFORE
#: cosign runs. Module-level constant so the test payload + the
#: bundle-content fixture stay byte-coupled.
_BUNDLE_CONTENT = b"BUNDLE\n"
_BUNDLE_DIGEST = hashlib.sha256(_BUNDLE_CONTENT).hexdigest()


_REGISTER_PAYLOAD = {
    "model_id": "cognic-tier1-acme-v1",
    "base_model": "qwen3-8b-instruct",
    "version": "1.0.0",
    "kind": "fine_tune",
    "signature_digest": _BUNDLE_DIGEST,
    "signed_artifact_ref": "artefact.bin",
    "sigstore_bundle_ref": "bundle.sigstore",
}


# ──────────────────────────────────────────────────────────────────────
# 1. Register endpoint
# ──────────────────────────────────────────────────────────────────────


class TestRegisterEndpoint:
    """POST /api/v1/models — genesis (state=proposed)."""

    async def test_register_creates_proposed_model(self, client_register: AsyncClient) -> None:
        response = await client_register.post("/api/v1/models", json=_REGISTER_PAYLOAD)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["model_id"] == _REGISTER_PAYLOAD["model_id"]
        assert body["lifecycle_state"] == "proposed"
        # tenant_id MUST come from the actor, NEVER the body — pin the
        # server-side assignment.
        assert body["tenant_id"] == "tenant-acme"
        # last_actor populated from actor.subject.
        assert body["last_actor"] == "test-user"

    async def test_register_refused_without_scope(self, make_app: Any) -> None:
        app = make_app(scopes=frozenset())
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/api/v1/models", json=_REGISTER_PAYLOAD)
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "scope_not_held"
        assert response.json()["detail"]["required_scope"] == "model.register"

    async def test_register_duplicate_refused_409(self, client_register: AsyncClient) -> None:
        await client_register.post("/api/v1/models", json=_REGISTER_PAYLOAD)
        response = await client_register.post("/api/v1/models", json=_REGISTER_PAYLOAD)
        assert response.status_code == 409
        assert response.json()["detail"]["reason"] == "model_register_duplicate_id"

    async def test_register_extra_field_refused_422(self, client_register: AsyncClient) -> None:
        """Pydantic ``extra='forbid'`` enforcement at the wire — a
        client cannot smuggle ``tenant_id`` or ``lifecycle_state``
        through the body to bypass server-side assignment."""
        bad_payload = {**_REGISTER_PAYLOAD, "tenant_id": "tenant-attacker"}
        response = await client_register.post("/api/v1/models", json=bad_payload)
        assert response.status_code == 422


# ──────────────────────────────────────────────────────────────────────
# 2. Promote endpoint — body-aware authz + cosign gate
# ──────────────────────────────────────────────────────────────────────


class TestPromoteEndpoint:
    """POST /api/v1/models/{model_id}/promote — body-aware scope
    resolution + cosign-OUTSIDE-transaction + B2 wire-body collapse."""

    async def test_promote_unknown_model_returns_404(self, make_app: Any) -> None:
        app = make_app(scopes=frozenset({"model.promote.eval_passed"}))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/api/v1/models/no-such/promote",
                json={"target_state": "eval_passed"},
            )
        assert response.status_code == 404
        assert response.json()["detail"]["reason"] == "model_not_found"

    async def test_promote_cross_tenant_collapses_to_model_not_found(
        self,
        make_app: Any,
        client_register: AsyncClient,
    ) -> None:
        """B2 R1 wire-body-collapse pin — cross-tenant promote renders
        as ``model_not_found`` at the wire (NOT ``tenant_id_mismatch``)
        so a probe cannot distinguish from a genuinely unknown
        model."""
        await client_register.post("/api/v1/models", json=_REGISTER_PAYLOAD)
        app_other = make_app(
            tenant_id="tenant-other",
            scopes=frozenset({"model.promote.eval_passed"}),
        )
        async with AsyncClient(
            transport=ASGITransport(app=app_other), base_url="http://test"
        ) as client:
            response = await client.post(
                f"/api/v1/models/{_REGISTER_PAYLOAD['model_id']}/promote",
                json={"target_state": "eval_passed"},
            )
        assert response.status_code == 404
        assert response.json()["detail"]["reason"] == "model_not_found"

    async def test_promote_scope_resolved_body_aware(
        self, make_app: Any, client_register: AsyncClient
    ) -> None:
        """The required scope for ``/promote`` is
        ``model.promote.<target_state>`` — resolved from the body, NOT
        the URL. An actor holding ``model.promote.eval_passed`` is
        refused when trying to promote to ``serving``."""
        await client_register.post("/api/v1/models", json=_REGISTER_PAYLOAD)
        app = make_app(scopes=frozenset({"model.promote.eval_passed"}))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                f"/api/v1/models/{_REGISTER_PAYLOAD['model_id']}/promote",
                json={"target_state": "serving"},
            )
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "scope_not_held"
        assert response.json()["detail"]["required_scope"] == "model.promote.serving"

    async def test_promote_eval_passed_with_cosign_verified(
        self, make_app: Any, client_register: AsyncClient
    ) -> None:
        await client_register.post("/api/v1/models", json=_REGISTER_PAYLOAD)
        app = make_app(scopes=frozenset({"model.promote.eval_passed"}))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                f"/api/v1/models/{_REGISTER_PAYLOAD['model_id']}/promote",
                json={"target_state": "eval_passed"},
            )
        assert response.status_code == 200, response.text
        assert response.json()["lifecycle_state"] == "eval_passed"

    async def test_promote_eval_passed_refused_when_cosign_fails(
        self, make_app: Any, client_register: AsyncClient
    ) -> None:
        await client_register.post("/api/v1/models", json=_REGISTER_PAYLOAD)
        app = make_app(
            scopes=frozenset({"model.promote.eval_passed"}),
            cosign_exit_zero=False,
        )
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                f"/api/v1/models/{_REGISTER_PAYLOAD['model_id']}/promote",
                json={"target_state": "eval_passed"},
            )
        assert response.status_code == 409
        assert response.json()["detail"]["reason"] == "model_promote_signature_verification_failed"

    async def test_promote_eval_passed_refused_on_digest_mismatch(
        self,
        make_app: Any,
        client_register: AsyncClient,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """B4 R1 P1 — load-bearing evidence-integrity pin. A client
        registers with a ``signature_digest`` claim that does NOT
        match the actual SHA-256 of the bundle bytes. Cosign would
        STILL exit 0 (the stub doesn't check the claim) — but
        ``_verify_record_signature`` now recomputes the bundle hash
        + compares to the claim BEFORE running cosign + refuses on
        mismatch. The 409 carries the same closed-enum reason as a
        cosign negative verdict — wire-public single-reason
        collapse per the B2 R1 doctrine, but the internal log
        distinguishes ``signature_digest_mismatch``."""
        # Use the canonical payload structure but with a wrong
        # digest claim ("a" * 64 != sha256("BUNDLE\n")).
        bad_payload = {**_REGISTER_PAYLOAD, "signature_digest": "a" * 64}
        await client_register.post("/api/v1/models", json=bad_payload)
        app = make_app(scopes=frozenset({"model.promote.eval_passed"}))
        # cosign_exit_zero defaults to True — the stub WOULD pass
        # if it ran. The digest pre-check is what blocks.
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            with caplog.at_level(
                logging.WARNING,
                logger="cognic_agentos.portal.api.models.lifecycle_routes",
            ):
                response = await client.post(
                    f"/api/v1/models/{bad_payload['model_id']}/promote",
                    json={"target_state": "eval_passed"},
                )
        assert response.status_code == 409
        assert response.json()["detail"]["reason"] == "model_promote_signature_verification_failed"
        # Internal log distinguishes the digest-mismatch root cause
        # for ops + SIEM correlation.
        mismatch_logs = [
            r for r in caplog.records if r.getMessage() == "portal.models.signature_digest_mismatch"
        ]
        assert len(mismatch_logs) == 1
        assert mismatch_logs[0].reason == "signature_digest_mismatch"  # type: ignore[attr-defined]
        assert mismatch_logs[0].model_id == bad_payload["model_id"]  # type: ignore[attr-defined]


# ──────────────────────────────────────────────────────────────────────
# 3. Promote → serving Human-actor gate (user-locked pin #1)
# ──────────────────────────────────────────────────────────────────────


class TestPromoteServingHumanActorGate:
    """User-locked B4 pin #1 — promote → serving requires a HUMAN
    actor BEFORE the state transition fires. A service actor holding
    the right ``model.promote.serving`` scope still gets 403
    ``actor_type_must_be_human`` AND the model's ``lifecycle_state``
    stays ``tenant_approved`` (proof the gate runs pre-transition)."""

    @pytest.fixture
    async def model_at_tenant_approved(
        self, make_app: Any, client_register: AsyncClient, store: ModelRecordStore
    ) -> str:
        """Register a model + walk it through eval_passed +
        tenant_approved as a human actor. Returns the model_id."""
        await client_register.post("/api/v1/models", json=_REGISTER_PAYLOAD)
        human_app = make_app(
            scopes=frozenset(
                {
                    "model.promote.eval_passed",
                    "model.promote.tenant_approved",
                }
            )
        )
        async with AsyncClient(
            transport=ASGITransport(app=human_app), base_url="http://test"
        ) as client:
            await client.post(
                f"/api/v1/models/{_REGISTER_PAYLOAD['model_id']}/promote",
                json={"target_state": "eval_passed"},
            )
            response = await client.post(
                f"/api/v1/models/{_REGISTER_PAYLOAD['model_id']}/promote",
                json={
                    "target_state": "tenant_approved",
                    "eval_results_ref": "evalpack://run/1",
                    "adversarial_pass_rate": 0.999,
                },
            )
            assert response.status_code == 200, response.text
            assert response.json()["lifecycle_state"] == "tenant_approved"
        return str(_REGISTER_PAYLOAD["model_id"])

    async def test_service_actor_with_scope_refused_403(
        self,
        make_app: Any,
        model_at_tenant_approved: str,
    ) -> None:
        """The proof — service actor HOLDS the right scope
        (``model.promote.serving``) yet still gets 403
        ``actor_type_must_be_human``. If the human gate ran AFTER the
        transition, the reason would be different (or the test would
        see a 200). The 403 + the closed-enum reason is the proof the
        gate is positioned correctly."""
        service_app = make_app(
            scopes=frozenset({"model.promote.serving"}),
            actor_type="service",
        )
        async with AsyncClient(
            transport=ASGITransport(app=service_app), base_url="http://test"
        ) as client:
            response = await client.post(
                f"/api/v1/models/{model_at_tenant_approved}/promote",
                json={"target_state": "serving"},
            )
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "actor_type_must_be_human"

    async def test_service_actor_refusal_does_not_advance_state(
        self,
        make_app: Any,
        store: ModelRecordStore,
        model_at_tenant_approved: str,
    ) -> None:
        """LOAD-BEARING — proves the human gate runs BEFORE the
        storage transition. After the 403, the model's
        ``lifecycle_state`` MUST still be ``tenant_approved`` (NOT
        ``serving``). If the gate ran after the transition, this
        assertion fails because the row would have advanced to
        ``serving`` before the 403 emitted.

        Reads storage directly (NOT through an HTTP probe) to keep
        the proof unambiguous — a probe would re-traverse the route
        + ownership guard, mixing the state-read with the
        authorization layer."""
        service_app = make_app(
            scopes=frozenset({"model.promote.serving"}),
            actor_type="service",
        )
        async with AsyncClient(
            transport=ASGITransport(app=service_app), base_url="http://test"
        ) as client:
            response = await client.post(
                f"/api/v1/models/{model_at_tenant_approved}/promote",
                json={"target_state": "serving"},
            )
        assert response.status_code == 403
        # Direct storage read — proves the row stayed at
        # tenant_approved through the refusal path.
        record = await store.load_by_model_id(model_at_tenant_approved)
        assert record is not None
        assert record.lifecycle_state == "tenant_approved", (
            f"state advanced past tenant_approved despite 403; got {record.lifecycle_state!r}"
        )

    async def test_human_actor_succeeds(self, make_app: Any, model_at_tenant_approved: str) -> None:
        """Sibling positive — a human actor holding
        ``model.promote.serving`` DOES promote successfully (proves
        the gate refuses ONLY service actors, not all actors)."""
        human_app = make_app(
            scopes=frozenset({"model.promote.serving"}),
            actor_type="human",
        )
        async with AsyncClient(
            transport=ASGITransport(app=human_app), base_url="http://test"
        ) as client:
            response = await client.post(
                f"/api/v1/models/{model_at_tenant_approved}/promote",
                json={"target_state": "serving"},
            )
        assert response.status_code == 200, response.text
        assert response.json()["lifecycle_state"] == "serving"


# ──────────────────────────────────────────────────────────────────────
# 4. Retire endpoint — state-aware human gate
# ──────────────────────────────────────────────────────────────────────


class TestRetireEndpoint:
    """POST /api/v1/models/{model_id}/retire — human gate fires ONLY
    when current ``lifecycle_state == 'serving'`` (retiring an
    already-serving model is a customer-facing action; retiring a
    proposed/eval_passed/deprecated model is mechanical cleanup)."""

    async def test_retire_from_proposed_allows_service_actor(
        self, make_app: Any, client_register: AsyncClient
    ) -> None:
        """Service actor CAN retire a proposed-state model (pre-
        serving — no customer impact)."""
        await client_register.post("/api/v1/models", json=_REGISTER_PAYLOAD)
        service_app = make_app(
            scopes=frozenset({"model.retire"}),
            actor_type="service",
        )
        async with AsyncClient(
            transport=ASGITransport(app=service_app), base_url="http://test"
        ) as client:
            response = await client.post(f"/api/v1/models/{_REGISTER_PAYLOAD['model_id']}/retire")
        assert response.status_code == 200, response.text
        assert response.json()["lifecycle_state"] == "retired"

    async def test_retire_refused_without_scope(
        self, make_app: Any, client_register: AsyncClient
    ) -> None:
        await client_register.post("/api/v1/models", json=_REGISTER_PAYLOAD)
        app = make_app(scopes=frozenset())
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(f"/api/v1/models/{_REGISTER_PAYLOAD['model_id']}/retire")
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "scope_not_held"


# ──────────────────────────────────────────────────────────────────────
# 4b. Retire state-aware human gate (user-locked B4 R1 P2 #1 sibling)
# ──────────────────────────────────────────────────────────────────────


class TestServingRetireHumanGate:
    """User-locked B4 R1 P2 — the route implements a state-aware
    human gate at ``/retire`` (only fires when current
    ``lifecycle_state == 'serving'``), but the original test surface
    did NOT pin it. Add the symmetric negative/positive pair:
    service actor with ``model.retire`` cannot retire a serving
    model AND state stays ``serving``; human actor with the same
    scope can.
    """

    @pytest.fixture
    async def model_at_serving(
        self,
        make_app: Any,
        client_register: AsyncClient,
    ) -> str:
        """Walk the canonical model through every transition up to
        ``serving`` as a human actor (eval_passed → tenant_approved
        → serving). Returns the model_id."""
        await client_register.post("/api/v1/models", json=_REGISTER_PAYLOAD)
        human_app = make_app(
            scopes=frozenset(
                {
                    "model.promote.eval_passed",
                    "model.promote.tenant_approved",
                    "model.promote.serving",
                }
            ),
            actor_type="human",
        )
        async with AsyncClient(
            transport=ASGITransport(app=human_app), base_url="http://test"
        ) as client:
            await client.post(
                f"/api/v1/models/{_REGISTER_PAYLOAD['model_id']}/promote",
                json={"target_state": "eval_passed"},
            )
            await client.post(
                f"/api/v1/models/{_REGISTER_PAYLOAD['model_id']}/promote",
                json={
                    "target_state": "tenant_approved",
                    "eval_results_ref": "evalpack://run/1",
                    "adversarial_pass_rate": 0.999,
                },
            )
            r = await client.post(
                f"/api/v1/models/{_REGISTER_PAYLOAD['model_id']}/promote",
                json={"target_state": "serving"},
            )
            assert r.status_code == 200, r.text
            assert r.json()["lifecycle_state"] == "serving"
        return str(_REGISTER_PAYLOAD["model_id"])

    async def test_service_actor_with_retire_scope_refused_at_serving(
        self,
        make_app: Any,
        store: ModelRecordStore,
        model_at_serving: str,
    ) -> None:
        """LOAD-BEARING — service actor HOLDS ``model.retire`` scope
        yet gets 403 ``actor_type_must_be_human`` when the model is
        at ``serving``. AND the model's lifecycle_state stays
        ``serving`` (state did NOT advance to ``retired``) — proving
        the state-aware human gate runs BEFORE the storage
        transition."""
        service_app = make_app(
            scopes=frozenset({"model.retire"}),
            actor_type="service",
        )
        async with AsyncClient(
            transport=ASGITransport(app=service_app), base_url="http://test"
        ) as client:
            response = await client.post(f"/api/v1/models/{model_at_serving}/retire")
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "actor_type_must_be_human"
        # Direct storage read — proves the row stayed at serving.
        record = await store.load_by_model_id(model_at_serving)
        assert record is not None
        assert record.lifecycle_state == "serving", (
            f"state advanced past serving despite 403; got {record.lifecycle_state!r}"
        )

    async def test_human_actor_can_retire_serving_model(
        self,
        make_app: Any,
        model_at_serving: str,
    ) -> None:
        """Sibling positive — a human actor with ``model.retire``
        scope CAN retire a serving model (proves the gate refuses
        ONLY service actors at the serving state, not all retires
        of serving models)."""
        human_app = make_app(
            scopes=frozenset({"model.retire"}),
            actor_type="human",
        )
        async with AsyncClient(
            transport=ASGITransport(app=human_app), base_url="http://test"
        ) as client:
            response = await client.post(f"/api/v1/models/{model_at_serving}/retire")
        assert response.status_code == 200, response.text
        assert response.json()["lifecycle_state"] == "retired"


# ──────────────────────────────────────────────────────────────────────
# 5. Path-containment direct-helper tests (user-locked pin #2)
# ──────────────────────────────────────────────────────────────────────


class TestPathContainmentDirectHelper:
    """User-locked B4 pin #2 — pin every guard branch of
    :func:`_resolve_under_tenant_root` directly (no HTTP overhead).
    Both ``signed_artifact_ref`` AND ``sigstore_bundle_ref`` test
    surfaces flow through the SAME helper, so a single parametrize
    over (ref_kind, bad_value) proves both surfaces are protected.
    """

    @pytest.fixture
    def root(self, tmp_path: Path) -> Path:
        """A two-tenant artefact tree so cross-tenant symlink-escape
        tests have a real target outside ``tenant-acme``'s subtree."""
        root = tmp_path / "containment_root"
        acme = root / "tenant-acme"
        acme.mkdir(parents=True)
        (acme / "trust-root.pub").write_text("PUBKEY-ACME\n")
        (acme / "good.bin").write_text("OK\n")
        # A directory below the tenant root (legitimate nested file).
        nested = acme / "v1"
        nested.mkdir()
        (nested / "artefact.bin").write_text("NESTED\n")
        # A separate tenant tree to exercise wrong-tenant crossing.
        other = root / "tenant-other"
        other.mkdir()
        (other / "secret.bin").write_text("SECRET\n")
        return root

    @pytest.mark.parametrize(
        ("ref_kind",),
        [("signed_artifact_ref",), ("sigstore_bundle_ref",)],
    )
    def test_legitimate_relative_ref_resolves(self, root: Path, ref_kind: str) -> None:
        """Happy path — a relative ref inside the tenant subtree
        resolves to the expected file. Both ref kinds traverse the
        SAME helper, so this is parametrized to prove BOTH surfaces
        admit valid input."""
        resolved = _resolve_under_tenant_root(
            relative_ref="good.bin",
            tenant_id="tenant-acme",
            root=root,
        )
        assert resolved == (root / "tenant-acme" / "good.bin").resolve()
        # Sibling — nested relative ref also resolves.
        resolved_nested = _resolve_under_tenant_root(
            relative_ref="v1/artefact.bin",
            tenant_id="tenant-acme",
            root=root,
        )
        assert resolved_nested.name == "artefact.bin"
        # ref_kind is captured to make the parametrize explicit in
        # test names (artifact vs bundle surface).
        assert ref_kind in {"signed_artifact_ref", "sigstore_bundle_ref"}

    @pytest.mark.parametrize(
        "bad_ref",
        ["/etc/passwd", "/tmp/foo.bin", "/var/lib/cognic/x"],
    )
    @pytest.mark.parametrize("ref_kind", ["signed_artifact_ref", "sigstore_bundle_ref"])
    def test_absolute_paths_refused(self, root: Path, bad_ref: str, ref_kind: str) -> None:
        """Both artefact + bundle surfaces refuse absolute paths."""
        with pytest.raises(ValueError, match="absolute_path"):
            _resolve_under_tenant_root(relative_ref=bad_ref, tenant_id="tenant-acme", root=root)

    def test_empty_string_refused(self, root: Path) -> None:
        with pytest.raises(ValueError, match="absolute_path"):
            _resolve_under_tenant_root(relative_ref="", tenant_id="tenant-acme", root=root)

    @pytest.mark.parametrize(
        "bad_ref",
        [
            "s3://bucket/foo",
            "http://evil.com/payload",
            "https://attacker/x",
            "file:///etc/passwd",
        ],
    )
    def test_uri_schemes_refused(self, root: Path, bad_ref: str) -> None:
        """URI schemes (``s3://`` / ``http://`` / ``file://`` / etc.)
        refused — wave-1 is filesystem-only; object-store-backed fetch
        is a wave-2 seam (per ADR-009)."""
        with pytest.raises(ValueError) as exc_info:
            _resolve_under_tenant_root(relative_ref=bad_ref, tenant_id="tenant-acme", root=root)
        # Either uri_scheme or absolute_path is acceptable — `//` is
        # caught by the `://` check OR the absolute-path check;
        # exact branch is implementation detail.
        assert exc_info.value.args[0] in {"uri_scheme", "absolute_path"}

    @pytest.mark.parametrize(
        "bad_ref",
        [
            "../tenant-other/secret.bin",
            "../../etc/passwd",
            "v1/../../tenant-other/secret.bin",
            "..",
            "v1/..",
            "v1/../good.bin",
        ],
    )
    @pytest.mark.parametrize("ref_kind", ["signed_artifact_ref", "sigstore_bundle_ref"])
    def test_dotdot_traversal_refused(self, root: Path, bad_ref: str, ref_kind: str) -> None:
        """Any ``..`` segment is refused at the syntax check BEFORE
        resolve — defence-in-depth even if the resolved path would
        coincidentally land back inside the tenant root."""
        with pytest.raises(ValueError, match="traversal_segment"):
            _resolve_under_tenant_root(relative_ref=bad_ref, tenant_id="tenant-acme", root=root)

    @pytest.mark.skipif(sys.platform == "win32", reason="symlink semantics differ on Windows")
    @pytest.mark.parametrize("ref_kind", ["signed_artifact_ref", "sigstore_bundle_ref"])
    def test_symlink_escape_outside_root_refused(self, root: Path, ref_kind: str) -> None:
        """A symlink inside the tenant tree pointing OUTSIDE the
        artifact root entirely (e.g. to ``/etc/passwd``) is caught
        by the post-resolve ``relative_to(tenant_root)`` check —
        ``.resolve()`` follows the symlink, ``relative_to`` raises,
        helper translates to ``escapes_tenant_root``."""
        outside = root.parent / "outside.bin"
        outside.write_text("OUTSIDE\n")
        symlink = root / "tenant-acme" / "escape_link"
        symlink.symlink_to(outside)
        with pytest.raises(ValueError, match="escapes_tenant_root"):
            _resolve_under_tenant_root(
                relative_ref="escape_link",
                tenant_id="tenant-acme",
                root=root,
            )

    @pytest.mark.skipif(sys.platform == "win32", reason="symlink semantics differ on Windows")
    @pytest.mark.parametrize("ref_kind", ["signed_artifact_ref", "sigstore_bundle_ref"])
    def test_symlink_wrong_tenant_crossing_refused(self, root: Path, ref_kind: str) -> None:
        """A symlink inside ``tenant-acme`` pointing to a file under
        ``tenant-other`` is caught by the same post-resolve guard.
        Wrong-tenant crossing must be invisible regardless of the
        attack vector (direct ``..`` syntax OR symlink redirection).
        """
        symlink = root / "tenant-acme" / "cross_tenant_link"
        symlink.symlink_to(root / "tenant-other" / "secret.bin")
        with pytest.raises(ValueError, match="escapes_tenant_root"):
            _resolve_under_tenant_root(
                relative_ref="cross_tenant_link",
                tenant_id="tenant-acme",
                root=root,
            )

    def test_missing_file_refused(self, root: Path) -> None:
        with pytest.raises(ValueError, match="missing_or_not_file"):
            _resolve_under_tenant_root(
                relative_ref="nonexistent.bin",
                tenant_id="tenant-acme",
                root=root,
            )

    def test_directory_refused(self, root: Path) -> None:
        """A directory (e.g. ``v1/``) is not a file — refused."""
        with pytest.raises(ValueError, match="missing_or_not_file"):
            _resolve_under_tenant_root(
                relative_ref="v1",
                tenant_id="tenant-acme",
                root=root,
            )

    def test_guard_branches_have_distinct_reasons(self, root: Path) -> None:
        """Closed-set check — every guard raises a ValueError whose
        single-string arg is from the documented set. A future change
        that uses a free-text reason would surface here.

        7 documented reasons after B4 R1 P2 (the 5 original
        relative-ref guards + the 2 tenant_id/tenant-root guards).
        """
        documented_reasons = {
            "absolute_path",
            "uri_scheme",
            "traversal_segment",
            "escapes_tenant_root",
            "missing_or_not_file",
            "tenant_id_invalid",
            "tenant_root_escapes_root",
        }
        # Trip the relative-ref branches.
        observed: set[str] = set()
        for bad_ref in (
            "/abs/path",
            "s3://bucket/x",
            "../escape",
            "nonexistent.bin",
        ):
            try:
                _resolve_under_tenant_root(
                    relative_ref=bad_ref,
                    tenant_id="tenant-acme",
                    root=root,
                )
            except ValueError as exc:
                observed.add(exc.args[0])
        # Trip the tenant_id branches too (the closed-set is union
        # across both guard categories).
        for bad_tenant in ("..", "/abs", "with/slash"):
            try:
                _resolve_under_tenant_root(
                    relative_ref="good.bin",
                    tenant_id=bad_tenant,
                    root=root,
                )
            except ValueError as exc:
                observed.add(exc.args[0])
        assert observed <= documented_reasons, (
            f"undocumented ValueError reason(s) emitted: {observed - documented_reasons}"
        )


# ──────────────────────────────────────────────────────────────────────
# 5b. Tenant-id + tenant-root path containment (B4 R1 P2)
# ──────────────────────────────────────────────────────────────────────


class TestTenantIdAndTenantRootContainment:
    """User-locked B4 R1 P2 — defence-in-depth against malformed
    ``tenant_id`` values reaching the resolver, AND post-resolve
    containment of the tenant subtree itself.

    Without these guards, a malformed ``tenant_id`` like ``..`` or
    ``other-tenant`` (via path separator) would let
    ``(root / tenant_id).resolve()`` land outside the artifact root
    and become the trusted containment boundary for every
    subsequent ``relative_ref`` resolve. A symlinked tenant directory
    (``<root>/tenant-acme -> /etc``) would similarly poison the
    trust boundary."""

    @pytest.fixture
    def root(self, tmp_path: Path) -> Path:
        """Per-test artifact root with one legitimate tenant subtree
        + a file in it for the happy-path control test."""
        root = tmp_path / "tenant_root_containment_root"
        acme = root / "tenant-acme"
        acme.mkdir(parents=True)
        (acme / "good.bin").write_text("OK\n")
        return root

    @pytest.mark.parametrize(
        "bad_tenant_id",
        [
            "",
            ".",
            "..",
            "/abs",
            "/etc/passwd",
            "tenant/with/slash",
            "tenant\\with\\backslash",
            ".hidden",
            ".env",
            "../other-tenant",
        ],
    )
    def test_malformed_tenant_id_refused(self, root: Path, bad_tenant_id: str) -> None:
        """Tenant_id with empty / ``.`` / ``..`` / path separators /
        leading-dot all trip the ``tenant_id_invalid`` guard BEFORE
        any filesystem resolve."""
        with pytest.raises(ValueError, match="tenant_id_invalid"):
            _resolve_under_tenant_root(
                relative_ref="good.bin",
                tenant_id=bad_tenant_id,
                root=root,
            )

    def test_legitimate_tenant_id_resolves(self, root: Path) -> None:
        """Sanity — the well-formed tenant_id 'tenant-acme' still
        resolves cleanly through both guards."""
        resolved = _resolve_under_tenant_root(
            relative_ref="good.bin",
            tenant_id="tenant-acme",
            root=root,
        )
        assert resolved.name == "good.bin"

    @pytest.mark.skipif(sys.platform == "win32", reason="symlink semantics differ on Windows")
    def test_tenant_dir_symlink_escape_refused(self, tmp_path: Path) -> None:
        """A symlinked tenant directory pointing OUTSIDE the artifact
        root entirely (e.g. ``<root>/tenant-acme -> /tmp/outside``)
        trips ``tenant_root_escapes_root`` BEFORE candidate
        resolution starts. Without this guard, ``/tmp/outside``
        would become the trusted containment root for every
        ``relative_ref`` resolved through this helper call."""
        root = tmp_path / "symlink_root"
        root.mkdir()
        outside = tmp_path / "outside_root"
        outside.mkdir()
        (outside / "good.bin").write_text("OUTSIDE\n")
        # tenant-acme inside root is a symlink to outside_root.
        (root / "tenant-acme").symlink_to(outside)
        with pytest.raises(ValueError, match="tenant_root_escapes_root"):
            _resolve_under_tenant_root(
                relative_ref="good.bin",
                tenant_id="tenant-acme",
                root=root,
            )

    @pytest.mark.skipif(sys.platform == "win32", reason="symlink semantics differ on Windows")
    def test_tenant_dir_symlink_to_other_tenant_refused(self, tmp_path: Path) -> None:
        """A symlinked tenant directory pointing to ANOTHER tenant's
        subtree (cross-tenant symlink at the directory level) trips
        ``tenant_root_escapes_root`` via the ``tenant_root.name ==
        tenant_id`` invariant — the resolved canonical path of
        ``<root>/tenant-acme`` becomes ``<root>/tenant-other``,
        whose ``.name`` ("tenant-other") does NOT equal the
        tenant_id ("tenant-acme") the helper was called with.

        Without this guard, a tenant-acme actor could read
        tenant-other's files via the symlink — operator-misconfig
        that the helper must defend against regardless. Same
        closed-enum reason as the outside-root case
        (operator-discipline invariant: tenant directories are real
        directories, never symlinks)."""
        root = tmp_path / "cross_tenant_symlink_root"
        root.mkdir()
        other = root / "tenant-other"
        other.mkdir()
        (other / "secret.bin").write_text("SECRET\n")
        # tenant-acme is a symlink to tenant-other.
        (root / "tenant-acme").symlink_to(other)
        with pytest.raises(ValueError, match="tenant_root_escapes_root"):
            _resolve_under_tenant_root(
                relative_ref="secret.bin",
                tenant_id="tenant-acme",
                root=root,
            )


# ──────────────────────────────────────────────────────────────────────
# 6. Path-containment integration — bad ref reaches cosign as False
# ──────────────────────────────────────────────────────────────────────


class TestPathContainmentIntegratesWithCosignGate:
    """Pin that a malformed ref on a registered model surfaces as the
    same closed-enum ``model_promote_signature_verification_failed``
    refusal as a clean negative cosign verdict — proving the helper's
    ``ValueError`` cascade reaches the storage layer's gate via
    ``_verify_record_signature``'s False return."""

    async def test_bad_signed_artifact_ref_blocks_promote_eval_passed(
        self, make_app: Any, client_register: AsyncClient
    ) -> None:
        """Register a model with a ``..``-traversal
        ``signed_artifact_ref`` — promote_eval_passed refused with the
        same closed-enum reason as a clean cosign negative verdict."""
        payload = {**_REGISTER_PAYLOAD, "signed_artifact_ref": "../escape.bin"}
        await client_register.post("/api/v1/models", json=payload)
        app = make_app(scopes=frozenset({"model.promote.eval_passed"}))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                f"/api/v1/models/{payload['model_id']}/promote",
                json={"target_state": "eval_passed"},
            )
        assert response.status_code == 409
        assert response.json()["detail"]["reason"] == "model_promote_signature_verification_failed"

    async def test_bad_sigstore_bundle_ref_blocks_promote_eval_passed(
        self, make_app: Any, client_register: AsyncClient
    ) -> None:
        """Symmetric pin on the bundle ref — proves BOTH surfaces are
        protected (per user pin #2 "test surface should pin both
        artifact and bundle refs")."""
        payload = {**_REGISTER_PAYLOAD, "sigstore_bundle_ref": "/etc/passwd"}
        await client_register.post("/api/v1/models", json=payload)
        app = make_app(scopes=frozenset({"model.promote.eval_passed"}))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                f"/api/v1/models/{payload['model_id']}/promote",
                json={"target_state": "eval_passed"},
            )
        assert response.status_code == 409
        assert response.json()["detail"]["reason"] == "model_promote_signature_verification_failed"


# ──────────────────────────────────────────────────────────────────────
# 7. Refusal-shape pins (B2 wire-body collapse + Sprint-7B.2 contract)
# ──────────────────────────────────────────────────────────────────────


class TestRefusalShapeContract:
    """Defence-in-depth — every model-route 4xx response body conforms
    to a known shape. Drift here would break SIEM correlation."""

    @pytest.mark.parametrize(
        ("status_code", "reason_pattern"),
        [
            (403, r"^scope_not_held$"),
            (404, r"^model_not_found$"),
            # 409 closed-enum vocabulary covers the lifecycle
            # refusal reasons (registry.py ``ModelLifecycleRefusalReason``).
            # The duplicate-register reason is the only one that
            # surfaces on the register path; the parametrize triggers
            # that branch here. Promote / retire reasons are covered
            # by their own dedicated tests (cosign-failed +
            # scope-resolved-body-aware) so this regex stays narrow.
            (409, r"^model_register_duplicate_id$"),
        ],
    )
    async def test_4xx_body_always_carries_reason_key(
        self,
        status_code: int,
        reason_pattern: str,
        make_app: Any,
        client_register: AsyncClient,
    ) -> None:
        """All 4xx responses carry ``{"detail": {"reason": "..."}}``
        with the reason matching a documented closed-enum pattern."""
        if status_code == 403:
            app = make_app(scopes=frozenset())  # no scopes → scope_not_held
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.post("/api/v1/models", json=_REGISTER_PAYLOAD)
        elif status_code == 404:
            app = make_app(scopes=frozenset({"model.promote.eval_passed"}))
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.post(
                    "/api/v1/models/no-such/promote",
                    json={"target_state": "eval_passed"},
                )
        else:  # 409 duplicate
            await client_register.post("/api/v1/models", json=_REGISTER_PAYLOAD)
            response = await client_register.post("/api/v1/models", json=_REGISTER_PAYLOAD)
        assert response.status_code == status_code, response.text
        body = response.json()
        assert "detail" in body
        assert "reason" in body["detail"]
        assert re.match(reason_pattern, body["detail"]["reason"]), (
            f"reason {body['detail']['reason']!r} does not match {reason_pattern}"
        )


# ──────────────────────────────────────────────────────────────────────
# 8. Structured log emission (Wave 1 — no UIEventBroker chain)
# ──────────────────────────────────────────────────────────────────────


class TestStructuredLogEmission:
    """Wave-1 emission posture — every refusal emits one
    ``portal.models.<verb>_refused`` structured log record carrying
    the reason + actor + model_id, mirroring the B2 model_tenant_isolation
    pattern."""

    async def test_register_duplicate_emits_structured_log(
        self,
        client_register: AsyncClient,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        await client_register.post("/api/v1/models", json=_REGISTER_PAYLOAD)
        with caplog.at_level(
            logging.WARNING,
            logger="cognic_agentos.portal.api.models.lifecycle_routes",
        ):
            await client_register.post("/api/v1/models", json=_REGISTER_PAYLOAD)
        records = [r for r in caplog.records if r.getMessage() == "portal.models.register_refused"]
        assert len(records) == 1
        assert records[0].reason == "model_register_duplicate_id"  # type: ignore[attr-defined]
