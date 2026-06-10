"""Sprint 7B.3 T9 — ``POST /{pack_id}/approve`` five-gate composition.

Per the plan-of-record §439-528: the approve handler replaces the T5
fail-loud 503 stub with the ADR-012 §41 five-gate composer
(:func:`~cognic_agentos.packs.approval_gates.compose_approval_gates`)
wired through pre-computed gate inputs.

This file covers the NON-override terminal axes:

- the three pre-composer 409s (``pack_not_yet_submitted`` /
  ``manifest_evidence_not_persisted`` / ``pack_kind_mismatch``);
- the gate-1 (cosign signature) resolution branches — the R15 P2 #2
  four-class ``verify_pack_signature`` except set + the resolver +
  trust-root + verifier failure mappings;
- the all-green green path (transition + ``approve_5_gate_green``);
- the not-all-green-no-override 412 (``approve_5_gate_red_no_override``);
- the R15 P2 #3 ``approve_transition_refused`` path;
- the pure gate-input builders (``_build_evaluation_gate_input`` /
  ``_build_adversarial_gate_input`` / ``_build_owasp_gate_input``).

The override path lives in ``test_review_approve_override.py``; the
factory/app wiring lives in the two ``*_trust_gate_wiring.py`` files.
"""

from __future__ import annotations

import logging
import math
from typing import Any

import pytest
from fastapi.testclient import TestClient

from cognic_agentos.packs.lifecycle import LifecycleTransitionRefused
from cognic_agentos.packs.storage import PackRecord, PackRecordStore
from cognic_agentos.portal.api.packs.review_routes import (
    _build_adversarial_gate_input,
    _build_evaluation_gate_input,
    _build_owasp_gate_input,
)
from cognic_agentos.protocol.trust_gate import (
    CosignNotInstalledError,
    CosignVerificationFailed,
    PathTraversalError,
)
from tests.unit.portal.api.packs._approve_test_support import (
    StubTrustGate,
    StubTrustRootResolver,
    approve_body,
    build_app,
    default_manifest,
    make_actor,
    make_bundle,
    seed_draft_pack,
    seed_submitted_pack,
    seed_under_review_pack,
)

# ``engine`` + ``store`` are conftest fixtures (tests/unit/portal/api/packs/
# conftest.py) — requested directly as test parameters, not imported.

_GREEN_CONFORMANCE = {
    "overall_status": "green",
    "results": {},
    "summary": {},
    "errored_categories": [],
}


def _records(caplog: pytest.LogCaptureFixture, message: str) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.message == message]


# ---------------------------------------------------------------------------
# Pre-composer 409 refusals.
# ---------------------------------------------------------------------------


class TestSprint7B3T9ApprovePreComposerRefusals:
    """The three Lifecycle / persistence boundaries the handler refuses
    BEFORE reaching the composer — all 409 + ``portal.packs.approve_refused``."""

    async def test_pack_not_yet_submitted_returns_409(self, store: PackRecordStore) -> None:
        record = await seed_draft_pack(store)
        app = build_app(actor=make_actor(), store=store)
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/approve", json=approve_body())
        assert response.status_code == 409, response.text
        assert response.json()["detail"]["reason"] == "pack_not_yet_submitted"

    async def test_manifest_evidence_not_persisted_returns_409(
        self, store: PackRecordStore
    ) -> None:
        record = await seed_under_review_pack(store, persist_manifest=False)
        app = build_app(actor=make_actor(), store=store)
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/approve", json=approve_body())
        assert response.status_code == 409, response.text
        assert response.json()["detail"]["reason"] == "manifest_evidence_not_persisted"

    async def test_pack_kind_mismatch_returns_409(self, store: PackRecordStore) -> None:
        # record.kind == "tool"; the persisted manifest declares "agent".
        record = await seed_under_review_pack(
            store, kind="tool", manifest=default_manifest(kind="agent")
        )
        app = build_app(actor=make_actor(), store=store)
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/approve", json=approve_body())
        assert response.status_code == 409, response.text
        assert response.json()["detail"]["reason"] == "pack_kind_mismatch"

    async def test_pre_composer_refusal_emits_approve_refused_log(
        self, store: PackRecordStore, caplog: pytest.LogCaptureFixture
    ) -> None:
        record = await seed_draft_pack(store)
        app = build_app(actor=make_actor(), store=store)
        caplog.set_level(logging.WARNING)
        with TestClient(app) as client:
            client.post(f"/api/v1/packs/{record.id}/approve", json=approve_body())
        assert len(_records(caplog, "portal.packs.approve_refused")) == 1


# ---------------------------------------------------------------------------
# Gate-1 (cosign signature) resolution branches.
# ---------------------------------------------------------------------------


def _signature_gate(detail: dict[str, Any]) -> dict[str, Any]:
    """Extract the gate-1 (signature) entry from a 412 refusal body."""
    return next(g for g in detail["gates"] if g["gate"] == "signature")


class TestSprint7B3T9ApproveSignatureGate:
    """The approve handler's gate-1 resolution — every failure mode maps
    to a ``red`` signature gate (binary outcome per ADR-012 §110)."""

    async def _seed_signature_ready(self, store: PackRecordStore, tmp_path: object) -> PackRecord:
        """Seed an under-review pack whose submit row carries a valid
        manifest + a real on-disk bundle + a green OWASP verdict."""
        bundle = make_bundle(tmp_path)  # type: ignore[arg-type]
        record = await seed_under_review_pack(
            store,
            manifest=default_manifest(),
            signed_artefact_root=str(bundle),
            conformance=_GREEN_CONFORMANCE,
        )
        return record

    async def test_trust_gate_none_resolves_verifier_not_configured(
        self, store: PackRecordStore, tmp_path: object
    ) -> None:
        record = await self._seed_signature_ready(store, tmp_path)
        # trust_gate omitted → None.
        app = build_app(
            actor=make_actor(),
            store=store,
            trust_root_resolver=StubTrustRootResolver(),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/approve", json=approve_body())
        assert response.status_code == 412, response.text
        gate = _signature_gate(response.json()["detail"])
        assert gate["outcome"] == "red"
        assert gate["red_reason"] == "signature_verifier_not_configured"

    async def test_trust_root_resolver_none_resolves_trust_root_not_configured(
        self, store: PackRecordStore, tmp_path: object
    ) -> None:
        record = await self._seed_signature_ready(store, tmp_path)
        app = build_app(actor=make_actor(), store=store, trust_gate=StubTrustGate())
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/approve", json=approve_body())
        assert response.status_code == 412
        gate = _signature_gate(response.json()["detail"])
        assert gate["red_reason"] == "signature_trust_root_not_configured"

    async def test_trust_root_resolver_not_implemented_resolves_trust_root_not_configured(
        self, store: PackRecordStore, tmp_path: object
    ) -> None:
        record = await self._seed_signature_ready(store, tmp_path)
        app = build_app(
            actor=make_actor(),
            store=store,
            trust_gate=StubTrustGate(),
            trust_root_resolver=StubTrustRootResolver(raises=NotImplementedError("kernel default")),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/approve", json=approve_body())
        assert response.status_code == 412
        gate = _signature_gate(response.json()["detail"])
        assert gate["red_reason"] == "signature_trust_root_not_configured"

    async def test_signed_artefact_root_missing_resolves_resolver_red_reason(
        self, store: PackRecordStore
    ) -> None:
        # No signed_artefact_root persisted on the submit row → the
        # resolver returns root_missing → that resolver red-reason
        # threads straight through (R7 P2 #1 — no translation table).
        record = await seed_under_review_pack(
            store, manifest=default_manifest(), conformance=_GREEN_CONFORMANCE
        )
        app = build_app(
            actor=make_actor(),
            store=store,
            trust_gate=StubTrustGate(),
            trust_root_resolver=StubTrustRootResolver(),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/approve", json=approve_body())
        assert response.status_code == 412
        gate = _signature_gate(response.json()["detail"])
        assert gate["red_reason"] == "signature_signed_artefact_root_not_declared_at_submit"

    async def test_bundle_path_unreachable_when_cosign_sig_file_absent(
        self, store: PackRecordStore, tmp_path: object
    ) -> None:
        # signed_artefact_root + manifest declarations exist, but the
        # cosign.sig file is NOT written to disk.
        bundle = make_bundle(tmp_path, write_sig=False)  # type: ignore[arg-type]
        record = await seed_under_review_pack(
            store,
            manifest=default_manifest(),
            signed_artefact_root=str(bundle),
            conformance=_GREEN_CONFORMANCE,
        )
        app = build_app(
            actor=make_actor(),
            store=store,
            trust_gate=StubTrustGate(),
            trust_root_resolver=StubTrustRootResolver(),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/approve", json=approve_body())
        assert response.status_code == 412
        gate = _signature_gate(response.json()["detail"])
        assert gate["red_reason"] == "signature_bundle_path_unreachable"

    async def test_cosign_verification_failed_resolves_cosign_verify_failed(
        self, store: PackRecordStore, tmp_path: object
    ) -> None:
        record = await self._seed_signature_ready(store, tmp_path)
        app = build_app(
            actor=make_actor(),
            store=store,
            trust_gate=StubTrustGate(raises=CosignVerificationFailed("non-zero cosign exit")),
            trust_root_resolver=StubTrustRootResolver(),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/approve", json=approve_body())
        assert response.status_code == 412
        gate = _signature_gate(response.json()["detail"])
        assert gate["red_reason"] == "signature_cosign_verify_failed"

    async def test_cosign_not_installed_resolves_verifier_not_configured(
        self, store: PackRecordStore, tmp_path: object
    ) -> None:
        record = await self._seed_signature_ready(store, tmp_path)
        app = build_app(
            actor=make_actor(),
            store=store,
            trust_gate=StubTrustGate(raises=CosignNotInstalledError("cosign missing")),
            trust_root_resolver=StubTrustRootResolver(),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/approve", json=approve_body())
        assert response.status_code == 412
        gate = _signature_gate(response.json()["detail"])
        assert gate["red_reason"] == "signature_verifier_not_configured"

    async def test_path_traversal_error_resolves_bundle_path_unreachable(
        self, store: PackRecordStore, tmp_path: object
    ) -> None:
        # R15 P2 #2 — PathTraversalError (resolved path outside the
        # operator-approved signature root) maps to bundle_path_unreachable.
        #
        # This ALSO pins the R16 P3 KNOWN LIMITATION: PathTraversalError
        # is raised undifferentiated for signature_path / blob_path /
        # trust_root, so a trust-root-prefix escape ALSO surfaces here as
        # bundle_path_unreachable. Distinguishing it requires touching
        # protocol/trust_gate.py — explicitly out of T9 scope (plan §114
        # + §444-447) — and is unreachable in 7B.3 (no real resolver
        # ships). Deferred to the real-resolver work; this assertion
        # makes the current conflation deliberate, not accidental.
        record = await self._seed_signature_ready(store, tmp_path)
        app = build_app(
            actor=make_actor(),
            store=store,
            trust_gate=StubTrustGate(raises=PathTraversalError("escaped signature root")),
            trust_root_resolver=StubTrustRootResolver(),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/approve", json=approve_body())
        assert response.status_code == 412
        gate = _signature_gate(response.json()["detail"])
        assert gate["red_reason"] == "signature_bundle_path_unreachable"

    async def test_value_error_resolves_attestation_missing(
        self, store: PackRecordStore, tmp_path: object
    ) -> None:
        # R15 P2 #2 — a bare ValueError (regex-invalid version reaching
        # _validate_version) maps to signature_attestation_missing.
        record = await self._seed_signature_ready(store, tmp_path)
        app = build_app(
            actor=make_actor(),
            store=store,
            trust_gate=StubTrustGate(raises=ValueError("invalid version")),
            trust_root_resolver=StubTrustRootResolver(),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/approve", json=approve_body())
        assert response.status_code == 412
        gate = _signature_gate(response.json()["detail"])
        assert gate["red_reason"] == "signature_attestation_missing"

    async def test_missing_manifest_version_resolves_attestation_missing(
        self, store: PackRecordStore, tmp_path: object
    ) -> None:
        bundle = make_bundle(tmp_path)  # type: ignore[arg-type]
        manifest = default_manifest()
        del manifest["pack"]["version"]  # author omitted [pack].version
        record = await seed_under_review_pack(
            store,
            manifest=manifest,
            signed_artefact_root=str(bundle),
            conformance=_GREEN_CONFORMANCE,
        )
        app = build_app(
            actor=make_actor(),
            store=store,
            trust_gate=StubTrustGate(),
            trust_root_resolver=StubTrustRootResolver(),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/approve", json=approve_body())
        assert response.status_code == 412
        gate = _signature_gate(response.json()["detail"])
        assert gate["red_reason"] == "signature_attestation_missing"


# ---------------------------------------------------------------------------
# Terminal axes — all-green green path + not-all-green-no-override 412.
# ---------------------------------------------------------------------------


class TestSprint7B3T9ApproveTerminalAxes:
    """The all-green green path + the not-all-green-no-override 412."""

    async def _seed_all_green_ready(self, store: PackRecordStore, tmp_path: object) -> PackRecord:
        bundle = make_bundle(tmp_path)  # type: ignore[arg-type]
        record = await seed_under_review_pack(
            store,
            manifest=default_manifest(),
            signed_artefact_root=str(bundle),
            conformance=_GREEN_CONFORMANCE,
        )
        return record

    async def _seed_genuinely_all_green(
        self, store: PackRecordStore, tmp_path: object
    ) -> PackRecord:
        """Seed a pack whose submit row makes ALL 5 gates green —
        signature (real bundle + StubTrustGate), OWASP green, AND
        gates 2-3 spliced green via the test-only evidence injection."""
        bundle = make_bundle(tmp_path)  # type: ignore[arg-type]
        return await seed_under_review_pack(
            store,
            manifest=default_manifest(),
            signed_artefact_root=str(bundle),
            conformance=_GREEN_CONFORMANCE,
            evaluation={"pass_rate": 1.0, "threshold": 0.9},
            adversarial={
                "pass_rate": 1.0,
                "high_severity_failures": 0,
                "regressions": 0,
                "regression_evaluated": False,
                "candidate_run_id": "run-13c",
                "baseline_run_id": None,
            },
        )

    async def test_evidence_not_attached_gates_block_with_412(
        self, store: PackRecordStore, tmp_path: object
    ) -> None:
        # The realistic 7B.3 state: signature + OWASP green, but gates
        # 2-3 (eval/adversarial) are evidence_not_attached because
        # nobody writes those payloads in 7B.3 (Reviewer Flag #3 (c)).
        # composition.all_green is False → 412, NO transition.
        record = await self._seed_all_green_ready(store, tmp_path)
        app = build_app(
            actor=make_actor(),
            store=store,
            trust_gate=StubTrustGate(),
            trust_root_resolver=StubTrustRootResolver(),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/approve", json=approve_body())
        assert response.status_code == 412, response.text
        detail = response.json()["detail"]
        assert detail["all_green"] is False
        assert _signature_gate(detail)["outcome"] == "green"
        # the green signature gate carries the digest as evidence_pointer
        assert _signature_gate(detail)["evidence_pointer"] == "sig-digest-deadbeefcafe"
        # pack stays under_review — no transition on the 412 path
        loaded = await store.load(record.id)
        assert loaded is not None and loaded.state == "under_review"

    async def test_genuinely_all_green_transitions_to_approved(
        self, store: PackRecordStore, tmp_path: object, caplog: pytest.LogCaptureFixture
    ) -> None:
        # All 5 gates green (gates 2-3 spliced green) → the green path:
        # store.transition("approve", ...) → 200 + approve_5_gate_green.
        record = await self._seed_genuinely_all_green(store, tmp_path)
        app = build_app(
            actor=make_actor(),
            store=store,
            trust_gate=StubTrustGate(),
            trust_root_resolver=StubTrustRootResolver(),
        )
        caplog.set_level(logging.WARNING)
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/approve", json=approve_body())
        assert response.status_code == 200, response.text
        assert response.json()["state"] == "approved"
        loaded = await store.load(record.id)
        assert loaded is not None and loaded.state == "approved"
        # exactly the green terminal-axis log — mutually exclusive
        assert len(_records(caplog, "portal.packs.approve_5_gate_green")) == 1
        assert _records(caplog, "portal.packs.approve_5_gate_red_no_override") == []
        assert _records(caplog, "portal.packs.approve_transition_refused") == []

    async def test_no_override_412_emits_red_no_override_log(
        self, store: PackRecordStore, tmp_path: object, caplog: pytest.LogCaptureFixture
    ) -> None:
        record = await self._seed_all_green_ready(store, tmp_path)
        app = build_app(
            actor=make_actor(),
            store=store,
            trust_gate=StubTrustGate(),
            trust_root_resolver=StubTrustRootResolver(),
        )
        caplog.set_level(logging.WARNING)
        with TestClient(app) as client:
            client.post(f"/api/v1/packs/{record.id}/approve", json=approve_body())
        assert len(_records(caplog, "portal.packs.approve_5_gate_red_no_override")) == 1
        assert _records(caplog, "portal.packs.approve_5_gate_green") == []

    async def test_412_body_carries_pack_kind_and_gate_composition(
        self, store: PackRecordStore, tmp_path: object
    ) -> None:
        record = await self._seed_all_green_ready(store, tmp_path)
        app = build_app(
            actor=make_actor(),
            store=store,
            trust_gate=StubTrustGate(),
            trust_root_resolver=StubTrustRootResolver(),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/approve", json=approve_body())
        detail = response.json()["detail"]
        assert detail["pack_kind"] == "tool"
        assert [g["gate"] for g in detail["gates"]] == [
            "signature",
            "evaluation",
            "adversarial",
            "owasp_conformance",
            "reviewer_acknowledgement",
        ]
        assert detail["override_refusal_reason"] is None

    async def test_owasp_red_makes_gate_4_red(
        self, store: PackRecordStore, tmp_path: object
    ) -> None:
        bundle = make_bundle(tmp_path)  # type: ignore[arg-type]
        record = await seed_under_review_pack(
            store,
            manifest=default_manifest(),
            signed_artefact_root=str(bundle),
            conformance={"overall_status": "red", "results": {}, "summary": {}},
        )
        app = build_app(
            actor=make_actor(),
            store=store,
            trust_gate=StubTrustGate(),
            trust_root_resolver=StubTrustRootResolver(),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/approve", json=approve_body())
        assert response.status_code == 412
        owasp = next(
            g for g in response.json()["detail"]["gates"] if g["gate"] == "owasp_conformance"
        )
        assert owasp["outcome"] == "red"
        assert owasp["red_reason"] == "owasp_conformance_red"

    async def test_reviewer_ack_incomplete_makes_gate_5_red(
        self, store: PackRecordStore, tmp_path: object
    ) -> None:
        record = await self._seed_all_green_ready(store, tmp_path)
        app = build_app(
            actor=make_actor(),
            store=store,
            trust_gate=StubTrustGate(),
            trust_root_resolver=StubTrustRootResolver(),
        )
        with TestClient(app) as client:
            response = client.post(
                f"/api/v1/packs/{record.id}/approve",
                # one panel left unacknowledged
                json=approve_body(conformance_acknowledged=False),
            )
        assert response.status_code == 412
        ack_gate = next(
            g for g in response.json()["detail"]["gates"] if g["gate"] == "reviewer_acknowledgement"
        )
        assert ack_gate["outcome"] == "red"
        assert ack_gate["red_reason"] == "reviewer_acknowledgement_incomplete"


# ---------------------------------------------------------------------------
# R15 P2 #3 — approve-transition leg refusal.
# ---------------------------------------------------------------------------


class TestSprint7B3T9ApproveTransitionRefused:
    """R15 P2 #3 — when the gate decision greenlights a transition but
    ``store.transition("approve", ...)`` refuses (the pack is not in
    ``under_review``), the handler translates to 409 +
    ``portal.packs.approve_transition_refused``."""

    async def test_approve_on_submitted_pack_refuses_with_409(
        self, store: PackRecordStore, tmp_path: object, caplog: pytest.LogCaptureFixture
    ) -> None:
        # The pack is in ``submitted`` (NOT claimed → not under_review).
        # It is reachable by the handler (the dep chain only needs the
        # record + a distinct reviewer). To reach the transition leg we
        # need an all-green-OR-override gate decision; here we use the
        # override path so the gate decision greenlights a transition,
        # then transition() refuses (submitted → approved is illegal).
        bundle = make_bundle(tmp_path)  # type: ignore[arg-type]
        record = await seed_submitted_pack(
            store,
            manifest=default_manifest(),
            signed_artefact_root=str(bundle),
            conformance={"overall_status": "red", "results": {}, "summary": {}},
        )
        actor = make_actor(scopes=frozenset({"pack.review.approve", "pack.override.approval_gate"}))
        app = build_app(
            actor=actor,
            store=store,
            trust_gate=StubTrustGate(),
            trust_root_resolver=StubTrustRootResolver(),
        )
        caplog.set_level(logging.WARNING)
        with TestClient(app) as client:
            response = client.post(
                f"/api/v1/packs/{record.id}/approve",
                json=approve_body(override_reason="security_exception"),
            )
        assert response.status_code == 409, response.text
        # the lifecycle state-machine closed-enum reason is surfaced
        assert "reason" in response.json()["detail"]
        assert len(_records(caplog, "portal.packs.approve_transition_refused")) == 1

    async def test_all_green_path_transition_refused_via_monkeypatch(
        self,
        store: PackRecordStore,
        tmp_path: object,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # The OTHER transition leg (R15 P2 #3): a genuinely-all-green
        # composition greenlights the all-green transition leg, then
        # ``store.transition`` refuses (a LifecycleTransitionRefused
        # race). Forced via monkeypatch since an all-green pack in a
        # non-under_review state cannot be reached through real seeding.
        bundle = make_bundle(tmp_path)  # type: ignore[arg-type]
        record = await seed_under_review_pack(
            store,
            manifest=default_manifest(),
            signed_artefact_root=str(bundle),
            conformance=_GREEN_CONFORMANCE,
            evaluation={"pass_rate": 1.0, "threshold": 0.9},
            adversarial={
                "pass_rate": 1.0,
                "high_severity_failures": 0,
                "regressions": 0,
                "regression_evaluated": False,
                "candidate_run_id": "run-13c",
                "baseline_run_id": None,
            },
        )
        app = build_app(
            actor=make_actor(),
            store=store,
            trust_gate=StubTrustGate(),
            trust_root_resolver=StubTrustRootResolver(),
        )

        async def _raise_transition_refused(**_kwargs: object) -> None:
            raise LifecycleTransitionRefused("lifecycle_transition_invalid_state_pair")

        monkeypatch.setattr(store, "transition", _raise_transition_refused)
        caplog.set_level(logging.WARNING)
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/approve", json=approve_body())
        assert response.status_code == 409, response.text
        assert response.json()["detail"]["reason"] == "lifecycle_transition_invalid_state_pair"
        assert len(_records(caplog, "portal.packs.approve_transition_refused")) == 1
        # no gate-decision log fired — the gate decision GREENLIT a
        # transition; the transition leg itself refused.
        assert _records(caplog, "portal.packs.approve_5_gate_green") == []


# ---------------------------------------------------------------------------
# Pure gate-input builders.
# ---------------------------------------------------------------------------


class TestSprint7B3T9GateInputBuilders:
    """The pure-functional gate-2/3/4 input builders."""

    def test_evaluation_missing_payload_is_evidence_not_attached(self) -> None:
        result = _build_evaluation_gate_input(None)
        assert result.outcome == "evidence_not_attached"
        assert result.red_reason == "evaluation_evidence_not_attached"

    def test_evaluation_dict_with_non_numeric_pass_rate_is_evidence_not_attached(
        self,
    ) -> None:
        # a dict present but malformed (non-numeric pass_rate) → the
        # second evidence-not-attached return, not a crash.
        result = _build_evaluation_gate_input({"pass_rate": "bad", "threshold": 0.9})
        assert result.outcome == "evidence_not_attached"
        assert result.red_reason == "evaluation_evidence_not_attached"

    def test_evaluation_below_threshold_is_red(self) -> None:
        result = _build_evaluation_gate_input({"pass_rate": 0.5, "threshold": 0.9})
        assert result.outcome == "red"
        assert result.red_reason == "evaluation_pass_rate_below_threshold"

    def test_evaluation_at_or_above_threshold_is_green(self) -> None:
        result = _build_evaluation_gate_input({"pass_rate": 0.95, "threshold": 0.9})
        assert result.outcome == "green"
        assert result.red_reason is None

    def test_adversarial_missing_payload_is_evidence_not_attached(self) -> None:
        result = _build_adversarial_gate_input(None)
        assert result.outcome == "evidence_not_attached"
        assert result.red_reason == "adversarial_evidence_not_attached"

    def test_adversarial_dict_missing_high_severity_is_evidence_not_attached(
        self,
    ) -> None:
        # a dict present but missing high_severity_failures → the second
        # evidence-not-attached return.
        result = _build_adversarial_gate_input({"pass_rate": 1.0})
        assert result.outcome == "evidence_not_attached"
        assert result.red_reason == "adversarial_evidence_not_attached"

    def test_adversarial_high_severity_failure_is_red(self) -> None:
        result = _build_adversarial_gate_input(
            {
                "pass_rate": 1.0,
                "high_severity_failures": 2,
                "regressions": 0,
                "regression_evaluated": False,
                "candidate_run_id": "run-13c",
                "baseline_run_id": None,
            }
        )
        assert result.outcome == "red"
        assert result.red_reason == "adversarial_high_severity_failure"

    def test_adversarial_low_pass_rate_is_red(self) -> None:
        result = _build_adversarial_gate_input(
            {
                "pass_rate": 0.5,
                "high_severity_failures": 0,
                "regressions": 0,
                "regression_evaluated": False,
                "candidate_run_id": "run-13c",
                "baseline_run_id": None,
            }
        )
        assert result.outcome == "red"
        assert result.red_reason == "adversarial_corpus_pass_rate_below_threshold"

    def test_adversarial_clean_corpus_is_green(self) -> None:
        result = _build_adversarial_gate_input(
            {
                "pass_rate": 1.0,
                "high_severity_failures": 0,
                "regressions": 0,
                "regression_evaluated": False,
                "candidate_run_id": "run-13c",
                "baseline_run_id": None,
            }
        )
        assert result.outcome == "green"

    def test_owasp_missing_payload_is_evidence_not_attached(self) -> None:
        result = _build_owasp_gate_input(None)
        assert result.outcome == "evidence_not_attached"
        assert result.red_reason == "owasp_evidence_not_attached"

    def test_owasp_green_is_green(self) -> None:
        result = _build_owasp_gate_input({"overall_status": "green"})
        assert result.outcome == "green"

    def test_owasp_red_is_red(self) -> None:
        result = _build_owasp_gate_input({"overall_status": "red"})
        assert result.outcome == "red"
        assert result.red_reason == "owasp_conformance_red"

    def test_owasp_yellow_blocks_approval(self) -> None:
        # R10 LOCK Flag #2 — yellow means checker incompleteness → red.
        result = _build_owasp_gate_input({"overall_status": "yellow"})
        assert result.outcome == "red"
        assert result.red_reason == "owasp_yellow_blocks_approval"


class TestSprint7B3T9GateInputBuildersFailClosed:
    """Reviewer P2 — malformed pass-rate / threshold / count evidence
    must route to ``evidence_not_attached``, NEVER ``green``.

    ``nan < x`` and ``2.0 < x`` are both ``False`` — a builder that only
    rejected non-numbers (the pre-fix ``_is_real_number``) would fall
    through the ``<`` comparison to ``green`` on a malformed persisted
    ``pass_rate``. The fixed builders require a finite ``[0.0, 1.0]``
    rate (and a non-negative high-severity count) BEFORE comparing.
    """

    @pytest.mark.parametrize(
        "bad_rate",
        [math.nan, math.inf, -math.inf, 2.0, -0.5, 1.0001],
        ids=["nan", "inf", "-inf", "2.0", "-0.5", "1.0001"],
    )
    def test_evaluation_malformed_pass_rate_is_evidence_not_attached(self, bad_rate: float) -> None:
        result = _build_evaluation_gate_input({"pass_rate": bad_rate, "threshold": 0.9})
        assert result.outcome == "evidence_not_attached"
        assert result.red_reason == "evaluation_evidence_not_attached"

    @pytest.mark.parametrize(
        "bad_threshold",
        [math.nan, math.inf, 2.0, -0.5],
        ids=["nan", "inf", "2.0", "-0.5"],
    )
    def test_evaluation_malformed_threshold_is_evidence_not_attached(
        self, bad_threshold: float
    ) -> None:
        result = _build_evaluation_gate_input({"pass_rate": 1.0, "threshold": bad_threshold})
        assert result.outcome == "evidence_not_attached"
        assert result.red_reason == "evaluation_evidence_not_attached"

    @pytest.mark.parametrize(
        "bad_rate",
        [math.nan, math.inf, -math.inf, 2.0, -0.5],
        ids=["nan", "inf", "-inf", "2.0", "-0.5"],
    )
    def test_adversarial_malformed_pass_rate_is_evidence_not_attached(
        self, bad_rate: float
    ) -> None:
        result = _build_adversarial_gate_input({"pass_rate": bad_rate, "high_severity_failures": 0})
        assert result.outcome == "evidence_not_attached"
        assert result.red_reason == "adversarial_evidence_not_attached"

    def test_adversarial_negative_high_severity_count_is_evidence_not_attached(
        self,
    ) -> None:
        result = _build_adversarial_gate_input({"pass_rate": 1.0, "high_severity_failures": -3})
        assert result.outcome == "evidence_not_attached"
        assert result.red_reason == "adversarial_evidence_not_attached"

    def test_evaluation_boundary_rates_are_accepted(self) -> None:
        # the closed interval [0.0, 1.0] — both endpoints are VALID:
        # pass_rate at its UPPER bound (1.0) + threshold at its LOWER
        # bound (0.0) must NOT be mis-rejected as out-of-range, so this
        # is green.
        result = _build_evaluation_gate_input({"pass_rate": 1.0, "threshold": 0.0})
        assert result.outcome == "green"
