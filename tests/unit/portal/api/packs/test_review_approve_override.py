"""Sprint 7B.3 T9 — ``POST /{pack_id}/approve`` ADR-012 §107 override path.

Per the plan-of-record §519-528: when the 5-gate composition is not
all-green AND the request body supplies an ``override_reason``, the
handler calls
:func:`~cognic_agentos.packs.approval_gates.evaluate_override_decision`.

- **granted** → emit the ``pack.approval_override`` chain event FIRST
  (immutable authorisation fact, R3 P2 #4), then
  ``store.transition("approve", ..., override_event_id=...)`` →
  ``portal.packs.approve_overridden`` + the updated pack.
- **refused** → 412 carrying :class:`ApproveRefusalResponse` with
  ``override_refusal_reason`` + ``portal.packs.approve_override_refused``.

**Handler-reachable refusal subset.** Of the 4
:data:`~cognic_agentos.packs.approval_gates.OverrideRefusalReason`
values, only TWO are reachable through the T9 handler —
``non_overridable_red_gate`` (a red signature gate) and
``override_scope_not_held``. The other two are unreachable by
construction: ``composition_already_all_green`` (the handler routes
every all-green composition through the green path BEFORE
``evaluate_override_decision`` — plan §517) and ``override_reason_missing``
(the handler's branch 2 catches ``body.override_reason is None`` BEFORE
``evaluate_override_decision`` is ever called). All 4 helper branches
are unit-tested in ``tests/unit/packs/test_approval_gates.py`` Slice J.

The R3 P2 #4 dangling-override audit design: if the approve transition
leg refuses AFTER the override event committed, the
``pack.approval_override`` chain row CORRECTLY survives as an orphan —
the override authorisation is itself the recorded fact.
"""

from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.core.decision_history import DecisionRecord
from cognic_agentos.packs.storage import PackNotFound, PackRecord, PackRecordStore
from tests.unit.portal.api.packs._approve_test_support import (
    StubTrustGate,
    StubTrustRootResolver,
    approve_body,
    build_app,
    default_manifest,
    make_actor,
    make_bundle,
    read_chain_rows,
    seed_submitted_pack,
    seed_under_review_pack,
)

# ``engine`` + ``store`` are conftest fixtures (tests/unit/portal/api/packs/
# conftest.py) — requested directly as test parameters, not imported.

#: An actor holding BOTH the reviewer-approve scope AND the override scope.
_OVERRIDE_SCOPES = frozenset({"pack.review.approve", "pack.override.approval_gate"})

_RED_CONFORMANCE = {"overall_status": "red", "results": {}, "summary": {}}
_GREEN_CONFORMANCE = {"overall_status": "green", "results": {}, "summary": {}}


def _records(caplog: pytest.LogCaptureFixture, message: str) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.message == message]


def _rows_of_type(history: list[DecisionRecord], decision_type: str) -> list[DecisionRecord]:
    return [r for r in history if r.decision_type == decision_type]


class TestSprint7B3T9OverrideGranted:
    """The override is granted — green signature + a blocking non-red
    gate (gates 2-3 are ``evidence_not_attached`` in 7B.3) + the
    override scope + a categorised reason."""

    async def _seed_overridable(self, store: PackRecordStore, tmp_path: object) -> PackRecord:
        # signature WILL resolve green (real bundle + StubTrustGate);
        # OWASP green; gates 2-3 evidence_not_attached → not all-green,
        # zero non-overridable red gates → overridable.
        bundle = make_bundle(tmp_path)  # type: ignore[arg-type]
        return await seed_under_review_pack(
            store,
            manifest=default_manifest(),
            signed_artefact_root=str(bundle),
            conformance=_GREEN_CONFORMANCE,
        )

    async def test_override_granted_transitions_to_approved(
        self, store: PackRecordStore, tmp_path: object
    ) -> None:
        record = await self._seed_overridable(store, tmp_path)
        app = build_app(
            actor=make_actor(scopes=_OVERRIDE_SCOPES),
            store=store,
            trust_gate=StubTrustGate(),
            trust_root_resolver=StubTrustRootResolver(),
        )
        with TestClient(app) as client:
            response = client.post(
                f"/api/v1/packs/{record.id}/approve",
                json=approve_body(override_reason="security_exception"),
            )
        assert response.status_code == 200, response.text
        assert response.json()["state"] == "approved"
        loaded = await store.load(record.id)
        assert loaded is not None and loaded.state == "approved"

    async def test_override_granted_emits_approve_overridden_log(
        self, store: PackRecordStore, tmp_path: object, caplog: pytest.LogCaptureFixture
    ) -> None:
        record = await self._seed_overridable(store, tmp_path)
        app = build_app(
            actor=make_actor(scopes=_OVERRIDE_SCOPES),
            store=store,
            trust_gate=StubTrustGate(),
            trust_root_resolver=StubTrustRootResolver(),
        )
        caplog.set_level(logging.WARNING)
        with TestClient(app) as client:
            client.post(
                f"/api/v1/packs/{record.id}/approve",
                json=approve_body(override_reason="security_exception"),
            )
        assert len(_records(caplog, "portal.packs.approve_overridden")) == 1
        # mutually exclusive with the other terminal axes
        assert _records(caplog, "portal.packs.approve_5_gate_green") == []
        assert _records(caplog, "portal.packs.approve_override_refused") == []

    async def test_override_emits_pack_approval_override_chain_event(
        self, store: PackRecordStore, engine: AsyncEngine, tmp_path: object
    ) -> None:
        record = await self._seed_overridable(store, tmp_path)
        app = build_app(
            actor=make_actor(scopes=_OVERRIDE_SCOPES),
            store=store,
            trust_gate=StubTrustGate(),
            trust_root_resolver=StubTrustRootResolver(),
        )
        with TestClient(app) as client:
            client.post(
                f"/api/v1/packs/{record.id}/approve",
                json=approve_body(override_reason="security_exception"),
            )
        # load_lifecycle_history only surfaces ``pack.lifecycle.%`` rows;
        # the ``pack.approval_override`` event needs a direct chain read.
        override_rows = await read_chain_rows(engine, event_type="pack.approval_override")
        assert len(override_rows) == 1
        payload = override_rows[0].payload
        assert payload["pack_id"] == str(record.id)
        assert payload["actor_subject"] == "alice@bank.example"
        assert payload["override_reason"] == "security_exception"
        assert payload["outcome"] == "authorized"
        # the canonical-safe gate-composition snapshot is carried
        snapshot = payload["gate_composition_snapshot"]
        assert snapshot["pack_kind"] == "tool"
        assert isinstance(snapshot["gates"], list)
        assert snapshot["all_green"] is False

    async def test_approve_chain_row_carries_override_event_id(
        self, store: PackRecordStore, engine: AsyncEngine, tmp_path: object
    ) -> None:
        record = await self._seed_overridable(store, tmp_path)
        app = build_app(
            actor=make_actor(scopes=_OVERRIDE_SCOPES),
            store=store,
            trust_gate=StubTrustGate(),
            trust_root_resolver=StubTrustRootResolver(),
        )
        with TestClient(app) as client:
            client.post(
                f"/api/v1/packs/{record.id}/approve",
                json=approve_body(override_reason="security_exception"),
            )
        override_rows = await read_chain_rows(engine, event_type="pack.approval_override")
        history = await store.load_lifecycle_history(record.id)
        approved_rows = _rows_of_type(history, "pack.lifecycle.approved")
        assert len(override_rows) == 1
        assert len(approved_rows) == 1
        # the approve chain row correlates back to the override event
        assert approved_rows[0].payload["override_event_id"] == str(override_rows[0].record_id)


class TestSprint7B3T9OverrideRefused:
    """The override is refused — the two handler-reachable
    :data:`OverrideRefusalReason` branches."""

    async def test_refused_non_overridable_red_gate_when_signature_red(
        self, store: PackRecordStore, tmp_path: object
    ) -> None:
        # trust_gate omitted → signature red → non_overridable_red_gates
        # = {"signature"} → evaluate_override_decision refuses regardless
        # of who asks (ADR-012 §110).
        bundle = make_bundle(tmp_path)  # type: ignore[arg-type]
        record = await seed_under_review_pack(
            store,
            manifest=default_manifest(),
            signed_artefact_root=str(bundle),
            conformance=_GREEN_CONFORMANCE,
        )
        app = build_app(
            actor=make_actor(scopes=_OVERRIDE_SCOPES),
            store=store,
            trust_root_resolver=StubTrustRootResolver(),
        )
        with TestClient(app) as client:
            response = client.post(
                f"/api/v1/packs/{record.id}/approve",
                json=approve_body(override_reason="security_exception"),
            )
        assert response.status_code == 412, response.text
        assert response.json()["detail"]["override_refusal_reason"] == "non_overridable_red_gate"

    async def test_refused_scope_not_held(self, store: PackRecordStore, tmp_path: object) -> None:
        # signature green, OWASP red (a blocking but OVERRIDABLE gate),
        # actor supplies an override_reason but does NOT hold the
        # pack.override.approval_gate scope → override_scope_not_held.
        bundle = make_bundle(tmp_path)  # type: ignore[arg-type]
        record = await seed_under_review_pack(
            store,
            manifest=default_manifest(),
            signed_artefact_root=str(bundle),
            conformance=_RED_CONFORMANCE,
        )
        app = build_app(
            actor=make_actor(scopes=frozenset({"pack.review.approve"})),
            store=store,
            trust_gate=StubTrustGate(),
            trust_root_resolver=StubTrustRootResolver(),
        )
        with TestClient(app) as client:
            response = client.post(
                f"/api/v1/packs/{record.id}/approve",
                json=approve_body(override_reason="security_exception"),
            )
        assert response.status_code == 412, response.text
        assert response.json()["detail"]["override_refusal_reason"] == "override_scope_not_held"

    async def test_override_refused_emits_override_refused_log(
        self, store: PackRecordStore, tmp_path: object, caplog: pytest.LogCaptureFixture
    ) -> None:
        bundle = make_bundle(tmp_path)  # type: ignore[arg-type]
        record = await seed_under_review_pack(
            store,
            manifest=default_manifest(),
            signed_artefact_root=str(bundle),
            conformance=_GREEN_CONFORMANCE,
        )
        # signature red (no trust_gate) → non_overridable_red_gate.
        app = build_app(
            actor=make_actor(scopes=_OVERRIDE_SCOPES),
            store=store,
            trust_root_resolver=StubTrustRootResolver(),
        )
        caplog.set_level(logging.WARNING)
        with TestClient(app) as client:
            client.post(
                f"/api/v1/packs/{record.id}/approve",
                json=approve_body(override_reason="security_exception"),
            )
        assert len(_records(caplog, "portal.packs.approve_override_refused")) == 1
        # no transition was attempted — no transition-refused log
        assert _records(caplog, "portal.packs.approve_transition_refused") == []

    async def test_override_refused_does_not_emit_a_chain_event(
        self, store: PackRecordStore, engine: AsyncEngine, tmp_path: object
    ) -> None:
        bundle = make_bundle(tmp_path)  # type: ignore[arg-type]
        record = await seed_under_review_pack(
            store,
            manifest=default_manifest(),
            signed_artefact_root=str(bundle),
            conformance=_GREEN_CONFORMANCE,
        )
        app = build_app(
            actor=make_actor(scopes=_OVERRIDE_SCOPES),
            store=store,
            trust_root_resolver=StubTrustRootResolver(),
        )
        with TestClient(app) as client:
            client.post(
                f"/api/v1/packs/{record.id}/approve",
                json=approve_body(override_reason="security_exception"),
            )
        # a REFUSED override emits NO pack.approval_override chain event
        # (direct chain read — load_lifecycle_history would not surface
        # the event even if it HAD been emitted, so the assertion would
        # be vacuous against that seam).
        override_rows = await read_chain_rows(engine, event_type="pack.approval_override")
        assert override_rows == []


class TestSprint7B3T9OverrideDanglingAuditDesign:
    """R3 P2 #4 — the override event is emitted FIRST as an immutable
    authorisation fact; if the approve transition leg then refuses, the
    ``pack.approval_override`` chain row CORRECTLY dangles."""

    async def test_override_event_survives_when_transition_refuses(
        self,
        store: PackRecordStore,
        engine: AsyncEngine,
        tmp_path: object,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # The pack is in ``submitted`` (NOT under_review) — the override
        # is granted (green signature, OWASP red but overridable, scope
        # held), the override event commits, then transition("approve")
        # refuses because submitted → approved is illegal.
        bundle = make_bundle(tmp_path)  # type: ignore[arg-type]
        record = await seed_submitted_pack(
            store,
            manifest=default_manifest(),
            signed_artefact_root=str(bundle),
            conformance=_RED_CONFORMANCE,
        )
        app = build_app(
            actor=make_actor(scopes=_OVERRIDE_SCOPES),
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
        assert len(_records(caplog, "portal.packs.approve_transition_refused")) == 1
        # the override event committed (separate plain-append txn) and
        # CORRECTLY dangles — direct chain read ...
        override_rows = await read_chain_rows(engine, event_type="pack.approval_override")
        assert len(override_rows) == 1
        assert override_rows[0].payload["pack_id"] == str(record.id)
        # ... but NO pack.lifecycle.approved row exists (transition rolled back)
        history = await store.load_lifecycle_history(record.id)
        assert _rows_of_type(history, "pack.lifecycle.approved") == []
        # the pack is still in ``submitted`` — not approved
        loaded = await store.load(record.id)
        assert loaded is not None and loaded.state == "submitted"

    async def test_pack_not_found_race_on_override_transition_leg(
        self,
        store: PackRecordStore,
        engine: AsyncEngine,
        tmp_path: object,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # R15 P2 #3 — the PackNotFound branch of _raise_transition_refused:
        # the pack exists at dep-chain time (RequireTenantOwnership.load
        # succeeds) but is deleted before transition()'s SELECT FOR
        # UPDATE. Simulated by monkeypatching store.transition to raise
        # PackNotFound AFTER the override event has been appended.
        bundle = make_bundle(tmp_path)  # type: ignore[arg-type]
        record = await seed_under_review_pack(
            store,
            manifest=default_manifest(),
            signed_artefact_root=str(bundle),
            conformance=_GREEN_CONFORMANCE,
        )
        app = build_app(
            actor=make_actor(scopes=_OVERRIDE_SCOPES),
            store=store,
            trust_gate=StubTrustGate(),
            trust_root_resolver=StubTrustRootResolver(),
        )

        async def _raise_pack_not_found(**_kwargs: object) -> None:
            raise PackNotFound(record.id)

        # store.load (used by RequireTenantOwnership) stays real; only
        # the transition leg is forced to race.
        monkeypatch.setattr(store, "transition", _raise_pack_not_found)
        caplog.set_level(logging.WARNING)
        with TestClient(app) as client:
            response = client.post(
                f"/api/v1/packs/{record.id}/approve",
                json=approve_body(override_reason="security_exception"),
            )
        assert response.status_code == 404, response.text
        assert response.json()["detail"]["reason"] == "pack_not_found"
        assert len(_records(caplog, "portal.packs.approve_transition_refused")) == 1
        # the override event was appended BEFORE the transition leg —
        # it committed and CORRECTLY dangles.
        override_rows = await read_chain_rows(engine, event_type="pack.approval_override")
        assert len(override_rows) == 1
