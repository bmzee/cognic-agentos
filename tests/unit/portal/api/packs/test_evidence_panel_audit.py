"""Sprint 7B.3 T10 — evidence-panel route-side audit-emission integration tests.

Pins the production behaviour of the route-handler audit seam per plan
§533-566 acceptance. Each of the 4 GET evidence-panel endpoints emits
EXACTLY ONE ``pack.evidence_read.<panel_name>`` chain event per 200
response (via :meth:`PackRecordStore.append_evidence_read_event`), and
ZERO audit events on any 4xx/5xx path (the read did not happen).

Covers:

- Each of the 4 panels emits exactly 1 audit event per 200 response,
  carrying the correct ``panel_name`` / ``actor_subject`` / ``pack_id``
  + the ``tenant_id`` on the chain row's first-class column (R17 P2 #2).
- Cross-panel emission isolation — a data-governance read does NOT emit
  a risk-tier event by mistake (per-panel negative assertion).
- 4xx paths emit ZERO audit events (draft-state 409 ``pack_not_yet_submitted``
  + RBAC 403 ``scope_not_held`` + tenant-isolation 404).
- Sequential 4-panel reads land as 4 distinct chain rows with
  monotonically increasing sequence.

Uses the shared SQLite ``engine`` + ``store`` fixtures from
``conftest.py`` (requested as plain params — no import → no ``F811``).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.core.decision_history import _decision_history as _dh
from cognic_agentos.packs.lifecycle import PackKind
from cognic_agentos.packs.storage import EvidencePanelName, PackRecord, PackRecordStore
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.rbac.actor import Actor

# --- Route surface --------------------------------------------------------
# The path uses hyphens + "conformance"; the chain-event panel_name uses
# underscores + "conformance_matrix". The pairs below are the wire-protocol
# contract this module pins.
_PANEL_ROUTES: dict[EvidencePanelName, str] = {
    "data_governance": "/api/v1/packs/{pack_id}/evidence/data-governance",
    "risk_tier": "/api/v1/packs/{pack_id}/evidence/risk-tier",
    "supply_chain": "/api/v1/packs/{pack_id}/evidence/supply-chain",
    "conformance_matrix": "/api/v1/packs/{pack_id}/evidence/conformance",
}
_ALL_PANELS: tuple[EvidencePanelName, ...] = tuple(_PANEL_ROUTES)

# The module-level projector name each handler calls — monkeypatch target
# for the R18 P2 DTO-validation-failure regression class.
_PANEL_PROJECTORS: dict[EvidencePanelName, str] = {
    "data_governance": "project_data_governance_panel",
    "risk_tier": "project_risk_tier_panel",
    "supply_chain": "project_supply_chain_panel",
    "conformance_matrix": "project_conformance_matrix_panel",
}


def _contract_drift_projector(**_kwargs: Any) -> dict[str, Any]:
    """A stand-in projector that returns a dict which FAILS every panel
    DTO's ``model_validate`` (no required fields) — simulates a
    projector / DTO contract drift that 500s the handler AFTER the
    projector returns. Accepts arbitrary kwargs so it can stand in for
    any of the 4 projectors regardless of their per-panel signatures."""
    return {"__t10_dto_contract_drift__": "missing all required panel fields"}


# --- Actor injection ------------------------------------------------------


class _StubBinder:
    """Test-only ``ActorBinder`` returning a configured actor."""

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
    return Actor(
        subject=subject,
        tenant_id=tenant_id,
        scopes=scopes,  # type: ignore[arg-type]
        actor_type=actor_type,  # type: ignore[arg-type]
    )


def _build_app(*, actor: Actor, store: PackRecordStore) -> FastAPI:
    return create_app(actor_binder=_StubBinder(actor), pack_record_store=store)


# --- Manifest + seed helpers ----------------------------------------------

_DATA_GOVERNANCE_BLOCK: dict[str, Any] = {
    "data_classes": ["customer_pii", "audit_trail"],
    "purpose": "transaction_processing",
    "purpose_description": "End-to-end payment flow",
    "retention_policy": "regulator_floor",
    "retention_max_window": 86400,
    "egress_allow_list": ["https://core-banking.internal"],
    "dlp_pre_hooks": ["redact_pii_in_input"],
    "dlp_post_hooks": ["mask_account_numbers"],
}


def _build_manifest(*, kind: PackKind, pack_id_field: str) -> dict[str, Any]:
    """A minimal-but-complete manifest that projects cleanly through ALL
    four panel projectors (supply-chain / conformance blocks are absent —
    those projectors handle the missing-block defensive path)."""
    return {
        "pack": {
            "kind": kind,
            "pack_id": pack_id_field,
            "display_name": "Fixture Pack",
            "version": "0.0.1",
        },
        "data_governance": dict(_DATA_GOVERNANCE_BLOCK),
        "risk_tier": {"tier": "customer_data_read"},
    }


def _new_record(*, kind: PackKind, tenant_id: str, created_by: str) -> PackRecord:
    now = datetime.now(UTC)
    return PackRecord(
        id=uuid.uuid4(),
        kind=kind,
        pack_id=f"cognic-{kind}-{uuid.uuid4().hex[:8]}",
        display_name="Fixture Pack",
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


async def _seed_submitted_pack(
    store: PackRecordStore,
    *,
    kind: PackKind = "tool",
    tenant_id: str = "t1",
    created_by: str = "bob@bank.example",
) -> PackRecord:
    """Save a draft + transition to submitted WITH the T2 ``payload_manifest``
    kwarg so the evidence panels can project a persisted manifest."""
    record = _new_record(kind=kind, tenant_id=tenant_id, created_by=created_by)
    await store.save_draft(record)
    await store.transition(
        pack_id=record.id,
        transition="submit",
        actor_id=created_by,
        tenant_id=tenant_id,
        evidence_pointer=None,
        request_id=f"submit-seed-{record.id.hex[:8]}",
        payload_manifest=_build_manifest(kind=kind, pack_id_field=record.pack_id),
    )
    return record.model_copy(update={"state": "submitted"})


async def _seed_draft_pack(
    store: PackRecordStore,
    *,
    kind: PackKind = "tool",
    tenant_id: str = "t1",
    created_by: str = "bob@bank.example",
) -> PackRecord:
    record = _new_record(kind=kind, tenant_id=tenant_id, created_by=created_by)
    await store.save_draft(record)
    return record


# --- Chain-row reader -----------------------------------------------------


async def _read_evidence_read_rows(
    engine: AsyncEngine, *, event_type: str | None = None
) -> list[Any]:
    """Read ``decision_history`` rows DIRECTLY — ``load_lifecycle_history``
    only returns ``pack.lifecycle.%`` rows, so ``pack.evidence_read.%``
    rows need a direct chain-table read. Returns rows ordered by sequence;
    when ``event_type`` is None returns ONLY the evidence-read slice."""
    async with engine.connect() as conn:
        stmt = select(
            _dh.c.record_id,
            _dh.c.event_type,
            _dh.c.payload,
            _dh.c.tenant_id,
            _dh.c.sequence,
            _dh.c.request_id,
        ).order_by(_dh.c.sequence)
        if event_type is not None:
            stmt = stmt.where(_dh.c.event_type == event_type)
        else:
            stmt = stmt.where(_dh.c.event_type.like("pack.evidence_read.%"))
        rows = (await conn.execute(stmt)).all()
    return list(rows)


def _decode(raw: Any) -> Any:
    import json

    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        return json.loads(raw)
    return raw


# ===========================================================================
# Section A — happy path: 1 audit event per 200 response
# ===========================================================================


class TestSprint7B3T10PanelReadEmitsAuditEvent:
    @pytest.mark.parametrize("panel_name", _ALL_PANELS)
    async def test_panel_200_emits_exactly_one_audit_event(
        self, store: PackRecordStore, engine: AsyncEngine, panel_name: EvidencePanelName
    ) -> None:
        record = await _seed_submitted_pack(store, kind="tool")
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_PANEL_ROUTES[panel_name].format(pack_id=record.id))
        assert response.status_code == 200
        rows = await _read_evidence_read_rows(engine, event_type=f"pack.evidence_read.{panel_name}")
        assert len(rows) == 1

    @pytest.mark.parametrize("panel_name", _ALL_PANELS)
    async def test_audit_event_payload_carries_correct_fields(
        self, store: PackRecordStore, engine: AsyncEngine, panel_name: EvidencePanelName
    ) -> None:
        record = await _seed_submitted_pack(store, kind="tool", tenant_id="tenant-x")
        actor = _make_actor(subject="reviewer-x@bank.example", tenant_id="tenant-x")
        app = _build_app(actor=actor, store=store)
        with TestClient(app) as client:
            response = client.get(_PANEL_ROUTES[panel_name].format(pack_id=record.id))
        assert response.status_code == 200
        rows = await _read_evidence_read_rows(engine)
        assert len(rows) == 1
        row = rows[0]
        payload = _decode(row.payload)
        assert payload["panel_name"] == panel_name
        assert payload["actor_subject"] == "reviewer-x@bank.example"
        assert payload["pack_id"] == str(record.id)
        # R17 P2 #2 — tenant_id on the chain row's first-class column.
        assert row.tenant_id == "tenant-x"
        assert "tenant_id" not in payload

    @pytest.mark.parametrize("panel_name", _ALL_PANELS)
    async def test_panel_read_does_not_emit_other_panel_events(
        self, store: PackRecordStore, engine: AsyncEngine, panel_name: EvidencePanelName
    ) -> None:
        """Cross-panel emission isolation — reading one panel emits ONLY
        that panel's event, never a sibling panel's."""
        record = await _seed_submitted_pack(store, kind="tool")
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_PANEL_ROUTES[panel_name].format(pack_id=record.id))
        assert response.status_code == 200
        for other in _ALL_PANELS:
            if other == panel_name:
                continue
            sibling_rows = await _read_evidence_read_rows(
                engine, event_type=f"pack.evidence_read.{other}"
            )
            assert sibling_rows == []


# ===========================================================================
# Section B — 4xx paths emit ZERO audit events
# ===========================================================================


class TestSprint7B3T10RefusalPathsEmitNoAudit:
    @pytest.mark.parametrize("panel_name", _ALL_PANELS)
    async def test_draft_pack_409_emits_no_audit_event(
        self, store: PackRecordStore, engine: AsyncEngine, panel_name: EvidencePanelName
    ) -> None:
        """A ``pack_not_yet_submitted`` 409 means the read did not happen
        — the projector never ran, so no audit event is emitted."""
        record = await _seed_draft_pack(store, kind="tool")
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_PANEL_ROUTES[panel_name].format(pack_id=record.id))
        assert response.status_code == 409
        assert response.json()["detail"]["reason"] == "pack_not_yet_submitted"
        assert await _read_evidence_read_rows(engine) == []

    async def test_rbac_403_emits_no_audit_event(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        record = await _seed_submitted_pack(store, kind="tool")
        # Actor without pack.review.claim → RBAC 403 at the dep chain.
        actor = _make_actor(scopes=frozenset({"pack.audit.read"}))
        app = _build_app(actor=actor, store=store)
        with TestClient(app) as client:
            response = client.get(_PANEL_ROUTES["data_governance"].format(pack_id=record.id))
        assert response.status_code == 403
        assert await _read_evidence_read_rows(engine) == []

    async def test_tenant_isolation_404_emits_no_audit_event(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        record = await _seed_submitted_pack(store, kind="tool", tenant_id="t1")
        # Actor scoped to a different tenant → cross-tenant 404.
        actor = _make_actor(tenant_id="t2")
        app = _build_app(actor=actor, store=store)
        with TestClient(app) as client:
            response = client.get(_PANEL_ROUTES["risk_tier"].format(pack_id=record.id))
        assert response.status_code == 404
        assert await _read_evidence_read_rows(engine) == []


# ===========================================================================
# Section C — sequencing across multiple panel reads
# ===========================================================================


class TestSprint7B3T10MultiPanelSequencing:
    async def test_four_panel_reads_land_as_four_distinct_chain_rows(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        record = await _seed_submitted_pack(store, kind="tool")
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            for panel_name in _ALL_PANELS:
                response = client.get(_PANEL_ROUTES[panel_name].format(pack_id=record.id))
                assert response.status_code == 200
        rows = await _read_evidence_read_rows(engine)
        assert len(rows) == 4
        # Distinct record_ids; monotonically increasing sequence.
        assert len({r.record_id for r in rows}) == 4
        sequences = [r.sequence for r in rows]
        assert sequences == sorted(sequences)
        assert len(set(sequences)) == 4
        # One row per panel_name, in request order.
        assert [_decode(r.payload)["panel_name"] for r in rows] == list(_ALL_PANELS)


# ===========================================================================
# Section D — R18 P2: DTO-validation failure (500) emits ZERO audit events
# ===========================================================================


class TestSprint7B3T10DtoValidationFailureEmitsNoAudit:
    """R18 P2 — the audit event must be emitted ONLY after BOTH the
    projector AND the response-DTO ``model_validate`` succeed. A
    projector / DTO contract drift that 500s the handler AFTER the
    projector returns must leave ZERO ``pack.evidence_read.*`` chain
    rows: a 500 is not a successful read, and the T10 contract is that
    only 200 panel reads emit audit events.

    Pins the handler-body ordering ``validate DTO → emit → return``
    against a regression back to ``emit → return validate(...)``."""

    @pytest.mark.parametrize("panel_name", _ALL_PANELS)
    async def test_dto_validation_500_emits_no_audit_event(
        self,
        store: PackRecordStore,
        engine: AsyncEngine,
        monkeypatch: pytest.MonkeyPatch,
        panel_name: EvidencePanelName,
    ) -> None:
        record = await _seed_submitted_pack(store, kind="tool")
        # Force the panel's projector to return a DTO-invalid dict — the
        # handler will 500 inside model_validate, AFTER the projector call.
        monkeypatch.setattr(
            f"cognic_agentos.portal.api.packs.evidence_routes.{_PANEL_PROJECTORS[panel_name]}",
            _contract_drift_projector,
        )
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.get(_PANEL_ROUTES[panel_name].format(pack_id=record.id))
        assert response.status_code == 500
        # The read did not succeed → no pack.evidence_read.* row written.
        assert await _read_evidence_read_rows(engine) == []
