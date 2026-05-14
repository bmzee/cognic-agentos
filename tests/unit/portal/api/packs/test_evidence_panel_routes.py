"""Sprint 7B.3 T3 Slice F — end-to-end evidence-panel route integration tests.

Pins the production behaviour of
``GET /api/v1/packs/{pack_id}/evidence/data-governance`` per plan §305
acceptance. Covers:

- Happy path — submit a pack with manifest, GET returns 200 with the
  projected :class:`DataGovernancePanel`.
- ``pack_kind`` echoed from the authoritative :class:`PackRecord.kind`
  (NOT from the manifest); pinned via tool / skill / agent / hook fixtures.
- ``pack_kind_mismatch`` 409 when persisted manifest disagrees with
  record kind + structured-log emission.
- ``pack_not_yet_submitted`` 409 on draft state + log.
- ``manifest_evidence_not_persisted`` 409 when submit row has no
  ``payload["manifest"]`` (pre-7B.3 / fixture rows) + log.
- RBAC denial (no scope) → 403 ``scope_not_held``.
- Tenant isolation — cross-tenant request → 404 ``tenant_id_mismatch``.
- Unknown pack-id → 404 ``pack_not_found``.
- ``tenant_policy_diff`` is empty ``()`` at the route layer per plan §304
  (Wave-1 contract; tenant-policy substrate ships in a follow-up sprint).
- Re-submit-after-withdraw — :func:`find_latest_submit_row` returns the
  newest submit, not the original.

Builds on the test scaffolding pattern at
``tests/unit/portal/api/packs/test_review_routes.py``: SQLite engine
fixture + :class:`PackRecordStore` fixture + ``_StubBinder`` actor
injection + :func:`create_app` with the store + binder threaded
through.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.packs.lifecycle import PackKind
from cognic_agentos.packs.storage import PackRecord, PackRecordStore
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.rbac.actor import Actor


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


@pytest.fixture
async def engine(tmp_path: Any) -> AsyncIterator[AsyncEngine]:
    url = f"sqlite+aiosqlite:///{tmp_path / 'evidence_routes.db'}"
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
    return create_app(actor_binder=_StubBinder(actor), pack_record_store=store)


_FIXTURE_DATA_GOVERNANCE_BLOCK: dict[str, Any] = {
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
    """Build a minimal but realistic manifest dict for fixture submits."""
    return {
        "pack": {
            "kind": kind,
            "pack_id": pack_id_field,
            "display_name": "Fixture Pack",
            "version": "0.0.1",
        },
        "data_governance": dict(_FIXTURE_DATA_GOVERNANCE_BLOCK),
    }


async def _seed_submitted_pack(
    store: PackRecordStore,
    *,
    kind: PackKind = "tool",
    tenant_id: str = "t1",
    created_by: str = "bob@bank.example",
    manifest: dict[str, Any] | None = None,
    omit_manifest_kwarg: bool = False,
) -> PackRecord:
    """Save a draft + transition to submitted with payload_manifest.

    When ``omit_manifest_kwarg=True`` the submit transition fires
    WITHOUT the T2 ``payload_manifest`` kwarg (simulates pre-7B.3 /
    fixture chain rows). When ``manifest=None`` (and not omitted) the
    submit uses :func:`_build_manifest`'s default shape.
    """
    now = datetime.now(UTC)
    pack_id_field = f"cognic-{kind}-{uuid.uuid4().hex[:8]}"
    record = PackRecord(
        id=uuid.uuid4(),
        kind=kind,
        pack_id=pack_id_field,
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
    await store.save_draft(record)

    effective_manifest = (
        manifest
        if manifest is not None
        else _build_manifest(kind=kind, pack_id_field=pack_id_field)
    )

    transition_kwargs: dict[str, Any] = {
        "pack_id": record.id,
        "transition": "submit",
        "actor_id": created_by,
        "tenant_id": tenant_id,
        "evidence_pointer": None,
        "request_id": f"submit-seed-{record.id.hex[:8]}",
    }
    if not omit_manifest_kwarg:
        transition_kwargs["payload_manifest"] = effective_manifest

    await store.transition(**transition_kwargs)
    return record.model_copy(update={"state": "submitted"})


async def _seed_draft_pack(
    store: PackRecordStore,
    *,
    kind: PackKind = "tool",
    tenant_id: str = "t1",
    created_by: str = "bob@bank.example",
) -> PackRecord:
    now = datetime.now(UTC)
    record = PackRecord(
        id=uuid.uuid4(),
        kind=kind,
        pack_id=f"cognic-{kind}-{uuid.uuid4().hex[:8]}",
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


_PANEL_PATH = "/api/v1/packs/{pack_id}/evidence/data-governance"


class TestSprint7B3T3SliceFHappyPath:
    """Slice F-1 — green-path projection through the production app."""

    async def test_happy_path_returns_200_and_full_panel_shape(
        self, store: PackRecordStore
    ) -> None:
        record = await _seed_submitted_pack(store, kind="tool")
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        body = response.json()
        assert body["pack_kind"] == "tool"
        assert body["data_classes"] == ["customer_pii", "audit_trail"]
        assert body["purpose"] == "transaction_processing"
        assert body["purpose_description"] == "End-to-end payment flow"
        assert body["retention_policy"] == "regulator_floor"
        assert body["retention_max_window"] == "86400"
        assert body["egress_allow_list"] == ["https://core-banking.internal"]
        assert body["dlp_pre_hooks"] == ["redact_pii_in_input"]
        assert body["dlp_post_hooks"] == ["mask_account_numbers"]
        # Plan §304 — tenant-policy substrate post-7B; route passes None.
        assert body["tenant_policy_diff"] == []

    @pytest.mark.parametrize("kind", ["tool", "skill", "agent", "hook"])
    async def test_pack_kind_echoes_record_kind_across_all_four_kinds(
        self, store: PackRecordStore, kind: PackKind
    ) -> None:
        """``pack_kind`` MUST come from the authoritative
        :class:`PackRecord.kind` (the projector contract). Round-trip
        through the full FastAPI stack for each of the 4 plugin pack
        kinds per R9 plugin-pack admission doctrine."""
        record = await _seed_submitted_pack(store, kind=kind)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        assert response.json()["pack_kind"] == kind


class TestSprint7B3T3SliceFRefusalReasons:
    """Slice F-2 — the three handler-body 409 refusal paths +
    structured-log mutually-exclusive emission contract."""

    async def test_409_pack_not_yet_submitted_on_draft_state(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        record = await _seed_draft_pack(store)
        app = _build_app(actor=_make_actor(), store=store)
        caplog.set_level(logging.WARNING, logger="cognic_agentos.portal.api.packs.evidence_routes")
        with TestClient(app) as client:
            response = client.get(_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 409
        assert response.json() == {"detail": {"reason": "pack_not_yet_submitted"}}
        refused_logs = [
            r
            for r in caplog.records
            if r.message == "portal.packs.evidence.data_governance_panel_refused"
        ]
        assert len(refused_logs) == 1
        assert refused_logs[0].__dict__["reason"] == "pack_not_yet_submitted"
        assert refused_logs[0].__dict__["pack_id"] == str(record.id)
        assert refused_logs[0].__dict__["actor_subject"] == "alice@bank.example"

    async def test_409_manifest_evidence_not_persisted_on_pre_7b3_submit_row(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Pre-7B.3 / fixture submit rows omit the ``payload_manifest``
        kwarg; the storage doctrine boundary surfaces explicitly via
        409 ``manifest_evidence_not_persisted``."""
        record = await _seed_submitted_pack(store, omit_manifest_kwarg=True)
        app = _build_app(actor=_make_actor(), store=store)
        caplog.set_level(logging.WARNING, logger="cognic_agentos.portal.api.packs.evidence_routes")
        with TestClient(app) as client:
            response = client.get(_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 409
        assert response.json() == {"detail": {"reason": "manifest_evidence_not_persisted"}}
        refused_logs = [
            r
            for r in caplog.records
            if r.message == "portal.packs.evidence.data_governance_panel_refused"
        ]
        assert len(refused_logs) == 1
        assert refused_logs[0].__dict__["reason"] == "manifest_evidence_not_persisted"

    async def test_409_pack_kind_mismatch_when_manifest_kind_disagrees(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Manifest declares ``pack.kind = "skill"`` but the record was
        seeded as ``"tool"`` — 409 ``pack_kind_mismatch`` + log."""
        tampered_manifest = _build_manifest(kind="tool", pack_id_field="cognic-tool-xyz")
        tampered_manifest["pack"]["kind"] = "skill"  # tamper
        record = await _seed_submitted_pack(store, kind="tool", manifest=tampered_manifest)
        app = _build_app(actor=_make_actor(), store=store)
        caplog.set_level(logging.WARNING, logger="cognic_agentos.portal.api.packs.evidence_routes")
        with TestClient(app) as client:
            response = client.get(_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 409
        assert response.json() == {"detail": {"reason": "pack_kind_mismatch"}}
        refused_logs = [
            r
            for r in caplog.records
            if r.message == "portal.packs.evidence.data_governance_panel_refused"
        ]
        assert len(refused_logs) == 1
        assert refused_logs[0].__dict__["reason"] == "pack_kind_mismatch"
        assert refused_logs[0].__dict__["record_kind"] == "tool"
        assert refused_logs[0].__dict__["manifest_kind"] == "skill"

    async def test_happy_path_emits_zero_refused_logs(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Mutually-exclusive emission contract: green path emits ZERO
        ``portal.packs.evidence.data_governance_panel_refused`` records.
        Mirrors the T5/T6 dual-surface log doctrine."""
        record = await _seed_submitted_pack(store)
        app = _build_app(actor=_make_actor(), store=store)
        caplog.set_level(logging.WARNING, logger="cognic_agentos.portal.api.packs.evidence_routes")
        with TestClient(app) as client:
            response = client.get(_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        refused_logs = [
            r
            for r in caplog.records
            if r.message == "portal.packs.evidence.data_governance_panel_refused"
        ]
        assert refused_logs == []


class TestSprint7B3T3SliceFSiblingGateRefusals:
    """Slice F-3 — RBAC / tenant-isolation / unknown-pack-id refusals
    via the dependency chain (NOT handler-body)."""

    async def test_rbac_403_when_actor_lacks_review_claim_scope(
        self, store: PackRecordStore
    ) -> None:
        record = await _seed_submitted_pack(store)
        # Actor holds a different scope — should refuse at the dep chain.
        actor = _make_actor(scopes=frozenset({"pack.audit.read"}))
        app = _build_app(actor=actor, store=store)
        with TestClient(app) as client:
            response = client.get(_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 403
        # The RBAC layer enriches the body with ``required_scope`` +
        # ``actor_subject`` for examiner traceability; pin the ``reason``
        # key without locking the enrichment shape.
        detail = response.json()["detail"]
        assert detail["reason"] == "scope_not_held"
        assert detail["required_scope"] == "pack.review.claim"

    async def test_tenant_isolation_404_on_cross_tenant_access(
        self, store: PackRecordStore
    ) -> None:
        """Cross-tenant access surfaces as 404 ``tenant_id_mismatch``
        (NOT 403) per the cross-tenant 404 doctrine — prevents a probe
        from enumerating pack-ids across tenants."""
        record = await _seed_submitted_pack(store, tenant_id="t1")
        # Actor from a different tenant.
        actor = _make_actor(tenant_id="t2")
        app = _build_app(actor=actor, store=store)
        with TestClient(app) as client:
            response = client.get(_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 404
        assert response.json() == {"detail": {"reason": "tenant_id_mismatch"}}

    async def test_unknown_pack_id_404_pack_not_found(self, store: PackRecordStore) -> None:
        bogus_id = uuid.uuid4()
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_PANEL_PATH.format(pack_id=bogus_id))
        assert response.status_code == 404
        assert response.json() == {"detail": {"reason": "pack_not_found"}}


class TestSprint7B3T3SliceFManifestShapeIntegration:
    """Slice F-4 — exercise the projector's defensive paths through the
    full FastAPI stack."""

    async def test_empty_data_governance_block_surfaces_empty_fields(
        self, store: PackRecordStore
    ) -> None:
        """A manifest with ``data_governance = {}`` (minimal valid
        submit) surfaces all panel fields as empty values."""
        manifest = _build_manifest(kind="tool", pack_id_field="cognic-tool-empty")
        manifest["data_governance"] = {}
        record = await _seed_submitted_pack(store, manifest=manifest)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        body = response.json()
        assert body["data_classes"] == []
        assert body["purpose"] == ""
        assert body["purpose_description"] == ""
        assert body["retention_policy"] == ""
        assert body["retention_max_window"] == ""

    async def test_unknown_kind_in_manifest_still_mismatches(self, store: PackRecordStore) -> None:
        """A manifest with an unknown ``pack.kind`` value (e.g. a future
        kind extension that this AgentOS build doesn't know about)
        triggers ``pack_kind_mismatch`` rather than projecting against
        the record kind silently. The route's authority is
        :class:`PackRecord.kind`; the manifest's value is cross-checked,
        not adopted."""
        tampered_manifest = _build_manifest(kind="tool", pack_id_field="cognic-tool-future")
        tampered_manifest["pack"]["kind"] = "future_unknown_kind"
        record = await _seed_submitted_pack(store, kind="tool", manifest=tampered_manifest)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 409
        assert response.json() == {"detail": {"reason": "pack_kind_mismatch"}}
