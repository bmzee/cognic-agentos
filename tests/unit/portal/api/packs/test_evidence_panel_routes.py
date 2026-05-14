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


# Signer-shaped [supply_chain] block — the live `agentos sign --bundle`
# contract declares every attestation FILE through `attestation_paths`
# under the canonical filenames per `cli/verify.py:_REQUIRED_ATTESTATION_FILES`.
# `slsa_level` is the one optional author-declared key (the validator
# tolerates it; the signer does not auto-populate it).
_FIXTURE_SUPPLY_CHAIN_BLOCK: dict[str, Any] = {
    "attestation_paths": [
        "attestations/cosign.sig",
        "attestations/bundle.sigstore",
        "attestations/sbom.cdx.json",
        "attestations/vuln-scan.json",
        "attestations/license-audit.json",
        "attestations/slsa-provenance.intoto.json",
        "attestations/intoto-layout.json",
    ],
    "slsa_level": 3,
}


def _build_manifest(
    *,
    kind: PackKind,
    pack_id_field: str,
    risk_tier_value: str | None = "customer_data_read",
    supply_chain_block: dict[str, Any] | None = None,
    mcp_block: dict[str, Any] | None = None,
    a2a_block: dict[str, Any] | None = None,
    identity_block: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a minimal but realistic manifest dict for fixture submits.

    The ``risk_tier_value`` kwarg is non-None by default so T3 fixtures
    keep working unchanged (the data-governance projector ignores the
    block). T4 fixtures parameterise on this value to exercise the
    full 8-value :data:`RiskTier` set + the defensive-fallback paths.
    Pass ``None`` to OMIT the ``risk_tier`` block entirely (exercises
    the missing-block defensive path).

    Sprint 7B.3 T5 extension — the ``supply_chain_block`` kwarg is
    None-by-default (mirrors the missing-block defensive path for
    T5 fixtures); pass a populated dict (or :data:`_FIXTURE_SUPPLY_CHAIN_BLOCK`)
    to exercise the full attestation-set projection. T3/T4 fixtures
    keep working unchanged — the data-governance / risk-tier
    projectors ignore the block.

    Sprint 7B.3 T6 extension — the ``mcp_block`` / ``a2a_block`` /
    ``identity_block`` kwargs are None-by-default (mirror the missing-
    block defensive path for T6 fixtures); pass populated dicts to
    exercise the conformance-matrix projection's MCP / A2A / OASF
    declaration paths. T3/T4/T5 fixtures keep working unchanged — the
    data-governance / risk-tier / supply-chain projectors ignore these
    blocks.
    """
    manifest: dict[str, Any] = {
        "pack": {
            "kind": kind,
            "pack_id": pack_id_field,
            "display_name": "Fixture Pack",
            "version": "0.0.1",
        },
        "data_governance": dict(_FIXTURE_DATA_GOVERNANCE_BLOCK),
    }
    if risk_tier_value is not None:
        manifest["risk_tier"] = {"tier": risk_tier_value}
    if supply_chain_block is not None:
        manifest["supply_chain"] = supply_chain_block
    if mcp_block is not None:
        manifest["mcp"] = mcp_block
    if a2a_block is not None:
        manifest["a2a"] = a2a_block
    if identity_block is not None:
        manifest["identity"] = identity_block
    return manifest


async def _seed_submitted_pack(
    store: PackRecordStore,
    *,
    kind: PackKind = "tool",
    tenant_id: str = "t1",
    created_by: str = "bob@bank.example",
    manifest: dict[str, Any] | None = None,
    omit_manifest_kwarg: bool = False,
    conformance_payload: dict[str, Any] | None = None,
) -> PackRecord:
    """Save a draft + transition to submitted with payload_manifest.

    When ``omit_manifest_kwarg=True`` the submit transition fires
    WITHOUT the T2 ``payload_manifest`` kwarg (simulates pre-7B.3 /
    fixture chain rows). When ``manifest=None`` (and not omitted) the
    submit uses :func:`_build_manifest`'s default shape.

    Sprint 7B.3 T6 extension — when ``conformance_payload`` is non-None
    the submit transition ALSO threads the 7B.2-T9 ``payload_conformance``
    kwarg so the chain row carries ``payload["conformance"]`` (the
    OWASP suite verdict the conformance-matrix panel surfaces inline).
    When ``None`` the submit row has no ``conformance`` key — simulates
    a pre-7B.2-T9 chain row, exercising the panel's graceful
    ``owasp_verdict=None`` path.
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
    if conformance_payload is not None:
        transition_kwargs["payload_conformance"] = conformance_payload

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


# ===========================================================================
# Sprint 7B.3 T4 Slice E — risk-tier evidence-panel integration tests
# ===========================================================================
#
# Mirrors the T3 Slice F layout (Happy path / Refusal reasons / Sibling-gate
# refusals / Manifest-shape integration) for the risk-tier endpoint. The 4
# T4 classes pin the SAME refusal contract + the SAME RBAC + tenant-isolation
# gates as T3 — drift in any path-shared invariant would surface in both
# classes simultaneously, catching the "panel-specific drift" regression
# class.
# ===========================================================================


_RISK_TIER_PANEL_PATH = "/api/v1/packs/{pack_id}/evidence/risk-tier"


class TestSprint7B3T4SliceEHappyPath:
    """Slice E-1 — green-path projection for the risk-tier panel."""

    async def test_happy_path_returns_200_and_full_panel_shape(
        self, store: PackRecordStore
    ) -> None:
        record = await _seed_submitted_pack(store, kind="tool")
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_RISK_TIER_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        body = response.json()
        # _build_manifest default tier is customer_data_read → single_approval.
        assert body["pack_kind"] == "tool"
        assert body["risk_tier"] == "customer_data_read"
        assert body["approval_flow"] == "single_approval"
        assert isinstance(body["approval_flow_description"], str)
        assert body["approval_flow_description"] != ""
        # Wire-shape — exactly 4 fields, none smuggled.
        assert frozenset(body.keys()) == frozenset(
            {"pack_kind", "risk_tier", "approval_flow", "approval_flow_description"}
        )

    @pytest.mark.parametrize(
        ("tier", "expected_flow"),
        [
            ("read_only", "auto_run"),
            ("internal_write", "audit_emphasis"),
            ("customer_data_read", "single_approval"),
            ("customer_data_write", "single_approval"),
            ("payment_action", "four_eyes"),
            ("regulator_communication", "four_eyes_categorised"),
            ("cross_tenant", "operator_legal_signoff"),
            ("high_risk_custom", "pack_declared"),
        ],
    )
    async def test_every_canonical_tier_resolves_through_full_stack(
        self, store: PackRecordStore, tier: str, expected_flow: str
    ) -> None:
        """Every one of the 8 canonical :data:`RiskTier` values resolves
        through the full FastAPI stack to its ADR-014 approval flow.
        Pins the projector → DTO → JSON serialization round-trip for
        every canonical tier (NOT just the projector contract)."""
        manifest = _build_manifest(
            kind="tool",
            pack_id_field=f"cognic-tool-{tier}",
            risk_tier_value=tier,
        )
        record = await _seed_submitted_pack(store, kind="tool", manifest=manifest)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_RISK_TIER_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        body = response.json()
        assert body["risk_tier"] == tier
        assert body["approval_flow"] == expected_flow

    @pytest.mark.parametrize("kind", ["tool", "skill", "agent", "hook"])
    async def test_pack_kind_echoes_record_kind_across_all_four_kinds(
        self, store: PackRecordStore, kind: PackKind
    ) -> None:
        """``pack_kind`` MUST come from the authoritative
        :class:`PackRecord.kind`. Mirror of T3's parametrised kind test
        — pinned independently because each panel's projector contract
        is independently auditable."""
        record = await _seed_submitted_pack(store, kind=kind)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_RISK_TIER_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        assert response.json()["pack_kind"] == kind


class TestSprint7B3T4SliceERefusalReasons:
    """Slice E-2 — the three handler-body 409 refusal paths +
    structured-log mutually-exclusive emission contract.

    Distinct log message ``portal.packs.evidence.risk_tier_panel_refused``
    (NOT ``data_governance_panel_refused``) pinned to catch the cross-
    panel emission-drift regression class.
    """

    async def test_409_pack_not_yet_submitted_on_draft_state(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        record = await _seed_draft_pack(store)
        app = _build_app(actor=_make_actor(), store=store)
        caplog.set_level(logging.WARNING, logger="cognic_agentos.portal.api.packs.evidence_routes")
        with TestClient(app) as client:
            response = client.get(_RISK_TIER_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 409
        assert response.json() == {"detail": {"reason": "pack_not_yet_submitted"}}
        refused_logs = [
            r
            for r in caplog.records
            if r.message == "portal.packs.evidence.risk_tier_panel_refused"
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
        record = await _seed_submitted_pack(store, omit_manifest_kwarg=True)
        app = _build_app(actor=_make_actor(), store=store)
        caplog.set_level(logging.WARNING, logger="cognic_agentos.portal.api.packs.evidence_routes")
        with TestClient(app) as client:
            response = client.get(_RISK_TIER_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 409
        assert response.json() == {"detail": {"reason": "manifest_evidence_not_persisted"}}
        refused_logs = [
            r
            for r in caplog.records
            if r.message == "portal.packs.evidence.risk_tier_panel_refused"
        ]
        assert len(refused_logs) == 1
        assert refused_logs[0].__dict__["reason"] == "manifest_evidence_not_persisted"

    async def test_409_pack_kind_mismatch_when_manifest_kind_disagrees(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        tampered_manifest = _build_manifest(kind="tool", pack_id_field="cognic-tool-xyz")
        tampered_manifest["pack"]["kind"] = "skill"
        record = await _seed_submitted_pack(store, kind="tool", manifest=tampered_manifest)
        app = _build_app(actor=_make_actor(), store=store)
        caplog.set_level(logging.WARNING, logger="cognic_agentos.portal.api.packs.evidence_routes")
        with TestClient(app) as client:
            response = client.get(_RISK_TIER_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 409
        assert response.json() == {"detail": {"reason": "pack_kind_mismatch"}}
        refused_logs = [
            r
            for r in caplog.records
            if r.message == "portal.packs.evidence.risk_tier_panel_refused"
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
        ``portal.packs.evidence.risk_tier_panel_refused`` records."""
        record = await _seed_submitted_pack(store)
        app = _build_app(actor=_make_actor(), store=store)
        caplog.set_level(logging.WARNING, logger="cognic_agentos.portal.api.packs.evidence_routes")
        with TestClient(app) as client:
            response = client.get(_RISK_TIER_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        refused_logs = [
            r
            for r in caplog.records
            if r.message == "portal.packs.evidence.risk_tier_panel_refused"
        ]
        assert refused_logs == []

    async def test_risk_tier_handler_does_not_emit_data_governance_log(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Cross-panel emission-drift regression: the risk-tier refusal
        path emits ONLY the ``risk_tier_panel_refused`` log message —
        NEVER the data-governance log. A future change that copies
        T3's emission inline into the T4 handler by mistake would
        cross-fire and be caught by this assertion."""
        record = await _seed_draft_pack(store)
        app = _build_app(actor=_make_actor(), store=store)
        caplog.set_level(logging.WARNING, logger="cognic_agentos.portal.api.packs.evidence_routes")
        with TestClient(app) as client:
            response = client.get(_RISK_TIER_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 409
        # The data-governance panel's log MUST NOT fire here.
        dg_logs = [
            r
            for r in caplog.records
            if r.message == "portal.packs.evidence.data_governance_panel_refused"
        ]
        assert dg_logs == []


class TestSprint7B3T4SliceESiblingGateRefusals:
    """Slice E-3 — RBAC / tenant-isolation / unknown-pack-id refusals
    via the dependency chain. Same gate semantics as T3."""

    async def test_rbac_403_when_actor_lacks_review_claim_scope(
        self, store: PackRecordStore
    ) -> None:
        record = await _seed_submitted_pack(store)
        actor = _make_actor(scopes=frozenset({"pack.audit.read"}))
        app = _build_app(actor=actor, store=store)
        with TestClient(app) as client:
            response = client.get(_RISK_TIER_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 403
        detail = response.json()["detail"]
        assert detail["reason"] == "scope_not_held"
        assert detail["required_scope"] == "pack.review.claim"

    async def test_tenant_isolation_404_on_cross_tenant_access(
        self, store: PackRecordStore
    ) -> None:
        record = await _seed_submitted_pack(store, tenant_id="t1")
        actor = _make_actor(tenant_id="t2")
        app = _build_app(actor=actor, store=store)
        with TestClient(app) as client:
            response = client.get(_RISK_TIER_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 404
        assert response.json() == {"detail": {"reason": "tenant_id_mismatch"}}

    async def test_unknown_pack_id_404_pack_not_found(self, store: PackRecordStore) -> None:
        bogus_id = uuid.uuid4()
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_RISK_TIER_PANEL_PATH.format(pack_id=bogus_id))
        assert response.status_code == 404
        assert response.json() == {"detail": {"reason": "pack_not_found"}}


class TestSprint7B3T4SliceEManifestShapeIntegration:
    """Slice E-4 — exercise the projector's defensive-fallback paths
    through the full FastAPI stack."""

    async def test_missing_risk_tier_block_resolves_to_pack_declared_fallback(
        self, store: PackRecordStore
    ) -> None:
        """Manifest without a ``risk_tier`` block surfaces ``risk_tier=""``
        + ``approval_flow="pack_declared"`` so the reviewer is routed
        through the most-conservative flow rather than auto-running."""
        manifest = _build_manifest(
            kind="tool",
            pack_id_field="cognic-tool-norisk",
            risk_tier_value=None,  # omit risk_tier block
        )
        record = await _seed_submitted_pack(store, manifest=manifest)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_RISK_TIER_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        body = response.json()
        assert body["risk_tier"] == ""
        assert body["approval_flow"] == "pack_declared"

    async def test_unknown_tier_value_resolves_to_pack_declared_fallback(
        self, store: PackRecordStore
    ) -> None:
        """A manifest with a ``tier`` value outside the canonical 8
        (e.g. drift / corruption / future-vocab) surfaces the raw
        value echoed onto ``risk_tier`` + the conservative
        ``pack_declared`` flow. Reviewer sees the drift on-panel."""
        manifest = _build_manifest(
            kind="tool",
            pack_id_field="cognic-tool-legacy",
            risk_tier_value="legacy_unknown_tier",
        )
        record = await _seed_submitted_pack(store, manifest=manifest)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_RISK_TIER_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        body = response.json()
        assert body["risk_tier"] == "legacy_unknown_tier"
        assert body["approval_flow"] == "pack_declared"

    async def test_malformed_risk_tier_block_resolves_to_pack_declared_fallback(
        self, store: PackRecordStore
    ) -> None:
        """A manifest with ``risk_tier`` as a non-dict value (e.g. a
        bare string from corrupted persistence) surfaces empty +
        pack_declared fallback rather than crashing the route."""
        manifest = _build_manifest(
            kind="tool",
            pack_id_field="cognic-tool-malformed",
        )
        manifest["risk_tier"] = "not-a-dict"  # tamper with shape
        record = await _seed_submitted_pack(store, manifest=manifest)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_RISK_TIER_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        body = response.json()
        assert body["risk_tier"] == ""
        assert body["approval_flow"] == "pack_declared"

    async def test_approval_flow_description_present_in_response(
        self, store: PackRecordStore
    ) -> None:
        """The ``approval_flow_description`` field MUST be present
        AND non-empty on every successful panel response — wire-
        protocol-public guarantee for the reviewer UI hint."""
        record = await _seed_submitted_pack(store, kind="tool")
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_RISK_TIER_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        description = response.json()["approval_flow_description"]
        assert isinstance(description, str)
        assert description != ""


# ===========================================================================
# Sprint 7B.3 T4 R-reviewer-round P2 #2 — kind-integrity refusal hardening
# (shared evidence-route fix — applies to BOTH data-governance and risk-tier
#  panels; pinned by dual-panel regression tests so a future drift in either
#  handler's kind check fails this suite)
# ===========================================================================


class TestSprint7B3T4ReviewerP2KindIntegrityHardening:
    """R-reviewer-round P2 #2 — fix the latent T3 + T4 bug where the
    handler accepted a manifest with missing / non-string ``pack.kind``
    by silently projecting against :class:`PackRecord.kind`. Per R9
    kind-integrity invariant the manifest kind MUST be present, MUST
    be a string, AND MUST equal the authoritative record kind.

    Sprint 7B.3 T5 + T6 carry-forward: parametrize extended to include
    the ``/supply-chain`` (T5) and ``/conformance`` (T6) panel paths —
    same widened predicate doctrine applies to all FOUR evidence-panel
    handlers. Four failure modes covered for EACH of the 4 panel
    handlers (total: 16 regression cases) — drift in any handler trips
    the suite.
    """

    @pytest.mark.parametrize(
        "panel_path",
        [
            "/api/v1/packs/{pack_id}/evidence/data-governance",
            "/api/v1/packs/{pack_id}/evidence/risk-tier",
            "/api/v1/packs/{pack_id}/evidence/supply-chain",
            "/api/v1/packs/{pack_id}/evidence/conformance",
        ],
    )
    async def test_missing_pack_block_refuses_409_kind_mismatch(
        self,
        store: PackRecordStore,
        panel_path: str,
    ) -> None:
        """Manifest without a top-level ``pack`` block — handler MUST
        refuse with 409 ``pack_kind_mismatch`` rather than projecting
        against ``record.kind``. Mirrors the strict-integrity contract
        a forged / corrupted persisted manifest cannot bypass."""
        manifest = _build_manifest(kind="tool", pack_id_field="cognic-tool-nopack")
        del manifest["pack"]  # remove entire pack block
        record = await _seed_submitted_pack(store, kind="tool", manifest=manifest)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(panel_path.format(pack_id=record.id))
        assert response.status_code == 409
        assert response.json() == {"detail": {"reason": "pack_kind_mismatch"}}

    @pytest.mark.parametrize(
        "panel_path",
        [
            "/api/v1/packs/{pack_id}/evidence/data-governance",
            "/api/v1/packs/{pack_id}/evidence/risk-tier",
            "/api/v1/packs/{pack_id}/evidence/supply-chain",
            "/api/v1/packs/{pack_id}/evidence/conformance",
        ],
    )
    async def test_missing_kind_field_in_pack_block_refuses_409(
        self,
        store: PackRecordStore,
        panel_path: str,
    ) -> None:
        """``pack`` block present but ``kind`` field missing — same
        refusal. Per R9 the manifest MUST declare its kind explicitly;
        the route does NOT default to ``record.kind``."""
        manifest = _build_manifest(kind="tool", pack_id_field="cognic-tool-nokind")
        del manifest["pack"]["kind"]  # remove only the kind field
        record = await _seed_submitted_pack(store, kind="tool", manifest=manifest)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(panel_path.format(pack_id=record.id))
        assert response.status_code == 409
        assert response.json() == {"detail": {"reason": "pack_kind_mismatch"}}

    @pytest.mark.parametrize(
        "panel_path",
        [
            "/api/v1/packs/{pack_id}/evidence/data-governance",
            "/api/v1/packs/{pack_id}/evidence/risk-tier",
            "/api/v1/packs/{pack_id}/evidence/supply-chain",
            "/api/v1/packs/{pack_id}/evidence/conformance",
        ],
    )
    async def test_non_string_kind_value_refuses_409(
        self,
        store: PackRecordStore,
        panel_path: str,
    ) -> None:
        """``pack.kind`` carries a non-string value (e.g. dict / int /
        bool from a corrupted manifest) — handler MUST refuse rather
        than allowing the type-confusion to slip through the
        ``!=`` comparison (where ``42 != "tool"`` is True but the
        ``pack_kind_mismatch`` reason is the canonical refusal)."""
        manifest = _build_manifest(kind="tool", pack_id_field="cognic-tool-badkind")
        manifest["pack"]["kind"] = 42  # non-string value
        record = await _seed_submitted_pack(store, kind="tool", manifest=manifest)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(panel_path.format(pack_id=record.id))
        assert response.status_code == 409
        assert response.json() == {"detail": {"reason": "pack_kind_mismatch"}}

    @pytest.mark.parametrize(
        "panel_path",
        [
            "/api/v1/packs/{pack_id}/evidence/data-governance",
            "/api/v1/packs/{pack_id}/evidence/risk-tier",
            "/api/v1/packs/{pack_id}/evidence/supply-chain",
            "/api/v1/packs/{pack_id}/evidence/conformance",
        ],
    )
    async def test_non_dict_pack_block_refuses_409(
        self,
        store: PackRecordStore,
        panel_path: str,
    ) -> None:
        """``pack`` block present but is a non-dict value (e.g. a bare
        string from corrupted persistence) — handler MUST refuse. Pins
        the ``isinstance(pack_meta, dict)`` defensive branch + the
        widened kind-integrity check together."""
        manifest = _build_manifest(kind="tool", pack_id_field="cognic-tool-strpack")
        manifest["pack"] = "not-a-dict"  # corrupt block shape
        record = await _seed_submitted_pack(store, kind="tool", manifest=manifest)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(panel_path.format(pack_id=record.id))
        assert response.status_code == 409
        assert response.json() == {"detail": {"reason": "pack_kind_mismatch"}}


# ===========================================================================
# Sprint 7B.3 T5 Slice D — supply-chain evidence-panel route integration.
#
# Mirrors the T4 Slice E layout (HappyPath / RefusalReasons / SiblingGate /
# ManifestShapeIntegration) for the supply-chain endpoint. The 4 T5 classes
# pin the SAME refusal contract + RBAC + tenant-isolation gates as T3+T4 —
# drift in any path-shared invariant would surface in all classes
# simultaneously.
# ===========================================================================


_SUPPLY_CHAIN_PANEL_PATH = "/api/v1/packs/{pack_id}/evidence/supply-chain"


class TestSprint7B3T5SliceDHappyPath:
    """Slice D-1 — green-path projection for the supply-chain panel."""

    async def test_happy_path_returns_200_and_full_panel_shape(
        self, store: PackRecordStore
    ) -> None:
        """Full-shape green path: manifest with the full
        :data:`_FIXTURE_SUPPLY_CHAIN_BLOCK` declarations + a submit
        chain row whose ``created_at`` feeds the 7-year sigstore
        retention computation."""
        manifest = _build_manifest(
            kind="tool",
            pack_id_field="cognic-tool-fullsupplychain",
            supply_chain_block=dict(_FIXTURE_SUPPLY_CHAIN_BLOCK),
        )
        record = await _seed_submitted_pack(store, kind="tool", manifest=manifest)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_SUPPLY_CHAIN_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        body = response.json()
        # Wire-shape — exactly 9 fields, none smuggled.
        assert frozenset(body.keys()) == frozenset(
            {
                "pack_kind",
                "declared_attestation_paths",
                "slsa_level_declared",
                "sbom_path_declared",
                "vuln_scan_path_declared",
                "license_audit_path_declared",
                "sigstore_bundle_path_declared",
                "in_toto_layout_declared",
                "sigstore_bundle_retention_expires_at",
            }
        )
        assert body["pack_kind"] == "tool"
        assert body["declared_attestation_paths"] == [
            "attestations/cosign.sig",
            "attestations/bundle.sigstore",
            "attestations/sbom.cdx.json",
            "attestations/vuln-scan.json",
            "attestations/license-audit.json",
            "attestations/slsa-provenance.intoto.json",
            "attestations/intoto-layout.json",
        ]
        assert body["slsa_level_declared"] == 3
        # The five named path fields are DERIVED from attestation_paths
        # by canonical-basename match (R1 P2 #1).
        assert body["sbom_path_declared"] == "attestations/sbom.cdx.json"
        assert body["vuln_scan_path_declared"] == "attestations/vuln-scan.json"
        assert body["license_audit_path_declared"] == "attestations/license-audit.json"
        assert body["sigstore_bundle_path_declared"] == "attestations/bundle.sigstore"
        assert body["in_toto_layout_declared"] == "attestations/intoto-layout.json"
        # Retention surfaces as ISO 8601 datetime (Pydantic v2 datetime
        # serialisation default).
        assert body["sigstore_bundle_retention_expires_at"] is not None
        assert isinstance(body["sigstore_bundle_retention_expires_at"], str)

    @pytest.mark.parametrize("kind", ["tool", "skill", "agent", "hook"])
    async def test_pack_kind_echoes_record_kind_across_all_four_kinds(
        self, store: PackRecordStore, kind: PackKind
    ) -> None:
        """``pack_kind`` MUST come from the authoritative
        :class:`PackRecord.kind`. Mirror of T3/T4's parametrised kind
        test — pinned independently because each panel's projector
        contract is independently auditable."""
        record = await _seed_submitted_pack(store, kind=kind)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_SUPPLY_CHAIN_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        assert response.json()["pack_kind"] == kind

    async def test_retention_computed_when_sigstore_bundle_declared(
        self, store: PackRecordStore
    ) -> None:
        """When the manifest's ``attestation_paths`` carries the
        canonical ``bundle.sigstore`` file, the panel DERIVES
        ``sigstore_bundle_path_declared`` + projects a non-None
        retention timestamp. Pinned independently of the full-shape
        happy path — the retention computation is the load-bearing
        ADR-016 §70-72 contract for the reviewer UI. This is the exact
        signer-shaped case R1 P2 #1 fixed (pre-fix returned None)."""
        block = {"attestation_paths": ["attestations/bundle.sigstore"]}
        manifest = _build_manifest(
            kind="tool",
            pack_id_field="cognic-tool-sigonly",
            supply_chain_block=block,
        )
        record = await _seed_submitted_pack(store, kind="tool", manifest=manifest)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_SUPPLY_CHAIN_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        assert response.json()["sigstore_bundle_path_declared"] == ("attestations/bundle.sigstore")
        assert response.json()["sigstore_bundle_retention_expires_at"] is not None

    async def test_retention_none_when_no_sigstore_declaration(
        self, store: PackRecordStore
    ) -> None:
        """When ``attestation_paths`` carries NO canonical
        ``bundle.sigstore`` entry, retention surfaces as None — even
        though the submit row's ``created_at`` is available (the
        retention is a property of the BUNDLE, not the submit row)."""
        # attestation_paths declares only cosign.sig — no bundle.
        block = {"attestation_paths": ["attestations/cosign.sig"], "slsa_level": 3}
        manifest = _build_manifest(
            kind="tool",
            pack_id_field="cognic-tool-noslsa",
            supply_chain_block=block,
        )
        record = await _seed_submitted_pack(store, kind="tool", manifest=manifest)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_SUPPLY_CHAIN_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        body = response.json()
        assert body["sigstore_bundle_path_declared"] is None
        assert body["sigstore_bundle_retention_expires_at"] is None
        # slsa_level still projects (optional author-declared key).
        assert body["slsa_level_declared"] == 3


class TestSprint7B3T5SliceDRefusalReasons:
    """Slice D-2 — the three handler-body 409 refusal paths +
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
            response = client.get(_SUPPLY_CHAIN_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 409
        assert response.json() == {"detail": {"reason": "pack_not_yet_submitted"}}
        refused_logs = [
            r
            for r in caplog.records
            if r.message == "portal.packs.evidence.supply_chain_panel_refused"
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
        record = await _seed_submitted_pack(store, omit_manifest_kwarg=True)
        app = _build_app(actor=_make_actor(), store=store)
        caplog.set_level(logging.WARNING, logger="cognic_agentos.portal.api.packs.evidence_routes")
        with TestClient(app) as client:
            response = client.get(_SUPPLY_CHAIN_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 409
        assert response.json() == {"detail": {"reason": "manifest_evidence_not_persisted"}}
        refused_logs = [
            r
            for r in caplog.records
            if r.message == "portal.packs.evidence.supply_chain_panel_refused"
        ]
        assert len(refused_logs) == 1
        assert refused_logs[0].__dict__["reason"] == "manifest_evidence_not_persisted"

    async def test_409_pack_kind_mismatch_when_manifest_kind_disagrees(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        tampered_manifest = _build_manifest(kind="tool", pack_id_field="cognic-tool-xyz")
        tampered_manifest["pack"]["kind"] = "skill"
        record = await _seed_submitted_pack(store, kind="tool", manifest=tampered_manifest)
        app = _build_app(actor=_make_actor(), store=store)
        caplog.set_level(logging.WARNING, logger="cognic_agentos.portal.api.packs.evidence_routes")
        with TestClient(app) as client:
            response = client.get(_SUPPLY_CHAIN_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 409
        assert response.json() == {"detail": {"reason": "pack_kind_mismatch"}}
        refused_logs = [
            r
            for r in caplog.records
            if r.message == "portal.packs.evidence.supply_chain_panel_refused"
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
        ``portal.packs.evidence.supply_chain_panel_refused`` records."""
        record = await _seed_submitted_pack(store)
        app = _build_app(actor=_make_actor(), store=store)
        caplog.set_level(logging.WARNING, logger="cognic_agentos.portal.api.packs.evidence_routes")
        with TestClient(app) as client:
            response = client.get(_SUPPLY_CHAIN_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        refused_logs = [
            r
            for r in caplog.records
            if r.message == "portal.packs.evidence.supply_chain_panel_refused"
        ]
        assert refused_logs == []

    async def test_supply_chain_handler_does_not_emit_other_panel_logs(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Cross-panel emission-drift regression: the supply-chain
        refusal path emits ONLY the ``supply_chain_panel_refused``
        log message — NEVER the data-governance OR risk-tier logs.
        A future change that copies a sibling handler's emission
        inline by mistake would cross-fire."""
        record = await _seed_draft_pack(store)
        app = _build_app(actor=_make_actor(), store=store)
        caplog.set_level(logging.WARNING, logger="cognic_agentos.portal.api.packs.evidence_routes")
        with TestClient(app) as client:
            response = client.get(_SUPPLY_CHAIN_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 409
        # Neither sibling panel's log MUST fire here.
        dg_logs = [
            r
            for r in caplog.records
            if r.message == "portal.packs.evidence.data_governance_panel_refused"
        ]
        rt_logs = [
            r
            for r in caplog.records
            if r.message == "portal.packs.evidence.risk_tier_panel_refused"
        ]
        assert dg_logs == []
        assert rt_logs == []


class TestSprint7B3T5SliceDSiblingGateRefusals:
    """Slice D-3 — RBAC / tenant-isolation / unknown-pack-id refusals
    via the dependency chain. Same gate semantics as T3+T4."""

    async def test_rbac_403_when_actor_lacks_review_claim_scope(
        self, store: PackRecordStore
    ) -> None:
        record = await _seed_submitted_pack(store)
        actor = _make_actor(scopes=frozenset({"pack.audit.read"}))
        app = _build_app(actor=actor, store=store)
        with TestClient(app) as client:
            response = client.get(_SUPPLY_CHAIN_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 403
        detail = response.json()["detail"]
        assert detail["reason"] == "scope_not_held"
        assert detail["required_scope"] == "pack.review.claim"

    async def test_tenant_isolation_404_on_cross_tenant_access(
        self, store: PackRecordStore
    ) -> None:
        record = await _seed_submitted_pack(store, tenant_id="t1")
        actor = _make_actor(tenant_id="t2")
        app = _build_app(actor=actor, store=store)
        with TestClient(app) as client:
            response = client.get(_SUPPLY_CHAIN_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 404
        assert response.json() == {"detail": {"reason": "tenant_id_mismatch"}}

    async def test_unknown_pack_id_404_pack_not_found(self, store: PackRecordStore) -> None:
        bogus_id = uuid.uuid4()
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_SUPPLY_CHAIN_PANEL_PATH.format(pack_id=bogus_id))
        assert response.status_code == 404
        assert response.json() == {"detail": {"reason": "pack_not_found"}}


class TestSprint7B3T5SliceDManifestShapeIntegration:
    """Slice D-4 — exercise the projector's defensive-fallback paths
    through the full FastAPI stack."""

    async def test_missing_supply_chain_block_returns_all_empty_or_none(
        self, store: PackRecordStore
    ) -> None:
        """Manifest without a ``supply_chain`` block surfaces every
        declared field as None / empty + retention None — the
        reviewer sees the gap on-panel rather than the route
        crashing on a missing block."""
        # Default _build_manifest carries NO supply_chain block.
        record = await _seed_submitted_pack(store, kind="tool")
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_SUPPLY_CHAIN_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        body = response.json()
        assert body["declared_attestation_paths"] == []
        assert body["slsa_level_declared"] is None
        assert body["sbom_path_declared"] is None
        assert body["vuln_scan_path_declared"] is None
        assert body["license_audit_path_declared"] is None
        assert body["sigstore_bundle_path_declared"] is None
        assert body["in_toto_layout_declared"] is None
        assert body["sigstore_bundle_retention_expires_at"] is None

    async def test_non_dict_supply_chain_block_falls_back(self, store: PackRecordStore) -> None:
        """Corrupted persistence — ``supply_chain`` as a bare string —
        surfaces the defensive fallback (all None / empty + retention
        None) WITHOUT crashing the route."""
        manifest = _build_manifest(kind="tool", pack_id_field="cognic-tool-malformed")
        manifest["supply_chain"] = "not-a-dict"
        record = await _seed_submitted_pack(store, kind="tool", manifest=manifest)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_SUPPLY_CHAIN_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        body = response.json()
        assert body["declared_attestation_paths"] == []
        assert body["sigstore_bundle_path_declared"] is None
        assert body["sigstore_bundle_retention_expires_at"] is None

    async def test_non_string_entries_in_attestation_paths_filtered_through_stack(
        self, store: PackRecordStore
    ) -> None:
        """Non-string drift in ``attestation_paths`` is silently
        filtered at the projector — the wire never carries a
        non-string entry even when the persisted manifest contains
        one."""
        block = {
            "attestation_paths": [
                "valid/path.sig",
                42,  # non-string drift
                None,
                "another/valid.bundle",
            ],
        }
        manifest = _build_manifest(
            kind="tool",
            pack_id_field="cognic-tool-drift",
            supply_chain_block=block,
        )
        record = await _seed_submitted_pack(store, kind="tool", manifest=manifest)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_SUPPLY_CHAIN_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        assert response.json()["declared_attestation_paths"] == [
            "valid/path.sig",
            "another/valid.bundle",
        ]


# ===========================================================================
# Sprint 7B.3 T6 Slice D — conformance-matrix evidence-panel route integration.
#
# Mirrors the T5 Slice D layout (HappyPath / RefusalReasons / SiblingGate /
# ManifestShapeIntegration) for the conformance endpoint, PLUS two T6-
# specific classes: KindAwareMatrix (R9 4-kind applicability matrix per
# plan §354) and OwaspVerdict (the payload["conformance"] inline-surfacing
# contract per plan §353). The conformance handler shares the SAME refusal
# + RBAC + tenant-isolation contract as T3-T5 — drift in any path-shared
# invariant surfaces across all four panels' suites simultaneously.
# ===========================================================================


_CONFORMANCE_PANEL_PATH = "/api/v1/packs/{pack_id}/evidence/conformance"

# Signer-shaped protocol blocks for T6 fixtures. The [mcp] block declares
# `sampling` (⚠️ restricted in the shipped matrix → mcp_capability_restricted)
# + `resources` (✅ supported → clean). The [a2a] block declares
# `streaming` (✅ supported → clean) + `push_notification_config`
# (⚠️ restricted + Wave-2-promoted → a2a_wave2_feature_declared). The
# [identity] block declares one OASF capability → oasf_capability_wave2_declared.
_FIXTURE_MCP_BLOCK: dict[str, Any] = {
    "sampling_supported": True,
    "resources_supported": True,
}
_FIXTURE_A2A_BLOCK: dict[str, Any] = {
    "streaming": True,
    "push_notification_config": True,
}
_FIXTURE_IDENTITY_BLOCK: dict[str, Any] = {
    "oasf_capability_set": ["search.v1"],
}

# 4-key OWASP suite verdict dict — the shape 7B.2 T9's
# `run_owasp_conformance_for_chain_payload` writes to the chain row's
# `payload["conformance"]` key.
_FIXTURE_CONFORMANCE_PAYLOAD: dict[str, Any] = {
    "overall_status": "green",
    "results": {
        "tool_misuse": {"category": "tool_misuse", "status": "pass", "findings": []},
        "secret_exfiltration": {
            "category": "secret_exfiltration",
            "status": "pass",
            "findings": [],
        },
    },
    "summary": "9 pass / 0 fail / 1 not_applicable",
    "errored_categories": [],
}


class TestSprint7B3T6SliceDHappyPath:
    """Slice D-1 — green-path projection through the production app."""

    async def test_happy_path_returns_200_and_full_panel_shape(
        self, store: PackRecordStore
    ) -> None:
        manifest = _build_manifest(
            kind="agent",
            pack_id_field="cognic-agent-conf",
            mcp_block=_FIXTURE_MCP_BLOCK,
            a2a_block=_FIXTURE_A2A_BLOCK,
            identity_block=_FIXTURE_IDENTITY_BLOCK,
        )
        record = await _seed_submitted_pack(
            store,
            kind="agent",
            manifest=manifest,
            conformance_payload=_FIXTURE_CONFORMANCE_PAYLOAD,
        )
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_CONFORMANCE_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        body = response.json()
        assert body["pack_kind"] == "agent"
        assert set(body["declarations"].keys()) == {"mcp", "a2a", "oasf"}
        assert body["declarations"]["mcp"]["applicable"] is True
        assert body["declarations"]["a2a"]["applicable"] is True
        assert body["declarations"]["oasf"]["applicable"] is True
        # sampling (restricted) + push_notification_config (wave2) + oasf
        # capability all flag; resources + streaming are clean.
        assert set(body["flagged_mismatches"]) == {
            "mcp_capability_restricted",
            "a2a_wave2_feature_declared",
            "oasf_capability_wave2_declared",
        }
        assert body["owasp_verdict"]["overall_status"] == "green"

    async def test_clean_agent_pack_has_empty_flagged_mismatches(
        self, store: PackRecordStore
    ) -> None:
        """An agent pack declaring only ✅-supported features produces
        an empty ``flagged_mismatches`` tuple."""
        manifest = _build_manifest(
            kind="agent",
            pack_id_field="cognic-agent-clean",
            mcp_block={"resources_supported": True},
            a2a_block={"streaming": True, "artifacts_supported": True},
        )
        record = await _seed_submitted_pack(store, kind="agent", manifest=manifest)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_CONFORMANCE_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        assert response.json()["flagged_mismatches"] == []

    async def test_comparisons_carry_protocol_feature_flag(self, store: PackRecordStore) -> None:
        manifest = _build_manifest(
            kind="agent",
            pack_id_field="cognic-agent-cmp",
            mcp_block={"sampling_supported": True},
        )
        record = await _seed_submitted_pack(store, kind="agent", manifest=manifest)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_CONFORMANCE_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        comparisons = response.json()["comparisons"]
        sampling = next(c for c in comparisons if c["feature"] == "sampling")
        assert sampling["protocol"] == "mcp"
        assert sampling["matrix_wave_1"] == "restricted"
        assert sampling["flag"] == "mcp_capability_restricted"


class TestSprint7B3T6SliceDKindAwareMatrix:
    """Slice D-2 — R9 4-kind protocol-applicability matrix per plan §354.

    tool/skill/agent → MCP applicable; agent → +A2A +OASF; hook → none.
    Applicability is derived from the authoritative PackRecord.kind.
    """

    @pytest.mark.parametrize(
        ("kind", "mcp_applies", "a2a_applies", "oasf_applies"),
        [
            ("tool", True, False, False),
            ("skill", True, False, False),
            ("agent", True, True, True),
            ("hook", False, False, False),
        ],
    )
    async def test_protocol_applicability_per_kind(
        self,
        store: PackRecordStore,
        kind: PackKind,
        mcp_applies: bool,
        a2a_applies: bool,
        oasf_applies: bool,
    ) -> None:
        record = await _seed_submitted_pack(store, kind=kind)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_CONFORMANCE_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        declarations = response.json()["declarations"]
        assert declarations["mcp"]["applicable"] is mcp_applies
        assert declarations["a2a"]["applicable"] is a2a_applies
        assert declarations["oasf"]["applicable"] is oasf_applies

    async def test_hook_pack_with_mcp_block_produces_no_comparisons(
        self, store: PackRecordStore
    ) -> None:
        """A hook pack that (wrongly) carries an [mcp] block — the panel
        marks MCP not_applicable + emits ZERO comparisons rather than
        failing the absent-protocol expectation per plan §351."""
        manifest = _build_manifest(
            kind="hook",
            pack_id_field="cognic-hook-mcp",
            mcp_block=_FIXTURE_MCP_BLOCK,
        )
        record = await _seed_submitted_pack(store, kind="hook", manifest=manifest)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_CONFORMANCE_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        body = response.json()
        assert body["declarations"]["mcp"]["applicable"] is False
        assert body["comparisons"] == []
        assert body["flagged_mismatches"] == []

    async def test_tool_pack_a2a_block_ignored(self, store: PackRecordStore) -> None:
        """A tool pack carrying an [a2a] block — A2A is not applicable
        for tool kind, so the block produces no comparisons."""
        manifest = _build_manifest(
            kind="tool",
            pack_id_field="cognic-tool-a2a",
            a2a_block=_FIXTURE_A2A_BLOCK,
        )
        record = await _seed_submitted_pack(store, kind="tool", manifest=manifest)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_CONFORMANCE_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        body = response.json()
        assert body["declarations"]["a2a"]["applicable"] is False
        assert [c for c in body["comparisons"] if c["protocol"] == "a2a"] == []


class TestSprint7B3T6SliceDOwaspVerdict:
    """Slice D-3 — the payload["conformance"] inline-surfacing contract
    per plan §353."""

    async def test_owasp_verdict_surfaced_inline(self, store: PackRecordStore) -> None:
        record = await _seed_submitted_pack(
            store, kind="tool", conformance_payload=_FIXTURE_CONFORMANCE_PAYLOAD
        )
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_CONFORMANCE_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        verdict = response.json()["owasp_verdict"]
        assert verdict["overall_status"] == "green"
        assert verdict["summary"] == "9 pass / 0 fail / 1 not_applicable"
        assert {r["category"] for r in verdict["results"]} == {
            "tool_misuse",
            "secret_exfiltration",
        }

    async def test_pre_7b2_t9_submit_row_surfaces_none_verdict_not_409(
        self, store: PackRecordStore
    ) -> None:
        """A submit chain row without a ``conformance`` key (pre-7B.2-T9)
        surfaces ``owasp_verdict=None`` gracefully — the OWASP verdict
        is supplementary evidence, NOT a manifest-evidence-persistence
        boundary, so this is a 200 (not a 409)."""
        record = await _seed_submitted_pack(store, kind="tool")  # no conformance_payload
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_CONFORMANCE_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        assert response.json()["owasp_verdict"] is None

    async def test_red_verdict_with_findings_surfaced(self, store: PackRecordStore) -> None:
        payload: dict[str, Any] = {
            "overall_status": "red",
            "results": {
                "unsafe_network": {
                    "category": "unsafe_network",
                    "status": "fail",
                    "findings": ["manifest.egress: wildcard egress not allowed"],
                }
            },
            "summary": "9 pass / 1 fail / 0 not_applicable",
            "errored_categories": [],
        }
        record = await _seed_submitted_pack(store, kind="tool", conformance_payload=payload)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_CONFORMANCE_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        verdict = response.json()["owasp_verdict"]
        assert verdict["overall_status"] == "red"
        assert verdict["results"][0]["findings"] == ["manifest.egress: wildcard egress not allowed"]


class TestSprint7B3T6SliceDRefusalReasons:
    """Slice D-4 — handler-body 409 refusals + per-panel mutually-
    exclusive log emission. Same refusal contract as T3-T5."""

    async def test_409_pack_not_yet_submitted_on_draft_state(
        self, store: PackRecordStore, caplog: pytest.LogCaptureFixture
    ) -> None:
        record = await _seed_draft_pack(store)
        app = _build_app(actor=_make_actor(), store=store)
        caplog.set_level(logging.WARNING, logger="cognic_agentos.portal.api.packs.evidence_routes")
        with TestClient(app) as client:
            response = client.get(_CONFORMANCE_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 409
        assert response.json() == {"detail": {"reason": "pack_not_yet_submitted"}}
        refused = [
            r
            for r in caplog.records
            if r.message == "portal.packs.evidence.conformance_panel_refused"
        ]
        assert len(refused) == 1
        assert refused[0].reason == "pack_not_yet_submitted"  # type: ignore[attr-defined]

    async def test_409_manifest_evidence_not_persisted_on_pre_7b3_submit_row(
        self, store: PackRecordStore
    ) -> None:
        record = await _seed_submitted_pack(store, omit_manifest_kwarg=True)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_CONFORMANCE_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 409
        assert response.json() == {"detail": {"reason": "manifest_evidence_not_persisted"}}

    async def test_409_pack_kind_mismatch_when_manifest_kind_disagrees(
        self, store: PackRecordStore
    ) -> None:
        manifest = _build_manifest(kind="agent", pack_id_field="cognic-agent-x")
        record = await _seed_submitted_pack(store, kind="tool", manifest=manifest)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_CONFORMANCE_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 409
        assert response.json() == {"detail": {"reason": "pack_kind_mismatch"}}

    async def test_happy_path_emits_zero_refused_logs(
        self, store: PackRecordStore, caplog: pytest.LogCaptureFixture
    ) -> None:
        record = await _seed_submitted_pack(store, kind="agent")
        app = _build_app(actor=_make_actor(), store=store)
        caplog.set_level(logging.WARNING, logger="cognic_agentos.portal.api.packs.evidence_routes")
        with TestClient(app) as client:
            response = client.get(_CONFORMANCE_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        refused = [
            r
            for r in caplog.records
            if r.message == "portal.packs.evidence.conformance_panel_refused"
        ]
        assert refused == []

    async def test_conformance_handler_does_not_emit_other_panel_logs(
        self, store: PackRecordStore, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Cross-panel emission-drift regression: the conformance
        refusal path emits ONLY the ``conformance_panel_refused`` log
        — NEVER the data-governance / risk-tier / supply-chain logs."""
        record = await _seed_draft_pack(store)
        app = _build_app(actor=_make_actor(), store=store)
        caplog.set_level(logging.WARNING, logger="cognic_agentos.portal.api.packs.evidence_routes")
        with TestClient(app) as client:
            response = client.get(_CONFORMANCE_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 409
        for sibling in (
            "portal.packs.evidence.data_governance_panel_refused",
            "portal.packs.evidence.risk_tier_panel_refused",
            "portal.packs.evidence.supply_chain_panel_refused",
        ):
            assert [r for r in caplog.records if r.message == sibling] == []


class TestSprint7B3T6SliceDSiblingGateRefusals:
    """Slice D-5 — RBAC / tenant-isolation / unknown-pack-id refusals
    via the dependency chain. Same gate semantics as T3-T5."""

    async def test_rbac_403_when_actor_lacks_review_claim_scope(
        self, store: PackRecordStore
    ) -> None:
        record = await _seed_submitted_pack(store)
        actor = _make_actor(scopes=frozenset({"pack.audit.read"}))
        app = _build_app(actor=actor, store=store)
        with TestClient(app) as client:
            response = client.get(_CONFORMANCE_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "scope_not_held"

    async def test_tenant_isolation_404_on_cross_tenant_access(
        self, store: PackRecordStore
    ) -> None:
        record = await _seed_submitted_pack(store, tenant_id="t1")
        actor = _make_actor(tenant_id="t2")
        app = _build_app(actor=actor, store=store)
        with TestClient(app) as client:
            response = client.get(_CONFORMANCE_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 404
        assert response.json() == {"detail": {"reason": "tenant_id_mismatch"}}

    async def test_unknown_pack_id_404_pack_not_found(self, store: PackRecordStore) -> None:
        bogus_id = uuid.uuid4()
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_CONFORMANCE_PANEL_PATH.format(pack_id=bogus_id))
        assert response.status_code == 404
        assert response.json() == {"detail": {"reason": "pack_not_found"}}


class TestSprint7B3T6SliceDManifestShapeIntegration:
    """Slice D-6 — exercise the projector's defensive-fallback paths
    through the full FastAPI stack."""

    async def test_missing_protocol_blocks_return_empty_declared_features(
        self, store: PackRecordStore
    ) -> None:
        """Default _build_manifest carries NO mcp/a2a/identity blocks —
        every protocol's ``declared_features`` is empty + no
        comparisons + no flags."""
        record = await _seed_submitted_pack(store, kind="agent")
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_CONFORMANCE_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        body = response.json()
        assert body["declarations"]["mcp"]["declared_features"] == []
        assert body["declarations"]["a2a"]["declared_features"] == []
        assert body["declarations"]["oasf"]["declared_features"] == []
        assert body["comparisons"] == []
        assert body["flagged_mismatches"] == []

    async def test_non_dict_protocol_block_falls_back(self, store: PackRecordStore) -> None:
        """Corrupted persistence — ``mcp`` as a bare string — surfaces
        the defensive fallback (empty declared_features) WITHOUT
        crashing the route."""
        manifest = _build_manifest(kind="agent", pack_id_field="cognic-agent-bad")
        manifest["mcp"] = "not-a-dict"
        record = await _seed_submitted_pack(store, kind="agent", manifest=manifest)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_CONFORMANCE_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        assert response.json()["declarations"]["mcp"]["declared_features"] == []

    async def test_non_string_oasf_entries_filtered_through_stack(
        self, store: PackRecordStore
    ) -> None:
        """Non-string drift in ``oasf_capability_set`` is silently
        filtered at the projector — the wire never carries a non-string
        capability even when the persisted manifest contains one."""
        manifest = _build_manifest(
            kind="agent",
            pack_id_field="cognic-agent-oasf-drift",
            identity_block={"oasf_capability_set": ["ok.v1", 42, None]},
        )
        record = await _seed_submitted_pack(store, kind="agent", manifest=manifest)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_CONFORMANCE_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        assert response.json()["declarations"]["oasf"]["declared_features"] == ["ok.v1"]

    async def test_malformed_conformance_payload_surfaces_none_verdict(
        self, store: PackRecordStore
    ) -> None:
        """A persisted ``conformance`` payload with a bogus
        ``overall_status`` surfaces ``owasp_verdict=None`` — the panel
        does NOT crash + does NOT leak a half-formed verdict."""
        record = await _seed_submitted_pack(
            store,
            kind="tool",
            conformance_payload={"overall_status": "purple", "results": {}},
        )
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_CONFORMANCE_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        assert response.json()["owasp_verdict"] is None


class TestSprint7B3T6SliceDDualPathAndScaffoldShapes:
    """Slice D-7 — R-reviewer P2 #1 (canonical scaffold ``[mcp]`` field
    families) + P2 #2 (legacy ``[tool.cognic.*]`` dual-path block
    resolution) through the full FastAPI stack. A real ``agentos
    init-tool`` pack OR a docs-shaped submitted manifest must project
    its protocol declarations — not empty."""

    async def test_scaffold_shaped_mcp_block_projects_through_stack(
        self, store: PackRecordStore
    ) -> None:
        """The canonical shape ``agentos init-tool`` emits — ``caching``
        + ``elicitation_form`` booleans (NOT ``caching_strategy`` /
        ``elicitation_modes``)."""
        manifest = _build_manifest(
            kind="tool",
            pack_id_field="cognic-tool-scaffold",
            mcp_block={"caching": True, "elicitation_form": True},
        )
        record = await _seed_submitted_pack(store, kind="tool", manifest=manifest)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_CONFORMANCE_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        body = response.json()
        assert set(body["declarations"]["mcp"]["declared_features"]) == {
            "caching",
            "elicitation",
        }
        # elicitation is ⚠️ restricted; caching is ✅ supported.
        assert body["flagged_mismatches"] == ["mcp_capability_restricted"]

    async def test_nested_tool_cognic_mcp_block_projects_through_stack(
        self, store: PackRecordStore
    ) -> None:
        """A docs-shaped submitted manifest carrying ``[tool.cognic.mcp]``
        (NOT top-level ``[mcp]``) MUST still project — the dual-path
        resolver mirrors the validator + runtime-reader R23 doctrine."""
        manifest: dict[str, Any] = {
            "pack": {
                "kind": "tool",
                "pack_id": "cognic-tool-nested",
                "display_name": "Nested Pack",
                "version": "0.0.1",
            },
            "data_governance": dict(_FIXTURE_DATA_GOVERNANCE_BLOCK),
            "tool": {"cognic": {"mcp": {"sampling_supported": True}}},
        }
        record = await _seed_submitted_pack(store, kind="tool", manifest=manifest)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_CONFORMANCE_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        body = response.json()
        assert body["declarations"]["mcp"]["declared_features"] == ["sampling"]
        assert body["flagged_mismatches"] == ["mcp_capability_restricted"]

    async def test_nested_tool_cognic_identity_oasf_projects_through_stack(
        self, store: PackRecordStore
    ) -> None:
        """Legacy ``[tool.cognic.identity]`` OASF capabilities resolve
        through the full stack for an agent pack."""
        manifest: dict[str, Any] = {
            "pack": {
                "kind": "agent",
                "pack_id": "cognic-agent-nested-id",
                "display_name": "Nested Identity Pack",
                "version": "0.0.1",
            },
            "data_governance": dict(_FIXTURE_DATA_GOVERNANCE_BLOCK),
            "tool": {"cognic": {"identity": {"oasf_capability_set": ["kyc.v1"]}}},
        }
        record = await _seed_submitted_pack(store, kind="agent", manifest=manifest)
        app = _build_app(actor=_make_actor(), store=store)
        with TestClient(app) as client:
            response = client.get(_CONFORMANCE_PANEL_PATH.format(pack_id=record.id))
        assert response.status_code == 200
        body = response.json()
        assert body["declarations"]["oasf"]["declared_features"] == ["kyc.v1"]
        assert body["flagged_mismatches"] == ["oasf_capability_wave2_declared"]
