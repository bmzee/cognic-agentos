"""Sprint 7B.3 T2 Slice C — ``transition()`` payload-shape regression matrix
for the 4 NEW optional keyword-only kwargs landed at T2.

Mirrors the Sprint 7B.2 T9 ``test_storage_transition_payload_schema.py``
test pattern (sectioned by kwarg). The 4 new kwargs:

- ``reviewer_acknowledgement: dict[str, Any] | None = None`` (R1 P2 #1) —
  approve-route only; populated by ``portal/api/packs/review_routes.py``
  (T9 of 7B.3) with the 4-boolean dict from
  :class:`cognic_agentos.portal.api.packs.dto.ReviewerAcknowledgement`
  (4 panel-ack booleans).
- ``payload_manifest: dict[str, Any] | None = None`` (R1 P2 #1) —
  submit-route only; populated by
  ``portal/api/packs/author_routes.py:submit_draft`` with the
  full author-submitted manifest body so T3-T6 evidence panels can
  reach the manifest at approve / panel-read time (manifest-evidence-
  source seam).
- ``override_event_id: str | None = None`` (R2 P2 #3) — approve-route
  only; populated when the 5-gate composer ran the override path,
  carrying the chain-event ID of the separately-emitted
  ``pack.approval_override`` record (correlation seam between the two
  chain events; T8 introduces the ``append_override_event`` method
  that produces the ID).
- ``signed_artefact_root: str | None = None`` (R6 P2 #4) — submit-
  route only; populated by ``portal/api/packs/author_routes.py``
  with the submit-declared absolute path to the signed-bundle
  directory on the approve-time host (R8 P2 #4 — submit-declared at
  the author surface, NOT operator-declared). The approve handler
  reads this via :func:`find_latest_submit_row` + passes to the
  signature path resolver.

User-watchpoint (ii) invariant — omitted kwargs do NOT add empty keys
to ``DecisionRecord.payload``. Keys appear ONLY when their kwarg was
non-None. Preserves byte-shape compat with every pre-T2 chain row +
every call site that doesn't need the T2 surfaces.

Cross-section: non-target transitions (e.g. payload_manifest on a
non-submit transition, signed_artefact_root on a non-submit transition,
reviewer_acknowledgement on a non-approve transition, override_event_id
on a non-approve transition) MUST NOT raise — storage stays a thin
passthrough; the route handlers own which kwarg fires on which
transition. The route-side discipline is owned by separate T5/T9
acceptance tests; this file only pins the storage-layer behaviour.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import _decision_history as _dh
from cognic_agentos.packs.lifecycle import PackKind, PackState
from cognic_agentos.packs.storage import PackRecord, PackRecordStore


@pytest.fixture
async def engine(tmp_path: Any) -> Any:
    url = f"sqlite+aiosqlite:///{tmp_path / 'packs-t2-kwargs.db'}"
    eng: AsyncEngine = create_async_engine(url)
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
    yield eng
    await eng.dispose()


@pytest.fixture
async def store(engine: AsyncEngine) -> PackRecordStore:
    return PackRecordStore(engine)


def _make_record(
    *,
    pack_id: str,
    kind: PackKind = "tool",
    state: PackState = "draft",
) -> PackRecord:
    now = datetime.now(UTC)
    return PackRecord(
        id=uuid.uuid4(),
        kind=kind,
        pack_id=pack_id,
        display_name=pack_id,
        state=state,
        manifest_digest=b"\x01" * 32,
        signed_artefact_digest=b"\x02" * 32,
        sbom_pointer=None,
        tenant_id=None,
        created_by="t2-kwargs-author",
        last_actor="t2-kwargs-author",
        created_at=now,
        updated_at=now,
    )


async def _read_last_payload(engine: AsyncEngine) -> dict[str, Any]:
    async with engine.connect() as conn:
        row = (
            await conn.execute(select(_dh.c.payload).order_by(_dh.c.sequence.desc()).limit(1))
        ).first()
    assert row is not None
    raw = row[0]
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        parsed: dict[str, Any] = json.loads(raw)
        return parsed
    assert isinstance(raw, dict), f"unexpected payload type {type(raw).__name__}"
    return raw


# ===========================================================================
# Section A — reviewer_acknowledgement kwarg behaviour (R1 P2 #1)
# ===========================================================================


class TestSprint7B3T2ReviewerAcknowledgementKwarg:
    """``reviewer_acknowledgement`` kwarg threads into
    ``payload["reviewer_acknowledgement"]`` when non-None; omitted leaves
    the payload byte-shape compatible."""

    async def test_non_none_kwarg_writes_reviewer_acknowledgement_key(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        rec = _make_record(pack_id="rec-ack-present", state="under_review")
        # Force the record into under_review so we can run approve
        # without going through submit + claim.
        async with engine.begin() as conn:
            from cognic_agentos.packs.storage import _packs

            await conn.execute(
                _packs.insert().values(
                    id=rec.id,
                    kind=rec.kind,
                    pack_id=rec.pack_id,
                    display_name=rec.display_name,
                    state=rec.state,
                    manifest_digest=rec.manifest_digest,
                    signed_artefact_digest=rec.signed_artefact_digest,
                    sbom_pointer=rec.sbom_pointer,
                    tenant_id=rec.tenant_id,
                    created_by=rec.created_by,
                    last_actor=rec.last_actor,
                    created_at=rec.created_at,
                    updated_at=rec.updated_at,
                )
            )

        ack_dict: dict[str, Any] = {
            "data_governance_acknowledged": True,
            "risk_tier_acknowledged": True,
            "supply_chain_acknowledged": True,
            "conformance_acknowledged": True,
        }
        await store.transition(
            pack_id=rec.id,
            transition="approve",
            actor_id="t2-reviewer",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-t2-ack-present",
            reviewer_acknowledgement=ack_dict,
        )

        payload = await _read_last_payload(engine)
        assert "reviewer_acknowledgement" in payload
        assert payload["reviewer_acknowledgement"] == ack_dict

    async def test_none_kwarg_omits_reviewer_acknowledgement_key(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        rec = _make_record(pack_id="rec-ack-absent", state="under_review")
        async with engine.begin() as conn:
            from cognic_agentos.packs.storage import _packs

            await conn.execute(
                _packs.insert().values(
                    id=rec.id,
                    kind=rec.kind,
                    pack_id=rec.pack_id,
                    display_name=rec.display_name,
                    state=rec.state,
                    manifest_digest=rec.manifest_digest,
                    signed_artefact_digest=rec.signed_artefact_digest,
                    sbom_pointer=rec.sbom_pointer,
                    tenant_id=rec.tenant_id,
                    created_by=rec.created_by,
                    last_actor=rec.last_actor,
                    created_at=rec.created_at,
                    updated_at=rec.updated_at,
                )
            )

        await store.transition(
            pack_id=rec.id,
            transition="approve",
            actor_id="t2-reviewer",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-t2-ack-absent",
            # reviewer_acknowledgement omitted
        )

        payload = await _read_last_payload(engine)
        assert "reviewer_acknowledgement" not in payload


# ===========================================================================
# Section B — payload_manifest kwarg behaviour (R1 P2 #1)
# ===========================================================================


class TestSprint7B3T2PayloadManifestKwarg:
    """``payload_manifest`` kwarg threads into ``payload["manifest"]``
    when non-None; the FULL author-submitted manifest body is persisted
    so T3-T6 evidence panels can reach it at panel-read / approve time."""

    async def test_non_none_kwarg_writes_payload_manifest_key(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        rec = _make_record(pack_id="rec-manifest-present")
        await store.save_draft(rec)

        manifest: dict[str, Any] = {
            "pack": {"name": "rec-manifest-present", "version": "1.0.0", "kind": "tool"},
            "data_governance": {
                "data_classes": ["public"],
                "purpose": "answer_compliance_question",
                "retention_policy": "in_flight_only",
            },
            "supply_chain": {
                "attestation_paths": ["cosign.sig", "sbom.json"],
                "blob_path": "rec-manifest-present-1.0.0.whl",
            },
            "risk_tier": {"tier": "read_only"},
        }
        await store.transition(
            pack_id=rec.id,
            transition="submit",
            actor_id="t2-author",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-t2-manifest-present",
            payload_manifest=manifest,
        )

        payload = await _read_last_payload(engine)
        assert "manifest" in payload
        assert payload["manifest"] == manifest

    async def test_none_kwarg_omits_payload_manifest_key(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        rec = _make_record(pack_id="rec-manifest-absent")
        await store.save_draft(rec)

        await store.transition(
            pack_id=rec.id,
            transition="submit",
            actor_id="t2-author",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-t2-manifest-absent",
            # payload_manifest omitted
        )

        payload = await _read_last_payload(engine)
        assert "manifest" not in payload


# ===========================================================================
# Section C — override_event_id kwarg behaviour (R2 P2 #3)
# ===========================================================================


class TestSprint7B3T2OverrideEventIdKwarg:
    """``override_event_id`` kwarg threads into ``payload["override_event_id"]``
    when non-None; correlation seam for the override-then-approve
    two-event pattern per ADR-012 §107."""

    async def test_non_none_kwarg_writes_override_event_id_key(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        rec = _make_record(pack_id="rec-override-present", state="under_review")
        async with engine.begin() as conn:
            from cognic_agentos.packs.storage import _packs

            await conn.execute(
                _packs.insert().values(
                    id=rec.id,
                    kind=rec.kind,
                    pack_id=rec.pack_id,
                    display_name=rec.display_name,
                    state=rec.state,
                    manifest_digest=rec.manifest_digest,
                    signed_artefact_digest=rec.signed_artefact_digest,
                    sbom_pointer=rec.sbom_pointer,
                    tenant_id=rec.tenant_id,
                    created_by=rec.created_by,
                    last_actor=rec.last_actor,
                    created_at=rec.created_at,
                    updated_at=rec.updated_at,
                )
            )

        override_id = str(uuid.uuid4())
        await store.transition(
            pack_id=rec.id,
            transition="approve",
            actor_id="t2-reviewer",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-t2-override-present",
            override_event_id=override_id,
        )

        payload = await _read_last_payload(engine)
        assert "override_event_id" in payload
        assert payload["override_event_id"] == override_id

    async def test_none_kwarg_omits_override_event_id_key(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        rec = _make_record(pack_id="rec-override-absent", state="under_review")
        async with engine.begin() as conn:
            from cognic_agentos.packs.storage import _packs

            await conn.execute(
                _packs.insert().values(
                    id=rec.id,
                    kind=rec.kind,
                    pack_id=rec.pack_id,
                    display_name=rec.display_name,
                    state=rec.state,
                    manifest_digest=rec.manifest_digest,
                    signed_artefact_digest=rec.signed_artefact_digest,
                    sbom_pointer=rec.sbom_pointer,
                    tenant_id=rec.tenant_id,
                    created_by=rec.created_by,
                    last_actor=rec.last_actor,
                    created_at=rec.created_at,
                    updated_at=rec.updated_at,
                )
            )

        await store.transition(
            pack_id=rec.id,
            transition="approve",
            actor_id="t2-reviewer",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-t2-override-absent",
            # override_event_id omitted
        )

        payload = await _read_last_payload(engine)
        assert "override_event_id" not in payload


# ===========================================================================
# Section D — signed_artefact_root kwarg behaviour (R6 P2 #4)
# ===========================================================================


class TestSprint7B3T2SignedArtefactRootKwarg:
    """``signed_artefact_root`` kwarg threads into
    ``payload["signed_artefact_root"]`` when non-None; the submit-
    declared absolute path to the bundle directory on the approve-time
    host. Storage stays a thin string passthrough — the route owns
    absolute-path validation (DTO + Pydantic); storage just persists."""

    async def test_non_none_kwarg_writes_signed_artefact_root_key(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        rec = _make_record(pack_id="rec-bundle-root-present")
        await store.save_draft(rec)

        bundle_root = "/var/cognic/bundles/tenant-a/rec-bundle-root-present-1.0.0"
        await store.transition(
            pack_id=rec.id,
            transition="submit",
            actor_id="t2-author",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-t2-bundle-root-present",
            signed_artefact_root=bundle_root,
        )

        payload = await _read_last_payload(engine)
        assert "signed_artefact_root" in payload
        assert payload["signed_artefact_root"] == bundle_root

    async def test_none_kwarg_omits_signed_artefact_root_key(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        rec = _make_record(pack_id="rec-bundle-root-absent")
        await store.save_draft(rec)

        await store.transition(
            pack_id=rec.id,
            transition="submit",
            actor_id="t2-author",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-t2-bundle-root-absent",
            # signed_artefact_root omitted
        )

        payload = await _read_last_payload(engine)
        assert "signed_artefact_root" not in payload


# ===========================================================================
# Cross-section — byte-shape backward-compat invariant
# ===========================================================================


class TestSprint7B3T2BackwardCompatInvariant:
    """User-watchpoint (ii) — omitting ALL 4 new T2 kwargs leaves the
    chain payload byte-identical to a pre-T2 submit-transition row.

    This pins the additive-only contract: every non-T2 caller stays
    compatible without modification. Pre-T2 callers don't pass any of
    the 4 kwargs; default-None paths produce a payload with NONE of
    the 4 new keys."""

    async def test_pre_t2_caller_payload_unchanged(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        rec = _make_record(pack_id="rec-pre-t2-compat")
        await store.save_draft(rec)

        await store.transition(
            pack_id=rec.id,
            transition="submit",
            actor_id="t2-canary",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-t2-compat",
            # No T2 kwargs passed; mimics a pre-T2 caller.
        )

        payload = await _read_last_payload(engine)
        # None of the 4 T2 keys should be present.
        for key in (
            "reviewer_acknowledgement",
            "manifest",
            "override_event_id",
            "signed_artefact_root",
        ):
            assert key not in payload, (
                f"T2 backward-compat broken: omitting all 4 T2 kwargs added "
                f"empty {key!r} key to payload. Expected payload keyset to "
                f"match pre-T2 baseline."
            )
