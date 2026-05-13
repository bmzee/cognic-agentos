"""Sprint 7B.2 T9 — ``transition()`` payload-shape regression matrix.

Pins the exact ``DecisionRecord.payload`` keyset behaviour for the three NEW
optional keyword-only kwargs landed at T9:

- ``payload_conformance: dict[str, Any] | None = None`` — submit-route only;
  populated by ``portal/api/packs/author_routes.py`` with the
  ``dataclasses.asdict(report)`` shape of a :class:`ConformanceReport`.
- ``expected_manifest_digest: bytes | None = None`` — submit-route only;
  race-condition fix per plan §1181 (the row-locked precondition
  cross-checks the row's ``manifest_digest`` against this kwarg, raising
  ``lifecycle_transition_manifest_digest_changed_during_submit`` on
  mismatch).  Locked-precondition regressions live in
  ``test_lifecycle_audit.py::TestSprint7B2T9LockedManifestDigestPrecondition``.
- ``evidence_attachments: dict[str, Any] | None = None`` — reject-route
  (T5 carry-forward) carries categorised reason + reviewer comments;
  storage stays a thin string passthrough (no vocabulary validation —
  shape/closed-enum lives in ``review_routes.py`` tests).

User-watchpoint (ii): **omitted kwargs do NOT add empty keys to
``DecisionRecord.payload``** — keys appear ONLY when their kwarg was
non-None.  This preserves byte-shape compat with every pre-T9 chain row +
every call site that doesn't need the T9 extension surfaces.

Doctrine Lock D — all three kwargs are captured BEFORE the ``_precondition``
closure is defined; no I/O lives inside the closure beyond the SELECT FOR
UPDATE + the cross-check.
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
from cognic_agentos.packs.storage import (
    PackRecord,
    PackRecordStore,
)


@pytest.fixture
async def engine(tmp_path: Any) -> Any:
    url = f"sqlite+aiosqlite:///{tmp_path / 'packs-t9-schema.db'}"
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
        created_by="t9-schema-author",
        last_actor="t9-schema-author",
        created_at=now,
        updated_at=now,
    )


async def _read_last_payload(engine: AsyncEngine) -> dict[str, Any]:
    """Return the JSON-deserialised payload of the most recently appended
    ``decision_history`` row."""
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
# Section A — payload_conformance kwarg behaviour
# ===========================================================================


class TestSprint7B2T9PayloadConformanceKwarg:
    """``payload_conformance`` kwarg threads into ``payload["conformance"]``
    when non-None; omitted (default None) leaves the payload byte-shape
    compatible with every pre-T9 chain row."""

    async def test_non_none_kwarg_writes_payload_conformance_key(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        rec = _make_record(pack_id="rec-conf-present")
        await store.save_draft(rec)

        conformance_dict: dict[str, Any] = {
            "overall_status": "green",
            "results": {},
            "summary": "10 pass / 0 fail / 0 not_applicable",
            "errored_categories": [],
        }
        await store.transition(
            pack_id=rec.id,
            transition="submit",
            actor_id="t9-canary",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-t9-conf-present",
            payload_conformance=conformance_dict,
        )

        payload = await _read_last_payload(engine)
        assert "conformance" in payload
        assert payload["conformance"] == conformance_dict

    async def test_none_kwarg_omits_payload_conformance_key(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        """User watchpoint (ii) — omitted kwarg MUST NOT add an empty
        ``"conformance": None`` / ``"conformance": {}`` entry to the
        payload.  Backward-compat with every non-submit caller."""
        rec = _make_record(pack_id="rec-conf-absent")
        await store.save_draft(rec)

        await store.transition(
            pack_id=rec.id,
            transition="submit",
            actor_id="t9-canary",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-t9-conf-absent",
            # payload_conformance omitted → defaults to None
        )

        payload = await _read_last_payload(engine)
        assert "conformance" not in payload


# ===========================================================================
# Section B — evidence_attachments kwarg behaviour
# ===========================================================================


class TestSprint7B2T9EvidenceAttachmentsKwarg:
    """``evidence_attachments`` kwarg threads into
    ``payload["evidence_attachments"]`` when non-None; omitted (default
    None) leaves no empty key.  Storage is a thin string passthrough —
    no closed-enum vocabulary validation; the reject route owns the
    ``{"rejection_reason", "reviewer_comments"}`` shape contract via
    its own DTO + handler tests."""

    async def test_non_none_kwarg_writes_evidence_attachments_key(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        # Drive a record to under_review so reject is a legal transition.
        rec = _make_record(pack_id="rec-evid-present")
        await store.save_draft(rec)
        for t in ("submit", "claim"):
            await store.transition(
                pack_id=rec.id,
                transition=t,
                actor_id="t9-canary",
                tenant_id=None,
                evidence_pointer=None,
                request_id=f"req-pre-{t}",
            )

        evidence = {
            "rejection_reason": "security_policy_violation",
            "reviewer_comments": "Allow-list not honoured on outbound egress.",
        }
        await store.transition(
            pack_id=rec.id,
            transition="reject",
            actor_id="t9-canary",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-t9-reject-with-evid",
            evidence_attachments=evidence,
        )

        payload = await _read_last_payload(engine)
        assert "evidence_attachments" in payload
        assert payload["evidence_attachments"] == evidence

    async def test_none_kwarg_omits_evidence_attachments_key(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        """User watchpoint (ii) for the reject route — omitted kwarg
        MUST NOT add an empty key to the payload."""
        rec = _make_record(pack_id="rec-evid-absent")
        await store.save_draft(rec)
        for t in ("submit", "claim"):
            await store.transition(
                pack_id=rec.id,
                transition=t,
                actor_id="t9-canary",
                tenant_id=None,
                evidence_pointer=None,
                request_id=f"req-pre-{t}",
            )

        await store.transition(
            pack_id=rec.id,
            transition="reject",
            actor_id="t9-canary",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-t9-reject-no-evid",
            # evidence_attachments omitted → defaults to None
        )

        payload = await _read_last_payload(engine)
        assert "evidence_attachments" not in payload

    async def test_storage_is_thin_passthrough_no_vocabulary_check(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        """``evidence_attachments`` accepts an arbitrary dict; storage
        performs no closed-enum / shape validation.  The portal route's
        DTO + handler tests own the ``{"rejection_reason",
        "reviewer_comments"}`` closed-set contract.  Pinning here so a
        future refactor that tries to push vocabulary checks into
        storage is forced to update this test + revisit the
        ``packs/storage MUST NOT depend on portal/*`` layering."""
        rec = _make_record(pack_id="rec-evid-passthrough")
        await store.save_draft(rec)
        for t in ("submit", "claim"):
            await store.transition(
                pack_id=rec.id,
                transition=t,
                actor_id="t9-canary",
                tenant_id=None,
                evidence_pointer=None,
                request_id=f"req-pre-{t}",
            )

        # Deliberately off-vocabulary keys — storage accepts whatever the
        # caller provides; the wire-shape closed-enum lives at the route.
        weird_evidence = {"arbitrary_key": ["any", "shape"], "n": 42}
        await store.transition(
            pack_id=rec.id,
            transition="reject",
            actor_id="t9-canary",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-t9-reject-weird",
            evidence_attachments=weird_evidence,
        )

        payload = await _read_last_payload(engine)
        assert payload["evidence_attachments"] == weird_evidence


# ===========================================================================
# Section C — combined kwarg shape + canonical-form invariance
# ===========================================================================


class TestSprint7B2T9CombinedPayloadShape:
    """Cross-section: submit transition with BOTH ``payload_conformance``
    AND ``expected_manifest_digest`` matched kwargs lands a chain row with
    the exact canonical T9 keyset on top of the pre-T9 keys (no key
    removed / renamed / re-ordered)."""

    async def test_pre_t9_payload_keys_preserved_alongside_new_optionals(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        rec = _make_record(pack_id="rec-pre-t9-keys")
        await store.save_draft(rec)

        await store.transition(
            pack_id=rec.id,
            transition="submit",
            actor_id="t9-canary",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-t9-combined",
            payload_conformance={
                "overall_status": "green",
                "results": {},
                "summary": "0 pass / 0 fail / 0 not_applicable",
                "errored_categories": [],
            },
            expected_manifest_digest=b"\x01" * 32,
        )

        payload = await _read_last_payload(engine)
        # Pre-T9 keys still present and unchanged.
        pre_t9_keys = {
            "pack_id",
            "kind",
            "from_state",
            "to_state",
            "transition_name",
            "evidence_pointer",
            "iso_controls",
        }
        assert pre_t9_keys <= set(payload.keys())
        # New T9 key present.
        assert "conformance" in payload
        # ``expected_manifest_digest`` is consumed by the locked
        # precondition — NOT persisted into the payload (the digest is
        # already in the persisted ``packs.manifest_digest`` column +
        # the chain row is keyed to the pack via ``pack_id``).
        assert "expected_manifest_digest" not in payload
        assert "manifest_digest" not in payload

    async def test_non_submit_transition_does_not_emit_conformance_key(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        """Non-submit transitions (claim / approve / install / etc.) never
        thread ``payload_conformance`` from their portal handlers; pin
        that the resulting chain rows are pre-T9-byte-compatible."""
        rec = _make_record(pack_id="rec-non-submit")
        await store.save_draft(rec)
        # Walk through submit (no conformance kwarg) + claim.
        for t in ("submit", "claim"):
            await store.transition(
                pack_id=rec.id,
                transition=t,
                actor_id="t9-canary",
                tenant_id=None,
                evidence_pointer=None,
                request_id=f"req-walk-{t}",
            )

        # Read the LAST row (claim).
        payload = await _read_last_payload(engine)
        assert payload["transition_name"] == "claim"
        assert "conformance" not in payload
        assert "evidence_attachments" not in payload
