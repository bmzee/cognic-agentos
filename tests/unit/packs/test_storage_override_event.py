"""Sprint 7B.3 T8 — ``PackRecordStore.append_override_event`` regression matrix.

``append_override_event`` emits a ``pack.approval_override`` chain event
recording a privileged reviewer's ADR-012 §107 force-approve authorisation.
Unlike ``transition()`` it uses the plain ``DecisionHistoryStore.append``
API (NOT ``append_with_precondition``) — an override is NOT a lifecycle
state-machine transition, so there is no precondition closure and no
``packs.state`` cache mutation; the chain-head row-lock provides canonical
ordering only.

Pins (plan §421-433):

- Return type ``OverrideEventAppendResult(record_id, chain_hash)`` — a
  frozen dataclass carrying the ``(uuid, bytes)`` pair ``append`` returns
  (NOT a ``DecisionRecord`` — the live model has no persisted id field).
- Chain row ``decision_type`` = ``pack.approval_override`` verbatim;
  ISO control = ``A.6.2.4`` (governance overrides); payload is the
  explicit 5-key shape ``{pack_id, actor_subject, override_reason,
  gate_composition_snapshot, outcome}`` with ``outcome == "authorized"``
  (R14 P2 — ``pack_id`` added so the dangling-override row stays
  pack-linkable; persisted as ``str(pack_id)``).
- ``gate_composition_snapshot`` (built via
  :func:`cognic_agentos.packs.approval_gates.composition_snapshot`)
  survives the ``core.canonical.canonical_bytes`` round-trip — the
  load-bearing test for the list/sorted-list conversion.
- R3 P2 #4 dangling-override audit design — the override event remains
  in the chain even when the subsequent approve transition refuses;
  the override authorisation IS the audit fact being recorded.
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
from cognic_agentos.packs.approval_gates import (
    AdversarialGateInput,
    EvaluationGateInput,
    OwaspGateInput,
    SignatureGateInput,
    compose_approval_gates,
    composition_snapshot,
)
from cognic_agentos.packs.lifecycle import LifecycleTransitionRefused, PackKind, PackState
from cognic_agentos.packs.storage import (
    OverrideEventAppendResult,
    PackRecord,
    PackRecordStore,
)


@pytest.fixture
async def engine(tmp_path: Any) -> Any:
    url = f"sqlite+aiosqlite:///{tmp_path / 'packs-override-event.db'}"
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
    pack_id: str = "override-pack",
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
        created_by="override-author",
        last_actor="override-author",
        created_at=now,
        updated_at=now,
    )


def _realistic_snapshot() -> dict[str, Any]:
    """A canonical-safe snapshot of a not-all-green composition (gate 2
    ``evidence_not_attached``, gates 1/3/4/5 green) — the shape the T9
    override path passes into ``append_override_event``."""
    composition = compose_approval_gates(
        signature_input=SignatureGateInput(
            outcome="green", red_reason=None, signature_digest="a" * 64
        ),
        evaluation_input=EvaluationGateInput(
            outcome="evidence_not_attached",
            red_reason="evaluation_evidence_not_attached",
            pass_rate=None,
            threshold=None,
        ),
        adversarial_input=AdversarialGateInput(
            outcome="green", red_reason=None, pass_rate=1.0, high_severity_failures=0
        ),
        owasp_input=OwaspGateInput(outcome="green", red_reason=None, owasp_overall_status="green"),
        pack_kind="tool",
        reviewer_acknowledgement={
            "data_governance_acknowledged": True,
            "risk_tier_acknowledged": True,
            "supply_chain_acknowledged": True,
            "conformance_acknowledged": True,
        },
    )
    return composition_snapshot(composition)


async def _read_all_rows(engine: AsyncEngine) -> list[Any]:
    async with engine.connect() as conn:
        rows = (
            await conn.execute(
                select(
                    _dh.c.record_id,
                    _dh.c.event_type,
                    _dh.c.iso_controls,
                    _dh.c.payload,
                    _dh.c.sequence,
                    _dh.c.request_id,
                ).order_by(_dh.c.sequence)
            )
        ).all()
    return list(rows)


def _decode(raw: Any) -> Any:
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        return json.loads(raw)
    return raw


# ===========================================================================
# Section A — return type + chain-row shape
# ===========================================================================


class TestSprint7B3T8AppendOverrideEventReturnAndShape:
    async def test_returns_override_event_append_result(self, store: PackRecordStore) -> None:
        result = await store.append_override_event(
            pack_id=uuid.uuid4(),
            override_actor_subject="reviewer-alice",
            override_reason="security_exception",
            gate_composition_snapshot=_realistic_snapshot(),
            request_id="override-req-1",
        )
        assert isinstance(result, OverrideEventAppendResult)

    async def test_record_id_is_valid_uuid(self, store: PackRecordStore) -> None:
        result = await store.append_override_event(
            pack_id=uuid.uuid4(),
            override_actor_subject="reviewer-alice",
            override_reason="prerelease_validation",
            gate_composition_snapshot=_realistic_snapshot(),
            request_id="override-req-2",
        )
        assert isinstance(result.record_id, uuid.UUID)

    async def test_chain_hash_is_canonical_32_bytes(self, store: PackRecordStore) -> None:
        result = await store.append_override_event(
            pack_id=uuid.uuid4(),
            override_actor_subject="reviewer-alice",
            override_reason="legacy_grandfather",
            gate_composition_snapshot=_realistic_snapshot(),
            request_id="override-req-3",
        )
        assert isinstance(result.chain_hash, bytes)
        assert len(result.chain_hash) == 32

    async def test_chain_row_decision_type_is_pack_approval_override(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        await store.append_override_event(
            pack_id=uuid.uuid4(),
            override_actor_subject="reviewer-alice",
            override_reason="other",
            gate_composition_snapshot=_realistic_snapshot(),
            request_id="override-req-4",
        )
        rows = await _read_all_rows(engine)
        assert len(rows) == 1
        assert rows[0].event_type == "pack.approval_override"

    async def test_chain_row_iso_control_is_a624(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        await store.append_override_event(
            pack_id=uuid.uuid4(),
            override_actor_subject="reviewer-alice",
            override_reason="security_exception",
            gate_composition_snapshot=_realistic_snapshot(),
            request_id="override-req-5",
        )
        rows = await _read_all_rows(engine)
        assert _decode(rows[0].iso_controls) == ["A.6.2.4"]

    async def test_payload_is_exact_five_key_shape(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        await store.append_override_event(
            pack_id=uuid.uuid4(),
            override_actor_subject="reviewer-bob",
            override_reason="security_exception",
            gate_composition_snapshot=_realistic_snapshot(),
            request_id="override-req-6",
        )
        rows = await _read_all_rows(engine)
        payload = _decode(rows[0].payload)
        assert set(payload.keys()) == {
            "pack_id",
            "actor_subject",
            "override_reason",
            "gate_composition_snapshot",
            "outcome",
        }

    async def test_payload_carries_pack_id(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        """The override event MUST be pack-linkable — under the R3 P2 #4
        dangling-override audit design the surviving override row is the
        only record of the authorisation, so examiners must be able to
        trace it back to a pack. ``pack_id`` is persisted as ``str(...)``,
        mirroring ``transition()``'s ``_build_record`` payload contract."""
        pack_id = uuid.uuid4()
        await store.append_override_event(
            pack_id=pack_id,
            override_actor_subject="reviewer-bob",
            override_reason="security_exception",
            gate_composition_snapshot=_realistic_snapshot(),
            request_id="override-req-pack-id",
        )
        rows = await _read_all_rows(engine)
        payload = _decode(rows[0].payload)
        assert payload["pack_id"] == str(pack_id)

    async def test_payload_outcome_is_authorized(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        await store.append_override_event(
            pack_id=uuid.uuid4(),
            override_actor_subject="reviewer-bob",
            override_reason="other",
            gate_composition_snapshot=_realistic_snapshot(),
            request_id="override-req-7",
        )
        rows = await _read_all_rows(engine)
        payload = _decode(rows[0].payload)
        assert payload["outcome"] == "authorized"

    async def test_payload_carries_override_reason_and_actor_verbatim(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        await store.append_override_event(
            pack_id=uuid.uuid4(),
            override_actor_subject="reviewer-carol",
            override_reason="prerelease_validation",
            gate_composition_snapshot=_realistic_snapshot(),
            request_id="override-req-8",
        )
        rows = await _read_all_rows(engine)
        payload = _decode(rows[0].payload)
        # The closed-enum value verbatim — no synonym substitution.
        assert payload["override_reason"] == "prerelease_validation"
        assert payload["actor_subject"] == "reviewer-carol"

    async def test_payload_carries_gate_composition_snapshot(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        snapshot = _realistic_snapshot()
        await store.append_override_event(
            pack_id=uuid.uuid4(),
            override_actor_subject="reviewer-carol",
            override_reason="security_exception",
            gate_composition_snapshot=snapshot,
            request_id="override-req-9",
        )
        rows = await _read_all_rows(engine)
        payload = _decode(rows[0].payload)
        assert payload["gate_composition_snapshot"] == snapshot

    async def test_request_id_threads_to_chain_row(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        await store.append_override_event(
            pack_id=uuid.uuid4(),
            override_actor_subject="reviewer-carol",
            override_reason="other",
            gate_composition_snapshot=_realistic_snapshot(),
            request_id="override-req-10",
        )
        rows = await _read_all_rows(engine)
        assert rows[0].request_id == "override-req-10"


# ===========================================================================
# Section B — canonical-form survival (the load-bearing snapshot test)
# ===========================================================================


class TestSprint7B3T8GateCompositionSnapshotCanonicalSurvival:
    """``composition_snapshot`` output must survive ``canonical_bytes`` —
    a raw ``dataclasses.asdict`` would leave ``gates`` a tuple +
    ``non_overridable_red_gates`` a frozenset, both rejected by the
    canonical-form gate inside ``DecisionHistoryStore.append``."""

    async def test_red_signature_snapshot_appends_without_error(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        # A red-signature composition exercises BOTH the tuple ``gates``
        # field AND the non-empty frozenset ``non_overridable_red_gates``.
        composition = compose_approval_gates(
            signature_input=SignatureGateInput(
                outcome="red",
                red_reason="signature_cosign_verify_failed",
                signature_digest=None,
            ),
            evaluation_input=EvaluationGateInput(
                outcome="evidence_not_attached",
                red_reason="evaluation_evidence_not_attached",
                pass_rate=None,
                threshold=None,
            ),
            adversarial_input=AdversarialGateInput(
                outcome="green", red_reason=None, pass_rate=1.0, high_severity_failures=0
            ),
            owasp_input=OwaspGateInput(
                outcome="green", red_reason=None, owasp_overall_status="green"
            ),
            pack_kind="agent",
            reviewer_acknowledgement={
                "data_governance_acknowledged": True,
                "risk_tier_acknowledged": True,
                "supply_chain_acknowledged": True,
                "conformance_acknowledged": True,
            },
        )
        snapshot = composition_snapshot(composition)
        # No raise → the list/sorted-list conversion is load-bearing.
        result = await store.append_override_event(
            pack_id=uuid.uuid4(),
            override_actor_subject="reviewer-dave",
            override_reason="security_exception",
            gate_composition_snapshot=snapshot,
            request_id="override-req-canon",
        )
        assert len(result.chain_hash) == 32
        rows = await _read_all_rows(engine)
        persisted = _decode(rows[0].payload)["gate_composition_snapshot"]
        assert persisted["non_overridable_red_gates"] == ["signature"]
        assert isinstance(persisted["gates"], list)


# ===========================================================================
# Section C — concurrent appends + dangling-override audit design
# ===========================================================================


class TestSprint7B3T8SequencingAndDanglingOverride:
    async def test_sequential_override_appends_get_distinct_sequences(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        """Back-to-back ``append_override_event`` calls land as distinct
        chain rows with distinct ``record_id``s and monotonically
        increasing ``sequence`` (1, then 2) — the hermetic SQLite proof
        that the override seam appends to the canonical chain correctly.

        The REAL concurrent-lock serialisation proof lives upstream:
        ``append_override_event`` is a thin wrapper over
        ``DecisionHistoryStore.append``, whose chain-head ``SELECT FOR
        UPDATE`` serialisation is proven on live Postgres + Oracle by
        Sprint 2 T12's ``tests/integration/db/test_concurrent_append.py``.
        The override seam adds NO new locking behaviour, so it needs no
        separate integration canary (SQLite cannot prove locking — see
        ``core/decision_history.py`` class docstring)."""
        first = await store.append_override_event(
            pack_id=uuid.uuid4(),
            override_actor_subject="reviewer-a",
            override_reason="security_exception",
            gate_composition_snapshot=_realistic_snapshot(),
            request_id="override-seq-1",
        )
        second = await store.append_override_event(
            pack_id=uuid.uuid4(),
            override_actor_subject="reviewer-b",
            override_reason="other",
            gate_composition_snapshot=_realistic_snapshot(),
            request_id="override-seq-2",
        )
        assert first.record_id != second.record_id
        rows = await _read_all_rows(engine)
        assert len(rows) == 2
        assert [r.sequence for r in rows] == [1, 2]

    async def test_dangling_override_when_approve_transition_refuses(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        """R3 P2 #4 dangling-override audit design — the override event
        is the reviewer's authorisation fact; it stays in the chain even
        when the subsequent approve transition refuses (here: the pack is
        in ``draft``, so ``approve`` is an illegal state pair). Examiners
        read the chain as 'reviewer authorised override at T1; approve did
        not complete'."""
        record = _make_record(pack_id="dangling-pack", state="draft")
        pack_id = await store.save_draft(record)

        await store.append_override_event(
            pack_id=pack_id,
            override_actor_subject="reviewer-eve",
            override_reason="security_exception",
            gate_composition_snapshot=_realistic_snapshot(),
            request_id="override-dangling",
        )
        rows_before = await _read_all_rows(engine)
        assert [r.event_type for r in rows_before] == ["pack.approval_override"]

        # approve from draft is an illegal state pair → refused.
        with pytest.raises(LifecycleTransitionRefused):
            await store.transition(
                pack_id=pack_id,
                transition="approve",
                actor_id="reviewer-eve",
                tenant_id=None,
                evidence_pointer=None,
                request_id="approve-after-override",
            )

        rows_after = await _read_all_rows(engine)
        # The override event REMAINS; no pack.lifecycle.approved row exists.
        assert [r.event_type for r in rows_after] == ["pack.approval_override"]
        # ...and the surviving dangling-override row is still pack-linkable:
        # examiners can trace the orphan authorisation back to its pack.
        dangling_payload = _decode(rows_after[0].payload)
        assert dangling_payload["pack_id"] == str(pack_id)

    async def test_append_override_event_does_not_mutate_pack_state(
        self, store: PackRecordStore
    ) -> None:
        """An override is NOT a lifecycle transition — ``append_override_event``
        writes only the chain row, never the ``packs.state`` cache."""
        record = _make_record(pack_id="state-untouched-pack", state="draft")
        pack_id = await store.save_draft(record)

        await store.append_override_event(
            pack_id=pack_id,
            override_actor_subject="reviewer-frank",
            override_reason="other",
            gate_composition_snapshot=_realistic_snapshot(),
            request_id="override-state-check",
        )
        reloaded = await store.load(pack_id)
        assert reloaded is not None
        assert reloaded.state == "draft"
