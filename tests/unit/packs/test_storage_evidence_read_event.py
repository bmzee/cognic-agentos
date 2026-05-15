"""Sprint 7B.3 T10 — ``PackRecordStore.append_evidence_read_event`` regression matrix.

``append_evidence_read_event`` emits a ``pack.evidence_read.<panel_name>``
chain event recording a reviewer's access to one of the four evidence
panels (ADR-012 §638 panel-access audit). Like ``append_override_event``
it uses the plain ``DecisionHistoryStore.append`` API (NOT
``append_with_precondition``) — a panel read is NOT a lifecycle
state-machine transition, so there is no precondition closure and no
``packs.state`` cache mutation; the chain-head row-lock provides
canonical ordering only.

Pins (plan §533-566 + R17 patches):

- Return type ``EvidenceReadEventAppendResult(record_id, chain_hash)`` —
  a frozen dataclass carrying the ``(uuid, bytes)`` pair ``append``
  returns (mirrors ``OverrideEventAppendResult`` shape).
- Chain row ``decision_type`` = ``f"pack.evidence_read.{panel_name}"``
  (4 possible values from the closed-enum 4-value ``EvidencePanelName``
  Literal); ISO control = ``A.5.31`` (audit logs) pinned DIRECTLY (NOT
  derived via ``iso_controls_for`` — a panel read is not a transition).
- Payload is the explicit 4-key shape ``{actor_subject, pack_id,
  panel_name, requested_at}`` — no manifest content, no sensitive
  data-class values; ``requested_at`` is an ISO 8601 timestamp.
- **R17 P2 #2** — ``tenant_id`` threads to the ``DecisionRecord.tenant_id``
  dataclass field (DB column ``decision_history.tenant_id``), NOT the
  payload dict. ``append_evidence_read_event`` is the first pack
  chain-writing seam to populate that column.
- **R17 P2 #1** — ``request_id`` is a caller-minted keyword-only param
  (``DecisionRecord.request_id`` is required; the route handler mints it).
"""

from __future__ import annotations

import json
import typing
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
    EvidencePanelName,
    EvidenceReadEventAppendResult,
    PackRecord,
    PackRecordStore,
)

_ALL_PANELS: tuple[EvidencePanelName, ...] = (
    "data_governance",
    "risk_tier",
    "supply_chain",
    "conformance_matrix",
)


@pytest.fixture
async def engine(tmp_path: Any) -> Any:
    url = f"sqlite+aiosqlite:///{tmp_path / 'packs-evidence-read.db'}"
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
    pack_id: str = "evidence-read-pack",
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
        created_by="evidence-read-author",
        last_actor="evidence-read-author",
        created_at=now,
        updated_at=now,
    )


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
                    _dh.c.tenant_id,
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
# Section A — closed-enum vocabulary
# ===========================================================================


class TestSprint7B3T10EvidencePanelNameVocabulary:
    def test_evidence_panel_name_has_exactly_four_values(self) -> None:
        assert set(typing.get_args(EvidencePanelName)) == {
            "data_governance",
            "risk_tier",
            "supply_chain",
            "conformance_matrix",
        }


# ===========================================================================
# Section B — return type + chain-row shape
# ===========================================================================


class TestSprint7B3T10AppendEvidenceReadEventReturnAndShape:
    async def test_returns_evidence_read_event_append_result(self, store: PackRecordStore) -> None:
        result = await store.append_evidence_read_event(
            pack_id=uuid.uuid4(),
            actor_subject="reviewer-alice",
            panel_name="data_governance",
            tenant_id="t1",
            request_id="evidence-read-req-1",
        )
        assert isinstance(result, EvidenceReadEventAppendResult)

    async def test_record_id_is_valid_uuid(self, store: PackRecordStore) -> None:
        result = await store.append_evidence_read_event(
            pack_id=uuid.uuid4(),
            actor_subject="reviewer-alice",
            panel_name="risk_tier",
            tenant_id="t1",
            request_id="evidence-read-req-2",
        )
        assert isinstance(result.record_id, uuid.UUID)

    async def test_chain_hash_is_canonical_32_bytes(self, store: PackRecordStore) -> None:
        result = await store.append_evidence_read_event(
            pack_id=uuid.uuid4(),
            actor_subject="reviewer-alice",
            panel_name="supply_chain",
            tenant_id="t1",
            request_id="evidence-read-req-3",
        )
        assert isinstance(result.chain_hash, bytes)
        assert len(result.chain_hash) == 32

    @pytest.mark.parametrize("panel_name", _ALL_PANELS)
    async def test_chain_row_decision_type_is_panel_namespaced(
        self, store: PackRecordStore, engine: AsyncEngine, panel_name: EvidencePanelName
    ) -> None:
        await store.append_evidence_read_event(
            pack_id=uuid.uuid4(),
            actor_subject="reviewer-alice",
            panel_name=panel_name,
            tenant_id="t1",
            request_id=f"evidence-read-{panel_name}",
        )
        rows = await _read_all_rows(engine)
        assert len(rows) == 1
        assert rows[0].event_type == f"pack.evidence_read.{panel_name}"

    async def test_chain_row_iso_control_is_a531(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        await store.append_evidence_read_event(
            pack_id=uuid.uuid4(),
            actor_subject="reviewer-alice",
            panel_name="conformance_matrix",
            tenant_id="t1",
            request_id="evidence-read-req-iso",
        )
        rows = await _read_all_rows(engine)
        assert _decode(rows[0].iso_controls) == ["A.5.31"]

    async def test_payload_is_exact_four_key_shape(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        await store.append_evidence_read_event(
            pack_id=uuid.uuid4(),
            actor_subject="reviewer-bob",
            panel_name="data_governance",
            tenant_id="t1",
            request_id="evidence-read-req-shape",
        )
        rows = await _read_all_rows(engine)
        payload = _decode(rows[0].payload)
        assert set(payload.keys()) == {
            "actor_subject",
            "pack_id",
            "panel_name",
            "requested_at",
        }

    async def test_payload_carries_pack_id_as_str(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        pack_id = uuid.uuid4()
        await store.append_evidence_read_event(
            pack_id=pack_id,
            actor_subject="reviewer-bob",
            panel_name="risk_tier",
            tenant_id="t1",
            request_id="evidence-read-req-pack-id",
        )
        rows = await _read_all_rows(engine)
        payload = _decode(rows[0].payload)
        assert payload["pack_id"] == str(pack_id)

    @pytest.mark.parametrize("panel_name", _ALL_PANELS)
    async def test_payload_carries_panel_name_verbatim(
        self, store: PackRecordStore, engine: AsyncEngine, panel_name: EvidencePanelName
    ) -> None:
        await store.append_evidence_read_event(
            pack_id=uuid.uuid4(),
            actor_subject="reviewer-bob",
            panel_name=panel_name,
            tenant_id="t1",
            request_id=f"evidence-read-verbatim-{panel_name}",
        )
        rows = await _read_all_rows(engine)
        payload = _decode(rows[0].payload)
        assert payload["panel_name"] == panel_name

    async def test_payload_carries_actor_subject_verbatim(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        await store.append_evidence_read_event(
            pack_id=uuid.uuid4(),
            actor_subject="reviewer-carol@bank.example",
            panel_name="supply_chain",
            tenant_id="t1",
            request_id="evidence-read-req-actor",
        )
        rows = await _read_all_rows(engine)
        payload = _decode(rows[0].payload)
        assert payload["actor_subject"] == "reviewer-carol@bank.example"

    async def test_payload_requested_at_is_iso8601_parseable(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        await store.append_evidence_read_event(
            pack_id=uuid.uuid4(),
            actor_subject="reviewer-carol",
            panel_name="data_governance",
            tenant_id="t1",
            request_id="evidence-read-req-ts",
        )
        rows = await _read_all_rows(engine)
        payload = _decode(rows[0].payload)
        # Round-trips through datetime.fromisoformat → it is a valid
        # ISO 8601 timestamp; tz-aware (the seam stamps UTC).
        parsed = datetime.fromisoformat(payload["requested_at"])
        assert parsed.tzinfo is not None

    async def test_request_id_threads_to_chain_row(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        await store.append_evidence_read_event(
            pack_id=uuid.uuid4(),
            actor_subject="reviewer-carol",
            panel_name="risk_tier",
            tenant_id="t1",
            request_id="evidence-read-req-threads",
        )
        rows = await _read_all_rows(engine)
        assert rows[0].request_id == "evidence-read-req-threads"


# ===========================================================================
# Section C — R17 P2 #2: tenant_id threads to the DecisionRecord column
# ===========================================================================


class TestSprint7B3T10TenantIdOnChainColumn:
    async def test_tenant_id_threads_to_decision_history_column(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        """R17 P2 #2 — ``tenant_id`` lands on the ``decision_history.tenant_id``
        first-class column (via ``DecisionRecord.tenant_id``), making the
        chain row tenant-scoped for examiner traceability."""
        await store.append_evidence_read_event(
            pack_id=uuid.uuid4(),
            actor_subject="reviewer-dave",
            panel_name="conformance_matrix",
            tenant_id="tenant-alpha",
            request_id="evidence-read-req-tenant-col",
        )
        rows = await _read_all_rows(engine)
        assert rows[0].tenant_id == "tenant-alpha"

    async def test_tenant_id_is_not_duplicated_into_payload(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        """R17 P2 #2 — the tenant boundary belongs on the chain row's
        first-class column, NOT duplicated into the payload dict (the
        explicit 4-key payload shape carries no ``tenant_id`` key)."""
        await store.append_evidence_read_event(
            pack_id=uuid.uuid4(),
            actor_subject="reviewer-dave",
            panel_name="supply_chain",
            tenant_id="tenant-beta",
            request_id="evidence-read-req-no-payload-tenant",
        )
        rows = await _read_all_rows(engine)
        payload = _decode(rows[0].payload)
        assert "tenant_id" not in payload


# ===========================================================================
# Section D — sequencing + pure-chain-write (no state mutation)
# ===========================================================================


class TestSprint7B3T10SequencingAndPurity:
    async def test_sequential_appends_get_distinct_sequences(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        """Back-to-back ``append_evidence_read_event`` calls land as
        distinct chain rows with distinct ``record_id``s and monotonically
        increasing ``sequence`` — the hermetic SQLite proof that the seam
        appends to the canonical chain correctly. The real concurrent-lock
        serialisation proof lives upstream in Sprint 2 T12's integration
        canary; this seam is a thin wrapper over ``DecisionHistoryStore.append``
        and adds NO new locking behaviour."""
        first = await store.append_evidence_read_event(
            pack_id=uuid.uuid4(),
            actor_subject="reviewer-a",
            panel_name="data_governance",
            tenant_id="t1",
            request_id="evidence-read-seq-1",
        )
        second = await store.append_evidence_read_event(
            pack_id=uuid.uuid4(),
            actor_subject="reviewer-b",
            panel_name="risk_tier",
            tenant_id="t1",
            request_id="evidence-read-seq-2",
        )
        assert first.record_id != second.record_id
        rows = await _read_all_rows(engine)
        assert len(rows) == 2
        assert [r.sequence for r in rows] == [1, 2]

    async def test_append_evidence_read_event_does_not_mutate_pack_state(
        self, store: PackRecordStore
    ) -> None:
        """A panel read is NOT a lifecycle transition —
        ``append_evidence_read_event`` writes only the chain row, never the
        ``packs.state`` cache."""
        record = _make_record(pack_id="state-untouched-pack", state="draft")
        pack_id = await store.save_draft(record)

        await store.append_evidence_read_event(
            pack_id=pack_id,
            actor_subject="reviewer-frank",
            panel_name="conformance_matrix",
            tenant_id="t1",
            request_id="evidence-read-state-check",
        )
        reloaded = await store.load(pack_id)
        assert reloaded is not None
        assert reloaded.state == "draft"
