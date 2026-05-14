"""Sprint 7B.3 T5 Slice B — :meth:`PackRecordStore.load_latest_submit_created_at`
storage seam tests (CRITICAL CONTROLS).

The new storage seam returns the ``created_at`` timestamp of the most
recent submit chain row for a given pack — feeding the 7-year sigstore
bundle retention computation in the T5 supply-chain evidence panel per
ADR-016 §70-72.

Why a NEW method rather than extending the canonical
:class:`~cognic_agentos.core.decision_history.DecisionRecord`:
per AGENTS.md L138 precedent (Sprint 7B.2 T7) — extending the canonical
dataclass with a new field would be a CC-ADJ change to the wire-format
of every chain-row consumer (write path, append hooks, evidence-pack
export). The minimal-surface alternative is a NEW storage method that
queries the existing persisted ``created_at`` column at
:data:`_decision_history.c.created_at` (already there per Sprint 2 —
``Column("created_at", TIMESTAMP(timezone=True), nullable=False)``).

Method contract:

- Returns ``datetime | None`` — None when there is no submit chain row
  for the given pack-id (e.g. pack is in draft state; or pre-submit
  read; or unknown pack-id).
- Filters by ``event_type == "pack.lifecycle.submitted"`` AND
  ``payload['pack_id'] == str(pack_id)`` (same pattern as
  :meth:`load_lifecycle_history` for dialect-portability across PG /
  SQLite / Oracle).
- Returns the MOST-RECENT submit row when multiple exist (re-submit-
  after-withdraw flow per ADR-012 §59 + Sprint 7B.2 T4
  ``cancel_draft``).
- All returned datetimes are timezone-aware (the column type is
  ``TIMESTAMP(timezone=True)``).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.packs.lifecycle import PackKind
from cognic_agentos.packs.storage import PackRecord, PackRecordStore


@pytest.fixture
async def engine(tmp_path: Any) -> AsyncIterator[AsyncEngine]:
    url = f"sqlite+aiosqlite:///{tmp_path / 'latest_submit.db'}"
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


def _build_pack_record(*, kind: PackKind = "tool", tenant_id: str = "t1") -> PackRecord:
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
        created_by="bob@bank.example",
        last_actor="bob@bank.example",
        created_at=now,
        updated_at=now,
    )


class TestSprint7B3T5SliceBLoadLatestSubmitCreatedAt:
    """Pin the new :meth:`PackRecordStore.load_latest_submit_created_at`
    storage seam contract."""

    async def test_returns_none_for_unknown_pack_id(self, store: PackRecordStore) -> None:
        """An unknown pack-id returns None (no chain rows exist for
        it — the projector treats this as 'no submit row' and surfaces
        retention=None)."""
        result = await store.load_latest_submit_created_at(uuid.uuid4())
        assert result is None

    async def test_returns_none_for_draft_state_pack(self, store: PackRecordStore) -> None:
        """A pack in draft state has no submit chain row — method
        returns None (matches the 409 ``pack_not_yet_submitted``
        refusal at the route layer)."""
        record = _build_pack_record()
        await store.save_draft(record)
        # Note: save_draft does NOT emit a chain row.
        result = await store.load_latest_submit_created_at(record.id)
        assert result is None

    async def test_returns_submit_row_created_at_for_submitted_pack(
        self, store: PackRecordStore
    ) -> None:
        """A submitted pack returns the persisted ``created_at`` of
        the submit chain row."""
        record = _build_pack_record()
        await store.save_draft(record)
        before_submit = datetime.now(UTC)
        await store.transition(
            pack_id=record.id,
            transition="submit",
            actor_id="bob@bank.example",
            tenant_id="t1",
            evidence_pointer=None,
            request_id=f"submit-{record.id.hex[:8]}",
        )
        after_submit = datetime.now(UTC)
        result = await store.load_latest_submit_created_at(record.id)
        assert result is not None
        # The persisted timestamp lives between our two wall-clock
        # reads; pin the bracket relation rather than an exact match
        # (the chain-row INSERT mints its own ``datetime.now(UTC)``
        # inside the engine.begin() block per core/decision_history.py).
        assert before_submit <= result <= after_submit

    async def test_returns_timezone_aware_datetime(self, store: PackRecordStore) -> None:
        """The returned datetime MUST be timezone-aware — the
        ``TIMESTAMP(timezone=True)`` column type guarantees this on
        write, and the read path must preserve the tzinfo. Defends
        against a future regression that strips tzinfo via implicit
        ``datetime.replace(tzinfo=None)``."""
        record = _build_pack_record()
        await store.save_draft(record)
        await store.transition(
            pack_id=record.id,
            transition="submit",
            actor_id="bob@bank.example",
            tenant_id="t1",
            evidence_pointer=None,
            request_id=f"submit-{record.id.hex[:8]}",
        )
        result = await store.load_latest_submit_created_at(record.id)
        assert result is not None
        assert result.tzinfo is not None

    async def test_filters_to_pack_id_does_not_leak_other_packs(
        self, store: PackRecordStore
    ) -> None:
        """Tenant-isolation defence-in-depth: even when two packs are
        submitted, the method returns ONLY the queried pack's row.
        Closes the cross-pack leak class at the storage layer."""
        record_a = _build_pack_record()
        record_b = _build_pack_record()
        await store.save_draft(record_a)
        await store.save_draft(record_b)
        await store.transition(
            pack_id=record_a.id,
            transition="submit",
            actor_id="bob@bank.example",
            tenant_id="t1",
            evidence_pointer=None,
            request_id=f"submit-a-{record_a.id.hex[:8]}",
        )
        await store.transition(
            pack_id=record_b.id,
            transition="submit",
            actor_id="bob@bank.example",
            tenant_id="t1",
            evidence_pointer=None,
            request_id=f"submit-b-{record_b.id.hex[:8]}",
        )
        result_a = await store.load_latest_submit_created_at(record_a.id)
        result_b = await store.load_latest_submit_created_at(record_b.id)
        assert result_a is not None
        assert result_b is not None
        # Both packs got submits; their timestamps SHOULD differ
        # (sequentially-minted ``datetime.now(UTC)`` in
        # core/decision_history.py); but more importantly each query
        # gets ONLY its own pack's row.
        assert result_a != result_b

    async def test_query_orders_by_sequence_desc_for_most_recent_first(
        self, store: PackRecordStore
    ) -> None:
        """Defence-in-depth assertion: the production query MUST order
        by ``sequence DESC`` so the helper always returns the MOST
        RECENT submit when multiple exist.

        The current state machine only permits a single submit per
        pack lifetime (per ``packs/lifecycle.py:221`` —
        ``submit: draft → submitted``; no path returns to ``draft``
        from any other state). The ORDER BY DESC clause is therefore
        defensive against a future state-machine extension that would
        permit multiple submits per pack — the helper's contract
        promises "most recent" semantics regardless of the table's
        natural insertion order.

        Pin the SELECT shape by AST scan of the source module rather
        than a multi-submit fixture (which cannot be constructed in
        the current state machine)."""
        import inspect

        from cognic_agentos.packs.storage import PackRecordStore as _store_module

        source = inspect.getsource(_store_module.load_latest_submit_created_at)
        # The ORDER BY clause is the load-bearing guarantee; pin its
        # presence + DESC ordering. A future regression that drops
        # ``.desc()`` or replaces ``sequence`` would silently shift
        # semantics.
        assert ".order_by(" in source
        assert "sequence.desc()" in source
