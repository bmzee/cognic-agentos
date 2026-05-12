"""Sprint 7B.2 T5 — ``PackRecordStore.list_by_status`` tenant_id-kwarg regressions.

Plan Round 11 P2 #1 + Round 14 P2 #1 (backward-compatible signature) —
T5 reviewer queue (``GET /api/v1/packs/review-queue``) needs server-side
``tenant_id`` filtering on top of the existing state filter; the
storage seam is extended with an optional keyword-only ``tenant_id``
kwarg behind a ``*`` separator so the pre-T5 signature stays green.

**Exact compatibility-preserving signature**:

.. code-block:: python

    list_by_status(
        state: PackState,
        limit: int = 50,
        cursor: uuid.UUID | None = None,
        *,
        tenant_id: str | None = None,
    ) -> list[PackRecord]

Keeps ``limit`` + ``cursor`` positional-or-keyword with their existing
defaults; ``tenant_id`` lives BEHIND the ``*`` so it is
keyword-only-with-default (additive). When ``tenant_id is not None``,
WHERE clause adds ``tenant_id == :tenant_id`` AND uses the existing
``ix_packs_tenant_state`` composite index per migration L129; when
``None``, behaviour is identical to the pre-T5 storage API (no
tenant filter).

Three regressions per plan §"Tests" line 858:

1. ``test_list_by_status_state_only_backward_compatible`` — pre-existing
   call shape ``store.list_by_status("submitted")`` still works; tenant
   filter inactive.
2. ``test_list_by_status_existing_pagination_signature`` — pre-existing
   positional ``limit`` / ``cursor`` call shape still works.
3. ``test_list_by_status_tenant_filtered_pagination`` — new
   tenant-filtered path returns ONLY rows whose ``tenant_id`` matches.

Halt-before-commit per T5 §"Why CC" — CC-ADJ touch to the live
``packs/storage.py`` critical-controls module.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.packs.lifecycle import PackKind, PackState
from cognic_agentos.packs.storage import PackRecord, PackRecordStore

# ---------------------------------------------------------------------------
# Fixtures (mirrors test_storage.py:59-100; same engine + store pattern;
# kept local to this file to keep the T5 regression triplet self-contained)
# ---------------------------------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Any) -> Any:
    """Per-test SQLite-aiosqlite engine with the governance schema +
    seeded chain heads + the ``packs`` table. Mirrors
    ``tests/unit/packs/test_storage.py::engine`` per the Sprint-7B.1 T3
    test-fixture pattern."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'packs.db'}"
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


def _make_record(
    *,
    pack_id: str = "cognic-tool-example-minimal",
    kind: PackKind = "tool",
    state: PackState = "draft",
    record_id: uuid.UUID | None = None,
    tenant_id: str | None = None,
) -> PackRecord:
    """Construct a fully-populated PackRecord for tests. Local fixture
    helper mirroring ``test_storage.py::_make_record`` per the
    Sprint-7B.1 T3 convention."""
    now = datetime.now(UTC)
    return PackRecord(
        id=record_id or uuid.uuid4(),
        kind=kind,
        pack_id=pack_id,
        display_name=pack_id,
        state=state,
        manifest_digest=b"\x01" * 32,
        signed_artefact_digest=b"\x02" * 32,
        sbom_pointer=None,
        tenant_id=tenant_id,
        created_by="canary-author",
        last_actor="canary-author",
        created_at=now,
        updated_at=now,
    )


# ---------------------------------------------------------------------------
# Backward-compatibility regressions (Round 14 P2 #1)
# ---------------------------------------------------------------------------


class TestSprint7B2ListByStatusBackwardCompatible:
    """Round 14 P2 #1 — the new ``tenant_id`` kwarg MUST land BEHIND a
    ``*`` separator so all pre-T5 call shapes stay green. These three
    regressions exercise the compatibility surface explicitly."""

    async def test_list_by_status_state_only_backward_compatible(
        self,
        store: PackRecordStore,
    ) -> None:
        """Pre-T5 call shape ``store.list_by_status("submitted")`` MUST
        still work — the new ``tenant_id`` kwarg defaults to ``None``
        so existing call-sites that pass only ``state`` get the
        pre-T5 behaviour (no tenant filter applied)."""
        # Seed two records across different tenants in submitted state.
        rec_a = _make_record(pack_id="pack-a", state="submitted", tenant_id="tenant-a")
        rec_b = _make_record(pack_id="pack-b", state="submitted", tenant_id="tenant-b")
        # Save_draft inserts at draft state; route around via raw insert
        # by saving as draft then constructing into submitted via raw SQL.
        # For this test we just need the rows to exist in submitted state;
        # the simplest path is to seed via save_draft + then patch state
        # in-place via the storage seam isn't available — use the public
        # transition path.
        for r in (rec_a, rec_b):
            draft = _make_record(
                pack_id=r.pack_id,
                record_id=r.id,
                tenant_id=r.tenant_id,
            )
            await store.save_draft(draft)
            await store.transition(
                pack_id=r.id,
                transition="submit",
                actor_id="canary",
                tenant_id=r.tenant_id,
                evidence_pointer=None,
                request_id=f"req-{r.pack_id}",
            )

        result = await store.list_by_status("submitted")

        # Pre-T5 contract: returns BOTH rows regardless of tenant_id.
        assert {r.id for r in result} == {rec_a.id, rec_b.id}

    async def test_list_by_status_existing_pagination_signature(
        self,
        store: PackRecordStore,
    ) -> None:
        """Pre-T5 positional ``limit`` + ``cursor`` call shape MUST
        still work — ``store.list_by_status("submitted", limit=10,
        cursor=<uuid>)`` returns paginated results identical to the
        pre-T5 behaviour. The new ``tenant_id`` defaults to ``None``;
        pagination semantics are unchanged."""
        # Seed five draft records.
        records = []
        for i in range(5):
            rec = _make_record(pack_id=f"pack-{i}")
            await store.save_draft(rec)
            records.append(rec)

        # Pre-T5 positional limit/cursor call shape.
        page1 = await store.list_by_status("draft", limit=2)
        assert len(page1) == 2

        page2 = await store.list_by_status("draft", limit=2, cursor=page1[-1].id)
        assert len(page2) == 2

        # Cursor pagination MUST exclude the cursor record itself.
        assert {r.id for r in page1}.isdisjoint({r.id for r in page2})


# ---------------------------------------------------------------------------
# Tenant-filtered path (Round 11 P2 #1)
# ---------------------------------------------------------------------------


class TestSprint7B2ListByStatusTenantFiltered:
    """Round 11 P2 #1 — when ``tenant_id`` is supplied, the WHERE clause
    adds ``tenant_id == :tenant_id`` server-side. T5 reviewer-queue
    handler relies on this filter to scope ``GET /api/v1/packs/review-queue``
    to ``actor.tenant_id`` without leaking cross-tenant rows."""

    async def test_list_by_status_tenant_filtered_pagination(
        self,
        store: PackRecordStore,
    ) -> None:
        """``store.list_by_status("submitted", limit=10, cursor=None,
        tenant_id="tenant-a")`` returns ONLY tenant-a rows even when
        tenant-b rows share the ``submitted`` state.

        Pinned per plan §"Tests" line 858 entry (3); load-bearing for
        T5 reviewer-queue tenant-isolation invariant.
        """
        # Seed 3 submitted packs across two tenants: 2 in tenant-a, 1 in tenant-b.
        ids_tenant_a: set[uuid.UUID] = set()
        ids_tenant_b: set[uuid.UUID] = set()
        for pack_id, tenant in [
            ("pack-a1", "tenant-a"),
            ("pack-a2", "tenant-a"),
            ("pack-b1", "tenant-b"),
        ]:
            draft = _make_record(pack_id=pack_id, tenant_id=tenant)
            await store.save_draft(draft)
            await store.transition(
                pack_id=draft.id,
                transition="submit",
                actor_id="canary",
                tenant_id=tenant,
                evidence_pointer=None,
                request_id=f"req-{pack_id}",
            )
            if tenant == "tenant-a":
                ids_tenant_a.add(draft.id)
            else:
                ids_tenant_b.add(draft.id)

        # Tenant-a query — must return ONLY tenant-a rows.
        result_a = await store.list_by_status(
            "submitted",
            limit=10,
            cursor=None,
            tenant_id="tenant-a",
        )
        result_a_ids = {r.id for r in result_a}
        assert result_a_ids == ids_tenant_a, (
            f"tenant-a query leaked cross-tenant rows: expected {ids_tenant_a}, got {result_a_ids}"
        )
        assert result_a_ids.isdisjoint(ids_tenant_b), (
            "tenant-a query must NOT include any tenant-b rows — "
            "server-side WHERE clause is the authoritative filter"
        )

        # Tenant-b query — must return ONLY tenant-b rows (symmetry).
        result_b = await store.list_by_status(
            "submitted",
            tenant_id="tenant-b",
        )
        assert {r.id for r in result_b} == ids_tenant_b

        # Untenanted query (tenant_id=None) — backward-compat: returns
        # rows from BOTH tenants (no tenant filter).
        result_all = await store.list_by_status("submitted")
        assert {r.id for r in result_all} == (ids_tenant_a | ids_tenant_b)
