"""Sprint 7B.2 T7 — ``PackRecordStore.list_for_tenant`` tenant-scoped read regressions.

Plan Round 19 P2 #4 + Round 22 P2 #2 — T7 inspection surface
(``GET /api/v1/packs``) needs an UN-state-filtered listing scoped to
the actor's tenant; the storage seam adds a NEW method
``list_for_tenant(tenant_id, *, limit, cursor, state=None)`` that the
inspection route handler calls with ``tenant_id=actor.tenant_id``.

**Exact signature (per plan §966):**

.. code-block:: python

    list_for_tenant(
        tenant_id: str,
        *,
        limit: int = 50,
        cursor: uuid.UUID | None = None,
        state: PackState | None = None,
    ) -> list[PackRecord]

``tenant_id`` is REQUIRED (positional-or-keyword) — unlike
``list_by_status``'s optional kwarg, the inspection endpoint cannot
list packs without a tenant scope (server-side WHERE clause is the
authoritative tenant boundary; cross-tenant leakage is a wire-protocol
break). ``state`` is OPTIONAL keyword-only — when non-None, adds
``AND packs.state = :state`` to the WHERE clause; uses the existing
``ix_packs_tenant_state`` composite index per migration L129.

**Round 22 P2 #2 private statement-builder pattern**: production
``list_for_tenant`` MUST extract its query construction into a
module-private helper ``_build_list_for_tenant_stmt(tenant_id, *,
limit, cursor, state=None) -> Select`` that the public method calls
before passing to ``await conn.execute(...)``. The SQL-shape regression
below imports this SAME builder via
``cognic_agentos.packs.storage._build_list_for_tenant_stmt`` and asserts
on its compiled output — eliminates the "test-writes-its-own-select-
and-assertion-passes-while-production-drifts" vacuous-proof bug class.
The builder is module-private (underscore prefix) but module-public
for the test import, mirroring the existing ``_row_to_record`` helper
convention at ``packs/storage.py:1125``.

**Five regressions per plan §966 + §1013** (Round 21 P2 #2 bumped 4→5;
Round 22 P2 #2 + P3 #3 propagation refresh):

1. ``test_list_for_tenant_returns_only_matching_tenant_rows`` —
   two-tenant fixture; tenant-A actor gets only tenant-A rows.
2. ``test_list_for_tenant_with_optional_state_filter`` — when ``state``
   provided, applies AND clause; index used.
3. ``test_list_for_tenant_pagination_cursor`` — cursor pagination
   behaves identically to ``list_by_status``'s cursor logic.
4. ``test_list_for_tenant_with_no_packs_returns_empty_list`` — a
   tenant string with no matching packs returns ``[]`` correctly
   (renamed at Round 20 P2 #2 from prior "empty tenant" wording which
   conflated empty-``tenant_id`` (route-layer 500 in Slice 2) with the
   legitimate empty-result-set case (this storage-layer happy path)).
5. ``test_list_for_tenant_compiles_with_indexed_where_clause`` —
   imports the module-private ``_build_list_for_tenant_stmt`` (the
   SAME builder the production ``list_for_tenant`` invokes) and
   asserts the compiled SQL contains ``packs.tenant_id = `` (always)
   AND ``packs.state = `` (when ``state`` non-None); proves the
   production query path uses the ``ix_packs_tenant_state``
   composite-index columns. The shared-builder pattern eliminates the
   vacuous-proof bug class where a test-local duplicate ``select``
   could pass while the production query drifts.

Halt-before-commit per T7 §1012 — CC-ADJ touch to the live
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
# Fixtures (mirrors test_storage_list_by_status.py:63-95; same engine + store
# pattern; kept local to this file to keep the T7 regression set self-contained)
# ---------------------------------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Any) -> Any:
    """Per-test SQLite-aiosqlite engine with the governance schema +
    seeded chain heads + the ``packs`` table. Mirrors
    ``tests/unit/packs/test_storage_list_by_status.py::engine`` per the
    Sprint-7B.1 T3 test-fixture pattern."""
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
    helper mirroring ``test_storage_list_by_status.py::_make_record`` per
    the Sprint-7B.1 T3 convention."""
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
# Tenant-scoped read regressions (plan §966 + §1013)
# ---------------------------------------------------------------------------


class TestSprint7B2ListForTenant:
    """T7 inspection surface — server-side tenant filter is the
    AUTHORITATIVE boundary for ``GET /api/v1/packs`` (no ``{pack_id}``
    path-param means ``RequireTenantOwnership`` can't enforce row-level
    filtering; the WHERE clause IS the security boundary)."""

    async def test_list_for_tenant_returns_only_matching_tenant_rows(
        self,
        store: PackRecordStore,
    ) -> None:
        """Two-tenant fixture: 2 packs in tenant-a + 1 pack in tenant-b
        (mixed states); ``store.list_for_tenant("tenant-a")`` returns
        ONLY tenant-a rows. Pinned per plan §966 regression (1) +
        §1013 watchpoint (a) — server-side WHERE clause is the
        AUTHORITATIVE tenant boundary; no in-handler filtering can
        leak cross-tenant rows."""
        ids_tenant_a: set[uuid.UUID] = set()
        ids_tenant_b: set[uuid.UUID] = set()
        for pack_id, tenant in [
            ("pack-a1", "tenant-a"),
            ("pack-a2", "tenant-a"),
            ("pack-b1", "tenant-b"),
        ]:
            draft = _make_record(pack_id=pack_id, tenant_id=tenant)
            await store.save_draft(draft)
            if tenant == "tenant-a":
                ids_tenant_a.add(draft.id)
            else:
                ids_tenant_b.add(draft.id)

        result_a = await store.list_for_tenant("tenant-a")
        result_a_ids = {r.id for r in result_a}

        assert result_a_ids == ids_tenant_a, (
            f"tenant-a query leaked cross-tenant rows: expected {ids_tenant_a}, got {result_a_ids}"
        )
        assert result_a_ids.isdisjoint(ids_tenant_b), (
            "tenant-a query must NOT include any tenant-b rows — "
            "server-side WHERE clause is the authoritative filter"
        )

        # Symmetry: tenant-b query returns ONLY tenant-b rows.
        result_b = await store.list_for_tenant("tenant-b")
        assert {r.id for r in result_b} == ids_tenant_b

    async def test_list_for_tenant_with_optional_state_filter(
        self,
        store: PackRecordStore,
    ) -> None:
        """When ``state`` kwarg is provided, the WHERE clause adds
        ``AND packs.state = :state`` server-side. Both filter columns
        (``tenant_id`` + ``state``) are covered by the
        ``ix_packs_tenant_state`` composite index per migration L129.

        Pinned per plan §966 regression (2) + §1013 watchpoint (c) —
        the optional state filter must be wired through the same
        server-side WHERE clause; in-handler post-filtering breaks
        pagination correctness.
        """
        # Seed mix: tenant-a has 2 draft + 1 submitted; tenant-b has 1 draft.
        # All packs land at ``draft`` via ``save_draft``; the third one
        # is then transitioned to ``submitted`` to give a tenant-a row
        # in a different lifecycle state.
        draft_ids_a: set[uuid.UUID] = set()
        submitted_ids_a: set[uuid.UUID] = set()
        for pack_id in (
            "pack-a-draft-1",
            "pack-a-draft-2",
            "pack-a-submit-1",
        ):
            draft = _make_record(pack_id=pack_id, tenant_id="tenant-a")
            await store.save_draft(draft)
            if pack_id == "pack-a-submit-1":
                await store.transition(
                    pack_id=draft.id,
                    transition="submit",
                    actor_id="canary",
                    tenant_id="tenant-a",
                    evidence_pointer=None,
                    request_id=f"req-{pack_id}",
                )
                submitted_ids_a.add(draft.id)
            else:
                draft_ids_a.add(draft.id)

        draft_b = _make_record(pack_id="pack-b-draft-1", tenant_id="tenant-b")
        await store.save_draft(draft_b)

        # Tenant-a + state=draft must return ONLY tenant-a draft rows.
        result_a_draft = await store.list_for_tenant("tenant-a", state="draft")
        assert {r.id for r in result_a_draft} == draft_ids_a, (
            "tenant-a + state=draft must exclude tenant-a submitted AND tenant-b draft"
        )

        # Tenant-a + state=submitted must return ONLY the submitted row.
        result_a_sub = await store.list_for_tenant("tenant-a", state="submitted")
        assert {r.id for r in result_a_sub} == submitted_ids_a

        # Tenant-a + no state kwarg returns ALL tenant-a rows
        # (3: 2 draft + 1 submitted).
        result_a_all = await store.list_for_tenant("tenant-a")
        assert {r.id for r in result_a_all} == (draft_ids_a | submitted_ids_a)

    async def test_list_for_tenant_pagination_cursor(
        self,
        store: PackRecordStore,
    ) -> None:
        """Cursor pagination behaves identically to ``list_by_status``'s
        cursor logic — ``cursor`` is the last id returned by the
        previous page; ordering is by ``packs.id``; the cursor record
        itself is excluded from the next page (``packs.id > cursor``).

        Pinned per plan §966 regression (3); reused bounded-pagination
        pattern from Sprint-5 ``protocol/mcp_host.py``.
        """
        # Seed 5 draft records for tenant-a.
        for i in range(5):
            rec = _make_record(pack_id=f"pack-page-{i}", tenant_id="tenant-a")
            await store.save_draft(rec)

        # First page: limit=2 returns 2 records.
        page1 = await store.list_for_tenant("tenant-a", limit=2)
        assert len(page1) == 2

        # Second page: cursor=page1[-1].id returns the next 2 records.
        page2 = await store.list_for_tenant("tenant-a", limit=2, cursor=page1[-1].id)
        assert len(page2) == 2

        # Cursor pagination excludes the cursor record itself (no overlap).
        assert {r.id for r in page1}.isdisjoint({r.id for r in page2}), (
            "cursor pagination must exclude the cursor record itself (packs.id > cursor)"
        )

        # Third page: limit=2 from page2's last cursor returns the
        # remaining 1 record.
        page3 = await store.list_for_tenant("tenant-a", limit=2, cursor=page2[-1].id)
        assert len(page3) == 1
        assert {r.id for r in page3}.isdisjoint({r.id for r in page1} | {r.id for r in page2})

    async def test_list_for_tenant_with_no_packs_returns_empty_list(
        self,
        store: PackRecordStore,
    ) -> None:
        """Round 20 P2 #2 corrected — a tenant string with no matching
        packs returns ``[]`` correctly (legitimate happy-path read).

        Distinct from the empty-``tenant_id`` route-layer refusal case
        (handled in Slice 2 at the inspection list handler — kernel
        binder misconfig surfaces 500 + ``actor_tenant_id_missing``).
        This storage-layer test asserts the method behaves correctly
        when the tenant has no packs — a tenant-isolated query against
        a tenant with zero pack rows returns ``[]``, NOT an error.

        Pinned per plan §966 regression (4) — empty-result-set is a
        happy-path read; storage does NOT validate ``tenant_id`` shape
        (the route layer owns that).
        """
        # Seed packs ONLY for tenant-a; tenant-c gets nothing.
        for pack_id in ("pack-a1", "pack-a2"):
            draft = _make_record(pack_id=pack_id, tenant_id="tenant-a")
            await store.save_draft(draft)

        # Tenant-c has no packs — must return [] (legitimate happy path).
        result_c = await store.list_for_tenant("tenant-c")
        assert result_c == [], "tenant-c has no packs; storage MUST return [] without error"

        # Cross-check: tenant-a still returns its 2 packs.
        result_a = await store.list_for_tenant("tenant-a")
        assert len(result_a) == 2

    async def test_list_for_tenant_compiles_with_indexed_where_clause(self) -> None:
        """Round 21 P2 #2 + Round 22 P2 #2 — imports the module-private
        ``_build_list_for_tenant_stmt`` (the SAME builder the production
        ``list_for_tenant`` invokes) and asserts the compiled SQL
        contains ``packs.tenant_id = `` (always) AND ``packs.state = ``
        (when ``state`` non-None).

        Proves the production query path uses the ``ix_packs_tenant_state``
        composite-index columns. Shared-builder pattern eliminates the
        vacuous-proof bug class where a test-local duplicate ``select``
        could pass while the production query drifts.

        Pinned per plan §966 regression (5) + §1013 watchpoint (c) —
        single source of truth for the WHERE-clause shape; production
        + test reference the same module-private symbol.
        """
        # Import inside the test body so import-failure is isolated to
        # this test (other 4 regressions fail with AttributeError at
        # runtime, not at collection time). Production code lands
        # _build_list_for_tenant_stmt at module scope in Slice 1 GREEN.
        from cognic_agentos.packs.storage import _build_list_for_tenant_stmt

        # Shape 1: tenant_id only (no state kwarg) — WHERE clause has
        # ``packs.tenant_id = :tenant_id`` but NOT ``packs.state``.
        stmt_no_state = _build_list_for_tenant_stmt(
            "tenant-a",
            limit=50,
            cursor=None,
            state=None,
        )
        compiled_no_state = str(stmt_no_state.compile())
        assert "packs.tenant_id = " in compiled_no_state, (
            f"compiled SQL must contain 'packs.tenant_id = ' "
            f"(authoritative tenant filter); got:\n{compiled_no_state}"
        )
        assert "packs.state = " not in compiled_no_state, (
            f"state filter must be ABSENT when state kwarg is None; got:\n{compiled_no_state}"
        )

        # Shape 2: tenant_id + state kwarg — WHERE clause has BOTH
        # ``packs.tenant_id = :tenant_id`` AND ``packs.state = :state``;
        # both columns covered by the ``ix_packs_tenant_state`` index.
        stmt_with_state = _build_list_for_tenant_stmt(
            "tenant-a",
            limit=50,
            cursor=None,
            state="draft",
        )
        compiled_with_state = str(stmt_with_state.compile())
        assert "packs.tenant_id = " in compiled_with_state, (
            f"compiled SQL must contain 'packs.tenant_id = ' "
            f"(authoritative tenant filter even with state filter); "
            f"got:\n{compiled_with_state}"
        )
        assert "packs.state = " in compiled_with_state, (
            f"compiled SQL must contain 'packs.state = ' when state "
            f"kwarg is non-None; got:\n{compiled_with_state}"
        )
