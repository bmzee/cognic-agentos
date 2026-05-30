"""Sprint 11b T5 — real DI conformers for the sub-agent spawn path.

Two conformers under test:
  * ``LocalParentBudgetResolver`` — structural conformer for the
    ``ParentBudgetResolver`` Protocol over a Sprint-11-local budget
    snapshot. Fail-loud on an unknown parent (a missing snapshot entry
    is a programming error, NOT a silent zero).
  * ``PackStoreStateInterrogator`` — structural conformer for the
    ``PackStateInterrogator`` Protocol over ``packs/storage``. The
    scheduler seam passes the LOGICAL ``pack_id: str`` (e.g.
    ``"cognic-tool-loan-eligibility"``), NOT the DB row ``id: uuid``,
    so ``is_installed`` scans the tenant-scoped installed packs via
    ``list_for_tenant`` and matches ``record.pack_id`` — NOT
    ``store.load`` (which keys by row id).

Critical-controls (subagent/ stop-rule). The ``engine`` fixture
(governance schema + seeded chain heads, incl. the ``packs`` table)
comes from ``tests/unit/subagent/conftest.py``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.core.scheduler._seams import (
    PackStateInterrogator,
    ParentBudgetResolver,
)
from cognic_agentos.packs.storage import PackRecordStore, _packs
from cognic_agentos.subagent.conformers import (
    LocalParentBudgetResolver,
    PackStoreStateInterrogator,
)

# ===========================================================================
# (a) LocalParentBudgetResolver — Protocol conformance + snapshot semantics
# ===========================================================================


def test_resolver_conforms_to_parent_budget_resolver_protocol() -> None:
    assert isinstance(LocalParentBudgetResolver({}), ParentBudgetResolver)


async def test_local_resolver_returns_snapshot_value() -> None:
    pid = uuid.uuid4()
    assert await LocalParentBudgetResolver({pid: 1200}).remaining_budget_for(pid) == 1200


async def test_local_resolver_fails_loud_on_unknown_parent() -> None:
    # Missing parent budget is a programming error — fail loud, NOT silent zero.
    with pytest.raises(KeyError):
        await LocalParentBudgetResolver({}).remaining_budget_for(uuid.uuid4())


# ===========================================================================
# (b) PackStoreStateInterrogator — the load-vs-list_for_tenant correction
# ===========================================================================


async def _insert_installed_pack(
    engine: AsyncEngine,
    *,
    pack_id: str,
    tenant_id: str,
    row_id: uuid.UUID | None = None,
) -> uuid.UUID:
    """Create an ``installed``-state pack whose LOGICAL ``pack_id`` is a
    non-UUID string (e.g. ``"cognic-tool-loan-eligibility"``) for the given
    tenant, via a direct INSERT into the ``packs`` Table (the simplest
    robust path — mirrors the column set in ``packs/storage.py``; no chain
    rows are needed because ``list_for_tenant`` reads the ``packs`` state
    cache directly). ``row_id`` defaults to a random UUID; pass an explicit
    value to control ``list_for_tenant``'s ORDER-BY-id pagination. Returns the
    DB row ``id`` (a UUID, distinct from the logical ``pack_id``) so the test
    can prove the conformer matches on the logical id, not the row id."""

    row_id = row_id if row_id is not None else uuid.uuid4()
    now = datetime.now(UTC)
    async with engine.begin() as conn:
        await conn.execute(
            _packs.insert().values(
                id=row_id,
                kind="tool",
                pack_id=pack_id,
                display_name=pack_id,
                state="installed",
                manifest_digest=b"\x01" * 32,
                signed_artefact_digest=b"\x02" * 32,
                sbom_pointer=None,
                tenant_id=tenant_id,
                created_by="canary-author",
                last_actor="canary-author",
                created_at=now,
                updated_at=now,
            )
        )
    return row_id


async def test_interrogator_conforms_to_pack_state_interrogator_protocol(
    engine: AsyncEngine,
) -> None:
    store = PackRecordStore(engine)
    assert isinstance(PackStoreStateInterrogator(store=store), PackStateInterrogator)


async def test_is_installed_matches_logical_pack_id_not_row_id(
    engine: AsyncEngine,
) -> None:
    """The scheduler seam passes the LOGICAL pack_id (a non-UUID string);
    ``is_installed`` must scan ``list_for_tenant(state="installed")`` and
    match ``record.pack_id`` — NOT ``store.load`` (which keys by row id).
    The installed pack's logical id is deliberately a non-UUID string so a
    ``store.load`` implementation would raise/miss instead of matching."""

    store = PackRecordStore(engine)
    row_id = await _insert_installed_pack(
        engine, pack_id="cognic-tool-loan-eligibility", tenant_id="bank-a"
    )
    # The DB row id is a UUID, distinct from the logical pack_id under test.
    assert str(row_id) != "cognic-tool-loan-eligibility"

    itg = PackStoreStateInterrogator(store=store)
    assert (
        await itg.is_installed(tenant_id="bank-a", pack_id="cognic-tool-loan-eligibility") is True
    )
    # cross-tenant: same logical pack_id under a different tenant is invisible.
    assert (
        await itg.is_installed(tenant_id="bank-b", pack_id="cognic-tool-loan-eligibility") is False
    )
    # not found: unknown logical pack_id under the owning tenant.
    assert await itg.is_installed(tenant_id="bank-a", pack_id="nonexistent-pack") is False


async def test_is_installed_paginates_past_first_page(engine: AsyncEngine) -> None:
    """With ``page_size=1``, a target on the SECOND page must still be found —
    proves the conformer is NOT first-page-capped (Sprint 11b watchpoint).
    Row ids are controlled so the filler (id=int 1) sorts first and the target
    (id=int 2) lands on the second page under ``list_for_tenant``'s ORDER BY
    ``packs.id`` ASC (the ordering the cursor=last-id pagination relies on)."""

    store = PackRecordStore(engine)
    await _insert_installed_pack(
        engine, pack_id="filler-pack", tenant_id="bank-a", row_id=uuid.UUID(int=1)
    )
    await _insert_installed_pack(
        engine, pack_id="target-on-page-2", tenant_id="bank-a", row_id=uuid.UUID(int=2)
    )
    # Sanity (keeps this test non-vacuous): page 1 at limit=1 returns the
    # filler, so the target genuinely requires a second page.
    page1 = await store.list_for_tenant("bank-a", limit=1, state="installed")
    assert [r.pack_id for r in page1] == ["filler-pack"]

    itg = PackStoreStateInterrogator(store=store, page_size=1)
    assert await itg.is_installed(tenant_id="bank-a", pack_id="target-on-page-2") is True
