"""Sprint 11b — real DI conformers for the sub-agent spawn path.
ParentBudgetResolver over a local snapshot; PackStateInterrogator over
packs/storage. Critical-controls (subagent/ stop-rule)."""

from __future__ import annotations

import uuid

from cognic_agentos.packs.storage import PackRecordStore


class LocalParentBudgetResolver:
    """Real ParentBudgetResolver over a Sprint-11-local budget snapshot.
    Fail-loud on an unknown parent: a spawn flow must register the parent's
    budget before submitting a child; a missing entry is a programming error,
    NOT a silent zero."""

    def __init__(self, snapshot: dict[uuid.UUID, int]) -> None:
        self._snapshot = dict(snapshot)

    async def remaining_budget_for(self, parent_task_id: uuid.UUID, *, tenant_id: str) -> int:
        # tenant_id accepted for Protocol-compat; this Sprint-11b dict-snapshot
        # resolver does NOT tenant-scope (the scheduler-backed resolver does).
        if parent_task_id not in self._snapshot:
            raise KeyError(
                f"no parent-budget snapshot for parent_task_id={parent_task_id}; "
                "register the parent budget before spawning a child"
            )
        return self._snapshot[parent_task_id]


class PackStoreStateInterrogator:
    """Real minimal PackStateInterrogator. The scheduler seam passes the
    LOGICAL pack_id (str), NOT the DB row id (uuid) — so scan the tenant-scoped
    installed packs via ``list_for_tenant`` (the authoritative tenant boundary)
    and match ``record.pack_id``. NOT ``store.load``, which keys by row id.
    Pagination loop so the conformer is never capped at the first page."""

    def __init__(self, *, store: PackRecordStore, page_size: int = 200) -> None:
        self._store = store
        self._page_size = page_size

    async def is_installed(self, *, tenant_id: str, pack_id: str) -> bool:
        cursor: uuid.UUID | None = None
        while True:
            page = await self._store.list_for_tenant(
                tenant_id, limit=self._page_size, cursor=cursor, state="installed"
            )
            for record in page:
                if record.pack_id == pack_id:
                    return True
            if len(page) < self._page_size:
                return False
            cursor = page[-1].id
