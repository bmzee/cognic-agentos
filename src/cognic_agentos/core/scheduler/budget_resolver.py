"""Production ParentBudgetResolver — granted-budget snapshot ceiling primitive
(ADR-005 / ADR-022). Replaces the _NullParentBudgetResolver fail-loud sentinel.

Owns the policy interpretation of a parent task's snapshot: tenant-scoped
absence → parent_not_found, terminal state → parent_terminal, else the granted
token budget returned as the inherited ceiling. This budget authority is why
the module is on the durable critical-controls coverage gate.
"""

from __future__ import annotations

import uuid
from typing import Protocol, runtime_checkable

from cognic_agentos.core.scheduler._seams import ParentTaskBudgetUnavailable
from cognic_agentos.core.scheduler._types import SchedulerTaskState
from cognic_agentos.core.scheduler.storage import _BudgetSnapshot

#: Terminal SchedulerTaskState values — a parent in any of these cannot confer
#: budget. Partition-pinned against SchedulerTaskState by the resolver test.
_TERMINAL_STATES: frozenset[SchedulerTaskState] = frozenset(
    {"completed", "failed", "cancelled", "preempted", "expired"}
)


@runtime_checkable
class BudgetSnapshotReader(Protocol):
    """Narrow consumer-owned read seam (SchedulerStorage conforms structurally)."""

    async def get_budget_snapshot(
        self, task_id: uuid.UUID, *, tenant_id: str
    ) -> _BudgetSnapshot | None: ...


class SchedulerTaskParentBudgetResolver:
    """Resolves a parent task's GRANTED token budget (a snapshot, not a live
    balance). Ceiling-inheritance read primitive; sibling/shared-pool depletion
    is the later sub-agent-dispatch slice."""

    def __init__(self, reader: BudgetSnapshotReader) -> None:
        self._reader = reader

    async def remaining_budget_for(self, parent_task_id: uuid.UUID, *, tenant_id: str) -> int:
        snapshot = await self._reader.get_budget_snapshot(parent_task_id, tenant_id=tenant_id)
        if snapshot is None:
            # Absent OR cross-tenant — collapsed to not-found (invisibility).
            raise ParentTaskBudgetUnavailable("parent_not_found")
        if snapshot.state in _TERMINAL_STATES:
            raise ParentTaskBudgetUnavailable("parent_terminal")
        return snapshot.granted_tokens
