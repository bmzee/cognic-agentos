"""SchedulerTaskParentBudgetResolver — granted-snapshot ceiling primitive (ADR-005)."""

from __future__ import annotations

import uuid
from typing import get_args

import pytest

from cognic_agentos.core.scheduler._seams import ParentTaskBudgetUnavailable
from cognic_agentos.core.scheduler._types import SchedulerTaskState
from cognic_agentos.core.scheduler.budget_resolver import (
    _TERMINAL_STATES,
    SchedulerTaskParentBudgetResolver,
)
from cognic_agentos.core.scheduler.storage import _BudgetSnapshot

_PID = uuid.uuid4()


class _StubReader:
    def __init__(self, snapshot: _BudgetSnapshot | None) -> None:
        self._snapshot = snapshot
        self.seen: tuple[uuid.UUID, str] | None = None

    async def get_budget_snapshot(self, task_id, *, tenant_id):
        self.seen = (task_id, tenant_id)
        return self._snapshot


async def test_returns_granted_tokens_for_running_parent() -> None:
    reader = _StubReader(_BudgetSnapshot(granted_tokens=750, state="running"))
    r = SchedulerTaskParentBudgetResolver(reader)
    assert await r.remaining_budget_for(_PID, tenant_id="t") == 750
    assert reader.seen == (_PID, "t")  # tenant threaded to the read


async def test_returns_granted_tokens_for_pending_parent() -> None:
    reader = _StubReader(_BudgetSnapshot(granted_tokens=10, state="pending"))
    assert (
        await SchedulerTaskParentBudgetResolver(reader).remaining_budget_for(_PID, tenant_id="t")
        == 10
    )


async def test_absent_raises_parent_not_found() -> None:
    r = SchedulerTaskParentBudgetResolver(_StubReader(None))
    with pytest.raises(ParentTaskBudgetUnavailable) as ei:
        await r.remaining_budget_for(_PID, tenant_id="t")
    assert ei.value.reason == "parent_not_found"


@pytest.mark.parametrize("state", ["completed", "failed", "cancelled", "preempted", "expired"])
async def test_terminal_raises_parent_terminal(state: SchedulerTaskState) -> None:
    reader = _StubReader(_BudgetSnapshot(granted_tokens=500, state=state))
    with pytest.raises(ParentTaskBudgetUnavailable) as ei:
        await SchedulerTaskParentBudgetResolver(reader).remaining_budget_for(_PID, tenant_id="t")
    assert ei.value.reason == "parent_terminal"


def test_terminal_set_partitions_scheduler_task_state() -> None:
    # Drift guard: terminal | {pending, running} == all states; a new state fails this.
    assert _TERMINAL_STATES | {"pending", "running"} == set(get_args(SchedulerTaskState))
