"""Sprint 11 — pure-functional sub-agent policy per ADR-005: privilege
de-escalation (tool allow-list subset) + recursion-depth cap + budget
narrowing. No I/O. Critical-controls (subagent/ stop-rule)."""

from __future__ import annotations

from cognic_agentos.core.scheduler._seams import compute_child_budget
from cognic_agentos.subagent._types import (
    SubAgentBudgetExhausted,
    SubAgentDepthExceeded,
    SubAgentPrivilegeEscalation,
)


def narrow_tool_allow_list(*, parent: frozenset[str], requested: frozenset[str]) -> frozenset[str]:
    """Return ``requested`` iff it is a subset of ``parent`` (privilege
    de-escalation per ADR-005 §"Privilege de-escalation rule"). Raise
    :class:`SubAgentPrivilegeEscalation` listing the extra tools otherwise.
    The granted set is never wider than ``parent``."""
    extra = requested - parent
    if extra:
        raise SubAgentPrivilegeEscalation(extra_tools=extra)
    return requested


def check_depth(*, current_depth: int, max_depth: int) -> None:
    """Raise :class:`SubAgentDepthExceeded` if a child spawned from a parent
    at ``current_depth`` would exceed ``max_depth``. Root orchestrator is
    depth 0; the child sits at ``current_depth + 1``."""
    if current_depth + 1 > max_depth:
        raise SubAgentDepthExceeded(current_depth=current_depth, max_depth=max_depth)


def compute_spawn_budget(*, parent_remaining_budget: int, child_pack_quota: int) -> int:
    """Narrow the child's token budget to ``min(child_pack_quota,
    parent_remaining_budget)`` via the scheduler's pure ``compute_child_budget``
    helper. Raise :class:`SubAgentBudgetExhausted` when the narrowed budget is
    zero — the parent has nothing left to delegate."""
    granted = compute_child_budget(
        parent_remaining_budget=parent_remaining_budget,
        child_pack_quota=child_pack_quota,
    )
    if granted == 0:
        raise SubAgentBudgetExhausted(parent_remaining_budget=parent_remaining_budget)
    return granted
