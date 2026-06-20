"""Sprint 11 — pure-functional sub-agent policy per ADR-005: privilege
de-escalation (tool allow-list subset) + recursion-depth cap. No I/O.

Token-budget narrowing no longer lives here: the spawn-side
``compute_spawn_budget`` helper was retired with the 2026-06-20 live-path
refactor — the managed-run executor + core/scheduler now own the
effective-budget computation (``compute_child_budget`` + the scheduler's
zero-effective-budget admission guard). Critical-controls (subagent/
stop-rule)."""

from __future__ import annotations

from cognic_agentos.subagent._types import (
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
