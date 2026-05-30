"""Sprint 11 — sub-agent closed-enum vocabulary + frozen dataclasses per
ADR-005. Pure (no I/O). Critical-controls (subagent/ stop-rule)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

# Spawn-time refusal vocabulary (wire-public; pinned by the drift detector).
SubAgentRefusalReason = Literal[
    "subagent_depth_exceeded",
    "subagent_privilege_escalation",
    "subagent_parent_budget_exhausted",
    "subagent_child_quota_zero",
]

# Audit decision_types on the decision_history chain (ADR-005 §Audit).
SubAgentAuditEvent = Literal[
    "subagent.spawn",
    "subagent.start",
    "subagent.return",
    "subagent.budget",
]

# ISO 42001 control tuple stamped on every subagent.* chain row
# (delegation accountability + action traceability per ADR-005 §ISO;
# A.6.2.5 is implemented in the iso42001 registry + used by the scheduler).
SUBAGENT_ISO_CONTROLS: Final[tuple[str, ...]] = ("A.6.2.5",)


class SubAgentDepthExceeded(Exception):
    """Spawn refused: child would exceed the recursion-depth cap."""

    def __init__(self, *, current_depth: int, max_depth: int) -> None:
        super().__init__("subagent_depth_exceeded")
        self.reason: SubAgentRefusalReason = "subagent_depth_exceeded"
        self.current_depth = current_depth
        self.max_depth = max_depth


class SubAgentPrivilegeEscalation(Exception):
    """Spawn refused: requested tools are not a subset of the parent's."""

    def __init__(self, *, extra_tools: frozenset[str]) -> None:
        super().__init__("subagent_privilege_escalation")
        self.reason: SubAgentRefusalReason = "subagent_privilege_escalation"
        self.extra_tools = extra_tools


class SubAgentBudgetExhausted(Exception):
    """Spawn refused: the parent's narrowed budget is zero."""

    def __init__(self, *, parent_remaining_budget: int) -> None:
        super().__init__("subagent_parent_budget_exhausted")
        self.reason: SubAgentRefusalReason = "subagent_parent_budget_exhausted"
        self.parent_remaining_budget = parent_remaining_budget


class SubAgentChildQuotaZero(Exception):
    """Spawn refused: the child pack quota is zero (the parent has budget).

    Sprint 11b D3 — distinct from SubAgentBudgetExhausted so a zero child
    quota never surfaces as 'parent exhausted' once spawn is exposed."""

    def __init__(self, *, child_pack_quota: int) -> None:
        super().__init__("subagent_child_quota_zero")
        self.reason: SubAgentRefusalReason = "subagent_child_quota_zero"
        self.child_pack_quota = child_pack_quota


@dataclass(frozen=True)
class SubAgentSpawnRequest:
    """Explicit inputs to a sub-agent spawn — no inference from MCP host
    (Wave-1). ``parent_tool_allow_list`` and ``requested_tool_allow_list``
    are frozensets of tool IDs; the latter must be a subset of the former."""

    prompt: str
    parent_tool_allow_list: frozenset[str]
    requested_tool_allow_list: frozenset[str]
    current_depth: int
    requested_estimated_tokens: int
    tenant_id: str
    parent_task_id: str | None = None
