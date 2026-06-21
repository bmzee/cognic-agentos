"""Sprint 11 — sub-agent closed-enum vocabulary + frozen dataclasses per
ADR-005. Pure (no I/O). Critical-controls (subagent/ stop-rule)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Literal, Protocol, runtime_checkable

if TYPE_CHECKING:
    from cognic_agentos.portal.rbac.actor import Actor

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
    approval_request_id: str | None = None  # the granted id on an approval retry (else None)


@dataclass(frozen=True)
class ChildResult:
    summary: str
    tokens_used: int
    wall_time_used_s: float
    ok: bool = True
    #: 2026-06-20 (child approval-retry) — surfaced from the child RunResult on every
    #: branch (no longer flattened). approval_request_id is set ONLY on the pending path.
    run_id: str | None = None
    terminal_state: str | None = None  # mirrors core/run RunTerminalState; str avoids a core import
    approval_request_id: str | None = None


@dataclass(frozen=True)
class ManagedRunChildSpec:
    """Runner-specific managed-run execution shape (B + thin-C). Kept OUT of the
    runner-agnostic SubAgentSpawnRequest so a pack-provided runner is unaffected.
    No pack_kind/risk_tier — the executor derives them from the validated record.
    pack_version IS caller-provided (PackRecord has no version column)."""

    pack_id: str
    pack_version: str
    argv: tuple[str, ...]


@dataclass(frozen=True)
class ChildRunContext:
    """The already-narrowed execution context spawn.py hands to the runner.
    Frozen + stable so threading new fields (trace IDs, memory scope, harness
    metadata) never churns the ChildRunner signature (Sprint 11b)."""

    prompt: str
    granted_tools: frozenset[str]
    requested_estimated_tokens: int  # was `budget`; the REQUESTED (pre-narrowing)
    tenant_id: str
    current_depth: int
    child_trace_id: str
    request_id: str
    parent_record_id: uuid.UUID
    parent_task_id: str | None = None  # budget-inheritance key (from request.parent_task_id)
    # None → pack-provided runner; managed-run runner fail-closes
    managed_run: ManagedRunChildSpec | None = None
    # OPTIONAL/additive — the full portal Actor; managed-run runner fail-closes on None
    actor: Actor | None = None
    memory_scope: str | None = None  # 11.5-ready inert hook; NO durable writes in 11b
    # threaded into RunRequest.approval_request_id by the runner
    approval_request_id: str | None = None


@runtime_checkable
class ChildRunner(Protocol):
    """Injected child-execution seam (Sprint 11b D1: no agent runtime in 11b).
    spawn.py owns policy narrowing + scheduler submit + audit emit + budget
    accounting; the runner ONLY executes the child with the already-granted
    context. Production supplies a real runner; tests inject a fake."""

    async def run(self, context: ChildRunContext) -> ChildResult: ...


@dataclass(frozen=True)
class SubAgentResult:
    spawn_record_id: uuid.UUID
    child_result: ChildResult
    preempted: bool = False
