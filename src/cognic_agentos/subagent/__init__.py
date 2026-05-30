"""Sprint 11 — sub-agent primitive (ADR-005). Stop-rule isolation
boundary (privilege de-escalation). The SubAgent facade lands in 11b."""

from __future__ import annotations

from cognic_agentos.subagent._facade import SubAgent
from cognic_agentos.subagent._types import (
    SUBAGENT_ISO_CONTROLS,
    ChildResult,
    ChildRunContext,
    ChildRunner,
    SubAgentAuditEvent,
    SubAgentBudgetExhausted,
    SubAgentChildQuotaZero,
    SubAgentDepthExceeded,
    SubAgentPrivilegeEscalation,
    SubAgentRefusalReason,
    SubAgentResult,
    SubAgentSpawnRequest,
)

__all__ = [
    "SUBAGENT_ISO_CONTROLS",
    "ChildResult",
    "ChildRunContext",
    "ChildRunner",
    "SubAgent",
    "SubAgentAuditEvent",
    "SubAgentBudgetExhausted",
    "SubAgentChildQuotaZero",
    "SubAgentDepthExceeded",
    "SubAgentPrivilegeEscalation",
    "SubAgentRefusalReason",
    "SubAgentResult",
    "SubAgentSpawnRequest",
]
