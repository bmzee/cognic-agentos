"""Sprint 11 — sub-agent primitive (ADR-005). Stop-rule isolation
boundary (privilege de-escalation). The SubAgent facade lands in 11b."""

from __future__ import annotations

from cognic_agentos.subagent._types import (
    SUBAGENT_ISO_CONTROLS,
    SubAgentAuditEvent,
    SubAgentBudgetExhausted,
    SubAgentDepthExceeded,
    SubAgentPrivilegeEscalation,
    SubAgentRefusalReason,
    SubAgentSpawnRequest,
)

__all__ = [
    "SUBAGENT_ISO_CONTROLS",
    "SubAgentAuditEvent",
    "SubAgentBudgetExhausted",
    "SubAgentDepthExceeded",
    "SubAgentPrivilegeEscalation",
    "SubAgentRefusalReason",
    "SubAgentSpawnRequest",
]
