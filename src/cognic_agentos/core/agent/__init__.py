"""M8 (ADR-027) — governed agent-runtime package.

``AssignmentStore`` (CRITICAL CONTROLS) owns the grant-not-requested ingestion
invariant (spec §3.1): operator/config drift can never grant a capability the
persona never requested — fail-closed at load, NO partial grant set. The pure
types live in ``_types`` (off-gate per the ``core/scheduler/_types.py`` /
``core/run/_types.py`` precedent); the dispatcher + loop land at A5+.
"""

from cognic_agentos.core.agent._types import (
    AgentAskResult,
    AgentDispatchRefusalReason,
    AgentGrantNotRequested,
    AgentRunTerminalState,
    CapabilityRef,
    GrantedCapabilities,
    LoadedAgentRecord,
)
from cognic_agentos.core.agent.assignments import AssignmentStore

__all__ = [
    "AgentAskResult",
    "AgentDispatchRefusalReason",
    "AgentGrantNotRequested",
    "AgentRunTerminalState",
    "AssignmentStore",
    "CapabilityRef",
    "GrantedCapabilities",
    "LoadedAgentRecord",
]
