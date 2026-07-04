"""M6 (ADR-025) — governed skill-execution package.

``SkillBroker`` (CRITICAL CONTROLS) is the per-invocation Unix-socket
enforcement point between sandboxed skill actions and
``MCPHost.call_tool``; ``SkillCallProxy`` is the consumer-owned seam
the Task-A5 executor wires the real host through. ``SkillExecutor``
(CRITICAL CONTROLS) orchestrates the one governed sandboxed run.
"""

from cognic_agentos.core.skill._types import (
    LoadedSkillRecord,
    SkillCallProxy,
    SkillInvokeRefusalReason,
    SkillInvokeResult,
    SkillInvokeTerminalState,
    SkillRecordLoader,
)
from cognic_agentos.core.skill.broker import SkillBroker
from cognic_agentos.core.skill.executor import SkillExecutor

__all__ = [
    "LoadedSkillRecord",
    "SkillBroker",
    "SkillCallProxy",
    "SkillExecutor",
    "SkillInvokeRefusalReason",
    "SkillInvokeResult",
    "SkillInvokeTerminalState",
    "SkillRecordLoader",
]
