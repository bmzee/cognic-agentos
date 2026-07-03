"""M6 (ADR-025) — governed skill-execution package.

``SkillBroker`` (CRITICAL CONTROLS) is the per-invocation Unix-socket
enforcement point between sandboxed skill actions and
``MCPHost.call_tool``; ``SkillCallProxy`` is the consumer-owned seam
the Task-A5 executor wires the real host through.
"""

from cognic_agentos.core.skill._types import SkillCallProxy
from cognic_agentos.core.skill.broker import SkillBroker

__all__ = [
    "SkillBroker",
    "SkillCallProxy",
]
