"""Sprint-7A T14 fixture agent — minimal-but-valid synthetic Agent subclass.

Inert by design: ``handle()`` returns the Wave-1 single-text-Part
sentinel response. The fixture is exercised by the sign + verify
orchestrators which dispatch via the entry-point group; the agent
body itself is never invoked under T14 (sign + verify run filesystem-
level operations on the pack tree, not the pack code).
"""

from __future__ import annotations

from typing import Any, ClassVar

from cognic_agentos.protocol.a2a_capability_negotiation import A2ACapabilities
from cognic_agentos.protocol.a2a_endpoint import TaskRecord
from cognic_agentos.sdk.agent import Agent


class SignTargetAgent(Agent):
    """Inert agent used by the T14 sign + verify fixture pack."""

    name: ClassVar[str] = "sign_target"
    declared_capabilities: ClassVar[A2ACapabilities] = A2ACapabilities(
        capabilities_supported=(),
        streaming=False,
        push_notifications=False,
        extended_agent_card=False,
        artifacts_supported=False,
    )

    async def handle(
        self,
        payload: bytes,
        *,
        task: TaskRecord,
    ) -> dict[str, Any]:
        """Return the Wave-1 sentinel response."""
        del payload, task
        return {"text": "ok"}
