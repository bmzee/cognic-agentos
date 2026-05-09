"""Sprint-7A T15 reference agent — inert ``handle()``.

The agent receives an A2A 1.0 task envelope via ``handle(payload,
task=...)``; it ignores the payload and returns ``{"text": "ok"}``.
Lets pack authors copy a working ``Agent`` subclass with the
canonical ``declared_capabilities`` shape already in place.

Per Doctrine D (plan §59), the pack is **inert** — NOT a model for
production agent behavior.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from cognic_agentos.protocol.a2a_capability_negotiation import A2ACapabilities
from cognic_agentos.sdk.agent import Agent

if TYPE_CHECKING:
    from cognic_agentos.protocol.a2a_endpoint import TaskRecord


class ExampleMinimalAgent(Agent):
    """Inert example agent — Wave-1 reference implementation."""

    name: ClassVar[str] = "example_minimal"
    declared_capabilities: ClassVar[A2ACapabilities] = A2ACapabilities(
        capabilities_supported=(),
        streaming=False,
        push_notifications=False,
        extended_agent_card=False,
        artifacts_supported=False,
        extensions=(),
        deferred_wave2_features=(),
    )

    async def handle(
        self,
        payload: bytes,
        *,
        task: TaskRecord,
    ) -> dict[str, Any]:
        del payload, task  # inert reference; ignore A2A envelope + task record
        return {"text": "ok"}
