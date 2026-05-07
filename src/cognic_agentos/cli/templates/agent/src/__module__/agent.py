"""{{ class_name }} — AUTHOR-FILL: short description of what this agent does.

The pack-author contract:

  - Override ``handle(payload, *, task)`` (the public abstract; the
    signature matches the shipped Sprint-6 ``A2AEndpoint`` dispatch
    contract at ``protocol/a2a_endpoint.py:568``).
  - Declare ``declared_capabilities`` as a ClassVar carrying the
    Wave-1 A2A capability shape your agent advertises.
"""

from __future__ import annotations

from typing import Any, ClassVar

from cognic_agentos.protocol.a2a_capability_negotiation import A2ACapabilities
from cognic_agentos.protocol.a2a_endpoint import TaskRecord
from cognic_agentos.sdk.agent import Agent


class {{ class_name }}(Agent):
    """AUTHOR-FILL: docstring describing what this agent does."""

    name: ClassVar[str] = "{{ pack_name }}"

    declared_capabilities: ClassVar[A2ACapabilities] = A2ACapabilities()

    async def handle(self, payload: bytes, *, task: TaskRecord) -> dict[str, Any]:
        """AUTHOR-FILL: implement the agent body.

        ``payload`` is the raw inbound JSON-RPC 2.0 envelope bytes
        (already authn-validated + Wave-2-feature-refusal-checked +
        version-negotiated by the endpoint's gates 1-3). ``task`` is
        the :class:`TaskRecord` minted at gate 5; read
        ``task.task_id`` / ``task.parent_trace_id`` /
        ``task.child_trace_id`` for cross-agent chain linkage.
        """
        raise NotImplementedError(
            "AUTHOR-FILL: implement {{ class_name }}.handle"
        )
