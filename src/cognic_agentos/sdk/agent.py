"""Sprint-7A T2 — `agentos_sdk.Agent` base class for A2A-speaking agents.

R1 P2 #2 reviewer correction: the SDK base class signature MUST match
what the shipped Sprint-6 ``A2AEndpoint`` actually invokes at dispatch
time (`protocol/a2a_endpoint.py:568`):

    response = await agent.handle(payload, task=task)

Where ``payload: bytes`` is positional (the raw inbound JSON-RPC 2.0
envelope bytes — already authn-validated + Wave-2-feature-refusal-checked
+ version-negotiated by the endpoint's gates 1-3) and ``task: TaskRecord``
is keyword-only (the lifecycle record the endpoint mints at gate 5;
subclasses read ``task.task_id`` / ``task.target_agent`` /
``task.parent_trace_id`` / ``task.child_trace_id`` for cross-agent
chain linkage). ``TaskRecord`` deliberately does NOT carry
``tenant_id`` — tenant context is enforced at the endpoint boundary
(authz gate + audit emission), not threaded through the agent surface.
If a future wave needs tenant-aware agents, that's an ADR-level
decision (extend ``TaskRecord`` or add a context-var hand-off), not
an SDK signature change.

The SDK and the runtime endpoint share ONE contract — pinned by the
load-bearing alignment test in
``tests/unit/sdk/test_agent_dispatches_through_endpoint.py``.

Sub-agent dispatch (Sprint 8 per ADR-005) is NOT a kwarg here — when
Sprint 8 lands, sub-agent dispatch is accessed via a context-var
pattern that the harness sets up before calling ``handle``, NOT by
extending this signature (which would break every shipped pack).
"""

from __future__ import annotations

import abc
from typing import Any, ClassVar

from cognic_agentos.protocol.a2a_capability_negotiation import A2ACapabilities
from cognic_agentos.protocol.a2a_endpoint import TaskRecord


class Agent(abc.ABC):
    """Base class for ``cognic.agents`` entry-point implementations.

    Subclass receives Wave-1 A2A task envelopes via ``handle()``;
    the SDK and the runtime ``A2AEndpoint`` share the contract.
    """

    name: ClassVar[str]
    declared_capabilities: ClassVar[A2ACapabilities]

    @abc.abstractmethod
    async def handle(
        self,
        payload: bytes,
        *,
        task: TaskRecord,
    ) -> dict[str, Any]:
        """Agent-specific behaviour.

        ``payload`` is the raw inbound JSON-RPC 2.0 envelope bytes
        (already authn-validated + Wave-2-feature-refusal-checked +
        version-negotiated by the endpoint's gates 1-3 before
        dispatch reaches here).

        ``task`` is the :class:`TaskRecord` minted at the
        endpoint's gate 5; subclasses read ``task.task_id`` /
        ``task.target_agent`` / ``task.parent_trace_id`` /
        ``task.child_trace_id`` for cross-agent chain linkage.
        ``TaskRecord`` does NOT carry ``tenant_id`` — tenant
        context is enforced at the endpoint boundary, not the
        SDK surface.

        The agent's response is wrapped by the endpoint's
        lifecycle machinery into a ``StreamResponse`` envelope;
        agent code returns a Wave-1 dict per A2A 1.0 spec.
        """
        raise NotImplementedError


__all__ = ["Agent"]
