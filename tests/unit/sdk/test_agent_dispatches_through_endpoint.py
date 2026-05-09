# ruff: noqa: RUF012
# ^ stub agent declares ``captured: list[tuple[bytes, TaskRecord]] = []`` as a
#   ClassVar accumulator the test asserts against; throwaway test class, no
#   typing.ClassVar wrapper needed.
"""Sprint-7A T2 — load-bearing alignment test for Agent ↔ A2AEndpoint.

R1 P2 #2: the SDK Agent base class signature MUST match what
``A2AEndpoint`` actually invokes at dispatch time. This test wires
a stub agent (subclassing the SDK base) through a **real**
``A2AEndpoint.handle`` invocation with mocked authz + registry +
audit + decision-history. If the runtime endpoint's dispatch shape
changes (or the SDK base signature drifts), this test trips before
pack code does.

Shape pinned: ``await agent.handle(payload_bytes, task=TaskRecord)``.
The endpoint's gates 1-3 (version negotiation + authn + Wave-2
classification) run before dispatch reaches the agent; gate 4
(routing) returns the stub from the mocked registry; gate 5
mints a TaskRecord and dispatches. The test asserts the stub
captured ``(payload_bytes, TaskRecord)`` and the endpoint returned
the stub's response verbatim.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.protocol.a2a_authz import A2APinnedToken
from cognic_agentos.protocol.a2a_capability_negotiation import A2ACapabilities
from cognic_agentos.protocol.a2a_endpoint import A2AEndpoint, TaskRecord


async def test_sdk_agent_dispatches_through_real_a2a_endpoint() -> None:
    """Wire an SDK Agent subclass through a real A2AEndpoint;
    confirm the runtime calls ``agent.handle(payload, task=task)``
    matching the SDK base contract."""
    from cognic_agentos.sdk.agent import Agent

    class _StubAgent(Agent):
        """Captures the dispatched (payload, task) pair so the
        test can assert the runtime ↔ SDK contract."""

        name = "stub_agent"
        declared_capabilities = A2ACapabilities()
        captured: list[tuple[bytes, TaskRecord]] = []

        async def handle(self, payload: bytes, *, task: TaskRecord) -> dict[str, Any]:
            type(self).captured.append((payload, task))
            return {"echo": "ok", "agent": self.name}

    # Mock authz to accept every inbound token.
    authz = MagicMock()
    authz.validate_inbound_token = AsyncMock(
        return_value=A2APinnedToken(
            value="active-token",
            tenant_id="bank_a",
            issued_at=1_700_000_000.0,
            expires_at=None,
        ),
    )

    # Plugin registry resolves the stub by name.
    stub_agent = _StubAgent()
    registry = MagicMock()
    registry.load = MagicMock(return_value=stub_agent)

    # Audit + decision-history are silent-succeed mocks.
    audit_store = MagicMock()
    audit_store.append = AsyncMock(return_value=(None, b""))
    decision_history_store = MagicMock()
    decision_history_store.append = AsyncMock(return_value=(None, b""))

    endpoint = A2AEndpoint(
        settings=build_settings_without_env_file(),
        plugin_registry=registry,
        authz_client=authz,
        agent_card_verifier=MagicMock(),
        audit_store=audit_store,
        decision_history_store=decision_history_store,
    )

    # Minimal Wave-1 task envelope; the endpoint's gates accept it
    # (no Wave-2 features, no caller-URL, well-shaped JSON).
    payload_bytes = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "rid-sdk-alignment-1",
            "method": "message/send",
            "params": {"message": {"parts": [{"text": "hi"}]}},
        }
    ).encode("utf-8")

    result = await endpoint.handle(
        target_agent="stub_agent",
        payload=payload_bytes,
        authorization_header="Bearer active-token",
        a2a_version_header="1.0",
        parent_trace_id="trace-sdk-alignment-1",
        tenant_id="bank_a",
        request_id="rid-sdk-alignment-1",
    )

    # SDK contract: the runtime called agent.handle(payload, task=task).
    assert len(_StubAgent.captured) == 1
    captured_payload, captured_task = _StubAgent.captured[0]

    # The payload bytes are passed through verbatim.
    assert captured_payload == payload_bytes

    # The task is a real TaskRecord with the lifecycle fields populated.
    assert isinstance(captured_task, TaskRecord)
    assert captured_task.parent_trace_id == "trace-sdk-alignment-1"
    assert captured_task.target_agent == "stub_agent"
    # child_trace_id minted by the endpoint at gate 5; non-empty.
    assert captured_task.child_trace_id
    # task_id minted by the endpoint at gate 5; non-empty.
    assert captured_task.task_id

    # The endpoint returned the stub's response verbatim.
    assert result == {"echo": "ok", "agent": "stub_agent"}
