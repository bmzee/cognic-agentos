"""Sprint-7A T2 — `agentos_sdk.Agent` base-class contract tests.

The Agent base class signature MUST match what the shipped Sprint-6
``A2AEndpoint`` actually invokes at dispatch time
(`protocol/a2a_endpoint.py:568`):

    response = await agent.handle(payload, task=task)

Per R1 P2 #2 reviewer correction: the SDK + the runtime endpoint share
ONE contract — pinned by the alignment test in
``test_agent_dispatches_through_endpoint.py``.
"""

from __future__ import annotations

import inspect

import pytest

# ---------------------------------------------------------------------------
# (a) Abstract method enforcement on `handle`
# ---------------------------------------------------------------------------


def test_agent_handle_is_abstract() -> None:
    from cognic_agentos.sdk.agent import Agent

    class IncompleteAgent(Agent):
        name = "incomplete"
        # declared_capabilities omitted on purpose — abstract should
        # still trip on `handle` first.

    with pytest.raises(TypeError, match="abstract"):
        IncompleteAgent()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# (b) ClassVar declarations
# ---------------------------------------------------------------------------


def test_agent_classvar_name_declared() -> None:
    from cognic_agentos.sdk.agent import Agent

    assert "name" in Agent.__annotations__


def test_agent_classvar_declared_capabilities_declared() -> None:
    from cognic_agentos.sdk.agent import Agent

    assert "declared_capabilities" in Agent.__annotations__


# ---------------------------------------------------------------------------
# (c) handle signature matches shipped runtime endpoint contract
# ---------------------------------------------------------------------------


def test_agent_handle_signature_matches_a2a_endpoint_dispatch_shape() -> None:
    """R1 P2 #2 — pin the SDK `Agent.handle` signature against the
    shipped `A2AEndpoint` dispatch shape. This test inspects the
    declared signature of the abstract method; the alignment test
    in `test_agent_dispatches_through_endpoint.py` exercises the
    real runtime path.

    Shape: `async def handle(self, payload: bytes, *, task: TaskRecord) -> dict`.
    Specifically: `payload` is positional + bytes-typed; `task` is
    keyword-only + TaskRecord-typed.
    """
    import typing

    from cognic_agentos.protocol.a2a_endpoint import TaskRecord
    from cognic_agentos.sdk.agent import Agent

    # Param-kind invariant: payload positional, task keyword-only.
    sig = inspect.signature(Agent.handle)
    params = sig.parameters

    assert "payload" in params
    assert params["payload"].kind in (
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        inspect.Parameter.POSITIONAL_ONLY,
    )

    assert "task" in params
    assert params["task"].kind == inspect.Parameter.KEYWORD_ONLY

    # Type-annotation invariant via get_type_hints (resolves PEP 563
    # string annotations from `from __future__ import annotations`).
    hints = typing.get_type_hints(Agent.handle)
    assert hints["payload"] is bytes
    assert hints["task"] is TaskRecord
