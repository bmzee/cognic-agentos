"""Sprint 5 (A2A inbound reachability) — Wave-1 receiver-posture conformance.

Pins the inbound A2A receiver's Wave-1 method posture over a REAL
:class:`A2AEndpoint` (per ADR-003 + ``docs/A2A-CONFORMANCE.md``).
Three postures, each asserted against the wire-public closed-enum
:attr:`A2AEndpointError.code` (the A2A 1.0 spec error code) +
``A2AEndpointError.payload["policy_reason"]`` (the AgentOS policy
reason a remote caller observes in ``error.data``):

  1. ``message/send`` → a REGISTERED ``agents``-kind pack SUCCEEDS —
     the endpoint routes to the agent handler and returns its
     JSON-RPC response dict unchanged (verbatim passthrough per
     ``a2a_endpoint.py`` ``return response_dict``).
  2. ``message/send`` → an UNKNOWN agent is REFUSED at the routing
     gate (Gate 4) with spec ``method_not_found`` + policy reason
     ``unknown_target``. The registry's internal refusal taxonomy is
     never leaked across the A2A wire — every routing miss collapses
     to ``unknown_target``.
  3. ``tasks/cancel`` / ``tasks/get`` / ``message/stream`` — real
     A2A 1.0 methods this Wave-1 receiver does NOT yet serve — are
     REFUSED at the Wave-1 method allow-list (Gate 3.5) with spec
     ``unsupported_operation`` + policy reason
     ``method_not_supported_wave1``, BEFORE routing / task creation /
     dispatch. The auxiliary slice that broadens the receiver lifts
     this gate; until then the receiver serves only ``message/send``.

This is the receiver-posture conformance complement to the gate-by-
gate unit suite at ``tests/unit/protocol/test_a2a_endpoint.py``: it
builds the SAME real ``A2AEndpoint`` (a stub-registered ``agents``-kind
pack for the success path; mock audit / decision-history / authz /
agent-card-verifier collaborators) and exercises the end-to-end
``handle()`` posture a remote A2A caller observes. The construction
mirrors that suite's ``endpoint`` fixture verbatim so the success
path actually routes + dispatches.

No env gate (unlike the ``tests/conformance/sandbox`` suite, which
needs a live Docker / K8s runtime): ``a2a-sdk`` is a hard requirement
of ``A2AEndpoint`` construction (``require_a2a()`` fires at
``__init__``), and the unit suite this mirrors runs un-gated in the
same venv. A kernel-image deployment without the SDK never constructs
the endpoint at all — the SDK-gated lifespan leaves
``app.state.a2a_endpoint = None`` and the route returns 503.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.protocol.a2a_authz import A2APinnedToken
from cognic_agentos.protocol.a2a_endpoint import A2AEndpoint, A2AEndpointError
from cognic_agentos.protocol.plugin_registry import PluginNotRegistered

# =============================================================================
# Fixtures — mirror tests/unit/protocol/test_a2a_endpoint.py::endpoint so the
# conformance posture is exercised over a REAL A2AEndpoint with a stub-
# registered agents-kind pack on the success path.
# =============================================================================


@pytest.fixture
def audit_store() -> MagicMock:
    mock = MagicMock()
    mock.append = AsyncMock(return_value=(None, b""))
    return mock


@pytest.fixture
def decision_history_store() -> MagicMock:
    mock = MagicMock()
    mock.append = AsyncMock(return_value=(None, b""))
    return mock


@pytest.fixture
def authz_client() -> MagicMock:
    """Mock A2AAuthzClient — success path returns a valid pinned token
    so the conformance posture exercises the method/routing gates, not
    the authentication gate (covered by the unit suite)."""
    mock = MagicMock()
    mock.validate_inbound_token = AsyncMock(
        return_value=A2APinnedToken(
            value="active-token",
            tenant_id="bank_a",
            issued_at=1_700_000_000.0,
            expires_at=None,
        ),
    )
    return mock


@pytest.fixture
def agent_card_verifier() -> MagicMock:
    return MagicMock()


@pytest.fixture
def plugin_registry() -> MagicMock:
    """Stub-registered ``agents``-kind pack — ``load`` returns an agent
    stub whose ``handle`` returns a JSON-RPC-shaped success dict. The
    unknown-target test overrides ``load.side_effect``."""
    mock = MagicMock()

    agent = MagicMock()
    agent.handle = AsyncMock(
        return_value={"jsonrpc": "2.0", "id": 1, "result": {"ok": True}},
    )

    mock.load = MagicMock(return_value=agent)
    mock._agent_stub = agent  # convenience handle for the dispatch spy
    return mock


@pytest.fixture
def endpoint(
    authz_client: MagicMock,
    agent_card_verifier: MagicMock,
    plugin_registry: MagicMock,
    audit_store: MagicMock,
    decision_history_store: MagicMock,
) -> A2AEndpoint:
    return A2AEndpoint(
        settings=build_settings_without_env_file(),
        plugin_registry=plugin_registry,
        authz_client=authz_client,
        agent_card_verifier=agent_card_verifier,
        audit_store=audit_store,
        decision_history_store=decision_history_store,
    )


def _good_call_kwargs(**overrides: Any) -> dict[str, Any]:
    """A method-gate-clean, authn-clean, version-clean inbound call.
    Refusal-posture tests override ``payload`` / ``target_agent``."""
    base: dict[str, Any] = {
        "target_agent": "agent_alpha",
        "payload": _payload("message/send"),
        "authorization_header": "Bearer active-token",
        "a2a_version_header": "1.0",
        "parent_trace_id": "parent-trace-1",
        "tenant_id": "bank_a",
        "request_id": "rid-conformance-1",
    }
    base.update(overrides)
    return base


def _payload(method: str) -> bytes:
    """A minimal A2A 1.0 JSON-RPC envelope carrying ``method`` with
    empty params — no ``parts``, so the Wave-2 gate (Gate 3) lets it
    through and the Wave-1 method allow-list (Gate 3.5) decides."""
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": {}}).encode()


# =============================================================================
# Wave-1 receiver posture
# =============================================================================


class TestWave1ReceiverPosture:
    """The three closed-enum postures a remote A2A caller observes from
    the Wave-1 inbound receiver."""

    async def test_message_send_to_registered_agent_succeeds(
        self,
        endpoint: A2AEndpoint,
        plugin_registry: MagicMock,
    ) -> None:
        """Posture 1 — ``message/send`` to a registered ``agents``-kind
        pack routes + dispatches and returns the agent handler's
        JSON-RPC response dict verbatim."""
        result = await endpoint.handle(**_good_call_kwargs(payload=_payload("message/send")))

        # Verbatim passthrough of the agent handler's response dict.
        assert result == {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
        # Resolved under the ``agents`` PluginKind, then dispatched once.
        plugin_registry.load.assert_called_once_with("agents", "agent_alpha")
        plugin_registry._agent_stub.handle.assert_called_once()

    async def test_message_send_to_unknown_agent_refused_method_not_found(
        self,
        endpoint: A2AEndpoint,
        plugin_registry: MagicMock,
    ) -> None:
        """Posture 2 — ``message/send`` to an UNKNOWN agent refuses at
        the routing gate with spec ``method_not_found`` + policy reason
        ``unknown_target`` (the registry's internal refusal taxonomy is
        never leaked across the wire)."""
        plugin_registry.load.side_effect = PluginNotRegistered(
            "pack agents/'ghost-agent' has not been registered"
        )

        with pytest.raises(A2AEndpointError) as ei:
            await endpoint.handle(
                **_good_call_kwargs(
                    target_agent="ghost-agent",
                    payload=_payload("message/send"),
                )
            )

        assert ei.value.code == "method_not_found"
        assert ei.value.payload["policy_reason"] == "unknown_target"
        # No agent dispatch — routing refused before any handler ran.
        plugin_registry._agent_stub.handle.assert_not_called()

    @pytest.mark.parametrize("method", ["tasks/cancel", "tasks/get", "message/stream"])
    async def test_non_send_method_refused_unsupported_operation(
        self,
        endpoint: A2AEndpoint,
        plugin_registry: MagicMock,
        method: str,
    ) -> None:
        """Posture 3 — a real A2A 1.0 method this Wave-1 receiver does
        not yet serve refuses at the Wave-1 method allow-list with spec
        ``unsupported_operation`` + policy reason
        ``method_not_supported_wave1`` BEFORE routing / task creation /
        dispatch."""
        with pytest.raises(A2AEndpointError) as ei:
            await endpoint.handle(**_good_call_kwargs(payload=_payload(method)))

        assert ei.value.code == "unsupported_operation"
        assert ei.value.payload["policy_reason"] == "method_not_supported_wave1"
        # Gate 3.5 fires before Gate 4 (routing) / Gate 5 (dispatch):
        # no TaskRecord minted, registry never consulted, agent never run.
        assert endpoint._tasks == {}
        plugin_registry.load.assert_not_called()
        plugin_registry._agent_stub.handle.assert_not_called()
