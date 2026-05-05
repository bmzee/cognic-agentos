"""Sprint 6 T9 — protocol/a2a_endpoint.py contract tests.

Pin the inbound A2A receiver + task lifecycle state machine + cross-
agent chain linkage per ADR-003 + Sprint-6 plan-of-record T9. The
endpoint is on the critical-controls floor (single owner of the
state machine; chain linkage across the A2A boundary).

Six gates (in fixed order):

  1. Version negotiation (``A2A-Version`` header → 6-case matrix
     from T8 — only ``accepted`` / ``higher_minor_degraded`` proceed).
  2. Authentication (per-tenant pinned token via T5
     :class:`A2AAuthzClient`).
  3. Wave-2 feature refusal (push-notification subscribe / task
     resumption / multimodal Part shapes all map to
     ``unsupported_operation`` + ``wave2_feature_refused``). Fires
     BEFORE routing so a registered Wave-1 agent never receives
     Wave-2 traffic.
  4. Routing (target agent → :class:`PluginRegistry` lookup; unknown
     target maps to spec ``method_not_found`` with the
     :data:`A2APolicyRefusalReason` ``unknown_target`` carried in
     ``data.policy_reason``).
  5. Task creation + dispatch (single-writer ``TaskState``
     transitions; ``created → running → succeeded | failed``).
  6. Lifecycle transition emit (audit + decision-history rows on
     every transition; cancellation lands in T13).

Chain linkage: every inbound message takes the caller's
``parent_trace_id`` (or mints one if absent) + a fresh
``child_trace_id``; both flow into ``a2a.task_*`` audit/decision
rows so the cross-agent chain is walkable end-to-end.

Mirrors Sprint-5 ``test_mcp_host.py`` shape — same fixture
discipline (mock AuditStore / DecisionHistoryStore /
PluginRegistry / authz client), same audit-emission pattern (one
row per outcome), same token-free invariant (raw bearer bytes
NEVER appear in audit / decision payloads).
"""

from __future__ import annotations

import asyncio
import dataclasses
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.core.audit import AuditEvent
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.protocol.a2a_authz import (
    A2AAuthzError,
    A2APinnedToken,
)
from cognic_agentos.protocol.a2a_endpoint import (
    A2AEndpoint,
    A2AEndpointError,
    TaskRecord,
    TaskState,
)

# =============================================================================
# Fixtures
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
    """Mock A2AAuthzClient. Default: success — returns a pinned
    token. Tests that exercise refusal paths override
    ``validate_inbound_token.side_effect``."""
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
    """Mock A2AAgentCardVerifier — Sprint-6 T7 dependency that the
    endpoint holds for outbound dispatch URL resolution. T9 itself
    only handles inbound; the verifier is on the constructor for
    later (T10 streaming) consumers."""
    return MagicMock()


@pytest.fixture
def plugin_registry() -> MagicMock:
    """Mock PluginRegistry. Default: ``load`` returns an agent stub
    whose ``handle`` returns a successful response."""
    mock = MagicMock()

    agent = MagicMock()
    agent.handle = AsyncMock(return_value={"result": "ok"})

    mock.load = MagicMock(return_value=agent)
    mock._agent_stub = agent  # convenience handle for tests
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
    base: dict[str, Any] = {
        "target_agent": "agent_alpha",
        "payload": b'{"message":"hello"}',
        "authorization_header": "Bearer active-token",
        "a2a_version_header": "1.0",
        "parent_trace_id": "parent-trace-1",
        "tenant_id": "bank_a",
        "request_id": "rid-good-1",
    }
    base.update(overrides)
    return base


# =============================================================================
# Gate 1 — version negotiation
# =============================================================================


class TestGate1Version:
    """The ``A2A-Version`` header gate fires BEFORE authentication.

    Anything other than ``accepted`` / ``higher_minor_degraded`` from
    T8 :func:`negotiate_inbound_version` raises an
    :class:`A2AEndpointError` with the spec ``version_not_supported``
    code; the ``Supported-A2A-Versions`` value flows to the caller for
    retry hygiene.
    """

    async def test_absent_header_refused(self, endpoint: A2AEndpoint) -> None:
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs(a2a_version_header=None))
        assert exc.value.code == "version_not_supported"
        assert exc.value.payload["outcome"] == "absent_rejected"
        assert exc.value.payload["supported"] == "1.0"

    async def test_legacy_0x_refused(self, endpoint: A2AEndpoint) -> None:
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs(a2a_version_header="0.3"))
        assert exc.value.code == "version_not_supported"
        assert exc.value.payload["outcome"] == "legacy_rejected"

    async def test_unsupported_2x_refused(self, endpoint: A2AEndpoint) -> None:
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs(a2a_version_header="2.0"))
        assert exc.value.code == "version_not_supported"
        assert exc.value.payload["outcome"] == "unsupported_rejected"

    async def test_malformed_refused(self, endpoint: A2AEndpoint) -> None:
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs(a2a_version_header="v1.0"))
        assert exc.value.code == "version_not_supported"
        assert exc.value.payload["outcome"] == "malformed_rejected"

    async def test_higher_minor_degraded_proceeds(
        self,
        endpoint: A2AEndpoint,
        plugin_registry: MagicMock,
    ) -> None:
        """Same-major + higher-minor proceeds (with degradation
        warning surfaced separately by the caller)."""
        await endpoint.handle(**_good_call_kwargs(a2a_version_header="1.99"))
        plugin_registry.load.assert_called_once()

    async def test_version_gate_fires_before_authn(
        self,
        endpoint: A2AEndpoint,
        authz_client: MagicMock,
    ) -> None:
        """Critical ordering: a malformed version header MUST refuse
        WITHOUT consulting the authz client. Else a stale token can
        masquerade as a version-supported request and burn a Vault
        read."""
        with pytest.raises(A2AEndpointError):
            await endpoint.handle(**_good_call_kwargs(a2a_version_header="0.3"))
        authz_client.validate_inbound_token.assert_not_called()


# =============================================================================
# Gate 2 — authentication
# =============================================================================


class TestGate2Authn:
    """T5 :class:`A2AAuthzClient` failures map onto spec error codes
    via the closed-enum :data:`A2AAuthzReason` → :data:`A2AErrorCode`
    mapping. Anonymous → ``invalid_request`` + policy-reason
    ``anonymous_refused``; everything else → ``invalid_request`` +
    policy-reason ``tenant_token_invalid``.
    """

    async def test_anonymous_refused(
        self,
        endpoint: A2AEndpoint,
        authz_client: MagicMock,
    ) -> None:
        authz_client.validate_inbound_token.side_effect = A2AAuthzError(
            reason="a2a_anonymous_refused",
            message="missing Authorization header",
            tenant_id="bank_a",
            request_id="rid-anon-1",
        )
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs(authorization_header=None))
        assert exc.value.code == "invalid_request"
        assert exc.value.payload["policy_reason"] == "anonymous_refused"
        assert exc.value.payload["authz_reason"] == "a2a_anonymous_refused"

    async def test_token_malformed_refused(
        self,
        endpoint: A2AEndpoint,
        authz_client: MagicMock,
    ) -> None:
        authz_client.validate_inbound_token.side_effect = A2AAuthzError(
            reason="a2a_token_malformed",
            message="bad token bytes",
        )
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs())
        assert exc.value.code == "invalid_request"
        assert exc.value.payload["policy_reason"] == "tenant_token_invalid"
        assert exc.value.payload["authz_reason"] == "a2a_token_malformed"

    async def test_tenant_mismatch_refused(
        self,
        endpoint: A2AEndpoint,
        authz_client: MagicMock,
    ) -> None:
        authz_client.validate_inbound_token.side_effect = A2AAuthzError(
            reason="a2a_tenant_mismatch",
            message="cross-tenant token reuse",
        )
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs())
        assert exc.value.code == "invalid_request"
        assert exc.value.payload["policy_reason"] == "tenant_token_invalid"

    async def test_authn_gate_fires_before_routing(
        self,
        endpoint: A2AEndpoint,
        authz_client: MagicMock,
        plugin_registry: MagicMock,
    ) -> None:
        """Failed authn MUST refuse without ever touching the plugin
        registry — exhausting registry lookups against an unauthn'd
        caller is a DoS amplifier."""
        authz_client.validate_inbound_token.side_effect = A2AAuthzError(
            reason="a2a_token_revoked",
            message="token on revocation list",
        )
        with pytest.raises(A2AEndpointError):
            await endpoint.handle(**_good_call_kwargs())
        plugin_registry.load.assert_not_called()

    async def test_authn_token_bytes_never_in_payload(
        self,
        endpoint: A2AEndpoint,
        authz_client: MagicMock,
    ) -> None:
        """Token-free invariant: even on refusal the bearer token
        bytes MUST NOT appear in :class:`A2AEndpointError.payload`."""
        authz_client.validate_inbound_token.side_effect = A2AAuthzError(
            reason="a2a_token_malformed", message="bad token"
        )
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(
                **_good_call_kwargs(authorization_header="Bearer SUPER-SECRET-12345")
            )
        # Walk the entire payload tree for the secret string.
        rendered = repr(exc.value.payload)
        assert "SUPER-SECRET-12345" not in rendered


# =============================================================================
# Gate 4 — routing (unknown target)
# =============================================================================


class TestGate4Routing:
    """Unknown target → ``method_not_found`` (spec) + policy-reason
    ``unknown_target``. Per ADR-002, target identification is by
    entry-point name; the registry does the lookup."""

    async def test_unknown_target_refused(
        self,
        endpoint: A2AEndpoint,
        plugin_registry: MagicMock,
    ) -> None:
        from cognic_agentos.protocol.plugin_registry import PluginNotRegistered

        plugin_registry.load.side_effect = PluginNotRegistered(
            "pack agents/'unknown-agent' has not been registered"
        )
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs(target_agent="unknown-agent"))
        assert exc.value.code == "method_not_found"
        assert exc.value.payload["policy_reason"] == "unknown_target"
        assert exc.value.payload["target_agent"] == "unknown-agent"

    async def test_refused_pack_treated_as_unknown_target(
        self,
        endpoint: A2AEndpoint,
        plugin_registry: MagicMock,
    ) -> None:
        """A pack registered with a refusal status (e.g. trust-gate
        refusal) MUST surface as ``unknown_target`` to remote A2A
        callers — exposing the registry's internal
        :class:`RegistrationRefused` reasons would leak trust-state
        across the wire."""
        from cognic_agentos.protocol.plugin_registry import RegistrationRefused

        plugin_registry.load.side_effect = RegistrationRefused(
            "agents", "blocked-agent", "cosign_verification_failed"
        )
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs(target_agent="blocked-agent"))
        assert exc.value.code == "method_not_found"
        assert exc.value.payload["policy_reason"] == "unknown_target"

    async def test_routing_resolves_under_agents_kind(
        self,
        endpoint: A2AEndpoint,
        plugin_registry: MagicMock,
    ) -> None:
        """Endpoint MUST resolve under the ``agents`` PluginKind.
        Bypassing this pins the boundary against future drift where
        an attacker registers under ``tools``/``skills`` to capture
        an A2A target name."""
        await endpoint.handle(**_good_call_kwargs(target_agent="agent_alpha"))
        plugin_registry.load.assert_called_once_with("agents", "agent_alpha")


# =============================================================================
# Gate 3 — Wave-2 feature refusal
# =============================================================================


class TestGate3Wave2:
    """Push-notification subscribe + multi-modal payloads + long-
    running task resumption all map to spec ``unsupported_operation``
    + policy-reason ``wave2_feature_refused`` per Decision Lock #2."""

    async def test_push_notification_subscribe_refused(
        self,
        endpoint: A2AEndpoint,
    ) -> None:
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(
                **_good_call_kwargs(
                    payload=b'{"method":"tasks/pushNotificationConfig/set"}',
                )
            )
        assert exc.value.code == "unsupported_operation"
        assert exc.value.payload["policy_reason"] == "wave2_feature_refused"
        assert exc.value.payload["wave2_feature"] == "push_notification_subscribe"

    async def test_resumption_refused(
        self,
        endpoint: A2AEndpoint,
    ) -> None:
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(
                **_good_call_kwargs(
                    payload=b'{"method":"tasks/resubscribe"}',
                )
            )
        assert exc.value.code == "unsupported_operation"
        assert exc.value.payload["policy_reason"] == "wave2_feature_refused"
        assert exc.value.payload["wave2_feature"] == "task_resumption"


# =============================================================================
# Gate 5 + 6 — task lifecycle (single-writer + audit + dh emit)
# =============================================================================


class TestGate5Lifecycle:
    """Task lifecycle: ``created → running → succeeded | failed``.

    Single owner; transitions are single-writer (no concurrent
    mutation). Every transition emits exactly one audit row + exactly
    one decision_history row, both correlated by ``request_id``.
    """

    async def test_happy_path_succeeded(
        self,
        endpoint: A2AEndpoint,
        plugin_registry: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        result = await endpoint.handle(**_good_call_kwargs())
        assert result["result"] == "ok"
        plugin_registry._agent_stub.handle.assert_called_once()

        # Three audit rows expected: task_received (created),
        # task_running, task_succeeded.
        event_types = [call.args[0].event_type for call in audit_store.append.call_args_list]
        assert event_types == [
            "a2a.task_received",
            "a2a.task_running",
            "a2a.task_succeeded",
        ]

    async def test_handler_failure_emits_failed_transition(
        self,
        endpoint: A2AEndpoint,
        plugin_registry: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        plugin_registry._agent_stub.handle.side_effect = RuntimeError("boom")
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs())
        assert exc.value.code == "internal_error"
        assert exc.value.payload["error_type"] == "RuntimeError"

        event_types = [call.args[0].event_type for call in audit_store.append.call_args_list]
        assert event_types == [
            "a2a.task_received",
            "a2a.task_running",
            "a2a.task_failed",
        ]

    async def test_handler_failure_does_not_leak_exception_message(
        self,
        endpoint: A2AEndpoint,
        plugin_registry: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        """Sprint-5 T15 R1 P2 #3 doctrine: raw lower-layer exception
        text MUST NOT appear in the error payload — only the class
        name."""
        plugin_registry._agent_stub.handle.side_effect = RuntimeError("secret-internal-detail-9999")
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs())
        rendered = repr(exc.value.payload)
        assert "secret-internal-detail-9999" not in rendered

        # And it MUST NOT appear in the failed-transition audit row
        # either.
        for call in audit_store.append.call_args_list:
            event: AuditEvent = call.args[0]
            assert "secret-internal-detail-9999" not in repr(event.payload)

    async def test_each_transition_emits_one_audit_and_one_decision_row(
        self,
        endpoint: A2AEndpoint,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
    ) -> None:
        await endpoint.handle(**_good_call_kwargs())
        # 3 transitions x (1 audit + 1 decision) = 3 each.
        assert audit_store.append.await_count == 3
        assert decision_history_store.append.await_count == 3

    async def test_task_state_transitions_are_single_writer(
        self,
        endpoint: A2AEndpoint,
    ) -> None:
        """Run two concurrent calls with distinct request_ids and
        verify both create distinct ``TaskRecord``s (no races on the
        in-process task store). Pinning the single-writer invariant
        without spinning up real concurrency primitives is by
        construction — every transition runs through one
        ``_transition`` call inside the endpoint instance."""
        results = await asyncio.gather(
            endpoint.handle(**_good_call_kwargs(request_id="rid-conc-A")),
            endpoint.handle(**_good_call_kwargs(request_id="rid-conc-B")),
        )
        assert len(results) == 2
        assert all(r["result"] == "ok" for r in results)

    async def test_task_record_immutable_state_history(
        self,
        endpoint: A2AEndpoint,
    ) -> None:
        """A ``TaskRecord`` rejects backwards / illegal transitions
        (e.g. SUCCEEDED → RUNNING). Pin the invariant directly via
        the endpoint's :meth:`_transition` — no public mutation
        path."""
        # Mint a record via the success path to grab a reference.
        record_box: list[TaskRecord] = []

        original = endpoint._transition

        def _grab(task: TaskRecord, new_state: TaskState, **kw: Any) -> Any:
            record_box.append(task)
            return original(task, new_state, **kw)

        endpoint._transition = _grab  # type: ignore[method-assign]
        try:
            await endpoint.handle(**_good_call_kwargs())
        finally:
            endpoint._transition = original  # type: ignore[method-assign]

        record = record_box[0]
        assert record.state == TaskState.SUCCEEDED
        # Illegal backwards transition refused.
        with pytest.raises(ValueError):
            endpoint._transition(record, TaskState.RUNNING)


# =============================================================================
# Chain linkage
# =============================================================================


class TestChainLinkage:
    """Every ``a2a.task_*`` audit + decision row carries
    ``parent_trace_id`` (caller-supplied) + ``child_trace_id``
    (locally minted) so the cross-agent chain is walkable end-to-end.

    Mirrors Sprint-2's hash-chain primitives extended across the A2A
    boundary.
    """

    async def test_parent_trace_id_carried_through_all_transitions(
        self,
        endpoint: A2AEndpoint,
        audit_store: MagicMock,
    ) -> None:
        await endpoint.handle(**_good_call_kwargs(parent_trace_id="parent-X"))
        for call in audit_store.append.call_args_list:
            event: AuditEvent = call.args[0]
            assert event.payload["parent_trace_id"] == "parent-X"

    async def test_child_trace_id_minted_when_caller_omits(
        self,
        endpoint: A2AEndpoint,
        audit_store: MagicMock,
    ) -> None:
        await endpoint.handle(**_good_call_kwargs(parent_trace_id=None))
        for call in audit_store.append.call_args_list:
            event: AuditEvent = call.args[0]
            assert event.payload["parent_trace_id"] is not None
            assert event.payload["child_trace_id"] is not None
            # And they must differ — minted parent ≠ minted child.
            assert event.payload["parent_trace_id"] != event.payload["child_trace_id"]

    async def test_child_trace_id_stable_across_one_request(
        self,
        endpoint: A2AEndpoint,
        audit_store: MagicMock,
    ) -> None:
        await endpoint.handle(**_good_call_kwargs())
        child_trace_ids = {
            call.args[0].payload["child_trace_id"] for call in audit_store.append.call_args_list
        }
        assert len(child_trace_ids) == 1

    async def test_child_trace_ids_distinct_across_requests(
        self,
        endpoint: A2AEndpoint,
        audit_store: MagicMock,
    ) -> None:
        await endpoint.handle(**_good_call_kwargs(request_id="rid-child-A"))
        await endpoint.handle(**_good_call_kwargs(request_id="rid-child-B"))
        child_trace_ids = {
            call.args[0].payload["child_trace_id"] for call in audit_store.append.call_args_list
        }
        assert len(child_trace_ids) == 2

    async def test_chain_payload_carries_target_agent_and_tenant(
        self,
        endpoint: A2AEndpoint,
        audit_store: MagicMock,
    ) -> None:
        await endpoint.handle(**_good_call_kwargs(target_agent="agent_alpha", tenant_id="bank_a"))
        for call in audit_store.append.call_args_list:
            event: AuditEvent = call.args[0]
            assert event.tenant_id == "bank_a"
            assert event.payload["target_agent"] == "agent_alpha"

    async def test_decision_payload_mirrors_audit_payload(
        self,
        endpoint: A2AEndpoint,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
    ) -> None:
        """``_emit_a2a_evidence`` emits parallel rows; the
        request_id + tenant_id MUST match between the audit row and
        the decision row at every transition."""
        await endpoint.handle(**_good_call_kwargs(request_id="rid-mirror"))

        audit_pairs = [
            (call.args[0].request_id, call.args[0].tenant_id)
            for call in audit_store.append.call_args_list
        ]
        decision_pairs = [
            (call.args[0].request_id, call.args[0].tenant_id)
            for call in decision_history_store.append.call_args_list
        ]
        assert audit_pairs == decision_pairs


# =============================================================================
# Audit-pipeline failure resilience
# =============================================================================


class TestAuditFailureSafeSwallow:
    """Sprint-5 ``_emit_call_evidence`` discipline: audit-pipeline
    failure MUST NOT mask the primary outcome. Equivalent
    ``_emit_a2a_evidence`` MUST safe-swallow audit + decision-history
    pipeline failures and let the caller see the primary result.
    """

    async def test_audit_failure_does_not_mask_success(
        self,
        endpoint: A2AEndpoint,
        audit_store: MagicMock,
    ) -> None:
        audit_store.append.side_effect = RuntimeError("audit pipe broken")
        result = await endpoint.handle(**_good_call_kwargs())
        assert result["result"] == "ok"

    async def test_decision_history_failure_does_not_mask_success(
        self,
        endpoint: A2AEndpoint,
        decision_history_store: MagicMock,
    ) -> None:
        decision_history_store.append.side_effect = RuntimeError("dh pipe broken")
        result = await endpoint.handle(**_good_call_kwargs())
        assert result["result"] == "ok"


# =============================================================================
# Closed-enum + dataclass shape
# =============================================================================


class TestModuleShape:
    """Shape tests pin the module surface so future refactors can't
    silently drop fields the audit/decision rows depend on."""

    def test_task_state_is_closed_enum(self) -> None:
        assert {s.value for s in TaskState} == {
            "created",
            "running",
            "succeeded",
            "failed",
            "cancelled",
        }

    def test_task_record_carries_required_fields(self) -> None:
        fields = {f.name for f in dataclasses.fields(TaskRecord)}
        required = {
            "task_id",
            "target_agent",
            "parent_trace_id",
            "child_trace_id",
            "state",
            "created_at",
            "updated_at",
            "payload_digest",
        }
        missing = required - fields
        assert not missing, f"TaskRecord missing required fields: {missing}"

    def test_a2a_endpoint_error_carries_closed_enum_code(self) -> None:
        err = A2AEndpointError("invalid_request", "test")
        assert err.code == "invalid_request"
        assert isinstance(err.payload, dict)


# =============================================================================
# T9 R1 P2 #1 — gate-refusal evidence chain
# =============================================================================
#
# Pre-task gate refusals (version / authn / wave-2 / routing) all raise
# before any TaskRecord is minted. They must STILL emit a chained
# audit + decision_history row carrying parent_trace_id, child_trace_id,
# payload_digest, error_code, and (where applicable) policy_reason —
# else the cross-agent chain is silent on every refusal, which violates
# ADR-003 + A2A-CONFORMANCE.md "every A2A call is chain-linked".


class TestRefusalEvidenceChain:
    """Every gate refusal emits exactly one audit row + one
    decision_history row, both carrying the chain-linkage fields.
    """

    async def test_version_refusal_emits_chained_evidence(
        self,
        endpoint: A2AEndpoint,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
    ) -> None:
        with pytest.raises(A2AEndpointError):
            await endpoint.handle(
                **_good_call_kwargs(
                    a2a_version_header="0.3",
                    parent_trace_id="parent-V1",
                )
            )
        # Exactly one audit + one decision row.
        assert audit_store.append.await_count == 1
        assert decision_history_store.append.await_count == 1

        event: AuditEvent = audit_store.append.call_args.args[0]
        assert event.event_type == "a2a.task_refused"
        assert event.payload["error_code"] == "version_not_supported"
        assert event.payload["gate"] == "version"
        assert event.payload["parent_trace_id"] == "parent-V1"
        assert event.payload["child_trace_id"]
        assert event.payload["payload_digest"]
        assert event.payload["target_agent"] == "agent_alpha"
        # Version refusal has no AgentOS policy reason — it's wire-
        # protocol-spec direct. The field is intentionally absent.
        assert "policy_reason" not in event.payload

    async def test_authn_refusal_emits_chained_evidence(
        self,
        endpoint: A2AEndpoint,
        authz_client: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
    ) -> None:
        authz_client.validate_inbound_token.side_effect = A2AAuthzError(
            reason="a2a_anonymous_refused", message="missing"
        )
        with pytest.raises(A2AEndpointError):
            await endpoint.handle(**_good_call_kwargs(parent_trace_id="parent-A1"))
        assert audit_store.append.await_count == 1
        event: AuditEvent = audit_store.append.call_args.args[0]
        assert event.event_type == "a2a.task_refused"
        assert event.payload["error_code"] == "invalid_request"
        assert event.payload["policy_reason"] == "anonymous_refused"
        assert event.payload["gate"] == "authn"
        assert event.payload["authz_reason"] == "a2a_anonymous_refused"
        assert event.payload["parent_trace_id"] == "parent-A1"
        assert event.payload["child_trace_id"]
        assert event.payload["payload_digest"]

    async def test_wave2_refusal_emits_chained_evidence(
        self,
        endpoint: A2AEndpoint,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
    ) -> None:
        with pytest.raises(A2AEndpointError):
            await endpoint.handle(
                **_good_call_kwargs(
                    payload=b'{"method":"tasks/resubscribe"}',
                    parent_trace_id="parent-W1",
                )
            )
        assert audit_store.append.await_count == 1
        event: AuditEvent = audit_store.append.call_args.args[0]
        assert event.event_type == "a2a.task_refused"
        assert event.payload["error_code"] == "unsupported_operation"
        assert event.payload["policy_reason"] == "wave2_feature_refused"
        assert event.payload["gate"] == "wave2"
        assert event.payload["wave2_feature"] == "task_resumption"
        assert event.payload["parent_trace_id"] == "parent-W1"
        assert event.payload["child_trace_id"]
        assert event.payload["payload_digest"]

    async def test_unknown_target_refusal_emits_chained_evidence(
        self,
        endpoint: A2AEndpoint,
        plugin_registry: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
    ) -> None:
        from cognic_agentos.protocol.plugin_registry import PluginNotRegistered

        plugin_registry.load.side_effect = PluginNotRegistered("not registered")
        with pytest.raises(A2AEndpointError):
            await endpoint.handle(
                **_good_call_kwargs(
                    target_agent="ghost-agent",
                    parent_trace_id="parent-R1",
                )
            )
        assert audit_store.append.await_count == 1
        event: AuditEvent = audit_store.append.call_args.args[0]
        assert event.event_type == "a2a.task_refused"
        assert event.payload["error_code"] == "method_not_found"
        assert event.payload["policy_reason"] == "unknown_target"
        assert event.payload["gate"] == "routing"
        assert event.payload["target_agent"] == "ghost-agent"
        assert event.payload["parent_trace_id"] == "parent-R1"
        assert event.payload["child_trace_id"]
        assert event.payload["payload_digest"]

    async def test_refusal_evidence_decision_row_mirrors_audit_row(
        self,
        endpoint: A2AEndpoint,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
    ) -> None:
        """Audit + decision rows share request_id + tenant_id."""
        with pytest.raises(A2AEndpointError):
            await endpoint.handle(
                **_good_call_kwargs(
                    a2a_version_header="0.3",
                    request_id="rid-mirror-refusal",
                    tenant_id="bank_a",
                )
            )
        audit_evt: AuditEvent = audit_store.append.call_args.args[0]
        decision_evt = decision_history_store.append.call_args.args[0]
        assert audit_evt.request_id == decision_evt.request_id
        assert audit_evt.tenant_id == decision_evt.tenant_id
        # Decision row carries explicit transition='refused'.
        assert decision_evt.payload["transition"] == "refused"

    async def test_refusal_audit_failure_does_not_mask_refusal(
        self,
        endpoint: A2AEndpoint,
        audit_store: MagicMock,
    ) -> None:
        audit_store.append.side_effect = RuntimeError("audit pipe broken")
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs(a2a_version_header="0.3"))
        assert exc.value.code == "version_not_supported"


# =============================================================================
# T9 R1 P2 #2 + R2 P2 — multimodal Wave-2 refusal aligned to SDK Part shape
# =============================================================================
#
# A2A 1.0 ``Part`` proto (verified against ``a2a/types/a2a_pb2.pyi``
# shipped with ``a2a-sdk == 1.0.2``):
#
#     message Part {
#         oneof part {
#             string text = 1;     // Wave-1 (free-form prose)
#             bytes  raw  = 2;     // Wave-2 (file bytes)
#             string url  = 3;     // Wave-2 (file URL)
#             Value  data = 4;     // Wave-1 (Struct of business JSON)
#         }
#         Struct metadata     = 5;
#         string filename     = 6;
#         string media_type   = 7;
#     }
#
# There is NO ``kind`` discriminator and NO ``mimeType`` (the upstream
# spec renamed it ``media_type`` / JSON ``mediaType``). The R1 walker
# keyed on a synthetic ``kind`` and recursed through arbitrary dict
# trees, which both missed real Wave-2 shapes (raw / url file parts)
# AND falsely refused Wave-1 data parts whose business JSON happened
# to contain a ``kind`` or ``mimeType`` key. R2 P2 reviewer
# correction scopes the detector to actual ``parts[]`` entries +
# protobuf-JSON field names.


class TestGate3Wave2Multimodal:
    @pytest.mark.parametrize(
        "field",
        ["raw", "url"],
    )
    async def test_wave2_oneof_field_refused(
        self,
        endpoint: A2AEndpoint,
        field: str,
    ) -> None:
        """A Part populated with ``raw`` (file bytes) or ``url``
        (file URL) is Wave-2 by spec category — refuse before
        routing/dispatch."""
        # protobuf-JSON serialises bytes as base64 strings; here we
        # just exercise key presence (the gate refuses on the
        # presence of the Wave-2 oneof branch).
        payload = (
            b'{"method":"message/send","params":{"message":{"parts":'
            b'[{"' + field.encode() + b'":"placeholder","filename":"x"}]}}}'
        )
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs(payload=payload))
        assert exc.value.code == "unsupported_operation"
        assert exc.value.payload["policy_reason"] == "wave2_feature_refused"
        assert exc.value.payload["wave2_feature"] == "multimodal_payload"

    async def test_raw_with_application_pdf_refused(
        self,
        endpoint: A2AEndpoint,
    ) -> None:
        """A PDF Part necessarily sets ``raw`` or ``url``; refuses
        on the field-presence signal (mediaType is informational)."""
        payload = (
            b'{"method":"message/send","params":{"message":{"parts":'
            b'[{"raw":"JVBERi0xLjQK","mediaType":"application/pdf"}]}}}'
        )
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs(payload=payload))
        assert exc.value.payload["wave2_feature"] == "multimodal_payload"

    @pytest.mark.parametrize(
        "media_type",
        ["image/png", "audio/wav", "video/mp4", "IMAGE/JPEG"],
    )
    @pytest.mark.parametrize(
        "media_type_field",
        ["mediaType", "media_type"],
    )
    async def test_media_type_prefix_refused(
        self,
        endpoint: A2AEndpoint,
        media_type: str,
        media_type_field: str,
    ) -> None:
        """``mediaType`` / ``media_type`` (the protobuf snake-case
        alias) image|audio|video prefixes refuse defensively even
        without an explicit raw/url branch — case-insensitive."""
        payload = (
            b'{"params":{"message":{"parts":[{"'
            + media_type_field.encode()
            + b'":"'
            + media_type.encode()
            + b'"}]}}}'
        )
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs(payload=payload))
        assert exc.value.code == "unsupported_operation"
        assert exc.value.payload["wave2_feature"] == "multimodal_payload"

    async def test_text_part_proceeds(
        self,
        endpoint: A2AEndpoint,
    ) -> None:
        """Wave-1 ``text`` parts MUST flow through without refusal."""
        payload = b'{"method":"message/send","params":{"message":{"parts":[{"text":"hello"}]}}}'
        result = await endpoint.handle(**_good_call_kwargs(payload=payload))
        assert result["result"] == "ok"

    async def test_data_part_proceeds(
        self,
        endpoint: A2AEndpoint,
    ) -> None:
        """Wave-1 ``data`` parts (Struct of business JSON) MUST flow."""
        payload = b'{"method":"message/send","params":{"message":{"parts":[{"data":{"k":"v"}}]}}}'
        result = await endpoint.handle(**_good_call_kwargs(payload=payload))
        assert result["result"] == "ok"

    async def test_data_part_with_business_kind_field_proceeds(
        self,
        endpoint: A2AEndpoint,
    ) -> None:
        """T9 R2 P2 — a Wave-1 ``data`` part carrying business JSON
        like ``{"kind": "image"}`` must NOT be refused. The walker
        scopes on actual ``parts[]`` entries via real protobuf-JSON
        field names; arbitrary nested user JSON is opaque to it."""
        payload = (
            b'{"method":"message/send","params":{"message":'
            b'{"parts":[{"data":{"kind":"image","title":"chart"}}]}}}'
        )
        result = await endpoint.handle(**_good_call_kwargs(payload=payload))
        assert result["result"] == "ok"

    async def test_data_part_with_business_mimetype_field_proceeds(
        self,
        endpoint: A2AEndpoint,
    ) -> None:
        """T9 R2 P2 — a Wave-1 ``data`` part whose business JSON
        contains ``{"mimeType": "image/png"}`` (caller business
        metadata) must NOT be refused — the walker does not descend
        into the ``data`` Struct."""
        payload = (
            b'{"method":"message/send","params":{"message":'
            b'{"parts":[{"data":{"mimeType":"image/png","note":"ignored"}}]}}}'
        )
        result = await endpoint.handle(**_good_call_kwargs(payload=payload))
        assert result["result"] == "ok"

    async def test_metadata_with_image_keys_proceeds(
        self,
        endpoint: A2AEndpoint,
    ) -> None:
        """Per-Part / per-Message ``metadata`` is operator free-form
        — the walker MUST NOT descend into it."""
        payload = (
            b'{"method":"message/send","params":{"message":'
            b'{"parts":[{"text":"hi","metadata":{"raw":"xx","url":"u"}}],'
            b'"metadata":{"image":"snip"}}}}'
        )
        result = await endpoint.handle(**_good_call_kwargs(payload=payload))
        assert result["result"] == "ok"

    async def test_multimodal_refused_before_routing(
        self,
        endpoint: A2AEndpoint,
        plugin_registry: MagicMock,
    ) -> None:
        """Multimodal traffic MUST be refused at the gate before
        registry lookup; a registered Wave-1 agent must not see
        Wave-2 traffic."""
        payload = (
            b'{"method":"message/send","params":{"message":'
            b'{"parts":[{"url":"https://example/file.png"}]}}}'
        )
        with pytest.raises(A2AEndpointError):
            await endpoint.handle(**_good_call_kwargs(payload=payload))
        plugin_registry.load.assert_not_called()

    async def test_nested_history_parts_detected(
        self,
        endpoint: A2AEndpoint,
    ) -> None:
        """A Wave-2 Part nested inside ``params.message.history[]
        .parts[]`` (when the caller resends conversation history)
        is still detected — the walker descends through standard
        envelope structure (params, message, history, ...)."""
        payload = (
            b'{"method":"message/send","params":{"message":{"history":'
            b'[{"role":"ROLE_USER","parts":[{"text":"prior"},'
            b'{"raw":"AAAA"}]}]}}}'
        )
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs(payload=payload))
        assert exc.value.payload["wave2_feature"] == "multimodal_payload"

    async def test_deeply_nested_payload_fails_closed(
        self,
        endpoint: A2AEndpoint,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
    ) -> None:
        """T9 R3 P2 — a deeply nested attacker-controlled JSON
        payload MUST NOT raise raw ``RecursionError`` (escaping the
        closed refusal path). The walker is iterative + depth-
        bounded; on bound exceedance it fails closed with sub-tag
        ``payload_unscannable`` and chained refusal evidence.

        Construction: 200 levels of ``{"nested": {...}}`` is well
        above ``_MAX_PAYLOAD_DEPTH = 64``. Without the iterative
        walker + depth bound the prior recursive walker would have
        either consumed the recursion budget or processed unbounded
        attacker-controlled JSON before the closed gate fired.
        """
        import json as _json

        leaf: Any = {"text": "deep"}
        for _ in range(200):
            leaf = {"nested": leaf}
        payload = _json.dumps(leaf).encode()

        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs(payload=payload))
        assert exc.value.code == "unsupported_operation"
        assert exc.value.payload["policy_reason"] == "wave2_feature_refused"
        assert exc.value.payload["wave2_feature"] == "payload_unscannable"

        # And the refusal MUST emit chained evidence (the whole
        # point of the fail-closed path is that examiners still see
        # a chain row for the refused call).
        assert audit_store.append.await_count == 1
        assert decision_history_store.append.await_count == 1
        event: AuditEvent = audit_store.append.call_args.args[0]
        assert event.event_type == "a2a.task_refused"
        assert event.payload["gate"] == "wave2"
        assert event.payload["wave2_feature"] == "payload_unscannable"
        assert event.payload["error_code"] == "unsupported_operation"

    async def test_deeply_nested_refused_before_routing(
        self,
        endpoint: A2AEndpoint,
        plugin_registry: MagicMock,
    ) -> None:
        """An unscannable payload MUST be refused before routing —
        the registry MUST NOT be consulted for a payload we can't
        safely classify."""
        import json as _json

        leaf: Any = {"text": "deep"}
        for _ in range(200):
            leaf = {"nested": leaf}
        payload = _json.dumps(leaf).encode()

        with pytest.raises(A2AEndpointError):
            await endpoint.handle(**_good_call_kwargs(payload=payload))
        plugin_registry.load.assert_not_called()

    async def test_wide_payload_node_bound_fails_closed(
        self,
        endpoint: A2AEndpoint,
    ) -> None:
        """A flat-but-very-wide payload also fails closed via the
        node-count bound (``_MAX_PAYLOAD_NODES = 10_000``). Without
        this belt-and-suspenders limit, an attacker could craft a
        flat dict with 10 000 000 keys that completes scanning but
        burns CPU before any other gate fires."""
        import json as _json

        # 20 000 sibling keys — well above the 10 000 node budget.
        wide = {f"k{i}": {"v": i} for i in range(20_000)}
        payload = _json.dumps(wide).encode()

        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs(payload=payload))
        assert exc.value.payload["wave2_feature"] == "payload_unscannable"

    async def test_wide_scalar_payload_node_bound_fails_closed(
        self,
        endpoint: A2AEndpoint,
    ) -> None:
        """T9 R4 P2 #1 — a flat dict of scalar values must also trip
        the node bound. The earlier walker only counted containers
        popped from the stack, so a 20 000-key dict of integers would
        pop ONE container (the outer dict), iterate through 20 000
        scalar items WITHOUT counting them, and complete without
        tripping any bound. Counting every visited member tightens
        the budget to actual work performed."""
        import json as _json

        # Plain integers (scalars) — NOT wrapped in {"v": i} as the
        # prior test does — so this exercises the scalar-counting
        # path specifically.
        wide = {f"k{i}": i for i in range(20_000)}
        payload = _json.dumps(wide).encode()

        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs(payload=payload))
        assert exc.value.code == "unsupported_operation"
        assert exc.value.payload["wave2_feature"] == "payload_unscannable"

    async def test_wide_scalar_list_node_bound_fails_closed(
        self,
        endpoint: A2AEndpoint,
    ) -> None:
        """List-element scalar counterpart of the dict scalar
        regression — every list element MUST count toward the
        budget, not just nested containers."""
        import json as _json

        payload = _json.dumps({"params": {"items": list(range(20_000))}}).encode()
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs(payload=payload))
        assert exc.value.payload["wave2_feature"] == "payload_unscannable"

    async def test_decoder_recursion_error_fails_closed(
        self,
        endpoint: A2AEndpoint,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
    ) -> None:
        """T9 R5 P2 — Python's CPython ``_json`` decoder is C-side
        recursive over nested objects; deeply-nested *valid* JSON
        (~10k+ levels) raises ``RecursionError`` from json.loads
        BEFORE our iterative walker runs. That MUST be caught and
        mapped to the same ``payload_unscannable`` fail-closed
        refusal path so the chained ``a2a.task_refused`` evidence
        still fires.

        Constructs a 12 000-deep ``{"a":{"a":...}}`` payload as raw
        bytes (cannot use ``json.dumps`` on a 12k-deep Python
        structure — ``dumps`` would also recurse). The depth is
        empirically chosen above CPython 3.12's ~10 000 trip
        threshold.
        """
        depth = 12_000
        payload = (b'{"a":' * depth) + b'"x"' + (b"}" * depth)

        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs(payload=payload))
        assert exc.value.code == "unsupported_operation"
        assert exc.value.payload["policy_reason"] == "wave2_feature_refused"
        assert exc.value.payload["wave2_feature"] == "payload_unscannable"

        # Chained refusal evidence must still emit despite the
        # decoder-side fail-closed path.
        assert audit_store.append.await_count == 1
        assert decision_history_store.append.await_count == 1
        event: AuditEvent = audit_store.append.call_args.args[0]
        assert event.event_type == "a2a.task_refused"
        assert event.payload["gate"] == "wave2"
        assert event.payload["wave2_feature"] == "payload_unscannable"

    @pytest.mark.parametrize(
        "alias_pair",
        [
            # Wave-2 prefix on media_type, Wave-1 on mediaType
            ('"mediaType":"application/json","media_type":"image/png"'),
            # Wave-2 prefix on mediaType, Wave-1 on media_type
            ('"mediaType":"image/png","media_type":"text/plain"'),
            # Wave-2 on media_type, mediaType is non-string (masking
            # would happen if .get() truthiness were the only check)
            ('"mediaType":42,"media_type":"audio/wav"'),
            # Vice versa: Wave-2 on mediaType, media_type non-string
            ('"mediaType":"video/mp4","media_type":null'),
            # Both Wave-2 (different categories) — refuse on either
            ('"mediaType":"image/png","media_type":"audio/wav"'),
        ],
    )
    async def test_media_type_alias_collision_refused(
        self,
        endpoint: A2AEndpoint,
        alias_pair: str,
    ) -> None:
        """T9 R4 P2 #2 — both protobuf-JSON aliases (``mediaType`` /
        ``media_type``) MUST be checked independently. A payload
        with a Wave-1 string on one alias and a Wave-2 string on the
        other (or a non-string masking value on one alias) MUST
        refuse — defending against alias-collision smuggling."""
        payload = b'{"params":{"message":{"parts":[{' + alias_pair.encode() + b"}]}}}"
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs(payload=payload))
        assert exc.value.code == "unsupported_operation"
        assert exc.value.payload["wave2_feature"] == "multimodal_payload"

    async def test_media_type_both_wave1_proceeds(
        self,
        endpoint: A2AEndpoint,
    ) -> None:
        """If BOTH aliases are Wave-1 strings, the part proceeds.
        This pins that the alias-collision fix doesn't over-refuse
        legitimate dual-naming Wave-1 traffic."""
        payload = (
            b'{"method":"message/send","params":{"message":{"parts":'
            b'[{"text":"hi","mediaType":"text/plain",'
            b'"media_type":"text/plain"}]}}}'
        )
        result = await endpoint.handle(**_good_call_kwargs(payload=payload))
        assert result["result"] == "ok"


# =============================================================================
# T9 R1 P2 #3 — non-canonical response → invalid_agent_response
# =============================================================================


class TestInvalidAgentResponseGate:
    """Per A2A 1.0 the agent's response MUST be a JSON-RPC-shaped
    dict that is canonical-form-clean (no bytes / non-finite floats /
    tuples / non-string keys / naive datetimes). Non-dict OR non-
    canonical responses both refuse with ``invalid_agent_response``
    BEFORE the SUCCEEDED transition so the audit chain matches the
    wire error.
    """

    async def test_non_dict_response_refused(
        self,
        endpoint: A2AEndpoint,
        plugin_registry: MagicMock,
    ) -> None:
        plugin_registry._agent_stub.handle.return_value = ["not", "a", "dict"]
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs())
        assert exc.value.code == "invalid_agent_response"
        assert exc.value.payload["response_type"] == "list"

    async def test_unsupported_type_in_response_refused(
        self,
        endpoint: A2AEndpoint,
        plugin_registry: MagicMock,
    ) -> None:
        """``canonical_bytes`` rejects any type outside its allow-list
        (sets, complex numbers, arbitrary objects). The response gate
        maps the canonicalisation failure to ``invalid_agent_response``
        instead of letting a SUCCEEDED transition emit with a missing
        digest."""
        plugin_registry._agent_stub.handle.return_value = {"items": {1, 2, 3}}
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs())
        assert exc.value.code == "invalid_agent_response"
        assert "response_canonical_error_class" in exc.value.payload

    async def test_non_finite_float_in_response_refused(
        self,
        endpoint: A2AEndpoint,
        plugin_registry: MagicMock,
    ) -> None:
        plugin_registry._agent_stub.handle.return_value = {"score": float("nan")}
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs())
        assert exc.value.code == "invalid_agent_response"

    async def test_tuple_in_response_refused(
        self,
        endpoint: A2AEndpoint,
        plugin_registry: MagicMock,
    ) -> None:
        plugin_registry._agent_stub.handle.return_value = {"items": (1, 2)}
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs())
        assert exc.value.code == "invalid_agent_response"

    async def test_non_string_key_in_response_refused(
        self,
        endpoint: A2AEndpoint,
        plugin_registry: MagicMock,
    ) -> None:
        plugin_registry._agent_stub.handle.return_value = {1: "v"}
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs())
        assert exc.value.code == "invalid_agent_response"

    async def test_invalid_response_audit_records_invalid_agent_response(
        self,
        endpoint: A2AEndpoint,
        plugin_registry: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        """T9 R1 P2 #4 — the FAILED audit row MUST record
        ``invalid_agent_response`` (not ``internal_error``) so the
        audit chain agrees with the wire error returned to the
        caller."""
        plugin_registry._agent_stub.handle.return_value = ["not", "a", "dict"]
        with pytest.raises(A2AEndpointError):
            await endpoint.handle(**_good_call_kwargs())

        # Find the failed audit row (last one).
        failed_event = audit_store.append.call_args_list[-1].args[0]
        assert failed_event.event_type == "a2a.task_failed"
        assert failed_event.payload["error_code"] == "invalid_agent_response"

    async def test_invalid_response_emits_failed_not_succeeded(
        self,
        endpoint: A2AEndpoint,
        plugin_registry: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        plugin_registry._agent_stub.handle.return_value = {"items": {1, 2}}
        with pytest.raises(A2AEndpointError):
            await endpoint.handle(**_good_call_kwargs())

        event_types = [c.args[0].event_type for c in audit_store.append.call_args_list]
        assert "a2a.task_succeeded" not in event_types
        assert "a2a.task_failed" in event_types


# =============================================================================
# T9 R1 P2 #4 — audit error_code agrees with wire error
# =============================================================================


class TestAuditErrorCodeAgreesWithWireCode:
    async def test_handler_exception_audit_records_internal_error(
        self,
        endpoint: A2AEndpoint,
        plugin_registry: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        """Raw handler exception path keeps the ``internal_error``
        default — the caller saw ``internal_error`` and the audit
        records the same."""
        plugin_registry._agent_stub.handle.side_effect = RuntimeError("boom")
        with pytest.raises(A2AEndpointError) as exc:
            await endpoint.handle(**_good_call_kwargs())
        assert exc.value.code == "internal_error"

        failed_event = audit_store.append.call_args_list[-1].args[0]
        assert failed_event.event_type == "a2a.task_failed"
        assert failed_event.payload["error_code"] == "internal_error"


# =============================================================================
# T9 R1 P2 #5 — runtime-side SDK gate
# =============================================================================


class TestRuntimeSideSdkGate:
    """A2AEndpoint construction MUST call ``require_a2a()``; mounting
    on a kernel-image deployment (``a2a-sdk`` not installed) MUST
    raise :class:`A2ANotAvailableError` at __init__ time. Mirrors
    the Sprint-5 ``MCPHost`` / ``require_mcp()`` regression."""

    def test_require_a2a_called_at_construction(
        self,
        authz_client: MagicMock,
        agent_card_verifier: MagicMock,
        plugin_registry: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from cognic_agentos.protocol import A2ANotAvailableError
        from cognic_agentos.protocol import a2a_endpoint as endpoint_mod

        called: list[bool] = []

        def _stub() -> None:
            called.append(True)
            raise A2ANotAvailableError("sdk missing")

        monkeypatch.setattr(endpoint_mod, "require_a2a", _stub)

        with pytest.raises(A2ANotAvailableError):
            A2AEndpoint(
                settings=build_settings_without_env_file(),
                plugin_registry=plugin_registry,
                authz_client=authz_client,
                agent_card_verifier=agent_card_verifier,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
            )
        assert called, "require_a2a() was not called at A2AEndpoint construction"

    def test_a2a_endpoint_listed_in_protocol_optional_deps(self) -> None:
        """Pin the doctrine assertion: ``a2a_endpoint`` is on the
        runtime-side floor (not admission-side); future maintainers
        reading ``_PROTOCOL_OPTIONAL_DEPS`` see the kernel-vs-default-
        adapters boundary."""
        from cognic_agentos.protocol import _PROTOCOL_OPTIONAL_DEPS

        assert "cognic_agentos.protocol.a2a_endpoint" in _PROTOCOL_OPTIONAL_DEPS
        assert _PROTOCOL_OPTIONAL_DEPS["cognic_agentos.protocol.a2a_endpoint"] == frozenset({"a2a"})
