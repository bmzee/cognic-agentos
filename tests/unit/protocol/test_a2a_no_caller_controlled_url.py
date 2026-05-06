"""Sprint-6 T14 — runtime canary for the A2A caller-URL threat model.

Runtime backstop for ``docs/A2A-CALLER-URL-THREAT-MODEL.md`` and the
ADR-003 routing-safety doctrine. Complements the architecture-test
half (static AST scan in
``tests/architecture/test_a2a_no_caller_controlled_url.py``) with a
runtime check: every adversary-controlled URL surface MUST produce
the correct closed-enum refusal at the correct entry point. If this
test fails, the threat model has been breached and the build must
be reverted before merge.

Coverage map (per Sprint-6 plan §T14):

  TestCallerURLRefusedAtEndpoint
    URL-shaped ``target_agent`` arguments to :meth:`A2AEndpoint.handle`
    MUST be refused with spec code ``method_not_found`` + policy
    reason ``unknown_target`` (the registry has no record of a
    URL-shaped entry-point name) and MUST NOT cause any outbound
    HTTP traffic.

  TestOutboundDispatchURLFromVerifiedCard
    The only producer of outbound dispatch URLs is
    :meth:`A2AAgentCardVerifier.fetch_and_verify_outbound_card`, and
    the URLs it constructs are bound to operator-supplied
    ``target_origin`` values — never to caller-supplied or
    model-output strings. Origin validation refuses any path /
    query / fragment / userinfo / non-http(s) shapes BEFORE
    construction.

  TestSubagentTargetIsEntryPointName
    Sub-agent dispatch (whose primitive ships in Sprint 8) takes
    entry-point names, not URLs. The Sprint-6 transport-side
    invariant pinned here is INDIRECT: URL-shaped targets fed to
    the inbound endpoint are refused as unknown targets and never
    reach an outbound URL constructor. The direct
    ``spawn_subagent(target_url=...)`` canary lands with the
    Sprint 8 sub-agent primitive.

  TestPushNotificationWebhookRefusedWave1
    Push-notification subscribe / get methods (which carry a
    caller-supplied webhook URL in their params on the spec
    surface) MUST refuse at the Wave-2 gate BEFORE the webhook
    URL is parsed or considered.

  TestThreatModelInvariants
    Pin the four closed-enum vocabularies the canary depends on
    (``A2AAuthzReason`` / ``AgentCardValidationReason`` /
    ``A2AErrorCode`` / ``A2APolicyRefusalReason``). Drift = wire-
    protocol-public; any addition trips this test and forces an
    explicit doctrine-update PR (the canary author must look at
    every arm and decide whether the new value matters).
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.protocol import (
    A2AAuthzReason,
    A2AErrorCode,
    A2APolicyRefusalReason,
    AgentCardValidationReason,
)
from cognic_agentos.protocol.a2a_authz import A2APinnedToken
from cognic_agentos.protocol.a2a_endpoint import A2AEndpoint, A2AEndpointError
from cognic_agentos.protocol.plugin_registry import PluginNotRegistered

# ---------------------------------------------------------------------------
# Endpoint fixtures — real A2AEndpoint, mocks at the gates the canary
# is NOT exercising in the current arm.
# ---------------------------------------------------------------------------


def _stub_authz_accept() -> MagicMock:
    """Mocked :class:`A2AAuthzClient` that accepts every inbound
    token. Used by gates downstream of authn (Wave-2 / routing /
    dispatch) where the canary's subject is post-authn behaviour."""
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


def _stub_registry_unknown() -> MagicMock:
    """Mocked plugin registry that raises :class:`PluginNotRegistered`
    on every ``load`` — simulates the URL-shaped target landing on
    the routing gate (gate 4) without a corresponding entry-point."""
    registry = MagicMock()
    registry.load = MagicMock(side_effect=PluginNotRegistered("agents", "unused"))
    return registry


def _silent_audit_store() -> MagicMock:
    mock = MagicMock()
    mock.append = AsyncMock(return_value=(None, b""))
    return mock


def _silent_decision_history_store() -> MagicMock:
    mock = MagicMock()
    mock.append = AsyncMock(return_value=(None, b""))
    return mock


@pytest.fixture
def endpoint_for_routing_canary() -> tuple[A2AEndpoint, MagicMock]:
    """:class:`A2AEndpoint` instance configured so URL-shaped
    ``target_agent`` arguments land on the routing gate. Returns
    (endpoint, http_client_sentinel) — the sentinel is a MagicMock
    that the canary asserts is NEVER touched (no outbound HTTP for
    a refused-at-routing target).
    """
    http_client_sentinel = MagicMock()
    # Verifier wired with the sentinel so any accidental outbound
    # call would land here (and trip the canary).
    verifier = MagicMock()
    verifier._http = http_client_sentinel
    endpoint = A2AEndpoint(
        settings=build_settings_without_env_file(),
        plugin_registry=_stub_registry_unknown(),
        authz_client=_stub_authz_accept(),
        agent_card_verifier=verifier,
        audit_store=_silent_audit_store(),
        decision_history_store=_silent_decision_history_store(),
    )
    return endpoint, http_client_sentinel


# ---------------------------------------------------------------------------
# TestCallerURLRefusedAtEndpoint
# ---------------------------------------------------------------------------


# Adversarial URL-shaped strings + path-shaped strings that are NOT valid
# entry-point names. Expectation per the user's T14 lock:
#   - URL-shaped target → method_not_found + unknown_target (the
#     registry has no entry-point under that name; the routing gate
#     refuses).
# parse_error / invalid_request are reserved for malformed JSON-RPC
# payloads, not for unknown target names.
_URL_SHAPED_TARGETS: list[str] = [
    "https://evil.example/a2a",
    "https://evil.example:8443/a2a",
    "http://10.0.0.1",
    "http://[::1]:8080",
    "//cdn.example/a",
    "javascript:alert(1)",
    "file:///etc/passwd",
    "data:text/plain,x",
    "ftp://attacker.example",
    "agent_with/slash",
    "agent_with\\backslash",
    "agent_with://scheme",
    "  https://leading-space.example",
]


class TestCallerURLRefusedAtEndpoint:
    """URL-shaped ``target_agent`` arguments to
    :meth:`A2AEndpoint.handle` MUST be refused as unknown targets at
    the routing gate (the registry has no entry-point under those
    names) — they MUST NOT trigger any outbound HTTP traffic."""

    @pytest.mark.parametrize("target", _URL_SHAPED_TARGETS, ids=lambda s: s[:30])
    async def test_url_shaped_target_refused_with_unknown_target_policy_reason(
        self,
        target: str,
        endpoint_for_routing_canary: tuple[A2AEndpoint, MagicMock],
    ) -> None:
        endpoint, http_sentinel = endpoint_for_routing_canary
        minimal_payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "rid-1",
                "method": "message/send",
                "params": {"message": {"parts": [{"text": "hi"}]}},
            }
        ).encode("utf-8")
        with pytest.raises(A2AEndpointError) as excinfo:
            await endpoint.handle(
                target_agent=target,
                payload=minimal_payload,
                authorization_header="Bearer active-token",
                a2a_version_header="1.0",
                parent_trace_id="trace-1",
                tenant_id="bank_a",
                request_id="rid-canary-1",
            )
        # Spec wire code: method_not_found (registry routing failure
        # IS the spec's "method not found" semantically — there is
        # no agent under this name). Policy reason: unknown_target.
        assert excinfo.value.code == "method_not_found", (
            f"URL-shaped target {target!r} expected method_not_found, got {excinfo.value.code!r}"
        )
        assert excinfo.value.payload.get("policy_reason") == "unknown_target", (
            f"URL-shaped target {target!r} expected policy_reason="
            f"unknown_target, got {excinfo.value.payload.get('policy_reason')!r}"
        )
        # Hard invariant: NO outbound HTTP fired. Even a single
        # mock-call against the sentinel would mean the URL leaked
        # past the routing gate into a constructor.
        assert http_sentinel.method_calls == [], (
            f"caller-URL leaked into outbound HTTP for target "
            f"{target!r}: {http_sentinel.method_calls!r}"
        )


# ---------------------------------------------------------------------------
# TestOutboundDispatchURLFromVerifiedCard
# ---------------------------------------------------------------------------


_NON_ORIGIN_TARGETS: list[tuple[str, str]] = [
    # (target_origin, expected rejected_component)
    # Origin validation order in fetch_and_verify_outbound_card:
    #   1. not_string  2. scheme  3. netloc  4. path (non-"/", non-"")
    #   5. query_or_fragment  6. userinfo
    # Each arm targets the FIRST validator that should fire.
    ("https://host.example/path", "path"),
    ("https://host.example/foo/bar", "path"),
    ("https://host.example?q=1", "query_or_fragment"),
    ("https://host.example#frag", "query_or_fragment"),
    ("https://host.example/?q=1", "query_or_fragment"),  # path is "/" (allowed) → query trips
    ("https://user@host.example", "userinfo"),
    ("https://user:pwd@host.example", "userinfo"),
    ("ftp://host.example", "scheme"),
    ("javascript:alert(1)", "scheme"),
    ("file:///etc/passwd", "scheme"),
    ("//host.example", "scheme"),
    ("not-a-url-at-all", "scheme"),
    ("", "scheme"),
]


class TestOutboundDispatchURLFromVerifiedCard:
    """The only producer of outbound dispatch URLs is
    :meth:`A2AAgentCardVerifier.fetch_and_verify_outbound_card`, and
    every non-origin ``target_origin`` MUST be refused BEFORE
    ``httpx.AsyncClient.get`` is called. This pins the runtime
    counterpart of the static-AST T4 architecture test."""

    @pytest.mark.parametrize(
        "target_origin,expected_component",
        _NON_ORIGIN_TARGETS,
        ids=lambda v: str(v)[:32] if isinstance(v, str) else "tuple",
    )
    async def test_non_origin_target_refused_before_http_get(
        self,
        target_origin: str,
        expected_component: str,
    ) -> None:
        import httpx

        from cognic_agentos.protocol.a2a_agent_cards import (
            A2AAgentCardError,
            A2AAgentCardVerifier,
        )
        from cognic_agentos.protocol.trust_gate import TrustGate

        # Spy on the http_client so we can assert .get was NEVER
        # called (the verifier MUST refuse before reaching transport).
        http_client = MagicMock(spec=httpx.AsyncClient)
        http_client.get = AsyncMock()

        secret_adapter = MagicMock()
        secret_adapter.read = AsyncMock(return_value={"keys": []})
        audit_store = _silent_audit_store()
        decision_history_store = _silent_decision_history_store()
        settings = build_settings_without_env_file()
        verifier = A2AAgentCardVerifier(
            settings=settings,
            trust_gate=TrustGate(
                settings=settings,
                audit_store=audit_store,
                secret_adapter=secret_adapter,
            ),
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            http_client=http_client,
        )
        with pytest.raises(A2AAgentCardError) as excinfo:
            await verifier.fetch_and_verify_outbound_card(
                target_origin=target_origin,
                tenant_id="bank_a",
                request_id="rid-outbound-canary-1",
            )
        # Reason carries the closed-enum literal; the rejected_component
        # carried as a payload field identifies which non-origin part
        # tripped the check.
        assert excinfo.value.reason == "agent_card_jws_blob_unreadable", (
            f"target_origin {target_origin!r} expected reason "
            f"agent_card_jws_blob_unreadable, got {excinfo.value.reason!r}"
        )
        assert excinfo.value.payload.get("rejected_component") == expected_component, (
            f"target_origin {target_origin!r} expected component "
            f"{expected_component!r}, got "
            f"{excinfo.value.payload.get('rejected_component')!r}"
        )
        # Hard invariant: http_client.get was NEVER awaited.
        http_client.get.assert_not_awaited()

    async def test_non_string_target_refused_with_not_string_component(
        self,
    ) -> None:
        import httpx

        from cognic_agentos.protocol.a2a_agent_cards import (
            A2AAgentCardError,
            A2AAgentCardVerifier,
        )
        from cognic_agentos.protocol.trust_gate import TrustGate

        http_client = MagicMock(spec=httpx.AsyncClient)
        http_client.get = AsyncMock()
        secret_adapter = MagicMock()
        secret_adapter.read = AsyncMock(return_value={"keys": []})
        audit_store = _silent_audit_store()
        decision_history_store = _silent_decision_history_store()
        settings = build_settings_without_env_file()
        verifier = A2AAgentCardVerifier(
            settings=settings,
            trust_gate=TrustGate(
                settings=settings,
                audit_store=audit_store,
                secret_adapter=secret_adapter,
            ),
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            http_client=http_client,
        )
        with pytest.raises(A2AAgentCardError) as excinfo:
            await verifier.fetch_and_verify_outbound_card(
                target_origin=12345,  # type: ignore[arg-type]
                tenant_id="bank_a",
                request_id="rid-outbound-canary-2",
            )
        assert excinfo.value.payload.get("rejected_component") == "not_string"
        http_client.get.assert_not_awaited()


# ---------------------------------------------------------------------------
# TestSubagentTargetIsEntryPointName
# ---------------------------------------------------------------------------


class TestSubagentTargetIsEntryPointName:
    """Sub-agent dispatch takes entry-point names, not URLs (the
    primitive itself ships in Sprint 8). The Sprint-6 transport-side
    invariant pinned here is INDIRECT: URL-shaped target_agent values
    fed to the inbound endpoint are refused as unknown targets BEFORE
    the verifier or any URL constructor is reached. Direct
    ``spawn_subagent(target_url=...)`` canaries land alongside the
    Sprint 8 sub-agent primitive."""

    @pytest.mark.parametrize(
        "subagent_target",
        [
            "https://malicious.example/subagent",
            "http://attacker.example",
            "//cdn.example/sub",
            "file:///etc/passwd",
        ],
        ids=lambda s: s[:30],
    )
    async def test_url_shaped_subagent_target_refused_indirectly(
        self,
        subagent_target: str,
        endpoint_for_routing_canary: tuple[A2AEndpoint, MagicMock],
    ) -> None:
        # Sprint-6 surface: a URL-shaped target_agent on the inbound
        # endpoint surface (the only A2A entry the kernel exposes
        # today) MUST be refused without any outbound URL ever being
        # constructed. The Sprint-8 spawn_subagent primitive will
        # add a direct canary that pins the same invariant on the
        # outbound subagent-spawn surface.
        endpoint, http_sentinel = endpoint_for_routing_canary
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "rid-sub",
                "method": "message/send",
                "params": {"message": {"parts": [{"text": "spawn"}]}},
            }
        ).encode("utf-8")
        with pytest.raises(A2AEndpointError) as excinfo:
            await endpoint.handle(
                target_agent=subagent_target,
                payload=payload,
                authorization_header="Bearer active-token",
                a2a_version_header="1.0",
                parent_trace_id="trace-sub",
                tenant_id="bank_a",
                request_id="rid-sub-1",
            )
        assert excinfo.value.code == "method_not_found"
        assert excinfo.value.payload.get("policy_reason") == "unknown_target"
        assert http_sentinel.method_calls == [], (
            f"URL-shaped subagent target {subagent_target!r} leaked "
            f"into outbound HTTP: {http_sentinel.method_calls!r}"
        )


# ---------------------------------------------------------------------------
# TestPushNotificationWebhookRefusedWave1
# ---------------------------------------------------------------------------


class TestPushNotificationWebhookRefusedWave1:
    """Push-notification subscribe / get methods carry a caller-
    supplied webhook URL in their params on the A2A 1.0 wire surface.
    Wave-1 MUST refuse these methods at the Wave-2 gate BEFORE the
    webhook URL is parsed — :data:`A2AErrorCode` =
    ``unsupported_operation`` + :data:`A2APolicyRefusalReason` =
    ``wave2_feature_refused``."""

    @pytest.mark.parametrize(
        "method",
        [
            "tasks/pushNotificationConfig/set",
            "tasks/pushNotificationConfig/get",
        ],
    )
    async def test_push_notification_webhook_refused_at_wave2_gate(
        self,
        method: str,
        endpoint_for_routing_canary: tuple[A2AEndpoint, MagicMock],
    ) -> None:
        endpoint, http_sentinel = endpoint_for_routing_canary
        # Webhook URL is intentionally adversarial — it MUST NEVER
        # reach a transport. The gate fires on the method name, not
        # on URL parsing.
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "rid-push",
                "method": method,
                "params": {
                    "pushNotificationConfig": {
                        "url": "https://attacker.example/webhook",
                        "token": "leak",
                    }
                },
            }
        ).encode("utf-8")
        with pytest.raises(A2AEndpointError) as excinfo:
            await endpoint.handle(
                target_agent="cognic_test_agent_pack",
                payload=payload,
                authorization_header="Bearer active-token",
                a2a_version_header="1.0",
                parent_trace_id=None,
                tenant_id="bank_a",
                request_id="rid-push-1",
            )
        assert excinfo.value.code == "unsupported_operation"
        assert excinfo.value.payload.get("policy_reason") == "wave2_feature_refused"
        assert excinfo.value.payload.get("wave2_feature") == "push_notification_subscribe"
        assert http_sentinel.method_calls == []


# ---------------------------------------------------------------------------
# TestThreatModelInvariants — closed-enum vocabulary drift detector.
# ---------------------------------------------------------------------------


class TestThreatModelInvariants:
    """Pin the four closed-enum vocabularies the canary depends on.
    Drift = wire-protocol-public; any addition trips a test and
    forces an explicit doctrine-update PR (the canary author must
    look at every arm and decide whether the new value matters)."""

    @staticmethod
    def _literal_values(literal_alias: Any) -> set[str]:
        """Extract the set of ``str`` values from a ``Literal[...]``
        type alias. Works for both ``typing.Literal`` and
        ``typing.Annotated[Literal[...]]``."""
        from typing import get_args

        return set(get_args(literal_alias))

    def test_a2a_authz_reason_pinned(self) -> None:
        assert self._literal_values(A2AAuthzReason) == {
            "a2a_anonymous_refused",
            "a2a_token_missing",
            "a2a_token_malformed",
            "a2a_tenant_mismatch",
            "a2a_token_revoked",
            "a2a_vault_read_failed",
            "a2a_audience_mismatch",
            "a2a_scope_insufficient",
        }

    def test_agent_card_validation_reason_pinned(self) -> None:
        assert self._literal_values(AgentCardValidationReason) == {
            "agent_card_upstream_schema_invalid",
            "agent_card_profile_provider_missing",
            "agent_card_profile_security_schemes_missing",
            "agent_card_profile_security_requirements_missing",
            "agent_card_profile_signatures_missing",
            "agent_card_profile_supported_interfaces_empty",
            "agent_card_profile_top_level_url_forbidden",
            "agent_card_profile_wave2_auth_required",
            "agent_card_jws_blob_unreadable",
            "agent_card_signature_invalid",
            "agent_card_signer_not_allowlisted",
        }

    def test_a2a_error_code_pinned(self) -> None:
        assert self._literal_values(A2AErrorCode) == {
            "parse_error",
            "invalid_request",
            "method_not_found",
            "invalid_params",
            "internal_error",
            "task_not_found",
            "task_not_cancelable",
            "version_not_supported",
            "unsupported_operation",
            "content_type_not_supported",
            "invalid_agent_response",
            "push_notification_not_supported",
            "extended_agent_card_not_configured",
            "extension_support_required",
        }

    def test_a2a_policy_refusal_reason_pinned(self) -> None:
        assert self._literal_values(A2APolicyRefusalReason) == {
            "agent_card_signature_invalid",
            "agent_card_signer_not_allowlisted",
            "agent_card_not_found",
            "anonymous_refused",
            "tenant_token_invalid",
            "unknown_target",
            "capability_not_supported",
            "streaming_not_supported",
            "artifact_too_large",
            "artifact_retention_exceeded",
            "wave2_feature_refused",
        }
