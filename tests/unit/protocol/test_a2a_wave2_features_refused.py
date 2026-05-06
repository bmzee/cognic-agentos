"""Sprint-6 T14 — runtime canary for Wave-2 feature refusal.

Per A2A-CONFORMANCE.md §"Wave breakdown" + Sprint-6 Decision Lock #2:
Wave-2 features (push-notification subscribe / multimodal payloads /
long-running task resumption / mTLS auth) MUST be refused at the
inbound endpoint Wave-2 gate with spec code ``unsupported_operation``
+ policy reason ``wave2_feature_refused`` — they MUST NOT silent-
accept and degrade.

Canaries here drive the **real**
:meth:`A2AEndpoint._classify_wave2_feature` via :meth:`A2AEndpoint.handle`,
with authz mocked at the validate-inbound-token boundary so the
Wave-2 gate is reached. Mocking only the dependencies the canary
isn't testing keeps the gate-enforcement code under live test.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.protocol.a2a_authz import A2APinnedToken
from cognic_agentos.protocol.a2a_endpoint import A2AEndpoint, A2AEndpointError

# ---------------------------------------------------------------------------
# Endpoint fixture — real A2AEndpoint, mocked authz/registry/audit/dh.
# ---------------------------------------------------------------------------


def _make_endpoint() -> tuple[A2AEndpoint, MagicMock]:
    """Real endpoint, authz set to accept, registry that would
    resolve a stub agent (so Wave-2 refusals fire BEFORE routing
    succeeds — the gate ordering invariant). Returns (endpoint,
    audit_store) so canaries can pin the chained refusal evidence."""
    authz = MagicMock()
    authz.validate_inbound_token = AsyncMock(
        return_value=A2APinnedToken(
            value="active-token",
            tenant_id="bank_a",
            issued_at=1_700_000_000.0,
            expires_at=None,
        ),
    )
    stub_agent = MagicMock()
    stub_agent.handle = AsyncMock(return_value={"result": "should-not-reach"})
    registry = MagicMock()
    registry.load = MagicMock(return_value=stub_agent)
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
    return endpoint, audit_store


# ---------------------------------------------------------------------------
# TestWave2FeatureRefused — adversarial Wave-2 envelope-level surfaces.
# (mTLS-in-AgentCard is a card-level refusal driven through
# A2AAgentCardVerifier.validate_card and lives in the separate
# TestMtlsAgentCardSchemeRefusedWave1 class below.)
# ---------------------------------------------------------------------------


class TestWave2FeatureRefused:
    """Adversarial Wave-2 envelope-level traffic shapes (method
    names + Part-field signals + media-type prefixes + walker-
    bound exceedance), each pinned to refuse with spec code
    ``unsupported_operation`` + policy reason
    ``wave2_feature_refused``. Arm count grows when new Wave-2
    feature families land — we don't pin a numeric claim."""

    @pytest.mark.parametrize(
        "method,expected_feature",
        [
            ("tasks/pushNotificationConfig/set", "push_notification_subscribe"),
            ("tasks/pushNotificationConfig/get", "push_notification_subscribe"),
            ("tasks/resubscribe", "task_resumption"),
        ],
    )
    async def test_wave2_method_name_refused(self, method: str, expected_feature: str) -> None:
        endpoint, _ = _make_endpoint()
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "rid-w2-method",
                "method": method,
                "params": {},
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
                request_id="rid-w2-method-1",
            )
        assert excinfo.value.code == "unsupported_operation"
        assert excinfo.value.payload.get("policy_reason") == "wave2_feature_refused"
        assert excinfo.value.payload.get("wave2_feature") == expected_feature

    @pytest.mark.parametrize(
        "part",
        [
            {"raw": "aGVsbG8="},  # base64-encoded file bytes
            {"url": "https://attacker.example/leak.bin"},
        ],
        ids=["raw-file-bytes", "file-url"],
    )
    async def test_wave2_part_field_refused_multimodal_payload(self, part: dict[str, str]) -> None:
        endpoint, _ = _make_endpoint()
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "rid-w2-part",
                "method": "message/send",
                "params": {"message": {"parts": [part]}},
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
                request_id="rid-w2-part-1",
            )
        assert excinfo.value.code == "unsupported_operation"
        assert excinfo.value.payload.get("policy_reason") == "wave2_feature_refused"
        assert excinfo.value.payload.get("wave2_feature") == "multimodal_payload"

    @pytest.mark.parametrize(
        "media_type",
        [
            "image/png",
            "image/jpeg",
            "audio/mpeg",
            "video/mp4",
        ],
    )
    async def test_wave2_part_media_type_prefix_refused_multimodal_payload(
        self, media_type: str
    ) -> None:
        endpoint, _ = _make_endpoint()
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "rid-w2-mt",
                "method": "message/send",
                "params": {"message": {"parts": [{"text": "x", "mediaType": media_type}]}},
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
                request_id="rid-w2-mt-1",
            )
        assert excinfo.value.code == "unsupported_operation"
        assert excinfo.value.payload.get("policy_reason") == "wave2_feature_refused"
        assert excinfo.value.payload.get("wave2_feature") == "multimodal_payload"

    async def test_wave2_unscannable_payload_refused(self) -> None:
        # Payload depth far exceeds the walker bound; MUST refuse
        # with the closed sub-tag ``payload_unscannable`` rather
        # than blow the recursion budget. Builds the deeply-nested
        # JSON inline (committing the bytes would bloat the repo).
        endpoint, _ = _make_endpoint()
        depth = 5_000
        payload_bytes = b'{"a":' * depth + b'"x"' + b"}" * depth
        with pytest.raises(A2AEndpointError) as excinfo:
            await endpoint.handle(
                target_agent="cognic_test_agent_pack",
                payload=payload_bytes,
                authorization_header="Bearer active-token",
                a2a_version_header="1.0",
                parent_trace_id=None,
                tenant_id="bank_a",
                request_id="rid-w2-unscannable-1",
            )
        assert excinfo.value.code == "unsupported_operation"
        assert excinfo.value.payload.get("policy_reason") == "wave2_feature_refused"
        assert excinfo.value.payload.get("wave2_feature") == "payload_unscannable"


# ---------------------------------------------------------------------------
# TestMtlsAgentCardSchemeRefusedWave1 — mTLS in inbound AgentCard.
# ---------------------------------------------------------------------------


class TestMtlsAgentCardSchemeRefusedWave1:
    """Per A2A-CONFORMANCE.md §"Wave breakdown": Wave-1 = per-tenant
    bearer token, Wave-2 = mTLS, Wave-3 = verifiable credentials.
    An inbound AgentCard whose ``securitySchemes`` map declares any
    ``mtlsSecurityScheme`` entry MUST be refused as Wave-2 traffic
    by :class:`A2AAgentCardVerifier.validate_card` with the closed-
    enum reason ``agent_card_profile_wave2_auth_required``.

    The pre-T14-fix verifier had no surface that refused mTLS-in-card
    — this canary documented that production gap and forced the
    Wave-2 gate to be added before T14 could ship green."""

    async def test_mtls_security_scheme_in_card_refused(self) -> None:
        import json as _json

        import httpx

        from cognic_agentos.protocol.a2a_agent_cards import (
            A2AAgentCardVerifier,
        )
        from cognic_agentos.protocol.trust_gate import TrustGate

        card_dict = {
            "name": "MTLS Agent",
            "description": "Wave-2 mTLS canary",
            "version": "0.1.0",
            "provider": {"organization": "Cognic mTLS canary"},
            "capabilities": {"streaming": True},
            "defaultInputModes": ["text/plain"],
            "defaultOutputModes": ["text/plain"],
            "supportedInterfaces": [
                {
                    "url": "https://mtls.example/a2a",
                    "protocolBinding": "JSONRPC",
                    "tenant": "bank_a",
                    "protocolVersion": "1.0",
                }
            ],
            "securitySchemes": {"mtls": {"mtlsSecurityScheme": {"description": "mTLS only"}}},
            "securityRequirements": [{"schemes": {"mtls": {"list": []}}}],
            "skills": [
                {
                    "id": "s",
                    "name": "s",
                    "description": "s",
                    "tags": ["t"],
                }
            ],
            "signatures": [{"protected": "phdr", "signature": "psig"}],
        }
        card_bytes = _json.dumps(card_dict).encode("utf-8")
        # JWS bytes are intentionally unimportant for this canary —
        # the trust gate is mocked to accept everything so the
        # subject is the AgentCard-shape refusal, not JWS
        # verification (which has its own dedicated canary).
        jws_bytes = b"jws.placeholder.bytes"

        secret_adapter = MagicMock()
        secret_adapter.read = AsyncMock(return_value={"keys": []})
        audit_store = MagicMock()
        audit_store.append = AsyncMock(return_value=(None, b""))
        decision_history_store = MagicMock()
        decision_history_store.append = AsyncMock(return_value=(None, b""))
        settings = build_settings_without_env_file()

        trust_gate = MagicMock(spec=TrustGate)
        trust_gate.verify_jws_blob = AsyncMock(return_value=None)

        async with httpx.AsyncClient() as http_client:
            verifier = A2AAgentCardVerifier(
                settings=settings,
                trust_gate=trust_gate,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                http_client=http_client,
            )
            result = await verifier.validate_card(
                card_bytes=card_bytes,
                jws_bytes=jws_bytes,
                tenant_id="bank_a",
                request_id="rid-mtls-canary-1",
            )
        assert result.ok is False
        assert result.reason == "agent_card_profile_wave2_auth_required"
        assert result.payload.get("rejected_scheme_kind") == "mtls_security_scheme"
        assert result.payload.get("rejected_scheme_name") == "mtls"
