"""Sprint-6 T13 — fixture A2A pack admission + AgentCard JWS verify
+ A2AEndpoint receiver smoke.

Mirrors Sprint-5 ``test_mcp_fixture_pack_admission.py`` shape for
the A2A-side admission surface:

  1. Fixture-state guards — every required attestation file +
     manifest + AgentCard JSON + JWS bytes + public-key PEM is on
     disk. If a future commit deletes one, this test fails BEFORE
     the admission test runs (clearer failure mode).
  2. The fixture's ``__init__.py`` is import-poisoned — admission
     MUST NOT load pack code (deferred-load invariant per ADR-002
     §gate 1).
  3. AgentCard JWS verification — three layers, all against a
     mocked ``SecretAdapter`` that returns the fixture's public-key
     PEM at the canonical per-tenant Vault path:
       - direct ``joserfc.jws.deserialize_compact`` round-trip
         (proves card / JWS / pubkey are mutually consistent +
         pins detached-payload binding via tampered-payload
         regression);
       - ``TrustGate.verify_jws_blob`` (the runtime path that
         consults the per-tenant trust root + maps cryptographic
         failure to ``TrustGateError``);
       - the FULL ``A2AAgentCardVerifier.validate_card`` path
         (Pass-3 JWS verify → Pass-1 SDK protobuf parse → Pass-2
         bank-grade profile gates → success audit row).
     Every layer runs against the real fixture bytes, not a
     mocked verifier.
  4. ``A2AEndpoint`` receiver smoke: a stub agent registered as
     the fixture's ``cognic_test_agent_pack`` entry-point name
     receives a minimal Wave-1 Task envelope; the endpoint walks
     the 6 gates, dispatches, emits the chained
     ``a2a.task_received`` / ``a2a.task_running`` /
     ``a2a.task_succeeded`` audit rows. (The endpoint is wired
     with a ``MagicMock`` verifier here because the inbound
     ``validate_card`` invocation is exercised separately in
     layer 3 above; the endpoint smoke focuses on lifecycle +
     dispatch.)

The fixture's runnable-server path (live OAuth AS, real sockets,
signed AgentCard served at the spec well-known path with per-tenant
token round-trip against a real Vault) is deferred to a future
integration lane (Sprint 13.5 / pre-go-live), per the same scope
decision the Sprint-5 cognic_test_mcp_pack fixture made.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.core.audit import AuditEvent
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.protocol.a2a_authz import A2APinnedToken
from cognic_agentos.protocol.a2a_endpoint import A2AEndpoint, TaskState

# ---------------------------------------------------------------------------
# Fixture-state validation (mirrors Sprint-5 test_mcp_fixture_pack_admission)
# ---------------------------------------------------------------------------


_REPO_ROOT = Path(__file__).resolve().parents[3]
_FIXTURE_ROOT = _REPO_ROOT / "tests" / "fixtures" / "cognic_test_agent_pack"
_ATTESTATIONS = _FIXTURE_ROOT / "attestations"
_PACKAGE_DIR = _FIXTURE_ROOT / "cognic_test_agent_pack"
_MANIFEST_PATH = _PACKAGE_DIR / "cognic-pack-manifest.toml"
_AGENT_CARDS_DIR = _PACKAGE_DIR / "agent_cards"
_AGENT_CARD_JSON = _AGENT_CARDS_DIR / "test_agent.json"
_AGENT_CARD_JWS = _AGENT_CARDS_DIR / "test_agent.jws"
_AGENT_CARD_PUB_PEM = _AGENT_CARDS_DIR / "test_agent.pub.pem"

REQUIRED_ATTESTATION_FILES = (
    "sbom.cdx.json",
    "slsa-provenance.intoto.json",
    "intoto-layout.json",
    "vuln-scan.json",
    "license-audit.json",
    "cosign.sig",
    "bundle.sigstore",
)

_FIXTURE_KID = "test-agent-pack-fixture-key-v1"


class TestFixturePackBytesPresent:
    """Fixture-state guards: every required file is on disk + the
    manifest is parseable + the AgentCard JSON parses + the JWS
    string is non-empty + the public-key PEM is non-empty. If a
    future commit deletes one of these, this test fails BEFORE the
    end-to-end admission test runs."""

    def test_attestation_files_exist(self) -> None:
        for name in REQUIRED_ATTESTATION_FILES:
            assert (_ATTESTATIONS / name).is_file(), f"missing attestation file: {name}"

    def test_pyproject_toml_parses(self) -> None:
        path = _FIXTURE_ROOT / "pyproject.toml"
        assert path.is_file()
        data = tomllib.loads(path.read_text())
        assert data["project"]["name"] == "cognic-test-agent-pack"
        assert data["project"]["version"] == "0.1.0"
        # Entry-point group is cognic.agents (not .tools per Sprint-5).
        ep = data["project"]["entry-points"]["cognic.agents"]
        assert "cognic_test_agent_pack" in ep

    def test_pack_manifest_parses(self) -> None:
        assert _MANIFEST_PATH.is_file()
        data = tomllib.loads(_MANIFEST_PATH.read_text())
        assert data["tool"]["cognic"]["identity"]["pack_id"] == ("cognic-test-agent-pack")
        # FLAT [tool.cognic.a2a] block per A2A-CONFORMANCE.md.
        a2a = data["tool"]["cognic"]["a2a"]
        assert a2a["spec_version"] == "1.0"
        assert a2a["agent_card_jws_path"] == "agent_cards/test_agent.jws"
        assert a2a["streaming"] is True
        assert a2a["artifacts_supported"] is True
        assert a2a["push_notification_config"] is False  # Wave-2 stays off

    def test_agent_card_json_parses(self) -> None:
        import json

        assert _AGENT_CARD_JSON.is_file()
        card = json.loads(_AGENT_CARD_JSON.read_text())
        assert card["name"] == "Cognic Test Agent"
        # SDK-valid profile fields per A2A 1.0 AgentCard.
        assert card["provider"]["organization"]
        assert card["securitySchemes"]
        assert card["securityRequirements"]
        assert card["supportedInterfaces"]
        assert card["signatures"]

    def test_agent_card_json_parses_through_sdk(self) -> None:
        # T13 R1 P2 #1 regression: the static fixture MUST round-trip
        # through the pinned A2A 1.0 SDK ``AgentCard`` message, not
        # just through arbitrary JSON. Earlier fixture used non-SDK
        # fields (``protocolVersion`` / ``additionalInterfaces`` /
        # ``security``) that would fail this parse.
        from a2a.types.a2a_pb2 import AgentCard
        from google.protobuf import json_format

        json_format.Parse(_AGENT_CARD_JSON.read_bytes(), AgentCard())

    def test_agent_card_jws_is_detached(self) -> None:
        # T13 R1 P2 #2 regression: the JWS MUST be in plain detached
        # compact form (``<header>..<signature>`` with empty middle
        # segment) — the standard joserfc/PyJWT convention, NOT RFC
        # 7797 unencoded-payload mode (which would also require
        # ``b64: false`` + ``crit: ["b64"]`` in the protected
        # header). An embedded JWS would let the verifier accept the
        # fixture against any payload, defeating the binding.
        assert _AGENT_CARD_JWS.is_file()
        jws_str = _AGENT_CARD_JWS.read_text().strip()
        assert jws_str.count(".") == 2
        head, middle, sig = jws_str.split(".")
        assert head, "JWS header segment must be non-empty"
        assert middle == "", (
            "JWS payload segment must be empty for detached form; "
            f"got non-empty payload of length {len(middle)}"
        )
        assert sig, "JWS signature segment must be non-empty"
        # Sanity: leading segment decodes to a header carrying alg + kid.
        import base64
        import json as _json

        pad = "=" * (-len(head) % 4)
        header = _json.loads(base64.urlsafe_b64decode(head + pad))
        assert header["alg"] == "RS256"
        assert header["kid"] == _FIXTURE_KID

    def test_agent_card_public_key_present(self) -> None:
        assert _AGENT_CARD_PUB_PEM.is_file()
        pem = _AGENT_CARD_PUB_PEM.read_text()
        assert "BEGIN PUBLIC KEY" in pem
        assert "END PUBLIC KEY" in pem


class TestImportPoisonInvariant:
    """Per ADR-002 §gate 1: the admission pipeline MUST resolve the
    pack manifest + agent_cards/ via ``Distribution.locate_file()``
    WITHOUT importing the package code. The fixture's ``__init__.py``
    raises AssertionError on import — verifies the invariant is
    pinned by the actual fixture state."""

    def test_init_py_raises_on_import(self) -> None:
        # Direct file read confirms the AssertionError raise statement
        # is still in place (spec-vs-source diff catches a future edit
        # that accidentally removes the poison).
        init_py = _PACKAGE_DIR / "__init__.py"
        source = init_py.read_text()
        assert "raise AssertionError" in source
        assert "MUST NOT be executed" in source


# ---------------------------------------------------------------------------
# AgentCard JWS round-trip via real cryptographic verification
# ---------------------------------------------------------------------------


class TestAgentCardJwsRoundTrip:
    """Round-trip the fixture's static RS256 JWS bytes through
    ``joserfc.jws.deserialize_compact`` against the fixture's
    public-key PEM. This pins that the fixture's signing material
    is consistent (card + JWS + PEM mutually agree)."""

    def test_fixture_jws_verifies_against_fixture_pubkey(self) -> None:
        from joserfc import jws as jws_module
        from joserfc.jwk import RSAKey

        card_bytes = _AGENT_CARD_JSON.read_bytes()
        jws_str = _AGENT_CARD_JWS.read_text().strip()
        pub_pem = _AGENT_CARD_PUB_PEM.read_text()

        pub_key = RSAKey.import_key(pub_pem)
        # Plain detached compact JWS (joserfc convention): the JWS
        # middle segment is empty; ``deserialize_compact`` MUST be
        # given the original bytes via the ``payload=`` kwarg to
        # reconstruct the signing input. This is NOT RFC 7797
        # unencoded-payload mode — the signing input is still
        # ``b64url(header) + "." + b64url(payload)``.
        verified = jws_module.deserialize_compact(
            jws_str,
            pub_key,
            algorithms=["RS256"],
            payload=card_bytes,
        )
        assert verified.headers().get("alg") == "RS256"
        assert verified.headers().get("kid") == _FIXTURE_KID
        # The original card bytes round-trip (matches the payload
        # the JWS was signed over).
        assert verified.payload == card_bytes

    def test_fixture_jws_rejects_tampered_payload(self) -> None:
        # T13 R1 P2 #2 regression: detached JWS verification MUST
        # reject any payload bytes that don't match what was signed.
        # An embedded JWS would happily round-trip its own bundled
        # payload regardless of what callers pass — the detached
        # form forces the verifier to bind to the supplied bytes.
        from joserfc import errors as joserfc_errors
        from joserfc import jws as jws_module
        from joserfc.jwk import RSAKey

        card_bytes = _AGENT_CARD_JSON.read_bytes()
        jws_str = _AGENT_CARD_JWS.read_text().strip()
        pub_key = RSAKey.import_key(_AGENT_CARD_PUB_PEM.read_text())

        with pytest.raises(joserfc_errors.BadSignatureError):
            jws_module.deserialize_compact(
                jws_str,
                pub_key,
                algorithms=["RS256"],
                payload=card_bytes + b"X",
            )


class TestAgentCardJwsViaTrustGate:
    """Exercise ``TrustGate.verify_jws_blob`` against the fixture's
    static JWS + a mocked ``SecretAdapter`` that returns the
    fixture's public-key PEM at the per-tenant trust-root path. This
    is the same code path Sprint-6 T7
    (:class:`A2AAgentCardVerifier`) drives at runtime."""

    async def test_trust_gate_verifies_fixture_jws(self) -> None:
        from cognic_agentos.protocol.trust_gate import TrustGate

        secret_adapter = MagicMock()
        secret_adapter.read = AsyncMock(
            return_value={
                "keys": [
                    {
                        "kid": _FIXTURE_KID,
                        "pem": _AGENT_CARD_PUB_PEM.read_text(),
                    }
                ]
            }
        )
        audit_store = MagicMock()
        audit_store.append = AsyncMock(return_value=(None, b""))
        trust_gate = TrustGate(
            settings=build_settings_without_env_file(),
            audit_store=audit_store,
            secret_adapter=secret_adapter,
        )
        await trust_gate.verify_jws_blob(
            jws_bytes=_AGENT_CARD_JWS.read_bytes(),
            payload_bytes=_AGENT_CARD_JSON.read_bytes(),
            tenant_id="bank_a",
        )
        # No exception = verified. Confirm the secret adapter was
        # consulted at the canonical per-tenant Vault path.
        secret_adapter.read.assert_awaited_once_with("secret/cognic/bank_a/a2a-jws-trust-root")

    async def test_trust_gate_rejects_fixture_jws_with_tampered_payload(self) -> None:
        # T13 R1 P2 #2 regression: at the runtime trust-gate path,
        # ``verify_jws_blob`` MUST refuse the fixture JWS when called
        # with ``payload_bytes`` that don't match the bytes the JWS
        # was signed over. Confirms the detached-payload binding is
        # enforced end-to-end (not just in the joserfc round-trip).
        from cognic_agentos.protocol.trust_gate import TrustGate, TrustGateError

        secret_adapter = MagicMock()
        secret_adapter.read = AsyncMock(
            return_value={
                "keys": [
                    {
                        "kid": _FIXTURE_KID,
                        "pem": _AGENT_CARD_PUB_PEM.read_text(),
                    }
                ]
            }
        )
        audit_store = MagicMock()
        audit_store.append = AsyncMock(return_value=(None, b""))
        trust_gate = TrustGate(
            settings=build_settings_without_env_file(),
            audit_store=audit_store,
            secret_adapter=secret_adapter,
        )
        with pytest.raises(TrustGateError):
            await trust_gate.verify_jws_blob(
                jws_bytes=_AGENT_CARD_JWS.read_bytes(),
                payload_bytes=_AGENT_CARD_JSON.read_bytes() + b"X",
                tenant_id="bank_a",
            )


class TestAgentCardJwsViaCardVerifier:
    """T13 R2 P3 #1 regression — drive the FULL T7
    :class:`A2AAgentCardVerifier.validate_card` path against the
    fixture's static ``test_agent.json`` + ``test_agent.jws``. The
    fixture pack's docstring claims the static card round-trips
    through the verifier; this regression pins that claim end-to-end
    (JWS verify → JSON parse → SDK protobuf parse → bank-grade
    profile gates → success audit row), so a future change that
    breaks any of those passes against the fixture trips the test."""

    async def test_validate_card_accepts_fixture_pack_bytes(self) -> None:
        import httpx

        from cognic_agentos.protocol.a2a_agent_cards import A2AAgentCardVerifier
        from cognic_agentos.protocol.trust_gate import TrustGate

        secret_adapter = MagicMock()
        secret_adapter.read = AsyncMock(
            return_value={
                "keys": [
                    {
                        "kid": _FIXTURE_KID,
                        "pem": _AGENT_CARD_PUB_PEM.read_text(),
                    }
                ]
            }
        )
        audit_store = MagicMock()
        audit_store.append = AsyncMock(return_value=(None, b""))
        decision_history_store = MagicMock()
        decision_history_store.append = AsyncMock(return_value=(None, b""))
        settings = build_settings_without_env_file()
        trust_gate = TrustGate(
            settings=settings,
            audit_store=audit_store,
            secret_adapter=secret_adapter,
        )
        # The verifier requires an httpx.AsyncClient for the
        # outbound fetch path even though this test exercises the
        # inbound ``validate_card`` path (which doesn't issue HTTP).
        async with httpx.AsyncClient() as http_client:
            verifier = A2AAgentCardVerifier(
                settings=settings,
                trust_gate=trust_gate,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                http_client=http_client,
            )
            result = await verifier.validate_card(
                card_bytes=_AGENT_CARD_JSON.read_bytes(),
                jws_bytes=_AGENT_CARD_JWS.read_bytes(),
                tenant_id="bank_a",
                request_id="rid-fixture-validate-card-1",
            )
        assert result.ok is True, (
            f"fixture card+JWS rejected by validate_card: "
            f"reason={result.reason!r} payload={result.payload!r}"
        )
        assert result.reason is None
        # No decision-history row on success (only refusals emit one).
        decision_history_store.append.assert_not_awaited()
        # Success-path audit row was emitted.
        success_event_types = [
            call.args[0].event_type for call in audit_store.append.call_args_list
        ]
        assert "audit.a2a_agent_card_validated" in success_event_types


# ---------------------------------------------------------------------------
# A2AEndpoint receiver smoke against the fixture
# ---------------------------------------------------------------------------


class TestEndpointReceiverSmoke:
    """Sprint-6 receiver smoke: an inbound Wave-1 message envelope
    addressed at ``cognic_test_agent_pack`` walks the T9 gates and
    dispatches to a stub agent. The plugin registry is mocked at
    ``load("agents", target)`` so we don't need a real entry-point
    resolution (the fixture is import-poisoned by design).

    Intentionally narrow scope: this proves the endpoint integrates
    with the fixture's manifest-declared entry-point name, not the
    full HTTP / Vault / OAuth round-trip (deferred to integration
    lane per the same scope decision Sprint-5 T12 made)."""

    @pytest.fixture
    def stub_agent(self) -> MagicMock:
        agent = MagicMock()
        agent.handle = AsyncMock(return_value={"result": "ok", "agent": "cognic_test_agent_pack"})
        return agent

    @pytest.fixture
    def plugin_registry(self, stub_agent: MagicMock) -> MagicMock:
        registry = MagicMock()
        registry.load = MagicMock(return_value=stub_agent)
        return registry

    @pytest.fixture
    def authz_client(self) -> MagicMock:
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
    def audit_store(self) -> MagicMock:
        mock = MagicMock()
        mock.append = AsyncMock(return_value=(None, b""))
        return mock

    @pytest.fixture
    def decision_history_store(self) -> MagicMock:
        mock = MagicMock()
        mock.append = AsyncMock(return_value=(None, b""))
        return mock

    @pytest.fixture
    def endpoint(
        self,
        plugin_registry: MagicMock,
        authz_client: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
    ) -> A2AEndpoint:
        return A2AEndpoint(
            settings=build_settings_without_env_file(),
            plugin_registry=plugin_registry,
            authz_client=authz_client,
            agent_card_verifier=MagicMock(),
            audit_store=audit_store,
            decision_history_store=decision_history_store,
        )

    async def test_minimal_task_envelope_dispatched_to_fixture_agent(
        self,
        endpoint: A2AEndpoint,
        plugin_registry: MagicMock,
        stub_agent: MagicMock,
    ) -> None:
        """Inbound minimal Wave-1 task envelope is dispatched to
        ``cognic_test_agent_pack``'s stub handler; result returned
        verbatim."""
        valid_fixture = (
            _REPO_ROOT
            / "tests"
            / "fixtures"
            / "a2a-conformance"
            / "valid"
            / "task_request__minimal.json"
        )
        result = await endpoint.handle(
            target_agent="cognic_test_agent_pack",
            payload=valid_fixture.read_bytes(),
            authorization_header="Bearer active-token",
            a2a_version_header="1.0",
            parent_trace_id="trace-fixture-1",
            tenant_id="bank_a",
            request_id="rid-fixture-1",
        )
        assert result["result"] == "ok"
        assert result["agent"] == "cognic_test_agent_pack"
        # Registry resolved under the agents kind with the fixture's
        # entry-point name.
        plugin_registry.load.assert_called_once_with("agents", "cognic_test_agent_pack")
        stub_agent.handle.assert_awaited_once()

    async def test_lifecycle_emits_three_audit_rows(
        self,
        endpoint: A2AEndpoint,
        audit_store: MagicMock,
    ) -> None:
        valid_fixture = (
            _REPO_ROOT
            / "tests"
            / "fixtures"
            / "a2a-conformance"
            / "valid"
            / "task_request__minimal.json"
        )
        await endpoint.handle(
            target_agent="cognic_test_agent_pack",
            payload=valid_fixture.read_bytes(),
            authorization_header="Bearer active-token",
            a2a_version_header="1.0",
            parent_trace_id="trace-fixture-2",
            tenant_id="bank_a",
            request_id="rid-fixture-2",
        )
        event_types = [call.args[0].event_type for call in audit_store.append.call_args_list]
        # T9's lifecycle emits 3 transitions: created → running →
        # succeeded (typed audit rows).
        assert event_types == [
            "a2a.task_received",
            "a2a.task_running",
            "a2a.task_succeeded",
        ]
        # Final state.
        last_event: AuditEvent = audit_store.append.call_args.args[0]
        assert last_event.payload["task_state"] == TaskState.SUCCEEDED.value
        assert last_event.payload["target_agent"] == "cognic_test_agent_pack"
