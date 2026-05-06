"""Sprint 6 T7 — protocol/a2a_agent_cards.py contract tests.

Covers the three-pass Agent Card validator + outbound-dispatch
verifier. Each of the 11 :class:`AgentCardValidationReason`
literals has at least one fire-path arm (T14 added
``agent_card_profile_wave2_auth_required`` as the 11th value —
covered by ``TestProfileWave2AuthRequired``); happy path + audit
emission + outbound-fetch behaviour are pinned in their own
classes.

The plan-of-record specifies four test files
(test_a2a_agent_cards.py, test_a2a_agent_card_jws_required.py,
test_a2a_agent_card_outbound_verification.py,
test_a2a_agent_card_chain_audit.py). T7 R0 implementation
consolidates these into the single file below — every contract
point named in the four files is preserved, organised as test
classes within one module so the verifier's contract surface is
audit-able in one place. The unified file uses one test class
per contract point (one class per ``AgentCardValidationReason``
literal + happy-path + audit-emission + outbound-fetch +
trust-gate-direct + tenant-validation + origin-validation +
closed-enum drift detector); the exact class count grows when
new contract points land, so we don't pin a numeric count here.

Per ADR-003 + A2A-CONFORMANCE.md §"Card shape" + §"Card signatures
(JWS)": every inbound A2A pack registration MUST present a
JWS-signed Agent Card; outbound dispatch MUST verify the
target's card before sending. This test file backs both halves.
"""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from joserfc import jws as jws_module
from joserfc.jwk import RSAKey

from cognic_agentos.core.audit import AuditEvent
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.decision_history import DecisionRecord
from cognic_agentos.protocol.a2a_agent_cards import (
    A2AAgentCardError,
    A2AAgentCardVerifier,
    AgentCardValidation,
)
from cognic_agentos.protocol.trust_gate import (
    TrustGate,
    TrustGateError,
    TrustGateSignerNotAllowlistedError,
)

# =============================================================================
# Fixtures — RSA keypair, signed-card builder, mock substrate
# =============================================================================


@pytest.fixture(scope="module")
def rsa_keypair() -> tuple[str, str]:
    """A real 2048-bit RSA keypair used to sign + verify the test
    cards. Module-scoped so we generate it once per test session
    rather than once per arm (RSA generation is slow)."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_pem = (
        priv.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return priv_pem, pub_pem


@pytest.fixture(scope="module")
def alt_rsa_keypair() -> tuple[str, str]:
    """A second, separate RSA keypair for negative-control arms
    (signature-mismatch / non-allowlisted-signer scenarios)."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_pem = (
        priv.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return priv_pem, pub_pem


@pytest.fixture
def secret_adapter(rsa_keypair: tuple[str, str]) -> MagicMock:
    """Mock SecretAdapter wired to return the per-tenant trust root
    payload for ``bank_a``. The trust root contains one allow-listed
    key with kid ``bank-a-key-1``."""
    _, pub_pem = rsa_keypair
    mock = MagicMock()

    async def _read(path: str) -> dict[str, Any]:
        if path == "secret/cognic/bank_a/a2a-jws-trust-root":
            return {
                "keys": [
                    {"kid": "bank-a-key-1", "pem": pub_pem},
                ]
            }
        raise KeyError(f"unknown vault path: {path}")

    mock.read = AsyncMock(side_effect=_read)
    return mock


@pytest.fixture
def audit_store() -> MagicMock:
    mock = MagicMock()
    mock.append = AsyncMock()
    return mock


@pytest.fixture
def decision_history_store() -> MagicMock:
    mock = MagicMock()
    mock.append = AsyncMock()
    return mock


@pytest.fixture
def trust_gate(secret_adapter: MagicMock, audit_store: MagicMock) -> TrustGate:
    """Real TrustGate with mocked SecretAdapter. The cosign half of
    TrustGate isn't exercised by these tests; only ``verify_jws_blob``
    runs."""
    return TrustGate(
        settings=build_settings_without_env_file(),
        audit_store=audit_store,
        secret_adapter=secret_adapter,
    )


@pytest.fixture
async def http_client() -> AsyncGenerator[httpx.AsyncClient, None]:
    """A real httpx AsyncClient — outbound-fetch tests use respx to
    mock the network layer."""
    async with httpx.AsyncClient() as client:
        yield client


@pytest.fixture
def verifier(
    trust_gate: TrustGate,
    audit_store: MagicMock,
    decision_history_store: MagicMock,
    http_client: httpx.AsyncClient,
) -> A2AAgentCardVerifier:
    return A2AAgentCardVerifier(
        settings=build_settings_without_env_file(),
        trust_gate=trust_gate,
        audit_store=audit_store,
        decision_history_store=decision_history_store,
        http_client=http_client,
    )


def _sign_card(
    card_dict: dict[str, Any],
    priv_pem: str,
    *,
    kid: str = "bank-a-key-1",
) -> tuple[bytes, bytes]:
    """Serialise a card dict to canonical JSON bytes + produce a
    detached RFC-7797 JWS over those bytes. Returns
    ``(card_bytes, jws_bytes)``.

    Detached JWS: the payload is NOT embedded in the JWS; the
    signature is computed over the unencoded payload (RFC 7797
    ``b64=False``)."""
    priv_key = RSAKey.import_key(priv_pem, parameters={"kid": kid})
    card_bytes = json.dumps(card_dict, sort_keys=True).encode()
    signed = jws_module.serialize_compact(
        {"alg": "RS256", "kid": kid, "b64": False, "crit": ["b64"]},
        card_bytes,
        priv_key,
        algorithms=["RS256"],
    )
    return card_bytes, signed.encode() if isinstance(signed, str) else signed


def _valid_card_dict() -> dict[str, Any]:
    """Build a card dict that satisfies the AgentOS profile gates +
    the protobuf schema. Each profile gate test starts from this
    dict and removes ONE field to assert the matching reason fires.

    Note the protobuf shape (per ``a2a-sdk == 1.0.2``):

    - ``securitySchemes`` is ``map<string, SecurityScheme>`` (an
      object keyed by scheme name, NOT a list).
    - ``securityRequirements[].schemes`` is ``map<string, StringList>``
      where ``StringList`` itself wraps a ``list`` field — hence the
      ``{"bearer": {"list": ["scope1"]}}`` shape below.
    - ``signatures`` is a repeated ``AgentCardSignature``.
    - ``supportedInterfaces`` is a repeated ``AgentInterface``.

    These are protobuf-canonical JSON shapes (verified via
    ``google.protobuf.json_format.Parse`` round-trip)."""
    return {
        "name": "cognic_test_agent",
        "description": "T7 happy-path agent card",
        "version": "1.0.0",
        "provider": {"organization": "Cognic", "url": "https://cognic.ai"},
        "supportedInterfaces": [{"url": "https://example.com/a2a", "protocolBinding": "a2a"}],
        "securitySchemes": {"bearer": {}},
        "securityRequirements": [{"schemes": {"bearer": {"list": ["scope1"]}}}],
        "signatures": [{"protected": "abc", "signature": "def"}],
    }


# =============================================================================
# Pass 3 — JWS verification (3 reasons)
# =============================================================================


class TestJwsBlobUnreadable:
    """Reason: ``agent_card_jws_blob_unreadable`` — JWS bytes
    exceed the per-tenant size cap. Defends against DoS via
    large-blob signature verification."""

    async def test_jws_over_size_cap_refused(self, verifier: A2AAgentCardVerifier) -> None:
        oversized_jws = b"x" * (65 * 1024)  # default cap is 64 KiB
        result = await verifier.validate_card(
            card_bytes=b"{}",
            jws_bytes=oversized_jws,
            tenant_id="bank_a",
            request_id="rid",
        )
        assert result.ok is False
        assert result.reason == "agent_card_jws_blob_unreadable"
        assert result.payload["reason_detail"] == "size_cap_exceeded"


class TestSignerNotAllowlisted:
    """Reason: ``agent_card_signer_not_allowlisted`` — the JWS
    advertises a ``kid`` that is NOT on the per-tenant trust root.
    Distinct from cryptographic-verify failure."""

    async def test_unknown_kid_refused(
        self,
        verifier: A2AAgentCardVerifier,
        rsa_keypair: tuple[str, str],
    ) -> None:
        priv_pem, _ = rsa_keypair
        # Sign with a kid that's NOT on the trust root.
        card_bytes, jws_bytes = _sign_card(_valid_card_dict(), priv_pem, kid="rogue-kid")
        result = await verifier.validate_card(
            card_bytes=card_bytes,
            jws_bytes=jws_bytes,
            tenant_id="bank_a",
            request_id="rid",
        )
        assert result.ok is False
        assert result.reason == "agent_card_signer_not_allowlisted"


class TestSignatureInvalid:
    """Reason: ``agent_card_signature_invalid`` — JWS parse failure
    OR cryptographic verify failure OR missing kid header."""

    async def test_unparseable_jws_refused(self, verifier: A2AAgentCardVerifier) -> None:
        result = await verifier.validate_card(
            card_bytes=b'{"name": "agent"}',
            jws_bytes=b"not-a-jws-blob",
            tenant_id="bank_a",
            request_id="rid",
        )
        assert result.ok is False
        assert result.reason == "agent_card_signature_invalid"

    async def test_signed_with_wrong_key_refused(
        self,
        verifier: A2AAgentCardVerifier,
        alt_rsa_keypair: tuple[str, str],
    ) -> None:
        """Sign with a key whose kid IS on the trust root but the
        signature was made with a different private key — the
        cryptographic verify fails. Maps to signature_invalid."""
        priv_pem, _ = alt_rsa_keypair
        # Use the trust-root's kid but sign with the wrong private key.
        card_bytes, jws_bytes = _sign_card(_valid_card_dict(), priv_pem, kid="bank-a-key-1")
        result = await verifier.validate_card(
            card_bytes=card_bytes,
            jws_bytes=jws_bytes,
            tenant_id="bank_a",
            request_id="rid",
        )
        assert result.ok is False
        assert result.reason == "agent_card_signature_invalid"

    async def test_payload_tampered_after_signing_refused(
        self,
        verifier: A2AAgentCardVerifier,
        rsa_keypair: tuple[str, str],
    ) -> None:
        """Sign card A; submit card B with the JWS for A. The
        cryptographic verify fails because the JWS was computed
        over A's bytes."""
        priv_pem, _ = rsa_keypair
        _, jws_for_a = _sign_card(_valid_card_dict(), priv_pem)
        tampered = json.dumps({"name": "tampered_agent"}).encode()
        result = await verifier.validate_card(
            card_bytes=tampered,
            jws_bytes=jws_for_a,
            tenant_id="bank_a",
            request_id="rid",
        )
        assert result.ok is False
        assert result.reason == "agent_card_signature_invalid"


# =============================================================================
# Pass 1 — upstream A2A 1.0 schema (1 reason + the dedicated forbidden-url)
# =============================================================================


class TestUpstreamSchemaInvalid:
    """Reason: ``agent_card_upstream_schema_invalid`` — JSON is
    malformed OR protobuf parse rejects the field shape."""

    async def test_malformed_json_refused(
        self,
        verifier: A2AAgentCardVerifier,
        rsa_keypair: tuple[str, str],
    ) -> None:
        priv_pem, _ = rsa_keypair
        bad_bytes = b"{not-valid-json"
        # We need to sign the bad bytes so JWS verification passes
        # and the schema gate fires next.
        priv_key = RSAKey.import_key(priv_pem, parameters={"kid": "bank-a-key-1"})
        signed = jws_module.serialize_compact(
            {"alg": "RS256", "kid": "bank-a-key-1", "b64": False, "crit": ["b64"]},
            bad_bytes,
            priv_key,
            algorithms=["RS256"],
        )
        jws_bytes = signed.encode() if isinstance(signed, str) else signed
        result = await verifier.validate_card(
            card_bytes=bad_bytes,
            jws_bytes=jws_bytes,
            tenant_id="bank_a",
            request_id="rid",
        )
        assert result.ok is False
        assert result.reason == "agent_card_upstream_schema_invalid"

    async def test_protobuf_unknown_field_refused(
        self,
        verifier: A2AAgentCardVerifier,
        rsa_keypair: tuple[str, str],
    ) -> None:
        """Card with a field name that isn't in the AgentCard
        protobuf schema (other than the forbidden top-level ``url``,
        which has its own dedicated reason). The protobuf parse
        rejects on ParseError."""
        priv_pem, _ = rsa_keypair
        card = _valid_card_dict()
        card["thisFieldDoesNotExistInTheSpec"] = "value"
        card_bytes, jws_bytes = _sign_card(card, priv_pem)
        result = await verifier.validate_card(
            card_bytes=card_bytes,
            jws_bytes=jws_bytes,
            tenant_id="bank_a",
            request_id="rid",
        )
        assert result.ok is False
        assert result.reason == "agent_card_upstream_schema_invalid"


class TestForbiddenTopLevelUrl:
    """Reason: ``agent_card_profile_top_level_url_forbidden`` — card
    carries a top-level ``url`` field. Per ADR-003 + A2A-
    CONFORMANCE.md §"Card shape", endpoint URLs live in
    ``supportedInterfaces[].url``, NEVER at the top level. T7 R5
    P2 reviewer correction: this check fires BEFORE protobuf parse
    so the dedicated reason stays reachable."""

    async def test_top_level_url_refused(
        self,
        verifier: A2AAgentCardVerifier,
        rsa_keypair: tuple[str, str],
    ) -> None:
        priv_pem, _ = rsa_keypair
        card = _valid_card_dict()
        card["url"] = "https://forbidden.example.com/wrong-place"
        card_bytes, jws_bytes = _sign_card(card, priv_pem)
        result = await verifier.validate_card(
            card_bytes=card_bytes,
            jws_bytes=jws_bytes,
            tenant_id="bank_a",
            request_id="rid",
        )
        assert result.ok is False
        assert result.reason == "agent_card_profile_top_level_url_forbidden"
        assert result.payload["forbidden_field"] == "url"


# =============================================================================
# Pass 2 — AgentOS profile gates (5 reasons)
# =============================================================================


class TestProfileProviderMissing:
    """Reason: ``agent_card_profile_provider_missing`` — provider
    field absent OR provider.organization is empty (the spec
    treats provider as identifying who owns the agent; AgentOS
    rejects unidentified provenance)."""

    async def test_provider_omitted_refused(
        self,
        verifier: A2AAgentCardVerifier,
        rsa_keypair: tuple[str, str],
    ) -> None:
        priv_pem, _ = rsa_keypair
        card = _valid_card_dict()
        del card["provider"]
        card_bytes, jws_bytes = _sign_card(card, priv_pem)
        result = await verifier.validate_card(
            card_bytes=card_bytes,
            jws_bytes=jws_bytes,
            tenant_id="bank_a",
            request_id="rid",
        )
        assert result.ok is False
        assert result.reason == "agent_card_profile_provider_missing"

    async def test_provider_with_empty_organization_refused(
        self,
        verifier: A2AAgentCardVerifier,
        rsa_keypair: tuple[str, str],
    ) -> None:
        """Provider sub-message present but organization is empty
        — defends against the protobuf default-instance trap (a
        protobuf message is always truthy regardless of contents,
        so a missing-organization check is the load-bearing gate)."""
        priv_pem, _ = rsa_keypair
        card = _valid_card_dict()
        card["provider"] = {"url": "https://cognic.ai"}  # organization absent
        card_bytes, jws_bytes = _sign_card(card, priv_pem)
        result = await verifier.validate_card(
            card_bytes=card_bytes,
            jws_bytes=jws_bytes,
            tenant_id="bank_a",
            request_id="rid",
        )
        assert result.ok is False
        assert result.reason == "agent_card_profile_provider_missing"


class TestProfileSecuritySchemesMissing:
    async def test_security_schemes_empty_refused(
        self,
        verifier: A2AAgentCardVerifier,
        rsa_keypair: tuple[str, str],
    ) -> None:
        """``securitySchemes`` is a ``map<string, SecurityScheme>``;
        empty map = profile gate fires."""
        priv_pem, _ = rsa_keypair
        card = _valid_card_dict()
        card["securitySchemes"] = {}
        card_bytes, jws_bytes = _sign_card(card, priv_pem)
        result = await verifier.validate_card(
            card_bytes=card_bytes,
            jws_bytes=jws_bytes,
            tenant_id="bank_a",
            request_id="rid",
        )
        assert result.ok is False
        assert result.reason == "agent_card_profile_security_schemes_missing"


class TestProfileSecurityRequirementsMissing:
    async def test_security_requirements_empty_refused(
        self,
        verifier: A2AAgentCardVerifier,
        rsa_keypair: tuple[str, str],
    ) -> None:
        priv_pem, _ = rsa_keypair
        card = _valid_card_dict()
        card["securityRequirements"] = []
        card_bytes, jws_bytes = _sign_card(card, priv_pem)
        result = await verifier.validate_card(
            card_bytes=card_bytes,
            jws_bytes=jws_bytes,
            tenant_id="bank_a",
            request_id="rid",
        )
        assert result.ok is False
        assert result.reason == "agent_card_profile_security_requirements_missing"


class TestProfileSignaturesMissing:
    async def test_signatures_empty_refused(
        self,
        verifier: A2AAgentCardVerifier,
        rsa_keypair: tuple[str, str],
    ) -> None:
        priv_pem, _ = rsa_keypair
        card = _valid_card_dict()
        card["signatures"] = []
        card_bytes, jws_bytes = _sign_card(card, priv_pem)
        result = await verifier.validate_card(
            card_bytes=card_bytes,
            jws_bytes=jws_bytes,
            tenant_id="bank_a",
            request_id="rid",
        )
        assert result.ok is False
        assert result.reason == "agent_card_profile_signatures_missing"


class TestProfileSupportedInterfacesEmpty:
    async def test_supported_interfaces_empty_refused(
        self,
        verifier: A2AAgentCardVerifier,
        rsa_keypair: tuple[str, str],
    ) -> None:
        priv_pem, _ = rsa_keypair
        card = _valid_card_dict()
        card["supportedInterfaces"] = []
        card_bytes, jws_bytes = _sign_card(card, priv_pem)
        result = await verifier.validate_card(
            card_bytes=card_bytes,
            jws_bytes=jws_bytes,
            tenant_id="bank_a",
            request_id="rid",
        )
        assert result.ok is False
        assert result.reason == "agent_card_profile_supported_interfaces_empty"


class TestProfileWave2AuthRequired:
    """T14: a card whose ``securitySchemes`` map declares any
    ``mtlsSecurityScheme`` entry MUST be refused under Wave-1
    bearer-token transport policy. Wave-1 = per-tenant pinned
    bearer token; Wave-2 = mTLS; Wave-3 = verifiable credentials
    per A2A-CONFORMANCE.md §"Wave breakdown"."""

    async def test_mtls_only_card_refused_with_wave2_reason(
        self,
        verifier: A2AAgentCardVerifier,
        rsa_keypair: tuple[str, str],
    ) -> None:
        priv_pem, _ = rsa_keypair
        card = _valid_card_dict()
        card["securitySchemes"] = {"mtls": {"mtlsSecurityScheme": {"description": "mTLS only"}}}
        card_bytes, jws_bytes = _sign_card(card, priv_pem)
        result = await verifier.validate_card(
            card_bytes=card_bytes,
            jws_bytes=jws_bytes,
            tenant_id="bank_a",
            request_id="rid-mtls-only",
        )
        assert result.ok is False
        assert result.reason == "agent_card_profile_wave2_auth_required"

    async def test_mtls_alongside_bearer_still_refused(
        self,
        verifier: A2AAgentCardVerifier,
        rsa_keypair: tuple[str, str],
    ) -> None:
        # Even with a bearer scheme on offer, the presence of mTLS
        # anywhere in the map signals a Wave-2 expectation. The gate
        # fires conservatively — when Wave-2 lands, lift it to
        # ``mtls-ONLY-card refused`` per the docstring on
        # ``validate_card``.
        priv_pem, _ = rsa_keypair
        card = _valid_card_dict()
        card["securitySchemes"] = {
            "bearer": {},
            "mtls": {"mtlsSecurityScheme": {"description": "Wave-2 future"}},
        }
        card_bytes, jws_bytes = _sign_card(card, priv_pem)
        result = await verifier.validate_card(
            card_bytes=card_bytes,
            jws_bytes=jws_bytes,
            tenant_id="bank_a",
            request_id="rid-mtls-mixed",
        )
        assert result.ok is False
        assert result.reason == "agent_card_profile_wave2_auth_required"


# =============================================================================
# Happy path
# =============================================================================


class TestValidCardAccepted:
    async def test_valid_three_pass_card_accepted(
        self,
        verifier: A2AAgentCardVerifier,
        rsa_keypair: tuple[str, str],
    ) -> None:
        priv_pem, _ = rsa_keypair
        card_bytes, jws_bytes = _sign_card(_valid_card_dict(), priv_pem)
        result = await verifier.validate_card(
            card_bytes=card_bytes,
            jws_bytes=jws_bytes,
            tenant_id="bank_a",
            request_id="rid-happy",
        )
        assert result.ok is True
        assert result.reason is None
        assert result.payload == {}


# =============================================================================
# Audit + decision-history emission (T7 chain-audit contract)
# =============================================================================


class TestAuditEmissionOnAccept:
    """Plan-of-record `test_a2a_agent_card_chain_audit.py` contract:
    accepted card → audit row in the chain; no decision-history row
    (audit-only on accept, mirrors Sprint-5 mcp_authz pattern)."""

    async def test_accept_emits_audit_event(
        self,
        verifier: A2AAgentCardVerifier,
        audit_store: MagicMock,
        rsa_keypair: tuple[str, str],
    ) -> None:
        priv_pem, _ = rsa_keypair
        card_bytes, jws_bytes = _sign_card(_valid_card_dict(), priv_pem)
        await verifier.validate_card(
            card_bytes=card_bytes,
            jws_bytes=jws_bytes,
            tenant_id="bank_a",
            request_id="rid-accept",
        )
        audit_store.append.assert_called_once()
        event: AuditEvent = audit_store.append.call_args.args[0]
        assert event.event_type == "audit.a2a_agent_card_validated"
        assert event.tenant_id == "bank_a"
        assert event.request_id == "rid-accept"
        assert event.payload["outcome"] == "validated"

    async def test_accept_does_not_emit_decision_history(
        self,
        verifier: A2AAgentCardVerifier,
        decision_history_store: MagicMock,
        rsa_keypair: tuple[str, str],
    ) -> None:
        priv_pem, _ = rsa_keypair
        card_bytes, jws_bytes = _sign_card(_valid_card_dict(), priv_pem)
        await verifier.validate_card(
            card_bytes=card_bytes,
            jws_bytes=jws_bytes,
            tenant_id="bank_a",
            request_id="rid",
        )
        decision_history_store.append.assert_not_called()


class TestAuditEmissionOnRefusal:
    """Every refusal emits BOTH an audit event AND a decision-
    history row. Operators can correlate refusals via request_id."""

    async def test_signature_invalid_emits_both_chains(
        self,
        verifier: A2AAgentCardVerifier,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
    ) -> None:
        await verifier.validate_card(
            card_bytes=b"{}",
            jws_bytes=b"unparseable",
            tenant_id="bank_a",
            request_id="rid-refusal",
        )
        audit_store.append.assert_called_once()
        decision_history_store.append.assert_called_once()
        event: AuditEvent = audit_store.append.call_args.args[0]
        assert event.event_type == "audit.a2a_agent_card_rejected"
        assert event.payload["reason"] == "agent_card_signature_invalid"
        record: DecisionRecord = decision_history_store.append.call_args.args[0]
        assert record.decision_type == "a2a_agent_card_rejected"
        assert record.payload["reason"] == "agent_card_signature_invalid"

    async def test_audit_payload_carries_jws_error_class_not_raw_text(
        self,
        verifier: A2AAgentCardVerifier,
        audit_store: MagicMock,
    ) -> None:
        """Sprint-5 T15 R1 P2 #3 doctrine: ``type(exc).__name__``
        lands in payload; raw exception text never does. The trust-
        gate's exception-mapping wraps lower-layer joserfc errors
        into :class:`TrustGateError` before they reach the verifier,
        so the payload's ``jws_error_class`` carries the trust-gate
        class name (the gate's stable boundary)."""
        await verifier.validate_card(
            card_bytes=b"{}",
            jws_bytes=b"not-a-jws",
            tenant_id="bank_a",
            request_id="rid",
        )
        event: AuditEvent = audit_store.append.call_args.args[0]
        assert "jws_error_class" in event.payload
        # The trust gate's verify_jws_blob wraps every joserfc
        # exception class into TrustGateError before re-raising —
        # that's the stable closed-enum boundary the verifier sees.
        # Pin the exact class name for unambiguous diagnostics.
        assert event.payload["jws_error_class"] == "TrustGateError"


# =============================================================================
# Outbound dispatch verification — `fetch_and_verify_outbound_card`
# =============================================================================


class TestOutboundFetchAndVerify:
    """Plan-of-record `test_a2a_agent_card_outbound_verification.py`
    contract: outbound dispatch fetches the target's card + JWS,
    verifies, and only then returns the AgentCard for the caller
    to dispatch against. Any failure raises A2AAgentCardError."""

    @respx.mock
    async def test_valid_remote_card_returns_agent_card(
        self,
        verifier: A2AAgentCardVerifier,
        rsa_keypair: tuple[str, str],
    ) -> None:
        priv_pem, _ = rsa_keypair
        card_bytes, jws_bytes = _sign_card(_valid_card_dict(), priv_pem)
        respx.get("https://remote.example.com/.well-known/agent-card.json").mock(
            return_value=httpx.Response(200, content=card_bytes)
        )
        respx.get("https://remote.example.com/.well-known/agent-card.json.jws").mock(
            return_value=httpx.Response(200, content=jws_bytes)
        )
        result = await verifier.fetch_and_verify_outbound_card(
            target_origin="https://remote.example.com",
            tenant_id="bank_a",
            request_id="rid",
        )
        # The returned object is a protobuf AgentCard message.
        assert hasattr(result, "name")
        assert result.name == "cognic_test_agent"
        # supported_interfaces is the SAFE source of dispatch URLs.
        assert len(result.supported_interfaces) >= 1
        assert result.supported_interfaces[0].url == "https://example.com/a2a"

    @respx.mock
    async def test_card_404_raises_blob_unreadable(
        self,
        verifier: A2AAgentCardVerifier,
    ) -> None:
        respx.get("https://remote.example.com/.well-known/agent-card.json").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://remote.example.com/.well-known/agent-card.json.jws").mock(
            return_value=httpx.Response(200, content=b"x")
        )
        with pytest.raises(A2AAgentCardError) as exc:
            await verifier.fetch_and_verify_outbound_card(
                target_origin="https://remote.example.com",
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "agent_card_jws_blob_unreadable"
        assert exc.value.payload["card_status"] == 404

    @respx.mock
    async def test_jws_404_raises_blob_unreadable(
        self,
        verifier: A2AAgentCardVerifier,
    ) -> None:
        respx.get("https://remote.example.com/.well-known/agent-card.json").mock(
            return_value=httpx.Response(200, content=b"{}")
        )
        respx.get("https://remote.example.com/.well-known/agent-card.json.jws").mock(
            return_value=httpx.Response(404)
        )
        with pytest.raises(A2AAgentCardError) as exc:
            await verifier.fetch_and_verify_outbound_card(
                target_origin="https://remote.example.com",
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "agent_card_jws_blob_unreadable"

    @respx.mock
    async def test_remote_card_with_top_level_url_refused(
        self,
        verifier: A2AAgentCardVerifier,
        rsa_keypair: tuple[str, str],
    ) -> None:
        """Spec-violation: remote card carries top-level ``url``.
        The outbound verify refuses with the dedicated reason —
        this is the runtime backstop for the T4 architecture test
        + T14 canary that bans caller-controlled URLs."""
        priv_pem, _ = rsa_keypair
        bad_card = _valid_card_dict()
        bad_card["url"] = "https://attacker.example.com/redirect"
        card_bytes, jws_bytes = _sign_card(bad_card, priv_pem)
        respx.get("https://remote.example.com/.well-known/agent-card.json").mock(
            return_value=httpx.Response(200, content=card_bytes)
        )
        respx.get("https://remote.example.com/.well-known/agent-card.json.jws").mock(
            return_value=httpx.Response(200, content=jws_bytes)
        )
        with pytest.raises(A2AAgentCardError) as exc:
            await verifier.fetch_and_verify_outbound_card(
                target_origin="https://remote.example.com",
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "agent_card_profile_top_level_url_forbidden"

    async def test_non_http_target_origin_refused(
        self,
        verifier: A2AAgentCardVerifier,
    ) -> None:
        """Defensive: a target_origin that isn't http/https is
        refused without firing a network call. Defends against
        a degenerate empty / file:// origin slipping through."""
        with pytest.raises(A2AAgentCardError) as exc:
            await verifier.fetch_and_verify_outbound_card(
                target_origin="file:///etc/passwd",
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "agent_card_jws_blob_unreadable"


# =============================================================================
# Plan-of-record `test_a2a_agent_card_jws_required.py` contract:
# unsigned cards + non-allow-listed signers refused at the verifier level.
# =============================================================================


class TestJwsRequired:
    """The JWS verification gate IS the registration-refused
    backstop. An unsigned card (empty JWS bytes) fires
    signature_invalid; a card signed by a non-allow-listed kid
    fires signer_not_allowlisted. The plugin-registry-side
    integration that calls validate_card at registration-time
    lives in plugin_registry.py (a separate task); this test
    file pins the verifier-level behaviour the registry depends
    on."""

    async def test_empty_jws_bytes_refused(self, verifier: A2AAgentCardVerifier) -> None:
        result = await verifier.validate_card(
            card_bytes=json.dumps(_valid_card_dict()).encode(),
            jws_bytes=b"",
            tenant_id="bank_a",
            request_id="rid",
        )
        assert result.ok is False
        # Empty JWS bytes are unparseable, so they map to
        # signature_invalid (not blob_unreadable — that's reserved
        # for size-cap exceeded + fetch errors).
        assert result.reason == "agent_card_signature_invalid"

    async def test_non_allowlisted_signer_refused(
        self,
        verifier: A2AAgentCardVerifier,
        rsa_keypair: tuple[str, str],
    ) -> None:
        priv_pem, _ = rsa_keypair
        card_bytes, jws_bytes = _sign_card(_valid_card_dict(), priv_pem, kid="non-allowlisted-kid")
        result = await verifier.validate_card(
            card_bytes=card_bytes,
            jws_bytes=jws_bytes,
            tenant_id="bank_a",
            request_id="rid",
        )
        assert result.ok is False
        assert result.reason == "agent_card_signer_not_allowlisted"


# =============================================================================
# Trust-gate verify_jws_blob — pin the closed-enum split between
# TrustGateError + TrustGateSignerNotAllowlistedError directly.
# (Plan-of-record asks for these arms to be added to test_trust_gate.py;
# T7 R0 implementation places them here so the JWS-related arms live
# co-located with the verifier they back.)
# =============================================================================


class TestTrustGateVerifyJwsBlob:
    async def test_signer_not_allowlisted_subclass_distinct_from_parent(
        self,
        trust_gate: TrustGate,
        rsa_keypair: tuple[str, str],
    ) -> None:
        priv_pem, _ = rsa_keypair
        priv_key = RSAKey.import_key(priv_pem, parameters={"kid": "rogue-kid"})
        payload = b'{"name": "agent"}'
        signed = jws_module.serialize_compact(
            {"alg": "RS256", "kid": "rogue-kid", "b64": False, "crit": ["b64"]},
            payload,
            priv_key,
            algorithms=["RS256"],
        )
        jws_bytes = signed.encode() if isinstance(signed, str) else signed
        with pytest.raises(TrustGateSignerNotAllowlistedError):
            await trust_gate.verify_jws_blob(
                jws_bytes=jws_bytes,
                payload_bytes=payload,
                tenant_id="bank_a",
            )

    async def test_signer_subclass_inherits_parent(self) -> None:
        """The subclass MUST inherit TrustGateError so callers that
        only catch the parent still see signer-allow-list failures
        (defensive Python isinstance behaviour)."""
        assert issubclass(TrustGateSignerNotAllowlistedError, TrustGateError)

    async def test_signature_mismatch_raises_parent_only(
        self,
        trust_gate: TrustGate,
        alt_rsa_keypair: tuple[str, str],
    ) -> None:
        priv_pem, _ = alt_rsa_keypair
        priv_key = RSAKey.import_key(priv_pem, parameters={"kid": "bank-a-key-1"})
        payload = b'{"name": "agent"}'
        signed = jws_module.serialize_compact(
            {"alg": "RS256", "kid": "bank-a-key-1", "b64": False, "crit": ["b64"]},
            payload,
            priv_key,
            algorithms=["RS256"],
        )
        jws_bytes = signed.encode() if isinstance(signed, str) else signed
        with pytest.raises(TrustGateError) as exc:
            await trust_gate.verify_jws_blob(
                jws_bytes=jws_bytes,
                payload_bytes=payload,
                tenant_id="bank_a",
            )
        # NOT the subclass — cryptographic verify failure, not
        # signer-allow-list failure.
        assert not isinstance(exc.value, TrustGateSignerNotAllowlistedError)

    async def test_missing_secret_adapter_raises(self) -> None:
        """A TrustGate built without a secret_adapter cannot verify
        JWS — fails loudly rather than silently allowing."""
        gate = TrustGate(
            settings=build_settings_without_env_file(),
            audit_store=MagicMock(append=AsyncMock()),
        )
        with pytest.raises(TrustGateError) as exc:
            await gate.verify_jws_blob(
                jws_bytes=b"x",
                payload_bytes=b"y",
                tenant_id="bank_a",
            )
        assert "secret_adapter" in str(exc.value)


class TestTrustGateTenantIdValidation:
    """**T7 R1 P2 #2 contract tests:** ``tenant_id`` MUST be
    validated against a strict-segment regex before interpolation
    into the per-tenant Vault path. Without this gate, a tenant id
    like ``bank_a/../bank_b`` could address a different secret
    depending on the SecretAdapter's path-resolution semantics —
    exactly the per-tenant boundary this trust root protects.

    Raw tenant text MUST NOT appear in exception messages — even
    after validation, tenant identifiers reach operator log
    surfaces where they're PII-class data.
    """

    @pytest.mark.parametrize(
        "bad_tenant_id",
        [
            "bank_a/../bank_b",  # path traversal
            "bank_a/etc/passwd",  # path injection
            "bank_a%2F..",  # percent-encoded slash
            "bank_a\nbank_b",  # newline injection
            "bank_a\x00bank_b",  # null byte
            "bank a",  # space
            "bank.a",  # dot (not in allow-list — defensive)
            "BANK_A",  # uppercase (not in allow-list)
            "",  # empty
            "_bank_a",  # leading underscore (regex rejects)
            "x" * 65,  # too long (regex max is 64 chars)
        ],
    )
    async def test_malformed_tenant_id_refused(
        self,
        trust_gate: TrustGate,
        bad_tenant_id: str,
    ) -> None:
        with pytest.raises(TrustGateError) as exc:
            await trust_gate.verify_jws_blob(
                jws_bytes=b"x",
                payload_bytes=b"y",
                tenant_id=bad_tenant_id,
            )
        # Subclass MUST NOT fire — the validator runs BEFORE the
        # signer-allow-list check.
        assert not isinstance(exc.value, TrustGateSignerNotAllowlistedError)
        # Raw tenant text MUST NOT appear in the exception message.
        # Skip empty-string check (every string trivially contains
        # the empty string).
        if bad_tenant_id:
            assert bad_tenant_id not in str(exc.value), (
                f"raw tenant_id {bad_tenant_id!r} leaked into exception text: {exc.value!s}"
            )
        # The exception MUST cite the validator's failure mode so
        # operators distinguish this from the parse / verify errors.
        assert "tenant_id" in str(exc.value) and "validation" in str(exc.value)

    async def test_non_string_tenant_id_refused(
        self,
        trust_gate: TrustGate,
    ) -> None:
        """A non-string tenant_id (None / int / dict) is rejected
        without firing the regex check itself."""
        with pytest.raises(TrustGateError) as exc:
            await trust_gate.verify_jws_blob(
                jws_bytes=b"x",
                payload_bytes=b"y",
                tenant_id=None,  # type: ignore[arg-type]
            )
        assert "tenant_id" in str(exc.value)

    async def test_well_formed_tenant_id_proceeds_past_validator(
        self,
        trust_gate: TrustGate,
        rsa_keypair: tuple[str, str],
        secret_adapter: MagicMock,
    ) -> None:
        """Negative control: a well-formed tenant_id ``bank_a``
        passes the validator. Sign a card with a valid RSA key (so
        JWS parse succeeds) but use a non-allowlisted kid (so the
        Vault read fires + the signer-allow-list check then fails).
        Vault read happening is the proof that the tenant_id
        validator did NOT block the call."""
        priv_pem, _ = rsa_keypair
        priv_key = RSAKey.import_key(priv_pem, parameters={"kid": "rogue-kid"})
        payload = b'{"name": "agent"}'
        signed = jws_module.serialize_compact(
            {"alg": "RS256", "kid": "rogue-kid", "b64": False, "crit": ["b64"]},
            payload,
            priv_key,
            algorithms=["RS256"],
        )
        jws_bytes = signed.encode() if isinstance(signed, str) else signed
        with pytest.raises(TrustGateSignerNotAllowlistedError):
            await trust_gate.verify_jws_blob(
                jws_bytes=jws_bytes,
                payload_bytes=payload,
                tenant_id="bank_a",
            )
        # Vault was consulted — the tenant_id validator passed.
        secret_adapter.read.assert_called_once_with("secret/cognic/bank_a/a2a-jws-trust-root")


class TestOutboundOriginStrictValidation:
    """**T7 R1 P3 contract tests:** ``target_origin`` MUST be a
    bare origin (scheme + netloc only — no path beyond ``/``, no
    query, no fragment, no userinfo). Relaxing this would allow
    attacker-shaped URLs like ``https://host/base?x=y`` that
    silently change which target the well-known suffix
    concatenates onto."""

    @pytest.mark.parametrize(
        "bad_origin,expected_component",
        [
            ("https://host.example.com/base", "path"),
            ("https://host.example.com/base/", "path"),
            ("https://host.example.com?x=y", "query_or_fragment"),
            ("https://host.example.com#frag", "query_or_fragment"),
            ("https://user@host.example.com", "userinfo"),
            ("https://user:pass@host.example.com", "userinfo"),
            ("file:///etc/passwd", "scheme"),
            ("//host.example.com", "scheme"),  # protocol-relative
            ("https://", "netloc"),  # no host
        ],
    )
    async def test_non_origin_target_refused(
        self,
        verifier: A2AAgentCardVerifier,
        bad_origin: str,
        expected_component: str,
    ) -> None:
        with pytest.raises(A2AAgentCardError) as exc:
            await verifier.fetch_and_verify_outbound_card(
                target_origin=bad_origin,
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "agent_card_jws_blob_unreadable"
        # T7 R2 P3: rejected-component classification lands in the
        # payload instead of the raw URL.
        assert exc.value.payload["rejected_component"] == expected_component

    @pytest.mark.parametrize(
        "bad_origin",
        [
            "https://user:supersecret@host.example.com",
            "https://admin:p%40ssw0rd@host.example.com",
            "https://api_key_token@host.example.com",
            "https://host.example.com/base?token=secret123",
        ],
    )
    async def test_credential_material_not_echoed_in_rejection_payload(
        self,
        verifier: A2AAgentCardVerifier,
        bad_origin: str,
    ) -> None:
        """**T7 R2 P3 contract test:** the rejection payload MUST
        NOT echo the raw ``target_origin`` — userinfo /
        password / query-token shapes carry credential material
        that would leak into operator-facing exception payloads
        otherwise. The rejection identifies the component class
        (``userinfo`` / ``query_or_fragment``) without echoing the
        offending bytes."""
        with pytest.raises(A2AAgentCardError) as exc:
            await verifier.fetch_and_verify_outbound_card(
                target_origin=bad_origin,
                tenant_id="bank_a",
                request_id="rid",
            )
        # The raw bad_origin MUST NOT appear in either the message
        # body or the payload (which feeds the audit chain).
        rendered = str(exc.value) + repr(exc.value.payload)
        # Strip the path-suffix-only components from the comparison
        # — `host.example.com` itself is a benign hostname that the
        # validator may legitimately reference. The credential-class
        # bytes are what we want to confirm absent.
        for credential_fragment in (
            "supersecret",
            "p%40ssw0rd",
            "api_key_token",
            "secret123",
        ):
            if credential_fragment in bad_origin:
                assert credential_fragment not in rendered, (
                    f"credential fragment {credential_fragment!r} leaked "
                    f"into rejection rendering: {rendered!r}"
                )

    @respx.mock
    async def test_origin_with_trailing_slash_accepted(
        self,
        verifier: A2AAgentCardVerifier,
        rsa_keypair: tuple[str, str],
    ) -> None:
        """Negative control: a bare origin with a single trailing
        slash (``https://host/``) IS accepted — the most common
        URL form. Per the strict origin contract, path must be
        empty OR exactly ``/``."""
        priv_pem, _ = rsa_keypair
        card_bytes, jws_bytes = _sign_card(_valid_card_dict(), priv_pem)
        respx.get("https://remote.example.com/.well-known/agent-card.json").mock(
            return_value=httpx.Response(200, content=card_bytes)
        )
        respx.get("https://remote.example.com/.well-known/agent-card.json.jws").mock(
            return_value=httpx.Response(200, content=jws_bytes)
        )
        result = await verifier.fetch_and_verify_outbound_card(
            target_origin="https://remote.example.com/",
            tenant_id="bank_a",
            request_id="rid",
        )
        assert result.name == "cognic_test_agent"


# =============================================================================
# Drift detector — pin the 11-value reason enum so a future edit
# that adds/drops a reason must also update the test surface.
# =============================================================================


class TestClosedEnumReasonsExhaustive:
    def test_reason_set_matches_protocol_literal(self) -> None:
        from typing import get_args

        from cognic_agentos.protocol import AgentCardValidationReason

        expected = {
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
        actual = set(get_args(AgentCardValidationReason))
        assert actual == expected, (
            f"AgentCardValidationReason literal drift: "
            f"extra={actual - expected}, missing={expected - actual}"
        )


# Keep AgentCardValidation import alive even if never used in arms
# directly — re-exported for downstream reviewers reading this file
# alongside the module.
_ = AgentCardValidation
