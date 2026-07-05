"""M8 Task A6 (ADR-027 §c) — kernel-signed query-context token mint/verify.

RSA keys are generated AT TEST TIME via ``cryptography`` (never hardcoded
key/digest fixtures, per the repo's crypto-fixture byte-coupling doctrine
``feedback_test_fixture_byte_coupling_for_crypto_claims``); the sample
``args_sha256`` claim values are computed from real sample-args bytes via
the same ``canonical_bytes`` recipe the dispatch caller uses.

Covers:

* mint→verify round-trip with full dataclass equality (byte-equal claims)
* the ATTACHED 3-segment compact contract (NOT cli/sign.py's detached form)
* the deterministic refusal precedence:
  signature → claims_malformed → expired → audience_mismatch
* the two-key rotation window (either ordering)
* the EXACTLY-12-keys claims shape gate (missing / extra / wrong-typed /
  bool-as-int / wrong-iss all → ``query_context_claims_malformed``)
* args_sha256 is NOT verify's business (the caller's recompute check)
* the 4-value closed-enum refusal vocabulary count pin
* the joserfc-absent fail-loud arm naming the ``adapters`` extra
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import sys
import typing
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cognic_agentos.core.agent.query_context import (
    _ISSUER,
    QueryContextClaims,
    QueryContextRefusal,
    QueryContextRefusalReason,
    mint_query_context,
    verify_query_context,
)
from cognic_agentos.core.canonical import canonical_bytes

#: Fixed deterministic epoch base for iat/exp arithmetic.
_NOW = 1_760_000_000
_TTL_S = 120
_EXP = _NOW + _TTL_S

#: Byte-coupled args digests (never hardcoded hex) — computed from the SAME
#: canonical_bytes recipe the dispatch caller uses for the real claim.
_SAMPLE_ARGS: dict[str, Any] = {"sql": "SELECT COUNT(*) FROM customers"}
_ARGS_SHA256 = hashlib.sha256(canonical_bytes(_SAMPLE_ARGS)).hexdigest()
_OTHER_ARGS_SHA256 = hashlib.sha256(canonical_bytes({"sql": "SELECT 1"})).hexdigest()

_AUD = "cognic-tool-oracle-schema"


def _generate_keypair() -> tuple[bytes, bytes]:
    """Generate an RSA-2048 keypair at test time → (private_pem, public_pem)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


@pytest.fixture(scope="module")
def keypair_a() -> tuple[bytes, bytes]:
    return _generate_keypair()


@pytest.fixture(scope="module")
def keypair_b() -> tuple[bytes, bytes]:
    return _generate_keypair()


def _claims(**overrides: Any) -> QueryContextClaims:
    base: dict[str, Any] = {
        "iss": _ISSUER,
        "aud": _AUD,
        "sub": "bank-analyst",
        "act": "human:analyst@bank",
        "tenant_id": "tenant-a",
        "scope_id": "customer-data",
        "objects": ("CUSTOMERS", "ACCOUNTS"),
        "proxy_db_identity": "AGENT_RO",
        "args_sha256": _ARGS_SHA256,
        "jti": "b0e9c1f2a3d4e5f60718293a4b5c6d7e",
        "iat": _NOW,
        "exp": _EXP,
    }
    base.update(overrides)
    return QueryContextClaims(**base)


def _claims_payload_dict(**overrides: Any) -> dict[str, Any]:
    """The 12-key wire payload dict (``objects`` as a LIST — canonical form
    rejects tuples) for hand-built raw minting in the malformed tests."""
    base: dict[str, Any] = {
        "iss": _ISSUER,
        "aud": _AUD,
        "sub": "bank-analyst",
        "act": "human:analyst@bank",
        "tenant_id": "tenant-a",
        "scope_id": "customer-data",
        "objects": ["CUSTOMERS", "ACCOUNTS"],
        "proxy_db_identity": "AGENT_RO",
        "args_sha256": _ARGS_SHA256,
        "jti": "b0e9c1f2a3d4e5f60718293a4b5c6d7e",
        "iat": _NOW,
        "exp": _EXP,
    }
    base.update(overrides)
    return base


def _mint_raw(payload: Any, private_pem: bytes) -> str:
    """Mint a JWS over a hand-built payload with the SAME canonical_bytes +
    joserfc RS256 attached-compact stack production uses — so the malformed
    tests exercise verify's claims gate, not a divergent test-only wire."""
    from joserfc import jws
    from joserfc.jwk import RSAKey

    body = payload if isinstance(payload, bytes) else canonical_bytes(payload)
    return jws.serialize_compact({"alg": "RS256"}, body, RSAKey.import_key(private_pem))


def _tamper_middle_segment(token: str) -> str:
    """Flip one byte of the (base64url) payload segment and re-encode —
    still a syntactically valid 3-segment compact JWS, but the signature
    no longer matches."""
    header, payload, signature = token.split(".")
    raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    tampered = raw[:-1] + bytes([raw[-1] ^ 0x01])
    reencoded = base64.urlsafe_b64encode(tampered).rstrip(b"=").decode("ascii")
    return f"{header}.{reencoded}.{signature}"


# --- Round-trip --------------------------------------------------------------


class TestMintVerifyRoundTrip:
    def test_round_trip_claims_full_dataclass_equality(
        self, keypair_a: tuple[bytes, bytes]
    ) -> None:
        private_pem, public_pem = keypair_a
        claims = _claims()
        token = mint_query_context(claims=claims, signing_key_pem=private_pem)
        verified = verify_query_context(
            token=token,
            public_keys_pem=[public_pem],
            expected_aud=_AUD,
            now=_NOW,
        )
        assert verified == claims

    def test_minted_token_is_attached_three_segment_compact(
        self, keypair_a: tuple[bytes, bytes]
    ) -> None:
        """The FULL attached compact form — three NON-EMPTY dot-separated
        segments. Pins the deliberate difference from cli/sign.py's
        AgentCard flow, which strips the payload segment to detached
        ``header..signature`` form."""
        private_pem, _ = keypair_a
        token = mint_query_context(claims=_claims(), signing_key_pem=private_pem)
        parts = token.split(".")
        assert len(parts) == 3
        assert all(part for part in parts), "attached form must keep the payload segment"

    def test_round_trip_reconstructs_objects_as_tuple(self, keypair_a: tuple[bytes, bytes]) -> None:
        private_pem, public_pem = keypair_a
        token = mint_query_context(claims=_claims(), signing_key_pem=private_pem)
        verified = verify_query_context(
            token=token, public_keys_pem=[public_pem], expected_aud=_AUD, now=_NOW
        )
        assert isinstance(verified.objects, tuple)
        assert verified.objects == ("CUSTOMERS", "ACCOUNTS")


# --- Expiry ------------------------------------------------------------------


class TestExpiry:
    def test_expired_token_refuses(self, keypair_a: tuple[bytes, bytes]) -> None:
        private_pem, public_pem = keypair_a
        token = mint_query_context(claims=_claims(), signing_key_pem=private_pem)
        with pytest.raises(QueryContextRefusal) as excinfo:
            verify_query_context(
                token=token, public_keys_pem=[public_pem], expected_aud=_AUD, now=_EXP + 10
            )
        assert excinfo.value.reason == "query_context_expired"

    def test_boundary_now_equal_exp_refuses(self, keypair_a: tuple[bytes, bytes]) -> None:
        """``now >= exp`` — the boundary itself refuses (a token is dead
        AT its expiry instant, not one second after)."""
        private_pem, public_pem = keypair_a
        token = mint_query_context(claims=_claims(), signing_key_pem=private_pem)
        with pytest.raises(QueryContextRefusal) as excinfo:
            verify_query_context(
                token=token, public_keys_pem=[public_pem], expected_aud=_AUD, now=_EXP
            )
        assert excinfo.value.reason == "query_context_expired"

    def test_now_just_before_exp_passes(self, keypair_a: tuple[bytes, bytes]) -> None:
        private_pem, public_pem = keypair_a
        claims = _claims()
        token = mint_query_context(claims=claims, signing_key_pem=private_pem)
        verified = verify_query_context(
            token=token, public_keys_pem=[public_pem], expected_aud=_AUD, now=_EXP - 1
        )
        assert verified == claims


# --- Audience ----------------------------------------------------------------


class TestAudience:
    def test_wrong_audience_refuses(self, keypair_a: tuple[bytes, bytes]) -> None:
        private_pem, public_pem = keypair_a
        token = mint_query_context(claims=_claims(), signing_key_pem=private_pem)
        with pytest.raises(QueryContextRefusal) as excinfo:
            verify_query_context(
                token=token,
                public_keys_pem=[public_pem],
                expected_aud="cognic-tool-other",
                now=_NOW,
            )
        assert excinfo.value.reason == "query_context_audience_mismatch"


# --- Signature ---------------------------------------------------------------


class TestSignature:
    def test_tampered_payload_refuses_signature_invalid(
        self, keypair_a: tuple[bytes, bytes]
    ) -> None:
        private_pem, public_pem = keypair_a
        token = mint_query_context(claims=_claims(), signing_key_pem=private_pem)
        tampered = _tamper_middle_segment(token)
        with pytest.raises(QueryContextRefusal) as excinfo:
            verify_query_context(
                token=tampered, public_keys_pem=[public_pem], expected_aud=_AUD, now=_NOW
            )
        assert excinfo.value.reason == "query_context_signature_invalid"

    def test_wrong_key_only_refuses_signature_invalid(
        self, keypair_a: tuple[bytes, bytes], keypair_b: tuple[bytes, bytes]
    ) -> None:
        private_pem_a, _ = keypair_a
        _, public_pem_b = keypair_b
        token = mint_query_context(claims=_claims(), signing_key_pem=private_pem_a)
        with pytest.raises(QueryContextRefusal) as excinfo:
            verify_query_context(
                token=token, public_keys_pem=[public_pem_b], expected_aud=_AUD, now=_NOW
            )
        assert excinfo.value.reason == "query_context_signature_invalid"

    def test_two_key_rotation_window_verifies_under_either_ordering(
        self, keypair_a: tuple[bytes, bytes], keypair_b: tuple[bytes, bytes]
    ) -> None:
        """The rotation contract: a token signed with key A verifies under
        BOTH ``[pem_B, pem_A]`` (new key first — the mid-rotation shape)
        AND ``[pem_A, pem_B]``."""
        private_pem_a, public_pem_a = keypair_a
        _, public_pem_b = keypair_b
        claims = _claims()
        token = mint_query_context(claims=claims, signing_key_pem=private_pem_a)
        for ordering in ([public_pem_b, public_pem_a], [public_pem_a, public_pem_b]):
            verified = verify_query_context(
                token=token, public_keys_pem=ordering, expected_aud=_AUD, now=_NOW
            )
            assert verified == claims

    def test_empty_public_key_list_refuses_signature_invalid(
        self, keypair_a: tuple[bytes, bytes]
    ) -> None:
        private_pem, _ = keypair_a
        token = mint_query_context(claims=_claims(), signing_key_pem=private_pem)
        with pytest.raises(QueryContextRefusal) as excinfo:
            verify_query_context(token=token, public_keys_pem=[], expected_aud=_AUD, now=_NOW)
        assert excinfo.value.reason == "query_context_signature_invalid"

    def test_garbage_token_refuses_signature_invalid(self, keypair_a: tuple[bytes, bytes]) -> None:
        """A non-JWS string is a signature-family refusal (the token never
        reaches the claims gate)."""
        _, public_pem = keypair_a
        with pytest.raises(QueryContextRefusal) as excinfo:
            verify_query_context(
                token="not-a-jws", public_keys_pem=[public_pem], expected_aud=_AUD, now=_NOW
            )
        assert excinfo.value.reason == "query_context_signature_invalid"

    def test_rs512_token_with_correct_key_refuses_signature_invalid(
        self, keypair_a: tuple[bytes, bytes]
    ) -> None:
        """The alg-pin: verify accepts EXACTLY the alg mint emits (RS256).

        An RS512 token minted with the CORRECT private key must still
        refuse — ``algorithms=["RS256"]`` at deserialize closes the
        alg-agility surface on the reference implementation the oracle
        pack mirrors (controller-added hardening, A5-A6 batch)."""
        from joserfc import jws
        from joserfc.jwk import RSAKey

        private_pem, public_pem = keypair_a
        payload = canonical_bytes(_claims_payload_dict())
        # joserfc's default registry refuses to SERIALIZE non-recommended
        # algs too — force-mint the RS512 attack token explicitly.
        rs512_token = jws.serialize_compact(
            {"alg": "RS512"}, payload, RSAKey.import_key(private_pem), algorithms=["RS512"]
        )
        with pytest.raises(QueryContextRefusal) as excinfo:
            verify_query_context(
                token=rs512_token, public_keys_pem=[public_pem], expected_aud=_AUD, now=_NOW
            )
        assert excinfo.value.reason == "query_context_signature_invalid"


# --- Malformed claims ---------------------------------------------------------


def _payload_missing_jti() -> dict[str, Any]:
    payload = _claims_payload_dict()
    del payload["jti"]
    return payload


class TestMalformedClaims:
    """The EXACTLY-12-keys claims gate — every shape violation refuses
    ``query_context_claims_malformed``. Payloads are hand-built and minted
    with the SAME canonical_bytes + joserfc stack production uses."""

    @pytest.mark.parametrize(
        ("label", "payload"),
        [
            ("missing_key_jti", _payload_missing_jti()),
            ("extra_key", _claims_payload_dict(extra="x")),
            ("objects_list_with_int", _claims_payload_dict(objects=[1, "CUSTOMERS"])),
            ("objects_not_a_list", _claims_payload_dict(objects="CUSTOMERS")),
            ("bool_typed_iat", _claims_payload_dict(iat=True)),
            ("str_typed_exp", _claims_payload_dict(exp="2026-07-05T00:00:00+00:00")),
            ("int_typed_tenant_id", _claims_payload_dict(tenant_id=42)),
            ("wrong_iss", _claims_payload_dict(iss="not-cognic-agentos")),
        ],
    )
    def test_malformed_claims_refuse(
        self, keypair_a: tuple[bytes, bytes], label: str, payload: dict[str, Any]
    ) -> None:
        private_pem, public_pem = keypair_a
        token = _mint_raw(payload, private_pem)
        with pytest.raises(QueryContextRefusal) as excinfo:
            verify_query_context(
                token=token, public_keys_pem=[public_pem], expected_aud=_AUD, now=_NOW
            )
        assert excinfo.value.reason == "query_context_claims_malformed", label

    def test_payload_json_root_not_object_refuses_malformed(
        self, keypair_a: tuple[bytes, bytes]
    ) -> None:
        private_pem, public_pem = keypair_a
        token = _mint_raw(["not", "an", "object"], private_pem)
        with pytest.raises(QueryContextRefusal) as excinfo:
            verify_query_context(
                token=token, public_keys_pem=[public_pem], expected_aud=_AUD, now=_NOW
            )
        assert excinfo.value.reason == "query_context_claims_malformed"

    def test_payload_not_valid_json_refuses_malformed(self, keypair_a: tuple[bytes, bytes]) -> None:
        private_pem, public_pem = keypair_a
        token = _mint_raw(b"not json{{", private_pem)
        with pytest.raises(QueryContextRefusal) as excinfo:
            verify_query_context(
                token=token, public_keys_pem=[public_pem], expected_aud=_AUD, now=_NOW
            )
        assert excinfo.value.reason == "query_context_claims_malformed"


# --- Deterministic refusal precedence -----------------------------------------


class TestRefusalPrecedence:
    """The documented order: signature → claims_malformed → expired →
    audience_mismatch."""

    def test_expired_wins_over_audience_mismatch(self, keypair_a: tuple[bytes, bytes]) -> None:
        """An EXPIRED token presented with a WRONG audience refuses
        ``query_context_expired`` — expired is checked before audience."""
        private_pem, public_pem = keypair_a
        token = mint_query_context(claims=_claims(), signing_key_pem=private_pem)
        with pytest.raises(QueryContextRefusal) as excinfo:
            verify_query_context(
                token=token,
                public_keys_pem=[public_pem],
                expected_aud="cognic-tool-other",
                now=_EXP + 10,
            )
        assert excinfo.value.reason == "query_context_expired"

    def test_malformed_wins_over_expired(self, keypair_a: tuple[bytes, bytes]) -> None:
        """A wrong-iss payload whose exp is ALSO in the past refuses
        ``query_context_claims_malformed`` — the claims gate runs before
        the expiry gate."""
        private_pem, public_pem = keypair_a
        payload = _claims_payload_dict(iss="not-cognic-agentos", exp=_NOW - 10)
        token = _mint_raw(payload, private_pem)
        with pytest.raises(QueryContextRefusal) as excinfo:
            verify_query_context(
                token=token, public_keys_pem=[public_pem], expected_aud=_AUD, now=_NOW
            )
        assert excinfo.value.reason == "query_context_claims_malformed"

    def test_signature_wins_over_malformed(
        self, keypair_a: tuple[bytes, bytes], keypair_b: tuple[bytes, bytes]
    ) -> None:
        """A malformed payload signed by an UNKNOWN key refuses
        ``query_context_signature_invalid`` — nothing is parsed off an
        unverified payload."""
        private_pem_a, _ = keypair_a
        _, public_pem_b = keypair_b
        token = _mint_raw(_claims_payload_dict(iss="not-cognic-agentos"), private_pem_a)
        with pytest.raises(QueryContextRefusal) as excinfo:
            verify_query_context(
                token=token, public_keys_pem=[public_pem_b], expected_aud=_AUD, now=_NOW
            )
        assert excinfo.value.reason == "query_context_signature_invalid"


# --- args_sha256 ownership boundary --------------------------------------------


class TestArgsSha256IsCallerOwned:
    def test_arbitrary_args_sha256_passes_verify(self, keypair_a: tuple[bytes, bytes]) -> None:
        """Documented-behavior pin: the recompute-vs-actual-args comparison
        is the CALLER's check (dispatch/tool side) — verify only shape-
        checks the claim as a str and rides it through."""
        private_pem, public_pem = keypair_a
        claims = _claims(args_sha256=_OTHER_ARGS_SHA256)
        token = mint_query_context(claims=claims, signing_key_pem=private_pem)
        verified = verify_query_context(
            token=token, public_keys_pem=[public_pem], expected_aud=_AUD, now=_NOW
        )
        assert verified.args_sha256 == _OTHER_ARGS_SHA256


# --- Closed-enum vocabulary + exception shape -----------------------------------


class TestRefusalVocabulary:
    def test_refusal_reason_literal_has_exactly_four_values(self) -> None:
        assert len(typing.get_args(QueryContextRefusalReason)) == 4

    def test_refusal_reason_literal_exact_set(self) -> None:
        assert set(typing.get_args(QueryContextRefusalReason)) == {
            "query_context_signature_invalid",
            "query_context_expired",
            "query_context_audience_mismatch",
            "query_context_claims_malformed",
        }


class TestQueryContextRefusalShape:
    def test_refusal_sets_reason_and_message(self) -> None:
        exc = QueryContextRefusal(reason="query_context_expired", detail="now=10 >= exp=5")
        assert exc.reason == "query_context_expired"
        assert str(exc) == "query_context_expired: now=10 >= exp=5"

    def test_refusal_is_a_runtime_error(self) -> None:
        assert issubclass(QueryContextRefusal, RuntimeError)


# --- Claims dataclass shape ------------------------------------------------------


class TestQueryContextClaimsDataclass:
    def test_claims_dataclass_is_frozen(self) -> None:
        claims = _claims()
        with pytest.raises(dataclasses.FrozenInstanceError):
            claims.aud = "other"  # type: ignore[misc]

    def test_claims_field_order_is_the_documented_twelve(self) -> None:
        """12 fields, THIS order — the wire payload key set + the
        reference-implementation shape the oracle tool pack mirrors."""
        assert [f.name for f in dataclasses.fields(QueryContextClaims)] == [
            "iss",
            "aud",
            "sub",
            "act",
            "tenant_id",
            "scope_id",
            "objects",
            "proxy_db_identity",
            "args_sha256",
            "jti",
            "iat",
            "exp",
        ]


# --- joserfc-absent fail-loud arm -------------------------------------------------


class TestJoserfcAbsentFailLoud:
    """The harness/runtime.py function-local-import posture: joserfc
    absence fails loud naming the ``adapters`` extra. Pinned by nulling
    the ``sys.modules`` entry so the function-local import raises
    ImportError (monkeypatch restores the real module afterwards)."""

    def test_mint_fails_loud_naming_the_adapters_extra(
        self, keypair_a: tuple[bytes, bytes], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        private_pem, _ = keypair_a
        monkeypatch.setitem(sys.modules, "joserfc", None)
        with pytest.raises(RuntimeError, match="adapters"):
            mint_query_context(claims=_claims(), signing_key_pem=private_pem)

    def test_verify_fails_loud_naming_the_adapters_extra(
        self, keypair_a: tuple[bytes, bytes], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, public_pem = keypair_a
        monkeypatch.setitem(sys.modules, "joserfc", None)
        with pytest.raises(RuntimeError, match="adapters"):
            verify_query_context(
                token="x.y.z", public_keys_pem=[public_pem], expected_aud=_AUD, now=_NOW
            )
