"""M8.5-D D2-C action-context token wire contract."""

from __future__ import annotations

import dataclasses
import hashlib
import typing
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cognic_agentos.core.agent.action_context import (
    _ISSUER,
    ActionContextClaims,
    ActionContextRefusal,
    ActionContextRefusalReason,
    derive_idempotency_key,
    mint_action_context,
    verify_action_context,
)
from cognic_agentos.core.canonical import canonical_bytes

_NOW = 1_760_000_000
_EXP = _NOW + 120
_AUD = "cognic-tool-leave/apply_leave"
_REQUEST_ID = "a1b2c3d4-1111-4222-8333-444455556666"
_ARGS_SHA256 = "0123456789abcdef" * 4


def _generate_keypair() -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return (
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


@pytest.fixture(scope="module")
def keypair() -> tuple[bytes, bytes]:
    return _generate_keypair()


def _claims(**overrides: Any) -> ActionContextClaims:
    base: dict[str, Any] = {
        "iss": _ISSUER,
        "aud": _AUD,
        "sub": "analyst.amir",
        "act": "bank-agent",
        "tenant_id": "tenant-a",
        "action_id": _AUD,
        "args_sha256": _ARGS_SHA256,
        "approval_request_id": _REQUEST_ID,
        "idempotency_key": derive_idempotency_key(
            approval_request_id=_REQUEST_ID,
            args_sha256=_ARGS_SHA256,
        ),
        "jti": "b0e9c1f2a3d4e5f60718293a4b5c6d7e",
        "iat": _NOW,
        "exp": _EXP,
    }
    base.update(overrides)
    return ActionContextClaims(**base)


def _mint_bytes(payload: bytes, private_pem: bytes) -> str:
    from joserfc import jws
    from joserfc.jwk import RSAKey

    return jws.serialize_compact(
        {"alg": "RS256"},
        payload,
        RSAKey.import_key(private_pem),
    )


def _mint_raw(payload: Any, private_pem: bytes) -> str:
    return _mint_bytes(canonical_bytes(payload), private_pem)


def test_round_trip_preserves_all_twelve_claims(keypair: tuple[bytes, bytes]) -> None:
    private, public = keypair
    claims = _claims()
    token = mint_action_context(claims=claims, signing_key_pem=private)
    assert len(token.split(".")) == 3
    assert (
        verify_action_context(
            token=token,
            public_keys_pem=[public],
            expected_aud=_AUD,
            now=_NOW,
        )
        == claims
    )
    assert set(dataclasses.asdict(claims)) == {
        "iss",
        "aud",
        "sub",
        "act",
        "tenant_id",
        "action_id",
        "args_sha256",
        "approval_request_id",
        "idempotency_key",
        "jti",
        "iat",
        "exp",
    }


def test_idempotency_key_uses_uuid_text_plus_raw_digest_bytes_without_separator() -> None:
    # Known vector: sha256(UTF-8 request UUID || raw 32 digest bytes).
    assert (
        derive_idempotency_key(
            approval_request_id=_REQUEST_ID,
            args_sha256=_ARGS_SHA256,
        )
        == "62a47dda83904947c1e480ebfcc388e31a4115180c872842006c9ec00e1c9d08"
    )
    separated = hashlib.sha256(
        _REQUEST_ID.encode() + b":" + bytes.fromhex(_ARGS_SHA256)
    ).hexdigest()
    assert separated != derive_idempotency_key(
        approval_request_id=_REQUEST_ID,
        args_sha256=_ARGS_SHA256,
    )


def test_idempotency_key_refuses_a_non_sha256_digest() -> None:
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        derive_idempotency_key(
            approval_request_id=_REQUEST_ID,
            args_sha256="00" * 31,
        )


@pytest.mark.parametrize("now", [_EXP, _EXP + 1])
def test_expiry_boundary_refuses(keypair: tuple[bytes, bytes], now: int) -> None:
    private, public = keypair
    token = mint_action_context(claims=_claims(), signing_key_pem=private)
    with pytest.raises(ActionContextRefusal) as exc_info:
        verify_action_context(
            token=token,
            public_keys_pem=[public],
            expected_aud=_AUD,
            now=now,
        )
    assert exc_info.value.reason == "action_context_expired"


@pytest.mark.parametrize("mutation", ["missing", "extra"])
def test_exact_twelve_key_gate_refuses_missing_or_extra(
    keypair: tuple[bytes, bytes], mutation: str
) -> None:
    private, public = keypair
    payload = dataclasses.asdict(_claims())
    if mutation == "missing":
        del payload["action_id"]
    else:
        payload["unexpected"] = "x"
    token = _mint_raw(payload, private)
    with pytest.raises(ActionContextRefusal) as exc_info:
        verify_action_context(
            token=token,
            public_keys_pem=[public],
            expected_aud=_AUD,
            now=_NOW,
        )
    assert exc_info.value.reason == "action_context_claims_malformed"


def test_signature_precedes_claims_and_audience(keypair: tuple[bytes, bytes]) -> None:
    private, _ = keypair
    _, other_public = _generate_keypair()
    token = mint_action_context(
        claims=_claims(aud="wrong", exp=_NOW - 1),
        signing_key_pem=private,
    )
    with pytest.raises(ActionContextRefusal) as exc_info:
        verify_action_context(
            token=token,
            public_keys_pem=[other_public],
            expected_aud=_AUD,
            now=_NOW,
        )
    assert exc_info.value.reason == "action_context_signature_invalid"


def test_audience_mismatch_follows_valid_claims_and_expiry(
    keypair: tuple[bytes, bytes],
) -> None:
    private, public = keypair
    token = mint_action_context(claims=_claims(aud="another/tool"), signing_key_pem=private)
    with pytest.raises(ActionContextRefusal) as exc_info:
        verify_action_context(
            token=token,
            public_keys_pem=[public],
            expected_aud=_AUD,
            now=_NOW,
        )
    assert exc_info.value.reason == "action_context_audience_mismatch"


@pytest.mark.parametrize(
    "payload",
    [
        b"not-json",
        canonical_bytes(["not", "an", "object"]),
    ],
)
def test_verified_payload_must_be_a_json_object(
    keypair: tuple[bytes, bytes], payload: bytes
) -> None:
    private, public = keypair
    token = _mint_bytes(payload, private)
    with pytest.raises(ActionContextRefusal) as exc_info:
        verify_action_context(
            token=token,
            public_keys_pem=[public],
            expected_aud=_AUD,
            now=_NOW,
        )
    assert exc_info.value.reason == "action_context_claims_malformed"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("sub", 7),
        ("exp", True),
        ("iss", "another-issuer"),
    ],
)
def test_verified_claim_types_and_issuer_are_strict(
    keypair: tuple[bytes, bytes], field: str, value: Any
) -> None:
    private, public = keypair
    payload = dataclasses.asdict(_claims())
    payload[field] = value
    token = _mint_raw(payload, private)
    with pytest.raises(ActionContextRefusal) as exc_info:
        verify_action_context(
            token=token,
            public_keys_pem=[public],
            expected_aud=_AUD,
            now=_NOW,
        )
    assert exc_info.value.reason == "action_context_claims_malformed"


def test_refusal_vocabulary_and_rs256_pin_are_closed() -> None:
    assert set(typing.get_args(ActionContextRefusalReason)) == {
        "action_context_signature_invalid",
        "action_context_expired",
        "action_context_audience_mismatch",
        "action_context_claims_malformed",
    }
    source = __import__("inspect").getsource(verify_action_context)
    assert 'algorithms=["RS256"]' in source
