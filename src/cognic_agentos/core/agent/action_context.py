"""Kernel-signed action-context token for approved write replay (CC).

The wire mirrors :mod:`query_context`: an attached compact RS256 JWS over
canonical bytes, an exact claims set, and deterministic refusal precedence
``signature -> claims -> expiry -> audience``. The token binds the approved
argument digest and approval request to one actor, agent, tenant and tool.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, Literal

from cognic_agentos.core.canonical import canonical_bytes

_ISSUER: Final[str] = "cognic-agentos"
ACTION_CONTEXT_ARGUMENT: Final[str] = "_cognic_action_context"

ActionContextRefusalReason = Literal[
    "action_context_signature_invalid",
    "action_context_expired",
    "action_context_audience_mismatch",
    "action_context_claims_malformed",
]


@dataclass(frozen=True, slots=True)
class ActionContextClaims:
    """The exact twelve action-context claims in wire-documentation order."""

    iss: str
    aud: str
    sub: str
    act: str
    tenant_id: str
    action_id: str
    args_sha256: str
    approval_request_id: str
    idempotency_key: str
    jti: str
    iat: int
    exp: int


class ActionContextRefusal(RuntimeError):
    """An action-context token failed a closed-enum verification gate."""

    def __init__(self, *, reason: ActionContextRefusalReason, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason: ActionContextRefusalReason = reason


_STR_FIELDS: Final[tuple[str, ...]] = (
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
)
_INT_FIELDS: Final[tuple[str, ...]] = ("iat", "exp")
_CLAIM_KEYS: Final[frozenset[str]] = frozenset((*_STR_FIELDS, *_INT_FIELDS))


def derive_idempotency_key(*, approval_request_id: str, args_sha256: str) -> str:
    """Return ``sha256(request-id UTF-8 || raw args digest)``.

    The framing deliberately has no separator. ``bytes.fromhex`` is the
    fail-loud shape gate for the 32-byte argument digest.
    """

    digest = bytes.fromhex(args_sha256)
    if len(digest) != 32:
        raise ValueError("args_sha256 must encode exactly 32 bytes")
    return hashlib.sha256(approval_request_id.encode("utf-8") + digest).hexdigest()


def mint_action_context(*, claims: ActionContextClaims, signing_key_pem: bytes) -> str:
    """Mint the attached RS256 compact JWS over canonical claim bytes."""

    try:
        from joserfc import jws
        from joserfc.jwk import RSAKey
    except ImportError as exc:  # pragma: no cover - environment contract
        raise RuntimeError(
            "joserfc is required for action-context minting; install the 'adapters' extra"
        ) from exc
    return jws.serialize_compact(
        {"alg": "RS256"},
        canonical_bytes(
            {
                "iss": claims.iss,
                "aud": claims.aud,
                "sub": claims.sub,
                "act": claims.act,
                "tenant_id": claims.tenant_id,
                "action_id": claims.action_id,
                "args_sha256": claims.args_sha256,
                "approval_request_id": claims.approval_request_id,
                "idempotency_key": claims.idempotency_key,
                "jti": claims.jti,
                "iat": claims.iat,
                "exp": claims.exp,
            }
        ),
        RSAKey.import_key(signing_key_pem),
    )


def verify_action_context(
    *,
    token: str,
    public_keys_pem: Sequence[bytes],
    expected_aud: str,
    now: int,
) -> ActionContextClaims:
    """Verify and project claims with deterministic refusal precedence."""

    try:
        from joserfc import jws
        from joserfc.errors import JoseError
        from joserfc.jwk import RSAKey
    except ImportError as exc:  # pragma: no cover - environment contract
        raise RuntimeError(
            "joserfc is required for action-context verification; install the 'adapters' extra"
        ) from exc

    payload: bytes | None = None
    for pem in public_keys_pem:
        try:
            verified = jws.deserialize_compact(
                token,
                RSAKey.import_key(pem),
                algorithms=["RS256"],
            )
        except (JoseError, ValueError, TypeError):
            continue
        payload = verified.payload
        break
    if payload is None:
        raise ActionContextRefusal(
            reason="action_context_signature_invalid",
            detail=f"token did not verify under {len(public_keys_pem)} configured key(s)",
        )

    claims = _parse_claims(payload)
    if now >= claims.exp:
        raise ActionContextRefusal(
            reason="action_context_expired",
            detail=f"now={now} >= exp={claims.exp}",
        )
    if claims.aud != expected_aud:
        raise ActionContextRefusal(
            reason="action_context_audience_mismatch",
            detail=f"aud={claims.aud!r} != expected_aud={expected_aud!r}",
        )
    return claims


def _malformed(detail: str) -> ActionContextRefusal:
    return ActionContextRefusal(reason="action_context_claims_malformed", detail=detail)


def _parse_claims(payload: bytes) -> ActionContextClaims:
    try:
        parsed = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise _malformed("payload is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise _malformed("payload JSON root is not an object")
    if set(parsed) != _CLAIM_KEYS:
        raise _malformed("claims key-set mismatch")
    for field in _STR_FIELDS:
        if not isinstance(parsed[field], str):
            raise _malformed(f"claim {field!r} must be str")
    for field in _INT_FIELDS:
        value = parsed[field]
        if isinstance(value, bool) or not isinstance(value, int):
            raise _malformed(f"claim {field!r} must be int")
    if parsed["iss"] != _ISSUER:
        raise _malformed(f"claim 'iss' must equal {_ISSUER!r}")
    return ActionContextClaims(**parsed)


__all__ = (
    "ACTION_CONTEXT_ARGUMENT",
    "ActionContextClaims",
    "ActionContextRefusal",
    "ActionContextRefusalReason",
    "derive_idempotency_key",
    "mint_action_context",
    "verify_action_context",
)
