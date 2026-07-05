"""M8 Task A6 — kernel-signed query-context token mint/verify (CRITICAL
CONTROLS).

Critical-controls module (``core/`` stop-rule per AGENTS.md L48).
Every edit is halt-before-commit per [[feedback_strict_review_off_gate]].

Per ADR-027 §c: the kernel mints a short-TTL RS256-signed query-context
token binding one agent dispatch to its resolved data scope
(``tenant_id`` / ``scope_id`` / ``objects`` / ``proxy_db_identity``) and
its exact arguments (``args_sha256`` over ``canonical_bytes(args)``).
The token IS the tool-side authority: the oracle tool pack refuses any
SQL call whose token does not verify, is expired, is for another
audience, or names objects outside the claims.

Wire form: the FULL 3-segment ATTACHED compact JWS
(``header.payload.signature``) — NOT ``cli/sign.py``'s AgentCard
detached form (which strips the payload segment). The payload bytes are
``canonical_bytes(<the 12-key claims dict>)`` with ``objects`` as a
LIST (canonical form rejects tuples per ``core/canonical.py``).

Verification precedence is DETERMINISTIC (pinned by the A6 test suite):
**signature → claims_malformed → expired → audience_mismatch**. Nothing
is parsed off an unverified payload; a malformed claims-set refuses
before any time/audience semantics are evaluated.

Ownership boundaries (deliberate, per ADR-027 §c):

* **jti replay/nonce enforcement is TOOL-SIDE** — the pack keeps the
  per-token ``jti`` seen-set (Wave-2: Redis). NOT kernel-side: putting
  the seen-set here would make the kernel's cache adapter mandatory,
  breaking the cache-adapter-optional invariant.
* **``args_sha256`` recompute-vs-actual-args is the CALLER's check**
  (the dispatch caller mints over the real args; the tool recomputes
  over the args it received and compares). ``verify_query_context``
  only shape-checks the claim as a str and rides it through.
* **This kernel verify is the REFERENCE implementation** the oracle
  tool pack mirrors (the cross-repo wire pin): the pack's tests mint
  with THIS ``mint_query_context`` via the kernel dev-dep, so any wire
  drift between kernel mint and pack verify trips in the pack's CI.

joserfc is imported FUNCTION-LOCALLY (the ``harness/runtime.py``
function-local-import posture): the ``adapters`` extra owns the
dependency, and absence fails loud with a RuntimeError naming the
extra — never a silent fallback.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, Literal

from cognic_agentos.core.canonical import canonical_bytes

#: The fixed kernel issuer claim — the only value ``verify_query_context``
#: accepts for ``iss`` (anything else is claims-malformed).
_ISSUER: Final[str] = "cognic-agentos"

#: Closed-enum refusal vocabulary for query-context verification. The
#: 4-value count pin lives in this batch's tests
#: (``tests/unit/core/agent/test_query_context.py``).
QueryContextRefusalReason = Literal[
    "query_context_signature_invalid",
    "query_context_expired",
    "query_context_audience_mismatch",
    "query_context_claims_malformed",
]


@dataclass(frozen=True, slots=True)
class QueryContextClaims:
    """The 12 query-context claims, in wire-documentation order.

    ``objects`` rides the wire as a JSON list (canonical form rejects
    tuples) and is reconstructed to a tuple here; ``iat``/``exp`` are
    integer epoch seconds (bool is NOT an int at the verify boundary).
    """

    iss: str
    aud: str
    sub: str
    act: str
    tenant_id: str
    scope_id: str
    objects: tuple[str, ...]
    proxy_db_identity: str
    args_sha256: str
    jti: str
    iat: int
    exp: int


class QueryContextRefusal(RuntimeError):
    """A query-context token failed verification (fail-closed).

    Carries the closed-enum ``reason``; the message is
    ``f"{reason}: {detail}"`` so log lines stay greppable by reason.
    """

    def __init__(self, *, reason: QueryContextRefusalReason, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason: QueryContextRefusalReason = reason


#: The 9 string-typed claim fields (``iss`` additionally carries the
#: ``== _ISSUER`` equality gate below).
_CLAIM_STR_FIELDS: Final[tuple[str, ...]] = (
    "iss",
    "aud",
    "sub",
    "act",
    "tenant_id",
    "scope_id",
    "proxy_db_identity",
    "args_sha256",
    "jti",
)

#: The 2 integer-typed claim fields (epoch seconds; bool refused).
_CLAIM_INT_FIELDS: Final[tuple[str, ...]] = ("iat", "exp")

#: The EXACT 12-key claims key set — missing OR extra keys are malformed.
_CLAIM_KEYS: Final[frozenset[str]] = frozenset((*_CLAIM_STR_FIELDS, "objects", *_CLAIM_INT_FIELDS))


def mint_query_context(*, claims: QueryContextClaims, signing_key_pem: bytes) -> str:
    """Mint the RS256 ATTACHED compact JWS over the canonical claims.

    Payload = ``canonical_bytes(<the 12-key dict>)`` with ``objects``
    converted tuple→list (canonical form rejects tuples). Returns the
    FULL 3-segment compact string — NOT ``cli/sign.py``'s detached
    AgentCard form.

    Raises:
        RuntimeError: joserfc is not installed (the ``adapters`` extra
            owns it) — fail-loud, never a silent fallback.
    """
    try:
        from joserfc import jws
        from joserfc.jwk import RSAKey
    except ImportError as exc:
        raise RuntimeError(
            "joserfc is required for query-context minting; install the 'adapters' extra"
        ) from exc

    payload = canonical_bytes(
        {
            "iss": claims.iss,
            "aud": claims.aud,
            "sub": claims.sub,
            "act": claims.act,
            "tenant_id": claims.tenant_id,
            "scope_id": claims.scope_id,
            # canonical_bytes rejects tuples (the Sprint-2 list/tuple
            # ambiguity doctrine) — convert explicitly at this call site.
            "objects": list(claims.objects),
            "proxy_db_identity": claims.proxy_db_identity,
            "args_sha256": claims.args_sha256,
            "jti": claims.jti,
            "iat": claims.iat,
            "exp": claims.exp,
        }
    )
    return jws.serialize_compact({"alg": "RS256"}, payload, RSAKey.import_key(signing_key_pem))


def verify_query_context(
    *,
    token: str,
    public_keys_pem: Sequence[bytes],
    expected_aud: str,
    now: int,
) -> QueryContextClaims:
    """Verify a query-context token and reconstruct its claims.

    Deterministic refusal precedence (pinned by the A6 test suite):

      1. **signature** — the token must deserialize + verify under at
         least one key in ``public_keys_pem`` (tried in order — the
         two-key rotation window: operators list [new, old] during a
         rotation), with the accepted algorithm PINNED to ``RS256``
         (``algorithms=["RS256"]`` — an RS384/RS512/other-alg token,
         even one minted with the correct private key, refuses; the
         wire contract admits exactly the alg ``mint_query_context``
         emits). Every key failing (any joserfc/ValueError-class
         exception) OR an empty key list →
         ``query_context_signature_invalid``. Nothing is parsed off an
         unverified payload.
      2. **claims_malformed** — the payload must be a JSON object with
         EXACTLY the 12 documented keys, each type-correct (``objects``
         a list of str; ``iat``/``exp`` ints with bool refused; the
         string fields str) and ``iss == "cognic-agentos"`` →
         ``query_context_claims_malformed`` otherwise.
      3. **expired** — ``now >= exp`` → ``query_context_expired`` (the
         boundary instant itself refuses).
      4. **audience_mismatch** — ``aud != expected_aud`` →
         ``query_context_audience_mismatch``.

    Raises:
        QueryContextRefusal: closed-enum ``reason`` per the precedence
            above.
        RuntimeError: joserfc is not installed (the ``adapters`` extra
            owns it) — fail-loud, never a silent fallback.
    """
    try:
        from joserfc import jws
        from joserfc.errors import JoseError
        from joserfc.jwk import RSAKey
    except ImportError as exc:
        raise RuntimeError(
            "joserfc is required for query-context verification; install the 'adapters' extra"
        ) from exc

    # --- 1. Signature (first — nothing is parsed off an unverified payload).
    payload_bytes: bytes | None = None
    for pem in public_keys_pem:
        try:
            # algorithms pinned to exactly what mint_query_context emits.
            # NOT load-bearing against RS512 TODAY (joserfc 1.6.4's default
            # registry already refuses non-recommended algs — empirically
            # verified) — the pin is VERSION-DRIFT ARMOR: without it the
            # accepted-alg set is joserfc's mutable "recommended" default,
            # and a future joserfc widening that set would silently widen
            # this wire contract. With the pin, the set is ours.
            verified = jws.deserialize_compact(token, RSAKey.import_key(pem), algorithms=["RS256"])
        except (JoseError, ValueError, TypeError):
            # Wrong key / non-RS256 alg / tampered token / malformed compact
            # shape / unimportable PEM — try the next rotation-window key.
            continue
        payload_bytes = verified.payload
        break
    if payload_bytes is None:
        raise QueryContextRefusal(
            reason="query_context_signature_invalid",
            detail=(
                f"token did not verify under any of the {len(public_keys_pem)} "
                "configured public key(s)"
            ),
        )

    # --- 2. Claims shape (exactly 12 keys, type-checked, pinned issuer).
    claims = _parse_claims(payload_bytes)

    # --- 3. Expiry (now >= exp refuses — the boundary instant is dead).
    if now >= claims.exp:
        raise QueryContextRefusal(
            reason="query_context_expired",
            detail=f"now={now} >= exp={claims.exp}",
        )

    # --- 4. Audience.
    if claims.aud != expected_aud:
        raise QueryContextRefusal(
            reason="query_context_audience_mismatch",
            detail=f"aud={claims.aud!r} != expected_aud={expected_aud!r}",
        )

    return claims


def _malformed(detail: str) -> QueryContextRefusal:
    return QueryContextRefusal(reason="query_context_claims_malformed", detail=detail)


def _parse_claims(payload_bytes: bytes) -> QueryContextClaims:
    """Parse + shape-gate the verified payload into QueryContextClaims.

    EXACTLY the 12 documented keys (missing OR extra → malformed);
    every field type-checked (bool is NOT an int for ``iat``/``exp``);
    ``iss`` must equal ``_ISSUER``. Every violation refuses
    ``query_context_claims_malformed`` — the closed-enum boundary never
    leaks a raw ``TypeError``/``KeyError`` to the tool-side caller.
    """
    try:
        parsed = json.loads(payload_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise _malformed(f"payload is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise _malformed(f"payload JSON root is not an object (got {type(parsed).__name__})")

    keys = set(parsed.keys())
    if keys != _CLAIM_KEYS:
        missing = sorted(_CLAIM_KEYS - keys)
        extra = sorted(keys - _CLAIM_KEYS)
        raise _malformed(f"claims key-set mismatch: missing={missing} extra={extra}")

    for field_name in _CLAIM_STR_FIELDS:
        if not isinstance(parsed[field_name], str):
            raise _malformed(
                f"claim {field_name!r} must be str (got {type(parsed[field_name]).__name__})"
            )
    for field_name in _CLAIM_INT_FIELDS:
        value = parsed[field_name]
        # bool is a subclass of int — guard it FIRST so a JSON true/false
        # can never ride through as an epoch timestamp.
        if isinstance(value, bool) or not isinstance(value, int):
            raise _malformed(f"claim {field_name!r} must be int (got {type(value).__name__})")

    objects_raw = parsed["objects"]
    if not isinstance(objects_raw, list) or not all(isinstance(o, str) for o in objects_raw):
        raise _malformed("claim 'objects' must be a list of str")

    if parsed["iss"] != _ISSUER:
        raise _malformed(f"claim 'iss' must equal {_ISSUER!r} (got {parsed['iss']!r})")

    return QueryContextClaims(
        iss=parsed["iss"],
        aud=parsed["aud"],
        sub=parsed["sub"],
        act=parsed["act"],
        tenant_id=parsed["tenant_id"],
        scope_id=parsed["scope_id"],
        objects=tuple(objects_raw),
        proxy_db_identity=parsed["proxy_db_identity"],
        args_sha256=parsed["args_sha256"],
        jti=parsed["jti"],
        iat=parsed["iat"],
        exp=parsed["exp"],
    )


__all__ = (
    "QueryContextClaims",
    "QueryContextRefusal",
    "QueryContextRefusalReason",
    "mint_query_context",
    "verify_query_context",
)
