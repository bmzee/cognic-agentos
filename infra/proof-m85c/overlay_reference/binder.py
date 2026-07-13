"""The reference OIDC ``ActorBinder`` (M8.5-C design §4) — the worked example a
bank overlay adapts. Validates a Keycloak-issued OAuth ACCESS token locally and
binds it to a kernel :class:`~cognic_agentos.portal.rbac.actor.Actor`.

The ten ruled requirements, in the order ``bind()`` enforces them:

1.  ``Authorization: Bearer`` extraction — anything else refuses.
2.  Protected-header pre-parse (no crypto yet): ``alg`` MUST be on the explicit
    RS256 allow-list (an ``alg`` swap/none refuses BEFORE any signature work)
    and ``typ`` MUST be ``at+jwt`` — the structural ID-token rejection (an ID
    token's header ``typ`` is ``JWT``; RFC 9068 header type pinned by the
    realm's ``access.token.header.type.rfc9068`` setting).
3.  ``kid`` resolution against the lifecycle-owned JWKS cache. An unknown
    ``kid`` fails the CURRENT request closed and triggers exactly one
    single-flight BACKGROUND refresh for later retries — a bad signature never
    triggers a refresh.
4.  RS256 signature verification (joserfc) against the resolved key.
5.  ``iss`` — exact match with the configured issuer.
6.  ``aud`` — normalized (string-or-array) and required to equal EXACTLY the
    set ``{cognic-agentos}`` (the AgentOS resource audience; over-broad refuses).
7.  ``azp`` — validated against the exact claim contract the pinned Keycloak
    realm emits (``cognic-harness``, the requesting client).
8.  ``exp`` / ``iat`` required + ``nbf`` optional-but-strict, all finite
    numbers (bool/NaN/inf refuse) with bounded clock skew.
9.  Nonempty stable ``sub``; closed-shape tenant claim. The bound
    ``Actor.subject`` is the ISSUER-QUALIFIED ``sub`` — ``<issuer>#<sub>`` —
    because ``Actor.subject`` keys data-scope entitlements and approval
    ORIGINATOR binding: ``sub`` is the only subject claim Keycloak guarantees
    stable and non-reassignable, while ``preferred_username`` is MUTABLE (an
    admin can reassign a username to a different human, who would then inherit
    the old holder's entitlements and replay their approval grants), so
    ``preferred_username`` NEVER determines the subject. Issuer-qualification
    prevents subject collision across IdPs — two realms may both mint
    ``sub=1234``.
10. Closed/allow-listed portal RBAC scope claims — every scope value must be in
    the kernel's own exported scope vocabulary; unknown values refuse.

``actor_type`` is ALWAYS ``"human"``: the pinned realm's grant profile only
mints access tokens through the interactive Authorization Code flow (client
credentials + direct access grants are disabled — Bar B proves the negative
space), so a token accepted under this profile maps to a human. A
caller-supplied actor-type claim NEVER decides it.

I/O model per the ruling: ``bind()`` is synchronous and performs LOCAL
verification only. Discovery + JWKS live in a cache built at startup
(:func:`build_reference_binder`) and refreshed OUTSIDE the request path.
Failures raise :class:`ActorBinderUnauthenticated` (never ``HTTPException``)
so the kernel's existing ``403 actor_unauthenticated`` mapping is preserved.
Every refusal emits exactly ONE stdlib-``logging`` WARNING with the stable,
greppable literal prefix ``reference_binder.refused reason=`` carrying the
bounded reason code only — never a token, never a claim value. The live proof
greps the kernel pod log for that prefix to assert WHICH gate fired.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import json
import logging
import math
import re
import threading
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
from joserfc import jws
from joserfc.errors import JoseError
from joserfc.jwk import KeySet
from starlette.requests import Request

from cognic_agentos.portal.rbac.actor import Actor, ActorBinderUnauthenticated

logger = logging.getLogger(__name__)

#: The ONLY signature algorithm the pinned realm signs access tokens with.
_ALLOWED_ALGS = ("RS256",)
#: RFC 9068 access-token header type (realm setting pins it; NEVER rely on defaults).
_ACCESS_TOKEN_TYP = "at+jwt"
#: Closed shape for the tenant claim value.
_TENANT_SHAPE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


def kernel_scope_allow_list() -> frozenset[str]:
    """The CLOSED portal-RBAC scope vocabulary, built from the kernel's own
    exported ``*_SCOPES`` frozensets — drift-free by construction: a scope the
    kernel does not know cannot enter an Actor through this binder."""
    import cognic_agentos.portal.rbac.scopes as scopes_mod

    allowed: set[str] = set()
    for name in dir(scopes_mod):
        if name.endswith("_SCOPES"):
            value = getattr(scopes_mod, name)
            if isinstance(value, frozenset):
                allowed.update(str(scope) for scope in value)
    if not allowed:  # pragma: no cover - kernel regression guard
        raise RuntimeError("kernel scope vocabulary resolved empty")
    return frozenset(allowed)


@dataclasses.dataclass(frozen=True)
class ReferenceBinderConfig:
    """The pinned identity contract (issuer + the exact claim contract the
    pinned Keycloak realm emits — established from the realm export, not
    assumed from folklore)."""

    issuer: str
    audience: str = "cognic-agentos"
    authorized_party: str = "cognic-harness"
    tenant_claim: str = "tenant_id"
    scopes_claim: str = "cognic_scopes"
    clock_skew_s: float = 30.0
    #: floor between two JWKS refreshes (stampede guard for the single-flight).
    jwks_min_refresh_interval_s: float = 5.0


class _JwksCache:
    """Lifecycle-owned JWKS cache. Built at startup; refreshed OUTSIDE the
    request path via the single-flight trigger. Thread-safe (bind() runs on
    FastAPI's sync-dependency threadpool)."""

    def __init__(self, initial_jwks: dict[str, Any], refresh_fn: Any) -> None:
        self._lock = threading.Lock()
        self._refresh_fn = refresh_fn  # () -> dict (the raw JWKS document)
        self._keys_by_kid: dict[str, Any] = {}
        self._last_refresh_monotonic = 0.0
        self._refresh_thread: threading.Thread | None = None
        self._install(initial_jwks)

    def _install(self, jwks: dict[str, Any]) -> None:
        key_set = KeySet.import_key_set(jwks)  # type: ignore[arg-type]
        by_kid = {key.kid: key for key in key_set.keys if key.kid}
        with self._lock:
            self._keys_by_kid = by_kid
            self._last_refresh_monotonic = time.monotonic()

    def key_for(self, kid: str) -> Any | None:
        with self._lock:
            return self._keys_by_kid.get(kid)

    def trigger_refresh(self, *, min_interval_s: float) -> bool:
        """Single-flight background refresh: at most one in flight, floored to
        ``min_interval_s`` between refreshes. Returns True when a refresh was
        actually scheduled (test observability). NEVER blocks the request."""
        with self._lock:
            if self._refresh_thread is not None and self._refresh_thread.is_alive():
                return False
            if time.monotonic() - self._last_refresh_monotonic < min_interval_s:
                return False
            thread = threading.Thread(target=self._refresh_once, daemon=True)
            self._refresh_thread = thread
        thread.start()
        return True

    def _refresh_once(self) -> None:
        try:
            self._install(self._refresh_fn())
            logger.info("reference_binder.jwks_refreshed")
        except Exception:  # background; fail closed by NOT updating the cache
            logger.warning("reference_binder.jwks_refresh_failed")


class ReferenceOidcBinder:
    """Conforms structurally to the kernel ``ActorBinder`` Protocol."""

    def __init__(self, *, config: ReferenceBinderConfig, jwks_cache: _JwksCache) -> None:
        self._config = config
        self._jwks = jwks_cache
        self._allowed_scopes = kernel_scope_allow_list()

    # -- the sync, local-only per-request path --------------------------------

    def bind(self, *, request: Request) -> Actor:
        token = self._extract_bearer(request)
        header = self._preparse_protected_header(token)
        key = self._resolve_key(header)
        claims = self._verify_and_decode(token, key)
        return self._actor_from_claims(claims)

    # -- steps -----------------------------------------------------------------

    def _refuse(self, reason: str) -> ActorBinderUnauthenticated:
        # Exactly ONE structured WARNING per refusal, VALUE-FREE: the bounded
        # reason code only — never the token, the subject, the username, or any
        # claim value. The literal prefix is STABLE: the live proof greps the
        # kernel pod log for `reference_binder.refused reason=` to assert WHICH
        # gate fired (WARNING so the line survives default logging config;
        # the reason rides the MESSAGE, not `extra=`, so a pod-log grep sees it).
        logger.warning("reference_binder.refused reason=%s", reason)
        return ActorBinderUnauthenticated(reason)

    def _extract_bearer(self, request: Request) -> str:
        header = request.headers.get("Authorization")
        if not header or not header.startswith("Bearer ") or not header[7:]:
            raise self._refuse("bearer_missing")
        return header[7:]

    def _preparse_protected_header(self, token: str) -> dict[str, Any]:
        parts = token.split(".")
        if len(parts) != 3:
            raise self._refuse("token_malformed")
        try:
            padded = parts[0] + "=" * (-len(parts[0]) % 4)
            header_raw = base64.urlsafe_b64decode(padded.encode())
            header = json.loads(header_raw)
        except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
            raise self._refuse("token_malformed") from exc
        if not isinstance(header, dict):
            raise self._refuse("token_malformed")
        # explicit algorithm allow-list BEFORE any signature work.
        if header.get("alg") not in _ALLOWED_ALGS:
            raise self._refuse("alg_not_allowed")
        # structural ID-token rejection: the access token header type is pinned.
        if header.get("typ") != _ACCESS_TOKEN_TYP:
            raise self._refuse("typ_not_at_jwt")
        return header

    def _resolve_key(self, header: dict[str, Any]) -> Any:
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise self._refuse("kid_missing")
        key = self._jwks.key_for(kid)
        if key is None:
            # unknown kid: fail THIS request closed + one single-flight
            # background refresh so a rotated key serves later retries.
            self._jwks.trigger_refresh(min_interval_s=self._config.jwks_min_refresh_interval_s)
            raise self._refuse("kid_unknown")
        return key

    def _verify_and_decode(self, token: str, key: Any) -> dict[str, Any]:
        try:
            verified = jws.deserialize_compact(token, key, algorithms=list(_ALLOWED_ALGS))
        except (JoseError, ValueError) as exc:
            # an ordinary bad signature NEVER triggers a JWKS refresh.
            raise self._refuse("signature_invalid") from exc
        payload = verified.payload
        if payload is None:
            raise self._refuse("token_malformed")
        try:
            claims = json.loads(payload)
        except ValueError as exc:
            raise self._refuse("token_malformed") from exc
        if not isinstance(claims, dict):
            raise self._refuse("token_malformed")
        return claims

    def _actor_from_claims(self, claims: dict[str, Any]) -> Actor:
        config = self._config
        # 5. issuer — exact.
        if claims.get("iss") != config.issuer:
            raise self._refuse("issuer_mismatch")
        # 6. audience — normalized string-or-array; EXACTLY {cognic-agentos}.
        aud = claims.get("aud")
        audiences: list[str]
        if isinstance(aud, str):
            audiences = [aud]
        elif isinstance(aud, list) and all(isinstance(a, str) for a in aud):
            audiences = list(aud)
        else:
            raise self._refuse("audience_malformed")
        if set(audiences) != {config.audience}:
            raise self._refuse("audience_not_exact")
        # 7. authorized party — the pinned realm contract.
        if claims.get("azp") != config.authorized_party:
            raise self._refuse("azp_mismatch")
        # 8. time claims — strict finite numbers with bounded skew.
        now_ts = datetime.now(tz=UTC).timestamp()
        exp = _finite_number(claims.get("exp"))
        if exp is None or now_ts > exp + config.clock_skew_s:
            raise self._refuse("token_expired")
        iat = _finite_number(claims.get("iat"))
        if iat is None or now_ts + config.clock_skew_s < iat:
            raise self._refuse("iat_invalid")
        if "nbf" in claims:
            nbf = _finite_number(claims.get("nbf"))
            if nbf is None or now_ts + config.clock_skew_s < nbf:
                raise self._refuse("nbf_invalid")
        # 9. subject + tenant.
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub:
            raise self._refuse("subject_missing")
        tenant = claims.get(config.tenant_claim)
        if not isinstance(tenant, str) or not _TENANT_SHAPE.fullmatch(tenant):
            raise self._refuse("tenant_claim_invalid")
        # The AUTHORIZATION subject is the ISSUER-QUALIFIED `sub`. `Actor.subject`
        # keys data-scope ENTITLEMENTS and approval ORIGINATOR binding, so it must
        # be stable and non-reassignable: Keycloak's `sub` is the immutable user
        # id, while `preferred_username` is MUTABLE — a reassigned username would
        # hand the new holder the old holder's entitlements and let them replay
        # the old holder's approval grants. `preferred_username` therefore NEVER
        # determines the subject (it stays in the token for human-readable
        # display only). Qualifying with the binder's configured issuer — proven
        # equal to the token's `iss` at step 5 above — prevents subject collision
        # across IdPs: a bank with two realms must not conflate `sub=1234` from
        # each. The kernel seed matrix keys on this exact composed value
        # (realm-subjects.env, rendered into kernel-seed.sql by seed-db.sh).
        subject = f"{config.issuer}#{sub}"
        # 10. closed/allow-listed portal RBAC scope claims.
        raw_scopes = claims.get(config.scopes_claim, [])
        if not isinstance(raw_scopes, list) or not all(
            isinstance(scope, str) for scope in raw_scopes
        ):
            raise self._refuse("scopes_claim_malformed")
        unknown = set(raw_scopes) - self._allowed_scopes
        if unknown:
            raise self._refuse("scope_not_in_vocabulary")
        # actor_type: derived from the LOCKED grant profile — a token accepted
        # under this profile is a human login; caller claims never decide.
        return Actor(
            subject=subject,
            tenant_id=tenant,
            scopes=frozenset(raw_scopes),
            actor_type="human",
        )


def _finite_number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def build_reference_binder(
    *,
    issuer: str,
    verify: str | bool = True,
    audience: str = "cognic-agentos",
    authorized_party: str = "cognic-harness",
    timeout_s: float = 10.0,
) -> ReferenceOidcBinder:
    """Startup-time construction: fetch + validate the discovery document (the
    self-declared ``issuer`` must equal the configured one; the ``jwks_uri``
    must keep the issuer's scheme — no downgrade), fetch the initial JWKS, and
    return the binder with its lifecycle-owned cache. Runs OUTSIDE the request
    path (proof-app factory), synchronously."""
    disc_url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    with httpx.Client(verify=verify, timeout=timeout_s) as client:
        disc = client.get(disc_url)
        disc.raise_for_status()
        doc = disc.json()
        if doc.get("issuer") != issuer:
            raise RuntimeError("reference binder: discovery issuer mismatch")
        jwks_uri = doc.get("jwks_uri")
        issuer_scheme = urlsplit(issuer).scheme
        parts = urlsplit(jwks_uri) if isinstance(jwks_uri, str) else None
        if parts is None or not parts.netloc or parts.scheme != issuer_scheme:
            raise RuntimeError("reference binder: jwks_uri malformed or scheme downgrade")
        jwks_resp = client.get(jwks_uri)
        jwks_resp.raise_for_status()
        initial_jwks = jwks_resp.json()

    def _refresh() -> dict[str, Any]:
        with httpx.Client(verify=verify, timeout=timeout_s) as refresh_client:
            response = refresh_client.get(jwks_uri)
            response.raise_for_status()
            return response.json()  # type: ignore[no-any-return]

    config = ReferenceBinderConfig(
        issuer=issuer, audience=audience, authorized_party=authorized_party
    )
    return ReferenceOidcBinder(config=config, jwks_cache=_JwksCache(initial_jwks, _refresh))
