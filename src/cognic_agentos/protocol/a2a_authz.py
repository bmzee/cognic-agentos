"""protocol/a2a_authz.py — A2A per-tenant pinned-token authorization.

Critical-controls module per AGENTS.md (Sprint-6 amendment, "Protocol
— A2A endpoint" section). Per Sprint-5 R3 P1 doctrine, this module
is **admission-side**: it imports + constructs cleanly without the
``a2a-sdk`` SDK installed. Token validation uses Vault + sha256 +
plain-string comparisons — no SDK wire-format types are touched.
**Does NOT call ``require_a2a()`` at construction.**

Per A2A-CONFORMANCE.md §"Authorization": Wave 1 uses per-tenant
pinned tokens stored at ``secret/cognic/<tenant>/a2a-pinned-token``.
Every inbound A2A call MUST carry ``Authorization: Bearer <token>``;
the bytes are matched against the pinned token, the SHA-256 digest is
checked against the per-tenant revocation list, and (optionally) the
declared audience + required scopes are verified. mTLS lands in
Wave 2; Verifiable Credentials in Wave 3.

The 8-value :class:`A2AAuthzReason` closed-enum literal lives in
:mod:`cognic_agentos.protocol`; this module raises
:class:`A2AAuthzError` carrying one of those values plus a sanitised
payload dict consumed by the audit emission.

**Vault-read exception-mapping discipline** (Sprint-5 T15 R1 P2 #2 +
#3): adapter exceptions MUST be wrapped in :class:`A2AAuthzError`
with reason ``a2a_vault_read_failed``. Raw exception text NEVER
leaks into the wrapped error message; ``type(exc).__name__`` lands
in the payload only. ``asyncio.CancelledError`` propagates unwrapped
— wrapping it would mask cooperative-cancellation semantics.

**Token-free invariant**: :class:`A2APinnedToken.value` (the raw
bearer bytes) NEVER appears in audit / decision-history payloads,
``__repr__``, or log output. Frozen+slotted dataclass disables
``__dict__`` access; custom ``__repr__`` redacts ``value``.

**Per-tenant cache**: TTL keyed on ``tenant_id``, controlled by
``settings.a2a_token_cache_ttl_s`` (default 3600s — parity with
Sprint-5 ``mcp_oauth_token_cache_ttl_s`` per T1 R1 P3). Cached
secrets are dropped when the TTL elapses; the next request triggers
a fresh Vault read.

**Audit + decision-history emission**:

- Accepted calls emit ``audit.a2a_token_validated`` into the audit
  chain. No decision-history row (audit-only — accepts are not
  policy-relevant decisions).
- Refused calls emit BOTH ``audit.a2a_token_rejected`` AND a
  decision-history row labelled ``a2a_token_rejected``. Operators
  can correlate refusals via ``request_id``.
- Token bytes NEVER appear in any payload. The validator carries
  digests + metadata only.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import hmac
import logging
import time
from typing import Any

from cognic_agentos.core.audit import AuditEvent, AuditStore
from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.db.adapters.protocols import SecretAdapter
from cognic_agentos.protocol import A2AAuthzReason

_LOG = logging.getLogger(__name__)

#: ``Authorization`` header scheme prefix. Pinned exact-match per
#: the Wave-1 contract (RFC 6750 says scheme matching is case-
#: insensitive but AgentOS pins the canonical capitalisation to
#: keep the validator deterministic; a future spec amendment can
#: relax this).
_BEARER_PREFIX = "Bearer "


@dataclasses.dataclass(frozen=True, slots=True)
class A2APinnedToken:
    """A per-tenant pinned A2A token, returned by
    :meth:`A2AAuthzClient.validate_inbound_token` on success.

    Frozen + slotted so the bytes can't leak via ``__dict__``
    exposure; custom ``__repr__`` redacts ``value`` so log lines /
    audit serialisations / debugger inspections do not capture the
    raw bearer bytes.
    """

    #: Raw bearer-token bytes. Operators MUST NOT log or audit this.
    value: str

    #: The per-tenant identifier the token is bound to.
    tenant_id: str

    #: Unix epoch seconds when the token was minted (carried for
    #: audit-correlation; not used for validation).
    issued_at: float

    #: Unix epoch seconds when the token expires, or ``None`` for
    #: non-expiring pinned tokens. Wave-1 default is non-expiring;
    #: Wave-2 / mTLS introduces explicit expiry.
    expires_at: float | None

    def __repr__(self) -> str:
        """Defensive ``__repr__`` that never leaks the token value.

        Frozen+slotted dataclass already disables ``__dict__`` access,
        but Python's default repr for slotted dataclasses still
        includes every field — override to redact ``value``.
        """
        return (
            f"A2APinnedToken(value=<redacted>, tenant_id={self.tenant_id!r}, "
            f"issued_at={self.issued_at}, expires_at={self.expires_at})"
        )


class A2AAuthzError(Exception):
    """A2A authorization failure with closed-enum reason + structured
    payload for audit emission.

    Per Sprint-5 T15 R1 P2 #3 doctrine: raw lower-layer exception
    text NEVER appears in the message body; ``type(exc).__name__``
    lands in the payload only (under ``vault_error_class``).
    """

    def __init__(
        self,
        reason: A2AAuthzReason,
        message: str = "",
        **payload: Any,
    ) -> None:
        self.reason: A2AAuthzReason = reason
        self.payload: dict[str, Any] = payload
        super().__init__(f"{reason}: {message}" if message else reason)


@dataclasses.dataclass(frozen=True, slots=True)
class _CacheEntry:
    """Per-tenant Vault-read cache entry. Holds the decoded secret
    payload + the monotonic-clock timestamp the read landed at;
    expiry is computed on lookup against
    ``settings.a2a_token_cache_ttl_s``."""

    secret: dict[str, Any]
    cached_at: float


class A2AAuthzClient:
    """Per-tenant pinned-token validator.

    Constructor-required:

    - ``settings`` — supplies ``a2a_token_cache_ttl_s``.
    - ``vault_client`` — :class:`SecretAdapter` for reading the
      per-tenant pinned-token secret at
      ``secret/cognic/<tenant>/a2a-pinned-token``.
    - ``audit_store`` — every outcome (success + failure) emits a
      chained audit row.
    - ``decision_history_store`` — every refusal emits a chained
      decision-history row (accepts are audit-only).

    Usage::

        token = await client.validate_inbound_token(
            authorization_header=request.headers.get("Authorization"),
            tenant_id="bank_a",
            request_id=correlation_id,
            expected_audience="cognic_agent_alpha",  # optional
            claimed_scopes=("a2a:invoke",),  # optional
        )
    """

    def __init__(
        self,
        *,
        settings: Settings,
        vault_client: SecretAdapter,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        self._settings = settings
        self._vault = vault_client
        self._audit = audit_store
        self._dh = decision_history_store
        # Per-tenant TTL cache. Synchronous dict access is safe
        # because every method is async-single-task per call;
        # concurrent calls for different tenants race on different
        # keys and concurrent calls for the same tenant either race
        # the Vault read (acceptable — both will populate the cache
        # with the same value) or both hit a fresh entry.
        self._cache: dict[str, _CacheEntry] = {}

    async def validate_inbound_token(
        self,
        *,
        authorization_header: str | None,
        tenant_id: str,
        request_id: str,
        expected_audience: str | None = None,
        claimed_scopes: tuple[str, ...] = (),
    ) -> A2APinnedToken:
        """Validate an inbound A2A request's Authorization header
        against the per-tenant pinned token.

        Returns an :class:`A2APinnedToken` on success. Raises
        :class:`A2AAuthzError` on any of the 8 closed-enum failure
        paths; ``asyncio.CancelledError`` propagates unwrapped.

        Every outcome emits an audit row; every refusal emits a
        decision-history row in addition.
        """
        # 1. Anonymous: no header at all.
        if not authorization_header:
            await self._refuse(
                reason="a2a_anonymous_refused",
                message="inbound A2A request missing Authorization header",
                tenant_id=tenant_id,
                request_id=request_id,
            )

        # 2. Bearer scheme check (header present but wrong scheme).
        assert authorization_header is not None  # for mypy after the truthy check
        if not authorization_header.startswith(_BEARER_PREFIX):
            await self._refuse(
                reason="a2a_token_missing",
                message="Authorization header present but no Bearer scheme",
                tenant_id=tenant_id,
                request_id=request_id,
            )

        # 3. Empty / whitespace-only token.
        candidate = authorization_header[len(_BEARER_PREFIX) :].strip()
        if not candidate:
            await self._refuse(
                reason="a2a_token_malformed",
                message="Bearer token is empty / whitespace-only",
                tenant_id=tenant_id,
                request_id=request_id,
            )

        # 4. Vault read (with cache + closed-enum exception mapping).
        secret = await self._read_secret_cached(tenant_id=tenant_id, request_id=request_id)

        # 5. Tenant-mismatch check (defends against cross-tenant
        #    token reuse). Only fires if the secret declares a
        #    ``tenant_id`` field; absence is permitted (Vault path
        #    itself encodes the tenant).
        secret_tenant = secret.get("tenant_id")
        if secret_tenant is not None and secret_tenant != tenant_id:
            await self._refuse(
                reason="a2a_tenant_mismatch",
                message=(
                    f"token's tenant_id ({secret_tenant!r}) does not match "
                    f"request tenant_id ({tenant_id!r})"
                ),
                tenant_id=tenant_id,
                request_id=request_id,
                token_tenant_id=secret_tenant,
            )

        # 6. Revocation check — token's SHA-256 digest on the
        #    per-tenant revocation list. Shape validation has already
        #    confirmed ``revoked_digests`` is ``list[str]`` (or absent)
        #    in :meth:`_validate_secret_shape` — malformed shapes fail
        #    closed before we get here per T5 R1 P2 #2.
        digest = hashlib.sha256(candidate.encode()).hexdigest()
        revoked = secret.get("revoked_digests", [])
        if digest in revoked:
            await self._refuse(
                reason="a2a_token_revoked",
                message="token digest matches revocation list entry",
                tenant_id=tenant_id,
                request_id=request_id,
                token_digest_prefix=digest[:8],
            )

        # 7. Active-token match — bytes must match the per-tenant
        #    pinned token. Constant-time comparison via
        #    :func:`hmac.compare_digest` (T5 R1 P2 #1 reviewer
        #    correction): ``str.__ne__`` short-circuits at the first
        #    differing byte, leaking prefix-match timing on the
        #    bearer token across the network. ``hmac.compare_digest``
        #    is the standard library's constant-time string compare
        #    designed for exactly this auth-boundary case (RFC 6234
        #    timing-attack class). Both sides have been validated as
        #    strings (``candidate`` by the Bearer-prefix parser; the
        #    Vault ``token`` field by :meth:`_validate_secret_shape`).
        active = secret.get("token")
        if not isinstance(active, str) or not hmac.compare_digest(active, candidate):
            await self._refuse(
                reason="a2a_token_malformed",
                message="candidate token does not match the active per-tenant pinned token",
                tenant_id=tenant_id,
                request_id=request_id,
            )

        # 8. Audience check (optional — fires only if the caller
        #    passes ``expected_audience`` AND Vault declares an
        #    ``audience`` for the secret). Shape validation has
        #    confirmed ``audience`` is ``str`` (or absent).
        token_audience = secret.get("audience")
        if (
            expected_audience is not None
            and token_audience is not None
            and token_audience != expected_audience
        ):
            await self._refuse(
                reason="a2a_audience_mismatch",
                message=(
                    f"token audience ({token_audience!r}) does not match "
                    f"expected audience ({expected_audience!r})"
                ),
                tenant_id=tenant_id,
                request_id=request_id,
                expected_audience=expected_audience,
                token_audience=token_audience,
            )

        # 9. Scope check (optional — fires only if Vault declares
        #    ``required_scopes`` and the request claims insufficient
        #    scopes). Shape validation has confirmed ``required_scopes``
        #    is ``list[str]`` (or absent).
        required_scopes = secret.get("required_scopes")
        if required_scopes:
            claimed_set = set(claimed_scopes)
            missing = [s for s in required_scopes if s not in claimed_set]
            if missing:
                await self._refuse(
                    reason="a2a_scope_insufficient",
                    message=(f"required scopes not satisfied; missing: {missing}"),
                    tenant_id=tenant_id,
                    request_id=request_id,
                    missing_scopes=missing,
                    required_scopes=list(required_scopes),
                    claimed_scopes=list(claimed_scopes),
                )

        # Happy path — emit audit + return the pinned token.
        # ``active`` was proven equal to ``candidate`` (a ``str``) by
        # the active-match check above; pass ``candidate`` so mypy
        # can narrow the type without an explicit cast. Shape
        # validation has confirmed ``issued_at`` / ``expires_at`` are
        # numeric-or-None — but ``dict.get(key, default)`` returns the
        # stored value when the key exists, even if that value is
        # ``None``. So a Vault secret with explicit ``"issued_at":
        # null`` would surface ``None`` here. Treat explicit-null as
        # equivalent to omission (T5 R2 P2 reviewer correction —
        # avoids a raw ``TypeError`` from ``float(None)`` escaping
        # the closed-enum / audit path post-shape-validation).
        # ``expires_at = None`` is a legitimate value (non-expiring
        # tokens) — preserve it as-is.
        raw_issued = secret.get("issued_at")
        raw_expires = secret.get("expires_at")
        token = A2APinnedToken(
            value=candidate,
            tenant_id=tenant_id,
            issued_at=float(raw_issued) if raw_issued is not None else 0.0,
            expires_at=float(raw_expires) if raw_expires is not None else None,
        )
        await self._audit.append(
            AuditEvent(
                event_type="audit.a2a_token_validated",
                request_id=request_id,
                tenant_id=tenant_id,
                payload={
                    "outcome": "validated",
                    "token_digest_prefix": digest[:8],
                    "issued_at": token.issued_at,
                    "expires_at": token.expires_at,
                },
            )
        )
        return token

    async def _read_secret_cached(
        self,
        *,
        tenant_id: str,
        request_id: str,
    ) -> dict[str, Any]:
        """Vault read with TTL cache + closed-enum exception mapping
        per Sprint-5 T15 R1 P2 #2 doctrine."""
        ttl = self._settings.a2a_token_cache_ttl_s
        now = time.monotonic()
        entry = self._cache.get(tenant_id)
        if entry is not None and (now - entry.cached_at) < ttl:
            return entry.secret

        path = f"secret/cognic/{tenant_id}/a2a-pinned-token"
        try:
            secret = await self._vault.read(path)
        except asyncio.CancelledError:
            # Cooperative-cancellation propagates unwrapped per
            # Sprint-5 T15 R1 P2 #2 doctrine.
            raise
        except Exception as exc:
            await self._refuse(
                reason="a2a_vault_read_failed",
                message=f"Vault read at {path} failed",
                tenant_id=tenant_id,
                request_id=request_id,
                vault_error_class=type(exc).__name__,
            )
            # Unreachable — _refuse always raises — but keeps mypy happy.
            raise  # pragma: no cover

        if not isinstance(secret, dict):
            await self._refuse(
                reason="a2a_vault_read_failed",
                message=f"Vault secret at {path} is not a mapping",
                tenant_id=tenant_id,
                request_id=request_id,
                vault_payload_type=type(secret).__name__,
            )

        # T5 R1 P2 #2 + R1 P3 reviewer corrections: shape-validate
        # every security-relevant field BEFORE caching. Malformed
        # security fields (non-list ``revoked_digests``, non-list
        # ``required_scopes``, non-numeric ``issued_at``/
        # ``expires_at``, non-string ``token``/``tenant_id``/
        # ``audience``) MUST fail closed — silently dropping
        # ``revoked_digests`` would re-enable a revoked token; a
        # malformed ``required_scopes`` would skip the scope gate;
        # a malformed ``issued_at`` would raise raw ``ValueError``
        # at audit-emission time, escaping the closed-enum/audit path.
        await self._validate_secret_shape(
            secret=secret,
            path=path,
            tenant_id=tenant_id,
            request_id=request_id,
        )

        # Cache the decoded secret. Cache the actual mapping returned
        # by Vault (callers MUST NOT mutate the cached dict — the
        # validator only reads from it). Caching only after shape
        # validation means malformed fields never poison the cache.
        self._cache[tenant_id] = _CacheEntry(secret=secret, cached_at=now)
        return secret

    async def _validate_secret_shape(
        self,
        *,
        secret: dict[str, Any],
        path: str,
        tenant_id: str,
        request_id: str,
    ) -> None:
        """Shape-validate every security-relevant field on a Vault
        secret before it is cached or consumed.

        T5 R1 P2 #2 + R1 P3 reviewer corrections: malformed explicit
        fields fail closed at the secret-shape gate rather than
        silently disabling security checks downstream. Maps every
        violation to ``a2a_vault_read_failed`` with a payload field
        identifying the malformed key + the type seen, so operators
        diagnosing the audit log can find + fix the Vault entry.

        Validation rules:

        - ``token`` (if present): ``str``.
        - ``tenant_id`` (if present): ``str``.
        - ``audience`` (if present): ``str``.
        - ``revoked_digests`` (if present): ``list`` of ``str``.
          Non-list shape (dict / scalar / non-list-of-str) fails
          closed; an empty list is valid.
        - ``required_scopes`` (if present): ``list`` of ``str``.
          Non-list shape fails closed; empty list is valid (skips
          the scope check).
        - ``issued_at`` (if present): ``int`` / ``float`` / ``None``.
          Non-numeric fails closed.
        - ``expires_at`` (if present): ``int`` / ``float`` / ``None``.
          Non-numeric fails closed.

        Always raises via :meth:`_refuse` on any malformed field;
        returns ``None`` (and ``_refuse`` raises terminal-loud) on
        the bad path; returns ``None`` on the clean path so the
        caller falls through to caching + consumption.
        """
        for key in ("token", "tenant_id", "audience"):
            if key in secret and not isinstance(secret[key], str):
                await self._refuse(
                    reason="a2a_vault_read_failed",
                    message=(f"Vault secret at {path} field {key!r} has unexpected type"),
                    tenant_id=tenant_id,
                    request_id=request_id,
                    malformed_field=key,
                    field_type=type(secret[key]).__name__,
                )
        for key in ("revoked_digests", "required_scopes"):
            if key not in secret:
                continue
            value = secret[key]
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                await self._refuse(
                    reason="a2a_vault_read_failed",
                    message=(f"Vault secret at {path} field {key!r} must be list[str]"),
                    tenant_id=tenant_id,
                    request_id=request_id,
                    malformed_field=key,
                    field_type=type(value).__name__,
                )
        for key in ("issued_at", "expires_at"):
            if key not in secret:
                continue
            value = secret[key]
            # ``None`` is permitted (non-expiring tokens / unset
            # issued_at); ``bool`` is rejected because bool is a
            # subclass of int and we want explicit numeric values.
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                await self._refuse(
                    reason="a2a_vault_read_failed",
                    message=(
                        f"Vault secret at {path} field {key!r} must be numeric (int / float / null)"
                    ),
                    tenant_id=tenant_id,
                    request_id=request_id,
                    malformed_field=key,
                    field_type=type(value).__name__,
                )

    async def _refuse(
        self,
        *,
        reason: A2AAuthzReason,
        message: str,
        tenant_id: str,
        request_id: str,
        **payload: Any,
    ) -> None:
        """Emit audit + decision-history rows for the refusal, then
        raise :class:`A2AAuthzError`. Token bytes NEVER appear in
        the emitted payloads.

        Always raises (return type narrows to ``NoReturn`` from the
        caller's perspective).
        """
        full_payload: dict[str, Any] = {
            "reason": reason,
            "outcome": "rejected",
            **payload,
        }
        await self._audit.append(
            AuditEvent(
                event_type="audit.a2a_token_rejected",
                request_id=request_id,
                tenant_id=tenant_id,
                payload=dict(full_payload),
            )
        )
        await self._dh.append(
            DecisionRecord(
                decision_type="a2a_token_rejected",
                request_id=request_id,
                tenant_id=tenant_id,
                payload=dict(full_payload),
            )
        )
        raise A2AAuthzError(
            reason,
            message,
            tenant_id=tenant_id,
            request_id=request_id,
            **payload,
        )


__all__ = ("A2AAuthzClient", "A2AAuthzError", "A2APinnedToken")
