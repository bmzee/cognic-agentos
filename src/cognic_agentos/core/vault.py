"""core/vault.py — dynamic-secret leasing primitive (Sprint 10 T4).

The substantive sandbox-credential-leasing layer per ADR-004 §25/§68/§102,
spec ``docs/superpowers/specs/2026-05-23-sprint-10-vault-credential-leasing-design.md``.

CRITICAL CONTROL — ``core/`` stop-rule (AGENTS.md L48). Every edit halts
before commit. Spec §3.1-§3.4 + §7.1 are the wire-protocol-public surface.

Module surface:

* :class:`VaultLeaseActorRef` — core-owned projection of the portal
  :class:`Actor` (subject + actor_type). Lives here precisely so
  ``core/vault.py`` does NOT import from ``portal/rbac/`` (architectural-
  arrow contract per spec §3.1 R1 P2). The portal-side caller (T7
  ``portal/api/sandbox/`` admission routes) projects ``Actor`` → this
  small two-field shape and threads it through to
  :class:`VaultLeaseRequest`.
* :class:`VaultLeaseRequest` — 5-field frozen dataclass with
  construction-time validation. ``actor_ref`` field (NOT ``actor``)
  pins the architectural-arrow contract.
* :class:`CredentialLease` — 6-field frozen dataclass returned by
  :func:`lease_credential`. ``token`` is ``dict[str, str]`` passthrough
  — kernel does NOT normalise across backends (DB exposes
  ``{username, password}``; AWS STS exposes
  ``{access_key, secret_key, session_token}``; etc.).
* 4-value exception taxonomy: :class:`VaultUnavailable` /
  :class:`VaultPathNotFound` / :class:`VaultAuthDenied` /
  :class:`VaultProtocolError`. Distinct types so the T6
  :class:`VaultCredentialAdapter` at the sandbox boundary can map each
  to the matching ``sandbox_credential_mint_failed_*`` closed-enum
  refusal reason per spec §7.1. :class:`VaultProtocolError` is
  intentionally distinct in ``core/`` — the sandbox boundary at T6
  collapses it to
  ``sandbox_credential_mint_failed_vault_unavailable`` for closed-enum
  stability (the operator surface stays at the documented
  taxonomy; the protocol-error case is a synthesis of "transport
  succeeded but response is malformed" which examiners read as
  "Vault is functionally unavailable" — same external observable).
* :func:`lease_credential` — async entry-point. Calls
  ``transport.lease(secret_path, ttl_s)`` — the read-style dynamic-
  secret lease path per the Z2 Gap Q amendment (Sprint 10 round-9,
  2026-05-24); ``ttl_s`` is informational at Wave 1 (Vault's role-
  side ``default_ttl`` / ``max_ttl`` are authoritative). T4 IS the
  consumer the T3 ``transport.lease`` carve-out was reserved for —
  the Sprint-1C ``VaultAdapter.lease()`` funnels through
  ``transport.read(path)`` to produce a :class:`SecretLease` shape,
  while T4's ``lease_credential`` funnels through
  ``transport.lease(path, ttl_s)`` to produce a :class:`CredentialLease`
  shape. Both transport methods delegate to ``client.read(path)`` at
  the hvac level post-Gap-Q; the distinct method names exist so the
  two consumer-shape contracts can evolve independently (e.g. PKI
  write-style support lands as a separate ``transport`` method —
  NOT a runtime overload of ``lease()``). Maps hvac exceptions →
  4-value taxonomy.
* :func:`revoke_credential` — async tombstone for a minted lease.
  Caller (T10 sandbox ``destroy()``) wraps in fail-soft try/except
  per spec §7.2 — but the underlying exception class still needs to
  be the taxonomy type for diagnostic surface.

Architectural arrow: ``core/vault.py`` MUST NOT import from
``cognic_agentos.portal.*``. The portal-side caller projects
``Actor`` → :class:`VaultLeaseActorRef` at its own boundary. Pinned
by ``tests/unit/core/test_vault.py::TestArchitecturalArrow``.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import re
from typing import Literal

import hvac
import hvac.exceptions

from cognic_agentos.core._vault_transport import VaultTransport
from cognic_agentos.core.config import Settings

# ──────────────────────────────────────────────────────────────────────
# 1. Validation helpers (module-private; tested via the dataclasses' constructors).
# ──────────────────────────────────────────────────────────────────────


_SECRET_PATH_PATTERN = re.compile(r"^[a-z0-9_/\-]+$")
"""Vault path syntax per spec §3.1: lowercase + digits + underscore +
forward-slash + hyphen. Rejects uppercase, whitespace, dots (traversal
segments), URI scheme markers (``://``), and any other shell-metacharacter.
"""

_MAX_SCOPE_LABEL_LEN = 64
"""Operator-facing audit-label cap per spec §3.1 — bounded so the
``decision_history.payload`` column does not explode on a misconfigured
caller passing a multi-MB scope_label."""


def _validate_secret_path(value: str) -> None:
    """Raise ``ValueError`` if ``value`` is not a well-formed Vault path."""
    if not value:
        raise ValueError("secret_path must be non-empty")
    if "://" in value:
        raise ValueError(f"secret_path must be a path (not a URI scheme): {value!r}")
    if ".." in value.split("/"):
        raise ValueError(f"secret_path must not contain '..' traversal segments: {value!r}")
    if not _SECRET_PATH_PATTERN.fullmatch(value):
        raise ValueError(f"secret_path must match {_SECRET_PATH_PATTERN.pattern!r}: {value!r}")


def _validate_ttl_s(value: int) -> None:
    if value <= 0:
        raise ValueError(f"ttl_s must be > 0, got {value!r}")


def _validate_scope_label(value: str) -> None:
    if len(value) > _MAX_SCOPE_LABEL_LEN:
        raise ValueError(f"scope_label must be ≤ {_MAX_SCOPE_LABEL_LEN} chars, got {len(value)}")


# ──────────────────────────────────────────────────────────────────────
# 2. Frozen dataclasses (wire-protocol-public per spec §3.1, §3.2).
# ──────────────────────────────────────────────────────────────────────


@dataclasses.dataclass(frozen=True, slots=True)
class VaultLeaseActorRef:
    """Core-owned projection of the portal :class:`Actor` per spec §3.1.

    Two-field shape carrying ONLY what the kernel-side audit chain
    actually needs to record about the originating actor — keeping
    ``core/`` independent of ``portal/rbac/`` (architectural-arrow
    contract per spec §3.1 R1 P2).
    """

    actor_subject: str
    actor_type: Literal["human", "service"]


@dataclasses.dataclass(frozen=True, slots=True)
class VaultLeaseRequest:
    """5-field admission shape per spec §3.1.

    The ``tenant_id ↔ originating-Actor-tenant_id`` consistency check
    happens at the call site in ``sandbox/admission.py`` (Sprint 10 T7),
    NOT in this constructor — re-introducing that check here would force
    a ``portal/rbac/Actor`` import and violate the architectural-arrow
    contract. The kernel boundary refuses a cross-tenant mismatch with
    the new closed-enum
    ``sandbox_credential_request_tenant_mismatch`` per spec §6.1.
    """

    secret_path: str
    ttl_s: int
    tenant_id: str
    actor_ref: VaultLeaseActorRef
    scope_label: str

    def __post_init__(self) -> None:
        _validate_secret_path(self.secret_path)
        _validate_ttl_s(self.ttl_s)
        _validate_scope_label(self.scope_label)


@dataclasses.dataclass(frozen=True, slots=True)
class CredentialLease:
    """6-field lease record per spec §3.2.

    ``token`` is ``dict[str, str]`` passthrough — the kernel does NOT
    normalise across Vault backends (DB exposes
    ``{username, password}``; AWS STS exposes
    ``{access_key, secret_key, session_token}``; PKI exposes
    ``{certificate, private_key, ca_chain}``; etc.). Plugin packs
    own the per-backend schema knowledge.

    ``ttl_s_granted`` is the value Vault actually returned — may be
    LESS than the requested ``ttl_s`` if the backend role caps at e.g.
    1 hour. Examiners audit the granted TTL, not the requested.
    """

    lease_id: str
    request: VaultLeaseRequest
    token: dict[str, str]
    minted_at: _dt.datetime
    ttl_s_granted: int
    expires_at: _dt.datetime


# ──────────────────────────────────────────────────────────────────────
# 3. Exception taxonomy (4 distinct classes per spec §7.1).
# ──────────────────────────────────────────────────────────────────────


class VaultUnavailable(Exception):
    """Vault returned 5xx, rate-limited after retries exhausted, or the
    network-level transport failed. T6 sandbox boundary maps to
    ``sandbox_credential_mint_failed_vault_unavailable``."""


class VaultPathNotFound(Exception):
    """Vault returned 404 on the secret_path (path / mount / role does
    not exist). T6 sandbox boundary maps to
    ``sandbox_credential_mint_failed_secret_path_unknown``."""


class VaultAuthDenied(Exception):
    """Vault returned 401 (missing creds) or 403 (creds rejected) on
    the secret_path. T6 sandbox boundary maps to
    ``sandbox_credential_mint_failed_auth_denied``."""


class VaultProtocolError(Exception):
    """Transport succeeded but the response is malformed (missing
    ``lease_id``, unexpected 2xx with no body, etc.). Intentionally
    distinct in the ``core/`` taxonomy — T6 sandbox boundary collapses
    to ``sandbox_credential_mint_failed_vault_unavailable`` for
    closed-enum stability per spec §6.1 / §7.1 last row, but the core
    diagnostic surface keeps the distinction so operators can
    correlate the protocol-error pattern in Langfuse / Dynatrace."""


# ──────────────────────────────────────────────────────────────────────
# 4. Public async API (spec §3.3).
# ──────────────────────────────────────────────────────────────────────


async def lease_credential(
    request: VaultLeaseRequest,
    *,
    transport: VaultTransport,
    settings: Settings,
) -> CredentialLease:
    """Mint a dynamic credential lease against Vault.

    Calls ``transport.lease(secret_path, ttl_s)`` — the read-style
    dynamic-secret lease path per the Z2 Gap Q amendment (Sprint 10
    round-9, 2026-05-24). ``ttl_s`` is informational at Wave 1 — Vault's
    role-side ``default_ttl`` / ``max_ttl`` are authoritative, and
    :attr:`CredentialLease.ttl_s_granted` reflects whatever Vault
    returns in the response's ``lease_duration`` field. T4 IS the
    consumer the T3 ``transport.lease`` carve-out was reserved for —
    the Sprint-1C ``VaultAdapter.lease()`` funnels through
    ``transport.read(path)`` to produce a :class:`SecretLease` shape,
    while T4's ``lease_credential`` funnels through
    ``transport.lease(path, ttl_s)`` to produce a :class:`CredentialLease`
    shape. Both transport methods delegate to ``client.read(path)`` at
    the hvac level post-Gap-Q; the distinct method names exist so the
    two consumer-shape contracts can evolve independently (e.g. PKI
    write-style support lands as a separate ``transport`` method —
    NOT a runtime overload of ``lease()`` per spec §3.5).

    Exception mapping (spec §7.1):

    * :class:`hvac.exceptions.VaultDown` /
      :class:`hvac.exceptions.InternalServerError` /
      :class:`hvac.exceptions.RateLimitExceeded` /
      :class:`hvac.exceptions.BadGateway` →
      :class:`VaultUnavailable`
    * network-transport :class:`OSError` family (timeouts / DNS
      failures / connection-refused). Catches both the builtin
      :class:`ConnectionError` (which inherits ``OSError``) AND the
      ``requests.exceptions.Timeout`` / ``requests.exceptions.ConnectionError``
      that bubble up from hvac's underlying HTTP library (both
      inherit ``OSError`` via ``IOError``). → :class:`VaultUnavailable`
    * :class:`hvac.exceptions.InvalidPath` → :class:`VaultPathNotFound`
    * :class:`hvac.exceptions.Forbidden` /
      :class:`hvac.exceptions.Unauthorized` →
      :class:`VaultAuthDenied`
    * response is ``None`` or missing ``lease_id`` →
      :class:`VaultProtocolError`
    * **anything else** (unexpected hvac subclass, unforeseen
      transport-layer exception, etc.) → :class:`VaultProtocolError`
      per spec §7.1 "anything else" row. The closed taxonomy is the
      contract — no exception escapes outside the 4-value set.
      :class:`asyncio.CancelledError` inherits ``BaseException`` (not
      ``Exception``) under modern Python so it correctly passes through
      uncaught when the caller cancels the task.

    ``settings`` is currently unused but reserved for future
    operator-policy hooks (per-call TTL clamps, audit context, etc.)
    per spec §3.3 — keeping it on the signature avoids a wire-protocol
    break when the future hook lands.
    """
    # ``settings`` is reserved for future use; explicitly discard to
    # silence linters without dropping the spec-promised parameter.
    del settings

    try:
        response = await transport.lease(request.secret_path, request.ttl_s)
    except (
        hvac.exceptions.VaultDown,
        hvac.exceptions.InternalServerError,
        hvac.exceptions.RateLimitExceeded,
        hvac.exceptions.BadGateway,
        OSError,
    ) as exc:
        raise VaultUnavailable(f"Vault unavailable for {request.secret_path!r}: {exc}") from exc
    except hvac.exceptions.InvalidPath as exc:
        raise VaultPathNotFound(
            f"Vault secret path not found: {request.secret_path!r}: {exc}"
        ) from exc
    except (hvac.exceptions.Forbidden, hvac.exceptions.Unauthorized) as exc:
        raise VaultAuthDenied(f"Vault auth denied for {request.secret_path!r}: {exc}") from exc
    except Exception as exc:
        # Spec §7.1 "anything else" row — closed-taxonomy guarantee.
        # Catches any future hvac exception class not in the 4-class
        # specific set above, plus any unforeseen transport-layer
        # exception. asyncio.CancelledError inherits BaseException in
        # modern Python so it passes through this guard correctly.
        raise VaultProtocolError(
            f"Vault returned an unexpected error for lease at "
            f"{request.secret_path!r}: {type(exc).__name__}: {exc}"
        ) from exc

    if response is None:
        raise VaultProtocolError(f"Vault returned no body for lease at {request.secret_path!r}")
    lease_id = response.get("lease_id")
    if not lease_id or not isinstance(lease_id, str):
        raise VaultProtocolError(
            f"Vault response missing/invalid lease_id at {request.secret_path!r}: got {lease_id!r}"
        )

    minted_at = _dt.datetime.now(_dt.UTC)
    # ttl_s_granted = what Vault actually returned (NOT the request).
    # Default to the requested ttl_s only if Vault omitted the field
    # (defensive — should not happen in practice for a 2xx with body).
    granted_raw = response.get("lease_duration", request.ttl_s)
    try:
        ttl_s_granted = int(granted_raw)
    except (TypeError, ValueError) as exc:
        raise VaultProtocolError(
            f"Vault returned non-integer lease_duration at {request.secret_path!r}: "
            f"got {granted_raw!r}"
        ) from exc
    expires_at = minted_at + _dt.timedelta(seconds=ttl_s_granted)

    # Token = passthrough of response['data']. dict() copies to detach
    # from any internal hvac structures; we do NOT normalise key set
    # or coerce value types per spec §3.4.
    #
    # USE ``get("data", {})`` (default-on-MISSING) — NOT ``get("data") or {}``
    # (default-on-FALSY) — so falsy non-dict shapes (``[]`` / ``""`` /
    # ``None`` / ``0``) survive to the ``isinstance(dict)`` guard below
    # and route to ``VaultProtocolError``. With the ``or {}`` form
    # those would silently collapse to ``{}`` and the guard would
    # vacuously pass — the exact bug class
    # ``[[feedback_evidence_boundary_runtime_validation]]`` warns about.
    raw_data = response.get("data", {})
    if not isinstance(raw_data, dict):
        raise VaultProtocolError(
            f"Vault response.data is not a dict at {request.secret_path!r}: "
            f"got {type(raw_data).__name__}"
        )
    token: dict[str, str] = dict(raw_data)

    return CredentialLease(
        lease_id=lease_id,
        request=request,
        token=token,
        minted_at=minted_at,
        ttl_s_granted=ttl_s_granted,
        expires_at=expires_at,
    )


async def revoke_credential(
    lease_id: str,
    *,
    transport: VaultTransport,
) -> None:
    """Revoke a Vault lease by ID.

    Caller (T10 sandbox ``destroy()``) wraps this in fail-soft
    try/except per spec §7.2 — but the underlying exception class
    still needs to be the taxonomy type for diagnostic surface (the
    sandbox audit emits ``sandbox.lifecycle.lease_revoke_failed``
    carrying the exception class name).

    Exception mapping mirrors :func:`lease_credential` (spec §7.1) —
    including the ``except Exception`` catch-all that ensures every
    failure surface stays inside the closed 4-value taxonomy.
    :class:`asyncio.CancelledError` inherits ``BaseException`` so it
    correctly passes through uncaught on cooperative cancellation.
    """
    try:
        await transport.revoke(lease_id)
    except (
        hvac.exceptions.VaultDown,
        hvac.exceptions.InternalServerError,
        hvac.exceptions.RateLimitExceeded,
        hvac.exceptions.BadGateway,
        OSError,
    ) as exc:
        raise VaultUnavailable(f"Vault unavailable on revoke of {lease_id!r}: {exc}") from exc
    except hvac.exceptions.InvalidPath as exc:
        raise VaultPathNotFound(f"Vault lease not found on revoke: {lease_id!r}: {exc}") from exc
    except (hvac.exceptions.Forbidden, hvac.exceptions.Unauthorized) as exc:
        raise VaultAuthDenied(f"Vault auth denied on revoke of {lease_id!r}: {exc}") from exc
    except Exception as exc:
        # Spec §7.1 "anything else" row — closed-taxonomy guarantee
        # mirrors lease_credential's catch-all so revoke can never
        # surface an exception class outside the 4-value set.
        raise VaultProtocolError(
            f"Vault returned an unexpected error on revoke of "
            f"{lease_id!r}: {type(exc).__name__}: {exc}"
        ) from exc


__all__ = [
    "CredentialLease",
    "VaultAuthDenied",
    "VaultLeaseActorRef",
    "VaultLeaseRequest",
    "VaultPathNotFound",
    "VaultProtocolError",
    "VaultUnavailable",
    "lease_credential",
    "revoke_credential",
]
