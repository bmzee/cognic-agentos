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
* 5-value exception taxonomy: :class:`VaultUnavailable` /
  :class:`VaultPathNotFound` / :class:`VaultAuthDenied` /
  :class:`VaultProtocolError` / :class:`VaultLeaseGrantExceedsRequest`
  (Sprint 10.1 amendment — post-mint granted-vs-requested TTL
  enforcement; raises with best-effort ``transport.revoke`` before
  the raise so an over-cap lease does not leak into Vault's role
  default_ttl window; carries ``lease_id`` + ``revoke_outcome ∈
  {"revoked", "revoke_failed"}`` attributes). Distinct types so the T6
  :class:`VaultCredentialAdapter` at the sandbox boundary can map each
  to the matching ``sandbox_credential_*`` closed-enum refusal reason
  per spec §7.1. :class:`VaultProtocolError` is intentionally distinct
  in ``core/`` — the sandbox boundary at T6 collapses it to
  ``sandbox_credential_mint_failed_vault_unavailable`` for closed-enum
  stability (the operator surface stays at the documented
  taxonomy; the protocol-error case is a synthesis of "transport
  succeeded but response is malformed" which examiners read as
  "Vault is functionally unavailable" — same external observable).
* :func:`lease_credential` — async entry-point. Calls
  ``transport.lease(secret_path, ttl_s)`` — the read-style dynamic-
  secret lease path per the Z2 Gap Q amendment (Sprint 10 round-9,
  2026-05-24); ``ttl_s`` is NOT passed to Vault on the wire (the
  dominant dynamic-secret endpoints are GET-only), but Sprint 10.1
  upgrades the kernel-side semantic per ADR-004 §25 amendment:
  ``lease_credential`` now enforces ``ttl_s_granted <= request.ttl_s``
  post-mint via the new :class:`VaultLeaseGrantExceedsRequest` exception
  (with best-effort ``transport.revoke(lease_id)`` before raise) so
  Vault's role-side ``default_ttl`` / ``max_ttl`` cannot silently
  exceed AgentOS' cap. T4 IS the
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
  5-value taxonomy (Sprint 10.1 amendment) + enforces
  ``ttl_s_granted <= request.ttl_s`` post-mint with best-effort
  revoke before raise.
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


class VaultLeaseGrantExceedsRequest(Exception):
    """Sprint 10.1 — Vault returned a ``lease_duration`` greater than the
    requested ``ttl_s``. This indicates a Vault role configuration whose
    ``default_ttl`` / ``max_ttl`` exceeds AgentOS' cap; the per-tenant
    cap declared at the Rego rule-6 level (``sandbox.rego`` rule 6 +
    spec §6.1) gates the REQUESTED TTL but cannot gate the GRANTED TTL
    because the cap is evaluated before the Vault round-trip.

    Carries ``lease_id`` (the Vault-issued lease id the kernel attempted
    to revoke before raising) + ``revoke_outcome`` (``"revoked"`` if
    cleanup succeeded; ``"revoke_failed"`` if the best-effort
    ``transport.revoke(lease_id)`` raised — in which case the revoke
    exception is chained via ``__cause__``). Operators reading
    ``revoke_outcome="revoke_failed"`` MUST investigate the dangling
    Vault lease (it will only expire at the Vault role's
    ``default_ttl`` / ``max_ttl``).

    The formatted exception message ALSO includes the ``lease_id`` token
    (not only the attribute) because the sandbox backend raises
    ``SandboxLifecycleRefused(reason, detail=str(exc))`` — only the
    message text reaches the chain payload (per Finding 3 of the
    2026-05-24 plan-review round 2).

    Mapped at the sandbox boundary (via
    ``sandbox/backends/_shared_credentials.py``) to the wire-public
    ``SandboxRefusalReason("sandbox_credential_lease_ttl_grant_exceeds_request")``
    closed-enum value. Mirrors the
    ``[[feedback_recompute_derived_facts_not_just_wrapper]]`` doctrine:
    Rego cap fires pre-mint against the request; this exception fires
    post-mint against the actual grant; both layers together prevent
    over-cap leases regardless of where the misconfiguration lives.

    The 5th member of the closed ``core/vault`` exception taxonomy per
    Sprint-10.1 amendment of ADR-004 §25.
    """

    def __init__(
        self,
        message: str,
        *,
        lease_id: str,
        revoke_outcome: Literal["revoked", "revoke_failed"],
    ) -> None:
        super().__init__(message)
        self.lease_id = lease_id
        self.revoke_outcome = revoke_outcome


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
    round-9, 2026-05-24). ``ttl_s`` is NOT passed to Vault on the wire
    — Vault's role-side ``default_ttl`` / ``max_ttl`` are authoritative
    for what the wire returns, and :attr:`CredentialLease.ttl_s_granted`
    reflects whatever Vault hands back in the response's ``lease_duration``
    field. Sprint 10.1 amendment to ADR-004 §25: this function now
    refuses with :class:`VaultLeaseGrantExceedsRequest` (after a
    best-effort ``transport.revoke(lease_id)``) when
    ``ttl_s_granted > request.ttl_s``, complementing the Rego rule-6
    pre-mint cap with a post-mint kernel-side gate. T4 IS the
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
      contract — no exception escapes outside the 5-value set
      (Sprint 10.1 amendment).
      :class:`asyncio.CancelledError` inherits ``BaseException`` (not
      ``Exception``) under modern Python so it correctly passes through
      uncaught when the caller cancels the task.
    * ``response['lease_duration'] > request.ttl_s`` →
      :class:`VaultLeaseGrantExceedsRequest` (Sprint 10.1 — finding #2
      from post-merge review of PR #38; granted-vs-requested TTL
      enforcement post-mint, complementing the Rego rule-6 pre-mint
      cap per ADR-004 §25 amendment). Best-effort
      ``transport.revoke(lease_id)`` runs BEFORE the raise so an
      over-cap lease does not leak into Vault's role
      ``default_ttl`` / ``max_ttl`` window; revoke failure does NOT
      mask the TTL refusal — the exception still raises, with
      ``revoke_outcome="revoke_failed"`` + the revoke exception
      chained via ``__cause__``. The formatted message string also
      includes the ``lease_id`` token (not only the attribute) so the
      sandbox backend's ``SandboxLifecycleRefused(detail=str(exc))``
      carries the dangling-lease correlator through to the chain
      payload (Finding 3 of the 2026-05-24 plan-review round 2).

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

    # Sprint 10.1 — granted-vs-requested TTL enforcement per ADR-004 §25
    # amendment. The Rego rule-6 cap gates the REQUESTED ttl pre-mint;
    # this gate fires post-mint against the ACTUAL grant. Together they
    # prevent over-cap leases regardless of whether the misconfiguration
    # lives in the caller (requested too high; caught by Rego) or in
    # Vault (role default_ttl/max_ttl exceeds the cap; caught here).
    # Per [[feedback_recompute_derived_facts_not_just_wrapper]] — do not
    # trust the wrapper's verdict for the claim; recompute against the
    # source data.
    if ttl_s_granted > request.ttl_s:
        # Best-effort revoke per Finding A of the 2026-05-24 plan-review
        # round 1: AgentOS minted the credential via Vault; refusing it
        # without revoking would leak the dynamic credential into
        # Vault's role default_ttl/max_ttl window. Revoke failure does
        # NOT mask the TTL refusal — the exception still raises;
        # revoke_outcome attribute distinguishes the two cases for the
        # audit trail.
        revoke_outcome: Literal["revoked", "revoke_failed"] = "revoked"
        revoke_cause: Exception | None = None
        try:
            await transport.revoke(lease_id)
        except Exception as revoke_exc:
            # Catch broadly — we are already in the refusal path and
            # MUST raise the TTL exception regardless of revoke outcome.
            # asyncio.CancelledError still passes through (inherits
            # BaseException, not Exception).
            revoke_outcome = "revoke_failed"
            revoke_cause = revoke_exc
        # Note (Sprint 10.1 plan-review round 2, Finding 3): lease_id
        # is in the FORMATTED MESSAGE STRING (not only on the attribute)
        # because the sandbox backends raise
        # ``SandboxLifecycleRefused(reason, detail=str(exc))`` — only the
        # message text reaches the chain payload. Without lease_id in
        # the string, operators reading a ``revoke_outcome="revoke_failed"``
        # refusal cannot correlate it to the dangling Vault lease.
        message = (
            f"Vault granted ttl_s_granted={ttl_s_granted} for "
            f"{request.secret_path!r} but the request asked for "
            f"ttl_s={request.ttl_s}. Vault role default_ttl/max_ttl "
            f"likely exceeds the AgentOS cap; tighten the Vault role "
            f"configuration to match the per-tenant max_credential_ttl_s "
            f"setting (see spec §6.1). lease_id={lease_id!r}; "
            f"cleanup revoke_outcome={revoke_outcome}."
        )
        refusal = VaultLeaseGrantExceedsRequest(
            message,
            lease_id=lease_id,
            revoke_outcome=revoke_outcome,
        )
        if revoke_cause is not None:
            raise refusal from revoke_cause
        raise refusal

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

    Revoke-side exception mapping mirrors the hvac/transport-error
    subset of :func:`lease_credential` (spec §7.1); because revoke has
    no granted-vs-requested TTL concept, it maps failures into the
    original 4 hvac/transport taxonomy classes
    (``VaultUnavailable`` / ``VaultPathNotFound`` / ``VaultAuthDenied`` /
    ``VaultProtocolError``) — the 5th class
    :class:`VaultLeaseGrantExceedsRequest` (Sprint 10.1 amendment per
    ADR-004 §25) is raised only by ``lease_credential``'s post-mint
    enforcement check and has no corresponding code path on the
    revoke surface. The ``except Exception`` catch-all ensures every
    revoke-side failure surface stays inside the closed taxonomy.
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
        # Spec §7.1 "anything else" row — closed-taxonomy guarantee for
        # revoke-side hvac/transport errors; mirrors lease_credential's
        # catch-all on the hvac/transport-error subset so revoke can
        # never surface an exception class outside the closed
        # core/vault taxonomy.
        raise VaultProtocolError(
            f"Vault returned an unexpected error on revoke of "
            f"{lease_id!r}: {type(exc).__name__}: {exc}"
        ) from exc


__all__ = [
    "CredentialLease",
    "VaultAuthDenied",
    "VaultLeaseActorRef",
    "VaultLeaseGrantExceedsRequest",  # NEW per Sprint 10.1 amendment
    "VaultLeaseRequest",
    "VaultPathNotFound",
    "VaultProtocolError",
    "VaultUnavailable",
    "lease_credential",
    "revoke_credential",
]
