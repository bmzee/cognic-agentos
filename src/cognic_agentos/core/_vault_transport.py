"""Sprint 10 §2.1 — shared low-level Vault transport.

INTERNAL — not part of any documented public surface. Both
:class:`cognic_agentos.db.adapters.vault_adapter.VaultAdapter` (Sprint
1C; persistent secret fetch) AND
:func:`cognic_agentos.core.vault.lease_credential` (Sprint 10; dynamic
credential leasing — lands at T4) consume this for one Vault transport
discipline:

* ONE shared :class:`hvac.Client` per ``(vault_addr, vault_token,
  vault_namespace)`` triple.
* ONE static-token auth context (Wave-1 only — no
  ``refresh_token()``; AppRole / Kubernetes ServiceAccount / JWT-OIDC
  auth flows are future work per spec §10).
* ONE retry discipline — bounded exponential-backoff on transient
  hvac exceptions (5xx / 429 / vault-down / bad-gateway); 4xx-class
  exceptions (auth / path-not-found / bad-request) do NOT retry +
  raise immediately so caller mapping stays sharp.
* Async-friendly façade via :func:`asyncio.to_thread` (hvac is sync;
  every method wraps the sync call so the FastAPI event loop stays
  cooperative).

The underscore-prefixed module path signals INTERNAL. Banks wire
:class:`cognic_agentos.db.adapters.vault_adapter.VaultAdapter` (Sprint
1C public adapter) or :class:`cognic_agentos.sandbox.credentials.VaultCredentialAdapter`
(Sprint 10 T6 public adapter), NOT :class:`VaultTransport` directly.
The transport is INTERNAL plumbing — it does NOT register as a
``readyz``-visible adapter; only the public adapters do.

**Architectural arrow:** ``core/`` is the kernel layer; ``db/adapters/``
is above ``core/`` and imports FROM ``core/``. The transport therefore
declares its OWN internal probe shape (:class:`VaultTransportProbe`)
and does NOT import :class:`cognic_agentos.db.adapters.protocols.AdapterHealth`
(that would invert the layering). Public adapters convert
:class:`VaultTransportProbe` to their layer's ``AdapterHealth`` at the
adapter boundary.

Per spec §3.5 the public methods are **domain-shaped**
(``read`` / ``write`` / ``lease`` / ``revoke`` / ``health_check``),
matching hvac's surface. The earlier brainstorm flirted with HTTP-shaped
methods (``get`` / ``post`` / ``delete``) — rejected because both
consumers need the same domain operations, and pushing HTTP-shape
semantics to consumers would defeat the "one Vault discipline" goal.

Per AGENTS.md L48, anything under ``core/`` is critical-controls by
the ``core/`` stop-rule.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, TypeVar

import hvac
import hvac.exceptions

_LOG = logging.getLogger(__name__)

T = TypeVar("T")


# ──────────────────────────────────────────────────────────────────────
# Internal result shape — NOT the public adapter health surface.
# ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class VaultTransportProbe:
    """Internal Vault health-probe result.

    Sprint 10 T2 (R2 P1.1 fix) — replaces an earlier draft that
    imported ``AdapterHealth`` from ``db/adapters/protocols.py`` and
    violated the ``core/`` → ``db/adapters/`` architectural arrow.

    Sprint 10 T2 (R3 P1 fix) — mirrors the Sprint-1C ``VaultAdapter``
    health contract pinned at ``tests/unit/db/test_vault_adapter.py::TestHealth``:
    healthy ONLY when ``initialized=True`` AND ``sealed=False``. The
    earlier R2 draft used ``is_initialized()`` and would silently
    classify an initialized-but-sealed Vault as "reachable but not
    healthy" — Sprint-1C reports that case as ``unreachable`` with a
    "vault sealed" detail. T3's refactor depends on the transport
    preserving the same 4-state semantic so ``/readyz`` doesn't
    regress.

    Four meaningful states:

    - ``ok=True, reason=None, error_class=None``
        Vault is reachable + initialized + unsealed.
    - ``ok=False, reason='vault_not_initialized', error_class=None``
        Vault is reachable but ``initialized=False`` (operator hasn't
        run ``vault operator init`` yet). Distinct operational state,
        not an exception.
    - ``ok=False, reason='vault_sealed', error_class=None``
        Vault is reachable + initialized but ``sealed=True`` (operator
        hasn't unsealed yet after restart). Distinct operational
        state. **Defensive default:** if the health-status response
        is missing the ``sealed`` key, the probe treats it as sealed
        (fail-closed; mirrors Sprint-1C's ``status.get("sealed", True)``
        pattern).
    - ``ok=False, reason=None, error_class='<ClassName>'``
        Vault is unreachable OR the probe raised after retry
        exhaustion. ``error_class`` is the exception class name only
        (no message — message text may leak auth tokens or paths).

    Public adapters (Sprint-1C ``VaultAdapter`` at T3,
    ``VaultCredentialAdapter`` at T6) convert this to their layer's
    ``AdapterHealth`` at the adapter boundary, mapping each of the
    three non-OK states to the appropriate ``detail`` text per the
    pinned ``/readyz`` contract.
    """

    ok: bool
    reason: Literal["vault_not_initialized", "vault_sealed"] | None = None
    error_class: str | None = None


# ──────────────────────────────────────────────────────────────────────
# Retry classification — transient (retryable) vs non-transient.
# ──────────────────────────────────────────────────────────────────────


#: Sprint 10 T2 (R2 P1.2) — hvac exceptions classified as TRANSIENT.
#: Bounded exponential-backoff retry applies; if retries are exhausted
#: the underlying exception re-raises.
_TRANSIENT_HVAC_EXCEPTIONS: tuple[type[Exception], ...] = (
    hvac.exceptions.RateLimitExceeded,  # 429
    hvac.exceptions.InternalServerError,  # 500
    hvac.exceptions.VaultDown,  # 503
    hvac.exceptions.BadGateway,  # 502
)

#: Initial backoff in seconds; doubles each retry attempt. With the
#: default ``max_retries=3``, worst-case retry budget is
#: ``0.1 + 0.2 + 0.4 = 0.7s`` extra wall-clock per call.
_RETRY_BACKOFF_BASE_S: float = 0.1


# ──────────────────────────────────────────────────────────────────────
# VaultTransport — shared hvac.Client wrapper.
# ──────────────────────────────────────────────────────────────────────


class VaultTransport:
    """Shared hvac.Client wrapper. See module docstring."""

    __slots__ = (
        "_addr",
        "_client",
        "_max_retries",
        "_namespace",
        "_timeout_s",
        "_token",
    )

    def __init__(
        self,
        *,
        vault_addr: str,
        vault_token: str | None,
        vault_namespace: str | None,
        timeout_s: float,
        max_retries: int,
    ) -> None:
        # Fail-loud on misconfig — mirrors the Sprint-1C VaultAdapter
        # check at ``db/adapters/vault_adapter.py:31``.
        if not vault_addr:
            raise ValueError("VaultTransport requires vault_addr; got empty/None")
        # Trailing-slash normalisation — Sprint-1C VaultAdapter convention.
        self._addr = vault_addr.rstrip("/")
        self._token = vault_token
        self._namespace = vault_namespace
        self._timeout_s = timeout_s
        self._max_retries = max_retries
        # Lazy hvac.Client — constructor stays side-effect-free per the
        # Sprint-1C contract; the network is not touched at __init__.
        self._client: hvac.Client | None = None

    def _ensure_client(self) -> hvac.Client:
        """Return the lazy-minted shared ``hvac.Client`` (build on
        first access; reuse forever).

        This is the "one shared hvac.Client" promise from the module
        docstring + spec §2.1 — pinned by
        ``test_consecutive_calls_reuse_same_hvac_client``.
        """
        if self._client is None:
            self._client = hvac.Client(
                url=self._addr,
                token=self._token,
                namespace=self._namespace,
                timeout=self._timeout_s,
            )
        return self._client

    async def _execute_with_retry(self, op: Callable[[], T]) -> T:
        """Execute a sync hvac callable via :func:`asyncio.to_thread`
        with bounded exponential-backoff retry on transient hvac
        exceptions.

        Sprint 10 T2 (R2 P1.2) — wires the
        ``vault_http_max_retries`` setting into the actual transport
        behaviour. The earlier draft stored ``_max_retries`` but
        never used it; that was a spec/promise violation.

        Semantics:

        - ``max_retries=0`` ⇒ EXACTLY ONE attempt (no retries).
        - ``max_retries=N`` ⇒ up to ``N+1`` total attempts.
        - Retry-on: members of :data:`_TRANSIENT_HVAC_EXCEPTIONS`
          (5xx / 429 / vault-down / bad-gateway).
        - Raise-immediately-on: every other exception (4xx auth /
          path / bad-request errors; transport-level errors hvac
          doesn't wrap) — caller mapping at T4 / T6 stays sharp.
        - Backoff: ``_RETRY_BACKOFF_BASE_S * 2 ** attempt`` per gap
          (100ms, 200ms, 400ms, ...); bounded by ``max_retries``.
        """
        attempts = self._max_retries + 1
        for attempt in range(attempts):
            try:
                return await asyncio.to_thread(op)
            except _TRANSIENT_HVAC_EXCEPTIONS:
                # Last attempt — let the exception propagate.
                if attempt + 1 >= attempts:
                    raise
                await asyncio.sleep(_RETRY_BACKOFF_BASE_S * (2**attempt))
        # Unreachable: the loop either returns or raises on the final
        # iteration. ``raise RuntimeError`` would mask a logic bug if
        # the loop body changes; assert is more accurate.
        raise AssertionError("VaultTransport._execute_with_retry: unreachable")

    async def read(self, path: str) -> dict[str, Any] | None:
        """Read the secret at ``path``. Wraps :meth:`hvac.Client.read`
        via :func:`asyncio.to_thread` + bounded retry.

        Sprint 10 T2 (R2 P2 fix) — preserves hvac's ``None`` semantics
        for missing-path responses. hvac returns ``None`` for 404; the
        transport surfaces that ``None`` unchanged so the Sprint-1C
        :meth:`VaultAdapter.read` `if resp is None: raise KeyError`
        behavior keeps working after T3's refactor. Earlier draft
        coalesced ``None`` to ``{}`` — would have broken T3 backward
        compat by collapsing "missing path" with "empty secret body".

        Caller normalises the response shape (kernel-secrets adapter
        handles KV v1 vs KV v2 nesting at its layer; core/vault.py
        handles dynamic-secret-backend lease shapes at its layer)."""

        def _read() -> dict[str, Any] | None:
            result = self._ensure_client().read(path)
            # ``dict(...)`` wrap satisfies mypy on un-stubbed hvac call;
            # ``None`` semantics preserved per the Sprint-1C
            # backward-compat contract.
            return dict(result) if result is not None else None

        return await self._execute_with_retry(_read)

    async def write(self, path: str, body: dict[str, Any]) -> dict[str, Any] | None:
        """Write to ``path`` with the keyword-spread ``body``. Wraps
        :meth:`hvac.Client.write` via :func:`asyncio.to_thread` +
        bounded retry. hvac's ``write`` takes the body as kwargs (e.g.
        ``client.write(path, **{"key": "value"})``); the body dict is
        therefore spread at the call site. Returns ``None`` for
        backends that don't return a body (KV v1 write); preserves the
        raw hvac response shape otherwise."""

        def _write() -> dict[str, Any] | None:
            result = self._ensure_client().write(path, **body)
            return dict(result) if result is not None else None

        return await self._execute_with_retry(_write)

    async def lease(self, path: str, ttl_s: int) -> dict[str, Any] | None:
        """Mint a dynamic-secret lease at ``path``. Wraps
        :meth:`hvac.Client.read` (HTTP ``GET /v1/<path>``) via
        :func:`asyncio.to_thread` + bounded retry. Returns the raw
        hvac response shape on success (caller —
        :func:`cognic_agentos.core.vault.lease_credential` at T4 —
        composes the :class:`CredentialLease` from this raw response).
        Returns ``None`` if hvac returns ``None`` (rare for dynamic-
        secret leases but possible).

        **Z2 Gap Q amendment (Sprint 10 round-9, 2026-05-24).** Pre-
        Gap-Q this method used ``client.write(path, ttl=f"{ttl_s}s")``
        — POST ``/v1/<path>`` with a ``{"ttl": "900s"}`` body — under
        the assumption it was the unified write-with-ttl dynamic-
        secret shape across all Vault backends. Z2's live proof
        execution against a real ``database/creds/<role>`` endpoint
        returned HTTP 405 unsupported operation, surfacing that Vault's
        dominant dynamic-secret endpoints (database/aws/gcp) are
        GET-only. Only PKI (``pki/issue/<role>``) accepts POST-with-ttl
        because it needs CN/SAN body params. Per spec §3.4 HTTP-verb
        table + §3.5 implementation-shape note: Wave-1 default is the
        read-style ``client.read(path)``; PKI write-style support is
        future engine-specific work (would land as a separate
        transport method e.g. ``lease_with_body(path, body)``, NOT a
        runtime fallback-on-405 heuristic).

        ``ttl_s`` is preserved on the method signature for caller
        wire-protocol stability + for the ``CredentialLease.request.ttl_s``
        audit-evidence projection. Pre-Sprint-10.1 this comment said
        "informational at Wave 1"; Sprint 10.1 upgrades the contract
        per ADR-004 §25 amendment — :func:`cognic_agentos.core.vault.lease_credential`
        now enforces ``ttl_s_granted <= request.ttl_s`` post-mint via
        the new :class:`cognic_agentos.core.vault.VaultLeaseGrantExceedsRequest`
        exception (with best-effort ``transport.revoke(lease_id)``
        before raise), complementing the Rego rule-6 pre-mint cap.
        ``ttl_s`` is still NOT passed to Vault on the wire (per Z2
        Gap Q, the dominant dynamic-secret endpoints are GET-only);
        Vault's role-side ``default_ttl`` / ``max_ttl`` remain
        authoritative for what the wire actually returns, but the
        kernel-side enforcement gate now refuses the lease (and
        revokes it) if the wire-returned value exceeds the request.
        """
        # ``ttl_s`` is NOT passed to Vault on the wire at this
        # transport layer — the dominant dynamic-secret endpoints are
        # GET-only per Z2 Gap Q. Sprint 10.1 amendment to ADR-004 §25:
        # the kernel-side ``core/vault.lease_credential`` now enforces
        # ``ttl_s_granted <= request.ttl_s`` post-mint via the new
        # :class:`VaultLeaseGrantExceedsRequest` exception (with
        # best-effort revoke before raise) so the transport's
        # caller-pinned ``ttl_s`` IS a load-bearing audit + enforcement
        # value even though it never reaches the Vault wire.
        # Explicit ``del`` matches the same reservation pattern used at
        # ``core/vault.lease_credential``'s ``settings`` arg.
        del ttl_s

        def _lease() -> dict[str, Any] | None:
            result = self._ensure_client().read(path)
            return dict(result) if result is not None else None

        return await self._execute_with_retry(_lease)

    async def revoke(self, lease_id: str) -> None:
        """Revoke an active lease. Wraps
        :meth:`hvac.Client.sys.revoke_lease` via
        :func:`asyncio.to_thread` + bounded retry. Returns ``None`` on
        success; raises the underlying hvac exception on failure (the
        caller's fail-soft ``destroy()`` path in T10 swallows the
        exception + emits ``sandbox.lifecycle.lease_revoke_failed``
        per spec §7.2)."""

        def _revoke() -> None:
            # Kwarg form ``lease_id=lease_id`` (not positional) matches
            # the Sprint-1C VaultAdapter call-shape convention pinned at
            # ``tests/unit/db/test_vault_adapter.py::TestLeaseRevoke::test_revoke``
            # — preserves the test assertion as T3 refactors the adapter
            # to delegate revoke through this transport.
            self._ensure_client().sys.revoke_lease(lease_id=lease_id)

        await self._execute_with_retry(_revoke)

    async def health_check(self) -> VaultTransportProbe:
        """Probe Vault availability via ``read_health_status(method='GET')``.

        Sprint 10 T2 (R3 P1 fix) — mirrors the Sprint-1C
        ``VaultAdapter`` health contract pinned at
        ``tests/unit/db/test_vault_adapter.py::TestHealth``:

        - Calls ``client.sys.read_health_status(method='GET')`` and
          parses both ``initialized`` + ``sealed`` from the response.
        - Healthy ONLY when ``initialized=True`` AND ``sealed=False``.
        - Defensive ``sealed=True`` default if the key is absent
          (fail-closed; mirrors Sprint-1C's
          ``status.get('sealed', True)`` at vault_adapter.py:121).

        Returns :class:`VaultTransportProbe` describing the result;
        NEVER raises (matches the ``/readyz`` fail-soft contract).
        Four result states map to the dataclass shape (see
        :class:`VaultTransportProbe`):

        - reachable + initialized + unsealed → ``ok=True``.
        - reachable + ``initialized=False`` → ``ok=False,
          reason='vault_not_initialized'``.
        - reachable + ``initialized=True, sealed=True`` →
          ``ok=False, reason='vault_sealed'``.
        - unreachable / retry-exhausted →
          ``ok=False, error_class=<exception class name>``.

        Public adapters at the layer above (Sprint-1C ``VaultAdapter``
        + Sprint-10 T6 ``VaultCredentialAdapter``) convert this to
        their layer's ``AdapterHealth(driver=..., detail=...)`` shape
        — the transport itself does NOT register as a ``/readyz``-
        visible adapter; the public adapters do."""

        def _probe() -> dict[str, Any]:
            # ``dict(... or {})`` satisfies mypy on the un-stubbed
            # hvac call AND provides a defensive empty-dict fallback
            # if hvac returns None (rare for read_health_status —
            # treated as sealed/uninitialised below).
            result = self._ensure_client().sys.read_health_status(method="GET")
            return dict(result) if result is not None else {}

        try:
            status = await self._execute_with_retry(_probe)
        except Exception as exc:
            return VaultTransportProbe(
                ok=False,
                error_class=type(exc).__name__,
            )

        if not status.get("initialized", False):
            return VaultTransportProbe(ok=False, reason="vault_not_initialized")
        # Defensive fail-closed: absent ``sealed`` key reads as sealed.
        # Mirrors Sprint-1C vault_adapter.py:121's ``status.get("sealed", True)``.
        if status.get("sealed", True):
            return VaultTransportProbe(ok=False, reason="vault_sealed")
        return VaultTransportProbe(ok=True)
