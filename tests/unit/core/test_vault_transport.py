"""Sprint 10 T2 — `core/_vault_transport.py` shared hvac transport.

CRITICAL CONTROL — `core/_vault_transport.py` is on the gate from
day 1 by the `core/` stop-rule (AGENTS.md L48). Tests pin:

* Construction with the 5-field Wave-1 static-token shape
  (`vault_addr` + `vault_token` + `vault_namespace` + `timeout_s` +
  `max_retries`); fail-loud on empty `vault_addr`; trailing-slash
  normalisation; lazy hvac.Client (constructor side-effect-free
  per the Sprint-1C contract).
* The 5 domain-shaped methods (`read` / `write` / `lease` /
  `revoke` / `health_check`) each delegate to the equivalent hvac
  call wrapped in `asyncio.to_thread` (matching the Sprint-1C
  VaultAdapter testing pattern at
  ``tests/unit/db/test_vault_adapter.py``).

Per spec §3.5: NO `refresh_token()` in Wave 1 — static-token auth is
configured at construction; AppRole / Kubernetes ServiceAccount /
JWT-OIDC auth flows are future work (spec §10).

hvac is patched at the consuming module's import site
(``cognic_agentos.core._vault_transport.hvac.Client``), NOT at the
hvac package level — matches the Sprint-1C testing convention so
the transport stays agnostic to whether hvac uses requests, urllib3,
or future async backends.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import hvac
import hvac.exceptions
import pytest

from cognic_agentos.core._vault_transport import VaultTransport, VaultTransportProbe
from cognic_agentos.core.config import Settings


def _settings(**overrides: Any) -> Settings:
    """Build a Settings carrying the Sprint 10 vault_http_* defaults.
    Overrides take precedence over defaults via dict-merge — so retry
    tests can pass ``vault_http_max_retries=N`` without colliding
    with a hardcoded kwarg."""
    kwargs: dict[str, Any] = {
        "_env_file": None,
        "vault_addr": "http://vault.test:8200",
        "vault_token": "test-token",
        "vault_namespace": None,
        "vault_http_timeout_s": 10.0,
        "vault_http_max_retries": 3,
    }
    kwargs.update(overrides)
    return Settings(**kwargs)


def _make_transport(**overrides: Any) -> VaultTransport:
    """Build a VaultTransport from the test Settings shape."""
    settings = _settings(**overrides)
    return VaultTransport(
        vault_addr=settings.vault_addr,  # type: ignore[arg-type]
        vault_token=settings.vault_token,
        vault_namespace=settings.vault_namespace,
        timeout_s=settings.vault_http_timeout_s,
        max_retries=settings.vault_http_max_retries,
    )


# ──────────────────────────────────────────────────────────────────────
# 1. Construction — Wave-1 static-token shape; lazy hvac.Client.
# ──────────────────────────────────────────────────────────────────────


class TestVaultTransportConstruction:
    def test_constructs_with_required_fields(self) -> None:
        """T2 #1 — VaultTransport instantiates with the 5-field
        Wave-1 static-token shape (addr + token + namespace + timeout
        + max_retries)."""
        transport = _make_transport()
        assert transport is not None

    def test_refuses_empty_addr(self) -> None:
        """T2 #2 — empty ``vault_addr`` at construction raises
        ValueError; consistent with Sprint-1C VaultAdapter behavior.
        Fail-loud guard against misconfigured operators."""
        with pytest.raises(ValueError, match="vault_addr"):
            VaultTransport(
                vault_addr="",
                vault_token="t",
                vault_namespace=None,
                timeout_s=10.0,
                max_retries=3,
            )

    def test_strips_trailing_slash_on_addr(self) -> None:
        """T2 #3 — addr trailing slash normalised at construction;
        mirrors Sprint-1C VaultAdapter convention."""
        transport = VaultTransport(
            vault_addr="http://vault.test:8200/",
            vault_token="t",
            vault_namespace=None,
            timeout_s=10.0,
            max_retries=3,
        )
        assert transport._addr == "http://vault.test:8200"

    def test_lazy_client_construction_no_network_at_init(self) -> None:
        """T2 #4 — constructor MUST NOT touch the network. The internal
        hvac.Client is lazily minted on first domain-method call
        (matches Sprint-1C VaultAdapter; the constructor stays
        side-effect-free)."""
        transport = _make_transport()
        assert transport._client is None


# ──────────────────────────────────────────────────────────────────────
# 2. Domain-method delegation — 5 methods x hvac call x asyncio.to_thread.
# ──────────────────────────────────────────────────────────────────────


class TestVaultTransportDomainMethods:
    async def test_read_delegates_to_hvac_client_read(self) -> None:
        """T2 #5 — ``read(path)`` wraps ``client.read(path)`` via
        ``asyncio.to_thread``. Raw hvac response returned (no
        normalisation at the transport layer)."""
        with patch("cognic_agentos.core._vault_transport.hvac.Client") as cls:
            mock = MagicMock()
            mock.read.return_value = {"data": {"data": {"k": "v"}}}
            cls.return_value = mock
            transport = _make_transport()
            result = await transport.read("secret/data/test")
        mock.read.assert_called_once_with("secret/data/test")
        assert result == {"data": {"data": {"k": "v"}}}

    async def test_write_delegates_to_hvac_client_write(self) -> None:
        """T2 #6 — ``write(path, body)`` wraps ``client.write(path,
        **body)`` via ``asyncio.to_thread``. Kwargs-spread matches
        hvac's expected call shape."""
        with patch("cognic_agentos.core._vault_transport.hvac.Client") as cls:
            mock = MagicMock()
            mock.write.return_value = None
            cls.return_value = mock
            transport = _make_transport()
            await transport.write("secret/data/test", {"k": "v"})
        mock.write.assert_called_once_with("secret/data/test", k="v")

    async def test_lease_reads_via_hvac_client_read(self) -> None:
        """T2 #7 (Z2 Gap Q round-9 amendment, 2026-05-24) —
        ``lease(path, ttl_s)`` wraps ``client.read(path)`` via
        ``asyncio.to_thread`` (HTTP ``GET /v1/<path>``). Raw hvac
        response returned — caller normalises shape (e.g.
        ``core/vault.py::lease_credential`` builds ``CredentialLease``
        from the response).

        Pre-Gap-Q this test asserted ``client.write(path, ttl='900s')``
        per the legacy write-with-ttl assumption; Z2's live proof
        against a real ``database/creds/<role>`` endpoint returned
        HTTP 405 unsupported operation, surfacing that Vault's
        dominant dynamic-secret endpoints (database/aws/gcp) are
        GET-only. Per spec §3.4 HTTP-verb table + §3.5 implementation-
        shape note: Wave-1 default is the read-style ``client.read(path)``;
        ``ttl_s`` is NOT wire-forwarded to Vault at this transport layer
        (Vault's role-side ``default_ttl`` / ``max_ttl`` are authoritative
        for what the wire returns) but is load-bearing kernel-side
        post-Sprint-10.1 — ``core/vault.lease_credential`` enforces
        ``ttl_s_granted <= request.ttl_s`` post-mint via the new
        ``VaultLeaseGrantExceedsRequest`` exception per ADR-004 §25
        amendment.

        Load-bearing pins:
        * ``mock.read`` is called exactly once with the secret path.
        * ``mock.write`` is NEVER called from the lease path (no
          fallback-to-write-on-405 heuristic — PKI write-style support
          is future engine-specific work, not a runtime fallback).
        * ``ttl_s`` is NOT forwarded as any kwarg to hvac (NOT
          wire-forwarded per spec §3.5; kernel-side enforcement at
          ``core/vault.lease_credential`` per Sprint-10.1 amendment).
        """
        with patch("cognic_agentos.core._vault_transport.hvac.Client") as cls:
            mock = MagicMock()
            mock.read.return_value = {
                "lease_id": "L-1",
                "lease_duration": 900,
                "data": {"username": "u", "password": "p"},
            }
            cls.return_value = mock
            transport = _make_transport()
            result = await transport.lease("database/creds/payment-readonly", 900)
        mock.read.assert_called_once_with("database/creds/payment-readonly")
        # No fallback-to-write on the lease path — Gap Q load-bearing
        # pin. PKI write-style support is future engine-specific work
        # (separate transport method), NOT a runtime fallback.
        mock.write.assert_not_called()
        assert result is not None
        assert result["lease_id"] == "L-1"
        assert result["lease_duration"] == 900

    async def test_revoke_delegates_to_client_sys_revoke_lease(self) -> None:
        """T2 #8 — ``revoke(lease_id)`` wraps
        ``client.sys.revoke_lease(lease_id)`` via
        ``asyncio.to_thread``. Vault-side revoke; if it fails the
        caller's fail-soft destroy() path is responsible for the
        audit emission (per spec §7.2)."""
        with patch("cognic_agentos.core._vault_transport.hvac.Client") as cls:
            mock = MagicMock()
            mock.sys.revoke_lease.return_value = None
            cls.return_value = mock
            transport = _make_transport()
            await transport.revoke("L-1")
        # Kwarg form matches the Sprint-1C VaultAdapter call-shape
        # convention pinned at
        # tests/unit/db/test_vault_adapter.py::TestLeaseRevoke::test_revoke.
        mock.sys.revoke_lease.assert_called_once_with(lease_id="L-1")

    async def test_health_check_returns_ok_when_initialized_and_unsealed(self) -> None:
        """T2 #9 (R3 P1 update) — ``health_check()`` calls
        ``client.sys.read_health_status(method='GET')`` and returns
        ``VaultTransportProbe(ok=True)`` ONLY when both
        ``initialized=True`` AND ``sealed=False``. Mirrors the
        Sprint-1C VaultAdapter contract pinned at
        ``tests/unit/db/test_vault_adapter.py::TestHealth::test_health_ok``."""
        with patch("cognic_agentos.core._vault_transport.hvac.Client") as cls:
            mock = MagicMock()
            mock.sys.read_health_status.return_value = {
                "initialized": True,
                "sealed": False,
            }
            cls.return_value = mock
            transport = _make_transport()
            result = await transport.health_check()
        assert isinstance(result, VaultTransportProbe)
        assert result.ok is True
        assert result.reason is None
        assert result.error_class is None
        mock.sys.read_health_status.assert_called_once_with(method="GET")

    async def test_health_check_returns_sealed_when_initialized_but_sealed(self) -> None:
        """T2 #10 (R3 P1 NEW) — ``health_check()`` returns
        ``VaultTransportProbe(ok=False, reason='vault_sealed')`` when
        Vault is initialised but sealed. Mirrors the Sprint-1C
        VaultAdapter contract pinned at
        ``tests/unit/db/test_vault_adapter.py::TestHealth::test_health_unreachable_when_sealed``.

        Sprint 10 T2 R2 incorrectly classified a sealed Vault as
        ``ok=False, error_class=None`` ("reachable but not healthy") —
        Sprint-1C reports sealed as ``unreachable`` with a ``vault
        sealed`` detail. The R3 fix introduces the ``reason`` field
        carrying the distinct closed-enum value
        ``'vault_sealed'`` so T3 can preserve the detail text on
        ``AdapterHealth``."""
        with patch("cognic_agentos.core._vault_transport.hvac.Client") as cls:
            mock = MagicMock()
            mock.sys.read_health_status.return_value = {
                "initialized": True,
                "sealed": True,
            }
            cls.return_value = mock
            transport = _make_transport()
            result = await transport.health_check()
        assert isinstance(result, VaultTransportProbe)
        assert result.ok is False
        assert result.reason == "vault_sealed"
        assert result.error_class is None

    async def test_health_check_returns_not_initialized_when_not_initialized(self) -> None:
        """T2 #11 (R3 P1 update) — ``health_check()`` returns
        ``VaultTransportProbe(ok=False, reason='vault_not_initialized')``
        when Vault is reachable but ``initialized=False``. Mirrors
        the Sprint-1C VaultAdapter contract pinned at
        ``tests/unit/db/test_vault_adapter.py::TestHealth::test_health_unreachable_when_not_initialized``."""
        with patch("cognic_agentos.core._vault_transport.hvac.Client") as cls:
            mock = MagicMock()
            mock.sys.read_health_status.return_value = {
                "initialized": False,
                "sealed": False,
            }
            cls.return_value = mock
            transport = _make_transport()
            result = await transport.health_check()
        assert isinstance(result, VaultTransportProbe)
        assert result.ok is False
        assert result.reason == "vault_not_initialized"
        assert result.error_class is None

    async def test_health_check_returns_error_class_on_exception(self) -> None:
        """T2 #12 (R3 P1 update) — ``health_check()`` catches ANY
        exception (after retry exhaustion if transient; immediately if
        non-transient) and returns ``VaultTransportProbe(ok=False,
        error_class='<ExceptionClassName>')``. NEVER raises into the
        ``/readyz`` pattern. ``error_class`` carries the exception
        class name only (no message text — message may leak auth
        tokens or paths). Mirrors the Sprint-1C VaultAdapter contract
        pinned at
        ``tests/unit/db/test_vault_adapter.py::TestHealth::test_health_unreachable_on_connect_error``."""
        with patch("cognic_agentos.core._vault_transport.hvac.Client") as cls:
            mock = MagicMock()
            mock.sys.read_health_status.side_effect = ConnectionError("vault down")
            cls.return_value = mock
            transport = _make_transport()
            result = await transport.health_check()
        assert isinstance(result, VaultTransportProbe)
        assert result.ok is False
        assert result.reason is None
        assert result.error_class == "ConnectionError"

    async def test_health_check_defensive_fail_closed_on_missing_sealed_key(self) -> None:
        """T2 #13 (R3 P1 NEW — fail-closed defense-in-depth) — if the
        health-status response lacks the ``sealed`` key, the probe
        treats it as sealed (mirrors Sprint-1C's
        ``status.get('sealed', True)`` fail-closed posture at
        ``vault_adapter.py:121``). Catches a malformed Vault response
        OR a future hvac change that drops the key — never silently
        classifies an unknown-state Vault as healthy."""
        with patch("cognic_agentos.core._vault_transport.hvac.Client") as cls:
            mock = MagicMock()
            # Response carries ``initialized`` but no ``sealed`` key —
            # this is the malformed/changed-API surface area.
            mock.sys.read_health_status.return_value = {"initialized": True}
            cls.return_value = mock
            transport = _make_transport()
            result = await transport.health_check()
        assert isinstance(result, VaultTransportProbe)
        assert result.ok is False
        assert result.reason == "vault_sealed"
        assert result.error_class is None

    async def test_read_returns_none_when_hvac_returns_none(self) -> None:
        """T2 #12 (R2 P2 fix) — ``read()`` preserves hvac's ``None``
        semantics for missing-path responses. hvac returns ``None``
        for 404; the transport surfaces that ``None`` unchanged.

        Sprint-1C ``VaultAdapter.read()`` does ``if resp is None:
        raise KeyError(path)`` — T3's refactor relies on the transport
        surfacing ``None`` distinctly from an empty body so the
        adapter's KeyError-on-missing-path behavior continues
        working. Earlier draft of T2 coalesced ``None`` to ``{}``
        which would have silently collapsed "missing path" with
        "empty body" at the T3 refactor boundary."""
        with patch("cognic_agentos.core._vault_transport.hvac.Client") as cls:
            mock = MagicMock()
            mock.read.return_value = None
            cls.return_value = mock
            transport = _make_transport()
            result = await transport.read("missing/path")
        assert result is None


# ──────────────────────────────────────────────────────────────────────
# 3. Shared-client invariant — second call reuses the lazy hvac.Client.
# ──────────────────────────────────────────────────────────────────────


class TestVaultTransportClientSharing:
    async def test_consecutive_calls_reuse_same_hvac_client(self) -> None:
        """T2 #11 — two consecutive transport method calls MUST use
        the same underlying ``hvac.Client`` instance (lazy mint once;
        reuse forever). Pins the "ONE shared hvac.Client" purpose
        from spec §2.1; without this guarantee the shared-transport
        promise in T3's VaultAdapter refactor breaks down."""
        with patch("cognic_agentos.core._vault_transport.hvac.Client") as cls:
            mock = MagicMock()
            mock.read.return_value = {}
            cls.return_value = mock
            transport = _make_transport()
            await transport.read("path1")
            await transport.read("path2")
        # hvac.Client constructor called exactly once across the two
        # transport method invocations.
        assert cls.call_count == 1


# ──────────────────────────────────────────────────────────────────────
# 4. Retry discipline — bounded exponential-backoff on transient hvac
#    exceptions; non-transient exceptions raise immediately (R2 P1.2 fix).
# ──────────────────────────────────────────────────────────────────────


class TestVaultTransportRetry:
    """Sprint 10 T2 (R2 P1.2 fix) — wire the ``vault_http_max_retries``
    setting into the actual transport behaviour. The earlier draft
    stored ``_max_retries`` but never used it; that was a spec/promise
    violation (spec §2.1 promises "ONE retry discipline (bounded
    exponential-backoff for transient hvac failures)").

    Transient hvac exception classes (RateLimitExceeded /
    InternalServerError / VaultDown / BadGateway) — retry up to
    ``max_retries`` times with exponential backoff. Non-transient
    exception classes (Forbidden / InvalidPath / InvalidRequest) —
    raise immediately so the caller's mapping at T4 / T6 (the
    ``VaultUnavailable`` / ``VaultPathNotFound`` / ``VaultAuthDenied``
    exception taxonomy in ``core/vault.py``) stays sharp.

    The retry mechanism is exercised via the public domain methods
    (read / write / lease / revoke / health_check) — they all funnel
    through the same ``_execute_with_retry`` helper, so testing one
    method's retry behaviour proves the discipline applies to all.
    """

    async def test_max_retries_zero_means_single_attempt(self) -> None:
        """T2 #14 — ``max_retries=0`` ⇒ EXACTLY one hvac call attempt
        (no retries). Even a transient exception raises on the first
        attempt without retry."""
        with patch("cognic_agentos.core._vault_transport.hvac.Client") as cls:
            mock = MagicMock()
            mock.read.side_effect = hvac.exceptions.InternalServerError("transient 500")
            cls.return_value = mock
            transport = _make_transport(vault_http_max_retries=0)
            with pytest.raises(hvac.exceptions.InternalServerError):
                await transport.read("any/path")
        # EXACTLY one hvac.Client.read() call — no retry.
        assert mock.read.call_count == 1

    async def test_transient_exception_retries_then_succeeds(self) -> None:
        """T2 #15 — transient hvac exception (5xx / 429 /
        vault-down / bad-gateway) triggers retry; success on a later
        attempt returns the successful result. Asserts ``mock.read``
        called the correct number of times to prove the retry actually
        fired (NOT just that the result eventually arrived)."""
        with patch("cognic_agentos.core._vault_transport.hvac.Client") as cls:
            mock = MagicMock()
            # Fail twice transient, succeed on third attempt.
            mock.read.side_effect = [
                hvac.exceptions.RateLimitExceeded("429"),
                hvac.exceptions.VaultDown("503"),
                {"data": {"k": "v"}},
            ]
            cls.return_value = mock
            transport = _make_transport(vault_http_max_retries=3)
            result = await transport.read("retried/path")
        assert result == {"data": {"k": "v"}}
        assert mock.read.call_count == 3

    async def test_transient_exception_exhausts_retries_then_raises(self) -> None:
        """T2 #16 — transient hvac exception that persists past the
        retry budget re-raises the underlying exception. Total attempt
        count is ``max_retries + 1`` (one initial + N retries)."""
        with patch("cognic_agentos.core._vault_transport.hvac.Client") as cls:
            mock = MagicMock()
            # Fail transient on every attempt.
            mock.read.side_effect = hvac.exceptions.InternalServerError("persistent 500")
            cls.return_value = mock
            transport = _make_transport(vault_http_max_retries=2)
            with pytest.raises(hvac.exceptions.InternalServerError):
                await transport.read("always-fails/path")
        # max_retries=2 ⇒ 3 total attempts (1 initial + 2 retries).
        assert mock.read.call_count == 3

    async def test_non_transient_exception_raises_immediately_no_retry(self) -> None:
        """T2 #17 — non-transient hvac exception (4xx-class —
        Forbidden / InvalidPath / InvalidRequest etc.) raises
        IMMEDIATELY without retry. This keeps caller mapping at
        T4 / T6 sharp: the ``VaultPathNotFound`` /
        ``VaultAuthDenied`` exception taxonomy in ``core/vault.py``
        depends on these classes surfacing without retry delay."""
        with patch("cognic_agentos.core._vault_transport.hvac.Client") as cls:
            mock = MagicMock()
            mock.read.side_effect = hvac.exceptions.Forbidden("permission denied")
            cls.return_value = mock
            # max_retries=5 — generous budget that should NOT be used
            # because the exception is non-transient.
            transport = _make_transport(vault_http_max_retries=5)
            with pytest.raises(hvac.exceptions.Forbidden):
                await transport.read("forbidden/path")
        # EXACTLY one attempt — no retry on non-transient.
        assert mock.read.call_count == 1
