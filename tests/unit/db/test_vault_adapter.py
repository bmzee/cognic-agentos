"""VaultAdapter — hvac.Client mocked at the shared-transport module boundary.

Sprint 10 T3 — VaultAdapter now consumes the shared
:class:`cognic_agentos.core._vault_transport.VaultTransport`, which
owns the lazy ``hvac.Client``. Tests therefore patch
``cognic_agentos.core._vault_transport.hvac.Client`` (NOT the
adapter's own import path, which no longer references hvac directly
after the T3 refactor). The patch-site relocation preserves every
existing Sprint-1C test assertion behaviour — they still mock the
hvac.Client constructor; the mock just resolves at the transport
module rather than the adapter module."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from cognic_agentos.db.adapters import bundled_registry
from cognic_agentos.db.adapters import protocols as P
from cognic_agentos.db.adapters.vault_adapter import VaultAdapter

VAULT_ADDR = "http://vault.test:8200"


def _make_client(**attrs: Any) -> MagicMock:
    """Build a MagicMock hvac.Client; pass attribute overrides via kwargs."""

    client = MagicMock()
    for k, v in attrs.items():
        setattr(client, k, v)
    return client


class TestRegistration:
    def test_vault_registered_under_bundled(self) -> None:
        assert bundled_registry.has("secret", "vault")
        assert bundled_registry.resolve("secret", "vault") is VaultAdapter


class TestConstruction:
    def test_constructor_refuses_empty_addr(self) -> None:
        with pytest.raises(ValueError, match="vault_addr"):
            VaultAdapter(None, "tok", None)
        with pytest.raises(ValueError, match="vault_addr"):
            VaultAdapter("", "tok", None)


class TestReadWrite:
    async def test_read_kv_v2(self) -> None:
        # KV v2 nests under data/data
        with patch("cognic_agentos.core._vault_transport.hvac.Client") as cls:
            mock = MagicMock()
            mock.read.return_value = {"data": {"data": {"k": "v"}}}
            cls.return_value = mock
            a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
            assert await a.read("secret/data/p/q") == {"k": "v"}
            mock.read.assert_called_once_with("secret/data/p/q")

    async def test_read_kv_v1(self) -> None:
        # KV v1 returns flat under data
        with patch("cognic_agentos.core._vault_transport.hvac.Client") as cls:
            mock = MagicMock()
            mock.read.return_value = {"data": {"k": "v"}}
            cls.return_value = mock
            a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
            assert await a.read("secret/p/q") == {"k": "v"}

    async def test_read_missing_raises(self) -> None:
        with patch("cognic_agentos.core._vault_transport.hvac.Client") as cls:
            mock = MagicMock()
            mock.read.return_value = None
            cls.return_value = mock
            a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
            with pytest.raises(KeyError):
                await a.read("secret/data/missing")

    async def test_write_kv_v2(self) -> None:
        """KV v2 paths (``<mount>/data/<key>``) require a ``data={...}``
        envelope. The adapter must wrap; passing **value directly is
        wrong for KV v2."""

        with patch("cognic_agentos.core._vault_transport.hvac.Client") as cls:
            mock = MagicMock()
            cls.return_value = mock
            a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
            await a.write("secret/data/p/q", {"k": "v"})
            mock.write.assert_called_once_with("secret/data/p/q", data={"k": "v"})

    async def test_write_kv_v1(self) -> None:
        """KV v1 paths take raw kwargs; no ``data=`` envelope."""

        with patch("cognic_agentos.core._vault_transport.hvac.Client") as cls:
            mock = MagicMock()
            cls.return_value = mock
            a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
            await a.write("secret/p/q", {"k": "v"})
            mock.write.assert_called_once_with("secret/p/q", k="v")


class TestLeaseRevoke:
    async def test_lease(self) -> None:
        with patch("cognic_agentos.core._vault_transport.hvac.Client") as cls:
            mock = MagicMock()
            mock.read.return_value = {
                "lease_id": "abc-lease",
                "lease_duration": 60,
                "data": {"username": "u", "password": "p"},
            }
            cls.return_value = mock
            a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
            lease = await a.lease("database/creds/test", ttl_s=60)
            assert lease.lease_id == "abc-lease"
            assert lease.ttl_s == 60
            assert lease.value == {"username": "u", "password": "p"}

    async def test_revoke(self) -> None:
        with patch("cognic_agentos.core._vault_transport.hvac.Client") as cls:
            mock = MagicMock()
            cls.return_value = mock
            a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
            await a.revoke("abc-lease")
            mock.sys.revoke_lease.assert_called_once_with(lease_id="abc-lease")


class TestHealth:
    async def test_health_ok(self) -> None:
        with patch("cognic_agentos.core._vault_transport.hvac.Client") as cls:
            mock = MagicMock()
            mock.sys.read_health_status.return_value = {
                "initialized": True,
                "sealed": False,
            }
            cls.return_value = mock
            a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
            h = await a.health_check()
            assert h.status == "ok"
            assert h.driver == "vault"
            assert h.latency_ms is not None

    async def test_health_unreachable_when_sealed(self) -> None:
        with patch("cognic_agentos.core._vault_transport.hvac.Client") as cls:
            mock = MagicMock()
            mock.sys.read_health_status.return_value = {
                "initialized": True,
                "sealed": True,
            }
            cls.return_value = mock
            a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
            h = await a.health_check()
            assert h.status == "unreachable"
            assert h.detail is not None and "sealed" in h.detail.lower()

    async def test_health_unreachable_when_not_initialized(self) -> None:
        with patch("cognic_agentos.core._vault_transport.hvac.Client") as cls:
            mock = MagicMock()
            mock.sys.read_health_status.return_value = {
                "initialized": False,
                "sealed": False,
            }
            cls.return_value = mock
            a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
            h = await a.health_check()
            assert h.status == "unreachable"
            assert h.detail is not None and "initialized" in h.detail.lower()

    async def test_health_unreachable_on_connect_error(self) -> None:
        with patch("cognic_agentos.core._vault_transport.hvac.Client") as cls:
            mock = MagicMock()
            mock.sys.read_health_status.side_effect = ConnectionError("nope")
            cls.return_value = mock
            a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
            h = await a.health_check()
            assert h.status == "unreachable"


class TestSatisfiesProtocol:
    def test_protocol_conformance(self) -> None:
        a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
        assert isinstance(a, P.SecretAdapter)


# ──────────────────────────────────────────────────────────────────────
# Sprint 10 T3 — VaultAdapter consumes the shared VaultTransport.
# ──────────────────────────────────────────────────────────────────────


class TestT3TransportInjection:
    """Sprint 10 T3 — ``VaultAdapter`` refactored to delegate hvac
    mechanics through the shared :class:`VaultTransport` from
    ``core/_vault_transport.py``. Public API unchanged; existing 14
    Sprint-1C tests still pass after a test-site patch relocation
    (hvac.Client lives in the transport's import path now, not the
    adapter's).

    Sprint 10 T3 user-locked carve-out: ``VaultAdapter.lease()``
    MUST continue to funnel through ``transport.read(path)`` — NOT
    ``transport.lease(path, ttl_s)`` which is the T4-consumer API
    reserved for ``core/vault.py::lease_credential`` (wraps the raw
    hvac response in ``core.vault.CredentialLease``, NOT the
    Sprint-1C ``SecretLease`` shape). Switching ``VaultAdapter.lease``
    to ``transport.lease`` would change the Sprint-1C wire contract
    (SecretLease consumer shape → CredentialLease consumer shape)
    and break the pinned ``TestLeaseRevoke::test_lease`` assertion.
    Post-Z2-Gap-Q (Sprint 10 round-9, 2026-05-24) both
    ``transport.read`` and ``transport.lease`` delegate to
    ``client.read(path)`` at the hvac level — the carve-out remains
    load-bearing because the two transport methods give the two
    distinct consumer-shape contracts independent forward-evolution
    surfaces.
    """

    def test_accepts_optional_transport_kwarg(self) -> None:
        """T3 #1 — ``VaultAdapter.__init__`` accepts an optional
        ``transport=`` kwarg for explicit injection. Used by Sprint 10
        ``create_app`` wiring to share a single ``VaultTransport``
        across BOTH ``VaultAdapter`` (Sprint-1C kernel-secrets) AND
        ``VaultCredentialAdapter`` (T6 sandbox credentials)."""
        from cognic_agentos.core._vault_transport import VaultTransport

        transport = VaultTransport(
            vault_addr=VAULT_ADDR,
            vault_token="dev",
            vault_namespace=None,
            timeout_s=10.0,
            max_retries=3,
        )
        adapter = VaultAdapter(VAULT_ADDR, token="dev", namespace=None, transport=transport)
        # Pin via internal attribute — adapter stores the injected transport
        # for delegation; private attribute is part of the T3 contract
        # (the lazy-default fallback inspects it too).
        assert adapter._transport is transport

    def test_backward_compat_3_arg_constructor_still_works(self) -> None:
        """T3 #2 — Sprint-1C 3-arg constructor (``addr``, ``token``,
        ``namespace`` — no ``transport=`` kwarg) MUST keep working.
        Out-of-tree consumers (bank overlays, plugin packs) construct
        ``VaultAdapter(addr, token, namespace)`` directly; the lazy
        ``transport`` default mints one internally on first method
        call so no caller breaks."""
        adapter = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
        # Constructor still side-effect-free per Sprint-1C contract;
        # transport not yet built.
        assert adapter._transport is None

    def test_shared_transport_invariant(self) -> None:
        """T3 #3 — two ``VaultAdapter`` instances built with the SAME
        ``VaultTransport`` see the same underlying instance — pins the
        "one Vault discipline" promise from the spec §2.1: a single
        shared ``hvac.Client``, single auth, single retry state."""
        from cognic_agentos.core._vault_transport import VaultTransport

        transport = VaultTransport(
            vault_addr=VAULT_ADDR,
            vault_token="dev",
            vault_namespace=None,
            timeout_s=10.0,
            max_retries=3,
        )
        a1 = VaultAdapter(VAULT_ADDR, token="dev", namespace=None, transport=transport)
        a2 = VaultAdapter(VAULT_ADDR, token="dev", namespace=None, transport=transport)
        assert a1._transport is a2._transport

    async def test_lease_uses_transport_read_not_transport_lease(self) -> None:
        """T3 #4 — USER-LOCKED CARVE-OUT pin (R0 review of T3 plan).
        ``VaultAdapter.lease()`` MUST funnel through
        ``transport.read(path)`` — wrapping the response in the
        Sprint-1C ``SecretLease`` shape — and MUST NOT funnel
        through ``transport.lease(path, ttl_s)`` (which is the
        T4-consumer API reserved for ``core/vault.py::lease_credential``;
        wraps the raw hvac response in ``core.vault.CredentialLease``,
        a distinct consumer-shape contract).

        Switching ``VaultAdapter.lease`` to ``transport.lease`` would
        change the Sprint-1C consumer-shape contract (SecretLease →
        CredentialLease) and break the pinned
        ``TestLeaseRevoke::test_lease`` mock expectation
        (``transport.lease.assert_not_called()`` would fail, and the
        adapter would return the T4 ``CredentialLease`` consumer
        shape instead of the Sprint-1C ``SecretLease`` shape).
        """
        from unittest.mock import AsyncMock

        from cognic_agentos.core._vault_transport import VaultTransport

        # Mock the transport's read AND lease methods explicitly so
        # we can prove which one the adapter calls.
        transport = MagicMock(spec=VaultTransport)
        transport.read = AsyncMock(
            return_value={
                "lease_id": "abc-lease",
                "lease_duration": 60,
                "data": {"username": "u", "password": "p"},
            }
        )
        transport.lease = AsyncMock()  # MUST NOT be called

        adapter = VaultAdapter(VAULT_ADDR, token="dev", namespace=None, transport=transport)
        lease = await adapter.lease("database/creds/test", ttl_s=60)

        # CARVE-OUT pin: lease() funnels through read(), NOT lease().
        transport.read.assert_awaited_once_with("database/creds/test")
        transport.lease.assert_not_called()

        # And the result shape is the Sprint-1C SecretLease.
        assert lease.lease_id == "abc-lease"
        assert lease.ttl_s == 60
        assert lease.value == {"username": "u", "password": "p"}

    async def test_health_check_maps_all_4_probe_states(self) -> None:
        """T3 #5 — R3 health-mapping contract pin. The 4-state
        :class:`VaultTransportProbe` returned by
        ``transport.health_check()`` MUST be mapped to the
        Sprint-1C-pinned ``AdapterHealth`` strings:

        - ``ok=True`` → ``status='ok'`` + ``latency_ms`` populated
        - ``reason='vault_not_initialized'`` →
          ``status='unreachable', detail='vault not initialized'``
        - ``reason='vault_sealed'`` →
          ``status='unreachable', detail='vault sealed'``
        - ``error_class='<ClassName>'`` →
          ``status='unreachable', detail='<ClassName>'``

        Exact detail strings match
        ``src/cognic_agentos/db/adapters/vault_adapter.py:111-124``
        — preserves ``TestHealth`` pinned assertions across the
        T3 refactor.
        """
        from unittest.mock import AsyncMock

        from cognic_agentos.core._vault_transport import (
            VaultTransport,
            VaultTransportProbe,
        )

        # Test each of the 4 states by injecting a mocked transport
        # that returns the matching VaultTransportProbe.
        cases: list[tuple[VaultTransportProbe, str, str | None]] = [
            (
                VaultTransportProbe(ok=True),
                "ok",
                None,  # latency_ms set; no detail assertion needed
            ),
            (
                VaultTransportProbe(ok=False, reason="vault_not_initialized"),
                "unreachable",
                "vault not initialized",
            ),
            (
                VaultTransportProbe(ok=False, reason="vault_sealed"),
                "unreachable",
                "vault sealed",
            ),
            (
                VaultTransportProbe(ok=False, error_class="ConnectionError"),
                "unreachable",
                "ConnectionError",
            ),
        ]

        for probe, expected_status, expected_detail in cases:
            transport = MagicMock(spec=VaultTransport)
            transport.health_check = AsyncMock(return_value=probe)
            adapter = VaultAdapter(VAULT_ADDR, token="dev", namespace=None, transport=transport)

            health = await adapter.health_check()

            assert health.status == expected_status, (
                f"probe={probe} expected status={expected_status} got={health.status}"
            )
            assert health.driver == "vault", (
                f"probe={probe} driver must remain 'vault' for the bundled_registry key"
            )
            if expected_detail is not None:
                assert health.detail == expected_detail, (
                    f"probe={probe} expected detail={expected_detail!r} got={health.detail!r}"
                )
            else:
                # ok=True case: latency_ms must be populated; detail absent
                assert health.latency_ms is not None
                assert health.detail is None
