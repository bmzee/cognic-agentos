"""VaultAdapter — hvac.Client mocked at the module boundary.

We patch ``hvac.Client`` (not the underlying transport) so the test stays
agnostic to whether hvac uses ``requests``, ``urllib3``, or future async
backends. This is the intended hvac unit-test pattern."""

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
        with patch("cognic_agentos.db.adapters.vault_adapter.hvac.Client") as cls:
            mock = MagicMock()
            mock.read.return_value = {"data": {"data": {"k": "v"}}}
            cls.return_value = mock
            a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
            assert await a.read("secret/data/p/q") == {"k": "v"}
            mock.read.assert_called_once_with("secret/data/p/q")

    async def test_read_kv_v1(self) -> None:
        # KV v1 returns flat under data
        with patch("cognic_agentos.db.adapters.vault_adapter.hvac.Client") as cls:
            mock = MagicMock()
            mock.read.return_value = {"data": {"k": "v"}}
            cls.return_value = mock
            a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
            assert await a.read("secret/p/q") == {"k": "v"}

    async def test_read_missing_raises(self) -> None:
        with patch("cognic_agentos.db.adapters.vault_adapter.hvac.Client") as cls:
            mock = MagicMock()
            mock.read.return_value = None
            cls.return_value = mock
            a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
            with pytest.raises(KeyError):
                await a.read("secret/data/missing")

    async def test_write(self) -> None:
        with patch("cognic_agentos.db.adapters.vault_adapter.hvac.Client") as cls:
            mock = MagicMock()
            cls.return_value = mock
            a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
            await a.write("secret/data/p/q", {"k": "v"})
            mock.write.assert_called_once_with("secret/data/p/q", k="v")


class TestLeaseRevoke:
    async def test_lease(self) -> None:
        with patch("cognic_agentos.db.adapters.vault_adapter.hvac.Client") as cls:
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
        with patch("cognic_agentos.db.adapters.vault_adapter.hvac.Client") as cls:
            mock = MagicMock()
            cls.return_value = mock
            a = VaultAdapter(VAULT_ADDR, token="dev", namespace=None)
            await a.revoke("abc-lease")
            mock.sys.revoke_lease.assert_called_once_with(lease_id="abc-lease")


class TestHealth:
    async def test_health_ok(self) -> None:
        with patch("cognic_agentos.db.adapters.vault_adapter.hvac.Client") as cls:
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
        with patch("cognic_agentos.db.adapters.vault_adapter.hvac.Client") as cls:
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
        with patch("cognic_agentos.db.adapters.vault_adapter.hvac.Client") as cls:
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
        with patch("cognic_agentos.db.adapters.vault_adapter.hvac.Client") as cls:
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
