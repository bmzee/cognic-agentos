"""Harness Injection T1 — cache adapter Protocol + registry typing + in-memory fixture."""

from __future__ import annotations

import typing

from cognic_agentos.db.adapters import protocols as P
from cognic_agentos.db.adapters.registry import PROTOCOL_FOR_KIND, AdapterKind
from tests.support.adapter_fixtures import InMemoryCacheAdapter


def test_cache_kind_in_adapter_kind_literal() -> None:
    assert "cache" in typing.get_args(AdapterKind)


def test_cache_kind_in_protocol_for_kind() -> None:
    assert PROTOCOL_FOR_KIND["cache"] is P.CacheAdapter


def test_in_memory_cache_adapter_satisfies_protocol() -> None:
    adapter = InMemoryCacheAdapter()
    assert isinstance(adapter, P.CacheAdapter)


async def test_in_memory_cache_client_roundtrip() -> None:
    adapter = InMemoryCacheAdapter()
    await adapter.connect()
    await adapter.client.set("k", "v")
    assert await adapter.client.get("k") == "v"
    assert await adapter.client.get("missing") is None
    health = await adapter.health_check()
    assert health.status == "ok"
    assert health.driver == "memory"
    await adapter.close()


def test_in_memory_cache_client_satisfies_quota_protocol() -> None:
    """Sprint 13.7 (ADR-022) — the in-memory cache client carries the quota ops
    (incrby/decrby/getdel/expire) so a cache_driver='memory' runtime can drive
    the REAL QuotaEngine plane the SchedulerEngine depends on, without a real
    Redis. The shared ``_AsyncKVClient`` adapter Protocol stays get/set-only."""
    from cognic_agentos.core.emergency.quotas import _AsyncRedisQuotaLike

    adapter = InMemoryCacheAdapter()
    assert isinstance(adapter.client, _AsyncRedisQuotaLike)


async def test_in_memory_cache_client_quota_ops_roundtrip() -> None:
    """incrby accumulates, decrby rolls back, getdel is atomic exactly-once,
    expire is an accepted no-op (mirrors tests/integration/emergency/
    test_quota_e2e.py::_FakeRedis)."""
    adapter = InMemoryCacheAdapter()
    assert await adapter.client.incrby("c", 5) == 5
    assert await adapter.client.incrby("c", 3) == 8
    assert await adapter.client.decrby("c", 2) == 6
    await adapter.client.expire("c", 60)  # TTL accepted-and-ignored no-op (does not evict)
    assert await adapter.client.getdel("c") == "6"  # incrby stores str; expire left it intact
    assert await adapter.client.getdel("c") is None  # exactly-once → gone
