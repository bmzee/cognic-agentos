"""Harness Injection T3 — cache adapter wired into the pool (Adapters.cache + none-opt-out)."""

from __future__ import annotations

import pytest

from cognic_agentos.core.config import Settings
from cognic_agentos.db.adapters.factory import build_adapters
from cognic_agentos.db.adapters.registry import AdapterNotInstalled, AdapterRegistry
from tests.support.adapter_fixtures import InMemoryCacheAdapter


def test_cache_none_yields_none(
    memory_registry: AdapterRegistry, memory_settings: Settings
) -> None:
    s = memory_settings.model_copy(update={"cache_driver": "none"})
    adapters = build_adapters(s, registry=memory_registry)
    assert adapters.cache is None


def test_cache_memory_driver_resolves(
    memory_registry: AdapterRegistry, memory_settings: Settings
) -> None:
    s = memory_settings.model_copy(update={"cache_driver": "memory"})
    adapters = build_adapters(s, registry=memory_registry)
    assert adapters.cache is not None
    # ``CacheAdapter`` Protocol carries no ``driver``; the memory fixture does.
    # isinstance narrows for mypy AND proves the memory driver resolved.
    assert isinstance(adapters.cache, InMemoryCacheAdapter)
    assert adapters.cache.driver == "memory"


def test_cache_redis_unregistered_fails_loud(
    memory_registry: AdapterRegistry, memory_settings: Settings
) -> None:
    # memory_registry has no ("cache","redis") — must fail loud, never None.
    s = memory_settings.model_copy(
        update={"cache_driver": "redis", "redis_url": "redis://x:6379/0"}
    )
    with pytest.raises(AdapterNotInstalled):
        build_adapters(s, registry=memory_registry)


async def test_cache_in_open_all_lifecycle(
    memory_settings: Settings, memory_registry: AdapterRegistry
) -> None:
    s = memory_settings.model_copy(update={"cache_driver": "memory"})
    adapters = build_adapters(s, registry=memory_registry)
    # Pin the __post_init__ append: the cache adapter is in the managed-lifecycle
    # set, so open_all/close_all drive its connect()/close(). Without this, the
    # no-op in-memory connect/close would let the test pass even if the append
    # branch were dropped — a real bug for the Redis driver.
    assert adapters.cache in adapters._all
    await adapters.open_all()  # must not raise; the cache adapter has connect()
    await adapters.close_all()
