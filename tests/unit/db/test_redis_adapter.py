"""Harness Injection T2 — real Redis cache adapter (optional adapters-extra driver)."""

from __future__ import annotations

import pytest

from cognic_agentos.db.adapters import protocols as P
from cognic_agentos.db.adapters.registry import bundled_registry


def test_redis_adapter_registered_on_import() -> None:
    import cognic_agentos.db.adapters.redis_adapter  # noqa: F401

    assert bundled_registry.has("cache", "redis")
    cls = bundled_registry.resolve("cache", "redis")
    # ``resolve`` returns a bare ``type``; ``getattr`` reads the structural
    # ``driver`` class attr without an attr-defined suppression.
    assert getattr(cls, "driver", None) == "redis"


def test_redis_adapter_satisfies_cache_protocol() -> None:
    from cognic_agentos.db.adapters.redis_adapter import RedisAdapter

    adapter = RedisAdapter("redis://localhost:6379/0")
    assert isinstance(adapter, P.CacheAdapter)


def test_redis_adapter_requires_url() -> None:
    from cognic_agentos.db.adapters.redis_adapter import RedisAdapter

    with pytest.raises(ValueError, match="redis_url"):
        RedisAdapter(None)


def test_client_before_connect_raises() -> None:
    from cognic_agentos.db.adapters.redis_adapter import RedisAdapter

    adapter = RedisAdapter("redis://localhost:6379/0")
    with pytest.raises(RuntimeError, match="not connected"):
        _ = adapter.client
