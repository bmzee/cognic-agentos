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
