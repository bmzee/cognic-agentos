"""Redis cache adapter — the harness's first-class ``cache`` driver (ADR-009).

Optional ``adapters``-extra driver. ``redis`` is imported at module top level
(mirroring qdrant_adapter); kernel-image resilience lives in
``load_bundled_adapters``'s allowlist + try/except, not a lazy import. Exposes
the live ``redis.asyncio.Redis`` client via ``.client`` for the memory
subsystem (scratch tier + ADR-018 write-freeze kill switch).
"""

from __future__ import annotations

import time
from typing import cast

import redis.asyncio as _redis

from cognic_agentos.db.adapters.protocols import AdapterHealth, _AsyncKVClient
from cognic_agentos.db.adapters.registry import bundled_registry


class RedisAdapter:
    driver = "redis"

    def __init__(self, url: str | None) -> None:
        if not url:
            raise ValueError("RedisAdapter requires redis_url; got empty/None")
        self._url = url
        self._client: _redis.Redis | None = None

    async def connect(self) -> None:
        # decode_responses=True so get() returns str (matches the in-memory
        # fixture + the memory scratch/kill-switch consumers' str handling).
        self._client = _redis.Redis.from_url(self._url, decode_responses=True)

    @property
    def client(self) -> _AsyncKVClient:
        if self._client is None:
            raise RuntimeError("RedisAdapter.client accessed before connect(): not connected")
        # redis-py stubs type Redis.get as ``get(name=...)`` / set with a concrete
        # signature, which is not structurally assignable to the permissive
        # _AsyncKVClient (``get(key=...)`` / ``set(*args, **kwargs)``) — a parameter-name
        # mismatch, not a behavioural one. Cast minimally rather than loosen the Protocol.
        return cast(_AsyncKVClient, self._client)

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def health_check(self) -> AdapterHealth:
        if self._client is None:
            return AdapterHealth(status="unreachable", driver=self.driver, detail="not connected")
        start = time.perf_counter()
        try:
            # redis-py stubs type ``ping()`` as ``Awaitable[bool] | bool`` (sync-or-async
            # union); awaiting the union trips mypy though the async client always returns
            # the awaitable. Narrow ignore rather than restructure the health probe.
            await self._client.ping()  # type: ignore[misc]
        except Exception as exc:
            return AdapterHealth(
                status="unreachable",
                driver=self.driver,
                detail=type(exc).__name__,
            )
        return AdapterHealth(
            status="ok",
            driver=self.driver,
            latency_ms=(time.perf_counter() - start) * 1000.0,
        )


bundled_registry.register("cache", "redis", RedisAdapter)
