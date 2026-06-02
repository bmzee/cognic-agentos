"""Sprint 11.5b — real Redis-backed memory.write_freeze kill-switch (ADR-018).

CRITICAL CONTROL + stop-rule (core/ per AGENTS.md). Replaces the 11.5a
_NullMemoryKillSwitchInterrogator sentinel. Conforms structurally to
core.memory._seams.MemoryKillSwitchInterrogator so it drops into MemoryGate
construction with ZERO gate-code change. Redis key schema is FROZEN for the
Sprint-13.5 full kill-switch matrix (no migration when the other classes land).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

_KEY_PREFIX = "cognic:killswitch:memory_write_freeze:"


def _write_freeze_key(tenant_id: str) -> str:
    return f"{_KEY_PREFIX}{tenant_id}"


@runtime_checkable
class _AsyncRedisKVLike(Protocol):
    async def get(self, key: str) -> Any: ...
    async def set(self, key: str, value: Any, **kwargs: Any) -> Any: ...


def _utcnow() -> datetime:
    return datetime.now(UTC)


class RedisMemoryWriteFreezeKillSwitch:
    """Per-tenant memory.write-freeze probe with fail-closed cached grace.

    is_write_frozen(): read Redis -> parse {frozen, updated_at, actor_id, reason}
    -> refresh the per-tenant last-known-good cache -> return frozen. On a Redis
    error: serve the cached value while its age <= cache_ttl_s; otherwise (stale
    or no cache) FAIL CLOSED (return True). A malformed value also fails closed.
    """

    def __init__(
        self,
        *,
        redis_client: _AsyncRedisKVLike,
        cache_ttl_s: int,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._redis = redis_client
        self._cache_ttl_s = cache_ttl_s
        self._clock = clock
        self._cache: dict[str, tuple[bool, datetime]] = {}  # tenant_id -> (frozen, observed_at)

    async def is_write_frozen(self, *, tenant_id: str) -> bool:
        try:
            raw = await self._redis.get(_write_freeze_key(tenant_id))
        except Exception:
            # Redis unreachable: cached last-known-good while fresh, else fail-closed.
            cached = self._cache.get(tenant_id)
            if cached is not None:
                frozen, observed_at = cached
                if (self._clock() - observed_at).total_seconds() <= self._cache_ttl_s:
                    return frozen
            return True
        if raw is None:
            self._cache[tenant_id] = (False, self._clock())  # absent key => not frozen
            return False
        try:
            doc = json.loads(raw if isinstance(raw, str) else raw.decode())
            frozen = doc["frozen"]
            _custody = (doc["updated_at"], doc["actor_id"], doc["reason"])  # ALL required
            if not isinstance(frozen, bool):
                # non-bool `frozen` is malformed; do NOT bool()-coerce (0 => fail-open)
                raise ValueError("frozen must be a JSON bool")
        except (ValueError, TypeError, KeyError, AttributeError):
            # Malformed/partial state POISONS the cache fail-closed: cache (True, now)
            # so a later Redis outage within TTL serves frozen, NOT a stale unfrozen
            # last-known-good. A valid Redis read supersedes it. (Cross-call blocker —
            # malformed is NOT a legit value and must invalidate the prior grace.)
            self._cache[tenant_id] = (True, self._clock())
            return True  # malformed / partial => fail-closed
        self._cache[tenant_id] = (frozen, self._clock())
        return frozen

    async def set_write_freeze(
        self, *, tenant_id: str, frozen: bool, actor_id: str, reason: str
    ) -> None:
        """Ops/portal write surface (the portal RBAC gate is 11.5c). Writes the
        frozen-state JSON; the read path + cache pick it up on the next probe."""
        payload = json.dumps(
            {
                "frozen": frozen,
                "updated_at": self._clock().isoformat(),
                "actor_id": actor_id,
                "reason": reason,
            }
        )
        await self._redis.set(_write_freeze_key(tenant_id), payload)


__all__ = ("RedisMemoryWriteFreezeKillSwitch", "_write_freeze_key")
