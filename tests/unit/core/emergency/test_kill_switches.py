import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from cognic_agentos.core.emergency.kill_switches import (
    RedisMemoryWriteFreezeKillSwitch,
    _write_freeze_key,
)
from cognic_agentos.core.memory._seams import MemoryKillSwitchInterrogator


class _FakeRedis:
    """Duck-typed get/set; `available=False` simulates an unreachable backend."""

    def __init__(self, available: bool = True) -> None:
        self.store: dict[str, Any] = {}
        self.available = available

    async def get(self, key: str) -> Any:
        if not self.available:
            raise ConnectionError("redis down")
        return self.store.get(key)

    async def set(self, key: str, value: Any, **kw: Any) -> Any:
        if not self.available:
            raise ConnectionError("redis down")
        self.store[key] = value
        return True


def _clock(t: datetime) -> Callable[[], datetime]:  # deterministic injectable clock
    return lambda: t


def test_conforms_to_interrogator_protocol():
    ks = RedisMemoryWriteFreezeKillSwitch(redis_client=_FakeRedis(), cache_ttl_s=60)
    assert isinstance(ks, MemoryKillSwitchInterrogator)


def test_key_schema_is_frozen_for_13_5():
    assert _write_freeze_key("acme") == "cognic:killswitch:memory_write_freeze:acme"


@pytest.mark.asyncio
async def test_frozen_true_when_value_says_frozen():
    redis = _FakeRedis()
    redis.store[_write_freeze_key("t1")] = json.dumps(
        {
            "frozen": True,
            "updated_at": "2026-06-01T00:00:00+00:00",
            "actor_id": "ops",
            "reason": "audit",
        }
    )
    ks = RedisMemoryWriteFreezeKillSwitch(redis_client=redis, cache_ttl_s=60)
    assert await ks.is_write_frozen(tenant_id="t1") is True


@pytest.mark.asyncio
async def test_unfrozen_when_absent_or_false():
    redis = _FakeRedis()
    ks = RedisMemoryWriteFreezeKillSwitch(redis_client=redis, cache_ttl_s=60)
    assert await ks.is_write_frozen(tenant_id="t1") is False
    redis.store[_write_freeze_key("t1")] = json.dumps(
        {"frozen": False, "updated_at": "x", "actor_id": "ops", "reason": "lifted"}
    )
    assert await ks.is_write_frozen(tenant_id="t1") is False


@pytest.mark.asyncio
async def test_redis_unreachable_uses_fresh_cache_then_fails_closed_when_stale():
    t0 = datetime(2026, 6, 1, tzinfo=UTC)
    redis = _FakeRedis()
    redis.store[_write_freeze_key("t1")] = json.dumps(
        {"frozen": False, "updated_at": "x", "actor_id": "ops", "reason": "ok"}
    )
    ks = RedisMemoryWriteFreezeKillSwitch(redis_client=redis, cache_ttl_s=60, clock=_clock(t0))
    assert await ks.is_write_frozen(tenant_id="t1") is False  # primes cache (frozen=False)
    redis.available = False
    ks._clock = _clock(t0 + timedelta(seconds=30))  # within grace
    assert await ks.is_write_frozen(tenant_id="t1") is False  # cached last-known-good
    ks._clock = _clock(t0 + timedelta(seconds=61))  # cache stale (> ttl)
    assert await ks.is_write_frozen(tenant_id="t1") is True  # FAIL-CLOSED frozen


@pytest.mark.asyncio
async def test_redis_unreachable_no_cache_fails_closed():
    ks = RedisMemoryWriteFreezeKillSwitch(redis_client=_FakeRedis(available=False), cache_ttl_s=60)
    assert await ks.is_write_frozen(tenant_id="never-seen") is True


@pytest.mark.asyncio
async def test_malformed_value_fails_closed():
    redis = _FakeRedis()
    redis.store[_write_freeze_key("t1")] = "{not json"
    ks = RedisMemoryWriteFreezeKillSwitch(redis_client=redis, cache_ttl_s=60)
    assert await ks.is_write_frozen(tenant_id="t1") is True


@pytest.mark.asyncio
async def test_set_write_freeze_round_trips():
    redis = _FakeRedis()
    ks = RedisMemoryWriteFreezeKillSwitch(redis_client=redis, cache_ttl_s=60)
    await ks.set_write_freeze(tenant_id="t1", frozen=True, actor_id="ops", reason="incident")
    assert await ks.is_write_frozen(tenant_id="t1") is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "doc",
    [
        {"frozen": 0, "updated_at": "x", "actor_id": "a", "reason": "r"},  # non-bool (int) frozen
        {
            "frozen": "true",
            "updated_at": "x",
            "actor_id": "a",
            "reason": "r",
        },  # non-bool (str) frozen
        {"frozen": False, "actor_id": "a", "reason": "r"},  # missing updated_at
        {"frozen": False, "updated_at": "x", "reason": "r"},  # missing actor_id
        {"frozen": False, "updated_at": "x", "actor_id": "a"},  # missing reason
    ],
)
async def test_non_bool_or_missing_custody_fails_closed(doc):
    # Locked value-shape {frozen: bool, updated_at, actor_id, reason}: a non-bool
    # `frozen` (NOT bool()-coerced — `0` would fail OPEN) or ANY absent custody
    # field is malformed => fail-closed frozen (True).
    redis = _FakeRedis()
    redis.store[_write_freeze_key("t1")] = json.dumps(doc)
    ks = RedisMemoryWriteFreezeKillSwitch(redis_client=redis, cache_ttl_s=60)
    assert await ks.is_write_frozen(tenant_id="t1") is True


@pytest.mark.asyncio
async def test_malformed_poisons_cache_so_later_outage_within_ttl_fails_closed():
    # COMPOSED cross-call sequence (the read-probe blocker): a valid `False` primes
    # the cache, then a malformed current state must POISON it — so a subsequent
    # Redis OUTAGE within cache TTL serves frozen `True`, NOT the stale unfrozen
    # last-known-good. Malformed is NOT a legit value; it invalidates the prior grace.
    t0 = datetime(2026, 6, 1, tzinfo=UTC)
    redis = _FakeRedis()
    key = _write_freeze_key("t1")
    redis.store[key] = json.dumps(
        {"frozen": False, "updated_at": "x", "actor_id": "ops", "reason": "ok"}
    )
    ks = RedisMemoryWriteFreezeKillSwitch(redis_client=redis, cache_ttl_s=60, clock=_clock(t0))
    assert await ks.is_write_frozen(tenant_id="t1") is False  # (1) prime cache False
    redis.store[key] = "{not json"  # (2) malformed current state
    assert await ks.is_write_frozen(tenant_id="t1") is True  # fail-closed AND poisons cache
    redis.available = False  # (3) outage within TTL
    ks._clock = _clock(t0 + timedelta(seconds=30))
    assert await ks.is_write_frozen(tenant_id="t1") is True  # poisoned True, NOT stale False
