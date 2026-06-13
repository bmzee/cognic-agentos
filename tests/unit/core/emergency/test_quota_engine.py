"""Sprint 13.6b T1 — QuotaEngine decomposed atomic-counter meter (ADR-018).

Pins the F1 decomposed-counter contract per the LOCKED spec
``docs/superpowers/specs/2026-06-13-sprint-13.6b-quotas-design.md``:
``would_admit`` does INCRBY-first-check-own-cumulative + rollback;
``release_reservation`` is GETDEL-first (deny-safe + idempotent); the
duplicate-task_id contract (idempotent same-shape / fail-loud mismatch); the
fail-closed + partial-increment deny-safe posture (§3.5); and the gateway
tenant-aggregate actuals gate (precision lock 2). NOT Lua — decomposed atomic
counters over a deterministic dict-fake.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.emergency.quotas import (
    QuotaEngine,
    QuotaReservationConflict,
    _actual_tenant_key,
    _reservation_key,
    _reserved_pack_key,
    _reserved_tenant_key,
)
from cognic_agentos.core.scheduler._seams import QuotaInterrogator


class _FakeQuotaRedis:
    """Deterministic dict-fake implementing the six _AsyncRedisQuotaLike ops.
    Single-loop asyncio → deterministic interleaving; atomic per-op."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.fail = False

    async def get(self, key: str) -> Any:
        if self.fail:
            raise ConnectionError("redis down")
        return self.store.get(key)

    async def set(self, key: str, value: Any, **kwargs: Any) -> Any:
        if self.fail:
            raise ConnectionError("redis down")
        self.store[key] = value

    async def incrby(self, key: str, amount: int) -> int:
        if self.fail:
            raise ConnectionError("redis down")
        new = int(self.store.get(key, "0")) + amount
        self.store[key] = str(new)
        return new

    async def decrby(self, key: str, amount: int) -> int:
        if self.fail:
            raise ConnectionError("redis down")
        new = int(self.store.get(key, "0")) - amount
        self.store[key] = str(new)
        return new

    async def getdel(self, key: str) -> Any:
        if self.fail:
            raise ConnectionError("redis down")
        return self.store.pop(key, None)

    async def expire(self, key: str, seconds: int) -> Any:
        return None


def _settings(tenant_limit: int = 1000, pack_limit: int = 600) -> Any:
    return build_settings_without_env_file().model_copy(
        update={
            "quota_tokens_per_tenant_per_day": tenant_limit,
            "quota_tokens_per_pack_per_day": pack_limit,
        }
    )


def _engine(redis: _FakeQuotaRedis, **kw: int) -> QuotaEngine:
    return QuotaEngine(
        redis_client=redis,
        settings=_settings(**kw),
        clock=lambda: datetime(2026, 6, 13, 12, 0, tzinfo=UTC),
    )


class TestSeamConformance:
    def test_structurally_conforms_to_quota_interrogator(self) -> None:
        assert isinstance(_engine(_FakeQuotaRedis()), QuotaInterrogator)


class TestWouldAdmitReserve:
    async def test_under_limit_reserves_and_returns_true(self) -> None:
        redis = _FakeQuotaRedis()
        eng = _engine(redis)
        tid = uuid.uuid4()
        assert (
            await eng.would_admit(task_id=tid, tenant_id="t1", pack_id="p1", estimated_tokens=400)
            is True
        )
        assert redis.store[_reserved_tenant_key("t1", "20260613")] == "400"
        assert redis.store[_reserved_pack_key("t1", "p1", "20260613")] == "400"
        assert _reservation_key(tid) in redis.store

    async def test_over_tenant_limit_rolls_back_and_returns_false(self) -> None:
        redis = _FakeQuotaRedis()
        eng = _engine(redis, tenant_limit=500)
        assert (
            await eng.would_admit(
                task_id=uuid.uuid4(), tenant_id="t1", pack_id="p1", estimated_tokens=600
            )
            is False
        )
        assert redis.store.get(_reserved_tenant_key("t1", "20260613"), "0") == "0"
        assert all(not k.startswith("cognic:quota:reservation:") for k in redis.store)

    async def test_actuals_count_against_the_tenant_limit(self) -> None:
        redis = _FakeQuotaRedis()
        redis.store[_actual_tenant_key("t1", "20260613")] = "700"
        eng = _engine(redis, tenant_limit=1000)
        assert (
            await eng.would_admit(
                task_id=uuid.uuid4(), tenant_id="t1", pack_id="p1", estimated_tokens=400
            )
            is False
        )

    async def test_two_reservations_crossing_the_line_resolve_correctly(self) -> None:
        redis = _FakeQuotaRedis()
        eng = _engine(redis, tenant_limit=1000)
        assert (
            await eng.would_admit(
                task_id=uuid.uuid4(), tenant_id="t1", pack_id="p1", estimated_tokens=400
            )
            is True
        )
        assert (
            await eng.would_admit(
                task_id=uuid.uuid4(), tenant_id="t1", pack_id="p1", estimated_tokens=700
            )
            is False
        )
        assert redis.store[_reserved_tenant_key("t1", "20260613")] == "400"

    async def test_over_pack_limit_refuses(self) -> None:
        redis = _FakeQuotaRedis()
        eng = _engine(redis, tenant_limit=10000, pack_limit=300)
        assert (
            await eng.would_admit(
                task_id=uuid.uuid4(), tenant_id="t1", pack_id="p1", estimated_tokens=400
            )
            is False
        )


class TestDuplicateTaskId:
    async def test_same_shape_is_idempotent_no_second_increment(self) -> None:
        redis = _FakeQuotaRedis()
        eng = _engine(redis)
        tid = uuid.uuid4()
        assert (
            await eng.would_admit(task_id=tid, tenant_id="t1", pack_id="p1", estimated_tokens=400)
            is True
        )
        assert (
            await eng.would_admit(task_id=tid, tenant_id="t1", pack_id="p1", estimated_tokens=400)
            is True
        )
        assert redis.store[_reserved_tenant_key("t1", "20260613")] == "400"  # NOT 800

    async def test_mismatched_shape_fails_loud(self) -> None:
        redis = _FakeQuotaRedis()
        eng = _engine(redis)
        tid = uuid.uuid4()
        await eng.would_admit(task_id=tid, tenant_id="t1", pack_id="p1", estimated_tokens=400)
        with pytest.raises(QuotaReservationConflict):
            await eng.would_admit(task_id=tid, tenant_id="t1", pack_id="p2", estimated_tokens=400)


class TestRelease:
    async def test_release_decrements_and_is_idempotent(self) -> None:
        redis = _FakeQuotaRedis()
        eng = _engine(redis)
        tid = uuid.uuid4()
        await eng.would_admit(task_id=tid, tenant_id="t1", pack_id="p1", estimated_tokens=400)
        await eng.release_reservation(tid)
        assert redis.store[_reserved_tenant_key("t1", "20260613")] == "0"
        assert _reservation_key(tid) not in redis.store
        await eng.release_reservation(tid)  # second release = no-op
        assert redis.store[_reserved_tenant_key("t1", "20260613")] == "0"

    async def test_release_unknown_task_id_is_noop(self) -> None:
        eng = _engine(_FakeQuotaRedis())
        await eng.release_reservation(uuid.uuid4())  # must not raise


class TestFailClosed:
    async def test_redis_error_refuses_immediately(self) -> None:
        redis = _FakeQuotaRedis()
        redis.fail = True
        eng = _engine(redis)
        assert (
            await eng.would_admit(
                task_id=uuid.uuid4(), tenant_id="t1", pack_id="p1", estimated_tokens=1
            )
            is False
        )

    async def test_partial_increment_leak_is_deny_safe(self) -> None:
        redis = _FakeQuotaRedis()
        eng = _engine(redis)
        calls = {"n": 0}
        real_incrby = redis.incrby

        async def flaky_incrby(key: str, amount: int) -> int:
            calls["n"] += 1
            if calls["n"] == 2:  # the pack INCRBY
                raise ConnectionError("redis down mid-reserve")
            return await real_incrby(key, amount)

        redis.incrby = flaky_incrby  # type: ignore[method-assign]
        assert (
            await eng.would_admit(
                task_id=uuid.uuid4(), tenant_id="t1", pack_id="p1", estimated_tokens=400
            )
            is False
        )
        assert (
            redis.store[_reserved_tenant_key("t1", "20260613")] == "400"
        )  # leaked HIGH = deny-safe
        assert all(not k.startswith("cognic:quota:reservation:") for k in redis.store)


class TestGatewayActualsAndGate:
    async def test_record_actuals_increments_tenant_counter(self) -> None:
        redis = _FakeQuotaRedis()
        eng = _engine(redis)
        await eng.record_actuals(tenant_id="t1", tokens=250)
        assert redis.store[_actual_tenant_key("t1", "20260613")] == "250"

    async def test_record_actuals_zero_is_noop(self) -> None:
        redis = _FakeQuotaRedis()
        eng = _engine(redis)
        await eng.record_actuals(tenant_id="t1", tokens=0)
        assert _actual_tenant_key("t1", "20260613") not in redis.store

    async def test_check_gateway_admit_refuses_when_already_exhausted(self) -> None:
        redis = _FakeQuotaRedis()
        redis.store[_actual_tenant_key("t1", "20260613")] = "900"
        redis.store[_reserved_tenant_key("t1", "20260613")] = "150"
        eng = _engine(redis, tenant_limit=1000)
        assert await eng.check_gateway_admit(tenant_id="t1") is False

    async def test_check_gateway_admit_allows_under_limit(self) -> None:
        eng = _engine(_FakeQuotaRedis(), tenant_limit=1000)
        assert await eng.check_gateway_admit(tenant_id="t1") is True

    async def test_check_gateway_admit_redis_error_fails_closed_refuse(self) -> None:
        redis = _FakeQuotaRedis()
        redis.fail = True
        eng = _engine(redis)
        assert await eng.check_gateway_admit(tenant_id="t1") is False

    async def test_usage_view_returns_limit_actuals_reserved(self) -> None:
        redis = _FakeQuotaRedis()
        redis.store[_actual_tenant_key("t1", "20260613")] = "300"
        redis.store[_reserved_tenant_key("t1", "20260613")] = "120"
        eng = _engine(redis, tenant_limit=1000)
        view = await eng.usage_view(tenant_id="t1")
        assert view == {"tenant_limit": 1000, "actuals": 300, "reserved": 120}


class _FakeResolver:
    """Minimal TenantConfigResolver shape — resolves the tighten-only ceiling
    per field (a tenant has LOWERED its budget below the Settings default)."""

    def __init__(self, *, tenant_limit: int, pack_limit: int) -> None:
        self._tenant = tenant_limit
        self._pack = pack_limit

    async def effective(self, field_key: str, tenant_id: str) -> int:
        return self._tenant if "tenant" in field_key else self._pack


class TestResolverPath:
    async def test_resolver_tightened_ceiling_overrides_settings_default(self) -> None:
        # Settings says 1000/600; the tenant overlay tightened to 500/300.
        redis = _FakeQuotaRedis()
        eng = QuotaEngine(
            redis_client=redis,
            settings=_settings(tenant_limit=1000, pack_limit=600),
            resolver=_FakeResolver(tenant_limit=500, pack_limit=300),  # type: ignore[arg-type]
            clock=lambda: datetime(2026, 6, 13, 12, 0, tzinfo=UTC),
        )
        # 600 > the resolver's 500 tenant ceiling → refuse (not the 1000 default).
        assert (
            await eng.would_admit(
                task_id=uuid.uuid4(), tenant_id="t1", pack_id="p1", estimated_tokens=600
            )
            is False
        )
        view = await eng.usage_view(tenant_id="t1")
        assert view["tenant_limit"] == 500


class TestReleaseRedisError:
    async def test_release_swallows_redis_error_and_never_raises(self) -> None:
        redis = _FakeQuotaRedis()
        eng = _engine(redis)
        tid = uuid.uuid4()
        await eng.would_admit(task_id=tid, tenant_id="t1", pack_id="p1", estimated_tokens=400)
        redis.fail = True
        # GETDEL raises → the except arm logs + returns; the leaked-high reserved
        # counter is deny-safe + TTL-heals. MUST NOT raise.
        await eng.release_reservation(tid)


class TestDefaultClock:
    def test_utcnow_default_is_tz_aware(self) -> None:
        from cognic_agentos.core.emergency.quotas import _utcnow

        now = _utcnow()
        assert now.tzinfo is not None
        assert now.utcoffset() is not None

    async def test_engine_without_injected_clock_uses_utcnow(self) -> None:
        # Constructs with the default clock (no clock= kwarg) — exercises the
        # _utcnow default path end-to-end.
        redis = _FakeQuotaRedis()
        eng = QuotaEngine(redis_client=redis, settings=_settings(tenant_limit=1000, pack_limit=600))
        assert (
            await eng.would_admit(
                task_id=uuid.uuid4(), tenant_id="t1", pack_id="p1", estimated_tokens=10
            )
            is True
        )
