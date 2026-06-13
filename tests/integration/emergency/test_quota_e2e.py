"""Sprint 13.6b T6 (ADR-018) — quota cross-surface e2e (dict-fake Redis).

Proves the reserve→actuals→exhaust→release lifecycle across the two planes a
single QuotaEngine serves: the scheduler-plane reservation (``would_admit`` /
``release_reservation``) and the gateway-plane actuals + gate
(``record_actuals`` / ``check_gateway_admit``). One engine, one tenant; the
reserved + actuals counter families compose into the admission decision.

The cross-process atomicity itself is proved against a REAL Redis in the
env-gated ``test_quota_redis_atomicity.py``; this e2e proves the
lifecycle composition deterministically.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.emergency.quotas import (
    QuotaEngine,
    _actual_tenant_key,
    _reserved_tenant_key,
)

_WINDOW = "20260613"


class _FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    async def get(self, key: str) -> Any:
        return self.store.get(key)

    async def set(self, key: str, value: Any, **kwargs: Any) -> Any:
        self.store[key] = value

    async def incrby(self, key: str, amount: int) -> int:
        new = int(self.store.get(key, "0")) + amount
        self.store[key] = str(new)
        return new

    async def decrby(self, key: str, amount: int) -> int:
        new = int(self.store.get(key, "0")) - amount
        self.store[key] = str(new)
        return new

    async def getdel(self, key: str) -> Any:
        return self.store.pop(key, None)

    async def expire(self, key: str, seconds: int) -> Any:
        return None


def _engine(redis: _FakeRedis, *, limit: int) -> QuotaEngine:
    settings = build_settings_without_env_file().model_copy(
        update={
            "quota_tokens_per_tenant_per_day": limit,
            "quota_tokens_per_pack_per_day": limit,
        }
    )
    return QuotaEngine(
        redis_client=redis,
        settings=settings,
        clock=lambda: datetime(2026, 6, 13, 12, 0, tzinfo=UTC),
    )


@pytest.mark.asyncio
async def test_reserve_actuals_exhaust_release_lifecycle() -> None:
    redis = _FakeRedis()
    eng = _engine(redis, limit=1000)
    tid = uuid.uuid4()

    # 1. scheduler reserves 400 → admitted.
    assert await eng.would_admit(task_id=tid, tenant_id="t1", pack_id="p1", estimated_tokens=400)
    assert redis.store[_reserved_tenant_key("t1", _WINDOW)] == "400"

    # 2. gateway records 500 ACTUAL tokens for the same tenant.
    await eng.record_actuals(tenant_id="t1", tokens=500)
    assert redis.store[_actual_tenant_key("t1", _WINDOW)] == "500"

    # 3. the gateway gate now sees 500 actuals + 400 reserved = 900 < 1000 → admit.
    assert await eng.check_gateway_admit(tenant_id="t1") is True

    # 4. one more gateway call pushes actuals to 950 (500+450) → 950+400=1350 ≥
    #    1000 → the gate refuses (already exhausted).
    await eng.record_actuals(tenant_id="t1", tokens=450)
    assert await eng.check_gateway_admit(tenant_id="t1") is False

    # 5. a fresh scheduler reservation also refuses (actuals + reserved + new
    #    request over the limit) and rolls back.
    assert not await eng.would_admit(
        task_id=uuid.uuid4(), tenant_id="t1", pack_id="p1", estimated_tokens=200
    )
    assert redis.store[_reserved_tenant_key("t1", _WINDOW)] == "400"  # rolled back

    # 6. the task completes → release frees its 400; the gate is still over
    #    (actuals 950 alone ≥ ... no, 950 < 1000) so a small call admits again.
    await eng.release_reservation(tid)
    assert redis.store[_reserved_tenant_key("t1", _WINDOW)] == "0"
    assert await eng.check_gateway_admit(tenant_id="t1") is True  # 950 + 0 < 1000
