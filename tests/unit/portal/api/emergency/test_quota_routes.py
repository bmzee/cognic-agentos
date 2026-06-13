"""Sprint 13.6b T5 — read-only quota portal surface (ADR-018).

`GET /api/v1/emergency/quotas?tenant=...` behind `quota.read` returns the
tenant's resolved limit + current usage (actuals + reserved) + usage_pct from
the QuotaEngine read counters. No override / write surface (deferred).
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from cognic_agentos.core.config import Settings, build_settings_without_env_file
from cognic_agentos.core.emergency.quotas import (
    QuotaEngine,
    _actual_tenant_key,
    _reserved_tenant_key,
)
from cognic_agentos.portal.api.emergency.quota_routes import build_quota_routes
from cognic_agentos.portal.rbac.actor import Actor

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


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


def _actor(*, scopes: frozenset[str] = frozenset({"quota.read"})) -> Actor:
    return Actor(
        subject="examiner@bank.example",
        tenant_id="t1",
        scopes=scopes,  # type: ignore[arg-type]
        actor_type="human",
    )


def _settings(limit: int = 1000) -> Settings:
    return build_settings_without_env_file().model_copy(
        update={
            "quota_tokens_per_tenant_per_day": limit,
            "quota_tokens_per_pack_per_day": limit,
        }
    )


def _engine(redis: _FakeRedis, *, limit: int = 1000) -> QuotaEngine:
    from datetime import UTC, datetime

    return QuotaEngine(
        redis_client=redis,
        settings=_settings(limit),
        clock=lambda: datetime(2026, 6, 13, 12, 0, tzinfo=UTC),
    )


def _client(actor: Actor, engine: QuotaEngine) -> AsyncClient:
    app = FastAPI()
    app.state.actor_binder = _StubBinder(actor)
    app.state.ui_event_broker = None
    app.include_router(build_quota_routes(quota_engine=engine, settings=_settings()))
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://t")


class TestQuotaRead:
    async def test_returns_limit_usage_and_pct(self) -> None:
        redis = _FakeRedis()
        redis.store[_actual_tenant_key("t1", _WINDOW)] = "300"
        redis.store[_reserved_tenant_key("t1", _WINDOW)] = "120"
        async with _client(_actor(), _engine(redis, limit=1000)) as client:
            resp = await client.get("/api/v1/emergency/quotas", params={"tenant": "t1"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["tenant_limit"] == 1000
        assert body["actuals"] == 300
        assert body["reserved"] == 120
        assert body["usage_pct"] == 42.0  # (300 + 120) / 1000 * 100

    async def test_requires_quota_read_scope(self) -> None:
        async with _client(
            _actor(scopes=frozenset({"emergency.read"})), _engine(_FakeRedis())
        ) as client:
            resp = await client.get("/api/v1/emergency/quotas", params={"tenant": "t1"})
        assert resp.status_code == 403
        assert resp.json()["detail"]["reason"] == "scope_not_held"

    async def test_tenant_param_required(self) -> None:
        async with _client(_actor(), _engine(_FakeRedis())) as client:
            resp = await client.get("/api/v1/emergency/quotas")
        assert resp.status_code == 422

    async def test_zero_usage_pct(self) -> None:
        async with _client(_actor(), _engine(_FakeRedis(), limit=1000)) as client:
            resp = await client.get("/api/v1/emergency/quotas", params={"tenant": "t1"})
        assert resp.json()["usage_pct"] == 0.0
