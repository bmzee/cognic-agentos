"""Sprint 13.6b T3 — gateway tenant-quota gate + actual-usage metering (ADR-018).

The quota gate sits at the F4 slot AFTER the kill-switch gate (precedence pin)
and BEFORE the rate-slot acquire — a tenant already over-quota refuses without
consuming concurrency (precision lock 2: tenant-aggregate, actuals-based, NOT a
per-call reservation). Post-completion the gateway records ACTUAL usage. Uses
the REAL QuotaEngine over a dict-fake Redis (no mock in the path).
"""

from __future__ import annotations

import typing
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
import respx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.config import Settings, build_settings_without_env_file
from cognic_agentos.core.emergency.kill_switches import KillSwitchEngine, _switch_key
from cognic_agentos.core.emergency.quotas import (
    QuotaEngine,
    _actual_tenant_key,
)
from cognic_agentos.core.sla import SLAPolicy
from cognic_agentos.llm.concurrency import ProfileRateLimiter
from cognic_agentos.llm.gateway import (
    GatewayKillSwitchActive,
    GatewayQuotaExhausted,
    GatewayTraceOutcome,
    LLMGateway,
)
from cognic_agentos.llm.ledger import GatewayCallLedger, _ledger_table
from cognic_agentos.llm.preflight import PreflightResolver

_CLOCK = lambda: datetime(2026, 6, 13, 12, 0, tzinfo=UTC)  # noqa: E731
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


def _quota_settings(limit: int = 1000) -> Settings:
    return build_settings_without_env_file().model_copy(
        update={
            "quota_tokens_per_tenant_per_day": limit,
            "quota_tokens_per_pack_per_day": limit,
        }
    )


def _quota_engine(redis: _FakeRedis, *, limit: int = 1000) -> QuotaEngine:
    return QuotaEngine(redis_client=redis, settings=_quota_settings(limit), clock=_CLOCK)


def _ok_litellm_response(usage: dict[str, int] | None = None) -> httpx.Response:
    body: dict[str, Any] = {
        "id": "resp-test",
        "object": "chat.completion",
        "model": "ollama/qwen3:8b",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "hello"},
                "finish_reason": "stop",
            }
        ],
    }
    if usage is not None:
        body["usage"] = usage
    return httpx.Response(200, json=body)


def _build_gateway(
    *,
    settings: Settings,
    ledger: GatewayCallLedger,
    audit_store: AuditStore,
    rate_limiter: ProfileRateLimiter,
    preflight: PreflightResolver,
    sla_policy: SLAPolicy,
    quota_engine: QuotaEngine | None = None,
    kill_switch_engine: KillSwitchEngine | None = None,
) -> LLMGateway:
    return LLMGateway(
        settings=settings,
        ledger=ledger,
        audit_store=audit_store,
        rate_limiter=rate_limiter,
        preflight=preflight,
        sla_policy=sla_policy,
        quota_engine=quota_engine,
        kill_switch_engine=kill_switch_engine,
    )


async def _ledger_outcomes(engine: AsyncEngine) -> list[str]:
    async with engine.connect() as conn:
        rows = (await conn.execute(select(_ledger_table.c.outcome))).all()
    return [r[0] for r in rows]


class TestQuotaGate:
    @respx.mock
    async def test_already_exhausted_refuses_before_slot_and_dispatch(
        self,
        monkeypatch: pytest.MonkeyPatch,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        gateway_engine: AsyncEngine,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        route = respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_ok_litellm_response()
        )
        acquire_calls: list[str] = []
        orig_acquire = rate_limiter.acquire

        def counting_acquire(*, profile: str) -> Any:
            acquire_calls.append(profile)
            return orig_acquire(profile=profile)

        monkeypatch.setattr(rate_limiter, "acquire", counting_acquire)

        redis = _FakeRedis()
        redis.store[_actual_tenant_key("t1", _WINDOW)] = "1000"  # already at limit
        gateway = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            quota_engine=_quota_engine(redis, limit=1000),
        )
        with pytest.raises(GatewayQuotaExhausted):
            await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-q-1",
                tenant_id="t1",
            )
        assert acquire_calls == []  # F4 slot — no rate slot consumed
        assert route.call_count == 0  # no dispatch
        assert await _ledger_outcomes(gateway_engine) == ["quota_exhausted"]

    @respx.mock
    async def test_under_limit_proceeds_and_records_actuals(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        gateway_engine: AsyncEngine,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_ok_litellm_response(usage={"prompt_tokens": 30, "completion_tokens": 12})
        )
        redis = _FakeRedis()
        gateway = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            quota_engine=_quota_engine(redis, limit=1000),
        )
        resp = await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-q-2",
            tenant_id="t1",
        )
        assert resp.content == "hello"
        # post-completion actuals INCRBY by prompt+completion.
        assert redis.store[_actual_tenant_key("t1", _WINDOW)] == "42"
        # ledger row carries the token columns.
        async with gateway_engine.connect() as conn:
            r = (
                await conn.execute(
                    select(_ledger_table.c.prompt_tokens, _ledger_table.c.completion_tokens).where(
                        _ledger_table.c.request_id == "req-q-2"
                    )
                )
            ).one()
        assert (r.prompt_tokens, r.completion_tokens) == (30, 12)

    @respx.mock
    async def test_kill_switch_takes_precedence_over_quota(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        gateway_engine: AsyncEngine,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_ok_litellm_response()
        )
        redis = _FakeRedis()
        redis.store[_actual_tenant_key("t1", _WINDOW)] = "1000"  # over quota
        redis.store[_switch_key("tenant_full", "t1")] = (
            '{"active": true, "updated_at": "x", "actor_id": "ops", "reason": "r"}'
        )
        gateway = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            quota_engine=_quota_engine(redis, limit=1000),
            kill_switch_engine=KillSwitchEngine(redis_client=redis, cache_ttl_s=60),
        )
        # BOTH killed and over-quota → kill_switch_active wins (gate ordering).
        with pytest.raises(GatewayKillSwitchActive):
            await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-q-3",
                tenant_id="t1",
            )

    @respx.mock
    async def test_no_tenant_skips_quota_gate(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        gateway_engine: AsyncEngine,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_ok_litellm_response()
        )
        redis = _FakeRedis()
        gateway = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            quota_engine=_quota_engine(redis, limit=1),  # tiny limit
        )
        # tenant_id=None → quota gate skipped (quotas are tenant-scoped).
        resp = await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-q-4",
            tenant_id=None,
        )
        assert resp.content == "hello"

    @respx.mock
    async def test_no_usage_in_response_skips_actuals(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        gateway_engine: AsyncEngine,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        # No `usage` key in the provider response → record_actuals skipped
        # (best-effort no-op), completion still succeeds.
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_ok_litellm_response(usage=None)
        )
        redis = _FakeRedis()
        gateway = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            quota_engine=_quota_engine(redis, limit=1000),
        )
        resp = await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-q-6",
            tenant_id="t1",
        )
        assert resp.content == "hello"
        assert _actual_tenant_key("t1", _WINDOW) not in redis.store  # no actuals incremented

    @respx.mock
    async def test_actuals_metering_failure_does_not_fail_completion(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        gateway_engine: AsyncEngine,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        # record_actuals raises (Redis incrby down) AFTER a delivered
        # completion → the completion still succeeds (best-effort metering).
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_ok_litellm_response(usage={"prompt_tokens": 5, "completion_tokens": 5})
        )

        class _IncrFailsRedis(_FakeRedis):
            async def incrby(self, key: str, amount: int) -> int:
                raise ConnectionError("redis down on actuals incrby")

        gateway = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            quota_engine=_quota_engine(_IncrFailsRedis(), limit=1000),
        )
        resp = await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-q-7",
            tenant_id="t1",
        )
        assert resp.content == "hello"  # metering failure did NOT fail the call


class TestEngineAbsentByteCompat:
    @respx.mock
    async def test_none_quota_engine_proceeds(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        gateway_engine: AsyncEngine,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_ok_litellm_response()
        )
        gateway = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            quota_engine=None,  # default — pre-13.6b byte-compat
        )
        resp = await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-q-5",
            tenant_id="t1",
        )
        assert resp.content == "hello"
        assert await _ledger_outcomes(gateway_engine) == ["ok"]


class TestVocabulary:
    def test_trace_outcome_has_quota_exhausted(self) -> None:
        values = typing.get_args(GatewayTraceOutcome)
        assert "quota_exhausted" in values
        assert len(values) == 13  # 12 (incl. kill_switch_active) + quota_exhausted
