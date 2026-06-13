"""Sprint 13.6 T4 — gateway emergency gate at the F4 slot (ADR-018).

The kill-switch gate sits AFTER preflight + pre-call cloud-policy (routing
facts known) and BEFORE the rate-slot acquire — a killed call must not
consume concurrency capacity (spec lock F4). Engine-absent (the default)
preserves the pre-13.6 pipeline byte-for-byte. Uses the REAL
``KillSwitchEngine`` over a fake Redis (no mock engine in the path).
"""

from __future__ import annotations

import typing
from typing import Any

import httpx
import pytest
import respx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.config import Settings
from cognic_agentos.core.emergency.kill_switches import KillSwitchEngine, _switch_key
from cognic_agentos.core.sla import SLAPolicy
from cognic_agentos.llm.concurrency import ProfileRateLimiter
from cognic_agentos.llm.gateway import (
    GatewayKillSwitchActive,
    GatewayTraceOutcome,
    LLMGateway,
)
from cognic_agentos.llm.ledger import GatewayCallLedger, GatewayCallRow, _ledger_table
from cognic_agentos.llm.preflight import PreflightResolver


class _FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    async def get(self, key: str) -> Any:
        return self.store.get(key)

    async def set(self, key: str, value: Any, **kwargs: Any) -> Any:
        self.store[key] = value


def _active_doc() -> str:
    return (
        '{"active": true, "updated_at": "2026-06-13T00:00:00+00:00",'
        ' "actor_id": "ops-1", "reason": "incident"}'
    )


def _engine_with(*switches: tuple[str, str]) -> KillSwitchEngine:
    redis = _FakeRedis()
    for class_, scope_key in switches:
        redis.store[_switch_key(class_, scope_key)] = _active_doc()  # type: ignore[arg-type]
    return KillSwitchEngine(redis_client=redis, cache_ttl_s=60)


def _ok_litellm_response(model: str = "ollama/qwen3:8b") -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "id": "resp-test",
            "object": "chat.completion",
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "hello"},
                    "finish_reason": "stop",
                }
            ],
        },
    )


def _build_gateway(
    *,
    settings: Settings,
    ledger: GatewayCallLedger,
    audit_store: AuditStore,
    rate_limiter: ProfileRateLimiter,
    preflight: PreflightResolver,
    sla_policy: SLAPolicy,
    kill_switch_engine: KillSwitchEngine | None = None,
) -> LLMGateway:
    return LLMGateway(
        settings=settings,
        ledger=ledger,
        audit_store=audit_store,
        rate_limiter=rate_limiter,
        preflight=preflight,
        sla_policy=sla_policy,
        kill_switch_engine=kill_switch_engine,
    )


async def _ledger_outcomes(engine: AsyncEngine) -> list[str]:
    async with engine.connect() as conn:
        rows = (await conn.execute(select(_ledger_table.c.outcome))).all()
    return [r[0] for r in rows]


class TestModelKill:
    @respx.mock
    async def test_model_kill_refuses_before_slot_and_dispatch(
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

        gateway = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            kill_switch_engine=_engine_with(("model", "cognic-tier1-dev")),
        )
        with pytest.raises(GatewayKillSwitchActive) as exc_info:
            await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-ks-1",
                tenant_id="t-1",
            )
        assert exc_info.value.tripped_class == "model"
        # F4 slot: NO rate-slot consumed, NO dispatch attempted.
        assert acquire_calls == []
        assert route.call_count == 0
        # Best-effort ledger visibility.
        assert await _ledger_outcomes(gateway_engine) == ["kill_switch_active"]


class TestTenantFullKill:
    @respx.mock
    async def test_tenant_full_kill_refuses(
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
            kill_switch_engine=_engine_with(("tenant_full", "t-1")),
        )
        with pytest.raises(GatewayKillSwitchActive) as exc_info:
            await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-ks-2",
                tenant_id="t-1",
            )
        assert exc_info.value.tripped_class == "tenant_full"

    @respx.mock
    async def test_other_tenant_unaffected(
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
            kill_switch_engine=_engine_with(("tenant_full", "t-1")),
        )
        resp = await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-ks-3",
            tenant_id="t-2",
        )
        assert resp.content == "hello"


class TestCloudRoutingKill:
    @respx.mock
    async def test_cloud_kill_does_not_touch_self_hosted_calls(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        gateway_engine: AsyncEngine,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        # cloud_routing active, but the dev resolver is self-hosted
        # (external=False) — the call proceeds.
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
            kill_switch_engine=_engine_with(("cloud_routing", "global")),
        )
        resp = await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-ks-4",
            tenant_id="t-1",
        )
        assert resp.content == "hello"


class TestEngineAbsentByteCompat:
    @respx.mock
    async def test_none_engine_never_consults_even_with_active_switches(
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
            kill_switch_engine=None,  # the default — pre-13.6 byte-compat
        )
        resp = await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-ks-5",
            tenant_id="t-1",
        )
        assert resp.content == "hello"
        assert await _ledger_outcomes(gateway_engine) == ["ok"]


class TestVocabulary:
    def test_trace_outcome_has_kill_switch_active(self) -> None:
        values = typing.get_args(GatewayTraceOutcome)
        assert "kill_switch_active" in values
        assert len(values) == 12  # 11 pre-13.6 + kill_switch_active

    def test_ledger_accepts_kill_switch_active_outcome(self) -> None:
        import datetime as _dt
        import uuid

        row = GatewayCallRow(
            id=uuid.uuid4(),
            ts=_dt.datetime.now(_dt.UTC),
            request_id="req-ks-6",
            tenant_id="t-1",
            tier="tier1",
            litellm_alias="cognic-tier1-dev",
            upstream_model="ollama/qwen3:8b",
            upstream_api_base="http://ollama:11434",
            external=False,
            provenance="resolved",
            latency_ms=1,
            outcome="kill_switch_active",
            model_id=None,
        )
        assert row.outcome == "kill_switch_active"
