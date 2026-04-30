"""Sprint 3 T6 phase B — SLA classification.

Tests cover:
- BREACHED → audit_event(sla.breach) emitted; does NOT raise.
- GREEN → no audit emission.
- ledger row carries outcome="ok" regardless of SLA classification
  (SLA is informational; doesn't change outcome).
"""

from __future__ import annotations

import httpx
import respx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.core.audit import AuditStore, _audit_event
from cognic_agentos.core.config import Settings
from cognic_agentos.core.sla import SLAPolicy
from cognic_agentos.llm.concurrency import ProfileRateLimiter
from cognic_agentos.llm.gateway import LLMGateway
from cognic_agentos.llm.ledger import GatewayCallLedger
from cognic_agentos.llm.preflight import PreflightResolver


def _ok() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "model": "ollama/qwen3:8b",
            "choices": [{"message": {"content": "hi"}}],
        },
    )


class TestSLAClassification:
    @respx.mock
    async def test_breach_emits_audit_does_not_raise(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        gateway_engine: AsyncEngine,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        fast_sla_policy: SLAPolicy,
    ) -> None:
        """1ms budget → guaranteed breach. Asserts audit emitted +
        call still returns successfully (informational, not abort)."""
        respx.post("http://litellm.test:4000/chat/completions").mock(return_value=_ok())
        gateway = LLMGateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=fast_sla_policy,
        )
        response = await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-breach",
        )
        # Returned successfully despite breach.
        assert response.content == "hi"

        # Audit event emitted.
        async with gateway_engine.connect() as conn:
            result = await conn.execute(
                select(_audit_event).where(_audit_event.c.event_type == "sla.breach")
            )
            rows = list(result.fetchall())
        assert len(rows) == 1
        assert rows[0].payload["alias"] == "cognic-tier1-dev"
        assert rows[0].payload["preflight_model"] == "ollama/qwen3:8b"
        assert rows[0].payload["actual_model"] == "ollama/qwen3:8b"

        # Ledger row outcome="ok" — SLA breach is evidence, not abort.
        ledger_rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(ledger_rows) == 1
        assert ledger_rows[0].outcome == "ok"

    @respx.mock
    async def test_green_no_breach_audit(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        gateway_engine: AsyncEngine,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """30s budget → green. No sla.breach audit emitted."""
        respx.post("http://litellm.test:4000/chat/completions").mock(return_value=_ok())
        gateway = LLMGateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
        )
        await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-green",
        )
        async with gateway_engine.connect() as conn:
            result = await conn.execute(
                select(_audit_event).where(_audit_event.c.event_type == "sla.breach")
            )
            rows = list(result.fetchall())
        assert rows == []
