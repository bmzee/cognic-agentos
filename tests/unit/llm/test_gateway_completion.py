"""Sprint 3 T6 phase B — LLMGateway.completion happy + denial paths.

Test posture (critical-controls per AGENTS.md):
- Happy path: tier1 → cognic-tier1-dev → ollama. Asserts ledger row
  written BEFORE return, outcome="ok", external=False, no audit_event.
- Denial path: cloud upstream + flag off → audit(gateway.cloud_policy_
  denied, post_response=False) + CloudPolicyViolationError; NO LiteLLM
  HTTP call made; ledger row best-effort outcome="denied".

Uses ``respx`` to mock the LiteLLM HTTP shape — no live LiteLLM
required; tests run hermetically.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest
import respx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.core.audit import AuditStore, _audit_event
from cognic_agentos.core.config import Settings
from cognic_agentos.core.guardrails import GuardrailPipeline
from cognic_agentos.core.sla import SLAPolicy
from cognic_agentos.llm.concurrency import ProfileRateLimiter
from cognic_agentos.llm.gateway import (
    GatewayResponse,
    LLMGateway,
)
from cognic_agentos.llm.ledger import GatewayCallLedger
from cognic_agentos.llm.policy import CloudPolicyViolationError
from cognic_agentos.llm.preflight import PreflightResolver


def _build_gateway(
    *,
    settings: Settings,
    ledger: GatewayCallLedger,
    audit_store: AuditStore,
    rate_limiter: ProfileRateLimiter,
    preflight: PreflightResolver,
    sla_policy: SLAPolicy,
    input_pipeline: GuardrailPipeline | None = None,
    output_pipeline: GuardrailPipeline | None = None,
) -> LLMGateway:
    return LLMGateway(
        settings=settings,
        ledger=ledger,
        audit_store=audit_store,
        rate_limiter=rate_limiter,
        preflight=preflight,
        sla_policy=sla_policy,
        input_pipeline=input_pipeline,
        output_pipeline=output_pipeline,
        # Use the default httpx.AsyncClient — respx patches it
        # transport-side via @respx.mock.
    )


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


# ---------------------------------------------------------------------------
# TestHappyPath — tier1 → ollama → ok.
# ---------------------------------------------------------------------------


class TestHappyPath:
    @respx.mock
    async def test_self_hosted_call_returns_response_and_writes_ledger(
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
            return_value=_ok_litellm_response("ollama/qwen3:8b")
        )

        gateway = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
        )

        response = await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-happy-1",
            tenant_id="tenant-a",
        )

        # GatewayResponse shape.
        assert isinstance(response, GatewayResponse)
        assert response.content == "hello"
        assert response.upstream_model == "ollama/qwen3:8b"
        assert response.api_base == "http://ollama:11434"
        assert response.external is False
        assert response.request_id == "req-happy-1"
        assert response.tier == "tier1"
        assert response.latency_ms >= 0

        # Ledger row written with outcome="ok" + provenance="resolved".
        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        ledger_row = rows[0]
        assert ledger_row.request_id == "req-happy-1"
        assert ledger_row.tenant_id == "tenant-a"
        assert ledger_row.outcome == "ok"
        assert ledger_row.provenance == "resolved"
        assert ledger_row.upstream_model == "ollama/qwen3:8b"
        assert ledger_row.upstream_api_base == "http://ollama:11434"
        assert ledger_row.external is False
        assert ledger_row.tier == "tier1"

    @respx.mock
    async def test_no_audit_events_emitted_on_happy_path(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        gateway_engine: AsyncEngine,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """Happy path emits NO audit_event rows. SLA green; no drift;
        no policy denial; no guardrail trip; no provenance gap."""
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_ok_litellm_response("ollama/qwen3:8b")
        )
        gateway = _build_gateway(
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
            request_id="req-no-audit",
        )

        # Check audit_event table — should be empty.
        async with gateway_engine.connect() as conn:
            result = await conn.execute(select(_audit_event))
            audit_rows = list(result.fetchall())
        assert audit_rows == [], f"happy path emitted {len(audit_rows)} unexpected audit events"


# ---------------------------------------------------------------------------
# TestPreDispatchDenialPath — cloud upstream + flag off.
# ---------------------------------------------------------------------------


class TestPreDispatchDenialPath:
    @respx.mock
    async def test_cloud_upstream_with_flag_off_denies_pre_dispatch(
        self,
        gateway_ledger: GatewayCallLedger,
        gateway_engine: AsyncEngine,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        cloud_openai_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
        make_settings: Callable[..., Settings],
    ) -> None:
        """Pre-dispatch denial path: cloud upstream classified as
        external; default settings refuse it. Asserts:

        - CloudPolicyViolationError raised.
        - No LiteLLM HTTP call (respx records zero requests).
        - audit_event(gateway.cloud_policy_denied, post_response=False)
          emitted with the policy decision payload.
        - Ledger row best-effort outcome="denied",
          provenance="no_dispatch", carrying the INTENDED preflight
          identity.
        """
        # Default settings: allow_external_llm=False, etc.
        settings = make_settings()
        # Mock the LiteLLM endpoint. respx will let us assert no calls
        # were made.
        litellm_route = respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_ok_litellm_response()
        )

        gateway = _build_gateway(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=cloud_openai_resolver,  # tier1 → openai/gpt-5.4 cloud
            sla_policy=default_sla_policy,
        )

        with pytest.raises(CloudPolicyViolationError) as exc_info:
            await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-denied",
            )

        # Decision payload exposes the denial reason.
        assert "allow_external_llm=False" in exc_info.value.decision.reason
        assert exc_info.value.decision.post_response is False

        # No LiteLLM HTTP call.
        assert litellm_route.call_count == 0, "pre-dispatch denial must NOT reach LiteLLM"

        # Audit event emitted.
        async with gateway_engine.connect() as conn:
            result = await conn.execute(select(_audit_event))
            audit_rows = list(result.fetchall())
        assert len(audit_rows) == 1
        event = audit_rows[0]
        assert event.event_type == "gateway.cloud_policy_denied"
        # iso_controls is a JSON column; SQLite stores native list.
        assert "ISO42001.A.9.2" in event.iso_controls
        # Payload carries post_response=False.
        assert event.payload["post_response"] is False

        # Ledger row written best-effort with provenance="no_dispatch".
        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        ledger_row = rows[0]
        assert ledger_row.outcome == "denied"
        assert ledger_row.provenance == "no_dispatch"
        assert ledger_row.upstream_model == "openai/gpt-5.4"  # preflight identity
        assert ledger_row.external is True

    @respx.mock
    async def test_cloud_upstream_with_flag_on_and_provider_allowed_passes(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        cloud_openai_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
        make_settings: Callable[..., Settings],
    ) -> None:
        """When the operator explicitly allows external + the provider
        is on the allow-list, the pre-call policy passes and the call
        proceeds normally."""
        settings = make_settings(
            {
                "allow_external_llm": True,
                "policy_mode": "cloud_openai",
                "allowed_providers": ["openai"],
            }
        )
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_ok_litellm_response("openai/gpt-5.4")
        )

        gateway = _build_gateway(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=cloud_openai_resolver,
            sla_policy=default_sla_policy,
        )

        response = await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-cloud-allowed",
        )

        assert response.upstream_model == "openai/gpt-5.4"
        assert response.external is True

        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].outcome == "ok"
        assert rows[0].provenance == "resolved"
        assert rows[0].external is True
