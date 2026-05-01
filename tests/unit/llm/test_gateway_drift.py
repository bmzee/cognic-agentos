"""Sprint 3 T6 phase B — drift detection (Round-2 + Round-7 P1).

Three subtests pin Round-2 reviewer-P1#1 + Round-4 reviewer-P1:

- Drift + actual allowed → drift event + ledger outcome="drift"; no
  raise.
- Drift + actual denied → drift event + post-response cloud_policy_
  denied event + raise CloudPolicyViolationError.
- External-to-external drift (preflight openai allowed, actual
  bedrock not allowed) → same path as above, pins that the post-
  response recheck closes the silent-drift class Round-2 P1#1
  flagged.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest
import respx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.core.audit import AuditStore, _audit_event
from cognic_agentos.core.config import Settings
from cognic_agentos.core.sla import SLAPolicy
from cognic_agentos.llm.concurrency import ProfileRateLimiter
from cognic_agentos.llm.gateway import LLMGateway
from cognic_agentos.llm.ledger import GatewayCallLedger
from cognic_agentos.llm.policy import CloudPolicyViolationError
from cognic_agentos.llm.preflight import PreflightResolver


def _resp(model: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "model": model,
            "choices": [{"message": {"content": "hi"}}],
        },
    )


def _multi_alias_resolver(
    make_resolver: Callable[[list[dict[str, Any]]], PreflightResolver],
) -> PreflightResolver:
    """Resolver with both cognic-tier1-cloud-openai (openai/gpt-5.4)
    AND cognic-tier1-cloud-azure (azure/gpt-4o) declared so reverse_
    lookup resolves drift targets to a known shape."""
    return make_resolver(
        [
            {
                "model_name": "cognic-tier1-cloud-openai",
                "litellm_params": {"model": "openai/gpt-5.4", "api_key": "sk"},
            },
            {
                "model_name": "cognic-tier2-cloud-openai",
                "litellm_params": {"model": "openai/gpt-5.4", "api_key": "sk"},
            },
            {
                "model_name": "cognic-tier1-cloud-azure",
                "litellm_params": {"model": "azure/gpt-4o", "api_key": "az"},
            },
            {
                "model_name": "cognic-tier1-cloud-bedrock",
                "litellm_params": {"model": "bedrock/anthropic.claude-3-5", "api_key": "bd"},
            },
        ]
    )


# Map tier1_alias to cognic-tier1-cloud-openai.
def _settings_with_tier1(
    make_settings: Callable[..., Settings],
    *,
    allowed_providers: list[str],
) -> Settings:
    s = make_settings(
        {
            "allow_external_llm": True,
            "policy_mode": "cloud_mixed",
            "allowed_providers": allowed_providers,
        }
    )
    return Settings(
        allow_external_llm=s.allow_external_llm,
        policy_mode=s.policy_mode,
        allowed_providers=list(s.allowed_providers),
        llm_guardrail_scope=s.llm_guardrail_scope,
        llm_concurrency_per_profile=s.llm_concurrency_per_profile,
        llm_concurrency_mode=s.llm_concurrency_mode,
        litellm_base_url=s.litellm_base_url,
        litellm_master_key=s.litellm_master_key,
        tier1_alias="cognic-tier1-cloud-openai",
    )


class TestDriftDetection:
    @respx.mock
    async def test_drift_with_actual_allowed_returns_drift_outcome(
        self,
        gateway_ledger: GatewayCallLedger,
        gateway_engine: AsyncEngine,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        default_sla_policy: SLAPolicy,
        make_settings: Callable[..., Settings],
        make_resolver: Callable[[list[dict[str, Any]]], PreflightResolver],
    ) -> None:
        """Preflight cognic-tier1-cloud-openai (openai/gpt-5.4); LiteLLM
        actually returns azure/gpt-4o. Both providers on allow-list →
        actual policy passes; drift event emitted; outcome="drift"."""
        resolver = _multi_alias_resolver(make_resolver)
        settings = _settings_with_tier1(make_settings, allowed_providers=["openai", "azure"])
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_resp("azure/gpt-4o")
        )
        gateway = LLMGateway(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=resolver,
            sla_policy=default_sla_policy,
        )
        response = await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-drift-allowed",
        )
        # Drift event emitted.
        async with gateway_engine.connect() as conn:
            result = await conn.execute(
                select(_audit_event).where(
                    _audit_event.c.event_type == "gateway.upstream_drift_detected"
                )
            )
            drift_rows = list(result.fetchall())
            denied_result = await conn.execute(
                select(_audit_event).where(
                    _audit_event.c.event_type == "gateway.cloud_policy_denied"
                )
            )
            denied_rows = list(denied_result.fetchall())
        assert len(drift_rows) == 1
        # NO post-response denial event — actual is allowed.
        assert len(denied_rows) == 0

        # Response carries the actual upstream identity.
        assert response.upstream_model == "azure/gpt-4o"
        assert response.external is True

        # Ledger row outcome="drift".
        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].outcome == "drift"
        assert rows[0].provenance == "resolved"
        assert rows[0].upstream_model == "azure/gpt-4o"

    @respx.mock
    async def test_drift_with_actual_denied_raises_post_response(
        self,
        gateway_ledger: GatewayCallLedger,
        gateway_engine: AsyncEngine,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        default_sla_policy: SLAPolicy,
        make_settings: Callable[..., Settings],
        make_resolver: Callable[[list[dict[str, Any]]], PreflightResolver],
    ) -> None:
        """openai allow-listed; actual is azure (NOT in allowed). Drift
        event + post-response cloud_policy_denied + raise."""
        resolver = _multi_alias_resolver(make_resolver)
        settings = _settings_with_tier1(make_settings, allowed_providers=["openai"])
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_resp("azure/gpt-4o")
        )
        gateway = LLMGateway(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=resolver,
            sla_policy=default_sla_policy,
        )
        with pytest.raises(CloudPolicyViolationError) as exc_info:
            await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-drift-denied",
            )
        assert exc_info.value.decision.post_response is True
        assert "azure" in exc_info.value.decision.reason

        # Both events emitted.
        async with gateway_engine.connect() as conn:
            drift_r = await conn.execute(
                select(_audit_event).where(
                    _audit_event.c.event_type == "gateway.upstream_drift_detected"
                )
            )
            assert len(list(drift_r.fetchall())) == 1
            denied_r = await conn.execute(
                select(_audit_event).where(
                    _audit_event.c.event_type == "gateway.cloud_policy_denied"
                )
            )
            denied_rows = list(denied_r.fetchall())
        assert len(denied_rows) == 1
        # post_response=True on the drift-denial event.
        assert denied_rows[0].payload["post_response"] is True

        # Strict-regime ledger row written before raise.
        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].outcome == "denied"
        assert rows[0].upstream_model == "azure/gpt-4o"

    @respx.mock
    async def test_external_to_external_drift_caught_post_response(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        default_sla_policy: SLAPolicy,
        make_settings: Callable[..., Settings],
        make_resolver: Callable[[list[dict[str, Any]]], PreflightResolver],
    ) -> None:
        """Round-2 reviewer-P1#1: preflight openai allow-listed; actual
        bedrock NOT in allow-list. Both classify as external (so the
        Round-1 classification-equality check would have missed this).
        Round-2 fix: post-response policy recheck on actual_resolved
        catches the divergence."""
        resolver = _multi_alias_resolver(make_resolver)
        settings = _settings_with_tier1(make_settings, allowed_providers=["openai"])
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_resp("bedrock/anthropic.claude-3-5")
        )
        gateway = LLMGateway(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=resolver,
            sla_policy=default_sla_policy,
        )
        with pytest.raises(CloudPolicyViolationError) as exc_info:
            await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-bedrock",
            )
        assert "bedrock" in exc_info.value.decision.reason
