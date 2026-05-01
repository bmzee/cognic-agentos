"""Sprint 3 T6 phase B — api_base-aware classification end-to-end.

Round-2 reviewer-P1#2: vLLM/SGLang serving ``model: openai/X`` against
a private api_base classify as self-hosted. Cloud OpenAI without
api_base classifies as external. Tests drive the full gateway flow
through the resolver to confirm the classification flows correctly
into ``enforce_cloud_policy``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest
import respx

from cognic_agentos.core.audit import AuditStore
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
        json={"model": model, "choices": [{"message": {"content": "hi"}}]},
    )


def _settings(
    make_settings: Callable[..., Settings],
    *,
    tier1: str,
    **overrides: Any,
) -> Settings:
    s = make_settings(overrides)
    return Settings(
        allow_external_llm=s.allow_external_llm,
        policy_mode=s.policy_mode,
        allowed_providers=list(s.allowed_providers),
        llm_guardrail_scope=s.llm_guardrail_scope,
        llm_concurrency_per_profile=s.llm_concurrency_per_profile,
        llm_concurrency_mode=s.llm_concurrency_mode,
        litellm_base_url=s.litellm_base_url,
        litellm_master_key=s.litellm_master_key,
        tier1_alias=tier1,
    )


class TestVllmSelfHostedClassification:
    @respx.mock
    async def test_vllm_with_private_api_base_passes_default_policy(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        default_sla_policy: SLAPolicy,
        make_settings: Callable[..., Settings],
        make_resolver: Callable[[list[dict[str, Any]]], PreflightResolver],
    ) -> None:
        """Round-2 reviewer-P1#2 load-bearing for the gateway: vLLM
        serving ``openai/X`` against a private api_base must pass
        the default ``allow_external_llm=False`` policy because
        api_base is dispositive — host=vllm classifies as private →
        self-hosted."""
        resolver = make_resolver(
            [
                {
                    "model_name": "cognic-tier1-vllm",
                    "litellm_params": {
                        "model": "openai/Qwen3-8B-Instruct",
                        "api_base": "http://vllm:8000/v1",
                    },
                }
            ]
        )
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_resp("openai/Qwen3-8B-Instruct")
        )
        settings = _settings(make_settings, tier1="cognic-tier1-vllm")
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
            request_id="req-vllm",
        )
        assert response.external is False
        assert response.api_base == "http://vllm:8000/v1"

        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].external is False
        assert rows[0].upstream_api_base == "http://vllm:8000/v1"

    @respx.mock
    async def test_cloud_openai_without_api_base_denies_default_policy(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        default_sla_policy: SLAPolicy,
        make_settings: Callable[..., Settings],
        make_resolver: Callable[[list[dict[str, Any]]], PreflightResolver],
    ) -> None:
        """Cloud OpenAI without api_base classifies as external →
        default policy denies."""
        resolver = make_resolver(
            [
                {
                    "model_name": "cognic-tier1-cloud-openai",
                    "litellm_params": {
                        "model": "openai/gpt-5.4",
                        "api_key": "sk",
                    },
                }
            ]
        )
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_resp("openai/gpt-5.4")
        )
        settings = _settings(make_settings, tier1="cognic-tier1-cloud-openai")
        gateway = LLMGateway(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=resolver,
            sla_policy=default_sla_policy,
        )
        with pytest.raises(CloudPolicyViolationError):
            await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-cloud-deny",
            )
