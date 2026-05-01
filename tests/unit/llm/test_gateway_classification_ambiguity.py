"""Sprint 3 T6 phase B — Round-3+4+5+6 ambiguity + unresolved paths.

Subtests pin:

- Collision (mixed-classification YAML) under default + permissive
  + max-permissive settings: all DENY (Round-4 reviewer-P1
  ambiguous-overrides-allow-list).
- Unresolved actual (model not declared in YAML) under default +
  permissive settings: both DENY (Round-5 reviewer-P1).
- Missing/invalid response model field: DENY with
  ``cause="missing_model_field"`` event (Round-6 reviewer-P1).
- Direct ``enforce_cloud_policy`` test: provenance != "resolved"
  denies under cloud_mixed + every-provider allow-list.
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
from cognic_agentos.llm.policy import CloudPolicyViolationError, enforce_cloud_policy
from cognic_agentos.llm.preflight import PreflightResolver, ResolvedUpstream


def _resp(model_value: Any) -> httpx.Response:
    body: dict[str, Any] = {"choices": [{"message": {"content": "hi"}}]}
    if model_value is not None:
        body["model"] = model_value
    return httpx.Response(200, json=body)


def _collision_resolver(
    make_resolver: Callable[[list[dict[str, Any]]], PreflightResolver],
) -> PreflightResolver:
    """YAML with two aliases sharing model: openai/gpt-4o — vLLM
    self-hosted (api_base=private) AND cloud OpenAI (no api_base)."""
    return make_resolver(
        [
            {
                "model_name": "cognic-tier1-vllm-shape",
                "litellm_params": {
                    "model": "openai/gpt-4o",
                    "api_base": "http://vllm:8000/v1",
                },
            },
            {
                "model_name": "cognic-tier1-cloud-openai",
                "litellm_params": {
                    "model": "openai/gpt-4o",
                    "api_key": "sk",
                },
            },
        ]
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


class TestCollisionAmbiguity:
    @respx.mock
    async def test_collision_default_settings_denies(
        self,
        gateway_ledger: GatewayCallLedger,
        gateway_engine: AsyncEngine,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        default_sla_policy: SLAPolicy,
        make_settings: Callable[..., Settings],
        make_resolver: Callable[[list[dict[str, Any]]], PreflightResolver],
    ) -> None:
        """Subtest A: collision + default settings → ambiguous deny."""
        resolver = _collision_resolver(make_resolver)
        # Cloud-OpenAI alias is the preflight target; allow it through
        # the pre-call check so we exercise the post-response
        # ambiguity path. Settings: external allowed but providers
        # empty → pre-call would deny. Instead use cloud_mixed +
        # openai allowed for pre-call pass.
        settings = _settings(
            make_settings,
            tier1="cognic-tier1-cloud-openai",
            allow_external_llm=True,
            policy_mode="cloud_mixed",
            allowed_providers=["openai"],
        )
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_resp("openai/gpt-4o")
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
                request_id="req-collision",
            )
        assert "provenance gap" in exc_info.value.decision.reason
        assert exc_info.value.decision.resolved.provenance == "ambiguous"

        # gateway.upstream_classification_ambiguous + cloud_policy_denied
        # both emitted.
        async with gateway_engine.connect() as conn:
            ambig = await conn.execute(
                select(_audit_event).where(
                    _audit_event.c.event_type == "gateway.upstream_classification_ambiguous"
                )
            )
            denied = await conn.execute(
                select(_audit_event).where(
                    _audit_event.c.event_type == "gateway.cloud_policy_denied"
                )
            )
        assert len(list(ambig.fetchall())) == 1
        assert len(list(denied.fetchall())) == 1

        # Strict-regime ledger row.
        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].outcome == "denied"
        assert rows[0].provenance == "ambiguous"
        assert rows[0].upstream_api_base is None  # gateway refused to claim

    @respx.mock
    async def test_collision_max_permissive_settings_still_denies(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        default_sla_policy: SLAPolicy,
        make_settings: Callable[..., Settings],
        make_resolver: Callable[[list[dict[str, Any]]], PreflightResolver],
    ) -> None:
        """Round-4 reviewer-P1: even with cloud_mixed + every provider
        allow-listed, the ambiguous case denies because provenance gap
        overrides the surface allow-list."""
        resolver = _collision_resolver(make_resolver)
        settings = _settings(
            make_settings,
            tier1="cognic-tier1-cloud-openai",
            allow_external_llm=True,
            policy_mode="cloud_mixed",
            allowed_providers=["openai", "azure", "anthropic", "bedrock", "cohere"],
        )
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_resp("openai/gpt-4o")
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
                request_id="req-collision-permissive",
            )
        assert "provenance gap" in exc_info.value.decision.reason


class TestUnresolvedActual:
    @respx.mock
    async def test_unresolved_default_settings_denies(
        self,
        gateway_ledger: GatewayCallLedger,
        gateway_engine: AsyncEngine,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        default_sla_policy: SLAPolicy,
        make_settings: Callable[..., Settings],
        make_resolver: Callable[[list[dict[str, Any]]], PreflightResolver],
    ) -> None:
        """Resolver only knows openai/gpt-5.4; LiteLLM returns
        openai/gpt-7. Zero matches → unresolved → ambiguous policy
        deny."""
        resolver = make_resolver(
            [
                {
                    "model_name": "cognic-tier1-cloud-openai",
                    "litellm_params": {"model": "openai/gpt-5.4", "api_key": "sk"},
                }
            ]
        )
        settings = _settings(
            make_settings,
            tier1="cognic-tier1-cloud-openai",
            allow_external_llm=True,
            policy_mode="cloud_mixed",
            allowed_providers=["openai"],
        )
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_resp("openai/gpt-7")  # not declared
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
                request_id="req-unresolved",
            )
        assert "provenance gap" in exc_info.value.decision.reason
        assert exc_info.value.decision.resolved.provenance == "unresolved"

        # gateway.upstream_unresolved emitted with cause.
        async with gateway_engine.connect() as conn:
            result = await conn.execute(
                select(_audit_event).where(
                    _audit_event.c.event_type == "gateway.upstream_unresolved"
                )
            )
            rows = list(result.fetchall())
        assert len(rows) == 1
        assert rows[0].payload["cause"] == "model_not_in_yaml"

    @respx.mock
    async def test_missing_response_model_field_denies(
        self,
        gateway_ledger: GatewayCallLedger,
        gateway_engine: AsyncEngine,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        default_sla_policy: SLAPolicy,
        make_settings: Callable[..., Settings],
        make_resolver: Callable[[list[dict[str, Any]]], PreflightResolver],
    ) -> None:
        """Round-6 reviewer-P1: response with no/empty/non-string
        ``model`` field → unresolved with cause="missing_model_field"
        → policy deny."""
        resolver = make_resolver(
            [
                {
                    "model_name": "cognic-tier1-cloud-openai",
                    "litellm_params": {"model": "openai/gpt-5.4", "api_key": "sk"},
                }
            ]
        )
        settings = _settings(
            make_settings,
            tier1="cognic-tier1-cloud-openai",
            allow_external_llm=True,
            policy_mode="cloud_mixed",
            allowed_providers=["openai"],
        )
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_resp(model_value=None)  # no model field
        )
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
                request_id="req-missing-model",
            )
        async with gateway_engine.connect() as conn:
            result = await conn.execute(
                select(_audit_event).where(
                    _audit_event.c.event_type == "gateway.upstream_unresolved"
                )
            )
            rows = list(result.fetchall())
        assert len(rows) == 1
        assert rows[0].payload["cause"] == "missing_model_field"

    @respx.mock
    async def test_non_string_response_model_field_denies(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        default_sla_policy: SLAPolicy,
        make_settings: Callable[..., Settings],
        make_resolver: Callable[[list[dict[str, Any]]], PreflightResolver],
    ) -> None:
        """Non-string model field (e.g. ``42``) is also a provenance
        gap. Round-6 reviewer-P1."""
        resolver = make_resolver(
            [
                {
                    "model_name": "cognic-tier1-cloud-openai",
                    "litellm_params": {"model": "openai/gpt-5.4", "api_key": "sk"},
                }
            ]
        )
        settings = _settings(
            make_settings,
            tier1="cognic-tier1-cloud-openai",
            allow_external_llm=True,
            policy_mode="cloud_mixed",
            allowed_providers=["openai"],
        )
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "model": 42,  # non-string
                    "choices": [{"message": {"content": "hi"}}],
                },
            )
        )
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
                request_id="req-non-string-model",
            )


class TestEnforceCloudPolicyAmbiguousDirect:
    """Direct ``enforce_cloud_policy`` regression — Round-4 P1: any
    ``provenance != "resolved"`` denies even under maximally-permissive
    settings."""

    def test_ambiguous_under_max_permissive_denies(self, settings_cloud_mixed: Settings) -> None:
        ambiguous = ResolvedUpstream(
            alias="x",
            model_string="openai/gpt-4o",
            api_base=None,
            external=True,
            provenance="ambiguous",
        )
        decision = enforce_cloud_policy(
            resolved=ambiguous,
            settings=settings_cloud_mixed,
            post_response=True,
        )
        assert decision.allowed is False
        assert "provenance gap" in decision.reason

    def test_unresolved_under_max_permissive_denies(self, settings_cloud_mixed: Settings) -> None:
        unresolved = ResolvedUpstream(
            alias="x",
            model_string="openai/gpt-7",
            api_base=None,
            external=True,
            provenance="unresolved",
        )
        decision = enforce_cloud_policy(
            resolved=unresolved,
            settings=settings_cloud_mixed,
            post_response=True,
        )
        assert decision.allowed is False
