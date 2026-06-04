"""Wave-1 Deploy-Safety T3 — LiteLLM master-key resolution seam.

Critical-controls per AGENTS.md (``llm/gateway.py`` is the cloud-policy
enforcer + provider-honesty ledger feed). T1 turned
``litellm_master_key`` into a ``vault://`` URI in strict profiles; T2
resolved the three *adapter* secrets. T3 closes the loop for the 4th
secret — the gateway's own master key — by:

- Adding a keyword-only ``litellm_master_key=`` constructor seam so a
  future harness can pass the already-resolved key.
- Reading the master key **once at construction** (NOT per-call), so a
  post-construction mutation of ``settings.litellm_master_key`` cannot
  change what goes on the wire.
- **Failing loud** in ``__init__`` if no pre-resolved value is passed
  AND ``settings.litellm_master_key`` is a ``vault://`` URI — the
  gateway must NEVER put ``Bearer vault://...`` on the wire.

These tests pin the three behaviours. They use ``respx`` to intercept
the LiteLLM POST and inspect the captured request's ``Authorization``
header, so the Bearer-on-the-wire assertion is real, not a mock of the
gateway's internal state.
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
from cognic_agentos.llm.preflight import PreflightResolver

_LITELLM_URL = "http://litellm.test:4000/chat/completions"


def _resp(model: str = "openai/gpt-5.4", content: str = "hi") -> httpx.Response:
    """Minimal well-formed LiteLLM chat-completion response."""
    return httpx.Response(
        200,
        json={
            "id": "resp-test",
            "object": "chat.completion",
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
        },
    )


def _cloud_settings(
    make_settings: Callable[..., Settings],
    *,
    litellm_master_key: str | None,
) -> Settings:
    """A cloud-OpenAI-allowed Settings carrying a caller-chosen
    ``litellm_master_key`` (the conftest ``make_settings`` hardcodes the
    key, so we re-build to override it). Cloud posture lets the
    completion flow dispatch to the (respx-mocked) openai upstream."""
    base = make_settings(
        {
            "allow_external_llm": True,
            "policy_mode": "cloud_openai",
            "allowed_providers": ["openai"],
        }
    )
    return Settings(
        allow_external_llm=base.allow_external_llm,
        policy_mode=base.policy_mode,
        allowed_providers=list(base.allowed_providers),
        llm_guardrail_scope=base.llm_guardrail_scope,
        llm_concurrency_per_profile=base.llm_concurrency_per_profile,
        llm_concurrency_mode=base.llm_concurrency_mode,
        litellm_base_url=base.litellm_base_url,
        litellm_master_key=litellm_master_key,
    )


def _openai_resolver(
    make_resolver: Callable[[list[dict[str, Any]]], PreflightResolver],
) -> PreflightResolver:
    """tier1 → openai/gpt-5.4 cloud alias so dispatch actually fires."""
    return make_resolver(
        [
            {
                "model_name": "cognic-tier1-dev",
                "litellm_params": {"model": "openai/gpt-5.4", "api_key": "sk-test"},
            }
        ]
    )


class TestMasterKeyReadOnce:
    @respx.mock
    async def test_master_key_read_once_and_used_in_bearer(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        default_sla_policy: SLAPolicy,
        make_settings: Callable[..., Settings],
        make_resolver: Callable[[list[dict[str, Any]]], PreflightResolver],
    ) -> None:
        """The pre-resolved ``litellm_master_key=`` param is read ONCE at
        construction and placed on the wire as ``Bearer <param>``. A
        post-construction mutation of ``settings.litellm_master_key`` does
        NOT change the Bearer — proving read-once, not read-per-call."""
        settings = _cloud_settings(make_settings, litellm_master_key="sk-settings-key")
        route = respx.post(_LITELLM_URL).mock(return_value=_resp("openai/gpt-5.4"))

        gateway = LLMGateway(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=_openai_resolver(make_resolver),
            sla_policy=default_sla_policy,
            litellm_master_key="resolved-key",
        )

        await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-1",
        )

        assert route.calls.last.request.headers["Authorization"] == "Bearer resolved-key"

        # Read-once proof: mutate settings AFTER construction; the next
        # call MUST still use the value captured at construction.
        settings.litellm_master_key = "DIFFERENT-AFTER-CONSTRUCTION"
        await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi again"}],
            request_id="req-2",
        )
        assert route.calls.last.request.headers["Authorization"] == "Bearer resolved-key"

    @respx.mock
    async def test_fallback_to_settings_when_no_param(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        default_sla_policy: SLAPolicy,
        make_settings: Callable[..., Settings],
        make_resolver: Callable[[list[dict[str, Any]]], PreflightResolver],
    ) -> None:
        """With NO ``litellm_master_key=`` param and a PLAIN (non-vault://)
        ``settings.litellm_master_key``, the gateway falls back to the
        settings value — once at construction. Pins that the new seam does
        not break the existing plain-key path."""
        settings = _cloud_settings(make_settings, litellm_master_key="plain-key")
        route = respx.post(_LITELLM_URL).mock(return_value=_resp("openai/gpt-5.4"))

        gateway = LLMGateway(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=_openai_resolver(make_resolver),
            sla_policy=default_sla_policy,
        )

        await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-fallback",
        )

        assert route.calls.last.request.headers["Authorization"] == "Bearer plain-key"


class TestUnresolvedVaultUriFailsLoud:
    async def test_unresolved_vault_uri_fails_loud(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        default_sla_policy: SLAPolicy,
        make_resolver: Callable[[list[dict[str, Any]]], PreflightResolver],
    ) -> None:
        """A ``vault://`` master key with NO pre-resolved param fails loud
        at construction — the gateway must NEVER put ``Bearer vault://...``
        on the wire. This is a CONSTRUCTION-only assertion: the guard fires
        in ``__init__`` before any collaborator is touched, so no respx /
        completion is needed.

        Settings are built in the ``dev`` profile (default) so T1's strict
        G1 plaintext-guard does not fire, with ``vault_addr`` + ``vault_token``
        set so T1's G3 bootstrap guard is satisfied (a vault:// secret with
        unset bootstrap would be rejected by ``Settings`` construction itself,
        masking the gateway's own guard)."""
        settings = Settings(
            allow_external_llm=True,
            policy_mode="cloud_openai",
            allowed_providers=["openai"],
            litellm_base_url="http://litellm.test:4000",
            litellm_master_key="vault://secret/litellm",
            vault_addr="https://vault.test:8200",
            vault_token="hvs.plain-bootstrap-token",
        )

        with pytest.raises(RuntimeError, match="litellm_master_key_unresolved_vault_uri"):
            LLMGateway(
                settings=settings,
                ledger=gateway_ledger,
                audit_store=audit_store,
                rate_limiter=rate_limiter,
                preflight=_openai_resolver(make_resolver),
                sla_policy=default_sla_policy,
            )
