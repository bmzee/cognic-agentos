"""Shared fixtures for Sprint 3 LLM gateway tests.

T3 introduces four canonical ``Settings`` profiles consumed by the
cloud-policy enforcer tests; later tasks (T6 LLMGateway, T8/T9 portal
endpoints) consume the same fixtures so the operator-policy matrix
stays uniform across the suite.
"""

from __future__ import annotations

import pytest

from cognic_agentos.core.config import Settings


@pytest.fixture
def settings_self_hosted() -> Settings:
    """Default Sprint-1B-baseline shape: ``allow_external_llm=False`` +
    empty ``allowed_providers`` + ``policy_mode="self_hosted"``. Every
    external upstream is denied. The bank's secure default."""
    return Settings(
        allow_external_llm=False,
        policy_mode="self_hosted",
        allowed_providers=[],
    )


@pytest.fixture
def settings_cloud_openai_allowed() -> Settings:
    """OpenAI explicitly allow-listed; mode upgraded to ``cloud_openai``
    so the mode-vs-flag inconsistency check doesn't fire on the openai
    upstream test cases."""
    return Settings(
        allow_external_llm=True,
        policy_mode="cloud_openai",
        allowed_providers=["openai"],
    )


@pytest.fixture
def settings_cloud_anthropic_only() -> Settings:
    """Anthropic allow-listed but openai is NOT — pins the
    provider-not-in-allow-list deny path."""
    return Settings(
        allow_external_llm=True,
        policy_mode="cloud_anthropic",
        allowed_providers=["anthropic"],
    )


@pytest.fixture
def settings_self_hosted_mode_with_flag_on() -> Settings:
    """Operator misconfiguration: flag is on AND provider is
    allow-listed BUT mode is still ``self_hosted``. The mode-vs-flag
    inconsistency check denies (Plan §2 step 5)."""
    return Settings(
        allow_external_llm=True,
        policy_mode="self_hosted",
        allowed_providers=["openai"],
    )


@pytest.fixture
def settings_cloud_mixed() -> Settings:
    """Most-permissive shape: every known cloud provider allow-listed
    + mode=cloud_mixed. Used by tests that want to verify the
    provenance-gap deny still fires under maximally-permissive
    settings (Round-4+5+6 reviewer-P1)."""
    return Settings(
        allow_external_llm=True,
        policy_mode="cloud_mixed",
        allowed_providers=["openai", "azure", "anthropic", "bedrock", "cohere"],
    )
