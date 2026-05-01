"""Shared fixtures for Sprint 3 LLM gateway tests.

T3 introduces four canonical ``Settings`` profiles consumed by the
cloud-policy enforcer tests; T6 phase B extends with gateway-
construction fixtures (engine + ledger + audit_store + rate_limiter
+ preflight + sla_policy + GuardrailPipeline factories).
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import pytest
import yaml
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import AuditStore, _audit_event, _chain_heads
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.config import Settings
from cognic_agentos.core.guardrails import (
    Guardrail,
    GuardrailPipeline,
    GuardrailResult,
)
from cognic_agentos.core.sla import SLAPolicy
from cognic_agentos.llm.concurrency import ProfileRateLimiter
from cognic_agentos.llm.ledger import GatewayCallLedger, _ledger_table
from cognic_agentos.llm.preflight import PreflightResolver


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


# ---------------------------------------------------------------------------
# T6 phase B — gateway construction fixtures.
# ---------------------------------------------------------------------------


def _settings_with_url(
    base: dict[str, Any] | None = None,
    *,
    base_url: str = "http://litellm.test:4000",
) -> Settings:
    """Build a Settings carrying litellm_base_url + the requested
    cloud-policy posture. Defaults to the secure self-hosted shape."""
    base = base or {}
    return Settings(
        allow_external_llm=base.get("allow_external_llm", False),
        policy_mode=base.get("policy_mode", "self_hosted"),
        allowed_providers=base.get("allowed_providers", []),
        llm_guardrail_scope=base.get("llm_guardrail_scope", "all"),
        llm_concurrency_per_profile=base.get("llm_concurrency_per_profile", 4),
        llm_concurrency_mode=base.get("llm_concurrency_mode", "queued"),
        litellm_base_url=base_url,
        litellm_master_key="sk-test-key",
    )


@pytest.fixture
def settings_for_gateway() -> Settings:
    """Default gateway-shape Settings. Tests override the base shape
    via ``Settings(**override)`` when they need a different posture."""
    return _settings_with_url()


@pytest.fixture
def make_settings() -> Callable[..., Settings]:
    """Factory for tests that need custom Settings posture."""
    return _settings_with_url


# --- Engine + audit_store + ledger ---------------------------------


@pytest.fixture
async def gateway_engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    """SQLite-aiosqlite engine with audit_event + decision_history +
    chain_heads + gateway_call_ledger tables created. Mirrors the
    Sprint-2 pattern in tests/unit/core/test_decision_history.py."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'gateway_test.db'}"
    engine: AsyncEngine = create_async_engine(url)
    async with engine.begin() as conn:
        # Sprint 2 governance tables.
        await conn.run_sync(_audit_event.metadata.create_all)
        # Seed the audit chain head.
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="audit_event",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=_dt.datetime.now(_dt.UTC),
            )
        )
        # T5 ledger.
        await conn.run_sync(_ledger_table.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def audit_store(gateway_engine: AsyncEngine) -> AuditStore:
    return AuditStore(gateway_engine)


@pytest.fixture
async def gateway_ledger(gateway_engine: AsyncEngine) -> GatewayCallLedger:
    return GatewayCallLedger(gateway_engine)


# --- PreflightResolver factory -------------------------------------


def _write_litellm_yaml(tmp_path: Path, model_list: list[dict[str, Any]]) -> Path:
    cfg = tmp_path / "litellm.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "model_list": model_list,
                "litellm_settings": {},
                "general_settings": {},
            }
        )
    )
    return cfg


@pytest.fixture
def make_resolver(tmp_path: Path) -> Callable[[list[dict[str, Any]]], PreflightResolver]:
    """Factory: build a PreflightResolver from an inline model_list."""

    def _build(model_list: list[dict[str, Any]]) -> PreflightResolver:
        return PreflightResolver.from_yaml(_write_litellm_yaml(tmp_path, model_list))

    return _build


@pytest.fixture
def dev_resolver(
    make_resolver: Callable[[list[dict[str, Any]]], PreflightResolver],
) -> PreflightResolver:
    """The plan's canonical dev shape: cognic-tier1-dev → ollama with
    a private api_base."""
    return make_resolver(
        [
            {
                "model_name": "cognic-tier1-dev",
                "litellm_params": {
                    "model": "ollama/qwen3:8b",
                    "api_base": "http://ollama:11434",
                },
            },
            {
                "model_name": "cognic-tier2-dev",
                "litellm_params": {
                    "model": "ollama/qwen3:32b",
                    "api_base": "http://ollama:11434",
                },
            },
        ]
    )


@pytest.fixture
def cloud_openai_resolver(
    make_resolver: Callable[[list[dict[str, Any]]], PreflightResolver],
) -> PreflightResolver:
    """Resolver with a cloud-OpenAI alias for denial-path tests."""
    return make_resolver(
        [
            {
                "model_name": "cognic-tier1-dev",
                "litellm_params": {
                    "model": "openai/gpt-5.4",
                    "api_key": "sk-test",
                },
            },
            {
                "model_name": "cognic-tier2-dev",
                "litellm_params": {
                    "model": "openai/gpt-5.4",
                    "api_key": "sk-test",
                },
            },
        ]
    )


# --- ProfileRateLimiter --------------------------------------------


@pytest.fixture
def rate_limiter() -> ProfileRateLimiter:
    """Default queued limiter — capacity 4 per profile."""
    return ProfileRateLimiter(per_profile=4, mode="queued")


@pytest.fixture
def fail_fast_limiter() -> ProfileRateLimiter:
    """Saturated-immediately fail_fast limiter — capacity 1 per profile."""
    return ProfileRateLimiter(per_profile=1, mode="fail_fast")


# --- SLAPolicy -----------------------------------------------------


@pytest.fixture
def default_sla_policy() -> SLAPolicy:
    """30s budget / 20s warning — matches the plan's default."""
    return SLAPolicy(
        name="default",
        total_budget=_dt.timedelta(seconds=30),
        warning_threshold=_dt.timedelta(seconds=20),
    )


@pytest.fixture
def fast_sla_policy() -> SLAPolicy:
    """1µs budget / 0µs warning — guarantees a BREACH on any real
    call. SLAPolicy validates ``total_budget > 0`` so 1µs is the
    smallest valid value; the SLA timer's ``classify`` returns
    BREACHED whenever ``now >= deadline``, and any real work
    between ``compute_deadline`` and ``classify`` takes >1µs."""
    return SLAPolicy(
        name="fast",
        total_budget=_dt.timedelta(microseconds=1),
        warning_threshold=_dt.timedelta(0),
    )


# --- Guardrail factories -------------------------------------------


class _AlwaysTripGuardrail:
    """Test-only guardrail that always trips with the named pattern.

    Matches the Sprint-2.5 ``Guardrail`` Protocol shape: synchronous
    ``check(content) -> GuardrailResult`` (not async — the
    GuardrailPipeline wraps the call in tuple-comprehension; only
    the pipeline's ``check`` is async because of the audit emission).
    """

    name: str = "test_always_trip"

    def check(self, content: str) -> GuardrailResult:
        return GuardrailResult(
            guardrail_name=self.name,
            passed=False,
            matches=("test_pattern",),
        )


class _NeverTripGuardrail:
    """Test-only guardrail that always passes."""

    name: str = "test_never_trip"

    def check(self, content: str) -> GuardrailResult:
        return GuardrailResult(
            guardrail_name=self.name,
            passed=True,
            matches=(),
        )


@pytest.fixture
def always_trip_guardrail() -> Guardrail:
    return _AlwaysTripGuardrail()


@pytest.fixture
def never_trip_guardrail() -> Guardrail:
    return _NeverTripGuardrail()


@pytest.fixture
def trip_pipeline(audit_store: AuditStore, always_trip_guardrail: Guardrail) -> GuardrailPipeline:
    return GuardrailPipeline(
        guardrails=(always_trip_guardrail,),
        audit_store=audit_store,
    )


@pytest.fixture
def pass_pipeline(audit_store: AuditStore, never_trip_guardrail: Guardrail) -> GuardrailPipeline:
    return GuardrailPipeline(
        guardrails=(never_trip_guardrail,),
        audit_store=audit_store,
    )
