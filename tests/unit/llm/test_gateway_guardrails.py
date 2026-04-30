"""Sprint 3 T6 phase B — guardrail attach + scope matrix.

Tests cover:
- INPUT trip → halt + raise GuardrailViolationError("input") +
  best-effort ledger row outcome="guardrail_input".
- OUTPUT trip → strict-regime ledger row outcome="guardrail_output"
  BEFORE the raise.
- llm_guardrail_scope matrix (T1 follow-up): all / external_only /
  self_hosted_only / off — plus inject-None composes correctly.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest
import respx

from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.config import Settings
from cognic_agentos.core.guardrails import GuardrailPipeline
from cognic_agentos.core.sla import SLAPolicy
from cognic_agentos.llm.concurrency import ProfileRateLimiter
from cognic_agentos.llm.gateway import LLMGateway, _guardrails_enabled_for
from cognic_agentos.llm.ledger import GatewayCallLedger
from cognic_agentos.llm.policy import GuardrailViolationError
from cognic_agentos.llm.preflight import PreflightResolver, ResolvedUpstream


def _ok_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "model": "ollama/qwen3:8b",
            "choices": [{"message": {"content": "hello"}}],
        },
    )


def _build(
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
    )


# ---------------------------------------------------------------------------
# Scope helper unit tests.
# ---------------------------------------------------------------------------


class TestGuardrailsEnabledFor:
    def _r(self, *, external: bool) -> ResolvedUpstream:
        return ResolvedUpstream(
            alias="x",
            model_string="m/y",
            api_base=None,
            external=external,
        )

    def test_all_runs_for_external(self) -> None:
        assert _guardrails_enabled_for(self._r(external=True), "all") is True

    def test_all_runs_for_self_hosted(self) -> None:
        assert _guardrails_enabled_for(self._r(external=False), "all") is True

    def test_external_only_skips_self_hosted(self) -> None:
        assert _guardrails_enabled_for(self._r(external=False), "external_only") is False

    def test_external_only_runs_for_external(self) -> None:
        assert _guardrails_enabled_for(self._r(external=True), "external_only") is True

    def test_self_hosted_only_runs_for_self_hosted(self) -> None:
        assert _guardrails_enabled_for(self._r(external=False), "self_hosted_only") is True

    def test_self_hosted_only_skips_external(self) -> None:
        assert _guardrails_enabled_for(self._r(external=True), "self_hosted_only") is False

    def test_off_skips_everything(self) -> None:
        assert _guardrails_enabled_for(self._r(external=True), "off") is False
        assert _guardrails_enabled_for(self._r(external=False), "off") is False

    def test_unreachable_scope_raises(self) -> None:
        with pytest.raises(AssertionError, match="unreachable"):
            _guardrails_enabled_for(self._r(external=True), "unknown")


# ---------------------------------------------------------------------------
# TestInputGuardrail — trip halts before policy + best-effort ledger.
# ---------------------------------------------------------------------------


class TestInputGuardrail:
    @respx.mock
    async def test_input_trip_halts_before_litellm_dispatch(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
        trip_pipeline: GuardrailPipeline,
    ) -> None:
        litellm_route = respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_ok_response()
        )
        gateway = _build(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            input_pipeline=trip_pipeline,
        )
        with pytest.raises(GuardrailViolationError) as exc_info:
            await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "input prompt"}],
                request_id="req-input-trip",
            )
        assert exc_info.value.direction == "input"
        # No LiteLLM call.
        assert litellm_route.call_count == 0
        # Best-effort ledger row.
        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].outcome == "guardrail_input"
        assert rows[0].provenance == "no_dispatch"

    async def test_input_pass_lets_dispatch_proceed(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
        pass_pipeline: GuardrailPipeline,
    ) -> None:
        with respx.mock:
            respx.post("http://litellm.test:4000/chat/completions").mock(
                return_value=_ok_response()
            )
            gateway = _build(
                settings=settings_for_gateway,
                ledger=gateway_ledger,
                audit_store=audit_store,
                rate_limiter=rate_limiter,
                preflight=dev_resolver,
                sla_policy=default_sla_policy,
                input_pipeline=pass_pipeline,
            )
            response = await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "ok prompt"}],
                request_id="req-input-pass",
            )
        assert response.content == "hello"


# ---------------------------------------------------------------------------
# TestOutputGuardrail — trip raises after strict ledger.
# ---------------------------------------------------------------------------


class TestOutputGuardrail:
    @respx.mock
    async def test_output_trip_strict_ledgers_before_raising(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
        trip_pipeline: GuardrailPipeline,
    ) -> None:
        respx.post("http://litellm.test:4000/chat/completions").mock(return_value=_ok_response())
        gateway = _build(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            output_pipeline=trip_pipeline,
        )
        with pytest.raises(GuardrailViolationError) as exc_info:
            await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-output-trip",
            )
        assert exc_info.value.direction == "output"
        # Strict-regime ledger row exists.
        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].outcome == "guardrail_output"
        # Post-dispatch — provenance="resolved" (actual was matched).
        assert rows[0].provenance == "resolved"


# ---------------------------------------------------------------------------
# TestGuardrailScope — T1 follow-up four-mode matrix.
# ---------------------------------------------------------------------------


class TestGuardrailScope:
    @respx.mock
    async def test_scope_off_skips_input_pipeline(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
        trip_pipeline: GuardrailPipeline,
        make_settings: Callable[..., Settings],
    ) -> None:
        """scope=off + input_pipeline=trip_pipeline: pipeline does NOT
        execute, so the trip never fires + dispatch proceeds."""
        respx.post("http://litellm.test:4000/chat/completions").mock(return_value=_ok_response())
        settings = make_settings({"llm_guardrail_scope": "off"})
        gateway = _build(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            input_pipeline=trip_pipeline,
        )
        response = await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-off",
        )
        assert response.content == "hello"

    @respx.mock
    async def test_scope_external_only_skips_self_hosted_input_pipeline(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
        trip_pipeline: GuardrailPipeline,
        make_settings: Callable[..., Settings],
    ) -> None:
        """external_only + dev (self-hosted) tier1: input pipeline must
        NOT execute → trip never fires."""
        respx.post("http://litellm.test:4000/chat/completions").mock(return_value=_ok_response())
        settings = make_settings({"llm_guardrail_scope": "external_only"})
        gateway = _build(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            input_pipeline=trip_pipeline,
        )
        response = await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-ext-only",
        )
        assert response.content == "hello"

    @respx.mock
    async def test_scope_self_hosted_only_runs_self_hosted_input_pipeline(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
        trip_pipeline: GuardrailPipeline,
        make_settings: Callable[..., Settings],
    ) -> None:
        """self_hosted_only + dev (self-hosted) tier1: input pipeline
        DOES execute → trip fires → raise."""
        respx.post("http://litellm.test:4000/chat/completions").mock(return_value=_ok_response())
        settings = make_settings({"llm_guardrail_scope": "self_hosted_only"})
        gateway = _build(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            input_pipeline=trip_pipeline,
        )
        with pytest.raises(GuardrailViolationError):
            await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-self-only",
            )

    @respx.mock
    async def test_inject_none_pipeline_disables_direction_globally(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """input_pipeline=None disables INPUT regardless of scope."""
        respx.post("http://litellm.test:4000/chat/completions").mock(return_value=_ok_response())
        # scope=all (default) but pipeline is None.
        gateway = _build(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            input_pipeline=None,
            output_pipeline=None,
        )
        response = await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-no-pipelines",
        )
        assert response.content == "hello"


# ---------------------------------------------------------------------------
# TestGuardrailScopeExternalRoutes — external-route runs/skips matrix.
# Round-9 reviewer-P2: the four-mode scope matrix is bank/operator-
# load-bearing; the previous slice only covered self-hosted+input.
# This block pins external-route classification end-to-end.
# ---------------------------------------------------------------------------


def _cloud_settings(make_settings: Callable[..., Settings]) -> Settings:
    """Cloud-allowed settings shape so cloud_openai_resolver passes
    pre-call policy and the input/output pipelines actually execute."""
    return make_settings(
        {
            "allow_external_llm": True,
            "policy_mode": "cloud_openai",
            "allowed_providers": ["openai"],
        }
    )


def _cloud_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "model": "openai/gpt-5.4",
            "choices": [{"message": {"content": "hello"}}],
        },
    )


class TestGuardrailScopeExternalRoutes:
    @respx.mock
    async def test_scope_external_only_runs_external_input_pipeline(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        cloud_openai_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
        trip_pipeline: GuardrailPipeline,
        make_settings: Callable[..., Settings],
    ) -> None:
        """external_only + cloud route + INPUT trip pipeline: pipeline
        DOES execute → trip fires → raise."""
        respx.post("http://litellm.test:4000/chat/completions").mock(return_value=_cloud_response())
        s = _cloud_settings(make_settings)
        settings = Settings(
            allow_external_llm=s.allow_external_llm,
            policy_mode=s.policy_mode,
            allowed_providers=list(s.allowed_providers),
            llm_guardrail_scope="external_only",
            llm_concurrency_per_profile=s.llm_concurrency_per_profile,
            llm_concurrency_mode=s.llm_concurrency_mode,
            litellm_base_url=s.litellm_base_url,
            litellm_master_key=s.litellm_master_key,
        )
        gateway = _build(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=cloud_openai_resolver,
            sla_policy=default_sla_policy,
            input_pipeline=trip_pipeline,
        )
        with pytest.raises(GuardrailViolationError) as exc_info:
            await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-ext-input-trip",
            )
        assert exc_info.value.direction == "input"

    @respx.mock
    async def test_scope_self_hosted_only_skips_external_input_pipeline(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        cloud_openai_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
        trip_pipeline: GuardrailPipeline,
        make_settings: Callable[..., Settings],
    ) -> None:
        """self_hosted_only + cloud route + INPUT trip pipeline:
        pipeline must NOT execute → trip never fires → dispatch
        proceeds normally."""
        respx.post("http://litellm.test:4000/chat/completions").mock(return_value=_cloud_response())
        s = _cloud_settings(make_settings)
        settings = Settings(
            allow_external_llm=s.allow_external_llm,
            policy_mode=s.policy_mode,
            allowed_providers=list(s.allowed_providers),
            llm_guardrail_scope="self_hosted_only",
            llm_concurrency_per_profile=s.llm_concurrency_per_profile,
            llm_concurrency_mode=s.llm_concurrency_mode,
            litellm_base_url=s.litellm_base_url,
            litellm_master_key=s.litellm_master_key,
        )
        gateway = _build(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=cloud_openai_resolver,
            sla_policy=default_sla_policy,
            input_pipeline=trip_pipeline,
        )
        response = await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-ext-input-skip",
        )
        assert response.content == "hello"
        assert response.external is True


# ---------------------------------------------------------------------------
# TestOutputScopeMatrix — OUTPUT-direction four-mode matrix.
# The original slice only exercised INPUT scope. OUTPUT direction
# classifies on actual_resolved (post-dispatch), so it needs its own
# coverage.
# ---------------------------------------------------------------------------


class TestOutputScopeMatrix:
    @respx.mock
    async def test_scope_off_skips_output_pipeline(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
        trip_pipeline: GuardrailPipeline,
        make_settings: Callable[..., Settings],
    ) -> None:
        """scope=off + output_pipeline=trip: pipeline must NOT execute
        → trip never fires."""
        respx.post("http://litellm.test:4000/chat/completions").mock(return_value=_ok_response())
        settings = make_settings({"llm_guardrail_scope": "off"})
        gateway = _build(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            output_pipeline=trip_pipeline,
        )
        response = await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-output-off",
        )
        assert response.content == "hello"

    @respx.mock
    async def test_scope_external_only_skips_self_hosted_output_pipeline(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
        trip_pipeline: GuardrailPipeline,
        make_settings: Callable[..., Settings],
    ) -> None:
        """external_only + dev (self-hosted) + output_pipeline=trip:
        pipeline must NOT execute → trip never fires."""
        respx.post("http://litellm.test:4000/chat/completions").mock(return_value=_ok_response())
        settings = make_settings({"llm_guardrail_scope": "external_only"})
        gateway = _build(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            output_pipeline=trip_pipeline,
        )
        response = await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-output-ext-only-skip",
        )
        assert response.content == "hello"

    @respx.mock
    async def test_scope_external_only_runs_external_output_pipeline(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        cloud_openai_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
        trip_pipeline: GuardrailPipeline,
        make_settings: Callable[..., Settings],
    ) -> None:
        """external_only + cloud + output_pipeline=trip: pipeline DOES
        execute → trip fires → strict ledger row before raise."""
        respx.post("http://litellm.test:4000/chat/completions").mock(return_value=_cloud_response())
        s = _cloud_settings(make_settings)
        settings = Settings(
            allow_external_llm=s.allow_external_llm,
            policy_mode=s.policy_mode,
            allowed_providers=list(s.allowed_providers),
            llm_guardrail_scope="external_only",
            llm_concurrency_per_profile=s.llm_concurrency_per_profile,
            llm_concurrency_mode=s.llm_concurrency_mode,
            litellm_base_url=s.litellm_base_url,
            litellm_master_key=s.litellm_master_key,
        )
        gateway = _build(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=cloud_openai_resolver,
            sla_policy=default_sla_policy,
            output_pipeline=trip_pipeline,
        )
        with pytest.raises(GuardrailViolationError) as exc_info:
            await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-output-ext-only-trip",
            )
        assert exc_info.value.direction == "output"
        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].outcome == "guardrail_output"


# ---------------------------------------------------------------------------
# TestInjectNoneIndependence — None disables that direction only.
# ---------------------------------------------------------------------------


class TestInjectNoneIndependence:
    @respx.mock
    async def test_input_none_with_output_trip_still_fires_output(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
        trip_pipeline: GuardrailPipeline,
    ) -> None:
        """input_pipeline=None disables INPUT only; OUTPUT trip still
        executes."""
        respx.post("http://litellm.test:4000/chat/completions").mock(return_value=_ok_response())
        gateway = _build(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            input_pipeline=None,
            output_pipeline=trip_pipeline,
        )
        with pytest.raises(GuardrailViolationError) as exc_info:
            await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-input-none-output-trip",
            )
        assert exc_info.value.direction == "output"

    @respx.mock
    async def test_output_none_with_input_pass_lets_dispatch_complete(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
        pass_pipeline: GuardrailPipeline,
    ) -> None:
        """output_pipeline=None disables OUTPUT only; INPUT pass runs;
        dispatch completes."""
        respx.post("http://litellm.test:4000/chat/completions").mock(return_value=_ok_response())
        gateway = _build(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            input_pipeline=pass_pipeline,
            output_pipeline=None,
        )
        response = await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-output-none",
        )
        assert response.content == "hello"


# ---------------------------------------------------------------------------
# TestScopeAsymmetryUnderDrift — input gates on PREFLIGHT, output gates
# on ACTUAL. Round-9 reviewer-P2: under drift the two directions can
# disagree on classification, and the gateway must not collapse them.
# ---------------------------------------------------------------------------


def _drift_resolver(
    make_resolver: Callable[..., PreflightResolver],
    *,
    extra: list[dict[str, object]] | None = None,
) -> PreflightResolver:
    """Resolver carrying BOTH a self-hosted dev alias AND a cloud-OpenAI
    alias. Tests pick the preflight tier1 and seed LiteLLM to return
    the OTHER alias's model_string so reverse_lookup classifies the
    actual upstream differently from preflight."""
    base: list[dict[str, object]] = [
        {
            "model_name": "cognic-tier1-dev",
            "litellm_params": {
                "model": "ollama/qwen3:8b",
                "api_base": "http://ollama:11434",
            },
        },
        {
            "model_name": "cognic-tier1-cloud-openai",
            "litellm_params": {"model": "openai/gpt-5.4", "api_key": "sk"},
        },
        {
            "model_name": "cognic-tier2-dev",
            "litellm_params": {
                "model": "ollama/qwen3:32b",
                "api_base": "http://ollama:11434",
            },
        },
        {
            "model_name": "cognic-tier2-cloud-openai",
            "litellm_params": {"model": "openai/gpt-5.4", "api_key": "sk"},
        },
    ]
    if extra:
        base.extend(extra)
    return make_resolver(base)


class TestScopeAsymmetryUnderDrift:
    @respx.mock
    async def test_external_only_preflight_external_actual_self_hosted(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        default_sla_policy: SLAPolicy,
        pass_pipeline: GuardrailPipeline,
        trip_pipeline: GuardrailPipeline,
        make_settings: Callable[..., Settings],
        make_resolver: Callable[..., PreflightResolver],
    ) -> None:
        """scope=external_only + preflight=cloud + drift→actual=self-
        hosted: INPUT direction sees external (preflight) → pass
        pipeline runs (and passes); OUTPUT direction sees self-hosted
        (actual) → trip pipeline SKIPPED → call completes successfully.
        Confirms input/output scope decisions use independent resolved
        objects."""
        resolver = _drift_resolver(make_resolver)
        s = make_settings(
            {
                "allow_external_llm": True,
                "policy_mode": "cloud_mixed",
                "allowed_providers": ["openai"],
            }
        )
        settings = Settings(
            allow_external_llm=s.allow_external_llm,
            policy_mode=s.policy_mode,
            allowed_providers=list(s.allowed_providers),
            llm_guardrail_scope="external_only",
            llm_concurrency_per_profile=s.llm_concurrency_per_profile,
            llm_concurrency_mode=s.llm_concurrency_mode,
            litellm_base_url=s.litellm_base_url,
            litellm_master_key=s.litellm_master_key,
            tier1_alias="cognic-tier1-cloud-openai",  # preflight: external
        )
        # LiteLLM "drifts" to a self-hosted model; reverse_lookup
        # finds the dev alias → actual classifies as self-hosted.
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_ok_response()  # model: ollama/qwen3:8b
        )
        gateway = _build(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=resolver,
            sla_policy=default_sla_policy,
            input_pipeline=pass_pipeline,  # pass — runs because preflight=external
            output_pipeline=trip_pipeline,  # would trip — but skipped because actual=self-hosted
        )
        response = await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-asym-1",
        )
        assert response.content == "hello"
        # Drift recorded: outcome="drift" or "ok"; either way one row.
        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].outcome == "drift"
        assert rows[0].external is False  # actual was self-hosted

    @respx.mock
    async def test_external_only_preflight_self_hosted_actual_external(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        default_sla_policy: SLAPolicy,
        pass_pipeline: GuardrailPipeline,
        trip_pipeline: GuardrailPipeline,
        make_settings: Callable[..., Settings],
        make_resolver: Callable[..., PreflightResolver],
    ) -> None:
        """Mirror image: scope=external_only + preflight=self-hosted +
        drift→actual=external. INPUT direction sees self-hosted
        (preflight) → trip pipeline SKIPPED; OUTPUT direction sees
        external (actual) → pass pipeline RUNS and passes. Asserts
        the inverse asymmetry — input/output do not share a single
        resolved-object decision."""
        resolver = _drift_resolver(make_resolver)
        s = make_settings(
            {
                "allow_external_llm": True,
                "policy_mode": "cloud_mixed",
                "allowed_providers": ["openai"],
            }
        )
        settings = Settings(
            allow_external_llm=s.allow_external_llm,
            policy_mode=s.policy_mode,
            allowed_providers=list(s.allowed_providers),
            llm_guardrail_scope="external_only",
            llm_concurrency_per_profile=s.llm_concurrency_per_profile,
            llm_concurrency_mode=s.llm_concurrency_mode,
            litellm_base_url=s.litellm_base_url,
            litellm_master_key=s.litellm_master_key,
            tier1_alias="cognic-tier1-dev",  # preflight: self-hosted
        )
        # LiteLLM "drifts" to a cloud model.
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=_cloud_response()  # model: openai/gpt-5.4
        )
        gateway = _build(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=resolver,
            sla_policy=default_sla_policy,
            input_pipeline=trip_pipeline,  # would trip — but skipped because preflight=self-hosted
            output_pipeline=pass_pipeline,  # passes — runs because actual=external
        )
        response = await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-asym-2",
        )
        assert response.content == "hello"
        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].outcome == "drift"
        assert rows[0].external is True  # actual was external
