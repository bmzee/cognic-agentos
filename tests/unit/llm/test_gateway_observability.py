"""Gateway-observability workstream — value-free OTel span (ADR-009).

Critical-controls posture (gateway.py is on the CC coverage gate):
- Task 1 unit-tests the emit helper in ISOLATION (every attribute branch +
  the None-observability early return + the fail-open path), so the helper
  is fully covered at this commit before Task 2 wires it into completion().
"""

from __future__ import annotations

import logging
import typing
from collections.abc import Callable
from typing import Any

import httpx
import pytest
import respx

from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.config import Settings
from cognic_agentos.core.guardrails import GuardrailPipeline
from cognic_agentos.core.sla import SLAPolicy
from cognic_agentos.db.adapters.protocols import AdapterHealth
from cognic_agentos.llm.concurrency import LLMConcurrencyExceeded, ProfileRateLimiter
from cognic_agentos.llm.gateway import (
    GatewayTraceOutcome,
    LedgerWriteFailed,
    LLMGateway,
    _CompletionTrace,
)
from cognic_agentos.llm.ledger import GatewayCallLedger
from cognic_agentos.llm.policy import CloudPolicyViolationError, GuardrailViolationError
from cognic_agentos.llm.preflight import PreflightResolver, ResolvedUpstream


class _RecordingObservability:
    """Hermetic in-process ObservabilityAdapter test double — structurally
    conforms to the @runtime_checkable Protocol; only emit_trace is exercised."""

    def __init__(self, *, raise_on_emit: bool = False) -> None:
        self.captured: list[tuple[str, dict[str, object]]] = []
        self._raise = raise_on_emit

    async def emit_trace(self, name: str, attributes: dict[str, object]) -> None:
        if self._raise:
            raise RuntimeError("boom: emit_trace failed")
        self.captured.append((name, attributes))

    async def emit_metric(self, name: str, value: float, attributes: dict[str, object]) -> None: ...
    async def flush(self) -> None: ...
    async def health_check(self) -> AdapterHealth:
        # MUST return AdapterHealth (not object) — the double is assigned to an
        # ``ObservabilityAdapter``-typed slot, so mypy checks Protocol conformance
        # and a wider return type (object) fails. Never called in unit tests.
        return AdapterHealth(status="ok", driver="recording", latency_ms=0.0)


def _build_gateway(
    *,
    settings: Settings,
    ledger: GatewayCallLedger,
    audit_store: AuditStore,
    rate_limiter: ProfileRateLimiter,
    preflight: PreflightResolver,
    sla_policy: SLAPolicy,
    observability: _RecordingObservability | None = None,
) -> LLMGateway:
    return LLMGateway(
        settings=settings,
        ledger=ledger,
        audit_store=audit_store,
        rate_limiter=rate_limiter,
        preflight=preflight,
        sla_policy=sla_policy,
        observability=observability,
    )


def _trace(**overrides: object) -> _CompletionTrace:
    base: dict[str, object] = {
        "request_id": "req-1",
        "tenant_id": "tenant-a",
        "tier": "tier1",
        "flow_start": 0.0,
        "agent_workforce_id": None,
    }
    base.update(overrides)
    return _CompletionTrace(**base)  # type: ignore[arg-type]


def _preflight_upstream() -> ResolvedUpstream:
    return ResolvedUpstream(
        alias="cognic-tier1-dev",
        model_string="ollama/qwen3:8b",
        api_base="http://ollama:11434",
        external=False,
        provenance="resolved",
    )


class TestTraceOutcomeVocabularyClosed:
    def test_trace_outcome_has_exactly_eleven_values(self) -> None:
        assert len(typing.get_args(GatewayTraceOutcome)) == 11

    def test_trace_outcome_value_set_is_pinned(self) -> None:
        assert set(typing.get_args(GatewayTraceOutcome)) == {
            "errored_pre_resolution",
            "invalid_tier",
            "preflight_failure",
            "guardrail_input",
            "policy_denied",
            "concurrency_exhausted",
            "upstream_error",
            "guardrail_output",
            "strict_ledger_failure",
            "ok",
            "drift",
        }


class TestConstructorSeam:
    def test_observability_defaults_to_none(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        gw = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
        )
        assert gw._observability is None

    def test_observability_is_held_when_injected(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        rec = _RecordingObservability()
        gw = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            observability=rec,
        )
        assert gw._observability is rec


class TestEmitHelperValueFree:
    async def test_full_trace_emits_one_value_free_span(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        rec = _RecordingObservability()
        gw = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            observability=rec,
        )
        pf = _preflight_upstream()
        tr = _trace(
            outcome="ok",
            litellm_alias="cognic-tier1-dev",
            preflight=pf,
            actual=pf,
            usage={"prompt_tokens": 12, "completion_tokens": 7},
            agent_workforce_id="wf-9",
        )
        await gw._emit_completion_trace_best_effort(tr)

        assert len(rec.captured) == 1
        name, attrs = rec.captured[0]
        assert name == "llm.gateway.completion"
        assert attrs["llm.gateway.outcome"] == "ok"
        assert attrs["llm.gateway.request_id"] == "req-1"
        assert attrs["llm.gateway.tenant_id"] == "tenant-a"
        assert attrs["llm.gateway.tier"] == "tier1"
        assert attrs["llm.gateway.litellm_alias"] == "cognic-tier1-dev"
        assert attrs["gen_ai.request.model"] == "ollama/qwen3:8b"
        assert attrs["gen_ai.response.model"] == "ollama/qwen3:8b"
        assert attrs["llm.gateway.external"] is False
        assert attrs["llm.gateway.provenance"] == "resolved"
        assert attrs["gen_ai.usage.input_tokens"] == 12
        assert attrs["gen_ai.usage.output_tokens"] == 7
        assert attrs["llm.gateway.agent_workforce_id"] == "wf-9"
        assert "llm.gateway.latency_ms" in attrs
        # VALUE-FREE: no message / prompt / response content anywhere.
        blob = repr(attrs).lower()
        assert "content" not in blob and "message" not in blob and "hello" not in blob

    async def test_minimal_trace_omits_optional_attributes(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        rec = _RecordingObservability()
        gw = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            observability=rec,
        )
        # Pre-resolution failure shape: no alias, no preflight, no actual, no usage,
        # no workforce id, tenant None.
        tr = _trace(outcome="invalid_tier", tenant_id=None)
        await gw._emit_completion_trace_best_effort(tr)

        _, attrs = rec.captured[0]
        assert attrs["llm.gateway.outcome"] == "invalid_tier"
        for absent in (
            "llm.gateway.tenant_id",
            "llm.gateway.litellm_alias",
            "gen_ai.request.model",
            "llm.gateway.external",
            "gen_ai.response.model",
            "llm.gateway.provenance",
            "gen_ai.usage.input_tokens",
            "gen_ai.usage.output_tokens",
            "llm.gateway.agent_workforce_id",
        ):
            assert absent not in attrs

    async def test_usage_without_int_tokens_omits_token_attrs(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        rec = _RecordingObservability()
        gw = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            observability=rec,
        )
        tr = _trace(outcome="ok", usage={"note": "no counts here"})
        await gw._emit_completion_trace_best_effort(tr)
        _, attrs = rec.captured[0]
        assert "gen_ai.usage.input_tokens" not in attrs
        assert "gen_ai.usage.output_tokens" not in attrs

    async def test_none_observability_is_a_noop(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        gw = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            observability=None,
        )
        # Must not raise.
        await gw._emit_completion_trace_best_effort(_trace(outcome="ok"))

    async def test_emit_failure_is_swallowed_and_logged(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        rec = _RecordingObservability(raise_on_emit=True)
        gw = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            observability=rec,
        )
        with caplog.at_level(logging.ERROR, logger="cognic_agentos.llm.gateway"):
            await gw._emit_completion_trace_best_effort(_trace(outcome="ok"))  # must NOT raise
        assert any("llm.gateway.trace_emit_failed" in r.message for r in caplog.records)


# ===========================================================================
# Task 2 — the per-path span matrix.
#
# completion() is now a thin wrapper delegating to _run_completion; the
# wrapper's ``finally`` emits ONE value-free span per call on EVERY exit.
# These tests pin the ``trace_outcome`` for each of the 11 closed-enum
# values + the strict-ledger override + the fail-open-through-completion
# contract. They mirror the respx + fixture patterns in
# test_gateway_completion.py / test_gateway_drift.py /
# test_gateway_httpx_dispatch_errors.py / test_gateway_guardrails.py /
# test_gateway_concurrency_ledger.py / test_gateway_ledger.py.
# ===========================================================================

from unittest.mock import AsyncMock, patch  # noqa: E402  (Task-2 block-local import)

_LITELLM_URL = "http://litellm.test:4000/chat/completions"


def _ok_litellm_response(
    model: str = "ollama/qwen3:8b", *, usage: dict[str, Any] | None = None
) -> httpx.Response:
    body: dict[str, Any] = {
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
    }
    if usage is not None:
        body["usage"] = usage
    return httpx.Response(200, json=body)


def _only_span(rec: _RecordingObservability) -> dict[str, object]:
    assert len(rec.captured) == 1, f"expected exactly one span, got {len(rec.captured)}"
    name, attrs = rec.captured[0]
    assert name == "llm.gateway.completion"
    return attrs


def _multi_alias_resolver(
    make_resolver: Callable[[list[dict[str, Any]]], PreflightResolver],
) -> PreflightResolver:
    """Resolver carrying both a cloud-openai alias AND a cloud-azure alias
    so reverse_lookup classifies a drifted azure model. Mirrors
    test_gateway_drift.py::_multi_alias_resolver."""
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
        ]
    )


def _cloud_settings_tier1(
    make_settings: Callable[..., Settings],
    *,
    allowed_providers: list[str],
    tier1_alias: str = "cognic-tier1-cloud-openai",
) -> Settings:
    """Cloud-mixed settings with tier1 mapped to a cloud alias. Mirrors
    test_gateway_drift.py::_settings_with_tier1."""
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
        tier1_alias=tier1_alias,
    )


class TestCompletionSpanPerPath:
    """One test per closed-enum ``trace_outcome``."""

    @respx.mock
    async def test_success_emits_ok_span_with_usage(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        respx.post(_LITELLM_URL).mock(
            return_value=_ok_litellm_response(
                "ollama/qwen3:8b", usage={"prompt_tokens": 5, "completion_tokens": 9}
            )
        )
        rec = _RecordingObservability()
        gw = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            observability=rec,
        )
        await gw.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-ok",
            tenant_id="tenant-a",
        )
        attrs = _only_span(rec)
        assert attrs["llm.gateway.outcome"] == "ok"
        assert attrs["gen_ai.request.model"] == "ollama/qwen3:8b"
        assert attrs["gen_ai.response.model"] == "ollama/qwen3:8b"
        assert attrs["gen_ai.usage.input_tokens"] == 5
        assert attrs["gen_ai.usage.output_tokens"] == 9
        assert attrs["llm.gateway.provenance"] == "resolved"
        # value-free even on the success path.
        assert "hello" not in repr(attrs).lower()

    @respx.mock
    async def test_drift_emits_drift_span(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        default_sla_policy: SLAPolicy,
        make_settings: Callable[..., Settings],
        make_resolver: Callable[[list[dict[str, Any]]], PreflightResolver],
    ) -> None:
        """Preflight openai/gpt-5.4; LiteLLM returns azure/gpt-4o. Both
        providers allow-listed → actual policy passes; outcome="drift"."""
        resolver = _multi_alias_resolver(make_resolver)
        settings = _cloud_settings_tier1(make_settings, allowed_providers=["openai", "azure"])
        respx.post(_LITELLM_URL).mock(return_value=_ok_litellm_response("azure/gpt-4o"))
        rec = _RecordingObservability()
        gw = _build_gateway(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=resolver,
            sla_policy=default_sla_policy,
            observability=rec,
        )
        await gw.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-drift",
        )
        attrs = _only_span(rec)
        assert attrs["llm.gateway.outcome"] == "drift"
        # Drift signal: response model differs from request model — the two
        # distinct values below ARE the proof (an explicit `!=` is redundant and
        # mypy flags it as a non-overlapping-literal comparison).
        assert attrs["gen_ai.response.model"] == "azure/gpt-4o"
        assert attrs["gen_ai.request.model"] == "openai/gpt-5.4"

    async def test_invalid_tier_emits_invalid_tier_span(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """tier="tier99" → resolve_tier_alias raises UnknownTierError
        BEFORE preflight. Span carries invalid_tier; no request model."""
        from cognic_agentos.llm.gateway import UnknownTierError

        rec = _RecordingObservability()
        gw = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            observability=rec,
        )
        with pytest.raises(UnknownTierError):
            await gw.completion(
                tier="tier99",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-invalid-tier",
            )
        attrs = _only_span(rec)
        assert attrs["llm.gateway.outcome"] == "invalid_tier"
        # No preflight ran — no request model on the span.
        assert "gen_ai.request.model" not in attrs
        assert "llm.gateway.litellm_alias" not in attrs

    async def test_preflight_failure_emits_preflight_failure_span(
        self,
        monkeypatch: pytest.MonkeyPatch,
        make_settings: Callable[..., Settings],
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        make_resolver: Callable[[list[dict[str, Any]]], PreflightResolver],
        default_sla_policy: SLAPolicy,
    ) -> None:
        """tier1 alias maps to a model template referencing an UNSET
        ``${VAR}`` → PreflightResolver.resolve raises ValueError. Pins the
        ValueError arm of the ``except (UnknownAliasError, ValueError)``
        narrowed catch."""
        monkeypatch.delenv("COGNIC_OBS_UNSET_VAR", raising=False)
        resolver = make_resolver(
            [
                {
                    "model_name": "cognic-tier1-dev",
                    # No api_base; model references an env var that is not set.
                    "litellm_params": {"model": "openai/${COGNIC_OBS_UNSET_VAR}"},
                },
            ]
        )
        settings = make_settings()  # tier1_alias default = cognic-tier1-dev
        rec = _RecordingObservability()
        gw = _build_gateway(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=resolver,
            sla_policy=default_sla_policy,
            observability=rec,
        )
        with pytest.raises(ValueError, match="COGNIC_OBS_UNSET_VAR"):
            await gw.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-preflight-fail",
            )
        attrs = _only_span(rec)
        assert attrs["llm.gateway.outcome"] == "preflight_failure"
        # The alias resolved (tier→alias succeeded) but preflight did not.
        assert attrs["llm.gateway.litellm_alias"] == "cognic-tier1-dev"
        assert "gen_ai.request.model" not in attrs

    async def test_preflight_unknown_alias_emits_preflight_failure_span(
        self,
        make_settings: Callable[..., Settings],
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        make_resolver: Callable[[list[dict[str, Any]]], PreflightResolver],
        default_sla_policy: SLAPolicy,
    ) -> None:
        """tier1_alias points at an alias NOT declared in the resolver YAML
        → PreflightResolver.resolve raises UnknownAliasError. Pins the
        UnknownAliasError arm of the narrowed catch (sibling of the
        ValueError arm above)."""
        from cognic_agentos.llm.preflight import UnknownAliasError

        resolver = make_resolver(
            [
                {
                    "model_name": "cognic-some-other-alias",
                    "litellm_params": {
                        "model": "ollama/qwen3:8b",
                        "api_base": "http://ollama:11434",
                    },
                },
            ]
        )
        s = make_settings()
        settings = Settings(
            allow_external_llm=s.allow_external_llm,
            policy_mode=s.policy_mode,
            allowed_providers=list(s.allowed_providers),
            llm_guardrail_scope=s.llm_guardrail_scope,
            llm_concurrency_per_profile=s.llm_concurrency_per_profile,
            llm_concurrency_mode=s.llm_concurrency_mode,
            litellm_base_url=s.litellm_base_url,
            litellm_master_key=s.litellm_master_key,
            tier1_alias="cognic-tier1-not-in-yaml",
        )
        rec = _RecordingObservability()
        gw = _build_gateway(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=resolver,
            sla_policy=default_sla_policy,
            observability=rec,
        )
        with pytest.raises(UnknownAliasError):
            await gw.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-unknown-alias",
            )
        attrs = _only_span(rec)
        assert attrs["llm.gateway.outcome"] == "preflight_failure"

    @respx.mock
    async def test_input_guardrail_trip_emits_guardrail_input_span(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
        trip_pipeline: GuardrailPipeline,
    ) -> None:
        respx.post(_LITELLM_URL).mock(return_value=_ok_litellm_response())
        rec = _RecordingObservability()
        gw = LLMGateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            input_pipeline=trip_pipeline,
            observability=rec,
        )
        with pytest.raises(GuardrailViolationError):
            await gw.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-input-guard",
            )
        attrs = _only_span(rec)
        assert attrs["llm.gateway.outcome"] == "guardrail_input"
        # Input trip halts before dispatch — no response model.
        assert "gen_ai.response.model" not in attrs

    @respx.mock
    async def test_pre_dispatch_policy_deny_emits_policy_denied_span(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        cloud_openai_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
        make_settings: Callable[..., Settings],
    ) -> None:
        """Cloud upstream + default-deny settings → pre-dispatch
        CloudPolicyViolationError; the span says policy_denied (the ledger
        says 'denied')."""
        respx.post(_LITELLM_URL).mock(return_value=_ok_litellm_response())
        rec = _RecordingObservability()
        gw = _build_gateway(
            settings=make_settings(),
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=cloud_openai_resolver,
            sla_policy=default_sla_policy,
            observability=rec,
        )
        with pytest.raises(CloudPolicyViolationError):
            await gw.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-pre-deny",
            )
        attrs = _only_span(rec)
        assert attrs["llm.gateway.outcome"] == "policy_denied"
        # Pre-dispatch denial — preflight resolved, but no dispatch.
        assert attrs["gen_ai.request.model"] == "openai/gpt-5.4"
        assert "gen_ai.response.model" not in attrs

    @respx.mock
    async def test_post_dispatch_policy_deny_emits_policy_denied_span(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        default_sla_policy: SLAPolicy,
        make_settings: Callable[..., Settings],
        make_resolver: Callable[[list[dict[str, Any]]], PreflightResolver],
    ) -> None:
        """openai allow-listed; LiteLLM drifts to azure (NOT allowed) →
        post-response recheck denies. The span says policy_denied AND
        carries the dispatched response model (post-dispatch path)."""
        resolver = _multi_alias_resolver(make_resolver)
        settings = _cloud_settings_tier1(make_settings, allowed_providers=["openai"])
        respx.post(_LITELLM_URL).mock(return_value=_ok_litellm_response("azure/gpt-4o"))
        rec = _RecordingObservability()
        gw = _build_gateway(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=resolver,
            sla_policy=default_sla_policy,
            observability=rec,
        )
        with pytest.raises(CloudPolicyViolationError):
            await gw.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-post-deny",
            )
        attrs = _only_span(rec)
        assert attrs["llm.gateway.outcome"] == "policy_denied"
        # Post-dispatch — actual provenance is on the span.
        assert attrs["gen_ai.response.model"] == "azure/gpt-4o"

    async def test_concurrency_exhausted_emits_concurrency_span(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        fail_fast_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """Pre-saturate the fail_fast limiter so the gateway's nested
        acquire raises LLMConcurrencyExceeded. Mirrors
        test_gateway_concurrency_ledger.py."""
        rec = _RecordingObservability()
        gw = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=fail_fast_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            observability=rec,
        )
        async with fail_fast_limiter.acquire(profile="tier1"):
            with pytest.raises(LLMConcurrencyExceeded):
                await gw.completion(
                    tier="tier1",
                    messages=[{"role": "user", "content": "hi"}],
                    request_id="req-conc",
                )
        attrs = _only_span(rec)
        assert attrs["llm.gateway.outcome"] == "concurrency_exhausted"
        # Slot never acquired — no dispatch.
        assert "gen_ai.response.model" not in attrs

    async def test_connect_error_emits_upstream_error_span(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """Connect-class httpx error (best-effort regime) → upstream_error."""
        rec = _RecordingObservability()
        gw = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            observability=rec,
        )
        with (
            patch.object(
                gw._http,
                "post",
                new=AsyncMock(side_effect=httpx.ConnectError("simulated connect")),
            ),
            pytest.raises(httpx.ConnectError),
        ):
            await gw.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-connect",
            )
        attrs = _only_span(rec)
        assert attrs["llm.gateway.outcome"] == "upstream_error"

    async def test_possibly_dispatched_error_emits_upstream_error_span(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """Possibly-dispatched httpx error (strict regime) → upstream_error."""
        rec = _RecordingObservability()
        gw = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            observability=rec,
        )
        with (
            patch.object(
                gw._http,
                "post",
                new=AsyncMock(side_effect=httpx.ReadTimeout("simulated read timeout")),
            ),
            pytest.raises(httpx.ReadTimeout),
        ):
            await gw.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-readtimeout",
            )
        attrs = _only_span(rec)
        assert attrs["llm.gateway.outcome"] == "upstream_error"

    @respx.mock
    async def test_http_status_error_emits_upstream_error_span(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """A 500 response → raise_for_status → HTTPStatusError (strict
        regime) → upstream_error."""
        respx.post(_LITELLM_URL).mock(return_value=httpx.Response(500, json={"error": "boom"}))
        rec = _RecordingObservability()
        gw = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            observability=rec,
        )
        with pytest.raises(httpx.HTTPStatusError):
            await gw.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-500",
            )
        attrs = _only_span(rec)
        assert attrs["llm.gateway.outcome"] == "upstream_error"

    @respx.mock
    async def test_output_guardrail_trip_emits_guardrail_output_span(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
        trip_pipeline: GuardrailPipeline,
    ) -> None:
        respx.post(_LITELLM_URL).mock(return_value=_ok_litellm_response())
        rec = _RecordingObservability()
        gw = LLMGateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            output_pipeline=trip_pipeline,
            observability=rec,
        )
        with pytest.raises(GuardrailViolationError):
            await gw.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-output-guard",
            )
        attrs = _only_span(rec)
        assert attrs["llm.gateway.outcome"] == "guardrail_output"
        # Output trip is post-dispatch — actual provenance present.
        assert attrs["gen_ai.response.model"] == "ollama/qwen3:8b"

    @respx.mock
    async def test_strict_ledger_failure_overrides_to_strict_ledger_failure_span(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """THE OVERRIDE PIN (load-bearing). Happy-path response, but the
        SUCCESS-path strict ledger write raises → LedgerWriteFailed. The
        per-path trace.outcome was already "ok"; the wrapper's
        ``except LedgerWriteFailed`` OVERRIDES it to strict_ledger_failure
        because the call ultimately failed on the provenance write."""
        respx.post(_LITELLM_URL).mock(return_value=_ok_litellm_response())
        rec = _RecordingObservability()
        gw = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            observability=rec,
        )
        with (
            patch.object(
                gateway_ledger,
                "write_row",
                side_effect=RuntimeError("ledger DB down"),
            ),
            pytest.raises(LedgerWriteFailed),
        ):
            await gw.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-strict-ledger",
            )
        attrs = _only_span(rec)
        assert attrs["llm.gateway.outcome"] == "strict_ledger_failure", (
            "the wrapper must OVERRIDE the per-path 'ok' to strict_ledger_failure"
        )


class TestCompletionSpanEndToEnd:
    @respx.mock
    async def test_agent_workforce_id_threads_to_span(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        respx.post(_LITELLM_URL).mock(return_value=_ok_litellm_response())
        rec = _RecordingObservability()
        gw = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            observability=rec,
        )
        await gw.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-wf",
            agent_workforce_id="wf-42",
        )
        assert _only_span(rec)["llm.gateway.agent_workforce_id"] == "wf-42"

    @respx.mock
    async def test_omitted_agent_workforce_id_absent_from_span(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        respx.post(_LITELLM_URL).mock(return_value=_ok_litellm_response())
        rec = _RecordingObservability()
        gw = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            observability=rec,
        )
        await gw.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-no-wf",
        )
        assert "llm.gateway.agent_workforce_id" not in _only_span(rec)

    @respx.mock
    async def test_emit_failure_does_not_fail_the_call(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """Fail-open through completion(): the span adapter raises in the
        ``finally``, but the LLM call still returns its GatewayResponse."""
        respx.post(_LITELLM_URL).mock(return_value=_ok_litellm_response())
        rec = _RecordingObservability(raise_on_emit=True)
        gw = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            observability=rec,
        )
        resp = await gw.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-failopen",
        )
        assert resp.content == "hello"  # call succeeded despite the trace failure
