"""Gateway-observability workstream — value-free OTel span (ADR-009).

Critical-controls posture (gateway.py is on the CC coverage gate):
- Task 1 unit-tests the emit helper in ISOLATION (every attribute branch +
  the None-observability early return + the fail-open path), so the helper
  is fully covered at this commit before Task 2 wires it into completion().
"""

from __future__ import annotations

import logging
import typing

import pytest

from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.config import Settings
from cognic_agentos.core.sla import SLAPolicy
from cognic_agentos.db.adapters.protocols import AdapterHealth
from cognic_agentos.llm.concurrency import ProfileRateLimiter
from cognic_agentos.llm.gateway import (
    GatewayTraceOutcome,
    LLMGateway,
    _CompletionTrace,
)
from cognic_agentos.llm.ledger import GatewayCallLedger
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
