"""Sprint 3 T6 phase B — Round-7 + Round-8 post-dispatch strict
discipline.

After dispatch, the gateway emits sla.breach,
gateway.upstream_drift_detected, post-response gateway.cloud_policy_
denied, gateway.upstream_unresolved, gateway.upstream_classification_
ambiguous. Round-7 reviewer-P1: if AuditStore.append raises on any
of these, the gateway must still strict-ledger before propagating
the AuditStore exception. Round-8 reviewer-P1: ``actual_resolved``
is bound BEFORE the audit emit so the catch-all ledgers with the
correct provenance state, not the preflight identity.

Tests cover:
- AuditStore raises on the unresolved event → ledger row carries
  provenance="unresolved", NOT preflight provenance="resolved".
- AuditStore raises on the ambiguous event → ledger row carries
  provenance="ambiguous", NOT preflight.
- AuditStore raises on the drift event → ledger row carries actual_
  resolved provenance.
- Malformed response content (non-string content) → strict ledger +
  re-raise.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest
import respx

from cognic_agentos.core.audit import AuditEvent, AuditStore
from cognic_agentos.core.config import Settings
from cognic_agentos.core.sla import SLAPolicy
from cognic_agentos.llm.concurrency import ProfileRateLimiter
from cognic_agentos.llm.gateway import LLMGateway
from cognic_agentos.llm.ledger import GatewayCallLedger
from cognic_agentos.llm.preflight import PreflightResolver


def _resp(model: str | None = "ollama/qwen3:8b", content: str = "hi") -> httpx.Response:
    body: dict[str, Any] = {"choices": [{"message": {"content": content}}]}
    if model is not None:
        body["model"] = model
    return httpx.Response(200, json=body)


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


class _RaisingAuditStore:
    """Test wrapper: raises RuntimeError when ``event_type`` matches
    ``raise_on``; otherwise delegates to the inner store."""

    def __init__(self, inner: AuditStore, *, raise_on: str) -> None:
        self._inner = inner
        self._raise_on = raise_on
        self.calls: list[str] = []

    async def append(self, event: AuditEvent) -> None:
        self.calls.append(event.event_type)
        if event.event_type == self._raise_on:
            raise RuntimeError(f"simulated audit failure on {event.event_type}")
        await self._inner.append(event)


class TestPostDispatchAuditFailures:
    @respx.mock
    async def test_audit_failure_on_upstream_unresolved_preserves_provenance(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        default_sla_policy: SLAPolicy,
        make_settings: Callable[..., Settings],
        make_resolver: Callable[[list[dict[str, Any]]], PreflightResolver],
    ) -> None:
        """Round-7 P1#2 + Round-8 P1: AuditStore raises on
        gateway.upstream_unresolved. Strict ledger row MUST carry
        provenance="unresolved" — NOT preflight resolved."""
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
            return_value=_resp("openai/gpt-7")  # unresolved
        )
        raising_store = _RaisingAuditStore(audit_store, raise_on="gateway.upstream_unresolved")
        gateway = LLMGateway(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=raising_store,  # type: ignore[arg-type]
            rate_limiter=rate_limiter,
            preflight=resolver,
            sla_policy=default_sla_policy,
        )
        with pytest.raises(RuntimeError, match="simulated audit failure"):
            await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-audit-fail-unresolved",
            )
        # Strict-regime ledger row written with the CORRECT provenance.
        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].provenance == "unresolved"
        assert rows[0].upstream_model == "openai/gpt-7"
        assert rows[0].upstream_api_base is None
        assert rows[0].outcome == "upstream_error"

    @respx.mock
    async def test_audit_failure_on_classification_ambiguous_preserves_provenance(
        self,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        default_sla_policy: SLAPolicy,
        make_settings: Callable[..., Settings],
        make_resolver: Callable[[list[dict[str, Any]]], PreflightResolver],
    ) -> None:
        """AuditStore raises on
        gateway.upstream_classification_ambiguous. Strict ledger row
        MUST carry provenance="ambiguous" — NOT preflight."""
        resolver = make_resolver(
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
                    "litellm_params": {"model": "openai/gpt-4o", "api_key": "sk"},
                },
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
            return_value=_resp("openai/gpt-4o")
        )
        raising_store = _RaisingAuditStore(
            audit_store, raise_on="gateway.upstream_classification_ambiguous"
        )
        gateway = LLMGateway(
            settings=settings,
            ledger=gateway_ledger,
            audit_store=raising_store,  # type: ignore[arg-type]
            rate_limiter=rate_limiter,
            preflight=resolver,
            sla_policy=default_sla_policy,
        )
        with pytest.raises(RuntimeError, match="simulated audit failure"):
            await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-audit-fail-ambig",
            )
        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].provenance == "ambiguous"
        assert rows[0].upstream_api_base is None

    @respx.mock
    async def test_invalid_json_body_writes_exactly_one_ledger_row(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """Round-9 reviewer-P2: when ``resp.json()`` raises (LiteLLM
        returned a 200 with non-JSON body), the inner handler strict-
        ledgers + re-raises. The outer post-dispatch catch-all MUST
        treat the JSON-parse exception as already-ledgered — otherwise
        a single call writes two ``outcome='upstream_error'`` rows
        and ADR-007's one-call/one-ledger-row contract for
        ``/effective-routing`` counts breaks. Asserts exactly one
        ledger row."""
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=httpx.Response(200, content=b"not-valid-json")
        )
        gateway = LLMGateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
        )
        with pytest.raises(Exception):  # noqa: B017 — json.JSONDecodeError surfaces
            await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-bad-json",
            )
        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1, (
            f"expected exactly one ledger row per call (ADR-007 honesty contract); got {len(rows)}"
        )
        # Inner handler ledgers with preflight identity (actual not yet
        # built — body never parsed).
        assert rows[0].outcome == "upstream_error"
        assert rows[0].provenance == "resolved"  # preflight resolved fine
        assert rows[0].upstream_model == "ollama/qwen3:8b"

    @respx.mock
    async def test_http_status_error_writes_exactly_one_ledger_row(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """Companion guard: a non-2xx response from LiteLLM also
        triggers the inner strict-ledger path. Confirm only one row
        is written. The outer catch-all already lists
        ``_httpx.HTTPStatusError`` as already-ledgered, but the same
        single-row contract still needs a regression because we just
        widened the inner-pass-through set."""
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=httpx.Response(500, json={"error": "upstream down"})
        )
        gateway = LLMGateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
        )
        with pytest.raises(httpx.HTTPStatusError):
            await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-500",
            )
        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].outcome == "upstream_error"
        assert rows[0].provenance == "resolved"

    @respx.mock
    async def test_malformed_content_no_choices_strict_ledgers_and_reraises(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """Round-7 reviewer-P1 malformed content path: response has no
        ``choices`` key → KeyError → ``_MalformedResponseContent`` →
        outer catch-all strict-ledgers + re-raises."""
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={"model": "ollama/qwen3:8b"},  # no choices
            )
        )
        gateway = LLMGateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
        )
        with pytest.raises(Exception):  # noqa: B017 — _MalformedResponseContent is internal
            await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-malformed",
            )
        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        # actual_resolved was built before the malformed-content
        # extraction → provenance="resolved" (the model field was
        # parsed successfully).
        assert rows[0].provenance == "resolved"
        assert rows[0].outcome == "upstream_error"

    @respx.mock
    async def test_malformed_content_non_string_strict_ledgers(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        respx.post("http://litellm.test:4000/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "model": "ollama/qwen3:8b",
                    "choices": [{"message": {"content": 42}}],  # non-string
                },
            )
        )
        gateway = LLMGateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
        )
        with pytest.raises(Exception):  # noqa: B017
            await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-non-string",
            )
        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].outcome == "upstream_error"
