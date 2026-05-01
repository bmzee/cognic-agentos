"""Sprint 3 T6 phase B — Round-5 reviewer-P1 httpx exception split.

Pre-dispatch (best-effort regime): connect-class failures only —
``ConnectError``, ``ConnectTimeout``, ``PoolTimeout``,
``LocalProtocolError``.

Post-dispatch (strict regime): ALL OTHER ``httpx.RequestError``
subclasses (``ReadTimeout``, ``ReadError``, ``WriteError``,
``WriteTimeout``, ``RemoteProtocolError``) — request bytes left the
gateway, LiteLLM may already have contacted upstream.

Plus HTTP status errors after ``httpx.post`` succeeded + JSON parse
errors on response body — both strict regime.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.config import Settings
from cognic_agentos.core.sla import SLAPolicy
from cognic_agentos.llm.concurrency import ProfileRateLimiter
from cognic_agentos.llm.gateway import LedgerWriteFailed, LLMGateway
from cognic_agentos.llm.ledger import GatewayCallLedger
from cognic_agentos.llm.preflight import PreflightResolver


def _build(
    *,
    settings: Settings,
    ledger: GatewayCallLedger,
    audit_store: AuditStore,
    rate_limiter: ProfileRateLimiter,
    preflight: PreflightResolver,
    sla_policy: SLAPolicy,
) -> LLMGateway:
    return LLMGateway(
        settings=settings,
        ledger=ledger,
        audit_store=audit_store,
        rate_limiter=rate_limiter,
        preflight=preflight,
        sla_policy=sla_policy,
    )


# ---------------------------------------------------------------------------
# Parametrise across the connect-class (best-effort) + dispatched
# (strict) httpx error families.
# ---------------------------------------------------------------------------


_PRE_DISPATCH_ERRORS = [
    httpx.ConnectError("simulated connect"),
    httpx.ConnectTimeout("simulated connect timeout"),
    httpx.PoolTimeout("simulated pool timeout"),
    httpx.LocalProtocolError("simulated local protocol"),
]

_POST_DISPATCH_ERRORS = [
    httpx.ReadTimeout("simulated read timeout"),
    httpx.ReadError("simulated read error"),
    httpx.WriteError("simulated write error"),
    httpx.WriteTimeout("simulated write timeout"),
    httpx.RemoteProtocolError("simulated remote protocol"),
]


class TestPreDispatchHttpxErrors:
    @pytest.mark.parametrize(
        "exc_factory",
        _PRE_DISPATCH_ERRORS,
        ids=lambda e: type(e).__name__,
    )
    async def test_pre_dispatch_uses_best_effort_regime(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
        exc_factory: httpx.RequestError,
    ) -> None:
        """ConnectError / ConnectTimeout / PoolTimeout /
        LocalProtocolError are pre-dispatch best-effort: ledger row
        with preflight identity + provenance="no_dispatch"."""
        gateway = _build(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
        )
        with (
            patch.object(
                gateway._http,
                "post",
                new=AsyncMock(side_effect=exc_factory),
            ),
            pytest.raises(type(exc_factory)),
        ):
            await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id=f"req-pre-{type(exc_factory).__name__}",
            )
        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].outcome == "upstream_error"
        assert rows[0].provenance == "no_dispatch"
        assert rows[0].upstream_model == "ollama/qwen3:8b"


class TestPostDispatchHttpxErrors:
    @pytest.mark.parametrize(
        "exc_factory",
        _POST_DISPATCH_ERRORS,
        ids=lambda e: type(e).__name__,
    )
    async def test_post_dispatch_uses_strict_regime(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
        exc_factory: httpx.RequestError,
    ) -> None:
        """ReadTimeout / ReadError / WriteError / WriteTimeout /
        RemoteProtocolError are possibly-dispatched: strict regime
        with preflight identity (LiteLLM didn't return a parseable
        model field) + provenance="resolved"."""
        gateway = _build(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
        )
        with (
            patch.object(
                gateway._http,
                "post",
                new=AsyncMock(side_effect=exc_factory),
            ),
            pytest.raises(type(exc_factory)),
        ):
            await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id=f"req-post-{type(exc_factory).__name__}",
            )
        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].outcome == "upstream_error"
        # provenance="resolved" because the strict path uses the
        # preflight ResolvedUpstream as identity when LiteLLM didn't
        # return a parseable model field. The dev resolver's preflight
        # is unambiguous.
        assert rows[0].provenance == "resolved"
        assert rows[0].upstream_model == "ollama/qwen3:8b"

    async def test_strict_ledger_failure_on_dispatched_httpx_error_raises_LedgerWriteFailed(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """Negative regression: when both the dispatched httpx error
        AND the strict ledger write fail, the caller sees
        LedgerWriteFailed (chained from the original httpx error) —
        NOT the bare httpx.ReadTimeout. ADR-007 success contract."""
        gateway = _build(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
        )
        with (
            patch.object(
                gateway._http,
                "post",
                new=AsyncMock(side_effect=httpx.ReadTimeout("read timeout")),
            ),
            patch.object(
                gateway_ledger,
                "write_row",
                side_effect=RuntimeError("ledger DB down"),
            ),
            pytest.raises(LedgerWriteFailed),
        ):
            await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-strict-rt",
            )
