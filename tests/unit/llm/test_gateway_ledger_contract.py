"""Sprint 3 T6 phase B — Round-1 reviewer-P1#1 ledger success contract.

ADR-007's authoritativeness contract: a successful ``GatewayResponse``
cannot return without a persisted ledger row. If the strict-regime
ledger write fails, the gateway raises :class:`LedgerWriteFailed`
(chained from any in-flight exception via ``raise from``) — caller
sees a 5xx, never a successful response with no provenance.

Pre-dispatch failure paths use the best-effort regime: ledger gap
costs ``/effective-routing`` count fidelity but not chain-of-custody
because the hash-chained ``audit_event`` already records the
violation.
"""

from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest
import respx

from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.config import Settings
from cognic_agentos.core.sla import SLAPolicy
from cognic_agentos.llm.concurrency import ProfileRateLimiter
from cognic_agentos.llm.gateway import GatewayResponse, LedgerWriteFailed, LLMGateway
from cognic_agentos.llm.ledger import GatewayCallLedger
from cognic_agentos.llm.preflight import PreflightResolver


def _ok() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "model": "ollama/qwen3:8b",
            "choices": [{"message": {"content": "hi"}}],
        },
    )


class TestStrictWriteFailureContract:
    @respx.mock
    async def test_strict_write_failure_raises_LedgerWriteFailed(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        respx.post("http://litellm.test:4000/chat/completions").mock(return_value=_ok())
        gateway = LLMGateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
        )
        # Stub the ledger's write_row to raise on the FIRST call (the
        # happy-path strict write).
        with (
            patch.object(
                gateway_ledger,
                "write_row",
                side_effect=RuntimeError("simulated DB down"),
            ),
            pytest.raises(LedgerWriteFailed) as exc_info,
        ):
            await gateway.completion(
                tier="tier1",
                messages=[{"role": "user", "content": "hi"}],
                request_id="req-strict-fail",
            )
        # __cause__ chains from the original RuntimeError.
        assert isinstance(exc_info.value.__cause__, RuntimeError)
        assert "simulated DB down" in str(exc_info.value.__cause__)

    @respx.mock
    async def test_no_GatewayResponse_returned_when_strict_write_fails(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """Negative regression: caller MUST NOT receive a
        GatewayResponse when the strict write fails. The whole point
        of ADR-007's success contract."""
        respx.post("http://litellm.test:4000/chat/completions").mock(return_value=_ok())
        gateway = LLMGateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
        )
        with patch.object(
            gateway_ledger,
            "write_row",
            side_effect=RuntimeError("DB down"),
        ):
            try:
                result = await gateway.completion(
                    tier="tier1",
                    messages=[{"role": "user", "content": "hi"}],
                    request_id="req-no-response",
                )
            except LedgerWriteFailed:
                # Expected — caller does NOT see a GatewayResponse.
                return
            pytest.fail(
                f"unexpected GatewayResponse {result!r} returned despite strict-ledger failure"
            )

    @respx.mock
    async def test_happy_path_writes_exactly_one_ledger_row(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """Negative regression confirming the success path writes
        exactly one row — no double-write, no off-by-one."""
        respx.post("http://litellm.test:4000/chat/completions").mock(return_value=_ok())
        gateway = LLMGateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
        )
        response = await gateway.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-happy-once",
        )
        assert isinstance(response, GatewayResponse)
        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
