"""Sprint 3 T6 phase B — Round-2 reviewer-P2 concurrency-ledger.

LLMConcurrencyExceeded must produce a best-effort ledger row before
propagating, so ``/effective-routing`` records the saturation event.
Without this, fail_fast saturation would exit silently from the
gateway with no ledger trail.
"""

from __future__ import annotations

import pytest

from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.config import Settings
from cognic_agentos.core.sla import SLAPolicy
from cognic_agentos.llm.concurrency import LLMConcurrencyExceeded, ProfileRateLimiter
from cognic_agentos.llm.gateway import LLMGateway
from cognic_agentos.llm.ledger import GatewayCallLedger
from cognic_agentos.llm.preflight import PreflightResolver


class TestConcurrencyLedger:
    async def test_saturation_writes_best_effort_ledger_then_raises(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        fail_fast_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """Saturate the limiter via the public acquire(), then the
        gateway's nested acquire raises LLMConcurrencyExceeded. Asserts:
        - The exception propagates to the caller.
        - A ledger row exists with outcome="concurrency_exhausted",
          provenance="no_dispatch", upstream identity = preflight.
        """
        # Pre-saturate the limiter outside the gateway.
        gateway = LLMGateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=fail_fast_limiter,  # capacity=1, mode=fail_fast
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
        )
        async with fail_fast_limiter.acquire(profile="tier1"):
            # Slot saturated. gateway.completion → fail_fast raise.
            with pytest.raises(LLMConcurrencyExceeded):
                await gateway.completion(
                    tier="tier1",
                    messages=[{"role": "user", "content": "hi"}],
                    request_id="req-saturated",
                )
        # Ledger row written best-effort BEFORE the exception
        # propagated.
        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].outcome == "concurrency_exhausted"
        assert rows[0].provenance == "no_dispatch"
        assert rows[0].upstream_model == "ollama/qwen3:8b"  # preflight identity
        assert rows[0].external is False
