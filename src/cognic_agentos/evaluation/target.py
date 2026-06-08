# src/cognic_agentos/evaluation/target.py
"""Sprint 12 evaluation target seam (ADR-010 amendment).

``EvaluationTarget`` is the Sprint-13 plug-in surface (MCP / A2A / replay targets
conform later). ``GatewayTarget`` is the only Wave-1 target: it dispatches a case's
message list through the governed ``LLMGateway`` at the operator-configured
``eval_bulk_target_tier`` and catches the known gateway exceptions, surfacing them
as an ``errored`` CandidateOutput so a single bad case never aborts the run.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from cognic_agentos.evaluation.types import CandidateOutput
from cognic_agentos.llm.concurrency import LLMConcurrencyExceeded
from cognic_agentos.llm.gateway import LedgerWriteFailed, UnknownTierError
from cognic_agentos.llm.policy import CloudPolicyViolationError, GuardrailViolationError
from cognic_agentos.llm.preflight import UnknownAliasError

if TYPE_CHECKING:
    from cognic_agentos.evaluation.corpus import EvalCase
    from cognic_agentos.llm.gateway import LLMGateway

#: The closed set of gateway exceptions a target converts to an ``errored`` case.
#: SLA breaches do NOT raise (audit-only), so there is no SLA exception here.
_GATEWAY_EXCEPTIONS: tuple[type[Exception], ...] = (
    LLMConcurrencyExceeded,
    CloudPolicyViolationError,
    GuardrailViolationError,
    UnknownAliasError,
    UnknownTierError,
    LedgerWriteFailed,
)


class EvaluationTarget(Protocol):
    async def run_case(
        self, case: EvalCase, *, request_id: str, tenant_id: str
    ) -> CandidateOutput: ...


class GatewayTarget:
    """Wave-1 target — one governed ``completion()`` per case."""

    target_kind = "gateway"

    def __init__(self, *, gateway: LLMGateway, tier: str) -> None:
        self._gateway = gateway
        self._tier = tier

    @property
    def tier(self) -> str:
        return self._tier

    async def run_case(self, case: EvalCase, *, request_id: str, tenant_id: str) -> CandidateOutput:
        messages = [{"role": m.role, "content": m.content} for m in case.messages]
        try:
            resp = await self._gateway.completion(
                tier=self._tier,
                messages=messages,
                request_id=request_id,
                tenant_id=tenant_id,
            )
        except _GATEWAY_EXCEPTIONS as exc:
            return CandidateOutput(
                text="",
                model="",
                tier=self._tier,
                latency_ms=0,
                outcome="errored",
                error_category=type(exc).__name__,
            )
        return CandidateOutput(
            text=resp.content,
            model=resp.upstream_model,
            tier=resp.tier,
            latency_ms=resp.latency_ms,
            outcome="succeeded",
        )
