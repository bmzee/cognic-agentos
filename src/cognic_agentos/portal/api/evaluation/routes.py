"""ADR-010 eval judge surface — POST /api/v1/eval/judge.

DI fail-closed BEFORE any gateway call (both the gateway AND the decision-history
store): a judge call must never dispatch unless its evidence can be recorded.
``from __future__ import annotations`` is OMITTED (FastAPI closure-local Depends).
"""

import hashlib
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request

from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.evaluation.judge import JudgeParsed, JudgeUnparseable, run_judge
from cognic_agentos.llm.concurrency import LLMConcurrencyExceeded
from cognic_agentos.llm.gateway import LLMGateway
from cognic_agentos.llm.policy import CloudPolicyViolationError, GuardrailViolationError
from cognic_agentos.portal.api.evaluation.dto import JudgeRequest, JudgeVerdictResponse
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope

_LOG = logging.getLogger(__name__)
_ISO = ("ISO42001.A.7.4",)


def _digest(text: str | None) -> str | None:
    return hashlib.sha256(text.encode("utf-8")).hexdigest() if text is not None else None


def _gateway_exc_to_status(exc: Exception) -> int:
    # explicit table; 502 default covers httpx/SLA/upstream/unknown — no raw 500.
    if isinstance(exc, LLMConcurrencyExceeded):
        return 429
    if isinstance(exc, GuardrailViolationError | CloudPolicyViolationError):
        return 502
    return 502


def _require_llm_gateway(request: Request) -> LLMGateway:
    gw: LLMGateway | None = getattr(request.app.state, "llm_gateway", None)
    if gw is None:
        raise HTTPException(status_code=503, detail={"reason": "llm_gateway_unavailable"})
    return gw


def _require_decision_history_store(request: Request) -> DecisionHistoryStore:
    runtime = getattr(request.app.state, "runtime", None)
    store: DecisionHistoryStore | None = (
        runtime.decision_history_store
        if runtime is not None
        else getattr(request.app.state, "decision_history_store", None)
    )
    if store is None:
        raise HTTPException(status_code=503, detail={"reason": "decision_history_unavailable"})
    return store


def build_eval_routes(*, eval_judge_tier: str) -> APIRouter:
    router = APIRouter()
    _require_scope = RequireScope("eval.judge.run")

    @router.post("/judge", summary="Run a governed LLM-as-judge over a candidate output")
    async def judge(
        request: Request,
        actor: Annotated[Actor, Depends(_require_scope)],
        gateway: Annotated[LLMGateway, Depends(_require_llm_gateway)],
        store: Annotated[DecisionHistoryStore, Depends(_require_decision_history_store)],
        body: JudgeRequest,
    ) -> JudgeVerdictResponse:
        request_id = getattr(request.state, "request_id", None) or "eval-judge"
        input_digest = _digest(body.candidate_input)
        output_digest = _digest(body.candidate_output)
        criteria = [{"name": c.name, "description": c.description} for c in body.criteria]
        try:
            outcome = await run_judge(
                request=body,
                gateway=gateway,
                request_id=request_id,
                tenant_id=actor.tenant_id,
                tier=eval_judge_tier,
            )
        except Exception as exc:
            # run_judge's only raising op is the gateway call (it parses fail-closed).
            # Mode B: gateway failed before content; it already audited/ledgered → NO eval event.
            status = _gateway_exc_to_status(exc)
            _LOG.warning(
                "eval.judge.gateway_failed",
                extra={"exc_type": type(exc).__name__, "request_id": request_id},
            )
            raise HTTPException(
                status_code=status, detail={"reason": "gateway_call_failed"}
            ) from None

        if isinstance(outcome, JudgeUnparseable):
            await store.append(
                DecisionRecord(
                    decision_type="eval.judge_verdict",
                    request_id=request_id,
                    actor_id=actor.subject,
                    tenant_id=actor.tenant_id,
                    iso_controls=_ISO,
                    payload={
                        "status": "errored",
                        "parse_reason": outcome.parse_reason,
                        "criteria": criteria,
                        "input_digest": input_digest,
                        "output_digest": output_digest,
                        "response_digest": _digest(outcome.response.content),
                        "model": outcome.response.upstream_model,
                        "tier": outcome.response.tier,
                        "latency_ms": outcome.response.latency_ms,
                    },
                )
            )
            raise HTTPException(status_code=502, detail={"reason": "judge_verdict_unparseable"})

        assert isinstance(outcome, JudgeParsed)
        await store.append(
            DecisionRecord(
                decision_type="eval.judge_verdict",
                request_id=request_id,
                actor_id=actor.subject,
                tenant_id=actor.tenant_id,
                iso_controls=_ISO,
                payload={
                    "status": "succeeded",
                    "verdict": outcome.verdict,
                    "score": outcome.score,
                    "criteria_results": [r.model_dump() for r in outcome.criteria_results],
                    "criteria": criteria,
                    "input_digest": input_digest,
                    "output_digest": output_digest,
                    "model": outcome.response.upstream_model,
                    "tier": outcome.response.tier,
                    "latency_ms": outcome.response.latency_ms,
                },
            )
        )
        return JudgeVerdictResponse(
            verdict=outcome.verdict,
            score=outcome.score,
            rationale=outcome.rationale,
            criteria_results=list(outcome.criteria_results),
            model=outcome.response.upstream_model,
            tier=outcome.response.tier,
            latency_ms=outcome.response.latency_ms,
        )

    return router
