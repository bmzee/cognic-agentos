"""ADR-010 amendment — POST /api/v1/eval/bulk-run + GET /api/v1/eval/runs/{run_id}.

Single execution path: the portal runs the corpus synchronously under a cap and
persists atomically via :class:`EvalRunStore`. DI fails closed (gateway +
decision-history store resolved BEFORE execution). Endpoint statuses are bounded
to request/infra problems (403 / 503 / 413 / 400); per-case gateway failures
surface as ``errored`` cases inside the 200 body — never as a 4xx/5xx.

``from __future__ import annotations`` is OMITTED on purpose: the route builds
closure-local ``Depends(...)`` instances and FastAPI must resolve the
``Annotated[..., Depends(<local>)]`` hints eagerly (PEP 563 string-deferral would
silently demote the body to query params → 422 at request time).
"""

import uuid
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request

from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.evaluation.corpus import CorpusLoadError, validate_corpus_payload
from cognic_agentos.evaluation.runner import EvalRunner, apply_raw_output
from cognic_agentos.evaluation.scorers import AssertionScorer, CaseScorer, JudgeScorer
from cognic_agentos.evaluation.storage import EvalRunStore, mint_eval_request_id
from cognic_agentos.evaluation.target import GatewayTarget
from cognic_agentos.evaluation.types import EvalRunResult
from cognic_agentos.llm.gateway import LLMGateway
from cognic_agentos.portal.api.evaluation.dto import (
    BulkCaseResultResponse,
    BulkRunRequest,
    BulkRunResponse,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope

#: Closed-enum vocabulary for the route-owned bulk-run refusal bodies (413 / 400).
EvalBulkRefusalReason = Literal["eval_corpus_too_large", "eval_corpus_empty"]


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
    if store is None or not isinstance(store, DecisionHistoryStore):
        raise HTTPException(status_code=503, detail={"reason": "decision_history_unavailable"})
    return store


def build_eval_bulk_routes(
    *, max_cases: int, max_raw_output_chars: int, target_tier: str, judge_tier: str
) -> APIRouter:
    router = APIRouter()
    _require_bulk = RequireScope("eval.bulk.run")
    _require_read = RequireScope("eval.runs.read")

    @router.post("/bulk-run", summary="Run a corpus against a target and persist the eval run")
    async def bulk_run(
        request: Request,
        actor: Annotated[Actor, Depends(_require_bulk)],
        gateway: Annotated[LLMGateway, Depends(_require_llm_gateway)],
        dh_store: Annotated[DecisionHistoryStore, Depends(_require_decision_history_store)],
        body: BulkRunRequest,
    ) -> BulkRunResponse:
        # Correction (A): ``Corpus.cases`` carries Pydantic ``min_length=1``, so an
        # empty corpus would fail INSIDE ``validate_corpus_payload`` as a generic
        # ``corpus_*`` error. Check the RAW body cases length FIRST so the dedicated
        # ``eval_corpus_empty`` reason is reachable.
        raw_cases = body.corpus.get("cases") if isinstance(body.corpus, dict) else None
        if isinstance(raw_cases, list) and len(raw_cases) == 0:
            raise HTTPException(status_code=400, detail={"reason": "eval_corpus_empty"})
        try:
            corpus = validate_corpus_payload(body.corpus)
        except CorpusLoadError as exc:
            raise HTTPException(status_code=400, detail={"reason": exc.reason}) from None
        if len(corpus.cases) > max_cases:
            raise HTTPException(status_code=413, detail={"reason": "eval_corpus_too_large"})

        target = GatewayTarget(gateway=gateway, tier=target_tier)
        scorers: list[CaseScorer] = [
            AssertionScorer(),
            JudgeScorer(gateway=gateway, tier=judge_tier),
        ]
        run_id = uuid.uuid4()
        request_id = mint_eval_request_id()
        result = await EvalRunner().run(
            corpus,
            target=target,
            scorers=scorers,
            run_id=run_id,
            chain_request_id=request_id,
            tenant_id=actor.tenant_id,
            capture_raw_output=body.persist_raw_output,
        )
        result = apply_raw_output(
            result, persist=body.persist_raw_output, max_chars=max_raw_output_chars
        )
        store = EvalRunStore(dh_store)
        await store.persist_run(
            result=result, actor_subject=actor.subject, tenant_id=actor.tenant_id
        )
        return _to_response(result)

    @router.get("/runs/{run_id}", summary="Read a persisted eval run (tenant-scoped)")
    async def get_run(
        request: Request,
        run_id: uuid.UUID,
        actor: Annotated[Actor, Depends(_require_read)],
        dh_store: Annotated[DecisionHistoryStore, Depends(_require_decision_history_store)],
    ) -> dict[str, Any]:
        store = EvalRunStore(dh_store)
        row = await store.get_run(run_id=run_id, tenant_id=actor.tenant_id)
        if row is None:  # cross-tenant + unknown both collapse to 404
            raise HTTPException(status_code=404, detail={"reason": "eval_run_not_found"})
        return {"run": dict(row["run"]), "cases": [dict(c) for c in row["cases"]]}

    return router


def _to_response(result: EvalRunResult) -> BulkRunResponse:
    return BulkRunResponse(
        run_id=str(result.run_id),
        chain_request_id=result.chain_request_id,
        corpus_id=result.corpus_id,
        target_kind=result.target_kind,
        tier=result.tier,
        total=result.total,
        passed=result.passed,
        failed=result.failed,
        errored=result.errored,
        latency_p50_ms=result.latency_p50_ms,
        latency_p95_ms=result.latency_p95_ms,
        cases=[
            BulkCaseResultResponse(
                case_id=c.case_id,
                passed=c.passed,
                outcome=c.outcome,
                latency_ms=c.latency_ms,
                model=c.model,
                raw_output_persisted=c.raw_output_persisted,
                output_truncated=c.output_truncated,
            )
            for c in result.cases
        ],
    )
