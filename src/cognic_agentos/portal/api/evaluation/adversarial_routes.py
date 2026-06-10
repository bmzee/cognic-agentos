"""ADR-011 Sprint-13b — POST /api/v1/eval/adversarial-run.

Run an all-adversarial corpus against the current target config + RefusalScorer →
single-run AdversarialVerdict + a value-free eval.adversarial_run row. Fail-closed
DI (gateway + decision-history store before work). Statuses: 403/503/413/400 (+422).
NO baseline_run_id (13b is standalone). ``from __future__ import annotations`` is
OMITTED (closure-local Depends).
"""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request

from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.evaluation.adversarial.runner import run_adversarial
from cognic_agentos.evaluation.corpus import CorpusLoadError, validate_corpus_payload
from cognic_agentos.evaluation.storage import EvalRunStore
from cognic_agentos.llm.gateway import LLMGateway
from cognic_agentos.portal.api.evaluation.dto import (
    AdversarialCaseResultResponse,
    AdversarialRunRequest,
    AdversarialVerdictResponse,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope

# The ONE adversarial-specific post-validate refusal. The corpus/cap reasons
# (``eval_corpus_empty`` / ``eval_corpus_too_large``) are reused from the shared
# eval vocabulary (``EvalBulkRefusalReason`` in bulk_routes.py — not redeclared
# here to avoid two competing owners of the same strings) and the DI-layer 503
# reasons (``llm_gateway_unavailable`` / ``decision_history_unavailable``) are
# shared with bulk + replay. Pinned by test_adversarial_refusal_reason_closed_set
# in tests/unit/portal/api/evaluation/test_adversarial_routes.py.
EvalAdversarialRefusalReason = Literal["corpus_not_all_adversarial"]


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


def build_eval_adversarial_routes(
    *, max_cases: int, max_raw_output_chars: int, target_tier: str, judge_tier: str
) -> APIRouter:
    router = APIRouter()
    _require_adv = RequireScope("eval.adversarial.run")

    @router.post("/adversarial-run", summary="Run an adversarial corpus; refusal verdict")
    async def adversarial_run(
        request: Request,
        actor: Annotated[Actor, Depends(_require_adv)],
        gateway: Annotated[LLMGateway, Depends(_require_llm_gateway)],
        dh_store: Annotated[DecisionHistoryStore, Depends(_require_decision_history_store)],
        body: AdversarialRunRequest,
    ) -> AdversarialVerdictResponse:
        raw_cases = body.corpus.get("cases") if isinstance(body.corpus, dict) else None
        if isinstance(raw_cases, list) and len(raw_cases) == 0:
            raise HTTPException(status_code=400, detail={"reason": "eval_corpus_empty"})
        try:
            corpus = validate_corpus_payload(body.corpus)
        except CorpusLoadError as exc:
            raise HTTPException(status_code=400, detail={"reason": exc.reason}) from None
        # Adversarial-only preflight (fail-closed): every case must be adversarial.
        # Runs AFTER empty + validate (those refusals keep precedence) but BEFORE
        # the cap so the expanded-count cap can safely read each case's
        # mutation_strategies (a completion case carries no adversarial block). This
        # is also the route's primary gate against a completion case reaching
        # run_adversarial (whose own ValueError guard is defence-in-depth).
        if any(c.case_kind != "adversarial" for c in corpus.cases):
            raise HTTPException(status_code=400, detail={"reason": "corpus_not_all_adversarial"})
        # Cap the EXPANDED runnable set (base x strategies), NOT the authored base
        # count: run_adversarial expands each case to base x mutation_strategies and
        # runs/persists the expanded set, so this is what actually bounds target
        # calls. The base count is subsumed (expanded >= base, every case has >=1
        # strategy), so no separate base-count cap is needed.
        blocks = [c.adversarial for c in corpus.cases if c.adversarial is not None]
        expanded_count = sum(len(b.mutation_strategies) for b in blocks)
        if expanded_count > max_cases:
            raise HTTPException(status_code=413, detail={"reason": "eval_corpus_too_large"})

        store = EvalRunStore(dh_store)
        verdict = await run_adversarial(
            corpus=corpus,
            gateway=gateway,
            store=store,
            target_tier=target_tier,
            judge_tier=judge_tier,
            max_raw_output_chars=max_raw_output_chars,
            tenant_id=actor.tenant_id,
            actor_subject=actor.subject,
            persist_raw_output=body.persist_raw_output,
        )
        return AdversarialVerdictResponse(
            candidate_run_id=str(verdict.candidate_run_id),
            corpus_id=verdict.corpus_id,
            total=verdict.total,
            passed=verdict.passed,
            failed=verdict.failed,
            errored=verdict.errored,
            overall_pass_rate=verdict.overall_pass_rate,
            per_category_pass_rate=dict(verdict.per_category_pass_rate),
            high_severity_all_pass=verdict.high_severity_all_pass,
            cases=[
                AdversarialCaseResultResponse(
                    base_case_id=c.base_case_id,
                    expanded_case_id=c.expanded_case_id,
                    attack_category=c.attack_category,
                    mutation_strategy=c.mutation_strategy,
                    severity=c.severity,
                    passed=c.passed,
                )
                for c in verdict.per_case
            ],
        )

    return router
