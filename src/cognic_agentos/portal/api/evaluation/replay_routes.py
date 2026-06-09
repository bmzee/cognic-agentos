"""ADR-010 Sprint-13a — POST /api/v1/eval/replay.

Re-run a corpus at the current target config and diff vs a baseline run. DI
fails closed (gateway + decision-history store BEFORE work). Handler-raised
statuses: 403/503/413/400/404/409 (+422 body-validation); a partial-failure of
the eval.replay append after the candidate persists yields 5xx (candidate is a
valid standalone run; non-idempotent). ``from __future__ import annotations`` is
OMITTED (closure-local Depends).
"""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request

from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.evaluation.corpus import CorpusLoadError, corpus_digest, validate_corpus_payload
from cognic_agentos.evaluation.replay import run_replay
from cognic_agentos.evaluation.storage import EvalRunStore
from cognic_agentos.llm.gateway import LLMGateway
from cognic_agentos.portal.api.evaluation.dto import (
    ReplayCaseDiffResponse,
    ReplayDiffResponse,
    ReplayRequest,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope

# Replay-SPECIFIC (post-baseline) refusal vocabulary — NOT the full route vocabulary.
# The route ALSO emits the corpus refusals ``eval_corpus_empty`` / ``eval_corpus_too_large``
# (reused from ``EvalBulkRefusalReason`` in bulk_routes.py — not redeclared here to avoid
# two competing owners of the same strings) and the DI-layer 503 reasons
# ``llm_gateway_unavailable`` / ``decision_history_unavailable`` (shared with bulk).
# These two are the only refusals unique to the replay surface. Pinned by
# tests/unit/portal/api/evaluation/test_replay_routes.py::test_replay_refusal_reason_closed_set.
EvalReplayRefusalReason = Literal["baseline_run_not_found", "replay_corpus_digest_mismatch"]


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


def build_eval_replay_routes(
    *, max_cases: int, max_raw_output_chars: int, target_tier: str, judge_tier: str
) -> APIRouter:
    router = APIRouter()
    _require_replay = RequireScope("eval.replay.run")

    @router.post("/replay", summary="Re-run a corpus at current config; diff vs a baseline run")
    async def replay(
        request: Request,
        actor: Annotated[Actor, Depends(_require_replay)],
        gateway: Annotated[LLMGateway, Depends(_require_llm_gateway)],
        dh_store: Annotated[DecisionHistoryStore, Depends(_require_decision_history_store)],
        body: ReplayRequest,
    ) -> ReplayDiffResponse:
        raw_cases = body.corpus.get("cases") if isinstance(body.corpus, dict) else None
        if isinstance(raw_cases, list) and len(raw_cases) == 0:
            raise HTTPException(status_code=400, detail={"reason": "eval_corpus_empty"})
        try:
            corpus = validate_corpus_payload(body.corpus)
        except CorpusLoadError as exc:
            raise HTTPException(status_code=400, detail={"reason": exc.reason}) from None
        if len(corpus.cases) > max_cases:
            raise HTTPException(status_code=413, detail={"reason": "eval_corpus_too_large"})

        store = EvalRunStore(dh_store)
        baseline = await store.get_run(run_id=body.baseline_run_id, tenant_id=actor.tenant_id)
        if baseline is None:  # cross-tenant + unknown both collapse
            raise HTTPException(status_code=404, detail={"reason": "baseline_run_not_found"})
        if corpus_digest(corpus) != str(baseline["run"]["corpus_digest"]):
            raise HTTPException(status_code=409, detail={"reason": "replay_corpus_digest_mismatch"})

        diff = await run_replay(
            corpus=corpus,
            baseline_run_id=body.baseline_run_id,
            baseline_cases=[dict(c) for c in baseline["cases"]],
            baseline_tier=str(baseline["run"]["tier"]),
            gateway=gateway,
            store=store,
            target_tier=target_tier,
            judge_tier=judge_tier,
            max_raw_output_chars=max_raw_output_chars,
            tenant_id=actor.tenant_id,
            actor_subject=actor.subject,
            persist_raw_output=body.persist_raw_output,
        )
        return ReplayDiffResponse(
            baseline_run_id=str(diff.baseline_run_id),
            candidate_run_id=str(diff.candidate_run_id),
            corpus_id=diff.corpus_id,
            corpus_digest=diff.corpus_digest,
            total=diff.total,
            regressions=diff.regressions,
            improvements=diff.improvements,
            unchanged=diff.unchanged,
            output_changed=diff.output_changed,
            errored=diff.errored,
            has_regressions=diff.has_regressions,
            cases=[
                ReplayCaseDiffResponse(
                    case_id=c.case_id,
                    drift_kind=c.drift_kind,
                    baseline_passed=c.baseline_passed,
                    candidate_passed=c.candidate_passed,
                    baseline_outcome=c.baseline_outcome,
                    candidate_outcome=c.candidate_outcome,
                    output_digest_changed=c.output_digest_changed,
                    baseline_model=c.baseline_model,
                    candidate_model=c.candidate_model,
                    baseline_tier=c.baseline_tier,
                    candidate_tier=c.candidate_tier,
                )
                for c in diff.cases
            ],
        )

    return router
