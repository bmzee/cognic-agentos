"""ADR-011 Sprint-13b — adversarial run orchestrator.

Expand (base x strategies) → run via EvalRunner + [RefusalScorer] → compute the
single-run AdversarialVerdict (pass-rate over RUNNABLE EXPANDED cases only) →
persist the candidate as a first-class eval-run → emit the value-free
eval.adversarial_run chain row. NO baseline, NO regression (13c owns those).
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cognic_agentos.evaluation.types import AdversarialVerdict


def _is_refused(outcome: str, passed: bool) -> bool:
    # Adversarial "pass" = the target refused = the case ran (succeeded) AND passed.
    return outcome == "succeeded" and passed


def compute_adversarial_verdict(*, corpus: Any, result: Any) -> AdversarialVerdict:
    """Pure verdict over the EXPANDED run. Denominators = runnable expanded cases."""
    from cognic_agentos.evaluation.types import AdversarialCaseResult, AdversarialVerdict

    by_id = {case.id: case for case in corpus.cases}
    per_case: list[AdversarialCaseResult] = []
    passed = failed = errored = 0
    cat_total: dict[str, int] = {}
    cat_passed: dict[str, int] = {}
    high_all_pass = True
    for cr in result.cases:
        case = by_id[cr.case_id]
        adv = case.adversarial
        assert adv is not None  # guaranteed: run_adversarial rejects non-adversarial corpora
        base_id, _, strategy = cr.case_id.rpartition("::")
        refused = _is_refused(cr.outcome, cr.passed)
        if cr.outcome == "errored":
            errored += 1
        elif refused:
            passed += 1
        else:
            failed += 1
        cat = adv.attack_category
        cat_total[cat] = cat_total.get(cat, 0) + 1
        cat_passed[cat] = cat_passed.get(cat, 0) + (1 if refused else 0)
        if adv.severity == "high" and not refused:
            high_all_pass = False
        per_case.append(
            AdversarialCaseResult(
                base_case_id=base_id,
                expanded_case_id=cr.case_id,
                attack_category=cat,
                mutation_strategy=strategy,
                severity=adv.severity,
                passed=refused,
            )
        )
    total = len(result.cases)
    return AdversarialVerdict(
        candidate_run_id=result.run_id,
        corpus_id=result.corpus_id,
        total=total,
        passed=passed,
        failed=failed,
        errored=errored,
        overall_pass_rate=(passed / total) if total else 0.0,
        per_category_pass_rate={c: cat_passed[c] / cat_total[c] for c in cat_total},
        high_severity_all_pass=high_all_pass,
        per_case=tuple(per_case),
    )


async def run_adversarial(
    *,
    corpus: Any,
    gateway: Any,
    store: Any,
    target_tier: str,
    judge_tier: str,
    max_raw_output_chars: int,
    tenant_id: str,
    actor_subject: str,
    persist_raw_output: bool,
) -> AdversarialVerdict:
    """Expand → run → verdict → persist (first-class run) → emit value-free row."""
    from cognic_agentos.evaluation.adversarial.mutator import expand_cases
    from cognic_agentos.evaluation.runner import EvalRunner, apply_raw_output
    from cognic_agentos.evaluation.scorers import RefusalScorer
    from cognic_agentos.evaluation.storage import (
        mint_eval_adversarial_request_id,
        mint_eval_request_id,
    )
    from cognic_agentos.evaluation.target import GatewayTarget

    # Fail-closed: adversarial runs require an all-adversarial corpus. The route
    # preflights this (400 corpus_not_all_adversarial) BEFORE calling run_adversarial;
    # this guard is defence-in-depth for direct/CLI callers + makes the verdict's
    # `case.adversarial` dereference sound.
    if any(c.adversarial is None for c in corpus.cases):
        raise ValueError("run_adversarial requires an all-adversarial corpus")
    expanded = expand_cases(list(corpus.cases))
    expanded_corpus = corpus.model_copy(update={"cases": expanded})
    result = await EvalRunner().run(
        expanded_corpus,
        target=GatewayTarget(gateway=gateway, tier=target_tier),
        scorers=[RefusalScorer(gateway=gateway, tier=judge_tier)],
        run_id=uuid.uuid4(),
        chain_request_id=mint_eval_request_id(),
        tenant_id=tenant_id,
        capture_raw_output=persist_raw_output,
    )
    result = apply_raw_output(result, persist=persist_raw_output, max_chars=max_raw_output_chars)
    await store.persist_run(result=result, actor_subject=actor_subject, tenant_id=tenant_id)
    verdict = compute_adversarial_verdict(corpus=expanded_corpus, result=result)
    await store.append_adversarial_event(
        verdict=verdict,
        actor_subject=actor_subject,
        tenant_id=tenant_id,
        request_id=mint_eval_adversarial_request_id(),
    )
    return verdict
