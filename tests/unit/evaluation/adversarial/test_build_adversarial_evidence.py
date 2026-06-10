from __future__ import annotations

import asyncio
import typing
import uuid
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.evaluation.adversarial.evidence import (
    AdversarialEvidenceError,
    AdversarialEvidenceRefusalReason,
    build_adversarial_evidence,
)
from cognic_agentos.evaluation.storage import EvalRunStore
from cognic_agentos.evaluation.types import (
    AdversarialCaseResult,
    AdversarialVerdict,
    CaseResult,
    EvalRunResult,
)


async def _store(tmp_path: Any) -> EvalRunStore:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'bae.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    return EvalRunStore(DecisionHistoryStore(create_async_engine(url)))


def _case(
    cid: str, *, passed: bool, outcome: str, severity: str
) -> tuple[CaseResult, AdversarialCaseResult]:
    cr = CaseResult(
        case_id=cid,
        passed=passed,
        outcome=outcome,  # type: ignore[arg-type]
        scorer_results=(),
        latency_ms=1,
        model="m",
        input_digest="i",
        output_digest="o",
        candidate_output_text=None,
        raw_output_persisted=False,
        output_truncated=False,
    )
    base, _, strat = cid.rpartition("::")
    adv = AdversarialCaseResult(
        base_case_id=base,
        expanded_case_id=cid,
        attack_category="direct_prompt_injection",
        mutation_strategy=strat,
        severity=severity,
        passed=passed,
    )
    return cr, adv


async def _persist_adv_run(
    store: EvalRunStore,
    *,
    tenant: str,
    corpus_digest: str,
    cases: list[tuple[CaseResult, AdversarialCaseResult]],
) -> uuid.UUID:
    run_id = uuid.uuid4()
    crs = tuple(c for c, _ in cases)
    advs = tuple(a for _, a in cases)
    result = EvalRunResult(
        run_id=run_id,
        chain_request_id="eval-" + uuid.uuid4().hex,
        corpus_id="adv",
        corpus_digest=corpus_digest,
        target_kind="gateway",
        tier="tier1",
        total=len(crs),
        passed=sum(c.passed for c in crs),
        failed=sum(not c.passed for c in crs),
        errored=sum(c.outcome == "errored" for c in crs),
        latency_p50_ms=1,
        latency_p95_ms=1,
        cases=crs,
    )
    await store.persist_run(result=result, actor_subject="svc", tenant_id=tenant)
    verdict = AdversarialVerdict(
        candidate_run_id=run_id,
        corpus_id="adv",
        total=len(advs),
        passed=sum(a.passed for a in advs),
        failed=sum(not a.passed for a in advs),
        errored=0,
        overall_pass_rate=(sum(a.passed for a in advs) / len(advs)) if advs else 0.0,
        per_category_pass_rate={"direct_prompt_injection": 0.0},
        high_severity_all_pass=all(a.passed for a in advs if a.severity == "high"),
        per_case=advs,
    )
    await store.append_adversarial_event(
        verdict=verdict,
        actor_subject="svc",
        tenant_id=tenant,
        request_id="eval-adv-" + uuid.uuid4().hex,
    )
    return run_id


@pytest.mark.asyncio
async def test_no_baseline_skips_regression(tmp_path: Any) -> None:
    store = await _store(tmp_path)
    run_id = await _persist_adv_run(
        store,
        tenant="t1",
        corpus_digest="dig",
        cases=[_case("a::none", passed=True, outcome="succeeded", severity="high")],
    )
    snap = await build_adversarial_evidence(
        store, tenant_id="t1", adversarial_run_id=str(run_id), baseline_adversarial_run_id=None
    )
    assert snap["regression_evaluated"] is False
    assert snap["regressions"] == 0
    assert snap["high_severity_failures"] == 0
    assert snap["pass_rate"] == 1.0
    assert snap["candidate_run_id"] == str(run_id)
    assert snap["baseline_run_id"] is None
    assert set(snap.keys()) == {
        "pass_rate",
        "high_severity_failures",
        "regressions",
        "regression_evaluated",
        "candidate_run_id",
        "baseline_run_id",
    }


@pytest.mark.asyncio
async def test_baseline_regression_counts_passed_to_failed_only(tmp_path: Any) -> None:
    store = await _store(tmp_path)
    # baseline: both refused (passed=True)
    base_id = await _persist_adv_run(
        store,
        tenant="t1",
        corpus_digest="dig",
        cases=[
            _case("a::none", passed=True, outcome="succeeded", severity="standard"),
            _case("b::none", passed=True, outcome="succeeded", severity="standard"),
        ],
    )
    # candidate: a regressed (now succeeds → passed=False), b errored (NOT a regression)
    cand_id = await _persist_adv_run(
        store,
        tenant="t1",
        corpus_digest="dig",
        cases=[
            _case("a::none", passed=False, outcome="succeeded", severity="standard"),
            _case("b::none", passed=False, outcome="errored", severity="standard"),
        ],
    )
    snap = await build_adversarial_evidence(
        store,
        tenant_id="t1",
        adversarial_run_id=str(cand_id),
        baseline_adversarial_run_id=str(base_id),
    )
    assert snap["regression_evaluated"] is True
    assert snap["regressions"] == 1  # a regressed; b errored → excluded by _classify
    assert snap["baseline_run_id"] == str(base_id)


@pytest.mark.asyncio
async def test_high_severity_failures_counted_from_verdict(tmp_path: Any) -> None:
    store = await _store(tmp_path)
    run_id = await _persist_adv_run(
        store,
        tenant="t1",
        corpus_digest="dig",
        cases=[
            _case("a::none", passed=False, outcome="succeeded", severity="high"),
            _case("b::none", passed=True, outcome="succeeded", severity="high"),
        ],
    )
    snap = await build_adversarial_evidence(
        store, tenant_id="t1", adversarial_run_id=str(run_id), baseline_adversarial_run_id=None
    )
    assert snap["high_severity_failures"] == 1


@pytest.mark.asyncio
async def test_unknown_candidate_raises_not_found(tmp_path: Any) -> None:
    store = await _store(tmp_path)
    with pytest.raises(AdversarialEvidenceError) as ei:
        await build_adversarial_evidence(
            store,
            tenant_id="t1",
            adversarial_run_id=str(uuid.uuid4()),
            baseline_adversarial_run_id=None,
        )
    assert ei.value.reason == "adversarial_run_not_found"


@pytest.mark.asyncio
async def test_malformed_candidate_id_raises_not_found(tmp_path: Any) -> None:
    store = await _store(tmp_path)
    with pytest.raises(AdversarialEvidenceError) as ei:
        await build_adversarial_evidence(
            store, tenant_id="t1", adversarial_run_id="not-a-uuid", baseline_adversarial_run_id=None
        )
    assert ei.value.reason == "adversarial_run_not_found"


@pytest.mark.asyncio
async def test_non_adversarial_candidate_raises(tmp_path: Any) -> None:
    # A persisted eval-run with NO eval.adversarial_run verdict row.
    store = await _store(tmp_path)
    run_id = uuid.uuid4()
    cr, _ = _case("x::none", passed=True, outcome="succeeded", severity="standard")
    result = EvalRunResult(
        run_id=run_id,
        chain_request_id="eval-x",
        corpus_id="adv",
        corpus_digest="dig",
        target_kind="gateway",
        tier="tier1",
        total=1,
        passed=1,
        failed=0,
        errored=0,
        latency_p50_ms=1,
        latency_p95_ms=1,
        cases=(cr,),
    )
    await store.persist_run(
        result=result, actor_subject="svc", tenant_id="t1"
    )  # NO adversarial event
    with pytest.raises(AdversarialEvidenceError) as ei:
        await build_adversarial_evidence(
            store, tenant_id="t1", adversarial_run_id=str(run_id), baseline_adversarial_run_id=None
        )
    assert ei.value.reason == "adversarial_run_not_adversarial"


@pytest.mark.asyncio
async def test_baseline_not_found_and_not_adversarial_and_digest_mismatch(tmp_path: Any) -> None:
    store = await _store(tmp_path)
    cand = await _persist_adv_run(
        store,
        tenant="t1",
        corpus_digest="dig",
        cases=[_case("a::none", passed=True, outcome="succeeded", severity="standard")],
    )
    # missing baseline
    with pytest.raises(AdversarialEvidenceError) as ei:
        await build_adversarial_evidence(
            store,
            tenant_id="t1",
            adversarial_run_id=str(cand),
            baseline_adversarial_run_id=str(uuid.uuid4()),
        )
    assert ei.value.reason == "adversarial_baseline_run_not_found"

    # baseline is a non-adversarial eval-run
    base_plain = uuid.uuid4()
    cr, _ = _case("a::none", passed=True, outcome="succeeded", severity="standard")
    await store.persist_run(
        result=EvalRunResult(
            run_id=base_plain,
            chain_request_id="eval-b",
            corpus_id="adv",
            corpus_digest="dig",
            target_kind="gateway",
            tier="tier1",
            total=1,
            passed=1,
            failed=0,
            errored=0,
            latency_p50_ms=1,
            latency_p95_ms=1,
            cases=(cr,),
        ),
        actor_subject="svc",
        tenant_id="t1",
    )
    with pytest.raises(AdversarialEvidenceError) as ei:
        await build_adversarial_evidence(
            store,
            tenant_id="t1",
            adversarial_run_id=str(cand),
            baseline_adversarial_run_id=str(base_plain),
        )
    assert ei.value.reason == "adversarial_baseline_run_not_adversarial"

    # digest mismatch
    base_diff = await _persist_adv_run(
        store,
        tenant="t1",
        corpus_digest="OTHER",
        cases=[_case("a::none", passed=True, outcome="succeeded", severity="standard")],
    )
    with pytest.raises(AdversarialEvidenceError) as ei:
        await build_adversarial_evidence(
            store,
            tenant_id="t1",
            adversarial_run_id=str(cand),
            baseline_adversarial_run_id=str(base_diff),
        )
    assert ei.value.reason == "adversarial_baseline_corpus_digest_mismatch"


@pytest.mark.asyncio
async def test_verdict_row_without_eval_run_raises_not_found(tmp_path: Any) -> None:
    # Defence (reviewer P1): a dangling ``eval.adversarial_run`` verdict row whose
    # ``candidate_run_id`` has NO ``persist_run`` eval-run (append_adversarial_event
    # has no FK to ``_eval_runs``) must NOT yield a frozen snapshot — existence is
    # verified FIRST, so this is ``adversarial_run_not_found``, not a silent accept.
    store = await _store(tmp_path)
    run_id = uuid.uuid4()
    _, adv = _case("a::none", passed=True, outcome="succeeded", severity="standard")
    await store.append_adversarial_event(
        verdict=AdversarialVerdict(
            candidate_run_id=run_id,
            corpus_id="adv",
            total=1,
            passed=1,
            failed=0,
            errored=0,
            overall_pass_rate=1.0,
            per_category_pass_rate={"direct_prompt_injection": 1.0},
            high_severity_all_pass=True,
            per_case=(adv,),
        ),
        actor_subject="svc",
        tenant_id="t1",
        request_id="eval-adv-" + uuid.uuid4().hex,
    )  # NO persist_run → candidate eval-run does not exist
    with pytest.raises(AdversarialEvidenceError) as ei:
        await build_adversarial_evidence(
            store, tenant_id="t1", adversarial_run_id=str(run_id), baseline_adversarial_run_id=None
        )
    assert ei.value.reason == "adversarial_run_not_found"


def test_refusal_reason_closed_set() -> None:
    assert set(typing.get_args(AdversarialEvidenceRefusalReason)) == {
        "adversarial_run_not_found",
        "adversarial_run_not_adversarial",
        "adversarial_baseline_run_not_found",
        "adversarial_baseline_run_not_adversarial",
        "adversarial_baseline_corpus_digest_mismatch",
    }
