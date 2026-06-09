# src/cognic_agentos/evaluation/replay.py
"""Sprint 13a live replay (ADR-010) — CC.

Eval-run replay: re-run a fixed corpus against the current operator-configured
target and diff per-case vs a stored baseline. ``compute_replay_diff`` is pure;
``run_replay`` (added in the route-integration task) orchestrates run + persist +
diff + the value-free ``eval.replay`` chain row.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from cognic_agentos.evaluation.scorers import CaseScorer
    from cognic_agentos.evaluation.types import EvalRunResult

DriftKind = Literal["regression", "improvement", "unchanged", "output_changed", "errored"]


@dataclass(frozen=True, slots=True)
class CaseDiff:
    case_id: str
    drift_kind: DriftKind
    baseline_passed: bool
    candidate_passed: bool
    baseline_outcome: str
    candidate_outcome: str
    output_digest_changed: bool
    baseline_model: str
    candidate_model: str
    baseline_tier: str
    candidate_tier: str


@dataclass(frozen=True, slots=True)
class ReplayDiff:
    baseline_run_id: uuid.UUID
    candidate_run_id: uuid.UUID
    corpus_id: str
    corpus_digest: str
    total: int
    regressions: int
    improvements: int
    unchanged: int
    output_changed: int
    errored: int
    has_regressions: bool
    cases: tuple[CaseDiff, ...]


def _classify(*, baseline: dict[str, Any] | None, candidate: Any) -> DriftKind:
    if baseline is None:
        return "errored"  # defensive — cannot happen under a matching corpus_digest
    b_outcome = str(baseline["outcome"])
    if b_outcome == "errored" or candidate.outcome == "errored":
        return "errored"
    b_passed = bool(baseline["passed"])
    if b_passed and not candidate.passed:
        return "regression"
    if not b_passed and candidate.passed:
        return "improvement"
    if str(baseline["output_digest"]) != candidate.output_digest:
        return "output_changed"
    return "unchanged"


def compute_replay_diff(
    *,
    baseline_run_id: uuid.UUID,
    candidate: EvalRunResult,
    baseline_cases: list[dict[str, Any]],
    baseline_tier: str,
) -> ReplayDiff:
    """Pure diff. Cases keyed by ``case_id``; emitted in CANDIDATE/corpus order."""
    by_id: dict[str, dict[str, Any]] = {bc["case_id"]: bc for bc in baseline_cases}
    diffs: list[CaseDiff] = []
    for cc in candidate.cases:  # candidate/corpus order, NOT baseline DB row order
        bc = by_id.get(cc.case_id)
        kind = _classify(baseline=bc, candidate=cc)
        diffs.append(
            CaseDiff(
                case_id=cc.case_id,
                drift_kind=kind,
                baseline_passed=bool(bc["passed"]) if bc is not None else False,
                candidate_passed=cc.passed,
                baseline_outcome=str(bc["outcome"]) if bc is not None else "errored",
                candidate_outcome=cc.outcome,
                output_digest_changed=(
                    bc is not None and str(bc["output_digest"]) != cc.output_digest
                ),
                baseline_model=str(bc["model"]) if bc is not None else "",
                candidate_model=cc.model,
                baseline_tier=baseline_tier,
                candidate_tier=candidate.tier,
            )
        )
    # Defensive (spec §4 pin): baseline cases with NO candidate cannot happen under
    # a matching corpus_digest, but are emitted as ``errored`` AFTER the candidate-
    # order cases so they are never silently dropped.
    candidate_ids = {cc.case_id for cc in candidate.cases}
    for bc in baseline_cases:
        if str(bc["case_id"]) in candidate_ids:
            continue
        diffs.append(
            CaseDiff(
                case_id=str(bc["case_id"]),
                drift_kind="errored",
                baseline_passed=bool(bc["passed"]),
                candidate_passed=False,
                baseline_outcome=str(bc["outcome"]),
                candidate_outcome="errored",
                output_digest_changed=False,
                baseline_model=str(bc["model"]),
                candidate_model="",
                baseline_tier=baseline_tier,
                candidate_tier=candidate.tier,
            )
        )
    regressions = sum(1 for d in diffs if d.drift_kind == "regression")
    return ReplayDiff(
        baseline_run_id=baseline_run_id,
        candidate_run_id=candidate.run_id,
        corpus_id=candidate.corpus_id,
        corpus_digest=candidate.corpus_digest,
        total=len(diffs),
        regressions=regressions,
        improvements=sum(1 for d in diffs if d.drift_kind == "improvement"),
        unchanged=sum(1 for d in diffs if d.drift_kind == "unchanged"),
        output_changed=sum(1 for d in diffs if d.drift_kind == "output_changed"),
        errored=sum(1 for d in diffs if d.drift_kind == "errored"),
        has_regressions=regressions > 0,
        cases=tuple(diffs),
    )


async def run_replay(
    *,
    corpus: Any,
    baseline_run_id: uuid.UUID,
    baseline_cases: list[dict[str, Any]],
    baseline_tier: str,
    gateway: Any,
    store: Any,
    target_tier: str,
    judge_tier: str,
    max_raw_output_chars: int,
    tenant_id: str,
    actor_subject: str,
    persist_raw_output: bool,
) -> ReplayDiff:
    """Run the candidate, persist it, diff vs baseline, emit eval.replay.

    Two sequential chain appends (spec §3): persist_run (eval.bulk_run) then
    append_replay_event (eval.replay). If the second raises after the first
    succeeds, the candidate is a valid standalone run; this function propagates
    the exception (route → 5xx). NON-idempotent (a retry mints a fresh candidate).
    """
    from cognic_agentos.evaluation.runner import EvalRunner, apply_raw_output
    from cognic_agentos.evaluation.scorers import AssertionScorer, JudgeScorer
    from cognic_agentos.evaluation.storage import mint_eval_replay_request_id, mint_eval_request_id
    from cognic_agentos.evaluation.target import GatewayTarget

    target = GatewayTarget(gateway=gateway, tier=target_tier)
    scorers: list[CaseScorer] = [AssertionScorer(), JudgeScorer(gateway=gateway, tier=judge_tier)]
    candidate = await EvalRunner().run(
        corpus,
        target=target,
        scorers=scorers,
        run_id=uuid.uuid4(),
        chain_request_id=mint_eval_request_id(),
        tenant_id=tenant_id,
        capture_raw_output=persist_raw_output,
    )
    # Apply the Sprint-12 raw-output safety contract BEFORE persisting (truncate to
    # max_raw_output_chars + set raw_output_persisted/output_truncated). output_digest
    # is the digest of the ORIGINAL text (set in the runner), so truncation does not
    # affect the diff — the diff compares output_digest, not the stored text.
    candidate = apply_raw_output(
        candidate, persist=persist_raw_output, max_chars=max_raw_output_chars
    )
    # Step 6: persist candidate (eval.bulk_run) — reuses Sprint-12 persist_run.
    await store.persist_run(result=candidate, actor_subject=actor_subject, tenant_id=tenant_id)
    # Step 7: pure diff.
    diff = compute_replay_diff(
        baseline_run_id=baseline_run_id,
        candidate=candidate,
        baseline_cases=baseline_cases,
        baseline_tier=baseline_tier,
    )
    # Step 8: emit eval.replay (value-free). May raise → candidate stays a valid run.
    await store.append_replay_event(
        diff=diff,
        actor_subject=actor_subject,
        tenant_id=tenant_id,
        request_id=mint_eval_replay_request_id(),
    )
    return diff
