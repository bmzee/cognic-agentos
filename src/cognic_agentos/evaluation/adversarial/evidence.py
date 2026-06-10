"""ADR-011 Sprint-13c — adversarial promotion-gate evidence producer.

Resolve a referenced 13b adversarial eval-run, verify it (5-value closed-enum
refusal taxonomy), compute baseline regression by reusing 13a's
``compute_replay_diff`` over the two persisted eval-runs, and map the result to
the frozen ``payload["adversarial"]`` snapshot the existing 5-gate composer reads.
NO new gate; NO auto-run; reference-based only.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from cognic_agentos.evaluation.types import EvalRunResult

AdversarialEvidenceRefusalReason = Literal[
    "adversarial_run_not_found",
    "adversarial_run_not_adversarial",
    "adversarial_baseline_run_not_found",
    "adversarial_baseline_run_not_adversarial",
    "adversarial_baseline_corpus_digest_mismatch",
]


class AdversarialEvidenceError(Exception):
    """Submit-time refusal carrying a route-owned closed-enum ``reason``.

    ``author_routes`` maps ``reason`` → (HTTP status, body).
    """

    def __init__(self, reason: AdversarialEvidenceRefusalReason) -> None:
        super().__init__(reason)
        self.reason: AdversarialEvidenceRefusalReason = reason


def _eval_run_from_get_run(get_run_result: dict[str, Any]) -> EvalRunResult:
    """Reconstruct an :class:`EvalRunResult` from an
    ``EvalRunStore.get_run`` mapping so it can feed ``compute_replay_diff``.
    Only the fields the differ reads are load-bearing.
    """
    from cognic_agentos.evaluation.types import CaseResult, EvalRunResult

    run = get_run_result["run"]
    cases = tuple(
        CaseResult(
            case_id=str(c["case_id"]),
            passed=bool(c["passed"]),
            outcome=str(c["outcome"]),  # type: ignore[arg-type]
            scorer_results=(),
            latency_ms=int(c["latency_ms"]),
            model=str(c["model"]),
            input_digest=str(c["input_digest"]),
            output_digest=str(c["output_digest"]),
            candidate_output_text=c.get("candidate_output_text"),
            raw_output_persisted=False,
            output_truncated=False,
        )
        for c in get_run_result["cases"]
    )
    return EvalRunResult(
        run_id=run["run_id"]
        if isinstance(run["run_id"], uuid.UUID)
        else uuid.UUID(str(run["run_id"])),
        chain_request_id=str(run["chain_request_id"]),
        corpus_id=str(run["corpus_id"]),
        corpus_digest=str(run["corpus_digest"]),
        target_kind=str(run["target_kind"]),
        tier=str(run["tier"]),
        total=int(run["total"]),
        passed=int(run["passed"]),
        failed=int(run["failed"]),
        errored=int(run["errored"]),
        latency_p50_ms=int(run["latency_p50_ms"]),
        latency_p95_ms=int(run["latency_p95_ms"]),
        cases=cases,
    )


def _parse_run_id(raw: str, *, missing: AdversarialEvidenceRefusalReason) -> uuid.UUID:
    try:
        return uuid.UUID(raw)
    except (ValueError, AttributeError, TypeError):
        raise AdversarialEvidenceError(missing) from None


def _high_severity_failures(verdict: Any) -> int:
    return sum(1 for c in verdict.per_case if c.severity == "high" and not c.passed)


async def build_adversarial_evidence(
    store: Any,
    *,
    tenant_id: str,
    adversarial_run_id: str,
    baseline_adversarial_run_id: str | None,
) -> dict[str, Any]:
    """Resolve + verify + map the referenced adversarial run into the frozen
    ``payload["adversarial"]`` snapshot. Raises :class:`AdversarialEvidenceError`
    on any verification failure (spec §2/§3 closed-enum).
    """
    from cognic_agentos.evaluation.replay import compute_replay_diff

    cand_uuid = _parse_run_id(adversarial_run_id, missing="adversarial_run_not_found")

    # Step 0 — the candidate must be a QUERYABLE eval-run (existence FIRST, per
    # spec §0 "run id = the queryable persist_run eval-run id"), THEN it must
    # carry an adversarial verdict. ``append_adversarial_event`` has NO FK to the
    # eval-run row, so a dangling verdict row whose candidate_run_id was never
    # ``persist_run``-persisted would otherwise produce a frozen snapshot for a
    # non-queryable run (or, on the baseline path, crash on ``cand_run["run"]``).
    # Verifying existence first makes that adversarial_run_not_found, not a silent
    # accept. ``cand_run`` is fetched ONCE and reused for the baseline diff.
    cand_run = await store.get_run(run_id=cand_uuid, tenant_id=tenant_id)
    if cand_run is None:
        raise AdversarialEvidenceError("adversarial_run_not_found")
    verdict = await store.load_adversarial_verdict(run_id=cand_uuid, tenant_id=tenant_id)
    if verdict is None:
        raise AdversarialEvidenceError("adversarial_run_not_adversarial")

    pass_rate = verdict.overall_pass_rate
    high_severity_failures = _high_severity_failures(verdict)

    regressions = 0
    regression_evaluated = False
    baseline_run_id_out: str | None = None

    if baseline_adversarial_run_id is not None:
        base_uuid = _parse_run_id(
            baseline_adversarial_run_id, missing="adversarial_baseline_run_not_found"
        )
        base_run = await store.get_run(run_id=base_uuid, tenant_id=tenant_id)
        if base_run is None:
            raise AdversarialEvidenceError("adversarial_baseline_run_not_found")
        if await store.load_adversarial_verdict(run_id=base_uuid, tenant_id=tenant_id) is None:
            raise AdversarialEvidenceError("adversarial_baseline_run_not_adversarial")
        if cand_run["run"]["corpus_digest"] != base_run["run"]["corpus_digest"]:
            raise AdversarialEvidenceError("adversarial_baseline_corpus_digest_mismatch")
        candidate_result = _eval_run_from_get_run(cand_run)  # reuse the Step-0 fetch
        diff = compute_replay_diff(
            baseline_run_id=base_uuid,
            candidate=candidate_result,
            baseline_cases=list(base_run["cases"]),
            baseline_tier=str(base_run["run"]["tier"]),
        )
        regressions = diff.regressions
        regression_evaluated = True
        baseline_run_id_out = str(base_uuid)

    return {
        "pass_rate": pass_rate,
        "high_severity_failures": high_severity_failures,
        "regressions": regressions,
        "regression_evaluated": regression_evaluated,
        "candidate_run_id": str(cand_uuid),
        "baseline_run_id": baseline_run_id_out,
    }
