"""ADR-011 Sprint-13c — adversarial promotion-gate evidence producer.

Resolve a referenced 13b adversarial eval-run, verify it (5-value closed-enum
refusal taxonomy), compute baseline regression by reusing 13a's
``compute_replay_diff`` over the two persisted eval-runs, and map the result to
the frozen ``payload["adversarial"]`` snapshot the existing 5-gate composer reads.
NO new gate; NO auto-run; reference-based only.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cognic_agentos.evaluation.types import EvalRunResult


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
