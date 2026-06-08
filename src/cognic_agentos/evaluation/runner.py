"""Sprint 12 bulk eval runner (ADR-010 amendment) — CC.

Pure library: target- and scorer-agnostic. Per-case error isolation is the
governing rule — a single failed case (target raises / returns errored, OR a
scorer raises) becomes an ``errored`` CaseResult and the run continues. A case
passes iff every declared scorer passes. NO I/O — identity (run_id /
chain_request_id) is passed in by the caller; persistence is the store's job.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import TYPE_CHECKING

from cognic_agentos.evaluation.corpus import corpus_digest as compute_corpus_digest
from cognic_agentos.evaluation.types import CandidateOutput, CaseResult, EvalRunResult, ScorerResult

if TYPE_CHECKING:
    from cognic_agentos.evaluation.corpus import Corpus, EvalCase
    from cognic_agentos.evaluation.scorers import CaseScorer
    from cognic_agentos.evaluation.target import EvaluationTarget


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _percentile(values: list[int], pct: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, round((pct / 100.0) * (len(ordered) - 1)))
    return ordered[idx]


def _errored_case(case_id: str, *, input_digest: str, output: CandidateOutput | None) -> CaseResult:
    return CaseResult(
        case_id=case_id,
        passed=False,
        outcome="errored",
        scorer_results=(),
        latency_ms=output.latency_ms if output is not None else 0,
        model=output.model if output is not None else "",
        input_digest=input_digest,
        output_digest=_digest(output.text if output is not None else ""),
        candidate_output_text=None,
        raw_output_persisted=False,
        output_truncated=False,
    )


class EvalRunner:
    async def run(
        self,
        corpus: Corpus,
        *,
        target: EvaluationTarget,
        scorers: list[CaseScorer],
        run_id: uuid.UUID,
        chain_request_id: str,
        tenant_id: str,
        capture_raw_output: bool = False,
    ) -> EvalRunResult:
        cases: list[CaseResult] = [
            await self._run_case(
                case,
                target=target,
                scorers=scorers,
                chain_request_id=chain_request_id,
                tenant_id=tenant_id,
                capture_raw_output=capture_raw_output,
            )
            for case in corpus.cases
        ]
        passed = sum(1 for c in cases if c.outcome == "succeeded" and c.passed)
        failed = sum(1 for c in cases if c.outcome == "succeeded" and not c.passed)
        errored = sum(1 for c in cases if c.outcome == "errored")
        latencies = [c.latency_ms for c in cases]
        return EvalRunResult(
            run_id=run_id,
            chain_request_id=chain_request_id,
            corpus_id=corpus.corpus_id,
            corpus_digest=compute_corpus_digest(corpus),
            target_kind=getattr(target, "target_kind", "gateway"),
            tier=getattr(target, "tier", ""),
            total=len(cases),
            passed=passed,
            failed=failed,
            errored=errored,
            latency_p50_ms=_percentile(latencies, 50),
            latency_p95_ms=_percentile(latencies, 95),
            cases=tuple(cases),
        )

    async def _run_case(
        self,
        case: EvalCase,
        *,
        target: EvaluationTarget,
        scorers: list[CaseScorer],
        chain_request_id: str,
        tenant_id: str,
        capture_raw_output: bool,
    ) -> CaseResult:
        user_input = next((m.content for m in case.messages if m.role == "user"), "")
        input_digest = _digest(user_input)
        try:
            output = await target.run_case(case, request_id=chain_request_id, tenant_id=tenant_id)
            if output.outcome == "errored":
                return _errored_case(case.id, input_digest=input_digest, output=output)
            applicable = self._applicable_scorers(case, scorers)
            # Fail closed: every scorer block the case DECLARES must have a scorer that
            # runs. A declared scorer that never ran has NOT passed (spec contract), so a
            # case whose declared block lacks its scorer is harness misconfiguration and is
            # errored — NOT a vacuous ``all(())`` pass. The production route always injects
            # both scorers, so this is defence-in-depth.
            if not self._declared_blocks_covered(case, applicable):
                return _errored_case(case.id, input_digest=input_digest, output=output)
            scorer_results: list[ScorerResult] = [
                await scorer.score(case, output, request_id=chain_request_id, tenant_id=tenant_id)
                for scorer in applicable
            ]
            return CaseResult(
                case_id=case.id,
                passed=all(s.passed for s in scorer_results),
                outcome="succeeded",
                scorer_results=tuple(scorer_results),
                latency_ms=output.latency_ms,
                model=output.model,
                input_digest=input_digest,
                output_digest=_digest(output.text),
                candidate_output_text=output.text if capture_raw_output else None,
                raw_output_persisted=False,
                output_truncated=False,
            )
        except Exception:  # per-case isolation; a single bad case never aborts the run
            return _errored_case(case.id, input_digest=input_digest, output=None)

    @staticmethod
    def _applicable_scorers(case: EvalCase, scorers: list[CaseScorer]) -> list[CaseScorer]:
        out: list[CaseScorer] = []
        for s in scorers:
            name = type(s).__name__
            if name == "AssertionScorer" and case.assertions is None:
                continue
            if name == "JudgeScorer" and case.judge is None:
                continue
            out.append(s)
        return out

    @staticmethod
    def _declared_blocks_covered(case: EvalCase, applicable: list[CaseScorer]) -> bool:
        """Every block the case DECLARES must have its scorer in the applicable set.
        Keyed on scorer class name (same coupling as ``_applicable_scorers``)."""
        names = {type(s).__name__ for s in applicable}
        if case.assertions is not None and "AssertionScorer" not in names:
            return False
        if case.judge is not None and "JudgeScorer" not in names:  # noqa: SIM103
            return False
        return True
