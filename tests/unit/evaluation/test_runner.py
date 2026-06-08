"""ADR-010 Task 5 — pure EvalRunner aggregation, isolation, scorer-coverage."""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from cognic_agentos.evaluation.corpus import validate_corpus_payload
from cognic_agentos.evaluation.runner import EvalRunner, _percentile
from cognic_agentos.evaluation.scorers import AssertionScorer, JudgeScorer
from cognic_agentos.evaluation.types import CandidateOutput, ScorerResult
from cognic_agentos.llm.gateway import GatewayResponse


def _ok(text: str = "ok") -> CandidateOutput:
    return CandidateOutput(text=text, model="m", tier="tier1", latency_ms=5, outcome="succeeded")


class _Target:
    target_kind = "gateway"
    tier = "tier1"

    def __init__(
        self, *, outcomes: dict[str, CandidateOutput], raise_on: str | None = None
    ) -> None:
        self._outcomes = outcomes
        self._raise_on = raise_on

    async def run_case(self, case: Any, *, request_id: str, tenant_id: str) -> CandidateOutput:
        if case.id == self._raise_on:
            raise RuntimeError("boom")
        return self._outcomes[case.id]


class _PassJudgeGateway:
    """Parseable 'pass' verdict so a JudgeScorer that RUNS succeeds."""

    async def completion(
        self,
        *,
        tier: str,
        messages: list[dict[str, str]],
        request_id: str,
        tenant_id: str | None = None,
    ) -> GatewayResponse:
        return GatewayResponse(
            content='{"verdict": "pass", "score": 1.0, "rationale": "ok", '
            '"criteria_results": [{"name": "n", "passed": true, "note": "ok"}]}',
            upstream_model="judge-m",
            api_base=None,
            external=False,
            request_id=request_id,
            tier=tier,
            latency_ms=2,
        )


class _NeverGateway:
    """A JudgeScorer constructed with this must be SKIPPED — completion never runs."""

    async def completion(
        self,
        *,
        tier: str,
        messages: list[dict[str, str]],
        request_id: str,
        tenant_id: str | None = None,
    ) -> GatewayResponse:
        raise AssertionError("JudgeScorer was applied but should have been skipped")


class _ExplodingScorer:
    """A scorer that RAISES for a target case id — pins scorer-exception isolation.
    Named neither AssertionScorer nor JudgeScorer, so it is always applicable and
    does not affect the declared-block coverage check."""

    def __init__(self, *, raise_on: str) -> None:
        self._raise_on = raise_on

    async def score(
        self, case: Any, output: Any, *, request_id: str, tenant_id: str
    ) -> ScorerResult:
        if case.id == self._raise_on:
            raise RuntimeError("scorer boom")
        return ScorerResult(scorer="assertions", passed=True, detail=())


_JUDGE_BLOCK: dict[str, Any] = {
    "judge": {"rubric": "r", "criteria": [{"name": "n", "description": "d"}]}
}
_ASSERT_BLOCK: dict[str, Any] = {"assertions": {"contains": ["ok"]}}


def _single_case_corpus(payload: dict[str, Any]) -> Any:
    base: dict[str, Any] = {
        "id": "c1",
        "case_kind": "completion",
        "messages": [{"role": "user", "content": "q"}],
    }
    base.update(payload)
    return validate_corpus_payload({"schema_version": 1, "corpus_id": "cp", "cases": [base]})


def _assertion_corpus(*case_ids: str) -> Any:
    return validate_corpus_payload(
        {
            "schema_version": 1,
            "corpus_id": "cp",
            "cases": [
                {
                    "id": cid,
                    "case_kind": "completion",
                    "messages": [{"role": "user", "content": "q"}],
                    "assertions": {"contains": ["ok"]},
                }
                for cid in case_ids
            ],
        }
    )


@pytest.mark.asyncio
async def test_run_aggregates_pass_fail_counts() -> None:
    corpus = _assertion_corpus("a", "b")
    target = _Target(outcomes={"a": _ok("ok"), "b": _ok("no")})  # "no" lacks "ok" -> fail
    result = await EvalRunner().run(
        corpus,
        target=target,
        scorers=[AssertionScorer()],
        run_id=uuid.uuid4(),
        chain_request_id="r",
        tenant_id="t",
    )
    assert result.total == 2 and result.passed == 1 and result.failed == 1 and result.errored == 0
    assert result.target_kind == "gateway" and result.tier == "tier1"


@pytest.mark.asyncio
async def test_target_errored_skips_scorers() -> None:
    corpus = _assertion_corpus("a")
    target = _Target(
        outcomes={
            "a": CandidateOutput(
                text="",
                model="",
                tier="tier1",
                latency_ms=0,
                outcome="errored",
                error_category="LLMConcurrencyExceeded",
            )
        }
    )
    result = await EvalRunner().run(
        corpus,
        target=target,
        scorers=[AssertionScorer()],
        run_id=uuid.uuid4(),
        chain_request_id="r",
        tenant_id="t",
    )
    assert result.errored == 1 and result.passed == 0 and result.failed == 0
    assert result.cases[0].outcome == "errored" and result.cases[0].scorer_results == ()


@pytest.mark.asyncio
async def test_target_exception_isolates_to_errored_case() -> None:
    corpus = _assertion_corpus("a", "b")
    target = _Target(outcomes={"a": _ok("ok"), "b": _ok("ok")}, raise_on="a")
    result = await EvalRunner().run(
        corpus,
        target=target,
        scorers=[AssertionScorer()],
        run_id=uuid.uuid4(),
        chain_request_id="r",
        tenant_id="t",
    )
    assert result.errored == 1 and result.passed == 1


@pytest.mark.asyncio
async def test_scorer_exception_isolates_to_errored_case() -> None:
    # A scorer that RAISES (after declared-block coverage passes) errors only its
    # case; the run continues and a sibling case still succeeds.
    corpus = _assertion_corpus("a", "b")
    target = _Target(outcomes={"a": _ok("ok"), "b": _ok("ok")})
    result = await EvalRunner().run(
        corpus,
        target=target,
        scorers=[AssertionScorer(), _ExplodingScorer(raise_on="a")],
        run_id=uuid.uuid4(),
        chain_request_id="r",
        tenant_id="t",
    )
    assert result.errored == 1 and result.passed == 1
    assert result.cases[0].outcome == "errored"  # case 'a' — scorer raised
    assert result.cases[1].outcome == "succeeded"  # case 'b' survived the run


@pytest.mark.asyncio
async def test_capture_raw_output_true_carries_candidate_text() -> None:
    corpus = _assertion_corpus("a")
    target = _Target(outcomes={"a": _ok("the full answer ok")})
    result = await EvalRunner().run(
        corpus,
        target=target,
        scorers=[AssertionScorer()],
        run_id=uuid.uuid4(),
        chain_request_id="r",
        tenant_id="t",
        capture_raw_output=True,
    )
    assert result.cases[0].candidate_output_text == "the full answer ok"


@pytest.mark.asyncio
async def test_assertion_scorer_skipped_judge_still_runs() -> None:
    # judge-only case + BOTH scorers: AssertionScorer skipped, JudgeScorer RUNS + passes.
    corpus = _single_case_corpus(_JUDGE_BLOCK)
    result = await EvalRunner().run(
        corpus,
        target=_Target(outcomes={"c1": _ok()}),
        scorers=[AssertionScorer(), JudgeScorer(gateway=_PassJudgeGateway(), tier="tier1")],  # type: ignore[arg-type]
        run_id=uuid.uuid4(),
        chain_request_id="r",
        tenant_id="t",
    )
    assert result.cases[0].outcome == "succeeded" and result.passed == 1
    assert [s.scorer for s in result.cases[0].scorer_results] == ["judge"]


@pytest.mark.asyncio
async def test_judge_scorer_skipped_assertion_still_runs() -> None:
    # assertion-only case + BOTH scorers: JudgeScorer skipped (never invoked), AssertionScorer RUNS.
    corpus = _single_case_corpus(_ASSERT_BLOCK)
    result = await EvalRunner().run(
        corpus,
        target=_Target(outcomes={"c1": _ok()}),
        scorers=[AssertionScorer(), JudgeScorer(gateway=_NeverGateway(), tier="tier1")],  # type: ignore[arg-type]
        run_id=uuid.uuid4(),
        chain_request_id="r",
        tenant_id="t",
    )
    assert result.cases[0].outcome == "succeeded" and result.passed == 1
    assert [s.scorer for s in result.cases[0].scorer_results] == ["assertions"]


@pytest.mark.asyncio
async def test_declared_judge_without_judge_scorer_fails_closed() -> None:
    # judge-only case but ONLY AssertionScorer injected -> declared judge never ran -> errored.
    corpus = _single_case_corpus(_JUDGE_BLOCK)
    result = await EvalRunner().run(
        corpus,
        target=_Target(outcomes={"c1": _ok()}),
        scorers=[AssertionScorer()],
        run_id=uuid.uuid4(),
        chain_request_id="r",
        tenant_id="t",
    )
    assert result.cases[0].outcome == "errored" and result.errored == 1 and result.passed == 0


@pytest.mark.asyncio
async def test_declared_assertions_without_assertion_scorer_fails_closed() -> None:
    # assertion-only case but ONLY JudgeScorer injected -> declared assertions never ran -> errored.
    corpus = _single_case_corpus(_ASSERT_BLOCK)
    result = await EvalRunner().run(
        corpus,
        target=_Target(outcomes={"c1": _ok()}),
        scorers=[JudgeScorer(gateway=_NeverGateway(), tier="tier1")],  # type: ignore[arg-type]
        run_id=uuid.uuid4(),
        chain_request_id="r",
        tenant_id="t",
    )
    assert result.cases[0].outcome == "errored" and result.errored == 1 and result.passed == 0


def test_percentile_empty_list_returns_zero() -> None:
    assert _percentile([], 50) == 0
