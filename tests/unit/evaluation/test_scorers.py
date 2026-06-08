# tests/unit/evaluation/test_scorers.py
from __future__ import annotations

from typing import Any

import pytest

from cognic_agentos.evaluation.corpus import EvalCase
from cognic_agentos.evaluation.scorers import AssertionScorer, JudgeScorer
from cognic_agentos.evaluation.types import CandidateOutput
from cognic_agentos.llm.gateway import GatewayResponse


def _case(payload: dict[str, Any]) -> EvalCase:
    base = {"id": "c1", "case_kind": "completion", "messages": [{"role": "user", "content": "q"}]}
    base.update(payload)
    return EvalCase.model_validate(base)


def _out(text: str) -> CandidateOutput:
    return CandidateOutput(text=text, model="m", tier="tier1", latency_ms=1, outcome="succeeded")


@pytest.mark.asyncio
async def test_assertion_scorer_contains_pass_and_fail() -> None:
    case = _case({"assertions": {"contains": ["capital adequacy"], "not_contains": ["wrong"]}})
    sc = AssertionScorer()
    ok = await sc.score(case, _out("capital adequacy ratio"), request_id="r", tenant_id="t")
    assert ok.passed is True and ok.scorer == "assertions"
    bad = await sc.score(case, _out("nope wrong nope"), request_id="r", tenant_id="t")
    assert bad.passed is False
    assert any(not d.passed for d in bad.detail)
    assert all(isinstance(d.critique, str) and d.critique for d in bad.detail)


@pytest.mark.asyncio
async def test_assertion_scorer_regex() -> None:
    case = _case({"assertions": {"regex": [r"\bCAR\b"]}})
    sc = AssertionScorer()
    assert (await sc.score(case, _out("the CAR metric"), request_id="r", tenant_id="t")).passed
    assert not (await sc.score(case, _out("scared"), request_id="r", tenant_id="t")).passed


class _FakeGateway:
    def __init__(self, content: str) -> None:
        self._content = content

    async def completion(
        self,
        *,
        tier: str,
        messages: list[dict[str, str]],
        request_id: str,
        tenant_id: str | None = None,
    ) -> GatewayResponse:
        return GatewayResponse(
            content=self._content,
            upstream_model="judge-m",
            api_base=None,
            external=False,
            request_id=request_id,
            tier=tier,
            latency_ms=9,
        )


@pytest.mark.asyncio
async def test_judge_scorer_passes_on_verdict_pass() -> None:
    case = _case(
        {"judge": {"rubric": "greeting", "criteria": [{"name": "g", "description": "says hi"}]}}
    )
    content = (
        '{"verdict": "pass", "score": 0.9, "rationale": "ok", '
        '"criteria_results": [{"name": "g", "passed": true, "note": "yes"}]}'
    )
    sc = JudgeScorer(gateway=_FakeGateway(content), tier="tier1")  # type: ignore[arg-type]
    res = await sc.score(case, _out("hello there"), request_id="r", tenant_id="t")
    assert res.scorer == "judge"
    assert res.passed is True
    assert res.verdict == "pass"
    assert res.detail[0].name == "g" and res.detail[0].passed is True


@pytest.mark.asyncio
async def test_judge_scorer_fails_on_verdict_fail() -> None:
    case = _case(
        {"judge": {"rubric": "greeting", "criteria": [{"name": "g", "description": "says hi"}]}}
    )
    content = (
        '{"verdict": "fail", "score": 0.1, "rationale": "no", '
        '"criteria_results": [{"name": "g", "passed": false, "note": "nope"}]}'
    )
    sc = JudgeScorer(gateway=_FakeGateway(content), tier="tier1")  # type: ignore[arg-type]
    res = await sc.score(case, _out("goodbye"), request_id="r", tenant_id="t")
    assert res.passed is False and res.verdict == "fail"


@pytest.mark.asyncio
async def test_judge_scorer_unparseable_fails_with_parse_reason_critique() -> None:
    case = _case(
        {"judge": {"rubric": "greeting", "criteria": [{"name": "g", "description": "says hi"}]}}
    )
    sc = JudgeScorer(gateway=_FakeGateway("not json at all"), tier="tier1")  # type: ignore[arg-type]
    res = await sc.score(case, _out("x"), request_id="r", tenant_id="t")
    assert res.passed is False
    assert res.detail[0].critique == "not_json"


@pytest.mark.asyncio
async def test_assertion_scorer_json_path_success_and_mismatch() -> None:
    case = _case({"assertions": {"json_path": [{"path": "a.b", "equals": "x"}]}})
    sc = AssertionScorer()
    ok = await sc.score(case, _out('{"a": {"b": "x"}}'), request_id="r", tenant_id="t")
    assert ok.passed is True
    assert ok.detail[0].name == "json_path:a.b"
    mismatch = await sc.score(case, _out('{"a": {"b": "y"}}'), request_id="r", tenant_id="t")
    assert mismatch.passed is False
    assert any("expected" in d.critique for d in mismatch.detail)


@pytest.mark.asyncio
async def test_assertion_scorer_json_path_key_not_found() -> None:
    case = _case({"assertions": {"json_path": [{"path": "a.missing", "equals": "x"}]}})
    sc = AssertionScorer()
    res = await sc.score(case, _out('{"a": {"b": "x"}}'), request_id="r", tenant_id="t")
    assert res.passed is False
    assert any("not found" in d.critique for d in res.detail)


@pytest.mark.asyncio
async def test_assertion_scorer_json_path_non_dict_intermediate() -> None:
    # path descends past a non-dict node ("a.b" is the string "x", ".c" cannot resolve)
    case = _case({"assertions": {"json_path": [{"path": "a.b.c", "equals": "x"}]}})
    sc = AssertionScorer()
    res = await sc.score(case, _out('{"a": {"b": "x"}}'), request_id="r", tenant_id="t")
    assert res.passed is False
    assert any("not found" in d.critique for d in res.detail)


@pytest.mark.asyncio
async def test_assertion_scorer_json_path_non_json_fails_closed() -> None:
    case = _case({"assertions": {"json_path": [{"path": "a", "equals": "x"}]}})
    sc = AssertionScorer()
    res = await sc.score(case, _out("not valid json at all"), request_id="r", tenant_id="t")
    assert res.passed is False
    assert any("not valid JSON" in d.critique for d in res.detail)
