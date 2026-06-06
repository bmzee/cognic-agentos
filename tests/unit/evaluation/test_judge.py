from __future__ import annotations

import json
from typing import cast

import pytest

from cognic_agentos.evaluation.judge import (
    JudgeOutcome,
    JudgeParsed,
    JudgeUnparseable,
    run_judge,
)
from cognic_agentos.llm.gateway import GatewayResponse, LLMGateway
from cognic_agentos.portal.api.evaluation.dto import JudgeCriterion, JudgeRequest


class _FakeGateway:
    """Structural stand-in for :class:`LLMGateway` — returns a fixed ``content``.

    ``run_judge`` annotates ``gateway: LLMGateway`` (a concrete class, not a
    Protocol), so the fake is threaded through :func:`_invoke` which performs the
    single ``cast`` rather than scattering per-call ``# type: ignore`` comments.
    """

    def __init__(self, content: str) -> None:
        self._content = content
        self.calls: list[dict[str, object]] = []

    async def completion(
        self,
        *,
        tier: str,
        messages: list[dict[str, str]],
        request_id: str,
        tenant_id: str | None = None,
    ) -> GatewayResponse:
        self.calls.append({"tier": tier, "messages": messages, "request_id": request_id})
        return GatewayResponse(
            content=self._content,
            upstream_model="m",
            api_base=None,
            external=False,
            request_id=request_id,
            tier=tier,
            latency_ms=5,
        )


async def _invoke(
    gw: _FakeGateway,
    *,
    request: JudgeRequest | None = None,
    request_id: str = "r",
    tenant_id: str | None = None,
    tier: str = "tier1",
) -> JudgeOutcome:
    return await run_judge(
        request=request if request is not None else _req(),
        gateway=cast(LLMGateway, gw),
        request_id=request_id,
        tenant_id=tenant_id,
        tier=tier,
    )


def _req() -> JudgeRequest:
    return JudgeRequest(
        candidate_output="2+2=4",
        criteria=[JudgeCriterion(name="correct", description="is it correct")],
    )


def _good_verdict() -> str:
    return json.dumps(
        {
            "verdict": "pass",
            "score": 1.0,
            "rationale": "right",
            "criteria_results": [{"name": "correct", "passed": True, "note": "ok"}],
        }
    )


async def test_parses_good_verdict() -> None:
    gw = _FakeGateway(_good_verdict())
    out = await _invoke(gw, request_id="r1", tenant_id="t1", tier="tier1")
    assert isinstance(out, JudgeParsed)
    assert out.verdict == "pass" and out.response.tier == "tier1"
    assert gw.calls[0]["tier"] == "tier1"


async def test_not_json_is_unparseable() -> None:
    out = await _invoke(_FakeGateway("not json at all"))
    assert isinstance(out, JudgeUnparseable) and out.parse_reason == "not_json"


async def test_schema_mismatch_is_unparseable() -> None:
    out = await _invoke(_FakeGateway(json.dumps({"verdict": "maybe"})))
    assert isinstance(out, JudgeUnparseable) and out.parse_reason == "schema_mismatch"


async def test_criteria_mismatch_is_unparseable() -> None:
    bad = json.dumps(
        {
            "verdict": "pass",
            "score": None,
            "rationale": "x",
            "criteria_results": [{"name": "WRONG", "passed": True, "note": ""}],
        }
    )
    out = await _invoke(_FakeGateway(bad))
    assert isinstance(out, JudgeUnparseable) and out.parse_reason == "criteria_mismatch"


@pytest.mark.parametrize("bad_score", ["true", "2.0", "-0.1", "NaN", "Infinity"])
async def test_invalid_score_is_schema_mismatch(bad_score: str) -> None:
    raw = (
        '{"verdict": "pass", "score": ' + bad_score + ', "rationale": "r", '
        '"criteria_results": [{"name": "correct", "passed": true, "note": ""}]}'
    )
    out = await _invoke(_FakeGateway(raw))
    assert isinstance(out, JudgeUnparseable) and out.parse_reason == "schema_mismatch"


async def test_long_rationale_and_note_are_truncated() -> None:
    from cognic_agentos.evaluation.judge import _MAX_VERDICT_TEXT_CHARS

    long = "x" * (_MAX_VERDICT_TEXT_CHARS + 500)
    raw = json.dumps(
        {
            "verdict": "pass",
            "score": 1.0,
            "rationale": long,
            "criteria_results": [{"name": "correct", "passed": True, "note": long}],
        }
    )
    out = await _invoke(_FakeGateway(raw))
    assert isinstance(out, JudgeParsed)
    assert out.rationale.endswith("…[truncated]")
    assert out.criteria_results[0].note.endswith("…[truncated]")


async def test_duplicate_response_criterion_names_is_unparseable() -> None:
    dup = json.dumps(
        {
            "verdict": "pass",
            "score": 1.0,
            "rationale": "r",
            "criteria_results": [
                {"name": "correct", "passed": True, "note": "a"},
                {"name": "correct", "passed": False, "note": "b"},
            ],
        }
    )
    out = await _invoke(_FakeGateway(dup))
    assert isinstance(out, JudgeUnparseable) and out.parse_reason == "criteria_mismatch"


async def test_candidate_input_is_threaded_into_the_user_message() -> None:
    """When ``candidate_input`` is set the prompt carries a CANDIDATE INPUT block."""
    req = JudgeRequest(
        candidate_input="what is 2+2?",
        candidate_output="2+2=4",
        criteria=[JudgeCriterion(name="correct", description="is it correct")],
    )
    gw = _FakeGateway(_good_verdict())
    out = await _invoke(gw, request=req)
    assert isinstance(out, JudgeParsed)
    messages = cast(list[dict[str, str]], gw.calls[0]["messages"])
    user_msg = next(m for m in messages if m["role"] == "user")
    assert "CANDIDATE INPUT:\nwhat is 2+2?" in user_msg["content"]


@pytest.mark.parametrize("body", ["[1, 2, 3]", "42", '"a string"', "true", "null"])
async def test_valid_json_non_object_is_not_json(body: str) -> None:
    """Parseable JSON that is not an object fails closed as ``not_json``."""
    out = await _invoke(_FakeGateway(body))
    assert isinstance(out, JudgeUnparseable) and out.parse_reason == "not_json"


@pytest.mark.parametrize(
    "rationale, criteria_results",
    [
        (123, [{"name": "correct", "passed": True, "note": ""}]),  # rationale not str
        (None, [{"name": "correct", "passed": True, "note": ""}]),  # rationale null
        ("r", "not a list"),  # criteria_results not list
        ("r", {"name": "correct"}),  # criteria_results an object, not a list
        ("r", None),  # criteria_results null
    ],
)
async def test_bad_rationale_or_results_shape_is_schema_mismatch(
    rationale: object, criteria_results: object
) -> None:
    """A verdict-valid payload with a wrong-typed rationale OR criteria_results."""
    raw = json.dumps(
        {
            "verdict": "pass",
            "score": 1.0,
            "rationale": rationale,
            "criteria_results": criteria_results,
        }
    )
    out = await _invoke(_FakeGateway(raw))
    assert isinstance(out, JudgeUnparseable) and out.parse_reason == "schema_mismatch"


@pytest.mark.parametrize(
    "element",
    [
        "not a dict",  # element not a dict
        {"passed": True, "note": ""},  # missing name
        {"name": 1, "passed": True, "note": ""},  # name not str
        {"name": "correct", "note": ""},  # missing passed
        {"name": "correct", "passed": "yes", "note": ""},  # passed not bool
        {"name": "correct", "passed": True},  # missing note
        {"name": "correct", "passed": True, "note": 0},  # note not str
    ],
)
async def test_malformed_criteria_result_element_is_schema_mismatch(element: object) -> None:
    """Each per-element shape violation fails closed as ``schema_mismatch``."""
    raw = json.dumps(
        {"verdict": "pass", "score": 1.0, "rationale": "r", "criteria_results": [element]}
    )
    out = await _invoke(_FakeGateway(raw))
    assert isinstance(out, JudgeUnparseable) and out.parse_reason == "schema_mismatch"
