"""ADR-010 LLM-as-judge — the generic, persona-agnostic governed-call primitive.

CRITICAL CONTROLS: the single LLM-judge call surface. Dispatches through
``LLMGateway.completion`` (cloud-policy + ledger + audit governance) and parses
the model verdict fail-closed — it NEVER fabricates a verdict. No HTTP, no
persistence (the route owns those). Gateway exceptions PROPAGATE (Mode B is the
route's concern). Imports no agent/persona surface (OS/pack fence).
"""

from __future__ import annotations

import dataclasses
import json
import math
from typing import TYPE_CHECKING, Literal

from cognic_agentos.portal.api.evaluation.dto import JudgeCriterionResult, JudgeRequest

if TYPE_CHECKING:
    from cognic_agentos.llm.gateway import GatewayResponse, LLMGateway

ParseReason = Literal["not_json", "schema_mismatch", "criteria_mismatch"]

#: Cap model-supplied verdict text (rationale + each note) so the chain payload
#: AND the 200 response stay bounded. The DTO bounds the REQUEST side; this bounds
#: the model OUTPUT side, which the DTO cannot.
_MAX_VERDICT_TEXT_CHARS = 4_000


def _cap(text: str) -> str:
    return (
        text
        if len(text) <= _MAX_VERDICT_TEXT_CHARS
        else text[:_MAX_VERDICT_TEXT_CHARS] + "…[truncated]"
    )


_SYSTEM = (
    "You are a rigorous evaluator. Judge the candidate output against EACH named "
    "criterion. Respond with ONLY a JSON object of the form "
    '{"verdict": "pass"|"fail"|"inconclusive", "score": number-in-[0,1]-or-null, '
    '"rationale": string, "criteria_results": [{"name": string, "passed": bool, '
    '"note": string}]}. The criteria_results MUST list EXACTLY the requested '
    'criterion names. Use "inconclusive" when the material is insufficient.'
)


@dataclasses.dataclass(frozen=True, slots=True)
class JudgeParsed:
    verdict: Literal["pass", "fail", "inconclusive"]
    score: float | None
    rationale: str
    criteria_results: tuple[JudgeCriterionResult, ...]
    response: GatewayResponse


@dataclasses.dataclass(frozen=True, slots=True)
class JudgeUnparseable:
    parse_reason: ParseReason
    response: GatewayResponse


JudgeOutcome = JudgeParsed | JudgeUnparseable


def _build_messages(request: JudgeRequest) -> list[dict[str, str]]:
    lines = [f"- {c.name}: {c.description}" for c in request.criteria]
    user = "CRITERIA:\n" + "\n".join(lines)
    if request.candidate_input is not None:
        user += f"\n\nCANDIDATE INPUT:\n{request.candidate_input}"
    user += f"\n\nCANDIDATE OUTPUT:\n{request.candidate_output}"
    return [{"role": "system", "content": _SYSTEM}, {"role": "user", "content": user}]


def _parse_verdict(
    content: str, request: JudgeRequest
) -> (
    tuple[
        Literal["pass", "fail", "inconclusive"], float | None, str, tuple[JudgeCriterionResult, ...]
    ]
    | ParseReason
):
    """Returns the parsed 4-tuple, or a ParseReason on failure. NEVER raises."""
    try:
        obj = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return "not_json"
    if not isinstance(obj, dict):
        return "not_json"
    verdict = obj.get("verdict")
    if verdict not in ("pass", "fail", "inconclusive"):
        return "schema_mismatch"
    score = obj.get("score")
    if score is not None:
        # strict: bool is an int subclass; NaN/inf pass isinstance; out-of-[0,1] invalid.
        if isinstance(score, bool) or not isinstance(score, int | float):
            return "schema_mismatch"
        if not math.isfinite(float(score)) or not (0.0 <= float(score) <= 1.0):
            return "schema_mismatch"
    rationale = obj.get("rationale")
    raw_results = obj.get("criteria_results")
    if not isinstance(rationale, str) or not isinstance(raw_results, list):
        return "schema_mismatch"
    results: list[JudgeCriterionResult] = []
    for r in raw_results:
        if (
            not isinstance(r, dict)
            or not isinstance(r.get("name"), str)
            or not isinstance(r.get("passed"), bool)
            or not isinstance(r.get("note"), str)
        ):
            return "schema_mismatch"
        results.append(
            JudgeCriterionResult(name=r["name"], passed=r["passed"], note=_cap(r["note"]))
        )
    requested = {c.name for c in request.criteria}
    # EXACT bijection — same COUNT and same SET (request names are unique per the
    # DTO validator, so this rejects duplicate response names a bare set would accept).
    if len(results) != len(request.criteria) or {r.name for r in results} != requested:
        return "criteria_mismatch"
    return verdict, (float(score) if score is not None else None), _cap(rationale), tuple(results)


async def run_judge(
    *,
    request: JudgeRequest,
    gateway: LLMGateway,
    request_id: str,
    tenant_id: str | None,
    tier: str,
) -> JudgeOutcome:
    response = await gateway.completion(
        tier=tier,
        messages=_build_messages(request),
        request_id=request_id,
        tenant_id=tenant_id,
    )
    parsed = _parse_verdict(response.content, request)
    if isinstance(parsed, str):
        return JudgeUnparseable(parse_reason=parsed, response=response)
    verdict, score, rationale, results = parsed
    return JudgeParsed(
        verdict=verdict,
        score=score,
        rationale=rationale,
        criteria_results=results,
        response=response,
    )
