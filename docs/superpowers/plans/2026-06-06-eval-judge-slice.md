# Eval Judge Slice — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first in-repo consumer of the harness-built `app.state.llm_gateway` — a generic OS LLM-as-judge primitive (`evaluation/judge.py`) + `POST /api/v1/eval/judge` that runs a single governed judge call and records a value-free `eval.judge_verdict` chain event.

**Architecture:** A persona-agnostic primitive does the governed gateway call + verdict parse (no I/O beyond the gateway); a portal route owns DI + RBAC + request bounds + the chain append + HTTP mapping. Both the gateway and the decision-history store are resolved **fail-closed before any gateway call**. Langfuse trace is deferred (the gateway emits none today).

**Tech Stack:** FastAPI + Pydantic v2, `LLMGateway.completion`, `DecisionHistoryStore.append`, the existing RBAC `RequireScope` + `Actor` seam.

**Source spec:** `docs/superpowers/specs/2026-06-06-eval-judge-slice-design.md` (committed `33c5a00`).

---

## File map

- Create `src/cognic_agentos/evaluation/__init__.py` — package marker.
- Create `src/cognic_agentos/evaluation/judge.py` — **the governed-call primitive (CRITICAL CONTROLS — 113th gate entry).** `run_judge(...) -> JudgeOutcome` + the `JudgeParsed` / `JudgeUnparseable` result types + `_parse_verdict`.
- Create `src/cognic_agentos/portal/api/evaluation/__init__.py` + `dto.py` (request/response DTOs + bound constants) + `routes.py` (the route + DI deps).
- Modify `src/cognic_agentos/portal/rbac/scopes.py` (add `EvalRBACScope` + `EVAL_SCOPES`) + `src/cognic_agentos/portal/rbac/actor.py` (add `| EvalRBACScope` to the `scopes` union) + `src/cognic_agentos/portal/rbac/enforcement.py` (widen the `RequireScope` scope union with `EvalRBACScope`).
- Modify `src/cognic_agentos/core/config.py` (add `eval_judge_tier`).
- Modify `src/cognic_agentos/portal/api/app.py` (mount `build_eval_routes` under `/api/v1/eval`).
- Modify `tools/check_critical_coverage.py` (112 → 113; add `evaluation/judge.py`).
- Create `tests/unit/architecture/test_eval_fences.py` (OS/pack fence).
- Tests under `tests/unit/evaluation/`, `tests/unit/portal/api/evaluation/`, `tests/unit/core/`, `tests/unit/portal/rbac/`.

> **Conventions to respect:** route modules OMIT `from __future__ import annotations` (FastAPI closure-local `Depends`); package is `evaluation/` not `eval/` (ruff `A005`); `uv run` for all Python; full-tree `mypy src tests` + `ruff check .` + `ruff format --check .` at every HALT; pytest narrow at HALT, full suite at COMMIT for CC-adjacent tasks.

---

## Task 1: RBAC scope family + `eval_judge_tier` Setting

**HALT-before-commit** — T1 touches the **RBAC enforcement** surface (`RequireScope`'s typed scope union) AND `core/config.py` (Settings, stop-rule-adjacent), so it is NOT narrow-only: full-tree `mypy` + **full suite at commit**. Use `core-controls-engineer` for the RBAC edits.

**Files:**
- Modify: `src/cognic_agentos/portal/rbac/scopes.py` (add `EvalRBACScope` + `EVAL_SCOPES`)
- Modify: `src/cognic_agentos/portal/rbac/actor.py:107-114` (add `| EvalRBACScope` to the `scopes` union)
- Modify: `src/cognic_agentos/portal/rbac/enforcement.py:40-46,243-249` (import `EvalRBACScope` + add it to the `RequireScope(scope: …)` union — **required for `RequireScope("eval.judge.run")` in Task 4 to type-check**)
- Modify: `src/cognic_agentos/core/config.py` (add `eval_judge_tier`)
- Test: `tests/unit/portal/rbac/test_eval_scopes.py`, `tests/unit/core/test_config_eval.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/portal/rbac/test_eval_scopes.py
from __future__ import annotations

import typing

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.scopes import EVAL_SCOPES, EvalRBACScope


def test_eval_scope_family_has_exactly_one_value() -> None:
    assert set(typing.get_args(EvalRBACScope)) == {"eval.judge.run"}
    assert EVAL_SCOPES == frozenset({"eval.judge.run"})


def test_actor_accepts_eval_scope() -> None:
    a = Actor(subject="svc", tenant_id="t1", scopes=frozenset({"eval.judge.run"}), actor_type="service")
    assert "eval.judge.run" in a.scopes
```

```python
# tests/unit/core/test_config_eval.py
from __future__ import annotations

import pytest
from pydantic import ValidationError

from cognic_agentos.core.config import Settings


def test_eval_judge_tier_defaults_to_tier1() -> None:
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.eval_judge_tier == "tier1"


def test_eval_judge_tier_rejects_non_logical_tier() -> None:
    # An alias (not a logical tier) must be refused at config-load — the gateway
    # only knows logical tiers (tier1/tier2); a bad value must not reach runtime.
    with pytest.raises(ValidationError):
        Settings(_env_file=None, eval_judge_tier="cognic-tier1-dev")  # type: ignore[call-arg]
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/portal/rbac/test_eval_scopes.py tests/unit/core/test_config_eval.py -q`
Expected: FAIL (`EvalRBACScope` / `eval_judge_tier` don't exist).

- [ ] **Step 3: Add the scope family** (`scopes.py`, after the `EmergencyRBACScope` block; plain `= Literal[...]`, no `TypeAlias`, matching the repo convention):

```python
#: Eval surface scope family (ADR-010 judge slice). Single value; service or
#: human actors may run judges (not a Human-only decision).
EvalRBACScope = Literal["eval.judge.run"]

#: All eval scopes as a frozenset (1:1 with EvalRBACScope) for bank-overlay binders.
EVAL_SCOPES: frozenset[EvalRBACScope] = frozenset({"eval.judge.run"})
```

- [ ] **Step 4: Add `EvalRBACScope` to BOTH the Actor scopes union AND the `RequireScope` union**

In `actor.py:107-114` (and add `EvalRBACScope` to the existing `from cognic_agentos.portal.rbac.scopes import (...)`):
```python
    scopes: frozenset[
        PackRBACScope
        | UIRBACScope
        | ComplianceRBACScope
        | ModelRBACScope
        | MemoryRBACScope
        | EmergencyRBACScope
        | EvalRBACScope
    ]
```

In `enforcement.py` — add `EvalRBACScope` to the scopes import (lines 40-46) AND to the `RequireScope` scope-param union (lines 243-249):
```python
def RequireScope(
    scope: PackRBACScope
    | UIRBACScope
    | ComplianceRBACScope
    | ModelRBACScope
    | MemoryRBACScope
    | EmergencyRBACScope
    | EvalRBACScope,
) -> Callable[..., Awaitable[Actor]]:
```
**Without the enforcement.py widening, `RequireScope("eval.judge.run")` (Task 4) fails `mypy`** — the literal is not in the union.

- [ ] **Step 5: Add the Setting** (`config.py`, near the `tier1_alias` / `tier2_alias` fields). `eval_judge_tier` is a **logical tier** (`tier1`/`tier2`), NOT an alias — `LLMGateway.completion(tier=...)` resolves it via `resolve_tier_alias`, which only knows `tier1`/`tier2` (`gateway.py:64`). Constrain at config-load so a bad value can't reach runtime:

```python
    eval_judge_tier: Literal["tier1", "tier2"] = Field(
        default="tier1",
        description=(
            "Logical tier the eval LLM-as-judge dispatches against (resolved to "
            "tier{1,2}_alias by the gateway). Operator-configured; callers cannot "
            "choose the tier (cost/abuse guard). Per ADR-010."
        ),
    )
```
(`Literal` is already imported in `config.py`; if not, add `from typing import Literal`.)

- [ ] **Step 6: Run to verify they pass + the RBAC partition test**

Run: `uv run pytest tests/unit/portal/rbac/ tests/unit/core/test_config_eval.py -q`
Expected: PASS. If a scope-partition invariant test enumerates the families, add `EVAL_SCOPES` to its expected union (grep `EMERGENCY_SCOPES` in `tests/unit/portal/rbac/` to find it).

- [ ] **Step 7: HALT-before-commit, then commit (full suite — RBAC enforcement + config touched)**

Full-tree `uv run ruff check . && uv run ruff format --check . && uv run mypy src tests` + halt summary (the scope family; BOTH unions widened — actor.py + enforcement.py; the `eval_judge_tier` Literal guard). Wait for `commit`, then **full suite** (`uv run pytest -q`):
```bash
git add src/cognic_agentos/portal/rbac/scopes.py src/cognic_agentos/portal/rbac/actor.py \
        src/cognic_agentos/portal/rbac/enforcement.py src/cognic_agentos/core/config.py \
        tests/unit/portal/rbac/test_eval_scopes.py tests/unit/core/test_config_eval.py
git commit -m "feat(eval): eval.judge.run RBAC scope family + eval_judge_tier Setting"
```

---

## Task 2: Request/response DTOs + bounds

**Files:**
- Create: `src/cognic_agentos/portal/api/evaluation/__init__.py` (empty package marker)
- Create: `src/cognic_agentos/portal/api/evaluation/dto.py`
- Test: `tests/unit/portal/api/evaluation/test_dto.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/portal/api/evaluation/test_dto.py
from __future__ import annotations

import pytest
from pydantic import ValidationError

from cognic_agentos.portal.api.evaluation.dto import (
    _MAX_CANDIDATE_CHARS,
    JudgeCriterion,
    JudgeRequest,
)


def _crit(name: str = "accuracy") -> dict:
    return {"name": name, "description": "is it accurate"}


def test_valid_request() -> None:
    r = JudgeRequest(candidate_output="hi", criteria=[JudgeCriterion(**_crit())])
    assert r.candidate_input is None and len(r.criteria) == 1


def test_empty_output_rejected() -> None:
    with pytest.raises(ValidationError):
        JudgeRequest(candidate_output="", criteria=[JudgeCriterion(**_crit())])


def test_zero_criteria_rejected() -> None:
    with pytest.raises(ValidationError):
        JudgeRequest(candidate_output="hi", criteria=[])


def test_duplicate_criterion_names_rejected() -> None:
    with pytest.raises(ValidationError):
        JudgeRequest(
            candidate_output="hi",
            criteria=[JudgeCriterion(**_crit("a")), JudgeCriterion(**_crit("a"))],
        )


def test_overlong_output_rejected() -> None:
    with pytest.raises(ValidationError):
        JudgeRequest(candidate_output="x" * (_MAX_CANDIDATE_CHARS + 1), criteria=[JudgeCriterion(**_crit())])


def test_empty_criterion_description_rejected() -> None:
    with pytest.raises(ValidationError):
        JudgeRequest(candidate_output="hi", criteria=[JudgeCriterion(name="a", description="")])
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/portal/api/evaluation/test_dto.py -q`
Expected: FAIL (module missing).

- [ ] **Step 3: Implement `dto.py`**

```python
"""Eval judge slice — request/response DTOs + bound constants (ADR-010 judge)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

#: Bound constants — every text field is capped so total prompt size (hence
#: gateway cost) is bounded. candidate text is the largest vector. Tunable.
_MAX_CANDIDATE_CHARS = 50_000
_MAX_CRITERIA = 20
_MAX_CRITERION_NAME_CHARS = 200
_MAX_CRITERION_DESC_CHARS = 2_000


class JudgeCriterion(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str = Field(min_length=1, max_length=_MAX_CRITERION_NAME_CHARS)
    description: str = Field(min_length=1, max_length=_MAX_CRITERION_DESC_CHARS)


class JudgeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    candidate_output: str = Field(min_length=1, max_length=_MAX_CANDIDATE_CHARS)
    candidate_input: str | None = Field(default=None, max_length=_MAX_CANDIDATE_CHARS)
    criteria: list[JudgeCriterion] = Field(min_length=1, max_length=_MAX_CRITERIA)

    @field_validator("criteria")
    @classmethod
    def _unique_names(cls, v: list[JudgeCriterion]) -> list[JudgeCriterion]:
        names = [c.name for c in v]
        if len(names) != len(set(names)):
            raise ValueError("criterion names must be unique")
        return v


class JudgeCriterionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str
    passed: bool
    note: str


class JudgeVerdictResponse(BaseModel):
    """200 response — the parsed verdict + honesty fields from GatewayResponse."""

    model_config = ConfigDict(extra="forbid")
    verdict: Literal["pass", "fail", "inconclusive"]
    score: float | None
    rationale: str
    criteria_results: list[JudgeCriterionResult]
    model: str
    tier: str
    latency_ms: int
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/unit/portal/api/evaluation/test_dto.py -q`
Expected: PASS.

- [ ] **Step 5: Commit (narrow gate — off-gate DTOs)**

`uv run ruff check . && uv run ruff format --check . && uv run mypy src tests`, then:
```bash
git add src/cognic_agentos/portal/api/evaluation/__init__.py \
        src/cognic_agentos/portal/api/evaluation/dto.py \
        tests/unit/portal/api/evaluation/test_dto.py
git commit -m "feat(eval): judge request/response DTOs + bound constants"
```

---

## Task 3: `evaluation/judge.py` — the governed-call primitive (CRITICAL CONTROLS)

**HALT-before-commit** (this is the governed-call decision surface + a CC-gate module). Negative-path tests required. Use `core-controls-engineer` + `/critical-module-mode`.

**Files:**
- Create: `src/cognic_agentos/evaluation/__init__.py` (empty)
- Create: `src/cognic_agentos/evaluation/judge.py`
- Test: `tests/unit/evaluation/test_judge.py`

The primitive is pure of HTTP/persistence: it builds the judge prompt, calls `gateway.completion` (letting gateway exceptions propagate — Mode B is the route's concern), and parses `GatewayResponse.content` into a result. It returns `JudgeParsed | JudgeUnparseable`.

- [ ] **Step 1: Write the failing tests** (happy + each `parse_reason`; a fake gateway):

```python
# tests/unit/evaluation/test_judge.py
from __future__ import annotations

import json

import pytest

from cognic_agentos.evaluation.judge import JudgeParsed, JudgeUnparseable, run_judge
from cognic_agentos.llm.gateway import GatewayResponse
from cognic_agentos.portal.api.evaluation.dto import JudgeCriterion, JudgeRequest


class _FakeGateway:
    def __init__(self, content: str) -> None:
        self._content = content
        self.calls: list[dict] = []

    async def completion(self, *, tier, messages, request_id, tenant_id=None) -> GatewayResponse:
        self.calls.append({"tier": tier, "messages": messages, "request_id": request_id})
        return GatewayResponse(
            content=self._content, upstream_model="m", api_base=None, external=False,
            request_id=request_id, tier=tier, latency_ms=5,
        )


def _req() -> JudgeRequest:
    return JudgeRequest(
        candidate_output="2+2=4",
        criteria=[JudgeCriterion(name="correct", description="is it correct")],
    )


def _good_verdict() -> str:
    return json.dumps({
        "verdict": "pass", "score": 1.0, "rationale": "right",
        "criteria_results": [{"name": "correct", "passed": True, "note": "ok"}],
    })


async def test_parses_good_verdict() -> None:
    gw = _FakeGateway(_good_verdict())
    out = await run_judge(request=_req(), gateway=gw, request_id="r1", tenant_id="t1", tier="tier1")  # type: ignore[arg-type]
    assert isinstance(out, JudgeParsed)
    assert out.verdict == "pass" and out.response.tier == "tier1"
    assert gw.calls[0]["tier"] == "tier1"  # logical tier threaded through


async def test_not_json_is_unparseable() -> None:
    out = await run_judge(request=_req(), gateway=_FakeGateway("not json at all"), request_id="r", tenant_id=None, tier="tier1")  # type: ignore[arg-type]
    assert isinstance(out, JudgeUnparseable) and out.parse_reason == "not_json"


async def test_schema_mismatch_is_unparseable() -> None:
    out = await run_judge(request=_req(), gateway=_FakeGateway(json.dumps({"verdict": "maybe"})), request_id="r", tenant_id=None, tier="tier1")  # type: ignore[arg-type]
    assert isinstance(out, JudgeUnparseable) and out.parse_reason == "schema_mismatch"


async def test_criteria_mismatch_is_unparseable() -> None:
    bad = json.dumps({
        "verdict": "pass", "score": None, "rationale": "x",
        "criteria_results": [{"name": "WRONG", "passed": True, "note": ""}],
    })
    out = await run_judge(request=_req(), gateway=_FakeGateway(bad), request_id="r", tenant_id=None, tier="tier1")  # type: ignore[arg-type]
    assert isinstance(out, JudgeUnparseable) and out.parse_reason == "criteria_mismatch"


@pytest.mark.parametrize("bad_score", ["true", "2.0", "-0.1", "NaN", "Infinity"])
async def test_invalid_score_is_schema_mismatch(bad_score: str) -> None:
    # [P1] bool / out-of-[0,1] / NaN / inf must NOT become a clean verdict.
    # The bad literal is embedded directly (json.loads accepts NaN/Infinity).
    raw = (
        '{"verdict": "pass", "score": ' + bad_score + ', "rationale": "r", '
        '"criteria_results": [{"name": "correct", "passed": true, "note": ""}]}'
    )
    out = await run_judge(request=_req(), gateway=_FakeGateway(raw), request_id="r", tenant_id=None, tier="tier1")  # type: ignore[arg-type]
    assert isinstance(out, JudgeUnparseable) and out.parse_reason == "schema_mismatch"


async def test_long_rationale_and_note_are_truncated() -> None:
    # [P2] model text is capped on the way out so the chain payload stays bounded.
    from cognic_agentos.evaluation.judge import _MAX_VERDICT_TEXT_CHARS

    long = "x" * (_MAX_VERDICT_TEXT_CHARS + 500)
    raw = json.dumps({
        "verdict": "pass", "score": 1.0, "rationale": long,
        "criteria_results": [{"name": "correct", "passed": True, "note": long}],
    })
    out = await run_judge(request=_req(), gateway=_FakeGateway(raw), request_id="r", tenant_id=None, tier="tier1")  # type: ignore[arg-type]
    assert isinstance(out, JudgeParsed)
    assert out.rationale.endswith("…[truncated]")
    assert out.criteria_results[0].note.endswith("…[truncated]")


async def test_duplicate_response_criterion_names_is_unparseable() -> None:
    # [P1] two results for the same requested criterion — set matches but COUNT
    # does not; must be criteria_mismatch, never a clean verdict.
    dup = json.dumps({
        "verdict": "pass", "score": 1.0, "rationale": "r",
        "criteria_results": [
            {"name": "correct", "passed": True, "note": "a"},
            {"name": "correct", "passed": False, "note": "b"},
        ],
    })
    out = await run_judge(request=_req(), gateway=_FakeGateway(dup), request_id="r", tenant_id=None, tier="tier1")  # type: ignore[arg-type]
    assert isinstance(out, JudgeUnparseable) and out.parse_reason == "criteria_mismatch"
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/evaluation/test_judge.py -q`
Expected: FAIL (module missing).

- [ ] **Step 3: Implement `evaluation/judge.py`**

```python
"""ADR-010 LLM-as-judge — the generic, persona-agnostic governed-call primitive.

CRITICAL CONTROLS: this is the single LLM-judge call surface. It dispatches
through ``LLMGateway.completion`` (cloud-policy + ledger + audit governance) and
parses the model verdict fail-closed — it NEVER fabricates a verdict. It performs
no HTTP and no persistence; the route owns those. Gateway exceptions PROPAGATE
(Mode B is the route's concern). Imports no agent/persona surface (OS/pack fence).
"""

from __future__ import annotations

import dataclasses
import json
import math
from typing import TYPE_CHECKING, Literal

from cognic_agentos.portal.api.evaluation.dto import (
    JudgeCriterionResult,
    JudgeRequest,
)

if TYPE_CHECKING:
    from cognic_agentos.llm.gateway import GatewayResponse, LLMGateway

ParseReason = Literal["not_json", "schema_mismatch", "criteria_mismatch"]

#: Cap model-supplied verdict text (rationale + each note) so the chain payload
#: AND the 200 response stay bounded. The DTO bounds the REQUEST side; this bounds
#: the model OUTPUT side, which the DTO cannot. [P2 fix]
_MAX_VERDICT_TEXT_CHARS = 4_000


def _cap(text: str) -> str:
    return (
        text if len(text) <= _MAX_VERDICT_TEXT_CHARS
        else text[:_MAX_VERDICT_TEXT_CHARS] + "…[truncated]"
    )


_SYSTEM = (
    "You are a rigorous evaluator. Judge the candidate output against EACH named "
    "criterion. Respond with ONLY a JSON object of the form "
    '{"verdict": "pass"|"fail"|"inconclusive", "score": number-in-[0,1]-or-null, '
    '"rationale": string, "criteria_results": [{"name": string, "passed": bool, '
    '"note": string}]}. The criteria_results MUST list EXACTLY the requested '
    "criterion names. Use \"inconclusive\" when the material is insufficient."
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


def _parse_verdict(content: str, request: JudgeRequest) -> tuple[
    Literal["pass", "fail", "inconclusive"], float | None, str, tuple[JudgeCriterionResult, ...]
] | ParseReason:
    """Returns the parsed 4-tuple, or a ParseReason on failure. Never raises."""
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
        # [P1 fix] strict: bool is an int subclass; NaN/inf pass isinstance;
        # out-of-[0,1] is invalid. Any of these must NOT become a clean verdict.
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
        if not isinstance(r, dict) or not isinstance(r.get("name"), str) \
                or not isinstance(r.get("passed"), bool) or not isinstance(r.get("note"), str):
            return "schema_mismatch"
        results.append(JudgeCriterionResult(name=r["name"], passed=r["passed"], note=_cap(r["note"])))
    requested = {c.name for c in request.criteria}
    # [P1 fix] EXACT bijection — same COUNT and same SET. Request names are unique
    # (DTO validator), so len+set together reject duplicate response names (which a
    # bare set check would accept, e.g. [correct, correct] for requested {correct}).
    if len(results) != len(request.criteria) or {r.name for r in results} != requested:
        return "criteria_mismatch"
    # [P2 fix] cap model text on the way out (rationale + each note).
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
    return JudgeParsed(verdict=verdict, score=score, rationale=rationale,
                       criteria_results=results, response=response)
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/unit/evaluation/test_judge.py -v`
Expected: PASS (all 4).

- [ ] **Step 5: HALT-before-commit** (CC module). Full-tree `mypy`/`ruff`, narrow pytest, halt summary mapping the 3 `parse_reason` branches + the propagation contract to their tests. Wait for `commit`, then **full suite**:
```bash
git add src/cognic_agentos/evaluation/__init__.py src/cognic_agentos/evaluation/judge.py \
        tests/unit/evaluation/test_judge.py
git commit -m "feat(eval): governed LLM-as-judge primitive (parse fail-closed, gateway-exception propagate)"
```

---

## Task 4: `POST /api/v1/eval/judge` route + fail-closed DI

**HALT-before-commit** (governance-adjacent: the DI fail-closed ordering + the chain append + the Mode-B no-event contract).

**Files:**
- Create: `src/cognic_agentos/portal/api/evaluation/routes.py`
- Test: `tests/unit/portal/api/evaluation/test_routes.py`

> `routes.py` OMITS `from __future__ import annotations` (closure-local `Depends`).

The route: `RequireScope("eval.judge.run")` → `_require_llm_gateway` + `_require_decision_history_store` (both fail-closed BEFORE the body) → `run_judge` (catch gateway exceptions = Mode B → HTTP, NO eval event) → on `JudgeParsed`: append `succeeded` + 200; on `JudgeUnparseable`: append `errored` + 502.

- [ ] **Step 1: Write the failing tests** (build the app via `create_app`; a fake gateway/store on `app.state`).

```python
# tests/unit/portal/api/evaluation/test_routes.py — abridged; mirror tests/unit/portal/api/memory/test_memory_routes.py harness
# Cases (each asserted):
#  - 200 succeeded: fake gateway returns a good verdict JSON → body is JudgeVerdictResponse;
#    a "succeeded" eval.judge_verdict row was appended (capture via a fake store);
#    payload is VALUE-FREE (no candidate_output text; input_digest/output_digest present).
#  - 502 judge_verdict_unparseable: gateway returns junk → 502 {"reason": "judge_verdict_unparseable"};
#    an "errored" row appended with safe evidence only (response_digest + parse_reason, NO verdict).
#  - 503 llm_gateway_unavailable: app.state.llm_gateway = None → 503; the fake gateway saw ZERO calls.
#  - 503 decision_history_unavailable: store unresolvable → 503; ZERO gateway calls.
#  - 403 scope_not_held: actor without eval.judge.run.
#  - 422: empty output / 0 criteria / dup names / over-length output.
#  - Mode B exception→HTTP table (each case pins ZERO eval events appended): fake gateway
#    raises CloudPolicyViolationError / GuardrailViolationError → 502; LLMConcurrencyExceeded
#    → 429; a generic RuntimeError (stand-in for httpx/SLA/upstream) → 502 (default — proves
#    no raw 500 leak). Every Mode-B case asserts the capturing store received NO append.
#  - Prod-DI: app with app.state.runtime set (no decision_history_store kwarg) resolves the store from runtime.
```

(Write each case explicitly in the file — the controller provides the full harness when dispatching; use a `_FakeGateway` with a `raise_exc` option for Mode B and a `_CapturingStore` recording appended `DecisionRecord`s.)

- [ ] **Step 2: Run to verify it fails** — `uv run pytest tests/unit/portal/api/evaluation/test_routes.py -q` → FAIL (module missing).

- [ ] **Step 3: Implement `routes.py`**

```python
"""ADR-010 eval judge surface — POST /api/v1/eval/judge.

DI fail-closed BEFORE any gateway call (both the gateway AND the decision-history
store): a judge call must never dispatch unless its evidence can be recorded.
``from __future__ import annotations`` is OMITTED (FastAPI closure-local Depends).
"""

import hashlib
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request

from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.evaluation.judge import JudgeParsed, JudgeUnparseable, run_judge
from cognic_agentos.llm.concurrency import LLMConcurrencyExceeded
from cognic_agentos.llm.gateway import LLMGateway
from cognic_agentos.llm.policy import CloudPolicyViolationError, GuardrailViolationError
from cognic_agentos.portal.api.evaluation.dto import (
    JudgeCriterionResult,
    JudgeRequest,
    JudgeVerdictResponse,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope

_LOG = logging.getLogger(__name__)
_ISO = ("ISO42001.A.7.4",)
_UNPARSEABLE = "judge_verdict_unparseable"


def _digest(text: str | None) -> str | None:
    return hashlib.sha256(text.encode("utf-8")).hexdigest() if text is not None else None


def _gateway_exc_to_status(exc: Exception) -> int:
    # [P1 fix] explicit exception→HTTP table; the 502 default covers every other
    # gateway-before-content failure (httpx / SLA / upstream / malformed /
    # UnknownTier / unknown) so nothing leaks as a raw 500.
    if isinstance(exc, LLMConcurrencyExceeded):
        return 429  # too many concurrent LLM calls — retryable
    if isinstance(exc, GuardrailViolationError | CloudPolicyViolationError):
        return 502  # the governed gateway refused the call
    return 502


def _require_llm_gateway(request: Request) -> LLMGateway:
    gw: LLMGateway | None = getattr(request.app.state, "llm_gateway", None)
    if gw is None:
        raise HTTPException(status_code=503, detail={"reason": "llm_gateway_unavailable"})
    return gw


def _require_decision_history_store(request: Request) -> DecisionHistoryStore:
    runtime = getattr(request.app.state, "runtime", None)
    store: DecisionHistoryStore | None = (
        runtime.decision_history_store
        if runtime is not None
        else getattr(request.app.state, "decision_history_store", None)
    )
    if store is None:
        raise HTTPException(status_code=503, detail={"reason": "decision_history_unavailable"})
    return store


def build_eval_routes(*, eval_judge_tier: str) -> APIRouter:
    router = APIRouter()
    _require_scope = RequireScope("eval.judge.run")

    @router.post("/judge", summary="Run a governed LLM-as-judge over a candidate output")
    async def judge(
        request: Request,
        actor: Annotated[Actor, Depends(_require_scope)],
        gateway: Annotated[LLMGateway, Depends(_require_llm_gateway)],
        store: Annotated[DecisionHistoryStore, Depends(_require_decision_history_store)],
        body: JudgeRequest,
    ) -> JudgeVerdictResponse:
        request_id = getattr(request.state, "request_id", None) or "eval-judge"
        input_digest = _digest(body.candidate_input)
        output_digest = _digest(body.candidate_output)
        criteria = [{"name": c.name, "description": c.description} for c in body.criteria]
        try:
            outcome = await run_judge(
                request=body, gateway=gateway, request_id=request_id,
                tenant_id=actor.tenant_id, tier=eval_judge_tier,
            )
        except Exception as exc:  # noqa: BLE001 — justified below
            # [P1 fix] Mode B — ANY gateway-before-content failure. run_judge's ONLY
            # raising op is gateway.completion (the parse never raises — it returns
            # JudgeUnparseable), so this catches exactly the gateway exception surface
            # (httpx / SLA / upstream / guardrail / cloud-policy / concurrency /
            # malformed / UnknownTier). The gateway has ALREADY audited/ledgered its
            # own evidence → emit NO eval event. The explicit table + 502 default
            # guarantees no raw 500 leaks. asyncio.CancelledError extends
            # BaseException, so cancellation is NOT swallowed.
            status = _gateway_exc_to_status(exc)
            _LOG.warning(
                "eval.judge.gateway_failed",
                extra={"exc_type": type(exc).__name__, "request_id": request_id},
            )
            raise HTTPException(status_code=status, detail={"reason": "gateway_call_failed"}) from None

        if isinstance(outcome, JudgeUnparseable):
            await store.append(DecisionRecord(
                decision_type="eval.judge_verdict", request_id=request_id,
                actor_id=actor.subject, tenant_id=actor.tenant_id, iso_controls=_ISO,
                payload={
                    "status": "errored", "parse_reason": outcome.parse_reason,
                    "criteria": criteria, "input_digest": input_digest,
                    "output_digest": output_digest,
                    "response_digest": _digest(outcome.response.content),
                    "model": outcome.response.upstream_model, "tier": outcome.response.tier,
                    "latency_ms": outcome.response.latency_ms,
                },
            ))
            raise HTTPException(status_code=502, detail={"reason": _UNPARSEABLE})

        assert isinstance(outcome, JudgeParsed)
        await store.append(DecisionRecord(
            decision_type="eval.judge_verdict", request_id=request_id,
            actor_id=actor.subject, tenant_id=actor.tenant_id, iso_controls=_ISO,
            payload={
                "status": "succeeded", "verdict": outcome.verdict, "score": outcome.score,
                "criteria_results": [r.model_dump() for r in outcome.criteria_results],
                "criteria": criteria, "input_digest": input_digest, "output_digest": output_digest,
                "model": outcome.response.upstream_model, "tier": outcome.response.tier,
                "latency_ms": outcome.response.latency_ms,
            },
        ))
        return JudgeVerdictResponse(
            verdict=outcome.verdict, score=outcome.score, rationale=outcome.rationale,
            criteria_results=list(outcome.criteria_results),
            model=outcome.response.upstream_model, tier=outcome.response.tier,
            latency_ms=outcome.response.latency_ms,
        )

    return router
```

- [ ] **Step 4: Run to verify it passes** — `uv run pytest tests/unit/portal/api/evaluation/test_routes.py -v` → PASS (all cases). Confirm the value-free assertion (no raw `candidate_output` in any appended payload).

- [ ] **Step 5: HALT-before-commit** (governance-adjacent). Full-tree `mypy`/`ruff` + narrow pytest + halt summary (DI fail-closed-before-dispatch; Mode A errored-event; Mode B no-event; value-free payload). Wait for `commit`, then full suite:
```bash
git add src/cognic_agentos/portal/api/evaluation/routes.py tests/unit/portal/api/evaluation/test_routes.py
git commit -m "feat(eval): POST /api/v1/eval/judge — fail-closed DI + value-free eval.judge_verdict"
```

---

## Task 5: Mount + OS/pack architecture fence

**Files:**
- Modify: `src/cognic_agentos/portal/api/app.py` (mount under `/api/v1/eval`)
- Create: `tests/unit/architecture/test_eval_fences.py`
- Test: `tests/unit/portal/api/test_app_eval_mount.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/portal/api/test_app_eval_mount.py
from __future__ import annotations

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.portal.api.app import create_app


def test_eval_judge_route_mounted() -> None:
    app = create_app(build_settings_without_env_file())
    assert any(getattr(r, "path", "") == "/api/v1/eval/judge" for r in app.routes)
```

```python
# tests/unit/architecture/test_eval_fences.py — mirror test_harness_fences.py exactly:
#   absolute _EVAL_DIR = parents[3]/src/cognic_agentos/evaluation; _imported_modules AST helper;
#   test_eval_dir_has_expected_sources (== {"__init__.py","judge.py"});
#   test_eval_imports_no_layer_c (no "cognic_agentos.agents" import);
#   test_eval_imports_no_agent_sdk (no "cognic_agentos.sdk.agent" import).
```

- [ ] **Step 2: Run to verify they fail** — `uv run pytest tests/unit/architecture/test_eval_fences.py tests/unit/portal/api/test_app_eval_mount.py -q` → mount FAILs (not mounted); fence may pass already (judge.py imports clean) — that's fine.

- [ ] **Step 3: Mount in `app.py`** (near the `/memory` mount block; unconditional — the gateway is always built; the `503` covers the unwired window). Lazy import keeps the eval package out of the import graph until mounted:

```python
    # Eval judge surface (ADR-010 — first gateway consumer).
    from cognic_agentos.portal.api.evaluation.routes import build_eval_routes

    app.include_router(
        build_eval_routes(eval_judge_tier=settings.eval_judge_tier),
        prefix="/api/v1/eval",
        tags=["eval"],
    )
```

- [ ] **Step 4: Run to verify they pass** — `uv run pytest tests/unit/architecture/test_eval_fences.py tests/unit/portal/api/test_app_eval_mount.py -q` → PASS.

- [ ] **Step 5: HALT-before-commit** (app.py is a composition surface + the fence is security-adjacent). Full-tree gate + halt summary. Wait for `commit`, then full suite:
```bash
git add src/cognic_agentos/portal/api/app.py tests/unit/architecture/test_eval_fences.py \
        tests/unit/portal/api/test_app_eval_mount.py
git commit -m "feat(eval): mount /api/v1/eval + OS/pack architecture fence"
```

---

## Task 6: CC-gate promotion (113th) + Z-gate + closeout

**HALT-before-commit** (gate change + closeout).

**Files:**
- Modify: `tools/check_critical_coverage.py` (add `evaluation/judge.py` to `_CRITICAL_FILES`)
- Modify: `tests/unit/tools/test_check_critical_coverage.py` (bump the expected-count `n` 112 → 113 — the count guard asserting `len(_CRITICAL_FILES) == n` lives in the TEST, not the tool)
- Create: `docs/closeouts/2026-06-06-eval-judge-slice.md`

- [ ] **Step 1: Promote `evaluation/judge.py`** — add `("src/cognic_agentos/evaluation/judge.py", 0.95, 0.90),` to `_CRITICAL_FILES` in `tools/check_critical_coverage.py`, AND bump the expected-count `n` (112 → 113) in `tests/unit/tools/test_check_critical_coverage.py` (the `assert len(_CRITICAL_FILES) == n` guard lives in the TEST, per the [P1] review finding). **Both edits in this same commit** — otherwise the count test fails.

- [ ] **Step 2: Verify promotion against FRESH coverage IN this commit** (per `feedback_verify_promotion_meets_floor_at_promotion_time`):
```
uv run pytest -q --cov=cognic_agentos --cov-branch --cov-report=json
uv run python tools/check_critical_coverage.py
```
Expected: **113/113 PASS**. If `evaluation/judge.py` is below floor, add the missing negative-path test (each `parse_reason`, the propagation path) before proceeding — do NOT lower the floor.

- [ ] **Step 3: Full Z-gate** — `uv run pytest -q` (all green; record counts) · `uv run ruff check . && uv run ruff format --check . && uv run mypy src tests` (clean) · grep `type: ignore` in `src/cognic_agentos/evaluation/` (expect none, or justify).

- [ ] **Step 4: Write the closeout** — `docs/closeouts/2026-06-06-eval-judge-slice.md`: commit table, the gateway-now-exercised result, the two-mode failure taxonomy, the value-free chain row + `A.7.4`, CC 112 → 113, the honest **Langfuse-deferred** marker + the named gateway-observability follow-on workstream.

- [ ] **Step 5: HALT-before-commit (READY FOR GATE)**, then commit + finish:
```bash
git add tools/check_critical_coverage.py tests/unit/tools/test_check_critical_coverage.py \
        docs/closeouts/2026-06-06-eval-judge-slice.md
git commit -m "feat(eval): promote judge primitive to CC gate (113) + Z-gate + closeout"
```
Then `superpowers:finishing-a-development-branch` (push + PR on explicit tokens; never `--auto`).

---

## Self-review (controller)

- **Spec coverage:** every spec section maps to a task — DTOs+bounds (T2), primitive+failure-taxonomy (T3), route+DI fail-closed+value-free chain+Mode-A/B (T4), RBAC+Settings (T1), mount+fence (T5), CC-gate+closeout+Langfuse-deferral (T6). ✓
- **Type consistency:** `JudgeRequest`/`JudgeCriterion`/`JudgeCriterionResult`/`JudgeVerdictResponse` (T2) are consumed unchanged in T3/T4; `JudgeParsed`/`JudgeUnparseable`/`run_judge` (T3) consumed in T4; `EvalRBACScope`/`eval_judge_tier` (T1) consumed in T4/T5; `_require_decision_history_store` runtime-first matches the spec [P1] fix. ✓
- **Plan-level items resolved:** gateway-exception→HTTP table (T4: Guardrail/CloudPolicy→502, Concurrency→429, NO eval event); `eval_judge_tier` default `"tier1"` logical tier (T1); ISO `A.7.4` (T4). ✓
- **Open confirmation for the implementer (bounded, not a placeholder):** the exact name of any scope-partition test to extend (T1 step 6 — grep `EMERGENCY_SCOPES`).
- **Review patches (2026-06-06, spec/plan review round):** [P1] `RequireScope` is a typed scope union (`enforcement.py:243-249`) → T1 widens it AND is re-gated HALT/full-suite; [P1] T3 `score` validation hardened (rejects `bool` / `NaN` / `inf` / out-of-`[0,1]`); [P1] T4 explicit gateway-exception→HTTP table + catch-all (no raw 500 leak; no eval event for any Mode-B class); [P1] T6 bumps the count guard in `tests/unit/tools/test_check_critical_coverage.py` (not just the tool); [P2] T3 caps model `rationale`/`note` via `_MAX_VERDICT_TEXT_CHARS`; [P2] T1 re-gated HALT (RBAC enforcement + config surface).
