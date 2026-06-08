"""Eval judge slice — request/response DTOs + bound constants (ADR-010 judge).

Every text field is length-capped so total prompt size (hence gateway cost) is
bounded — the candidate text is the largest vector. Bounds are tunable.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator

#: Named bound constants (tunable). Capping every text field bounds prompt cost.
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


# --- ADR-010 amendment: bulk-run DTOs (Task 10) --------------------------------


class BulkRunRequest(BaseModel):
    """POST /api/v1/eval/bulk-run body.

    ``corpus`` is an inline corpus document validated against the strict
    ``corpus.Corpus`` model in the handler (not re-modelled here — one validator,
    no drift). ``persist_raw_output`` opts into storing the candidate text on the
    relational case rows (capped + truncation-flagged); default-off keeps a run
    value-free by default.
    """

    model_config = ConfigDict(extra="forbid")
    corpus: dict[str, Any]
    target: Literal["gateway"] = "gateway"
    persist_raw_output: StrictBool = False


class BulkCaseResultResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: str
    passed: bool
    outcome: Literal["succeeded", "errored"]
    latency_ms: int
    model: str
    raw_output_persisted: bool
    output_truncated: bool


class BulkRunResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: str
    chain_request_id: str
    corpus_id: str
    target_kind: str
    tier: str
    total: int
    passed: int
    failed: int
    errored: int
    latency_p50_ms: int
    latency_p95_ms: int
    cases: list[BulkCaseResultResponse]
