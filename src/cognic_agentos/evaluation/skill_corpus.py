"""A-007 skill-corpus manifest and fail-closed JSONL loader.

This is deliberately a sibling of :mod:`cognic_agentos.evaluation.corpus`.
That module owns the ADR-010 YAML wire contract; this module owns the signed
skill-pack convention at ``golden/{manifest.toml,queries.jsonl}`` and has its
own closed refusal vocabulary.
"""

from __future__ import annotations

import json
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, StrictBool, ValidationError

_SCHEMA_VERSION = 1
_MAX_QUERY_LINE_BYTES = 256_000

SkillCaseKind = Literal["golden", "adversarial", "refusal", "trigger_pos", "trigger_neg"]
SkillExpectedMode = Literal["rows", "scalar", "refusal", "assumption", "clarify", "route"]
SkillScoring = Literal["deterministic", "judge"]
SkillHardKind = Literal["refusal", "adversarial"]

SkillCorpusLoadReason = Literal[
    "skill_corpus_manifest_missing",
    "skill_corpus_queries_missing",
    "skill_corpus_manifest_unparseable",
    "skill_corpus_query_unparseable",
    "skill_corpus_unknown_key",
    "skill_corpus_schema_version_unsupported",
    "skill_corpus_manifest_invalid",
    "skill_corpus_n_reps_invalid",
    "skill_corpus_judge_calibration_insufficient",
    "skill_corpus_no_cases",
    "skill_corpus_case_invalid",
    "skill_corpus_duplicate_case_id",
    "skill_corpus_case_balance_invalid",
    "skill_corpus_trigger_expectation_invalid",
    "skill_corpus_trigger_balance_invalid",
    "skill_corpus_holdout_mismatch",
    "skill_corpus_performance_conformance_invalid",
]


class SkillCorpusLoadError(Exception):
    """Fail-closed skill-corpus rejection with a wire-stable reason."""

    def __init__(self, reason: SkillCorpusLoadReason, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason: SkillCorpusLoadReason = reason
        self.detail = detail


class SkillJudgeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    model_alias: str = Field(min_length=1, max_length=200)
    rubric_ref: str = Field(min_length=1, max_length=200)
    calibration_set_id: str = Field(min_length=1, max_length=200)
    measured_kappa: float | None = Field(default=None, ge=-1.0, le=1.0, strict=True)


class SkillAblationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: StrictBool
    minimum_uplift: float = Field(gt=0.0, le=1.0, strict=True)


class SkillGateConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    hard_failure_kinds: tuple[SkillHardKind, ...]
    zero_observed_failures: Literal[True]
    wrong_answer_rate_target: float = Field(gt=0.0, le=0.02, strict=True)
    rate_gate_min_observations: int = Field(ge=1, strict=True)
    minimum_trigger_accuracy: float = Field(ge=0.0, le=1.0, strict=True)
    minimum_trigger_positive: int = Field(ge=3, strict=True)
    minimum_trigger_negative: int = Field(ge=3, strict=True)
    minimum_judge_kappa: float = Field(ge=0.7, le=1.0, strict=True)


class SkillHoldoutConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_ids: tuple[str, ...]


class SkillPerformanceConformanceConfig(BaseModel):
    """Shape checks reported independently and never folded into A-007."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    non_gating_case_ids: tuple[str, ...]


class SkillReferenceConfig(BaseModel):
    """How the proof runner obtains objective live anchors for SQL cases."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    server_id: str = Field(min_length=1, max_length=200)
    tool_name: str = Field(min_length=1, max_length=200)
    scope_id: str = Field(min_length=1, max_length=128)


class SkillEvalManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(strict=True)
    skill_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,127}$")
    n_reps: int = Field(ge=3, le=5, strict=True)
    judge: SkillJudgeConfig
    ablation: SkillAblationConfig
    gates: SkillGateConfig
    holdouts: SkillHoldoutConfig
    performance_conformance: SkillPerformanceConformanceConfig
    reference: SkillReferenceConfig


class SkillExpected(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: SkillExpectedMode
    value: JsonValue
    verify_live: StrictBool


class SkillCorpusCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    kind: SkillCaseKind
    question: str = Field(min_length=1, max_length=32_000)
    reference_sql: str | None = Field(default=None, max_length=50_000)
    expected: SkillExpected
    scoring: SkillScoring
    holdout: StrictBool
    notes: str = Field(min_length=1, max_length=20_000)


class SkillCorpus(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest: SkillEvalManifest
    cases: tuple[SkillCorpusCase, ...]

    @property
    def case_by_id(self) -> dict[str, SkillCorpusCase]:
        return {case.case_id: case for case in self.cases}


def _validation_reason(exc: ValidationError, *, manifest: bool) -> SkillCorpusLoadReason:
    for error in exc.errors():
        if error.get("type") == "extra_forbidden":
            return "skill_corpus_unknown_key"
        if manifest and "n_reps" in error.get("loc", ()):
            return "skill_corpus_n_reps_invalid"
    return "skill_corpus_manifest_invalid" if manifest else "skill_corpus_case_invalid"


def _reject_nonstandard_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant {value}")


def _load_manifest(path: Path) -> SkillEvalManifest:
    if not path.is_file():
        raise SkillCorpusLoadError("skill_corpus_manifest_missing", str(path))
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise SkillCorpusLoadError("skill_corpus_manifest_unparseable", path.name) from exc
    if payload.get("schema_version") != _SCHEMA_VERSION:
        raise SkillCorpusLoadError(
            "skill_corpus_schema_version_unsupported",
            f"expected {_SCHEMA_VERSION}, got {payload.get('schema_version')!r}",
        )
    try:
        manifest = SkillEvalManifest.model_validate(payload)
    except ValidationError as exc:
        raise SkillCorpusLoadError(_validation_reason(exc, manifest=True), str(exc)) from exc

    if (
        set(manifest.gates.hard_failure_kinds) != {"refusal", "adversarial"}
        or len(manifest.gates.hard_failure_kinds) != 2
    ):
        raise SkillCorpusLoadError(
            "skill_corpus_manifest_invalid", "hard_failure_kinds must be exact"
        )
    if (
        manifest.judge.measured_kappa is not None
        and manifest.judge.measured_kappa < manifest.gates.minimum_judge_kappa
    ):
        raise SkillCorpusLoadError(
            "skill_corpus_judge_calibration_insufficient",
            "measured kappa is below the manifest gate",
        )
    for values, label in (
        (manifest.holdouts.case_ids, "holdouts.case_ids"),
        (
            manifest.performance_conformance.non_gating_case_ids,
            "performance_conformance.non_gating_case_ids",
        ),
    ):
        if len(values) != len(set(values)):
            raise SkillCorpusLoadError("skill_corpus_manifest_invalid", f"duplicate {label}")
    return manifest


def _load_cases(path: Path) -> tuple[SkillCorpusCase, ...]:
    if not path.is_file():
        raise SkillCorpusLoadError("skill_corpus_queries_missing", str(path))
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise SkillCorpusLoadError("skill_corpus_query_unparseable", path.name) from exc
    if not lines:
        raise SkillCorpusLoadError("skill_corpus_no_cases")

    cases: list[SkillCorpusCase] = []
    seen: set[str] = set()
    for line_number, line in enumerate(lines, start=1):
        if not line or len(line.encode("utf-8")) > _MAX_QUERY_LINE_BYTES:
            raise SkillCorpusLoadError("skill_corpus_query_unparseable", f"line {line_number}")
        try:
            payload = json.loads(line, parse_constant=_reject_nonstandard_json_constant)
        except (json.JSONDecodeError, ValueError) as exc:
            raise SkillCorpusLoadError(
                "skill_corpus_query_unparseable", f"line {line_number}"
            ) from exc
        if not isinstance(payload, dict):
            raise SkillCorpusLoadError("skill_corpus_query_unparseable", f"line {line_number}")
        try:
            case = SkillCorpusCase.model_validate(payload)
        except ValidationError as exc:
            raise SkillCorpusLoadError(
                _validation_reason(exc, manifest=False), f"line {line_number}: {exc}"
            ) from exc
        if case.case_id in seen:
            raise SkillCorpusLoadError("skill_corpus_duplicate_case_id", case.case_id)
        seen.add(case.case_id)
        cases.append(case)
    return tuple(cases)


def expected_route(case: SkillCorpusCase, *, skill_id: str) -> bool | None:
    """Return a trigger case's semantic route expectation.

    The three E-S1 corpora were intentionally copied verbatim from their
    reviewed drafts and use three historical encodings. They normalize to one
    strict boolean here; every accepted mapping must have the exact key set.
    """
    if case.kind not in {"trigger_pos", "trigger_neg"}:
        return None
    value = case.expected.value
    if case.expected.mode == "route" and isinstance(value, Mapping):
        key = f"routes_to_{skill_id.replace('-', '_')}"
        route_value = value.get(key)
        if set(value) == {key} and isinstance(route_value, bool):
            return route_value
    if (
        case.expected.mode == "assumption"
        and isinstance(value, Mapping)
        and set(value) == {"skill_triggered"}
    ):
        route_value = value.get("skill_triggered")
        if isinstance(route_value, bool):
            return route_value
    if case.expected.mode == "scalar" and isinstance(value, bool):
        return value
    return None


def _validate_cross_document_contract(
    manifest: SkillEvalManifest, cases: tuple[SkillCorpusCase, ...]
) -> None:
    by_id = {case.case_id: case for case in cases}

    if any(case.expected.verify_live and case.reference_sql is None for case in cases):
        raise SkillCorpusLoadError(
            "skill_corpus_case_invalid", "verify_live requires reference_sql"
        )

    performance_ids = set(manifest.performance_conformance.non_gating_case_ids)
    if any(
        case_id not in by_id
        or by_id[case_id].scoring != "judge"
        or by_id[case_id].kind not in {"golden", "adversarial"}
        for case_id in performance_ids
    ):
        raise SkillCorpusLoadError(
            "skill_corpus_performance_conformance_invalid",
            "non-gating shape cases must be judge-scored answer cases",
        )

    actual_holdouts = {case.case_id for case in cases if case.holdout}
    if (
        actual_holdouts != set(manifest.holdouts.case_ids)
        or not actual_holdouts
        or not any(case.holdout and case.kind == "golden" for case in cases)
    ):
        raise SkillCorpusLoadError("skill_corpus_holdout_mismatch")

    present_kinds = {case.kind for case in cases}
    if not {"golden", "adversarial", "refusal"} <= present_kinds:
        raise SkillCorpusLoadError(
            "skill_corpus_case_balance_invalid",
            "golden, adversarial, and refusal classes are all required",
        )

    positives = 0
    negatives = 0
    for case in cases:
        if case.kind not in {"trigger_pos", "trigger_neg"}:
            continue
        expected = expected_route(case, skill_id=manifest.skill_id)
        required = case.kind == "trigger_pos"
        if expected is None or expected is not required:
            raise SkillCorpusLoadError("skill_corpus_trigger_expectation_invalid", case.case_id)
        positives += int(required)
        negatives += int(not required)
    if (
        positives < manifest.gates.minimum_trigger_positive
        or negatives < manifest.gates.minimum_trigger_negative
    ):
        raise SkillCorpusLoadError(
            "skill_corpus_trigger_balance_invalid",
            f"positive={positives}, negative={negatives}",
        )


def load_skill_corpus(pack_path: Path) -> SkillCorpus:
    """Load a signed skill pack's strict A-007 corpus convention."""
    golden = pack_path / "golden"
    manifest = _load_manifest(golden / "manifest.toml")
    cases = _load_cases(golden / "queries.jsonl")
    _validate_cross_document_contract(manifest, cases)
    return SkillCorpus(manifest=manifest, cases=cases)
