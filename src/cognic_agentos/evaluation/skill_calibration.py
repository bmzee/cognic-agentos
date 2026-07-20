"""Human-labelled calibration for the A-007 skill-evaluation judge."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Final, Literal
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from cognic_agentos.evaluation.skill_corpus import SkillCorpus
from cognic_agentos.evaluation.skill_eval import _criterion_description, _routes_to_judge
from cognic_agentos.portal.api.evaluation.dto import JudgeVerdictResponse

CalibrationLabel = Literal["pass", "fail"]
_SCHEMA_VERSION: Final[Literal[1]] = 1
_TRIGGER_KINDS = frozenset({"trigger_pos", "trigger_neg"})


class SkillCalibrationContractError(ValueError):
    """Calibration evidence is incomplete, inconsistent, or unidentifiable."""


class SkillCalibrationItem(BaseModel):
    """One blind human-label item; judge labels live in a separate artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    item_id: str = Field(min_length=1, max_length=200)
    case_id: str = Field(min_length=1, max_length=200)
    question: str = Field(min_length=1, max_length=50_000)
    candidate_output: str = Field(min_length=1, max_length=50_000)
    human_label: CalibrationLabel | None = None


class SkillCalibrationSheet(BaseModel):
    """Pinned candidate set presented to the maintainer without judge labels."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    skill_id: str = Field(min_length=1, max_length=200)
    calibration_set_id: str = Field(min_length=1, max_length=200)
    model_alias: str = Field(min_length=1, max_length=200)
    rubric_ref: str = Field(min_length=1, max_length=200)
    minimum_kappa: float = Field(ge=0.7, le=1.0, strict=True)
    items: tuple[SkillCalibrationItem, ...] = Field(min_length=2)

    @model_validator(mode="after")
    def _unique_items(self) -> SkillCalibrationSheet:
        item_ids = [item.item_id for item in self.items]
        case_ids = [item.case_id for item in self.items]
        if len(item_ids) != len(set(item_ids)):
            raise ValueError("calibration item ids must be unique")
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("calibration case ids must be unique")
        return self


class SkillJudgeCalibrationItem(BaseModel):
    """A value-only judge label kept separate from the blind human sheet."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    item_id: str = Field(min_length=1, max_length=200)
    case_id: str = Field(min_length=1, max_length=200)
    judge_label: CalibrationLabel


class SkillJudgeCalibrationResults(BaseModel):
    """Pinned-model labels for one calibration set."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    skill_id: str = Field(min_length=1, max_length=200)
    calibration_set_id: str = Field(min_length=1, max_length=200)
    model_alias: str = Field(min_length=1, max_length=200)
    items: tuple[SkillJudgeCalibrationItem, ...] = Field(min_length=2)

    @model_validator(mode="after")
    def _unique_items(self) -> SkillJudgeCalibrationResults:
        item_ids = [item.item_id for item in self.items]
        if len(item_ids) != len(set(item_ids)):
            raise ValueError("judge-result item ids must be unique")
        return self


@dataclasses.dataclass(frozen=True, slots=True)
class SkillCalibrationReport:
    skill_id: str
    calibration_set_id: str
    model_alias: str
    sample_count: int
    observed_agreement: float
    measured_kappa: float
    minimum_kappa: float
    passed: bool


def _effective_judge_case_ids(corpus: SkillCorpus) -> set[str]:
    return {
        case.case_id
        for case in corpus.cases
        if case.kind not in _TRIGGER_KINDS and _routes_to_judge(case)
    }


def validate_calibration_sheet(corpus: SkillCorpus, sheet: SkillCalibrationSheet) -> None:
    """Bind a sheet to the exact signed corpus and judge configuration."""
    expected_metadata = (
        corpus.manifest.skill_id,
        corpus.manifest.judge.calibration_set_id,
        corpus.manifest.judge.model_alias,
        corpus.manifest.judge.rubric_ref,
        corpus.manifest.gates.minimum_judge_kappa,
    )
    actual_metadata = (
        sheet.skill_id,
        sheet.calibration_set_id,
        sheet.model_alias,
        sheet.rubric_ref,
        sheet.minimum_kappa,
    )
    if actual_metadata != expected_metadata:
        raise SkillCalibrationContractError("calibration metadata mismatch")
    if {item.case_id for item in sheet.items} != _effective_judge_case_ids(corpus):
        raise SkillCalibrationContractError("calibration case set mismatch")
    for item in sheet.items:
        if item.question != corpus.case_by_id[item.case_id].question:
            raise SkillCalibrationContractError(f"calibration question mismatch: {item.case_id}")


def render_labeling_sheet(corpus: SkillCorpus, sheet: SkillCalibrationSheet) -> str:
    """Render a blind, human-readable labeling sheet with no judge outcomes."""
    validate_calibration_sheet(corpus, sheet)
    lines = [
        f"# A-007 human labeling sheet: {sheet.skill_id}",
        "",
        f"Calibration set: `{sheet.calibration_set_id}`",
        f"Pinned judge: `{sheet.model_alias}`",
        "",
        "Label each candidate independently. Do not inspect the judge-results artifact first.",
    ]
    for item in sheet.items:
        lines.extend(
            (
                "",
                f"## {item.item_id}",
                "",
                f"Case ID: `{item.case_id}`",
                "",
                "Question:",
                "",
                item.question,
                "",
                "Candidate output:",
                "",
                "```text",
                item.candidate_output,
                "```",
                "",
                "Human label: [ ] PASS  [ ] FAIL",
            )
        )
    return "\n".join(lines) + "\n"


def load_calibration_sheet(path: Path) -> SkillCalibrationSheet:
    """Load a strict JSON calibration sheet without accepting non-standard numbers."""
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-standard JSON constant {value}")
            ),
        )
        return SkillCalibrationSheet.model_validate(payload)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, ValidationError) as exc:
        raise SkillCalibrationContractError("calibration sheet is unreadable") from exc


def load_judge_results(path: Path) -> SkillJudgeCalibrationResults:
    """Load strict, value-free judge labels."""
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-standard JSON constant {value}")
            ),
        )
        return SkillJudgeCalibrationResults.model_validate(payload)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, ValidationError) as exc:
        raise SkillCalibrationContractError("judge results are unreadable") from exc


async def run_calibration_judge(
    corpus: SkillCorpus,
    sheet: SkillCalibrationSheet,
    *,
    target_url: str,
    token: str,
    http_client: httpx.AsyncClient | None = None,
) -> SkillJudgeCalibrationResults:
    """Run the pinned governed judge over a blind calibration sheet."""
    validate_calibration_sheet(corpus, sheet)
    if not token:
        raise SkillCalibrationContractError("bearer token is required")
    parsed_target = urlsplit(target_url)
    if (
        parsed_target.scheme not in {"http", "https"}
        or not parsed_target.netloc
        or parsed_target.username is not None
        or parsed_target.password is not None
        or parsed_target.path not in {"", "/"}
        or parsed_target.query
        or parsed_target.fragment
    ):
        raise SkillCalibrationContractError("target URL must be an absolute HTTP(S) origin")

    owned_client = http_client is None
    client = http_client or httpx.AsyncClient(
        timeout=httpx.Timeout(360.0, connect=10.0, write=10.0, pool=10.0),
        follow_redirects=False,
    )
    results: list[SkillJudgeCalibrationItem] = []
    try:
        for item in sheet.items:
            case = corpus.case_by_id[item.case_id]
            shape_case = case.case_id in corpus.manifest.performance_conformance.non_gating_case_ids
            criteria = [
                {
                    "name": "value",
                    "description": _criterion_description(
                        case=case,
                        expected=case.expected.value,
                        rubric_ref=sheet.rubric_ref,
                        shape=False,
                    ),
                }
            ]
            if shape_case:
                criteria.append(
                    {
                        "name": "performance_conformance",
                        "description": _criterion_description(
                            case=case,
                            expected=case.expected.value,
                            rubric_ref=sheet.rubric_ref,
                            shape=True,
                        ),
                    }
                )
            try:
                response = await client.post(
                    f"{target_url.rstrip('/')}/api/v1/eval/judge",
                    headers={"Authorization": f"Bearer {token}"},
                    json={
                        "candidate_output": item.candidate_output,
                        "candidate_input": item.question,
                        "criteria": criteria,
                    },
                    follow_redirects=False,
                )
            except httpx.HTTPError:
                raise SkillCalibrationContractError("judge request failed") from None
            if response.status_code != 200:
                raise SkillCalibrationContractError(
                    f"judge request failed with status {response.status_code}"
                )
            try:
                verdict = JudgeVerdictResponse.model_validate(response.json())
            except (ValueError, ValidationError):
                raise SkillCalibrationContractError("judge response shape invalid") from None
            if verdict.model_alias != sheet.model_alias:
                raise SkillCalibrationContractError("judge model alias drift")
            names = {row["name"] for row in criteria}
            if (
                len(verdict.criteria_results) != len(criteria)
                or {row.name for row in verdict.criteria_results} != names
            ):
                raise SkillCalibrationContractError("judge criteria response mismatch")
            by_name = {row.name: row for row in verdict.criteria_results}
            value_passed = by_name["value"].passed and (shape_case or verdict.verdict == "pass")
            results.append(
                SkillJudgeCalibrationItem(
                    item_id=item.item_id,
                    case_id=item.case_id,
                    judge_label="pass" if value_passed else "fail",
                )
            )
    finally:
        if owned_client:
            await client.aclose()
    return SkillJudgeCalibrationResults(
        schema_version=_SCHEMA_VERSION,
        skill_id=sheet.skill_id,
        calibration_set_id=sheet.calibration_set_id,
        model_alias=sheet.model_alias,
        items=tuple(results),
    )


def compute_calibration_report(
    sheet: SkillCalibrationSheet,
    judge_results: SkillJudgeCalibrationResults,
) -> SkillCalibrationReport:
    """Compute binary Cohen's kappa only from complete human labels."""
    if (
        judge_results.skill_id != sheet.skill_id
        or judge_results.calibration_set_id != sheet.calibration_set_id
        or judge_results.model_alias != sheet.model_alias
    ):
        raise SkillCalibrationContractError("judge-result metadata mismatch")
    by_item = {item.item_id: item for item in judge_results.items}
    if set(by_item) != {item.item_id for item in sheet.items}:
        raise SkillCalibrationContractError("judge-result item set mismatch")

    human_labels: list[CalibrationLabel] = []
    judge_labels: list[CalibrationLabel] = []
    for item in sheet.items:
        if item.human_label is None:
            raise SkillCalibrationContractError("human labels are incomplete")
        result = by_item[item.item_id]
        if result.case_id != item.case_id:
            raise SkillCalibrationContractError("judge-result case mismatch")
        human_labels.append(item.human_label)
        judge_labels.append(result.judge_label)
    if len(set(human_labels)) < 2 or len(set(judge_labels)) < 2:
        raise SkillCalibrationContractError("kappa is unidentifiable for single-class labels")

    sample_count = len(human_labels)
    observed_agreement = (
        sum(human == judge for human, judge in zip(human_labels, judge_labels, strict=True))
        / sample_count
    )
    human_pass_rate = human_labels.count("pass") / sample_count
    judge_pass_rate = judge_labels.count("pass") / sample_count
    expected_agreement = human_pass_rate * judge_pass_rate + (1.0 - human_pass_rate) * (
        1.0 - judge_pass_rate
    )
    if expected_agreement == 1.0:
        raise SkillCalibrationContractError("kappa is unidentifiable")
    measured_kappa = (observed_agreement - expected_agreement) / (1.0 - expected_agreement)
    return SkillCalibrationReport(
        skill_id=sheet.skill_id,
        calibration_set_id=sheet.calibration_set_id,
        model_alias=sheet.model_alias,
        sample_count=sample_count,
        observed_agreement=observed_agreement,
        measured_kappa=measured_kappa,
        minimum_kappa=sheet.minimum_kappa,
        passed=measured_kappa >= sheet.minimum_kappa,
    )
