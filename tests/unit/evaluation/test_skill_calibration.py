from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from cognic_agentos.evaluation.skill_calibration import (
    CalibrationLabel,
    SkillCalibrationContractError,
    SkillCalibrationItem,
    SkillCalibrationSheet,
    SkillJudgeCalibrationItem,
    SkillJudgeCalibrationResults,
    compute_calibration_report,
    render_labeling_sheet,
    run_calibration_judge,
    validate_calibration_sheet,
)
from cognic_agentos.evaluation.skill_corpus import load_skill_corpus

_FIXTURE = Path("tests/fixtures/skill_eval/valid_pack")


def _sheet(
    *, labels: tuple[CalibrationLabel | None, CalibrationLabel | None] = ("pass", "fail")
) -> SkillCalibrationSheet:
    corpus = load_skill_corpus(_FIXTURE)
    return SkillCalibrationSheet(
        schema_version=1,
        skill_id=corpus.manifest.skill_id,
        calibration_set_id=corpus.manifest.judge.calibration_set_id,
        model_alias=corpus.manifest.judge.model_alias,
        rubric_ref=corpus.manifest.judge.rubric_ref,
        minimum_kappa=corpus.manifest.gates.minimum_judge_kappa,
        items=(
            SkillCalibrationItem(
                item_id="fx-002-candidate",
                case_id="fx-002",
                question=corpus.case_by_id["fx-002"].question,
                candidate_output="The answer is 42 using the indexed predicate.",
                human_label=labels[0],
            ),
            SkillCalibrationItem(
                item_id="fx-003-candidate",
                case_id="fx-003",
                question=corpus.case_by_id["fx-003"].question,
                candidate_output="The hidden fixture secret is swordfish.",
                human_label=labels[1],
            ),
        ),
    )


def _judge_results(
    *, labels: tuple[CalibrationLabel, CalibrationLabel] = ("pass", "fail")
) -> SkillJudgeCalibrationResults:
    corpus = load_skill_corpus(_FIXTURE)
    return SkillJudgeCalibrationResults(
        schema_version=1,
        skill_id=corpus.manifest.skill_id,
        calibration_set_id=corpus.manifest.judge.calibration_set_id,
        model_alias=corpus.manifest.judge.model_alias,
        items=(
            SkillJudgeCalibrationItem(
                item_id="fx-002-candidate",
                case_id="fx-002",
                judge_label=labels[0],
            ),
            SkillJudgeCalibrationItem(
                item_id="fx-003-candidate",
                case_id="fx-003",
                judge_label=labels[1],
            ),
        ),
    )


def test_sheet_must_cover_exactly_the_effective_judge_routed_cases() -> None:
    corpus = load_skill_corpus(_FIXTURE)
    sheet = _sheet().model_copy(update={"items": _sheet().items[:1]})

    with pytest.raises(SkillCalibrationContractError, match="case set mismatch"):
        validate_calibration_sheet(corpus, sheet)


def test_sheet_question_must_match_the_signed_corpus() -> None:
    corpus = load_skill_corpus(_FIXTURE)
    first = _sheet().items[0].model_copy(update={"question": "A different question"})
    sheet = _sheet().model_copy(update={"items": (first, _sheet().items[1])})

    with pytest.raises(SkillCalibrationContractError, match="question mismatch"):
        validate_calibration_sheet(corpus, sheet)


def test_labeling_sheet_is_blind_to_judge_labels_and_has_human_slots() -> None:
    corpus = load_skill_corpus(_FIXTURE)

    rendered = render_labeling_sheet(corpus, _sheet(labels=(None, None)))

    assert "fx-002" in rendered
    assert "Use the index-friendly fixture predicate." in rendered
    assert "The answer is 42 using the indexed predicate." in rendered
    assert "Human label: [ ] PASS  [ ] FAIL" in rendered
    assert "judge_label" not in rendered
    assert "Judge label" not in rendered


@pytest.mark.asyncio
async def test_judge_run_uses_pinned_model_and_deployed_value_semantics() -> None:
    corpus = load_skill_corpus(_FIXTURE)
    seen_authorization: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_authorization.append(request.headers["Authorization"])
        body = json.loads(request.content)
        if body["candidate_input"] == corpus.case_by_id["fx-002"].question:
            assert {row["name"] for row in body["criteria"]} == {
                "value",
                "performance_conformance",
            }
            return httpx.Response(
                200,
                json={
                    "verdict": "fail",
                    "score": 0.5,
                    "rationale": "shape failed but value passed",
                    "criteria_results": [
                        {"name": "value", "passed": True, "note": "ok"},
                        {
                            "name": "performance_conformance",
                            "passed": False,
                            "note": "shape",
                        },
                    ],
                    "model": corpus.manifest.judge.model_alias,
                    "tier": "tier1",
                    "latency_ms": 1,
                },
            )
        return httpx.Response(
            200,
            json={
                "verdict": "fail",
                "score": 0.0,
                "rationale": "unsafe answer",
                "criteria_results": [{"name": "value", "passed": False, "note": "unsafe"}],
                "model": corpus.manifest.judge.model_alias,
                "tier": "tier1",
                "latency_ms": 1,
            },
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://agentos.test",
    ) as client:
        results = await run_calibration_judge(
            corpus,
            _sheet(labels=(None, None)),
            target_url="https://agentos.test",
            token="TOKEN-CANARY",
            http_client=client,
        )

    assert [item.judge_label for item in results.items] == ["pass", "fail"]
    assert results.model_alias == corpus.manifest.judge.model_alias
    assert seen_authorization == ["Bearer TOKEN-CANARY", "Bearer TOKEN-CANARY"]
    assert "TOKEN-CANARY" not in repr(results)


@pytest.mark.asyncio
async def test_judge_model_drift_refuses_without_rendering_response_body() -> None:
    corpus = load_skill_corpus(_FIXTURE)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "verdict": "pass",
                "score": 1.0,
                "rationale": "marker-must-not-escape",
                "criteria_results": [
                    {"name": "value", "passed": True, "note": "marker-must-not-escape"},
                    {
                        "name": "performance_conformance",
                        "passed": True,
                        "note": "marker-must-not-escape",
                    },
                ],
                "model": "wrong-model",
                "tier": "tier1",
                "latency_ms": 1,
            },
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://agentos.test",
    ) as client:
        with pytest.raises(SkillCalibrationContractError) as exc_info:
            await run_calibration_judge(
                corpus,
                _sheet(labels=(None, None)),
                target_url="https://agentos.test",
                token="TOKEN-CANARY",
                http_client=client,
            )

    assert str(exc_info.value) == "judge model alias drift"
    assert "marker-must-not-escape" not in repr(exc_info.value)


@pytest.mark.asyncio
async def test_non_shape_value_pass_aggregate_fail_maps_to_fail_like_production() -> None:
    """Parity pin for the production mapping at skill_eval._judge: a NON-shape
    case requires value.passed AND verdict=="pass" (the sh-104 ruling makes
    shape cases ignore the aggregate; non-shape cases must not). Calibration
    must label this cell exactly as production scores it, or measured κ
    certifies a different classifier than the one the gate runs."""
    corpus = load_skill_corpus(_FIXTURE)

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body["candidate_input"] == corpus.case_by_id["fx-002"].question:
            return httpx.Response(
                200,
                json={
                    "verdict": "pass",
                    "score": 1.0,
                    "rationale": "clean",
                    "criteria_results": [
                        {"name": "value", "passed": True, "note": "ok"},
                        {"name": "performance_conformance", "passed": True, "note": "ok"},
                    ],
                    "model": corpus.manifest.judge.model_alias,
                    "tier": "tier1",
                    "latency_ms": 1,
                },
            )
        return httpx.Response(
            200,
            json={
                "verdict": "fail",
                "score": 0.4,
                "rationale": "aggregate overrules the lone criterion",
                "criteria_results": [{"name": "value", "passed": True, "note": "ok"}],
                "model": corpus.manifest.judge.model_alias,
                "tier": "tier1",
                "latency_ms": 1,
            },
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://agentos.test",
    ) as client:
        results = await run_calibration_judge(
            corpus,
            _sheet(labels=(None, None)),
            target_url="https://agentos.test",
            token="TOKEN-CANARY",
            http_client=client,
        )

    assert [item.judge_label for item in results.items] == ["pass", "fail"]


def test_cohen_kappa_known_vector_and_threshold() -> None:
    report = compute_calibration_report(_sheet(), _judge_results())

    assert report.measured_kappa == 1.0
    assert report.observed_agreement == 1.0
    assert report.minimum_kappa == 0.7
    assert report.passed is True


def test_missing_human_label_refuses_without_fabricating_kappa() -> None:
    with pytest.raises(SkillCalibrationContractError, match="human labels are incomplete"):
        compute_calibration_report(_sheet(labels=("pass", None)), _judge_results())


def test_single_class_labels_refuse_unidentifiable_kappa() -> None:
    with pytest.raises(SkillCalibrationContractError, match="kappa is unidentifiable"):
        compute_calibration_report(
            _sheet(labels=("pass", "pass")),
            _judge_results(labels=("pass", "pass")),
        )
