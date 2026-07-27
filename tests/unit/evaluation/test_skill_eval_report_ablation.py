"""Report-only evidence for the existing skill-eval ablation decision."""

from __future__ import annotations

import dataclasses
from pathlib import Path

from cognic_agentos.evaluation.skill_corpus import SkillCorpus, load_skill_corpus
from cognic_agentos.evaluation.skill_eval import (
    SkillCaseVerdict,
    SkillEvalVariant,
    SkillGateReport,
    compute_skill_gate,
    skill_gate_report_payload,
)

_FIXTURE = Path("tests/fixtures/skill_eval/valid_pack")
_ADDITIVE_KEYS = {
    "ablation_without_skill_total",
    "ablation_without_skill_passed",
    "ablation_without_skill_errored",
}
_PRIOR_PAYLOAD_KEYS = {
    "skill_id",
    "corpus_case_count",
    "n_reps",
    "judge_model_alias",
    "judge_calibration_set_id",
    "measured_judge_kappa",
    "minimum_judge_kappa",
    "holdout_case_ids",
    "passed",
    "hard_zero_observed",
    "trigger_accuracy",
    "trigger_passed",
    "accuracy",
    "wrong_answer_rate",
    "golden_accuracy",
    "golden_all_correct",
    "golden_failure_case_ids",
    "ablation_uplift",
    "ablation_passed",
    "performance_conformance",
    "class_metrics",
    "failure_case_ids",
}


def _corpus(*, ablation_enabled: bool = True) -> SkillCorpus:
    corpus = load_skill_corpus(_FIXTURE)
    if ablation_enabled:
        return corpus
    manifest = corpus.manifest.model_copy(
        update={
            "ablation": corpus.manifest.ablation.model_copy(update={"enabled": False}),
        }
    )
    return corpus.model_copy(update={"manifest": manifest})


def _verdicts(corpus: SkillCorpus) -> list[SkillCaseVerdict]:
    variants: tuple[SkillEvalVariant, ...] = (
        ("with_skill", "without_skill") if corpus.manifest.ablation.enabled else ("with_skill",)
    )
    return [
        SkillCaseVerdict(
            case_id=case.case_id,
            kind=case.kind,
            repetition=repetition,
            variant=variant,
            passed=variant == "with_skill",
            errored=False,
        )
        for variant in variants
        for repetition in range(1, corpus.manifest.n_reps + 1)
        for case in corpus.cases
    ]


def _without_non_trigger(verdict: SkillCaseVerdict) -> bool:
    return verdict.variant == "without_skill" and verdict.kind not in {
        "trigger_pos",
        "trigger_neg",
    }


def test_enabled_ablation_counts_match_the_exact_variant_matrix() -> None:
    corpus = _corpus()
    verdicts = _verdicts(corpus)
    changed = 0
    for index, verdict in enumerate(verdicts):
        if _without_non_trigger(verdict) and changed < 2:
            verdicts[index] = dataclasses.replace(verdict, passed=True)
            changed += 1

    report = compute_skill_gate(corpus, verdicts)

    assert changed == 2
    assert report.ablation_without_skill_total == 9
    assert report.ablation_without_skill_passed == 2
    assert report.ablation_without_skill_errored == 0
    assert report.ablation_uplift == 1.0 - (2 / 9)
    assert report.ablation_passed is True
    assert report.passed is True


def test_without_skill_error_is_reported_without_changing_the_existing_decision() -> None:
    corpus = _corpus()
    verdicts = _verdicts(corpus)
    target = next(index for index, verdict in enumerate(verdicts) if _without_non_trigger(verdict))
    verdicts[target] = dataclasses.replace(verdicts[target], errored=True)

    report = compute_skill_gate(corpus, verdicts)

    assert report.ablation_without_skill_total == 9
    assert report.ablation_without_skill_passed == 0
    assert report.ablation_without_skill_errored == 1
    assert report.ablation_uplift == 1.0
    assert report.ablation_passed is False
    assert report.passed is False


def test_disabled_ablation_emits_the_exact_empty_population() -> None:
    corpus = _corpus(ablation_enabled=False)

    report = compute_skill_gate(corpus, _verdicts(corpus))

    assert report.ablation_without_skill_total == 0
    assert report.ablation_without_skill_passed == 0
    assert report.ablation_without_skill_errored == 0
    assert report.ablation_uplift == 0.0
    assert report.ablation_passed is True
    assert report.passed is True


def test_payload_extension_is_exactly_three_additive_count_fields() -> None:
    report = compute_skill_gate(_corpus(), _verdicts(_corpus()))

    payload = skill_gate_report_payload(report)

    assert set(payload) == _PRIOR_PAYLOAD_KEYS | _ADDITIVE_KEYS
    assert {key: payload[key] for key in _ADDITIVE_KEYS} == {
        "ablation_without_skill_total": 9,
        "ablation_without_skill_passed": 0,
        "ablation_without_skill_errored": 0,
    }


def test_python_report_construction_keeps_additive_tail_defaults() -> None:
    fields = {field.name: field for field in dataclasses.fields(SkillGateReport)}

    assert fields["ablation_without_skill_total"].default == 0
    assert fields["ablation_without_skill_passed"].default == 0
    assert fields["ablation_without_skill_errored"].default == 0
