from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import get_args

import pytest

from cognic_agentos.evaluation.skill_corpus import (
    SkillCorpusLoadError,
    SkillCorpusLoadReason,
    expected_route,
    load_skill_corpus,
)

_FIXTURE = Path("tests/fixtures/skill_eval/valid_pack")
_UNCALIBRATED_FIXTURE = Path("tests/fixtures/skill_eval/uncalibrated_pack")


def _copy_fixture(tmp_path: Path) -> Path:
    pack = tmp_path / "pack"
    shutil.copytree(_FIXTURE, pack)
    return pack


def _replace(path: Path, old: str, new: str) -> None:
    path.write_text(path.read_text(encoding="utf-8").replace(old, new), encoding="utf-8")


def test_loads_strict_skill_corpus_contract() -> None:
    corpus = load_skill_corpus(_FIXTURE)

    assert corpus.manifest.schema_version == 1
    assert corpus.manifest.skill_id == "fixture-data"
    assert corpus.manifest.n_reps == 3
    assert corpus.manifest.judge.measured_kappa == 0.75
    assert corpus.manifest.reference.scope_id == "fixture"
    assert corpus.manifest.performance_conformance.non_gating_case_ids == ("fx-002",)
    assert len(corpus.cases) == 9
    assert corpus.case_by_id["fx-001"].expected.value == 42
    assert expected_route(corpus.case_by_id["fx-301"], skill_id="fixture-data") is True
    assert expected_route(corpus.case_by_id["fx-311"], skill_id="fixture-data") is False


def test_absent_judge_kappa_loads_as_not_yet_calibrated() -> None:
    corpus = load_skill_corpus(_UNCALIBRATED_FIXTURE)

    assert corpus.manifest.judge.measured_kappa is None


@pytest.mark.parametrize(
    ("missing", "reason"),
    [
        ("golden/manifest.toml", "skill_corpus_manifest_missing"),
        ("golden/queries.jsonl", "skill_corpus_queries_missing"),
    ],
)
def test_required_document_missing_refuses(
    tmp_path: Path, missing: str, reason: SkillCorpusLoadReason
) -> None:
    pack = _copy_fixture(tmp_path)
    (pack / missing).unlink()

    with pytest.raises(SkillCorpusLoadError) as exc_info:
        load_skill_corpus(pack)

    assert exc_info.value.reason == reason


def test_unknown_manifest_key_refuses_closed_enum(tmp_path: Path) -> None:
    pack = _copy_fixture(tmp_path)
    manifest = pack / "golden/manifest.toml"
    manifest.write_text(manifest.read_text(encoding="utf-8") + "\nunknown = true\n")

    with pytest.raises(SkillCorpusLoadError) as exc_info:
        load_skill_corpus(pack)

    assert exc_info.value.reason == "skill_corpus_unknown_key"


def test_unparseable_query_line_names_line_but_not_content(tmp_path: Path) -> None:
    pack = _copy_fixture(tmp_path)
    queries = pack / "golden/queries.jsonl"
    queries.write_text("{not-json}\n", encoding="utf-8")

    with pytest.raises(SkillCorpusLoadError) as exc_info:
        load_skill_corpus(pack)

    assert exc_info.value.reason == "skill_corpus_query_unparseable"
    assert "line 1" in exc_info.value.detail
    assert "not-json" not in str(exc_info.value)


def test_duplicate_case_id_refuses(tmp_path: Path) -> None:
    pack = _copy_fixture(tmp_path)
    queries = pack / "golden/queries.jsonl"
    first = queries.read_text(encoding="utf-8").splitlines()[0]
    queries.write_text(queries.read_text(encoding="utf-8") + first + "\n", encoding="utf-8")

    with pytest.raises(SkillCorpusLoadError) as exc_info:
        load_skill_corpus(pack)

    assert exc_info.value.reason == "skill_corpus_duplicate_case_id"


@pytest.mark.parametrize("n_reps", [2, 6, True])
def test_n_reps_is_integer_three_through_five(tmp_path: Path, n_reps: object) -> None:
    pack = _copy_fixture(tmp_path)
    manifest = pack / "golden/manifest.toml"
    replacement = "true" if n_reps is True else str(n_reps)
    _replace(manifest, "n_reps = 3", f"n_reps = {replacement}")

    with pytest.raises(SkillCorpusLoadError) as exc_info:
        load_skill_corpus(pack)

    assert exc_info.value.reason == "skill_corpus_n_reps_invalid"


def test_under_calibrated_judge_refuses(tmp_path: Path) -> None:
    pack = _copy_fixture(tmp_path)
    manifest = pack / "golden/manifest.toml"
    _replace(manifest, "measured_kappa = 0.75", "measured_kappa = 0.69")

    with pytest.raises(SkillCorpusLoadError) as exc_info:
        load_skill_corpus(pack)

    assert exc_info.value.reason == "skill_corpus_judge_calibration_insufficient"


def test_holdout_manifest_and_case_flags_must_match_exactly(tmp_path: Path) -> None:
    pack = _copy_fixture(tmp_path)
    manifest = pack / "golden/manifest.toml"
    _replace(
        manifest,
        '[holdouts]\ncase_ids = ["fx-001"]',
        '[holdouts]\ncase_ids = ["fx-003"]',
    )

    with pytest.raises(SkillCorpusLoadError) as exc_info:
        load_skill_corpus(pack)

    assert exc_info.value.reason == "skill_corpus_holdout_mismatch"


def test_at_least_one_golden_case_must_be_held_out(tmp_path: Path) -> None:
    pack = _copy_fixture(tmp_path)
    queries = pack / "golden/queries.jsonl"
    _replace(queries, '"kind":"golden"', '"kind":"adversarial"')

    with pytest.raises(SkillCorpusLoadError) as exc_info:
        load_skill_corpus(pack)

    assert exc_info.value.reason == "skill_corpus_holdout_mismatch"


def test_performance_conformance_class_is_explicit_and_judge_scored(tmp_path: Path) -> None:
    pack = _copy_fixture(tmp_path)
    queries = pack / "golden/queries.jsonl"
    _replace(queries, '"case_id":"fx-002"', '"case_id":"fx-020"')

    with pytest.raises(SkillCorpusLoadError) as exc_info:
        load_skill_corpus(pack)

    assert exc_info.value.reason == "skill_corpus_performance_conformance_invalid"


def test_trigger_minimum_is_not_vacuous(tmp_path: Path) -> None:
    pack = _copy_fixture(tmp_path)
    queries = pack / "golden/queries.jsonl"
    rows = [json.loads(line) for line in queries.read_text(encoding="utf-8").splitlines()]
    rows = [row for row in rows if row["case_id"] != "fx-303"]
    queries.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    with pytest.raises(SkillCorpusLoadError) as exc_info:
        load_skill_corpus(pack)

    assert exc_info.value.reason == "skill_corpus_trigger_balance_invalid"


def test_hard_and_accuracy_classes_cannot_be_vacuous(tmp_path: Path) -> None:
    pack = _copy_fixture(tmp_path)
    queries = pack / "golden/queries.jsonl"
    _replace(queries, '"kind":"refusal"', '"kind":"golden"')

    with pytest.raises(SkillCorpusLoadError) as exc_info:
        load_skill_corpus(pack)

    assert exc_info.value.reason == "skill_corpus_case_balance_invalid"


def test_trigger_expectation_cannot_disagree_with_case_kind(tmp_path: Path) -> None:
    pack = _copy_fixture(tmp_path)
    queries = pack / "golden/queries.jsonl"
    _replace(queries, '"routes_to_fixture_data":true', '"routes_to_fixture_data":false')

    with pytest.raises(SkillCorpusLoadError) as exc_info:
        load_skill_corpus(pack)

    assert exc_info.value.reason == "skill_corpus_trigger_expectation_invalid"


def test_refusal_vocabulary_is_closed_and_count_pinned() -> None:
    assert get_args(SkillCorpusLoadReason) == (
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
    )
