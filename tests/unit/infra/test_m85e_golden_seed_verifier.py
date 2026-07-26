from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Protocol

import pytest

_REPO = Path(__file__).resolve().parents[3]
_VERIFIER = _REPO / "infra" / "proof-m85c" / "oracle-seed" / "verify_golden_seed.py"


class _Check(Protocol):
    check_id: str
    runs: int


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write_corpus(path: Path, *, second_sql: str | None = None) -> None:
    rows = (
        {
            "case_id": "fx-001",
            "kind": "golden",
            "question": "How many rows were recorded in calendar 2021?",
            "reference_sql": "SELECT COUNT(*) FROM fx.rows",
        },
        {
            "case_id": "fx-201",
            "kind": "refusal",
            "question": "Show private details for Example Product.",
            "reference_sql": second_sql,
        },
    )
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))


def _write_facts(path: Path, *, question_contains: str = "Example Product") -> None:
    payload = {
        "schema_version": 1,
        "checks": [
            {
                "skill_id": "fixture-skill",
                "case_id": "fx-201",
                "kind": "refusal",
                "question_contains": question_contains,
                "sql": "SELECT COUNT(*) FROM fx.products WHERE name = 'Example Product'",
                "expected": ["1"],
            }
        ],
    }
    path.write_text(json.dumps(payload))


def _result_text(
    module: ModuleType, checks: tuple[_Check, ...], values: dict[str, tuple[str, ...]]
) -> str:
    lines: list[str] = []
    for check in checks:
        for run_index in range(1, check.runs + 1):
            lines.append(module.result_marker(check.check_id, run_index, "BEGIN"))
            lines.extend(values[check.check_id])
            lines.append(module.result_marker(check.check_id, run_index, "END"))
    return "\n".join(lines) + "\n"


def test_reference_queries_run_twice_and_fact_checks_cover_non_golden_cases(tmp_path: Path) -> None:
    module = _load(_VERIFIER, "proof_m85e_golden_verifier_happy")
    corpus = tmp_path / "queries.jsonl"
    facts = tmp_path / "facts.json"
    _write_corpus(corpus)
    _write_facts(facts)

    checks = module.load_checks((f"fixture-skill={corpus}",), facts)

    assert [(check.check_id, check.runs) for check in checks] == [
        ("reference:fixture-skill:fx-001", 2),
        ("fact:fixture-skill:fx-201:1", 1),
    ]
    output = _result_text(
        module,
        checks,
        {
            "reference:fixture-skill:fx-001": ("7",),
            "fact:fixture-skill:fx-201:1": ("1",),
        },
    )
    module.verify_results(checks, module.parse_results(output))


@pytest.mark.parametrize(
    ("first", "second", "message"),
    (((), (), "returned no rows"), (("7",), ("8",), "not deterministic")),
)
def test_reference_query_refuses_empty_or_non_deterministic_results(
    tmp_path: Path,
    first: tuple[str, ...],
    second: tuple[str, ...],
    message: str,
) -> None:
    module = _load(_VERIFIER, f"proof_m85e_golden_verifier_{message.replace(' ', '_')}")
    corpus = tmp_path / "queries.jsonl"
    facts = tmp_path / "facts.json"
    _write_corpus(corpus)
    _write_facts(facts)
    checks = module.load_checks((f"fixture-skill={corpus}",), facts)
    reference = checks[0]
    fact = checks[1]
    output = "\n".join(
        (
            module.result_marker(reference.check_id, 1, "BEGIN"),
            *first,
            module.result_marker(reference.check_id, 1, "END"),
            module.result_marker(reference.check_id, 2, "BEGIN"),
            *second,
            module.result_marker(reference.check_id, 2, "END"),
            module.result_marker(fact.check_id, 1, "BEGIN"),
            "1",
            module.result_marker(fact.check_id, 1, "END"),
        )
    )

    with pytest.raises(module.GoldenSeedVerificationError, match=message):
        module.verify_results(checks, module.parse_results(output))


def test_fact_contract_must_match_the_signed_question_text(tmp_path: Path) -> None:
    module = _load(_VERIFIER, "proof_m85e_golden_verifier_question")
    corpus = tmp_path / "queries.jsonl"
    facts = tmp_path / "facts.json"
    _write_corpus(corpus)
    _write_facts(facts, question_contains="Lore Product")

    with pytest.raises(module.GoldenSeedVerificationError, match="question fact drift"):
        module.load_checks((f"fixture-skill={corpus}",), facts)


def test_fact_result_mismatch_refuses(tmp_path: Path) -> None:
    module = _load(_VERIFIER, "proof_m85e_golden_verifier_fact")
    corpus = tmp_path / "queries.jsonl"
    facts = tmp_path / "facts.json"
    _write_corpus(corpus)
    _write_facts(facts)
    checks = module.load_checks((f"fixture-skill={corpus}",), facts)
    output = _result_text(
        module,
        checks,
        {
            "reference:fixture-skill:fx-001": ("7",),
            "fact:fixture-skill:fx-201:1": ("0",),
        },
    )

    with pytest.raises(module.GoldenSeedVerificationError, match="fact mismatch"):
        module.verify_results(checks, module.parse_results(output))
