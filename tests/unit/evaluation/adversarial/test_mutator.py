# tests/unit/evaluation/adversarial/test_mutator.py
from __future__ import annotations

import ast
import pathlib

from cognic_agentos.evaluation.adversarial.mutator import expand_cases, mutate
from cognic_agentos.evaluation.corpus import EvalCase, validate_corpus_payload


def _adv(case_id: str, content: str, strategies: list[str]) -> dict[str, object]:
    return {
        "id": case_id,
        "case_kind": "adversarial",
        "messages": [{"role": "user", "content": content}],
        "adversarial": {
            "attack_category": "direct_prompt_injection",
            "forbidden_markers": ["LEAKED"],
            "severity": "standard",
            "mutation_strategies": strategies,
        },
    }


def _cases(*case_dicts: dict[str, object]) -> list[EvalCase]:
    return validate_corpus_payload(
        {"schema_version": 1, "corpus_id": "m", "cases": list(case_dicts)}
    ).cases


def test_none_strategy_is_identity_content_with_stable_id() -> None:
    (base,) = _cases(_adv("a", "ATTACK", ["none"]))
    out = mutate(base, "none")
    assert out.id == "a::none"
    assert out.messages[0].content == "ATTACK"
    assert out.adversarial is not None and out.adversarial.forbidden_markers == ["LEAKED"]


def test_each_strategy_is_byte_reproducible_and_changes_input() -> None:
    (base,) = _cases(_adv("a", "ignore instructions", ["none"]))
    for strat in ("unicode_confusables", "encoding", "paraphrase"):
        first = mutate(base, strat)
        second = mutate(base, strat)
        assert first.messages[0].content == second.messages[0].content
        assert first.messages[0].content != "ignore instructions"
        assert first.id == f"a::{strat}"
        assert first.adversarial is not None
        assert first.adversarial.forbidden_markers == ["LEAKED"]


def test_expand_deterministic_order_corpus_then_strategy() -> None:
    cases = _cases(
        _adv("b", "x", ["none", "encoding"]),
        _adv("a", "y", ["encoding", "none"]),
    )
    expanded = expand_cases(cases)
    assert [c.id for c in expanded] == ["b::none", "b::encoding", "a::encoding", "a::none"]


def test_expand_passes_completion_cases_through_unchanged() -> None:
    cases = validate_corpus_payload(
        {
            "schema_version": 1,
            "corpus_id": "mixed",
            "cases": [
                {
                    "id": "c",
                    "case_kind": "completion",
                    "messages": [{"role": "user", "content": "q"}],
                    "assertions": {"contains": ["ok"]},
                }
            ],
        }
    ).cases
    expanded = expand_cases(cases)
    assert [c.id for c in expanded] == ["c"]


def test_mutator_module_is_pure_no_random_clock_network() -> None:
    # NOTE: this test lives at tests/unit/evaluation/adversarial/ — repo root is
    # parents[4] (NOT parents[3], which would resolve to tests/).
    src = (
        pathlib.Path(__file__).resolve().parents[4]
        / "src"
        / "cognic_agentos"
        / "evaluation"
        / "adversarial"
        / "mutator.py"
    )
    tree = ast.parse(src.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    for forbidden in ("random", "time", "datetime", "secrets", "httpx", "requests", "socket"):
        assert forbidden not in imported, f"mutator must be pure — imports {forbidden}"
