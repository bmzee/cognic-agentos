# tests/unit/evaluation/adversarial/test_bundled_corpus.py
from __future__ import annotations

import pathlib

import yaml

from cognic_agentos.evaluation.adversarial.mutator import expand_cases
from cognic_agentos.evaluation.adversarial.templates import RUNNABLE_TEMPLATES
from cognic_agentos.evaluation.corpus import _RUNNABLE_CATEGORIES, load_corpus


def _corpus_path() -> pathlib.Path:
    # tests/unit/evaluation/adversarial/ → repo root is parents[4] (NOT parents[3]).
    return (
        pathlib.Path(__file__).resolve().parents[4]
        / "src"
        / "cognic_agentos"
        / "evaluation"
        / "corpora"
        / "adversarial"
        / "runnable.yaml"
    )


def test_bundled_runnable_corpus_loads_and_only_runnable_categories() -> None:
    corpus = load_corpus(_corpus_path().parent)  # load_corpus takes a directory
    assert len(corpus.cases) >= 12
    blocks = []
    for case in corpus.cases:
        assert case.case_kind == "adversarial"
        assert case.adversarial is not None  # narrows for the append + later asserts
        assert case.adversarial.attack_category in _RUNNABLE_CATEGORIES
        blocks.append(case.adversarial)
    # Pin the full T10 contract — a future edit must not collapse the reference
    # corpus to a single category, and every base case must declare >=2 strategies
    # so expansion is meaningful for ALL cases (not just on average).
    assert {b.attack_category for b in blocks} == _RUNNABLE_CATEGORIES
    assert all(len(b.mutation_strategies) >= 2 for b in blocks)


def test_bundled_corpus_expands_within_message_bounds() -> None:
    corpus = load_corpus(_corpus_path().parent)
    expanded = expand_cases(list(corpus.cases))
    assert len(expanded) > len(corpus.cases)  # mutations expand the set
    for case in expanded:  # _Message.content max_length=50_000
        assert all(len(m.content) <= 50_000 for m in case.messages)


def test_bundled_corpus_matches_templates_module() -> None:
    # Test-only drift pin: the authored YAML is the source-of-truth and
    # templates.py exposes the SAME cases programmatically (for tests / future
    # generation). Raw-dict equality — divergence in either direction fails.
    doc = yaml.safe_load(_corpus_path().read_text(encoding="utf-8"))
    assert doc["cases"] == RUNNABLE_TEMPLATES
