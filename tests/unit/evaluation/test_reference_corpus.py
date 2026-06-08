# tests/unit/evaluation/test_reference_corpus.py
from __future__ import annotations

from pathlib import Path

import cognic_agentos.evaluation as evalpkg
from cognic_agentos.evaluation.corpus import load_corpus


def test_reference_corpus_loads_strictly() -> None:
    corpus_dir = Path(evalpkg.__file__).parent / "corpora" / "example"
    corpus = load_corpus(corpus_dir)
    assert corpus.corpus_id == "generic-completion-smoke"
    assert len(corpus.cases) >= 2
    # demonstrates BOTH scorer kinds across the corpus
    assert any(c.assertions is not None for c in corpus.cases)
    assert any(c.judge is not None for c in corpus.cases)
