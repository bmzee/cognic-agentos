# tests/integration/pack_loop/test_corpus_search.py
"""Proof 1a Task 2 — deterministic substring/keyword search over the bundled corpus."""

import importlib.util

import pytest

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("cognic_tool_search") is None,
    reason="cognic-tool-search not installed; run `uv pip install -e examples/cognic-tool-search`",
)


def test_search_is_deterministic_and_matches_keyword() -> None:
    from cognic_tool_search.corpus_loader import load_corpus, search

    corpus = load_corpus()
    assert len(corpus) >= 3  # a small static set

    hits = search(corpus, "retention")
    # deterministic: same input → identical ordered output
    assert hits == search(corpus, "retention")
    assert hits, "expected at least one doc mentioning 'retention'"
    assert all({"doc_id", "title", "snippet"} <= set(h) for h in hits)
    assert any("retention" in h["snippet"].lower() for h in hits)


def test_search_empty_query_returns_empty() -> None:
    from cognic_tool_search.corpus_loader import load_corpus, search

    assert search(load_corpus(), "   ") == []


def test_search_no_match_returns_empty() -> None:
    from cognic_tool_search.corpus_loader import load_corpus, search

    assert search(load_corpus(), "zzz-no-such-term-zzz") == []
