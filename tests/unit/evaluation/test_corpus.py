# tests/unit/evaluation/test_corpus.py
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from cognic_agentos.evaluation.corpus import (
    CorpusLoadError,
    load_corpus,
    validate_corpus_payload,
)

_GOOD = """\
schema_version: 1
corpus_id: smoke
description: demo
cases:
  - id: c1
    case_kind: completion
    messages:
      - role: system
        content: "Be precise."
      - role: user
        content: "Define CAR."
    assertions:
      contains: ["capital adequacy"]
"""


def _write(tmp_path: Path, name: str, body: str) -> Path:
    (tmp_path / name).write_text(textwrap.dedent(body), encoding="utf-8")
    return tmp_path


def test_loads_valid_corpus(tmp_path: Path) -> None:
    d = _write(tmp_path, "a.yaml", _GOOD)
    corpus = load_corpus(d)
    assert corpus.corpus_id == "smoke"
    assert len(corpus.cases) == 1
    assert corpus.cases[0].assertions is not None
    assert corpus.cases[0].assertions.contains == ["capital adequacy"]


def test_no_documents_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(CorpusLoadError) as e:
        load_corpus(tmp_path)
    assert e.value.reason == "corpus_no_documents"


def test_unknown_key_fails_closed(tmp_path: Path) -> None:
    d = _write(tmp_path, "a.yaml", _GOOD + "    surprise: 1\n")
    with pytest.raises(CorpusLoadError) as e:
        load_corpus(d)
    assert e.value.reason == "corpus_unknown_key"


def test_unsupported_schema_version_fails_closed(tmp_path: Path) -> None:
    d = _write(tmp_path, "a.yaml", _GOOD.replace("schema_version: 1", "schema_version: 2"))
    with pytest.raises(CorpusLoadError) as e:
        load_corpus(d)
    assert e.value.reason == "corpus_schema_version_unsupported"


def test_duplicate_case_id_across_files_fails_closed(tmp_path: Path) -> None:
    _write(tmp_path, "a.yaml", _GOOD)
    _write(tmp_path, "b.yaml", _GOOD.replace("corpus_id: smoke", "corpus_id: smoke2"))
    with pytest.raises(CorpusLoadError) as e:
        load_corpus(tmp_path)
    assert e.value.reason == "corpus_duplicate_case_id"


def test_case_without_scorer_fails_closed(tmp_path: Path) -> None:
    body = _GOOD.replace('    assertions:\n      contains: ["capital adequacy"]\n', "")
    d = _write(tmp_path, "a.yaml", body)
    with pytest.raises(CorpusLoadError) as e:
        load_corpus(d)
    assert e.value.reason == "corpus_case_no_scorer"


def test_unsupported_case_kind_fails_closed(tmp_path: Path) -> None:
    d = _write(tmp_path, "a.yaml", _GOOD.replace("case_kind: completion", "case_kind: replay"))
    with pytest.raises(CorpusLoadError) as e:
        load_corpus(d)
    assert e.value.reason == "corpus_case_kind_unsupported"


def test_unparseable_yaml_fails_closed(tmp_path: Path) -> None:
    d = _write(tmp_path, "a.yaml", "schema_version: 1\n  : : :\n")
    with pytest.raises(CorpusLoadError) as e:
        load_corpus(d)
    assert e.value.reason == "corpus_unparseable_yaml"


def test_validate_corpus_payload_shares_the_model(tmp_path: Path) -> None:
    # Portal path: validate an already-parsed dict against the SAME model.
    payload = {
        "schema_version": 1,
        "corpus_id": "smoke",
        "cases": [
            {
                "id": "c1",
                "case_kind": "completion",
                "messages": [{"role": "user", "content": "hi"}],
                "judge": {
                    "rubric": "is a greeting",
                    "criteria": [{"name": "greeting", "description": "says hello"}],
                },
            }
        ],
    }
    corpus = validate_corpus_payload(payload)
    assert corpus.cases[0].judge is not None
    assert corpus.cases[0].judge.criteria[0].description == "says hello"


def test_assertions_block_with_no_clauses_fails_closed() -> None:
    # Covers AssertionsBlock._at_least_one_clause raise (corpus.py:57) +
    # branch [56,57]. The single value_error has no "messages"/"case_kind" in
    # loc and its msg does not contain "neither assertions nor judge", so the
    # loop in _reason_for_validation_error falls through to the L111 fallback
    # (branches [109,99] back-edge + [99,111] loop-exhausted exit).
    payload = {
        "schema_version": 1,
        "corpus_id": "smoke",
        "cases": [
            {
                "id": "c1",
                "case_kind": "completion",
                "messages": [{"role": "user", "content": "hi"}],
                "assertions": {"contains": []},
            }
        ],
    }
    with pytest.raises(CorpusLoadError) as e:
        validate_corpus_payload(payload)
    # Maps through the fallback (corpus.py:111).
    assert e.value.reason == "corpus_case_messages_invalid"


def test_empty_messages_list_fails_closed() -> None:
    # Covers the "messages" in loc branch (corpus.py:107) + branch [106,107].
    # An empty messages list trips _Message list min_length=1; the resulting
    # "too_short" error carries "messages" in its loc.
    payload = {
        "schema_version": 1,
        "corpus_id": "smoke",
        "cases": [
            {
                "id": "c1",
                "case_kind": "completion",
                "messages": [],
                "assertions": {"contains": ["x"]},
            }
        ],
    }
    with pytest.raises(CorpusLoadError) as e:
        validate_corpus_payload(payload)
    assert e.value.reason == "corpus_case_messages_invalid"


def test_yaml_top_level_list_fails_closed(tmp_path: Path) -> None:
    # Covers the non-mapping raise (corpus.py:146) + branch [145,146]:
    # yaml.safe_load returns a list, so the doc is not a dict.
    d = _write(tmp_path, "a.yaml", "- not\n- a\n- mapping\n")
    with pytest.raises(CorpusLoadError) as e:
        load_corpus(d)
    assert e.value.reason == "corpus_unparseable_yaml"
