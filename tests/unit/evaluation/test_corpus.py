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
