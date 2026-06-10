# tests/unit/evaluation/test_scorer_name_vocab.py
from __future__ import annotations

import typing

from cognic_agentos.evaluation.types import ScorerName


def test_scorer_name_closed_vocab_includes_refusal() -> None:
    # ADR-011 Sprint-13b: RefusalScorer returns scorer="refusal"; the wire-public
    # scorer-name set must carry exactly these three values.
    assert set(typing.get_args(ScorerName)) == {"assertions", "judge", "refusal"}
