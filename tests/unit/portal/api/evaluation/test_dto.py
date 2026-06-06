from __future__ import annotations

import pytest
from pydantic import ValidationError

from cognic_agentos.portal.api.evaluation.dto import (
    _MAX_CANDIDATE_CHARS,
    JudgeCriterion,
    JudgeRequest,
)


def _crit(name: str = "accuracy") -> dict[str, str]:
    return {"name": name, "description": "is it accurate"}


def test_valid_request() -> None:
    r = JudgeRequest(candidate_output="hi", criteria=[JudgeCriterion(**_crit())])
    assert r.candidate_input is None and len(r.criteria) == 1


def test_empty_output_rejected() -> None:
    with pytest.raises(ValidationError):
        JudgeRequest(candidate_output="", criteria=[JudgeCriterion(**_crit())])


def test_zero_criteria_rejected() -> None:
    with pytest.raises(ValidationError):
        JudgeRequest(candidate_output="hi", criteria=[])


def test_duplicate_criterion_names_rejected() -> None:
    with pytest.raises(ValidationError):
        JudgeRequest(
            candidate_output="hi",
            criteria=[JudgeCriterion(**_crit("a")), JudgeCriterion(**_crit("a"))],
        )


def test_overlong_output_rejected() -> None:
    with pytest.raises(ValidationError):
        JudgeRequest(
            candidate_output="x" * (_MAX_CANDIDATE_CHARS + 1), criteria=[JudgeCriterion(**_crit())]
        )


def test_empty_criterion_description_rejected() -> None:
    with pytest.raises(ValidationError):
        JudgeRequest(candidate_output="hi", criteria=[JudgeCriterion(name="a", description="")])
