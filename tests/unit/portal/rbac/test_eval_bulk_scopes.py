from __future__ import annotations

import typing

from cognic_agentos.portal.rbac.scopes import EVAL_SCOPES, EvalRBACScope


def test_eval_scopes_include_bulk_and_runs_read() -> None:
    values = set(typing.get_args(EvalRBACScope))
    assert values == {"eval.judge.run", "eval.bulk.run", "eval.runs.read"}
    assert frozenset({"eval.judge.run", "eval.bulk.run", "eval.runs.read"}) == EVAL_SCOPES
