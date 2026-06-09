# tests/unit/portal/rbac/test_eval_replay_scope.py
from __future__ import annotations

import typing

from cognic_agentos.portal.rbac.scopes import EVAL_SCOPES, EvalRBACScope


def test_eval_scopes_include_replay_run() -> None:
    expected = {"eval.judge.run", "eval.bulk.run", "eval.runs.read", "eval.replay.run"}
    assert set(typing.get_args(EvalRBACScope)) == expected
    assert frozenset(expected) == EVAL_SCOPES
