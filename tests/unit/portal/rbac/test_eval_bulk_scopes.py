from __future__ import annotations

import typing

from cognic_agentos.portal.rbac.scopes import EVAL_SCOPES, EvalRBACScope


def test_eval_scopes_include_bulk_and_runs_read() -> None:
    # Sprint 13b added eval.adversarial.run (4 → 5); the exact-set pin advances with it.
    expected = {
        "eval.judge.run",
        "eval.bulk.run",
        "eval.runs.read",
        "eval.replay.run",
        "eval.adversarial.run",
    }
    values = set(typing.get_args(EvalRBACScope))
    assert values == expected
    assert frozenset(expected) == EVAL_SCOPES
