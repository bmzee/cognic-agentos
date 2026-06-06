from __future__ import annotations

import typing

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.scopes import EVAL_SCOPES, EvalRBACScope


def test_eval_scope_family_has_exactly_one_value() -> None:
    assert set(typing.get_args(EvalRBACScope)) == {"eval.judge.run"}
    assert frozenset({"eval.judge.run"}) == EVAL_SCOPES


def test_actor_accepts_eval_scope() -> None:
    a = Actor(
        subject="svc",
        tenant_id="t1",
        scopes=frozenset({"eval.judge.run"}),
        actor_type="service",
    )
    assert "eval.judge.run" in a.scopes
