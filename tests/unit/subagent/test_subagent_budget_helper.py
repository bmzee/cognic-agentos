import pytest

from cognic_agentos.subagent._types import SubAgentBudgetExhausted, SubAgentChildQuotaZero
from cognic_agentos.subagent.policy import compute_spawn_budget


def test_narrows_to_min_of_parent_and_child():
    assert compute_spawn_budget(parent_remaining_budget=500, child_pack_quota=300) == 300
    assert compute_spawn_budget(parent_remaining_budget=200, child_pack_quota=300) == 200


def test_parent_zero_raises_parent_exhausted():
    with pytest.raises(SubAgentBudgetExhausted) as exc:
        compute_spawn_budget(parent_remaining_budget=0, child_pack_quota=300)
    assert exc.value.parent_remaining_budget == 0
    assert exc.value.reason == "subagent_parent_budget_exhausted"


def test_child_quota_zero_raises_distinct_refusal():
    # D3: a zero CHILD quota must not surface as "parent exhausted".
    with pytest.raises(SubAgentChildQuotaZero) as exc:
        compute_spawn_budget(parent_remaining_budget=500, child_pack_quota=0)
    assert exc.value.child_pack_quota == 0
    assert exc.value.reason == "subagent_child_quota_zero"
