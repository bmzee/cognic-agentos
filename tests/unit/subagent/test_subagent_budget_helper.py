import pytest

from cognic_agentos.subagent._types import SubAgentBudgetExhausted
from cognic_agentos.subagent.policy import compute_spawn_budget


def test_narrows_to_min_of_parent_and_child():
    assert compute_spawn_budget(parent_remaining_budget=500, child_pack_quota=300) == 300
    assert compute_spawn_budget(parent_remaining_budget=200, child_pack_quota=300) == 200


def test_raises_when_narrowed_budget_is_zero():
    with pytest.raises(SubAgentBudgetExhausted) as exc:
        compute_spawn_budget(parent_remaining_budget=0, child_pack_quota=300)
    assert exc.value.parent_remaining_budget == 0
    assert exc.value.reason == "subagent_parent_budget_exhausted"
