import pytest

from cognic_agentos.subagent._types import SubAgentDepthExceeded
from cognic_agentos.subagent.policy import check_depth


@pytest.mark.parametrize("current_depth", [0, 1, 2])
def test_depth_below_cap_is_allowed(current_depth):
    check_depth(current_depth=current_depth, max_depth=3)  # no raise


def test_depth_4_spawn_beyond_max_3_raises():
    with pytest.raises(SubAgentDepthExceeded) as exc:
        check_depth(current_depth=3, max_depth=3)
    assert exc.value.current_depth == 3
    assert exc.value.max_depth == 3
    assert exc.value.reason == "subagent_depth_exceeded"
