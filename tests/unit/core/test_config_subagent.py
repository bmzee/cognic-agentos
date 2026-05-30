import pytest
from pydantic import ValidationError

from cognic_agentos.core.config import Settings


def test_subagent_max_recursion_depth_defaults_to_3():
    assert Settings().subagent_max_recursion_depth == 3


def test_subagent_max_recursion_depth_rejects_zero():
    with pytest.raises(ValidationError):
        Settings(subagent_max_recursion_depth=0)
