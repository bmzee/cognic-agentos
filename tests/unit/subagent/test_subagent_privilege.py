import pytest

from cognic_agentos.subagent._types import SubAgentPrivilegeEscalation
from cognic_agentos.subagent.policy import narrow_tool_allow_list


def test_subset_request_is_granted_unchanged():
    parent = frozenset({"search", "read", "summarize"})
    requested = frozenset({"search", "read"})
    assert narrow_tool_allow_list(parent=parent, requested=requested) == requested


def test_equal_request_is_granted():
    s = frozenset({"search"})
    assert narrow_tool_allow_list(parent=s, requested=s) == s


def test_extra_tool_raises_privilege_escalation():
    parent = frozenset({"search"})
    requested = frozenset({"search", "wire_transfer"})
    with pytest.raises(SubAgentPrivilegeEscalation) as exc:
        narrow_tool_allow_list(parent=parent, requested=requested)
    assert exc.value.extra_tools == frozenset({"wire_transfer"})
    assert exc.value.reason == "subagent_privilege_escalation"
