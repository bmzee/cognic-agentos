from __future__ import annotations

import typing

from cognic_agentos.portal.rbac.scopes import TOOL_APPROVAL_SCOPES, ToolApprovalRBACScope

_EXPECTED = {
    "tool.approve.customer_data",
    "tool.approve.customer_data_write",
    "tool.approve.payment",
    "tool.approve.regulator",
    "tool.approve.cross_tenant",
    "tool.approve.high_risk_custom",
    "tool.approve.observe",
}


def test_seven_tool_approve_scopes() -> None:
    assert set(typing.get_args(ToolApprovalRBACScope)) == _EXPECTED


def test_tool_approval_frozenset_matches_literal() -> None:
    # 1:1 with the Literal (mirrors EMERGENCY_SCOPES doctrine).
    assert frozenset(typing.get_args(ToolApprovalRBACScope)) == TOOL_APPROVAL_SCOPES
