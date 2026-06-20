"""Closed-enum drift detectors for the sub-agent vocabulary
(per [[feedback_drift_detector_test_only_no_runtime_import]]). Single
pinning surface; production declares its own Literals, this asserts the sets."""

from typing import get_args

from cognic_agentos.subagent._types import (
    SUBAGENT_ISO_CONTROLS,
    SubAgentAuditEvent,
    SubAgentRefusalReason,
)
from cognic_agentos.subagent.audit import ReturnOutcome


class TestSubAgentRefusalReasonVocabulary:
    def test_exactly_four_values(self):
        assert len(get_args(SubAgentRefusalReason)) == 4

    def test_value_set(self):
        assert set(get_args(SubAgentRefusalReason)) == {
            "subagent_depth_exceeded",
            "subagent_privilege_escalation",
            "subagent_parent_budget_exhausted",
            "subagent_child_quota_zero",
        }


class TestSubAgentAuditEventVocabulary:
    def test_exactly_four_values_in_adr005_order(self):
        assert get_args(SubAgentAuditEvent) == (
            "subagent.spawn",
            "subagent.start",
            "subagent.return",
            "subagent.budget",
        )


class TestSubAgentIsoControls:
    def test_a_6_2_5(self):
        assert SUBAGENT_ISO_CONTROLS == ("A.6.2.5",)


class TestReturnOutcomeVocabulary:
    def test_exactly_three_values_incl_pending_approval(self):
        assert set(get_args(ReturnOutcome)) == {"completed", "failed", "pending_approval"}
