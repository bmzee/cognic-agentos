"""Closed-enum drift detectors per [[feedback_drift_detector_test_only_no_runtime_import]].

These tests are the SINGLE pinning surface for the scheduler-side
closed-enum vocabularies. They do NOT live in production code — the
production module defines its own Literals; this test module independently
asserts the value sets match the spec §4.2 contract.
"""

from typing import get_args

from cognic_agentos.core.scheduler import (
    ActorType,
    SchedulerAdmissionOutcome,
    SchedulerPriorityClass,
    SchedulerRefusalReason,
    SchedulerTaskCancelledReason,
    SchedulerTaskFailedReason,
    SchedulerTaskPreemptedReason,
    SchedulerTaskState,
)


class TestSchedulerAdmissionOutcomeVocabulary:
    def test_exactly_seven_values(self):
        assert len(get_args(SchedulerAdmissionOutcome)) == 7

    def test_accepted_values(self):
        accepted = {v for v in get_args(SchedulerAdmissionOutcome) if v.startswith("accepted_")}
        assert accepted == {"accepted_immediate", "accepted_queued"}

    def test_refused_values(self):
        refused = {v for v in get_args(SchedulerAdmissionOutcome) if v.startswith("refused_")}
        assert refused == {
            "refused_queue_full",
            "refused_quota_exhausted",
            "refused_policy_denied",
            "refused_kill_switch_active",
            "refused_pack_not_installed",
        }


class TestSchedulerRefusalReasonIsAdmissionSubset:
    """SchedulerRefusalReason is wire-equal to the 5-value refused subset
    of SchedulerAdmissionOutcome. Drift between the two = wire-protocol
    regression."""

    def test_refusal_reason_equals_refused_admission_subset(self):
        admission_refused = {
            v for v in get_args(SchedulerAdmissionOutcome) if v.startswith("refused_")
        }
        refusal_reason = set(get_args(SchedulerRefusalReason))
        assert admission_refused == refusal_reason


class TestSchedulerTaskStateVocabulary:
    def test_exactly_seven_states(self):
        assert set(get_args(SchedulerTaskState)) == {
            "pending",
            "running",
            "completed",
            "failed",
            "cancelled",
            "preempted",
            "expired",
        }


class TestTaskCancelledReasonVocabulary:
    """Per spec §4.6 + locked correction: quota_exhausted moved to
    preempted (resource-driven); cancelled is intent-driven only."""

    def test_exactly_four_values(self):
        assert set(get_args(SchedulerTaskCancelledReason)) == {
            "actor_cancelled",
            "parent_run_cancelled",
            "tenant_admin_cancelled",
            "sandbox_boundary_killed",
        }

    def test_quota_exhausted_NOT_in_cancelled(self):
        """Per locked Section 1 correction #2."""
        assert "quota_exhausted_in_flight" not in get_args(SchedulerTaskCancelledReason)


class TestTaskPreemptedReasonVocabulary:
    def test_wave1_exactly_one_value(self):
        """Wave-1 only trigger per ADR-022 §4.4."""
        assert set(get_args(SchedulerTaskPreemptedReason)) == {"quota_exhausted_in_flight"}


class TestTaskFailedReasonVocabulary:
    """Scheduler-side failure reason; carries upstream sandbox_refusal_reason
    in payload for cross-layer correlation per spec §4.2. Per reviewer-round
    P2 finding: pin EXACT set (not inclusion-only) so an accidental
    Wave-1 third value trips the detector."""

    def test_exactly_two_values(self):
        assert set(get_args(SchedulerTaskFailedReason)) == {
            "scheduler_task_failed_sandbox_create_refused",
            "scheduler_task_failed_workload_runtime_error",
        }


class TestSchedulerPriorityClassVocabulary:
    """Wave-1 2-value class taxonomy per spec §4.1. Wave-2 (deferred) adds
    weighted fair-share + arbitrary-N operator-defined classes; Wave-1
    Literal MUST stay exactly at these two values."""

    def test_exactly_two_values(self):
        assert set(get_args(SchedulerPriorityClass)) == {"interactive", "background"}


class TestActorTypeVocabulary:
    """Identity boundary per AGENTS.md Human-only-decisions doctrine +
    Sprint 7B.2 actor_type 2-value Literal. Reused here for TaskActor.actor_type."""

    def test_exactly_two_values(self):
        assert set(get_args(ActorType)) == {"human", "service"}
