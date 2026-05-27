"""Spec §4.4 state machine — pure-functional validator pattern mirrors
packs/lifecycle.validate_transition. Pinning ALL legal transitions
including the two new ones (pending → failed, pending → cancelled)."""

import pytest

from cognic_agentos.core.scheduler import (
    SchedulerTransitionRefused,
    validate_transition,
)


class TestLegalTransitions:
    """Spec §4.4 amended state machine — 8 legal transitions (4 pending + 4 running)."""

    @pytest.mark.parametrize(
        "from_state,to_state",
        [
            ("pending", "running"),  # capacity opens + create succeeds
            ("pending", "failed"),  # NEW: create/projection failure
            ("pending", "cancelled"),  # NEW: cancel during create
            ("pending", "expired"),  # queue TTL exceeded
            ("running", "completed"),  # normal completion
            ("running", "failed"),  # workload runtime error
            ("running", "cancelled"),  # cooperative cancel
            ("running", "preempted"),  # quota exhausted in-flight
        ],
    )
    def test_legal_transition_returns_none(self, from_state, to_state):
        # validate_transition raises only on illegal; returns None on legal
        validate_transition(from_state=from_state, to_state=to_state)

    def test_transition_table_exact_set(self):
        from cognic_agentos.core.scheduler._types import _VALID_TRANSITIONS

        expected = frozenset(
            {
                ("pending", "running"),
                ("pending", "failed"),
                ("pending", "cancelled"),
                ("pending", "expired"),
                ("running", "completed"),
                ("running", "failed"),
                ("running", "cancelled"),
                ("running", "preempted"),
            }
        )
        assert expected == _VALID_TRANSITIONS


class TestIllegalTransitions:
    @pytest.mark.parametrize(
        "from_state,to_state",
        [
            # Terminal states can't transition out
            ("completed", "running"),
            ("failed", "running"),
            ("cancelled", "running"),
            ("preempted", "running"),
            ("expired", "running"),
            # Pending can't skip to completed
            ("pending", "completed"),
            # Pending can't skip to preempted (preempted is running-only)
            ("pending", "preempted"),
            # Running can't go back to pending
            ("running", "pending"),
            # Running can't expire
            ("running", "expired"),
        ],
    )
    def test_illegal_transition_raises(self, from_state, to_state):
        with pytest.raises(SchedulerTransitionRefused) as exc_info:
            validate_transition(from_state=from_state, to_state=to_state)
        assert exc_info.value.reason == "scheduler_transition_invalid_state_pair"


class TestPendingFailedIsNewTransition:
    """ADR-022 amendment — pending → failed for create-time failures."""

    def test_pending_to_failed_legal(self):
        validate_transition(from_state="pending", to_state="failed")

    def test_pending_to_failed_in_transition_table(self):
        # If a future refactor reverts ADR-022 amendment, this fails fast
        from cognic_agentos.core.scheduler._types import _VALID_TRANSITIONS

        assert ("pending", "failed") in _VALID_TRANSITIONS


class TestPendingCancelledIsNewTransition:
    """ADR-022 amendment — pending → cancelled for cancel-during-create."""

    def test_pending_to_cancelled_legal(self):
        validate_transition(from_state="pending", to_state="cancelled")

    def test_pending_to_cancelled_in_transition_table(self):
        from cognic_agentos.core.scheduler._types import _VALID_TRANSITIONS

        assert ("pending", "cancelled") in _VALID_TRANSITIONS


class TestKeywordOnlyArgs:
    """Eliminate positional-misuse bug class (mirrors packs/lifecycle.py:421)."""

    def test_rejects_positional_args(self):
        with pytest.raises(TypeError):
            validate_transition("pending", "running")  # type: ignore[misc]
