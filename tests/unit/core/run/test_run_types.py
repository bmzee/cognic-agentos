"""Sprint 14A-A3a — RunState closed enum + the A3a synchronous transition
subset + the 'full vocab upfront, expand-matrix-only' doctrine pin."""

from __future__ import annotations

from typing import get_args

import pytest

from cognic_agentos.core.run._types import (
    RunRecord,
    RunState,
    RunTransitionRefused,
    validate_transition,
)

_FULL_VOCAB = {
    "pending",
    "running",
    "completed",
    "failed",
    "refused",
    "pending_approval",
    "suspended",
    "woken",
    "cancelled",
}

_A3A_LEGAL_PAIRS = {
    ("pending", "running"),
    ("pending", "refused"),
    ("running", "completed"),
    ("running", "failed"),
    ("running", "refused"),
    ("running", "pending_approval"),
}


def test_run_state_vocabulary_is_exactly_nine_values() -> None:
    assert set(get_args(RunState)) == _FULL_VOCAB
    assert len(get_args(RunState)) == 9


@pytest.mark.parametrize("pair", sorted(_A3A_LEGAL_PAIRS))
def test_a3a_synchronous_pairs_are_legal(pair: tuple[str, str]) -> None:
    validate_transition(from_state=pair[0], to_state=pair[1])  # type: ignore[arg-type]  # no raise


def test_run_record_is_frozen_with_expected_fields() -> None:
    import dataclasses

    fields = {f.name for f in dataclasses.fields(RunRecord)}
    assert fields == {
        "run_id",
        "tenant_id",
        "pack_id",
        "pack_uuid",
        "pack_version",
        "task_id",
        "session_id",
        "checkpoint_id",
        "approval_request_id",
        "state",
        "created_at",
        "updated_at",
    }


_A3B_LEGAL_PAIRS = {
    ("running", "suspended"),
    ("suspended", "woken"),
    ("suspended", "refused"),
    ("suspended", "failed"),
    ("woken", "completed"),
    ("woken", "failed"),
}


@pytest.mark.parametrize("pair", sorted(_A3B_LEGAL_PAIRS))
def test_a3b_suspend_wake_pairs_are_legal(pair: tuple[str, str]) -> None:
    validate_transition(from_state=pair[0], to_state=pair[1])  # type: ignore[arg-type]  # no raise


def test_run_state_vocabulary_still_exactly_nine_after_a3b() -> None:
    # A3b EXPANDS the matrix, never the vocabulary.
    assert len(get_args(RunState)) == 9


_A3C_LEGAL_PAIRS = {
    ("suspended", "pending_approval"),
    ("pending_approval", "woken"),
    ("pending_approval", "refused"),
    ("pending_approval", "failed"),
}

# Reserved AFTER A3c — pairs no runtime path produces (pending_approval only
# leaves to woken/refused/failed; cancelled still deferred; no re-loop/re-suspend).
_RESERVED_PAIRS_A3C = {
    ("woken", "running"),
    ("woken", "suspended"),
    ("woken", "pending_approval"),
    ("suspended", "completed"),
    ("pending_approval", "running"),
    ("pending_approval", "suspended"),
    ("pending_approval", "completed"),
    ("running", "cancelled"),
    ("pending", "cancelled"),
    ("suspended", "cancelled"),
    ("pending_approval", "cancelled"),
}


@pytest.mark.parametrize("pair", sorted(_A3C_LEGAL_PAIRS))
def test_a3c_pending_approval_pairs_are_legal(pair: tuple[str, str]) -> None:
    validate_transition(from_state=pair[0], to_state=pair[1])  # type: ignore[arg-type]  # no raise


@pytest.mark.parametrize("pair", sorted(_RESERVED_PAIRS_A3C))
def test_reserved_pairs_refuse_after_a3c(pair: tuple[str, str]) -> None:
    with pytest.raises(RunTransitionRefused) as exc:
        validate_transition(from_state=pair[0], to_state=pair[1])  # type: ignore[arg-type]
    assert exc.value.reason == "run_transition_invalid_state_pair"


def test_run_state_vocabulary_still_exactly_nine_after_a3c() -> None:
    assert len(get_args(RunState)) == 9
