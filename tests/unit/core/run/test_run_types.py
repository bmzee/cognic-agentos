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

# Reserved for A3b/A3c — MUST refuse today (the doctrine: A3b EXPANDS the
# matrix; the vocabulary is fixed at A3a).
_RESERVED_PAIRS = {
    ("running", "suspended"),
    ("suspended", "woken"),
    ("woken", "running"),
    ("running", "cancelled"),
    ("pending", "cancelled"),
}


def test_run_state_vocabulary_is_exactly_nine_values() -> None:
    assert set(get_args(RunState)) == _FULL_VOCAB
    assert len(get_args(RunState)) == 9


@pytest.mark.parametrize("pair", sorted(_A3A_LEGAL_PAIRS))
def test_a3a_synchronous_pairs_are_legal(pair: tuple[str, str]) -> None:
    validate_transition(from_state=pair[0], to_state=pair[1])  # type: ignore[arg-type]  # no raise


@pytest.mark.parametrize("pair", sorted(_RESERVED_PAIRS))
def test_reserved_pairs_refuse_until_expanded(pair: tuple[str, str]) -> None:
    # The doctrine pin: reserved (suspend/wake/cancel) pairs REFUSE today, so an
    # A3b change that permits them is provably an EXPANSION of the legal matrix,
    # not a vocabulary change.
    with pytest.raises(RunTransitionRefused) as exc:
        validate_transition(from_state=pair[0], to_state=pair[1])  # type: ignore[arg-type]
    assert exc.value.reason == "run_transition_invalid_state_pair"


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
