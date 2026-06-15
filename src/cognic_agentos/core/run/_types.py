"""Sprint 14A-A3a — run-lifecycle closed enums + frozen RunRecord + the
pure-functional run-state validator. Re-export surface for core/run/storage.py.

Mirrors core/scheduler/_types.py. OFF the critical-controls gate (pure types +
pure-functional validator; the closed-enum + state-machine drift detectors at
tests/unit/core/run/test_run_types.py cover the surface). No I/O; no DB access.

DOCTRINE (Sprint 14A-A3a, locked): the RunState VOCABULARY is fixed here at 9
values. Future slices (A3b suspend/wake, A3c) may only EXPAND
``_A3A_VALID_TRANSITIONS`` (add legal pairs over the existing states) — NEVER
add a state value (that would be a stored-column-vocabulary migration). The
``test_reserved_pairs_refuse_until_expanded`` pin proves the reserved pairs
refuse today.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Final, Literal

#: The full forward-compatible run-lifecycle vocabulary (9 values). ACTIVE in
#: A3a: pending (genesis) / running / completed / failed / refused /
#: pending_approval. RESERVED (no A3a transition; A3b/A3c expand the matrix):
#: suspended / woken / cancelled.
RunState = Literal[
    "pending",
    "running",
    "completed",
    "failed",
    "refused",
    "pending_approval",
    "suspended",
    "woken",
    "cancelled",
]

#: A3a synchronous legal-transition subset. A3b EXPANDS this set (suspend/wake);
#: it MUST NOT change the RunState vocabulary above.
_A3A_VALID_TRANSITIONS: Final[frozenset[tuple[RunState, RunState]]] = frozenset(
    {
        ("pending", "running"),
        ("pending", "refused"),
        ("running", "completed"),
        ("running", "failed"),
        ("running", "refused"),
        ("running", "pending_approval"),
    }
)


class RunTransitionRefused(Exception):
    """Raised by validate_transition on an illegal (from_state, to_state) pair.
    Thin wrapper carrying only the closed-enum reason (mirrors
    core/scheduler/_types.SchedulerTransitionRefused)."""

    def __init__(self, reason: Literal["run_transition_invalid_state_pair"]) -> None:
        super().__init__(reason)
        self.reason = reason


def validate_transition(*, from_state: RunState, to_state: RunState) -> None:
    """Pure-functional run-state-machine validator. No I/O. Keyword-only args
    eliminate the positional-misuse bug class. Raises RunTransitionRefused on an
    illegal pair; returns None on a legal pair."""
    if (from_state, to_state) not in _A3A_VALID_TRANSITIONS:
        raise RunTransitionRefused("run_transition_invalid_state_pair")


@dataclass(frozen=True)
class RunRecord:
    """Read projection of a ``runs`` row (returned by RunRecordStore.load /
    list_for_tenant). ``checkpoint_id`` is the sandbox ``CheckpointId`` hex
    string (32 chars), NOT a UUID; ``approval_request_id`` is the approval-engine
    request UUID."""

    run_id: uuid.UUID
    tenant_id: str
    pack_id: str
    pack_uuid: uuid.UUID
    pack_version: str
    task_id: uuid.UUID | None
    session_id: str | None
    checkpoint_id: str | None
    approval_request_id: uuid.UUID | None
    state: RunState
    created_at: datetime
    updated_at: datetime
