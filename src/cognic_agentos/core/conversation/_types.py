"""ADR-028 M8.5-A — conversation closed enums + frozen records + the
pure-functional state validator. Re-export surface for
``core/conversation/storage.py``.

Mirrors ``core/scheduler/_types.py`` and ``core/run/_types.py``. OFF the
critical-controls gate (pure types + a pure-functional validator; the
closed-enum + state-machine drift detectors at
``tests/unit/core/conversation/test_types.py`` cover the surface). No I/O; no
DB access.

DOCTRINE (locked at M8.5-A, mirroring the Sprint-14A-A3a ``RunState`` rule):
the :data:`ConversationState` VOCABULARY is fixed here at 4 values. Later
slices (the reaper's idle expiry, the M8.5-F erasure pathway) may only EXPAND
the legal-transition matrix over these states — NEVER add a state value, which
would be a stored-column-vocabulary migration.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Final, Literal

#: Full forward-compatible lifecycle vocabulary (4 values). ACTIVE in M8.5-A:
#: ``active`` (genesis) / ``closed``. RESERVED (no M8.5-A transition): ``expired``
#: (reaper slice) / ``erased`` (M8.5-F erasure slice).
ConversationState = Literal["active", "closed", "expired", "erased"]

#: Closed-enum refusal vocabulary for a turn POST. Wire-protocol-public: it is
#: the ``reason`` field of the 409 response body (M8.5-C route surface).
#: ``conversation_turn_claim_stale`` is the FENCING refusal (P0, 2026-07-10): a
#: worker whose lease was reclaimed after TTL expiry may not persist its turn --
#: TTL expiry is liveness recovery, not mutual exclusion, and only the fencing
#: token makes the single-writer claim true.
ConversationTurnRefusalReason = Literal[
    "conversation_not_active",
    "conversation_turn_in_progress",
    "conversation_max_turns_exceeded",
    "conversation_token_budget_exceeded",
    "conversation_turn_claim_stale",
    "conversation_hook_refused",
]

#: Closed, additive ADR-028 decision-history vocabulary. The original six
#: retain their order. ``conversation.system_turn_appended`` is the
#: already-shipped D2 approval-outcome row whose omission from the design
#: document is being corrected in the coordinated docs half; R21 then adds
#: ``conversation.turn_refused`` for chain-atomic usage settlement when a
#: model-authored output is suppressed before transcript persistence.
ConversationChainEventType = Literal[
    "conversation.created",
    "conversation.turn_completed",
    "conversation.escalated",
    "conversation.closed",
    "conversation.expired",
    "conversation.erased",
    "conversation.system_turn_appended",
    "conversation.turn_refused",
]

_OUTPUT_HOOK_REQUEST_ID_RE: Final[re.Pattern[str]] = re.compile(r"conv-hook-[0-9a-f]{32}\Z")
_SHA256_HEX_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


def _is_output_hook_request_id(value: str) -> bool:
    """Return whether ``value`` is the kernel-minted output-hook group id."""

    return _OUTPUT_HOOK_REQUEST_ID_RE.fullmatch(value) is not None


def _validate_output_hook_correlation(*, request_id: str | None, hook_count: object) -> None:
    """Require the output-hook request/count pair to be complete or absent."""

    if request_id is None:
        if isinstance(hook_count, bool) or not isinstance(hook_count, int) or hook_count != 0:
            raise ValueError(
                "conversation output hook count must be exact integer zero without a request id"
            )
        return
    if not isinstance(request_id, str) or not _is_output_hook_request_id(request_id):
        raise ValueError("conversation output hook request id has an invalid shape")
    if isinstance(hook_count, bool) or not isinstance(hook_count, int) or hook_count <= 0:
        raise ValueError("conversation output hook count must be a positive integer")


#: M8.5-A legal-transition subset. EXPAND ONLY; never change the vocabulary.
_SLICE_VALID_TRANSITIONS: Final[frozenset[tuple[ConversationState, ConversationState]]] = frozenset(
    {("active", "closed")}
)

_VALID_TRANSITIONS: Final[frozenset[tuple[ConversationState, ConversationState]]] = (
    _SLICE_VALID_TRANSITIONS
)


class ConversationNotFound(Exception):
    """Absent OR cross-tenant OR cross-actor.

    The route collapses all three to a 404 byte-identical to a genuine
    not-found, so a probe cannot enumerate conversations across tenants or
    actors (the established cross-tenant-invisibility doctrine).
    """


class ConversationTransitionRefused(Exception):
    """Illegal state pair. ``reason`` is the closed-enum wire value."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ConversationTurnRefused(Exception):
    """Governed turn refusal.

    Most reasons fire before the AgentLoop is invoked
    (``conversation_not_active`` at claim, ``conversation_turn_in_progress``,
    the two bounds, and an input-phase ``conversation_hook_refused``). An
    output-phase ``conversation_hook_refused`` fires after the run completed
    but before the answer ships or the turn persists. Two more fire AT
    PERSIST TIME, after the loop has run:
    ``conversation_turn_claim_stale`` (the fencing refusal -- the lease was
    reclaimed while the turn ran) and ``conversation_not_active`` re-raised by
    the ``_PERSISTABLE_STATES`` rule when the row moved to ``expired`` /
    ``erased`` mid-turn. Carries the conversation's current state so the route
    can surface it alongside the closed-enum reason.
    """

    def __init__(
        self,
        reason: ConversationTurnRefusalReason,
        *,
        current_state: ConversationState,
        conversation_output_request_id: str | None = None,
        conversation_output_hook_count: int = 0,
        conversation_output_value_sha256: str | None = None,
        conversation_output_value_bytes: int | None = None,
    ) -> None:
        _validate_output_hook_correlation(
            request_id=conversation_output_request_id,
            hook_count=conversation_output_hook_count,
        )
        if (conversation_output_value_sha256 is None) != (conversation_output_value_bytes is None):
            raise ValueError("conversation output value digest/size must be present together")
        if conversation_output_value_sha256 is not None:
            if _SHA256_HEX_RE.fullmatch(conversation_output_value_sha256) is None:
                raise ValueError("conversation output value digest must be lowercase SHA-256")
            if (
                isinstance(conversation_output_value_bytes, bool)
                or not isinstance(conversation_output_value_bytes, int)
                or conversation_output_value_bytes < 0
            ):
                raise ValueError("conversation output value size must be a non-negative integer")
        super().__init__(reason)
        self.reason: ConversationTurnRefusalReason = reason
        self.current_state: ConversationState = current_state
        # Internal evidence correlation only; portal wire rendering remains the
        # established reason + current_state shape.
        self.conversation_output_request_id = conversation_output_request_id
        self.conversation_output_hook_count = conversation_output_hook_count
        self.conversation_output_value_sha256 = conversation_output_value_sha256
        self.conversation_output_value_bytes = conversation_output_value_bytes


def validate_transition(*, from_state: ConversationState, to_state: ConversationState) -> None:
    """Pure-functional conversation-state-machine validator.

    No I/O. Keyword-only args eliminate the positional-misuse bug class. Raises
    :class:`ConversationTransitionRefused` on an illegal pair; returns ``None``
    on a legal pair.
    """
    if (from_state, to_state) not in _VALID_TRANSITIONS:
        raise ConversationTransitionRefused("conversation_transition_invalid_state_pair")


@dataclass(frozen=True, slots=True)
class ConversationRecord:
    """Operational projection of a ``conversations`` row."""

    conversation_id: uuid.UUID
    tenant_id: str
    agent_id: str
    creator_subject: str
    state: ConversationState
    turn_count: int
    cumulative_tokens: int
    created_at: datetime
    last_turn_at: datetime | None


@dataclass(frozen=True, slots=True)
class TurnRecord:
    """Operational projection of a ``conversation_turns`` row.

    ``user_message`` / ``answer`` are ``None`` after erasure (tombstoned
    plaintext).  Exchange rows retain a real ``agent-run-*`` correlator.
    System rows instead retain the released schema-v1
    ``system-<approval UUID>`` placeholder plus ``approval_request_id``;
    that placeholder is not an agent run and must not be followed into
    ``agent.run.*`` evidence.  Output-refused attempts create no
    ``TurnRecord`` at all and settle through ``conversation.turn_refused``.
    """

    turn_id: uuid.UUID
    seq: int
    user_message: str | None
    answer: str | None
    agent_run_id: str
    prompt_tokens: int
    completion_tokens: int
    created_at: datetime
    approval_request_id: str | None = None
    turn_kind: Literal["exchange", "system"] = "exchange"


@dataclass(frozen=True, slots=True)
class TurnClaim:
    """The single-writer lease minted by ``ConversationStore.claim_turn``.

    ``claim_id`` is a FENCING TOKEN (P0 correction, 2026-07-10): TTL expiry lets
    a new worker reclaim a stalled conversation (liveness), but only the holder
    of the CURRENT ``claim_id`` may persist a turn or release the claim
    (mutual exclusion). A worker whose lease was reclaimed finds its token
    stale: its ``append_turn`` refuses ``conversation_turn_claim_stale`` and its
    ``release_claim`` is a no-op, so it can neither write over nor unlock the
    new holder's lease.
    """

    record: ConversationRecord
    claim_id: uuid.UUID
