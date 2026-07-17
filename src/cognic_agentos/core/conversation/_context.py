"""ADR-028 M8.5-B — bounded-replay context selection. Pure-functional, no I/O.

v1 ``context_strategy`` vocabulary has exactly ONE value: ``bounded_replay``
(ADR-028 §5). Summarization is deferred to v1.1.

The input is ALWAYS the output of ``ConversationStore.load_replay_turns``, which
is already tenant- and conversation-scoped. This module performs no isolation of
its own -- that boundary is upstream and on the critical-controls gate.

OFF the gate by maintainer ruling (M8.5-A recon): pure selection over
already-scoped rows; ``storage.py`` and ``turn.py`` own the enforcement
boundaries. Precedent: ``core/scheduler/_seams.py``, ``packs/_lifecycle_helpers.py``.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from cognic_agentos.core.agent._types import PriorTurn
from cognic_agentos.core.conversation._types import TurnRecord

#: Characters per token. A coarse PRE-FILTER estimate, NOT an authoritative
#: count -- the loop's own ``run_token_budget`` round-top check counts real
#: gateway usage and is the binding bound. Do not present this as accounting.
_CHARS_PER_TOKEN: Final[int] = 4


def _estimate_tokens(text: str) -> int:
    """Non-empty text NEVER costs zero.

    Plain ``len // 4`` floors any message under 4 characters to 0 tokens, which
    would let a ``token_ceiling`` admit an unbounded number of short turns for
    free. Empty text is genuinely free.
    """
    if not text:
        return 0
    return max(1, len(text) // _CHARS_PER_TOKEN)


def _cost(turn: TurnRecord) -> int:
    return _estimate_tokens(turn.user_message or "") + _estimate_tokens(turn.answer or "")


def assemble_prior_context(
    turns: Sequence[TurnRecord], *, replay_last_n: int, token_ceiling: int
) -> tuple[PriorTurn, ...]:
    """Select the replay window and flatten it to alternating user/assistant
    messages in ascending ``seq`` order.

    Erased turns (tombstoned plaintext) are dropped ENTIRELY: replaying a
    tombstone would leak the fact of erasure into the model context and add
    nothing. A half-erased turn (plaintext on one side only) is not replayable
    and is dropped too.

    Trimming removes the OLDEST NON-GROUNDING turn first; the grounding turn
    (lowest surviving ``seq``) is never trimmed, since carrying it is the entire
    point of bounded replay.
    """
    surviving = [
        t
        for t in sorted(turns, key=lambda t: t.seq)
        if t.turn_kind == "exchange" and t.user_message is not None and t.answer is not None
    ]
    if not surviving:
        return ()

    grounding, rest = surviving[0], surviving[1:]
    window = rest[-replay_last_n:] if replay_last_n > 0 else []

    budget = token_ceiling - _cost(grounding)
    kept: list[TurnRecord] = []
    for turn in reversed(window):  # newest first; drop the oldest on overflow
        cost = _cost(turn)
        if cost > budget:
            break
        budget -= cost
        kept.append(turn)
    kept.reverse()

    messages: list[PriorTurn] = []
    for turn in [grounding, *kept]:
        messages.append(PriorTurn(role="user", content=turn.user_message or ""))
        messages.append(PriorTurn(role="assistant", content=turn.answer or ""))
    return tuple(messages)
