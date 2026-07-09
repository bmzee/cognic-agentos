"""ADR-028 M8.5-B (Sprint B, Task 5) — bounded-replay selection.

The I-1 surface BAR 2 pins: the model context derives exclusively from the
kernel store. This module never sees a client payload; its input is always the
already tenant- and conversation-scoped output of
``ConversationStore.load_replay_turns``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from cognic_agentos.core.agent._types import PriorTurn
from cognic_agentos.core.conversation._context import assemble_prior_context
from cognic_agentos.core.conversation._types import TurnRecord


def _turn(seq: int, q: str = "q", a: str = "a") -> TurnRecord:
    return TurnRecord(
        turn_id=uuid.uuid4(),
        seq=seq,
        user_message=q,
        answer=a,
        agent_run_id=f"r{seq}",
        prompt_tokens=1,
        completion_tokens=1,
        created_at=datetime.now(UTC),
    )


def _erased(seq: int) -> TurnRecord:
    return TurnRecord(
        turn_id=uuid.uuid4(),
        seq=seq,
        user_message=None,
        answer=None,
        agent_run_id=f"r{seq}",
        prompt_tokens=0,
        completion_tokens=0,
        created_at=datetime.now(UTC),
    )


def test_empty_history_yields_empty_context() -> None:
    assert assemble_prior_context([], replay_last_n=10, token_ceiling=1000) == ()


def test_each_turn_becomes_a_user_then_assistant_pair() -> None:
    out = assemble_prior_context([_turn(1, "who?", "Acme")], replay_last_n=10, token_ceiling=1000)
    assert out == (
        PriorTurn(role="user", content="who?"),
        PriorTurn(role="assistant", content="Acme"),
    )


def test_turns_are_ordered_by_seq_regardless_of_input_order() -> None:
    out = assemble_prior_context(
        [_turn(3, "c", "C"), _turn(1, "a", "A"), _turn(2, "b", "B")],
        replay_last_n=10,
        token_ceiling=1000,
    )
    assert [m.content for m in out] == ["a", "A", "b", "B", "c", "C"]


def test_erased_turns_are_dropped_entirely() -> None:
    """Replaying a tombstone would leak the fact of erasure and add nothing."""
    out = assemble_prior_context(
        [_turn(1), _erased(2), _turn(3)], replay_last_n=10, token_ceiling=1000
    )
    assert len(out) == 4  # two surviving turns x 2 messages
    assert all(m.content for m in out)


def test_all_erased_yields_empty_context() -> None:
    assert (
        assemble_prior_context([_erased(1), _erased(2)], replay_last_n=10, token_ceiling=1000) == ()
    )


def test_half_erased_turn_is_dropped() -> None:
    """A turn with plaintext on one side only is not replayable."""
    half = TurnRecord(
        turn_id=uuid.uuid4(),
        seq=2,
        user_message="q",
        answer=None,
        agent_run_id="r2",
        prompt_tokens=0,
        completion_tokens=0,
        created_at=datetime.now(UTC),
    )
    out = assemble_prior_context([_turn(1), half], replay_last_n=10, token_ceiling=1000)
    assert len(out) == 2


def test_replay_window_keeps_grounding_plus_last_n() -> None:
    turns = [_turn(i, f"q{i}", f"a{i}") for i in range(1, 6)]
    out = assemble_prior_context(turns, replay_last_n=2, token_ceiling=1000)
    assert [m.content for m in out] == ["q1", "a1", "q4", "a4", "q5", "a5"]


def test_replay_last_n_zero_keeps_only_the_grounding_turn() -> None:
    turns = [_turn(i) for i in range(1, 4)]
    out = assemble_prior_context(turns, replay_last_n=0, token_ceiling=1000)
    assert len(out) == 2


def test_ceiling_trims_oldest_non_grounding_turn_first() -> None:
    turns = [_turn(1, "GROUNDING", "g"), _turn(2, "X" * 400, "x"), _turn(3, "Y" * 40, "y")]
    out = assemble_prior_context(turns, replay_last_n=10, token_ceiling=40)
    contents = [m.content for m in out]
    assert contents[0] == "GROUNDING"
    assert not any(c.startswith("XXXX") for c in contents)  # oldest non-grounding dropped
    assert any(c.startswith("YYYY") for c in contents)  # newest retained


def test_grounding_turn_never_trimmed_even_if_alone_over_ceiling() -> None:
    out = assemble_prior_context([_turn(1, "Z" * 4000, "z")], replay_last_n=10, token_ceiling=1)
    assert len(out) == 2


def test_ceiling_zero_keeps_grounding_only() -> None:
    turns = [_turn(1, "g", "G"), _turn(2, "b", "B")]
    out = assemble_prior_context(turns, replay_last_n=10, token_ceiling=0)
    assert [m.content for m in out] == ["g", "G"]


def test_output_is_an_immutable_tuple_of_frozen_prior_turns() -> None:
    out = assemble_prior_context([_turn(1)], replay_last_n=10, token_ceiling=1000)
    assert isinstance(out, tuple)
    assert all(isinstance(m, PriorTurn) for m in out)


def test_short_messages_are_not_free_under_a_tight_ceiling() -> None:
    """`len // 4` floors sub-4-char text to 0 tokens; a non-empty message must
    never cost nothing, or a ceiling admits unbounded short turns."""
    turns = [_turn(1, "g", "G"), _turn(2, "b", "B"), _turn(3, "c", "C")]
    out = assemble_prior_context(turns, replay_last_n=10, token_ceiling=2)
    # grounding costs 2 (1 + 1); budget 0 -> no further turn admitted
    assert [m.content for m in out] == ["g", "G"]


def test_empty_text_is_genuinely_free() -> None:
    """The `if not text: return 0` arm — an empty message costs nothing."""
    turns = [_turn(1, "", ""), _turn(2, "b", "B")]
    out = assemble_prior_context(turns, replay_last_n=10, token_ceiling=2)
    # grounding costs 0, so the next turn (cost 2) still fits exactly
    assert [m.content for m in out] == ["", "", "b", "B"]
