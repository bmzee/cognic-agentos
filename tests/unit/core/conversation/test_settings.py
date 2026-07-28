"""ADR-028 M8.5-C — the four ``conversation_*`` Settings.

Ruling 5 (2026-07-09): ``core/config.py`` enters this slice, so the Settings get
dedicated tests — defaults, environment overrides, invalid bounds, and the
declared-budget headroom relationship
``conversation_claim_ttl_s > agent_run_wall_clock_s + admitted hook invocation
timeouts`` that ``ConversationTurnExecutor`` refuses to violate. This is a
configuration check, not an end-to-end lease deadline; claim-id fencing owns
stale append refusal.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from cognic_agentos.core.config import Settings


class _ZeroHookBudget:
    def turn_timeout_budget_s(self) -> float:
        return 0.0


def _settings(**overrides: Any) -> Settings:
    return Settings(**overrides)


# --- defaults ------------------------------------------------------------------


def test_defaults_match_adr_028_section_5() -> None:
    s = _settings()
    assert s.conversation_max_turns == 20
    assert s.conversation_replay_last_n == 10
    assert s.conversation_replay_token_ceiling == 8_000
    assert s.conversation_claim_ttl_s == 300.0
    assert s.conversation_chain_candidate_limit == 10_000


def test_default_claim_ttl_exceeds_default_agent_wall_clock_before_hook_budget() -> None:
    """The shipped defaults must satisfy the executor's construction guard,
    else a stock deployment cannot build a ConversationTurnExecutor at all."""
    s = _settings()
    assert s.conversation_claim_ttl_s > s.agent_run_wall_clock_s


# --- environment overrides -----------------------------------------------------


@pytest.mark.parametrize(
    ("env_name", "value", "attr", "expected"),
    [
        ("COGNIC_CONVERSATION_MAX_TURNS", "5", "conversation_max_turns", 5),
        ("COGNIC_CONVERSATION_REPLAY_LAST_N", "3", "conversation_replay_last_n", 3),
        (
            "COGNIC_CONVERSATION_REPLAY_TOKEN_CEILING",
            "1234",
            "conversation_replay_token_ceiling",
            1234,
        ),
        ("COGNIC_CONVERSATION_CLAIM_TTL_S", "600.5", "conversation_claim_ttl_s", 600.5),
        (
            "COGNIC_CONVERSATION_CHAIN_CANDIDATE_LIMIT",
            "500",
            "conversation_chain_candidate_limit",
            500,
        ),
    ],
)
def test_environment_override(
    monkeypatch: pytest.MonkeyPatch, env_name: str, value: str, attr: str, expected: Any
) -> None:
    monkeypatch.setenv(env_name, value)
    assert getattr(_settings(), attr) == expected


# --- invalid bounds ------------------------------------------------------------


@pytest.mark.parametrize("bad", [0, -1])
def test_max_turns_must_be_positive(bad: int) -> None:
    with pytest.raises(ValidationError):
        _settings(conversation_max_turns=bad)


def test_replay_last_n_may_be_zero_but_not_negative() -> None:
    """last_n == 0 is legal: replay the grounding turn only."""
    assert _settings(conversation_replay_last_n=0).conversation_replay_last_n == 0
    with pytest.raises(ValidationError):
        _settings(conversation_replay_last_n=-1)


@pytest.mark.parametrize("bad", [0, -1])
def test_replay_token_ceiling_must_be_positive(bad: int) -> None:
    with pytest.raises(ValidationError):
        _settings(conversation_replay_token_ceiling=bad)


@pytest.mark.parametrize("bad", [0.0, -0.5])
def test_claim_ttl_must_be_positive(bad: float) -> None:
    with pytest.raises(ValidationError):
        _settings(conversation_claim_ttl_s=bad)


@pytest.mark.parametrize("bad", [0, -1])
def test_chain_candidate_limit_must_be_positive(bad: int) -> None:
    with pytest.raises(ValidationError):
        _settings(conversation_chain_candidate_limit=bad)


# --- the startup relationship the executor enforces ----------------------------


def test_executor_refuses_when_claim_ttl_does_not_exceed_wall_clock() -> None:
    """Settings alone cannot express the cross-field guard; the executor does.

    A misconfigured deployment (claim_ttl_s <= agent_run_wall_clock_s) fails
    loudly instead of claiming declared-budget headroom it does not have.
    """
    from cognic_agentos.core.conversation.turn import ConversationTurnExecutor

    s = _settings(conversation_claim_ttl_s=60.0)  # < default wall clock (120.0)
    assert s.conversation_claim_ttl_s <= s.agent_run_wall_clock_s

    with pytest.raises(ValueError, match="claim_ttl_s"):
        ConversationTurnExecutor(
            store=object(),  # type: ignore[arg-type]
            loop=object(),  # type: ignore[arg-type]
            hook_guard=_ZeroHookBudget(),  # type: ignore[arg-type]
            max_turns=s.conversation_max_turns,
            cumulative_token_budget=1,
            replay_last_n=s.conversation_replay_last_n,
            replay_token_ceiling=s.conversation_replay_token_ceiling,
            claim_ttl_s=s.conversation_claim_ttl_s,
            agent_run_wall_clock_s=s.agent_run_wall_clock_s,
        )


def test_executor_accepts_the_shipped_defaults() -> None:
    from cognic_agentos.core.conversation.turn import ConversationTurnExecutor

    s = _settings()
    ex = ConversationTurnExecutor(
        store=object(),  # type: ignore[arg-type]
        loop=object(),  # type: ignore[arg-type]
        hook_guard=_ZeroHookBudget(),  # type: ignore[arg-type]
        max_turns=s.conversation_max_turns,
        cumulative_token_budget=s.agent_run_token_budget * s.conversation_max_turns,
        replay_last_n=s.conversation_replay_last_n,
        replay_token_ceiling=s.conversation_replay_token_ceiling,
        claim_ttl_s=s.conversation_claim_ttl_s,
        agent_run_wall_clock_s=s.agent_run_wall_clock_s,
    )
    assert ex is not None
