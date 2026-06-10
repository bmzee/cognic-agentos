from __future__ import annotations

import typing

import pytest

from cognic_agentos.core.approval._types import (
    _REASON_MANDATING_TIERS,
    _RISK_TIERS,
    ApprovalEnvelopeInvalidReason,
    ApprovalFlow,
    ApprovalState,
    ApprovalTransitionRefused,
    ApprovalTransitionRefusedReason,
    validate_transition,
)


def test_approval_state_closed_set() -> None:
    assert set(typing.get_args(ApprovalState)) == {
        "pending",
        "awaiting_second",
        "granted",
        "denied",
        "expired",
    }


def test_approval_flow_closed_set() -> None:
    assert set(typing.get_args(ApprovalFlow)) == {
        "auto_run",
        "require_single_approval",
        "require_4_eyes",
    }


def test_envelope_invalid_reason_count() -> None:
    assert len(typing.get_args(ApprovalEnvelopeInvalidReason)) == 7


def test_transition_refused_reason_count() -> None:
    assert len(typing.get_args(ApprovalTransitionRefusedReason)) == 10


@pytest.mark.parametrize(
    "from_state,action,flow,expected",
    [
        ("pending", "grant_first", "require_single_approval", "granted"),
        ("pending", "grant_first", "require_4_eyes", "awaiting_second"),
        ("awaiting_second", "grant_second", "require_4_eyes", "granted"),
        ("pending", "deny", "require_single_approval", "denied"),
        ("awaiting_second", "deny", "require_4_eyes", "denied"),
        ("pending", "expire", "require_single_approval", "expired"),
        ("awaiting_second", "expire", "require_4_eyes", "expired"),
    ],
)
def test_validate_transition_legal_pairs(
    from_state: str, action: str, flow: str, expected: str
) -> None:
    assert validate_transition(from_state=from_state, action=action, flow=flow) == expected


@pytest.mark.parametrize(
    "from_state,action,flow,reason",
    [
        ("pending", "grant_second", "require_4_eyes", "grant_second_requires_awaiting_second"),
        ("granted", "grant_first", "require_single_approval", "approval_already_finalized"),
        ("denied", "deny", "require_single_approval", "deny_requires_non_terminal"),
        ("expired", "grant_first", "require_4_eyes", "approval_already_finalized"),
    ],
)
def test_validate_transition_refusals(from_state: str, action: str, flow: str, reason: str) -> None:
    with pytest.raises(ApprovalTransitionRefused) as ei:
        validate_transition(from_state=from_state, action=action, flow=flow)
    assert ei.value.reason == reason


def test_risk_tier_mirror_matches_canonical() -> None:
    # Test-only drift detector: core/approval must NOT import cli/* at runtime,
    # so the 8-value RiskTier vocab is mirrored inline; this pins lockstep.
    from cognic_agentos.cli._governance_vocab import RiskTier

    assert frozenset(typing.get_args(RiskTier)) == _RISK_TIERS


def test_reason_mandating_tiers_subset() -> None:
    assert _REASON_MANDATING_TIERS <= _RISK_TIERS
