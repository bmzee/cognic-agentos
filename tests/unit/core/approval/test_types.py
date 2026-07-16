from __future__ import annotations

import inspect
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
    ClaimOutcome,
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
        "require_assigned",
    }


def test_envelope_invalid_reason_count() -> None:
    assert len(typing.get_args(ApprovalEnvelopeInvalidReason)) == 8


def test_transition_refused_reason_count() -> None:
    # HP-4 (M8.5-C T1): +approval_originator_mismatch; maker-checker hotfix:
    # +originator_cannot_approve. D2 phase A adds the assignment-membership
    # and N-way distinctness refusals. D2 phase B adds approval_consumed.
    assert len(typing.get_args(ApprovalTransitionRefusedReason)) == 15


def test_transition_progress_inputs_are_required_keyword_only() -> None:
    signature = inspect.signature(validate_transition)
    for name in ("decisions_recorded", "required_count"):
        parameter = signature.parameters[name]
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
        assert parameter.default is inspect.Parameter.empty


def test_claim_outcome_closed_set() -> None:
    assert set(typing.get_args(ClaimOutcome)) == {
        "first_claim",
        "already_consumed",
        "not_granted",
    }


@pytest.mark.parametrize(
    "from_state,action,flow,decisions_recorded,required_count,expected",
    [
        ("pending", "grant_first", "require_single_approval", 0, 1, "granted"),
        ("pending", "grant_first", "require_4_eyes", 0, 2, "awaiting_second"),
        ("awaiting_second", "grant_second", "require_4_eyes", 1, 2, "granted"),
        ("awaiting_second", "grant_second", "require_assigned", 1, 4, "awaiting_second"),
        ("awaiting_second", "grant_second", "require_assigned", 3, 4, "granted"),
        ("pending", "deny", "require_single_approval", 0, 1, "denied"),
        ("awaiting_second", "deny", "require_4_eyes", 1, 2, "denied"),
        ("pending", "expire", "require_single_approval", 0, 1, "expired"),
        ("awaiting_second", "expire", "require_4_eyes", 1, 2, "expired"),
    ],
)
def test_validate_transition_legal_pairs(
    from_state: str,
    action: str,
    flow: str,
    decisions_recorded: int,
    required_count: int,
    expected: str,
) -> None:
    assert (
        validate_transition(
            from_state=from_state,
            action=action,
            flow=flow,
            decisions_recorded=decisions_recorded,
            required_count=required_count,
        )
        == expected
    )


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
        validate_transition(
            from_state=from_state,
            action=action,
            flow=flow,
            decisions_recorded=0,
            required_count=2,
        )
    assert ei.value.reason == reason


def test_risk_tier_mirror_matches_canonical() -> None:
    # Test-only drift detector: core/approval must NOT import cli/* at runtime,
    # so the 8-value RiskTier vocab is mirrored inline; this pins lockstep.
    from cognic_agentos.cli._governance_vocab import RiskTier

    assert frozenset(typing.get_args(RiskTier)) == _RISK_TIERS


def test_reason_mandating_tiers_subset() -> None:
    assert _REASON_MANDATING_TIERS <= _RISK_TIERS
