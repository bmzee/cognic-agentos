"""Sprint 9.5 A1 — model-registry lifecycle state machine."""

from __future__ import annotations

from typing import get_args

import pytest

from cognic_agentos.compliance.iso42001.controls import control_ids
from cognic_agentos.models.registry import (
    MODEL_LIFECYCLE_ISO_CONTROLS,
    ModelKind,
    ModelLifecycleRefusalReason,
    ModelLifecycleRefused,
    ModelLifecycleState,
    ModelTransition,
    validate_transition,
)


def test_lifecycle_state_is_canonical_6_tuple() -> None:
    assert set(get_args(ModelLifecycleState)) == {
        "proposed",
        "eval_passed",
        "tenant_approved",
        "serving",
        "deprecated",
        "retired",
    }


def test_model_kind_is_canonical_4_tuple() -> None:
    assert set(get_args(ModelKind)) == {"foundation", "fine_tune", "adapter", "embedding"}


def test_transition_is_canonical_5_tuple() -> None:
    assert set(get_args(ModelTransition)) == {
        "promote_eval_passed",
        "promote_tenant_approved",
        "promote_serving",
        "promote_deprecated",
        "retire",
    }


def test_refusal_reason_has_exactly_nine_pinned_values() -> None:
    # Wire-protocol contract — every model lifecycle 409 refusal body carries one.
    assert set(get_args(ModelLifecycleRefusalReason)) == {
        "model_transition_invalid_state_pair",
        "model_transition_state_unknown",
        "model_transition_from_terminal_state",
        "model_register_duplicate_id",
        "model_promote_signature_verification_failed",
        "model_promote_signature_refs_changed_during_promote",
        "model_promote_eval_evidence_missing",
        "model_promote_eval_evidence_malformed",
        "model_retire_already_retired",
    }


@pytest.mark.parametrize(
    "from_state,to_state,transition",
    [
        ("proposed", "eval_passed", "promote_eval_passed"),
        ("eval_passed", "tenant_approved", "promote_tenant_approved"),
        ("tenant_approved", "serving", "promote_serving"),
        ("serving", "deprecated", "promote_deprecated"),
        ("proposed", "retired", "retire"),
        ("eval_passed", "retired", "retire"),
        ("tenant_approved", "retired", "retire"),
        ("serving", "retired", "retire"),
        ("deprecated", "retired", "retire"),
    ],
)
def test_valid_transition_returns_none(from_state: str, to_state: str, transition: str) -> None:
    result = validate_transition(
        from_state=from_state,  # type: ignore[arg-type]
        to_state=to_state,  # type: ignore[arg-type]
        transition=transition,  # type: ignore[arg-type]
    )
    assert result is None, f"expected None for {from_state}->{to_state}; got {result!r}"


def test_invalid_state_pair_refused() -> None:
    # proposed cannot jump straight to serving.
    result = validate_transition(
        from_state="proposed", to_state="serving", transition="promote_serving"
    )
    assert result == "model_transition_invalid_state_pair"


def test_transition_out_of_retired_refused_as_terminal() -> None:
    result = validate_transition(
        from_state="retired", to_state="deprecated", transition="promote_deprecated"
    )
    assert result == "model_transition_from_terminal_state"


def test_retire_already_retired_takes_precedence_over_terminal() -> None:
    result = validate_transition(from_state="retired", to_state="retired", transition="retire")
    assert result == "model_retire_already_retired"


def test_unknown_state_refused() -> None:
    result = validate_transition(
        from_state="bogus",  # type: ignore[arg-type]
        to_state="eval_passed",
        transition="promote_eval_passed",
    )
    assert result == "model_transition_state_unknown"


def test_keyword_only_signature_enforced() -> None:
    with pytest.raises(TypeError):
        validate_transition("proposed", "eval_passed", "promote_eval_passed")  # type: ignore[misc]


def test_refused_exception_carries_only_reason() -> None:
    exc = ModelLifecycleRefused("model_register_duplicate_id")
    assert exc.reason == "model_register_duplicate_id"
    assert not hasattr(exc, "transition")


def test_iso_controls_subset_of_canonical_registry() -> None:
    # Drift detector (test-only, no runtime cross-import): every model
    # ISO control must be a real ISO42001_CONTROLS entry.
    assert set(MODEL_LIFECYCLE_ISO_CONTROLS) <= control_ids()
    assert len(MODEL_LIFECYCLE_ISO_CONTROLS) == 5
