"""Sprint 13.5c2 (ADR-014) — scheduler approval seam cutover tests."""

from __future__ import annotations

import dataclasses
import typing


def test_admission_outcome_carries_five_approval_values() -> None:
    # Wire-protocol-public (spec §4): +5 on BOTH Literals; wire-equal subset
    # holds (pinned independently at test_closed_enums.py).
    from cognic_agentos.core.scheduler._types import (
        SchedulerAdmissionOutcome,
        SchedulerRefusalReason,
    )

    approval_values = {
        "refused_approval_pending",
        "refused_approval_denied",
        "refused_approval_expired",
        "refused_approval_binding_mismatch",
        "refused_approval_request_not_found",
    }
    assert approval_values <= set(typing.get_args(SchedulerAdmissionOutcome))
    assert approval_values <= set(typing.get_args(SchedulerRefusalReason))


def test_storage_closed_enum_guard_includes_approval_reasons() -> None:
    # storage._VALID_REFUSAL_REASONS is built via typing.get_args — the
    # runtime guard must accept the +5 with ZERO storage-code change.
    from cognic_agentos.core.scheduler.storage import _VALID_REFUSAL_REASONS

    assert "refused_approval_pending" in _VALID_REFUSAL_REASONS
    assert len(_VALID_REFUSAL_REASONS) == 10


def test_admission_decision_approval_request_id_defaults_none() -> None:
    from cognic_agentos.core.scheduler._types import AdmissionDecision

    d = AdmissionDecision(outcome="accepted_immediate", task_id=None)
    assert d.approval_request_id is None  # additive — old constructors green
    p = AdmissionDecision(
        outcome="refused_approval_pending", task_id=None, approval_request_id="abc"
    )
    assert p.approval_request_id == "abc"


def test_submit_input_carries_three_new_defaulted_fields() -> None:
    # Spec §2: approval_request_id (carrier) / approval_verified
    # (ENGINE-OWNED) / data_classes — all defaulted so every existing
    # constructor stays green.
    from cognic_agentos.core.scheduler._types import SubmitInput, TaskActor

    base = SubmitInput(
        tenant_id="t-1",
        pack_id="pack-x",
        actor=TaskActor(subject="svc-a", tenant_id="t-1", actor_type="service"),
        class_="interactive",
        pack_kind="tool",
        pack_risk_tier="internal_write",
        requested_estimated_tokens=500,
    )
    assert base.approval_request_id is None
    assert base.approval_verified is False
    assert base.data_classes == ()
    rich = dataclasses.replace(
        base,
        approval_request_id="11111111-1111-1111-1111-111111111111",
        approval_verified=True,
        data_classes=("payment_data",),
    )
    assert rich.approval_verified is True


def test_submit_input_invalid_field_vocabulary_two_values() -> None:
    # Spec §4: 1 → 2 (+ approval_request_id); Literal + frozenset lockstep
    # is pinned by test_engine.py::test_t10_invalid_field_literal_in_lockstep_with_constant.
    from cognic_agentos.core.scheduler.engine import (
        _VALID_SUBMIT_INPUT_INVALID_FIELDS,
        SchedulerSubmitInputInvalidField,
    )

    assert set(typing.get_args(SchedulerSubmitInputInvalidField)) == {
        "parent_task_id",
        "approval_request_id",
    }
    assert (
        frozenset({"parent_task_id", "approval_request_id"}) == _VALID_SUBMIT_INPUT_INVALID_FIELDS
    )
