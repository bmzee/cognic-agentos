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


# ---------------------------------------------------------------------------
# T2 — binding-digest helpers (spec §3.3, actor-bound F4)
# ---------------------------------------------------------------------------


def _seam_submit_input(**overrides: object) -> object:
    from cognic_agentos.core.scheduler._types import SubmitInput, TaskActor

    base: dict[str, object] = {
        "tenant_id": "t-1",
        "pack_id": "pack-x",
        "actor": TaskActor(subject="agent-1", tenant_id="t-1", actor_type="service"),
        "class_": "interactive",
        "pack_kind": "tool",
        "pack_risk_tier": "payment_action",
        "requested_estimated_tokens": 500,
        "data_classes": ("payment_data",),
    }
    base.update(overrides)
    return SubmitInput(**base)  # type: ignore[arg-type]


def test_canonical_scheduler_identity_shape_and_collision_proofing() -> None:
    from cognic_agentos.core.scheduler.engine import _canonical_scheduler_identity

    ident = _canonical_scheduler_identity(pack_id="pack-x", pack_kind="tool")
    assert ident.startswith("scheduler:")
    assert len(ident) == 10 + 64  # "scheduler:" + hexdigest — fits String(256)
    assert ident == _canonical_scheduler_identity(pack_id="pack-x", pack_kind="tool")
    # Collision-proofing (the F4 doctrine): separator content cannot alias.
    a = _canonical_scheduler_identity(pack_id="a:b", pack_kind="c")
    b = _canonical_scheduler_identity(pack_id="a", pack_kind="b:c")
    assert a != b


def test_args_digest_disposition_map_covers_every_submit_input_field() -> None:
    # Spec §3.3 drift pin (c1 doctrine extended): every SubmitInput field is
    # EXPLICITLY dispositioned; a future field FAILS here until its binding
    # decision is made.
    from cognic_agentos.core.scheduler._types import SubmitInput

    digested = {"class_", "pack_risk_tier", "requested_estimated_tokens", "parent_task_id"}
    digested_via_actor = {"actor"}  # as actor.subject + actor.actor_type
    identity = {"pack_id", "pack_kind"}
    envelope_first_class = {"tenant_id", "data_classes"}
    carrier_or_attestation = {"approval_request_id", "approval_verified"}
    assert {f.name for f in dataclasses.fields(SubmitInput)} == (
        digested | digested_via_actor | identity | envelope_first_class | carrier_or_attestation
    )


def test_args_digest_binds_actor_tokens_and_parent() -> None:
    # Spec §3.3 (USER-LOCKED actor binding): an actor swap, a token-request
    # change, or a parent change MUST change the digest; tenant/data_classes
    # changes MUST NOT (envelope-first-class).
    from cognic_agentos.core.scheduler._types import TaskActor
    from cognic_agentos.core.scheduler.engine import _submit_args_digest

    base = _submit_args_digest(_seam_submit_input())  # type: ignore[arg-type]
    assert base == _submit_args_digest(_seam_submit_input())  # type: ignore[arg-type]
    swapped_actor = _seam_submit_input(
        actor=TaskActor(subject="agent-2", tenant_id="t-1", actor_type="service")
    )
    human_actor = _seam_submit_input(
        actor=TaskActor(subject="agent-1", tenant_id="t-1", actor_type="human")
    )
    assert _submit_args_digest(swapped_actor) != base  # type: ignore[arg-type]
    assert _submit_args_digest(human_actor) != base  # type: ignore[arg-type]
    assert _submit_args_digest(_seam_submit_input(requested_estimated_tokens=501)) != base  # type: ignore[arg-type]
    assert (
        _submit_args_digest(
            _seam_submit_input(parent_task_id="11111111-1111-1111-1111-111111111111")  # type: ignore[arg-type]
        )
        != base
    )
    # Exclusion pins — every non-digested bucket of the disposition map is
    # proven BEHAVIOURALLY (not just by the field-set map): changing an
    # envelope-first-class or carrier/attestation field leaves the digest
    # unchanged, so the helper cannot silently start binding one.
    assert _submit_args_digest(_seam_submit_input(data_classes=())) == base  # type: ignore[arg-type]
    assert _submit_args_digest(_seam_submit_input(tenant_id="t-2")) == base  # type: ignore[arg-type]
    assert (
        _submit_args_digest(
            _seam_submit_input(approval_request_id="11111111-1111-1111-1111-111111111111")  # type: ignore[arg-type]
        )
        == base
    )
    assert _submit_args_digest(_seam_submit_input(approval_verified=True)) == base  # type: ignore[arg-type]


def test_submit_redacted_context_shape_and_cap() -> None:
    from cognic_agentos.core.approval._types import APPROVAL_REDACTED_CONTEXT_MAX_LEN
    from cognic_agentos.core.scheduler.engine import _submit_redacted_context

    text = _submit_redacted_context(_seam_submit_input())  # type: ignore[arg-type]
    assert text.startswith("scheduler_submit pack_id=pack-x ")
    assert "class=interactive" in text and "risk_tier=payment_action" in text
    long = _submit_redacted_context(_seam_submit_input(pack_id="p" * 5000))  # type: ignore[arg-type]
    assert len(long) == APPROVAL_REDACTED_CONTEXT_MAX_LEN
