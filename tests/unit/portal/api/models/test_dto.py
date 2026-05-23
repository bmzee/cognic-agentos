"""Sprint 9.5 B3 — Pydantic v2 request/response DTO shapes for the
model registry portal API.

Per the user-locked B3 invariants — "keep it boring and strict":

1. DTOs only, no store/route/RBAC logic
2. ``extra="forbid"`` where repo pattern supports it (every DTO)
3. exact field-set tests (every DTO's keyset pinned)
4. enum / target-state pins (``PromoteTargetState`` 4-value Literal)
5. response DTOs aligned to the storage model without inventing
   computed behavior (``ModelResponse`` field set == ``ModelRecord``
   field set 1:1; ``ModelLifecycleEventResponse`` field set is a
   strict subset of ``DecisionRecord`` — both alignments pinned)

The DTO module is wire-protocol-public per the same logic as
``portal/api/packs/dto.py`` (every 4xx body, every 200 response, every
request body conforms to these shapes), but it is NOT-CC at the
critical-controls level because there is no decision logic — just
type definitions + Pydantic validation. Halt-before-commit discipline
applies per the user-direction (review for shape stability, not
enforcement correctness).
"""

from __future__ import annotations

import datetime
import uuid
from typing import get_args

import pydantic
import pytest

from cognic_agentos.core.decision_history import DecisionRecord
from cognic_agentos.models.registry import ModelKind, ModelLifecycleState
from cognic_agentos.models.storage import ModelRecord
from cognic_agentos.portal.api.models.dto import (
    ModelBaseModel,
    ModelDetailResponse,
    ModelLifecycleEventResponse,
    ModelResponse,
    PromoteModelRequest,
    PromoteTargetState,
    RegisterModelRequest,
)

# ──────────────────────────────────────────────────────────────────────
# Helpers — minimal ModelRecord + DecisionRecord factories for the
# response DTOs. Per AGENTS.md test-fixture-placement rule.
# ──────────────────────────────────────────────────────────────────────


def _make_model_record(model_id: str = "m-test", tenant_id: str = "tenant-a") -> ModelRecord:
    now = datetime.datetime.now(datetime.UTC)
    return ModelRecord(
        id=uuid.uuid4(),
        model_id=model_id,
        tenant_id=tenant_id,
        base_model="cognic/foundation-12b",
        version="1.0.0",
        kind="foundation",
        recipe_hash=None,
        training_data_fingerprint=None,
        eval_results_ref=None,
        adversarial_pass_rate=None,
        signature_digest=None,
        signed_artifact_ref=None,
        sigstore_bundle_ref=None,
        serving_endpoint=None,
        lifecycle_state="proposed",
        last_actor="forge-bot",
        created_at=now,
        updated_at=now,
    )


def _make_decision_record() -> DecisionRecord:
    """Minimal DecisionRecord matching what
    :meth:`ModelRecordStore.load_lifecycle_history` produces — note
    ``actor_id=None`` per the A5 reconstruction convention (actor
    identity lives in ``payload["actor_id"]`` via canonical-form
    merge)."""
    return DecisionRecord(
        decision_type="model.lifecycle.proposed",
        request_id="req-test-1",
        payload={"model_id": "m-test", "to_state": "proposed"},
        actor_id=None,
        tenant_id="tenant-a",
        iso_controls=("ISO42001.A.6.2.6", "ISO42001.A.7.4"),
    )


# ──────────────────────────────────────────────────────────────────────
# 1. PromoteTargetState — closed-enum vocabulary (user invariant #4)
# ──────────────────────────────────────────────────────────────────────


class TestPromoteTargetState:
    """The 4-value Literal is the wire-protocol contract for the
    ``POST /api/v1/models/{model_id}/promote`` request body's
    ``target_state`` field. Resolved body-aware in the B4 route to
    ``model.promote.<target_state>`` for the RBAC scope check."""

    def test_count_is_exactly_four(self) -> None:
        assert len(get_args(PromoteTargetState)) == 4

    def test_exact_four_value_set(self) -> None:
        assert set(get_args(PromoteTargetState)) == {
            "eval_passed",
            "tenant_approved",
            "serving",
            "deprecated",
        }

    def test_retired_not_in_set(self) -> None:
        """``retired`` lives on the ``/retire`` endpoint, NOT
        ``/promote`` — a regression that lets ``retired`` through
        ``PromoteModelRequest`` would bypass the dedicated retire
        endpoint's RBAC check (``model.retire`` scope vs
        ``model.promote.<state>``)."""
        assert "retired" not in get_args(PromoteTargetState)

    def test_proposed_not_in_set(self) -> None:
        """``proposed`` is genesis-only — created by
        ``POST /api/v1/models`` (register), NOT a promote target."""
        assert "proposed" not in get_args(PromoteTargetState)

    def test_aligned_with_model_lifecycle_state_non_genesis_non_terminal(
        self,
    ) -> None:
        """The 4 promote targets MUST be a strict subset of
        ``ModelLifecycleState`` — exactly the 4 states reachable via
        a promote transition (excludes ``proposed`` = genesis-only and
        ``retired`` = via /retire endpoint). Prevents drift between
        the DTO Literal and the registry's state machine."""
        promote_set = set(get_args(PromoteTargetState))
        all_states = set(get_args(ModelLifecycleState))
        assert promote_set < all_states
        # The complement is exactly {proposed, retired}.
        assert all_states - promote_set == {"proposed", "retired"}


# ──────────────────────────────────────────────────────────────────────
# 2. ModelBaseModel — frozen + extra="forbid" base
# ──────────────────────────────────────────────────────────────────────


class TestModelBaseModelConfig:
    """The base class config IS the DTO module's wire-shape discipline
    — frozen defends against handler-side mutation; ``extra="forbid"``
    pins the request/response keyset against silent smuggling of
    extra fields. Pinned at the base so every DTO inherits the
    invariant automatically."""

    def test_base_is_frozen(self) -> None:
        assert ModelBaseModel.model_config.get("frozen") is True

    def test_base_forbids_extra(self) -> None:
        assert ModelBaseModel.model_config.get("extra") == "forbid"


# ──────────────────────────────────────────────────────────────────────
# 3. RegisterModelRequest — POST /api/v1/models body
# ──────────────────────────────────────────────────────────────────────


_EXPECTED_REGISTER_FIELDS = {
    "model_id",
    "base_model",
    "version",
    "kind",
    "recipe_hash",
    "training_data_fingerprint",
    "signature_digest",
    "signed_artifact_ref",
    "sigstore_bundle_ref",
    "serving_endpoint",
}


class TestRegisterModelRequest:
    """POST ``/api/v1/models`` request body shape. ``tenant_id`` is
    DELIBERATELY ABSENT — it comes from the resolved actor at the
    handler. ``lifecycle_state`` is DELIBERATELY ABSENT — the handler
    forces ``"proposed"`` (genesis). Same for ``last_actor`` /
    ``created_at`` / ``updated_at`` / ``id`` (handler-assigned).
    ``eval_results_ref`` + ``adversarial_pass_rate`` are
    DELIBERATELY ABSENT — they are set at the ``tenant_approved``
    promotion, not at register time."""

    def test_exact_field_set(self) -> None:
        """User invariant #3 — pin the exact field set so additions/
        removals require updating this test in lockstep."""
        assert set(RegisterModelRequest.model_fields) == _EXPECTED_REGISTER_FIELDS

    def test_tenant_id_absent(self) -> None:
        """tenant_id MUST come from the actor (server-side), NEVER the
        client body — pinning the absence prevents a tenant-spoofing
        bug class where a client could register a model in another
        tenant by setting body.tenant_id."""
        assert "tenant_id" not in RegisterModelRequest.model_fields

    def test_lifecycle_state_absent(self) -> None:
        """lifecycle_state MUST be handler-forced to 'proposed'
        (genesis). Pinning absence prevents a state-skip bug class
        where a client could register a model already in
        'serving'/'retired'/etc and bypass the eval/trust transition
        gates (mirrors the A3 R1 P1
        model_register_initial_state_not_proposed gate)."""
        assert "lifecycle_state" not in RegisterModelRequest.model_fields

    def test_eval_evidence_fields_absent(self) -> None:
        """eval_results_ref + adversarial_pass_rate are set at the
        tenant_approved promotion, NOT at register time. Pinning
        absence prevents a confused-deputy bug where a client could
        smuggle eval-passed evidence into the register payload."""
        assert "eval_results_ref" not in RegisterModelRequest.model_fields
        assert "adversarial_pass_rate" not in RegisterModelRequest.model_fields

    def test_handler_managed_fields_absent(self) -> None:
        """id / last_actor / created_at / updated_at MUST be
        handler/storage-assigned. Pinning absence prevents clients
        from injecting these."""
        for field in ("id", "last_actor", "created_at", "updated_at"):
            assert field not in RegisterModelRequest.model_fields

    def test_extra_forbid_refuses_smuggle(self) -> None:
        with pytest.raises(pydantic.ValidationError):
            RegisterModelRequest(
                model_id="m",
                version="1",
                kind="foundation",
                smuggled="x",  # type: ignore[call-arg]
            )

    def test_minimal_construction(self) -> None:
        """Required fields: model_id + version + kind. All other
        fields are optional (nullable per ModelRecord)."""
        req = RegisterModelRequest(model_id="m", version="1", kind="foundation")
        assert req.model_id == "m"
        assert req.version == "1"
        assert req.kind == "foundation"
        assert req.base_model is None
        assert req.signed_artifact_ref is None

    def test_frozen_refuses_mutation(self) -> None:
        req = RegisterModelRequest(model_id="m", version="1", kind="foundation")
        with pytest.raises(pydantic.ValidationError):
            req.model_id = "m2"


# ──────────────────────────────────────────────────────────────────────
# 4. PromoteModelRequest — POST /…/promote body
# ──────────────────────────────────────────────────────────────────────


_EXPECTED_PROMOTE_FIELDS = {
    "target_state",
    "eval_results_ref",
    "adversarial_pass_rate",
}


class TestPromoteModelRequest:
    """POST ``/api/v1/models/{model_id}/promote`` request body."""

    def test_exact_field_set(self) -> None:
        assert set(PromoteModelRequest.model_fields) == _EXPECTED_PROMOTE_FIELDS

    def test_extra_forbid_refuses_smuggle(self) -> None:
        with pytest.raises(pydantic.ValidationError):
            PromoteModelRequest(
                target_state="eval_passed",
                smuggled="x",  # type: ignore[call-arg]
            )

    def test_eval_passed_needs_no_evidence(self) -> None:
        """Storage-layer transition for promote_eval_passed reads
        signature_verified + expected_* refs from the route handler's
        cosign verdict — NOT from the request body. eval_results_ref
        / adversarial_pass_rate are optional + only used by
        promote_tenant_approved."""
        req = PromoteModelRequest(target_state="eval_passed")
        assert req.target_state == "eval_passed"
        assert req.eval_results_ref is None
        assert req.adversarial_pass_rate is None

    @pytest.mark.parametrize("bad_rate", [-0.001, 1.001, 2.0, -1.0, 100.0])
    def test_pass_rate_out_of_range_refused(self, bad_rate: float) -> None:
        """``adversarial_pass_rate`` is a ratio constrained to
        ``[0.0, 1.0]`` via pydantic.Field(ge=0.0, le=1.0). Out-of-range
        values refused at validation time (defence-in-depth against
        the storage layer's own shape gate — fail fast at the wire)."""
        with pytest.raises(pydantic.ValidationError):
            PromoteModelRequest(
                target_state="tenant_approved",
                eval_results_ref="evalpack://run/1",
                adversarial_pass_rate=bad_rate,
            )

    @pytest.mark.parametrize("good_rate", [0.0, 0.5, 0.99, 0.995, 1.0])
    def test_pass_rate_in_range_accepted(self, good_rate: float) -> None:
        """Boundary values 0.0 and 1.0 inclusive (ge/le not gt/lt)."""
        req = PromoteModelRequest(
            target_state="tenant_approved",
            eval_results_ref="evalpack://run/1",
            adversarial_pass_rate=good_rate,
        )
        assert req.adversarial_pass_rate == good_rate

    @pytest.mark.parametrize("state", sorted(get_args(PromoteTargetState)))
    def test_constructs_with_every_target_state(self, state: str) -> None:
        """Parametrized over all 4 PromoteTargetState values — every
        target_state value MUST construct cleanly."""
        req = PromoteModelRequest(target_state=state)  # type: ignore[arg-type]
        assert req.target_state == state

    def test_frozen_refuses_mutation(self) -> None:
        req = PromoteModelRequest(target_state="serving")
        with pytest.raises(pydantic.ValidationError):
            req.target_state = "deprecated"


# ──────────────────────────────────────────────────────────────────────
# 5. ModelResponse — projection of ModelRecord (user invariant #5)
# ──────────────────────────────────────────────────────────────────────


_EXPECTED_MODEL_RESPONSE_FIELDS = {
    "id",
    "model_id",
    "tenant_id",
    "base_model",
    "version",
    "kind",
    "recipe_hash",
    "training_data_fingerprint",
    "eval_results_ref",
    "adversarial_pass_rate",
    "signature_digest",
    "signed_artifact_ref",
    "sigstore_bundle_ref",
    "serving_endpoint",
    "lifecycle_state",
    "last_actor",
    "created_at",
    "updated_at",
}


class TestModelResponse:
    """Response projection of :class:`ModelRecord`. User-locked B3
    invariant #5 — aligned 1:1 with the storage model, no invented
    fields."""

    def test_exact_field_set(self) -> None:
        assert set(ModelResponse.model_fields) == _EXPECTED_MODEL_RESPONSE_FIELDS

    def test_field_set_aligned_one_to_one_with_model_record(self) -> None:
        """User invariant #5 — DTO field set MUST equal ModelRecord
        field set. No invented fields (response carries only what the
        storage row carries; no computed metadata). No missing fields
        (every storage-row column reaches the wire). Drift in either
        direction fails this test."""
        assert set(ModelResponse.model_fields) == set(ModelRecord.model_fields)

    def test_extra_forbid_inherited_from_base(self) -> None:
        assert ModelResponse.model_config.get("extra") == "forbid"

    def test_frozen_inherited_from_base(self) -> None:
        assert ModelResponse.model_config.get("frozen") is True

    def test_from_attributes_enabled(self) -> None:
        """The handler passes a loaded ModelRecord directly to
        ``ModelResponse.model_validate(record)`` — requires
        ``from_attributes=True`` on the model config."""
        assert ModelResponse.model_config.get("from_attributes") is True

    def test_validates_from_real_model_record(self) -> None:
        """End-to-end alignment proof — a real
        :class:`ModelRecord` instance round-trips through
        ``model_validate`` without ValidationError. The 1:1 field
        alignment + from_attributes config + types-compatible
        annotations together MUST produce a valid response.
        """
        record = _make_model_record("m-roundtrip")
        response = ModelResponse.model_validate(record)
        assert response.model_id == "m-roundtrip"
        assert response.lifecycle_state == "proposed"
        assert response.tenant_id == record.tenant_id
        assert response.id == record.id


# ──────────────────────────────────────────────────────────────────────
# 6. ModelLifecycleEventResponse — projection of DecisionRecord
# ──────────────────────────────────────────────────────────────────────


_EXPECTED_LIFECYCLE_EVENT_FIELDS = {
    "decision_type",
    "request_id",
    "tenant_id",
    "payload",
    "iso_controls",
}


class TestModelLifecycleEventResponse:
    """One ``model.lifecycle.*`` chain row projected onto the wire.
    Field set is a strict subset of :class:`DecisionRecord` — omits
    ``actor_id`` (always None for reconstructed records per A5),
    ``trace_id`` / ``span_id`` / ``langfuse_trace_id`` /
    ``provider_label`` (None for model.lifecycle.* events, not
    relevant to the audit wire surface)."""

    def test_exact_field_set(self) -> None:
        assert set(ModelLifecycleEventResponse.model_fields) == _EXPECTED_LIFECYCLE_EVENT_FIELDS

    def test_field_set_strict_subset_of_decision_record(self) -> None:
        """User invariant #5 — DTO field set MUST be a strict subset
        of DecisionRecord field set (no invented fields). Drift would
        mean the DTO has a field DecisionRecord doesn't carry —
        impossible to populate via ``from_attributes``."""
        dr_fields = {f.name for f in DecisionRecord.__dataclass_fields__.values()}
        assert set(ModelLifecycleEventResponse.model_fields) < dr_fields

    def test_omitted_fields_are_documented(self) -> None:
        """Explicit pin for the 5 DecisionRecord fields the DTO
        deliberately omits. A future addition to either side of the
        projection MUST be a conscious choice — this test forces an
        update to the DTO's docstring + the test's expected set."""
        dr_fields = {f.name for f in DecisionRecord.__dataclass_fields__.values()}
        omitted = dr_fields - set(ModelLifecycleEventResponse.model_fields)
        assert omitted == {
            "actor_id",
            "trace_id",
            "span_id",
            "langfuse_trace_id",
            "provider_label",
        }

    def test_extra_forbid_inherited(self) -> None:
        assert ModelLifecycleEventResponse.model_config.get("extra") == "forbid"

    def test_from_attributes_enabled(self) -> None:
        assert ModelLifecycleEventResponse.model_config.get("from_attributes") is True

    def test_validates_from_real_decision_record(self) -> None:
        """End-to-end — a real DecisionRecord projects via
        from_attributes without ValidationError."""
        record = _make_decision_record()
        response = ModelLifecycleEventResponse.model_validate(record)
        assert response.decision_type == "model.lifecycle.proposed"
        assert response.request_id == "req-test-1"
        assert response.tenant_id == "tenant-a"
        assert response.payload == {"model_id": "m-test", "to_state": "proposed"}
        assert response.iso_controls == (
            "ISO42001.A.6.2.6",
            "ISO42001.A.7.4",
        )

    def test_iso_controls_typed_as_tuple(self) -> None:
        """The Sprint-2 canonical-form rejects tuples inside payload
        dicts, but DecisionRecord.iso_controls is a tuple AT THE
        DATACLASS LEVEL. The DTO mirrors the dataclass type — tuple,
        not list — so a future change that flips the dataclass to
        list would surface here as a type mismatch via
        from_attributes."""
        record = _make_decision_record()
        response = ModelLifecycleEventResponse.model_validate(record)
        assert isinstance(response.iso_controls, tuple)


# ──────────────────────────────────────────────────────────────────────
# 7. ModelDetailResponse — composition of ModelResponse + history
# ──────────────────────────────────────────────────────────────────────


_EXPECTED_DETAIL_FIELDS = {"model", "history"}


class TestModelDetailResponse:
    """``GET /api/v1/models/{model_id}`` body composition:
    ``model`` (the latest record) + ``history`` (the lifecycle
    chain rows oldest-first)."""

    def test_exact_field_set(self) -> None:
        assert set(ModelDetailResponse.model_fields) == _EXPECTED_DETAIL_FIELDS

    def test_extra_forbid_inherited(self) -> None:
        assert ModelDetailResponse.model_config.get("extra") == "forbid"

    def test_frozen_inherited(self) -> None:
        assert ModelDetailResponse.model_config.get("frozen") is True

    def test_composes_model_response_and_event_list(self) -> None:
        record = _make_model_record("m-detail")
        event = _make_decision_record()
        response = ModelDetailResponse(
            model=ModelResponse.model_validate(record),
            history=[ModelLifecycleEventResponse.model_validate(event)],
        )
        assert response.model.model_id == "m-detail"
        assert len(response.history) == 1
        assert response.history[0].decision_type == "model.lifecycle.proposed"

    def test_history_accepts_empty_list(self) -> None:
        """A model with no chain rows is rare (genesis always emits)
        but the DTO allows an empty history — defensive against an
        examiner reading a freshly-registered model in flight."""
        record = _make_model_record()
        response = ModelDetailResponse(
            model=ModelResponse.model_validate(record),
            history=[],
        )
        assert response.history == []

    def test_extra_forbid_refuses_smuggle(self) -> None:
        record = _make_model_record()
        with pytest.raises(pydantic.ValidationError):
            ModelDetailResponse(
                model=ModelResponse.model_validate(record),
                history=[],
                smuggled="x",  # type: ignore[call-arg]
            )


# ──────────────────────────────────────────────────────────────────────
# 8. ModelKind enum re-export sanity (alignment with the registry)
# ──────────────────────────────────────────────────────────────────────


class TestModelKindAlignment:
    """``kind`` field on RegisterModelRequest + ModelResponse is typed
    as :data:`ModelKind` (re-used from ``models/registry.py``) — drift
    would mean the wire accepts kinds the registry doesn't recognise.
    Pinned to detect a future change that copies the Literal locally
    instead of importing.
    """

    @pytest.mark.parametrize("kind", sorted(get_args(ModelKind)))
    def test_register_request_accepts_every_model_kind(self, kind: str) -> None:
        req = RegisterModelRequest(model_id="m", version="1", kind=kind)  # type: ignore[arg-type]
        assert req.kind == kind

    def test_register_request_refuses_unknown_kind(self) -> None:
        with pytest.raises(pydantic.ValidationError):
            RegisterModelRequest(
                model_id="m",
                version="1",
                kind="agentic",  # type: ignore[arg-type]
            )
