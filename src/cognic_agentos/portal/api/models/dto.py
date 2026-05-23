"""Sprint 9.5 B3 — Pydantic v2 request/response DTOs for the model
registry portal API.

Mirrors the discipline of :file:`portal/api/packs/dto.py`:

- :class:`ModelBaseModel` — frozen + ``extra="forbid"`` base class
  that every Sprint-9.5 model DTO inherits. ``frozen=True`` defends
  against handler-side mutation mid-request (confused-deputy bug
  class); ``extra="forbid"`` pins the wire-shape — no silent
  smuggling of extra fields through the request/response models.
- Response DTOs additionally set ``from_attributes=True`` so handlers
  pass loaded storage records (:class:`ModelRecord`,
  :class:`DecisionRecord`) directly to ``model_validate(...)`` without
  a dict-coercion step.

**No logic in this module.** DTOs are type-only — no store / route /
RBAC / cosign / validator logic lives here. The closed-enum vocabularies
this module exposes (:data:`PromoteTargetState`) are wire-protocol-public
but carry no decision logic; the registry's own
:data:`~cognic_agentos.models.registry.ModelKind` /
:data:`~cognic_agentos.models.registry.ModelLifecycleState` Literals
are re-used directly (single source of truth — no local copies).

Wire-protocol-public surface: every request body, every 200 response,
every 4xx response body shape from the model-registry route handlers
(B4 + B5) conforms to these DTO shapes. Drift is a wire-protocol
break; pinned exhaustively by
:file:`tests/unit/portal/api/models/test_dto.py`.

Field-set boundaries pinned by the test suite:

- :class:`RegisterModelRequest` — client-controllable register fields
  ONLY. ``tenant_id`` / ``lifecycle_state`` / ``last_actor`` / ``id`` /
  ``created_at`` / ``updated_at`` / ``eval_results_ref`` /
  ``adversarial_pass_rate`` are ALL deliberately absent (handler /
  storage / promotion-time assigns them).
- :class:`PromoteModelRequest` — 3 fields; ``target_state`` resolves
  to the RBAC scope ``model.promote.<target_state>`` at the route;
  ``eval_results_ref`` + ``adversarial_pass_rate`` are only used by
  the ``promote_tenant_approved`` transition.
- :class:`ModelResponse` — 1:1 with :class:`ModelRecord`'s 18-field
  set. No invented fields; no computed metadata.
- :class:`ModelLifecycleEventResponse` — strict subset of
  :class:`DecisionRecord`'s field set (5 of 10); omits ``actor_id``
  (always None for reconstructed records per A5 convention),
  ``trace_id`` / ``span_id`` / ``langfuse_trace_id`` /
  ``provider_label`` (None for model.lifecycle.* events).
- :class:`ModelDetailResponse` — composition of
  :class:`ModelResponse` + ``list[ModelLifecycleEventResponse]``.
"""

from __future__ import annotations

import datetime
import uuid
from typing import Any, Literal

import pydantic

from cognic_agentos.models.registry import ModelKind, ModelLifecycleState

#: The 4 target states accepted by ``POST /api/v1/models/{model_id}/promote``.
#: Strict subset of :data:`ModelLifecycleState` — ``proposed`` is
#: genesis-only (created by ``POST /api/v1/models`` = register) and
#: ``retired`` lives on the dedicated ``POST /api/v1/models/{model_id}/retire``
#: endpoint (separate ``model.retire`` RBAC scope). Resolved
#: body-aware in the B4 promote handler to the RBAC scope
#: ``model.promote.<target_state>``.
#:
#: Style note: plain ``= Literal[...]`` (no ``TypeAlias`` annotation)
#: to match the Sprint-7B.1+ repo convention.
PromoteTargetState = Literal[
    "eval_passed",
    "tenant_approved",
    "serving",
    "deprecated",
]


class ModelBaseModel(pydantic.BaseModel):
    """Frozen + ``extra="forbid"`` base for every Sprint 9.5 model DTO.

    ``frozen=True`` defends against handler-side mutation mid-request
    (confused-deputy bug class). ``extra="forbid"`` pins the wire-shape
    — every request body / response body's key set is exactly what the
    DTO declares; smuggled fields trip a 422 at validation time.
    """

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")


class RegisterModelRequest(ModelBaseModel):
    """POST ``/api/v1/models`` request body.

    Carries ONLY the client-controllable register-time fields. The
    handler is responsible for:

    - ``tenant_id`` (from the resolved :class:`Actor.tenant_id` —
      NEVER the client body, to prevent cross-tenant register-spoofing)
    - ``lifecycle_state`` (forced to ``"proposed"`` — genesis state
      per the A3 R1 P1 ``model_register_initial_state_not_proposed``
      gate)
    - ``last_actor`` (from :class:`Actor.subject`)
    - ``id`` (UUID minted at register time)
    - ``created_at`` / ``updated_at`` (datetime.now(UTC))

    ``eval_results_ref`` / ``adversarial_pass_rate`` are ABSENT — they
    are set at the ``promote_tenant_approved`` transition, not at
    register time.
    """

    model_id: str
    base_model: str | None = None
    version: str
    kind: ModelKind
    recipe_hash: str | None = None
    training_data_fingerprint: str | None = None
    signature_digest: str | None = None
    signed_artifact_ref: str | None = None
    sigstore_bundle_ref: str | None = None
    serving_endpoint: str | None = None


class PromoteModelRequest(ModelBaseModel):
    """POST ``/api/v1/models/{model_id}/promote`` request body.

    ``target_state`` is the only required field — it both selects the
    transition kind (``promote_eval_passed`` / ``promote_tenant_approved``
    / ``promote_serving`` / ``promote_deprecated``) AND drives the
    body-aware RBAC scope check (``model.promote.<target_state>``) at
    the handler.

    ``eval_results_ref`` + ``adversarial_pass_rate`` are required ONLY
    when ``target_state == "tenant_approved"`` (the
    storage-layer transition checks shape under the precondition lock
    and refuses with the closed-enum
    ``model_promote_eval_evidence_missing`` /
    ``..._malformed`` reasons). The wire-side
    ``Field(ge=0.0, le=1.0)`` constraint on ``adversarial_pass_rate``
    is defence-in-depth — out-of-range values fail validation at the
    422 boundary BEFORE reaching storage's own shape gate.
    """

    target_state: PromoteTargetState
    eval_results_ref: str | None = None
    adversarial_pass_rate: float | None = pydantic.Field(default=None, ge=0.0, le=1.0)


class ModelResponse(ModelBaseModel):
    """Response projection of :class:`ModelRecord`. 1:1 alignment with
    the 18-field storage row — no invented fields, no computed
    metadata.

    ``from_attributes=True`` lets handlers pass a loaded
    :class:`ModelRecord` directly to ``ModelResponse.model_validate(record)``
    without a dict-coercion step (Pydantic falls back to
    ``getattr(obj, field_name)`` per field).
    """

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid", from_attributes=True)

    id: uuid.UUID
    model_id: str
    tenant_id: str
    base_model: str | None
    version: str
    kind: ModelKind
    recipe_hash: str | None
    training_data_fingerprint: str | None
    eval_results_ref: str | None
    adversarial_pass_rate: float | None
    signature_digest: str | None
    signed_artifact_ref: str | None
    sigstore_bundle_ref: str | None
    serving_endpoint: str | None
    lifecycle_state: ModelLifecycleState
    last_actor: str
    created_at: datetime.datetime
    updated_at: datetime.datetime


class ModelLifecycleEventResponse(ModelBaseModel):
    """One ``model.lifecycle.*`` chain row projected onto the wire.

    Strict subset of :class:`DecisionRecord` (5 of 10 fields). Omits:

    - ``actor_id`` — always ``None`` for records reconstructed by
      :meth:`ModelRecordStore.load_lifecycle_history` (the actor
      identity lives in ``payload["actor_id"]`` via the Sprint-2
      canonical-form merge; reading it off ``DecisionRecord.actor_id``
      would always yield None).
    - ``trace_id`` / ``span_id`` / ``langfuse_trace_id`` /
      ``provider_label`` — Langfuse/OTel trace fields, ``None`` for
      ``model.lifecycle.*`` events (governance lifecycle is not an
      LLM call).

    ``from_attributes=True`` lets handlers pass a reconstructed
    :class:`DecisionRecord` directly to
    ``ModelLifecycleEventResponse.model_validate(record)``.
    """

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid", from_attributes=True)

    decision_type: str
    request_id: str
    tenant_id: str | None
    payload: dict[str, Any]
    iso_controls: tuple[str, ...]


class ModelDetailResponse(ModelBaseModel):
    """``GET /api/v1/models/{model_id}`` response body composition:

    - ``model`` — the latest :class:`ModelResponse` projection.
    - ``history`` — oldest-first list of every
      ``model.lifecycle.*`` chain row for the model, projected to
      :class:`ModelLifecycleEventResponse`.

    Mirrors :class:`PackDetailResponse` from
    :file:`portal/api/packs/dto.py`. Inherits ``frozen=True`` +
    ``extra="forbid"`` from :class:`ModelBaseModel`.
    """

    model: ModelResponse
    history: list[ModelLifecycleEventResponse]


__all__ = [
    "ModelBaseModel",
    "ModelDetailResponse",
    "ModelLifecycleEventResponse",
    "ModelResponse",
    "PromoteModelRequest",
    "PromoteTargetState",
    "RegisterModelRequest",
]
