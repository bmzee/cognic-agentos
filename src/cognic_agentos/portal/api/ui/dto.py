"""Sprint-7B.4 T9 — Action DTOs + closed-enum Literals (pure type-only).

Public wire-types for the POST /api/v1/ui/actions surface per ADR-020
+ design spec §4.4a. Pydantic v2 frozen + extra=forbid throughout;
discriminated union on ``action_class``; mode/payload parity for the
``submit_elicitation`` class enforced via ``@model_validator(mode="after")``
so ill-formed requests refuse at Pydantic-parse time (HTTP 422) BEFORE
any chain row is appended.

**P1 #2 SCOPE LOCK (per the design spec):** this module is pure
type-only. No FastAPI / Starlette / sse_starlette / broker / RBAC
runtime imports. `RequireUIAction` (FastAPI dep + broker-coupled +
RBAC-coupled) lives in :file:`action_routes.py` (T11), NOT here.
:class:`UIActionContext` is declared HERE because T11's
``RequireUIAction`` returns it — but the dataclass itself carries
NO runtime imports (the ``actor: Actor`` annotation is a string-only
forward reference under ``TYPE_CHECKING``).

**Closed-enum vocabulary:** :data:`ActionClass` (6) +
:data:`ActionOutcome` (2) + :data:`ActionRejectionReason` (10). The
last one is held lockstep with the parallel Literal at
:data:`portal.api.ui.elicitation_gate.ActionRejectionReason` by the
test-only drift detector at
:file:`tests/unit/portal/api/ui/test_dto_action.py
::TestActionRejectionReasonCrossModuleEquality` (per the
user-locked feedback_drift_detector_test_only_no_runtime_import
doctrine — no runtime cross-module import enforces equality; each
module declares its own local copy + test imports both).
"""

from __future__ import annotations

import dataclasses
from datetime import datetime
from typing import TYPE_CHECKING, Annotated, Any, Literal

import pydantic
from pydantic import Field, model_validator

if TYPE_CHECKING:
    # Forward-only — TYPE_CHECKING import is string-resolved by
    # Pydantic + mypy without runtime evaluation. Keeps dto.py free of
    # the portal/rbac runtime arrow.
    from cognic_agentos.portal.rbac.actor import Actor


#: 6-value closed-enum of action verbs the POST /api/v1/ui/actions
#: surface accepts. Wire-protocol-public per ADR-020 + AGENTS.md
#: "Wire-protocol contracts" stop rule — drift breaks every UI client
#: consuming the action surface.
ActionClass = Literal[
    "approve",
    "deny",
    "cancel_run",
    "interrupt",
    "resume",
    "submit_elicitation",
]


#: 2-value closed-enum of outcomes the action handler emits onto the
#: response body + the ``frontend_action.{accepted,rejected}`` chain
#: row's family.type discriminator.
ActionOutcome = Literal["accepted", "rejected"]


#: 10-value closed-enum of rejection reasons. Wire-protocol-public —
#: published on:
#:
#:   - ``ActionResponse.reason`` field (T11 HTTP refusal body)
#:   - ``frontend_action.rejected`` chain row's ``payload.reason``
#:
#: MUST stay lockstep with the parallel Literal at
#: :data:`portal.api.ui.elicitation_gate.ActionRejectionReason`.
#: Pinned by ``test_dto_action.py::TestActionRejectionReasonCrossModuleEquality``.
#:
#: Split between gate-emitted (6 reasons) + handler-emitted (4 reasons):
#:
#:   Emitted by T8 elicitation_gate (the 5-step gate body):
#:     ``elicitation_backend_unwired`` (Step 1)
#:     ``elicitation_unknown_id`` (Step 2)
#:     ``elicitation_mode_not_permitted`` (Step 3)
#:     ``elicitation_restricted_data_class`` (Step 4)
#:     ``elicitation_unwired_evaluator`` (Step 5)
#:     ``elicitation_rego_denied`` (Step 5)
#:
#:   Emitted by T11 action_routes (the dispatch handler):
#:     ``elicitation_backend_failed`` (adapter.handle_submission raised
#:       AFTER the gate passed)
#:     ``action_backend_deferred_to_sprint_13_5`` (approve / deny stubs)
#:     ``action_backend_deferred_no_run_primitive`` (cancel_run /
#:       interrupt / resume — no agent_run primitive in Wave 1; the
#:       resume arm joined at Sprint 8.5 T11)
#:     ``action_backend_deferred_sandbox_unwired`` — RESERVED, currently
#:       UNMAPPED. Sprint 7B.4 mapped ``resume`` here; Sprint 8.5 T11
#:       remapped ``resume`` to ``action_backend_deferred_no_run_primitive``
#:       (the honest blocker is the missing run→session identity seam,
#:       not an unwired sandbox). Retained in the wire-public enum —
#:       removing it is a separate enum-shrink wire decision.
ActionRejectionReason = Literal[
    "action_backend_deferred_to_sprint_13_5",
    "action_backend_deferred_no_run_primitive",
    "action_backend_deferred_sandbox_unwired",
    "elicitation_mode_not_permitted",
    "elicitation_restricted_data_class",
    "elicitation_rego_denied",
    "elicitation_unwired_evaluator",
    "elicitation_backend_failed",
    "elicitation_backend_unwired",
    "elicitation_unknown_id",
]


class PackBaseModel(pydantic.BaseModel):
    """Frozen + extra=forbid base for all UI DTOs.

    Mirrors :class:`portal.api.packs.dto.PackBaseModel` (Sprint 7B.2 T3
    precedent). Frozen so the discriminated-union request bodies stay
    immutable between Pydantic parse + the T11 action handler's chain
    emit; extra=forbid so a bank-overlay client cannot smuggle unknown
    fields through the body without an explicit kernel update.

    Naming note: the class name ``PackBaseModel`` matches the
    pre-existing packs-module precedent; semantically it's a generic
    portal-DTO base. Kept as-is for naming-symmetry across the two
    DTO modules.
    """

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")


class _BaseActionRequest(PackBaseModel):
    """Common fields shared across the 6 per-class action requests."""

    action_class: ActionClass
    client_correlation_id: str | None = Field(default=None, max_length=64)


class ApproveActionRequest(_BaseActionRequest):
    """``action_class="approve"`` — grants a pending approval. The T11
    handler routes to the (deferred-stub) approval-backend dispatch."""

    action_class: Literal["approve"] = "approve"
    approval_id: str
    decision: Literal["grant", "grant_second"]


class DenyActionRequest(_BaseActionRequest):
    """``action_class="deny"`` — denies a pending approval."""

    action_class: Literal["deny"] = "deny"
    approval_id: str
    reason: str | None = None


class CancelRunActionRequest(_BaseActionRequest):
    """``action_class="cancel_run"`` — cancels an in-flight agent run.
    Wired at Sprint-11.5 when the agent_run primitive lands; T11
    handler emits the deferred-stub reason until then."""

    action_class: Literal["cancel_run"] = "cancel_run"
    run_id: str
    reason: str | None = None


class InterruptActionRequest(_BaseActionRequest):
    """``action_class="interrupt"`` — interrupts an in-flight agent
    run + optionally injects a message. Sprint-11.5 wires this; T11
    handler emits the deferred-stub reason until then."""

    action_class: Literal["interrupt"] = "interrupt"
    run_id: str
    message_to_agent: str | None = None


class ResumeActionRequest(_BaseActionRequest):
    """``action_class="resume"`` — resumes a suspended agent run by
    ``run_id``, with an optional ``payload``.

    Sprint 8.5 ships the sandbox ``wake()`` primitive, but the planned
    ``resume`` → ``wake()`` lift was rejected at the Sprint-8.5 T11
    review: ``run_id`` is an application/run identifier while
    ``wake()`` keys on a sandbox ``session_id``, and Wave 1 has no
    agent_run primitive to resolve one to the other. The T11 handler
    therefore keeps emitting a deferred-stub reason —
    ``action_backend_deferred_no_run_primitive`` (NOT the now-false
    ``action_backend_deferred_sandbox_unwired``). ``payload`` is
    accepted on the wire but not yet routed. The resumable-run UX
    lands with the Sprint 13.5 approval engine."""

    action_class: Literal["resume"] = "resume"
    run_id: str
    payload: dict[str, Any] | None = None


class SubmitElicitationActionRequest(_BaseActionRequest):
    """``action_class="submit_elicitation"`` — submits the user's
    completion of an elicitation requested by an agent. Body shape +
    parity enforced by the @model_validator below.

    Routed through the T8 elicitation_gate at the T11 handler;
    on green-path → ``adapter.handle_submission(...)``; on refusal →
    ``ActionResponse(outcome="rejected", reason=<gate refusal>)``.
    """

    action_class: Literal["submit_elicitation"] = "submit_elicitation"
    elicitation_id: str
    mode: Literal["url", "form"]
    url_completion_signal: dict[str, Any] | None = None
    form_payload: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _enforce_payload_matches_mode(self) -> SubmitElicitationActionRequest:
        """P2 LOCK from the design spec — exact mode/payload parity
        at Pydantic-parse time → 422 → NO chain row appended for
        ill-formed requests. Each branch raises a distinct, regex-
        matchable message so test assertions can pin the specific
        failure mode (form-without-form_payload / form-with-url_signal /
        url-without-completion_signal / url-with-form_payload)."""
        if self.mode == "form":
            if self.form_payload is None:
                raise ValueError("mode='form' requires form_payload")
            if self.url_completion_signal is not None:
                raise ValueError("mode='form' must not include url_completion_signal")
        else:  # mode == "url"
            if self.url_completion_signal is None:
                raise ValueError("mode='url' requires url_completion_signal")
            if self.form_payload is not None:
                raise ValueError("mode='url' must not include form_payload")
        return self


#: Discriminated union over the 6 per-class request DTOs. Pydantic v2
#: ``Field(discriminator="action_class")`` resolves the body to the
#: correct DTO at parse time; unknown ``action_class`` values reject
#: with 422 before any handler logic runs.
ActionRequest = Annotated[
    ApproveActionRequest
    | DenyActionRequest
    | CancelRunActionRequest
    | InterruptActionRequest
    | ResumeActionRequest
    | SubmitElicitationActionRequest,
    Field(discriminator="action_class"),
]


class ActionResponse(PackBaseModel):
    """POST /api/v1/ui/actions response body per spec §4.4a.

    Wire-protocol-public:
      - ``request_id`` — the portal-req-<uuid4.hex> minted by the T6
        portal middleware (operators correlate by this)
      - ``action_class`` — echoed from the request for client-side
        rendering
      - ``outcome`` — ``accepted`` or ``rejected``
      - ``reason`` — ``None`` on accepted; ``ActionRejectionReason``
        on rejected
      - ``submitted_at`` — UTC timestamp of the submit chain row
      - ``submitted_event_id`` — deterministic cursor for the
        ``frontend_action.submitted`` typed event (T4 broker's
        AppendResult.event_id); UIs use this to reconcile the
        optimistic-submit state with the SSE stream
      - ``resolution_event_id`` — deterministic cursor for the
        ``frontend_action.{accepted,rejected}`` resolution event;
        ``None`` only in the pre-rejected case (validation failure
        before the resolution row is appended)
      - ``client_correlation_id`` — echoed from request for client-
        side reconciliation
    """

    request_id: str
    action_class: ActionClass
    outcome: ActionOutcome
    reason: ActionRejectionReason | None
    submitted_at: datetime
    submitted_event_id: str
    resolution_event_id: str | None
    client_correlation_id: str | None


@dataclasses.dataclass(frozen=True)
class UIActionContext:
    """Returned by T11's ``RequireUIAction`` FastAPI dependency.

    Declared HERE (in the type-only DTO module) so T11's
    :file:`action_routes.py` can return it without ``action_routes``
    re-exporting it. The dataclass itself is type-only — no FastAPI /
    broker imports; the ``actor: Actor`` annotation is a string-only
    forward reference resolved via TYPE_CHECKING.

    Frozen so the action handler can pass the same context value
    through the chain-row append path without aliasing risk.
    """

    body: ActionRequest
    actor: Actor
    request_id: str


__all__ = [
    "ActionClass",
    "ActionOutcome",
    "ActionRejectionReason",
    "ActionRequest",
    "ActionResponse",
    "ApproveActionRequest",
    "CancelRunActionRequest",
    "DenyActionRequest",
    "InterruptActionRequest",
    "PackBaseModel",
    "ResumeActionRequest",
    "SubmitElicitationActionRequest",
    "UIActionContext",
]
