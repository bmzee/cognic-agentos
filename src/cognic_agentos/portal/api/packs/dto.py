"""Sprint 7B.2 T3 — Pack-API Pydantic DTOs.

Logic-free Pydantic v2 wire-shape definitions consumed by every T4-T7
pack endpoint. T3 ships:

- :class:`PackBaseModel` — frozen + ``extra="forbid"`` base class that
  every endpoint-specific DTO in T4-T7 inherits. Mirrors the
  :class:`~cognic_agentos.portal.rbac.actor.Actor` model-config at
  ``portal/rbac/actor.py:68``.
- :class:`PackResponse` — read-only projection of a
  :class:`~cognic_agentos.packs.storage.PackRecord`. Used by every
  pack-list / pack-detail endpoint that surfaces a single record.

The two SHA-256 digests (``manifest_digest`` / ``signed_artefact_digest``)
are deliberately EXCLUDED from :class:`PackResponse` — they are
admin-only fields surfaced through the inspection-tier endpoints at
T7 only (per the plan-of-record's ``inspection_routes.py``). The
default view is intentionally narrow to keep cross-tenant attackers
from harvesting cryptographic-signature material via the standard read
surfaces.

Style note: plain ``= Literal[...]`` would be re-exported here rather
than introduced fresh, but :data:`PackKind` and :data:`PackState`
already live at ``packs/lifecycle.py:111``/``:116`` and DTOs use them
directly via import. Mirrors the Sprint-7B.1 convention.
"""

from __future__ import annotations

import datetime
import uuid
from typing import Annotated, Any, Literal

import pydantic

from cognic_agentos.packs.approval_gates import (
    ApprovalGateName,
    ApprovalGateOutcome,
    ApprovalGateRedReason,
    OverrideRefusalReason,
)
from cognic_agentos.packs.approval_types import ApprovalOverrideReason
from cognic_agentos.packs.evidence.conformance_matrix import MatrixComparisonFlag
from cognic_agentos.packs.evidence.data_governance import DataGovernanceDiffFlag
from cognic_agentos.packs.evidence.risk_tier import ApprovalFlowKind
from cognic_agentos.packs.lifecycle import PackKind, PackState

# Note: :data:`AttestationKind` is intentionally NOT imported here even
# though the :class:`SupplyChainPanel` DTO is wire-protocol-public for
# that vocabulary. The DTO surfaces each attestation kind as a NAMED
# field (``slsa_level_declared`` / ``sbom_path_declared`` / …) rather
# than a flat ``dict[AttestationKind, ...]`` field, so the closed-enum
# Literal never appears in a field annotation. The Literal lives at
# the projector module + the drift detector at
# ``tests/unit/portal/api/packs/test_dto_t5_supply_chain_panel.py``
# pins lockstep between the field set and the projector dataclass.


class PackBaseModel(pydantic.BaseModel):
    """Frozen + ``extra="forbid"`` base for every Sprint 7B.2 pack DTO.

    ``frozen=True`` defends against handler-side mutation mid-request
    (confused-deputy bug class); ``extra="forbid"`` pins the wire-shape
    so a bank-overlay extension cannot smuggle unmodelled fields
    through. Every field added to a subclass is a deliberate
    wire-protocol decision.

    Subclassed by every endpoint-specific request/response DTO landing
    in T4-T7.
    """

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")


class PackResponse(PackBaseModel):
    """Default public-surface view of a
    :class:`~cognic_agentos.packs.storage.PackRecord`.

    Field set mirrors :class:`PackRecord` at ``packs/storage.py:352-379``
    minus the two SHA-256 digests (``manifest_digest`` /
    ``signed_artefact_digest``). The narrower projection keeps
    cryptographic-signature material off the default read surface;
    inspection-tier endpoints (T7) extend with a dedicated DTO that
    includes the digests under the ``pack.audit.read`` scope.

    The :data:`PackKind` and :data:`PackState` fields carry the same
    closed-enum constraints as the Sprint-7B.1 source-of-truth Literals
    at ``packs/lifecycle.py:111``/``:116`` — out-of-vocab values refuse
    at Pydantic validation time.

    ``from_attributes=True`` (T3-R1 P3 closure): :class:`PackResponse`
    accepts both dict-shaped input AND attribute-bearing objects (i.e.
    real :class:`PackRecord` instances). Pydantic v2's
    ``from_attributes`` falls back to ``getattr(obj, field_name)`` per
    declared field — fields the DTO does not declare (the two digests)
    are simply not read, so the ``extra="forbid"`` invariant inherited
    from :class:`PackBaseModel` is preserved while T4-T7 route authors
    can pass a freshly-loaded :class:`PackRecord` directly to
    ``PackResponse.model_validate`` without an intermediate
    ``model_dump`` conversion. Override scoped to :class:`PackResponse`
    only — sibling DTOs that take wire-input (T4-T7 request bodies)
    keep the strict dict-only contract from :class:`PackBaseModel`.
    """

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid", from_attributes=True)

    id: uuid.UUID
    kind: PackKind
    pack_id: str
    display_name: str
    state: PackState
    tenant_id: str | None
    created_by: str
    last_actor: str
    created_at: datetime.datetime
    updated_at: datetime.datetime


# ---------------------------------------------------------------------------
# Sprint 7B.2 T5 — RejectionReason 7-value closed-enum vocabulary
# (Plan Round 11 P2 #2 — anchored to ADR-012 §41 5-gate composition +
# operational categories + free-form fallback)
# ---------------------------------------------------------------------------

#: Plan Round 11 P2 #2 — closed-enum vocabulary carried on
#: :class:`RejectDraftRequest` bodies AND on the T5 reject-handler
#: structured-log ``extra["reason"]`` field. Wire-protocol-public; any
#: change is a wire-protocol break.
#:
#: 7 values anchored to ADR-012 §41's 5-gate composition + 2 operational
#: categories:
#:
#: - ``signature_invalid`` — cosign / SLSA failure (gate 1)
#: - ``evaluation_pass_rate_below_threshold`` — ADR-010 eval harness red (gate 2)
#: - ``adversarial_corpus_pass_rate_below_threshold`` — ADR-011 adversarial red (gate 3)
#: - ``owasp_conformance_red`` — ADR-012 §41 OWASP gate red (gate 4)
#: - ``data_governance_unfit`` — ADR-017 data-class / purpose mismatch
#: - ``documentation_incomplete`` — operational; manifest fields incomplete
#: - ``other`` — free-form fallback; ``comments`` IS the diagnostic
#:
#: Style note: plain ``= Literal[...]`` (no ``TypeAlias`` annotation) to
#: match the Sprint-7B.1 repo convention at ``packs/lifecycle.py:111``.
RejectionReason = Literal[
    "signature_invalid",
    "evaluation_pass_rate_below_threshold",
    "adversarial_corpus_pass_rate_below_threshold",
    "owasp_conformance_red",
    "data_governance_unfit",
    "documentation_incomplete",
    "other",
]


# ---------------------------------------------------------------------------
# Sprint 7B.2 T5 — RejectDraftRequest body schema
# (Plan Round 11 P2 #2 + Round 11 P2 #3 — bare-transition + structured-log
# in T5; T9 carry-forward attaches `{rejection_reason, reviewer_comments}`
# to the chain row via `evidence_attachments`)
# ---------------------------------------------------------------------------


class RejectDraftRequest(PackBaseModel):
    """POST ``/api/v1/packs/{pack_id}/reject`` request body.

    Plan Round 11 P2 #2 + Round 11 P2 #3:
    - ``reason``: closed-enum :data:`RejectionReason` (7 values).
    - ``comments``: required non-empty string; carries the reviewer's
      free-form diagnostic. When ``reason == "other"`` the comments
      field IS the evidence (no other semantic content on the reason).

    T5 ships reject as a bare transition + structured-log only emission
    of these fields (per Round 11 P2 #3); T9 carry-forward amends the
    reject handler to persist
    ``{"rejection_reason": body.reason, "reviewer_comments": body.comments}``
    to the chain row via ``evidence_attachments``. The DTO schema is
    stable across T5 + T9 (T9 changes the storage payload, not the
    wire-input shape).

    Inherits :class:`PackBaseModel`'s ``frozen=True`` + ``extra="forbid"``
    so smuggled fields refuse at validation; downstream handler cannot
    mutate the body mid-request.
    """

    reason: RejectionReason
    comments: Annotated[str, pydantic.Field(min_length=1)]

    @pydantic.model_validator(mode="after")
    def _refuse_other_reason_with_empty_comments(self) -> RejectDraftRequest:
        """Plan Round 11 P2 #2 — when ``reason == "other"`` the
        ``comments`` field IS the free-form diagnostic and MUST be
        non-empty. The ``Field(min_length=1)`` constraint already
        rejects empty strings for ALL reasons; this validator is a
        cross-axis guard so a future relaxation of the field
        constraint cannot silently undermine the ``other`` evidence
        contract.

        Pinned by ``test_refuses_other_reason_without_comments`` at
        ``tests/unit/portal/api/packs/test_router_scaffolding.py``.
        """
        if self.reason == "other" and not self.comments.strip():
            raise ValueError(
                "comments MUST be non-empty when reason == 'other'; the "
                "'other' value carries no semantic content of its own "
                "and the free-form comments are the evidence surface"
            )
        return self


# ---------------------------------------------------------------------------
# Sprint 7B.2 T9 — SubmitDraftRequest request schema
# (Plan §1183-1234 — POST /api/v1/packs/drafts/{pack_id}/submit body)
# ---------------------------------------------------------------------------


class SubmitDraftRequest(PackBaseModel):
    """POST ``/api/v1/packs/drafts/{pack_id}/submit`` request body
    (Sprint 7B.2 T9).

    Author / SDK / CLI sends the manifest dict as JSON; the route
    computes ``sha256(canonical_bytes(body.manifest))`` and cross-checks
    against the persisted ``packs.manifest_digest`` column (cheap pre-
    check) + threads ``expected_manifest_digest=record.manifest_digest``
    into the storage transition so the in-precondition cross-check
    closes the TOCTOU window per plan §1179-1181.

    The manifest dict is also fed to
    :func:`run_owasp_conformance_for_chain_payload` so the chain row's
    ``payload.conformance`` carries the OWASP suite result as evidence
    (non-gating per BUILD_PLAN §627; the actual gate composition is 7B.3).

    Inherits :class:`PackBaseModel`'s ``frozen=True`` + ``extra="forbid"``
    so smuggled top-level fields refuse at validation.  The ``manifest``
    field itself is intentionally typed as ``dict[str, Any]`` (NOT a
    closed Pydantic schema) — the manifest's internal shape is validated
    by the OWASP conformance check matrix + the build-time CLI
    validators; pinning a closed Pydantic schema here would re-implement
    that validation surface twice.

    Sprint 7B.3 T2 (R6 P2 #4 + R8 P2 #4) — NEW REQUIRED field
    ``signed_artefact_root: str``. The submit-declared absolute path
    to the signed-bundle directory on the approve-time host (R8 P2 #4
    — submit-declared at the author surface, NOT operator-declared).
    Pydantic validator refuses relative paths + empty strings +
    path-traversal ``..`` segments at request-body parse time → **422
    Unprocessable Entity** before any storage call (R-reviewer-round
    P2 #2 wire-status alignment — FastAPI's native ValidationError
    handler surfaces 422, matching the rest of the author route's
    body-validation doctrine; earlier draft incorrectly claimed 400).
    The approve handler reads this from the persisted
    ``payload["signed_artefact_root"]`` chain payload key via
    :func:`find_latest_submit_row` + passes to the signature path
    resolver to produce absolute cosign verification paths.
    """

    manifest: dict[str, Any]
    signed_artefact_root: str

    @pydantic.field_validator("signed_artefact_root")
    @classmethod
    def _validate_signed_artefact_root(cls, value: str) -> str:
        """Sprint 7B.3 T2 Slice D — R6 P2 #4 + R8 P2 #4 validation.

        Enforces three invariants at request-body parse time:

        1. Non-empty — empty string would let a misbehaving author
           pretend the bundle root exists at the empty path.
        2. Absolute — at approve time the handler has no base for
           relative-path resolution; relative paths cannot reach the
           cosign verifier (R5 P2 #3 doctrine, locked at R6).
        3. Path-traversal-safe — no ``..`` segments. Defense in depth
           alongside the resolver's traversal red-reasons.

        Per the FastAPI convention, Pydantic validators raise
        ``ValueError`` which Pydantic re-wraps into ``ValidationError``
        + FastAPI surfaces as 422 Unprocessable Entity (R-reviewer-round
        P2 #2 wire-status doctrine — the route does NOT map this to
        400 downstream; 422 IS the wire contract for request-body
        validation failures, matching the rest of the author route's
        existing validation surface). The validator's job is to refuse
        the value before any handler body runs.
        """
        # Invariant 1 — non-empty.
        if not value or not value.strip():
            raise ValueError("signed_artefact_root must be a non-empty string")
        # Invariant 2 — absolute path. Per POSIX convention, absolute
        # paths start with "/". Windows absolute paths (e.g. C:\) are
        # not currently supported; banks deploying on Windows host
        # operators would need to pre-mount POSIX-rooted volumes.
        if not value.startswith("/"):
            raise ValueError(
                "signed_artefact_root must be an absolute path "
                f"(received {value!r}); relative paths cannot be "
                "resolved at approve time per R5 P2 #3 + R6 P2 #4 "
                "doctrine."
            )
        # Invariant 3 — no path-traversal segments. Reject ``..``
        # anywhere in the path (defense in depth alongside the
        # resolver's signature_path_traversal_rejected codes).
        # Split on "/" and look for an exact ".." segment so values
        # like "/foo/..bar/baz" (legitimate filename with leading
        # dots) are NOT mis-rejected.
        segments = value.split("/")
        if ".." in segments:
            raise ValueError(
                "signed_artefact_root must not contain '..' path-traversal "
                f"segments (received {value!r})."
            )
        return value


# ---------------------------------------------------------------------------
# Sprint 7B.2 T5 — PackEvidenceResponse response schema
# (Plan Round 11 P3 #5 — GET /api/v1/packs/{pack_id}/evidence)
# ---------------------------------------------------------------------------


class PackEvidenceResponse(PackBaseModel):
    """GET ``/api/v1/packs/{pack_id}/evidence`` response body.

    Plan Round 11 P3 #5 — two-field shape exposing the T9
    auto-run-on-submit conformance evidence + a placeholder for the
    7B.3 reviewer evidence panels (always-null literal in 7B.2).

    Read-path:
    - Walk :meth:`PackRecordStore.load_lifecycle_history` for the pack.
    - Find the most-recent ``event_type == "pack.lifecycle.submitted"`` row.
    - Surface its ``payload.get("conformance")`` value on the
      ``conformance`` field.

    Sprint 7B.2 T9 Slice 2 wired auto-run-on-submit, so T9-era submit
    chain rows carry the 4-key runner payload (``overall_status`` /
    ``results`` / ``summary`` / ``errored_categories``) per
    :func:`~cognic_agentos.packs.conformance.runner.run_owasp_conformance_for_chain_payload`'s
    wire-shape contract.  Historical / pre-T9 submit chain rows
    (fixtures or rows created by the T5-era submit handler before
    Slice 2 landed) have no ``conformance`` key — the endpoint
    surfaces ``None`` for those rows gracefully (NOT 500); both shapes
    coexist via this schema, and the test surface pins both the
    historical-null path AND the T9-populated path.
    ``reviewer_evidence_panels`` stays literal-``None`` in 7B.2;
    7B.3 fills it with the full evidence-panel object once the 5-gate
    composition lands.

    Fields:
    - ``conformance: dict[str, Any] | None`` — populated when T9
      auto-run-on-submit has attached evidence; ``None`` otherwise.
    - ``reviewer_evidence_panels: None`` — literal-typed at ``None``
      in 7B.2; 7B.3 will widen this field to the full evidence-panel
      object. The literal-typed-at-``None`` constraint pins the
      always-null contract so a 7B.2 caller cannot silently surface a
      non-null value through this field; pinned by
      ``test_reviewer_evidence_panels_only_accepts_none`` at
      ``tests/unit/portal/api/packs/test_router_scaffolding.py``.
    """

    conformance: dict[str, Any] | None
    reviewer_evidence_panels: None


# ---------------------------------------------------------------------------
# Sprint 7B.2 T7 — inspection-surface response schemas
# (Plan §998 + §999 + §1000 — detail / audit / invocations)
# ---------------------------------------------------------------------------


class PackLifecycleEventResponse(PackBaseModel):
    """Projection of a :class:`~cognic_agentos.core.decision_history.DecisionRecord`
    row for inspection-surface responses (detail.history + audit +
    invocations endpoints share this shape).

    ``from_attributes=True`` (mirrors :class:`PackResponse` at T3) so
    handlers can pass loaded :class:`DecisionRecord` instances directly
    to ``model_validate`` without an intermediate ``dataclasses.asdict``
    conversion. Field set mirrors :class:`DecisionRecord` at
    ``core/decision_history.py:240-249`` minus the trace/span/langfuse
    correlation fields (those are observability-surface concerns and
    not part of the bank-facing audit DTO at Sprint 7B.2).

    The ``sequence`` column on the underlying ``decision_history`` row
    is deliberately NOT projected — :class:`DecisionRecord` itself
    does not carry it (the column is selected only for ``ORDER BY``
    inside :meth:`~cognic_agentos.packs.storage.PackRecordStore.load_lifecycle_history`).
    Adding sequence to the wire shape would require extending the
    canonical decision-history dataclass — a CC-ADJ change on
    ``core/decision_history.py`` deferred beyond Sprint 7B.2 T7.

    ``iso_controls`` accepts both the source-side ``tuple[str, ...]``
    representation and a wire-side ``list[str]`` — Pydantic v2 coerces
    tuples to lists at validation time so the JSON-serialised wire
    shape stays uniform.
    """

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid", from_attributes=True)

    decision_type: str
    request_id: str
    payload: dict[str, Any]
    tenant_id: str | None
    iso_controls: list[str]


class PackDetailResponse(PackBaseModel):
    """GET ``/api/v1/packs/{pack_id}`` response body.

    Plan §998 — "Pack detail incl. lifecycle history (read from
    packs/storage's state cache)". The response composes TWO data
    sources:

    - ``pack``: :class:`PackResponse` projection of the
      :class:`~cognic_agentos.packs.storage.PackRecord` returned by
      the :class:`~cognic_agentos.portal.rbac.tenant_isolation.RequireTenantOwnership`
      dependency (no second ``store.load`` call — the dependency
      already loaded + tenant-checked the row).
    - ``history``: walk of
      :meth:`~cognic_agentos.packs.storage.PackRecordStore.load_lifecycle_history`
      projected through :class:`PackLifecycleEventResponse`.

    The two-key composite (NOT a flat extension of
    :class:`PackResponse`) keeps the detail-surface and list-surface
    wire shapes orthogonal — a future detail-only field cannot
    accidentally leak into the list endpoint's
    :class:`PackResponse` projection.
    """

    pack: PackResponse
    history: list[PackLifecycleEventResponse]


# ---------------------------------------------------------------------------
# Sprint 7B.3 T2 Slice D — ReviewerAcknowledgement + ApproveRequest
# (R1 P2 #1 reviewer-ack DTO + R5 P2 #1 neutral-domain vocab import)
# ---------------------------------------------------------------------------


class ReviewerAcknowledgement(PackBaseModel):
    """Sprint 7B.3 — server-side reviewer-acknowledgement panel-ack model.

    4 booleans, one per reviewer evidence panel (T3-T6). Each reviewer
    MUST explicitly flip the corresponding flag to True before the
    5-gate composer's gate 5 will return green. The 5-gate composer
    (T7) reads this model's values via :class:`ApproveRequest`.

    Plan default per R10 LOCK #4: signature is the ONLY non-overridable
    gate per ADR-012 §110 literal; reviewer-acknowledgement CAN be
    skipped via the override path. The override chain event's
    ``gate_composition_snapshot`` records the ack state at override
    time so examiners see WHICH panels were unchecked when the
    override fired.

    Inherits :class:`PackBaseModel`'s ``frozen=True`` + ``extra="forbid"``
    so smuggled fields (e.g. a 5th panel ack) refuse at validation.
    Defaults all False — reviewer makes explicit affirmative choices
    per ADR-012 §38 (audit trail: which panels did the reviewer
    actually look at before approving).
    """

    data_governance_acknowledged: bool = False
    risk_tier_acknowledged: bool = False
    supply_chain_acknowledged: bool = False
    conformance_acknowledged: bool = False


class ApproveRequest(PackBaseModel):
    """Sprint 7B.3 — POST ``/api/v1/packs/{pack_id}/approve`` request body.

    Carries the reviewer's panel-ack values + optional override reason
    when invoking the override path. Replaces the T5 503-stub's empty
    body model at ``review_routes.py:271+``.

    Per R5 P2 #1 doctrinal fix: :data:`ApprovalOverrideReason` is
    imported from :mod:`cognic_agentos.packs.approval_types` (neutral
    domain vocabulary module). The portal DTO consumes the vocab; the
    architectural arrow ``portal → packs`` is preserved.

    Per R10 LOCK #4: ``override_reason is None`` → green-path approval
    (every gate must return green); ``override_reason is not None`` →
    override path (signature still non-overridable per ADR-012 §110;
    other 4 gates may be red).

    Inherits :class:`PackBaseModel`'s ``frozen=True`` + ``extra="forbid"``.
    """

    acknowledgement: ReviewerAcknowledgement
    override_reason: ApprovalOverrideReason | None = None


class ApproveGateResult(PackBaseModel):
    """Sprint 7B.3 T9 — one gate's result inside :class:`ApproveRefusalResponse`.

    Wire projection of
    :class:`~cognic_agentos.packs.approval_gates.ApprovalGateResult`
    (a frozen domain dataclass). Field set + order match the per-gate
    dicts :func:`~cognic_agentos.packs.approval_gates.composition_snapshot`
    emits, so the handler builds the 412 body straight from the
    snapshot with no intermediate massaging.

    Architectural-arrow invariant: this DTO consumes the composer's
    closed-enum vocabularies (``portal → packs``); the composer never
    imports portal.
    """

    gate: ApprovalGateName
    outcome: ApprovalGateOutcome
    red_reason: ApprovalGateRedReason | None
    evidence_pointer: str | None


class ApproveRefusalResponse(PackBaseModel):
    """Sprint 7B.3 T9 — ``POST /{pack_id}/approve`` **412** refusal body.

    Returned when the 5-gate composition is NOT all-green (plan §518 +
    §522). The first four fields are the EXACT shape
    :func:`~cognic_agentos.packs.approval_gates.composition_snapshot`
    emits — the handler does ``ApproveRefusalResponse(**composition_snapshot(
    composition), override_refusal_reason=...)``:

    - ``pack_kind`` / ``gates`` / ``all_green`` / ``non_overridable_red_gates``
      — the red-state gate composition payload so the reviewer UI can
      render WHICH gates blocked approval.
    - ``override_refusal_reason`` — ``None`` on the plain
      not-all-green-no-override 412; carries the closed-enum
      :data:`~cognic_agentos.packs.approval_gates.OverrideRefusalReason`
      on the override-attempted-but-refused 412 branch (e.g.
      ``non_overridable_red_gate`` when gate 1 is red, or
      ``override_scope_not_held``).

    The handler raises ``HTTPException(status_code=412,
    detail=ApproveRefusalResponse(...).model_dump())`` — the DTO is the
    wire-shape contract for that detail body.
    """

    pack_kind: PackKind
    gates: list[ApproveGateResult]
    all_green: bool
    non_overridable_red_gates: list[ApprovalGateName]
    override_refusal_reason: OverrideRefusalReason | None = None


# ---------------------------------------------------------------------------
# Sprint 7B.3 T3 — DataGovernancePanel response DTO
# (Plan §302 — GET /api/v1/packs/{pack_id}/evidence/data-governance)
# ---------------------------------------------------------------------------


class DataGovernancePanel(PackBaseModel):
    """Sprint 7B.3 T3 — GET ``/api/v1/packs/{pack_id}/evidence/data-governance``
    response body per plan §302.

    Wire-shape projection of a pack's persisted manifest's
    ``data_governance`` block per ADR-017. The route handler at
    :mod:`cognic_agentos.portal.api.packs.evidence_routes` fetches the
    persisted manifest via :func:`find_latest_submit_row` +
    ``payload["manifest"]`` and feeds it through
    :func:`cognic_agentos.packs.evidence.data_governance.project_data_governance_panel`
    to produce the :class:`DataGovernancePanelData` projector output,
    then ``DataGovernancePanel.model_validate(panel_data)`` projects
    onto this wire shape via ``from_attributes=True``.

    Architectural-arrow invariant: this DTO consumes the
    :data:`DataGovernanceDiffFlag` vocabulary from
    :mod:`cognic_agentos.packs.evidence.data_governance` (the source-
    of-truth module). The arrow runs ``portal → packs/evidence``
    exclusively — projectors do NOT import portal types.

    ``from_attributes=True`` matches the :class:`PackResponse` +
    :class:`PackLifecycleEventResponse` interop pattern: handlers can
    pass a :class:`DataGovernancePanelData` directly without an
    intermediate ``dataclasses.asdict`` conversion.

    Field set (10 fields, frozen per plan §302):

    - ``pack_kind: PackKind`` — authoritative kind from the
      :class:`PackRecord.kind` projection (handler cross-checks against
      ``manifest["pack"]["kind"]`` BEFORE invoking the projector;
      mismatch surfaces as 409 ``pack_kind_mismatch``, NOT a panel
      payload anomaly).
    - ``data_classes: tuple[str, ...]`` — ADR-017 data-class set.
    - ``purpose: str`` — single business purpose.
    - ``purpose_description: str`` — human-readable description
      (optional in the manifest; defaults to empty).
    - ``retention_policy: str`` — retention-policy enum value.
    - ``retention_max_window: str`` — stringified for display; the
      manifest stores a positive number when ``retention_policy !=
      "none"``.
    - ``egress_allow_list: tuple[str, ...]`` — allowed egress endpoints.
    - ``dlp_pre_hooks: tuple[str, ...]`` — declared pre-phase hook ids.
    - ``dlp_post_hooks: tuple[str, ...]`` — declared post-phase hook ids.
    - ``tenant_policy_diff: tuple[DataGovernanceDiffFlag, ...]`` —
      closed-enum tuple. Empty ``()`` means "no tenant policy wired"
      per plan §304; ``("none",)`` means "policy wired + no drift";
      otherwise one or more violation flags (never mixed with the
      ``"none"`` sentinel).

    Inherits :class:`PackBaseModel`'s ``frozen=True`` + ``extra="forbid"``
    — smuggled fields refuse at validation; downstream handler cannot
    mutate the DTO mid-request.
    """

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid", from_attributes=True)

    pack_kind: PackKind
    data_classes: tuple[str, ...]
    purpose: str
    purpose_description: str
    retention_policy: str
    retention_max_window: str
    egress_allow_list: tuple[str, ...]
    dlp_pre_hooks: tuple[str, ...]
    dlp_post_hooks: tuple[str, ...]
    tenant_policy_diff: tuple[DataGovernanceDiffFlag, ...]


# ---------------------------------------------------------------------------
# Sprint 7B.3 T4 — RiskTierPanel response DTO
# (Plan §318 — GET /api/v1/packs/{pack_id}/evidence/risk-tier)
# ---------------------------------------------------------------------------


class RiskTierPanel(PackBaseModel):
    """Sprint 7B.3 T4 — GET ``/api/v1/packs/{pack_id}/evidence/risk-tier``
    response body per plan §318.

    Wire-shape projection of a pack's persisted manifest's
    ``risk_tier.tier`` field per ADR-014 §24-37. The route handler at
    :mod:`cognic_agentos.portal.api.packs.evidence_routes` fetches the
    persisted manifest via :func:`find_latest_submit_row` +
    ``payload["manifest"]`` and feeds it through
    :func:`cognic_agentos.packs.evidence.risk_tier.project_risk_tier_panel`
    to produce the :class:`RiskTierPanelData` projector output, then
    ``RiskTierPanel.model_validate(panel_data)`` projects onto this
    wire shape via ``from_attributes=True``.

    Architectural-arrow invariant: this DTO consumes the
    :data:`ApprovalFlowKind` vocabulary from
    :mod:`cognic_agentos.packs.evidence.risk_tier` (the source-of-
    truth module). The arrow runs ``portal → packs/evidence``
    exclusively — projectors do NOT import portal types.

    ``from_attributes=True`` matches the :class:`DataGovernancePanel`
    interop pattern: handlers can pass a :class:`RiskTierPanelData`
    directly without an intermediate ``dataclasses.asdict`` conversion.

    Field set (4 fields, frozen per plan §318):

    - ``pack_kind: PackKind`` — authoritative kind from the
      :class:`PackRecord.kind` projection (handler cross-checks
      against ``manifest["pack"]["kind"]`` BEFORE invoking the
      projector; mismatch surfaces as 409 ``pack_kind_mismatch``).
    - ``risk_tier: str`` — bare string (NOT the :data:`RiskTier`
      Literal) so the defensive-fallback paths (missing block,
      non-dict block, unknown tier, non-string value) can surface a
      raw drift indicator (the unknown string or empty) without a
      Pydantic refusal at validation. The drift is signalled to the
      reviewer via the projector's ``approval_flow="pack_declared"``
      conservative fallback (NOT by refusing to serve the panel).
    - ``approval_flow: ApprovalFlowKind`` — closed-enum 7-value Literal
      per ADR-014 §30-37. Pydantic v2 refuses out-of-vocab values at
      validation time (mirrors :data:`DataGovernanceDiffFlag` strict
      validation on the data-governance panel).
    - ``approval_flow_description: str`` — per-flow display text for
      the reviewer UI hint; non-empty for every flow value.

    Inherits :class:`PackBaseModel`'s ``frozen=True`` + ``extra="forbid"``
    — smuggled fields refuse at validation; downstream handler cannot
    mutate the DTO mid-request.
    """

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid", from_attributes=True)

    pack_kind: PackKind
    risk_tier: str
    approval_flow: ApprovalFlowKind
    approval_flow_description: str


# ---------------------------------------------------------------------------
# Sprint 7B.3 T5 — SupplyChainPanel response DTO
# (Plan §334 — GET /api/v1/packs/{pack_id}/evidence/supply-chain)
# ---------------------------------------------------------------------------


class SupplyChainPanel(PackBaseModel):
    """Sprint 7B.3 T5 — GET ``/api/v1/packs/{pack_id}/evidence/supply-chain``
    response body per plan §334.

    Wire-shape projection of a pack's persisted manifest's
    ``supply_chain`` block per ADR-016 §23-33 + the 7-year sigstore-
    bundle retention floor per §70-72. The route handler at
    :mod:`cognic_agentos.portal.api.packs.evidence_routes` fetches the
    persisted manifest via :func:`find_latest_submit_row` +
    ``payload["manifest"]`` AND sources the submit-row ``created_at``
    via :meth:`PackRecordStore.load_latest_submit_created_at` and feeds
    both through
    :func:`cognic_agentos.packs.evidence.supply_chain.project_supply_chain_panel`
    to produce the :class:`SupplyChainPanelData` projector output, then
    ``SupplyChainPanel.model_validate(panel_data)`` projects onto this
    wire shape via ``from_attributes=True``.

    **Per plan §333 — declarations, NOT verification status**: every
    field on this DTO is "as declared in the manifest". Actual cosign-
    signature-verification status surfaces via the composer's Gate 1
    result on the approve endpoint (T7-T9), NOT on this panel. The
    reviewer reads the panel to see WHAT the author declared; the
    composer result to see WHETHER the declarations VERIFIED.

    Architectural-arrow invariant: this DTO consumes the
    :data:`AttestationKind` vocabulary from
    :mod:`cognic_agentos.packs.evidence.supply_chain` (the source-of-
    truth module). The arrow runs ``portal → packs/evidence``
    exclusively — projectors do NOT import portal types.

    ``from_attributes=True`` matches the :class:`DataGovernancePanel`
    + :class:`RiskTierPanel` interop pattern: handlers can pass a
    :class:`SupplyChainPanelData` directly without an intermediate
    :func:`dataclasses.asdict` conversion.

    Field set (9 fields, frozen per plan §334):

    - ``pack_kind: PackKind`` — authoritative kind from the
      :class:`PackRecord.kind` projection (handler cross-checks
      against ``manifest["pack"]["kind"]`` BEFORE invoking the
      projector; mismatch surfaces as 409 ``pack_kind_mismatch``).
    - ``declared_attestation_paths: tuple[str, ...]`` — paths the
      author declared in ``manifest.supply_chain.attestation_paths``.
      Non-string entries silently filtered at the projector.
    - ``slsa_level_declared: int | None`` — SLSA level (1-4) per ADR-016
      §24; None when missing / non-int / a bool subclass / out-of-range
      (defensive — the projector applies the 1..4 validity gate).
    - ``sbom_path_declared: str | None`` — SBOM file path per §25.
    - ``vuln_scan_path_declared: str | None`` — vuln-scan baseline
      path per §26.
    - ``license_audit_path_declared: str | None`` — license-audit
      output path per §27.
    - ``sigstore_bundle_path_declared: str | None`` — Rekor-bound
      bundle path per §28.
    - ``in_toto_layout_declared: str | None`` — in-toto layout path
      per §29.
    - ``sigstore_bundle_retention_expires_at: datetime | None`` —
      submit-row ``created_at`` + 7 years per §70-72 when BOTH the
      bundle is declared AND the submit-row timestamp is available;
      None otherwise.

    The :data:`AttestationKind` Literal is wire-protocol-public but is
    NOT directly carried on this DTO as a field annotation — the panel
    surfaces each kind as a NAMED field (``slsa_level_declared`` /
    ``sbom_path_declared`` / etc.) rather than a flat ``dict[
    AttestationKind, ...]``, so reviewers and bank-overlay consumers
    can audit individual declaration presence without dict-keyset
    drift. The closed-enum vocabulary lives at the projector module
    for the 5-gate composer (T7) to consume.

    Inherits :class:`PackBaseModel`'s ``frozen=True`` + ``extra="forbid"``
    — smuggled fields refuse at validation; downstream handler cannot
    mutate the DTO mid-request.
    """

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid", from_attributes=True)

    pack_kind: PackKind
    declared_attestation_paths: tuple[str, ...]
    slsa_level_declared: int | None
    sbom_path_declared: str | None
    vuln_scan_path_declared: str | None
    license_audit_path_declared: str | None
    sigstore_bundle_path_declared: str | None
    in_toto_layout_declared: str | None
    sigstore_bundle_retention_expires_at: datetime.datetime | None


# ---------------------------------------------------------------------------
# Sprint 7B.3 T6 — ConformanceMatrixPanel response DTO + nested sub-models
# (Plan §350 — GET /api/v1/packs/{pack_id}/evidence/conformance)
# ---------------------------------------------------------------------------


class MatrixDeclarationPanel(PackBaseModel):
    """Sprint 7B.3 T6 — per-protocol declaration summary sub-model.

    Pydantic mirror of
    :class:`cognic_agentos.packs.evidence.conformance_matrix.MatrixDeclaration`.
    Carried as the VALUE type of :attr:`ConformanceMatrixPanel.declarations`
    (keyed ``"mcp"`` / ``"a2a"`` / ``"oasf"``).

    Field set (3 fields):

    - ``applicable: bool`` — R9: whether the protocol matrix applies to
      the pack's kind (plan §351). ``False`` → no comparisons emitted.
    - ``applicability_reason: str`` — human-readable reason.
    - ``declared_features: tuple[str, ...]`` — conformance-matrix slugs
      (MCP / A2A) or capability strings (OASF) the manifest declared.
    """

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid", from_attributes=True)

    applicable: bool
    applicability_reason: str
    declared_features: tuple[str, ...]


class MatrixComparisonPanel(PackBaseModel):
    """Sprint 7B.3 T6 — one declared-feature → conformance-matrix
    comparison row sub-model.

    Pydantic mirror of
    :class:`cognic_agentos.packs.evidence.conformance_matrix.MatrixComparison`.
    Carried as the element type of :attr:`ConformanceMatrixPanel.comparisons`.

    Field set (5 fields):

    - ``protocol: str`` — ``"mcp"`` / ``"a2a"`` / ``"oasf"``.
    - ``feature: str`` — the conformance-matrix slug or OASF capability.
    - ``matrix_wave_1: str | None`` — the matrix's Wave-1 posture, or
      ``None`` for an unknown slug / OASF.
    - ``matrix_wave_2_promoted: bool`` — whether the matrix commits to
      promoting the feature in Wave 2.
    - ``flag: MatrixComparisonFlag | None`` — the closed-enum mismatch
      flag for this row, or ``None`` when the declaration is clean.
    """

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid", from_attributes=True)

    protocol: str
    feature: str
    matrix_wave_1: str | None
    matrix_wave_2_promoted: bool
    flag: MatrixComparisonFlag | None


class OwaspCheckResultPanel(PackBaseModel):
    """Sprint 7B.3 T6 — one OWASP per-category check result sub-model.

    Pydantic mirror of
    :class:`cognic_agentos.packs.evidence.conformance_matrix.OwaspCheckResultData`.
    Defensive ``str``-typed fields — the persisted
    ``payload["conformance"]`` is reconstructed defensively by the
    projector (unknown category / status filtered out).

    Field set (3 fields): ``category: str`` / ``status: str`` /
    ``findings: tuple[str, ...]``.
    """

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid", from_attributes=True)

    category: str
    status: str
    findings: tuple[str, ...]


class OwaspVerdictPanel(PackBaseModel):
    """Sprint 7B.3 T6 — projected T9 chain-row ``payload["conformance"]``
    OWASP suite verdict sub-model per plan §353.

    Pydantic mirror of
    :class:`cognic_agentos.packs.evidence.conformance_matrix.OwaspVerdictData`.
    NOT the
    :class:`cognic_agentos.packs.conformance.checks.ConformanceReport`
    dataclass directly — see the projector module docstring's "OWASP
    verdict projection" note (each 7B.3 projector owns its own output
    type; ``ConformanceReport``'s field order is itself ADR-006 wire-
    protocol-public).

    Field set (4 fields):

    - ``overall_status: str`` — ``"green"`` / ``"red"`` / ``"yellow"``.
    - ``results: tuple[OwaspCheckResultPanel, ...]`` — per-category
      results, preserving the persisted payload's iteration order.
    - ``summary: str`` — the runner's human-readable count phrase.
    - ``errored_categories: tuple[str, ...]`` — categories whose
      checker raised during the suite run.
    """

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid", from_attributes=True)

    overall_status: str
    results: tuple[OwaspCheckResultPanel, ...]
    summary: str
    errored_categories: tuple[str, ...]


class ConformanceMatrixPanel(PackBaseModel):
    """Sprint 7B.3 T6 — GET ``/api/v1/packs/{pack_id}/evidence/conformance``
    response body per plan §350.

    Wire-shape projection of a pack's persisted manifest's protocol
    declarations (``[mcp]`` / ``[a2a]`` / ``[identity]`` blocks)
    compared against the static-shipped AgentOS conformance matrix
    (per ``docs/MCP-CONFORMANCE.md`` + ``docs/A2A-CONFORMANCE.md``) +
    the submit chain row's ``payload["conformance"]`` OWASP verdict.

    The route handler at
    :mod:`cognic_agentos.portal.api.packs.evidence_routes` fetches the
    persisted manifest via :func:`find_latest_submit_row` +
    ``payload["manifest"]`` AND the submit-row ``payload["conformance"]``,
    feeds both through
    :func:`cognic_agentos.packs.evidence.conformance_matrix.project_conformance_matrix_panel`
    to produce the :class:`ConformanceMatrixPanelData` projector
    output, then ``ConformanceMatrixPanel.model_validate(panel_data)``
    projects onto this wire shape via ``from_attributes=True``.

    Architectural-arrow invariant: this DTO consumes the
    :data:`MatrixComparisonFlag` vocabulary from
    :mod:`cognic_agentos.packs.evidence.conformance_matrix` (the
    source-of-truth module). The arrow runs ``portal → packs/evidence``
    exclusively — projectors do NOT import portal types.

    Field set (5 fields, frozen per plan §350):

    - ``pack_kind: PackKind`` — authoritative kind from the
      :class:`PackRecord.kind` projection (handler cross-checks
      against ``manifest["pack"]["kind"]`` BEFORE invoking the
      projector; mismatch surfaces as 409 ``pack_kind_mismatch``).
    - ``declarations: dict[str, MatrixDeclarationPanel]`` — keyed
      ``"mcp"`` / ``"a2a"`` / ``"oasf"``; ALL THREE keys always
      present (R9 applicability carried IN the value, not by key
      absence).
    - ``comparisons: tuple[MatrixComparisonPanel, ...]`` — one row per
      declared feature across all APPLICABLE protocols.
    - ``flagged_mismatches: tuple[MatrixComparisonFlag, ...]`` —
      deduplicated, alphabetically-sorted distinct closed-enum
      mismatch flags; empty tuple = comparison ran, no mismatches.
    - ``owasp_verdict: OwaspVerdictPanel | None`` — the projected T9
      OWASP suite verdict, or ``None`` when the submit row carried no
      ``payload["conformance"]`` (pre-7B.2-T9 chain rows) or it was
      malformed.

    Inherits :class:`PackBaseModel`'s ``frozen=True`` + ``extra="forbid"``
    — smuggled fields refuse at validation; downstream handler cannot
    mutate the DTO mid-request.
    """

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid", from_attributes=True)

    pack_kind: PackKind
    declarations: dict[str, MatrixDeclarationPanel]
    comparisons: tuple[MatrixComparisonPanel, ...]
    flagged_mismatches: tuple[MatrixComparisonFlag, ...]
    owasp_verdict: OwaspVerdictPanel | None
