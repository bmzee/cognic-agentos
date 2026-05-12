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

from cognic_agentos.packs.lifecycle import PackKind, PackState


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

    Field set mirrors :class:`PackRecord` at ``packs/storage.py:351-378``
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
# Sprint 7B.2 T5 — PackEvidenceResponse response schema
# (Plan Round 11 P3 #5 — GET /api/v1/packs/{pack_id}/evidence)
# ---------------------------------------------------------------------------


class PackEvidenceResponse(PackBaseModel):
    """GET ``/api/v1/packs/{pack_id}/evidence`` response body.

    Plan Round 11 P3 #5 — two-field shape exposing the T9
    auto-run-on-submit conformance evidence + a placeholder for the
    7B.3 reviewer evidence panels (always-null literal in 7B.2).

    Read-path (T5):
    - Walk :meth:`PackRecordStore.load_lifecycle_history` for the pack.
    - Find the most-recent ``event_type == "pack.lifecycle.submitted"`` row.
    - Surface its ``payload.get("conformance")`` value on the
      ``conformance`` field; ``None`` for pre-T9 chain rows that carry
      no conformance key.

    Plan T5 caveat: until T9 lands, EVERY submit chain row is a pre-T9
    chain that carries no ``conformance`` key, so the endpoint surfaces
    ``{"conformance": null, "reviewer_evidence_panels": null}``
    gracefully — the test surface pins both the pre-T9 null path AND
    the forward-looking T9 populated path.

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
