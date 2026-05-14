"""Sprint 7B.3 T3 — reviewer evidence-panel routes (CRITICAL CONTROLS).

Per the plan-of-record at
``docs/superpowers/plans/2026-05-13-sprint-7b3-reviewer-evidence-panels-5-gate.md``
§290-307 — ships the data-governance evidence-panel handler under
``/api/v1/packs``. T4-T6 extend the SAME ``build_evidence_routes``
factory with the remaining three panels (risk-tier / supply-chain /
conformance); T7 wires the 5-gate composer that consumes the same
projector outputs.

T3 endpoint surface (this commit):

- ``GET  /{pack_id}/evidence/data-governance`` — gated by
  ``pack.review.claim`` + ``RequireTenantOwnership``; reads the
  authoritative manifest from the most recent submit chain row via
  :func:`find_latest_submit_row` + ``payload["manifest"]`` per plan
  R1 P2 #1's manifest-evidence-source seam; projects through
  :func:`project_data_governance_panel`; returns
  :class:`DataGovernancePanel` per plan §302.

Refusal taxonomy (handler-body 409s):

The route-owned :data:`EvidencePanelRefusalReason` literal is a
**3-value closed enum** distinct from the upstream RBAC / tenant-
isolation literals — pinned by the disjointness drift detectors at
``test_evidence_routes_structure.py``. The three reasons surface the
three Lifecycle / persistence boundaries the panel needs the manifest
to have crossed:

- ``pack_not_yet_submitted`` — pack is still in ``draft`` state (no
  submit chain row exists); the panel cannot project evidence that
  doesn't yet exist. Caller restages via the submit flow.
- ``manifest_evidence_not_persisted`` — submit chain row exists but
  predates Sprint 7B.3's manifest-persistence extension (T2 Slice D
  + author route extension); the storage-doctrine boundary surfaces
  explicitly rather than the panel silently rendering empty.
- ``pack_kind_mismatch`` — the persisted manifest's ``pack.kind``
  disagrees with the authoritative :class:`PackRecord.kind`. This is
  a serious integrity signal — either the manifest was tampered with
  between submit + the chain write OR the record's kind drifted via
  a non-chain path. The handler returns 409 + the closed-enum reason
  rather than projecting against the manifest (the projector's
  ``record_kind`` parameter is the authority; the manifest's value is
  cross-checked at the route layer, NOT the projector layer).

**Module-header invariant** (mirrors ``operator_routes.py`` +
``inspection_routes.py`` + ``review_routes.py`` + ``author_routes.py``
doctrine): ``from __future__ import annotations`` is INTENTIONALLY
OMITTED. PEP 563 string-deferred annotations break FastAPI's
``inspect.signature()`` / ``typing.get_type_hints()`` resolution on
``Annotated[..., Depends(<closure-local>)]`` parameters (the shared
``_require_pack_review_claim`` + ``_require_tenant_ownership``
instances are LOCAL variables inside :func:`build_evidence_routes`,
NOT module globals). A regression that adds the future-import would
make FastAPI silently fall back to treating handler parameters as
query params — pinned by the AST self-test at
``test_evidence_routes_structure.py::
TestSprint7B3T3SliceDModuleHeaderInvariant``.
"""

import logging
from typing import Annotated, Final, Literal

from fastapi import APIRouter, Depends, HTTPException

from cognic_agentos.packs._lifecycle_helpers import find_latest_submit_row
from cognic_agentos.packs.evidence.data_governance import project_data_governance_panel
from cognic_agentos.packs.storage import PackRecord, PackRecordStore
from cognic_agentos.portal.api.packs.dto import DataGovernancePanel
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope
from cognic_agentos.portal.rbac.tenant_isolation import RequireTenantOwnership

_LOG = logging.getLogger(__name__)


#: Sprint 7B.3 T3 — route-owned 3-value closed enum for evidence-panel
#: handler-body refusals per plan §300. Disjoint from
#: :data:`RBACDenialReason` + :data:`TenantIsolationFailure` —
#: a single 4xx response body carries exactly one ``reason`` field
#: from exactly one closed-enum source.
EvidencePanelRefusalReason = Literal[
    "pack_not_yet_submitted",
    "manifest_evidence_not_persisted",
    "pack_kind_mismatch",
]


#: Centralised constants mirror the
#: :data:`_PACK_NOT_FOUND_REASON` pattern at ``review_routes.py:101``
#: — keeps log emission + raise-detail in sync without typos.
_PACK_NOT_YET_SUBMITTED_REASON: Final[Literal["pack_not_yet_submitted"]] = "pack_not_yet_submitted"
_MANIFEST_EVIDENCE_NOT_PERSISTED_REASON: Final[Literal["manifest_evidence_not_persisted"]] = (
    "manifest_evidence_not_persisted"
)
_PACK_KIND_MISMATCH_REASON: Final[Literal["pack_kind_mismatch"]] = "pack_kind_mismatch"


def build_evidence_routes(*, store: PackRecordStore) -> APIRouter:
    """Build the evidence-panel sub-router.

    The ``store`` argument is captured in this factory so the handler
    closes over a single :class:`PackRecordStore` instance per app
    lifespan (mirrors :func:`build_review_routes` +
    :func:`build_operator_routes`).

    The returned router does NOT carry a prefix —
    :func:`build_packs_router` mounts it under the parent
    ``/api/v1/packs`` prefix.

    Shared dependency instances are closure-local: FastAPI's per-request
    sub-dependency cache deduplicates ``store.load`` round-trips when
    multiple endpoints share the same :class:`RequireTenantOwnership`
    instance. T3 only ships one handler so the cache savings are
    notional; T4-T6 extend the same factory + reuse the same instances
    so the cache benefit lights up there.

    Slices D-F of T3 ship the data-governance panel; T4 / T5 / T6 add
    the remaining three panels to this same factory.
    """
    router = APIRouter()

    _require_pack_review_claim = RequireScope("pack.review.claim")
    _require_tenant_ownership = RequireTenantOwnership(pack_id_param="pack_id")

    @router.get(
        "/{pack_id}/evidence/data-governance",
        summary="Reviewer data-governance evidence panel (ADR-017 projection)",
    )
    async def data_governance_panel(
        _actor: Annotated[Actor, Depends(_require_pack_review_claim)],
        record: Annotated[PackRecord, Depends(_require_tenant_ownership)],
    ) -> DataGovernancePanel:
        """Project the persisted manifest's ``data_governance`` block
        onto the reviewer-facing evidence panel.

        Dependency chain (resolution order):

        1. ``_require_pack_review_claim`` (:class:`RequireScope`) — 403
           ``scope_not_held`` for missing scope.
        2. ``_require_tenant_ownership`` (:class:`RequireTenantOwnership`) —
           404 ``tenant_id_mismatch`` for cross-tenant; returns the
           :class:`PackRecord` for the kind cross-check.

        Handler-body refusals (all 409 + closed-enum
        :data:`EvidencePanelRefusalReason`):

        - No submit chain row → ``pack_not_yet_submitted``.
        - Submit row missing ``payload["manifest"]`` → ``manifest_evidence_not_persisted``.
        - ``manifest["pack"]["kind"] != record.kind`` → ``pack_kind_mismatch``.

        Structured-log emission: every refusal path logs
        ``portal.packs.evidence.data_governance_panel_refused`` with
        reason + ``pack_id`` + ``actor_subject`` so observability
        tooling can audit panel-access refusal patterns.
        """
        history = await store.load_lifecycle_history(record.id)
        submit_row = find_latest_submit_row(history)
        if submit_row is None:
            _LOG.warning(
                "portal.packs.evidence.data_governance_panel_refused",
                extra={
                    "reason": _PACK_NOT_YET_SUBMITTED_REASON,
                    "actor_subject": _actor.subject,
                    "pack_id": str(record.id),
                    "from_state": record.state,
                },
            )
            raise HTTPException(
                status_code=409,
                detail={"reason": _PACK_NOT_YET_SUBMITTED_REASON},
            )

        manifest = submit_row.payload.get("manifest")
        if not isinstance(manifest, dict):
            _LOG.warning(
                "portal.packs.evidence.data_governance_panel_refused",
                extra={
                    "reason": _MANIFEST_EVIDENCE_NOT_PERSISTED_REASON,
                    "actor_subject": _actor.subject,
                    "pack_id": str(record.id),
                    "from_state": record.state,
                },
            )
            raise HTTPException(
                status_code=409,
                detail={"reason": _MANIFEST_EVIDENCE_NOT_PERSISTED_REASON},
            )

        pack_meta = manifest.get("pack")
        manifest_kind = pack_meta.get("kind") if isinstance(pack_meta, dict) else None
        if manifest_kind is not None and manifest_kind != record.kind:
            _LOG.warning(
                "portal.packs.evidence.data_governance_panel_refused",
                extra={
                    "reason": _PACK_KIND_MISMATCH_REASON,
                    "actor_subject": _actor.subject,
                    "pack_id": str(record.id),
                    "record_kind": record.kind,
                    "manifest_kind": manifest_kind,
                },
            )
            raise HTTPException(
                status_code=409,
                detail={"reason": _PACK_KIND_MISMATCH_REASON},
            )

        panel_data = project_data_governance_panel(
            manifest=manifest,
            record_kind=record.kind,
            tenant_policy=None,  # plan §304 — tenant-policy substrate is post-7B
        )
        return DataGovernancePanel.model_validate(panel_data)

    return router


__all__ = ["EvidencePanelRefusalReason", "build_evidence_routes"]
