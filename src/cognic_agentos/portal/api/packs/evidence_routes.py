"""Sprint 7B.3 T3+T4+T5+T6 — reviewer evidence-panel routes (CRITICAL CONTROLS).

Per the plan-of-record at
``docs/superpowers/plans/2026-05-13-sprint-7b3-reviewer-evidence-panels-5-gate.md``
§290-356 — ships the data-governance (T3) + risk-tier (T4) +
supply-chain (T5) + conformance-matrix (T6) evidence-panel handlers
under ``/api/v1/packs``. T7 wires the 5-gate composer that consumes
the same projector outputs.

Endpoint surface (T3 + T4 + T5 + T6):

- ``GET  /{pack_id}/evidence/data-governance`` (T3) — gated by
  ``pack.review.claim`` + ``RequireTenantOwnership``; reads the
  authoritative manifest from the most recent submit chain row via
  :func:`find_latest_submit_row` + ``payload["manifest"]`` per plan
  R1 P2 #1's manifest-evidence-source seam; projects through
  :func:`project_data_governance_panel`; returns
  :class:`DataGovernancePanel` per plan §302.
- ``GET  /{pack_id}/evidence/risk-tier`` (T4) — same RBAC + tenant
  isolation as T3; reads the same manifest via the same seam;
  projects through :func:`project_risk_tier_panel`; returns
  :class:`RiskTierPanel` per plan §318. The closed-enum
  :data:`ApprovalFlowKind` Literal at
  :mod:`cognic_agentos.packs.evidence.risk_tier` IS the wire-protocol
  contract for the panel's ``approval_flow`` field; ADR-014 §30-37
  is the canonical source of truth for the risk-tier → approval-flow
  mapping table.
- ``GET  /{pack_id}/evidence/supply-chain`` (T5) — same RBAC + tenant
  isolation as T3+T4; reads the same manifest via the same seam +
  sources the submit-row ``created_at`` via the T5 storage seam
  :meth:`PackRecordStore.load_latest_submit_created_at` (additive
  method; NO ``DecisionRecord`` extension per AGENTS.md L138 doctrine);
  projects through :func:`project_supply_chain_panel`; returns
  :class:`SupplyChainPanel` per plan §334. **The panel projects what
  the author DECLARED in the manifest — not the verification status**;
  actual cosign-signature-verification surfaces via the composer's
  Gate 1 result on the approve endpoint (T7-T9). The closed-enum
  :data:`AttestationKind` Literal at
  :mod:`cognic_agentos.packs.evidence.supply_chain` IS the wire-protocol
  contract for the 7 attestation kinds per ADR-016 §23-33; the 7-year
  sigstore-bundle retention floor per §70-72 surfaces as
  ``sigstore_bundle_retention_expires_at`` when BOTH the bundle is
  declared AND the storage seam returned a non-None timestamp.
- ``GET  /{pack_id}/evidence/conformance`` (T6) — same RBAC + tenant
  isolation as T3-T5; reads the same manifest via the same seam +
  ADDITIONALLY reads the submit chain row's ``payload["conformance"]``
  (the OWASP suite verdict written by 7B.2 T9); projects through
  :func:`project_conformance_matrix_panel`; returns
  :class:`ConformanceMatrixPanel` per plan §350. The projector
  compares the manifest's declared MCP/A2A/AGNTCY-OASF feature sets
  against the static-shipped conformance matrix (generated from
  ``docs/MCP-CONFORMANCE.md`` + ``docs/A2A-CONFORMANCE.md`` at build
  time by ``tools/generate_conformance_matrix_json.py``; loaded once
  at projector-module import — runtime never parses Markdown). The
  closed-enum :data:`MatrixComparisonFlag` Literal at
  :mod:`cognic_agentos.packs.evidence.conformance_matrix` IS the
  wire-protocol contract for the panel's ``flagged_mismatches`` tuple.
  **R9 kind-aware**: MCP applies to tool/skill/agent; A2A + OASF apply
  to agent only; hook packs mark all three matrices ``not_applicable``
  — applicability is derived from the authoritative
  :class:`PackRecord.kind`. A pre-7B.2-T9 submit row has no
  ``payload["conformance"]`` → ``owasp_verdict`` surfaces ``None``
  gracefully (supplementary evidence, NOT a 409 boundary).

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
from cognic_agentos.packs.evidence.conformance_matrix import project_conformance_matrix_panel
from cognic_agentos.packs.evidence.data_governance import project_data_governance_panel
from cognic_agentos.packs.evidence.risk_tier import project_risk_tier_panel
from cognic_agentos.packs.evidence.supply_chain import project_supply_chain_panel
from cognic_agentos.packs.storage import PackRecord, PackRecordStore
from cognic_agentos.portal.api.packs.dto import (
    ConformanceMatrixPanel,
    DataGovernancePanel,
    RiskTierPanel,
    SupplyChainPanel,
)
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
        # R9 kind-integrity invariant: the manifest's pack.kind MUST be
        # present, MUST be a string, AND MUST equal the authoritative
        # PackRecord.kind. Absent / non-string values are treated as
        # pack_kind_mismatch (NOT silently projected against record.kind)
        # so a corrupted persisted manifest cannot bypass the integrity
        # gate. Pinned by both panels' kind-integrity regression tests.
        if not isinstance(manifest_kind, str) or manifest_kind != record.kind:
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

    @router.get(
        "/{pack_id}/evidence/risk-tier",
        summary="Reviewer risk-tier evidence panel (ADR-014 projection)",
    )
    async def risk_tier_panel(
        _actor: Annotated[Actor, Depends(_require_pack_review_claim)],
        record: Annotated[PackRecord, Depends(_require_tenant_ownership)],
    ) -> RiskTierPanel:
        """Project the persisted manifest's ``risk_tier`` block onto
        the reviewer-facing evidence panel per plan §317-321.

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

        Per plan §319-321 + ADR-014 §30-37: the projector resolves the
        manifest's declared ``risk_tier.tier`` value through the 1:1
        :data:`_RISK_TIER_TO_APPROVAL_FLOW` mapping table to produce
        the :data:`ApprovalFlowKind` for the reviewer UI hint. The
        canonical 8 :data:`RiskTier` values resolve to their ADR-014
        flows; the defensive-fallback paths (missing block, malformed
        block, unknown tier, non-string tier value) ALL resolve to the
        most-conservative ``"pack_declared"`` flow so the reviewer is
        never auto-routed on a vacuous default.

        Structured-log emission: every refusal path logs
        ``portal.packs.evidence.risk_tier_panel_refused`` with reason
        + ``pack_id`` + ``actor_subject`` so observability tooling can
        audit panel-access refusal patterns (mirrors the T3 data-
        governance panel's emission contract — distinct log message
        per panel so a future regression that cross-fires (e.g. risk-
        tier handler emitting a data-governance log) is caught by the
        per-panel mutually-exclusive log assertions in
        ``test_evidence_panel_routes.py``).
        """
        history = await store.load_lifecycle_history(record.id)
        submit_row = find_latest_submit_row(history)
        if submit_row is None:
            _LOG.warning(
                "portal.packs.evidence.risk_tier_panel_refused",
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
                "portal.packs.evidence.risk_tier_panel_refused",
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
        # R9 kind-integrity invariant: the manifest's pack.kind MUST be
        # present, MUST be a string, AND MUST equal the authoritative
        # PackRecord.kind. Absent / non-string values are treated as
        # pack_kind_mismatch (NOT silently projected against record.kind)
        # so a corrupted persisted manifest cannot bypass the integrity
        # gate. Pinned by both panels' kind-integrity regression tests.
        if not isinstance(manifest_kind, str) or manifest_kind != record.kind:
            _LOG.warning(
                "portal.packs.evidence.risk_tier_panel_refused",
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

        panel_data = project_risk_tier_panel(
            manifest=manifest,
            record_kind=record.kind,
        )
        return RiskTierPanel.model_validate(panel_data)

    @router.get(
        "/{pack_id}/evidence/supply-chain",
        summary="Reviewer supply-chain evidence panel (ADR-016 projection)",
    )
    async def supply_chain_panel(
        _actor: Annotated[Actor, Depends(_require_pack_review_claim)],
        record: Annotated[PackRecord, Depends(_require_tenant_ownership)],
    ) -> SupplyChainPanel:
        """Project the persisted manifest's ``supply_chain`` block + the
        submit chain row's ``created_at`` onto the reviewer-facing
        evidence panel per plan §333-336.

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

        Per plan §333: the panel surfaces what the author DECLARED at
        sign time per ADR-016 §23-33; it does NOT re-verify cosign
        signatures at panel-read time (that's the composer's Gate 1
        concern at T7-T9). The reviewer reads the panel to see WHAT
        was declared; the composer result to see WHETHER it VERIFIED.

        The submit-row ``created_at`` feeds the 7-year sigstore-bundle
        retention computation per ADR-016 §70-72 — sourced via the T5
        storage seam :meth:`PackRecordStore.load_latest_submit_created_at`
        (additive method; NO :class:`DecisionRecord` extension per
        AGENTS.md L138 doctrine).

        Structured-log emission: every refusal path logs
        ``portal.packs.evidence.supply_chain_panel_refused`` with
        reason + ``pack_id`` + ``actor_subject`` — mirrors the T3/T4
        per-panel mutually-exclusive log emission contract pinned by
        ``test_evidence_panel_routes.py``.
        """
        history = await store.load_lifecycle_history(record.id)
        submit_row = find_latest_submit_row(history)
        if submit_row is None:
            _LOG.warning(
                "portal.packs.evidence.supply_chain_panel_refused",
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
                "portal.packs.evidence.supply_chain_panel_refused",
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
        # R9 kind-integrity invariant: the manifest's pack.kind MUST be
        # present, MUST be a string, AND MUST equal the authoritative
        # PackRecord.kind. Absent / non-string values are treated as
        # pack_kind_mismatch (NOT silently projected against record.kind)
        # so a corrupted persisted manifest cannot bypass the integrity
        # gate. Pinned by all three panels' kind-integrity regression
        # tests (T4 R1 P2 dual-panel parametrize + T5 carry-forward).
        if not isinstance(manifest_kind, str) or manifest_kind != record.kind:
            _LOG.warning(
                "portal.packs.evidence.supply_chain_panel_refused",
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

        # T5 storage seam: source the submit chain row's created_at to
        # feed the 7-year sigstore-bundle retention computation. The
        # method returns None when no submit row exists for the pack
        # — at this point in the handler the submit_row check above
        # has already passed, so the method should return a non-None
        # value on the green path. Defensive None handling in the
        # projector covers the edge case where the chain-row write +
        # the load are racing across replicas (read-after-write
        # consistency window on multi-replica Postgres).
        submit_created_at = await store.load_latest_submit_created_at(record.id)
        panel_data = project_supply_chain_panel(
            manifest=manifest,
            record_kind=record.kind,
            submit_created_at=submit_created_at,
        )
        return SupplyChainPanel.model_validate(panel_data)

    @router.get(
        "/{pack_id}/evidence/conformance",
        summary="Reviewer conformance-matrix evidence panel (ADR-002 + ADR-003 projection)",
    )
    async def conformance_panel(
        _actor: Annotated[Actor, Depends(_require_pack_review_claim)],
        record: Annotated[PackRecord, Depends(_require_tenant_ownership)],
    ) -> ConformanceMatrixPanel:
        """Project the persisted manifest's ``[mcp]`` / ``[a2a]`` /
        ``[identity]`` protocol declarations + the submit chain row's
        ``payload["conformance"]`` OWASP verdict onto the reviewer-
        facing conformance-matrix evidence panel per plan §349-353.

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

        Per plan §349-353: the projector compares the manifest's
        declared MCP/A2A/AGNTCY-OASF feature sets against the static-
        shipped conformance matrix (generated from
        ``docs/MCP-CONFORMANCE.md`` + ``docs/A2A-CONFORMANCE.md`` at
        build time; loaded once at projector-module import — runtime
        never parses Markdown) AND surfaces the T9 chain-row
        ``payload["conformance"]`` OWASP verdict inline. **R9 kind-
        aware**: tool/skill/agent packs project MCP; agent packs
        additionally project A2A + OASF; hook packs mark all three
        matrices ``not_applicable`` rather than failing absent protocol
        blocks — the applicability decision is derived from the
        authoritative :attr:`PackRecord.kind`, NOT the manifest.

        Unlike T3-T5, this handler ALSO reads ``payload["conformance"]``
        (in addition to ``payload["manifest"]``). A pre-7B.2-T9 submit
        chain row predates the OWASP-verdict persistence extension —
        ``payload.get("conformance")`` returns ``None`` and the
        projector surfaces ``owasp_verdict=None`` gracefully (NOT a
        409; the OWASP verdict is supplementary evidence, not a
        manifest-evidence-persistence boundary).

        Structured-log emission: every refusal path logs
        ``portal.packs.evidence.conformance_panel_refused`` with
        reason + ``pack_id`` + ``actor_subject`` — mirrors the T3/T4/T5
        per-panel mutually-exclusive log emission contract pinned by
        ``test_evidence_panel_routes.py``.
        """
        history = await store.load_lifecycle_history(record.id)
        submit_row = find_latest_submit_row(history)
        if submit_row is None:
            _LOG.warning(
                "portal.packs.evidence.conformance_panel_refused",
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
                "portal.packs.evidence.conformance_panel_refused",
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
        # R9 kind-integrity invariant: the manifest's pack.kind MUST be
        # present, MUST be a string, AND MUST equal the authoritative
        # PackRecord.kind. Absent / non-string values are treated as
        # pack_kind_mismatch (NOT silently projected against record.kind)
        # so a corrupted persisted manifest cannot bypass the integrity
        # gate. Pinned by all four panels' kind-integrity regression
        # tests (T4 R1 P2 dual-panel parametrize + T5/T6 carry-forward).
        if not isinstance(manifest_kind, str) or manifest_kind != record.kind:
            _LOG.warning(
                "portal.packs.evidence.conformance_panel_refused",
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

        # T6: the conformance panel reads BOTH payload["manifest"] AND
        # payload["conformance"] (the OWASP verdict written by 7B.2 T9).
        # A pre-7B.2-T9 submit row has no "conformance" key — .get()
        # returns None and the projector surfaces owasp_verdict=None
        # gracefully (supplementary evidence, NOT a 409 boundary).
        conformance_payload = submit_row.payload.get("conformance")
        panel_data = project_conformance_matrix_panel(
            manifest=manifest,
            record_kind=record.kind,
            conformance_payload=conformance_payload,
        )
        return ConformanceMatrixPanel.model_validate(panel_data)

    return router


__all__ = ["EvidencePanelRefusalReason", "build_evidence_routes"]
