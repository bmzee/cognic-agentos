"""Sprint 7B.2 T5 — review surface endpoints (CRITICAL CONTROLS).

Per the plan-of-record at
``docs/superpowers/plans/2026-05-11-sprint-7b2-portal-api-rbac-owasp.md``
§"Task 5: Review surface endpoints" — ships the 5 review-surface
endpoints behind ``/api/v1/packs``:

- ``GET  /review-queue`` — gated by ``pack.review.claim``; calls
  ``list_by_status("submitted", tenant_id=actor.tenant_id, ...)``.
- ``POST /{pack_id}/claim`` — gated by ``pack.review.claim`` + tenant
  + role-separation; transition ``submitted → under_review``.
- ``POST /{pack_id}/approve`` — gated by ``pack.review.approve`` +
  tenant + role-separation; FAIL-LOUD 503 in T5 (5-gate composer
  lands at 7B.3 per R1 P2 #1).
- ``POST /{pack_id}/reject`` — gated by ``pack.review.reject`` +
  tenant + role-separation; transition ``under_review → rejected``.
- ``GET  /{pack_id}/evidence`` — gated by ``pack.audit.read`` +
  tenant; reads ``payload.conformance`` from the submit chain row.

Slice 2a (this revision) lands the **claim** handler with the full
dependency-chain wiring (RBAC → tenant → role-separation → handler).
Slices 2b-2e fill the remaining 4 handlers using the same wiring
template. The route-shell stage left 4 stubs returning 501; this
slice converts ``claim`` to the real implementation.

Round 12 P2 #1: ``review-queue`` is a distinct path (NOT
``/api/v1/packs?status=submitted`` per ADR-012 §62 sketch).

Round 14 P2 #2 + Round 17 P2 #1: path UUIDs use ``{pack_id}``
matching T4's ``author_routes.py`` + the shared
``RequireTenantOwnership(pack_id_param="pack_id")`` dependency.

Round 14 P2 #2 + Round 17 P2 #3 — **T5 (this module) owns BOTH
the claim + reject request-id prefix declarations**;
``author_routes._mint_request_id`` is cross-imported as a single
source of truth for the minter; T9 reuses the T5-owned reject prefix
when amending the reject handler with ``evidence_attachments``.

**Round 15 P2 #1 — module-header invariant**: ``from __future__ import
annotations`` is INTENTIONALLY OMITTED here (same as
``portal/rbac/role_separation.py`` and ``portal/api/packs/author_routes.py``).
PEP 563 string-deferred annotations would prevent FastAPI's
``inspect.signature()`` / ``typing.get_type_hints()`` from resolving
``Annotated[..., Depends(<local-var>)]`` annotations on the inner
endpoint handlers (the shared dependency instances like
``_require_pack_review_claim`` are LOCAL variables inside
:func:`build_review_routes`, NOT module globals). A regression that
adds the future-import would make FastAPI silently fall back to
treating handler parameters as query params — exactly the bug
R15 P2 #1 pinned for ``role_separation.py``.
"""

import logging
import math
from pathlib import Path
from typing import Annotated, Any, Final, NoReturn, TypeGuard

from fastapi import APIRouter, Depends, HTTPException, Request

from cognic_agentos.core.decision_history import DecisionRecord
from cognic_agentos.packs._lifecycle_helpers import find_latest_submit_row
from cognic_agentos.packs._signature_path_resolver import resolve_signature_paths
from cognic_agentos.packs.approval_gates import (
    AdversarialGateInput,
    EvaluationGateInput,
    OwaspGateInput,
    SignatureGateInput,
    compose_approval_gates,
    composition_snapshot,
    evaluate_override_decision,
)
from cognic_agentos.packs.lifecycle import LifecycleTransitionRefused
from cognic_agentos.packs.storage import PackNotFound, PackRecord, PackRecordStore
from cognic_agentos.portal.api.packs.author_routes import _mint_request_id
from cognic_agentos.portal.api.packs.dto import (
    ApproveRefusalResponse,
    ApproveRequest,
    PackEvidenceResponse,
    PackResponse,
    RejectDraftRequest,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import (
    RequireScope,
    _emit_denial_or_500,
    _resolve_request_id,
)
from cognic_agentos.portal.rbac.role_separation import RequireDifferentActorThanCreator
from cognic_agentos.portal.rbac.tenant_isolation import RequireTenantOwnership
from cognic_agentos.protocol.trust_gate import (
    CosignNotInstalledError,
    CosignVerificationFailed,
    PathTraversalError,
    TrustGate,
)
from cognic_agentos.protocol.trust_root_resolver import TrustRootResolver

_LOG = logging.getLogger(__name__)


#: Plan Round 14 P2 #2 + Round 17 P2 #3 — T5 owns the claim
#: request-id prefix. 12 chars + uuid4().hex (32) = 44 chars; well
#: under the ``decision_history.request_id`` String(64) cap.
#: Double-dash maintains prefix-uniqueness against ``pack-cancel-``.
_PACK_CLAIM_REQUEST_ID_PREFIX: Final[str] = "pack-claim--"

#: Plan Round 14 P2 #2 + Round 17 P2 #3 — T5 owns the reject
#: request-id prefix. Used by the reject handler (slice 2b); T9
#: carry-forward reuses this exact prefix when amending the reject
#: handler with ``evidence_attachments``.
_PACK_REJECT_REQUEST_ID_PREFIX: Final[str] = "pack-reject-"


#: Plan Round 11 P2 #1 + Round 14 P2 #2 — bounded request-id length
#: invariant: every prefix + uuid4().hex (32) must fit under the 64-char
#: ``decision_history.request_id`` column cap. Module-foot assert below
#: pins this at import time.
_REQUEST_ID_MAX_LEN: Final[int] = 64


#: Plan Round 16 P2 #2 — shared ``pack_not_found`` reason for race
#: translation. Same string as :data:`TenantIsolationFailure`'s
#: ``pack_not_found`` value so the wire-protocol-public 404 body is
#: identical across review + author surfaces.
_PACK_NOT_FOUND_REASON: Final[str] = "pack_not_found"


# ---------------------------------------------------------------------------
# Sprint 7B.3 T9 — approve endpoint: 5-gate composer + override path.
# ---------------------------------------------------------------------------

#: Sprint 7B.3 T9 — approve request-id prefix. 12 chars + uuid4().hex
#: (32) = 44 chars, under the ``decision_history.request_id`` String(64)
#: cap; pinned by the module-foot assert. Distinct from the T5-owned
#: ``pack-claim--`` / ``pack-reject-`` prefixes.
_PACK_APPROVE_REQUEST_ID_PREFIX: Final[str] = "pack-approve"

#: ADR-011 adversarial-corpus pass-rate floor (mirrors the composer's
#: ``AdversarialGateInput`` docstring at ``packs/approval_gates.py``).
_ADVERSARIAL_PASS_RATE_THRESHOLD: Final[float] = 0.99

#: Sprint 7B.3 T9 — 409 pre-composer refusal reasons. ``pack_not_yet_submitted``
#: + ``manifest_evidence_not_persisted`` + ``pack_kind_mismatch`` mirror the
#: ``EvidencePanelRefusalReason`` closed-enum at ``evidence_routes.py`` so the
#: approve route + the evidence panels fail the same Lifecycle / persistence
#: boundaries with the same wire-protocol-public ``reason`` strings.
_PACK_NOT_YET_SUBMITTED_REASON: Final[str] = "pack_not_yet_submitted"
_MANIFEST_EVIDENCE_NOT_PERSISTED_REASON: Final[str] = "manifest_evidence_not_persisted"
_PACK_KIND_MISMATCH_REASON: Final[str] = "pack_kind_mismatch"


def _is_valid_rate(value: object) -> TypeGuard[float]:
    """True iff ``value`` is a usable pass-rate / threshold: a FINITE
    real number in the closed interval ``[0.0, 1.0]``.

    **Fail-closed (reviewer P2).** ``bool`` subclasses ``int``, and a
    raw ``isinstance(value, (int, float))`` check also lets ``nan`` /
    ``inf`` / out-of-range floats through. Because ``nan < threshold``
    and ``2.0 < threshold`` are BOTH ``False``, a malformed persisted
    ``pass_rate`` would fall through the builders' ``<`` comparison to
    ``green`` — malformed evidence greenlighting a gate. Requiring a
    finite ``[0.0, 1.0]`` value here means anything malformed routes to
    ``evidence_not_attached`` (the harness did not produce trustworthy
    evidence) rather than ``green``. Typed as a ``TypeGuard`` so the
    gate-input builders narrow the ``Any`` they read off the chain
    payload.
    """
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and 0.0 <= value <= 1.0
    )


def _build_evaluation_gate_input(raw: Any) -> EvaluationGateInput:
    """Build the gate-2 (evaluation) input from ``payload["evaluation"]``.

    Per plan §512 + Reviewer Flag #3 option (c): in Sprint 7B.3 nobody
    writes ``payload["evaluation"]``, so the common case is
    ``evidence_not_attached``. A present-but-shaped payload
    (``{pass_rate, threshold}``) is handled for forward-compatibility:
    ``pass_rate < threshold`` → ``red``; otherwise ``green``.

    **Fail-closed (reviewer P2):** ``pass_rate`` AND ``threshold`` must
    each be a finite real number in ``[0.0, 1.0]`` (see
    :func:`_is_valid_rate`) — ``nan`` / ``inf`` / out-of-range values
    route to ``evidence_not_attached``, NEVER ``green``.
    """
    if not isinstance(raw, dict):
        return EvaluationGateInput(
            outcome="evidence_not_attached",
            red_reason="evaluation_evidence_not_attached",
            pass_rate=None,
            threshold=None,
        )
    pass_rate = raw.get("pass_rate")
    threshold = raw.get("threshold")
    if not _is_valid_rate(pass_rate) or not _is_valid_rate(threshold):
        return EvaluationGateInput(
            outcome="evidence_not_attached",
            red_reason="evaluation_evidence_not_attached",
            pass_rate=None,
            threshold=None,
        )
    if pass_rate < threshold:
        return EvaluationGateInput(
            outcome="red",
            red_reason="evaluation_pass_rate_below_threshold",
            pass_rate=float(pass_rate),
            threshold=float(threshold),
        )
    return EvaluationGateInput(
        outcome="green",
        red_reason=None,
        pass_rate=float(pass_rate),
        threshold=float(threshold),
    )


def _build_adversarial_gate_input(raw: Any) -> AdversarialGateInput:
    """Build the gate-3 (adversarial) input from ``payload["adversarial"]``.

    Per plan §513: same evidence-not-attached default as evaluation. A
    present payload (``{pass_rate, high_severity_failures}``) reads:
    any high-severity failure → ``red``; else ``pass_rate`` below the
    ADR-011 floor → ``red``; else ``green``.

    **Fail-closed (reviewer P2):** ``pass_rate`` must be a finite real
    number in ``[0.0, 1.0]`` (see :func:`_is_valid_rate`) and
    ``high_severity_failures`` must be a NON-NEGATIVE ``int`` — ``nan``
    / ``inf`` / out-of-range pass rates and negative counts route to
    ``evidence_not_attached``, NEVER ``green``.
    """
    if not isinstance(raw, dict):
        return AdversarialGateInput(
            outcome="evidence_not_attached",
            red_reason="adversarial_evidence_not_attached",
            pass_rate=None,
            high_severity_failures=0,
        )
    pass_rate = raw.get("pass_rate")
    high_severity_failures = raw.get("high_severity_failures")
    if (
        not _is_valid_rate(pass_rate)
        or not isinstance(high_severity_failures, int)
        or isinstance(high_severity_failures, bool)
        or high_severity_failures < 0
    ):
        return AdversarialGateInput(
            outcome="evidence_not_attached",
            red_reason="adversarial_evidence_not_attached",
            pass_rate=None,
            high_severity_failures=0,
        )
    if high_severity_failures > 0:
        return AdversarialGateInput(
            outcome="red",
            red_reason="adversarial_high_severity_failure",
            pass_rate=float(pass_rate),
            high_severity_failures=high_severity_failures,
        )
    if pass_rate < _ADVERSARIAL_PASS_RATE_THRESHOLD:
        return AdversarialGateInput(
            outcome="red",
            red_reason="adversarial_corpus_pass_rate_below_threshold",
            pass_rate=float(pass_rate),
            high_severity_failures=high_severity_failures,
        )
    return AdversarialGateInput(
        outcome="green",
        red_reason=None,
        pass_rate=float(pass_rate),
        high_severity_failures=high_severity_failures,
    )


def _build_owasp_gate_input(raw: Any) -> OwaspGateInput:
    """Build the gate-4 (OWASP conformance) input from ``payload["conformance"]``.

    Per plan §514 + R10 LOCK Flag #2: ``green`` → green; ``red`` → red +
    ``owasp_conformance_red``; ``yellow`` → **red** + ``owasp_yellow_blocks_approval``
    (yellow means a checker raised → the verdict is untrustworthy); a
    missing / pre-7B.2-T9 ``conformance`` key → ``evidence_not_attached``.
    """
    overall_status = raw.get("overall_status") if isinstance(raw, dict) else None
    if overall_status == "green":
        return OwaspGateInput(outcome="green", red_reason=None, owasp_overall_status="green")
    if overall_status == "red":
        return OwaspGateInput(
            outcome="red",
            red_reason="owasp_conformance_red",
            owasp_overall_status="red",
        )
    if overall_status == "yellow":
        return OwaspGateInput(
            outcome="red",
            red_reason="owasp_yellow_blocks_approval",
            owasp_overall_status="yellow",
        )
    return OwaspGateInput(
        outcome="evidence_not_attached",
        red_reason="owasp_evidence_not_attached",
        owasp_overall_status=None,
    )


async def _resolve_signature_gate_input(
    *,
    trust_gate: TrustGate | None,
    trust_root_resolver: TrustRootResolver | None,
    manifest: dict[str, Any],
    submit_row: DecisionRecord,
    record: PackRecord,
    tenant_id: str,
    request_id: str,
) -> SignatureGateInput:
    """Resolve gate-1 (cosign signature, ADR-016) into a ``SignatureGateInput``.

    Plan T9 step 4 (R5 P2 #4 + R6 P2 #4 + R15 P2 #2 corrected mapping).
    The signature gate is verified at approve time and ALWAYS resolves
    to ``green`` or ``red`` — never ``evidence_not_attached`` (ADR-012
    §110: the cosign gate is absolutely non-overridable, so its outcome
    is the binary :data:`SignatureGateOutcome`).

    Resolution order:

    1. ``trust_gate is None`` → red ``signature_verifier_not_configured``.
    2. ``trust_root_resolver is None`` OR ``resolve_trust_root`` raises
       ``NotImplementedError`` → red ``signature_trust_root_not_configured``.
    3. resolve signature + blob paths via
       :func:`resolve_signature_paths`; ``outcome != "resolved"`` → red
       ``resolution.red_reason`` (one of the 8 resolver-side
       :data:`SignatureRedReason` values, no translation table per R7).
    4. ``payload["manifest"]["pack"]["version"]`` missing / non-string
       → red ``signature_attestation_missing``.
    5. either resolved path does not exist on disk → red
       ``signature_bundle_path_unreachable``.
    6. ``trust_gate.verify_pack_signature(...)`` — success → green +
       ``signature_digest``; ``CosignNotInstalledError`` → red
       ``signature_verifier_not_configured``; ``CosignVerificationFailed``
       → red ``signature_cosign_verify_failed``; ``PathTraversalError``
       → red ``signature_bundle_path_unreachable``; bare ``ValueError``
       (regex-invalid version) → red ``signature_attestation_missing``
       (R15 P2 #2 — ``verify_pack_signature`` raises 4 classes, not 2;
       ``PathTraversalError`` subclasses ``ValueError`` so it is caught
       first).
    """
    if trust_gate is None:
        return SignatureGateInput(
            outcome="red",
            red_reason="signature_verifier_not_configured",
            signature_digest=None,
        )
    if trust_root_resolver is None:
        return SignatureGateInput(
            outcome="red",
            red_reason="signature_trust_root_not_configured",
            signature_digest=None,
        )
    try:
        trust_root = await trust_root_resolver.resolve_trust_root(tenant_id=tenant_id)
    except NotImplementedError:
        return SignatureGateInput(
            outcome="red",
            red_reason="signature_trust_root_not_configured",
            signature_digest=None,
        )

    signed_artefact_root_raw = submit_row.payload.get("signed_artefact_root")
    signed_artefact_root = (
        Path(signed_artefact_root_raw)
        if isinstance(signed_artefact_root_raw, str) and signed_artefact_root_raw
        else None
    )
    resolution = resolve_signature_paths(manifest, signed_artefact_root=signed_artefact_root)
    if resolution.outcome != "resolved":
        return SignatureGateInput(
            outcome="red",
            red_reason=resolution.red_reason,
            signature_digest=None,
        )

    pack_meta = manifest.get("pack")
    version = pack_meta.get("version") if isinstance(pack_meta, dict) else None
    if not isinstance(version, str) or not version:
        return SignatureGateInput(
            outcome="red",
            red_reason="signature_attestation_missing",
            signature_digest=None,
        )

    signature_path = resolution.signature_path
    blob_path = resolution.blob_path
    if signature_path is None or blob_path is None:  # pragma: no cover - resolved ⇒ non-None
        return SignatureGateInput(
            outcome="red",
            red_reason="signature_bundle_path_unreachable",
            signature_digest=None,
        )
    if not signature_path.exists() or not blob_path.exists():
        return SignatureGateInput(
            outcome="red",
            red_reason="signature_bundle_path_unreachable",
            signature_digest=None,
        )

    try:
        result = await trust_gate.verify_pack_signature(
            pack_id=record.pack_id,
            version=version,
            signature_path=signature_path,
            blob_path=blob_path,
            trust_root=trust_root,
            tenant_id=tenant_id,
            request_id=request_id,
        )
    except CosignNotInstalledError:
        return SignatureGateInput(
            outcome="red",
            red_reason="signature_verifier_not_configured",
            signature_digest=None,
        )
    except CosignVerificationFailed:
        return SignatureGateInput(
            outcome="red",
            red_reason="signature_cosign_verify_failed",
            signature_digest=None,
        )
    except PathTraversalError:
        # R15 P2 #2 — resolved path canonicalised outside the operator-
        # approved ``settings.signature_root_path``; same operator-
        # pre-load failure class as "path does not exist". Caught BEFORE
        # bare ``ValueError`` because ``PathTraversalError`` subclasses it.
        #
        # KNOWN LIMITATION (reviewer R16 P3 — deferred): ``verify_pack_signature``
        # canonicalises THREE paths — ``signature_path`` + ``blob_path``
        # (under ``signature_root_path``) AND ``trust_root`` (under
        # ``trust_root_prefix``) — and ``PathTraversalError`` does not
        # carry which one tripped. A trust-root escaping its prefix
        # therefore surfaces here as ``signature_bundle_path_unreachable``
        # rather than a trust-root-specific reason. Distinguishing the
        # two requires either replicating ``trust_gate``'s canonicalisation
        # in this handler (duplicating a security boundary — its own bug
        # class) or extending ``protocol/trust_gate.py`` to expose
        # per-path errors — and the plan EXPLICITLY scopes
        # ``trust_gate.py`` OUT of T9 (plan §114 + §444-447), plus it is
        # an AGENTS.md stop-rule module. The conflation is also NOT
        # reachable in Sprint 7B.3: the only shipped ``TrustRootResolver``
        # is the ``NotImplementedError`` kernel scaffold, which the
        # handler maps to ``signature_trust_root_not_configured`` BEFORE
        # ``verify_pack_signature`` is ever called. Distinguishable
        # trust-root path diagnostics belong with the real Vault-backed
        # resolver work (when ``trust_root_resolver.py`` is promoted to
        # critical-controls per plan §530).
        return SignatureGateInput(
            outcome="red",
            red_reason="signature_bundle_path_unreachable",
            signature_digest=None,
        )
    except ValueError:
        # R15 P2 #2 — regex-invalid ``version`` from the author's
        # manifest reaches ``_validate_version`` inside
        # ``verify_pack_signature``; same "author didn't attach (a
        # usable) what's needed" class as a missing version.
        return SignatureGateInput(
            outcome="red",
            red_reason="signature_attestation_missing",
            signature_digest=None,
        )
    return SignatureGateInput(
        outcome="green",
        red_reason=None,
        signature_digest=result.signature_digest,
    )


def build_review_routes(
    *,
    store: PackRecordStore,
    trust_gate: TrustGate | None = None,
    trust_root_resolver: TrustRootResolver | None = None,
) -> APIRouter:
    """Build the review-surface sub-router.

    The ``store`` argument is captured in this factory so each endpoint
    closes over a single :class:`PackRecordStore` instance per app
    lifespan (mirrors :func:`build_author_routes` at
    ``portal/api/packs/author_routes.py:367``).

    **Sprint 7B.3 T9 — ``trust_gate`` + ``trust_root_resolver`` (R1 P2
    #3 + R2 P2 #1).** Both optional, both captured in the closure for
    the ``approve`` handler's gate-1 (cosign signature) resolution.
    When either is ``None`` the approve handler resolves Gate 1 to a
    ``red`` :class:`SignatureGateInput` (``signature_verifier_not_configured``
    / ``signature_trust_root_not_configured`` respectively) rather than
    crashing — fail-closed. :func:`build_packs_router` +
    :func:`~cognic_agentos.portal.api.app.create_app` thread both deps
    through; production deployments inject a real
    :class:`~cognic_agentos.protocol.trust_gate.TrustGate` +
    :class:`~cognic_agentos.protocol.trust_root_resolver.TrustRootResolver`.

    The returned router does NOT carry a prefix —
    :func:`build_packs_router` mounts it under the parent
    ``/api/v1/packs`` prefix so each endpoint's full path is
    ``/api/v1/packs[…]``.

    **Shared dependency instances** — built once per router-factory
    invocation. The shared ``_require_tenant_ownership`` instance is
    re-used by ``_require_different_actor_than_creator`` per Round 14
    P2 #3: FastAPI's per-request callable-identity sub-dependency
    cache deduplicates the ``PackRecord`` load → ONE ``store.load``
    call on the happy path.
    """
    router = APIRouter()

    # Shared dependency instances (R14 P2 #3 — same `_require_tenant_ownership`
    # passed to both the endpoint Depends AND the role-separation factory
    # so FastAPI's per-request cache dedupes the PackRecord load).
    _require_pack_review_claim = RequireScope("pack.review.claim")
    _require_pack_review_approve = RequireScope("pack.review.approve")
    _require_pack_review_reject = RequireScope("pack.review.reject")
    _require_pack_audit_read = RequireScope("pack.audit.read")
    _require_tenant_ownership = RequireTenantOwnership(pack_id_param="pack_id")
    _require_different_actor_than_creator = RequireDifferentActorThanCreator(
        tenant_ownership=_require_tenant_ownership,
    )

    @router.get("/review-queue", summary="Reviewer queue — submitted packs scoped to tenant")
    async def review_queue(
        request: Request,
        actor: Annotated[Actor, Depends(_require_pack_review_claim)],
    ) -> list[PackResponse]:
        """Reviewer queue scoped to ``actor.tenant_id``.

        Plan R2 P3 #8 — gated by ``pack.review.claim`` (the reviewer-
        claim scope, NOT examiner-facing ``pack.audit.read``).

        Plan R11 P2 #1 — calls
        ``store.list_by_status("submitted", tenant_id=actor.tenant_id)``
        so the tenant filter applies SERVER-SIDE via the
        ``ix_packs_tenant_state`` composite index per migration L129.
        No per-pack ``RequireTenantOwnership`` dependency — there is
        no ``{pack_id}`` to verify; the storage WHERE clause IS the
        authoritative tenant boundary.

        Plan R12 P2 #1 — path is ``/review-queue`` (distinct from
        ADR-012 §62's sketch ``?status=submitted`` which would collide
        with T7's ``GET /api/v1/packs``).

        **R23 P2 #1 — route-level ``actor_tenant_id_missing``
        preflight guard**: this endpoint bypasses
        :func:`RequireTenantOwnership` (no ``{pack_id}`` path-param)
        which means it ALSO bypasses the existing 500
        ``actor_tenant_id_missing`` emission at
        ``tenant_isolation.py``. An actor with empty ``tenant_id`` +
        scope held would otherwise receive 200 [] — silently hiding a
        kernel binder misconfig that path-param endpoints fail-loud-500
        on. Mirrors the T7 inspection-list preflight pattern.

        Sprint-7B.4 T6: now routes through the shared
        :func:`_emit_denial_or_500` helper (same dual-surface
        contract as the path-param-tenant-isolated endpoints — log
        first, then chain row via the broker if wired). The
        ``"<review-queue>"`` sentinel keeps log-aggregator bucketing
        discoverable while staying type-safe under mypy.
        """
        if not actor.tenant_id:
            broker = getattr(request.app.state, "ui_event_broker", None)
            await _emit_denial_or_500(
                broker,
                denial_type="actor_tenant_id_missing",
                actor_subject=actor.subject,
                tenant_id=None,  # actor.tenant_id is empty
                request_id=_resolve_request_id(request),
                http_status=500,
                pack_id="<review-queue>",  # sentinel — no {pack_id} at this endpoint
            )
            raise HTTPException(
                status_code=500,
                detail={"reason": "actor_tenant_id_missing"},
            )

        records = await store.list_by_status(
            "submitted",
            tenant_id=actor.tenant_id,
        )
        return [PackResponse.model_validate(r) for r in records]

    @router.post("/{pack_id}/claim", summary="Claim a submitted pack for review")
    async def claim(
        actor: Annotated[Actor, Depends(_require_pack_review_claim)],
        record: Annotated[PackRecord, Depends(_require_tenant_ownership)],
        _: Annotated[None, Depends(_require_different_actor_than_creator)],
    ) -> PackResponse:
        """Transition ``submitted → under_review`` via
        ``store.transition("claim", ...)``.

        Plan R14 P2 #3 dependency chain (resolution order):
        1. ``_require_pack_review_claim`` (RequireScope) — 403
           ``scope_not_held`` for missing scope.
        2. ``_require_tenant_ownership`` (RequireTenantOwnership) —
           404 ``tenant_id_mismatch`` for cross-tenant; returns the
           ``PackRecord`` (also reused by the role-separation guard).
        3. ``_require_different_actor_than_creator`` — 403
           ``actor_cannot_review_own_pack`` when actor.subject ==
           record.created_by (ADR-012 §17 cross-role separation).

        Handler-body refusals:
        - :class:`PackNotFound` race (R16 P2 #2) — concurrent delete
          between tenant-isolation preload + transition() SELECT FOR
          UPDATE → translate to 404 ``pack_not_found``.
        - :class:`LifecycleTransitionRefused` — state-machine refusal
          (e.g. claim on draft pack) → 409 + closed-enum reason from
          the :data:`LifecycleRefusalReason` literal.

        Structured-log contract (R17 P2 #2):
        ``portal.packs.claim_refused`` event fires on every handler-
        body refusal with reason + actor_subject + pack_id + from_state.
        """
        try:
            await store.transition(
                pack_id=record.id,
                transition="claim",
                actor_id=actor.subject,
                tenant_id=actor.tenant_id,
                evidence_pointer=None,
                request_id=_mint_request_id(_PACK_CLAIM_REQUEST_ID_PREFIX),
            )
        except PackNotFound:
            # R16 P2 #2 — race: row gone between tenant-isolation
            # preload + transition() precondition. Mirror the 404 +
            # closed-enum body the tenant-isolation layer surfaces.
            _LOG.warning(
                "portal.packs.claim_refused",
                extra={
                    "reason": _PACK_NOT_FOUND_REASON,
                    "actor_subject": actor.subject,
                    "pack_id": str(record.id),
                    "from_state": record.state,
                },
            )
            raise HTTPException(
                status_code=404,
                detail={"reason": _PACK_NOT_FOUND_REASON},
            ) from None
        except LifecycleTransitionRefused as exc:
            _LOG.warning(
                "portal.packs.claim_refused",
                extra={
                    "reason": exc.reason,
                    "actor_subject": actor.subject,
                    "pack_id": str(record.id),
                    "from_state": record.state,
                },
            )
            raise HTTPException(
                status_code=409,
                detail={"reason": exc.reason},
            ) from None

        updated = await store.load(record.id)
        if updated is None:  # pragma: no cover - defence-in-depth
            # Race: row deleted between transition success and re-load.
            raise HTTPException(
                status_code=404,
                detail={"reason": _PACK_NOT_FOUND_REASON},
            )
        return PackResponse.model_validate(updated)

    @router.post(
        "/{pack_id}/approve",
        summary="Approve a pack — ADR-012 §41 five-gate composition + override path",
    )
    async def approve(
        body: ApproveRequest,
        actor: Annotated[Actor, Depends(_require_pack_review_approve)],
        record: Annotated[PackRecord, Depends(_require_tenant_ownership)],
        _: Annotated[None, Depends(_require_different_actor_than_creator)],
    ) -> PackResponse:
        """Approve a pack via the ADR-012 §41 five-gate composition.

        Sprint 7B.3 T9 — replaces the T5 fail-loud 503 stub. Wires the
        :func:`~cognic_agentos.packs.approval_gates.compose_approval_gates`
        composer + the ADR-012 §107 override path.

        Dependency chain (resolution order — sibling-guard refusals
        never reach this body):

        1. ``_require_pack_review_approve`` → 403 ``scope_not_held``.
        2. ``_require_tenant_ownership`` → 404 ``tenant_id_mismatch``.
        3. ``_require_different_actor_than_creator`` → 403
           ``actor_cannot_review_own_pack`` (ADR-012 §17).

        Pre-composer handler-body refusals (all 409 + ``portal.packs.approve_refused``
        log; mirrors the ``EvidencePanelRefusalReason`` closed-enum):

        - no submit chain row → ``pack_not_yet_submitted``;
        - submit row missing ``payload["manifest"]`` →
          ``manifest_evidence_not_persisted``;
        - ``manifest["pack"]["kind"] != record.kind`` →
          ``pack_kind_mismatch`` (R9 kind-integrity).

        Gate composition + terminal axes (plan §500-528):

        - **all-green** → ``store.transition("approve", ...)`` →
          ``portal.packs.approve_5_gate_green`` + the updated
          :class:`PackResponse`.
        - **not-all-green, no override_reason** → **412** carrying
          :class:`ApproveRefusalResponse` +
          ``portal.packs.approve_5_gate_red_no_override``.
        - **not-all-green, override_reason supplied, override refused**
          (:func:`evaluate_override_decision` → ``allowed=False``) →
          **412** carrying :class:`ApproveRefusalResponse` with
          ``override_refusal_reason`` + ``portal.packs.approve_override_refused``.
        - **not-all-green, override granted** → emit the
          ``pack.approval_override`` chain event FIRST (immutable
          authorisation fact, R3 P2 #4), then ``store.transition(
          "approve", ..., override_event_id=...)`` →
          ``portal.packs.approve_overridden`` + the updated
          :class:`PackResponse`.
        - **R15 P2 #3** — on EITHER transition leg (all-green OR
          override-granted) a ``PackNotFound`` race / a
          ``LifecycleTransitionRefused`` state-machine refusal (approve
          called on a pack that passed the dep chain but is not in
          ``under_review``) translates to 404 ``pack_not_found`` / 409 +
          the closed-enum reason, with ``portal.packs.approve_transition_refused``.
          On the override-granted leg the ``pack.approval_override``
          chain event has already been emitted and CORRECTLY dangles
          (R3 P2 #4 dangling-override audit design) — NOT rolled back.
        """

        def _raise_transition_refused(
            exc: PackNotFound | LifecycleTransitionRefused,
        ) -> NoReturn:
            """R15 P2 #3 — translate an approve-transition leg refusal.

            Fires the ``portal.packs.approve_transition_refused`` log +
            raises 404 ``pack_not_found`` (race) / 409 + closed-enum
            ``LifecycleTransitionRefused.reason`` (state-machine).
            """
            if isinstance(exc, PackNotFound):
                status_code, reason = 404, _PACK_NOT_FOUND_REASON
            else:
                status_code, reason = 409, exc.reason
            _LOG.warning(
                "portal.packs.approve_transition_refused",
                extra={
                    "reason": reason,
                    "actor_subject": actor.subject,
                    "pack_id": str(record.id),
                    "from_state": record.state,
                },
            )
            raise HTTPException(status_code=status_code, detail={"reason": reason})

        async def _reload_approved_pack() -> PackResponse:
            updated = await store.load(record.id)
            if updated is None:  # pragma: no cover - defence-in-depth
                raise HTTPException(status_code=404, detail={"reason": _PACK_NOT_FOUND_REASON})
            return PackResponse.model_validate(updated)

        # --- Steps 2-3: lifecycle history → submit row → manifest + kind ---
        history = await store.load_lifecycle_history(record.id)
        submit_row = find_latest_submit_row(history)
        if submit_row is None:
            _LOG.warning(
                "portal.packs.approve_refused",
                extra={
                    "reason": _PACK_NOT_YET_SUBMITTED_REASON,
                    "actor_subject": actor.subject,
                    "pack_id": str(record.id),
                    "from_state": record.state,
                },
            )
            raise HTTPException(status_code=409, detail={"reason": _PACK_NOT_YET_SUBMITTED_REASON})

        manifest = submit_row.payload.get("manifest")
        if not isinstance(manifest, dict):
            _LOG.warning(
                "portal.packs.approve_refused",
                extra={
                    "reason": _MANIFEST_EVIDENCE_NOT_PERSISTED_REASON,
                    "actor_subject": actor.subject,
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
        # R9 kind-integrity: the manifest's pack.kind MUST be present,
        # a string, AND equal the authoritative PackRecord.kind — a
        # corrupted persisted manifest cannot bypass the integrity gate
        # (mirrors evidence_routes.py's kind-integrity invariant).
        if not isinstance(manifest_kind, str) or manifest_kind != record.kind:
            _LOG.warning(
                "portal.packs.approve_refused",
                extra={
                    "reason": _PACK_KIND_MISMATCH_REASON,
                    "actor_subject": actor.subject,
                    "pack_id": str(record.id),
                    "record_kind": record.kind,
                    "manifest_kind": manifest_kind,
                },
            )
            raise HTTPException(status_code=409, detail={"reason": _PACK_KIND_MISMATCH_REASON})

        request_id = _mint_request_id(_PACK_APPROVE_REQUEST_ID_PREFIX)

        # --- Steps 4-7: pre-compute the 5 gate inputs ---
        signature_input = await _resolve_signature_gate_input(
            trust_gate=trust_gate,
            trust_root_resolver=trust_root_resolver,
            manifest=manifest,
            submit_row=submit_row,
            record=record,
            tenant_id=actor.tenant_id,
            request_id=request_id,
        )
        evaluation_input = _build_evaluation_gate_input(submit_row.payload.get("evaluation"))
        adversarial_input = _build_adversarial_gate_input(submit_row.payload.get("adversarial"))
        owasp_input = _build_owasp_gate_input(submit_row.payload.get("conformance"))

        # --- Step 8: compose ---
        composition = compose_approval_gates(
            signature_input=signature_input,
            evaluation_input=evaluation_input,
            adversarial_input=adversarial_input,
            owasp_input=owasp_input,
            pack_kind=record.kind,
            reviewer_acknowledgement=body.acknowledgement.model_dump(),
        )

        # --- Step 9: branch on composition.all_green (R12) ---
        if composition.all_green:
            try:
                await store.transition(
                    pack_id=record.id,
                    transition="approve",
                    actor_id=actor.subject,
                    tenant_id=actor.tenant_id,
                    evidence_pointer=None,
                    request_id=request_id,
                    reviewer_acknowledgement=body.acknowledgement.model_dump(),
                )
            except (PackNotFound, LifecycleTransitionRefused) as exc:
                _raise_transition_refused(exc)
            _LOG.warning(
                "portal.packs.approve_5_gate_green",
                extra={
                    "actor_subject": actor.subject,
                    "pack_id": str(record.id),
                },
            )
            return await _reload_approved_pack()

        # not-all-green AND no override_reason → 412, no transition.
        if body.override_reason is None:
            _LOG.warning(
                "portal.packs.approve_5_gate_red_no_override",
                extra={
                    "actor_subject": actor.subject,
                    "pack_id": str(record.id),
                    "non_overridable_red_gates": sorted(composition.non_overridable_red_gates),
                },
            )
            raise HTTPException(
                status_code=412,
                detail=ApproveRefusalResponse(**composition_snapshot(composition)).model_dump(),
            )

        # not-all-green AND override_reason supplied → evaluate override.
        override_decision = evaluate_override_decision(
            composition=composition,
            override_scope_held="pack.override.approval_gate" in actor.scopes,
            override_reason=body.override_reason,
        )
        if not override_decision.allowed:
            _LOG.warning(
                "portal.packs.approve_override_refused",
                extra={
                    "reason": override_decision.refusal_reason,
                    "actor_subject": actor.subject,
                    "pack_id": str(record.id),
                },
            )
            raise HTTPException(
                status_code=412,
                detail=ApproveRefusalResponse(
                    **composition_snapshot(composition),
                    override_refusal_reason=override_decision.refusal_reason,
                ).model_dump(),
            )

        # Override granted — emit the pack.approval_override chain event
        # FIRST as the immutable authorisation fact (R3 P2 #4); the
        # subsequent approve transition is an INDEPENDENT chain event.
        override_result = await store.append_override_event(
            pack_id=record.id,
            override_actor_subject=actor.subject,
            override_reason=body.override_reason,
            gate_composition_snapshot=composition_snapshot(composition),
            request_id=request_id,
        )
        try:
            await store.transition(
                pack_id=record.id,
                transition="approve",
                actor_id=actor.subject,
                tenant_id=actor.tenant_id,
                evidence_pointer=None,
                request_id=request_id,
                reviewer_acknowledgement=body.acknowledgement.model_dump(),
                override_event_id=str(override_result.record_id),
            )
        except (PackNotFound, LifecycleTransitionRefused) as exc:
            # R3 P2 #4 — the pack.approval_override chain event above
            # has already committed and CORRECTLY dangles; the handler
            # does NOT (and cannot atomically) roll it back.
            _raise_transition_refused(exc)
        _LOG.warning(
            "portal.packs.approve_overridden",
            extra={
                "actor_subject": actor.subject,
                "pack_id": str(record.id),
                "override_reason": body.override_reason,
                "override_event_id": str(override_result.record_id),
            },
        )
        return await _reload_approved_pack()

    @router.post("/{pack_id}/reject", summary="Reject a pack with categorised reason")
    async def reject(
        body: RejectDraftRequest,
        actor: Annotated[Actor, Depends(_require_pack_review_reject)],
        record: Annotated[PackRecord, Depends(_require_tenant_ownership)],
        _: Annotated[None, Depends(_require_different_actor_than_creator)],
    ) -> PackResponse:
        """Transition ``under_review → rejected`` via
        ``store.transition("reject", ...)``.

        Plan R14 P2 #3 dependency chain: RBAC → tenant → role-separation
        (mirrors claim handler at slice 2a).

        Body: :class:`RejectDraftRequest` (R11 P2 #2) — ``reason``
        (7-value closed-enum :data:`RejectionReason`) + ``comments``
        (required non-empty str). Out-of-vocab reason or empty
        comments → 422 from Pydantic body validation BEFORE this
        handler runs.

        T5 narrow scope (R11 P2 #3 + R12 P2 #2 + R18 P2 #2) +
        Sprint 7B.2 T9 Slice 3 carry-forward: the categorised reason +
        comments emit via BOTH the ``portal.packs.review.reject``
        structured log (operations surface, T5 carry-forward) AND
        the chain row's ``payload["evidence_attachments"]`` field
        (examiner surface, NEW at T9 via the third ``transition()``
        kwarg per plan §1086-1088).  The chain payload is the
        authoritative source for evidence-pack export per ADR-006;
        the structured log stays as the ops surface for operational
        observability tooling (defence-in-depth dual emission).

        Storage stays a thin passthrough — the
        ``evidence_attachments`` kwarg accepts any dict; the
        ``{"rejection_reason", "reviewer_comments"}`` closed-set
        shape is owned by this route + its tests, NOT by storage.

        Mutually-exclusive structured-log emission per R18 P2 #2:
        - Green: EXACTLY ONE ``portal.packs.review.reject`` record.
        - Refused (state-machine OR PackNotFound race): EXACTLY ONE
          ``portal.packs.reject_refused`` record.
        """
        try:
            await store.transition(
                pack_id=record.id,
                transition="reject",
                actor_id=actor.subject,
                tenant_id=actor.tenant_id,
                evidence_pointer=None,
                request_id=_mint_request_id(_PACK_REJECT_REQUEST_ID_PREFIX),
                # T9 Slice 3 carry-forward (plan §1086-1088): categorised
                # reject payload migrates from log-only to chain row.
                # Closed-set shape {rejection_reason, reviewer_comments}
                # owned by this route — storage stays thin passthrough.
                evidence_attachments={
                    "rejection_reason": body.reason,
                    "reviewer_comments": body.comments,
                },
            )
        except PackNotFound:
            # R16 P2 #2 — race translation; refused-event log only
            # (mutually-exclusive with the accepted-evidence log per
            # R18 P2 #2).
            _LOG.warning(
                "portal.packs.reject_refused",
                extra={
                    "reason": _PACK_NOT_FOUND_REASON,
                    "actor_subject": actor.subject,
                    "pack_id": str(record.id),
                    "from_state": record.state,
                },
            )
            raise HTTPException(
                status_code=404,
                detail={"reason": _PACK_NOT_FOUND_REASON},
            ) from None
        except LifecycleTransitionRefused as exc:
            _LOG.warning(
                "portal.packs.reject_refused",
                extra={
                    "reason": exc.reason,
                    "actor_subject": actor.subject,
                    "pack_id": str(record.id),
                    "from_state": record.state,
                },
            )
            raise HTTPException(
                status_code=409,
                detail={"reason": exc.reason},
            ) from None

        # Green path: emit the structured operations-surface log
        # carrying the categorised reason + comments (R11 P2 #3 +
        # R18 P2 #2).  T9 Slice 3 has migrated the same pair to the
        # chain row's ``payload["evidence_attachments"]`` (examiner
        # surface, threaded via the ``evidence_attachments`` kwarg
        # above); the log emission stays as the operations surface
        # for live observability tooling (defence-in-depth dual
        # surface — chain row is the authoritative source per ADR-006).
        _LOG.warning(
            "portal.packs.review.reject",
            extra={
                "reason": body.reason,
                "comments": body.comments,
                "actor_subject": actor.subject,
                "pack_id": str(record.id),
            },
        )

        updated = await store.load(record.id)
        if updated is None:  # pragma: no cover - defence-in-depth
            raise HTTPException(
                status_code=404,
                detail={"reason": _PACK_NOT_FOUND_REASON},
            )
        return PackResponse.model_validate(updated)

    @router.get("/{pack_id}/evidence", summary="Read pack conformance evidence")
    async def evidence(
        actor: Annotated[Actor, Depends(_require_pack_audit_read)],
        record: Annotated[PackRecord, Depends(_require_tenant_ownership)],
    ) -> PackEvidenceResponse:
        """Read pack conformance evidence per plan R11 P3 #5.

        Walks :meth:`PackRecordStore.load_lifecycle_history` for the
        pack; finds the most-recent ``event_type ==
        "pack.lifecycle.submitted"`` chain row; surfaces its
        ``payload.get("conformance")`` value on the response's
        ``conformance`` field.

        Sprint 7B.2 T9 Slice 2 wired auto-run-on-submit, so submit
        chain rows produced from T9 onward carry the OWASP
        conformance suite result under ``payload.conformance`` per
        :func:`run_owasp_conformance_for_chain_payload`'s 4-key
        wire-shape.  Historical / pre-T9 submit chain rows (created
        by fixtures or by the T5-era submit handler before Slice 2
        landed) have no ``conformance`` key — the endpoint surfaces
        ``None`` for those rows gracefully (NOT 500); both shapes
        coexist in production via the same response schema.

        ``reviewer_evidence_panels`` remains always-null in 7B.2;
        Sprint 7B.3 will fill it with the full evidence-panel object
        once the 5-gate composition lands.

        Gated by ``RequireScope("pack.audit.read")`` (examiner-facing
        per ADR-012 §75) + ``RequireTenantOwnership`` (no role-
        separation guard — this is a read-only endpoint, anyone with
        audit-read on a tenant can inspect any pack in that tenant).
        """
        _ = actor  # bound for the auth trail; not used in read-path
        history = await store.load_lifecycle_history(record.id)
        # Most-recent submit row first. `load_lifecycle_history`
        # returns rows ordered by sequence ASC per the storage seam at
        # `packs/storage.py:919` (signature) — `order_by(sequence)` on
        # the inner query; iterate in reverse to find the most-recent
        # submit. (Pre-T9: there is at most one submit row per pack
        # lifecycle; post-T9 may have re-submits after withdraw/cancel
        # cycles, in which case the LATEST submit is the relevant
        # evidence surface.)
        conformance: dict[str, Any] | None = None
        for row in reversed(history):
            if row.decision_type == "pack.lifecycle.submitted":
                conformance = row.payload.get("conformance")
                break

        return PackEvidenceResponse(
            conformance=conformance,
            reviewer_evidence_panels=None,
        )

    return router


# Module-foot build-time invariant (mirrors T4 R3 P2 #1 at
# author_routes.py module-foot): every request-id prefix declared in
# this module + uuid4().hex (32) MUST fit under the 64-char
# decision_history.request_id column cap. Static prefix lengths are
# 12 chars each → 12 + 32 = 44 chars, well under the cap.
assert len(_PACK_CLAIM_REQUEST_ID_PREFIX) + 32 <= _REQUEST_ID_MAX_LEN, (
    f"_PACK_CLAIM_REQUEST_ID_PREFIX too long: "
    f"len(prefix)={len(_PACK_CLAIM_REQUEST_ID_PREFIX)} + 32 hex chars > "
    f"{_REQUEST_ID_MAX_LEN} (decision_history.request_id column cap)"
)
assert len(_PACK_REJECT_REQUEST_ID_PREFIX) + 32 <= _REQUEST_ID_MAX_LEN, (
    f"_PACK_REJECT_REQUEST_ID_PREFIX too long: "
    f"len(prefix)={len(_PACK_REJECT_REQUEST_ID_PREFIX)} + 32 hex chars > "
    f"{_REQUEST_ID_MAX_LEN} (decision_history.request_id column cap)"
)
assert len(_PACK_APPROVE_REQUEST_ID_PREFIX) + 32 <= _REQUEST_ID_MAX_LEN, (
    f"_PACK_APPROVE_REQUEST_ID_PREFIX too long: "
    f"len(prefix)={len(_PACK_APPROVE_REQUEST_ID_PREFIX)} + 32 hex chars > "
    f"{_REQUEST_ID_MAX_LEN} (decision_history.request_id column cap)"
)


__all__ = ["build_review_routes"]
