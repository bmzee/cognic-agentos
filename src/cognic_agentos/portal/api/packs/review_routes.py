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
from typing import Annotated, Any, Final

from fastapi import APIRouter, Depends, HTTPException

from cognic_agentos.packs.lifecycle import LifecycleTransitionRefused
from cognic_agentos.packs.storage import PackNotFound, PackRecord, PackRecordStore
from cognic_agentos.portal.api.packs.author_routes import _mint_request_id
from cognic_agentos.portal.api.packs.dto import (
    PackEvidenceResponse,
    PackResponse,
    RejectDraftRequest,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope
from cognic_agentos.portal.rbac.role_separation import RequireDifferentActorThanCreator
from cognic_agentos.portal.rbac.tenant_isolation import (
    RequireTenantOwnership,
    _emit_isolation_log,
)

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


def build_review_routes(*, store: PackRecordStore) -> APIRouter:
    """Build the review-surface sub-router.

    The ``store`` argument is captured in this factory so each endpoint
    closes over a single :class:`PackRecordStore` instance per app
    lifespan (mirrors :func:`build_author_routes` at
    ``portal/api/packs/author_routes.py:367``).

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
        ``tenant_isolation.py:144-152``. An actor with empty
        ``tenant_id`` + scope held would otherwise receive 200 [] —
        silently hiding a kernel binder misconfig that path-param
        endpoints fail-loud-500 on. Mirrors the T7 inspection-list
        preflight pattern (plan R20 P2 #2 + R21 P2 #1 type-corrected).
        ``_emit_isolation_log(pack_id: str)`` requires ``str``; the
        ``"<review-queue>"`` sentinel keeps log-aggregator bucketing
        discoverable while staying type-safe under mypy.
        """
        if not actor.tenant_id:
            _emit_isolation_log(
                reason="actor_tenant_id_missing",
                actor_subject=actor.subject,
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

    @router.post("/{pack_id}/approve", summary="Approve a pack (FAIL-LOUD 503 in T5)")
    async def approve(
        actor: Annotated[Actor, Depends(_require_pack_review_approve)],
        record: Annotated[PackRecord, Depends(_require_tenant_ownership)],
        _: Annotated[None, Depends(_require_different_actor_than_creator)],
    ) -> dict[str, object]:
        """FAIL-LOUD 503 scaffold per plan R1 P2 #1.

        ADR-012 §41 requires approve to refuse when any of the 5
        gates is red; shipping a green-path approve in T5 would
        either (a) make the transition rollback-required when 7B.3
        wires the gate composer in (data corruption risk if any pack
        got approved between 7B.2 land and 7B.3 land), or (b)
        silently violate ADR-012 §41 in production. T5 ships approve
        as a fail-loud 503 — the 5-gate composer lands at Sprint 7B.3.

        Plan R11 P3 #6 — 4-axis dependency-cascade matrix:
        (a) RequireScope → 403 ``scope_not_held``
        (b) RequireTenantOwnership → 404 ``tenant_id_mismatch``
        (c) RequireDifferentActorThanCreator → 403
            ``actor_cannot_review_own_pack``
        (d) Handler body (this code) → 503
            ``approve_gate_composer_not_wired``

        Plan T5 watchpoint (a) — NO state transition; NO chain row
        emitted. Plan R18 P2 #2 + R19 P2 #1 — handler-emitted log
        ``portal.packs.approve_fail_loud_503`` fires ONLY on axis (d)
        (this code path); axes (a)/(b)/(c) emit their sibling-guard
        logs and never reach the handler body.
        """
        # Round 16 P2 #3-style structured log on the handler-reached
        # path so observability tooling sees the 503 emission.
        _LOG.warning(
            "portal.packs.approve_fail_loud_503",
            extra={
                "reason": "approve_gate_composer_not_wired",
                "actor_subject": actor.subject,
                "pack_id": str(record.id),
                "next_sprint": "7B.3",
            },
        )
        raise HTTPException(
            status_code=503,
            detail={
                "reason": "approve_gate_composer_not_wired",
                "next_sprint": "7B.3",
                "adr": "ADR-012 §41",
            },
        )

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

        T5 narrow scope (R11 P2 #3 + R12 P2 #2 + R18 P2 #2):
        chain row carries the bare transition payload only.
        Categorised reason + comments emit via
        ``portal.packs.review.reject`` structured log on the green
        path (load-bearing T5 evidence surface). T9 carry-forward
        migrates these to the chain row's
        ``payload["evidence_attachments"]`` via the third
        ``transition()`` kwarg.

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

        # Green path: emit the load-bearing T5 evidence log carrying
        # the categorised reason + comments (R11 P2 #3 + R18 P2 #2).
        # T9 carry-forward will migrate these fields to the chain row.
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
        ``conformance`` field — ``None`` for pre-T9 chain rows that
        carry no ``conformance`` key.

        Plan T5 caveat: until T9 lands, ALL submit chain rows are
        pre-T9 fixtures with no ``conformance`` key — the endpoint
        surfaces ``{"conformance": null, "reviewer_evidence_panels":
        null}`` gracefully (NOT 500). The ``reviewer_evidence_panels``
        field is always-null in 7B.2; 7B.3 will fill it with the full
        evidence-panel object.

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


__all__ = ["build_review_routes"]
