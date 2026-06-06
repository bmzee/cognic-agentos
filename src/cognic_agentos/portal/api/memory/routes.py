"""Sprint 11.5c T5 — /api/v1/memory portal surface (CRITICAL CONTROLS).

Four endpoints mounted at ``/api/v1/memory`` (prefix added at include_router
time by app.py):

- ``GET  /records`` — ``memory.read`` scope; value-free enumerate.
- ``POST /records/{record_id}/forget`` — ``memory.forget`` scope; body-aware
  human-only gate on ``regulator_erasure``.
- ``POST /records/{record_id}/redact`` — ``memory.redact`` scope.
- ``POST /export`` — ``memory.export.read`` scope + static RequireHumanActor
  (export is ALWAYS human-only).

Human-only decisions enforcement:
- ``forget(reason="regulator_erasure")``: body-aware gate (cannot be a static
  Depends because the body determines whether the gate fires). The handler
  resolves the Actor from the primary scope dep, THEN inspects
  ``actor.scopes`` + ``actor.actor_type`` inline before the core call.
- ``export``: static ``Depends(RequireHumanActor())`` sub-dependency (export
  is ALWAYS human-only, no body-routing needed).

**Standing-offer §30 — module-header invariant**: ``from __future__ import
annotations`` is INTENTIONALLY OMITTED here (same as
``portal/api/packs/operator_routes.py``,
``portal/api/packs/review_routes.py``, etc.). PEP 563 string-deferred
annotations prevent FastAPI's ``inspect.signature()`` /
``typing.get_type_hints()`` from resolving
``Annotated[..., Depends(<closure-local>)]`` on the inner endpoint handlers
(the shared dependency instances like ``_require_memory_read`` are LOCAL
variables inside :func:`build_memory_routes`, NOT module globals). Adding the
future-import would make FastAPI silently fall back to treating handler
parameters as query params — a regression pinned by the AST self-test in
``tests/unit/portal/api/memory/test_memory_routes.py``.

Architecture guard: this module MUST NOT runtime-import
``cognic_agentos.core.memory.storage`` (the arch guard at
``tests/unit/architecture/test_memory_layer_c_no_direct_storage.py`` refuses
any such import). The route accesses memory exclusively via a per-request
:class:`MemoryAPI` built by the injected factory.
"""

import logging
import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request

from cognic_agentos.core.memory._context import (
    MemoryCallerContext,
    RedactionSpan,
    RegulatorErasureCommand,
)
from cognic_agentos.core.memory.api import MemoryAPI, MemoryApiFactory
from cognic_agentos.core.memory.tiers import MemoryOperationRefused, SubjectRef
from cognic_agentos.portal.api.memory.dto import (
    ExportReceiptResponse,
    ExportRequest,
    ForgetReceiptResponse,
    ForgetRequest,
    MemoryRecordMetadataResponse,
    RedactionReceiptResponse,
    RedactRequest,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope
from cognic_agentos.portal.rbac.human_actor import RequireHumanActor

_LOG = logging.getLogger(__name__)

# Wire-public closed-enum reason values mirrored from MemoryRefusalReason.
_MEMORY_RECORD_NOT_FOUND: str = "memory_record_not_found"

# Wire-public closed-enum reason for a mounted-but-unwired /memory surface.
_MEMORY_UNAVAILABLE: str = "memory_unavailable"


def _require_memory_api_factory(request: Request) -> MemoryApiFactory:
    """Resolve the MemoryAPI factory from ``app.state`` at REQUEST time.

    The factory is seeded at app construction (the ``create_app(
    memory_api_factory=...)`` path sets ``app.state.memory_api_factory``) or by
    ``build_runtime`` in the lifespan (prod path, T8). A mounted route whose
    factory is still absent fails closed ``503 memory_unavailable`` — never a
    500 from calling ``None``."""
    factory: MemoryApiFactory | None = getattr(request.app.state, "memory_api_factory", None)
    if factory is None:
        raise HTTPException(status_code=503, detail={"reason": _MEMORY_UNAVAILABLE})
    return factory


def _operator_context(
    actor: Actor,
    *,
    agent_id: str,
    subject: SubjectRef,
) -> MemoryCallerContext:
    """Build the per-request operator MemoryCallerContext from the resolved
    Actor + body-supplied identity fields. ``is_subagent`` is ALWAYS False —
    the portal surface is an operator surface, never a sub-agent. Identity
    comes from the Actor; the caller cannot smuggle a different tenant.
    """
    return MemoryCallerContext(
        tenant_id=actor.tenant_id,
        agent_id=agent_id,
        actor_id=actor.subject,
        served_subject=subject,
        is_subagent=False,
        long_term_writes_allowed=False,
        cross_subject_recall=False,
        memory_read_capabilities=frozenset({"memory_read.task", "memory_read.long_term"}),
        declared_purposes=frozenset(),
        declared_data_classes=frozenset(),
        risk_tier="read_only",
    )


def build_memory_routes() -> APIRouter:
    """Build the /memory sub-router.

    Each endpoint resolves the per-request :class:`MemoryAPI` factory from
    ``app.state.memory_api_factory`` via the module-level
    :func:`_require_memory_api_factory` dependency (seeded at construction on
    the test path via ``create_app(memory_api_factory=...)``, by
    ``build_runtime`` in the lifespan on the prod path), then builds a
    per-request :class:`MemoryAPI` from the operator context it derives from
    the resolved Actor + request body. A mounted route whose factory is absent
    fails closed ``503 memory_unavailable`` rather than 500-ing on a ``None``
    call.

    The returned router does NOT carry a prefix — ``create_app`` mounts it
    under ``/api/v1/memory`` so each endpoint's full path is
    ``/api/v1/memory/<path>``.

    **Shared dependency instances**: built once per router-factory invocation
    so FastAPI's per-request sub-dependency cache deduplicates the actor-bind
    call across all endpoints on the same request.
    """
    router = APIRouter()

    _require_memory_read = RequireScope("memory.read")
    _require_memory_forget = RequireScope("memory.forget")
    _require_memory_redact = RequireScope("memory.redact")
    _require_memory_export = RequireScope("memory.export.read")
    _require_human_actor = RequireHumanActor()

    @router.get(
        "/records",
        summary="List memory record metadata for a subject (value-free enumerate)",
    )
    async def list_records(
        actor: Annotated[Actor, Depends(_require_memory_read)],
        factory: Annotated[MemoryApiFactory, Depends(_require_memory_api_factory)],
        # subject_id + agent_id are REQUIRED, non-empty selectors: an empty
        # subject_id means "tenant-wide/unscoped memory" (refused by
        # SubjectRef.__post_init__) and an empty agent_id would silently call
        # the adapter under an empty agent namespace — both are 422 validation
        # refusals at the wire, NOT 500s from a downstream ValueError. Required
        # (no default) params must precede the defaulted subject_kind; FastAPI
        # matches query params by name, so the order does not affect the API.
        subject_id: Annotated[str, Query(min_length=1, description="Subject identifier")],
        agent_id: Annotated[str, Query(min_length=1, description="Agent identifier")],
        subject_kind: Annotated[Literal["human", "agent"], Query()] = "human",
    ) -> list[MemoryRecordMetadataResponse]:
        """Value-free enumerate of memory records for ``subject``.

        The response deliberately omits ``value`` — callers who need the
        actual values must go through the recall or export paths (both run
        through the full MemoryGate purpose-matrix).

        ``MemoryOperationRefused`` → 409 with the core refusal reason.
        """
        subject = SubjectRef(kind=subject_kind, id=subject_id)
        ctx = _operator_context(actor, agent_id=agent_id, subject=subject)
        api: MemoryAPI = factory(ctx)
        try:
            records = await api.list_records(subject)
        except MemoryOperationRefused as exc:
            raise HTTPException(
                status_code=409,
                detail={"reason": exc.reason},
            ) from None
        return [
            MemoryRecordMetadataResponse(
                record_id=m.record_id,
                agent_id=m.agent_id,
                tier=m.tier,
                data_classes=list(m.data_classes),
                purpose=m.purpose,
                created_at=m.created_at,
                block_kind=m.block_kind,
            )
            for m in records
        ]

    @router.post(
        "/records/{record_id}/forget",
        summary="Forget (tombstone or purge) a memory record",
    )
    async def forget(
        record_id: uuid.UUID,
        actor: Annotated[Actor, Depends(_require_memory_forget)],
        factory: Annotated[MemoryApiFactory, Depends(_require_memory_api_factory)],
        body: Annotated[ForgetRequest, Body()],
    ) -> ForgetReceiptResponse:
        """Forget a memory record.

        **Body-aware human-only gate for ``regulator_erasure``**: when
        ``body.reason == "regulator_erasure"`` the handler first checks
        (a) the actor holds ``memory.regulator_erasure`` scope → 403
        ``scope_not_held`` if missing; (b) the actor is human → 403
        ``actor_type_must_be_human`` if service. This MUST be an inline
        body-aware check — a static ``Depends(RequireHumanActor())`` that is
        never awaited enforces nothing; the guard must execute on the
        conditional path only.

        ``MemoryOperationRefused("memory_record_not_found")`` → 404.
        Other ``MemoryOperationRefused`` reasons → 409.
        """
        if body.reason == "regulator_erasure":
            # (a) scope check: actor must hold memory.regulator_erasure
            if "memory.regulator_erasure" not in actor.scopes:
                raise HTTPException(
                    status_code=403,
                    detail={
                        "reason": "scope_not_held",
                        "required_scope": "memory.regulator_erasure",
                    },
                )
            # (b) human-only check
            if actor.actor_type != "human":
                raise HTTPException(
                    status_code=403,
                    detail={"reason": "actor_type_must_be_human"},
                )

        subject = SubjectRef(kind=body.subject_kind, id=body.subject_id)
        ctx = _operator_context(actor, agent_id=body.agent_id, subject=subject)
        api: MemoryAPI = factory(ctx)

        erasure_command = None
        if body.erasure_command is not None:
            erasure_command = RegulatorErasureCommand(
                regulator_order_id=body.erasure_command.regulator_order_id,
                requester_scope=body.erasure_command.requester_scope,
                subject_id=body.erasure_command.subject_id,
                subject_kind=body.erasure_command.subject_kind,
            )

        try:
            receipt = await api.forget(
                record_id,
                reason=body.reason,
                erasure_command=erasure_command,
            )
        except MemoryOperationRefused as exc:
            status = 404 if exc.reason == _MEMORY_RECORD_NOT_FOUND else 409
            raise HTTPException(
                status_code=status,
                detail={"reason": exc.reason},
            ) from None

        return ForgetReceiptResponse(
            record_id=receipt.record_id,
            tombstoned=receipt.tombstoned,
            purged=receipt.purged,
        )

    @router.post(
        "/records/{record_id}/redact",
        summary="Redact a field within a memory record",
    )
    async def redact(
        record_id: uuid.UUID,
        actor: Annotated[Actor, Depends(_require_memory_redact)],
        factory: Annotated[MemoryApiFactory, Depends(_require_memory_api_factory)],
        body: Annotated[RedactRequest, Body()],
    ) -> RedactionReceiptResponse:
        """Redact a field within a memory record (creates a new sealed version).

        No human-only gate — redact is open to service actors holding
        ``memory.redact`` scope.

        ``MemoryOperationRefused("memory_record_not_found")`` → 404.
        Other ``MemoryOperationRefused`` reasons → 409.
        """
        subject = SubjectRef(kind=body.subject_kind, id=body.subject_id)
        ctx = _operator_context(actor, agent_id=body.agent_id, subject=subject)
        api: MemoryAPI = factory(ctx)

        span = RedactionSpan(
            path=tuple(body.span_path),
            replacement=body.replacement,
        )

        try:
            receipt = await api.redact(record_id, span=span, reason=body.reason)
        except MemoryOperationRefused as exc:
            status = 404 if exc.reason == _MEMORY_RECORD_NOT_FOUND else 409
            raise HTTPException(
                status_code=status,
                detail={"reason": exc.reason},
            ) from None

        return RedactionReceiptResponse(
            record_id=receipt.record_id,
            new_version_id=receipt.new_version_id,
            redaction_version=receipt.redaction_version,
        )

    @router.post(
        "/export",
        summary="Export memory records for a subject to a retention-disciplined archive",
    )
    async def export(
        actor: Annotated[Actor, Depends(_require_memory_export)],
        factory: Annotated[MemoryApiFactory, Depends(_require_memory_api_factory)],
        _human: Annotated[Actor, Depends(_require_human_actor)],
        body: Annotated[ExportRequest, Body()],
    ) -> ExportReceiptResponse:
        """Export memory records to a retention-disciplined archive.

        **Always human-only** — the static ``Depends(RequireHumanActor())``
        sub-dependency (``_human``) fires for EVERY export request. The
        ``_human`` parameter binding is unused inside the body but the FastAPI
        ``Depends`` declaration IS what registers the guard; dropping it would
        silently disable the human-actor refusal.

        ``MemoryOperationRefused`` → 409.
        """
        subject = SubjectRef(kind=body.subject_kind, id=body.subject_id)
        ctx = _operator_context(actor, agent_id=body.agent_id, subject=subject)
        api: MemoryAPI = factory(ctx)

        try:
            receipt = await api.export(subject)
        except MemoryOperationRefused as exc:
            raise HTTPException(
                status_code=409,
                detail={"reason": exc.reason},
            ) from None

        return ExportReceiptResponse(
            object_key=receipt.object_key,
            archive_sha256=receipt.archive_sha256,
            record_count=receipt.record_count,
        )

    return router
