"""Sprint 9.5 B5 — model-registry inspection routes: list / detail / audit.

NOT-CC at the critical-controls floor — pure-read; no
``store.transition()`` calls; no Human-only-decision enforcement; no
cosign verification. The ``/usage`` endpoint is Block C territory
(Task C3); B5 deliberately omits it.

Owns the three examiner-facing inspection endpoints behind
``/api/v1/models``:

* ``GET /``            — tenant-scoped list; scope ``model.audit.read``.
  Registered DIRECTLY on the parent router via
  :func:`register_model_inspection_list` so the compiled path is
  exactly ``/api/v1/models`` (no trailing slash). The bare-list
  cannot apply :class:`RequireModelTenantOwnership` (no
  ``{model_id}`` path-param) — the tenant boundary IS the
  ``store.list_for_tenant(actor.tenant_id, …)`` storage WHERE clause.
  The handler runs an EXPLICIT preflight on ``actor.tenant_id``
  (the dependency-chain bypass that exists for the bare-list shape
  is closed at the handler).
* ``GET /{model_id}``       — detail (record + lifecycle history);
  ``model.audit.read`` + ``RequireModelTenantOwnership``.
* ``GET /{model_id}/audit`` — hash-chained audit events oldest-first;
  same gates.

Mirrors :file:`portal/api/packs/inspection_routes.py`'s
register-list-on-parent-router pattern (T7 R33 P2 doctrine — the
slashless ``/api/v1/packs`` form IS the wire-protocol contract, not
the trailing-slash 307-redirect target).

Standing-offer §30 invariant: ``from __future__ import annotations``
is **INTENTIONALLY OMITTED** — FastAPI's ``inspect.signature()`` must
resolve ``Annotated[..., Depends(<closure-local>)]`` against
closure-local dependency instances (``_require_audit`` /
``_require_tenant_ownership`` live inside
:func:`register_model_inspection_list` /
:func:`build_model_inspection_routes`); PEP 563 would surface as 422
at request time. Per
``[[feedback_pep563_breaks_closure_local_depends]]``.
"""

import datetime
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from cognic_agentos.llm.ledger import GatewayCallLedger
from cognic_agentos.models.registry import ModelLifecycleState
from cognic_agentos.models.storage import ModelRecord, ModelRecordStore
from cognic_agentos.portal.api.models.dto import (
    ModelDetailResponse,
    ModelLifecycleEventResponse,
    ModelResponse,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope
from cognic_agentos.portal.rbac.model_tenant_isolation import (
    RequireModelTenantOwnership,
)

_LOG = logging.getLogger(__name__)


def register_model_inspection_list(parent: APIRouter, *, store: ModelRecordStore) -> None:
    """Register the bare ``GET /`` list endpoint DIRECTLY on the
    parent router so the compiled path is exactly the parent's
    prefix (``/api/v1/models``) with NO trailing slash.

    The bare-list endpoint cannot apply
    :class:`RequireModelTenantOwnership` (no ``{model_id}`` path-
    param). The tenant boundary IS the
    ``store.list_for_tenant(actor.tenant_id, …)`` storage WHERE
    clause — proven by the storage-layer test
    ``test_list_for_tenant_scopes_by_tenant`` at A5. This handler
    runs an EXPLICIT preflight on ``actor.tenant_id`` to defend the
    bare-list shape from the dependency-chain bypass (mirrors the
    pack inspection_routes T7 plan-R20 P2 #2 + R21 P2 #1 doctrine
    for the ``actor_tenant_id_missing`` 500 emission).

    Per the user-locked B5 invariant #1: NO client-controlled tenant
    filter — the handler signature takes only ``actor`` + ``limit`` +
    the optional ``state`` filter promised by spec §6.2 + BUILD_PLAN
    §789. A query-param ``tenant_id=...`` from the client is silently
    ignored by FastAPI (unknown query params don't bind to handler
    parameters; the actor's tenant is the only tenant input). The
    ``state`` filter narrows by :data:`ModelLifecycleState`; Pydantic
    Literal validation on the query param refuses invalid values with
    422 BEFORE the storage call runs.
    """
    _require_audit = RequireScope("model.audit.read")

    @parent.get(
        "",
        summary=(
            "List models scoped to actor.tenant_id (optional ?state=<ModelLifecycleState> filter)"
        ),
        response_model=list[ModelResponse],
    )
    async def list_models(
        actor: Annotated[Actor, Depends(_require_audit)],
        limit: int = 50,
        state: ModelLifecycleState | None = None,
    ) -> list[ModelResponse]:
        # Bare-list preflight per the pack inspection_routes precedent.
        # ``RequireModelTenantOwnership`` cannot fire here (no
        # ``{model_id}`` path-param) so the 500 emission for
        # ``actor.tenant_id`` being empty MUST come from the handler.
        if not actor.tenant_id:
            _LOG.warning(
                "portal.models.actor_tenant_id_missing",
                extra={
                    "reason": "actor_tenant_id_missing",
                    "actor_subject": actor.subject,
                    "model_id": "<list>",
                    "http_status": 500,
                },
            )
            raise HTTPException(status_code=500, detail={"reason": "actor_tenant_id_missing"})
        records = await store.list_for_tenant(actor.tenant_id, limit=limit, state=state)
        return [ModelResponse.model_validate(r) for r in records]


def build_model_inspection_routes(
    *,
    store: ModelRecordStore,
    ledger: GatewayCallLedger | None = None,
) -> APIRouter:
    """The ``{model_id}``-keyed inspection sub-handlers (detail +
    audit) plus the Sprint 9.5b C3 ``/usage`` endpoint.

    All endpoints flow through :class:`RequireModelTenantOwnership`
    which collapses cross-tenant + unknown to a 404
    ``model_not_found`` per the B2 R1 wire-body-collapse contract —
    a probe cannot distinguish "model exists in another tenant" from
    "no such model" by reading the response body.

    The ``ledger: GatewayCallLedger | None = None`` kwarg is the
    Sprint 9.5b C3 + PR #35 R2 plan-patch D7 user-locked policy
    surface: ``/usage`` mounts REGARDLESS of ledger presence; if the
    backend is not wired at call time the handler returns 503
    ``gateway_ledger_not_configured`` (NOT 404, which would look like
    route drift; NOT silent-skip, which would hide the partial
    config). Security gates (scope + tenant) run BEFORE the 503
    ledger check via FastAPI's dep-chain ordering — a missing-scope
    caller still sees 403 ``scope_not_held``; a cross-tenant probe
    still sees 404 ``model_not_found``.
    """
    router = APIRouter()
    _require_audit = RequireScope("model.audit.read")
    _require_usage = RequireScope("model.usage.read")
    _require_tenant_ownership = RequireModelTenantOwnership(model_id_param="model_id")

    # Register the audit + usage endpoints BEFORE the detail endpoint
    # so the more-specific path-segments
    # (``/{model_id}/audit`` and ``/{model_id}/usage``) match before
    # the broader ``/{model_id}`` pattern. FastAPI's path-segment-
    # exact matcher does not require this for correctness today,
    # but defensive ordering documented inline.

    @router.get(
        "/{model_id}/audit",
        summary="Hash-chained audit events for this model (oldest-first)",
        response_model=list[ModelLifecycleEventResponse],
    )
    async def get_audit(
        actor: Annotated[Actor, Depends(_require_audit)],
        record: Annotated[ModelRecord, Depends(_require_tenant_ownership)],
    ) -> list[ModelLifecycleEventResponse]:
        # Actor is bound by the scope dep; we don't read off it here.
        # The tenant-isolation dep already loaded + verified the
        # record's ownership.
        del actor
        history = await store.load_lifecycle_history(record.model_id)
        return [ModelLifecycleEventResponse.model_validate(event) for event in history]

    @router.get(
        "/{model_id}/usage",
        summary="Per-call invocation count from gateway ledger (Sprint 9.5b C3)",
    )
    async def get_usage(
        actor: Annotated[Actor, Depends(_require_usage)],
        record: Annotated[ModelRecord, Depends(_require_tenant_ownership)],
        from_: Annotated[datetime.datetime, Query(alias="from")],
        to: Annotated[datetime.datetime, Query()],
    ) -> dict[str, str | int]:
        """Sprint 9.5b C3 + PR #35 R2 plan-patch D7 user-locked
        policy — ``/usage`` is a documented public endpoint once
        9.5b lands. When the gateway ledger backend is not wired,
        return 503 closed-enum ``gateway_ledger_not_configured`` so
        operators see "backend not wired" rather than a 404 that
        would look like route drift.

        Security-gates-first dep-chain ordering: ``RequireScope`` +
        ``RequireModelTenantOwnership`` STILL run BEFORE the 503
        ledger check (the FastAPI dep chain resolves dependencies
        before the handler body), so a missing-scope caller sees
        403 ``scope_not_held`` and a cross-tenant probe sees 404
        ``model_not_found`` — the 503 is a backend-config signal,
        NOT a security signal.
        """
        del actor
        if ledger is None:
            raise HTTPException(
                status_code=503,
                detail={"reason": "gateway_ledger_not_configured"},
            )
        count = await ledger.count_by_model_id(
            model_id=record.model_id,
            since=from_,
            until=to,
        )
        return {"model_id": record.model_id, "count": count}

    @router.get(
        "/{model_id}",
        summary="Model detail + lifecycle history composition",
        response_model=ModelDetailResponse,
    )
    async def get_detail(
        actor: Annotated[Actor, Depends(_require_audit)],
        record: Annotated[ModelRecord, Depends(_require_tenant_ownership)],
    ) -> ModelDetailResponse:
        del actor
        history = await store.load_lifecycle_history(record.model_id)
        return ModelDetailResponse(
            model=ModelResponse.model_validate(record),
            history=[ModelLifecycleEventResponse.model_validate(event) for event in history],
        )

    return router


__all__ = [
    "build_model_inspection_routes",
    "register_model_inspection_list",
]
