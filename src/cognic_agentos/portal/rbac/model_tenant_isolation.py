"""Sprint 9.5 B2 — :func:`RequireModelTenantOwnership` tenant-isolation
guard for the model registry. Parallel to
:func:`~cognic_agentos.portal.rbac.tenant_isolation.RequireTenantOwnership`
but reads ``request.app.state.model_registry_store`` and looks up by
the **natural-key string** ``model_id`` (the path-param) — NOT a UUID
— so the URL ``/api/v1/models/{model_id}`` accepts wire-shape identities
like ``cognic-tier1-acme-v1`` directly without a parse step.

This module is part of the ``portal/rbac/`` stop-rule tree per
:file:`AGENTS.md`. Critical control: drift in the closed-enum vocabulary
OR the wire-body shape OR the cross-tenant-invisible-rendering doctrine
is a wire-protocol break.

Closed-enum :data:`ModelTenantIsolationFailure` (4 values) is the
**internal categorization vocabulary** carried in structured log
records for operator visibility. The wire-protocol body shape is
INTENTIONALLY narrower (3 distinct values reach the wire) — see the
*Wire-body collapse* section below.

Wire-body collapse for cross-tenant invisibility
================================================

The pack equivalent at
:file:`portal/rbac/tenant_isolation.py` rendered cross-tenant as a 404
with body ``{"reason": "tenant_id_mismatch"}`` and unknown-pack as a
404 with body ``{"reason": "pack_not_found"}``. The two failure modes
land on the same status code but a probe can DISTINGUISH them from
the response body — a residual info-leak: an attacker learns "the
target tenant DOES have a pack with this ID, I just can't access it".

Sprint 9.5 B2 takes the stronger position per the user-locked B2
invariant "cross-tenant + unknown indistinguishable at HTTP boundary":

- Cross-tenant access → 404 + body ``{"reason": "model_not_found"}``
  (NOT ``tenant_id_mismatch`` at the wire).
- Unknown-model access → 404 + body ``{"reason": "model_not_found"}``.

A probe reading just the wire response can NOT distinguish the two
cases. The internal structured log retains ``tenant_id_mismatch``
(``portal.models.tenant_id_mismatch`` message + ``reason`` attr) so
operators + SIEM correlation can still see which root cause fired —
the operations + examiner channels keep the distinction; only the
public wire surface collapses it.

This deliberately diverges from the pack pattern; the pack module is
NOT refactored here (user-locked B2 invariant "no broad RBAC refactor
while touching portal/rbac/").

Wave-1 emission posture
=======================

Structured-log-only — no :class:`UIEventBroker` chain emission. The
``RBACDenialType`` Literal in :file:`protocol/ui_events.py` is a stop-rule
wire contract; Wave-1 model RBAC denials stay log-only until a future
sprint adds model-denial event types to the taxonomy (the shape is
trivially extensible — every emission site here has the kwargs a
broker call would need, just not the broker hookup yet). Scope denials
via :func:`RequireScope` continue to use the existing
:func:`~cognic_agentos.portal.rbac.enforcement._emit_denial_or_500`
shared helper, unchanged by this task.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Annotated, Literal

from fastapi import Depends, HTTPException, Request

from cognic_agentos.models.storage import ModelRecord, ModelRecordStore
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import bind_actor

_LOG = logging.getLogger(__name__)


#: Closed-enum **internal categorization vocabulary** — the 4 distinct
#: failure modes the dependency emits to the structured log. Wire-body
#: shape is intentionally NARROWER per the wire-body collapse rule
#: above (cross-tenant + unknown both render as 404
#: ``{"reason": "model_not_found"}`` at the wire). Drift in this Literal
#: is a wire-protocol break on the log/SIEM correlation surface.
#:
#: Style note: plain ``= Literal[...]`` (no ``TypeAlias`` annotation)
#: to match the Sprint-7B.1 / 7B.2 / 7B.4 / 9 / 9.5-B1 repo convention.
ModelTenantIsolationFailure = Literal[
    "model_not_found",
    "tenant_id_mismatch",
    "actor_tenant_id_missing",
    "model_store_not_configured",
]


#: Wire-public 404/5xx body ``reason`` values — the 3 distinct strings
#: that actually reach the HTTP response. ``tenant_id_mismatch`` is
#: ABSENT here by design: the wire collapses it to ``model_not_found``
#: per the cross-tenant invisibility rule. Pinned for drift detection
#: in :file:`tests/unit/portal/rbac/test_model_tenant_isolation.py`.
ModelTenantIsolationWireReason = Literal[
    "model_not_found",
    "actor_tenant_id_missing",
    "model_store_not_configured",
]


def RequireModelTenantOwnership(
    model_id_param: str,
) -> Callable[..., Awaitable[ModelRecord]]:
    """FastAPI dependency factory — verify the resolved actor's tenant
    owns the model row identified by ``request.path_params[model_id_param]``.

    Pulls the natural-key string ``model_id`` from the path-params,
    loads the :class:`ModelRecord` via
    ``request.app.state.model_registry_store.load_by_model_id``, and
    verifies ``record.tenant_id == actor.tenant_id``. On the cross-
    tenant path the wire body collapses to ``model_not_found`` per the
    info-leak prevention rule documented in this module's docstring.

    Reuses :func:`~cognic_agentos.portal.rbac.enforcement.bind_actor`
    (the public alias added at B1) so FastAPI's sub-dep cache binds
    the actor exactly once per request across
    :func:`RequireScope` + :func:`RequireModelTenantOwnership` +
    body-aware authz handlers.

    Returns the loaded :class:`ModelRecord` on success so the
    downstream handler does not re-load (defence-in-depth against
    TOCTOU bugs — the same record fed to subsequent storage calls).
    """

    async def dependency(
        request: Request,
        actor: Annotated[Actor, Depends(bind_actor)],
    ) -> ModelRecord:
        model_id = request.path_params.get(model_id_param)
        if not isinstance(model_id, str) or not model_id:
            # Kernel routing bug — the route was wired with a different
            # path-param name than RequireModelTenantOwnership was
            # given. FastAPI's URL router would have rejected an empty
            # segment before reaching here; this guard catches the
            # name-mismatch case (a 500 with no body context, NOT
            # something a client could trigger).
            raise RuntimeError(
                f"RequireModelTenantOwnership path-param mismatch: "
                f"no '{model_id_param}' in request.path_params"
            )

        if not actor.tenant_id:
            # Kernel-misconfig — bank overlay should never mint an
            # actor with an empty tenant_id, but defended at the gate.
            _LOG.warning(
                "portal.models.actor_tenant_id_missing",
                extra={
                    "reason": "actor_tenant_id_missing",
                    "actor_subject": actor.subject,
                    "model_id": model_id,
                    "http_status": 500,
                },
            )
            raise HTTPException(
                status_code=500,
                detail={"reason": "actor_tenant_id_missing"},
            )

        store: ModelRecordStore | None = getattr(request.app.state, "model_registry_store", None)
        if store is None:
            # Symmetric mirror of the pack equivalent's
            # ``pack_store_not_configured`` branch — a route mounted
            # with an actor_binder but no model_registry_store would
            # otherwise surface FastAPI's generic 500
            # ``Internal Server Error`` (no closed-enum reason, no
            # structured log). Distinct closed-enum value so operators
            # can fingerprint WHICH wiring step the overlay bootstrap
            # missed.
            _LOG.warning(
                "portal.models.model_store_not_configured",
                extra={
                    "reason": "model_store_not_configured",
                    "actor_subject": actor.subject,
                    "actor_tenant": actor.tenant_id,
                    "model_id": model_id,
                    "http_status": 500,
                },
            )
            raise HTTPException(
                status_code=500,
                detail={"reason": "model_store_not_configured"},
            )

        record = await store.load_by_model_id(model_id)
        if record is None:
            _LOG.warning(
                "portal.models.model_not_found",
                extra={
                    "reason": "model_not_found",
                    "actor_subject": actor.subject,
                    "actor_tenant": actor.tenant_id,
                    "model_id": model_id,
                    "http_status": 404,
                },
            )
            raise HTTPException(
                status_code=404,
                detail={"reason": "model_not_found"},
            )

        if record.tenant_id != actor.tenant_id:
            # **Wire-body collapse for cross-tenant invisibility.**
            # Internal log keeps ``tenant_id_mismatch`` so operators +
            # SIEM correlation can distinguish cross-tenant from
            # unknown-model; the wire body collapses to
            # ``model_not_found`` so a probe cannot distinguish
            # "model exists, wrong tenant" from "no such model" by
            # reading the response. Diverges deliberately from the
            # pack equivalent at portal/rbac/tenant_isolation.py:217
            # (which leaks ``tenant_id_mismatch`` to the wire); the
            # pack module is NOT refactored here per the user-locked
            # "no broad RBAC refactor" B2 scope rule.
            _LOG.warning(
                "portal.models.tenant_id_mismatch",
                extra={
                    "reason": "tenant_id_mismatch",
                    "actor_subject": actor.subject,
                    "actor_tenant": actor.tenant_id,
                    "model_id": model_id,
                    "http_status": 404,
                },
            )
            raise HTTPException(
                status_code=404,
                detail={"reason": "model_not_found"},
            )

        return record

    return dependency


__all__ = [
    "ModelTenantIsolationFailure",
    "ModelTenantIsolationWireReason",
    "RequireModelTenantOwnership",
]
