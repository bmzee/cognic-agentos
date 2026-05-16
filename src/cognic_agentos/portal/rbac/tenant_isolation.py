"""Sprint 7B.2 T2 — RequireTenantOwnership dependency + TenantIsolationFailure closed-enum.

Plan Round 1 P2 #3 + T2 R1 P2 #1 — tenant-isolation guard ships in T2 so
T4 / T5 / T6 endpoints have a real module to depend on.

Closed-enum :data:`TenantIsolationFailure` is a 4-value wire-protocol
contract:

- ``tenant_id_mismatch`` (404) — actor's tenant_id differs from pack's
  tenant_id. **404 NOT 403** — info-leak prevention. A 403 would leak
  pack existence to a cross-tenant attacker who could fingerprint the
  multi-tenant landscape by status code.
- ``pack_not_found`` (404) — :meth:`PackRecordStore.load` returned
  ``None``. Same 404 status as ``tenant_id_mismatch`` for info-leak
  prevention symmetry.
- ``actor_tenant_id_missing`` (500) — actor's ``tenant_id`` field is
  empty. Kernel-misconfig defended at the gate even though a real
  bank-overlay binder should never mint such an actor.
- ``pack_store_not_configured`` (500) — added at T2 R1 P2 #1 as a
  symmetric mirror of :func:`enforcement._bind_actor`'s ``binder is None``
  defensive branch. Without it, a route mounted with a binder but no
  ``app.state.pack_record_store`` would surface FastAPI's generic 500
  ``Internal Server Error`` (no closed-enum reason, no structured log)
  — a fingerprint regression off the 7B.2 wire-protocol contract.

The dependency returns the loaded :class:`PackRecord` on success so
sub-handlers (T4-T6) consume it without re-loading.

Path-param resolution: the factory takes ``pack_id_param`` — the name of
the FastAPI path parameter that carries the pack UUID
(e.g. ``"pack_id"`` for routes like ``/packs/{pack_id}``). The dependency
reads ``request.path_params[pack_id_param]``, parses it to
:class:`uuid.UUID`, and surfaces a structured ``pack_not_found`` 404 on
parse failure (catches typos / malformed IDs without a 500).
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Annotated, Literal

from fastapi import Depends, HTTPException, Request

from cognic_agentos.packs.storage import PackRecord
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import (
    _bind_actor,
    _emit_denial_or_500,
    _resolve_request_id,
)

if TYPE_CHECKING:
    from cognic_agentos.protocol.ui_events import UIEventBroker

_LOG = logging.getLogger(__name__)


#: Closed-enum vocabulary for tenant-isolation failure bodies. Plan
#: Round 1 P2 #3 + T2 R1 P2 #1: four modes, two carry 404 (info-leak
#: prevention), two carry 500 (kernel-misconfig).
#:
#: Style note: plain ``= Literal[...]`` (no ``TypeAlias`` annotation) to
#: match the Sprint-7B.1 repo convention at ``packs/lifecycle.py:111``.
#:
#: T2 R1 P2 #1 added ``pack_store_not_configured`` as a symmetric mirror
#: of :func:`~cognic_agentos.portal.rbac.enforcement._bind_actor`'s
#: ``binder is None`` defensive branch. Without this, a route mounted
#: with a binder but no ``app.state.pack_record_store`` would surface
#: FastAPI's generic 500 ``Internal Server Error`` (no closed-enum
#: reason, no structured log) — a fingerprint regression off the
#: 7B.2 wire-protocol contract.
TenantIsolationFailure = Literal[
    "tenant_id_mismatch",
    "pack_not_found",
    "actor_tenant_id_missing",
    "pack_store_not_configured",
]


#: Sprint-7B.4 T6 — the per-module `_emit_isolation_log` helper was
#: removed when refusal sites switched to the shared
#: :func:`~cognic_agentos.portal.rbac.enforcement._emit_denial_or_500`
#: helper (one source of truth for log + chain emission across all 4
#: RBAC modules). The wire-shape change: log records now come from the
#: ``cognic_agentos.portal.rbac.enforcement`` logger with message
#: ``portal.rbac.<TenantIsolationFailure>`` (e.g.
#: ``portal.rbac.tenant_id_mismatch``) instead of the previous
#: per-module constant ``portal.rbac.tenant_isolation_failed``.
#: Structured ``reason`` attribute is unchanged — operators querying on
#: the structured field stay compatible without query updates.


def RequireTenantOwnership(
    pack_id_param: str,
) -> Callable[..., Awaitable[PackRecord]]:
    """FastAPI dependency factory — verify the actor's tenant owns the pack.

    Pulls the pack UUID from ``request.path_params[pack_id_param]``,
    loads the :class:`PackRecord` via
    ``request.app.state.pack_record_store``, and verifies
    ``record.tenant_id == actor.tenant_id``. Refuses with a structured
    HTTP response carrying a closed-enum :data:`TenantIsolationFailure`
    reason on any failure mode.

    Returns the loaded :class:`PackRecord` on success so the sub-handler
    consumes it without re-loading (defence-in-depth against
    TOCTOU bugs — same record fed to subsequent storage calls).

    Reuses :func:`~cognic_agentos.portal.rbac.enforcement._bind_actor`
    so FastAPI caches actor binding across both
    :class:`RequireScope` + :class:`RequireTenantOwnership` within a
    single request (one bind call per request, not two).
    """

    async def dependency(
        request: Request,
        actor: Annotated[Actor, Depends(_bind_actor)],
    ) -> PackRecord:
        raw = request.path_params.get(pack_id_param)
        if raw is None:
            # Kernel routing bug — the route was wired with a different
            # path-param name than RequireTenantOwnership was given.
            raise RuntimeError(
                f"RequireTenantOwnership path-param mismatch: "
                f"no '{pack_id_param}' in request.path_params"
            )
        # Sprint-7B.4 T6: resolve broker + request_id once for the whole
        # dependency so all 4 emit branches below share the same context.
        broker: UIEventBroker | None = getattr(request.app.state, "ui_event_broker", None)
        request_id = _resolve_request_id(request)

        try:
            pack_uuid = uuid.UUID(raw)
        except (ValueError, TypeError):
            await _emit_denial_or_500(
                broker,
                denial_type="pack_not_found",
                actor_subject=actor.subject,
                tenant_id=actor.tenant_id or None,
                request_id=request_id,
                http_status=404,
                pack_id=str(raw),
            )
            raise HTTPException(
                status_code=404,
                detail={"reason": "pack_not_found"},
            ) from None

        if not actor.tenant_id:
            await _emit_denial_or_500(
                broker,
                denial_type="actor_tenant_id_missing",
                actor_subject=actor.subject,
                tenant_id=None,  # actor.tenant_id is empty — chain row gets NULL
                request_id=request_id,
                http_status=500,
                pack_id=str(pack_uuid),
            )
            raise HTTPException(
                status_code=500,
                detail={"reason": "actor_tenant_id_missing"},
            )

        store = getattr(request.app.state, "pack_record_store", None)
        if store is None:
            # T2 R1 P2 #1 — symmetric mirror of the ``binder is None`` defensive
            # branch in :func:`enforcement._bind_actor`. A route mounted with
            # a binder but no store would otherwise surface FastAPI's generic
            # 500 ``Internal Server Error`` (no closed-enum reason, no
            # structured log). Distinct from ``actor_binder_not_configured``
            # so operators can fingerprint WHICH wiring step the overlay
            # bootstrap missed.
            await _emit_denial_or_500(
                broker,
                denial_type="pack_store_not_configured",
                actor_subject=actor.subject,
                tenant_id=actor.tenant_id,
                request_id=request_id,
                http_status=500,
                pack_id=str(pack_uuid),
            )
            raise HTTPException(
                status_code=500,
                detail={"reason": "pack_store_not_configured"},
            )

        record: PackRecord | None = await store.load(pack_uuid)
        if record is None:
            await _emit_denial_or_500(
                broker,
                denial_type="pack_not_found",
                actor_subject=actor.subject,
                tenant_id=actor.tenant_id,
                request_id=request_id,
                http_status=404,
                pack_id=str(pack_uuid),
            )
            raise HTTPException(
                status_code=404,
                detail={"reason": "pack_not_found"},
            )

        if record.tenant_id != actor.tenant_id:
            # 404 NOT 403 — info-leak prevention. A 403 leaks pack
            # existence to a cross-tenant attacker.
            await _emit_denial_or_500(
                broker,
                denial_type="tenant_id_mismatch",
                actor_subject=actor.subject,
                tenant_id=actor.tenant_id,
                request_id=request_id,
                http_status=404,
                pack_id=str(pack_uuid),
            )
            raise HTTPException(
                status_code=404,
                detail={"reason": "tenant_id_mismatch"},
            )

        return record

    return dependency
