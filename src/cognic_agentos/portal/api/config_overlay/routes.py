"""ADR-023 — operator-administered, human-only per-tenant config-overlay endpoints.

NO ``RequireTenantOwnership``: an operator sets config FOR a tenant, so a
cross-tenant operator holding the write scope is allowed (the scope IS the
boundary). The PUT/DELETE mutation surface is additionally human-only via
:class:`RequireHumanActor` per the AGENTS.md "Per-tenant ... changes"
human-only-decisions rule; GET is read-only and permits service actors.

``from __future__ import annotations`` is INTENTIONALLY OMITTED per the
standing FastAPI closure-local-``Depends`` gotcha: the ``RequireScope`` /
``RequireHumanActor`` dependency instances are closure-local variables inside
:func:`build_config_overlay_routes` (NOT module globals), and PEP 563
string-deferred annotations would break FastAPI's ``get_type_hints()``
resolution of ``Annotated[..., Depends(<closure-local>)]`` — silently
demoting handler params to query params. Pinned by ``test_no_future_import``.

``settings`` is a REQUIRED factory arg: the handlers read
``getattr(settings, field_key)`` from the closure-captured base (NEVER
``Settings()`` per request) AFTER :func:`overridable_field` has registry-gated
the path param, so a caller cannot name an arbitrary Setting via the URL.
``resolver`` is accepted for symmetry / future read-time use (the consumers
use the same resolver) even though the mutation handlers reach ``store`` +
``settings`` directly.
"""

import logging
import uuid
from typing import Annotated, Final

import pydantic
from fastapi import APIRouter, Body, Depends, HTTPException

from cognic_agentos.core.config import Settings
from cognic_agentos.core.config_overlay.registry import (
    TenantOverlayRejected,
    overridable_field,
)
from cognic_agentos.core.config_overlay.resolver import TenantConfigResolver
from cognic_agentos.core.config_overlay.storage import TenantConfigOverlayStore
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope
from cognic_agentos.portal.rbac.human_actor import RequireHumanActor

_LOG = logging.getLogger("cognic_agentos.portal.api.config_overlay")
_SET_PREFIX: Final[str] = "cfg-overlay-set-"  # 16 + 32 hex = 48 <= 64
_CLR_PREFIX: Final[str] = "cfg-overlay-clr-"  # 16 + 32 hex = 48 <= 64
assert len(_SET_PREFIX) + 32 <= 64 and len(_CLR_PREFIX) + 32 <= 64


def _mint(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex}"


class SetOverlayRequest(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="forbid")
    # JSON-number-only wire contract. StrictInt | StrictFloat rejects JSON
    # bool (true/false) AND string coercion ("2") at the request boundary, so
    # a non-numeric value can NEVER reach the registry pre-coerced. A lax
    # ``float | int`` would let Pydantic convert true -> 1.0 / "2" -> 2.0
    # BEFORE the registry's bool-guard (coerce_value) runs, silently
    # bypassing the Task-1 "bool is never accepted as numeric config"
    # invariant. The registry bool-guard is the second line of defence at the
    # storage boundary; the DTO is the first.
    value: pydantic.StrictInt | pydantic.StrictFloat


class OverlayResponse(pydantic.BaseModel):
    tenant_id: str
    field_key: str
    value: float | int
    set_by_actor: str
    last_request_id: str


def build_config_overlay_routes(
    *,
    store: TenantConfigOverlayStore,
    resolver: TenantConfigResolver,
    settings: Settings,
) -> APIRouter:
    router = APIRouter()
    _write = RequireScope("config.tenant_overlay.write")
    _read = RequireScope("config.tenant_overlay.read")
    _human = RequireHumanActor()

    @router.put(
        "/tenants/{tenant_id}/config-overlay/{field_key}",
        response_model=OverlayResponse,
    )
    async def set_overlay(
        tenant_id: str,
        field_key: str,
        body: Annotated[SetOverlayRequest, Body(...)],
        actor: Annotated[Actor, Depends(_write)],
        _h: Annotated[Actor, Depends(_human)],
    ) -> OverlayResponse:
        try:
            overridable_field(field_key)  # registry-gate the path param before getattr
            base_value = getattr(settings, field_key)  # closure-captured base
            await store.set_overlay(
                tenant_id=tenant_id,
                field_key=field_key,
                base_value=base_value,
                proposed=body.value,
                actor_subject=actor.subject,
                actor_type=actor.actor_type,
                request_id=_mint(_SET_PREFIX),
            )
        except TenantOverlayRejected as exc:
            _LOG.warning(
                "portal.config_overlay.set_refused",
                extra={
                    "reason": exc.reason,
                    "tenant_id": tenant_id,
                    "field_key": field_key,
                    "actor_subject": actor.subject,
                },
            )
            raise HTTPException(status_code=422, detail={"reason": exc.reason}) from exc
        row = next(r for r in await store.list_for_tenant(tenant_id) if r.field_key == field_key)
        return OverlayResponse(
            tenant_id=row.tenant_id,
            field_key=row.field_key,
            value=row.value,
            set_by_actor=row.set_by_actor,
            last_request_id=row.last_request_id,
        )

    @router.delete("/tenants/{tenant_id}/config-overlay/{field_key}", status_code=204)
    async def clear_overlay(
        tenant_id: str,
        field_key: str,
        actor: Annotated[Actor, Depends(_write)],
        _h: Annotated[Actor, Depends(_human)],
    ) -> None:
        try:
            overridable_field(field_key)  # registry-gate the path param
            await store.clear_overlay(
                tenant_id=tenant_id,
                field_key=field_key,
                actor_subject=actor.subject,
                actor_type=actor.actor_type,
                request_id=_mint(_CLR_PREFIX),
            )
        except TenantOverlayRejected as exc:
            _LOG.warning(
                "portal.config_overlay.clear_refused",
                extra={
                    "reason": exc.reason,
                    "tenant_id": tenant_id,
                    "field_key": field_key,
                },
            )
            raise HTTPException(status_code=422, detail={"reason": exc.reason}) from exc

    @router.get(
        "/tenants/{tenant_id}/config-overlay",
        response_model=list[OverlayResponse],
    )
    async def list_overlays(
        tenant_id: str,
        actor: Annotated[Actor, Depends(_read)],
    ) -> list[OverlayResponse]:
        return [
            OverlayResponse(
                tenant_id=r.tenant_id,
                field_key=r.field_key,
                value=r.value,
                set_by_actor=r.set_by_actor,
                last_request_id=r.last_request_id,
            )
            for r in await store.list_for_tenant(tenant_id)
        ]

    return router
