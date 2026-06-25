"""PR-2b-1 (ADR-002 amendment) — operator MCP ``server_url`` override + per-tenant
exact-IP internal-host allow-list write/read endpoints (CRITICAL CONTROLS).

Mirrors :mod:`cognic_agentos.portal.api.config_overlay.routes`. The endpoints are
OPERATOR-ADMINISTERED: an operator sets MCP config FOR a tenant, so there is
deliberately NO :class:`RequireTenantOwnership` gate — a cross-tenant operator
holding the write scope is allowed (the scope IS the boundary). Both write
surfaces (override PUT/DELETE; allow-list add/remove) are additionally human-only
via :class:`RequireHumanActor` per the AGENTS.md "Per-tenant ... changes"
human-only-decisions rule; the GET reads permit service actors.

**Grammar is enforced INSIDE the audited stores** (``validate_override_url`` /
``validate_allowlist_ip`` raise :class:`MCPConfigRejected` from within the
``append_with_precondition`` closure, so a refusal rolls back the chain row +
state row atomically). The route catches :class:`MCPConfigRejected` and maps the
closed-enum reason to a 422 — it NEVER validates the grammar itself and NEVER
touches the DB directly. Every mutation goes through the store mutators
(``set_override`` / ``clear_override`` / ``add_ip`` / ``remove_ip``), which are
the single audited write path; the route threads ``actor_subject`` /
``actor_type`` / a minted ``request_id`` into each.

**Allow-list IP delivery (spec §7 / the "test each refusal surface" contract).**
The allow-list ADD carries the IP in the request **body** (a strict-string DTO)
rather than a path param: a broad CIDR like ``10.0.0.0/8`` — whose ``/`` would
split a ``{ip}`` path segment and 404 before reaching the store — must reach the
store so its ``allowlist_ip_not_exact`` refusal surfaces as a 422. REMOVE carries
the IP in the path (stored entries are exact, slashless canonical IPs); GET lists
the tenant's allow-list. This honors the plan's ``…/mcp-allowlist[/{ip}]`` (the
path IP is OPTIONAL — present on DELETE, absent on PUT/GET) while keeping every
refusal reason route-deliverable for the 422 contract.

**``from __future__ import annotations`` is INTENTIONALLY OMITTED** per the
standing FastAPI closure-local-``Depends`` gotcha (mirrors
``config_overlay/routes.py`` + ``packs/operator_routes.py``): the
:class:`RequireScope` / :class:`RequireHumanActor` dependency instances are
closure-local variables inside the ``build_*`` factories (NOT module globals),
and PEP 563 string-deferred annotations would break FastAPI's
``get_type_hints()`` resolution of ``Annotated[..., Depends(<closure-local>)]`` —
silently demoting handler params to query params. Pinned by
``test_no_future_import``.
"""

import logging
import uuid
from typing import Annotated, Final

import pydantic
from fastapi import APIRouter, Body, Depends, HTTPException

from cognic_agentos.core.mcp_config.storage import (
    MCPConfigRejected,
    MCPInternalHostAllowlistStore,
    MCPServerUrlOverrideStore,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope
from cognic_agentos.portal.rbac.human_actor import RequireHumanActor

_LOG = logging.getLogger("cognic_agentos.portal.api.mcp_config")

# Per-verb request-id minter prefixes. uuid4().hex is exactly 32 chars; every
# prefix + 32 must fit under the ``decision_history.request_id`` String(64)
# column cap. The module-foot assert pins this at import time.
_OVERRIDE_SET_PREFIX: Final[str] = "mcp-ovr-set-"  # 12 + 32 = 44 <= 64
_OVERRIDE_CLR_PREFIX: Final[str] = "mcp-ovr-clr-"  # 12 + 32 = 44 <= 64
_ALLOWLIST_ADD_PREFIX: Final[str] = "mcp-alw-add-"  # 12 + 32 = 44 <= 64
_ALLOWLIST_REM_PREFIX: Final[str] = "mcp-alw-rem-"  # 12 + 32 = 44 <= 64
_REQUEST_ID_MAX_LEN: Final[int] = 64


def _mint(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex}"


class SetOverrideRequest(pydantic.BaseModel):
    """PUT body for an override-set. ``StrictStr`` so a non-string body is a 422
    at the request boundary (the store's ``override_url_not_string`` is then
    unreachable via the route — the DTO catches it first). The grammar
    (``http://``-IP-literal, internal-only) is enforced in the store."""

    model_config = pydantic.ConfigDict(extra="forbid")
    server_url: pydantic.StrictStr


class OverrideResponse(pydantic.BaseModel):
    tenant_id: str
    pack_id: str
    server_url: str | None


class AddAllowlistIPRequest(pydantic.BaseModel):
    """PUT body for an allow-list add. ``StrictStr`` (non-string → 422 at the
    boundary). The IP rides the body so a broad CIDR still reaches the store."""

    model_config = pydantic.ConfigDict(extra="forbid")
    ip: pydantic.StrictStr


class AllowlistEntryResponse(pydantic.BaseModel):
    tenant_id: str
    ip: str
    set_by_actor: str
    last_request_id: str


def build_mcp_override_routes(*, store: MCPServerUrlOverrideStore) -> APIRouter:
    """Operator ``server_url`` override sub-router (PUT/DELETE human-only; GET
    read). Mounted by Task 7 under ``/api/v1``."""
    router = APIRouter()
    _write = RequireScope("mcp.override.write")
    _read = RequireScope("mcp.override.read")
    _human = RequireHumanActor()

    @router.put(
        "/tenants/{tenant_id}/mcp-overrides/{pack_id}",
        response_model=OverrideResponse,
    )
    async def set_override(
        tenant_id: str,
        pack_id: str,
        body: Annotated[SetOverrideRequest, Body(...)],
        actor: Annotated[Actor, Depends(_write)],
        _h: Annotated[Actor, Depends(_human)],
    ) -> OverrideResponse:
        try:
            await store.set_override(
                tenant_id=tenant_id,
                pack_id=pack_id,
                server_url=body.server_url,
                actor_subject=actor.subject,
                actor_type=actor.actor_type,
                request_id=_mint(_OVERRIDE_SET_PREFIX),
            )
        except MCPConfigRejected as exc:
            _LOG.warning(
                "portal.mcp_config.override_set_refused",
                extra={
                    "reason": exc.reason,
                    "tenant_id": tenant_id,
                    "pack_id": pack_id,
                    "actor_subject": actor.subject,
                },
            )
            raise HTTPException(status_code=422, detail={"reason": exc.reason}) from exc
        _LOG.warning(
            "portal.mcp_config.override_set",
            extra={
                "tenant_id": tenant_id,
                "pack_id": pack_id,
                "actor_subject": actor.subject,
                "actor_type": actor.actor_type,
            },
        )
        current = await store.get(tenant_id=tenant_id, pack_id=pack_id)
        return OverrideResponse(tenant_id=tenant_id, pack_id=pack_id, server_url=current)

    @router.delete("/tenants/{tenant_id}/mcp-overrides/{pack_id}", status_code=204)
    async def clear_override(
        tenant_id: str,
        pack_id: str,
        actor: Annotated[Actor, Depends(_write)],
        _h: Annotated[Actor, Depends(_human)],
    ) -> None:
        # ``clear_override`` performs NO grammar validation (it only deletes), so
        # it has no ``MCPConfigRejected`` path — no try/except (an unreachable
        # except arm would be an uncovered branch on the CC gate).
        await store.clear_override(
            tenant_id=tenant_id,
            pack_id=pack_id,
            actor_subject=actor.subject,
            actor_type=actor.actor_type,
            request_id=_mint(_OVERRIDE_CLR_PREFIX),
        )
        _LOG.warning(
            "portal.mcp_config.override_cleared",
            extra={
                "tenant_id": tenant_id,
                "pack_id": pack_id,
                "actor_subject": actor.subject,
                "actor_type": actor.actor_type,
            },
        )

    @router.get(
        "/tenants/{tenant_id}/mcp-overrides/{pack_id}",
        response_model=OverrideResponse,
    )
    async def get_override(
        tenant_id: str,
        pack_id: str,
        actor: Annotated[Actor, Depends(_read)],
    ) -> OverrideResponse:
        current = await store.get(tenant_id=tenant_id, pack_id=pack_id)
        return OverrideResponse(tenant_id=tenant_id, pack_id=pack_id, server_url=current)

    return router


def build_mcp_allowlist_routes(*, store: MCPInternalHostAllowlistStore) -> APIRouter:
    """Operator internal-host allow-list sub-router (PUT add / DELETE remove
    human-only; GET list read). Mounted by Task 7 under ``/api/v1``."""
    router = APIRouter()
    _write = RequireScope("mcp.allowlist.write")
    _read = RequireScope("mcp.allowlist.read")
    _human = RequireHumanActor()

    @router.put(
        "/tenants/{tenant_id}/mcp-allowlist",
        response_model=list[AllowlistEntryResponse],
    )
    async def add_ip(
        tenant_id: str,
        body: Annotated[AddAllowlistIPRequest, Body(...)],
        actor: Annotated[Actor, Depends(_write)],
        _h: Annotated[Actor, Depends(_human)],
    ) -> list[AllowlistEntryResponse]:
        try:
            await store.add_ip(
                tenant_id=tenant_id,
                ip=body.ip,
                actor_subject=actor.subject,
                actor_type=actor.actor_type,
                request_id=_mint(_ALLOWLIST_ADD_PREFIX),
            )
        except MCPConfigRejected as exc:
            _LOG.warning(
                "portal.mcp_config.allowlist_add_refused",
                extra={
                    "reason": exc.reason,
                    "tenant_id": tenant_id,
                    "actor_subject": actor.subject,
                },
            )
            raise HTTPException(status_code=422, detail={"reason": exc.reason}) from exc
        _LOG.warning(
            "portal.mcp_config.allowlist_add",
            extra={
                "tenant_id": tenant_id,
                "actor_subject": actor.subject,
                "actor_type": actor.actor_type,
            },
        )
        return [
            AllowlistEntryResponse(
                tenant_id=r.tenant_id,
                ip=r.ip,
                set_by_actor=r.set_by_actor,
                last_request_id=r.last_request_id,
            )
            for r in await store.list_for_tenant(tenant_id)
        ]

    @router.delete("/tenants/{tenant_id}/mcp-allowlist/{ip}", status_code=204)
    async def remove_ip(
        tenant_id: str,
        ip: str,
        actor: Annotated[Actor, Depends(_write)],
        _h: Annotated[Actor, Depends(_human)],
    ) -> None:
        try:
            await store.remove_ip(
                tenant_id=tenant_id,
                ip=ip,
                actor_subject=actor.subject,
                actor_type=actor.actor_type,
                request_id=_mint(_ALLOWLIST_REM_PREFIX),
            )
        except MCPConfigRejected as exc:
            _LOG.warning(
                "portal.mcp_config.allowlist_remove_refused",
                extra={
                    "reason": exc.reason,
                    "tenant_id": tenant_id,
                    "actor_subject": actor.subject,
                },
            )
            raise HTTPException(status_code=422, detail={"reason": exc.reason}) from exc
        _LOG.warning(
            "portal.mcp_config.allowlist_remove",
            extra={
                "tenant_id": tenant_id,
                "actor_subject": actor.subject,
                "actor_type": actor.actor_type,
            },
        )

    @router.get(
        "/tenants/{tenant_id}/mcp-allowlist",
        response_model=list[AllowlistEntryResponse],
    )
    async def list_allowlist(
        tenant_id: str,
        actor: Annotated[Actor, Depends(_read)],
    ) -> list[AllowlistEntryResponse]:
        return [
            AllowlistEntryResponse(
                tenant_id=r.tenant_id,
                ip=r.ip,
                set_by_actor=r.set_by_actor,
                last_request_id=r.last_request_id,
            )
            for r in await store.list_for_tenant(tenant_id)
        ]

    return router


# Build-time invariant: every request-id prefix must fit under the
# ``decision_history.request_id`` String(64) column cap (prefix + uuid4().hex
# (32)). Mirrors ``operator_routes.py`` / ``config_overlay/routes.py``.
for _prefix in (
    _OVERRIDE_SET_PREFIX,
    _OVERRIDE_CLR_PREFIX,
    _ALLOWLIST_ADD_PREFIX,
    _ALLOWLIST_REM_PREFIX,
):
    assert len(_prefix) + 32 <= _REQUEST_ID_MAX_LEN, (
        f"request_id prefix {_prefix!r} ({len(_prefix)} chars) + uuid4().hex (32) "
        f"= {len(_prefix) + 32} > {_REQUEST_ID_MAX_LEN}; would overflow the "
        "decision_history.request_id column cap"
    )
del _prefix
