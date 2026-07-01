"""M4 Task 3 (ADR-026 D2/D3/D4) — operator runtime-config write/read endpoints.

Ships the two ``configure``-surface endpoints behind ``/api/v1/packs``:

- ``PUT  /{pack_id}/runtime-config`` — writes the per-``(tenant, pack)`` DESIRED
  runtime-config record (operator-pre-provisioned MCP ``server_url`` override +
  internal-host allow-list + OAuth/AS Vault *references*). Human-only per ADR-026
  D4 — a service-token actor holding ``pack.configure`` is refused at the
  :class:`RequireHumanActor` dep BEFORE the handler body.
- ``GET  /{pack_id}/runtime-config`` — reads it. Service actors PERMITTED (no
  :class:`RequireHumanActor` on the read, mirroring the ``mcp_config`` read
  endpoints).

**This task does NOT materialize anything.** A materializer (M4 Task 4) later
projects the desired record into the derived MCP carve-out tables on ``install``.
Task 3 touches ONLY :class:`PackRuntimeConfigStore` (the desired-state record) and
adds NO lifecycle-state gate — existence + tenant ownership via
:class:`RequireTenantOwnership` and the store's active-reconfigure refusal are the
only gates.

**Factory takes only the runtime-config store.** Mirrors
:func:`~cognic_agentos.portal.api.packs.operator_routes.build_operator_routes`:
:class:`RequireTenantOwnership` pulls the :class:`PackRecord` from
``app.state.pack_record_store`` itself, so the factory does NOT take the pack
store. The returned router carries NO prefix — Task 7 mounts it under
``/api/v1/packs`` so each endpoint's full path is
``/api/v1/packs/{pack_id}/runtime-config``.

**Store key.** ``tenant_id`` comes from ``actor.tenant_id`` (NOT a path param);
the pack identity is ``str(record.id)`` (the UUID stringified) where ``record`` is
returned by :class:`RequireTenantOwnership` (existence + tenant ownership already
verified).

**PUT status mapping (NON-uniform).** The store's :class:`RuntimeConfigRejected`
carries a closed-enum ``reason``: ``runtime_config_reconfigure_while_active`` is a
STATE CONFLICT → 409; every other :class:`RuntimeConfigRejected` reason (the
opaque-ref shape refusals + the revoked-reconfigure refusal) → 422. The
override/allow-list GRAMMAR refusals surface as the sibling store's
:class:`MCPConfigRejected` (propagated unchanged from
:func:`validate_override_url` / :func:`validate_allowlist_ip` inside the audited
write) → 422. The route NEVER validates the grammar itself and NEVER touches the
DB directly — every mutation goes through :meth:`PackRuntimeConfigStore.set_config`
(the single audited write path), threading ``actor_subject`` / ``actor_type`` / a
minted ``request_id``.

**``from __future__ import annotations`` is INTENTIONALLY OMITTED** per the
standing FastAPI closure-local-``Depends`` gotcha (mirrors ``operator_routes.py``
+ ``mcp_config/routes.py``): the :class:`RequireScope` / :class:`RequireHumanActor`
/ :class:`RequireTenantOwnership` dependency instances are closure-local variables
inside :func:`build_configure_routes` (NOT module globals), and PEP 563
string-deferred annotations would break FastAPI's ``get_type_hints()`` resolution
of ``Annotated[..., Depends(<closure-local>)]`` — silently demoting handler params
to query params. Pinned by ``test_no_future_import``.
"""

import logging
import uuid
from typing import Annotated, Final

import pydantic
from fastapi import APIRouter, Body, Depends, HTTPException

from cognic_agentos.core.mcp_config.runtime_config import (
    PackRuntimeConfigStore,
    RuntimeConfigRejected,
)
from cognic_agentos.core.mcp_config.storage import MCPConfigRejected
from cognic_agentos.packs.storage import PackRecord
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope
from cognic_agentos.portal.rbac.human_actor import RequireHumanActor
from cognic_agentos.portal.rbac.tenant_isolation import RequireTenantOwnership

_LOG = logging.getLogger(__name__)

#: The single configure-set request-id prefix. uuid4().hex is exactly 32 chars;
#: prefix + 32 must fit under the ``decision_history.request_id`` String(64)
#: column cap. The module-foot assert pins this at import time.
_PACK_CONFIGURE_SET_PREFIX: Final[str] = "pack-cfg-set-"  # 13 + 32 = 45 <= 64
_REQUEST_ID_MAX_LEN: Final[int] = 64

#: The state-conflict reason that maps to 409 (NOT 422). Every OTHER
#: :class:`RuntimeConfigRejected` reason maps to 422.
_RECONFIGURE_WHILE_ACTIVE_REASON: Final[str] = "runtime_config_reconfigure_while_active"

#: GET-absent closed-enum body reason. Mirrors the ``mcp_config`` /
#: ``operator_routes`` ``pack_not_found`` body shape (a structured ``reason``).
_RUNTIME_CONFIG_NOT_FOUND_REASON: Final[str] = "runtime_config_not_found"


def _mint(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex}"


class SetRuntimeConfigRequest(pydantic.BaseModel):
    """PUT body for a runtime-config write. ALL fields OPTIONAL — a partial
    desired record is valid (the store + install-time own completeness per
    ADR-026 §gate 3). ``extra="forbid"`` so a caller cannot smuggle unknown keys.

    ``server_url_override`` is a plain ``str | None`` (NOT ``StrictStr``): the
    store's :func:`validate_override_url` grammar owns its validation, and the
    route needs a malformed value to REACH the store so its
    :class:`MCPConfigRejected` 422 surfaces."""

    model_config = pydantic.ConfigDict(extra="forbid")

    server_url_override: str | None = None
    internal_host_allowlist: list[str] = pydantic.Field(default_factory=list)
    oauth_credential_ref: str | None = None
    as_allowlist_ref: str | None = None


class RuntimeConfigResponse(pydantic.BaseModel):
    """The DESIRED runtime-config record projected onto the wire."""

    tenant_id: str
    pack_id: str
    server_url_override: str | None
    internal_host_allowlist: list[str]
    oauth_credential_ref: str | None
    as_allowlist_ref: str | None
    activation_status: str
    generation: int


def build_configure_routes(*, store: PackRuntimeConfigStore) -> APIRouter:
    """Build the configure-surface sub-router (PUT human-only; GET service-readable).

    The ``store`` argument is captured in this factory so each endpoint closes
    over a single :class:`PackRuntimeConfigStore` instance per app lifespan
    (mirrors :func:`build_operator_routes`). The returned router does NOT carry a
    prefix — Task 7 mounts it under ``/api/v1/packs`` so each endpoint's full path
    is ``/api/v1/packs/{pack_id}/runtime-config``.
    """
    router = APIRouter()

    # Shared dependency instances — one scope dep + one tenant-ownership + one
    # human-actor (write only). FastAPI's per-request callable-identity
    # sub-dependency cache deduplicates the actor binding + the PackRecord load
    # across the write's three deps.
    _require_configure = RequireScope("pack.configure")
    _require_tenant_ownership = RequireTenantOwnership(pack_id_param="pack_id")
    _require_human_actor = RequireHumanActor()

    @router.put(
        "/{pack_id}/runtime-config",
        response_model=RuntimeConfigResponse,
        summary="Write the desired runtime-config record for this (tenant, pack)",
    )
    async def set_runtime_config(
        actor: Annotated[Actor, Depends(_require_configure)],
        record: Annotated[PackRecord, Depends(_require_tenant_ownership)],
        _human: Annotated[Actor, Depends(_require_human_actor)],
        body: Annotated[SetRuntimeConfigRequest, Body(...)],
    ) -> RuntimeConfigResponse:
        """Write the desired config via :meth:`PackRuntimeConfigStore.set_config`.

        Dependency chain (resolution order):
        1. :class:`RequireScope("pack.configure")` — 403 ``scope_not_held``.
        2. :class:`RequireTenantOwnership` — 404 ``tenant_id_mismatch`` /
           ``pack_not_found`` for cross-tenant / unknown pack; returns the
           :class:`PackRecord` (existence + tenant ownership verified).
        3. :class:`RequireHumanActor` — 403 ``actor_type_must_be_human`` for
           service-token actors (ADR-026 D4 — write is human-only). The
           ``_human`` binding is unused in the body but the :class:`Depends`
           declaration is what registers the guard.

        Handler-body refusals (NON-uniform status map):
        - :class:`RuntimeConfigRejected` with
          ``reason == "runtime_config_reconfigure_while_active"`` → 409
          (STATE CONFLICT — the derived carve-outs are live; a live config
          change is ``disable → configure → install``).
        - any OTHER :class:`RuntimeConfigRejected` (opaque-ref shape refusals;
          revoked-reconfigure) → 422.
        - :class:`MCPConfigRejected` (override / allow-list grammar, propagated
          unchanged from the audited store) → 422.

        Each refusal emits EXACTLY ONE ``portal.packs.configure_set_refused``
        log; the green path emits EXACTLY ONE ``portal.packs.configure_set`` log
        then re-reads the record for the response.
        """
        tenant_id = actor.tenant_id
        pack_id = str(record.id)
        try:
            await store.set_config(
                tenant_id=tenant_id,
                pack_id=pack_id,
                server_url_override=body.server_url_override,
                internal_host_allowlist=body.internal_host_allowlist,
                oauth_credential_ref=body.oauth_credential_ref,
                as_allowlist_ref=body.as_allowlist_ref,
                actor_subject=actor.subject,
                actor_type=actor.actor_type,
                request_id=_mint(_PACK_CONFIGURE_SET_PREFIX),
            )
        except RuntimeConfigRejected as exc:
            _LOG.warning(
                "portal.packs.configure_set_refused",
                extra={
                    "reason": exc.reason,
                    "tenant_id": tenant_id,
                    "pack_id": pack_id,
                    "actor_subject": actor.subject,
                },
            )
            # NON-uniform: the active-reconfigure state-conflict is a 409; every
            # other RuntimeConfigRejected reason (opaque-ref shape; revoked
            # reconfigure) is a 422.
            status_code = 409 if exc.reason == _RECONFIGURE_WHILE_ACTIVE_REASON else 422
            raise HTTPException(status_code=status_code, detail={"reason": exc.reason}) from exc
        except MCPConfigRejected as exc:
            # Override / allow-list grammar refusal — propagated unchanged from
            # the audited store's validators. Always a 422 (bad input shape).
            _LOG.warning(
                "portal.packs.configure_set_refused",
                extra={
                    "reason": exc.reason,
                    "tenant_id": tenant_id,
                    "pack_id": pack_id,
                    "actor_subject": actor.subject,
                },
            )
            raise HTTPException(status_code=422, detail={"reason": exc.reason}) from exc

        _LOG.warning(
            "portal.packs.configure_set",
            extra={
                "tenant_id": tenant_id,
                "pack_id": pack_id,
                "actor_subject": actor.subject,
                "actor_type": actor.actor_type,
            },
        )

        current = await store.get(tenant_id=tenant_id, pack_id=pack_id)
        if current is None:  # pragma: no cover - defence in depth (just written)
            raise HTTPException(
                status_code=404,
                detail={"reason": _RUNTIME_CONFIG_NOT_FOUND_REASON},
            )
        return RuntimeConfigResponse(
            tenant_id=current.tenant_id,
            pack_id=current.pack_id,
            server_url_override=current.server_url_override,
            internal_host_allowlist=list(current.internal_host_allowlist),
            oauth_credential_ref=current.oauth_credential_ref,
            as_allowlist_ref=current.as_allowlist_ref,
            activation_status=current.activation_status,
            generation=current.generation,
        )

    @router.get(
        "/{pack_id}/runtime-config",
        response_model=RuntimeConfigResponse,
        summary="Read the desired runtime-config record for this (tenant, pack)",
    )
    async def get_runtime_config(
        actor: Annotated[Actor, Depends(_require_configure)],
        record: Annotated[PackRecord, Depends(_require_tenant_ownership)],
    ) -> RuntimeConfigResponse:
        """Read the desired config. Service actors PERMITTED (no
        :class:`RequireHumanActor`, mirroring the ``mcp_config`` read endpoints).

        Dependency chain: :class:`RequireScope("pack.configure")` → 403
        ``scope_not_held``; :class:`RequireTenantOwnership` → 404
        ``tenant_id_mismatch`` / ``pack_not_found``. A read with no persisted
        record → 404 ``runtime_config_not_found``.
        """
        current = await store.get(tenant_id=actor.tenant_id, pack_id=str(record.id))
        if current is None:
            raise HTTPException(
                status_code=404,
                detail={"reason": _RUNTIME_CONFIG_NOT_FOUND_REASON},
            )
        return RuntimeConfigResponse(
            tenant_id=current.tenant_id,
            pack_id=current.pack_id,
            server_url_override=current.server_url_override,
            internal_host_allowlist=list(current.internal_host_allowlist),
            oauth_credential_ref=current.oauth_credential_ref,
            as_allowlist_ref=current.as_allowlist_ref,
            activation_status=current.activation_status,
            generation=current.generation,
        )

    return router


# Build-time invariant: the configure request-id prefix MUST fit under the
# ``decision_history.request_id`` String(64) column cap (prefix + uuid4().hex
# (32)). Mirrors ``operator_routes.py`` / ``mcp_config/routes.py``.
assert len(_PACK_CONFIGURE_SET_PREFIX) + 32 <= _REQUEST_ID_MAX_LEN, (
    f"request_id prefix {_PACK_CONFIGURE_SET_PREFIX!r} "
    f"({len(_PACK_CONFIGURE_SET_PREFIX)} chars) + uuid4().hex (32) "
    f"= {len(_PACK_CONFIGURE_SET_PREFIX) + 32} > {_REQUEST_ID_MAX_LEN}; "
    "would overflow the decision_history.request_id column cap"
)
