"""Sprint 7B.2 T2 — RequireHumanActor dependency + closed-enum HumanActorDenialReason.

Plan Round 1 P3 #8 — operator-surface endpoints that finalise per-tenant
state changes must refuse service actors. Specifically the
``/operator/{pack_id}/allow-list`` endpoint in T6 — per AGENTS.md
"Per-tenant allow-list changes" human-only-decisions rule, allow-list
changes are human-only and cannot be automated.

The closed-enum :data:`HumanActorDenialReason` carries a single value
(``actor_type_must_be_human``) because the guard has exactly one failure
mode in 7B.2. The closed-enum shape is preserved (rather than collapsing
to a bare string) so future expansion follows the same wire-protocol
contract as the other RBAC denial vocabularies.

Module is intentionally separate from :mod:`.enforcement` because:

- The closed-enum vocabulary is distinct.
- The use-case is operator-surface only (not every state-transition
  endpoint).
- Composability — endpoints declare ``Depends(RequireScope("pack.allow_list"))``
  AND ``Depends(RequireHumanActor())`` independently; FastAPI caches the
  shared :func:`~cognic_agentos.portal.rbac.enforcement._bind_actor` call
  so the actor is bound once per request.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Annotated, Literal

from fastapi import Depends, HTTPException, Request

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import (
    _bind_actor,
    _emit_denial_or_500,
    _resolve_request_id,
)

if TYPE_CHECKING:
    from cognic_agentos.protocol.ui_events import UIEventBroker

_LOG = logging.getLogger(__name__)


#: Closed-enum vocabulary for the human-only guard. 1-value Literal —
#: the closed-enum shape is preserved (rather than collapsing to a bare
#: string) so future expansion follows the same wire-protocol contract
#: as :data:`~cognic_agentos.portal.rbac.enforcement.RBACDenialReason`
#: and :data:`~cognic_agentos.portal.rbac.tenant_isolation.TenantIsolationFailure`.
#:
#: Style note: plain ``= Literal[...]`` (no ``TypeAlias`` annotation) to
#: match the Sprint-7B.1 repo convention at ``packs/lifecycle.py:111``.
HumanActorDenialReason = Literal["actor_type_must_be_human"]


def RequireHumanActor() -> Callable[..., Awaitable[Actor]]:
    """FastAPI dependency factory — admit only ``actor_type == "human"``.

    Refuses service actors with 403 +
    ``{"reason": "actor_type_must_be_human", "actor_subject": ...}``.

    Sprint-7B.4 T6: converted to async so the denial path can ``await
    broker.emit_rbac_denial`` via the shared
    :func:`~cognic_agentos.portal.rbac.enforcement._emit_denial_or_500`
    helper. FastAPI handles async sub-deps transparently for existing
    callers (the allow-list endpoint at
    ``portal/api/packs/operator_routes.py:..`` declares
    ``Depends(RequireHumanActor())`` — no callsite change required).

    Out-of-vocabulary ``actor_type`` values (e.g. ``"robot"``) are
    already refused at :class:`Actor` construction by Pydantic — this
    guard is purely the human-vs-service discriminator INSIDE the
    wire-protocol vocabulary, not an enum-membership check.

    Returns the bound :class:`Actor` on success so downstream handlers
    consume the resolved identity without re-binding.
    """

    async def dependency(
        request: Request,
        actor: Annotated[Actor, Depends(_bind_actor)],
    ) -> Actor:
        if actor.actor_type != "human":
            broker: UIEventBroker | None = getattr(request.app.state, "ui_event_broker", None)
            await _emit_denial_or_500(
                broker,
                denial_type="actor_type_must_be_human",
                actor_subject=actor.subject,
                tenant_id=actor.tenant_id,  # P1 #5: actor IS resolved
                request_id=_resolve_request_id(request),
                http_status=403,
                actor_type=actor.actor_type,
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "reason": "actor_type_must_be_human",
                    "actor_subject": actor.subject,
                },
            )
        return actor

    return dependency
