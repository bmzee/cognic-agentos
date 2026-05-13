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
from collections.abc import Callable
from typing import Annotated, Literal

from fastapi import Depends, HTTPException

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import _bind_actor

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


def RequireHumanActor() -> Callable[..., Actor]:
    """FastAPI dependency factory — admit only ``actor_type == "human"``.

    Refuses service actors with 403 +
    ``{"reason": "actor_type_must_be_human", "actor_subject": ...}``.

    Out-of-vocabulary ``actor_type`` values (e.g. ``"robot"``) are
    already refused at :class:`Actor` construction by Pydantic — this
    guard is purely the human-vs-service discriminator INSIDE the
    wire-protocol vocabulary, not an enum-membership check.

    Returns the bound :class:`Actor` on success so downstream handlers
    consume the resolved identity without re-binding.
    """

    def dependency(actor: Annotated[Actor, Depends(_bind_actor)]) -> Actor:
        if actor.actor_type != "human":
            _LOG.warning(
                "portal.rbac.human_actor_required",
                extra={
                    "reason": "actor_type_must_be_human",
                    "actor_subject": actor.subject,
                    "actor_type": actor.actor_type,
                },
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
