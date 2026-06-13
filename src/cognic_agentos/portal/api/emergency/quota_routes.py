"""Sprint 13.6b T5 — read-only quota portal surface (ADR-018 §Portal API).

`GET /api/v1/emergency/quotas?tenant=...` behind `RequireScope("quota.read")`
returns the tenant's resolved limit + current usage (actuals + reserved) +
usage_pct from the QuotaEngine read counters (the cache-for-display exception
per the design §3.5 — never used for admission). NO override / write surface
(deferred with the limit-write surface per the resolved spec-review decision).

NOTE: ``from __future__ import annotations`` is INTENTIONALLY OMITTED — PEP 563
string-deferred annotations break FastAPI's ``inspect.signature()`` resolution
on ``Annotated[..., Depends(<closure-local>)]`` (the standing portal route-
module invariant).
"""

import logging
import uuid
from typing import TYPE_CHECKING, Annotated, Final

from fastapi import APIRouter, Depends, Query

from cognic_agentos.portal.api.emergency.quota_dto import QuotaUsageResponse
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope

if TYPE_CHECKING:
    from cognic_agentos.core.config import Settings
    from cognic_agentos.core.emergency.quotas import QuotaEngine

logger = logging.getLogger(__name__)

_QUOTA_READ_REQUEST_ID_PREFIX: Final[str] = "emrg-quota-rd-"


def _mint_request_id(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex}"


def build_quota_routes(*, quota_engine: "QuotaEngine", settings: "Settings") -> APIRouter:
    """Route factory (mounted by ``create_app`` when the quota engine is wired
    — T6). Closure-local read scope per the standing portal convention."""
    router = APIRouter(prefix="/api/v1/emergency", tags=["emergency"])
    _require_read = RequireScope("quota.read")

    @router.get(
        "/quotas",
        summary="Read a tenant's token-quota limit + current usage",
        response_model=QuotaUsageResponse,
    )
    async def read_quota_usage(
        actor: Annotated[Actor, Depends(_require_read)],
        tenant: Annotated[str, Query(min_length=1)],
    ) -> QuotaUsageResponse:
        request_id = _mint_request_id(_QUOTA_READ_REQUEST_ID_PREFIX)
        view = await quota_engine.usage_view(tenant_id=tenant)
        limit = view["tenant_limit"]
        used = view["actuals"] + view["reserved"]
        usage_pct = round(100.0 * used / limit, 2) if limit > 0 else 0.0
        logger.info(
            "portal.emergency.quota_read",
            extra={
                "tenant": tenant,
                "actor_subject": actor.subject,
                "request_id": request_id,
                "usage_pct": usage_pct,
            },
        )
        return QuotaUsageResponse(
            tenant_limit=limit,
            actuals=view["actuals"],
            reserved=view["reserved"],
            usage_pct=usage_pct,
        )

    return router


# Build-time pin: emrg-quota-rd- (14) + uuid4 hex (32) = 46 <= 64.
assert len(_QUOTA_READ_REQUEST_ID_PREFIX) + 32 <= 64
