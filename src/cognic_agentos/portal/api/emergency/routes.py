"""Sprint 13.6 T6 — portal emergency kill-switch routes (ADR-018 §Portal API).

Surface: ``GET /api/v1/emergency/kill-switches`` (list active) + ``POST``
(flip) + ``DELETE /kill-switches/{switch_class}/{scope_key}`` (revert) +
``GET /audit`` (the ``emergency.*`` chain trail). Flip/revert run the
body-aware per-class ``EmergencyRBACScope`` check + the in-handler human gate
(the ``lifecycle_routes.py`` promote precedent — the required scope depends on
the parsed class, so a factory-time ``RequireScope`` dep cannot express it);
list/audit ride ``RequireScope("emergency.read")``. The engine owns the brake
+ the chain evidence; an evidence-degraded flip surfaces the closed-enum
``kill_switch_live_evidence_degraded`` 502 with ``switch_live=true`` (spec
review patch 3) — the operator KNOWS the brake is on and retries (the
idempotent re-flip converges the chain).

Mutually-exclusive structured-log contract per verb: green emits EXACTLY ONE
``portal.emergency.kill_switch_flipped`` / ``..._reverted``; a refusal emits
EXACTLY ONE ``portal.emergency.flip_refused`` / ``..._revert_refused`` and
ZERO green logs.

NOTE: ``from __future__ import annotations`` is INTENTIONALLY OMITTED — PEP
563 string-deferred annotations break FastAPI's ``inspect.signature()``
resolution on ``Annotated[..., Depends(<closure-local>)]`` (the standing
portal route-module invariant).
"""

import datetime
import logging
import uuid
from typing import Annotated, Final

from fastapi import APIRouter, Depends, HTTPException, Query

from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.core.emergency.audit_read import load_emergency_audit
from cognic_agentos.core.emergency.kill_switches import (
    ENFORCEMENT_STATUS_BY_CLASS,
    FlipResult,
    KillSwitchCategory,
    KillSwitchClass,
    KillSwitchEngine,
)
from cognic_agentos.portal.api.emergency.dto import (
    EmergencyAuditEntryResponse,
    KillSwitchEntryResponse,
    KillSwitchFlipRequest,
    KillSwitchFlipResponse,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope, bind_actor
from cognic_agentos.portal.rbac.scopes import EmergencyRBACScope

logger = logging.getLogger(__name__)

#: Body-aware per-class scope map — every flip/revert requires the scope the
#: ADR-018 table assigns to its class (§34-42; the seed + emergency.read per
#: the T5 9-value family).
_CLASS_TO_SCOPE: Final[dict[KillSwitchClass, EmergencyRBACScope]] = {
    "pack": "emergency.kill.pack",
    "tool": "emergency.kill.tool",
    "model": "emergency.kill.model",
    "tenant_packs": "emergency.kill.tenant_packs",
    "tenant_full": "emergency.kill.tenant_full",
    "cloud_routing": "emergency.kill.cloud",
    "feature": "emergency.kill.feature",
    "memory_write_freeze": "emergency.kill.memory_write_freeze",
}

#: Per-verb request-id minter prefixes (log correlation; the CHAIN request_id
#: is engine-minted with the distinct ``emrg-flip-`` prefix). 13 chars each.
_EMERGENCY_FLIP_REQUEST_ID_PREFIX: Final[str] = "emrg-flip-rt-"
_EMERGENCY_REVERT_REQUEST_ID_PREFIX: Final[str] = "emrg-rvrt-rt-"
_EMERGENCY_LIST_REQUEST_ID_PREFIX: Final[str] = "emrg-list-rt-"
_EMERGENCY_AUDIT_REQUEST_ID_PREFIX: Final[str] = "emrg-audt-rt-"


def _mint_request_id(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex}"


def _check_mutation_authority(
    *,
    actor: Actor,
    class_: KillSwitchClass,
    verb: str,
    request_id: str,
) -> None:
    """The two in-handler gates shared by flip + revert, in the
    lifecycle_routes order: (1) body-aware per-class scope; (2) human-only
    (ADR-018 flips are operator emergency actions — a service token holding
    the scope is still refused)."""
    required_scope = _CLASS_TO_SCOPE[class_]
    if required_scope not in actor.scopes:
        logger.warning(
            f"portal.emergency.{verb}_refused",
            extra={
                "reason": "scope_not_held",
                "required_scope": required_scope,
                "actor_subject": actor.subject,
                "request_id": request_id,
                "http_status": 403,
            },
        )
        raise HTTPException(
            status_code=403,
            detail={
                "reason": "scope_not_held",
                "required_scope": required_scope,
                "actor_subject": actor.subject,
            },
        )
    if actor.actor_type != "human":
        logger.warning(
            f"portal.emergency.{verb}_refused",
            extra={
                "reason": "actor_type_must_be_human",
                "actor_subject": actor.subject,
                "request_id": request_id,
                "http_status": 403,
            },
        )
        raise HTTPException(
            status_code=403,
            detail={
                "reason": "actor_type_must_be_human",
                "actor_subject": actor.subject,
            },
        )


def _translate_mutation_result(
    *,
    result: FlipResult,
    class_: KillSwitchClass,
    scope_key: str,
    actor: Actor,
    verb: str,
    green_log: str,
    request_id: str,
) -> KillSwitchFlipResponse:
    """Map the engine's FlipResult onto the wire: evidence-degraded → the
    closed-enum 502 (switch LIVE — review patch 3); green → 200 + EXACTLY ONE
    green structured log."""
    if result.evidence_degraded:
        logger.error(
            f"portal.emergency.{verb}_evidence_degraded",
            extra={
                "class": class_,
                "scope_key": scope_key,
                "actor_subject": actor.subject,
                "request_id": request_id,
                "switch_live": True,
                "http_status": 502,
            },
        )
        raise HTTPException(
            status_code=502,
            detail={
                "reason": "kill_switch_live_evidence_degraded",
                "switch_live": True,
            },
        )
    logger.info(
        green_log,
        extra={
            "class": class_,
            "scope_key": scope_key,
            "active": result.active,
            "actor_subject": actor.subject,
            "request_id": request_id,
            "chain_record_id": str(result.chain_record_id),
        },
    )
    # model_validate with the wire-shaped dict — the pydantic-mypy plugin
    # synthesizes __init__ keyed by the alias ("class"), which is not a valid
    # Python keyword; the dict form sidesteps that cleanly.
    return KillSwitchFlipResponse.model_validate(
        {
            "class": class_,
            "scope_key": scope_key,
            "active": result.active,
            "enforcement_status": ENFORCEMENT_STATUS_BY_CLASS[class_],
        }
    )


def build_emergency_routes(
    *,
    engine: KillSwitchEngine,
    decision_history_store: DecisionHistoryStore,
) -> APIRouter:
    """Route factory (mounted by ``create_app`` when the engine is wired —
    T7). Closure-local shared deps per the standing portal convention."""
    router = APIRouter(prefix="/api/v1/emergency", tags=["emergency"])
    _require_read = RequireScope("emergency.read")

    @router.get(
        "/kill-switches",
        summary="List ACTIVE kill switches (with enforcement_status honesty)",
        response_model=list[KillSwitchEntryResponse],
    )
    async def list_kill_switches(
        actor: Annotated[Actor, Depends(_require_read)],
    ) -> list[KillSwitchEntryResponse]:
        entries = await engine.list_active()
        return [KillSwitchEntryResponse.model_validate(entry) for entry in entries]

    @router.post(
        "/kill-switches",
        summary="Flip a kill switch (per-class scope + human-only + categorised reason)",
        response_model=KillSwitchFlipResponse,
    )
    async def flip_kill_switch(
        body: KillSwitchFlipRequest,
        actor: Annotated[Actor, Depends(bind_actor)],
    ) -> KillSwitchFlipResponse:
        request_id = _mint_request_id(_EMERGENCY_FLIP_REQUEST_ID_PREFIX)
        _check_mutation_authority(
            actor=actor, class_=body.class_, verb="flip", request_id=request_id
        )
        try:
            result = await engine.flip(
                class_=body.class_,
                scope_key=body.scope_key,
                actor_id=actor.subject,
                reason=body.reason,
                category=body.category,
            )
        except ValueError as exc:
            # The engine's closed feature-name vocabulary (resolved flag 4).
            logger.warning(
                "portal.emergency.flip_refused",
                extra={
                    "reason": "feature_name_unknown",
                    "class": body.class_,
                    "scope_key": body.scope_key,
                    "actor_subject": actor.subject,
                    "request_id": request_id,
                    "http_status": 422,
                },
            )
            raise HTTPException(
                status_code=422,
                detail={"reason": "feature_name_unknown", "detail": str(exc)},
            ) from exc
        return _translate_mutation_result(
            result=result,
            class_=body.class_,
            scope_key=body.scope_key,
            actor=actor,
            verb="flip",
            green_log="portal.emergency.kill_switch_flipped",
            request_id=request_id,
        )

    @router.delete(
        "/kill-switches/{switch_class}/{scope_key}",
        summary="Revert a kill switch (same gates; mandatory categorised reason)",
        response_model=KillSwitchFlipResponse,
    )
    async def revert_kill_switch(
        switch_class: KillSwitchClass,
        scope_key: str,
        actor: Annotated[Actor, Depends(bind_actor)],
        reason: Annotated[str, Query(min_length=1, max_length=2048)],
        category: Annotated[KillSwitchCategory, Query()],
    ) -> KillSwitchFlipResponse:
        request_id = _mint_request_id(_EMERGENCY_REVERT_REQUEST_ID_PREFIX)
        _check_mutation_authority(
            actor=actor, class_=switch_class, verb="revert", request_id=request_id
        )
        try:
            result = await engine.revert(
                class_=switch_class,
                scope_key=scope_key,
                actor_id=actor.subject,
                reason=reason,
                category=category,
            )
        except ValueError as exc:
            logger.warning(
                "portal.emergency.revert_refused",
                extra={
                    "reason": "feature_name_unknown",
                    "class": switch_class,
                    "scope_key": scope_key,
                    "actor_subject": actor.subject,
                    "request_id": request_id,
                    "http_status": 422,
                },
            )
            raise HTTPException(
                status_code=422,
                detail={"reason": "feature_name_unknown", "detail": str(exc)},
            ) from exc
        return _translate_mutation_result(
            result=result,
            class_=switch_class,
            scope_key=scope_key,
            actor=actor,
            verb="revert",
            green_log="portal.emergency.kill_switch_reverted",
            request_id=request_id,
        )

    @router.get(
        "/audit",
        summary="The emergency.* chain trail (newest-first)",
        response_model=list[EmergencyAuditEntryResponse],
    )
    async def emergency_audit(
        actor: Annotated[Actor, Depends(_require_read)],
        from_ts: Annotated[datetime.datetime | None, Query(alias="from")] = None,
        to_ts: Annotated[datetime.datetime | None, Query(alias="to")] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> list[EmergencyAuditEntryResponse]:
        rows = await load_emergency_audit(
            decision_history_store._engine,  # private-attr read; stream_routes precedent
            from_ts=from_ts,
            to_ts=to_ts,
            limit=limit,
        )
        return [EmergencyAuditEntryResponse.model_validate(row) for row in rows]

    return router


# Build-time pins: every minter prefix (13) + uuid4 hex (32) = 45 <= the
# 64-char request_id cap (the standing module-foot pattern).
assert len(_EMERGENCY_FLIP_REQUEST_ID_PREFIX) + 32 <= 64
assert len(_EMERGENCY_REVERT_REQUEST_ID_PREFIX) + 32 <= 64
assert len(_EMERGENCY_LIST_REQUEST_ID_PREFIX) + 32 <= 64
assert len(_EMERGENCY_AUDIT_REQUEST_ID_PREFIX) + 32 <= 64
