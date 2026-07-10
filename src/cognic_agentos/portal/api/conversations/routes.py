"""ADR-028 M8.5-C — the conversation portal surface.

Routes are mounted at APP-CONSTRUCTION time, before the lifespan has built an
engine or an agent loop. The ``ConversationStore`` and the
``ConversationTurnExecutor`` are read from ``app.state`` by request-time
dependencies that fail CLOSED with 503 until the lifespan populates them. This
mirrors ``portal/api/runs/routes.py``: ``app.include_router`` is NEVER called
from inside the lifespan (AST-verified -- zero such calls in ``app.py``'s
lifespan).

``from __future__ import annotations`` is INTENTIONALLY OMITTED: PEP 563
string-deferred annotations break FastAPI's ``inspect.signature()`` /
``typing.get_type_hints()`` resolution of ``Annotated[..., Depends(...)]`` when
the dependency is a closure-local, silently degrading path/body params to query
params.

Authoring validation (ADR-028 §6): the agent must exist and be hosted at
create-conversation time. This constrains early and cheaply -- and it is NOT
load-bearing alone. Dispatch remains the final authority: the M8 chokepoint
re-checks assignment -> entitlement -> policy on every dispatch of every turn.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from cognic_agentos.core.conversation._types import (
    ConversationNotFound,
    ConversationTransitionRefused,
    ConversationTurnRefused,
)
from cognic_agentos.core.conversation.storage import ConversationStore
from cognic_agentos.core.conversation.turn import ConversationTurnExecutor
from cognic_agentos.portal.api.conversations.dto import (
    ConversationResponse,
    CreateConversationRequest,
    PostTurnRequest,
    TurnResponse,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope

#: Byte-stable 404 bodies. A cross-tenant or cross-actor conversation is
#: indistinguishable from one that never existed.
_NOT_FOUND = {"reason": "conversation_not_found"}
_AGENT_NOT_FOUND = {"reason": "agent_not_found"}


def _require_store(request: Request) -> ConversationStore:
    store: ConversationStore | None = getattr(request.app.state, "conversation_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"reason": "conversation_store_unavailable"},
        )
    return store


def _require_executor(request: Request) -> ConversationTurnExecutor:
    executor: ConversationTurnExecutor | None = getattr(
        request.app.state, "conversation_executor", None
    )
    if executor is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"reason": "conversation_executor_unavailable"},
        )
    return executor


def _hosted_agent_ids(request: Request) -> frozenset[str]:
    """The boot-admitted agent set (``app.state.hosted_agents``, the same rows
    ``/api/v1/system/plugins`` surfaces)."""
    rows = getattr(request.app.state, "hosted_agents", []) or []
    return frozenset(str(row["agent_id"]) for row in rows if "agent_id" in row)


def build_conversation_routes() -> APIRouter:
    """No constructor args: neither the store nor the executor exists at
    app-construction time."""
    router = APIRouter()
    _require_create = RequireScope("conversation.create")
    _require_read = RequireScope("conversation.read")
    _require_post_turn = RequireScope("conversation.post_turn")
    _require_close = RequireScope("conversation.close")

    @router.post("", response_model=ConversationResponse, status_code=201)
    async def create_conversation(
        body: CreateConversationRequest,
        actor: Annotated[Actor, Depends(_require_create)],
        store: Annotated[ConversationStore, Depends(_require_store)],
        _executor: Annotated[ConversationTurnExecutor, Depends(_require_executor)],
        hosted: Annotated[frozenset[str], Depends(_hosted_agent_ids)],
    ) -> ConversationResponse:
        # Authoring validation: the agent must exist and be hosted (ADR-028 §6).
        # Early + cheap; never load-bearing alone.
        if body.agent_id not in hosted:
            raise HTTPException(status_code=404, detail=_AGENT_NOT_FOUND)

        conversation_id = uuid.uuid4()
        await store.create_conversation(
            conversation_id=conversation_id,
            tenant_id=actor.tenant_id,
            agent_id=body.agent_id,
            creator_subject=actor.subject,
            request_id=f"conv-create-{uuid.uuid4().hex}",
        )
        return ConversationResponse(
            conversation_id=conversation_id,
            agent_id=body.agent_id,
            state="active",
            turn_count=0,
        )

    @router.get("/{conversation_id}", response_model=ConversationResponse)
    async def read_conversation(
        conversation_id: uuid.UUID,
        actor: Annotated[Actor, Depends(_require_read)],
        store: Annotated[ConversationStore, Depends(_require_store)],
    ) -> ConversationResponse:
        record = await store.load(
            conversation_id, tenant_id=actor.tenant_id, creator_subject=actor.subject
        )
        if record is None:
            raise HTTPException(status_code=404, detail=_NOT_FOUND)
        return ConversationResponse(
            conversation_id=record.conversation_id,
            agent_id=record.agent_id,
            state=record.state,
            turn_count=record.turn_count,
        )

    @router.post("/{conversation_id}/turns", response_model=TurnResponse)
    async def post_turn(
        conversation_id: uuid.UUID,
        body: PostTurnRequest,
        actor: Annotated[Actor, Depends(_require_post_turn)],
        executor: Annotated[ConversationTurnExecutor, Depends(_require_executor)],
    ) -> TurnResponse:
        try:
            result = await executor.post_turn(
                conversation_id=conversation_id,
                tenant_id=actor.tenant_id,
                actor_subject=actor.subject,
                user_message=body.user_message,
            )
        except ConversationNotFound:
            raise HTTPException(status_code=404, detail=_NOT_FOUND) from None
        except ConversationTurnRefused as exc:
            raise HTTPException(
                status_code=409,
                detail={"reason": exc.reason, "current_state": exc.current_state},
            ) from None
        except LookupError:
            # the agent was un-hosted between create and this turn
            raise HTTPException(status_code=404, detail=_AGENT_NOT_FOUND) from None

        if result.terminal_state == "failed":
            raise HTTPException(status_code=502, detail={"reason": "agent_run_failed"})
        # a governed refusal IS a governed answer -- 200, never an error status
        return TurnResponse(
            turn_id=result.turn_id,
            seq=result.seq,
            answer=result.answer,
            agent_run_id=result.agent_run_id,
            terminal_state=result.terminal_state,
            refusal_reason=result.refusal_reason,
        )

    @router.post("/{conversation_id}/close", response_model=ConversationResponse)
    async def close_conversation(
        conversation_id: uuid.UUID,
        actor: Annotated[Actor, Depends(_require_close)],
        store: Annotated[ConversationStore, Depends(_require_store)],
    ) -> ConversationResponse:
        record = await store.load(
            conversation_id, tenant_id=actor.tenant_id, creator_subject=actor.subject
        )
        if record is None:
            raise HTTPException(status_code=404, detail=_NOT_FOUND)
        try:
            # No from_state kwarg: the store reads it under the row lock, so a
            # concurrent close cannot race a stale value into the chain row.
            # Graceful close: an in-flight turn keeps its claim and settles.
            await store.transition(
                conversation_id=conversation_id,
                tenant_id=actor.tenant_id,
                to_state="closed",
                actor_id=actor.subject,
                request_id=f"conv-close-{uuid.uuid4().hex}",
            )
        except ConversationTransitionRefused as exc:
            raise HTTPException(status_code=409, detail={"reason": exc.reason}) from None
        return ConversationResponse(
            conversation_id=conversation_id,
            agent_id=record.agent_id,
            state="closed",
            turn_count=record.turn_count,
        )

    return router
