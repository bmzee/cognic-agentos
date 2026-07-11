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

import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from cognic_agentos.core.conversation._types import (
    ConversationNotFound,
    ConversationState,
    ConversationTransitionRefused,
    ConversationTurnRefused,
)
from cognic_agentos.core.conversation.read_model import (
    ConversationChainIntegrityError,
    ConversationChainProjectionLimit,
    ConversationReadModel,
    ConversationTranscriptIntegrityError,
    CursorInvalid,
    TurnNotFound,
)
from cognic_agentos.core.conversation.storage import ConversationStore
from cognic_agentos.core.conversation.turn import ConversationTurnExecutor
from cognic_agentos.portal.api.conversations.dto import (
    ConversationListResponse,
    ConversationResponse,
    ConversationSummaryResponse,
    CreateConversationRequest,
    DispatchEvidenceResponse,
    PostTurnRequest,
    RunStartedEvidenceResponse,
    RunTerminalEvidenceResponse,
    TranscriptResponse,
    TranscriptTurnResponse,
    TurnChainResponse,
    TurnCompletedEvidenceResponse,
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


logger = logging.getLogger(__name__)


def _require_read_model(request: Request) -> ConversationReadModel:
    reader: ConversationReadModel | None = getattr(
        request.app.state, "conversation_read_model", None
    )
    if reader is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"reason": "conversation_read_model_unavailable"},
        )
    return reader


def _log_access(
    endpoint: str,
    *,
    actor: Actor,
    outcome: str,
    conversation_id: uuid.UUID | None = None,
    seq: int | None = None,
) -> None:
    """The ruled M8.5-B access log: identifiers + outcome ONLY — never
    transcript plaintext, never payload content. No chain/audit append rides
    a GET (a chain write would serialize every read on the chain-head lock)."""
    logger.info(
        "portal.conversations.%s",
        endpoint,
        extra={
            "tenant_id": actor.tenant_id,
            "actor_subject": actor.subject,
            "conversation_id": str(conversation_id) if conversation_id else None,
            "seq": seq,
            "outcome": outcome,
        },
    )


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

    @router.get("", response_model=ConversationListResponse)
    async def list_conversations(
        actor: Annotated[Actor, Depends(_require_read)],
        reader: Annotated[ConversationReadModel, Depends(_require_read_model)],
        limit: Annotated[int | None, Query(ge=1, le=200)] = None,
        state: Annotated[ConversationState | None, Query()] = None,
        cursor: Annotated[str | None, Query()] = None,
    ) -> ConversationListResponse:
        try:
            page = await reader.list_conversations(
                tenant_id=actor.tenant_id,
                creator_subject=actor.subject,
                limit=limit,
                state=state,
                cursor=cursor,
            )
        except CursorInvalid:
            _log_access("list", actor=actor, outcome="cursor_invalid")
            raise HTTPException(status_code=422, detail={"reason": "cursor_invalid"}) from None
        _log_access("list", actor=actor, outcome="ok")
        return ConversationListResponse(
            items=[
                ConversationSummaryResponse(
                    conversation_id=item.conversation_id,
                    agent_id=item.agent_id,
                    state=item.state,
                    turn_count=item.turn_count,
                    cumulative_tokens=item.cumulative_tokens,
                    created_at=item.created_at,
                    last_turn_at=item.last_turn_at,
                )
                for item in page.items
            ],
            next_cursor=page.next_cursor,
        )

    @router.get("/{conversation_id}/transcript", response_model=TranscriptResponse)
    async def read_transcript(
        conversation_id: uuid.UUID,
        actor: Annotated[Actor, Depends(_require_read)],
        reader: Annotated[ConversationReadModel, Depends(_require_read_model)],
        limit: Annotated[int | None, Query(ge=1, le=200)] = None,
        cursor: Annotated[str | None, Query()] = None,
    ) -> TranscriptResponse:
        try:
            page = await reader.read_transcript(
                conversation_id,
                tenant_id=actor.tenant_id,
                creator_subject=actor.subject,
                limit=limit,
                cursor=cursor,
            )
        except CursorInvalid:
            _log_access(
                "transcript",
                actor=actor,
                outcome="cursor_invalid",
                conversation_id=conversation_id,
            )
            raise HTTPException(status_code=422, detail={"reason": "cursor_invalid"}) from None
        except ConversationTranscriptIntegrityError as exc:
            # Detailed internals go to the operator log ONLY.
            logger.error(
                "portal.conversations.transcript_integrity_failed",
                extra={
                    "tenant_id": actor.tenant_id,
                    "actor_subject": actor.subject,
                    "conversation_id": str(conversation_id),
                    "detail": exc.detail,
                },
            )
            _log_access(
                "transcript",
                actor=actor,
                outcome="integrity_failed",
                conversation_id=conversation_id,
            )
            raise HTTPException(
                status_code=500,
                detail={"reason": "conversation_transcript_integrity_failed"},
            ) from None
        if page is None:
            _log_access(
                "transcript",
                actor=actor,
                outcome="not_found",
                conversation_id=conversation_id,
            )
            raise HTTPException(status_code=404, detail=_NOT_FOUND)
        _log_access("transcript", actor=actor, outcome="ok", conversation_id=conversation_id)
        return TranscriptResponse(
            conversation=ConversationSummaryResponse(
                conversation_id=page.conversation.conversation_id,
                agent_id=page.conversation.agent_id,
                state=page.conversation.state,
                turn_count=page.conversation.turn_count,
                cumulative_tokens=page.conversation.cumulative_tokens,
                created_at=page.conversation.created_at,
                last_turn_at=page.conversation.last_turn_at,
            ),
            turns=[
                TranscriptTurnResponse(
                    turn_id=turn.turn_id,
                    seq=turn.seq,
                    user_message=turn.user_message,
                    answer=turn.answer,
                    agent_run_id=turn.agent_run_id,
                    prompt_tokens=turn.prompt_tokens,
                    completion_tokens=turn.completion_tokens,
                    created_at=turn.created_at,
                    erased_at=turn.erased_at,
                )
                for turn in page.turns
            ],
            watermark=page.watermark,
            next_cursor=page.next_cursor,
        )

    @router.get("/{conversation_id}/turns/{seq}/chain", response_model=TurnChainResponse)
    async def read_turn_chain(
        conversation_id: uuid.UUID,
        seq: int,
        actor: Annotated[Actor, Depends(_require_read)],
        reader: Annotated[ConversationReadModel, Depends(_require_read_model)],
    ) -> TurnChainResponse:
        try:
            join = await reader.read_turn_chain(
                conversation_id,
                seq,
                tenant_id=actor.tenant_id,
                creator_subject=actor.subject,
            )
        except TurnNotFound:
            # Owner-visible only: the ownership gate already collapsed
            # foreign conversations to the byte-identical 404 above.
            _log_access(
                "chain",
                actor=actor,
                outcome="turn_not_found",
                conversation_id=conversation_id,
                seq=seq,
            )
            raise HTTPException(status_code=404, detail={"reason": "turn_not_found"}) from None
        except ConversationTranscriptIntegrityError as exc:
            # A turn ROW missing inside 1..turn_count: the record claims the
            # turn exists, so this is transcript-store corruption — the same
            # generic 500 the transcript endpoint serves, internals LOG-ONLY.
            logger.error(
                "portal.conversations.transcript_integrity_failed",
                extra={
                    "tenant_id": actor.tenant_id,
                    "actor_subject": actor.subject,
                    "conversation_id": str(conversation_id),
                    "seq": seq,
                    "detail": exc.detail,
                },
            )
            _log_access(
                "chain",
                actor=actor,
                outcome="integrity_failed",
                conversation_id=conversation_id,
                seq=seq,
            )
            raise HTTPException(
                status_code=500,
                detail={"reason": "conversation_transcript_integrity_failed"},
            ) from None
        except ConversationChainIntegrityError as exc:
            logger.error(
                "portal.conversations.chain_integrity_failed",
                extra={
                    "tenant_id": actor.tenant_id,
                    "actor_subject": actor.subject,
                    "conversation_id": str(conversation_id),
                    "seq": seq,
                    "internal_reason": exc.internal_reason,
                    "detail": exc.detail,
                },
            )
            _log_access(
                "chain",
                actor=actor,
                outcome="integrity_failed",
                conversation_id=conversation_id,
                seq=seq,
            )
            raise HTTPException(
                status_code=500,
                detail={"reason": "conversation_chain_integrity_failed"},
            ) from None
        except ConversationChainProjectionLimit as exc:
            logger.error(
                "portal.conversations.chain_projection_limit",
                extra={
                    "tenant_id": actor.tenant_id,
                    "actor_subject": actor.subject,
                    "conversation_id": str(conversation_id),
                    "seq": seq,
                    "detail": exc.detail,
                },
            )
            _log_access(
                "chain",
                actor=actor,
                outcome="projection_limit",
                conversation_id=conversation_id,
                seq=seq,
            )
            raise HTTPException(
                status_code=503,
                detail={"reason": "conversation_chain_projection_limit"},
            ) from None
        if join is None:
            _log_access(
                "chain",
                actor=actor,
                outcome="not_found",
                conversation_id=conversation_id,
                seq=seq,
            )
            raise HTTPException(status_code=404, detail=_NOT_FOUND)
        _log_access("chain", actor=actor, outcome="ok", conversation_id=conversation_id, seq=seq)
        tc, st, tm = join.turn_completed, join.started, join.terminal
        return TurnChainResponse(
            turn_completed=TurnCompletedEvidenceResponse(
                sequence=tc.sequence,
                created_at=tc.created_at,
                turn_id=tc.turn_id,
                seq=tc.seq,
                agent_run_id=tc.agent_run_id,
                actor_id=tc.actor_id,
                question_sha256=tc.question_sha256,
                question_bytes=tc.question_bytes,
                answer_sha256=tc.answer_sha256,
                answer_bytes=tc.answer_bytes,
                prompt_tokens=tc.prompt_tokens,
                completion_tokens=tc.completion_tokens,
            ),
            started=RunStartedEvidenceResponse(
                sequence=st.sequence,
                created_at=st.created_at,
                run_id=st.run_id,
                agent_id=st.agent_id,
                actor_id=st.actor_id,
                originator_subject=st.originator_subject,
                question_sha256=st.question_sha256,
                question_bytes=st.question_bytes,
                max_steps=st.max_steps,
                token_budget=st.token_budget,
                wall_clock_s=st.wall_clock_s,
                prior_context_turns=st.prior_context_turns,
                prior_context_sha256=st.prior_context_sha256,
            ),
            terminal=RunTerminalEvidenceResponse(
                sequence=tm.sequence,
                created_at=tm.created_at,
                terminal_state=tm.terminal_state,
                answer_sha256=tm.answer_sha256,
                answer_bytes=tm.answer_bytes,
                steps_used=tm.steps_used,
                prompt_tokens_total=tm.prompt_tokens_total,
                completion_tokens_total=tm.completion_tokens_total,
                refusal_reason=tm.refusal_reason,
                bound=tm.bound,
                error_class=tm.error_class,
            ),
            dispatches=[
                DispatchEvidenceResponse(
                    sequence=d.sequence,
                    step_index=d.step_index,
                    capability_kind=d.capability_kind,
                    capability_ref=d.capability_ref,
                    scope_id=d.scope_id,
                    outcome=d.outcome,
                    refusal_reason=d.refusal_reason,
                    args_sha256=d.args_sha256,
                    result_sha256=d.result_sha256,
                    result_bytes=d.result_bytes,
                )
                for d in join.dispatches
            ],
        )

    return router
