"""Auto-execute a finally granted action from digest-verified replay (CC)."""

from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol

from cognic_agentos.core.agent.action_context import (
    _ISSUER,
    ACTION_CONTEXT_ARGUMENT,
    ActionContextClaims,
    derive_idempotency_key,
    mint_action_context,
)
from cognic_agentos.core.approval._types import (
    ApprovalCheckResult,
    ApprovalTransitionRefused,
)
from cognic_agentos.core.approval.replay import ApprovalReplayUnavailable
from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.decision_history import DecisionRecord

ExecutionOutcome = Literal[
    "executed",
    "already_executed",
    "replay_unavailable",
    "dispatch_failed",
]

_EXECUTOR_ACTOR = "system:approval-executor"


class _EngineLike(Protocol):
    async def check(self, *, request_id: uuid.UUID, tenant_id: str) -> ApprovalCheckResult: ...

    async def list_granted_unconsumed_before(
        self, *, cutoff: datetime
    ) -> tuple[tuple[uuid.UUID, str], ...]: ...


class _ReplayStoreLike(Protocol):
    async def load(self, *, request_id: uuid.UUID, tenant_id: str) -> bytes: ...

    async def load_result(self, *, request_id: uuid.UUID, tenant_id: str) -> bytes | None: ...

    async def record_result(
        self,
        *,
        request_id: uuid.UUID,
        tenant_id: str,
        result_canonical: bytes,
        executed_at: datetime,
    ) -> None: ...


class _ToolProxyLike(Protocol):
    async def execute_consumed_action(
        self,
        *,
        server_id: str,
        tool_name: str,
        request_id: str,
        tenant_id: str,
        originator_subject: str,
        approval_request_id: uuid.UUID,
        prepare_arguments: Callable[[ApprovalCheckResult], Awaitable[Mapping[str, Any]]],
    ) -> Any: ...


class _ConversationCompleterLike(Protocol):
    async def resolve_approval_context(
        self,
        *,
        approval_request_id: uuid.UUID,
        tenant_id: str,
    ) -> tuple[uuid.UUID, str] | None: ...

    async def post_system_turn(
        self,
        *,
        conversation_id: uuid.UUID,
        tenant_id: str,
        text: str,
        approval_request_id: str,
        actor_id: str,
        request_id: str,
    ) -> uuid.UUID: ...


class _SettingsLike(Protocol):
    action_context_ttl_s: float
    approval_executor_grace_s: float


class _DecisionHistoryLike(Protocol):
    async def append(self, record: DecisionRecord) -> Any: ...


@dataclass(frozen=True, slots=True)
class _ExecutionContext:
    approval: ApprovalCheckResult
    tenant_id: str
    conversation_id: uuid.UUID
    agent_id: str
    server_id: str
    tool_name: str

    @property
    def action_id(self) -> str:
        return f"{self.server_id}/{self.tool_name}"


class ApprovalExecutionService:
    """Consume, replay and evidence an approved action without another model turn."""

    def __init__(
        self,
        *,
        engine: _EngineLike,
        replay_store: _ReplayStoreLike,
        tool_proxy: _ToolProxyLike,
        conversation_completer: _ConversationCompleterLike,
        decision_history: _DecisionHistoryLike,
        signing_key: bytes,
        settings: _SettingsLike,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._engine = engine
        self._replay = replay_store
        self._tool_proxy = tool_proxy
        self._completer = conversation_completer
        self._history = decision_history
        self._signing_key = signing_key
        self._settings = settings
        self._clock = clock

    async def supports_request(self, *, request_id: uuid.UUID, tenant_id: str) -> bool:
        """Whether this approval is correlated to a governed chat turn."""

        return (
            await self._completer.resolve_approval_context(
                approval_request_id=request_id,
                tenant_id=tenant_id,
            )
            is not None
        )

    async def execute_granted(self, *, request_id: uuid.UUID, tenant_id: str) -> ExecutionOutcome:
        """Execute one final grant from stored bytes through the MCP host lane."""

        context = await self._resolve_context(request_id=request_id, tenant_id=tenant_id)
        if context is None:
            return "replay_unavailable"
        now = self._clock()

        async def _prepare(consumed: ApprovalCheckResult) -> Mapping[str, Any]:
            canonical_args = await self._replay.load(
                request_id=request_id,
                tenant_id=tenant_id,
            )
            if hashlib.sha256(canonical_args).digest() != consumed.args_digest:
                raise ApprovalReplayUnavailable("replay_digest_mismatch")
            arguments = _decode_arguments(canonical_args)
            if ACTION_CONTEXT_ARGUMENT in arguments:
                raise ApprovalReplayUnavailable("replay_digest_mismatch")
            issued_at = int(now.timestamp())
            args_sha256 = consumed.args_digest.hex()
            arguments[ACTION_CONTEXT_ARGUMENT] = mint_action_context(
                claims=ActionContextClaims(
                    iss=_ISSUER,
                    aud=context.action_id,
                    sub=consumed.originator_subject,
                    act=context.agent_id,
                    tenant_id=tenant_id,
                    action_id=context.action_id,
                    args_sha256=args_sha256,
                    approval_request_id=str(request_id),
                    idempotency_key=derive_idempotency_key(
                        approval_request_id=str(request_id),
                        args_sha256=args_sha256,
                    ),
                    jti=secrets.token_hex(16),
                    iat=issued_at,
                    exp=issued_at + int(self._settings.action_context_ttl_s),
                ),
                signing_key_pem=self._signing_key,
            )
            return arguments

        try:
            call_result = await self._tool_proxy.execute_consumed_action(
                server_id=context.server_id,
                tool_name=context.tool_name,
                request_id=f"approval-exec-{uuid.uuid4().hex}",
                tenant_id=tenant_id,
                originator_subject=context.approval.originator_subject,
                approval_request_id=request_id,
                prepare_arguments=_prepare,
            )
            result_canonical = canonical_bytes(_project_result(call_result))
        except ApprovalTransitionRefused as exc:
            if exc.reason != "approval_consumed":
                return await self._replay_failure(context=context, reason=exc.reason)
            try:
                previous = await self._replay.load_result(
                    request_id=request_id,
                    tenant_id=tenant_id,
                )
            except ApprovalReplayUnavailable:
                return await self._replay_failure(
                    context=context, reason="stored_result_unavailable"
                )
            if previous is None:
                return await self._replay_failure(
                    context=context, reason="stored_result_unavailable"
                )
            return "already_executed"
        except ApprovalReplayUnavailable as exc:
            return await self._replay_failure(context=context, reason=exc.reason)
        except Exception as exc:
            failure = canonical_bytes({"status": "failed", "error_type": type(exc).__name__})
            await self._replay.record_result(
                request_id=request_id,
                tenant_id=tenant_id,
                result_canonical=failure,
                executed_at=now,
            )
            await self._post_and_chain(
                context=context,
                outcome="dispatch_failed",
                result_canonical=failure,
                text=f"Approved, but execution failed ({type(exc).__name__}).",
            )
            return "dispatch_failed"

        await self._replay.record_result(
            request_id=request_id,
            tenant_id=tenant_id,
            result_canonical=result_canonical,
            executed_at=now,
        )
        await self._post_and_chain(
            context=context,
            outcome="executed",
            result_canonical=result_canonical,
            text=f"Approved and executed. Result: {result_canonical.decode('utf-8')}",
        )
        return "executed"

    async def post_denied(
        self,
        *,
        request_id: uuid.UUID,
        tenant_id: str,
        approver_subject: str,
        reason: str,
    ) -> bool:
        context = await self._resolve_context(request_id=request_id, tenant_id=tenant_id)
        if context is None:
            return False
        await self._completer.post_system_turn(
            conversation_id=context.conversation_id,
            tenant_id=tenant_id,
            text=f"Declined by {approver_subject} — {reason}.",
            approval_request_id=str(request_id),
            actor_id=_EXECUTOR_ACTOR,
            request_id=f"approval-denied-{uuid.uuid4().hex}",
        )
        return True

    async def sweep_granted_unconsumed(
        self, grace_s: float | None = None
    ) -> tuple[tuple[uuid.UUID, ExecutionOutcome], ...]:
        """Re-drive old, unconsumed conversation approvals at startup."""

        grace = self._settings.approval_executor_grace_s if grace_s is None else grace_s
        candidates = await self._engine.list_granted_unconsumed_before(
            cutoff=self._clock() - timedelta(seconds=grace)
        )
        outcomes: list[tuple[uuid.UUID, ExecutionOutcome]] = []
        for request_id, tenant_id in candidates:
            if not await self.supports_request(request_id=request_id, tenant_id=tenant_id):
                continue
            outcome = await self.execute_granted(request_id=request_id, tenant_id=tenant_id)
            outcomes.append((request_id, outcome))
        return tuple(outcomes)

    async def _resolve_context(
        self, *, request_id: uuid.UUID, tenant_id: str
    ) -> _ExecutionContext | None:
        approval = await self._engine.check(request_id=request_id, tenant_id=tenant_id)
        correlation = await self._completer.resolve_approval_context(
            approval_request_id=request_id,
            tenant_id=tenant_id,
        )
        if correlation is None:
            return None
        server_id = approval.required_refs.get("mcp_server_id")
        tool_name = approval.required_refs.get("mcp_tool_name")
        if not server_id or not tool_name:
            return None
        return _ExecutionContext(
            approval=approval,
            tenant_id=tenant_id,
            conversation_id=correlation[0],
            agent_id=correlation[1],
            server_id=server_id,
            tool_name=tool_name,
        )

    async def _replay_failure(self, *, context: _ExecutionContext, reason: str) -> ExecutionOutcome:
        failure = canonical_bytes({"status": "failed", "error_type": "approved_replay_unavailable"})
        await self._post_and_chain(
            context=context,
            outcome="replay_unavailable",
            result_canonical=failure,
            text=(
                "Approved, but execution could not proceed because the approved "
                "payload is unavailable."
            ),
            failure_reason=reason,
        )
        return "replay_unavailable"

    async def _post_and_chain(
        self,
        *,
        context: _ExecutionContext,
        outcome: ExecutionOutcome,
        result_canonical: bytes,
        text: str,
        failure_reason: str | None = None,
    ) -> None:
        turn_id = await self._completer.post_system_turn(
            conversation_id=context.conversation_id,
            tenant_id=context.tenant_id,
            text=text,
            approval_request_id=str(context.approval.request_id),
            actor_id=_EXECUTOR_ACTOR,
            request_id=f"approval-system-{uuid.uuid4().hex}",
        )
        payload: dict[str, Any] = {
            "approval_request_id": str(context.approval.request_id),
            "action_id": context.action_id,
            "args_sha256": context.approval.args_digest.hex(),
            "result_sha256": hashlib.sha256(result_canonical).hexdigest(),
            "system_turn_id": str(turn_id),
            "execution": outcome,
        }
        if failure_reason is not None:
            payload["failure_reason"] = failure_reason
        await self._history.append(
            DecisionRecord(
                decision_type="approval.executed",
                request_id=f"approval-executed-{uuid.uuid4().hex}",
                payload=payload,
                actor_id=context.approval.originator_subject,
                tenant_id=context.tenant_id,
                iso_controls=("ISO42001.A.6.2.5", "ISO42001.A.7.4", "ISO42001.A.10.2"),
            )
        )


def _decode_arguments(value: bytes) -> dict[str, Any]:
    try:
        decoded = json.loads(value)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ApprovalReplayUnavailable("replay_digest_mismatch") from exc
    if not isinstance(decoded, dict):
        raise ApprovalReplayUnavailable("replay_digest_mismatch")
    return decoded


def _project_result(call_result: Any) -> dict[str, Any]:
    payload = getattr(call_result, "payload", call_result)
    if getattr(payload, "isError", False) or getattr(payload, "is_error", False):
        raise RuntimeError("MCP action result carries isError=true")
    if hasattr(payload, "model_dump"):
        payload = payload.model_dump(mode="json")
    if isinstance(payload, dict):
        if payload.get("isError") is True or payload.get("is_error") is True:
            raise RuntimeError("MCP action result carries isError=true")
        structured = payload.get("structuredContent")
        if isinstance(structured, dict):
            return structured
        return payload
    raise TypeError("MCP action result is not a JSON object")


__all__ = ("ApprovalExecutionService", "ExecutionOutcome")
