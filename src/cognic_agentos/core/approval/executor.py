"""Auto-execute a finally granted action from digest-verified replay (CC).

Terminal outcome and delivery are separate governed facts.
``approval.executed`` is appended immediately after the external outcome and
before replay-result persistence or any conversation-output screening. Its
event name alone is not proof of
successful execution:
examiners must also require ``payload.execution == "executed"`` because the
established event carries replay and dispatch failure outcomes.

The subsequent delivery path either commits a screened system turn with
``conversation.system_turn_appended`` or observes a hook-screening refusal
and then appends ``approval.delivery_refused``. A later conversation
append/fencing refusal has no authorized delivery fact in F-S2a. These are
ordered awaited transactions, not one cross-store transaction: a crash or
evidence-store failure can leave a prefix of the sequence. The external
action can execute in the bank's system
and the subsequent ``approval.executed`` evidence append can still fail;
later delivery then does not run. A consumed retry never redispatches or
redelivers; when a stored result exists it appends a fresh
``approval.executed`` observation only. The tagged envelope necessarily
postdates the original evidence attempt, so this is a new observation rather
than a claim to repair a missing pre-storage row. Evidence insertion itself
is not idempotent. A distinct digest-only event for the late race in which
screening passes but the conversation append refuses is parked and is not
authorized in F-S2a.
"""

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
from cognic_agentos.core.conversation._types import ConversationTurnRefused
from cognic_agentos.core.decision_history import DecisionRecord

ExecutionOutcome = Literal[
    "executed",
    "already_executed",
    "replay_unavailable",
    "dispatch_failed",
]
_StoredExecutionOutcome = Literal["executed", "dispatch_failed"]
_REPLAY_RESULT_MARKER = "cognic.approval.replay-result.v1"

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
                return await self._consumed_replay_failure(
                    context=context, reason="stored_result_unavailable"
                )
            if previous is None:
                return await self._consumed_replay_failure(
                    context=context, reason="stored_result_unavailable"
                )
            try:
                stored_outcome, previous_result = _decode_stored_result(previous)
            except ApprovalReplayUnavailable:
                return await self._consumed_replay_failure(
                    context=context, reason="stored_result_unavailable"
                )
            replay_outcome: ExecutionOutcome = (
                "already_executed" if stored_outcome == "executed" else "dispatch_failed"
            )
            await self._append_execution_evidence(
                context=context,
                # The API outcome tells the caller whether this invocation
                # dispatched. Evidence tells the historical truth recovered
                # from the kernel-tagged stored result. In the crash gap where
                # result storage succeeded but the first evidence append did
                # not, the repair row must still say the action executed.
                outcome=stored_outcome,
                result_canonical=previous_result,
                delivery_request_id=None,
                delivery_input=None,
                replay_result_envelope=previous,
            )
            return replay_outcome
        except ApprovalReplayUnavailable as exc:
            return await self._replay_failure(context=context, reason=exc.reason)
        except Exception as exc:
            failure = canonical_bytes({"status": "failed", "error_type": type(exc).__name__})
            await self._post_and_chain(
                context=context,
                outcome="dispatch_failed",
                result_canonical=failure,
                text=f"Approved, but execution failed ({type(exc).__name__}).",
                stored_outcome="dispatch_failed",
                executed_at=now,
            )
            return "dispatch_failed"

        await self._post_and_chain(
            context=context,
            outcome="executed",
            result_canonical=result_canonical,
            text=f"Approved and executed. Result: {result_canonical.decode('utf-8')}",
            stored_outcome="executed",
            executed_at=now,
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
        text = f"Declined by {approver_subject} — {reason}."
        delivery_request_id = f"approval-denied-{uuid.uuid4().hex}"
        delivery_input = text.encode("utf-8")
        try:
            await self._completer.post_system_turn(
                conversation_id=context.conversation_id,
                tenant_id=tenant_id,
                text=text,
                approval_request_id=str(request_id),
                actor_id=_EXECUTOR_ACTOR,
                request_id=delivery_request_id,
            )
        except ConversationTurnRefused as exc:
            # The approval denial is already durable in the approval engine.
            # A screen may withhold its rendering, but must not turn that true
            # denial into a route-level 500 or create a retry invitation.
            if exc.reason == "conversation_hook_refused":
                await self._append_delivery_refusal(
                    context=context,
                    exc=exc,
                    delivery_request_id=delivery_request_id,
                    delivery_input=delivery_input,
                    approval_state="denied",
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

    async def _consumed_replay_failure(
        self, *, context: _ExecutionContext, reason: str
    ) -> ExecutionOutcome:
        """Evidence an ambiguous consumed replay without redispatch or redelivery."""

        failure = canonical_bytes({"status": "failed", "error_type": "approved_replay_unavailable"})
        await self._append_execution_evidence(
            context=context,
            outcome="replay_unavailable",
            result_canonical=failure,
            delivery_request_id=None,
            delivery_input=None,
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
        stored_outcome: _StoredExecutionOutcome | None = None,
        executed_at: datetime | None = None,
    ) -> None:
        """Record terminal-outcome truth before screening its rendering.

        The durable ordering is ``approval.executed`` before optional
        replay-result persistence and before any output-hook row, followed by
        a successful system-turn append or, on the hook-screening refusal
        path, ``approval.delivery_refused``. A later append/fencing refusal
        yields neither delivery fact in this slice. Each append has its own
        transaction; this method promises ordering and fail-loud propagation,
        not cross-step atomicity or crash-gap repair. The external action can
        execute before its evidence append fails. A distinct late-race
        delivery-withheld event is parked outside F-S2a.
        """

        if (stored_outcome is None) != (executed_at is None):
            raise ValueError("stored outcome and execution timestamp must be present together")

        delivery_request_id = f"approval-system-{uuid.uuid4().hex}"
        delivery_input = text.encode("utf-8")
        replay_result_envelope = (
            _encode_stored_result(
                outcome=stored_outcome,
                result_canonical=result_canonical,
            )
            if stored_outcome is not None
            else None
        )
        await self._append_execution_evidence(
            context=context,
            outcome=outcome,
            result_canonical=result_canonical,
            delivery_request_id=delivery_request_id,
            delivery_input=delivery_input,
            failure_reason=failure_reason,
            replay_result_envelope=replay_result_envelope,
        )
        if stored_outcome is not None and executed_at is not None:
            if replay_result_envelope is None:  # pragma: no cover - local invariant
                raise RuntimeError("stored outcome is missing its replay envelope")
            await self._replay.record_result(
                request_id=context.approval.request_id,
                tenant_id=context.tenant_id,
                result_canonical=replay_result_envelope,
                executed_at=executed_at,
            )
        try:
            await self._completer.post_system_turn(
                conversation_id=context.conversation_id,
                tenant_id=context.tenant_id,
                text=text,
                approval_request_id=str(context.approval.request_id),
                actor_id=_EXECUTOR_ACTOR,
                request_id=delivery_request_id,
            )
        except ConversationTurnRefused as exc:
            if exc.reason == "conversation_hook_refused":
                await self._append_delivery_refusal(
                    context=context,
                    exc=exc,
                    delivery_request_id=delivery_request_id,
                    delivery_input=delivery_input,
                    approval_state="granted",
                    outcome=outcome,
                    result_canonical=result_canonical,
                )
            # The governed action outcome is already durable and evidenced.
            # A hook-screening refusal is a second, separately chained fact;
            # it must not turn the mounted final-grant route into a 500 or
            # invite a caller to retry an action that already ran. A distinct
            # fact for a later conversation append/fencing race remains
            # parked and is not synthesized under the hook-refusal vocabulary.
            return

    async def _append_delivery_refusal(
        self,
        *,
        context: _ExecutionContext,
        exc: ConversationTurnRefused,
        delivery_request_id: str,
        delivery_input: bytes,
        approval_state: Literal["granted", "denied"],
        outcome: ExecutionOutcome | None = None,
        result_canonical: bytes | None = None,
    ) -> None:
        """Append the digest-only fact that an approval rendering was withheld."""

        if (outcome is None) != (result_canonical is None):
            raise ValueError("execution outcome and result must be present together")
        if approval_state == "granted" and outcome is None:
            raise ValueError("granted delivery refusal requires an execution outcome")
        if approval_state == "denied" and outcome is not None:
            raise ValueError("denied delivery refusal cannot carry an execution outcome")

        if (
            exc.conversation_output_request_id is not None
            and exc.conversation_output_value_sha256 is None
        ):
            raise ValueError(
                "correlated delivery refusal is missing the final screened-value digest"
            )
        delivery_output_sha256 = exc.conversation_output_value_sha256
        delivery_output_bytes = exc.conversation_output_value_bytes
        if delivery_output_sha256 is None or delivery_output_bytes is None:
            delivery_output_sha256 = hashlib.sha256(delivery_input).hexdigest()
            delivery_output_bytes = len(delivery_input)
        refusal_payload: dict[str, Any] = {
            "approval_request_id": str(context.approval.request_id),
            "approval_state": approval_state,
            "conversation_id": str(context.conversation_id),
            "delivery_request_id": delivery_request_id,
            "delivery_input_sha256": hashlib.sha256(delivery_input).hexdigest(),
            "delivery_input_bytes": len(delivery_input),
            "delivery_output_sha256": delivery_output_sha256,
            "delivery_output_bytes": delivery_output_bytes,
            "refusal_reason": exc.reason,
            "conversation_output_request_id": exc.conversation_output_request_id,
            "conversation_output_hook_count": exc.conversation_output_hook_count,
        }
        if outcome is not None and result_canonical is not None:
            refusal_payload.update(
                {
                    "action_id": context.action_id,
                    "args_sha256": context.approval.args_digest.hex(),
                    "result_sha256": hashlib.sha256(result_canonical).hexdigest(),
                    "result_bytes": len(result_canonical),
                    "execution": outcome,
                }
            )
        await self._history.append(
            DecisionRecord(
                decision_type="approval.delivery_refused",
                request_id=delivery_request_id,
                payload=refusal_payload,
                actor_id=_EXECUTOR_ACTOR,
                tenant_id=context.tenant_id,
                iso_controls=(
                    "ISO42001.A.6.2.5",
                    "ISO42001.A.7.4",
                    "ISO42001.A.10.2",
                ),
            )
        )

    async def _append_execution_evidence(
        self,
        *,
        context: _ExecutionContext,
        outcome: ExecutionOutcome,
        result_canonical: bytes,
        delivery_request_id: str | None,
        delivery_input: bytes | None,
        failure_reason: str | None = None,
        replay_result_envelope: bytes | None = None,
    ) -> None:
        """Append one truthful execution observation before any delivery attempt."""

        payload: dict[str, Any] = {
            "approval_request_id": str(context.approval.request_id),
            "action_id": context.action_id,
            "args_sha256": context.approval.args_digest.hex(),
            "result_sha256": hashlib.sha256(result_canonical).hexdigest(),
            "result_bytes": len(result_canonical),
            "replay_result_sha256": (
                hashlib.sha256(replay_result_envelope).hexdigest()
                if replay_result_envelope is not None
                else None
            ),
            "replay_result_bytes": (
                len(replay_result_envelope) if replay_result_envelope is not None else 0
            ),
            "conversation_id": str(context.conversation_id),
            "delivery_request_id": delivery_request_id,
            "delivery_input_sha256": (
                hashlib.sha256(delivery_input).hexdigest() if delivery_input is not None else None
            ),
            "delivery_input_bytes": len(delivery_input) if delivery_input is not None else 0,
            # R23: terminal-outcome evidence is durable before delivery
            # screening, so no
            # system-turn row truthfully exists at this point. Retain the
            # established key for tolerant consumers but never pre-mint a
            # fictional row identifier.
            "system_turn_id": None,
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


def _encode_stored_result(
    *,
    outcome: _StoredExecutionOutcome,
    result_canonical: bytes,
) -> bytes:
    """Wrap a result with its kernel-owned replay outcome, without a migration.

    The wrapper is an array because every legacy stored execution result is a
    JSON object.  That structural separation prevents a tool-controlled object
    from colliding with the kernel-owned discriminator.
    """

    try:
        result = json.loads(result_canonical)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ApprovalReplayUnavailable("replay_digest_mismatch") from exc
    if not isinstance(result, dict):
        raise ApprovalReplayUnavailable("replay_digest_mismatch")
    return canonical_bytes([_REPLAY_RESULT_MARKER, outcome, result])


def _decode_stored_result(value: bytes) -> tuple[_StoredExecutionOutcome, bytes]:
    """Recover only unambiguous tagged results.

    Pre-F-S2a rows stored a bare JSON object for both successful and failed
    dispatches.  Their execution outcome therefore cannot be reconstructed
    safely.  A consumed retry for one of those rows fails closed as replay
    unavailable instead of inventing successful execution evidence.
    """

    try:
        decoded = json.loads(value)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ApprovalReplayUnavailable("replay_digest_mismatch") from exc
    if not isinstance(decoded, list) or len(decoded) != 3:
        raise ApprovalReplayUnavailable("replay_digest_mismatch")
    marker, outcome, result = decoded
    if marker != _REPLAY_RESULT_MARKER:
        raise ApprovalReplayUnavailable("replay_digest_mismatch")
    if outcome not in {"executed", "dispatch_failed"} or not isinstance(result, dict):
        raise ApprovalReplayUnavailable("replay_digest_mismatch")
    return outcome, canonical_bytes(result)


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
