"""ADR-028 M8.5-B — the governed conversation turn loop.

CRITICAL CONTROLS. Owns the terminal-state refusal contract: posting a turn to a
``closed`` / ``expired`` / ``erased`` conversation refuses with
``conversation_not_active`` and NEVER invokes the AgentLoop. The refusal fires at
the lifecycle gate, before context assembly and before any model/gateway
activity.

Flow (ADR-028 §4)::

    claim (atomic, single-writer, CREATOR-SCOPED)
      -> bounds (max_turns, cumulative token budget)
      -> context assembly (bounded replay, kernel store ONLY -- invariant I-1)
      -> conversation_input hook chain (fail closed; PASS/REFUSE only in F-S2a)
      -> AgentLoop.ask(prior_context=...)   [the M8 dispatch chokepoint re-checks
                                             the CURRENT envelope -- invariant I-2]
      -> conversation_output hook chain (fail closed; PASS/REFUSE only in F-S2a;
                                          completed run evidence stands)
      -> persist turn + digests, bump counters, append conversation.turn_completed
      -> release claim (finally-guarded)

**Creator scoping lives in the claim.** ``ConversationStore.append_turn`` and
``.transition`` take ``tenant_id`` but NOT ``creator_subject``; the only
creator-bound step is ``claim_turn``, which therefore MUST precede them. The
ordering is pinned by ``tests/unit/core/conversation/test_turn.py`` with a
call-recording store, not left to call-site discipline.

**The envelope is never cached across turns.** This module holds no entitlement
state at all: it hands the actor's identity to the loop, and the M8 dispatcher
re-resolves assignment -> entitlement -> policy on every dispatch of every turn.
That absence IS the I-2 enforcement, and BAR 3 pins it.
"""

from __future__ import annotations

import hashlib
import json
import math
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final, Literal, Protocol

from cognic_agentos.core.agent._types import (
    AgentDispatchRefusalReason,
    AgentRunTerminalState,
    PriorTurn,
)
from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.conversation._context import assemble_prior_context
from cognic_agentos.core.conversation._types import (
    ConversationRecord,
    ConversationState,
    ConversationTurnRefused,
    TurnClaim,
    TurnRecord,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from cognic_agentos.core.agent._types import AgentAskResult

_TURN_REQUEST_ID_PREFIX: Final[str] = "conv-turn-"
_HOOK_REQUEST_ID_PREFIX: Final[str] = "conv-hook-"
_CONVERSATION_HOOK_SCHEMA_VERSION: Final[int] = 1

ConversationHookPhase = Literal["conversation_input", "conversation_output"]
ConversationHookOutcome = Literal["passed", "refused", "failed"]
ConversationOutputOrigin = Literal["agent_run", "approval_delivery"]


@dataclass(frozen=True, slots=True)
class ConversationHookGovernance:
    """Immutable signed-manifest projection used by both conversation phases.

    The kernel does not interpret these values. It only validates the generic
    shape and binds them into the canonical hook invocation. The harness
    projects the values from the already-admitted agent pack.
    """

    pack_id: str
    declared_data_classes: tuple[str, ...]
    manifest_purpose: str

    def __post_init__(self) -> None:
        if not self.pack_id:
            raise ValueError("pack_id must be non-empty")
        if not self.manifest_purpose:
            raise ValueError("manifest_purpose must be non-empty")
        if (
            not self.declared_data_classes
            or any(not isinstance(value, str) or not value for value in self.declared_data_classes)
            or tuple(sorted(set(self.declared_data_classes))) != self.declared_data_classes
        ):
            raise ValueError("declared_data_classes must be sorted, unique non-empty strings")


@dataclass(frozen=True, slots=True)
class ConversationHookScanResult:
    """Layer-neutral projection of one shared-dispatcher phase result."""

    outcome: ConversationHookOutcome
    final_payload: bytes
    hook_decision_count: int = 0


class ConversationHookEvidenceError(RuntimeError):
    """A fail-loud sink error after a prefix of hook rows committed.

    The adapter translates the dispatcher-owned exception into this
    core-owned seam type without swallowing it. Payload bytes remain only in
    memory and never enter the exception message or repr.
    """

    def __init__(self, *, final_payload: bytes, hook_decision_count: int) -> None:
        super().__init__("conversation hook evidence emission failed")
        self.final_payload = final_payload
        self.hook_decision_count = hook_decision_count


class ConversationHookGuard(Protocol):
    """Narrow hook-runtime seam consumed by the conversation critical control."""

    def governance_for_agent(self, *, agent_id: str) -> ConversationHookGovernance: ...

    def turn_timeout_budget_s(self) -> float: ...

    async def scan(
        self,
        *,
        phase: ConversationHookPhase,
        payload: bytes,
        governance: ConversationHookGovernance,
        tenant_id: str,
        request_id: str,
        conversation_id: uuid.UUID,
        turn_seq: int,
        agent_run_id: str | None,
        output_origin: ConversationOutputOrigin | None,
        approval_delivery_id: str | None,
        validate_transformed_payload: Callable[[bytes], None],
        evidence_value_projector: Callable[[bytes], bytes] | None = None,
        evidence_input_value: bytes | None = None,
    ) -> ConversationHookScanResult: ...


def _reject_duplicate_properties(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """JSON object hook that refuses duplicates before a mapping is created."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON property")
        result[key] = value
    return result


def _reject_nonstandard_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def _decode_canonical_hook_payload(payload: bytes) -> dict[str, Any]:
    """Decode one hook-returned payload without last-wins or alternate encodings."""
    try:
        text = payload.decode("utf-8")
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_properties,
            parse_constant=_reject_nonstandard_constant,
        )
        if not isinstance(parsed, dict) or canonical_bytes(parsed) != payload:
            raise ValueError("hook payload is not a canonical JSON object")
        return parsed
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ValueError("conversation hook returned a malformed payload") from exc


def _common_hook_envelope(
    *,
    phase: ConversationHookPhase,
    conversation_id: uuid.UUID,
    tenant_id: str,
    turn_seq: int,
    governance: ConversationHookGovernance,
) -> dict[str, Any]:
    return {
        "schema_version": _CONVERSATION_HOOK_SCHEMA_VERSION,
        "phase": phase,
        "tenant_id": tenant_id,
        "conversation_id": str(conversation_id),
        "turn_seq": turn_seq,
        "declared_data_classes": list(governance.declared_data_classes),
    }


def _validate_common_hook_envelope(
    value: dict[str, Any],
    *,
    phase: ConversationHookPhase,
    conversation_id: uuid.UUID,
    tenant_id: str,
    turn_seq: int,
    governance: ConversationHookGovernance,
) -> None:
    for key in ("schema_version", "turn_seq"):
        integer = value.get(key)
        if isinstance(integer, bool) or not isinstance(integer, int):
            raise ValueError("hook payload used a non-integer governance counter")
    expected = _common_hook_envelope(
        phase=phase,
        conversation_id=conversation_id,
        tenant_id=tenant_id,
        turn_seq=turn_seq,
        governance=governance,
    )
    for key, expected_value in expected.items():
        if value.get(key) != expected_value:
            raise ValueError("hook payload changed immutable governance context")


def _input_hook_payload(
    *,
    conversation_id: uuid.UUID,
    tenant_id: str,
    turn_seq: int,
    governance: ConversationHookGovernance,
    prior_context: tuple[PriorTurn, ...],
    user_message: str,
) -> bytes:
    value = _common_hook_envelope(
        phase="conversation_input",
        conversation_id=conversation_id,
        tenant_id=tenant_id,
        turn_seq=turn_seq,
        governance=governance,
    )
    value["messages"] = [
        *[{"role": turn.role, "content": turn.content} for turn in prior_context],
        {"role": "user", "content": user_message},
    ]
    return canonical_bytes(value)


def _validated_input_hook_result(
    payload: bytes,
    *,
    conversation_id: uuid.UUID,
    tenant_id: str,
    turn_seq: int,
    governance: ConversationHookGovernance,
    prior_context: tuple[PriorTurn, ...],
) -> tuple[tuple[PriorTurn, ...], str]:
    value = _decode_canonical_hook_payload(payload)
    if set(value) != {
        "schema_version",
        "phase",
        "tenant_id",
        "conversation_id",
        "turn_seq",
        "declared_data_classes",
        "messages",
    }:
        raise ValueError("conversation input hook payload has an unexpected shape")
    _validate_common_hook_envelope(
        value,
        phase="conversation_input",
        conversation_id=conversation_id,
        tenant_id=tenant_id,
        turn_seq=turn_seq,
        governance=governance,
    )
    messages = value["messages"]
    expected_roles = [turn.role for turn in prior_context] + ["user"]
    if not isinstance(messages, list) or len(messages) != len(expected_roles):
        raise ValueError("conversation input hook changed message cardinality")
    contents: list[str] = []
    for message, expected_role in zip(messages, expected_roles, strict=True):
        if (
            not isinstance(message, dict)
            or set(message) != {"role", "content"}
            or message.get("role") != expected_role
            or not isinstance(message.get("content"), str)
        ):
            raise ValueError("conversation input hook changed message structure")
        contents.append(message["content"])
    transformed_prior = tuple(
        PriorTurn(role=turn.role, content=content)
        for turn, content in zip(prior_context, contents[:-1], strict=True)
    )
    return transformed_prior, contents[-1]


def _output_hook_payload(
    *,
    conversation_id: uuid.UUID,
    tenant_id: str,
    turn_seq: int,
    governance: ConversationHookGovernance,
    answer: str,
) -> bytes:
    value = _common_hook_envelope(
        phase="conversation_output",
        conversation_id=conversation_id,
        tenant_id=tenant_id,
        turn_seq=turn_seq,
        governance=governance,
    )
    value["answer"] = answer
    return canonical_bytes(value)


def _validated_output_hook_result(
    payload: bytes,
    *,
    conversation_id: uuid.UUID,
    tenant_id: str,
    turn_seq: int,
    governance: ConversationHookGovernance,
) -> str:
    value = _decode_canonical_hook_payload(payload)
    if set(value) != {
        "schema_version",
        "phase",
        "tenant_id",
        "conversation_id",
        "turn_seq",
        "declared_data_classes",
        "answer",
    }:
        raise ValueError("conversation output hook payload has an unexpected shape")
    _validate_common_hook_envelope(
        value,
        phase="conversation_output",
        conversation_id=conversation_id,
        tenant_id=tenant_id,
        turn_seq=turn_seq,
        governance=governance,
    )
    answer = value["answer"]
    if not isinstance(answer, str):
        raise ValueError("conversation output hook answer must be a string")
    return answer


class _StoreLike(Protocol):
    """The narrow ``ConversationStore`` surface this executor consumes.

    Signatures are EXACT, not ``**kwargs: Any``: a loose Protocol would
    structurally accept a store whose ``claim_turn`` omitted
    ``creator_subject``, silently dropping the creator boundary.
    """

    async def claim_turn(
        self,
        conversation_id: uuid.UUID,
        *,
        tenant_id: str,
        creator_subject: str,
        now: datetime,
        claim_ttl_s: float,
    ) -> TurnClaim: ...

    async def load(
        self,
        conversation_id: uuid.UUID,
        *,
        tenant_id: str,
        creator_subject: str,
    ) -> ConversationRecord | None: ...

    async def load_replay_turns(
        self, conversation_id: uuid.UUID, *, tenant_id: str, last_n: int
    ) -> list[TurnRecord]: ...

    async def resolve_approval_context(
        self,
        *,
        approval_request_id: uuid.UUID,
        tenant_id: str,
    ) -> tuple[uuid.UUID, str] | None: ...

    async def claim_system_turn(
        self,
        conversation_id: uuid.UUID,
        *,
        tenant_id: str,
        now: datetime,
        claim_ttl_s: float,
    ) -> TurnClaim: ...

    async def next_turn_seq(
        self,
        conversation_id: uuid.UUID,
        *,
        tenant_id: str,
        claim_id: uuid.UUID,
    ) -> int: ...

    async def append_turn(
        self,
        *,
        conversation_id: uuid.UUID,
        tenant_id: str,
        seq: int,
        user_message: str,
        answer: str,
        agent_run_id: str,
        prompt_tokens: int,
        completion_tokens: int,
        actor_id: str,
        request_id: str,
        claim_id: uuid.UUID,
        approval_request_id: str | None = None,
        turn_kind: Literal["exchange", "system"] = "exchange",
        conversation_output_request_id: str | None = None,
        conversation_output_hook_count: int = 0,
    ) -> uuid.UUID: ...

    async def settle_refused_turn(
        self,
        *,
        conversation_id: uuid.UUID,
        tenant_id: str,
        seq: int,
        question: str,
        answer: str,
        agent_run_id: str,
        prompt_tokens: int,
        completion_tokens: int,
        actor_id: str,
        request_id: str,
        claim_id: uuid.UUID,
        conversation_output_request_id: str | None = None,
        conversation_output_hook_count: int = 0,
    ) -> ConversationState: ...

    async def append_system_turn(
        self,
        *,
        conversation_id: uuid.UUID,
        tenant_id: str,
        text: str,
        approval_request_id: str,
        actor_id: str,
        request_id: str,
        claim_id: uuid.UUID,
        conversation_output_request_id: str | None = None,
        conversation_output_hook_count: int = 0,
    ) -> uuid.UUID: ...

    async def release_claim(
        self, conversation_id: uuid.UUID, *, tenant_id: str, claim_id: uuid.UUID
    ) -> None: ...


class _LoopLike(Protocol):
    """The narrow ``AgentLoop`` surface. Exact signature for the same reason."""

    async def ask(
        self,
        *,
        agent_id: str,
        question: str,
        actor_tenant_id: str,
        actor_subject: str,
        prior_context: tuple[PriorTurn, ...] = (),
    ) -> AgentAskResult: ...


@dataclass(frozen=True, slots=True)
class TurnResult:
    """Terminal result of one governed conversation turn.

    ``turn_id`` is the id the store minted and inserted -- never a fresh uuid.
    """

    turn_id: uuid.UUID
    seq: int
    answer: str
    agent_run_id: str
    terminal_state: AgentRunTerminalState
    refusal_reason: AgentDispatchRefusalReason | None
    approval_request_id: str | None = None


class ConversationTurnExecutor:
    """Wraps the M8 ``AgentLoop`` with the ADR-028 conversation turn contract.

    The claim-TTL constructor check provides configuration headroom over the
    declared AgentLoop wall-clock setting plus admitted hook invocation
    timeouts. It is not an end-to-end deadline and does not guarantee that a
    claim cannot be reclaimed: hook loading, cancellation delay, evidence
    writes, gateway execution, and persistence are not hard-bounded here.
    The claim-id fence on the final append remains the stale-writer authority.
    Heartbeat/deadline enforcement is separate follow-up work under R20.
    """

    def __init__(
        self,
        *,
        store: _StoreLike,
        loop: _LoopLike,
        hook_guard: ConversationHookGuard,
        max_turns: int,
        cumulative_token_budget: int,
        replay_last_n: int,
        replay_token_ceiling: int,
        claim_ttl_s: float,
        agent_run_wall_clock_s: float,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        hook_timeout_budget_s = hook_guard.turn_timeout_budget_s()
        if (
            isinstance(hook_timeout_budget_s, bool)
            or not isinstance(hook_timeout_budget_s, (int, float))
            or not math.isfinite(hook_timeout_budget_s)
            or hook_timeout_budget_s < 0
        ):
            raise ValueError("hook phase timeout budget must be finite and non-negative")
        if claim_ttl_s <= agent_run_wall_clock_s + hook_timeout_budget_s:
            raise ValueError(
                "claim_ttl_s must exceed agent_run_wall_clock_s plus the hook phase "
                "timeout budget as configuration headroom"
            )
        self._store = store
        self._loop = loop
        self._hook_guard = hook_guard
        self._max_turns = max_turns
        self._cumulative_token_budget = cumulative_token_budget
        self._replay_last_n = replay_last_n
        self._replay_token_ceiling = replay_token_ceiling
        self._claim_ttl_s = claim_ttl_s
        self._clock = clock

    async def post_turn(
        self,
        *,
        conversation_id: uuid.UUID,
        tenant_id: str,
        actor_subject: str,
        user_message: str,
    ) -> TurnResult:
        """Run one governed conversation turn.

        Raises:
            ConversationNotFound: absent / cross-tenant / cross-actor. The route
                collapses it to a 404 byte-identical to a genuine not-found.
            ConversationTurnRefused: a closed-enum governed refusal. Lifecycle,
                bounds, and input-hook refusals precede the AgentLoop; output-hook
                and persistence-fence refusals occur after the run.
        """
        now = self._clock()

        # 1. Atomic, CREATOR-SCOPED claim. Raises ConversationNotFound or
        #    ConversationTurnRefused (conversation_not_active /
        #    conversation_turn_in_progress) BEFORE any context assembly, any
        #    model call, or any gateway activity.
        claim = await self._store.claim_turn(
            conversation_id,
            tenant_id=tenant_id,
            creator_subject=actor_subject,
            now=now,
            claim_ttl_s=self._claim_ttl_s,
        )
        record = claim.record
        try:
            # 2. Conversation-level bounds. Still no loop invocation.
            if record.turn_count >= self._max_turns:
                raise ConversationTurnRefused(
                    "conversation_max_turns_exceeded", current_state=record.state
                )
            if record.cumulative_tokens >= self._cumulative_token_budget:
                raise ConversationTurnRefused(
                    "conversation_token_budget_exceeded", current_state=record.state
                )

            # 3. Context assembly -- the kernel store ONLY (invariant I-1).
            turns = await self._store.load_replay_turns(
                conversation_id, tenant_id=tenant_id, last_n=self._replay_last_n
            )
            prior_context = assemble_prior_context(
                turns,
                replay_last_n=self._replay_last_n,
                token_ceiling=self._replay_token_ceiling,
            )

            # One physical sequence correlates both hook phases and the eventual
            # chain-atomic settlement. Hook evidence has its own request id:
            # ``turn_completed_request_id`` is the unique indexed hop-1 lookup
            # for the examiner read model and may not be shared with hook rows.
            # A refused output leaves the sequence unused; the next live claim
            # recomputes it.
            seq = await self._store.next_turn_seq(
                conversation_id,
                tenant_id=tenant_id,
                claim_id=claim.claim_id,
            )
            request_id = f"{_TURN_REQUEST_ID_PREFIX}{uuid.uuid4().hex}"
            hook_request_id = f"{_HOOK_REQUEST_ID_PREFIX}{uuid.uuid4().hex}"

            # 4. The input phase sees the exact assembled bounded replay plus
            #    this message. Any dispatcher failure, policy refusal,
            #    transformation decision, or missing governance record collapses
            #    to one wire-public refusal. R25 keeps conversation phases
            #    PASS/REFUSE-only until F-S3 adds hook-aware examiner projection
            #    and digest continuity in the same slice.
            try:
                governance = self._hook_guard.governance_for_agent(agent_id=record.agent_id)

                def _validate_input_transform(candidate: bytes) -> None:
                    _validated_input_hook_result(
                        candidate,
                        conversation_id=conversation_id,
                        tenant_id=tenant_id,
                        turn_seq=seq,
                        governance=governance,
                        prior_context=prior_context,
                    )

                input_hook_payload = _input_hook_payload(
                    conversation_id=conversation_id,
                    tenant_id=tenant_id,
                    turn_seq=seq,
                    governance=governance,
                    prior_context=prior_context,
                    user_message=user_message,
                )
                input_scan = await self._hook_guard.scan(
                    phase="conversation_input",
                    payload=input_hook_payload,
                    governance=governance,
                    tenant_id=tenant_id,
                    request_id=hook_request_id,
                    conversation_id=conversation_id,
                    turn_seq=seq,
                    agent_run_id=None,
                    output_origin=None,
                    approval_delivery_id=None,
                    validate_transformed_payload=_validate_input_transform,
                )
                if input_scan.outcome != "passed":
                    raise ValueError("conversation input hook did not pass")
                if input_scan.final_payload != input_hook_payload:
                    raise ValueError("conversation input hook transformed a PASS/REFUSE-only phase")
                if (
                    isinstance(input_scan.hook_decision_count, bool)
                    or not isinstance(input_scan.hook_decision_count, int)
                    or input_scan.hook_decision_count <= 0
                ):
                    raise ValueError("conversation input hook evidence count is empty")
                prior_context, screened_user_message = _validated_input_hook_result(
                    input_scan.final_payload,
                    conversation_id=conversation_id,
                    tenant_id=tenant_id,
                    turn_seq=seq,
                    governance=governance,
                    prior_context=prior_context,
                )
            except Exception:
                latest = await self._store.load(
                    conversation_id,
                    tenant_id=tenant_id,
                    creator_subject=actor_subject,
                )
                raise ConversationTurnRefused(
                    "conversation_hook_refused",
                    current_state=latest.state if latest is not None else record.state,
                ) from None

            # 5. The M8 governed loop. Its dispatch chokepoint re-checks the
            #    CURRENT envelope on every dispatch (invariant I-2).
            result = await self._loop.ask(
                agent_id=record.agent_id,
                question=screened_user_message,
                actor_tenant_id=tenant_id,
                actor_subject=actor_subject,
                prior_context=prior_context,
            )

            async def _settle_refused_output(
                *,
                output_request_id: str | None = None,
                output_hook_count: int = 0,
                answer: str | None = None,
            ) -> ConversationState:
                # R21: output suppression spends model tokens but creates no
                # transcript turn. The store atomically couples this counter
                # movement to digest-only conversation.turn_refused evidence.
                return await self._store.settle_refused_turn(
                    conversation_id=conversation_id,
                    tenant_id=tenant_id,
                    seq=seq,
                    question=screened_user_message,
                    answer=result.answer if answer is None else answer,
                    agent_run_id=result.run_id,
                    prompt_tokens=result.prompt_tokens,
                    completion_tokens=result.completion_tokens,
                    actor_id=actor_subject,
                    request_id=request_id,
                    claim_id=claim.claim_id,
                    conversation_output_request_id=output_request_id,
                    conversation_output_hook_count=output_hook_count,
                )

            # 6. A completed/refused agent run is a historical fact. The output
            #    phase may nevertheless refuse shipping its answer; that refusal
            #    does not falsify or remove the run's terminal evidence. R25
            #    admits only a byte-identical pass or a refusal in F-S2a.
            #
            #    R19's one exact exemption is ``pending_approval``: AgentLoop
            #    constructs that terminal response solely from kernel constants
            #    plus the kernel-minted approval id. It contains no model-authored
            #    content or tool arguments, and persisting it is the sole D2
            #    conversation↔approval correlation. Tests pin the construction
            #    property so later enrichment forces this exemption back through
            #    review. No other terminal state is exempt.
            output_request_id: str | None = None
            output_hook_count = 0
            if result.terminal_state == "pending_approval":
                approval_request_id = result.approval_request_id
                if (
                    not isinstance(approval_request_id, str)
                    or not approval_request_id
                    or result.answer != f"Requested approval — #{approval_request_id[:4]}, pending."
                ):
                    current_state = await _settle_refused_output()
                    raise ConversationTurnRefused(
                        "conversation_hook_refused", current_state=current_state
                    )
                screened_answer = result.answer
            else:
                try:

                    def _validate_output_transform(candidate: bytes) -> None:
                        _validated_output_hook_result(
                            candidate,
                            conversation_id=conversation_id,
                            tenant_id=tenant_id,
                            turn_seq=seq,
                            governance=governance,
                        )

                    def _project_output_value(candidate: bytes) -> bytes:
                        return _validated_output_hook_result(
                            candidate,
                            conversation_id=conversation_id,
                            tenant_id=tenant_id,
                            turn_seq=seq,
                            governance=governance,
                        ).encode("utf-8")

                    output_hook_payload = _output_hook_payload(
                        conversation_id=conversation_id,
                        tenant_id=tenant_id,
                        turn_seq=seq,
                        governance=governance,
                        answer=result.answer,
                    )
                    output_scan = await self._hook_guard.scan(
                        phase="conversation_output",
                        payload=output_hook_payload,
                        governance=governance,
                        tenant_id=tenant_id,
                        request_id=hook_request_id,
                        conversation_id=conversation_id,
                        turn_seq=seq,
                        agent_run_id=result.run_id,
                        output_origin="agent_run",
                        approval_delivery_id=None,
                        validate_transformed_payload=_validate_output_transform,
                        evidence_value_projector=_project_output_value,
                        evidence_input_value=result.answer.encode("utf-8"),
                    )
                    output_request_id = hook_request_id
                    if (
                        isinstance(output_scan.hook_decision_count, bool)
                        or not isinstance(output_scan.hook_decision_count, int)
                        or output_scan.hook_decision_count <= 0
                    ):
                        current_state = await _settle_refused_output()
                        raise ConversationTurnRefused(
                            "conversation_hook_refused",
                            current_state=current_state,
                        )
                    output_hook_count = output_scan.hook_decision_count
                    if output_scan.outcome != "passed":
                        refused_answer = _validated_output_hook_result(
                            output_scan.final_payload,
                            conversation_id=conversation_id,
                            tenant_id=tenant_id,
                            turn_seq=seq,
                            governance=governance,
                        )
                        evidenced_output_request_id = (
                            output_request_id if output_hook_count > 0 else None
                        )
                        current_state = await _settle_refused_output(
                            output_request_id=evidenced_output_request_id,
                            output_hook_count=output_hook_count,
                            answer=refused_answer,
                        )
                        raise ConversationTurnRefused(
                            "conversation_hook_refused",
                            current_state=current_state,
                            conversation_output_request_id=evidenced_output_request_id,
                            conversation_output_hook_count=output_hook_count,
                        )
                    if output_scan.final_payload != output_hook_payload:
                        current_state = await _settle_refused_output(
                            output_request_id=output_request_id,
                            output_hook_count=output_hook_count,
                        )
                        raise ConversationTurnRefused(
                            "conversation_hook_refused",
                            current_state=current_state,
                            conversation_output_request_id=output_request_id,
                            conversation_output_hook_count=output_hook_count,
                        )
                    screened_answer = _validated_output_hook_result(
                        output_scan.final_payload,
                        conversation_id=conversation_id,
                        tenant_id=tenant_id,
                        turn_seq=seq,
                        governance=governance,
                    )
                except ConversationTurnRefused:
                    raise
                except ConversationHookEvidenceError as exc:
                    if (
                        isinstance(exc.hook_decision_count, bool)
                        or not isinstance(exc.hook_decision_count, int)
                        or exc.hook_decision_count < 0
                    ):
                        current_state = await _settle_refused_output()
                        raise ConversationTurnRefused(
                            "conversation_hook_refused",
                            current_state=current_state,
                        ) from None
                    refused_answer = _validated_output_hook_result(
                        exc.final_payload,
                        conversation_id=conversation_id,
                        tenant_id=tenant_id,
                        turn_seq=seq,
                        governance=governance,
                    )
                    output_hook_count = exc.hook_decision_count
                    evidenced_output_request_id = hook_request_id if output_hook_count > 0 else None
                    current_state = await _settle_refused_output(
                        output_request_id=evidenced_output_request_id,
                        output_hook_count=output_hook_count,
                        answer=refused_answer,
                    )
                    raise ConversationTurnRefused(
                        "conversation_hook_refused",
                        current_state=current_state,
                        conversation_output_request_id=evidenced_output_request_id,
                        conversation_output_hook_count=output_hook_count,
                    ) from None
                except Exception:
                    current_state = await _settle_refused_output(
                        output_request_id=(output_request_id if output_hook_count > 0 else None),
                        output_hook_count=output_hook_count,
                    )
                    raise ConversationTurnRefused(
                        "conversation_hook_refused",
                        current_state=current_state,
                        conversation_output_request_id=(
                            output_request_id if output_hook_count > 0 else None
                        ),
                        conversation_output_hook_count=output_hook_count,
                    ) from None

            # 7. Persist + chain row (digest-only). append_turn returns the
            #    turn_id it actually inserted -- surface THAT, never a fresh uuid.
            try:
                turn_id = await self._store.append_turn(
                    conversation_id=conversation_id,
                    tenant_id=tenant_id,
                    seq=seq,
                    user_message=screened_user_message,
                    answer=screened_answer,
                    agent_run_id=result.run_id,
                    prompt_tokens=result.prompt_tokens,
                    completion_tokens=result.completion_tokens,
                    actor_id=actor_subject,
                    request_id=request_id,
                    claim_id=claim.claim_id,
                    approval_request_id=result.approval_request_id,
                    turn_kind="exchange",
                    conversation_output_request_id=output_request_id,
                    conversation_output_hook_count=output_hook_count,
                )
            except ConversationTurnRefused as exc:
                # The terminal + successful output-hook prefix is already
                # durable. Preserve its exact final scalar on a late
                # lifecycle/fencing refusal so downstream refusal evidence can
                # join without falling back to the raw model answer.
                screened_bytes = screened_answer.encode("utf-8")
                raise ConversationTurnRefused(
                    exc.reason,
                    current_state=exc.current_state,
                    conversation_output_request_id=output_request_id,
                    conversation_output_hook_count=output_hook_count,
                    conversation_output_value_sha256=hashlib.sha256(screened_bytes).hexdigest(),
                    conversation_output_value_bytes=len(screened_bytes),
                ) from exc
            return TurnResult(
                turn_id=turn_id,
                seq=seq,
                answer=screened_answer,
                agent_run_id=result.run_id,
                terminal_state=result.terminal_state,
                refusal_reason=result.refusal_reason,
                approval_request_id=result.approval_request_id,
            )
        finally:
            # 8. Always release OUR OWN lease (fenced by claim_id): if the claim
            #    was reclaimed after TTL while we ran, this is a no-op and the
            #    new holder's lease survives. A crashed turn never wedges the
            #    conversation -- its lease is reclaimable after TTL.
            await self._store.release_claim(
                conversation_id, tenant_id=tenant_id, claim_id=claim.claim_id
            )

    async def post_system_turn(
        self,
        *,
        conversation_id: uuid.UUID,
        tenant_id: str,
        text: str,
        approval_request_id: str,
        actor_id: str = "system:approval-executor",
        request_id: str,
    ) -> uuid.UUID:
        """Screen and append an approval outcome without model-turn budgets.

        The system writer uses the same database-backed claim and fencing token
        as a user turn, so it cannot interleave with an in-flight model call.
        Approval/tool-result text is not R19's exact pending-response exemption:
        it crosses the same ``conversation_output`` boundary before persistence.
        """
        claim = await self._store.claim_system_turn(
            conversation_id,
            tenant_id=tenant_id,
            now=self._clock(),
            claim_ttl_s=self._claim_ttl_s,
        )
        try:
            record = claim.record
            output_request_id: str | None = None
            output_hook_count = 0
            try:
                governance = self._hook_guard.governance_for_agent(agent_id=record.agent_id)
                seq = await self._store.next_turn_seq(
                    conversation_id,
                    tenant_id=tenant_id,
                    claim_id=claim.claim_id,
                )
                hook_request_id = f"{_HOOK_REQUEST_ID_PREFIX}{uuid.uuid4().hex}"

                def _validate_output_transform(candidate: bytes) -> None:
                    _validated_output_hook_result(
                        candidate,
                        conversation_id=conversation_id,
                        tenant_id=tenant_id,
                        turn_seq=seq,
                        governance=governance,
                    )

                def _project_output_value(candidate: bytes) -> bytes:
                    return _validated_output_hook_result(
                        candidate,
                        conversation_id=conversation_id,
                        tenant_id=tenant_id,
                        turn_seq=seq,
                        governance=governance,
                    ).encode("utf-8")

                output_hook_payload = _output_hook_payload(
                    conversation_id=conversation_id,
                    tenant_id=tenant_id,
                    turn_seq=seq,
                    governance=governance,
                    answer=text,
                )
                output_scan = await self._hook_guard.scan(
                    phase="conversation_output",
                    payload=output_hook_payload,
                    governance=governance,
                    tenant_id=tenant_id,
                    request_id=hook_request_id,
                    conversation_id=conversation_id,
                    turn_seq=seq,
                    agent_run_id=None,
                    output_origin="approval_delivery",
                    approval_delivery_id=f"approval-delivery-{approval_request_id}",
                    validate_transformed_payload=_validate_output_transform,
                    evidence_value_projector=_project_output_value,
                    evidence_input_value=text.encode("utf-8"),
                )
                output_request_id = hook_request_id
                if (
                    isinstance(output_scan.hook_decision_count, bool)
                    or not isinstance(output_scan.hook_decision_count, int)
                    or output_scan.hook_decision_count <= 0
                ):
                    raise ValueError("conversation output hook evidence count is malformed")
                output_hook_count = output_scan.hook_decision_count
                if output_scan.outcome != "passed":
                    refused_text = _validated_output_hook_result(
                        output_scan.final_payload,
                        conversation_id=conversation_id,
                        tenant_id=tenant_id,
                        turn_seq=seq,
                        governance=governance,
                    )
                    refused_bytes = refused_text.encode("utf-8")
                    raise ConversationTurnRefused(
                        "conversation_hook_refused",
                        current_state=record.state,
                        conversation_output_request_id=hook_request_id,
                        conversation_output_hook_count=output_hook_count,
                        conversation_output_value_sha256=hashlib.sha256(refused_bytes).hexdigest(),
                        conversation_output_value_bytes=len(refused_bytes),
                    )
                if output_scan.final_payload != output_hook_payload:
                    raise ConversationTurnRefused(
                        "conversation_hook_refused",
                        current_state=record.state,
                        conversation_output_request_id=hook_request_id,
                        conversation_output_hook_count=output_hook_count,
                        conversation_output_value_sha256=hashlib.sha256(
                            text.encode("utf-8")
                        ).hexdigest(),
                        conversation_output_value_bytes=len(text.encode("utf-8")),
                    )
                screened_text = _validated_output_hook_result(
                    output_scan.final_payload,
                    conversation_id=conversation_id,
                    tenant_id=tenant_id,
                    turn_seq=seq,
                    governance=governance,
                )
            except ConversationTurnRefused as exc:
                latest = await self._store.load(
                    conversation_id,
                    tenant_id=tenant_id,
                    creator_subject=record.creator_subject,
                )
                raise ConversationTurnRefused(
                    exc.reason,
                    current_state=latest.state if latest is not None else exc.current_state,
                    conversation_output_request_id=exc.conversation_output_request_id,
                    conversation_output_hook_count=exc.conversation_output_hook_count,
                    conversation_output_value_sha256=exc.conversation_output_value_sha256,
                    conversation_output_value_bytes=exc.conversation_output_value_bytes,
                ) from exc
            except ConversationHookEvidenceError as exc:
                if (
                    isinstance(exc.hook_decision_count, bool)
                    or not isinstance(exc.hook_decision_count, int)
                    or exc.hook_decision_count < 0
                ):
                    refused_text = text
                    evidenced_request_id = None
                    evidenced_hook_count = 0
                else:
                    refused_text = _validated_output_hook_result(
                        exc.final_payload,
                        conversation_id=conversation_id,
                        tenant_id=tenant_id,
                        turn_seq=seq,
                        governance=governance,
                    )
                    evidenced_hook_count = exc.hook_decision_count
                    evidenced_request_id = hook_request_id if evidenced_hook_count > 0 else None
                refused_bytes = refused_text.encode("utf-8")
                latest = await self._store.load(
                    conversation_id,
                    tenant_id=tenant_id,
                    creator_subject=record.creator_subject,
                )
                raise ConversationTurnRefused(
                    "conversation_hook_refused",
                    current_state=latest.state if latest is not None else record.state,
                    conversation_output_request_id=evidenced_request_id,
                    conversation_output_hook_count=evidenced_hook_count,
                    conversation_output_value_sha256=hashlib.sha256(refused_bytes).hexdigest(),
                    conversation_output_value_bytes=len(refused_bytes),
                ) from None
            except Exception:
                refused_bytes = text.encode("utf-8")
                has_valid_correlation = (
                    isinstance(output_hook_count, int)
                    and not isinstance(output_hook_count, bool)
                    and output_hook_count > 0
                )
                latest = await self._store.load(
                    conversation_id,
                    tenant_id=tenant_id,
                    creator_subject=record.creator_subject,
                )
                raise ConversationTurnRefused(
                    "conversation_hook_refused",
                    current_state=latest.state if latest is not None else record.state,
                    conversation_output_request_id=(
                        output_request_id if has_valid_correlation else None
                    ),
                    conversation_output_hook_count=(
                        output_hook_count if has_valid_correlation else 0
                    ),
                    conversation_output_value_sha256=hashlib.sha256(refused_bytes).hexdigest(),
                    conversation_output_value_bytes=len(refused_bytes),
                ) from None

            try:
                return await self._store.append_system_turn(
                    conversation_id=conversation_id,
                    tenant_id=tenant_id,
                    text=screened_text,
                    approval_request_id=approval_request_id,
                    actor_id=actor_id,
                    request_id=request_id,
                    claim_id=claim.claim_id,
                    conversation_output_request_id=output_request_id,
                    conversation_output_hook_count=output_hook_count,
                )
            except ConversationTurnRefused as exc:
                # R25 admits only a byte-identical pass, so the screened scalar
                # is the original approval-delivery text. Preserve that digest
                # when a late lifecycle/fencing check refuses persistence.
                screened_bytes = screened_text.encode("utf-8")
                raise ConversationTurnRefused(
                    exc.reason,
                    current_state=exc.current_state,
                    conversation_output_request_id=output_request_id,
                    conversation_output_hook_count=output_hook_count,
                    conversation_output_value_sha256=hashlib.sha256(screened_bytes).hexdigest(),
                    conversation_output_value_bytes=len(screened_bytes),
                ) from exc
        finally:
            await self._store.release_claim(
                conversation_id,
                tenant_id=tenant_id,
                claim_id=claim.claim_id,
            )

    async def resolve_approval_context(
        self,
        *,
        approval_request_id: uuid.UUID,
        tenant_id: str,
    ) -> tuple[uuid.UUID, str] | None:
        """Delegate the tenant-scoped approval-to-conversation lookup."""
        return await self._store.resolve_approval_context(
            approval_request_id=approval_request_id,
            tenant_id=tenant_id,
        )
