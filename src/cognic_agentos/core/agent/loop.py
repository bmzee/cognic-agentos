"""M8 Task A11 (ADR-027) — the kernel-owned agent reasoning loop (CRITICAL CONTROLS).

Critical-controls module (``core/`` stop-rule per AGENTS.md L48).
Every edit is halt-before-commit per [[feedback_strict_review_off_gate]].

:meth:`AgentLoop.ask` is the single-shot governed agent run:

  1. **Pre-flight** (NO run minted, NO evidence): load the validated agent
     record through the consumer-owned :class:`AgentRecordLoader` seam —
     unknown / unregistered raises ``LookupError`` (the A13 route maps it to
     404); load the granted capability sets through the A4
     ``AssignmentStore`` — the ``AgentGrantNotRequested`` ingestion-invariant
     raise PROPAGATES fail-loud (config-drift emergency).
  2. **Mint the run**: ``agent-run-<uuid4.hex>``, resolve the EFFECTIVE
     max-steps bound (the record's declared value beats the kernel default),
     emit the digest-only ``agent.run.started`` evidence row, capture the
     monotonic start.
  3. **Prompt** (progressive disclosure per ADR-027 §a): persona body + an
     "Assigned skills" index carrying DESCRIPTIONS only — skill BODIES reach
     the model ONLY via the dispatch-gated ``read_skill`` built-in — + the
     kernel-owned tool-use contract. Tools = the A10
     :func:`build_llm_tool_specs` surface (advertised == dispatchable).
  4. **Iterate rounds**: round-top bound checks in this exact order BEFORE
     the completion call — max_steps, then cumulative prompt+completion
     tokens, then wall clock — each terminating ``refused`` /
     ``agent_max_steps_exceeded`` with a payload ``bound`` key naming which.
     ``agent_workforce_id == agent_id`` on EVERY gateway call (the BAR-5
     seam); ONLY the completion call is exception-wrapped (→ terminal
     ``failed`` carrying the exception CLASS name, never ``str(exc)``).
  5. **Dispatch**: every LLM-authored tool call goes through the A10
     :class:`AgentDispatcher` chokepoint — all dispatches of round ``n``
     share ``step_index=n`` (the round IS the reasoning step). Dispatch
     refusals NEVER terminate the run: they return to the model as tool
     messages so it can answer gracefully (the BAR-2 shape). The
     dispatcher's fail-loud missing-signing-key ``RuntimeError`` (a
     DEPLOYMENT error) propagates uncaught and unevidenced.
  6. **Terminate**: a no-tool-calls response is the final answer
     (``completed``). Every terminal state emits exactly ONE digest-only
     ``agent.run.<state>`` row — question/answer plaintext appears in NO
     payload (ADR-027 §f); the plaintext returns ONLY on
     :class:`AgentAskResult`. Then the best-effort task-tier memory digest
     is written through the governed ``remember`` built-in (a failure warns
     and leaves the run result unaffected).

Kernel-boot-clean: module-level imports are stdlib + ``core.*`` ONLY.
``llm.gateway`` is TYPE_CHECKING-only (the A10 ``build_llm_tool_specs``
precedent keeps gateway imports out of kernel boot — the loop only reads
attributes off injected/returned objects). No ``portal`` / ``protocol`` /
``sdk`` / ``cli`` import — pinned by
``tests/unit/architecture/test_agent_no_forbidden_imports.py``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from typing import TYPE_CHECKING, Any, Final, Literal, Protocol

from cognic_agentos.core.agent import builtins as _builtins
from cognic_agentos.core.agent._types import (
    AgentAskResult,
    AgentDispatchRefusalReason,
    AgentRunTerminalState,
    GrantedCapabilities,
    LoadedAgentRecord,
)
from cognic_agentos.core.agent.dispatch import AgentRunContext, build_llm_tool_specs
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord

if TYPE_CHECKING:
    from collections.abc import Callable

    from cognic_agentos.core.agent.assignments import AssignmentStore
    from cognic_agentos.core.agent.dispatch import (
        AgentDispatcher,
        MemoryApiFactory,
        SkillBodyReader,
    )
    from cognic_agentos.llm.gateway import GatewayToolCall, LLMGateway

logger = logging.getLogger(__name__)

#: The run-level bound that terminated a refused run — wire-visible on the
#: ``agent.run.refused`` payload's ``bound`` key (3 values, checked in this
#: order at every round top).
RunBoundKind = Literal["max_steps", "token_budget", "wall_clock"]

#: ISO-control mapping for agent.* evidence is a Human-only decision —
#: deferred (mirrors ``core/agent/dispatch.py``'s
#: ``_AGENT_DISPATCH_ISO_CONTROLS``).
_AGENT_RUN_ISO_CONTROLS: tuple[str, ...] = ()

#: Run-id prefix: ``agent-run-`` + 32 hex = 42 chars; the derived evidence
#: request-ids (``-started`` → 50, ``-terminal`` → 51, ``-s<n>`` ≤ 46 with
#: max_steps ≤ 32) all fit the decision_history ``request_id`` String(64).
_RUN_ID_PREFIX: Final[str] = "agent-run-"

#: Closed-form safe answer on terminal ``failed`` — the raw exception text
#: never reaches the caller-visible answer (CLASS name at most, and only in
#: the chain payload's ``error_class``).
_FAILED_ANSWER: Final[str] = (
    "the agent run failed before producing an answer; the failure has been recorded"
)

#: Kernel-owned tool-use contract appended to every system prompt.
_TOOL_USE_CONTRACT: Final[str] = (
    "Tool-use contract: before acting on a task an assigned skill covers, "
    "load that skill's guidance with the read_skill tool. Use only the tools "
    "listed for this run. When you have the final answer, reply with plain "
    "text and make no tool calls."
)


class AgentRecordLoader(Protocol):
    """Consumer-owned load seam for validated agent records (the ``core/run``
    ``PackRecordLoader`` precedent — the real conformer lands in harness at
    A13). ``None`` = unknown agent for this tenant (absent OR cross-tenant —
    the conformer collapses both per the wire-collapse doctrine)."""

    async def load_for_agent(
        self, *, agent_id: str, tenant_id: str
    ) -> LoadedAgentRecord | None: ...


# --- Pure helpers (module-level so every defensive arm is direct-testable —
# --- the A10 ``_granted_tool_name_map`` precedent) ------------------------------


def _token_count(value: object) -> int:
    """One usage counter, accepted ONLY as a real int — ``bool`` is an int
    subclass and is excluded (the A6 bool-guard precedent); anything else
    contributes 0."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return 0


def _usage_token_counts(usage: object) -> tuple[int, int]:
    """``(prompt_tokens, completion_tokens)`` off a delivered response's
    ``usage`` value. The gateway guarantees dict-or-None; the isinstance
    guard is the evidence-boundary defence (missing / None / malformed →
    0 contribution)."""
    if not isinstance(usage, dict):
        return (0, 0)
    return (
        _token_count(usage.get("prompt_tokens")),
        _token_count(usage.get("completion_tokens")),
    )


def _track_capability_use(
    call: GatewayToolCall, *, skills_read: set[str], scope_ids_used: set[str]
) -> None:
    """Track the memory-digest facts off an OK-dispatched call's LLM-authored
    args: ``read_skill`` skill_ids + ``run_readonly_query`` scope_ids. The
    isinstance guards are defensive — the dispatcher validated both for ok
    outcomes (the read_skill sub-gate / the gate-2 scope check) — and are
    direct-tested on this pure helper."""
    if call.name == "read_skill":
        skill_id = call.arguments.get("skill_id")
        if isinstance(skill_id, str):
            skills_read.add(skill_id)
    elif call.name == "run_readonly_query":
        scope_id = call.arguments.get("scope_id")
        if isinstance(scope_id, str):
            scope_ids_used.add(scope_id)


def _build_system_prompt(
    *, record: LoadedAgentRecord, granted: GrantedCapabilities, reader: SkillBodyReader
) -> str:
    """The kernel-owned system prompt (progressive disclosure, ADR-027 §a).

    Persona body + an "Assigned skills" index (GRANTED skills only — an
    unassigned skill id never enters the prompt; omitted entirely when the
    grant set is empty) + the kernel tool-use contract. A hosted instruction
    skill's index line carries the DESCRIPTION only — the BODY is
    deliberately DISCARDED here and reaches the model ONLY via the
    dispatch-gated ``read_skill`` built-in; an unhosted granted skill
    renders a name-only line."""
    sections: list[str] = [record.persona_body]
    if granted.skills:
        lines = ["Assigned skills:"]
        for skill_id in sorted(granted.skills):
            loaded = reader.read(skill_id)
            if loaded is None:
                lines.append(f"- {skill_id}")
            else:
                description, _body = loaded  # the body NEVER enters the prompt
                lines.append(f"- {skill_id}: {description}")
        sections.append("\n".join(lines))
    sections.append(_TOOL_USE_CONTRACT)
    return "\n\n".join(sections)


def _refused_answer(bound: RunBoundKind) -> str:
    """Closed-form safe answer on a run-level bound refusal (no LLM text,
    no exception text — the bound name is a kernel literal)."""
    return (
        "the agent run stopped before producing an answer: the run-level "
        f"'{bound}' bound was reached"
    )


class AgentLoop:
    """The kernel-owned reasoning loop of the governed agent run (ADR-027).

    Owns run minting, the progressive-disclosure prompt, the round-top run
    bounds, the per-round dispatch fan-out through the A10
    :class:`AgentDispatcher`, the run-level ``agent.run.*`` evidence rows,
    and the best-effort task-tier memory digest. Construction takes scalars
    (the dispatcher precedent — the composition root reads Settings) + an
    injectable monotonic ``clock`` (the BoundedQueue precedent).
    """

    def __init__(
        self,
        *,
        record_loader: AgentRecordLoader,
        assignments: AssignmentStore,
        gateway: LLMGateway,
        dispatcher: AgentDispatcher,
        skill_reader: SkillBodyReader,
        memory_factory: MemoryApiFactory,
        decision_history: DecisionHistoryStore,
        default_max_steps: int,
        run_token_budget: int,
        run_wall_clock_s: float,
        tier: str = "tier1",
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._record_loader = record_loader
        self._assignments = assignments
        self._gateway = gateway
        self._dispatcher = dispatcher
        self._skill_reader = skill_reader
        self._memory_factory = memory_factory
        self._decision_history = decision_history
        self._default_max_steps = default_max_steps
        self._run_token_budget = run_token_budget
        self._run_wall_clock_s = run_wall_clock_s
        self._tier = tier
        self._clock = clock

    async def ask(
        self,
        *,
        agent_id: str,
        question: str,
        actor_tenant_id: str,
        actor_subject: str,
    ) -> AgentAskResult:
        """One single-shot governed agent run (the module-docstring pipeline).

        Raises:
            LookupError: unknown OR unregistered agent for this tenant —
                pre-flight, NO run minted, NO evidence (the A13 route maps
                it to 404).
            AgentGrantNotRequested: the A4 ingestion invariant fired at
                grant load — config-drift emergency, propagated fail-loud.
            RuntimeError: the dispatcher's fail-loud missing-signing-key
                DEPLOYMENT error — propagated uncaught and unevidenced.
        """
        # --- 1. Pre-flight (NO run minted, NO evidence).
        record = await self._record_loader.load_for_agent(
            agent_id=agent_id, tenant_id=actor_tenant_id
        )
        if record is None or record.registered is False:
            raise LookupError(
                f"agent {agent_id!r} is not a registered agent pack for tenant {actor_tenant_id!r}"
            )
        granted = await self._assignments.load_for_agent(
            tenant_id=actor_tenant_id, agent_id=agent_id, record=record
        )

        # --- 2. Mint the run + the started evidence row.
        run_id = f"{_RUN_ID_PREFIX}{uuid.uuid4().hex}"
        effective_max_steps = (
            record.max_steps if record.max_steps is not None else self._default_max_steps
        )
        run = AgentRunContext(
            run_id=run_id,
            tenant_id=actor_tenant_id,
            originator_subject=actor_subject,
            agent_id=agent_id,
            granted=granted,
            max_steps=effective_max_steps,
            record=record,
        )
        question_encoded = question.encode("utf-8")
        question_sha256 = hashlib.sha256(question_encoded).hexdigest()
        await self._decision_history.append(
            DecisionRecord(
                decision_type="agent.run.started",
                request_id=f"{run_id}-started",
                payload={
                    "run_id": run_id,
                    # The ADR-027 §f dual identity: the AGENT rides the
                    # payload; the ORIGINATOR is DecisionRecord.actor_id.
                    "agent_id": agent_id,
                    "originator_subject": actor_subject,
                    "question_sha256": question_sha256,
                    "question_bytes": len(question_encoded),
                    "max_steps": effective_max_steps,
                    "token_budget": self._run_token_budget,
                    "wall_clock_s": self._run_wall_clock_s,
                },
                actor_id=actor_subject,
                tenant_id=actor_tenant_id,
                iso_controls=_AGENT_RUN_ISO_CONTROLS,
            )
        )
        start = self._clock()

        # --- 3. The conversation + the advertised capability surface.
        messages: list[dict[str, Any]] = [
            {
                "role": "system",
                "content": _build_system_prompt(
                    record=record, granted=granted, reader=self._skill_reader
                ),
            },
            {"role": "user", "content": question},
        ]
        specs = build_llm_tool_specs(run=run)

        prompt_tokens_total = 0
        completion_tokens_total = 0
        skills_read: set[str] = set()
        scope_ids_used: set[str] = set()

        # --- 4-7. Iterate rounds.
        n = 0
        while True:
            # Round-top bound checks, in this exact order, BEFORE the
            # completion call. first-tripping bound wins deterministically.
            bound: RunBoundKind | None = None
            if n >= effective_max_steps:
                bound = "max_steps"
            elif prompt_tokens_total + completion_tokens_total > self._run_token_budget:
                bound = "token_budget"
            elif self._clock() - start > self._run_wall_clock_s:
                bound = "wall_clock"
            if bound is not None:
                return await self._finish(
                    run=run,
                    state="refused",
                    answer=_refused_answer(bound),
                    steps_used=n,
                    prompt_tokens_total=prompt_tokens_total,
                    completion_tokens_total=completion_tokens_total,
                    question_sha256=question_sha256,
                    skills_read=skills_read,
                    scope_ids_used=scope_ids_used,
                    refusal_reason="agent_max_steps_exceeded",
                    bound=bound,
                )

            # ONLY the completion call is exception-wrapped: any gateway
            # failure terminates ``failed`` with the exception CLASS name
            # (never str(exc) — the raw text reaches the operator log only).
            try:
                response = await self._gateway.completion(
                    tier=self._tier,
                    messages=messages,
                    request_id=f"{run_id}-s{n}",
                    tenant_id=actor_tenant_id,
                    # BAR-5: the workforce id IS the agent id on EVERY call.
                    agent_workforce_id=agent_id,
                    tools=specs,
                )
            except Exception as exc:
                logger.warning(
                    "agent.run_gateway_failed",
                    extra={
                        "run_id": run_id,
                        "exception_class": type(exc).__name__,
                    },
                    exc_info=True,
                )
                return await self._finish(
                    run=run,
                    state="failed",
                    answer=_FAILED_ANSWER,
                    steps_used=n,
                    prompt_tokens_total=prompt_tokens_total,
                    completion_tokens_total=completion_tokens_total,
                    question_sha256=question_sha256,
                    skills_read=skills_read,
                    scope_ids_used=scope_ids_used,
                    error_class=type(exc).__name__,
                )

            round_prompt, round_completion = _usage_token_counts(response.usage)
            prompt_tokens_total += round_prompt
            completion_tokens_total += round_completion

            if not response.tool_calls:
                # The final answer: a no-tool-calls response terminates the run.
                return await self._finish(
                    run=run,
                    state="completed",
                    answer=response.content,
                    steps_used=n + 1,
                    prompt_tokens_total=prompt_tokens_total,
                    completion_tokens_total=completion_tokens_total,
                    question_sha256=question_sha256,
                    skills_read=skills_read,
                    scope_ids_used=scope_ids_used,
                )

            # The assistant tool-calls turn, in the OpenAI wire shape.
            messages.append(
                {
                    "role": "assistant",
                    "content": response.content or "",
                    "tool_calls": [
                        {
                            "id": tool_call.id,
                            "type": "function",
                            "function": {
                                "name": tool_call.name,
                                "arguments": json.dumps(tool_call.arguments),
                            },
                        }
                        for tool_call in response.tool_calls
                    ],
                }
            )
            # Dispatch sequentially in wire order; ALL dispatches of round n
            # share step_index=n (the round IS the reasoning step —
            # correlates dispatch rows to the ``{run_id}-s{n}`` request id).
            # Dispatch refusals NEVER terminate the run: they return to the
            # model as tool messages (the BAR-2 shape). The dispatcher's
            # fail-loud RuntimeError deliberately propagates.
            for tool_call in response.tool_calls:
                outcome = await self._dispatcher.dispatch(call=tool_call, step_index=n, run=run)
                if outcome.refused:
                    content = json.dumps(
                        {
                            "refused": True,
                            "reason": outcome.reason,
                            "message": outcome.message,
                        }
                    )
                else:
                    content = json.dumps(outcome.result)
                    _track_capability_use(
                        tool_call, skills_read=skills_read, scope_ids_used=scope_ids_used
                    )
                messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": content})
            n += 1

    async def _finish(
        self,
        *,
        run: AgentRunContext,
        state: AgentRunTerminalState,
        answer: str,
        steps_used: int,
        prompt_tokens_total: int,
        completion_tokens_total: int,
        question_sha256: str,
        skills_read: set[str],
        scope_ids_used: set[str],
        refusal_reason: AgentDispatchRefusalReason | None = None,
        bound: RunBoundKind | None = None,
        error_class: str | None = None,
    ) -> AgentAskResult:
        """One terminal arm: emit exactly ONE digest-only ``agent.run.<state>``
        row, then the best-effort memory digest, then return the result —
        the ONLY surface carrying the answer plaintext (ADR-027 §f)."""
        answer_encoded = answer.encode("utf-8")
        payload: dict[str, Any] = {
            "run_id": run.run_id,
            # The ADR-027 §f dual identity (see the started row).
            "agent_id": run.agent_id,
            "originator_subject": run.originator_subject,
            "answer_sha256": hashlib.sha256(answer_encoded).hexdigest(),
            "answer_bytes": len(answer_encoded),
            "steps_used": steps_used,
            "prompt_tokens_total": prompt_tokens_total,
            "completion_tokens_total": completion_tokens_total,
        }
        if state == "refused":
            payload["refusal_reason"] = refusal_reason
            payload["bound"] = bound
        elif state == "failed":
            payload["error_class"] = error_class
        await self._decision_history.append(
            DecisionRecord(
                decision_type=f"agent.run.{state}",
                request_id=f"{run.run_id}-terminal",
                payload=payload,
                actor_id=run.originator_subject,
                tenant_id=run.tenant_id,
                iso_controls=_AGENT_RUN_ISO_CONTROLS,
            )
        )
        await self._write_memory_digest_best_effort(
            run=run,
            terminal_state=state,
            question_sha256=question_sha256,
            skills_read=skills_read,
            scope_ids_used=scope_ids_used,
            steps_used=steps_used,
        )
        return AgentAskResult(
            run_id=run.run_id,
            terminal_state=state,
            answer=answer,
            steps_used=steps_used,
            refusal_reason=refusal_reason,
        )

    async def _write_memory_digest_best_effort(
        self,
        *,
        run: AgentRunContext,
        terminal_state: AgentRunTerminalState,
        question_sha256: str,
        skills_read: set[str],
        scope_ids_used: set[str],
        steps_used: int,
    ) -> None:
        """The task-tier run digest through the governed ``remember``
        built-in (tier="task" ONLY; ADR-019 long-term stays default-deny).
        Best-effort: a memory failure warns and NEVER affects the already-
        evidenced run result."""
        note = json.dumps(
            {
                "question_sha256": question_sha256,
                "skills_read": sorted(skills_read),
                "scope_ids_used": sorted(scope_ids_used),
                "terminal_state": terminal_state,
            },
            sort_keys=True,
        )
        try:
            await _builtins.remember(
                note=note,
                step_index=steps_used,
                memory_factory=self._memory_factory,
                run=run,
            )
        except Exception as exc:
            logger.warning(
                "agent.memory_digest_failed",
                extra={
                    "run_id": run.run_id,
                    "exception_class": type(exc).__name__,
                },
                exc_info=True,
            )


__all__ = (
    "AgentLoop",
    "AgentRecordLoader",
    "RunBoundKind",
)
