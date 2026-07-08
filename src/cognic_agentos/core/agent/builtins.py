"""M8 Task A10 (ADR-027) — the kernel-owned agent built-ins.

OFF the durable coverage gate: the substantive enforcement is UPSTREAM —
``core/agent/dispatch.py`` (on-gate) owns the read_skill ``skill_id`` sub-gate
(an unassigned id is refused BEFORE :func:`read_skill` is called) and the
governed ``MemoryAPI`` write gate (ADR-019) governs what :func:`remember`
may persist. These two functions carry only the execution glue:

* :func:`read_skill` — reads a hosted INSTRUCTION skill's body through the
  :class:`SkillBodyReader` seam. An unknown id raises ``LookupError`` — the
  dispatch sub-gate makes that unreachable for UNGRANTED ids; a
  granted-but-unhosted id surfaces as ``agent_tool_dispatch_failed`` via the
  dispatcher's exception arm (documented, deliberate).
* :func:`remember` — writes ONE task-tier run note through a kernel-built
  :class:`MemoryCallerContext`. ``long_term_writes_allowed=False`` is THE
  structural M9 boundary (an M8 agent can never durably learn) and the write
  is ``tier="task"`` ONLY — both test-pinned at
  ``tests/unit/core/agent/test_builtins.py``.

``core/agent`` fence: no ``portal`` / ``protocol`` / ``sdk`` / ``cli`` import
(``core.memory`` is core→core). The dispatch types are TYPE_CHECKING-only —
no runtime import cycle with ``core/agent/dispatch.py``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cognic_agentos.core.memory import SubjectRef
from cognic_agentos.core.memory._context import MemoryCallerContext

if TYPE_CHECKING:
    from cognic_agentos.core.agent.dispatch import (
        AgentRunContext,
        MemoryApiFactory,
        SkillBodyReader,
    )

__all__ = ["read_skill", "remember"]

#: The fixed governance declaration every ``remember`` note rides under —
#: run-scoped operational notes, never customer/payment data classes.
_REMEMBER_PURPOSE = "agent_run_notes"
_REMEMBER_DATA_CLASS = "operational_telemetry"


async def read_skill(*, skill_id: str, reader: SkillBodyReader) -> dict[str, Any]:
    """Read a hosted instruction skill's body (the ADR-027 §a M8 A7 source).

    ``skill_id`` is the GATE-1-VALIDATED id (the dispatch sub-gate refused any
    unassigned id before this call). Raises ``LookupError`` when the id is not
    a hosted instruction skill — granted-but-unhosted, surfaced by the
    dispatcher as ``agent_tool_dispatch_failed``.
    """
    loaded = reader.read(skill_id)
    if loaded is None:
        raise LookupError(f"skill {skill_id!r} is not hosted as an instruction skill")
    description, body = loaded
    return {"skill_id": skill_id, "description": description, "body": body}


async def remember(
    *,
    note: str,
    step_index: int,
    memory_factory: MemoryApiFactory,
    run: AgentRunContext,
) -> dict[str, Any]:
    """Persist ONE task-tier run note through the governed MemoryAPI.

    The :class:`MemoryCallerContext` is KERNEL-BUILT (no LLM-authored field
    reaches it): ``long_term_writes_allowed=False`` is THE structural M9
    boundary — combined with the ``tier="task"``-only write below, an M8
    agent structurally cannot create durable memory (ADR-019 default-deny
    long_term stays untouched until M9).
    """
    context = MemoryCallerContext(
        tenant_id=run.tenant_id,
        agent_id=run.agent_id,
        actor_id=run.originator_subject,
        served_subject=SubjectRef(kind="human", id=run.originator_subject),
        is_subagent=False,
        long_term_writes_allowed=False,  # THE structural M9 boundary
        cross_subject_recall=False,
        memory_read_capabilities=frozenset(),
        declared_purposes=frozenset({_REMEMBER_PURPOSE}),
        declared_data_classes=frozenset({_REMEMBER_DATA_CLASS}),
        risk_tier=run.record.risk_tier,
    )
    api = memory_factory(context)
    key = f"agent-note-{run.run_id}-{step_index}"
    await api.remember(
        key=key,
        value=note,
        tier="task",  # tier="task" ONLY — run-scoped, never durable
        data_classes=(_REMEMBER_DATA_CLASS,),
        purpose=_REMEMBER_PURPOSE,
    )
    return {"remembered": True, "key": key}
