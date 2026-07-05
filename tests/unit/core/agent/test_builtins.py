"""M8 Task A10 (ADR-027) — kernel-owned agent built-ins tests.

``builtins.py`` is OFF the durable gate (enforcement is upstream: the dispatch
gate 1 read_skill sub-gate + the governed MemoryAPI); these tests pin its two
structural contracts anyway:

* ``remember`` constructs the EXACT :class:`MemoryCallerContext` — with
  ``long_term_writes_allowed=False`` (THE structural M9 boundary: an M8 agent
  can never durably learn) and writes ``tier="task"`` ONLY.
* ``read_skill`` returns the (skill_id, description, body) triple and raises
  ``LookupError`` on an unknown id (the dispatch sub-gate makes that
  unreachable for UNGRANTED ids; a granted-but-unhosted id surfaces as
  ``agent_tool_dispatch_failed`` via the dispatcher's exception arm).
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from cognic_agentos.core.agent import builtins as agent_builtins
from cognic_agentos.core.agent._types import GrantedCapabilities, LoadedAgentRecord
from cognic_agentos.core.agent.dispatch import AgentRunContext
from cognic_agentos.core.memory import SubjectRef
from cognic_agentos.core.memory._context import MemoryCallerContext

_TENANT = "tenant-a"
_ORIGINATOR = "human:analyst@bank"
_AGENT_ID = "bank-analyst"


def _run(**overrides: Any) -> AgentRunContext:
    base: dict[str, Any] = {
        "run_id": "run-0001",
        "tenant_id": _TENANT,
        "originator_subject": _ORIGINATOR,
        "agent_id": _AGENT_ID,
        "granted": GrantedCapabilities(skills=frozenset({"schema-summary"}), tools=frozenset()),
        "max_steps": 6,
        "record": LoadedAgentRecord(
            agent_id=_AGENT_ID,
            persona_body="You are the bank analyst.",
            persona_sha256="0" * 64,
            requested_skills=("schema-summary",),
            requested_tools=(),
            max_steps=6,
            risk_tier="customer_data_read",
            pack_version="0.1.0",
            signed_artefact_digest=None,
            registered=True,
        ),
    }
    base.update(overrides)
    return AgentRunContext(**base)


class _StubReader:
    def __init__(self, *, bodies: dict[str, tuple[str, str]]) -> None:
        self._bodies = bodies
        self.calls: list[str] = []

    def read(self, skill_id: str) -> tuple[str, str] | None:
        self.calls.append(skill_id)
        return self._bodies.get(skill_id)


class _SpyMemoryApi:
    def __init__(self) -> None:
        self.remember_calls: list[dict[str, Any]] = []

    async def remember(
        self,
        key: str,
        value: object,
        *,
        tier: str,
        data_classes: tuple[str, ...],
        purpose: str,
    ) -> uuid.UUID:
        self.remember_calls.append(
            {
                "key": key,
                "value": value,
                "tier": tier,
                "data_classes": data_classes,
                "purpose": purpose,
            }
        )
        return uuid.uuid4()


class _SpyMemoryFactory:
    def __init__(self) -> None:
        self.api = _SpyMemoryApi()
        self.contexts: list[MemoryCallerContext] = []

    def __call__(self, context: MemoryCallerContext) -> _SpyMemoryApi:
        self.contexts.append(context)
        return self.api


# --- read_skill -----------------------------------------------------------------


class TestReadSkill:
    async def test_returns_the_triple(self) -> None:
        reader = _StubReader(bodies={"schema-summary": ("Schema summary", "# SKILL body")})
        result = await agent_builtins.read_skill(skill_id="schema-summary", reader=reader)
        assert result == {
            "skill_id": "schema-summary",
            "description": "Schema summary",
            "body": "# SKILL body",
        }
        assert reader.calls == ["schema-summary"]

    async def test_unknown_id_raises_lookup_error(self) -> None:
        reader = _StubReader(bodies={})
        with pytest.raises(LookupError):
            await agent_builtins.read_skill(skill_id="not-hosted", reader=reader)


# --- remember -------------------------------------------------------------------


class TestRemember:
    async def test_constructs_the_exact_memory_caller_context(self) -> None:
        """Every field pinned — ``long_term_writes_allowed is False`` IS the
        structural M9 boundary (an M8 agent can never write durable memory)."""
        factory = _SpyMemoryFactory()
        run = _run()
        await agent_builtins.remember(
            note="check the ATM ledger", step_index=2, memory_factory=factory, run=run
        )
        assert len(factory.contexts) == 1
        context = factory.contexts[0]
        assert isinstance(context, MemoryCallerContext)
        assert context.tenant_id == _TENANT
        assert context.agent_id == _AGENT_ID
        assert context.actor_id == _ORIGINATOR
        assert context.served_subject == SubjectRef(kind="human", id=_ORIGINATOR)
        assert context.served_subject.kind == "human"
        assert context.is_subagent is False
        assert context.long_term_writes_allowed is False  # THE structural M9 boundary
        assert context.cross_subject_recall is False
        assert context.memory_read_capabilities == frozenset()
        assert context.declared_purposes == frozenset({"agent_run_notes"})
        assert context.declared_data_classes == frozenset({"operational_telemetry"})
        assert context.risk_tier == run.record.risk_tier

    async def test_writes_task_tier_only(self) -> None:
        """``tier="task"`` ONLY (test-pinned): run-scoped notes, never durable."""
        factory = _SpyMemoryFactory()
        await agent_builtins.remember(
            note="check the ATM ledger", step_index=0, memory_factory=factory, run=_run()
        )
        assert len(factory.api.remember_calls) == 1
        recorded = factory.api.remember_calls[0]
        assert recorded["tier"] == "task"
        assert recorded["value"] == "check the ATM ledger"
        assert recorded["data_classes"] == ("operational_telemetry",)
        assert recorded["purpose"] == "agent_run_notes"

    async def test_key_shape_and_return_value(self) -> None:
        factory = _SpyMemoryFactory()
        run = _run(run_id="run-7f3a")
        result = await agent_builtins.remember(
            note="n", step_index=5, memory_factory=factory, run=run
        )
        expected_key = "agent-note-run-7f3a-5"
        assert factory.api.remember_calls[0]["key"] == expected_key
        assert result == {"remembered": True, "key": expected_key}
