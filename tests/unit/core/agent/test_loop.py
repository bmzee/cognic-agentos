"""M8 Task A11 (ADR-027) — AgentLoop reasoning-loop tests (CRITICAL CONTROLS).

The single-shot governed agent run: prompt built from the validated agent
record + granted capability surface (progressive disclosure — skill BODIES
reach the model ONLY via the ``read_skill`` built-in), gateway completions
iterated with round-top run bounds (max_steps / token_budget / wall_clock,
checked BEFORE the call), every LLM-authored tool call dispatched through the
REAL A10 :class:`AgentDispatcher` with refusals fed back as tool messages
(never terminating the run — the BAR-2 shape), digest-only ``agent.run.*``
evidence rows on a REAL in-memory :class:`DecisionHistoryStore`, and the
best-effort task-tier memory digest.

Fixture posture mirrors ``test_dispatch.py`` (spy/stub seams; gate 3 runs a
REAL :class:`AgentDispatchPolicy` over a stub OPA engine) + the
``core/run/test_executor.py`` REAL DecisionHistoryStore (in-memory sqlite —
the persisted rows are read back off the ``_decision_history`` table, where
``actor_id`` has been merged into the payload by the store).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
from collections.abc import AsyncIterator, Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.agent._types import (
    AgentAskResult,
    AgentGrantNotRequested,
    GrantedCapabilities,
    LoadedAgentRecord,
    PriorTurn,
)
from cognic_agentos.core.agent.dispatch import AgentDispatcher, AgentToolApprovalPending
from cognic_agentos.core.agent.loop import (
    AgentLoop,
    AgentRecordLoader,
    _build_system_prompt,
    _track_capability_use,
    _usage_token_counts,
)
from cognic_agentos.core.agent.policy import AgentDispatchPolicy
from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import (
    DecisionHistoryStore,
    _decision_history,
)
from cognic_agentos.core.entitlements import DataScope
from cognic_agentos.core.policy.engine import Decision
from cognic_agentos.llm.gateway import GatewayResponse, GatewayToolCall

# --- Shared fixture identities (mirror test_dispatch.py) ----------------------

_TENANT = "tenant-a"
_ORIGINATOR = "human:analyst@bank"
_AGENT_ID = "bank-analyst"
_ORACLE_REF = "cognic-tool-oracle-schema/run_readonly_query"
_OTHER_REF = "srv-b/other_tool"
_TOOL_CAPABILITY_CLASSES = {
    _ORACLE_REF: "data_query",
    _OTHER_REF: "unscoped",
}
_GRANTED_SKILL = "schema-summary"
_UNHOSTED_SKILL = "unhosted-skill"
_UNASSIGNED_SKILL = "atm-recon"
_SCOPE_ID = "customer-data"
_SCOPE = DataScope(
    scope_id=_SCOPE_ID,
    schema_name="BANK",
    objects=("V_CUSTOMERS", "V_ACCOUNTS"),
    proxy_db_identity="AGENT_RO",
)
_QUESTION = "How many tables?"

#: Default loop scalars threaded by ``_harness`` (Settings-shaped values).
_DEFAULT_MAX_STEPS = 6
_TOKEN_BUDGET = 24_000
_WALL_CLOCK_S = 120.0


def _generate_keypair() -> tuple[bytes, bytes]:
    """RSA-2048 keypair generated at test time → (private_pem, public_pem)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


@pytest.fixture(scope="module")
def keypair() -> tuple[bytes, bytes]:
    return _generate_keypair()


# --- Real in-memory DecisionHistoryStore (mirror core/run/test_executor.py) ---


@pytest.fixture
async def db(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'loop.db'}")
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id,
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=datetime.now(UTC),
                )
            )
    yield eng
    await eng.dispose()


async def _rows(db: AsyncEngine) -> list[Any]:
    """All persisted decision rows in chain-sequence order."""
    async with db.connect() as conn:
        result = await conn.execute(
            select(_decision_history).order_by(_decision_history.c.sequence)
        )
        return list(result.fetchall())


async def _rows_of_type(db: AsyncEngine, decision_type: str) -> list[Any]:
    return [r for r in await _rows(db) if r.event_type == decision_type]


# --- Builders ------------------------------------------------------------------


def _record(**overrides: Any) -> LoadedAgentRecord:
    base: dict[str, Any] = {
        "agent_id": _AGENT_ID,
        "persona_body": "You are the bank analyst.",
        "persona_sha256": hashlib.sha256(b"You are the bank analyst.").hexdigest(),
        "requested_skills": (_GRANTED_SKILL, _UNHOSTED_SKILL),
        "requested_tools": (_ORACLE_REF, _OTHER_REF),
        "max_steps": None,
        "risk_tier": "customer_data_read",
        "pack_version": "0.1.0",
        "signed_artefact_digest": None,
        "registered": True,
    }
    base.update(overrides)
    return LoadedAgentRecord(**base)


def _tc(name: str, call_id: str = "call_0", **arguments: Any) -> GatewayToolCall:
    return GatewayToolCall(id=call_id, name=name, arguments=arguments)


def _resp(
    content: str = "",
    *,
    tool_calls: tuple[GatewayToolCall, ...] = (),
    usage: dict[str, object] | None = None,
) -> GatewayResponse:
    return GatewayResponse(
        content=content,
        upstream_model="ollama/qwen3:8b",
        api_base=None,
        external=False,
        request_id="canned",
        tier="tier1",
        latency_ms=1,
        tool_calls=tool_calls,
        usage=usage,
    )


#: Default granted set — deliberately WITHOUT the stamped oracle tool so the
#: dispatcher never needs a signing key (test 13 grants it explicitly).
_DEFAULT_GRANTED = GrantedCapabilities(
    skills=frozenset({_GRANTED_SKILL}),
    tools=frozenset({_OTHER_REF}),
)


# --- Spies / stubs ---------------------------------------------------------------


class _FakeGateway:
    """Scripted gateway spy: records every ``completion(**kwargs)`` dict
    (``messages`` snapshotted — the loop appends to a LIVE list, so the
    recorded reference would otherwise mutate under later rounds) and pops
    canned :class:`GatewayResponse` objects; optionally raises."""

    def __init__(
        self,
        responses: list[GatewayResponse] | None = None,
        *,
        exc: Exception | None = None,
    ) -> None:
        self._responses = list(responses or [])
        self._exc = exc
        self.calls: list[dict[str, Any]] = []

    async def completion(self, **kwargs: Any) -> GatewayResponse:
        recorded = dict(kwargs)
        recorded["messages"] = [dict(m) for m in kwargs["messages"]]
        self.calls.append(recorded)
        if self._exc is not None:
            raise self._exc
        assert self._responses, "FakeGateway script exhausted"
        return self._responses.pop(0)


class _StubRecordLoader:
    """AgentRecordLoader conformer over an in-memory (tenant, agent) map."""

    def __init__(self, records: dict[tuple[str, str], LoadedAgentRecord]) -> None:
        self._records = records
        self.calls: list[dict[str, str]] = []

    async def load_for_agent(self, *, agent_id: str, tenant_id: str) -> LoadedAgentRecord | None:
        self.calls.append({"agent_id": agent_id, "tenant_id": tenant_id})
        return self._records.get((tenant_id, agent_id))


class _StubAssignments:
    """AssignmentStore-shaped stub (same async load_for_agent signature)."""

    def __init__(self, granted: GrantedCapabilities, *, exc: Exception | None = None) -> None:
        self._granted = granted
        self._exc = exc
        self.calls: list[dict[str, Any]] = []

    async def load_for_agent(
        self, *, tenant_id: str, agent_id: str, record: LoadedAgentRecord
    ) -> GrantedCapabilities:
        self.calls.append({"tenant_id": tenant_id, "agent_id": agent_id, "record": record})
        if self._exc is not None:
            raise self._exc
        return self._granted


class _StubEntitlements:
    def __init__(
        self,
        *,
        entitled: frozenset[str],
        scopes: dict[str, DataScope],
        action_entitled: bool,
    ) -> None:
        self._entitled = entitled
        self._scopes = scopes
        self._action_entitled = action_entitled

    async def entitled_scope_ids(self, *, tenant_id: str, subject: str) -> frozenset[str]:
        return self._entitled

    async def resolve_scope(self, *, tenant_id: str, scope_id: str) -> DataScope | None:
        return self._scopes.get(scope_id)

    async def entitled_action(
        self,
        *,
        tenant_id: str,
        subject: str,
        tool_identity: str,
    ) -> bool:
        return self._action_entitled


class _StubOPAEngine:
    """Fixed-verdict OPA engine behind the REAL AgentDispatchPolicy."""

    def __init__(self, *, allow: bool = True) -> None:
        self._allow = allow
        self.seen_inputs: list[dict[str, Any]] = []

    async def evaluate(self, *, decision_point: str, input: dict[str, Any]) -> Decision:
        self.seen_inputs.append(input)
        return Decision(
            allow=self._allow,
            rule_matched=decision_point,
            reasoning="stub",
            decision_data=None,
        )


class _SpyToolProxy:
    """AgentToolProxy conformer recording every call; configurable result."""

    def __init__(
        self,
        *,
        result: dict[str, Any] | None = None,
        exc: Exception | None = None,
    ) -> None:
        self._result = result if result is not None else {"rows": []}
        self._exc = exc
        self.calls: list[dict[str, Any]] = []

    async def call_tool(
        self,
        *,
        server_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        request_id: str,
        tenant_id: str,
        originator_subject: str,
        approval_request_id: UUID | None,
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "server_id": server_id,
                "tool_name": tool_name,
                "arguments": dict(arguments),
                "request_id": request_id,
                "tenant_id": tenant_id,
                "originator_subject": originator_subject,
                "approval_request_id": approval_request_id,
            }
        )
        if self._exc is not None:
            raise self._exc
        return self._result


class _SpySkillReader:
    def __init__(self, *, bodies: dict[str, tuple[str, str]] | None = None) -> None:
        self._bodies = bodies if bodies is not None else {}
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
    ) -> UUID:
        self.remember_calls.append(
            {
                "key": key,
                "value": value,
                "tier": tier,
                "data_classes": data_classes,
                "purpose": purpose,
            }
        )
        return uuid4()


class _SpyMemoryFactory:
    def __init__(self) -> None:
        self.api = _SpyMemoryApi()
        self.contexts: list[Any] = []

    def __call__(self, context: Any) -> Any:
        self.contexts.append(context)
        return self.api


class _ExplodingMemoryFactory:
    """Raises at mint time — drives the best-effort memory-digest arm."""

    def __call__(self, context: Any) -> Any:
        raise ValueError("memory backend down")


class _SteppingClock:
    """Injectable monotonic clock advancing by ``step`` per call."""

    def __init__(self, *, start: float = 0.0, step: float = 0.0) -> None:
        self._now = start
        self._step = step

    def __call__(self) -> float:
        current = self._now
        self._now += self._step
        return current


@dataclasses.dataclass
class _Harness:
    loop: AgentLoop
    gateway: _FakeGateway
    loader: _StubRecordLoader
    assignments: _StubAssignments
    proxy: _SpyToolProxy
    reader: _SpySkillReader
    memory: Any
    opa: _StubOPAEngine


def _harness(
    db: AsyncEngine,
    *,
    responses: list[GatewayResponse] | None = None,
    gateway_exc: Exception | None = None,
    record: LoadedAgentRecord | None = None,
    agent_known: bool = True,
    granted: GrantedCapabilities | None = None,
    assignments_exc: Exception | None = None,
    bodies: dict[str, tuple[str, str]] | None = None,
    entitled: frozenset[str] = frozenset(),
    scopes: dict[str, DataScope] | None = None,
    allow: bool = True,
    signing_key_pem: bytes | None = None,
    memory_factory: Any = None,
    default_max_steps: int = _DEFAULT_MAX_STEPS,
    run_token_budget: int = _TOKEN_BUDGET,
    run_wall_clock_s: float = _WALL_CLOCK_S,
    clock: Callable[[], float] | None = None,
    tool_capability_classes: Mapping[str, str] | None = None,
    action_entitled: bool = False,
    proxy_exc: Exception | None = None,
) -> _Harness:
    rec = record if record is not None else _record()
    loader = _StubRecordLoader({(_TENANT, _AGENT_ID): rec} if agent_known else {})
    assignments = _StubAssignments(
        granted if granted is not None else _DEFAULT_GRANTED, exc=assignments_exc
    )
    entitlements = _StubEntitlements(
        entitled=entitled,
        scopes=scopes or {},
        action_entitled=action_entitled,
    )
    opa = _StubOPAEngine(allow=allow)
    proxy = _SpyToolProxy(exc=proxy_exc)
    reader = _SpySkillReader(
        bodies=bodies
        if bodies is not None
        else {_GRANTED_SKILL: ("Schema summary", "# SKILL body")}
    )
    memory = memory_factory if memory_factory is not None else _SpyMemoryFactory()
    dh = DecisionHistoryStore(db)
    capability_classes = (
        tool_capability_classes if tool_capability_classes is not None else _TOOL_CAPABILITY_CLASSES
    )
    dispatcher = AgentDispatcher(
        entitlements=entitlements,  # type: ignore[arg-type]
        policy=AgentDispatchPolicy(opa_engine=opa),  # type: ignore[arg-type]
        tool_proxy=proxy,
        skill_reader=reader,
        memory_factory=memory,
        decision_history=dh,
        query_context_signing_key_pem=signing_key_pem,
        query_context_ttl_s=300.0,
        tool_capability_classes=capability_classes,
    )
    gateway = _FakeGateway(responses, exc=gateway_exc)
    kwargs: dict[str, Any] = {}
    if clock is not None:
        kwargs["clock"] = clock
    loop = AgentLoop(
        record_loader=loader,
        assignments=assignments,  # type: ignore[arg-type]
        gateway=gateway,  # type: ignore[arg-type]
        dispatcher=dispatcher,
        tool_capability_classes=capability_classes,
        skill_reader=reader,
        memory_factory=memory,
        decision_history=dh,
        default_max_steps=default_max_steps,
        run_token_budget=run_token_budget,
        run_wall_clock_s=run_wall_clock_s,
        **kwargs,
    )
    return _Harness(
        loop=loop,
        gateway=gateway,
        loader=loader,
        assignments=assignments,
        proxy=proxy,
        reader=reader,
        memory=memory,
        opa=opa,
    )


async def _ask(h: _Harness, question: str = _QUESTION) -> AgentAskResult:
    return await h.loop.ask(
        agent_id=_AGENT_ID,
        question=question,
        actor_tenant_id=_TENANT,
        actor_subject=_ORIGINATOR,
    )


# --- Test 1 — happy path -----------------------------------------------------------


class TestHappyPath:
    async def test_tool_round_then_answer_completes(self, db: AsyncEngine) -> None:
        """Round 0 = one granted read_skill call; round 1 = plain answer →
        ``completed`` with steps_used == 2; started + dispatch + completed
        rows all present with the ADR-027 §f dual identity; the task-tier
        memory digest is written through the governed remember built-in."""
        h = _harness(
            db,
            responses=[
                _resp(tool_calls=(_tc("read_skill", skill_id=_GRANTED_SKILL),)),
                _resp("The schema has 3 tables."),
            ],
        )
        result = await _ask(h)

        assert result.terminal_state == "completed"
        assert result.answer == "The schema has 3 tables."
        assert result.steps_used == 2
        assert result.refusal_reason is None
        assert result.run_id.startswith("agent-run-")

        rows = await _rows(db)
        assert [r.event_type for r in rows] == [
            "agent.run.started",
            "agent.run.dispatch",
            "agent.run.completed",
        ]
        for row in rows:
            # Dual identity: the ORIGINATOR is the store-merged actor_id
            # (human accountability); the AGENT rides the payload.
            assert row.payload["actor_id"] == _ORIGINATOR
            assert row.payload["agent_id"] == _AGENT_ID
            assert row.tenant_id == _TENANT
            assert row.payload["run_id"] == result.run_id

        started = rows[0]
        assert started.request_id == f"{result.run_id}-started"
        assert started.payload["originator_subject"] == _ORIGINATOR
        assert started.payload["max_steps"] == _DEFAULT_MAX_STEPS
        assert started.payload["token_budget"] == _TOKEN_BUDGET
        assert started.payload["wall_clock_s"] == _WALL_CLOCK_S

        completed = rows[2]
        assert completed.request_id == f"{result.run_id}-terminal"
        assert completed.payload["steps_used"] == 2
        assert completed.payload["prompt_tokens_total"] == 0
        assert completed.payload["completion_tokens_total"] == 0

        # The memory digest: ONE task-tier remember carrying the digest-note keys.
        assert len(h.memory.api.remember_calls) == 1
        digest = h.memory.api.remember_calls[0]
        assert digest["tier"] == "task"
        note = json.loads(digest["value"])
        assert set(note.keys()) == {
            "question_sha256",
            "skills_read",
            "scope_ids_used",
            "terminal_state",
        }
        assert note["question_sha256"] == hashlib.sha256(_QUESTION.encode()).hexdigest()
        assert note["skills_read"] == [_GRANTED_SKILL]
        assert note["scope_ids_used"] == []
        assert note["terminal_state"] == "completed"

    async def test_scope_ids_used_tracked_for_ok_oracle_dispatch(
        self, db: AsyncEngine, keypair: tuple[bytes, bytes]
    ) -> None:
        """An OK-dispatched run_readonly_query lands its scope_id in the
        memory digest (LOOP-side tracking off the ok outcome's call args)."""
        private_pem, _ = keypair
        h = _harness(
            db,
            responses=[
                _resp(tool_calls=(_tc("run_readonly_query", scope_id=_SCOPE_ID, sql="SELECT 1"),)),
                _resp("Two views are in scope."),
            ],
            granted=GrantedCapabilities(skills=frozenset(), tools=frozenset({_ORACLE_REF})),
            entitled=frozenset({_SCOPE_ID}),
            scopes={_SCOPE_ID: _SCOPE},
            signing_key_pem=private_pem,
        )
        result = await _ask(h)
        assert result.terminal_state == "completed"
        assert len(h.proxy.calls) == 1
        note = json.loads(h.memory.api.remember_calls[0]["value"])
        assert note["scope_ids_used"] == [_SCOPE_ID]
        assert note["skills_read"] == []


class TestPendingApprovalTerminal:
    async def test_pending_action_terminates_after_exactly_one_completion(
        self, db: AsyncEngine
    ) -> None:
        approval_id = "a1b2c3d4-1111-4222-8333-444455556666"
        h = _harness(
            db,
            responses=[
                _resp(
                    "model-authored proposal must not become the confirmation",
                    tool_calls=(_tc("other_tool", amount=10),),
                    usage={"prompt_tokens": 7, "completion_tokens": 3},
                ),
                _resp("a second completion would violate the pending terminal"),
            ],
            tool_capability_classes={_OTHER_REF: "action"},
            action_entitled=True,
            proxy_exc=AgentToolApprovalPending(
                approval_request_id=approval_id,
                flow="require_assigned",
            ),
        )

        result = await _ask(h)

        assert result == AgentAskResult(
            run_id=result.run_id,
            terminal_state="pending_approval",
            answer="Requested approval — #a1b2, pending.",
            steps_used=1,
            refusal_reason=None,
            prompt_tokens=7,
            completion_tokens=3,
            approval_request_id=approval_id,
        )
        assert len(h.gateway.calls) == 1
        rows = await _rows(db)
        assert [row.event_type for row in rows] == [
            "agent.run.started",
            "agent.run.dispatch",
            "agent.run.pending_approval",
        ]
        terminal = rows[-1]
        assert terminal.payload["approval_request_id"] == approval_id
        assert (
            terminal.payload["answer_sha256"] == hashlib.sha256(result.answer.encode()).hexdigest()
        )
        assert await _rows_of_type(db, "agent.run.completed") == []

    async def test_pending_without_approval_id_fails_loud_before_second_completion(
        self, db: AsyncEngine
    ) -> None:
        h = _harness(
            db,
            responses=[
                _resp(tool_calls=(_tc("other_tool", amount=10),)),
                _resp("must not run"),
            ],
            tool_capability_classes={_OTHER_REF: "action"},
            action_entitled=True,
            proxy_exc=AgentToolApprovalPending(
                approval_request_id="",
                flow="require_assigned",
            ),
        )

        with pytest.raises(RuntimeError, match="pending dispatch omitted approval_request_id"):
            await _ask(h)

        assert len(h.gateway.calls) == 1
        assert await _rows_of_type(db, "agent.run.pending_approval") == []


# --- Test 2 — refusal feedback (the BAR-2 shape) -------------------------------------


class TestRefusalFeedback:
    async def test_dispatch_refusal_feeds_back_and_model_answers_gracefully(
        self, db: AsyncEngine
    ) -> None:
        """An UNGRANTED tool call refuses ``agent_capability_not_assigned``;
        the refusal returns to the model as a tool message (NEVER terminating
        the run) and the model answers gracefully on round 1."""
        h = _harness(
            db,
            responses=[
                _resp(tool_calls=(_tc("made_up_tool", q="x"),)),
                _resp("I don't have access to that tool, so here is what I know."),
            ],
        )
        result = await _ask(h)

        assert result.terminal_state == "completed"
        assert result.answer != ""
        assert result.steps_used == 2

        # The recorded round-1 messages carry the refusal tool message.
        round1_messages = h.gateway.calls[1]["messages"]
        tool_messages = [m for m in round1_messages if m.get("role") == "tool"]
        assert len(tool_messages) == 1
        assert tool_messages[0]["tool_call_id"] == "call_0"
        fed_back = json.loads(tool_messages[0]["content"])
        assert fed_back == {
            "refused": True,
            "reason": "agent_capability_not_assigned",
            "message": "capability 'made_up_tool' is not assigned to this agent",
        }

        # The dispatch evidence row carries the refusal; the run completed.
        dispatch_rows = await _rows_of_type(db, "agent.run.dispatch")
        assert len(dispatch_rows) == 1
        assert dispatch_rows[0].payload["refusal_reason"] == "agent_capability_not_assigned"
        assert len(await _rows_of_type(db, "agent.run.completed")) == 1

    async def test_ok_dispatch_result_feeds_back_as_tool_message(self, db: AsyncEngine) -> None:
        """The ok arm: a granted plain tool's result dict is fed back verbatim
        as the tool message content (JSON-encoded)."""
        h = _harness(
            db,
            responses=[
                _resp(tool_calls=(_tc("other_tool", q="x"),)),
                _resp("done"),
            ],
        )
        result = await _ask(h)
        assert result.terminal_state == "completed"
        assert len(h.proxy.calls) == 1
        round1_messages = h.gateway.calls[1]["messages"]
        tool_messages = [m for m in round1_messages if m.get("role") == "tool"]
        assert json.loads(tool_messages[0]["content"]) == {"rows": []}
        # The assistant tool-calls message rides in the OpenAI wire shape.
        assistant = [m for m in round1_messages if m.get("role") == "assistant"]
        assert assistant[-1]["tool_calls"] == [
            {
                "id": "call_0",
                "type": "function",
                "function": {"name": "other_tool", "arguments": json.dumps({"q": "x"})},
            }
        ]


# --- Tests 3-5 — the round-top run bounds ---------------------------------------------


class TestRunBounds:
    async def test_max_steps_bound_record_override_beats_default(self, db: AsyncEngine) -> None:
        """``record.max_steps=1`` beats ``default_max_steps=6``: round 0
        dispatches, the round-1 top check fires → terminal ``refused`` /
        ``agent_max_steps_exceeded`` / ``bound == "max_steps"``."""
        h = _harness(
            db,
            record=_record(max_steps=1),
            responses=[
                _resp(tool_calls=(_tc("read_skill", skill_id=_GRANTED_SKILL),)),
            ],
        )
        result = await _ask(h)

        assert result.terminal_state == "refused"
        assert result.refusal_reason == "agent_max_steps_exceeded"
        assert result.steps_used == 1
        assert result.answer != ""

        refused_rows = await _rows_of_type(db, "agent.run.refused")
        assert len(refused_rows) == 1
        payload = refused_rows[0].payload
        assert payload["refusal_reason"] == "agent_max_steps_exceeded"
        assert payload["bound"] == "max_steps"
        assert payload["steps_used"] == 1
        # The started row records the EFFECTIVE (record-resolved) bound.
        started = (await _rows_of_type(db, "agent.run.started"))[0]
        assert started.payload["max_steps"] == 1
        # Exactly ONE completion call was made (the round-1 call never fires).
        assert len(h.gateway.calls) == 1

    async def test_token_budget_bound(self, db: AsyncEngine) -> None:
        """Canned round-0 usage exceeding the budget trips the round-1 top
        check → ``bound == "token_budget"``; the terminal row totals match
        the canned usage."""
        h = _harness(
            db,
            run_token_budget=100,
            responses=[
                _resp(
                    tool_calls=(_tc("read_skill", skill_id=_GRANTED_SKILL),),
                    usage={"prompt_tokens": 80, "completion_tokens": 40},
                ),
            ],
        )
        result = await _ask(h)

        assert result.terminal_state == "refused"
        assert result.refusal_reason == "agent_max_steps_exceeded"
        assert result.steps_used == 1
        refused_rows = await _rows_of_type(db, "agent.run.refused")
        payload = refused_rows[0].payload
        assert payload["bound"] == "token_budget"
        assert payload["prompt_tokens_total"] == 80
        assert payload["completion_tokens_total"] == 40

    async def test_wall_clock_bound(self, db: AsyncEngine) -> None:
        """An injected clock advancing 100s per call: start=0, round-0
        top=100 (≤150 — passes), round-1 top=200 (>150) → ``bound ==
        "wall_clock"``."""
        h = _harness(
            db,
            run_wall_clock_s=150.0,
            clock=_SteppingClock(step=100.0),
            responses=[
                _resp(tool_calls=(_tc("read_skill", skill_id=_GRANTED_SKILL),)),
            ],
        )
        result = await _ask(h)

        assert result.terminal_state == "refused"
        assert result.refusal_reason == "agent_max_steps_exceeded"
        refused_rows = await _rows_of_type(db, "agent.run.refused")
        assert refused_rows[0].payload["bound"] == "wall_clock"
        assert len(h.gateway.calls) == 1


# --- Test 6 — gateway exception → failed ---------------------------------------------


class _GatewayBoom(Exception):
    pass


class TestGatewayFailure:
    async def test_gateway_exception_terminates_failed_class_name_only(
        self, db: AsyncEngine
    ) -> None:
        secret = "SECRET-upstream-key-xyz"
        h = _harness(db, gateway_exc=_GatewayBoom(secret))
        result = await _ask(h)

        assert result.terminal_state == "failed"
        assert result.refusal_reason is None
        assert result.steps_used == 0
        assert result.answer != ""
        assert secret not in result.answer

        failed_rows = await _rows_of_type(db, "agent.run.failed")
        assert len(failed_rows) == 1
        payload = failed_rows[0].payload
        assert payload["error_class"] == "_GatewayBoom"
        # Class-name-only discipline: the raw exception text never lands in
        # ANY emitted payload.
        for row in await _rows(db):
            assert secret not in json.dumps(row.payload)


# --- Test 7 — prompt shaping (progressive disclosure) --------------------------------


class TestPromptShaping:
    async def test_unassigned_skill_invisible_and_granted_body_withheld(
        self, db: AsyncEngine
    ) -> None:
        """An unassigned skill's id appears NOWHERE in the system prompt nor
        in any advertised tool spec; a granted hosted skill's DESCRIPTION
        appears while its BODY does not (bodies reach the model ONLY via
        ``read_skill``)."""
        body_canary = "UNIQUE-SKILL-BODY-CANARY"
        h = _harness(
            db,
            bodies={_GRANTED_SKILL: ("Schema summary description", body_canary)},
            responses=[_resp("hello")],
        )
        result = await _ask(h)
        assert result.terminal_state == "completed"

        system_content = h.gateway.calls[0]["messages"][0]["content"]
        assert h.gateway.calls[0]["messages"][0]["role"] == "system"
        assert "You are the bank analyst." in system_content
        assert f"- {_GRANTED_SKILL}: Schema summary description" in system_content
        assert body_canary not in system_content
        assert _UNASSIGNED_SKILL not in system_content
        # ... and the unassigned id is advertised in NO tool spec either.
        specs = h.gateway.calls[0]["tools"]
        rendered_specs = json.dumps([dataclasses.asdict(spec) for spec in specs], sort_keys=True)
        assert _UNASSIGNED_SKILL not in rendered_specs
        # The body canary never reaches the advertised surface either.
        assert body_canary not in rendered_specs

    async def test_unhosted_granted_skill_renders_name_only_line(self, db: AsyncEngine) -> None:
        """A granted skill the reader does not host renders a name-only
        index line (no ': <description>' suffix)."""
        h = _harness(
            db,
            granted=GrantedCapabilities(
                skills=frozenset({_GRANTED_SKILL, _UNHOSTED_SKILL}),
                tools=frozenset(),
            ),
            responses=[_resp("hello")],
        )
        await _ask(h)
        system_content = h.gateway.calls[0]["messages"][0]["content"]
        lines = system_content.splitlines()
        assert f"- {_UNHOSTED_SKILL}" in lines  # name-only line, exact
        assert f"- {_GRANTED_SKILL}: Schema summary" in lines

    async def test_no_skills_granted_omits_assigned_skills_section(self, db: AsyncEngine) -> None:
        h = _harness(
            db,
            granted=GrantedCapabilities(skills=frozenset(), tools=frozenset({_OTHER_REF})),
            responses=[_resp("hello")],
        )
        await _ask(h)
        system_content = h.gateway.calls[0]["messages"][0]["content"]
        assert "Assigned skills:" not in system_content
        assert "You are the bank analyst." in system_content

    def test_build_system_prompt_pure_helper(self) -> None:
        """Direct pins on the pure helper: description-only disclosure +
        deterministic sorted order + the kernel tool-use contract."""
        reader = _SpySkillReader(bodies={"b-skill": ("B description", "B BODY")})
        prompt = _build_system_prompt(
            record=_record(),
            granted=GrantedCapabilities(
                skills=frozenset({"b-skill", "a-skill"}), tools=frozenset()
            ),
            reader=reader,
        )
        a_index = prompt.index("- a-skill")
        b_index = prompt.index("- b-skill: B description")
        assert a_index < b_index  # sorted skill order
        assert "B BODY" not in prompt
        assert "read_skill" in prompt  # the tool-use contract paragraph
        assert prompt.startswith("You are the bank analyst.")


# --- Test 8 — per-call identity threading (the BAR-5 seam) ----------------------------


class TestCompletionCallIdentity:
    async def test_every_call_carries_workforce_tenant_and_request_ids(
        self, db: AsyncEngine
    ) -> None:
        h = _harness(
            db,
            responses=[
                _resp(tool_calls=(_tc("read_skill", skill_id=_GRANTED_SKILL),)),
                _resp(tool_calls=(_tc("remember", call_id="call_1", note="n"),)),
                _resp("done"),
            ],
        )
        result = await _ask(h)
        assert result.terminal_state == "completed"
        assert len(h.gateway.calls) == 3
        for n, call in enumerate(h.gateway.calls):
            assert call["agent_workforce_id"] == _AGENT_ID  # BAR-5: == agent_id
            assert call["tenant_id"] == _TENANT
            assert call["request_id"] == f"{result.run_id}-s{n}"
            assert len(call["request_id"]) <= 64
            assert call["tier"] == "tier1"


# --- Test 9 — round-shared step_index --------------------------------------------------


class TestRoundStepIndex:
    async def test_two_tool_calls_share_round_step_index_in_wire_order(
        self, db: AsyncEngine
    ) -> None:
        """One round with TWO tool_calls: both dispatch rows carry
        ``step_index == 0`` (the round IS the reasoning step) and are
        dispatched sequentially in wire order."""
        h = _harness(
            db,
            responses=[
                _resp(
                    tool_calls=(
                        _tc("read_skill", call_id="call_0", skill_id=_GRANTED_SKILL),
                        _tc("remember", call_id="call_1", note="check ledger"),
                    )
                ),
                _resp("done"),
            ],
        )
        result = await _ask(h)
        assert result.terminal_state == "completed"

        dispatch_rows = await _rows_of_type(db, "agent.run.dispatch")
        assert len(dispatch_rows) == 2
        assert [r.payload["capability_ref"] for r in dispatch_rows] == [
            "read_skill",
            "remember",
        ]  # wire order preserved (chain-sequence order)
        assert [r.payload["step_index"] for r in dispatch_rows] == [0, 0]

        # Both tool messages fed back, in wire order, before round 1.
        round1_messages = h.gateway.calls[1]["messages"]
        tool_ids = [m["tool_call_id"] for m in round1_messages if m.get("role") == "tool"]
        assert tool_ids == ["call_0", "call_1"]


# --- Test 10 — digest-only evidence -----------------------------------------------------


class TestDigestOnlyEvidence:
    async def test_question_and_answer_plaintext_in_no_payload(self, db: AsyncEngine) -> None:
        question = "QUESTION-CANARY: how exposed is account 12345?"
        answer = "ANSWER-CANARY: the exposure is 42 lakh."
        h = _harness(
            db,
            responses=[
                _resp(tool_calls=(_tc("read_skill", skill_id=_GRANTED_SKILL),)),
                _resp(answer),
            ],
        )
        result = await _ask(h, question=question)
        assert result.answer == answer  # plaintext returns ONLY on the result

        rows = await _rows(db)
        assert len(rows) == 3
        for row in rows:
            rendered = json.dumps(row.payload)
            assert question not in rendered
            assert answer not in rendered

        started = rows[0]
        question_encoded = question.encode("utf-8")
        assert started.payload["question_sha256"] == (hashlib.sha256(question_encoded).hexdigest())
        assert started.payload["question_bytes"] == len(question_encoded)
        assert len(started.request_id) <= 64

        terminal = rows[2]
        answer_encoded = answer.encode("utf-8")
        assert terminal.payload["answer_sha256"] == (hashlib.sha256(answer_encoded).hexdigest())
        assert terminal.payload["answer_bytes"] == len(answer_encoded)
        assert len(terminal.request_id) <= 64


# --- Test 11 — memory digest is best-effort ---------------------------------------------


class TestMemoryDigestBestEffort:
    async def test_memory_failure_warns_and_run_unaffected(
        self, db: AsyncEngine, caplog: pytest.LogCaptureFixture
    ) -> None:
        h = _harness(
            db,
            memory_factory=_ExplodingMemoryFactory(),
            responses=[_resp("the answer")],
        )
        with caplog.at_level(logging.WARNING, logger="cognic_agentos.core.agent.loop"):
            result = await _ask(h)

        assert result.terminal_state == "completed"
        assert result.answer == "the answer"
        assert result.steps_used == 1
        # The terminal evidence row landed BEFORE the digest attempt.
        assert len(await _rows_of_type(db, "agent.run.completed")) == 1
        warnings = [r for r in caplog.records if r.getMessage() == "agent.memory_digest_failed"]
        assert len(warnings) == 1

    async def test_memory_digest_written_on_refused_terminal(self, db: AsyncEngine) -> None:
        """The digest is written on EVERY terminal state — refused included."""
        h = _harness(
            db,
            record=_record(max_steps=1),
            responses=[
                _resp(tool_calls=(_tc("read_skill", skill_id=_GRANTED_SKILL),)),
            ],
        )
        result = await _ask(h)
        assert result.terminal_state == "refused"
        note = json.loads(h.memory.api.remember_calls[0]["value"])
        assert note["terminal_state"] == "refused"
        assert note["skills_read"] == [_GRANTED_SKILL]


# --- Test 12 — pre-flight (NO run minted, NO evidence) -----------------------------------


class TestPreflight:
    async def test_unknown_agent_raises_lookup_error_no_rows(self, db: AsyncEngine) -> None:
        h = _harness(db, agent_known=False)
        with pytest.raises(LookupError):
            await _ask(h)
        assert await _rows(db) == []
        assert h.gateway.calls == []

    async def test_unregistered_agent_raises_lookup_error_no_rows(self, db: AsyncEngine) -> None:
        h = _harness(db, record=_record(registered=False))
        with pytest.raises(LookupError):
            await _ask(h)
        assert await _rows(db) == []
        assert h.gateway.calls == []

    async def test_grant_not_requested_propagates_no_rows(self, db: AsyncEngine) -> None:
        """The ingestion-invariant raise (config-drift emergency) propagates
        fail-loud out of ``ask()`` — no run minted, no evidence."""
        h = _harness(
            db,
            assignments_exc=AgentGrantNotRequested(
                capability_ref="srv-x/never-requested", capability_kind="tool"
            ),
        )
        with pytest.raises(AgentGrantNotRequested):
            await _ask(h)
        assert await _rows(db) == []
        assert h.gateway.calls == []


# --- Test 13 — deployment fail-loud passthrough ------------------------------------------


class TestDeploymentFailLoud:
    async def test_dispatcher_runtime_error_propagates_uncaught(self, db: AsyncEngine) -> None:
        """The dispatcher's fail-loud missing-signing-key RuntimeError (a
        DEPLOYMENT error) propagates out of ``ask()`` — NEVER converted to a
        ``failed`` terminal."""
        h = _harness(
            db,
            granted=GrantedCapabilities(skills=frozenset(), tools=frozenset({_ORACLE_REF})),
            entitled=frozenset({_SCOPE_ID}),
            scopes={_SCOPE_ID: _SCOPE},
            signing_key_pem=None,  # stamped tool granted; kernel has no key
            responses=[
                _resp(tool_calls=(_tc("run_readonly_query", scope_id=_SCOPE_ID, sql="SELECT 1"),)),
            ],
        )
        with pytest.raises(RuntimeError):
            await _ask(h)
        # The run was minted (started row) but NO terminal row exists.
        assert len(await _rows_of_type(db, "agent.run.started")) == 1
        assert await _rows_of_type(db, "agent.run.failed") == []
        assert await _rows_of_type(db, "agent.run.refused") == []
        assert await _rows_of_type(db, "agent.run.completed") == []


# --- Pure-helper direct pins ---------------------------------------------------------------


class TestUsageTokenCounts:
    @pytest.mark.parametrize(
        ("usage", "expected"),
        [
            (None, (0, 0)),
            ("not-a-dict", (0, 0)),
            ({}, (0, 0)),
            ({"prompt_tokens": 10, "completion_tokens": 5}, (10, 5)),
            ({"prompt_tokens": 10}, (10, 0)),
            ({"completion_tokens": 5}, (0, 5)),
            # bool is an int subclass — excluded per the A6 bool-guard precedent.
            ({"prompt_tokens": True, "completion_tokens": False}, (0, 0)),
            ({"prompt_tokens": 3.5, "completion_tokens": "7"}, (0, 0)),
            ({"prompt_tokens": None, "completion_tokens": None}, (0, 0)),
        ],
        ids=[
            "none",
            "non-dict",
            "empty",
            "both-ints",
            "prompt-only",
            "completion-only",
            "bools-excluded",
            "float-and-str",
            "none-values",
        ],
    )
    def test_usage_token_counts(self, usage: Any, expected: tuple[int, int]) -> None:
        assert _usage_token_counts(usage) == expected


class TestTrackCapabilityUse:
    def test_tracks_read_skill_and_oracle_scope(self) -> None:
        skills: set[str] = set()
        scopes: set[str] = set()
        _track_capability_use(
            _tc("read_skill", skill_id="s-1"), skills_read=skills, scope_ids_used=scopes
        )
        _track_capability_use(
            _tc("run_readonly_query", scope_id="sc-1", sql="SELECT 1"),
            skills_read=skills,
            scope_ids_used=scopes,
        )
        _track_capability_use(_tc("other_tool", q="x"), skills_read=skills, scope_ids_used=scopes)
        assert skills == {"s-1"}
        assert scopes == {"sc-1"}

    def test_defensive_non_str_args_not_tracked(self) -> None:
        """Defensive isinstance guards (the dispatcher validates both for ok
        outcomes) — direct-tested on the pure helper."""
        skills: set[str] = set()
        scopes: set[str] = set()
        _track_capability_use(
            _tc("read_skill", skill_id=7), skills_read=skills, scope_ids_used=scopes
        )
        _track_capability_use(
            _tc("run_readonly_query", scope_id=None, sql="SELECT 1"),
            skills_read=skills,
            scope_ids_used=scopes,
        )
        assert skills == set()
        assert scopes == set()


class TestRecordLoaderProtocol:
    def test_stub_loader_conforms_structurally(self) -> None:
        """AgentRecordLoader is a structural Protocol — the test stub (and the
        A13 harness conformer) satisfy it without inheritance."""
        loader: AgentRecordLoader = _StubRecordLoader({})
        assert loader is not None


class TestPriorContextAdditive:
    """ADR-028 M8.5-B (Sprint B, Task 4) — the additive ``prior_context`` input.

    Pins the properties BAR 1 and BAR 2 depend on: replayed turns sit between
    the system prompt and the new question, the default is empty (so every M8
    call site is behaviour-unchanged), and the started chain row records the
    prior context DIGEST-ONLY.
    """

    async def test_default_prior_context_is_empty_m8_shape_unchanged(self, db: AsyncEngine) -> None:
        h = _harness(db, responses=[_resp("done")])
        await _ask(h)
        roles = [m["role"] for m in h.gateway.calls[0]["messages"]]
        assert roles == ["system", "user"]

    async def test_prior_turns_sit_between_system_and_new_question(self, db: AsyncEngine) -> None:
        h = _harness(db, responses=[_resp("Beta Corp")])
        await h.loop.ask(
            agent_id=_AGENT_ID,
            question="and the second largest?",
            actor_tenant_id=_TENANT,
            actor_subject=_ORIGINATOR,
            prior_context=(
                PriorTurn(role="user", content="who is the largest depositor?"),
                PriorTurn(role="assistant", content="Acme Corp"),
            ),
        )
        msgs = h.gateway.calls[0]["messages"]
        assert [m["role"] for m in msgs] == ["system", "user", "assistant", "user"]
        assert msgs[1]["content"] == "who is the largest depositor?"
        assert msgs[2]["content"] == "Acme Corp"
        assert msgs[3]["content"] == "and the second largest?"

    async def test_started_row_records_prior_context_count_and_digest_only(
        self, db: AsyncEngine
    ) -> None:
        h = _harness(db, responses=[_resp("ok")])
        await h.loop.ask(
            agent_id=_AGENT_ID,
            question="q",
            actor_tenant_id=_TENANT,
            actor_subject=_ORIGINATOR,
            prior_context=(PriorTurn(role="user", content="earlier secret"),),
        )
        rows = await _rows_of_type(db, "agent.run.started")
        payload = rows[0].payload
        assert payload["prior_context_turns"] == 1
        assert len(payload["prior_context_sha256"]) == 64
        assert "earlier secret" not in str(payload)

    async def test_empty_prior_context_still_records_zero_and_a_digest(
        self, db: AsyncEngine
    ) -> None:
        h = _harness(db, responses=[_resp("ok")])
        await _ask(h)
        payload = (await _rows_of_type(db, "agent.run.started"))[0].payload
        assert payload["prior_context_turns"] == 0
        assert len(payload["prior_context_sha256"]) == 64


class TestRealTokenAccounting:
    """Sprint B Task 4 — AgentAskResult surfaces REAL token counts.

    Required fields, never defaulted: a cumulative budget fed by zeros reads as
    ENFORCED in the evidence and is worse than no bound at all.
    """

    async def test_ask_result_surfaces_real_token_counts(self, db: AsyncEngine) -> None:
        h = _harness(
            db,
            responses=[_resp("ok", usage={"prompt_tokens": 11, "completion_tokens": 7})],
        )
        result = await _ask(h)
        assert result.prompt_tokens == 11
        assert result.completion_tokens == 7

    async def test_token_counts_accumulate_across_rounds(self, db: AsyncEngine) -> None:
        h = _harness(
            db,
            responses=[
                _resp(
                    tool_calls=(_tc("read_skill", skill_id=_GRANTED_SKILL),),
                    usage={"prompt_tokens": 5, "completion_tokens": 2},
                ),
                _resp("answer", usage={"prompt_tokens": 6, "completion_tokens": 3}),
            ],
        )
        result = await _ask(h)
        assert result.prompt_tokens == 11
        assert result.completion_tokens == 5

    async def test_token_fields_are_required_not_defaulted(self) -> None:
        """A caller cannot silently construct a zero-token result."""
        with pytest.raises(TypeError):
            AgentAskResult(  # type: ignore[call-arg]
                run_id="r",
                terminal_state="completed",
                answer="a",
                steps_used=1,
                refusal_reason=None,
            )
