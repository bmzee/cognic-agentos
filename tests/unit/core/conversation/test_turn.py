"""ADR-028 M8.5-B (Sprint B, Task 6) — ConversationTurnExecutor.

REAL ConversationStore + REAL DecisionHistoryStore (file-backed sqlite) wrapped
in a call-recording spy, plus a stub AgentLoop that records whether it was
invoked at all.

The load-bearing pins:
  * terminal-state / bounds refusals fire with ZERO AgentLoop invocation
  * ``claim_turn`` (the ONLY creator-scoped step) precedes ``append_turn``
  * a cross-actor post raises ConversationNotFound with ZERO append_turn
  * the cumulative token budget is fed by REAL counts, never zeros
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.cli._governance_vocab import HookPhase
from cognic_agentos.core.agent._types import AgentAskResult, LoadedAgentRecord
from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.conversation._types import (
    ConversationNotFound,
    ConversationState,
    ConversationTurnRefused,
)
from cognic_agentos.core.conversation.read_model import ConversationReadModel
from cognic_agentos.core.conversation.storage import ConversationStore
from cognic_agentos.core.conversation.turn import (
    ConversationHookEvidenceError,
    ConversationHookGovernance,
    ConversationHookOutcome,
    ConversationHookScanResult,
    ConversationTurnExecutor,
    TurnResult,
)
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.harness.hook_registry import ConversationHookGuardAdapter
from cognic_agentos.packs.hooks.dispatcher import HookDispatcher
from cognic_agentos.packs.hooks.registry import (
    HookDeclaration,
    HookRegistry,
    VerifiedHookPack,
)
from cognic_agentos.sdk.hook import Hook, HookContext, HookResult

pytestmark = pytest.mark.asyncio

_TENANT = "t1"
_SUBJECT = "s1"


class _SpyLoop:
    """Records every ``ask`` kwargs dict; returns a canned result."""

    def __init__(
        self,
        *,
        prompt_tokens: int = 3,
        completion_tokens: int = 2,
        terminal_state: str = "completed",
        answer: str = "Acme Corp",
        approval_request_id: str | None = None,
        history: DecisionHistoryStore | None = None,
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        self._pt = prompt_tokens
        self._ct = completion_tokens
        self._terminal_state = terminal_state
        self._answer = answer
        self._approval_request_id = approval_request_id
        self._history = history

    async def ask(self, **kw: Any) -> AgentAskResult:
        self.calls.append(kw)
        if self._history is not None:
            question = kw["question"]
            await self._history.append(
                DecisionRecord(
                    decision_type="agent.run.started",
                    request_id="agent-run-1-started",
                    payload={
                        "run_id": "agent-run-1",
                        "agent_id": "analyst",
                        "actor_id": _SUBJECT,
                        "originator_subject": _SUBJECT,
                        "question_sha256": hashlib.sha256(question.encode()).hexdigest(),
                        "question_bytes": len(question.encode()),
                        "max_steps": 6,
                        "token_budget": 60_000,
                        "wall_clock_s": 300.0,
                        "prior_context_turns": len(kw["prior_context"]),
                        "prior_context_sha256": "b" * 64,
                    },
                    actor_id=_SUBJECT,
                    tenant_id=_TENANT,
                )
            )
            await self._history.append(
                DecisionRecord(
                    decision_type=f"agent.run.{self._terminal_state}",
                    request_id="agent-run-1-terminal",
                    payload={
                        "run_id": "agent-run-1",
                        "agent_id": "analyst",
                        "actor_id": _SUBJECT,
                        "originator_subject": _SUBJECT,
                        "answer_sha256": hashlib.sha256(self._answer.encode()).hexdigest(),
                        "answer_bytes": len(self._answer.encode()),
                        "steps_used": 1,
                        "prompt_tokens_total": self._pt,
                        "completion_tokens_total": self._ct,
                    },
                    actor_id=_SUBJECT,
                    tenant_id=_TENANT,
                )
            )
        return AgentAskResult(
            run_id="agent-run-1",
            terminal_state=self._terminal_state,  # type: ignore[arg-type]
            answer=self._answer,
            steps_used=1,
            refusal_reason=None,
            prompt_tokens=self._pt,
            completion_tokens=self._ct,
            approval_request_id=self._approval_request_id,
        )


class _RaisingLoop:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def ask(self, **kw: Any) -> AgentAskResult:
        self.calls.append(kw)
        raise RuntimeError("gateway exploded")


class _PassHookGuard:
    """Records both phases and leaves the canonical payload unchanged."""

    def __init__(
        self,
        *,
        history: DecisionHistoryStore | None = None,
        transform_output: Callable[[bytes], bytes] | None = None,
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        self._history = history
        self._transform_output = transform_output

    def governance_for_agent(self, *, agent_id: str) -> ConversationHookGovernance:
        assert agent_id == "analyst"
        return ConversationHookGovernance(
            pack_id="cognic-agent-analyst",
            declared_data_classes=("internal",),
            manifest_purpose="operational_telemetry",
        )

    def turn_timeout_budget_s(self) -> float:
        return 0.0

    async def scan(self, **kw: Any) -> ConversationHookScanResult:
        self.calls.append(kw)
        final_payload = (
            self._transform_output(kw["payload"])
            if kw["phase"] == "conversation_output" and self._transform_output is not None
            else kw["payload"]
        )
        if final_payload != kw["payload"]:
            kw["validate_transformed_payload"](final_payload)
        if self._history is not None:
            payload_digest = hashlib.sha256(kw["payload"]).hexdigest()
            output_digest = hashlib.sha256(final_payload).hexdigest()
            projector = kw.get("evidence_value_projector")
            input_value_digest = (
                hashlib.sha256(projector(kw["payload"])).hexdigest()
                if projector is not None
                else None
            )
            output_value_digest = (
                hashlib.sha256(projector(final_payload)).hexdigest()
                if projector is not None
                else None
            )
            await self._history.append(
                DecisionRecord(
                    decision_type="hook.decision",
                    request_id=kw["request_id"],
                    payload={
                        "event_type": "hook.decision",
                        "phase": kw["phase"],
                        "hook_id": f"{kw['phase']}-safety",
                        "pack_distribution_name": "cognic-hook-test",
                        "pack_distribution_version": "0.1.0",
                        "outcome": "passed",
                        "failure_mode": None,
                        "policy_reason": None,
                        "policy_input_digest": payload_digest,
                        "hook_input_digest": payload_digest,
                        "hook_output_digest": output_digest,
                        "request_id": kw["request_id"],
                        "tenant_id": _TENANT,
                        "decision": (
                            "mask"
                            if kw["phase"] == "conversation_output"
                            and self._transform_output is not None
                            else "pass"
                        ),
                        "exception_class": None,
                        "hook_input_value_sha256": input_value_digest,
                        "hook_output_value_sha256": output_value_digest,
                        "conversation_id": str(kw["conversation_id"]),
                        "conversation_turn_seq": kw["turn_seq"],
                        **(
                            {
                                "output_origin": kw["output_origin"],
                                "agent_run_id": kw["agent_run_id"],
                                "approval_delivery_id": kw["approval_delivery_id"],
                            }
                            if kw["phase"] == "conversation_output"
                            else {}
                        ),
                    },
                    actor_id=_SUBJECT,
                    tenant_id=_TENANT,
                )
            )
        return ConversationHookScanResult(
            outcome="passed", final_payload=final_payload, hook_decision_count=1
        )


class _ScriptedHookGuard(_PassHookGuard):
    def __init__(
        self,
        *,
        input_outcome: ConversationHookOutcome = "passed",
        output_outcome: ConversationHookOutcome = "passed",
        transform_input: Callable[[bytes], bytes] | None = None,
        transform_output: Callable[[bytes], bytes] | None = None,
        raise_phase: str | None = None,
    ) -> None:
        super().__init__()
        self._input_outcome = input_outcome
        self._output_outcome = output_outcome
        self._transform_input = transform_input
        self._transform_output = transform_output
        self._raise_phase = raise_phase

    async def scan(self, **kw: Any) -> ConversationHookScanResult:
        self.calls.append(kw)
        phase = kw["phase"]
        if phase == self._raise_phase:
            raise RuntimeError("secret hook failure detail")
        outcome = self._input_outcome if phase == "conversation_input" else self._output_outcome
        transform = (
            self._transform_input if phase == "conversation_input" else self._transform_output
        )
        payload = kw["payload"] if transform is None else transform(kw["payload"])
        return ConversationHookScanResult(
            outcome=outcome, final_payload=payload, hook_decision_count=1
        )


@pytest.mark.parametrize(
    "governance",
    [
        {
            "pack_id": "",
            "declared_data_classes": ("internal",),
            "manifest_purpose": "operational_telemetry",
        },
        {
            "pack_id": "cognic-agent-analyst",
            "declared_data_classes": ("internal",),
            "manifest_purpose": "",
        },
        {
            "pack_id": "cognic-agent-analyst",
            "declared_data_classes": (),
            "manifest_purpose": "operational_telemetry",
        },
        {
            "pack_id": "cognic-agent-analyst",
            "declared_data_classes": ("internal", "internal"),
            "manifest_purpose": "operational_telemetry",
        },
        {
            "pack_id": "cognic-agent-analyst",
            "declared_data_classes": ("restricted", "internal"),
            "manifest_purpose": "operational_telemetry",
        },
        {
            "pack_id": "cognic-agent-analyst",
            "declared_data_classes": ("",),
            "manifest_purpose": "operational_telemetry",
        },
    ],
)
async def test_hook_governance_rejects_incomplete_or_noncanonical_shape(
    governance: dict[str, Any],
) -> None:
    with pytest.raises(ValueError):
        ConversationHookGovernance(**governance)


class _OrderRecordingStore:
    """Delegates to the REAL store while recording the call order + kwargs."""

    def __init__(self, inner: ConversationStore) -> None:
        self._inner = inner
        self.order: list[str] = []
        self.claim_kwargs: list[dict[str, Any]] = []
        self.append_kwargs: list[dict[str, Any]] = []
        self.settle_refused_kwargs: list[dict[str, Any]] = []
        self.release_kwargs: list[dict[str, Any]] = []
        self.minted_claims: list[Any] = []

    async def claim_turn(self, conversation_id: uuid.UUID, **kw: Any) -> Any:
        self.order.append("claim_turn")
        self.claim_kwargs.append(kw)
        claim = await self._inner.claim_turn(conversation_id, **kw)
        self.minted_claims.append(claim)
        return claim

    async def load_replay_turns(self, conversation_id: uuid.UUID, **kw: Any) -> Any:
        self.order.append("load_replay_turns")
        return await self._inner.load_replay_turns(conversation_id, **kw)

    async def append_turn(self, **kw: Any) -> uuid.UUID:
        self.order.append("append_turn")
        self.append_kwargs.append(kw)
        return await self._inner.append_turn(**kw)

    async def settle_refused_turn(self, **kw: Any) -> ConversationState:
        self.order.append("settle_refused_turn")
        self.settle_refused_kwargs.append(kw)
        return await self._inner.settle_refused_turn(**kw)

    async def release_claim(self, conversation_id: uuid.UUID, **kw: Any) -> None:
        self.order.append("release_claim")
        self.release_kwargs.append(kw)
        await self._inner.release_claim(conversation_id, **kw)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


@pytest.fixture
async def db(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'turn.db'}")
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


def _executor(
    store: Any,
    loop: Any,
    *,
    max_turns: int = 20,
    cumulative_token_budget: int = 1000,
    hook_guard: Any | None = None,
) -> ConversationTurnExecutor:
    return ConversationTurnExecutor(
        store=store,
        loop=loop,
        hook_guard=hook_guard or _PassHookGuard(),
        max_turns=max_turns,
        cumulative_token_budget=cumulative_token_budget,
        replay_last_n=10,
        replay_token_ceiling=8000,
        claim_ttl_s=300.0,
        agent_run_wall_clock_s=120.0,
    )


async def _conversation(store: ConversationStore) -> uuid.UUID:
    cid = uuid.uuid4()
    await store.create_conversation(
        conversation_id=cid,
        tenant_id=_TENANT,
        agent_id="analyst",
        creator_subject=_SUBJECT,
        request_id="req-create",
    )
    return cid


async def _chain_rows(db: AsyncEngine) -> list[Any]:
    import sqlalchemy as sa

    from cognic_agentos.core.decision_history import _decision_history

    async with db.connect() as conn:
        return list(
            (
                await conn.execute(
                    sa.select(_decision_history).order_by(_decision_history.c.sequence)
                )
            ).all()
        )


async def _post(ex: ConversationTurnExecutor, cid: uuid.UUID, msg: str = "who?") -> TurnResult:
    return await ex.post_turn(
        conversation_id=cid, tenant_id=_TENANT, actor_subject=_SUBJECT, user_message=msg
    )


# --- happy path ----------------------------------------------------------------


async def test_happy_path_persists_turn_and_returns_answer(db: AsyncEngine) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    ex = _executor(store, _SpyLoop())
    result = await _post(ex, cid)
    assert isinstance(result, TurnResult)
    assert result.seq == 1
    assert result.answer == "Acme Corp"
    assert result.agent_run_id == "agent-run-1"
    rec = await store.load(cid, tenant_id=_TENANT, creator_subject=_SUBJECT)
    assert rec is not None and rec.turn_count == 1


async def test_returned_turn_id_names_a_real_row(db: AsyncEngine) -> None:
    import sqlalchemy as sa

    from cognic_agentos.core.conversation.storage import _conversation_turns

    store = ConversationStore(db)
    cid = await _conversation(store)
    ex = _executor(store, _SpyLoop())
    result = await _post(ex, cid)
    async with db.connect() as conn:
        found = (
            await conn.execute(
                sa.select(_conversation_turns.c.turn_id).where(
                    _conversation_turns.c.turn_id == result.turn_id
                )
            )
        ).first()
    assert found is not None


async def test_first_turn_has_empty_prior_context(db: AsyncEngine) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    loop = _SpyLoop()
    await _post(_executor(store, loop), cid)
    assert loop.calls[0]["prior_context"] == ()


async def test_second_turn_replays_the_first(db: AsyncEngine) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    loop = _SpyLoop()
    ex = _executor(store, loop)
    await _post(ex, cid, "who?")
    await _post(ex, cid, "and second?")
    prior = loop.calls[1]["prior_context"]
    assert [p.role for p in prior] == ["user", "assistant"]
    assert prior[0].content == "who?"
    assert prior[1].content == "Acme Corp"


async def test_pending_exchange_persists_id_and_replays_as_context(db: AsyncEngine) -> None:
    import sqlalchemy as sa

    from cognic_agentos.core.conversation.storage import _conversation_turns

    approval_id = "a1b2c3d4-1111-4222-8333-444455556666"
    store = ConversationStore(db)
    cid = await _conversation(store)
    pending_loop = _SpyLoop(
        terminal_state="pending_approval",
        answer="Requested approval — #a1b2, pending.",
        approval_request_id=approval_id,
    )
    pending = await _post(_executor(store, pending_loop), cid, "apply leave")

    assert pending.approval_request_id == approval_id
    async with db.connect() as conn:
        row = (
            await conn.execute(
                sa.select(
                    _conversation_turns.c.approval_request_id,
                    _conversation_turns.c.turn_kind,
                ).where(_conversation_turns.c.turn_id == pending.turn_id)
            )
        ).one()
    assert row.approval_request_id == approval_id
    assert row.turn_kind == "exchange"

    followup = _SpyLoop()
    await _post(_executor(store, followup), cid, "status?")
    assert [(turn.role, turn.content) for turn in followup.calls[0]["prior_context"]] == [
        ("user", "apply leave"),
        ("assistant", "Requested approval — #a1b2, pending."),
    ]


async def test_pending_exchange_is_the_only_output_hook_exemption(db: AsyncEngine) -> None:
    """R19: preserve D2 correlation for the kernel-authored pending response."""

    approval_id = "a1b2c3d4-1111-4222-8333-444455556666"
    store = ConversationStore(db)
    cid = await _conversation(store)
    hooks = _ScriptedHookGuard(output_outcome="refused")
    loop = _SpyLoop(
        terminal_state="pending_approval",
        answer="Requested approval — #a1b2, pending.",
        approval_request_id=approval_id,
    )

    pending = await _post(_executor(store, loop, hook_guard=hooks), cid, "apply leave")

    assert pending.terminal_state == "pending_approval"
    assert pending.approval_request_id == approval_id
    assert [call["phase"] for call in hooks.calls] == ["conversation_input"]
    assert await store.resolve_approval_context(
        approval_request_id=uuid.UUID(approval_id),
        tenant_id=_TENANT,
    ) == (cid, "analyst")


@pytest.mark.parametrize(
    ("approval_request_id", "answer"),
    [
        (None, "Requested approval — #a1b2, pending."),
        (
            "a1b2c3d4-1111-4222-8333-444455556666",
            "Requested approval — #a1b2, pending. secret model fragment",
        ),
    ],
    ids=["missing-approval-id", "non-kernel-answer"],
)
async def test_pending_exemption_refuses_when_kernel_only_property_is_broken(
    db: AsyncEngine,
    approval_request_id: str | None,
    answer: str,
) -> None:
    inner = ConversationStore(db)
    cid = await _conversation(inner)
    spy = _OrderRecordingStore(inner)
    hooks = _PassHookGuard()
    loop = _SpyLoop(
        terminal_state="pending_approval",
        answer=answer,
        approval_request_id=approval_request_id,
    )

    with pytest.raises(ConversationTurnRefused) as exc:
        await _post(_executor(spy, loop, hook_guard=hooks), cid, "apply leave")

    assert exc.value.reason == "conversation_hook_refused"
    assert [call["phase"] for call in hooks.calls] == ["conversation_input"]
    assert spy.append_kwargs == []


async def test_real_token_counts_accumulate_into_the_conversation(db: AsyncEngine) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    await _post(_executor(store, _SpyLoop(prompt_tokens=3, completion_tokens=2)), cid)
    rec = await store.load(cid, tenant_id=_TENANT, creator_subject=_SUBJECT)
    assert rec is not None and rec.cumulative_tokens == 5


# --- D2-C T9: system-authored completion turns ---------------------------------


async def test_system_turn_is_physical_but_does_not_consume_user_budget(
    db: AsyncEngine,
) -> None:
    import sqlalchemy as sa

    from cognic_agentos.core.conversation.storage import _conversation_turns
    from cognic_agentos.core.decision_history import _decision_history

    approval_id = "a1b2c3d4-1111-4222-8333-444455556666"
    text = "Approved action completed."
    store = ConversationStore(db)
    cid = await _conversation(store)
    ex = _executor(store, _SpyLoop(prompt_tokens=3, completion_tokens=2), max_turns=1)
    exchange = await _post(ex, cid, "please act")

    system_id = await ex.post_system_turn(
        conversation_id=cid,
        tenant_id=_TENANT,
        text=text,
        approval_request_id=approval_id,
        request_id="req-system-complete",
    )

    rec = await store.load(cid, tenant_id=_TENANT, creator_subject=_SUBJECT)
    assert rec is not None
    assert rec.turn_count == 1
    assert rec.cumulative_tokens == 5
    async with db.connect() as conn:
        rows = (
            (
                await conn.execute(
                    sa.select(_conversation_turns)
                    .where(_conversation_turns.c.conversation_id == cid)
                    .order_by(_conversation_turns.c.seq)
                )
            )
            .mappings()
            .all()
        )
        chain = (
            await conn.execute(
                sa.select(_decision_history.c.payload).where(
                    _decision_history.c.request_id == "req-system-complete",
                    _decision_history.c.event_type == "conversation.system_turn_appended",
                )
            )
        ).one()
    assert [row["turn_id"] for row in rows] == [exchange.turn_id, system_id]
    system = rows[1]
    assert system["seq"] == 2
    assert system["turn_kind"] == "system"
    assert system["user_message"] is None
    assert system["answer"] == text
    assert system["agent_run_id"] == f"system-{approval_id}"
    assert system["approval_request_id"] == approval_id
    assert (system["prompt_tokens"], system["completion_tokens"]) == (0, 0)
    assert chain.payload["actor_id"] == "system:approval-executor"
    assert chain.payload["answer_sha256"] == hashlib.sha256(text.encode()).hexdigest()
    assert chain.payload["answer_bytes"] == len(text.encode())
    assert text not in str(chain.payload)

    with pytest.raises(ConversationTurnRefused) as exc:
        await _post(ex, cid, "another user turn")
    assert exc.value.reason == "conversation_max_turns_exceeded"


async def test_system_turn_output_transformation_is_refused_with_delivery_identity(
    db: AsyncEngine,
) -> None:
    import sqlalchemy as sa

    from cognic_agentos.core.conversation.storage import _conversation_turns

    store = ConversationStore(db)
    cid = await _conversation(store)
    hooks = _ScriptedHookGuard(
        transform_output=lambda payload: _canonical_transform(
            payload,
            lambda value: value.__setitem__("answer", "[MASKED APPROVAL RESULT]"),
        )
    )
    approval_id = "a1b2c3d4-1111-4222-8333-444455556666"

    with pytest.raises(ConversationTurnRefused) as caught:
        await _executor(store, _SpyLoop(), hook_guard=hooks).post_system_turn(
            conversation_id=cid,
            tenant_id=_TENANT,
            text="tool-authored sensitive result",
            approval_request_id=approval_id,
            request_id="req-system-screened",
        )

    assert caught.value.reason == "conversation_hook_refused"
    assert [call["phase"] for call in hooks.calls] == ["conversation_output"]
    assert hooks.calls[0]["output_origin"] == "approval_delivery"
    assert hooks.calls[0]["agent_run_id"] is None
    assert hooks.calls[0]["approval_delivery_id"] == f"approval-delivery-{approval_id}"
    assert hooks.calls[0]["turn_seq"] == 1
    async with db.connect() as conn:
        persisted = (
            await conn.execute(
                sa.select(sa.func.count())
                .select_from(_conversation_turns)
                .where(_conversation_turns.c.conversation_id == cid)
            )
        ).scalar_one()
    assert persisted == 0


async def test_late_system_turn_refusal_retains_approval_delivery_identity(
    db: AsyncEngine,
) -> None:
    class _LateRefusingStore(_OrderRecordingStore):
        async def append_system_turn(self, **kw: Any) -> uuid.UUID:
            self.order.append("append_system_turn")
            raise ConversationTurnRefused(
                "conversation_turn_claim_stale",
                current_state="closed",
            )

    inner = ConversationStore(db)
    store = _LateRefusingStore(inner)
    cid = await _conversation(inner)
    history = DecisionHistoryStore(db)
    hooks = _PassHookGuard(history=history)
    text = "tool-authored sensitive result"
    approval_id = "a1b2c3d4-1111-4222-8333-444455556666"

    with pytest.raises(ConversationTurnRefused) as exc:
        await _executor(store, _SpyLoop(), hook_guard=hooks).post_system_turn(
            conversation_id=cid,
            tenant_id=_TENANT,
            text=text,
            approval_request_id=approval_id,
            request_id="req-system-late-refusal",
        )

    refused = exc.value
    assert refused.reason == "conversation_turn_claim_stale"
    assert refused.current_state == "closed"
    assert refused.conversation_output_request_id is not None
    assert refused.conversation_output_hook_count == 1
    assert refused.conversation_output_value_sha256 == hashlib.sha256(text.encode()).hexdigest()
    assert refused.conversation_output_value_bytes == len(text.encode())
    assert store.order[-2:] == ["append_system_turn", "release_claim"]

    rows = await _chain_rows(db)
    hook_row = next(row for row in rows if row.event_type == "hook.decision")
    assert hook_row.request_id == refused.conversation_output_request_id
    assert hook_row.payload["output_origin"] == "approval_delivery"
    assert hook_row.payload["agent_run_id"] is None
    assert hook_row.payload["approval_delivery_id"] == f"approval-delivery-{approval_id}"
    assert hook_row.payload["hook_output_value_sha256"] == refused.conversation_output_value_sha256


async def test_system_turn_output_refusal_persists_no_plaintext(
    db: AsyncEngine,
) -> None:
    import sqlalchemy as sa

    from cognic_agentos.core.conversation.storage import _conversation_turns

    store = ConversationStore(db)
    cid = await _conversation(store)
    hooks = _ScriptedHookGuard(output_outcome="refused")

    with pytest.raises(ConversationTurnRefused) as exc:
        await _executor(store, _SpyLoop(), hook_guard=hooks).post_system_turn(
            conversation_id=cid,
            tenant_id=_TENANT,
            text="must not persist",
            approval_request_id="a1b2c3d4-1111-4222-8333-444455556666",
            request_id="req-system-refused",
        )

    assert exc.value.reason == "conversation_hook_refused"
    async with db.connect() as conn:
        count = (
            await conn.execute(
                sa.select(sa.func.count())
                .select_from(_conversation_turns)
                .where(_conversation_turns.c.conversation_id == cid)
            )
        ).scalar_one()
    assert count == 0


async def test_exchange_after_system_turn_uses_the_next_physical_sequence(
    db: AsyncEngine,
) -> None:
    import sqlalchemy as sa

    from cognic_agentos.core.conversation.storage import _conversation_turns

    store = ConversationStore(db)
    cid = await _conversation(store)
    ex = _executor(store, _SpyLoop())
    assert (await _post(ex, cid, "q1")).seq == 1
    await ex.post_system_turn(
        conversation_id=cid,
        tenant_id=_TENANT,
        text="done",
        approval_request_id="a1b2c3d4-1111-4222-8333-444455556666",
        request_id="req-system-seq",
    )
    second = await _post(ex, cid, "q2")

    assert second.seq == 3
    rec = await store.load(cid, tenant_id=_TENANT, creator_subject=_SUBJECT)
    assert rec is not None and rec.turn_count == 2
    async with db.connect() as conn:
        seqs = (
            (
                await conn.execute(
                    sa.select(_conversation_turns.c.seq)
                    .where(_conversation_turns.c.conversation_id == cid)
                    .order_by(_conversation_turns.c.seq)
                )
            )
            .scalars()
            .all()
        )
    assert list(seqs) == [1, 2, 3]


async def test_system_turn_refuses_when_a_user_claim_is_live(db: AsyncEngine) -> None:
    import sqlalchemy as sa

    from cognic_agentos.core.conversation.storage import _conversation_turns

    store = ConversationStore(db)
    cid = await _conversation(store)
    claim = await store.claim_turn(
        cid,
        tenant_id=_TENANT,
        creator_subject=_SUBJECT,
        now=datetime.now(UTC),
        claim_ttl_s=300.0,
    )
    with pytest.raises(ConversationTurnRefused) as exc:
        await _executor(store, _SpyLoop()).post_system_turn(
            conversation_id=cid,
            tenant_id=_TENANT,
            text="must not interleave",
            approval_request_id="a1b2c3d4-1111-4222-8333-444455556666",
            request_id="req-system-collision",
        )
    assert exc.value.reason == "conversation_turn_in_progress"
    async with db.connect() as conn:
        count = (
            await conn.execute(
                sa.select(sa.func.count())
                .select_from(_conversation_turns)
                .where(_conversation_turns.c.conversation_id == cid)
            )
        ).scalar_one()
    assert count == 0
    await store.release_claim(cid, tenant_id=_TENANT, claim_id=claim.claim_id)


# --- ORDERING PIN: claim_turn (creator-scoped) precedes append_turn -------------


async def test_claim_precedes_append_and_carries_creator_subject(db: AsyncEngine) -> None:
    """append_turn / transition take tenant_id but NOT creator_subject.

    Creator scoping lives ENTIRELY in the claim_turn that must precede them. A
    reorder would silently drop the creator boundary, and no other test would
    notice.
    """
    inner = ConversationStore(db)
    cid = await _conversation(inner)
    spy = _OrderRecordingStore(inner)
    await _post(_executor(spy, _SpyLoop()), cid)

    assert spy.order.index("claim_turn") < spy.order.index("append_turn")
    assert spy.claim_kwargs[0]["creator_subject"] == _SUBJECT
    assert spy.claim_kwargs[0]["tenant_id"] == _TENANT


async def test_cross_actor_post_is_not_found_with_zero_append(db: AsyncEngine) -> None:
    inner = ConversationStore(db)
    cid = await _conversation(inner)
    spy = _OrderRecordingStore(inner)
    loop = _SpyLoop()
    ex = _executor(spy, loop)
    with pytest.raises(ConversationNotFound):
        await ex.post_turn(
            conversation_id=cid,
            tenant_id=_TENANT,
            actor_subject="mallory",
            user_message="q",
        )
    assert spy.append_kwargs == []
    assert "append_turn" not in spy.order
    assert loop.calls == []


async def test_cross_tenant_post_is_not_found_with_zero_append(db: AsyncEngine) -> None:
    inner = ConversationStore(db)
    cid = await _conversation(inner)
    spy = _OrderRecordingStore(inner)
    loop = _SpyLoop()
    ex = _executor(spy, loop)
    with pytest.raises(ConversationNotFound):
        await ex.post_turn(
            conversation_id=cid,
            tenant_id="tenant-b",
            actor_subject=_SUBJECT,
            user_message="q",
        )
    assert "append_turn" not in spy.order
    assert loop.calls == []


# --- terminal-state + bounds refuse BEFORE the loop ----------------------------


async def test_closed_conversation_refuses_without_invoking_the_loop(db: AsyncEngine) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    await store.transition(
        conversation_id=cid,
        tenant_id=_TENANT,
        to_state="closed",
        actor_id=_SUBJECT,
        request_id="req-close",
    )
    loop = _SpyLoop()
    with pytest.raises(ConversationTurnRefused) as exc:
        await _post(_executor(store, loop), cid)
    assert exc.value.reason == "conversation_not_active"
    assert exc.value.current_state == "closed"
    assert loop.calls == []  # <-- ZERO AgentLoop invocation


async def test_max_turns_exceeded_refuses_without_invoking_the_loop(db: AsyncEngine) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    loop = _SpyLoop()
    ex = _executor(store, loop, max_turns=1)
    await _post(ex, cid, "q1")
    loop.calls.clear()
    with pytest.raises(ConversationTurnRefused) as exc:
        await _post(ex, cid, "q2")
    assert exc.value.reason == "conversation_max_turns_exceeded"
    assert loop.calls == []


async def test_token_budget_exhaustion_refuses_without_invoking_the_loop(
    db: AsyncEngine,
) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    loop = _SpyLoop(prompt_tokens=3, completion_tokens=2)  # 5 per turn
    ex = _executor(store, loop, cumulative_token_budget=4)
    await _post(ex, cid, "q1")
    loop.calls.clear()
    with pytest.raises(ConversationTurnRefused) as exc:
        await _post(ex, cid, "q2")
    assert exc.value.reason == "conversation_token_budget_exceeded"
    assert loop.calls == []


async def test_bounds_refusal_writes_no_turn_row(db: AsyncEngine) -> None:
    inner = ConversationStore(db)
    cid = await _conversation(inner)
    spy = _OrderRecordingStore(inner)
    ex = _executor(spy, _SpyLoop(), max_turns=0)
    with pytest.raises(ConversationTurnRefused):
        await _post(ex, cid)
    assert "append_turn" not in spy.order


# --- claim lifecycle -----------------------------------------------------------


async def test_claim_is_released_when_the_loop_raises(db: AsyncEngine) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    ex = _executor(store, _RaisingLoop())
    with pytest.raises(RuntimeError):
        await _post(ex, cid)
    # a crashed turn must not wedge the conversation
    await store.claim_turn(
        cid,
        tenant_id=_TENANT,
        creator_subject=_SUBJECT,
        now=datetime.now(UTC),
        claim_ttl_s=300.0,
    )


async def test_claim_is_released_on_the_happy_path(db: AsyncEngine) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    await _post(_executor(store, _SpyLoop()), cid)
    await store.claim_turn(
        cid,
        tenant_id=_TENANT,
        creator_subject=_SUBJECT,
        now=datetime.now(UTC),
        claim_ttl_s=300.0,
    )


async def test_concurrent_turn_refuses_turn_in_progress(db: AsyncEngine) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    await store.claim_turn(
        cid,
        tenant_id=_TENANT,
        creator_subject=_SUBJECT,
        now=datetime.now(UTC),
        claim_ttl_s=300.0,
    )
    loop = _SpyLoop()
    with pytest.raises(ConversationTurnRefused) as exc:
        await _post(_executor(store, loop), cid)
    assert exc.value.reason == "conversation_turn_in_progress"
    assert loop.calls == []


# --- construction guard --------------------------------------------------------


async def test_claim_ttl_must_exceed_agent_wall_clock(db: AsyncEngine) -> None:
    """The configured claim window must exceed the declared AgentLoop budget."""
    store = ConversationStore(db)
    with pytest.raises(ValueError, match="claim_ttl_s"):
        ConversationTurnExecutor(
            store=store,
            loop=_SpyLoop(),
            hook_guard=_PassHookGuard(),
            max_turns=20,
            cumulative_token_budget=1000,
            replay_last_n=10,
            replay_token_ceiling=8000,
            claim_ttl_s=1.0,
            agent_run_wall_clock_s=120.0,
        )


async def test_claim_ttl_must_exceed_agent_and_both_hook_phase_budgets(
    db: AsyncEngine,
) -> None:
    """Declared hook timeouts are included in configuration headroom."""
    store = ConversationStore(db)
    hooks = _PassHookGuard()
    hooks.turn_timeout_budget_s = lambda: 181.0  # type: ignore[method-assign]

    with pytest.raises(ValueError, match="hook phase timeout budget"):
        ConversationTurnExecutor(
            store=store,
            loop=_SpyLoop(),
            hook_guard=hooks,
            max_turns=20,
            cumulative_token_budget=1000,
            replay_last_n=10,
            replay_token_ceiling=8000,
            claim_ttl_s=300.0,
            agent_run_wall_clock_s=120.0,
        )


async def test_claim_ttl_equal_to_declared_agent_and_hook_budgets_refuses(
    db: AsyncEngine,
) -> None:
    """Strict headroom is required; equality is not enough."""

    hooks = _PassHookGuard()
    hooks.turn_timeout_budget_s = lambda: 180.0  # type: ignore[method-assign]

    with pytest.raises(ValueError, match="configuration headroom"):
        ConversationTurnExecutor(
            store=ConversationStore(db),
            loop=_SpyLoop(),
            hook_guard=hooks,
            max_turns=20,
            cumulative_token_budget=1000,
            replay_last_n=10,
            replay_token_ceiling=8000,
            claim_ttl_s=300.0,
            agent_run_wall_clock_s=120.0,
        )


@pytest.mark.parametrize("budget", [float("nan"), float("inf"), -1.0, True])
async def test_hook_timeout_budget_must_be_finite_nonnegative(
    db: AsyncEngine, budget: float
) -> None:
    store = ConversationStore(db)
    hooks = _PassHookGuard()
    hooks.turn_timeout_budget_s = lambda: budget  # type: ignore[method-assign]

    with pytest.raises(ValueError, match="hook phase timeout budget"):
        ConversationTurnExecutor(
            store=store,
            loop=_SpyLoop(),
            hook_guard=hooks,
            max_turns=20,
            cumulative_token_budget=1000,
            replay_last_n=10,
            replay_token_ceiling=8000,
            claim_ttl_s=300.0,
            agent_run_wall_clock_s=120.0,
        )


async def test_loop_receives_the_conversation_agent_id_and_actor(db: AsyncEngine) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    loop = _SpyLoop()
    await _post(_executor(store, loop), cid)
    kw = loop.calls[0]
    assert kw["agent_id"] == "analyst"
    assert kw["actor_tenant_id"] == _TENANT
    assert kw["actor_subject"] == _SUBJECT


# --- FENCING (P0, 2026-07-10): the executor threads ITS OWN lease --------------


async def test_executor_threads_the_minted_claim_id_to_append_and_release(
    db: AsyncEngine,
) -> None:
    """The claim_id minted at claim_turn is the one append_turn verifies and
    the one release_claim conditions on. Any break in this chain reopens the
    lost-lease race."""
    inner = ConversationStore(db)
    cid = await _conversation(inner)
    spy = _OrderRecordingStore(inner)
    await _post(_executor(spy, _SpyLoop()), cid)

    minted = spy.minted_claims[0].claim_id
    assert spy.append_kwargs[0]["claim_id"] == minted
    assert spy.release_kwargs[0]["claim_id"] == minted


async def test_release_is_fenced_even_when_the_loop_raises(db: AsyncEngine) -> None:
    inner = ConversationStore(db)
    cid = await _conversation(inner)
    spy = _OrderRecordingStore(inner)
    with pytest.raises(RuntimeError):
        await _post(_executor(spy, _RaisingLoop()), cid)
    assert spy.release_kwargs[0]["claim_id"] == spy.minted_claims[0].claim_id


# --- F-S2a: conversation input/output hook phases -----------------------------


def _canonical_transform(payload: bytes, mutate: Callable[[dict[str, Any]], None]) -> bytes:
    import json

    from cognic_agentos.core.canonical import canonical_bytes

    value = json.loads(payload)
    mutate(value)
    return canonical_bytes(value)


async def test_hook_phases_wrap_loop_and_share_correlation(
    db: AsyncEngine,
) -> None:
    inner = ConversationStore(db)
    cid = await _conversation(inner)
    spy = _OrderRecordingStore(inner)
    loop = _SpyLoop()
    hooks = _PassHookGuard()

    result = await _post(_executor(spy, loop, hook_guard=hooks), cid, "screen me")

    assert result.answer == "Acme Corp"
    assert [call["phase"] for call in hooks.calls] == [
        "conversation_input",
        "conversation_output",
    ]
    hook_request_ids = [call["request_id"] for call in hooks.calls]
    assert len(set(hook_request_ids)) == 1
    assert spy.append_kwargs[0]["request_id"] not in hook_request_ids
    assert hooks.calls[0]["tenant_id"] == _TENANT
    assert hooks.calls[0]["governance"] == ConversationHookGovernance(
        pack_id="cognic-agent-analyst",
        declared_data_classes=("internal",),
        manifest_purpose="operational_telemetry",
    )
    import json

    input_envelope = json.loads(hooks.calls[0]["payload"])
    assert input_envelope == {
        "conversation_id": str(cid),
        "declared_data_classes": ["internal"],
        "messages": [{"content": "screen me", "role": "user"}],
        "phase": "conversation_input",
        "schema_version": 1,
        "tenant_id": _TENANT,
        "turn_seq": 1,
    }
    output_envelope = json.loads(hooks.calls[1]["payload"])
    assert output_envelope == {
        "answer": "Acme Corp",
        "conversation_id": str(cid),
        "declared_data_classes": ["internal"],
        "phase": "conversation_output",
        "schema_version": 1,
        "tenant_id": _TENANT,
        "turn_seq": 1,
    }


async def test_hook_request_id_cannot_collide_with_turn_chain_lookup(
    db: AsyncEngine,
) -> None:
    """A real hooked turn remains reconstructable by the examiner read model."""

    import sqlalchemy as sa

    from cognic_agentos.core.conversation.storage import _conversation_turns
    from cognic_agentos.core.decision_history import _decision_history

    store = ConversationStore(db)
    history = DecisionHistoryStore(db)
    cid = await _conversation(store)
    hooks = _PassHookGuard(history=history)

    result = await _post(
        _executor(store, _SpyLoop(history=history), hook_guard=hooks),
        cid,
        "screen me",
    )

    async with db.connect() as conn:
        turn_request_id = (
            await conn.execute(
                sa.select(_conversation_turns.c.turn_completed_request_id).where(
                    _conversation_turns.c.turn_id == result.turn_id
                )
            )
        ).scalar_one()
        hook_request_ids = (
            (
                await conn.execute(
                    sa.select(_decision_history.c.request_id)
                    .where(_decision_history.c.event_type == "hook.decision")
                    .order_by(_decision_history.c.sequence)
                )
            )
            .scalars()
            .all()
        )

    assert len(hook_request_ids) == 2
    assert len(set(hook_request_ids)) == 1
    assert turn_request_id not in hook_request_ids

    joined = await ConversationReadModel(db, chain_candidate_limit=10_000).read_turn_chain(
        cid,
        1,
        tenant_id=_TENANT,
        creator_subject=_SUBJECT,
    )
    assert joined is not None
    assert joined.turn_completed.turn_id == result.turn_id


async def test_substituted_output_guard_cannot_transform_conversation_answer(
    db: AsyncEngine,
) -> None:
    """Core rejects a changed PASS result even if the dispatcher seam is replaced."""

    store = ConversationStore(db)
    history = DecisionHistoryStore(db)
    cid = await _conversation(store)
    hooks = _PassHookGuard(
        history=history,
        transform_output=lambda payload: _canonical_transform(
            payload,
            lambda value: value.__setitem__("answer", "[MASKED]"),
        ),
    )

    with pytest.raises(ConversationTurnRefused) as caught:
        await _post(
            _executor(store, _SpyLoop(history=history), hook_guard=hooks),
            cid,
            "screen me",
        )
    assert caught.value.reason == "conversation_hook_refused"
    assert caught.value.conversation_output_hook_count == 1

    rows = await _chain_rows(db)
    terminal = next(row for row in rows if row.event_type == "agent.run.completed")
    hook = next(
        row
        for row in rows
        if row.event_type == "hook.decision" and row.payload["phase"] == "conversation_output"
    )
    refused = next(row for row in rows if row.event_type == "conversation.turn_refused")
    raw_digest = hashlib.sha256(b"Acme Corp").hexdigest()
    masked_digest = hashlib.sha256(b"[MASKED]").hexdigest()
    assert terminal.sequence < hook.sequence < refused.sequence
    assert (
        terminal.payload["answer_sha256"] == hook.payload["hook_input_value_sha256"] == raw_digest
    )
    assert hook.payload["hook_output_value_sha256"] == masked_digest
    assert refused.payload["answer_sha256"] == raw_digest
    assert hook.payload["decision"] == "mask"
    assert refused.payload["conversation_output_request_id"] == hook.request_id
    assert refused.payload["conversation_output_hook_count"] == 1


async def test_late_exchange_refusal_retains_agent_run_output_identity(
    db: AsyncEngine,
) -> None:
    class _LateRefusingStore(_OrderRecordingStore):
        async def append_turn(self, **kw: Any) -> uuid.UUID:
            self.order.append("append_turn")
            raise ConversationTurnRefused(
                "conversation_turn_claim_stale",
                current_state="active",
            )

    inner = ConversationStore(db)
    store = _LateRefusingStore(inner)
    history = DecisionHistoryStore(db)
    cid = await _conversation(inner)
    hooks = _PassHookGuard(history=history)
    raw_answer = "Acme Corp"

    with pytest.raises(ConversationTurnRefused) as caught:
        await _post(
            _executor(
                store,
                _SpyLoop(history=history),
                hook_guard=hooks,
            ),
            cid,
            "screen me",
        )

    refused = caught.value
    assert refused.reason == "conversation_turn_claim_stale"
    assert refused.current_state == "active"
    assert refused.conversation_output_request_id is not None
    assert refused.conversation_output_hook_count == 1
    assert (
        refused.conversation_output_value_sha256 == hashlib.sha256(raw_answer.encode()).hexdigest()
    )
    assert refused.conversation_output_value_bytes == len(raw_answer.encode())
    rows = await _chain_rows(db)
    hook = next(
        row
        for row in rows
        if row.event_type == "hook.decision" and row.payload["phase"] == "conversation_output"
    )
    assert hook.request_id == refused.conversation_output_request_id
    assert hook.payload["output_origin"] == "agent_run"
    assert hook.payload["agent_run_id"] == "agent-run-1"
    assert hook.payload["approval_delivery_id"] is None
    assert hook.payload["hook_output_value_sha256"] == refused.conversation_output_value_sha256
    assert store.order[-2:] == ["append_turn", "release_claim"]


async def test_real_adapter_dispatcher_refuses_conversation_transform_and_stops_chain(
    db: AsyncEngine,
) -> None:
    """R25: the real dispatcher evidences the first transform and stops."""

    class _InputPass(Hook):
        hook_id: ClassVar[str] = "input-pass"
        phase: ClassVar[HookPhase] = "conversation_input"

        async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
            return HookResult(decision="pass", redacted_payload=None, policy_reason=None)

    class _OutputMask(Hook):
        hook_id: ClassVar[str] = "output-mask"
        phase: ClassVar[HookPhase] = "conversation_output"
        calls: ClassVar[int] = 0

        async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
            type(self).calls += 1
            return HookResult(
                decision="mask",
                redacted_payload=_canonical_transform(
                    payload,
                    lambda value: value.__setitem__("answer", "[MASKED-1]"),
                ),
                policy_reason=None,
            )

    class _OutputRedact(Hook):
        hook_id: ClassVar[str] = "output-redact"
        phase: ClassVar[HookPhase] = "conversation_output"
        calls: ClassVar[int] = 0

        async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
            type(self).calls += 1
            return HookResult(
                decision="redact",
                redacted_payload=_canonical_transform(
                    payload,
                    lambda value: value.__setitem__("answer", "[MASKED-2]"),
                ),
                policy_reason=None,
            )

    registry = HookRegistry(max_timeout_seconds=30.0)
    registry.register_pack(
        VerifiedHookPack(
            distribution_name="cognic-hook-test",
            distribution_version="0.1.0",
            signature_digest="sha256:" + "a" * 64,
            declarations=(
                HookDeclaration(
                    hook_id="input-pass",
                    phase="conversation_input",
                    ordering_class="input_validation",
                    timeout_seconds=1.0,
                    fail_policy="fail_closed",
                    fail_open_exception=None,
                    callable_loader=lambda: _InputPass,
                ),
                HookDeclaration(
                    hook_id="output-mask",
                    phase="conversation_output",
                    ordering_class="output_validation",
                    timeout_seconds=1.0,
                    fail_policy="fail_closed",
                    fail_open_exception=None,
                    callable_loader=lambda: _OutputMask,
                ),
                HookDeclaration(
                    hook_id="output-redact",
                    phase="conversation_output",
                    ordering_class="output_masking",
                    timeout_seconds=1.0,
                    fail_policy="fail_closed",
                    fail_open_exception=None,
                    callable_loader=lambda: _OutputRedact,
                ),
            ),
        )
    )
    history = DecisionHistoryStore(db)

    async def emit(row: dict[str, object]) -> None:
        await history.append(
            DecisionRecord(
                decision_type=str(row["event_type"]),
                request_id=str(row["request_id"]),
                payload=dict(row),
                actor_id=_SUBJECT,
                tenant_id=_TENANT,
            )
        )

    adapter = ConversationHookGuardAdapter(
        dispatcher=HookDispatcher(
            registry=registry,
            max_payload_bytes=10_000,
            max_timeout_seconds_runtime=30.0,
            audit_emitter=emit,
        ),
        agent_records={
            "analyst": LoadedAgentRecord(
                agent_id="analyst",
                persona_body="test",
                persona_sha256="b" * 64,
                requested_skills=(),
                requested_tools=(),
                max_steps=6,
                risk_tier="read_only",
                pack_version="0.1.0",
                signed_artefact_digest="sha256:" + "c" * 64,
                registered=True,
                pack_id="cognic-agent-test",
                manifest_data_classes=("internal",),
                manifest_purpose="operational_telemetry",
            )
        },
    )
    store = ConversationStore(db)
    cid = await _conversation(store)
    with pytest.raises(ConversationTurnRefused) as caught:
        await _post(
            _executor(store, _SpyLoop(history=history), hook_guard=adapter),
            cid,
            "screen me",
        )
    assert caught.value.reason == "conversation_hook_refused"
    assert caught.value.conversation_output_hook_count == 1
    assert _OutputMask.calls == 1
    assert _OutputRedact.calls == 0

    rows = await _chain_rows(db)
    terminal = next(row for row in rows if row.event_type == "agent.run.completed")
    output_hooks = [
        row
        for row in rows
        if row.event_type == "hook.failed" and row.payload["phase"] == "conversation_output"
    ]
    refused = next(row for row in rows if row.event_type == "conversation.turn_refused")
    assert [row.payload["hook_id"] for row in output_hooks] == ["output-mask"]
    raw_sha256 = hashlib.sha256(b"Acme Corp").hexdigest()
    middle_sha256 = hashlib.sha256(b"[MASKED-1]").hexdigest()
    assert terminal.payload["answer_sha256"] == raw_sha256
    assert output_hooks[0].payload["hook_input_value_sha256"] == raw_sha256
    # The envelope digest records the attempted transform, while the scalar
    # value digest and settled refusal retain the original answer.
    assert (
        output_hooks[0].payload["hook_output_digest"]
        != output_hooks[0].payload["hook_input_digest"]
    )
    assert output_hooks[0].payload["hook_output_value_sha256"] == raw_sha256
    assert output_hooks[0].payload["failure_mode"] == (
        "hook_conversation_transformation_unsupported"
    )
    assert output_hooks[0].payload["output_origin"] == "agent_run"
    assert output_hooks[0].payload["agent_run_id"] == "agent-run-1"
    assert output_hooks[0].payload["approval_delivery_id"] is None
    assert refused.payload["answer_sha256"] == raw_sha256
    assert terminal.sequence < output_hooks[0].sequence < refused.sequence
    assert refused.payload["conversation_output_request_id"] == output_hooks[0].request_id
    assert refused.payload["conversation_output_hook_count"] == 1
    assert middle_sha256 not in {
        output_hooks[0].payload["hook_input_value_sha256"],
        output_hooks[0].payload["hook_output_value_sha256"],
        refused.payload["answer_sha256"],
    }


async def test_real_dispatcher_oversize_output_is_evidenced_before_turn_refusal(
    db: AsyncEngine,
) -> None:
    """A pre-loop technical refusal still carries one chainable hook row."""

    import sqlalchemy as sa

    from cognic_agentos.core.conversation.storage import _conversation_turns
    from cognic_agentos.core.decision_history import _decision_history

    class _InputPass(Hook):
        hook_id: ClassVar[str] = "input-pass"
        phase: ClassVar[HookPhase] = "conversation_input"

        async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
            return HookResult(decision="pass", redacted_payload=None, policy_reason=None)

    class _OutputPass(Hook):
        hook_id: ClassVar[str] = "output-pass"
        phase: ClassVar[HookPhase] = "conversation_output"

        async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
            return HookResult(decision="pass", redacted_payload=None, policy_reason=None)

    registry = HookRegistry(max_timeout_seconds=30.0)
    registry.register_pack(
        VerifiedHookPack(
            distribution_name="cognic-hook-test",
            distribution_version="0.1.0",
            signature_digest="sha256:" + "a" * 64,
            declarations=(
                HookDeclaration(
                    hook_id="input-pass",
                    phase="conversation_input",
                    ordering_class="input_validation",
                    timeout_seconds=1.0,
                    fail_policy="fail_closed",
                    fail_open_exception=None,
                    callable_loader=lambda: _InputPass,
                ),
                HookDeclaration(
                    hook_id="output-pass",
                    phase="conversation_output",
                    ordering_class="output_validation",
                    timeout_seconds=1.0,
                    fail_policy="fail_closed",
                    fail_open_exception=None,
                    callable_loader=lambda: _OutputPass,
                ),
            ),
        )
    )
    history = DecisionHistoryStore(db)

    async def emit(row: dict[str, object]) -> None:
        await history.append(
            DecisionRecord(
                decision_type=str(row["event_type"]),
                request_id=str(row["request_id"]),
                payload=dict(row),
                actor_id=_SUBJECT,
                tenant_id=_TENANT,
            )
        )

    adapter = ConversationHookGuardAdapter(
        dispatcher=HookDispatcher(
            registry=registry,
            max_payload_bytes=2_000,
            max_timeout_seconds_runtime=30.0,
            audit_emitter=emit,
        ),
        agent_records={
            "analyst": LoadedAgentRecord(
                agent_id="analyst",
                persona_body="test",
                persona_sha256="b" * 64,
                requested_skills=(),
                requested_tools=(),
                max_steps=6,
                risk_tier="read_only",
                pack_version="0.1.0",
                signed_artefact_digest="sha256:" + "c" * 64,
                registered=True,
                pack_id="cognic-agent-test",
                manifest_data_classes=("internal",),
                manifest_purpose="operational_telemetry",
            )
        },
    )
    raw_answer = "sensitive-output-" * 1_000
    store = ConversationStore(db)
    cid = await _conversation(store)

    with pytest.raises(ConversationTurnRefused) as caught:
        await _post(
            _executor(
                store,
                _SpyLoop(answer=raw_answer, history=history),
                hook_guard=adapter,
            ),
            cid,
            "short input",
        )

    exc = caught.value
    assert exc.reason == "conversation_hook_refused"
    assert exc.conversation_output_request_id is not None
    assert exc.conversation_output_request_id.startswith("conv-hook-")
    assert exc.conversation_output_hook_count == 1

    async with db.connect() as conn:
        rows = (
            (
                await conn.execute(
                    sa.select(_decision_history)
                    .where(
                        _decision_history.c.event_type.in_(
                            (
                                "agent.run.completed",
                                "hook.payload_unscannable",
                                "conversation.turn_refused",
                            )
                        )
                    )
                    .order_by(_decision_history.c.sequence)
                )
            )
            .mappings()
            .all()
        )
        persisted_turns = (
            await conn.execute(
                sa.select(sa.func.count())
                .select_from(_conversation_turns)
                .where(_conversation_turns.c.conversation_id == cid)
            )
        ).scalar_one()

    assert [row["event_type"] for row in rows] == [
        "agent.run.completed",
        "hook.payload_unscannable",
        "conversation.turn_refused",
    ]
    terminal, hook, refused = rows
    terminal_payload = terminal["payload"]
    hook_payload = hook["payload"]
    refused_payload = refused["payload"]
    answer_sha256 = hashlib.sha256(raw_answer.encode()).hexdigest()
    assert terminal_payload["answer_sha256"] == answer_sha256
    assert hook_payload["hook_input_value_sha256"] == answer_sha256
    assert hook_payload["hook_output_value_sha256"] == answer_sha256
    assert refused_payload["answer_sha256"] == answer_sha256
    assert hook["request_id"] == exc.conversation_output_request_id
    assert refused_payload["conversation_output_request_id"] == exc.conversation_output_request_id
    assert refused_payload["conversation_output_hook_count"] == 1
    assert persisted_turns == 0
    assert raw_answer not in repr(rows)

    conversation = await store.load(cid, tenant_id=_TENANT, creator_subject=_SUBJECT)
    assert conversation is not None
    assert conversation.cumulative_tokens == 5
    assert conversation.turn_count == 0


async def test_substituted_input_guard_transformation_refuses_before_loop(
    db: AsyncEngine,
) -> None:
    inner = ConversationStore(db)
    cid = await _conversation(inner)
    spy = _OrderRecordingStore(inner)
    loop = _SpyLoop()
    hooks = _ScriptedHookGuard(
        transform_input=lambda payload: _canonical_transform(
            payload,
            lambda value: value["messages"][-1].__setitem__("content", "[REDACTED]"),
        )
    )

    with pytest.raises(ConversationTurnRefused) as caught:
        await _post(_executor(spy, loop, hook_guard=hooks), cid, "raw secret")

    assert caught.value.reason == "conversation_hook_refused"
    assert loop.calls == []
    assert spy.append_kwargs == []


async def test_substituted_output_guard_transformation_refuses_without_turn(
    db: AsyncEngine,
) -> None:
    inner = ConversationStore(db)
    cid = await _conversation(inner)
    spy = _OrderRecordingStore(inner)
    hooks = _ScriptedHookGuard(
        transform_output=lambda payload: _canonical_transform(
            payload,
            lambda value: value.__setitem__("answer", "[MASKED]"),
        )
    )

    with pytest.raises(ConversationTurnRefused) as caught:
        await _post(_executor(spy, _SpyLoop(), hook_guard=hooks), cid)

    assert caught.value.reason == "conversation_hook_refused"
    assert caught.value.conversation_output_hook_count == 1
    assert spy.append_kwargs == []


async def test_input_hook_refusal_never_invokes_loop_or_persists(
    db: AsyncEngine,
) -> None:
    inner = ConversationStore(db)
    cid = await _conversation(inner)
    spy = _OrderRecordingStore(inner)
    loop = _SpyLoop()
    hooks = _ScriptedHookGuard(input_outcome="refused")

    with pytest.raises(ConversationTurnRefused) as exc:
        await _post(_executor(spy, loop, hook_guard=hooks), cid)

    assert exc.value.reason == "conversation_hook_refused"
    assert exc.value.current_state == "active"
    assert loop.calls == []
    assert spy.append_kwargs == []
    assert spy.settle_refused_kwargs == []
    assert len(spy.release_kwargs) == 1


@pytest.mark.parametrize("hook_decision_count", [0, False, 1.0])
async def test_passed_input_hook_requires_positive_exact_evidence_count(
    db: AsyncEngine,
    hook_decision_count: object,
) -> None:
    class _BadInputEvidenceCountGuard(_ScriptedHookGuard):
        async def scan(self, **kw: Any) -> ConversationHookScanResult:
            result = await super().scan(**kw)
            if kw["phase"] != "conversation_input":
                return result
            return ConversationHookScanResult(
                outcome=result.outcome,
                final_payload=result.final_payload,
                hook_decision_count=hook_decision_count,  # type: ignore[arg-type]
            )

    inner = ConversationStore(db)
    cid = await _conversation(inner)
    spy = _OrderRecordingStore(inner)
    loop = _SpyLoop()

    with pytest.raises(ConversationTurnRefused) as exc:
        await _post(
            _executor(spy, loop, hook_guard=_BadInputEvidenceCountGuard()),
            cid,
        )

    assert exc.value.reason == "conversation_hook_refused"
    assert loop.calls == []
    assert spy.append_kwargs == []
    assert spy.settle_refused_kwargs == []


@pytest.mark.parametrize("hook_decision_count", [True, -1, 1.5])
async def test_malformed_output_evidence_error_still_settles_spent_usage(
    db: AsyncEngine,
    hook_decision_count: object,
) -> None:
    class _MalformedEvidenceErrorGuard(_ScriptedHookGuard):
        async def scan(self, **kw: Any) -> ConversationHookScanResult:
            if kw["phase"] == "conversation_output":
                raise ConversationHookEvidenceError(
                    final_payload=kw["payload"],
                    hook_decision_count=hook_decision_count,  # type: ignore[arg-type]
                )
            return await super().scan(**kw)

    store = ConversationStore(db)
    cid = await _conversation(store)

    with pytest.raises(ConversationTurnRefused) as caught:
        await _post(
            _executor(store, _SpyLoop(), hook_guard=_MalformedEvidenceErrorGuard()),
            cid,
        )

    assert caught.value.reason == "conversation_hook_refused"
    assert caught.value.conversation_output_request_id is None
    assert caught.value.conversation_output_hook_count == 0
    record = await store.load(cid, tenant_id=_TENANT, creator_subject=_SUBJECT)
    assert record is not None
    assert record.cumulative_tokens == 5
    assert record.turn_count == 0
    rows = await _chain_rows(db)
    refused = [row for row in rows if row.event_type == "conversation.turn_refused"]
    assert len(refused) == 1


@pytest.mark.parametrize("terminal_state", ["completed", "refused", "failed"])
@pytest.mark.parametrize("outcome", ["refused", "failed"])
async def test_output_hook_nonpass_never_persists_or_returns_answer(
    db: AsyncEngine,
    outcome: ConversationHookOutcome,
    terminal_state: str,
) -> None:
    inner = ConversationStore(db)
    cid = await _conversation(inner)
    spy = _OrderRecordingStore(inner)
    loop = _SpyLoop(terminal_state=terminal_state)
    hooks = _ScriptedHookGuard(output_outcome=outcome)

    with pytest.raises(ConversationTurnRefused) as exc:
        await _post(_executor(spy, loop, hook_guard=hooks), cid)

    assert exc.value.reason == "conversation_hook_refused"
    assert len(loop.calls) == 1
    assert spy.append_kwargs == []
    assert len(spy.settle_refused_kwargs) == 1


async def test_input_hook_failure_collapses_without_exception_detail(
    db: AsyncEngine,
) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)

    with pytest.raises(ConversationTurnRefused) as exc:
        await _post(
            _executor(
                store,
                _SpyLoop(),
                hook_guard=_ScriptedHookGuard(raise_phase="conversation_input"),
            ),
            cid,
        )

    assert exc.value.reason == "conversation_hook_refused"
    assert "secret hook failure detail" not in str(exc.value)


async def test_output_hook_refusal_preserves_completed_run_but_persists_no_turn(
    db: AsyncEngine,
) -> None:
    inner = ConversationStore(db)
    cid = await _conversation(inner)
    spy = _OrderRecordingStore(inner)
    loop = _SpyLoop()
    hooks = _ScriptedHookGuard(output_outcome="refused")

    with pytest.raises(ConversationTurnRefused) as exc:
        await _post(_executor(spy, loop, hook_guard=hooks), cid)

    assert exc.value.reason == "conversation_hook_refused"
    assert len(loop.calls) == 1
    assert spy.append_kwargs == []
    assert len(spy.settle_refused_kwargs) == 1
    assert len(spy.release_kwargs) == 1
    output_call = hooks.calls[-1]
    assert output_call["conversation_id"] == cid
    assert output_call["turn_seq"] == 1
    assert output_call["agent_run_id"] == "agent-run-1"


async def test_repeated_output_refusals_settle_tokens_and_trip_budget(
    db: AsyncEngine,
) -> None:
    """R21: refused output spends tokens without becoming a transcript turn."""

    import sqlalchemy as sa

    from cognic_agentos.core.decision_history import _decision_history

    store = ConversationStore(db)
    cid = await _conversation(store)
    loop = _SpyLoop(
        prompt_tokens=3,
        completion_tokens=2,
        answer="model plaintext must never persist",
    )
    hooks = _ScriptedHookGuard(output_outcome="refused")
    executor = _executor(
        store,
        loop,
        hook_guard=hooks,
        cumulative_token_budget=10,
    )

    for _ in range(2):
        with pytest.raises(ConversationTurnRefused) as exc:
            await _post(executor, cid)
        assert exc.value.reason == "conversation_hook_refused"

    record = await store.load(cid, tenant_id=_TENANT, creator_subject=_SUBJECT)
    assert record is not None
    assert record.cumulative_tokens == 10
    assert record.turn_count == 0

    with pytest.raises(ConversationTurnRefused) as exc:
        await _post(executor, cid)
    assert exc.value.reason == "conversation_token_budget_exceeded"
    assert len(loop.calls) == 2

    async with db.connect() as conn:
        rows = (
            (
                await conn.execute(
                    sa.select(_decision_history.c.payload).where(
                        _decision_history.c.event_type == "conversation.turn_refused"
                    )
                )
            )
            .scalars()
            .all()
        )
    assert len(rows) == 2
    for payload in rows:
        assert payload["conversation_id"] == str(cid)
        assert payload["agent_run_id"] == "agent-run-1"
        assert payload["prompt_tokens"] == 3
        assert payload["completion_tokens"] == 2
        assert "model plaintext must never persist" not in str(payload)


async def test_malformed_hook_transformation_fails_closed(
    db: AsyncEngine,
) -> None:
    inner = ConversationStore(db)
    cid = await _conversation(inner)
    spy = _OrderRecordingStore(inner)
    loop = _SpyLoop()
    hooks = _ScriptedHookGuard(transform_input=lambda _payload: b'{"messages":[]}')

    with pytest.raises(ConversationTurnRefused) as exc:
        await _post(_executor(spy, loop, hook_guard=hooks), cid)

    assert exc.value.reason == "conversation_hook_refused"
    assert loop.calls == []
    assert spy.append_kwargs == []


async def test_hook_metadata_cannot_be_transformed(
    db: AsyncEngine,
) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    hooks = _ScriptedHookGuard(
        transform_input=lambda payload: _canonical_transform(
            payload,
            lambda value: value.__setitem__("tenant_id", "tenant-b"),
        )
    )

    with pytest.raises(ConversationTurnRefused) as exc:
        await _post(_executor(store, _SpyLoop(), hook_guard=hooks), cid)

    assert exc.value.reason == "conversation_hook_refused"


async def test_input_hook_refusal_reports_state_read_after_concurrent_close(
    db: AsyncEngine,
) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    loop = _SpyLoop()

    class _CloseThenRefuse(_PassHookGuard):
        async def scan(self, **kw: Any) -> ConversationHookScanResult:
            if kw["phase"] == "conversation_input":
                await store.transition(
                    conversation_id=cid,
                    tenant_id=_TENANT,
                    to_state="closed",
                    actor_id=_SUBJECT,
                    request_id="close-during-input-screening",
                )
                return ConversationHookScanResult(
                    outcome="refused",
                    final_payload=kw["payload"],
                    hook_decision_count=1,
                )
            return await super().scan(**kw)

    with pytest.raises(ConversationTurnRefused) as caught:
        await _post(_executor(store, loop, hook_guard=_CloseThenRefuse()), cid)

    assert caught.value.reason == "conversation_hook_refused"
    assert caught.value.current_state == "closed"
    assert loop.calls == []


@pytest.mark.parametrize(
    ("phase", "mutate"),
    [
        (
            "conversation_input",
            lambda value: value.__setitem__("schema_version", True),
        ),
        (
            "conversation_input",
            lambda value: value.__setitem__("schema_version", 1.0),
        ),
        (
            "conversation_output",
            lambda value: value.__setitem__("turn_seq", 1.0),
        ),
        (
            "conversation_input",
            lambda value: value.__setitem__("messages", []),
        ),
        (
            "conversation_input",
            lambda value: value["messages"][-1].__setitem__("role", "assistant"),
        ),
        (
            "conversation_output",
            lambda value: value.__setitem__("unexpected", "field"),
        ),
        (
            "conversation_output",
            lambda value: value.__setitem__("answer", 7),
        ),
    ],
    ids=[
        "boolean-integer",
        "float-schema-version",
        "float-turn-sequence",
        "input-cardinality",
        "input-structure",
        "output-shape",
        "output-answer-type",
    ],
)
async def test_hook_transformations_fail_closed_on_every_structural_boundary(
    db: AsyncEngine,
    phase: str,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)

    def transform(payload: bytes) -> bytes:
        return _canonical_transform(payload, mutate)

    hooks = _ScriptedHookGuard(
        transform_input=transform if phase == "conversation_input" else None,
        transform_output=transform if phase == "conversation_output" else None,
    )

    with pytest.raises(ConversationTurnRefused) as exc:
        await _post(_executor(store, _SpyLoop(), hook_guard=hooks), cid)

    assert exc.value.reason == "conversation_hook_refused"


@pytest.mark.parametrize(
    "malformed",
    [
        b'{"messages":[{"content":"a","content":"b"}]}',
        b'{"schema_version":NaN}',
        b"\xff",
    ],
    ids=["nested-duplicate", "nonstandard-number", "invalid-utf8"],
)
async def test_untrusted_hook_json_is_rejected_before_mapping(
    db: AsyncEngine,
    malformed: bytes,
) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    hooks = _ScriptedHookGuard(transform_input=lambda _payload: malformed)

    with pytest.raises(ConversationTurnRefused) as exc:
        await _post(_executor(store, _SpyLoop(), hook_guard=hooks), cid)

    assert exc.value.reason == "conversation_hook_refused"


async def test_noncanonical_hook_json_is_rejected(
    db: AsyncEngine,
) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    hooks = _ScriptedHookGuard(transform_input=lambda payload: payload.replace(b"{", b"{ ", 1))

    with pytest.raises(ConversationTurnRefused) as exc:
        await _post(_executor(store, _SpyLoop(), hook_guard=hooks), cid)

    assert exc.value.reason == "conversation_hook_refused"


async def test_substituted_input_guard_cannot_transform_prior_content(
    db: AsyncEngine,
) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    first = _executor(store, _SpyLoop())
    await _post(first, cid, "first")
    loop = _SpyLoop()
    hooks = _ScriptedHookGuard(
        transform_input=lambda payload: _canonical_transform(
            payload,
            lambda value: value["messages"][0].__setitem__("content", "[MASKED PRIOR]"),
        )
    )

    with pytest.raises(ConversationTurnRefused) as caught:
        await _post(_executor(store, loop, hook_guard=hooks), cid, "second")

    assert caught.value.reason == "conversation_hook_refused"
    assert loop.calls == []


# --- CC branch closure: canonical hook envelopes + refusal correlation --------


async def test_hook_payload_validators_reject_every_untrusted_shape() -> None:
    """Exercise each fail-closed parser boundary without a permissive test seam."""

    import json

    from cognic_agentos.core.canonical import canonical_bytes
    from cognic_agentos.core.conversation.turn import (
        _decode_canonical_hook_payload,
        _input_hook_payload,
        _output_hook_payload,
        _validated_input_hook_result,
        _validated_output_hook_result,
    )

    cid = uuid.uuid4()
    governance = ConversationHookGovernance(
        pack_id="cognic-agent-analyst",
        declared_data_classes=("internal",),
        manifest_purpose="operational_telemetry",
    )
    input_payload = _input_hook_payload(
        conversation_id=cid,
        tenant_id=_TENANT,
        turn_seq=1,
        governance=governance,
        prior_context=(),
        user_message="question",
    )
    output_payload = _output_hook_payload(
        conversation_id=cid,
        tenant_id=_TENANT,
        turn_seq=1,
        governance=governance,
        answer="answer",
    )

    with pytest.raises(ValueError, match="malformed payload"):
        _decode_canonical_hook_payload(b"[]")
    with pytest.raises(ValueError, match="malformed payload"):
        _decode_canonical_hook_payload(b'{"schema_version":NaN}')

    def mutate(payload: bytes, key: str, value: Any) -> bytes:
        decoded = json.loads(payload)
        decoded[key] = value
        return canonical_bytes(decoded)

    invalid_inputs = [
        mutate(input_payload, "unexpected", "field"),
        mutate(input_payload, "schema_version", True),
        mutate(input_payload, "tenant_id", "other-tenant"),
        mutate(input_payload, "messages", []),
        mutate(
            input_payload,
            "messages",
            [{"role": "assistant", "content": "question"}],
        ),
    ]
    for payload in invalid_inputs:
        with pytest.raises(ValueError):
            _validated_input_hook_result(
                payload,
                conversation_id=cid,
                tenant_id=_TENANT,
                turn_seq=1,
                governance=governance,
                prior_context=(),
            )

    for payload in (
        mutate(output_payload, "unexpected", "field"),
        mutate(output_payload, "answer", 7),
    ):
        with pytest.raises(ValueError):
            _validated_output_hook_result(
                payload,
                conversation_id=cid,
                tenant_id=_TENANT,
                turn_seq=1,
                governance=governance,
            )


async def test_both_turn_kinds_invoke_their_payload_validators(
    db: AsyncEngine,
) -> None:
    """The callback seam validates unchanged payloads for both output origins."""

    class _CallbackInvokingGuard(_PassHookGuard):
        async def scan(self, **kw: Any) -> ConversationHookScanResult:
            kw["validate_transformed_payload"](kw["payload"])
            projector = kw.get("evidence_value_projector")
            if projector is not None:
                assert projector(kw["payload"])
            return await super().scan(**kw)

    store = ConversationStore(db)
    cid = await _conversation(store)
    hooks = _CallbackInvokingGuard()
    executor = _executor(store, _SpyLoop(), hook_guard=hooks)

    await _post(executor, cid)
    await executor.post_system_turn(
        conversation_id=cid,
        tenant_id=_TENANT,
        text="approved result",
        approval_request_id="a1b2c3d4-1111-4222-8333-444455556666",
        request_id="req-callback-validator",
    )

    assert [call["phase"] for call in hooks.calls] == [
        "conversation_input",
        "conversation_output",
        "conversation_output",
    ]


@pytest.mark.parametrize("hook_decision_count", [0, False, 1.5])
async def test_regular_output_scan_requires_positive_exact_evidence_count(
    db: AsyncEngine,
    hook_decision_count: object,
) -> None:
    class _BadOutputCountGuard(_ScriptedHookGuard):
        async def scan(self, **kw: Any) -> ConversationHookScanResult:
            result = await super().scan(**kw)
            if kw["phase"] == "conversation_output":
                return ConversationHookScanResult(
                    outcome=result.outcome,
                    final_payload=result.final_payload,
                    hook_decision_count=hook_decision_count,  # type: ignore[arg-type]
                )
            return result

    store = ConversationStore(db)
    cid = await _conversation(store)
    with pytest.raises(ConversationTurnRefused) as caught:
        await _post(_executor(store, _SpyLoop(), hook_guard=_BadOutputCountGuard()), cid)

    assert caught.value.reason == "conversation_hook_refused"
    assert caught.value.conversation_output_request_id is None
    assert caught.value.conversation_output_hook_count == 0
    record = await store.load(cid, tenant_id=_TENANT, creator_subject=_SUBJECT)
    assert record is not None and record.cumulative_tokens == 5


async def test_regular_output_evidence_prefix_retains_correlation(
    db: AsyncEngine,
) -> None:
    class _EvidencePrefixGuard(_ScriptedHookGuard):
        async def scan(self, **kw: Any) -> ConversationHookScanResult:
            if kw["phase"] == "conversation_output":
                raise ConversationHookEvidenceError(
                    final_payload=kw["payload"],
                    hook_decision_count=1,
                )
            return await super().scan(**kw)

    store = ConversationStore(db)
    cid = await _conversation(store)
    with pytest.raises(ConversationTurnRefused) as caught:
        await _post(_executor(store, _SpyLoop(), hook_guard=_EvidencePrefixGuard()), cid)

    assert caught.value.reason == "conversation_hook_refused"
    assert caught.value.conversation_output_request_id is not None
    assert caught.value.conversation_output_hook_count == 1


async def test_regular_output_runtime_failure_has_no_false_correlation(
    db: AsyncEngine,
) -> None:
    store = ConversationStore(db)
    cid = await _conversation(store)
    with pytest.raises(ConversationTurnRefused) as caught:
        await _post(
            _executor(
                store,
                _SpyLoop(),
                hook_guard=_ScriptedHookGuard(raise_phase="conversation_output"),
            ),
            cid,
        )

    assert caught.value.reason == "conversation_hook_refused"
    assert caught.value.conversation_output_request_id is None
    assert caught.value.conversation_output_hook_count == 0


@pytest.mark.parametrize("hook_decision_count", [0, False, 1.5])
async def test_system_output_scan_requires_positive_exact_evidence_count(
    db: AsyncEngine,
    hook_decision_count: object,
) -> None:
    class _BadSystemOutputCountGuard(_PassHookGuard):
        async def scan(self, **kw: Any) -> ConversationHookScanResult:
            return ConversationHookScanResult(
                outcome="passed",
                final_payload=kw["payload"],
                hook_decision_count=hook_decision_count,  # type: ignore[arg-type]
            )

    store = ConversationStore(db)
    cid = await _conversation(store)
    with pytest.raises(ConversationTurnRefused) as caught:
        await _executor(
            store,
            _SpyLoop(),
            hook_guard=_BadSystemOutputCountGuard(),
        ).post_system_turn(
            conversation_id=cid,
            tenant_id=_TENANT,
            text="approved result",
            approval_request_id="a1b2c3d4-1111-4222-8333-444455556666",
            request_id="req-system-bad-count",
        )

    assert caught.value.reason == "conversation_hook_refused"
    assert caught.value.conversation_output_request_id is None
    assert caught.value.conversation_output_hook_count == 0


@pytest.mark.parametrize(
    ("hook_decision_count", "is_correlated"),
    [(True, False), (0, False), (1, True)],
)
async def test_system_output_evidence_error_preserves_only_valid_prefix(
    db: AsyncEngine,
    hook_decision_count: object,
    is_correlated: bool,
) -> None:
    class _SystemEvidenceErrorGuard(_PassHookGuard):
        async def scan(self, **kw: Any) -> ConversationHookScanResult:
            raise ConversationHookEvidenceError(
                final_payload=kw["payload"],
                hook_decision_count=hook_decision_count,  # type: ignore[arg-type]
            )

    store = ConversationStore(db)
    cid = await _conversation(store)
    with pytest.raises(ConversationTurnRefused) as caught:
        await _executor(
            store,
            _SpyLoop(),
            hook_guard=_SystemEvidenceErrorGuard(),
        ).post_system_turn(
            conversation_id=cid,
            tenant_id=_TENANT,
            text="approved result",
            approval_request_id="a1b2c3d4-1111-4222-8333-444455556666",
            request_id="req-system-evidence-error",
        )

    assert caught.value.reason == "conversation_hook_refused"
    assert (caught.value.conversation_output_request_id is not None) is is_correlated
    assert caught.value.conversation_output_hook_count == (1 if is_correlated else 0)


async def test_system_output_malformed_refusal_retains_assigned_correlation(
    db: AsyncEngine,
) -> None:
    class _MalformedRefusalGuard(_PassHookGuard):
        async def scan(self, **kw: Any) -> ConversationHookScanResult:
            return ConversationHookScanResult(
                outcome="refused",
                final_payload=b"not-json",
                hook_decision_count=1,
            )

    store = ConversationStore(db)
    cid = await _conversation(store)
    with pytest.raises(ConversationTurnRefused) as caught:
        await _executor(
            store,
            _SpyLoop(),
            hook_guard=_MalformedRefusalGuard(),
        ).post_system_turn(
            conversation_id=cid,
            tenant_id=_TENANT,
            text="approved result",
            approval_request_id="a1b2c3d4-1111-4222-8333-444455556666",
            request_id="req-system-malformed-refusal",
        )

    assert caught.value.reason == "conversation_hook_refused"
    assert caught.value.conversation_output_request_id is not None
    assert caught.value.conversation_output_hook_count == 1
