"""M8.5-D D2-C approval auto-executor contracts."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.approval._types import (
    ApprovalCheckResult,
    ApprovalTransitionRefused,
)
from cognic_agentos.core.approval.executor import ApprovalExecutionService
from cognic_agentos.core.approval.replay import ApprovalReplayUnavailable
from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH, canonical_bytes
from cognic_agentos.core.conversation._types import ConversationTurnRefused
from cognic_agentos.core.conversation.storage import ConversationStore, _conversation_turns
from cognic_agentos.core.conversation.turn import (
    ConversationHookGovernance,
    ConversationHookScanResult,
    ConversationTurnExecutor,
)
from cognic_agentos.core.decision_history import (
    DecisionHistoryStore,
    DecisionRecord,
    _decision_history,
)

_REQUEST_ID = uuid.UUID("a1b2c3d4-1111-4222-8333-444455556666")
_CONVERSATION_ID = uuid.UUID("00000000-1111-4222-8333-444455556666")
_TENANT = "tenant-a"
_ARGS = {"employee_id": "e-17", "day": "2026-07-21"}
_ARGS_BYTES = canonical_bytes(_ARGS)
_ARGS_DIGEST = hashlib.sha256(_ARGS_BYTES).digest()


def _private_key() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _check() -> ApprovalCheckResult:
    return ApprovalCheckResult(
        state="granted",
        request_id=_REQUEST_ID,
        flow="require_single_approval",
        risk_tier="payment_action",
        tool_identity="mcp:bound",
        args_digest=_ARGS_DIGEST,
        envelope_digest=b"e" * 32,
        originator_subject="analyst.amir",
        decisions_recorded=1,
        required_count=1,
        required_refs={
            "mcp_server_id": "cognic-tool-leave",
            "mcp_tool_name": "apply_leave",
        },
    )


class _Engine:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.rows = ((_REQUEST_ID, _TENANT),)

    async def check(self, **_: Any) -> ApprovalCheckResult:
        self.events.append("check")
        return _check()

    async def list_granted_unconsumed_before(self, **_: Any) -> tuple[tuple[uuid.UUID, str], ...]:
        self.events.append("list")
        return self.rows


class _Replay:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.args: bytes | Exception = _ARGS_BYTES
        self.result: bytes | None | Exception = canonical_bytes(
            [
                "cognic.approval.replay-result.v1",
                "executed",
                {"status": "applied"},
            ]
        )
        self.recorded: list[bytes] = []
        self.record_exc: Exception | None = None

    async def load(self, **_: Any) -> bytes:
        self.events.append("load")
        if isinstance(self.args, Exception):
            raise self.args
        return self.args

    async def load_result(self, **_: Any) -> bytes | None:
        self.events.append("load_result")
        if isinstance(self.result, Exception):
            raise self.result
        return self.result

    async def record_result(self, *, result_canonical: bytes, **_: Any) -> None:
        self.events.append("record")
        if self.record_exc is not None:
            raise self.record_exc
        self.recorded.append(result_canonical)


class _Completer:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.context: tuple[uuid.UUID, str] | None = (_CONVERSATION_ID, "bank-agent")
        self.posts: list[dict[str, Any]] = []
        self.exc: Exception | None = None

    async def resolve_approval_context(self, **_: Any) -> tuple[uuid.UUID, str] | None:
        self.events.append("resolve")
        return self.context

    async def post_system_turn(self, **kwargs: Any) -> uuid.UUID:
        self.events.append("system")
        self.posts.append(kwargs)
        if self.exc is not None:
            raise self.exc
        return uuid.UUID("10000000-1111-4222-8333-444455556666")


class _RefusingRealHookGuard:
    def __init__(self, history: DecisionHistoryStore) -> None:
        self._history = history

    def turn_timeout_budget_s(self) -> float:
        return 0.0

    def governance_for_agent(self, *, agent_id: str) -> ConversationHookGovernance:
        assert agent_id == "bank-agent"
        return ConversationHookGovernance(
            pack_id="cognic-agent-test",
            declared_data_classes=("internal",),
            manifest_purpose="operational_telemetry",
        )

    async def scan(self, **kwargs: Any) -> ConversationHookScanResult:
        assert kwargs["phase"] == "conversation_output"
        payload = kwargs["payload"]
        projector = kwargs["evidence_value_projector"]
        value = projector(payload)
        payload_sha256 = hashlib.sha256(payload).hexdigest()
        value_sha256 = hashlib.sha256(value).hexdigest()
        await self._history.append(
            DecisionRecord(
                decision_type="hook.refused",
                request_id=kwargs["request_id"],
                payload={
                    "event_type": "hook.refused",
                    "phase": "conversation_output",
                    "hook_id": "content-safety",
                    "pack_distribution_name": "cognic-hook-test",
                    "pack_distribution_version": "0.1.0",
                    "outcome": "refused",
                    "failure_mode": "hook_policy_refused",
                    "policy_reason": None,
                    "policy_input_digest": payload_sha256,
                    "hook_input_digest": payload_sha256,
                    "hook_output_digest": payload_sha256,
                    "tenant_id": kwargs["tenant_id"],
                    "request_id": kwargs["request_id"],
                    "decision": "refuse",
                    "exception_class": None,
                    "hook_input_value_sha256": value_sha256,
                    "hook_output_value_sha256": value_sha256,
                    "conversation_id": str(kwargs["conversation_id"]),
                    "conversation_turn_seq": kwargs["turn_seq"],
                    "agent_run_id": kwargs["agent_run_id"],
                },
                actor_id="system:hook-dispatcher",
                tenant_id=kwargs["tenant_id"],
            )
        )
        return ConversationHookScanResult(
            outcome="refused",
            final_payload=payload,
            hook_decision_count=1,
        )


class _ToolProxy:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.exc: Exception | None = None
        self.already_consumed = False
        self.arguments: dict[str, Any] | None = None

    async def execute_consumed_action(self, *, prepare_arguments: Any, **_: Any) -> Any:
        self.events.append("consume")
        if self.already_consumed:
            raise ApprovalTransitionRefused("approval_consumed")
        self.arguments = dict(await prepare_arguments(_check()))
        self.events.append("dispatch")
        if self.exc is not None:
            raise self.exc
        return SimpleNamespace(payload={"structuredContent": {"status": "applied"}})


class _History:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.records: list[Any] = []

    async def append(self, record: Any) -> tuple[uuid.UUID, bytes]:
        self.events.append("chain")
        self.records.append(record)
        return uuid.uuid4(), b"h" * 32


def _service() -> tuple[ApprovalExecutionService, list[str], Any, Any, Any, Any]:
    events: list[str] = []
    engine = _Engine(events)
    replay = _Replay(events)
    tool = _ToolProxy(events)
    completer = _Completer(events)
    history = _History(events)
    service = ApprovalExecutionService(
        engine=engine,
        replay_store=replay,
        tool_proxy=tool,
        conversation_completer=completer,
        decision_history=history,
        signing_key=_private_key(),
        settings=SimpleNamespace(action_context_ttl_s=120.0, approval_executor_grace_s=30.0),
        clock=lambda: datetime(2026, 7, 16, 12, 0, tzinfo=UTC),
    )
    return service, events, engine, replay, tool, completer


@pytest.mark.asyncio
async def test_happy_path_is_consume_load_dispatch_chain_record_turn() -> None:
    service, events, _, replay, tool, completer = _service()
    assert await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT) == "executed"
    assert events == [
        "check",
        "resolve",
        "consume",
        "load",
        "dispatch",
        "chain",
        "record",
        "system",
    ]
    assert len(replay.recorded) == 1
    assert json.loads(replay.recorded[0]) == [
        "cognic.approval.replay-result.v1",
        "executed",
        {"status": "applied"},
    ]
    assert tool.arguments is not None
    assert tool.arguments["employee_id"] == "e-17"
    assert "_cognic_action_context" in tool.arguments
    assert completer.posts[0]["conversation_id"] == _CONVERSATION_ID
    history = cast(_History, service._history)
    execution = history.records[0]
    assert execution.decision_type == "approval.executed"
    assert execution.payload["system_turn_id"] is None
    assert execution.payload["delivery_request_id"] == completer.posts[0]["request_id"]
    assert (
        execution.payload["replay_result_sha256"] == hashlib.sha256(replay.recorded[0]).hexdigest()
    )
    assert execution.payload["replay_result_bytes"] == len(replay.recorded[0])
    assert (
        execution.payload["delivery_input_sha256"]
        == hashlib.sha256(completer.posts[0]["text"].encode()).hexdigest()
    )


@pytest.mark.asyncio
async def test_already_consumed_re_evidences_without_redispatch_or_redelivery() -> None:
    service, events, _, _, tool, completer = _service()
    tool.already_consumed = True
    assert (
        await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT)
        == "already_executed"
    )
    assert events == [
        "check",
        "resolve",
        "consume",
        "load_result",
        "chain",
    ]
    assert "dispatch" not in events
    history = cast(_History, service._history)
    assert len(history.records) == 1
    assert history.records[0].decision_type == "approval.executed"
    assert history.records[0].payload["execution"] == "executed"
    assert history.records[0].payload["delivery_request_id"] is None
    assert history.records[0].payload["delivery_input_sha256"] is None
    assert history.records[0].payload["delivery_input_bytes"] == 0
    assert completer.posts == []


@pytest.mark.asyncio
async def test_digest_drift_after_consume_fails_closed_and_posts_failure_turn() -> None:
    service, events, _, replay, _, completer = _service()
    replay.args = canonical_bytes({"employee_id": "tampered"})
    assert (
        await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT)
        == "replay_unavailable"
    )
    assert events == ["check", "resolve", "consume", "load", "chain", "system"]
    assert "dispatch" not in events
    assert "unavailable" in completer.posts[0]["text"].lower()


@pytest.mark.asyncio
async def test_reserved_context_key_in_replay_fails_closed() -> None:
    service, events, _, replay, _, _ = _service()
    replay.args = canonical_bytes({**_ARGS, "_cognic_action_context": "caller-authored"})
    consumed = dataclasses.replace(
        _check(),
        args_digest=hashlib.sha256(replay.args).digest(),
    )

    async def load_with_reserved(**_: Any) -> bytes:
        events.append("load")
        assert isinstance(replay.args, bytes)
        return replay.args

    replay.load = load_with_reserved
    tool = _ToolProxy(events)

    async def execute_with_reserved(*, prepare_arguments: Any, **_: Any) -> Any:
        events.append("consume")
        await prepare_arguments(consumed)
        raise AssertionError("reserved replay unexpectedly dispatched")

    cast(Any, tool).execute_consumed_action = execute_with_reserved
    service._tool_proxy = tool
    assert (
        await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT)
        == "replay_unavailable"
    )
    assert "dispatch" not in events


@pytest.mark.asyncio
async def test_non_consumed_transition_refusal_becomes_replay_failure() -> None:
    service, events, _, _, tool, _ = _service()
    tool.exc = ApprovalTransitionRefused("approval_binding_mismatch")
    assert (
        await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT)
        == "replay_unavailable"
    )
    assert events[-2:] == ["chain", "system"]


@pytest.mark.asyncio
@pytest.mark.parametrize("stored_result", [None, ApprovalReplayUnavailable("replay_erased")])
async def test_consumed_without_a_verified_result_fails_closed(stored_result: Any) -> None:
    service, events, _, replay, tool, _ = _service()
    tool.already_consumed = True
    replay.result = stored_result
    assert (
        await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT)
        == "replay_unavailable"
    )
    assert "dispatch" not in events
    assert events[-1:] == ["chain"]
    assert "system" not in events


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "legacy_result",
    [
        {"status": "applied"},
        {"status": "failed", "error_type": "RuntimeError"},
    ],
)
async def test_consumed_legacy_raw_result_is_ambiguous_and_fails_closed(
    legacy_result: dict[str, str],
) -> None:
    service, events, _, replay, tool, _ = _service()
    tool.already_consumed = True
    replay.result = canonical_bytes(legacy_result)

    assert (
        await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT)
        == "replay_unavailable"
    )
    assert "dispatch" not in events
    assert "system" not in events
    history = cast(_History, service._history)
    assert history.records[-1].payload["execution"] == "replay_unavailable"


@pytest.mark.asyncio
async def test_dispatch_failure_is_evidenced_then_recorded_and_posts_failure_turn() -> None:
    service, events, _, replay, tool, completer = _service()
    tool.exc = RuntimeError("SECRET-upstream-body")
    assert (
        await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT)
        == "dispatch_failed"
    )
    assert events == [
        "check",
        "resolve",
        "consume",
        "load",
        "dispatch",
        "chain",
        "record",
        "system",
    ]
    rendered = replay.recorded[0].decode() + completer.posts[0]["text"]
    assert "SECRET-upstream-body" not in rendered
    assert "RuntimeError" in rendered


@pytest.mark.asyncio
async def test_result_store_failure_cannot_erase_execution_truth_or_attempt_delivery() -> None:
    service, events, _, replay, _, completer = _service()
    replay.record_exc = RuntimeError("result store unavailable")

    with pytest.raises(RuntimeError, match="result store unavailable"):
        await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT)

    history = cast(_History, service._history)
    assert [record.decision_type for record in history.records] == ["approval.executed"]
    assert history.records[0].payload["execution"] == "executed"
    assert events[-2:] == ["chain", "record"]
    assert "system" not in events
    assert completer.posts == []


@pytest.mark.asyncio
async def test_execution_is_evidenced_before_delivery_refusal_and_refusal_is_chained() -> None:
    service, events, _, _, _, completer = _service()
    refusal = ConversationTurnRefused(
        "conversation_hook_refused",
        current_state="active",
        conversation_output_request_id="conv-hook-" + "a" * 32,
        conversation_output_hook_count=2,
        conversation_output_value_sha256=hashlib.sha256(b"masked").hexdigest(),
        conversation_output_value_bytes=len(b"masked"),
    )
    completer.exc = refusal

    assert await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT) == "executed"
    assert events[-4:] == ["chain", "record", "system", "chain"]

    history = cast(_History, service._history)
    assert [record.decision_type for record in history.records] == [
        "approval.executed",
        "approval.delivery_refused",
    ]
    execution, delivery = history.records
    delivery_request_id = execution.payload["delivery_request_id"]
    assert delivery.request_id == delivery_request_id == completer.posts[0]["request_id"]
    assert delivery.payload == {
        "approval_request_id": str(_REQUEST_ID),
        "approval_state": "granted",
        "action_id": "cognic-tool-leave/apply_leave",
        "args_sha256": _ARGS_DIGEST.hex(),
        "result_sha256": execution.payload["result_sha256"],
        "result_bytes": execution.payload["result_bytes"],
        "execution": "executed",
        "conversation_id": str(_CONVERSATION_ID),
        "delivery_request_id": delivery_request_id,
        "delivery_input_sha256": execution.payload["delivery_input_sha256"],
        "delivery_input_bytes": execution.payload["delivery_input_bytes"],
        "delivery_output_sha256": hashlib.sha256(b"masked").hexdigest(),
        "delivery_output_bytes": len(b"masked"),
        "refusal_reason": "conversation_hook_refused",
        "conversation_output_request_id": "conv-hook-" + "a" * 32,
        "conversation_output_hook_count": 2,
    }
    assert "Approved and executed" not in repr(delivery.payload)
    assert "status" not in repr(delivery.payload)


@pytest.mark.asyncio
async def test_late_conversation_append_race_does_not_forge_hook_refusal_evidence() -> None:
    service, events, _, _, _, completer = _service()
    completer.exc = ConversationTurnRefused(
        "conversation_turn_claim_stale",
        current_state="active",
        conversation_output_request_id="conv-hook-" + "f" * 32,
        conversation_output_hook_count=1,
        conversation_output_value_sha256=hashlib.sha256(b"screened").hexdigest(),
        conversation_output_value_bytes=len(b"screened"),
    )

    assert await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT) == "executed"

    history = cast(_History, service._history)
    assert [record.decision_type for record in history.records] == ["approval.executed"]
    assert events[-3:] == ["chain", "record", "system"]


@pytest.mark.asyncio
async def test_real_chain_records_execution_then_hook_refusal_without_a_system_turn(
    tmp_path: Path,
) -> None:
    db = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'approval-refusal.db'}")
    try:
        async with db.begin() as conn:
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

        history = DecisionHistoryStore(db)
        store = ConversationStore(db)
        await store.create_conversation(
            conversation_id=_CONVERSATION_ID,
            tenant_id=_TENANT,
            agent_id="bank-agent",
            creator_subject="analyst.amir",
            request_id="conversation-create",
        )
        claim = await store.claim_turn(
            _CONVERSATION_ID,
            tenant_id=_TENANT,
            creator_subject="analyst.amir",
            now=datetime.now(UTC),
            claim_ttl_s=60.0,
        )
        await store.append_turn(
            conversation_id=_CONVERSATION_ID,
            tenant_id=_TENANT,
            seq=1,
            user_message="request",
            answer="Pending approval.",
            agent_run_id="agent-run-pending",
            prompt_tokens=1,
            completion_tokens=1,
            actor_id="analyst.amir",
            request_id="conversation-pending",
            claim_id=claim.claim_id,
            approval_request_id=str(_REQUEST_ID),
        )
        await store.release_claim(
            _CONVERSATION_ID,
            tenant_id=_TENANT,
            claim_id=claim.claim_id,
        )
        completer = ConversationTurnExecutor(
            store=store,
            loop=cast(Any, object()),
            hook_guard=_RefusingRealHookGuard(history),
            max_turns=10,
            cumulative_token_budget=10_000,
            replay_last_n=10,
            replay_token_ceiling=10_000,
            claim_ttl_s=60.0,
            agent_run_wall_clock_s=30.0,
        )
        service, events, _, _, tool, _ = _service()
        service._completer = completer
        service._history = history

        assert (
            await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT) == "executed"
        )
        assert events.count("dispatch") == 1

        async with db.connect() as conn:
            rows = (
                (
                    await conn.execute(
                        select(
                            _decision_history.c.sequence,
                            _decision_history.c.event_type,
                            _decision_history.c.payload,
                        )
                        .where(_decision_history.c.tenant_id == _TENANT)
                        .order_by(_decision_history.c.sequence)
                    )
                )
                .mappings()
                .all()
            )
            turn_count = (
                await conn.execute(
                    select(_conversation_turns.c.turn_id).where(
                        _conversation_turns.c.conversation_id == _CONVERSATION_ID,
                        _conversation_turns.c.turn_kind == "system",
                    )
                )
            ).all()

        relevant = [
            row
            for row in rows
            if row["event_type"]
            in {"approval.executed", "hook.refused", "approval.delivery_refused"}
        ]
        assert [row["event_type"] for row in relevant] == [
            "approval.executed",
            "hook.refused",
            "approval.delivery_refused",
        ]
        execution, hook_refusal, delivery_refusal = relevant
        assert (
            execution["payload"]["delivery_input_sha256"]
            == hook_refusal["payload"]["hook_input_value_sha256"]
            == hook_refusal["payload"]["hook_output_value_sha256"]
            == delivery_refusal["payload"]["delivery_input_sha256"]
            == delivery_refusal["payload"]["delivery_output_sha256"]
        )
        assert turn_count == []
        assert all(row["event_type"] != "conversation.system_turn_appended" for row in rows)

        before_retry = tuple((row["sequence"], row["event_type"]) for row in rows)
        tool.already_consumed = True
        assert (
            await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT)
            == "already_executed"
        )
        assert events.count("dispatch") == 1
        async with db.connect() as conn:
            after_retry = (
                (
                    await conn.execute(
                        select(
                            _decision_history.c.sequence,
                            _decision_history.c.event_type,
                        )
                        .where(_decision_history.c.tenant_id == _TENANT)
                        .order_by(_decision_history.c.sequence)
                    )
                )
                .tuples()
                .all()
            )
        assert tuple(after_retry[: len(before_retry)]) == before_retry
        assert [event_type for _, event_type in after_retry[len(before_retry) :]] == [
            "approval.executed",
        ]
    finally:
        await db.dispose()


@pytest.mark.asyncio
async def test_execution_evidence_failure_prevents_delivery() -> None:
    service, events, _, _, _, completer = _service()

    class _FailingHistory:
        async def append(self, record: Any) -> None:
            events.append("chain_failed")
            raise RuntimeError("evidence unavailable")

    service._history = _FailingHistory()
    with pytest.raises(RuntimeError, match="evidence unavailable"):
        await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT)
    assert "system" not in events
    assert completer.posts == []


@pytest.mark.asyncio
async def test_retry_after_delivery_refusal_re_evidences_without_redispatch_or_redelivery() -> None:
    service, events, _, _, tool, completer = _service()
    completer.exc = ConversationTurnRefused(
        "conversation_hook_refused",
        current_state="active",
        conversation_output_request_id="conv-hook-" + "b" * 32,
        conversation_output_hook_count=1,
        conversation_output_value_sha256=hashlib.sha256(b"screened").hexdigest(),
        conversation_output_value_bytes=len(b"screened"),
    )
    assert await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT) == "executed"
    history = cast(_History, service._history)
    assert len(history.records) == 2

    tool.already_consumed = True
    completer.exc = None
    assert (
        await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT)
        == "already_executed"
    )
    assert events.count("dispatch") == 1
    assert [record.decision_type for record in history.records] == [
        "approval.executed",
        "approval.delivery_refused",
        "approval.executed",
    ]
    assert history.records[-1].payload["execution"] == "executed"
    assert history.records[-1].payload["delivery_request_id"] is None
    assert len(completer.posts) == 1


@pytest.mark.asyncio
async def test_correlated_delivery_refusal_without_final_digest_fails_closed() -> None:
    service, _, _, _, _, completer = _service()
    completer.exc = ConversationTurnRefused(
        "conversation_hook_refused",
        current_state="active",
        conversation_output_request_id="conv-hook-" + "d" * 32,
        conversation_output_hook_count=1,
    )

    with pytest.raises(
        ValueError,
        match="correlated delivery refusal is missing the final screened-value digest",
    ):
        await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT)

    history = cast(_History, service._history)
    assert [record.decision_type for record in history.records] == ["approval.executed"]


@pytest.mark.asyncio
async def test_retry_of_stored_dispatch_failure_never_claims_execution_success() -> None:
    service, events, _, replay, tool, completer = _service()
    tool.exc = RuntimeError("upstream refused")

    assert (
        await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT)
        == "dispatch_failed"
    )
    assert len(replay.recorded) == 1
    replay.result = replay.recorded[0]
    tool.already_consumed = True
    tool.exc = None

    assert (
        await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT)
        == "dispatch_failed"
    )
    assert events.count("dispatch") == 1
    history = cast(_History, service._history)
    assert [record.payload["execution"] for record in history.records] == [
        "dispatch_failed",
        "dispatch_failed",
    ]
    assert history.records[-1].payload["delivery_request_id"] is None
    assert len(completer.posts) == 1


@pytest.mark.asyncio
async def test_mcp_tool_level_error_cannot_be_recorded_as_executed() -> None:
    """A transport-successful MCP ``isError`` result is still a failed action."""
    service, _, _, replay, tool, completer = _service()

    async def execute_error(*, prepare_arguments: Any, **_: Any) -> Any:
        await prepare_arguments(_check())
        return SimpleNamespace(
            payload=SimpleNamespace(
                isError=True,
                model_dump=lambda **_: {
                    "isError": True,
                    "content": [{"type": "text", "text": "SECRET-validation-body"}],
                },
            )
        )

    tool.execute_consumed_action = execute_error

    assert (
        await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT)
        == "dispatch_failed"
    )
    rendered = replay.recorded[-1] + completer.posts[-1]["text"].encode()
    assert b"SECRET-validation-body" not in rendered
    history = cast(Any, service._history)
    assert history.records[-1].payload["execution"] == "dispatch_failed"


@pytest.mark.asyncio
async def test_dumped_mcp_tool_level_error_cannot_be_recorded_as_executed() -> None:
    """The fail-closed check also covers an error exposed only after model_dump."""
    service, _, _, replay, tool, completer = _service()

    async def execute_error(*, prepare_arguments: Any, **_: Any) -> Any:
        await prepare_arguments(_check())
        return SimpleNamespace(
            payload=SimpleNamespace(
                model_dump=lambda **_: {
                    "isError": True,
                    "content": [{"type": "text", "text": "SECRET-validation-body"}],
                },
            )
        )

    tool.execute_consumed_action = execute_error

    assert (
        await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT)
        == "dispatch_failed"
    )
    rendered = replay.recorded[-1] + completer.posts[-1]["text"].encode()
    assert b"SECRET-validation-body" not in rendered
    history = cast(Any, service._history)
    assert history.records[-1].payload["execution"] == "dispatch_failed"


@pytest.mark.asyncio
async def test_sweep_redrives_only_supported_unconsumed_requests() -> None:
    service, events, engine, _, _, completer = _service()
    unsupported = uuid.UUID("b1b2c3d4-1111-4222-8333-444455556666")
    engine.rows = ((_REQUEST_ID, _TENANT), (unsupported, _TENANT))
    original = completer.resolve_approval_context

    async def resolve(*, approval_request_id: uuid.UUID, **kwargs: Any) -> Any:
        if approval_request_id == unsupported:
            events.append("resolve")
            return None
        return await original(approval_request_id=approval_request_id, **kwargs)

    completer.resolve_approval_context = resolve
    outcomes = await service.sweep_granted_unconsumed(grace_s=30.0)
    assert outcomes == ((_REQUEST_ID, "executed"),)
    assert events.count("dispatch") == 1


@pytest.mark.asyncio
async def test_sweep_uses_the_configured_grace_by_default() -> None:
    service, _, engine, _, _, _ = _service()
    engine.rows = ()
    captured: dict[str, datetime] = {}

    async def list_rows(*, cutoff: datetime) -> tuple[tuple[uuid.UUID, str], ...]:
        captured["cutoff"] = cutoff
        return ()

    engine.list_granted_unconsumed_before = list_rows
    assert await service.sweep_granted_unconsumed() == ()
    assert captured["cutoff"] == datetime(2026, 7, 16, 11, 59, 30, tzinfo=UTC)


@pytest.mark.asyncio
async def test_denial_posts_exact_contract_text_for_supported_request() -> None:
    service, _, _, _, _, completer = _service()
    assert await service.post_denied(
        request_id=_REQUEST_ID,
        tenant_id=_TENANT,
        approver_subject="approver.dana",
        reason="insufficient notice",
    )
    assert completer.posts[-1]["text"] == ("Declined by approver.dana — insufficient notice.")


@pytest.mark.asyncio
async def test_denial_delivery_refusal_is_evidenced_without_turning_denial_into_failure() -> None:
    service, events, _, _, _, completer = _service()
    completer.exc = ConversationTurnRefused(
        "conversation_hook_refused",
        current_state="active",
        conversation_output_request_id="conv-hook-" + "c" * 32,
        conversation_output_hook_count=1,
        conversation_output_value_sha256=hashlib.sha256(b"masked denial").hexdigest(),
        conversation_output_value_bytes=len(b"masked denial"),
    )

    assert await service.post_denied(
        request_id=_REQUEST_ID,
        tenant_id=_TENANT,
        approver_subject="approver.dana",
        reason="insufficient notice",
    )
    assert events[-2:] == ["system", "chain"]
    history = cast(_History, service._history)
    assert len(history.records) == 1
    refusal = history.records[0]
    assert refusal.decision_type == "approval.delivery_refused"
    assert refusal.payload["approval_state"] == "denied"
    assert refusal.payload["delivery_output_sha256"] == hashlib.sha256(b"masked denial").hexdigest()
    assert "action_id" not in refusal.payload
    assert "execution" not in refusal.payload
    assert "result_sha256" not in refusal.payload


@pytest.mark.asyncio
async def test_denial_late_append_race_does_not_forge_hook_refusal_evidence() -> None:
    service, events, _, _, _, completer = _service()
    completer.exc = ConversationTurnRefused(
        "conversation_turn_claim_stale",
        current_state="active",
    )

    assert await service.post_denied(
        request_id=_REQUEST_ID,
        tenant_id=_TENANT,
        approver_subject="approver.dana",
        reason="insufficient notice",
    )
    assert events[-1] == "system"
    assert cast(_History, service._history).records == []


@pytest.mark.asyncio
async def test_unsupported_request_neither_executes_nor_posts_denial() -> None:
    service, events, _, _, _, completer = _service()
    completer.context = None
    assert (
        await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT)
        == "replay_unavailable"
    )
    assert not await service.post_denied(
        request_id=_REQUEST_ID,
        tenant_id=_TENANT,
        approver_subject="approver.dana",
        reason="no",
    )
    assert "consume" not in events
    assert completer.posts == []


@pytest.mark.asyncio
@pytest.mark.parametrize("missing_ref", ["mcp_server_id", "mcp_tool_name"])
async def test_missing_mcp_reference_refuses_execution(missing_ref: str) -> None:
    service, events, engine, _, _, _ = _service()
    original = engine.check

    async def incomplete(**kwargs: Any) -> ApprovalCheckResult:
        result = await original(**kwargs)
        refs = dict(result.required_refs)
        del refs[missing_ref]
        return ApprovalCheckResult(
            state=result.state,
            request_id=result.request_id,
            flow=result.flow,
            risk_tier=result.risk_tier,
            tool_identity=result.tool_identity,
            args_digest=result.args_digest,
            envelope_digest=result.envelope_digest,
            originator_subject=result.originator_subject,
            decisions_recorded=result.decisions_recorded,
            required_count=result.required_count,
            required_refs=refs,
        )

    engine.check = incomplete
    assert (
        await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT)
        == "replay_unavailable"
    )
    assert "consume" not in events


@pytest.mark.asyncio
@pytest.mark.parametrize("replay", [b"not-json", canonical_bytes(["not", "an", "object"])])
async def test_replay_must_decode_to_a_json_object(replay: bytes) -> None:
    service, events, _, store, _, _ = _service()
    store.args = replay
    consumed = _check()
    consumed = ApprovalCheckResult(
        state=consumed.state,
        request_id=consumed.request_id,
        flow=consumed.flow,
        risk_tier=consumed.risk_tier,
        tool_identity=consumed.tool_identity,
        args_digest=hashlib.sha256(replay).digest(),
        envelope_digest=consumed.envelope_digest,
        originator_subject=consumed.originator_subject,
        decisions_recorded=consumed.decisions_recorded,
        required_count=consumed.required_count,
        required_refs=consumed.required_refs,
    )

    async def consume_invalid(*, prepare_arguments: Any, **_: Any) -> Any:
        events.append("consume")
        await prepare_arguments(consumed)
        raise AssertionError("non-object replay unexpectedly dispatched")

    cast(Any, service._tool_proxy).execute_consumed_action = consume_invalid
    assert (
        await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT)
        == "replay_unavailable"
    )
    assert "dispatch" not in events


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload", "expected_result"),
    [
        ({"status": "plain"}, canonical_bytes({"status": "plain"})),
        (
            SimpleNamespace(model_dump=lambda **_: {"status": "model"}),
            canonical_bytes({"status": "model"}),
        ),
    ],
)
async def test_supported_result_shapes_are_recorded(payload: Any, expected_result: bytes) -> None:
    service, _, _, replay, tool, _ = _service()

    async def execute(*, prepare_arguments: Any, **_: Any) -> Any:
        await prepare_arguments(_check())
        return payload

    tool.execute_consumed_action = execute
    assert await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT) == "executed"
    assert json.loads(replay.recorded[0]) == [
        "cognic.approval.replay-result.v1",
        "executed",
        json.loads(expected_result),
    ]


@pytest.mark.asyncio
async def test_non_object_result_is_a_value_free_dispatch_failure() -> None:
    service, _, _, replay, tool, completer = _service()

    async def execute(*, prepare_arguments: Any, **_: Any) -> Any:
        await prepare_arguments(_check())
        return "SECRET-result"

    tool.execute_consumed_action = execute
    assert (
        await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT)
        == "dispatch_failed"
    )
    rendered = replay.recorded[-1] + completer.posts[-1]["text"].encode()
    assert b"SECRET-result" not in rendered
