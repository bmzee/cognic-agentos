"""M8.5-D D2-C approval auto-executor contracts."""

from __future__ import annotations

import dataclasses
import hashlib
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cognic_agentos.core.approval._types import (
    ApprovalCheckResult,
    ApprovalTransitionRefused,
)
from cognic_agentos.core.approval.executor import ApprovalExecutionService
from cognic_agentos.core.approval.replay import ApprovalReplayUnavailable
from cognic_agentos.core.canonical import canonical_bytes

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
        self.result: bytes | None | Exception = canonical_bytes({"status": "applied"})
        self.recorded: list[bytes] = []

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
        self.recorded.append(result_canonical)


class _Completer:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.context: tuple[uuid.UUID, str] | None = (_CONVERSATION_ID, "bank-agent")
        self.posts: list[dict[str, Any]] = []

    async def resolve_approval_context(self, **_: Any) -> tuple[uuid.UUID, str] | None:
        self.events.append("resolve")
        return self.context

    async def post_system_turn(self, **kwargs: Any) -> uuid.UUID:
        self.events.append("system")
        self.posts.append(kwargs)
        return uuid.UUID("10000000-1111-4222-8333-444455556666")


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
async def test_happy_path_is_consume_load_dispatch_record_turn_chain() -> None:
    service, events, _, replay, tool, completer = _service()
    assert await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT) == "executed"
    assert events == [
        "check",
        "resolve",
        "consume",
        "load",
        "dispatch",
        "record",
        "system",
        "chain",
    ]
    assert replay.recorded == [canonical_bytes({"status": "applied"})]
    assert tool.arguments is not None
    assert tool.arguments["employee_id"] == "e-17"
    assert "_cognic_action_context" in tool.arguments
    assert completer.posts[0]["conversation_id"] == _CONVERSATION_ID


@pytest.mark.asyncio
async def test_already_consumed_loads_result_and_never_redispatches() -> None:
    service, events, _, _, tool, _ = _service()
    tool.already_consumed = True
    assert (
        await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT)
        == "already_executed"
    )
    assert events == ["check", "resolve", "consume", "load_result"]
    assert "dispatch" not in events


@pytest.mark.asyncio
async def test_digest_drift_after_consume_fails_closed_and_posts_failure_turn() -> None:
    service, events, _, replay, _, completer = _service()
    replay.args = canonical_bytes({"employee_id": "tampered"})
    assert (
        await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT)
        == "replay_unavailable"
    )
    assert events == ["check", "resolve", "consume", "load", "system", "chain"]
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
    assert events[-2:] == ["system", "chain"]


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
    assert events[-2:] == ["system", "chain"]


@pytest.mark.asyncio
async def test_dispatch_failure_is_recorded_after_consumption_and_posts_failure_turn() -> None:
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
        "record",
        "system",
        "chain",
    ]
    rendered = replay.recorded[0].decode() + completer.posts[0]["text"]
    assert "SECRET-upstream-body" not in rendered
    assert "RuntimeError" in rendered


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
    ("payload", "expected"),
    [
        ({"status": "plain"}, canonical_bytes({"status": "plain"})),
        (
            SimpleNamespace(model_dump=lambda **_: {"status": "model"}),
            canonical_bytes({"status": "model"}),
        ),
    ],
)
async def test_supported_result_shapes_are_recorded(payload: Any, expected: bytes) -> None:
    service, _, _, replay, tool, _ = _service()

    async def execute(*, prepare_arguments: Any, **_: Any) -> Any:
        await prepare_arguments(_check())
        return payload

    tool.execute_consumed_action = execute
    assert await service.execute_granted(request_id=_REQUEST_ID, tenant_id=_TENANT) == "executed"
    assert replay.recorded == [expected]


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
