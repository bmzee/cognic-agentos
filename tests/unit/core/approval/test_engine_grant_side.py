from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.approval._types import (
    ApprovalActor,
    ApprovalEnvelope,
    ApprovalTransitionRefused,
)
from cognic_agentos.core.approval.engine import ApprovalEngine
from cognic_agentos.core.approval.storage import ApprovalRequestStore
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.decision_history import DecisionHistoryStore


class _StubPolicy:
    def __init__(self, flow: str) -> None:
        self._flow = flow

    async def classify(self, *, risk_tier: str) -> str:
        return self._flow


class _Clock:
    def __init__(self, t: datetime) -> None:
        self.t = t

    def __call__(self) -> datetime:
        return self.t


def _t0() -> datetime:
    return datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


async def _engine(tmp_path: Any, *, flow: str, clock: _Clock) -> ApprovalEngine:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'grant.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    store = ApprovalRequestStore(DecisionHistoryStore(create_async_engine(url)))
    return ApprovalEngine(
        policy=_StubPolicy(flow),
        store=store,
        settings=build_settings_without_env_file(),
        clock=clock,
    )


def _env(tier: str, *, refs: dict[str, str] | None = None) -> ApprovalEnvelope:
    return ApprovalEnvelope(
        risk_tier=tier,
        tool_identity="cognic-tool-x",
        originator_subject="agent-1",
        tenant_id="t1",
        data_classes=("customer_pii",),
        args_digest=b"\x02" * 32,
        redacted_context="ctx",
        required_refs=refs or {},
    )


def _actor(
    subject: str, *, scope: str | None = None, actor_type: str = "human", tenant: str = "t1"
) -> ApprovalActor:
    return ApprovalActor(
        subject=subject,
        tenant_id=tenant,
        scopes=frozenset({scope}) if scope else frozenset(),
        actor_type=actor_type,  # type: ignore[arg-type]
    )


@pytest.mark.asyncio
async def test_single_grant_happy_path(tmp_path: Any) -> None:
    eng = await _engine(tmp_path, flow="require_single_approval", clock=_Clock(_t0()))
    req = await eng.create_request(envelope=_env("customer_data_read"))
    state = await eng.grant(
        request_id=req.request_id,
        tenant_id="t1",
        approver=_actor("rev-1", scope="tool.approve.customer_data"),
    )
    assert state == "granted"


@pytest.mark.asyncio
async def test_four_eyes_grant_then_second(tmp_path: Any) -> None:
    eng = await _engine(tmp_path, flow="require_4_eyes", clock=_Clock(_t0()))
    req = await eng.create_request(envelope=_env("payment_action"))
    s1 = await eng.grant(
        request_id=req.request_id,
        tenant_id="t1",
        approver=_actor("rev-a", scope="tool.approve.payment"),
    )
    assert s1 == "awaiting_second"
    # P2: first grant is NOT executable — check() reports awaiting_second.
    assert (await eng.check(request_id=req.request_id, tenant_id="t1")).state == "awaiting_second"
    s2 = await eng.grant_second(
        request_id=req.request_id,
        tenant_id="t1",
        approver=_actor("rev-b", scope="tool.approve.payment"),
    )
    assert s2 == "granted"


@pytest.mark.asyncio
async def test_four_eyes_second_must_differ_from_first(tmp_path: Any) -> None:
    eng = await _engine(tmp_path, flow="require_4_eyes", clock=_Clock(_t0()))
    req = await eng.create_request(envelope=_env("payment_action"))
    await eng.grant(
        request_id=req.request_id,
        tenant_id="t1",
        approver=_actor("rev-a", scope="tool.approve.payment"),
    )
    with pytest.raises(ApprovalTransitionRefused) as ei:
        await eng.grant_second(
            request_id=req.request_id,
            tenant_id="t1",
            approver=_actor("rev-a", scope="tool.approve.payment"),  # same as first
        )
    assert ei.value.reason == "four_eyes_approver_not_distinct"


@pytest.mark.asyncio
async def test_four_eyes_second_must_differ_from_originator(tmp_path: Any) -> None:
    eng = await _engine(tmp_path, flow="require_4_eyes", clock=_Clock(_t0()))
    req = await eng.create_request(envelope=_env("payment_action"))  # originator = agent-1
    await eng.grant(
        request_id=req.request_id,
        tenant_id="t1",
        approver=_actor("rev-a", scope="tool.approve.payment"),
    )
    with pytest.raises(ApprovalTransitionRefused) as ei:
        await eng.grant_second(
            request_id=req.request_id,
            tenant_id="t1",
            approver=_actor("agent-1", scope="tool.approve.payment"),  # == originator
        )
    assert ei.value.reason == "four_eyes_approver_not_distinct"


@pytest.mark.asyncio
async def test_grant_requires_human_actor(tmp_path: Any) -> None:
    eng = await _engine(tmp_path, flow="require_single_approval", clock=_Clock(_t0()))
    req = await eng.create_request(envelope=_env("customer_data_read"))
    with pytest.raises(ApprovalTransitionRefused) as ei:
        await eng.grant(
            request_id=req.request_id,
            tenant_id="t1",
            approver=_actor("svc", scope="tool.approve.customer_data", actor_type="service"),
        )
    assert ei.value.reason == "approver_not_human"


@pytest.mark.asyncio
async def test_grant_second_requires_human_actor(tmp_path: Any) -> None:
    eng = await _engine(tmp_path, flow="require_4_eyes", clock=_Clock(_t0()))
    req = await eng.create_request(envelope=_env("payment_action"))
    with pytest.raises(ApprovalTransitionRefused) as ei:
        await eng.grant_second(
            request_id=req.request_id,
            tenant_id="t1",
            approver=_actor("svc", scope="tool.approve.payment", actor_type="service"),
        )
    assert ei.value.reason == "approver_not_human"


@pytest.mark.asyncio
async def test_deny_requires_human_actor(tmp_path: Any) -> None:
    eng = await _engine(tmp_path, flow="require_single_approval", clock=_Clock(_t0()))
    req = await eng.create_request(envelope=_env("customer_data_read"))
    with pytest.raises(ApprovalTransitionRefused) as ei:
        await eng.deny(
            request_id=req.request_id,
            tenant_id="t1",
            approver=_actor("svc", scope="tool.approve.customer_data", actor_type="service"),
            reason="x",
        )
    assert ei.value.reason == "approver_not_human"


@pytest.mark.asyncio
async def test_grant_requires_tier_scope(tmp_path: Any) -> None:
    eng = await _engine(tmp_path, flow="require_4_eyes", clock=_Clock(_t0()))
    req = await eng.create_request(envelope=_env("payment_action"))
    with pytest.raises(ApprovalTransitionRefused) as ei:
        await eng.grant(
            request_id=req.request_id,
            tenant_id="t1",
            approver=_actor("rev", scope="tool.approve.customer_data"),  # wrong scope
        )
    assert ei.value.reason == "approver_scope_not_held"


@pytest.mark.asyncio
async def test_cross_tenant_approver_refused_no_transition(tmp_path: Any) -> None:
    # P1: a human approver from tenant t2 (with the correct scope) cannot grant a
    # tenant-t1 request. Tenant binding is enforced in the CORE engine, and the
    # request is left untouched (still pending).
    eng = await _engine(tmp_path, flow="require_4_eyes", clock=_Clock(_t0()))
    req = await eng.create_request(envelope=_env("payment_action"))  # tenant t1
    with pytest.raises(ApprovalTransitionRefused) as ei:
        await eng.grant(
            request_id=req.request_id,
            tenant_id="t1",
            approver=_actor("rev", scope="tool.approve.payment", tenant="t2"),  # wrong tenant
        )
    assert ei.value.reason == "approver_scope_not_held"
    assert (await eng.check(request_id=req.request_id, tenant_id="t1")).state == "pending"


@pytest.mark.asyncio
async def test_customer_data_write_grant_requires_reason(tmp_path: Any) -> None:
    eng = await _engine(tmp_path, flow="require_single_approval", clock=_Clock(_t0()))
    req = await eng.create_request(envelope=_env("customer_data_write"))
    with pytest.raises(ApprovalTransitionRefused) as ei:
        await eng.grant(
            request_id=req.request_id,
            tenant_id="t1",
            approver=_actor("rev", scope="tool.approve.customer_data_write"),  # no reason
        )
    assert ei.value.reason == "grant_reason_required"
    # with a reason it grants
    state = await eng.grant(
        request_id=req.request_id,
        tenant_id="t1",
        approver=_actor("rev", scope="tool.approve.customer_data_write"),
        reason="kyc-update",
    )
    assert state == "granted"


@pytest.mark.asyncio
async def test_stale_grant_after_ttl_refused_not_granted(tmp_path: Any) -> None:
    clock = _Clock(_t0())
    eng = await _engine(tmp_path, flow="require_single_approval", clock=clock)
    req = await eng.create_request(envelope=_env("customer_data_read"))
    clock.t = datetime(2026, 6, 10, 12, 10, tzinfo=UTC)  # 600s > 300s TTL
    with pytest.raises(ApprovalTransitionRefused) as ei:
        await eng.grant(
            request_id=req.request_id,
            tenant_id="t1",
            approver=_actor("rev", scope="tool.approve.customer_data"),
        )
    assert ei.value.reason == "approval_expired"
    assert (await eng.check(request_id=req.request_id, tenant_id="t1")).state == "expired"


@pytest.mark.asyncio
async def test_deny_happy_path(tmp_path: Any) -> None:
    eng = await _engine(tmp_path, flow="require_single_approval", clock=_Clock(_t0()))
    req = await eng.create_request(envelope=_env("customer_data_read"))
    state = await eng.deny(
        request_id=req.request_id,
        tenant_id="t1",
        approver=_actor("rev", scope="tool.approve.customer_data"),
        reason="not allowed",
    )
    assert state == "denied"


@pytest.mark.asyncio
async def test_replay_binding_gate(tmp_path: Any) -> None:
    # P1: a granted request cannot be replayed against a different invocation.
    eng = await _engine(tmp_path, flow="require_single_approval", clock=_Clock(_t0()))
    req = await eng.create_request(envelope=_env("customer_data_read"))
    await eng.grant(
        request_id=req.request_id,
        tenant_id="t1",
        approver=_actor("rev", scope="tool.approve.customer_data"),
    )
    # mismatched args_digest -> refused
    with pytest.raises(ApprovalTransitionRefused) as ei:
        await eng.verify_grant_for_action(
            request_id=req.request_id,
            tenant_id="t1",
            expected_args_digest=b"\x09" * 32,
            expected_tool_identity="cognic-tool-x",
        )
    assert ei.value.reason == "approval_binding_mismatch"
    # mismatched tool_identity -> refused
    with pytest.raises(ApprovalTransitionRefused):
        await eng.verify_grant_for_action(
            request_id=req.request_id,
            tenant_id="t1",
            expected_args_digest=b"\x02" * 32,
            expected_tool_identity="other-tool",
        )
    # matched binding -> granted
    res = await eng.verify_grant_for_action(
        request_id=req.request_id,
        tenant_id="t1",
        expected_args_digest=b"\x02" * 32,
        expected_tool_identity="cognic-tool-x",
    )
    assert res.state == "granted"
