from __future__ import annotations

import asyncio
import json
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.approval._types import (
    ApprovalActor,
    ApprovalEnvelope,
    ApprovalRequestNotFound,
    ApprovalTransitionRefused,
)
from cognic_agentos.core.approval.assignments import ApprovalAssignmentStore
from cognic_agentos.core.approval.engine import ApprovalEngine
from cognic_agentos.core.approval.storage import (
    ApprovalRequestStore,
    _approval_decisions,
    _approval_requests,
    _is_duplicate_decider,
    _required_count,
)
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.decision_history import DecisionHistoryStore


class _Policy:
    def __init__(self, flow: str) -> None:
        self.flow = flow
        self.calls: list[str] = []

    async def classify(self, *, risk_tier: str) -> str:
        self.calls.append(risk_tier)
        return self.flow


class _Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 7, 16, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


async def _harness(
    tmp_path: Any,
    *,
    policy_flow: str = "auto_run",
    with_assignments: bool = True,
    settings: Any = None,
    clock: _Clock | None = None,
) -> tuple[
    ApprovalEngine,
    ApprovalRequestStore,
    ApprovalAssignmentStore,
    _Policy,
    AsyncEngine,
]:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / f'{uuid.uuid4().hex}.db'}"
    await asyncio.to_thread(command.upgrade, make_alembic_config(url), "head")
    db = create_async_engine(url)
    history = DecisionHistoryStore(db)
    store = ApprovalRequestStore(history)
    assignments = ApprovalAssignmentStore(history)
    policy = _Policy(policy_flow)
    engine = ApprovalEngine(
        policy=policy,
        store=store,
        assignments=assignments if with_assignments else None,
        settings=settings or build_settings_without_env_file(),
        clock=clock or _Clock(),
    )
    return engine, store, assignments, policy, db


def _envelope(*, tier: str = "read_only", originator: str = "amir") -> ApprovalEnvelope:
    return ApprovalEnvelope(
        risk_tier=tier,
        tool_identity="mcp:approval-probe/write",
        originator_subject=originator,
        tenant_id="t1",
        data_classes=("internal",),
        args_digest=b"\x42" * 32,
        redacted_context="approval probe write",
        required_refs={},
    )


def _actor(subject: str, *, scope: str | None = None) -> ApprovalActor:
    return ApprovalActor(
        subject=subject,
        tenant_id="t1",
        scopes=frozenset({scope}) if scope else frozenset(),
        actor_type="human",
    )


async def _assign(assignments: ApprovalAssignmentStore, subjects: tuple[str, ...]) -> None:
    await assignments.assign(
        tenant_id="t1",
        tool_identity="mcp:approval-probe/write",
        approver_subjects=subjects,
        actor=_actor("admin"),
        request_request_id="assign-" + uuid.uuid4().hex,
    )


@pytest.mark.asyncio
async def test_assignment_tightens_auto_tier_without_policy_consult(tmp_path: Any) -> None:
    engine, store, assignments, policy, db = await _harness(tmp_path)
    try:
        await _assign(assignments, ("dana", "erin", "zara"))
        request = await engine.create_request(envelope=_envelope())
        row = await store.load(request_id=request.request_id, tenant_id="t1")
        assert request.flow == "require_assigned"
        assert row is not None
        assert row.required_count == 3
        assert row.eligible_approvers == ("dana", "erin", "zara")
        assert policy.calls == []
    finally:
        await db.dispose()


def test_runtime_metadata_carries_the_0018_decision_contract() -> None:
    assert {
        "required_count",
        "eligible_approvers",
        "decisions_recorded",
        "consumed_at",
        "consumed_by",
    } <= set(_approval_requests.c.keys())
    uniques = {
        constraint.name: tuple(column.name for column in constraint.columns)
        for constraint in _approval_decisions.constraints
        if isinstance(constraint, sa.UniqueConstraint)
    }
    assert uniques == {"uq_approval_decisions_request_approver": ("request_id", "approver_subject")}


def test_required_count_legacy_fallback_and_corruption_refusal() -> None:
    assert _required_count(flow="require_single_approval", stored=None) == 1
    assert _required_count(flow="require_4_eyes", stored=None) == 2
    with pytest.raises(RuntimeError, match="must be positive"):
        _required_count(flow="require_assigned", stored=0)
    with pytest.raises(RuntimeError, match="has no required_count"):
        _required_count(flow="require_assigned", stored=None)


def test_duplicate_decider_integrity_detection_is_constraint_specific() -> None:
    class _Diagnostic:
        constraint_name = "UQ_APPROVAL_DECISIONS_REQUEST_APPROVER"

    class _NamedViolation(Exception):
        diag = _Diagnostic()

    assert _is_duplicate_decider(IntegrityError("insert", {}, _NamedViolation()))
    assert not _is_duplicate_decider(IntegrityError("insert", {}, ValueError("other")))


@pytest.mark.asyncio
async def test_assigned_flow_uses_its_own_settings_ttl(tmp_path: Any) -> None:
    clock = _Clock()
    settings = build_settings_without_env_file().model_copy(
        update={"approval_assigned_ttl_s": 7, "approval_four_eyes_ttl_s": 600}
    )
    engine, _store, assignments, _policy, db = await _harness(
        tmp_path,
        settings=settings,
        clock=clock,
    )
    try:
        await _assign(assignments, ("dana", "erin"))
        request = await engine.create_request(envelope=_envelope())
        clock.now = datetime(2026, 7, 16, 12, 0, 8, tzinfo=UTC)
        assert (await engine.check(request_id=request.request_id, tenant_id="t1")).state == (
            "expired"
        )
    finally:
        await db.dispose()


@pytest.mark.asyncio
async def test_assigned_n_of_four_walk_persists_ordered_decision_ledger(tmp_path: Any) -> None:
    engine, _store, assignments, _policy, db = await _harness(tmp_path)
    try:
        subjects = ("dana", "erin", "zara", "omar")
        await _assign(assignments, subjects)
        request = await engine.create_request(envelope=_envelope())
        states = [
            await engine.grant(
                request_id=request.request_id,
                tenant_id="t1",
                approver=_actor(subject),
            )
            for subject in subjects
        ]
        assert states == ["awaiting_second", "awaiting_second", "awaiting_second", "granted"]

        async with db.connect() as conn:
            decisions = (
                await conn.execute(
                    sa.text(
                        "SELECT decision_index, approver_subject FROM approval_decisions "
                        "WHERE request_id = :request_id ORDER BY decision_index"
                    ),
                    {"request_id": request.request_id.hex},
                )
            ).all()
            events = (
                await conn.execute(
                    sa.text(
                        "SELECT event_type, payload FROM decision_history "
                        "WHERE event_type LIKE 'approval.%' ORDER BY sequence"
                    )
                )
            ).all()
        assert [(row.decision_index, row.approver_subject) for row in decisions] == list(
            enumerate(subjects)
        )
        assert [row.event_type for row in events] == [
            "approval.assignment_changed",
            "approval.requested",
            "approval.granted_first",
            "approval.granted_second",
            "approval.grant_recorded",
            "approval.grant_recorded",
        ]
        progress = [json.loads(row.payload) for row in events[-2:]]
        assert [(item["decision_index"], item["required_count"]) for item in progress] == [
            (2, 4),
            (3, 4),
        ]
    finally:
        await db.dispose()


@pytest.mark.asyncio
async def test_scope_holding_non_assignee_is_refused(tmp_path: Any) -> None:
    engine, _store, assignments, _policy, db = await _harness(
        tmp_path, policy_flow="require_4_eyes"
    )
    try:
        await _assign(assignments, ("dana", "erin"))
        request = await engine.create_request(envelope=_envelope(tier="payment_action"))
        with pytest.raises(ApprovalTransitionRefused) as exc_info:
            await engine.grant(
                request_id=request.request_id,
                tenant_id="t1",
                approver=_actor("zara", scope="tool.approve.payment"),
            )
        assert exc_info.value.reason == "approver_not_assigned"
    finally:
        await db.dispose()


@pytest.mark.asyncio
async def test_originator_is_refused_at_decision_index_two(tmp_path: Any) -> None:
    engine, store, assignments, _policy, db = await _harness(tmp_path)
    try:
        await _assign(assignments, ("dana", "erin", "amir", "omar"))
        request = await engine.create_request(envelope=_envelope(originator="amir"))
        for subject in ("dana", "erin"):
            await engine.grant(
                request_id=request.request_id,
                tenant_id="t1",
                approver=_actor(subject),
            )
        with pytest.raises(ApprovalTransitionRefused) as exc_info:
            await engine.grant(
                request_id=request.request_id,
                tenant_id="t1",
                approver=_actor("amir"),
            )
        assert exc_info.value.reason == "originator_cannot_approve"
        row = await store.load(request_id=request.request_id, tenant_id="t1")
        assert row is not None and row.decisions_recorded == 2
    finally:
        await db.dispose()


@pytest.mark.asyncio
async def test_concurrent_duplicate_approver_exactly_one_wins(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, store, assignments, _policy, db = await _harness(tmp_path)
    try:
        await _assign(assignments, ("dana", "erin", "zara", "omar"))
        request = await engine.create_request(envelope=_envelope())
        await engine.grant(
            request_id=request.request_id,
            tenant_id="t1",
            approver=_actor("dana"),
        )

        original = store.prior_deciders
        both_read = asyncio.Event()
        reads = 0

        async def _synchronised_prior_deciders(**kwargs: Any) -> tuple[str, ...]:
            nonlocal reads
            prior = await original(**kwargs)
            reads += 1
            if reads == 2:
                both_read.set()
            await asyncio.wait_for(both_read.wait(), timeout=2)
            return prior

        monkeypatch.setattr(store, "prior_deciders", _synchronised_prior_deciders)
        results = await asyncio.gather(
            *(
                engine.grant(
                    request_id=request.request_id,
                    tenant_id="t1",
                    approver=_actor("erin"),
                )
                for _ in range(2)
            ),
            return_exceptions=True,
        )
        assert results.count("awaiting_second") == 1
        refusals = [item for item in results if isinstance(item, ApprovalTransitionRefused)]
        assert len(refusals) == 1
        assert refusals[0].reason == "approver_not_distinct"
    finally:
        await db.dispose()


@pytest.mark.asyncio
async def test_decision_unique_constraint_maps_to_typed_distinctness_refusal(
    tmp_path: Any,
) -> None:
    engine, store, assignments, _policy, db = await _harness(tmp_path)
    try:
        await _assign(assignments, ("dana", "erin", "zara"))
        request = await engine.create_request(envelope=_envelope())
        await engine.grant(
            request_id=request.request_id,
            tenant_id="t1",
            approver=_actor("dana"),
        )
        # Bypass the advisory engine read to exercise the database race
        # authority directly: the same subject cannot take index 1.
        with pytest.raises(ApprovalTransitionRefused) as exc_info:
            await store.transition(
                request_id=request.request_id,
                tenant_id="t1",
                action="grant_second",
                actor_subject="dana",
                request_request_id="grant-" + uuid.uuid4().hex,
            )
        assert exc_info.value.reason == "approver_not_distinct"
        row = await store.load(request_id=request.request_id, tenant_id="t1")
        assert row is not None
        assert (row.state, row.decisions_recorded) == ("awaiting_second", 1)
    finally:
        await db.dispose()


@pytest.mark.asyncio
async def test_prior_deciders_falls_back_to_legacy_first_approver(tmp_path: Any) -> None:
    engine, store, _assignments, _policy, db = await _harness(
        tmp_path,
        policy_flow="require_4_eyes",
        with_assignments=False,
    )
    try:
        request = await engine.create_request(envelope=_envelope(tier="payment_action"))
        async with db.begin() as conn:
            await conn.execute(
                sa.update(_approval_requests)
                .where(_approval_requests.c.request_id == request.request_id)
                .values(first_approver="legacy-dana", state="awaiting_second")
            )
        assert await store.prior_deciders(
            request_id=request.request_id,
            tenant_id="t1",
        ) == ("legacy-dana",)
        with pytest.raises(ApprovalRequestNotFound):
            await store.eligible_approvers(
                request_id=request.request_id,
                tenant_id="foreign",
            )
        with pytest.raises(ApprovalRequestNotFound):
            await store.prior_deciders(
                request_id=request.request_id,
                tenant_id="foreign",
            )
        with pytest.raises(ValueError, match="grant transitions require actor_subject"):
            await store.transition(
                request_id=request.request_id,
                tenant_id="t1",
                action="grant_first",
                actor_subject=None,
                request_request_id="grant-" + uuid.uuid4().hex,
            )
    finally:
        await db.dispose()


@pytest.mark.asyncio
async def test_engine_without_assignment_store_preserves_bar_d_four_eyes_sequence(
    tmp_path: Any,
) -> None:
    engine, _store, _assignments, policy, db = await _harness(
        tmp_path,
        policy_flow="require_4_eyes",
        with_assignments=False,
    )
    try:
        denied = await engine.create_request(envelope=_envelope(tier="high_risk_custom"))
        assert (
            await engine.deny(
                request_id=denied.request_id,
                tenant_id="t1",
                approver=_actor("dana", scope="tool.approve.high_risk_custom"),
                reason="deny first request",
            )
            == "denied"
        )

        approved = await engine.create_request(envelope=_envelope(tier="high_risk_custom"))
        assert (
            await engine.grant(
                request_id=approved.request_id,
                tenant_id="t1",
                approver=_actor("dana", scope="tool.approve.high_risk_custom"),
            )
            == "awaiting_second"
        )
        with pytest.raises(ApprovalTransitionRefused) as same_approver:
            await engine.grant_second(
                request_id=approved.request_id,
                tenant_id="t1",
                approver=_actor("dana", scope="tool.approve.high_risk_custom"),
            )
        assert same_approver.value.reason == "four_eyes_approver_not_distinct"
        assert (
            await engine.grant_second(
                request_id=approved.request_id,
                tenant_id="t1",
                approver=_actor("erin", scope="tool.approve.high_risk_custom"),
            )
            == "granted"
        )
        assert policy.calls == ["high_risk_custom", "high_risk_custom"]
    finally:
        await db.dispose()
