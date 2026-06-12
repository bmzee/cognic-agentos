"""Sprint 13.5c2 — scheduler seam cross-surface e2e on a migrated DB.

Submit pending -> 13.5b1 HTTP grant -> re-submit ``accepted_immediate``,
with ``approval_verified=True`` attested into the policy-evaluator input
and the accepted chain row carrying the ``approval_request_id`` join
correlator (spec §6, user-locked P1). The REAL-bundle Rego arm lives in
tests/unit/policies/test_scheduler_rego.py (opa-gated); this e2e captures
the policy input via a stub evaluator to assert the attestation contract.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from starlette.requests import Request

from cognic_agentos.core.approval.engine import ApprovalEngine
from cognic_agentos.core.approval.storage import ApprovalRequestStore
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.core.scheduler._types import SubmitInput, TaskActor
from cognic_agentos.core.scheduler.engine import SchedulerEngine
from cognic_agentos.core.scheduler.policy import PolicyDecision
from cognic_agentos.core.scheduler.queue import ConcurrencyCaps
from cognic_agentos.core.scheduler.storage import SchedulerStorage
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.rbac.actor import Actor

# -- helpers (copied: test_approval_seam.py fixtures + test_mcp_seam_e2e.py binder) --


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


def _make_actor(*, scopes: frozenset[str]) -> Actor:
    return Actor(
        subject="rev@bank.example",
        tenant_id="t-1",
        scopes=scopes,  # type: ignore[arg-type]
        actor_type="human",
    )


class _StubApprovalPolicy:
    def __init__(self, flow: str = "require_single_approval") -> None:
        self._flow = flow

    async def classify(self, *, risk_tier: str) -> str:
        return self._flow


class _CapturingPolicy:
    """Policy-evaluator stub capturing the SubmitInput the engine hands it."""

    def __init__(self) -> None:
        self.seen: list[SubmitInput] = []

    async def __call__(self, submit_input: SubmitInput) -> PolicyDecision:
        self.seen.append(submit_input)
        return PolicyDecision(allow=True, policy_reason=None)


class _AllowAllQuota:
    async def would_admit(
        self, *, task_id: uuid.UUID, tenant_id: str, pack_id: str, estimated_tokens: int
    ) -> bool:
        return True

    async def release_reservation(self, task_id: uuid.UUID) -> None:
        return None


class _InactiveKillSwitch:
    async def is_active(self, *, tenant_id: str, pack_id: str) -> bool:
        return False


class _InstalledPackState:
    async def is_installed(self, *, tenant_id: str, pack_id: str) -> bool:
        return True


def _seam_submit_input(**overrides: Any) -> SubmitInput:
    base: dict[str, Any] = {
        "tenant_id": "t-1",
        "pack_id": "pack-x",
        "actor": TaskActor(subject="agent-1", tenant_id="t-1", actor_type="service"),
        "class_": "interactive",
        "pack_kind": "tool",
        "pack_risk_tier": "payment_action",
        "requested_estimated_tokens": 500,
        "data_classes": ("payment_data",),
    }
    base.update(overrides)
    return SubmitInput(**base)


async def _mk_migrated_db(tmp_path: Any) -> AsyncEngine:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'scheduler-e2e.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    return create_async_engine(url)


def _mk_approval_engine(db: AsyncEngine, *, flow: str) -> ApprovalEngine:
    return ApprovalEngine(
        policy=_StubApprovalPolicy(flow),
        store=ApprovalRequestStore(DecisionHistoryStore(db)),
        settings=build_settings_without_env_file(),
        clock=lambda: datetime(2026, 6, 12, 12, 0, tzinfo=UTC),
    )


def _mk_scheduler_engine(
    db: AsyncEngine, *, approval_engine: ApprovalEngine, policy: _CapturingPolicy
) -> SchedulerEngine:
    return SchedulerEngine(
        storage=SchedulerStorage(db),
        caps=ConcurrencyCaps(
            per_tenant_interactive=2, per_tenant_background=4, per_pack=4, per_actor=4
        ),
        class_settings={"interactive": (2, 0.200), "background": (4, 5.0)},
        policy_evaluator=policy,
        quota_interrogator=_AllowAllQuota(),
        kill_switch_interrogator=_InactiveKillSwitch(),
        pack_state_interrogator=_InstalledPackState(),
        approval_engine=approval_engine,
    )


async def _load_admission_rows(db: AsyncEngine) -> list[tuple[str, dict[str, Any]]]:
    """(event_type, payload) for every scheduler.admission_* chain row.

    NOTE: the DB column is ``event_type`` (decision_history.py:196) even
    though the ``DecisionRecord`` dataclass field is ``decision_type``."""
    async with db.connect() as conn:
        rows = await conn.execute(
            text(
                "SELECT event_type, payload FROM decision_history "
                "WHERE event_type LIKE 'scheduler.admission%' ORDER BY sequence"
            )
        )
        return [(r[0], json.loads(r[1])) for r in rows]


async def test_submit_pending_http_grant_resubmit_admits(tmp_path: Any) -> None:
    # The cross-surface e2e (spec §7): seam pending -> 13.5b1 portal grant
    # over HTTP -> re-submit admits, attests, and the accepted row carries
    # the examiner join correlator.
    db = await _mk_migrated_db(tmp_path)
    approval = _mk_approval_engine(db, flow="require_single_approval")
    policy = _CapturingPolicy()
    engine = _mk_scheduler_engine(db, approval_engine=approval, policy=policy)
    first = await engine.submit(submit_input=_seam_submit_input(), request_id="req-1")
    assert first.outcome == "refused_approval_pending"
    assert first.approval_request_id is not None
    rid = uuid.UUID(first.approval_request_id)

    reviewer = _make_actor(scopes=frozenset({"tool.approve.payment"}))
    app = create_app(
        actor_binder=_StubBinder(reviewer),
        approval_store=ApprovalRequestStore(DecisionHistoryStore(db)),
        approval_engine=approval,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(f"/api/v1/approvals/{rid}/grant", json={})
        assert resp.status_code == 200
        assert resp.json()["state"] == "granted"

    decision = await engine.submit(
        submit_input=_seam_submit_input(approval_request_id=str(rid)), request_id="req-2"
    )
    assert decision.outcome == "accepted_immediate"
    assert policy.seen[-1].approval_verified is True
    # Accepted-row join pin (spec §6, user-locked P1):
    rows = await _load_admission_rows(db)
    accepted = [p for t, p in rows if t == "scheduler.admission_accepted"]
    assert accepted[-1]["approval_request_id"] == str(rid)
    assert accepted[-1]["approval_verified"] is True
