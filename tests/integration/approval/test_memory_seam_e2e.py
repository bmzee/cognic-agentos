"""Sprint 13.5c3 — memory seam cross-surface e2e on a migrated DB.

``remember`` pending -> 13.5b1 HTTP grant -> re-``remember`` succeeds, with
the ``memory.write`` chain row carrying ``approval_verified=True`` + the
``approval_request_id`` examiner join (spec §6). Fixtures are self-contained
copies of the unit seam file + the sibling e2e binder.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from starlette.requests import Request

from cognic_agentos.core.approval.engine import ApprovalEngine
from cognic_agentos.core.approval.storage import ApprovalRequestStore
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.core.dlp.scanner import DLPVerdict
from cognic_agentos.core.memory._context import MemoryCallerContext
from cognic_agentos.core.memory.api import MemoryAPI
from cognic_agentos.core.memory.storage import PostgresMemoryAdapter
from cognic_agentos.core.memory.tiers import MemoryOperationRefused, SubjectRef
from cognic_agentos.core.policy.engine import Decision
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.rbac.actor import Actor

# -- helpers (copies: unit seam fixtures + test_mcp_seam_e2e.py binder) ------


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


def _make_actor(*, scopes: frozenset[str]) -> Actor:
    return Actor(
        subject="rev@bank.example",
        tenant_id="t1",
        scopes=scopes,  # type: ignore[arg-type]
        actor_type="human",
    )


class _StubApprovalPolicy:
    def __init__(self, flow: str = "require_single_approval") -> None:
        self._flow = flow

    async def classify(self, *, risk_tier: str) -> str:
        return self._flow


class _Frozen:
    async def is_write_frozen(self, *, tenant_id: str) -> bool:
        return False


class _FakeDLP:
    def scan(self, value: object) -> DLPVerdict:
        return DLPVerdict(detected_classes=frozenset(), redaction_spans=(), confidence=0.0)


class _FakeConsent:
    async def validate(self, token: object, **kwargs: object) -> None:
        return None


class _FakeOPA:
    async def evaluate(self, *, decision_point: str, input: dict[str, object]) -> Decision:
        return Decision(
            allow=True, rule_matched=decision_point, reasoning="fake", decision_data=None
        )


def _ctx() -> MemoryCallerContext:
    return MemoryCallerContext(
        tenant_id="t1",
        agent_id="kyc",
        actor_id="svc",
        served_subject=SubjectRef(kind="human", id="cust-7"),
        is_subagent=False,
        long_term_writes_allowed=True,
        cross_subject_recall=False,
        memory_read_capabilities=frozenset(),
        declared_purposes=frozenset({"customer_support"}),
        declared_data_classes=frozenset({"internal"}),
        risk_tier="payment_action",
    )


async def _mk_migrated_db(tmp_path: Any) -> AsyncEngine:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'memory-e2e.db'}"
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


def _mk_memory_api(db: AsyncEngine, *, approval_engine: ApprovalEngine) -> MemoryAPI:
    return MemoryAPI(
        context=_ctx(),
        adapter=PostgresMemoryAdapter(engine=db, dh_store=DecisionHistoryStore(db)),
        dlp=_FakeDLP(),
        consent=_FakeConsent(),  # type: ignore[arg-type]
        policy=_FakeOPA(),  # type: ignore[arg-type]
        kill_switch=_Frozen(),
        audit=DecisionHistoryStore(db),
        settings=build_settings_without_env_file(),
        approval_engine=approval_engine,
    )


async def _load_memory_write_rows(db: AsyncEngine) -> list[dict[str, Any]]:
    async with db.connect() as conn:
        rows = await conn.execute(
            text(
                "SELECT payload FROM decision_history "
                "WHERE event_type = 'memory.write' ORDER BY sequence"
            )
        )
        return [json.loads(r[0]) for r in rows]


async def test_remember_pending_http_grant_rewrite_succeeds(tmp_path: Any) -> None:
    # The cross-surface e2e (spec §7): gate pending -> 13.5b1 portal grant
    # over HTTP -> re-remember persists, attests, and joins.
    db = await _mk_migrated_db(tmp_path)
    approval = _mk_approval_engine(db, flow="require_single_approval")
    api = _mk_memory_api(db, approval_engine=approval)
    with pytest.raises(MemoryOperationRefused) as exc:
        await api.remember(
            "k1", {"x": 1}, tier="long_term", data_classes=("internal",), purpose="customer_support"
        )
    assert exc.value.reason == "memory_approval_pending"
    assert exc.value.approval_request_id is not None
    rid = uuid.UUID(exc.value.approval_request_id)

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

    record_id = await api.remember(
        "k1",
        {"x": 1},
        tier="long_term",
        data_classes=("internal",),
        purpose="customer_support",
        approval_request_id=str(rid),
    )
    assert record_id is not None
    # Evidence join pins (spec §6):
    payload = (await _load_memory_write_rows(db))[-1]
    assert payload["approval_verified"] is True
    assert payload["approval_request_id"] == str(rid)
