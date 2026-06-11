from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy.dialects import sqlite

from cognic_agentos.core.approval.storage import (
    ApprovalRequestDetail,
    ApprovalRequestStore,
    ApprovalRequestSummary,
    _build_list_pending_stmt,
)
from cognic_agentos.core.decision_history import DecisionHistoryStore


def test_build_list_pending_stmt_has_indexed_tenant_and_state_filter() -> None:
    # SQL-shape regression: production + test import the SAME builder
    # (no vacuous-proof duplicate select). The tenant filter is ALWAYS
    # present; the actionable-state IN-filter is always present.
    stmt = _build_list_pending_stmt("t1", limit=50, cursor=None)
    compiled = str(stmt.compile(dialect=sqlite.dialect()))
    assert "approval_requests.tenant_id = " in compiled
    assert "approval_requests.state IN " in compiled


def test_build_list_pending_stmt_adds_cursor_when_present() -> None:
    stmt = _build_list_pending_stmt("t1", limit=10, cursor=uuid.uuid4())
    compiled = str(stmt.compile(dialect=sqlite.dialect()))
    assert "approval_requests.request_id > " in compiled


async def _store(tmp_path: Any) -> ApprovalRequestStore:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'reads.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    from sqlalchemy.ext.asyncio import create_async_engine

    return ApprovalRequestStore(DecisionHistoryStore(create_async_engine(url)))


async def _seed_request(
    store: ApprovalRequestStore,
    *,
    request_id: uuid.UUID,
    tenant: str = "t1",
    risk_tier: str = "customer_data_read",
    flow: str = "require_single_approval",
    now: datetime,
) -> None:
    """Insert one ``pending`` approval-request row via the REAL genesis API.
    ``create_request_row`` takes EXPANDED keyword-only args (NOT an envelope) —
    grounded against ``storage.py:182-198``."""
    await store.create_request_row(
        request_id=request_id,
        tenant_id=tenant,
        flow=flow,
        risk_tier=risk_tier,
        tool_identity="cognic-tool-x",
        originator_subject="agent-1",
        envelope_digest=b"\x03" * 32,
        args_digest=b"\x02" * 32,
        redacted_context="ctx",
        data_classes=["customer_pii"],
        required_refs={},
        request_request_id=f"appr-{request_id.hex}",
        created_at=now,
        expires_at=now,
    )


@pytest.mark.asyncio
async def test_list_pending_returns_only_actionable_tenant_rows(tmp_path: Any) -> None:
    store = await _store(tmp_path)
    now = datetime(2026, 6, 11, 12, 0, tzinfo=UTC)
    # one pending in t1, one in t2 (must be invisible to t1)
    rid1 = uuid.uuid4()
    await _seed_request(store, request_id=rid1, now=now)
    await _seed_request(
        store,
        request_id=uuid.uuid4(),
        tenant="t2",
        risk_tier="payment_action",
        flow="require_4_eyes",
        now=now,
    )
    rows = await store.list_pending("t1", limit=50, cursor=None)
    assert [r.request_id for r in rows] == [rid1]
    assert isinstance(rows[0], ApprovalRequestSummary)
    assert rows[0].state == "pending"


@pytest.mark.asyncio
async def test_list_pending_empty_for_unknown_tenant(tmp_path: Any) -> None:
    store = await _store(tmp_path)
    assert await store.list_pending("nobody", limit=50, cursor=None) == []


@pytest.mark.asyncio
async def test_load_detail_returns_full_projection(tmp_path: Any) -> None:
    store = await _store(tmp_path)
    now = datetime(2026, 6, 11, 12, 0, tzinfo=UTC)
    rid = uuid.uuid4()
    await _seed_request(store, request_id=rid, now=now)
    detail = await store.load_detail(request_id=rid, tenant_id="t1")
    assert detail is not None
    assert isinstance(detail, ApprovalRequestDetail)
    assert detail.request_id == rid
    assert detail.data_classes == ("customer_pii",)
    assert detail.redacted_context == "ctx"
    assert detail.created_at.tzinfo is not None


@pytest.mark.asyncio
async def test_load_detail_cross_tenant_is_none(tmp_path: Any) -> None:
    store = await _store(tmp_path)
    now = datetime(2026, 6, 11, 12, 0, tzinfo=UTC)
    rid = uuid.uuid4()
    await _seed_request(
        store,
        request_id=rid,
        tenant="t2",
        risk_tier="payment_action",
        flow="require_4_eyes",
        now=now,
    )
    # tenant t1 cannot see t2's request — None (route maps to 404)
    assert await store.load_detail(request_id=rid, tenant_id="t1") is None


@pytest.mark.asyncio
async def test_load_detail_unknown_is_none(tmp_path: Any) -> None:
    store = await _store(tmp_path)
    assert await store.load_detail(request_id=uuid.uuid4(), tenant_id="t1") is None
