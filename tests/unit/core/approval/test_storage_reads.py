from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy.dialects import sqlite

from cognic_agentos.core.approval.storage import (
    APPROVAL_CURSOR_MAX_ENCODED_LEN,
    ApprovalCursorInvalid,
    ApprovalQueueCursor,
    ApprovalRequestDetail,
    ApprovalRequestStore,
    ApprovalRequestSummary,
    ListPendingPage,
    _approval_requests,
    _build_list_pending_stmt,
    decode_queue_cursor,
    encode_queue_cursor,
)
from cognic_agentos.core.decision_history import DecisionHistoryStore


def test_build_list_pending_stmt_has_indexed_tenant_and_state_filter() -> None:
    # SQL-shape regression: production + test import the SAME builder
    # (no vacuous-proof duplicate select). The tenant filter is ALWAYS
    # present; the actionable-state IN-filter is always present; ordering is
    # the HP-4 chronological keyset (created_at, request_id) the 0017 index
    # backs.
    stmt = _build_list_pending_stmt("t1", limit_plus_one=51, after=None)
    compiled = str(stmt.compile(dialect=sqlite.dialect()))
    assert "approval_requests.tenant_id = " in compiled
    assert "approval_requests.state IN " in compiled
    assert "ORDER BY approval_requests.created_at ASC, approval_requests.request_id ASC" in compiled


def test_build_list_pending_stmt_adds_keyset_tuple_expansion_when_cursor_present() -> None:
    after = ApprovalQueueCursor(
        created_at=datetime(2026, 7, 11, 12, 0, tzinfo=UTC), request_id=uuid.uuid4()
    )
    stmt = _build_list_pending_stmt("t1", limit_plus_one=11, after=after)
    compiled = str(stmt.compile(dialect=sqlite.dialect()))
    # Oracle-portable tuple expansion: created_at > :c OR (= :c AND request_id > :r).
    assert "approval_requests.created_at > " in compiled
    assert "approval_requests.created_at = " in compiled
    assert "approval_requests.request_id > " in compiled
    assert " OR " in compiled


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
    page = await store.list_pending("t1", limit=50, cursor=None)
    assert [r.request_id for r in page.items] == [rid1]
    assert isinstance(page.items[0], ApprovalRequestSummary)
    assert page.items[0].state == "pending"
    assert page.next_cursor is None


@pytest.mark.asyncio
async def test_list_pending_empty_for_unknown_tenant(tmp_path: Any) -> None:
    store = await _store(tmp_path)
    page = await store.list_pending("nobody", limit=50, cursor=None)
    assert page.items == ()
    assert page.next_cursor is None


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
async def test_summary_and_detail_project_two_of_four_progress(tmp_path: Any) -> None:
    store = await _store(tmp_path)
    now = datetime(2026, 6, 11, 12, 0, tzinfo=UTC)
    rid = uuid.uuid4()
    await _seed_request(store, request_id=rid, flow="require_4_eyes", now=now)
    async with store._engine.begin() as conn:
        await conn.execute(
            _approval_requests.update()
            .where(_approval_requests.c.request_id == rid)
            .values(decisions_recorded=2, required_count=4)
        )

    page = await store.list_pending("t1", limit=50, cursor=None)
    assert len(page.items) == 1
    assert (page.items[0].decisions_recorded, page.items[0].required_count) == (2, 4)

    detail = await store.load_detail(request_id=rid, tenant_id="t1")
    assert detail is not None
    assert (detail.decisions_recorded, detail.required_count) == (2, 4)


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


# ---------------------------------------------------------------------------
# HP-4 (M8.5-C T1): the typed strict cursor codec
# ---------------------------------------------------------------------------


def _cursor(when: datetime | None = None, rid: uuid.UUID | None = None) -> ApprovalQueueCursor:
    return ApprovalQueueCursor(
        created_at=when or datetime(2026, 7, 11, 12, 0, tzinfo=UTC),
        request_id=rid or uuid.uuid4(),
    )


def test_cursor_round_trip_identity() -> None:
    c = _cursor()
    assert decode_queue_cursor(encode_queue_cursor(c)) == c


def test_cursor_mint_normalizes_naive_to_utc() -> None:
    # The write path persists tz-aware UTC; drivers without tz storage
    # (sqlite) hand the instant back naive — the mint normalizes so the
    # strict aware-required decode holds on every dialect.
    naive = _cursor(when=datetime(2026, 7, 11, 12, 0))
    decoded = decode_queue_cursor(encode_queue_cursor(naive))
    assert decoded.created_at.tzinfo is not None
    assert decoded.created_at.replace(tzinfo=None) == naive.created_at


def test_cursor_over_length_refused_before_decode() -> None:
    with pytest.raises(ApprovalCursorInvalid, match="maximum encoded length"):
        decode_queue_cursor("A" * (APPROVAL_CURSOR_MAX_ENCODED_LEN + 1))


def test_cursor_trailing_garbage_refused() -> None:
    # urlsafe_b64decode silently DISCARDS non-alphabet bytes; strict
    # validation must refuse a "<valid>!!!" trailing-garbage form (the
    # cursor is a non-authoritative position, not a signed token — the ambiguity
    # is what's rejected, not "tampering").
    with pytest.raises(ApprovalCursorInvalid, match="base64url"):
        decode_queue_cursor(encode_queue_cursor(_cursor()) + "!!!")


def test_cursor_version_true_is_not_version_1() -> None:
    import base64 as b64
    import json as js

    raw = b64.urlsafe_b64encode(
        js.dumps(
            {
                "v": True,
                "created_at": "2026-07-11T12:00:00+00:00",
                "request_id": str(uuid.uuid4()),
            }
        ).encode()
    ).decode()
    with pytest.raises(ApprovalCursorInvalid, match="version"):
        decode_queue_cursor(raw)


@pytest.mark.parametrize(
    ("payload", "match"),
    [
        ([1, 2], "key set"),
        ({"v": 1, "created_at": "2026-07-11T12:00:00+00:00"}, "key set"),
        (
            {
                "v": 1,
                "created_at": "2026-07-11T12:00:00+00:00",
                "request_id": str(uuid.uuid4()),
                "extra": 1,
            },
            "key set",
        ),
        (
            {"v": 2, "created_at": "2026-07-11T12:00:00+00:00", "request_id": str(uuid.uuid4())},
            "version",
        ),
        ({"v": 1, "created_at": 123, "request_id": str(uuid.uuid4())}, "invalid types"),
        ({"v": 1, "created_at": "nope", "request_id": str(uuid.uuid4())}, "unparseable"),
        (
            {"v": 1, "created_at": "2026-07-11T12:00:00+00:00", "request_id": "not-a-uuid"},
            "unparseable",
        ),
        (
            {"v": 1, "created_at": "2026-07-11T12:00:00", "request_id": str(uuid.uuid4())},
            "timezone-aware",
        ),
    ],
    ids=[
        "not-an-object",
        "missing-key",
        "extra-key",
        "wrong-version",
        "non-string-timestamp",
        "unparseable-timestamp",
        "non-uuid-request-id",
        "naive-timestamp",
    ],
)
def test_cursor_decode_refusal_matrix(payload: Any, match: str) -> None:
    import base64 as b64
    import json as js

    raw = b64.urlsafe_b64encode(js.dumps(payload).encode()).decode()
    with pytest.raises(ApprovalCursorInvalid, match=match):
        decode_queue_cursor(raw)


# ---------------------------------------------------------------------------
# HP-4: keyset pagination behavior over the Alembic-migrated DB
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_pending_defensive_limit_clamp(tmp_path: Any) -> None:
    store = await _store(tmp_path)
    now = datetime(2026, 7, 11, 12, 0, tzinfo=UTC)
    for _ in range(2):
        await _seed_request(store, request_id=uuid.uuid4(), now=now)
    # limit=0 clamps to 1 (the route owns the wire 422; storage is defensive).
    page = await store.list_pending("t1", limit=0, cursor=None)
    assert len(page.items) == 1
    # limit=201 clamps to 200 (no error).
    page = await store.list_pending("t1", limit=201, cursor=None)
    assert len(page.items) == 2


@pytest.mark.asyncio
async def test_list_pending_equal_created_at_tiebreaks_by_request_id(tmp_path: Any) -> None:
    store = await _store(tmp_path)
    now = datetime(2026, 7, 11, 12, 0, tzinfo=UTC)
    rid_a = uuid.UUID(int=1)
    rid_b = uuid.UUID(int=2)
    # Insert in REVERSE id order to prove ordering comes from the keyset.
    await _seed_request(store, request_id=rid_b, now=now)
    await _seed_request(store, request_id=rid_a, now=now)
    page = await store.list_pending("t1", limit=50, cursor=None)
    assert [r.request_id for r in page.items] == [rid_a, rid_b]


@pytest.mark.asyncio
async def test_list_pending_three_page_walk_exact_id_set(tmp_path: Any) -> None:
    store = await _store(tmp_path)
    base = datetime(2026, 7, 11, 12, 0, tzinfo=UTC)
    seeded: list[uuid.UUID] = []
    for i in range(5):
        rid = uuid.UUID(int=i + 10)
        seeded.append(rid)
        await _seed_request(store, request_id=rid, now=base.replace(second=i))
    walked: list[uuid.UUID] = []
    cursor: str | None = None
    pages = 0
    while True:
        page = await store.list_pending("t1", limit=2, cursor=cursor)
        walked.extend(r.request_id for r in page.items)
        pages += 1
        if page.next_cursor is None:
            break
        cursor = page.next_cursor
    assert pages == 3
    assert walked == seeded  # exact order, no duplicates, no omissions
    # The probe row never leaks: page one carried exactly 2 items.


@pytest.mark.asyncio
async def test_list_pending_final_page_mints_no_cursor(tmp_path: Any) -> None:
    store = await _store(tmp_path)
    now = datetime(2026, 7, 11, 12, 0, tzinfo=UTC)
    await _seed_request(store, request_id=uuid.uuid4(), now=now)
    page = await store.list_pending("t1", limit=1, cursor=None)
    assert len(page.items) == 1
    assert page.next_cursor is None  # exactly one row; the probe found nothing


@pytest.mark.asyncio
async def test_list_pending_cursor_never_leaks_cross_tenant(tmp_path: Any) -> None:
    store = await _store(tmp_path)
    now = datetime(2026, 7, 11, 12, 0, tzinfo=UTC)
    early = now.replace(hour=11)
    # A FOREIGN-tenant row EARLIER than every t1 row: with a broken tenant
    # filter it would appear first.
    await _seed_request(store, request_id=uuid.uuid4(), tenant="t-foreign", now=early)
    rid1, rid2 = uuid.UUID(int=21), uuid.UUID(int=22)
    await _seed_request(store, request_id=rid1, now=now)
    await _seed_request(store, request_id=rid2, now=now.replace(minute=1))
    page1 = await store.list_pending("t1", limit=1, cursor=None)
    assert [r.request_id for r in page1.items] == [rid1]
    assert page1.next_cursor is not None
    page2 = await store.list_pending("t1", limit=1, cursor=page1.next_cursor)
    assert [r.request_id for r in page2.items] == [rid2]
    assert page2.next_cursor is None


@pytest.mark.asyncio
async def test_list_pending_invalid_cursor_raises_typed(tmp_path: Any) -> None:
    store = await _store(tmp_path)
    with pytest.raises(ApprovalCursorInvalid):
        await store.list_pending("t1", limit=10, cursor="@@not-base64url@@")


def test_list_pending_page_is_frozen_with_tuple_items() -> None:
    import dataclasses

    page = ListPendingPage(items=(), next_cursor=None)
    with pytest.raises(dataclasses.FrozenInstanceError):
        page.items = ()  # type: ignore[misc]


@pytest.mark.asyncio
async def test_list_pending_excludes_terminal_states(tmp_path: Any) -> None:
    # The queue is a FIXED actionable projection over pending | awaiting_second
    # (ADR-014 M8.5-C T1 amendment). granted / denied / expired rows are seeded
    # DIRECTLY (a query test — no engine transitions) and MUST NOT appear;
    # awaiting_second (an actionable state) MUST appear alongside pending.
    import sqlalchemy as sa

    store = await _store(tmp_path)
    base = datetime(2026, 6, 11, 12, 0, tzinfo=UTC)
    actionable = {
        "pending": uuid.UUID(int=101),
        "awaiting_second": uuid.UUID(int=102),
    }
    terminal = {
        "granted": uuid.UUID(int=201),
        "denied": uuid.UUID(int=202),
        "expired": uuid.UUID(int=203),
    }

    async def _seed_state(rid: uuid.UUID, state: str, minute: int) -> None:
        async with store._engine.begin() as conn:
            await conn.execute(
                _approval_requests.insert().values(
                    request_id=rid,
                    tenant_id="t1",
                    flow="require_single_approval",
                    risk_tier="customer_data_read",
                    tool_identity="cognic-tool-x",
                    originator_subject="agent-1",
                    state=state,
                    first_approver=None,
                    second_approver=None,
                    denier=None,
                    envelope_digest=b"\x03" * 32,
                    args_digest=b"\x02" * 32,
                    redacted_context="ctx",
                    data_classes=["customer_pii"],
                    required_refs={},
                    created_at=base.replace(minute=minute),
                    expires_at=base + timedelta(hours=2),
                    updated_at=base.replace(minute=minute),
                )
            )

    for minute, (state, rid) in enumerate({**actionable, **terminal}.items()):
        await _seed_state(rid, state, minute)

    page = await store.list_pending("t1", limit=50, cursor=None)
    seen = {r.request_id for r in page.items}
    assert seen == set(actionable.values()), (
        "the queue must contain EXACTLY the actionable rows; "
        f"terminal leak: {sorted(seen & set(terminal.values()))}"
    )
    assert {r.state for r in page.items} == {"pending", "awaiting_second"}
    # A sanity check that the terminal rows really exist (the exclusion is the
    # WHERE clause, not an empty table).
    async with store._engine.connect() as conn:
        total = (
            await conn.execute(sa.select(sa.func.count()).select_from(_approval_requests))
        ).scalar_one()
    assert total == 5
