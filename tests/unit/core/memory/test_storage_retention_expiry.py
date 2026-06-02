"""Sprint 11.5b T4 — retention-expiry read filter (T4/T7 invariant).

An expired-but-unpurged row is a miss IMMEDIATELY when ``retention_until``
passes — independent of the reaper sweep cadence.
"""

from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa

from cognic_agentos.core.memory.storage import _memory_records
from tests.unit.core.memory._builders import SUBJECT, _task_record


@pytest.mark.asyncio
async def test_get_treats_expired_retention_as_miss_before_physical_purge(
    memory_adapter, _mem_engine
):
    """An expired row is a get() miss even though the row physically exists
    and the reaper hasn't run yet."""
    rid = await memory_adapter.put(_task_record(value="v"))
    # Expire it in the past WITHOUT tombstoning and WITHOUT running the reaper.
    async with _mem_engine.begin() as c:
        await c.execute(
            sa.update(_memory_records)
            .where(_memory_records.c.record_id == rid)
            .values(retention_until=datetime.now(UTC) - timedelta(seconds=1))
        )
    # Confirm the row physically exists (so the filter is doing the work, not absence)
    async with _mem_engine.connect() as c:
        physical = (
            await c.execute(sa.select(_memory_records).where(_memory_records.c.record_id == rid))
        ).first()
    assert physical is not None  # row is physically there

    # get() must return None (expired → miss)
    hit = await memory_adapter.get(
        tenant_id="t1",
        agent_id="kyc",
        subject=SUBJECT,
        tier="task",
        key="greeting",
    )
    assert hit is None  # expired => miss IMMEDIATELY


@pytest.mark.asyncio
async def test_list_for_subject_treats_expired_retention_as_miss(memory_adapter, _mem_engine):
    """list_for_subject() must also exclude expired-but-unpurged rows."""
    rid = await memory_adapter.put(_task_record(value="v"))
    async with _mem_engine.begin() as c:
        await c.execute(
            sa.update(_memory_records)
            .where(_memory_records.c.record_id == rid)
            .values(retention_until=datetime.now(UTC) - timedelta(seconds=1))
        )
    rows = await memory_adapter.list_for_subject(tenant_id="t1", agent_id="kyc", subject=SUBJECT)
    assert rows == []  # enumerate excludes expired rows too


@pytest.mark.asyncio
async def test_active_rows_still_visible_after_retention_filter_added(memory_adapter):
    """Adding the retention-expiry filter must not regress active reads."""
    rid = await memory_adapter.put(_task_record(value="active"))
    hit = await memory_adapter.get(
        tenant_id="t1",
        agent_id="kyc",
        subject=SUBJECT,
        tier="task",
        key="greeting",
    )
    assert hit is not None and hit.record_id == rid


@pytest.mark.asyncio
async def test_null_retention_until_is_never_expired(memory_adapter):
    """A row with retention_until=None is never expired (no retention limit)."""
    await memory_adapter.put(_task_record(value="permanent"))
    hit = await memory_adapter.get(
        tenant_id="t1",
        agent_id="kyc",
        subject=SUBJECT,
        tier="task",
        key="greeting",
    )
    assert hit is not None  # NULL retention_until means no expiry
