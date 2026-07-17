"""M8.5-D D2 action-entitlement reads against an Alembic-migrated DB."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.entitlements.store import EntitlementStore, _action_entitlements


@pytest.fixture
async def engine(tmp_path: Any) -> Any:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'action-entitlements.db'}"
    await asyncio.to_thread(command.upgrade, make_alembic_config(url), "head")
    result = create_async_engine(url)
    yield result
    await result.dispose()


async def _seed(
    engine: AsyncEngine,
    *,
    tenant_id: str,
    subject: str,
    tool_identity: str,
) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            sa.insert(_action_entitlements).values(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                subject=subject,
                tool_identity=tool_identity,
                created_at=datetime.now(UTC),
            )
        )


async def test_exact_tenant_subject_tool_entitlement_returns_true(engine: AsyncEngine) -> None:
    await _seed(
        engine,
        tenant_id="tenant-a",
        subject="analyst.amir",
        tool_identity="probe/probe_write",
    )
    store = EntitlementStore(engine)
    assert await store.entitled_action(
        tenant_id="tenant-a",
        subject="analyst.amir",
        tool_identity="probe/probe_write",
    )


async def test_absent_action_entitlement_returns_false(engine: AsyncEngine) -> None:
    store = EntitlementStore(engine)
    assert not await store.entitled_action(
        tenant_id="tenant-a",
        subject="analyst.amir",
        tool_identity="probe/probe_write",
    )


@pytest.mark.parametrize(
    ("tenant_id", "subject", "tool_identity"),
    [
        ("tenant-b", "analyst.amir", "probe/probe_write"),
        ("tenant-a", "analyst.sara", "probe/probe_write"),
        ("tenant-a", "analyst.amir", "probe/other_write"),
    ],
)
async def test_each_wrong_identity_leg_is_invisible(
    engine: AsyncEngine,
    tenant_id: str,
    subject: str,
    tool_identity: str,
) -> None:
    await _seed(
        engine,
        tenant_id="tenant-a",
        subject="analyst.amir",
        tool_identity="probe/probe_write",
    )
    store = EntitlementStore(engine)
    assert not await store.entitled_action(
        tenant_id=tenant_id,
        subject=subject,
        tool_identity=tool_identity,
    )
