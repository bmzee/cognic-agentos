import asyncio
import os
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

_ORACLE_URL = "oracle+oracledb://cognic:cognic_dev_only@localhost:1521/?service_name=XEPDB1"


async def _upgrade_to_head(url: str) -> None:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")


@pytest.mark.oracle
@pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_ORACLE_INTEGRATION"),
    reason="live Oracle XE; opt in via COGNIC_RUN_ORACLE_INTEGRATION=1",
)
async def test_oracle_function_based_index_enforces_block_singleton() -> None:
    from cognic_agentos.core.memory.storage import _memory_records as t

    await _upgrade_to_head(_ORACLE_URL)
    eng = create_async_engine(_ORACLE_URL)
    vals: dict[str, Any] = dict(
        tenant_id="x",
        subject_ref="agent:a",
        agent_id="a",
        tier="long_term",
        block_kind="persona",
        key=None,
        data_classes=[],
        purpose="customer_support",
        redaction_version=0,
        created_at=datetime.now(UTC),
    )
    try:
        async with eng.begin() as c:
            await c.execute(t.insert().values(record_id=uuid.uuid4(), value={"v": 1}, **vals))
        with pytest.raises(sa.exc.IntegrityError):
            async with eng.begin() as c:
                await c.execute(t.insert().values(record_id=uuid.uuid4(), value={"v": 2}, **vals))
    finally:  # re-runnable on the persistent live Oracle
        async with eng.begin() as c:
            await c.execute(sa.delete(t).where(t.c.tenant_id == "x"))
        await eng.dispose()
