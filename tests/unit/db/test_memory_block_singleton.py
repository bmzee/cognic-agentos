# The partial-unique-index SEMANTICS test (proves ONE ACTIVE block per identity tuple).
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine


async def _upgrade_to_head(url: str) -> None:
    import asyncio

    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")


def _block_row(**over: Any) -> dict[str, Any]:
    # record_id (PK) + created_at supplied explicitly so the inserts don't depend
    # on server defaults; a FRESH uuid per call so the 2nd insert's IntegrityError
    # comes from the singleton unique index, NOT a PK collision.
    base = dict(
        record_id=uuid.uuid4(),
        tenant_id="x",
        subject_ref="agent:a",
        agent_id="a",
        tier="long_term",
        block_kind="persona",
        key=None,
        value={"v": 1},
        data_classes=[],
        purpose="customer_support",
        redaction_version=0,
        created_at=datetime.now(UTC),
    )
    base.update(over)
    return base


async def test_two_active_blocks_same_identity_rejected(tmp_path: Any) -> None:
    from cognic_agentos.core.memory.storage import _memory_records as t

    url = f"sqlite+aiosqlite:///{tmp_path / 'singleton.db'}"
    await _upgrade_to_head(url)
    eng = create_async_engine(url)
    async with eng.begin() as c:
        await c.execute(t.insert().values(**_block_row()))
    with pytest.raises(sa.exc.IntegrityError):
        async with eng.begin() as c:
            await c.execute(t.insert().values(**_block_row(value={"v": 2})))
    await eng.dispose()


async def test_tombstoned_block_frees_the_singleton_slot(tmp_path: Any) -> None:
    from cognic_agentos.core.memory.storage import _memory_records as t

    url = f"sqlite+aiosqlite:///{tmp_path / 'singleton_tomb.db'}"
    await _upgrade_to_head(url)
    eng = create_async_engine(url)
    async with eng.begin() as c:
        await c.execute(t.insert().values(**_block_row()))
        await c.execute(
            sa.update(t).where(t.c.subject_ref == "agent:a").values(tombstone=sa.func.now())
        )
        await c.execute(t.insert().values(**_block_row(value={"v": 2})))  # prior tombstoned -> OK
    await eng.dispose()
