"""Sprint 11.5b T4 (P1 review fix) — block redaction against the REAL migration index.

The conftest ``_mem_engine`` fixture builds ``memory_records`` via
``metadata.create_all()``, which OMITS the migration-only
``uq_memory_block_singleton`` partial unique index. This test runs the Alembic
migration to head so the real index exists, then proves ``redact_record`` on an
ACTIVE block seals the old version BEFORE inserting the new one
(tombstone-then-insert, matching ``upsert_block``) — no IntegrityError on the
singleton constraint. With the buggy insert-then-tombstone order the new active
block collides with the still-active old block under the partial unique index.
"""

import asyncio
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.decision_history import DecisionHistoryStore, _decision_history
from cognic_agentos.core.memory._context import MemoryWriteRecord, RedactionSpan
from cognic_agentos.core.memory.storage import PostgresMemoryAdapter, _memory_records
from cognic_agentos.core.memory.tiers import SubjectRef


async def _migrated_engine(tmp_path: Any) -> Any:
    """Alembic-migrated SQLite engine — the REAL partial unique index, NOT create_all().

    The migration creates AND seeds ``governance_chain_heads`` (audit_event +
    decision_history), so no manual chain-head seeding is needed here."""
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'block_redact.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    return create_async_engine(url)


@pytest.mark.asyncio
async def test_redact_active_block_against_real_singleton_index(tmp_path: Any) -> None:
    eng = await _migrated_engine(tmp_path)
    try:
        adapter = PostgresMemoryAdapter(engine=eng, dh_store=DecisionHistoryStore(eng))
        subject = SubjectRef(kind="agent", id="a")
        block = MemoryWriteRecord(
            tenant_id="x",
            agent_id="a",
            actor_id="op",
            subject=subject,
            tier="long_term",
            purpose="customer_support",
            data_classes=("internal",),
            value={"persona": {"tone": "formal"}, "note": "keep"},
            request_id="memory-write-seed",
            key=None,
            block_kind="persona",
        )
        old_rid = await adapter.upsert_block(block)

        # Redact a field of the ACTIVE block — must NOT trip uq_memory_block_singleton.
        receipt = await adapter.redact_record(
            tenant_id="x",
            agent_id="a",
            record_id=old_rid,
            span=RedactionSpan(path=("persona", "tone")),
            reason="pii_minimization",
            actor_id="op",
        )

        async with eng.connect() as c:
            old = (
                await c.execute(
                    sa.select(_memory_records).where(_memory_records.c.record_id == old_rid)
                )
            ).first()
            new = (
                await c.execute(
                    sa.select(_memory_records).where(
                        _memory_records.c.record_id == receipt.new_version_id
                    )
                )
            ).first()
        assert old.tombstone is not None  # prior block sealed
        assert new.tombstone is None and new.block_kind == "persona"  # new active block
        assert new.value == {"persona": {"tone": "[REDACTED]"}, "note": "keep"}
        assert new.sealed_prior_version_ref == old_rid

        # the single ACTIVE block for this identity is now the new version
        hit = await adapter.get(
            tenant_id="x", agent_id="a", subject=subject, tier="long_term", block_kind="persona"
        )
        assert hit is not None and hit.record_id == receipt.new_version_id

        async with eng.connect() as c:
            redact_rows = (
                await c.execute(
                    sa.select(_decision_history).where(
                        _decision_history.c.event_type == "memory.redact"
                    )
                )
            ).all()
        assert len(redact_rows) == 1  # one memory.redact chain row
    finally:
        await eng.dispose()
