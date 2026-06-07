"""ADR-023 — ``TenantConfigOverlayStore`` live-Postgres proof.

Mirrors ``tests/integration/core/memory/test_storage_pg_integration.py`` for
the env-gate + superuser-DSN convention. Covers the invariants the SQLite unit
suite cannot authoritatively reach (per
``feedback_storage_test_migrated_db_not_create_all``):

  - the ``uq_tenant_config_overlay_tenant_field`` UNIQUE constraint rejects a
    duplicate ``(tenant_id, field_key)`` INSERT at the DB layer (the store's
    upsert never trips it; a future direct-SQL writer would);
  - ``get_many`` is tenant-scoped on real Postgres (cross-tenant returns ``{}``);
  - ``GovernanceJSON`` round-trips int vs float without coercion (SQLite's
    looser typing cannot prove this).

Self-skips cleanly when ``COGNIC_RUN_POSTGRES_INTEGRATION`` /
``COGNIC_DATABASE_URL_POSTGRES_TEST`` are unset.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.config import _MEMORY_EXPORT_RETENTION_FLOOR_SECONDS
from cognic_agentos.core.config_overlay.storage import (
    TenantConfigOverlayStore,
    _tenant_config_overlay,
)
from cognic_agentos.core.decision_history import _decision_history

_PG_SKIPIF = pytest.mark.skipif(
    not (
        os.environ.get("COGNIC_RUN_POSTGRES_INTEGRATION")
        and os.environ.get("COGNIC_DATABASE_URL_POSTGRES_TEST")
    ),
    reason=(
        "live Postgres required; set COGNIC_RUN_POSTGRES_INTEGRATION=1 "
        "+ apply migrations + export COGNIC_DATABASE_URL_POSTGRES_TEST"
    ),
)


def _superuser_url() -> str:
    return os.environ["COGNIC_DATABASE_URL_POSTGRES_TEST"]


async def _reset_state(engine: AsyncEngine) -> None:
    """Ensure chain + overlay tables exist (checkfirst — harmless if the
    migration already ran), wipe rows, reset the ``decision_history``
    chain head to genesis."""
    async with engine.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        await conn.execute(delete(_tenant_config_overlay))
        await conn.execute(delete(_decision_history))
        existing = (
            await conn.execute(
                select(_chain_heads).where(_chain_heads.c.chain_id == "decision_history")
            )
        ).first()
        if existing is None:
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id="decision_history",
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=datetime.now(UTC),
                )
            )
        else:
            await conn.execute(
                update(_chain_heads)
                .where(_chain_heads.c.chain_id == "decision_history")
                .values(latest_sequence=0, latest_hash=ZERO_HASH, updated_at=datetime.now(UTC))
            )


@_PG_SKIPIF
async def test_unique_constraint_blocks_direct_duplicate_insert() -> None:
    engine = create_async_engine(_superuser_url())
    try:
        await _reset_state(engine)
        store = TenantConfigOverlayStore(engine)
        await store.set_overlay(
            tenant_id="t1",
            field_key="sandbox_per_tenant_max_cpu",
            base_value=4.0,
            proposed="2.0",
            actor_subject="op",
            actor_type="human",
            request_id="cfg-overlay-set-pg1",
        )
        # A DIRECT duplicate INSERT (bypassing the store's upsert) MUST trip the
        # uq constraint. pytest.raises OUTSIDE engine.begin() so the exception
        # propagates and the context manager rolls back (packs-storage idiom).
        with pytest.raises(IntegrityError):
            async with engine.begin() as conn:
                await conn.execute(
                    insert(_tenant_config_overlay).values(
                        id=uuid.uuid4(),
                        tenant_id="t1",
                        field_key="sandbox_per_tenant_max_cpu",
                        value=3.0,
                        set_by_actor="op",
                        set_at=datetime.now(UTC),
                        last_request_id="cfg-overlay-dup",
                    )
                )
    finally:
        await engine.dispose()


@_PG_SKIPIF
async def test_get_many_cross_tenant_returns_empty() -> None:
    engine = create_async_engine(_superuser_url())
    try:
        await _reset_state(engine)
        store = TenantConfigOverlayStore(engine)
        await store.set_overlay(
            tenant_id="t1",
            field_key="sandbox_per_tenant_max_cpu",
            base_value=4.0,
            proposed="2.0",
            actor_subject="op",
            actor_type="human",
            request_id="cfg-overlay-set-pg2",
        )
        assert await store.get_many("t2", ("sandbox_per_tenant_max_cpu",)) == {}
    finally:
        await engine.dispose()


@_PG_SKIPIF
async def test_governance_json_int_float_fidelity() -> None:
    engine = create_async_engine(_superuser_url())
    try:
        await _reset_state(engine)
        store = TenantConfigOverlayStore(engine)
        # float field — a fractional value is unambiguously float in JSON.
        await store.set_overlay(
            tenant_id="t1",
            field_key="sandbox_per_tenant_max_cpu",
            base_value=4.0,
            proposed="2.5",
            actor_subject="op",
            actor_type="human",
            request_id="cfg-overlay-set-pg3a",
        )
        # int floor field — raised above the kernel floor, unambiguously int.
        raised = _MEMORY_EXPORT_RETENTION_FLOOR_SECONDS + 1
        await store.set_overlay(
            tenant_id="t1",
            field_key="memory_export_retention_seconds",
            base_value=_MEMORY_EXPORT_RETENTION_FLOOR_SECONDS,
            proposed=str(raised),
            actor_subject="op",
            actor_type="human",
            request_id="cfg-overlay-set-pg3b",
        )
        got = await store.get_many(
            "t1", ("sandbox_per_tenant_max_cpu", "memory_export_retention_seconds")
        )
        assert got["sandbox_per_tenant_max_cpu"] == 2.5
        assert isinstance(got["sandbox_per_tenant_max_cpu"], float)
        assert got["memory_export_retention_seconds"] == raised
        assert isinstance(got["memory_export_retention_seconds"], int)
    finally:
        await engine.dispose()
