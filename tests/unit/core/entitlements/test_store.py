"""M8 Task A3 (ADR-027) — EntitlementStore against the Alembic-MIGRATED
aiosqlite DB (per ``feedback_storage_test_migrated_db_not_create_all``).

Pins: the m:n entitlement read (multi-scope subject AND shared scope), the
wire-collapse cross-tenant invisibility (wrong-tenant reads empty / None), and
the fail-closed malformed-``objects`` evidence-boundary guard — a malformed
objects column must never become a permissive allow-set downstream.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.entitlements.store import (
    DataScope,
    EntitlementStore,
    _data_scopes,
    _entitlements,
)


@pytest.fixture
async def engine(tmp_path: Any) -> Any:
    # Migrated DB — NOT create_all (feedback_storage_test_migrated_db_not_create_all).
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'entitlements.db'}"
    await asyncio.to_thread(command.upgrade, make_alembic_config(url), "head")
    eng = create_async_engine(url)
    yield eng
    await eng.dispose()


@pytest.fixture
def store(engine: AsyncEngine) -> EntitlementStore:
    return EntitlementStore(engine)


async def _seed_scope(
    engine: AsyncEngine,
    *,
    tenant_id: str,
    scope_id: str,
    schema_name: str = "RETAIL",
    objects: Any = ("V_CUSTOMERS", "V_DEPOSITS"),
    proxy_db_identity: str = "RETAIL_ANALYST_PROXY",
) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            sa.insert(_data_scopes).values(
                tenant_id=tenant_id,
                scope_id=scope_id,
                schema_name=schema_name,
                objects=list(objects) if isinstance(objects, tuple) else objects,
                proxy_db_identity=proxy_db_identity,
                created_at=datetime.now(UTC),
            )
        )


async def _seed_entitlement(
    engine: AsyncEngine, *, tenant_id: str, subject: str, scope_id: str
) -> None:
    import uuid

    async with engine.begin() as conn:
        await conn.execute(
            sa.insert(_entitlements).values(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                subject=subject,
                scope_id=scope_id,
                created_at=datetime.now(UTC),
            )
        )


# --------------------------------------------------------------------------- #
# entitled_scope_ids
# --------------------------------------------------------------------------- #


async def test_entitled_scope_ids_m_n_both_directions(
    engine: AsyncEngine, store: EntitlementStore
) -> None:
    # m:n proven in BOTH directions: one subject -> two scopes AND one of those
    # scopes -> a second subject. Each subject reads EXACTLY its own frozenset.
    await _seed_entitlement(
        engine, tenant_id="t1", subject="analyst.amir", scope_id="retail_analytics"
    )
    await _seed_entitlement(engine, tenant_id="t1", subject="analyst.amir", scope_id="financials")
    await _seed_entitlement(
        engine, tenant_id="t1", subject="analyst.sara", scope_id="retail_analytics"
    )

    amir = await store.entitled_scope_ids(tenant_id="t1", subject="analyst.amir")
    sara = await store.entitled_scope_ids(tenant_id="t1", subject="analyst.sara")

    assert isinstance(amir, frozenset)
    assert amir == frozenset({"retail_analytics", "financials"})
    assert sara == frozenset({"retail_analytics"})


async def test_entitled_scope_ids_no_rows_returns_empty_frozenset(
    store: EntitlementStore,
) -> None:
    result = await store.entitled_scope_ids(tenant_id="t1", subject="analyst.nobody")
    assert result == frozenset()
    assert isinstance(result, frozenset)


async def test_entitled_scope_ids_wrong_tenant_is_empty(
    engine: AsyncEngine, store: EntitlementStore
) -> None:
    # Cross-tenant wall: the SAME subject under a DIFFERENT tenant_id reads
    # empty — the WHERE tenant_id IS the boundary.
    await _seed_entitlement(
        engine, tenant_id="t1", subject="analyst.amir", scope_id="retail_analytics"
    )
    assert await store.entitled_scope_ids(tenant_id="t2", subject="analyst.amir") == frozenset()


# --------------------------------------------------------------------------- #
# resolve_scope
# --------------------------------------------------------------------------- #


async def test_resolve_scope_happy_path_returns_full_dataclass(
    engine: AsyncEngine, store: EntitlementStore
) -> None:
    await _seed_scope(
        engine,
        tenant_id="t1",
        scope_id="retail_analytics",
        schema_name="RETAIL",
        objects=("V_CUSTOMERS", "V_DEPOSITS"),
        proxy_db_identity="RETAIL_ANALYST_PROXY",
    )
    scope = await store.resolve_scope(tenant_id="t1", scope_id="retail_analytics")
    assert scope is not None
    assert scope == DataScope(
        scope_id="retail_analytics",
        schema_name="RETAIL",
        objects=("V_CUSTOMERS", "V_DEPOSITS"),
        proxy_db_identity="RETAIL_ANALYST_PROXY",
    )
    assert isinstance(scope.objects, tuple)


async def test_resolve_scope_empty_objects_list_is_legitimate(
    engine: AsyncEngine, store: EntitlementStore
) -> None:
    # An empty governed-view set is a valid (if useless) scope — NOT a
    # malformed row; it resolves with objects=() (and allows nothing).
    await _seed_scope(engine, tenant_id="t1", scope_id="empty_scope", objects=())
    scope = await store.resolve_scope(tenant_id="t1", scope_id="empty_scope")
    assert scope is not None
    assert scope.objects == ()


async def test_resolve_scope_cross_tenant_returns_none(
    engine: AsyncEngine, store: EntitlementStore
) -> None:
    # Wire-collapse invisibility: a scope belonging to tenant t1 is INVISIBLE
    # to t2 — same None as a genuinely unknown scope_id, so a probe cannot
    # distinguish the two.
    await _seed_scope(engine, tenant_id="t1", scope_id="retail_analytics")
    assert await store.resolve_scope(tenant_id="t2", scope_id="retail_analytics") is None


async def test_resolve_scope_unknown_returns_none(store: EntitlementStore) -> None:
    assert await store.resolve_scope(tenant_id="t1", scope_id="no_such_scope") is None


async def test_resolve_scope_malformed_objects_dict_raises_value_error(
    engine: AsyncEngine, store: EntitlementStore
) -> None:
    # Fail-closed evidence boundary: a JSON dict in the objects column must
    # NEVER become a permissive allow-set downstream.
    await _seed_scope(engine, tenant_id="t1", scope_id="bad_dict", objects={"V_CUSTOMERS": True})
    with pytest.raises(ValueError, match="bad_dict"):
        await store.resolve_scope(tenant_id="t1", scope_id="bad_dict")


async def test_resolve_scope_malformed_objects_non_string_element_raises_value_error(
    engine: AsyncEngine, store: EntitlementStore
) -> None:
    await _seed_scope(engine, tenant_id="t1", scope_id="bad_elem", objects=["V_CUSTOMERS", 42])
    with pytest.raises(ValueError, match="bad_elem"):
        await store.resolve_scope(tenant_id="t1", scope_id="bad_elem")
