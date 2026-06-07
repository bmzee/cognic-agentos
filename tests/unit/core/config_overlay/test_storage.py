from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.config_overlay.registry import TenantOverlayRejected
from cognic_agentos.core.config_overlay.storage import (
    TenantConfigOverlayStore,
    _tenant_config_overlay,
)
from cognic_agentos.core.decision_history import _decision_history


@pytest.fixture
async def engine(tmp_path: Any) -> Any:
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'ovl.db'}")
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="decision_history",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=datetime.now(UTC),
            )
        )
    yield eng
    await eng.dispose()


@pytest.fixture
def store(engine: AsyncEngine) -> TenantConfigOverlayStore:
    return TenantConfigOverlayStore(engine)


async def test_set_overlay_writes_row_and_chain_atomically(
    store: TenantConfigOverlayStore, engine: AsyncEngine
) -> None:
    await store.set_overlay(
        tenant_id="t1",
        field_key="sandbox_per_tenant_max_cpu",
        base_value=4.0,
        proposed="2.0",
        actor_subject="op@bank",
        actor_type="human",
        request_id="cfg-overlay-set-deadbeef",
    )
    async with engine.connect() as conn:
        rows = list((await conn.execute(select(_tenant_config_overlay))).fetchall())
        chain = list(
            (
                await conn.execute(
                    select(_decision_history).where(
                        _decision_history.c.event_type == "config.tenant_overlay.set"
                    )
                )
            ).fetchall()
        )
    assert len(rows) == 1
    assert rows[0].value == 2.0
    assert rows[0].last_request_id == "cfg-overlay-set-deadbeef"
    assert len(chain) == 1
    payload = chain[0].payload
    assert set(payload) >= {
        "tenant_id",
        "field_key",
        "direction",
        "base_value",
        "overlay_value",
        "previous_overlay_value",
        "actor_subject",
        "actor_type",
    }
    assert payload["direction"] == "ceiling"
    assert payload["base_value"] == 4.0
    assert payload["overlay_value"] == 2.0
    assert list(chain[0].iso_controls) == ["ISO42001.A.6.2.5"]


async def test_loosening_set_writes_zero_rows_and_zero_chain(
    store: TenantConfigOverlayStore, engine: AsyncEngine
) -> None:
    with pytest.raises(TenantOverlayRejected) as e:
        await store.set_overlay(
            tenant_id="t1",
            field_key="sandbox_per_tenant_max_cpu",
            base_value=4.0,
            proposed="8.0",
            actor_subject="op",
            actor_type="human",
            request_id="cfg-overlay-set-x",
        )
    assert e.value.reason == "tenant_overlay_loosens_ceiling"
    async with engine.connect() as conn:
        rows = list((await conn.execute(select(_tenant_config_overlay))).fetchall())
        chain = list((await conn.execute(select(_decision_history))).fetchall())
    assert rows == []
    assert chain == []


async def test_get_many_one_snapshot_returns_overrides_and_absent(
    store: TenantConfigOverlayStore,
) -> None:
    await store.set_overlay(
        tenant_id="t1",
        field_key="sandbox_per_tenant_max_cpu",
        base_value=4.0,
        proposed="2.0",
        actor_subject="op",
        actor_type="human",
        request_id="cfg-overlay-set-y",
    )
    got = await store.get_many(
        "t1", ("sandbox_per_tenant_max_cpu", "sandbox_per_tenant_max_memory")
    )
    assert got == {"sandbox_per_tenant_max_cpu": 2.0}


async def test_clear_deletes_row_and_emits_cleared_chain(
    store: TenantConfigOverlayStore, engine: AsyncEngine
) -> None:
    await store.set_overlay(
        tenant_id="t1",
        field_key="sandbox_per_tenant_max_cpu",
        base_value=4.0,
        proposed="2.0",
        actor_subject="op",
        actor_type="human",
        request_id="cfg-overlay-set-z",
    )
    await store.clear_overlay(
        tenant_id="t1",
        field_key="sandbox_per_tenant_max_cpu",
        actor_subject="op",
        actor_type="human",
        request_id="cfg-overlay-clear-z",
    )
    async with engine.connect() as conn:
        rows = list((await conn.execute(select(_tenant_config_overlay))).fetchall())
        chain = list(
            (
                await conn.execute(
                    select(_decision_history).where(
                        _decision_history.c.event_type == "config.tenant_overlay.cleared"
                    )
                )
            ).fetchall()
        )
    assert rows == []
    assert len(chain) == 1


async def test_get_many_is_tenant_scoped(store: TenantConfigOverlayStore) -> None:
    await store.set_overlay(
        tenant_id="t1",
        field_key="sandbox_per_tenant_max_cpu",
        base_value=4.0,
        proposed="2.0",
        actor_subject="op",
        actor_type="human",
        request_id="cfg-overlay-set-t1",
    )
    assert await store.get_many("t2", ("sandbox_per_tenant_max_cpu",)) == {}


async def test_get_many_empty_field_keys_returns_empty(store: TenantConfigOverlayStore) -> None:
    # Empty field-key tuple short-circuits to {} WITHOUT opening a connection.
    assert await store.get_many("t1", ()) == {}


async def test_set_overlay_update_path_overwrites_existing(
    store: TenantConfigOverlayStore, engine: AsyncEngine
) -> None:
    # Setting an overlay TWICE for the same (tenant, field) hits the UPDATE
    # branch (not INSERT): one row remains, carrying the latest value +
    # request_id, and the second chain row records the prior value as
    # previous_overlay_value. Both writes tighten the ceiling (<= base 4.0).
    await store.set_overlay(
        tenant_id="t1",
        field_key="sandbox_per_tenant_max_cpu",
        base_value=4.0,
        proposed="2.0",
        actor_subject="op",
        actor_type="human",
        request_id="cfg-overlay-set-first",
    )
    await store.set_overlay(
        tenant_id="t1",
        field_key="sandbox_per_tenant_max_cpu",
        base_value=4.0,
        proposed="1.5",
        actor_subject="op2",
        actor_type="human",
        request_id="cfg-overlay-set-second",
    )
    async with engine.connect() as conn:
        rows = list((await conn.execute(select(_tenant_config_overlay))).fetchall())
        chain = list(
            (
                await conn.execute(
                    select(_decision_history).where(
                        _decision_history.c.event_type == "config.tenant_overlay.set"
                    )
                )
            ).fetchall()
        )
    assert len(rows) == 1  # UPDATE, not a second INSERT
    assert rows[0].value == 1.5
    assert rows[0].set_by_actor == "op2"
    assert rows[0].last_request_id == "cfg-overlay-set-second"
    assert len(chain) == 2
    second = max(chain, key=lambda r: r.sequence)  # higher sequence = second write
    assert second.payload["overlay_value"] == 1.5
    assert second.payload["previous_overlay_value"] == 2.0
