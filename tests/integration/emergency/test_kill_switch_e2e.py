"""Sprint 13.6 T7 (ADR-018) — kill-switch cross-surface e2e on a migrated DB.

Proves the integration contract that the unit tests cannot: a SINGLE
``KillSwitchEngine``, mutated through the portal operator HTTP surface
(flip / revert), drives BOTH runtime enforcement read-surfaces — the gateway
F4 gate's ``check_gateway`` and the memory gate's ``MemoryFreezeConformer``
(seed OR tenant_full, review patch 5) — and leaves ``emergency.*`` chain
evidence reachable via ``GET /audit``.

The gateway's ``completion`` raising ``GatewayKillSwitchActive`` on an active
switch is unit-pinned in ``tests/unit/llm/test_gateway_kill_switch.py``; this
e2e proves the operator surface drives the SAME engine those enforcement
points consult. Real migrated DH store (alembic head); fake Redis control
plane.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.core.emergency.kill_switches import (
    KillSwitchEngine,
    MemoryFreezeConformer,
    RedisMemoryWriteFreezeKillSwitch,
)
from cognic_agentos.portal.api.emergency.routes import build_emergency_routes
from cognic_agentos.portal.rbac.actor import Actor


class _FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    async def get(self, key: str) -> Any:
        return self.store.get(key)

    async def set(self, key: str, value: Any, **kwargs: Any) -> Any:
        self.store[key] = value


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


def _ops_actor() -> Actor:
    return Actor(
        subject="ops@bank.example",
        tenant_id="t1",
        scopes=frozenset(
            {
                "emergency.kill.model",
                "emergency.kill.tenant_full",
                "emergency.read",
            }
        ),
        actor_type="human",
    )


async def _migrated_dh_store(tmp_path: Any) -> DecisionHistoryStore:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'e2e.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    return DecisionHistoryStore(create_async_engine(url))


def _client(engine: KillSwitchEngine, dh: DecisionHistoryStore) -> AsyncClient:
    app = FastAPI()
    app.state.actor_binder = _StubBinder(_ops_actor())
    app.state.ui_event_broker = None
    app.include_router(build_emergency_routes(engine=engine, decision_history_store=dh))
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://t")


@pytest.mark.asyncio
async def test_operator_flip_drives_gateway_and_memory_enforcement(tmp_path: Any) -> None:
    redis = _FakeRedis()
    dh = await _migrated_dh_store(tmp_path)
    # ONE engine — the production composition-root invariant (build_runtime
    # threads this same instance into the gateway + the memory conformer).
    engine = KillSwitchEngine(redis_client=redis, cache_ttl_s=60, decision_history=dh)
    memory_conformer = MemoryFreezeConformer(
        seed=RedisMemoryWriteFreezeKillSwitch(redis_client=redis, cache_ttl_s=60),
        engine=engine,
    )

    # --- baseline: nothing tripped on either enforcement surface ---
    assert await engine.check_gateway(tenant_id="t1", model_alias="tier1", external=True) is None
    assert await memory_conformer.is_write_frozen(tenant_id="t1") is False

    async with _client(engine, dh) as client:
        # --- operator flips the `model` switch via HTTP ---
        flip = await client.post(
            "/api/v1/emergency/kill-switches",
            json={
                "class": "model",
                "scope_key": "tier1",
                "reason": "model hallucinating in prod",
                "category": "incident_response",
            },
        )
        assert flip.status_code == 200

        # the gateway F4 gate's exact call now reports the tripped class...
        assert (
            await engine.check_gateway(tenant_id="t1", model_alias="tier1", external=True)
        ) == "model"
        # ...while memory writes for t1 are still free (model != tenant_full).
        assert await memory_conformer.is_write_frozen(tenant_id="t1") is False

        # --- operator flips tenant_full: freezes memory writes AND the gateway ---
        tf = await client.post(
            "/api/v1/emergency/kill-switches",
            json={
                "class": "tenant_full",
                "scope_key": "t1",
                "reason": "tenant under attack",
                "category": "incident_response",
            },
        )
        assert tf.status_code == 200
        assert await memory_conformer.is_write_frozen(tenant_id="t1") is True
        # tenant_full takes gateway precedence over the (still-active) model switch.
        assert (
            await engine.check_gateway(tenant_id="t1", model_alias="tier1", external=True)
        ) == "tenant_full"

        # --- operator reverts the model switch; tenant_full still holds both ---
        rv = await client.delete(
            "/api/v1/emergency/kill-switches/model/tier1",
            params={"reason": "rolled back the model", "category": "incident_response"},
        )
        assert rv.status_code == 200
        assert (
            await engine.check_gateway(tenant_id="t1", model_alias="tier1", external=True)
        ) == "tenant_full"

        # --- revert tenant_full: both enforcement surfaces clear ---
        rv2 = await client.delete(
            "/api/v1/emergency/kill-switches/tenant_full/t1",
            params={"reason": "attack mitigated", "category": "incident_response"},
        )
        assert rv2.status_code == 200
        assert await memory_conformer.is_write_frozen(tenant_id="t1") is False
        assert (
            await engine.check_gateway(tenant_id="t1", model_alias="tier1", external=True)
        ) is None

        # --- the chain trail: 2 flips + 2 reverts, newest-first ---
        audit = await client.get("/api/v1/emergency/audit")
    assert audit.status_code == 200
    decision_types = [r["decision_type"] for r in audit.json()]
    assert decision_types == [
        "emergency.kill_switch_reverted",
        "emergency.kill_switch_reverted",
        "emergency.kill_switch_flipped",
        "emergency.kill_switch_flipped",
    ]
    # the tenant_full rows carry tenant attribution + the live enforcement status.
    tenant_full_rows = [r for r in audit.json() if r["payload"]["class"] == "tenant_full"]
    assert all(r["tenant_id"] == "t1" for r in tenant_full_rows)
    assert all(r["payload"]["enforcement_status"] == "live" for r in tenant_full_rows)
