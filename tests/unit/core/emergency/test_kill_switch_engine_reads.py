"""Sprint 13.6 T1 — KillSwitchEngine read side (ADR-018 §kill switches).

Pins the 8-class matrix read primitives per the LOCKED spec
``docs/superpowers/specs/2026-06-13-sprint-13.6-emergency-controls-design.md``:
the review-patch-2 key scheme (no class-name duplication in scope_key), the
seed-identical fail-closed cache doctrine, the F3 scheduler aggregation
(pack OR tenant_packs OR tenant_full; feature NOT consulted Wave-1), the F4
gateway probe with deterministic tenant_full -> model -> cloud_routing
precedence (model keyed by the LiteLLM ALIAS per spec §11 item 5), the
review-patch-5 memory conformer (seed OR tenant_full), and the
review-patch-6 enforcement-status honesty map.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from cognic_agentos.core.emergency.kill_switches import (
    ENFORCEMENT_STATUS_BY_CLASS,
    KillSwitchClass,
    KillSwitchEngine,
    MemoryFreezeConformer,
    RedisMemoryWriteFreezeKillSwitch,
    SchedulerKillSwitchConformer,
    _switch_key,
    _write_freeze_key,
)
from cognic_agentos.core.scheduler._seams import KillSwitchInterrogator


class _FakeRedis:
    """Minimal _AsyncRedisKVLike conformer with a fail toggle."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.fail = False

    async def get(self, key: str) -> Any:
        if self.fail:
            raise ConnectionError("redis down")
        return self.store.get(key)

    async def set(self, key: str, value: Any, **kwargs: Any) -> Any:
        if self.fail:
            raise ConnectionError("redis down")
        self.store[key] = value


class _Clock:
    """Mutable injectable clock — tests advance ``now`` to age the cache."""

    def __init__(self) -> None:
        self.now = datetime.now(UTC)

    def __call__(self) -> datetime:
        return self.now


def _active_doc() -> str:
    return (
        '{"active": true, "updated_at": "2026-06-13T00:00:00+00:00",'
        ' "actor_id": "ops-1", "reason": "cve"}'
    )


def _inactive_doc() -> str:
    return (
        '{"active": false, "updated_at": "2026-06-13T00:00:00+00:00",'
        ' "actor_id": "ops-1", "reason": "reverted"}'
    )


class TestKeyScheme:
    def test_no_class_name_duplication(self) -> None:
        # Review patch 2: scope_key carries NO class prefix.
        assert _switch_key("pack", "pk-1") == "cognic:killswitch:pack:pk-1"
        assert _switch_key("cloud_routing", "global") == "cognic:killswitch:cloud_routing:global"

    def test_seed_key_conforms_to_generalized_scheme(self) -> None:
        assert _switch_key("memory_write_freeze", "t-1") == _write_freeze_key("t-1")


class TestFailClosedRead:
    async def test_absent_key_is_inactive(self) -> None:
        eng = KillSwitchEngine(redis_client=_FakeRedis(), cache_ttl_s=60)
        assert await eng.is_class_active(class_="model", scope_key="tier1") is False

    async def test_active_doc_reads_active(self) -> None:
        redis = _FakeRedis()
        redis.store[_switch_key("model", "tier1")] = _active_doc()
        eng = KillSwitchEngine(redis_client=redis, cache_ttl_s=60)
        assert await eng.is_class_active(class_="model", scope_key="tier1") is True

    async def test_inactive_doc_reads_inactive(self) -> None:
        redis = _FakeRedis()
        redis.store[_switch_key("model", "tier1")] = _inactive_doc()
        eng = KillSwitchEngine(redis_client=redis, cache_ttl_s=60)
        assert await eng.is_class_active(class_="model", scope_key="tier1") is False

    async def test_redis_error_serves_fresh_cache_then_fails_closed(self) -> None:
        redis = _FakeRedis()
        clock = _Clock()
        eng = KillSwitchEngine(redis_client=redis, cache_ttl_s=60, clock=clock)
        # Prime the last-known-good cache (absent key => inactive).
        assert await eng.is_class_active(class_="model", scope_key="tier1") is False
        redis.fail = True
        # Within TTL: cached value served.
        assert await eng.is_class_active(class_="model", scope_key="tier1") is False
        # Past TTL: FAIL CLOSED (active).
        clock.now = clock.now + timedelta(seconds=61)
        assert await eng.is_class_active(class_="model", scope_key="tier1") is True

    async def test_redis_error_with_no_cache_fails_closed(self) -> None:
        redis = _FakeRedis()
        redis.fail = True
        eng = KillSwitchEngine(redis_client=redis, cache_ttl_s=60)
        assert await eng.is_class_active(class_="model", scope_key="tier1") is True

    async def test_malformed_doc_fails_closed(self) -> None:
        redis = _FakeRedis()
        redis.store[_switch_key("model", "tier1")] = '{"active": "yes"}'  # non-bool
        eng = KillSwitchEngine(redis_client=redis, cache_ttl_s=60)
        assert await eng.is_class_active(class_="model", scope_key="tier1") is True

    async def test_malformed_doc_poisons_cache_fail_closed(self) -> None:
        # The seed doctrine: malformed invalidates a prior unfrozen grace —
        # a later Redis outage within TTL serves ACTIVE, not the stale False.
        redis = _FakeRedis()
        clock = _Clock()
        eng = KillSwitchEngine(redis_client=redis, cache_ttl_s=60, clock=clock)
        assert await eng.is_class_active(class_="model", scope_key="tier1") is False
        redis.store[_switch_key("model", "tier1")] = "not json"
        assert await eng.is_class_active(class_="model", scope_key="tier1") is True
        redis.fail = True
        assert await eng.is_class_active(class_="model", scope_key="tier1") is True

    async def test_missing_custody_field_is_malformed(self) -> None:
        # ALL of updated_at / actor_id / reason are required (seed parity).
        redis = _FakeRedis()
        redis.store[_switch_key("model", "tier1")] = '{"active": true, "actor_id": "x"}'
        eng = KillSwitchEngine(redis_client=redis, cache_ttl_s=60)
        assert await eng.is_class_active(class_="model", scope_key="tier1") is True


class TestSchedulerConformer:
    def test_structurally_conforms_to_seam_protocol(self) -> None:
        conformer = SchedulerKillSwitchConformer(
            engine=KillSwitchEngine(redis_client=_FakeRedis(), cache_ttl_s=60)
        )
        assert isinstance(conformer, KillSwitchInterrogator)

    @pytest.mark.parametrize(
        ("key_class", "scope_key"),
        [("pack", "pk-1"), ("tenant_packs", "t-1"), ("tenant_full", "t-1")],
    )
    async def test_aggregates_pack_or_tenant_switches(
        self, key_class: KillSwitchClass, scope_key: str
    ) -> None:
        redis = _FakeRedis()
        redis.store[_switch_key(key_class, scope_key)] = _active_doc()
        conformer = SchedulerKillSwitchConformer(
            engine=KillSwitchEngine(redis_client=redis, cache_ttl_s=60)
        )
        assert await conformer.is_active(tenant_id="t-1", pack_id="pk-1") is True

    async def test_inactive_everywhere_is_not_active(self) -> None:
        conformer = SchedulerKillSwitchConformer(
            engine=KillSwitchEngine(redis_client=_FakeRedis(), cache_ttl_s=60)
        )
        assert await conformer.is_active(tenant_id="t-1", pack_id="pk-1") is False

    async def test_feature_class_not_consulted_wave_1(self) -> None:
        # Resolved flag 4: scheduler aggregation does NOT consult `feature`.
        redis = _FakeRedis()
        redis.store[_switch_key("feature", "t-1:subagent_spawn")] = _active_doc()
        redis.store[_switch_key("feature", "subagent_spawn")] = _active_doc()
        conformer = SchedulerKillSwitchConformer(
            engine=KillSwitchEngine(redis_client=redis, cache_ttl_s=60)
        )
        assert await conformer.is_active(tenant_id="t-1", pack_id="pk-1") is False


class TestGatewayCheck:
    async def test_precedence_tenant_full_beats_model_and_cloud(self) -> None:
        redis = _FakeRedis()
        redis.store[_switch_key("tenant_full", "t-1")] = _active_doc()
        redis.store[_switch_key("model", "tier1")] = _active_doc()
        redis.store[_switch_key("cloud_routing", "global")] = _active_doc()
        eng = KillSwitchEngine(redis_client=redis, cache_ttl_s=60)
        tripped = await eng.check_gateway(tenant_id="t-1", model_alias="tier1", external=True)
        assert tripped == "tenant_full"

    async def test_model_beats_cloud(self) -> None:
        redis = _FakeRedis()
        redis.store[_switch_key("model", "tier1")] = _active_doc()
        redis.store[_switch_key("cloud_routing", "global")] = _active_doc()
        eng = KillSwitchEngine(redis_client=redis, cache_ttl_s=60)
        tripped = await eng.check_gateway(tenant_id="t-1", model_alias="tier1", external=True)
        assert tripped == "model"

    async def test_model_keyed_by_litellm_alias(self) -> None:
        # Spec §11 item 5: the model scope_key IS the LiteLLM alias.
        redis = _FakeRedis()
        redis.store[_switch_key("model", "cognic-tier1-cloud")] = _active_doc()
        eng = KillSwitchEngine(redis_client=redis, cache_ttl_s=60)
        assert (
            await eng.check_gateway(
                tenant_id="t-1", model_alias="cognic-tier1-cloud", external=False
            )
        ) == "model"
        assert (
            await eng.check_gateway(tenant_id="t-1", model_alias="other-alias", external=False)
        ) is None

    async def test_cloud_routing_only_checked_when_external(self) -> None:
        redis = _FakeRedis()
        redis.store[_switch_key("cloud_routing", "global")] = _active_doc()
        eng = KillSwitchEngine(redis_client=redis, cache_ttl_s=60)
        assert await eng.check_gateway(tenant_id="t-1", model_alias="m", external=False) is None
        assert (
            await eng.check_gateway(tenant_id="t-1", model_alias="m", external=True)
        ) == "cloud_routing"

    async def test_tenant_none_skips_tenant_full(self) -> None:
        redis = _FakeRedis()
        redis.store[_switch_key("tenant_full", "t-1")] = _active_doc()
        eng = KillSwitchEngine(redis_client=redis, cache_ttl_s=60)
        assert await eng.check_gateway(tenant_id=None, model_alias="m", external=False) is None

    async def test_all_clear_returns_none(self) -> None:
        eng = KillSwitchEngine(redis_client=_FakeRedis(), cache_ttl_s=60)
        assert await eng.check_gateway(tenant_id="t-1", model_alias="m", external=True) is None


class TestMemoryConformer:
    async def test_or_semantics_seed_or_tenant_full(self) -> None:
        redis = _FakeRedis()
        seed = RedisMemoryWriteFreezeKillSwitch(redis_client=redis, cache_ttl_s=60)
        eng = KillSwitchEngine(redis_client=redis, cache_ttl_s=60)
        conformer = MemoryFreezeConformer(seed=seed, engine=eng)
        assert await conformer.is_write_frozen(tenant_id="t-1") is False
        redis.store[_switch_key("tenant_full", "t-1")] = _active_doc()
        assert await conformer.is_write_frozen(tenant_id="t-1") is True

    async def test_seed_freeze_alone_freezes(self) -> None:
        # Existing memory_write_freeze semantics preserved (F2 superset).
        redis = _FakeRedis()
        seed = RedisMemoryWriteFreezeKillSwitch(redis_client=redis, cache_ttl_s=60)
        await seed.set_write_freeze(
            tenant_id="t-1", frozen=True, actor_id="ops-1", reason="incident"
        )
        conformer = MemoryFreezeConformer(
            seed=seed, engine=KillSwitchEngine(redis_client=redis, cache_ttl_s=60)
        )
        assert await conformer.is_write_frozen(tenant_id="t-1") is True

    async def test_conforms_to_memory_seam_protocol(self) -> None:
        from cognic_agentos.core.memory._seams import MemoryKillSwitchInterrogator

        redis = _FakeRedis()
        conformer = MemoryFreezeConformer(
            seed=RedisMemoryWriteFreezeKillSwitch(redis_client=redis, cache_ttl_s=60),
            engine=KillSwitchEngine(redis_client=redis, cache_ttl_s=60),
        )
        assert isinstance(conformer, MemoryKillSwitchInterrogator)


class TestEnforcementStatusMap:
    def test_half1_live_vs_armed_partition(self) -> None:
        live = {k for k, v in ENFORCEMENT_STATUS_BY_CLASS.items() if v == "live"}
        armed = {k for k, v in ENFORCEMENT_STATUS_BY_CLASS.items() if v == "armed_no_live_consumer"}
        assert live == {"memory_write_freeze", "model", "cloud_routing", "tenant_full"}
        assert armed == {"pack", "tool", "tenant_packs", "feature"}

    def test_map_covers_every_class(self) -> None:
        import typing

        assert set(ENFORCEMENT_STATUS_BY_CLASS) == set(typing.get_args(KillSwitchClass))
