"""Redis-backed kill switches (ADR-018) — the 11.5b seed + the 13.6 matrix engine.

CRITICAL CONTROL + stop-rule (core/ per AGENTS.md). The Sprint-11.5b
``RedisMemoryWriteFreezeKillSwitch`` seed (UNTOUCHED at 13.6 per spec lock F2)
conforms structurally to ``core.memory._seams.MemoryKillSwitchInterrogator``
so it drops into MemoryGate construction with ZERO gate-code change. Its Redis
key schema was FROZEN for the full matrix at 11.5b, and Sprint 13.6's
``KillSwitchEngine`` below generalizes exactly that scheme
(``cognic:killswitch:<class>:<scope_key>``) across the 8 ADR-018 classes —
no migration, no behavioral break for memory writes.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Final, Literal, Protocol, runtime_checkable

_KEY_PREFIX = "cognic:killswitch:memory_write_freeze:"


def _write_freeze_key(tenant_id: str) -> str:
    return f"{_KEY_PREFIX}{tenant_id}"


@runtime_checkable
class _AsyncRedisKVLike(Protocol):
    async def get(self, key: str) -> Any: ...
    async def set(self, key: str, value: Any, **kwargs: Any) -> Any: ...


def _utcnow() -> datetime:
    return datetime.now(UTC)


class RedisMemoryWriteFreezeKillSwitch:
    """Per-tenant memory.write-freeze probe with fail-closed cached grace.

    is_write_frozen(): read Redis -> parse {frozen, updated_at, actor_id, reason}
    -> refresh the per-tenant last-known-good cache -> return frozen. On a Redis
    error: serve the cached value while its age <= cache_ttl_s; otherwise (stale
    or no cache) FAIL CLOSED (return True). A malformed value also fails closed.
    """

    def __init__(
        self,
        *,
        redis_client: _AsyncRedisKVLike,
        cache_ttl_s: int,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._redis = redis_client
        self._cache_ttl_s = cache_ttl_s
        self._clock = clock
        self._cache: dict[str, tuple[bool, datetime]] = {}  # tenant_id -> (frozen, observed_at)

    async def is_write_frozen(self, *, tenant_id: str) -> bool:
        try:
            raw = await self._redis.get(_write_freeze_key(tenant_id))
        except Exception:
            # Redis unreachable: cached last-known-good while fresh, else fail-closed.
            cached = self._cache.get(tenant_id)
            if cached is not None:
                frozen, observed_at = cached
                if (self._clock() - observed_at).total_seconds() <= self._cache_ttl_s:
                    return frozen
            return True
        if raw is None:
            self._cache[tenant_id] = (False, self._clock())  # absent key => not frozen
            return False
        try:
            doc = json.loads(raw if isinstance(raw, str) else raw.decode())
            frozen = doc["frozen"]
            _custody = (doc["updated_at"], doc["actor_id"], doc["reason"])  # ALL required
            if not isinstance(frozen, bool):
                # non-bool `frozen` is malformed; do NOT bool()-coerce (0 => fail-open)
                raise ValueError("frozen must be a JSON bool")
        except (ValueError, TypeError, KeyError, AttributeError):
            # Malformed/partial state POISONS the cache fail-closed: cache (True, now)
            # so a later Redis outage within TTL serves frozen, NOT a stale unfrozen
            # last-known-good. A valid Redis read supersedes it. (Cross-call blocker —
            # malformed is NOT a legit value and must invalidate the prior grace.)
            self._cache[tenant_id] = (True, self._clock())
            return True  # malformed / partial => fail-closed
        self._cache[tenant_id] = (frozen, self._clock())
        return frozen

    async def set_write_freeze(
        self, *, tenant_id: str, frozen: bool, actor_id: str, reason: str
    ) -> None:
        """Ops/portal write surface (the portal RBAC gate is 11.5c). Writes the
        frozen-state JSON; the read path + cache pick it up on the next probe."""
        payload = json.dumps(
            {
                "frozen": frozen,
                "updated_at": self._clock().isoformat(),
                "actor_id": actor_id,
                "reason": reason,
            }
        )
        await self._redis.set(_write_freeze_key(tenant_id), payload)


# --- Sprint 13.6 (ADR-018) — the full kill-switch matrix engine --------------

#: The 8 ADR-018 switch classes = the 11.5b seed + the 7 ADR table classes
#: (spec lock F2).
KillSwitchClass = Literal[
    "memory_write_freeze",
    "pack",
    "tool",
    "model",
    "tenant_packs",
    "tenant_full",
    "cloud_routing",
    "feature",
]

#: ADR-018 §95 — the mandatory categorised flip/revert reason (spec lock F6).
KillSwitchCategory = Literal[
    "incident_response",
    "cost_control",
    "security_disclosure",
    "regulator_directive",
    "vendor_outage",
]

EnforcementStatus = Literal["live", "armed_no_live_consumer"]

#: Half-1 honesty map (spec review patch 6 + resolved flags 3/4). pack /
#: tenant_packs flip to "live" at the composition-root sprint (scheduler DI
#: binding); tool / feature flip when the MCP / sandbox / subagent consumers
#: wire. Carried on every flip chain payload + the portal list response so an
#: operator cannot mistake an armed switch for an enforced one.
ENFORCEMENT_STATUS_BY_CLASS: Final[dict[KillSwitchClass, EnforcementStatus]] = {
    "memory_write_freeze": "live",
    "model": "live",
    "cloud_routing": "live",
    "tenant_full": "live",
    "pack": "armed_no_live_consumer",
    "tool": "armed_no_live_consumer",
    "tenant_packs": "armed_no_live_consumer",
    "feature": "armed_no_live_consumer",
}

#: Closed Wave-1 feature-name vocabulary (resolved flag 4) — the ADR-018 §42
#: example features; enforcement checks land with their consumers.
_FEATURE_NAMES: Final[frozenset[str]] = frozenset({"subagent_spawn", "sandbox_create", "mcp_stdio"})


def _switch_key(class_: KillSwitchClass, scope_key: str) -> str:
    """Review patch 2: ``cognic:killswitch:<class>:<scope_key>`` — bare scope
    keys, no class-name duplication. The seed key conforms (class =
    memory_write_freeze, scope_key = tenant_id)."""
    return f"cognic:killswitch:{class_}:{scope_key}"


class KillSwitchEngine:
    """8-class matrix over the seed's Redis + fail-closed-cache semantics.

    Read primitive ``is_class_active``: per-(class, scope_key) last-known-good
    cache with the SAME doctrine as the seed — on a Redis error serve the
    cached value while its age <= cache_ttl_s, otherwise FAIL CLOSED (treat as
    ACTIVE, i.e. refuse); a malformed value poisons the cache fail-closed so a
    later outage within TTL cannot resurrect a stale inactive grace. The write
    side (flip / revert with the brake-before-evidence doctrine) lands at T2.
    """

    def __init__(
        self,
        *,
        redis_client: _AsyncRedisKVLike,
        cache_ttl_s: int,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._redis = redis_client
        self._cache_ttl_s = cache_ttl_s
        self._clock = clock
        self._cache: dict[str, tuple[bool, datetime]] = {}  # full key -> (active, observed_at)

    async def is_class_active(self, *, class_: KillSwitchClass, scope_key: str) -> bool:
        key = _switch_key(class_, scope_key)
        try:
            raw = await self._redis.get(key)
        except Exception:
            cached = self._cache.get(key)
            if cached is not None:
                active, observed_at = cached
                if (self._clock() - observed_at).total_seconds() <= self._cache_ttl_s:
                    return active
            return True  # FAIL CLOSED past cache (ADR-018 §48)
        if raw is None:
            self._cache[key] = (False, self._clock())  # absent key => inactive
            return False
        try:
            doc = json.loads(raw if isinstance(raw, str) else raw.decode())
            active = doc["active"]
            _custody = (doc["updated_at"], doc["actor_id"], doc["reason"])  # ALL required
            if not isinstance(active, bool):
                # non-bool `active` is malformed; do NOT bool()-coerce (0 => fail-open)
                raise ValueError("active must be a JSON bool")
        except (ValueError, TypeError, KeyError, AttributeError):
            # Malformed/partial state POISONS the cache fail-closed (seed doctrine).
            self._cache[key] = (True, self._clock())
            return True
        self._cache[key] = (active, self._clock())
        return active

    async def check_gateway(
        self, *, tenant_id: str | None, model_alias: str, external: bool
    ) -> KillSwitchClass | None:
        """F4 gateway probe. Deterministic precedence ``tenant_full`` ->
        ``model`` -> ``cloud_routing``; returns the FIRST tripped class for
        the refusal payload, ``None`` when clear. The ``model`` scope_key is
        the LITELLM ALIAS (alias-only doctrine per spec §11 item 5 — no
        hardcoded checkpoint names; registry-``model_id``-keyed kills are a
        registry-integration follow-up). ``cloud_routing`` is consulted only
        for ``external`` calls; ``tenant_full`` is skipped when the call has
        no tenant binding."""
        if tenant_id is not None and await self.is_class_active(
            class_="tenant_full", scope_key=tenant_id
        ):
            return "tenant_full"
        if await self.is_class_active(class_="model", scope_key=model_alias):
            return "model"
        if external and await self.is_class_active(class_="cloud_routing", scope_key="global"):
            return "cloud_routing"
        return None


class SchedulerKillSwitchConformer:
    """Thin structural conformer to ``core.scheduler._seams.KillSwitchInterrogator``
    (spec lock F3 aggregation: ``pack`` OR ``tenant_packs`` OR ``tenant_full``;
    ``feature`` NOT consulted Wave-1 per resolved flag 4). The scheduler stays
    import-free — this object is constructed at the composition root and
    passed via DI; production binding rides the composition-root sprint."""

    def __init__(self, *, engine: KillSwitchEngine) -> None:
        self._engine = engine

    async def is_active(self, *, tenant_id: str, pack_id: str) -> bool:
        if await self._engine.is_class_active(class_="pack", scope_key=pack_id):
            return True
        if await self._engine.is_class_active(class_="tenant_packs", scope_key=tenant_id):
            return True
        return await self._engine.is_class_active(class_="tenant_full", scope_key=tenant_id)


class MemoryFreezeConformer:
    """Review patch 5: ``MemoryKillSwitchInterrogator``-shaped strict superset —
    seed ``memory_write_freeze`` OR ``tenant_full``. The memory gate is
    code-untouched (it consumes the Protocol shape); ``build_runtime`` swaps
    this in at T7. Existing freeze semantics are unchanged; ``tenant_full``
    now also freezes memory writes (the half-1 LIVE surface per resolved
    flag 3)."""

    def __init__(self, *, seed: RedisMemoryWriteFreezeKillSwitch, engine: KillSwitchEngine) -> None:
        self._seed = seed
        self._engine = engine

    async def is_write_frozen(self, *, tenant_id: str) -> bool:
        if await self._seed.is_write_frozen(tenant_id=tenant_id):
            return True
        return await self._engine.is_class_active(class_="tenant_full", scope_key=tenant_id)


__all__ = (
    "ENFORCEMENT_STATUS_BY_CLASS",
    "EnforcementStatus",
    "KillSwitchCategory",
    "KillSwitchClass",
    "KillSwitchEngine",
    "MemoryFreezeConformer",
    "RedisMemoryWriteFreezeKillSwitch",
    "SchedulerKillSwitchConformer",
    "_switch_key",
    "_write_freeze_key",
)
