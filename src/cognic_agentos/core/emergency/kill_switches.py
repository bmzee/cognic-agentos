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

import dataclasses
import json
import logging
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Final, Literal, Protocol, runtime_checkable

from cognic_agentos.core.decision_history import DecisionRecord

logger = logging.getLogger(__name__)

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


def _state_field(class_: KillSwitchClass) -> str:
    """The seed class persists ``frozen`` (its FROZEN 11.5b schema, F2); every
    other class persists ``active``. Engine reads + writes are class-aware so
    the seed reader and the engine agree on the same Redis document."""
    return "frozen" if class_ == "memory_write_freeze" else "active"


def _tenant_for(class_: KillSwitchClass, scope_key: str) -> str | None:
    """Chain-row tenant attribution: tenant-scoped classes carry the tenant in
    the scope_key; a per-tenant feature key (``<tenant_id>:<name>``) carries it
    as the first segment; global classes attribute to no tenant."""
    if class_ in _TENANT_SCOPED_CLASSES:
        return scope_key
    if class_ == "feature" and ":" in scope_key:
        return scope_key.split(":", 1)[0]
    return None


_FLIP_REQUEST_ID_PREFIX: Final[str] = "emrg-flip-"
_EMERGENCY_ISO_CONTROLS: Final[tuple[str, ...]] = ("ISO42001.A.6.2.5", "ISO42001.A.9.2")
_TENANT_SCOPED_CLASSES: Final[frozenset[str]] = frozenset(
    {"memory_write_freeze", "tenant_packs", "tenant_full"}
)


@runtime_checkable
class _DecisionAppendLike(Protocol):
    """Narrow consumer-owned append seam — ``DecisionHistoryStore`` conforms
    structurally; tests pass recording fakes without nominal-type friction."""

    async def append(self, record: DecisionRecord) -> tuple[uuid.UUID, bytes]: ...


@dataclasses.dataclass(frozen=True, slots=True)
class FlipResult:
    """Outcome of a flip/revert. ``evidence_degraded=True`` means the brake IS
    in effect (Redis written / already in state) but the chain row failed —
    the portal surfaces ``kill_switch_live_evidence_degraded`` and the
    operator retries (idempotent re-flip appends the missing row)."""

    active: bool
    evidence_degraded: bool
    chain_record_id: uuid.UUID | None


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
        decision_history: _DecisionAppendLike | None = None,
    ) -> None:
        self._redis = redis_client
        self._cache_ttl_s = cache_ttl_s
        self._clock = clock
        self._decision_history = decision_history
        self._cache: dict[str, tuple[bool, datetime]] = {}  # full key -> (active, observed_at)

    async def is_class_active(self, *, class_: KillSwitchClass, scope_key: str) -> bool:
        key = _switch_key(class_, scope_key)
        field = _state_field(class_)
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
            active = doc[field]
            _custody = (doc["updated_at"], doc["actor_id"], doc["reason"])  # ALL required
            if not isinstance(active, bool):
                # non-bool state is malformed; do NOT bool()-coerce (0 => fail-open)
                raise ValueError(f"{field} must be a JSON bool")
        except (ValueError, TypeError, KeyError, AttributeError):
            # Malformed/partial state POISONS the cache fail-closed (seed doctrine).
            self._cache[key] = (True, self._clock())
            return True
        self._cache[key] = (active, self._clock())
        return active

    async def flip(
        self,
        *,
        class_: KillSwitchClass,
        scope_key: str,
        actor_id: str,
        reason: str,
        category: KillSwitchCategory,
    ) -> FlipResult:
        """Activate a switch — review patch 3 brake-before-evidence (see
        :meth:`_mutate`)."""
        return await self._mutate(
            class_=class_,
            scope_key=scope_key,
            actor_id=actor_id,
            reason=reason,
            category=category,
            active=True,
            decision_type="emergency.kill_switch_flipped",
        )

    async def revert(
        self,
        *,
        class_: KillSwitchClass,
        scope_key: str,
        actor_id: str,
        reason: str,
        category: KillSwitchCategory,
    ) -> FlipResult:
        """Deactivate a switch — same doctrine, ``emergency.kill_switch_reverted``."""
        return await self._mutate(
            class_=class_,
            scope_key=scope_key,
            actor_id=actor_id,
            reason=reason,
            category=category,
            active=False,
            decision_type="emergency.kill_switch_reverted",
        )

    async def _mutate(
        self,
        *,
        class_: KillSwitchClass,
        scope_key: str,
        actor_id: str,
        reason: str,
        category: KillSwitchCategory,
        active: bool,
        decision_type: str,
    ) -> FlipResult:
        """Review patch 3 — the brake-before-evidence doctrine. Redis write
        FIRST (the brake takes effect even if evidence fails), THEN the chain
        row. Evidence failure after a successful Redis write leaves the switch
        LIVE (it must never resurrect a killed path), logs loud, and reports
        ``evidence_degraded=True`` so the portal returns the closed-enum
        ``kill_switch_live_evidence_degraded`` error. Re-flipping an
        already-in-state switch performs NO Redis state change but appends the
        evidence row — the chain converges on retry."""
        if self._decision_history is None:
            raise RuntimeError(
                "kill_switch_engine_requires_decision_history_for_writes: construct "
                "KillSwitchEngine(decision_history=...) for flip/revert"
            )
        if class_ == "feature":
            name = scope_key.rsplit(":", 1)[-1]
            if name not in _FEATURE_NAMES:
                raise ValueError(
                    f"unknown feature name {name!r}; closed Wave-1 feature vocabulary: "
                    f"{sorted(_FEATURE_NAMES)}"
                )
        key = _switch_key(class_, scope_key)
        current = await self.is_class_active(class_=class_, scope_key=scope_key)
        if current != active:
            doc = json.dumps(
                {
                    _state_field(class_): active,
                    "updated_at": self._clock().isoformat(),
                    "actor_id": actor_id,
                    "reason": reason,
                }
            )
            await self._redis.set(key, doc)  # THE BRAKE — unconditional, before evidence
            self._cache[key] = (active, self._clock())
        evidence_degraded = False
        chain_record_id: uuid.UUID | None = None
        try:
            record_id, _new_hash = await self._decision_history.append(
                DecisionRecord(
                    decision_type=decision_type,
                    request_id=f"{_FLIP_REQUEST_ID_PREFIX}{uuid.uuid4().hex}",
                    payload={
                        "class": class_,
                        "scope_key": scope_key,
                        "category": category,
                        "reason": reason,
                        "active": active,
                        "enforcement_status": ENFORCEMENT_STATUS_BY_CLASS[class_],
                    },
                    actor_id=actor_id,
                    tenant_id=_tenant_for(class_, scope_key),
                    iso_controls=_EMERGENCY_ISO_CONTROLS,
                )
            )
            chain_record_id = record_id
        except Exception:
            logger.exception(
                "emergency.kill_switch_evidence_degraded class=%s scope_key=%s active=%s "
                "actor_id=%s — the switch state IS in effect; retry the flip to converge "
                "the evidence chain",
                class_,
                scope_key,
                active,
                actor_id,
            )
            evidence_degraded = True
        return FlipResult(
            active=active, evidence_degraded=evidence_degraded, chain_record_id=chain_record_id
        )

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
    "FlipResult",
    "KillSwitchCategory",
    "KillSwitchClass",
    "KillSwitchEngine",
    "MemoryFreezeConformer",
    "RedisMemoryWriteFreezeKillSwitch",
    "SchedulerKillSwitchConformer",
    "_switch_key",
    "_write_freeze_key",
)

# Build-time pin: emrg-flip- (10) + uuid4 hex (32) = 42 <= the 64-char
# decision_history.request_id column cap (established module-foot pattern).
assert len(_FLIP_REQUEST_ID_PREFIX) + 32 <= 64
