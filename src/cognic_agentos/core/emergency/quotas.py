"""Sprint 13.6b — ADR-018 token quota meter (decomposed atomic Redis counters).

CRITICAL CONTROL + stop-rule (core/ per AGENTS.md). "Atomic counter
reservation," NOT a single atomic transaction: ``INCRBY`` / ``DECRBY`` give
concurrency-safe admission + rollback (each caller checks its own
post-increment cumulative), but the bounded crash / partial-increment window
between counter mutation and reservation-record persistence is quota-DENYING
(never opening) and self-heals at the 48h key TTL. Conforms structurally to
``core.scheduler._seams.QuotaInterrogator``. NO shared ``db/adapters`` change —
declares its own consumer-owned Redis seam (the ``kill_switches``
``_AsyncRedisKVLike`` precedent); the real ``redis.asyncio.Redis`` satisfies it.

Gateway vs scheduler (precision lock 2): the scheduler has ``task_id`` +
``pack_id`` + ``estimated_tokens`` → TRUE per-task reservation via
``would_admit`` / ``release_reservation``. The gateway has neither pack identity
nor a pre-dispatch completion-token count → a coarse tenant-aggregate
already-exhausted gate (``check_gateway_admit``) + a post-completion actuals
``INCRBY`` (``record_actuals``).
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final, Protocol, runtime_checkable

if TYPE_CHECKING:
    from cognic_agentos.core.config import Settings
    from cognic_agentos.core.config_overlay.resolver import TenantConfigResolver

logger = logging.getLogger(__name__)

#: Counter + reservation-record TTL. > the calendar-day window so a day-boundary
#: read still sees yesterday's reservations until they release or expire; the
#: deny-safe leaks self-heal within this window.
_RESERVATION_TTL_S: Final[int] = 48 * 3600
#: Soft-threshold (ADR-018 §"warn at 80%") — Wave-1 structured-log warn ONLY.
_SOFT_THRESHOLD: Final[float] = 0.8


@runtime_checkable
class _AsyncRedisQuotaLike(Protocol):
    """Consumer-owned Redis seam (the ``kill_switches._AsyncRedisKVLike``
    precedent). The real ``redis.asyncio.Redis`` satisfies all six natively;
    ``getdel`` is Redis 6.2+ (within the bundled-Redis floor). Declaring our
    OWN Protocol means NO change to the shared ``db/adapters`` get/set surface."""

    async def get(self, key: str) -> Any: ...
    async def set(self, key: str, value: Any, **kwargs: Any) -> Any: ...
    async def incrby(self, key: str, amount: int) -> int: ...
    async def decrby(self, key: str, amount: int) -> int: ...
    async def getdel(self, key: str) -> Any: ...
    async def expire(self, key: str, seconds: int) -> Any: ...


class QuotaReservationConflict(RuntimeError):
    """A reused ``task_id`` arrived with DIFFERENT reservation params (tenant /
    pack / tokens) than the held reservation — a caller-contract violation,
    never a quota outcome. Fail-loud so the bug surfaces (the scheduler mints a
    fresh task_id per submit, so this never fires in practice)."""


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _window(clock: Callable[[], datetime]) -> str:
    return clock().strftime("%Y%m%d")


def _reserved_tenant_key(tenant_id: str, window: str) -> str:
    return f"cognic:quota:reserved:tokens:{tenant_id}:{window}"


def _reserved_pack_key(tenant_id: str, pack_id: str, window: str) -> str:
    return f"cognic:quota:reserved:tokens:{tenant_id}:{pack_id}:{window}"


def _actual_tenant_key(tenant_id: str, window: str) -> str:
    return f"cognic:quota:actual:tokens:{tenant_id}:{window}"


def _reservation_key(task_id: uuid.UUID) -> str:
    return f"cognic:quota:reservation:{task_id}"


class QuotaEngine:
    """The ADR-018 token meter. Constructed over ``adapters.cache.client`` at
    the composition root; the ``resolver`` (ADR-023) resolves tighten-only
    per-tenant ceilings, falling back to the kernel ``Settings`` defaults."""

    def __init__(
        self,
        *,
        redis_client: _AsyncRedisQuotaLike,
        settings: Settings,
        resolver: TenantConfigResolver | None = None,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._redis = redis_client
        self._settings = settings
        self._resolver = resolver
        self._clock = clock

    async def _tenant_limit(self, tenant_id: str) -> int:
        if self._resolver is not None:
            return int(await self._resolver.effective("quota_tokens_per_tenant_per_day", tenant_id))
        return int(self._settings.quota_tokens_per_tenant_per_day)

    async def _pack_limit(self, tenant_id: str) -> int:
        if self._resolver is not None:
            return int(await self._resolver.effective("quota_tokens_per_pack_per_day", tenant_id))
        return int(self._settings.quota_tokens_per_pack_per_day)

    async def would_admit(
        self, *, task_id: uuid.UUID, tenant_id: str, pack_id: str, estimated_tokens: int
    ) -> bool:
        """The scheduler-plane true reservation (satisfies QuotaInterrogator).
        Returns True iff the reservation was made. ``INCRBY``-first (cumulative
        return) → check ``actuals + tenant_reserved ≤ tenant_limit`` AND
        ``pack_reserved ≤ pack_limit`` → rollback ``DECRBY`` on over-limit."""
        window = _window(self._clock)
        rkey = _reservation_key(task_id)
        try:
            # 1. duplicate-task_id contract (spec §3.3 step 1)
            existing = await self._redis.get(rkey)
            if existing is not None:
                rec = json.loads(existing if isinstance(existing, str) else existing.decode())
                if (rec["tenant_id"], rec["pack_id"], rec["tokens"]) == (
                    tenant_id,
                    pack_id,
                    estimated_tokens,
                ):
                    return True  # idempotent — the reservation already holds
                raise QuotaReservationConflict(
                    f"task_id {task_id} re-reserved with a different shape: "
                    f"held={rec} new=({tenant_id},{pack_id},{estimated_tokens})"
                )
            # 2. INCRBY reserved (tenant + pack); INCRBY returns the cumulative
            tkey = _reserved_tenant_key(tenant_id, window)
            pkey = _reserved_pack_key(tenant_id, pack_id, window)
            tenant_reserved = await self._redis.incrby(tkey, estimated_tokens)
            await self._redis.expire(tkey, _RESERVATION_TTL_S)
            pack_reserved = await self._redis.incrby(pkey, estimated_tokens)
            await self._redis.expire(pkey, _RESERVATION_TTL_S)
            # 3. read actuals + 4. resolve limits + check
            actuals = int(await self._redis.get(_actual_tenant_key(tenant_id, window)) or 0)
            tenant_limit = await self._tenant_limit(tenant_id)
            pack_limit = await self._pack_limit(tenant_id)
            self._maybe_soft_warn(tenant_id, actuals + tenant_reserved, tenant_limit)
            if actuals + tenant_reserved > tenant_limit or pack_reserved > pack_limit:
                await self._redis.decrby(tkey, estimated_tokens)  # rollback
                await self._redis.decrby(pkey, estimated_tokens)
                return False
            await self._redis.set(
                rkey,
                json.dumps(
                    {
                        "tenant_id": tenant_id,
                        "pack_id": pack_id,
                        "tokens": estimated_tokens,
                        "window": window,
                    }
                ),
            )
            await self._redis.expire(rkey, _RESERVATION_TTL_S)
            return True
        except QuotaReservationConflict:
            # Symmetric exception ordering: domain-specific BEFORE generic.
            raise
        except Exception:
            # Any Redis error (incl. a partial increment) → refuse. The leaked
            # counter is quota-DENYING (never opening) + TTL-heals; NO
            # best-effort rollback against an unreachable Redis (it would itself
            # fail, and the deny-safe leak is the acceptable outcome). Spec §3.5.
            logger.warning(
                "quota.would_admit_redis_error",
                extra={"tenant_id": tenant_id, "task_id": str(task_id)},
            )
            return False

    async def release_reservation(self, task_id: uuid.UUID) -> None:
        """Idempotent release (QuotaInterrogator contract). GETDEL-first so the
        crash window (between the atomic get-and-delete and the DECRBYs) leaks
        the counter HIGH = deny-safe; DECRBY-first would risk a double-release
        double-decrement. Never raises on a Redis-present path."""
        try:
            raw = await self._redis.getdel(_reservation_key(task_id))
            if raw is None:
                return  # idempotent no-op (terminal-state paths may fire twice)
            rec = json.loads(raw if isinstance(raw, str) else raw.decode())
            window = rec["window"]
            await self._redis.decrby(_reserved_tenant_key(rec["tenant_id"], window), rec["tokens"])
            await self._redis.decrby(
                _reserved_pack_key(rec["tenant_id"], rec["pack_id"], window), rec["tokens"]
            )
        except Exception:
            # Deny-safe: a leaked-high reserved counter TTL-heals; never raise.
            logger.warning("quota.release_redis_error", extra={"task_id": str(task_id)})

    async def record_actuals(self, *, tenant_id: str, tokens: int) -> None:
        """Gateway-plane post-completion increment of the tenant actuals
        counter. Best-effort at the call site (metering must NOT fail a
        delivered completion)."""
        if tokens <= 0:
            return
        window = _window(self._clock)
        key = _actual_tenant_key(tenant_id, window)
        await self._redis.incrby(key, tokens)
        await self._redis.expire(key, _RESERVATION_TTL_S)

    async def check_gateway_admit(self, *, tenant_id: str) -> bool:
        """Gateway tenant-aggregate already-exhausted gate (precision lock 2):
        True = admit. The gateway has no pre-dispatch token count, so this is a
        coarse ``actuals + reserved < tenant_limit`` check, NOT a per-call
        reservation. Redis error → fail-closed refuse (False)."""
        window = _window(self._clock)
        try:
            actuals = int(await self._redis.get(_actual_tenant_key(tenant_id, window)) or 0)
            reserved = int(await self._redis.get(_reserved_tenant_key(tenant_id, window)) or 0)
        except Exception:
            logger.warning("quota.check_gateway_redis_error", extra={"tenant_id": tenant_id})
            return False
        limit = await self._tenant_limit(tenant_id)
        self._maybe_soft_warn(tenant_id, actuals + reserved, limit)
        return (actuals + reserved) < limit

    def _maybe_soft_warn(self, tenant_id: str, usage: int, limit: int) -> None:
        if limit > 0 and usage / limit >= _SOFT_THRESHOLD:
            logger.warning(
                "quota.soft_threshold_approaching",
                extra={"tenant_id": tenant_id, "usage": usage, "limit": limit},
            )

    async def usage_view(self, *, tenant_id: str) -> dict[str, int]:
        """Read-only portal view (the cache-for-display exception — never used
        for admission)."""
        window = _window(self._clock)
        actuals = int(await self._redis.get(_actual_tenant_key(tenant_id, window)) or 0)
        reserved = int(await self._redis.get(_reserved_tenant_key(tenant_id, window)) or 0)
        return {
            "tenant_limit": await self._tenant_limit(tenant_id),
            "actuals": actuals,
            "reserved": reserved,
        }


__all__ = (
    "QuotaEngine",
    "QuotaReservationConflict",
    "_AsyncRedisQuotaLike",
    "_actual_tenant_key",
    "_reservation_key",
    "_reserved_pack_key",
    "_reserved_tenant_key",
)
