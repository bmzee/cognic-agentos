"""Sprint 8A T9 — SandboxWarmPool per spec §11.

Critical-controls module per spec §17.

The warm-pool's job is to amortise sandbox-create latency by pre-creating
sessions for known (tenant_id, policy, pack_context) triples, so that a
tool call arriving at runtime can checkout a ready session in <50ms
instead of paying the 800-2000ms cold-create cost. The pool MUST NEVER
hand a session admitted for pack A to a request for pack B — even when
policy matches — because admission decisions can differ across pack
contexts (different risk_tier, different supply-chain attestations,
different artifact digest under cosign trust-gate pinning per ADR-016).
Similarly, the pool MUST NEVER hand a session admitted under tenant A's
trust roots / allow-lists / per-tenant max policy to a request from
tenant B (R1 P1 reviewer fix — pool key is tenant-scoped).

Pool key derivation (load-bearing for admission integrity per spec §11
lines 763-770 + R1 P1 tenant-scope extension):

    sha256(
        canonical_bytes({
            "tenant_id": str,
            "policy":    dataclasses.asdict(SandboxPolicy),
            "pack":      {5 admission-relevant PackAdmissionContext fields},
        })
    )

The 5 pack-admission-relevant fields are ``pack_id`` +
``pack_artifact_digest`` (cosign-verified sha256, ADR-016
trust-gate-pinned immutable identity) + ``risk_tier`` +
``declares_dynamic_install`` + ``profile``. ``pack_version`` is
INTENTIONALLY NOT in the key — it is human-mutable, and
``pack_artifact_digest`` is the load-bearing trust identity (per spec
§11 line 767 round-3-third-follow-on amendment).

Per-key serialisation: each pool key has its own ``asyncio.Lock`` so
concurrent checkouts + releases against the same key are serialised
(prevents two callers consuming the same deque slot via interleaved
async scheduling). The lock map itself is guarded by ``_locks_lock`` to
make lazy lock creation race-safe. ``drain()`` acquires each per-key
lock during snapshot so a concurrent precreate / release_or_destroy
that won the lock-race observes ``_drained == True`` on re-check (R1
P1 reviewer fix — closes the drained-pool-repopulation race).

Idle TTL semantics (R2 P2 reviewer fix): expiry is measured as
**time-since-deposit** (idle in pool), NOT time-since-creation. Each
deposited session is wrapped in a ``_PoolEntry`` carrying its
``deposited_at`` timestamp; checkout's eviction scan compares
``now - entry.deposited_at`` against ``idle_ttl_s``. A long-running
session that is released back to the pool restarts the idle clock; it
is only evicted if it sits unconsumed for ``idle_ttl_s`` thereafter.

Service actor (R2 P1 reviewer fix): the replenisher path calls
``backend.create(..., actor=service_actor, ...)`` with an
``Actor`` value supplied at construction time. The harness wires a
real ``actor_type='service'`` Actor at T10 integration time; tests
inject either a real Actor or a MagicMock. The pool itself does not
synthesise an identity — the harness owns service-actor minting per
the kernel's ADR-008 actor-binder contract.

Spec §11 vs plan reconciliation (resolved 2026-05-17 at T9 execute
time): spec line 723 declared ``checkout(policy_key: str, *, ...)``
but the pool-key derivation formula on line 763 requires the full
``SandboxPolicy`` to compute ``canonical_bytes(policy)``. The plan's
test recipe uses ``checkout(policy=SandboxPolicy, *, ...)`` which is
internally consistent with the derivation. T9 implements the plan
shape (full ``SandboxPolicy`` positional arg) — the spec's
``policy_key: str`` was a self-inconsistency in the spec body and the
derivation formula is the load-bearing constraint.

NOT a wire-protocol surface (in-process Python API only). The audit
chain row's ``payload.pool_key`` carries the human-readable
``SandboxPolicy.warm_pool_key`` string for examiner readability (per
spec §11 line 771) — the cryptographic pool key bytes are internal.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
from collections import deque
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.sandbox.audit import emit_sandbox_event
from cognic_agentos.sandbox.policy import PackAdmissionContext, SandboxPolicy
from cognic_agentos.sandbox.protocol import (
    SandboxBackend,
    SandboxLifecycleEvent,
    SandboxLifecycleRefused,
    SandboxSession,
)

_WARM_POOL_EVENTS: tuple[SandboxLifecycleEvent, ...] = (
    "sandbox.warm_pool.precreated",
    "sandbox.warm_pool.checked_out",
    "sandbox.warm_pool.drained",
)

if TYPE_CHECKING:
    from cognic_agentos.core.audit import AuditStore
    from cognic_agentos.core.decision_history import DecisionHistoryStore
    from cognic_agentos.portal.rbac.actor import Actor


@dataclasses.dataclass(frozen=True, slots=True)
class _PoolEntry:
    """Wrapper carrying a deposited session + its deposit timestamp.

    The deposit timestamp drives idle-TTL expiry at checkout — measuring
    time-IDLE-IN-POOL, NOT time-since-session-creation (R2 P2 reviewer
    fix). A long-running session that is released back to the pool
    carries a fresh ``deposited_at`` so it is not immediately evicted
    on the next checkout despite an old ``session.created_at``.
    """

    session: SandboxSession
    deposited_at: datetime


# ---------------------------------------------------------------------------
# Pool-key derivation (pure-functional)
# ---------------------------------------------------------------------------


def _pack_context_admission_subset(
    pack_context: PackAdmissionContext,
) -> dict[str, object]:
    """Project a PackAdmissionContext onto the 5 admission-relevant
    fields per spec §11 line 763. ``pack_version`` is intentionally
    omitted (human-mutable; not load-bearing for admission integrity
    per spec §11 line 767)."""

    return {
        "pack_id": pack_context.pack_id,
        "pack_artifact_digest": pack_context.pack_artifact_digest,
        "risk_tier": pack_context.risk_tier,
        "declares_dynamic_install": pack_context.declares_dynamic_install,
        "profile": pack_context.profile,
    }


def _tuples_to_lists(obj: object) -> object:
    """Recursively convert tuples to lists so the result is safe to
    pass to ``canonical_bytes``. ``canonical_bytes`` rejects tuples by
    design (chain-row list/tuple ambiguity bug class per
    ``core/canonical.py:170-178``); this helper coerces the pool-key
    INPUT — the pool key is in-process only (NEVER on the chain wire),
    so the conversion is safe + necessary.

    Used only by ``_derive_pool_key``; the chain-row payload assembly
    path at ``_emit_warm_event`` uses plain dicts + scalars + the
    helper's int output, which canonical_bytes accepts directly."""

    if isinstance(obj, dict):
        return {k: _tuples_to_lists(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_tuples_to_lists(v) for v in obj]
    return obj


def _derive_pool_key(
    policy: SandboxPolicy,
    pack_context: PackAdmissionContext,
    tenant_id: str,
) -> bytes:
    """SHA-256 over the canonical-bytes serialisation of the joined
    tenant_id + policy + admission-relevant pack_context dict.
    Deterministic, collision-resistant, 32-byte key suitable for use
    as a dict index.

    ``tenant_id`` is part of the key per R1 P1 reviewer fix: admission
    decisions, image trust roots, per-tenant max-policy caps, and
    egress allow-lists ARE all tenant-scoped, so a warm session
    admitted under tenant A's trust posture MUST NOT serve a request
    from tenant B even when policy + pack_context are byte-identical.
    Pinned by ``test_checkout_under_different_tenant_id_returns_none``.

    Two distinct (tenant_id, policy, pack_context) triples differing
    in ANY load-bearing field produce different keys; differing only
    in ``pack_version`` produces the SAME key per spec §11 line 767.

    ``dataclasses.asdict`` preserves tuple-typed fields as tuples (it
    only converts NESTED dataclasses to dicts). The
    ``_tuples_to_lists`` coercion exists because
    ``canonical_bytes`` refuses tuples per its defensive design
    (list/tuple ambiguity bug class for chain rows). The pool key is
    in-process only — never on the chain wire — so the coercion is
    safe.
    """

    serialised = canonical_bytes(
        _tuples_to_lists(
            {
                "tenant_id": tenant_id,
                "policy": dataclasses.asdict(policy),
                "pack": _pack_context_admission_subset(pack_context),
            }
        )
    )
    return hashlib.sha256(serialised).digest()


# ---------------------------------------------------------------------------
# SandboxWarmPool
# ---------------------------------------------------------------------------


class SandboxWarmPool:
    """Per-backend pool of pre-created sandbox sessions keyed by
    ``(tenant_id, canonical_bytes(policy), 5 PackAdmissionContext
    admission fields)``. ``tenant_id`` is part of the key per the
    R1 P1 reviewer fix — admission decisions, image trust roots,
    per-tenant max-policy caps, and egress allow-lists are all
    tenant-scoped, so a warm session admitted under tenant A's trust
    posture MUST NOT serve a request from tenant B even when policy +
    pack_context are byte-identical.

    Public surface:

    * 5 lifecycle coroutines: ``register`` / ``precreate`` / ``checkout`` /
      ``release_or_destroy`` / ``drain``.
    * 3 synchronous introspection helpers: ``current_size`` /
      ``registered_pair_count`` / ``registered_pairs`` (R2 P2 added
      the snapshot iterator that replaces the write-only register API).

    The cryptographic pool-key bytes are internal — the audit chain
    row's ``payload.pool_key`` carries the human-readable
    ``SandboxPolicy.warm_pool_key`` string for examiner readability
    (per spec §11 line 771).
    """

    def __init__(
        self,
        *,
        backend: SandboxBackend,
        max_pool_size_per_key: int,
        idle_ttl_s: float,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
        service_actor: Actor,
    ) -> None:
        """Initialise a per-backend warm pool.

        ``service_actor`` (R2 P1 reviewer fix) is the AgentOS system
        identity passed to ``backend.create(..., actor=...)`` on the
        replenisher path. Must be an ``Actor`` instance — the harness
        owns the service-actor minting policy per ADR-008 actor-binder
        contract; the pool does not synthesise one. Production wiring
        passes an ``actor_type='service'`` Actor with a system-scope
        ``subject``; tests inject either a real Actor or a MagicMock.
        """

        if max_pool_size_per_key < 1:
            raise ValueError(f"max_pool_size_per_key must be >= 1; got {max_pool_size_per_key}")
        if idle_ttl_s <= 0:
            raise ValueError(f"idle_ttl_s must be > 0; got {idle_ttl_s}")

        self._backend = backend
        self._max_pool_size_per_key = max_pool_size_per_key
        self._idle_ttl_s = idle_ttl_s
        # ``audit_store`` is wired through for API parity with spec §11
        # but the actual chain-emission seam is the on-gate
        # ``emit_sandbox_event`` which writes via
        # ``decision_history_store``. Held here so callers can introspect
        # the configured store (e.g. for telemetry roll-up).
        self._audit_store = audit_store
        self._decision_history_store = decision_history_store
        self._service_actor = service_actor

        # Pool state — bytes pool-key → deque of _PoolEntry (session +
        # deposit timestamp). The wrapper carries the deposit timestamp
        # so idle-TTL expiry measures time-IDLE-IN-POOL, not
        # time-since-session-creation (R2 P2 reviewer fix).
        self._pools: dict[bytes, deque[_PoolEntry]] = {}
        # Per-key serialisation lock; lazy-allocated under _locks_lock.
        self._locks: dict[bytes, asyncio.Lock] = {}
        self._locks_lock = asyncio.Lock()
        # Registered (policy, tenant, pack_context) triples for the
        # harness-side background replenisher to iterate. Keyed by the
        # same pool-key as the deque, so re-register is idempotent.
        self._registered: dict[bytes, tuple[SandboxPolicy, str, PackAdmissionContext]] = {}
        self._drained: bool = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def register(
        self,
        policy: SandboxPolicy,
        *,
        tenant_id: str,
        pack_context: PackAdmissionContext,
    ) -> None:
        """Register a (policy, tenant, pack_context) triple for ongoing
        warming. Idempotent — re-registering the same triple is a no-op
        so the replenisher does not over-warm a single key."""

        key = _derive_pool_key(policy, pack_context, tenant_id)
        # Last-writer-wins is fine; idempotency means same value anyway.
        self._registered[key] = (policy, tenant_id, pack_context)

    async def precreate(
        self,
        policy: SandboxPolicy,
        *,
        tenant_id: str,
        pack_context: PackAdmissionContext,
    ) -> None:
        """Background replenisher entry point. Calls
        ``backend.create(..., use_warm_pool=False)`` with the registered
        pack_context so the replenisher does NOT re-enter the warm-pool
        fast-path (spec §11 line 775).

        No-op when the pool is at ``max_pool_size_per_key`` (no point
        creating a session destined for immediate destruction) OR when
        the pool has been drained (a background replenisher tick firing
        after drain MUST NOT repopulate; R1 P1 reviewer fix). The
        drained-check is re-checked INSIDE the per-key lock so a
        concurrent drain that flips ``_drained`` while precreate is
        waiting for the lock still wins."""

        # Fast-path drain check — short-circuits before any per-key
        # lock acquisition for the common case where drain ran before
        # the replenisher tick.
        if self._drained:
            return

        key = _derive_pool_key(policy, pack_context, tenant_id)
        lock = await self._lock_for(key)
        async with lock:
            # Re-check inside the per-key lock — drain() acquires this
            # same lock (per the R1 P1 redesign) so once drain holds it
            # we are guaranteed _drained == True by the time we get
            # the lock if drain reached this key. The flag is set
            # BEFORE drain acquires the lock so a precreate that
            # acquires the lock after drain finished sees True.
            if self._drained:
                return
            pool = self._pools.setdefault(key, deque())
            # R3 P2a — evict expired entries BEFORE the capacity check
            # so a quiet pool full of stale entries does not block
            # replenishment until the next cold-miss.
            await self._evict_expired_in_place(pool)
            if len(pool) >= self._max_pool_size_per_key:
                return
            # Cold-create OUTSIDE the per-key lock would race the
            # capacity check; create under the lock so the post-create
            # deposit observes the exact capacity it checked. Spec §11
            # treats this as a single-writer envelope per key.
            session = await self._backend.create(
                policy,
                actor=self._service_actor,
                tenant_id=tenant_id,
                pack_context=pack_context,
                use_warm_pool=False,
            )
            # Wrap with deposit timestamp for idle-TTL semantics per
            # R2 P2 reviewer fix — measures time-idle-in-pool, NOT
            # time-since-session-creation.
            pool.append(_PoolEntry(session=session, deposited_at=datetime.now(UTC)))
            await self._emit_warm_event(
                event="sandbox.warm_pool.precreated",
                policy=policy,
                tenant_id=tenant_id,
                session_id=session.session_id,
                payload_extra={"pool_size_after": len(pool)},
            )

    async def checkout(
        self,
        policy: SandboxPolicy,
        *,
        tenant_id: str,
        pack_context: PackAdmissionContext,
    ) -> SandboxSession | None:
        """Returns a warm session matching policy AND pack_context AND
        tenant_id, or ``None`` on pool miss. Raises
        ``SandboxLifecycleRefused`` with ``sandbox_warm_pool_drained``
        after ``drain()`` has been called.

        Pack_context match uses the 5 admission-relevant fields per
        spec §11 line 740; tenant_id is part of the key per R1 P1
        reviewer fix; a mismatch on EITHER tenant_id OR pack_context
        is a pool miss (caller falls through to cold-create).

        Expired entries (idle for longer than ``idle_ttl_s``) are
        destroyed before serving — R1 P2 reviewer fix. The FIFO deque
        is scanned popleft-first: each expired head is destroyed and
        the scan continues to the next entry; the first non-expired
        entry is served. If all entries are expired the result is a
        pool miss (caller falls through to cold-create).
        """

        if self._drained:
            raise SandboxLifecycleRefused(
                "sandbox_warm_pool_drained",
                detail="pool drained; no checkouts permitted",
            )

        key = _derive_pool_key(policy, pack_context, tenant_id)
        lock = await self._lock_for(key)
        async with lock:
            pool = self._pools.get(key)
            if not pool:
                return None
            # Sweep expired before serving — head is always oldest by
            # FIFO + monotonic deposit time.
            await self._evict_expired_in_place(pool)
            if not pool:
                # All entries were expired + destroyed; pool miss.
                return None
            session = pool.popleft().session
            await self._emit_warm_event(
                event="sandbox.warm_pool.checked_out",
                policy=policy,
                tenant_id=tenant_id,
                session_id=session.session_id,
                payload_extra={"pool_size_after": len(pool)},
            )
            return session

    async def release_or_destroy(self, session: SandboxSession) -> None:
        """Deposit ``session`` back into the pool if there is room +
        the pool is not drained, otherwise destroy via
        ``backend.destroy()``. Pool-key derives from
        ``session.policy + session.pack_context + session.tenant_id``
        (the load-bearing round-3-FU Protocol amendment per spec §11
        line 749, extended with tenant_id per R1 P1)."""

        # Fast-path drain check. Re-checked inside the per-key lock
        # below to close the in-flight race where drain runs between
        # this check and the lock acquisition (R1 P1 reviewer fix).
        if self._drained:
            await self._backend.destroy(session)
            return

        key = _derive_pool_key(session.policy, session.pack_context, session.tenant_id)
        lock = await self._lock_for(key)
        async with lock:
            # Re-check inside the per-key lock — drain() acquires this
            # same lock (R1 P1 redesign), so a concurrent drain that
            # raced past our fast-path check WILL be observed here.
            if self._drained:
                await self._backend.destroy(session)
                return
            pool = self._pools.setdefault(key, deque())
            # R3 P2a — evict expired entries BEFORE the capacity check
            # so a fresh release is not destroyed while stale entries
            # occupy the cap.
            await self._evict_expired_in_place(pool)
            if len(pool) >= self._max_pool_size_per_key:
                # Pool full — destroy rather than deposit-then-evict.
                # Spec §11 treats this as the steady-state cap; never
                # exceed even temporarily.
                await self._backend.destroy(session)
                return
            # Fresh deposit timestamp — even if session.created_at is
            # old, the idle clock restarts here (R2 P2 reviewer fix).
            pool.append(_PoolEntry(session=session, deposited_at=datetime.now(UTC)))

    async def drain(self) -> None:
        """Shutdown: destroys all warm sessions across all pool keys.
        Subsequent ``checkout()`` raises ``sandbox_warm_pool_drained``;
        subsequent ``precreate()`` + ``release_or_destroy()`` are
        no-ops (precreate returns silently; release destroys). Emits
        one ``sandbox.warm_pool.drained`` audit event per non-empty
        pool key carrying the spec-locked payload
        ``{"pool_key": str, "drained_count": int}``.

        Race-safety per R1 P1 reviewer fix: the ``_drained`` flag is
        set FIRST (so concurrent precreate / release_or_destroy
        observers see True before drain acquires any per-key lock),
        then each per-key lock is acquired in turn while the deque is
        snapshotted + cleared. This ensures any concurrent operation
        that acquires the per-key lock after drain has held it sees
        ``_drained == True`` on re-check + bails. The lock-set is
        snapshotted under the global lock-map lock to avoid mutating
        ``_locks`` while iterating.
        """

        self._drained = True

        async with self._locks_lock:
            keys = list(self._pools.keys())

        # Acquire each per-key lock to snapshot + clear under
        # mutual exclusion with concurrent precreate / release.
        snapshot: dict[bytes, list[_PoolEntry]] = {}
        for key in keys:
            lock = await self._lock_for(key)
            async with lock:
                pool = self._pools.get(key)
                if pool:
                    snapshot[key] = list(pool)
                    pool.clear()

        # Destroy + emit OUTSIDE the per-key locks (no shared state
        # mutation needed at this point; pools are empty + _drained
        # is True so no new deposits).
        for key, entries in snapshot.items():
            if not entries:
                continue
            # Parallel destroy per spec §11 line 783
            sessions = [e.session for e in entries]
            await asyncio.gather(
                *(self._backend.destroy(s) for s in sessions),
                return_exceptions=False,
            )
            # Emit using the policy + tenant from the registered
            # triple for this key. If the key has no registration
            # (cold-released path), fall back to the first session's
            # policy + tenant_id for the audit row's payload.pool_key
            # human-readable name.
            policy: SandboxPolicy
            tenant_id: str
            if key in self._registered:
                policy, tenant_id, _ = self._registered[key]
            else:
                policy = sessions[0].policy
                tenant_id = sessions[0].tenant_id
            await self._emit_warm_event(
                event="sandbox.warm_pool.drained",
                policy=policy,
                tenant_id=tenant_id,
                session_id=sessions[0].session_id,
                payload_extra={"drained_count": len(sessions)},
            )

    async def _evict_expired_in_place(self, pool: deque[_PoolEntry]) -> None:
        """Sweep expired entries from the head of the FIFO deque +
        destroy them. After return, ``pool[0]`` is either non-expired
        or the deque is empty. Idempotent.

        Called from every capacity-sensitive path (checkout / precreate
        / release_or_destroy) BEFORE the capacity check per R3 P2a
        reviewer fix — otherwise a quiet pool can stay full of expired
        entries because precreate's ``len(pool) >= max`` check counts
        them, and release_or_destroy can destroy a fresh session while
        stale entries occupy the cap.

        Deposits are FIFO and use ``datetime.now(UTC)`` (monotonic in
        practice) so the head is always the oldest entry; head-first
        sweep is sufficient.

        Expiry compares ``now - entry.deposited_at`` against
        ``idle_ttl_s`` — measures time-IDLE-IN-POOL, NOT
        time-since-session-creation. A long-running session released
        back to the pool restarts its idle clock.

        Called under the per-key lock so deque mutation is single-
        writer-safe. The destroy call is awaited inside the loop —
        the deque cannot have new entries appended during this
        sequence because precreate / release_or_destroy contend for
        the same per-key lock.
        """
        now = datetime.now(UTC)
        while pool:
            head = pool[0]
            idle_s = (now - head.deposited_at).total_seconds()
            if idle_s < self._idle_ttl_s:
                return
            # Expired — pop + destroy + continue sweep
            pool.popleft()
            await self._backend.destroy(head.session)

    # ------------------------------------------------------------------
    # Synchronous introspection helpers (NOT wire-protocol-public)
    # ------------------------------------------------------------------

    def current_size(
        self,
        policy: SandboxPolicy,
        *,
        tenant_id: str,
        pack_context: PackAdmissionContext,
    ) -> int:
        """Number of warm sessions currently parked under
        ``(tenant_id, policy, pack_context)``. Used by tests +
        telemetry; NOT a wire-protocol surface. ``tenant_id`` is
        required per R1 P1 reviewer fix — the pool key is
        tenant-scoped so the introspection helper must be too."""

        key = _derive_pool_key(policy, pack_context, tenant_id)
        pool = self._pools.get(key)
        return len(pool) if pool else 0

    def registered_pair_count(self) -> int:
        """Number of distinct (policy, tenant, pack_context) triples
        currently registered for replenishment. Used by harness +
        tests; NOT a wire-protocol surface."""

        return len(self._registered)

    def registered_pairs(
        self,
    ) -> tuple[tuple[SandboxPolicy, str, PackAdmissionContext], ...]:
        """Snapshot of all registered (policy, tenant_id, pack_context)
        triples in registration order. Used by the harness-side
        background replenisher to iterate without reaching into
        ``_registered`` (R2 P2 reviewer fix — replacing the
        write-only register API with a proper read seam).

        Returns a tuple snapshot so callers can iterate without
        observing concurrent register() mutations. NOT a wire-protocol
        surface — in-process Python API only.
        """

        return tuple(self._registered.values())

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _lock_for(self, key: bytes) -> asyncio.Lock:
        """Lazy-allocate the per-key lock under ``_locks_lock`` so two
        concurrent first-touches do not produce two locks."""

        existing = self._locks.get(key)
        if existing is not None:
            return existing
        async with self._locks_lock:
            # Re-check inside the lock — another coroutine may have
            # allocated while we were awaiting the lock acquisition.
            existing = self._locks.get(key)
            if existing is not None:
                return existing
            new_lock = asyncio.Lock()
            self._locks[key] = new_lock
            return new_lock

    async def _emit_warm_event(
        self,
        *,
        event: SandboxLifecycleEvent,
        policy: SandboxPolicy,
        tenant_id: str,
        session_id: str,
        payload_extra: dict[str, object],
    ) -> None:
        """Emit one of the 3 warm-pool audit events with the
        spec-locked payload shape. ``pool_key`` carries the
        human-readable ``policy.warm_pool_key`` string per spec §11
        line 771 (NOT the cryptographic pool-key bytes — those are
        internal). Tagged ``A.6.2.5`` via ``emit_sandbox_event``.

        The chain row's ``actor_id`` carries the service actor's
        ``subject`` (R3 P2 reviewer fix — empty actor_id leaves
        warm-pool audit rows actorless even though the service
        identity is now available via ``self._service_actor``).
        Trace_id is empty because the warm-pool replenisher operates
        without a request-bound trace; admission rows under the
        actual checkout consumer carry the user-bound trace.

        The ``event`` parameter is restricted to the 3 warm-pool
        members of the ``SandboxLifecycleEvent`` Literal by the
        call sites (each passes a string-literal matching one of the
        ``_WARM_POOL_EVENTS`` members); the helper does not validate
        runtime — ``emit_sandbox_event`` itself rejects out-of-set
        values per ``audit.py:99``.
        """

        payload: dict[str, object] = {
            "pool_key": policy.warm_pool_key or "",
            **payload_extra,
        }
        await emit_sandbox_event(
            self._decision_history_store,
            event=event,
            tenant_id=tenant_id,
            actor_id=self._service_actor.subject,
            trace_id="",
            session_id=session_id,
            payload=payload,
        )
