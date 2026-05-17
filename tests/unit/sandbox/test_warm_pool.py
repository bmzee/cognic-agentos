"""Sprint 8A T9 — SandboxWarmPool unit tests.

Pins:

* Three spec §11 LOAD-BEARING regression classes (each pins a distinct
  bug class the spec rounds discovered):
    1. Replenisher MUST call backend.create(..., use_warm_pool=False)
       and pass the registered pack_context — without these kwargs the
       replenisher either consumes-while-incrementing or loops.
    2. Checkout with a pack_context whose 5 admission-relevant fields
       differ from the warmed-with context MUST be a pool miss — pack A
       cannot consume pack B's warm member even when policy matches.
    3. Cold-released session deposits under the key derived from
       session.policy + session.pack_context — subsequent matching
       checkout returns the deposited session.

* Drain semantics: destroys all warm members + refuses subsequent
  checkout with closed-enum ``sandbox_warm_pool_drained``.

* Per-key isolation: distinct pool keys never cross-feed each other.

* Pool-key derivation MUST depend on all 5 pack_context admission
  fields (pack_id, pack_artifact_digest, risk_tier,
  declares_dynamic_install, profile) — flipping ANY of the 5 produces
  a different key. pack_version is INTENTIONALLY NOT in the key
  (per spec §11 line 767 — human-mutable, not load-bearing).

* Audit emission: precreate → ``sandbox.warm_pool.precreated``;
  checkout (pool hit) → ``sandbox.warm_pool.checked_out``;
  drain → ``sandbox.warm_pool.drained``. Each payload carries the
  3 spec-locked keys (pool_key + pool_size_after OR drained_count).

* max_pool_size_per_key enforcement: release into a full pool destroys
  the session via backend.destroy() rather than deposit-then-evict.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox import (
    PackAdmissionContext,
    SandboxLifecycleRefused,
    SandboxPolicy,
)
from cognic_agentos.sandbox.warm_pool import SandboxWarmPool

# R2 P1 — real service Actor used by the pool's replenisher path.
# Production wiring injects an equivalent Actor at T10 from the
# harness's actor-binder service-account flow per ADR-008.
_SERVICE_ACTOR = Actor(
    subject="cognic-agentos-warm-pool-replenisher",
    tenant_id="cognic-system",
    scopes=frozenset(),
    actor_type="service",
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_POLICY = SandboxPolicy(
    cpu_cores=1.0,
    cpu_time_budget_s=None,
    memory_mb=256,
    walltime_s=30.0,
    runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    egress_allow_list=("api.example.com",),
    vault_path=None,
    warm_pool_key="python-interactive",
)

_PACK_CTX_A = PackAdmissionContext(
    pack_id="pack.a",
    pack_version="v1",
    pack_artifact_digest="sha256:" + "1" * 64,
    risk_tier="internal_write",
    declares_dynamic_install=False,
    profile="production",
)

# Pack B differs from A in pack_id + pack_artifact_digest (the 2 most
# common reason a pool miss should fire). Other 3 admission fields match.
_PACK_CTX_B = PackAdmissionContext(
    pack_id="pack.b",
    pack_version="v1",
    pack_artifact_digest="sha256:" + "2" * 64,
    risk_tier="internal_write",
    declares_dynamic_install=False,
    profile="production",
)


def _make_session(
    session_id: str,
    pack_ctx: PackAdmissionContext,
    *,
    policy: SandboxPolicy = _POLICY,
) -> MagicMock:
    """Mock SandboxSession that carries policy + pack_context per spec §5."""
    s = MagicMock()
    s.session_id = session_id
    s.policy = policy
    s.tenant_id = "t-1"
    s.pack_context = pack_ctx
    s.created_at = datetime.now(UTC)
    s.warm_pool_hit = False
    return s


def _make_decision_history_store() -> AsyncMock:
    """Default decision-history-store mock. The audit-emission seam at
    ``emit_sandbox_event`` does ``await
    decision_history_store.append_with_precondition(...)`` which
    returns ``(uuid, bytes)`` per ``audit.py:74``. ``AsyncMock`` so
    the await is valid; explicit 2-tuple return so the helper can
    unpack."""
    import uuid as _uuid

    store = AsyncMock()
    store.append_with_precondition.return_value = (_uuid.uuid4(), b"\x00" * 32)
    return store


def _make_pool(
    *,
    backend: AsyncMock | None = None,
    max_pool_size_per_key: int = 4,
    idle_ttl_s: float = 300.0,
    decision_history_store: AsyncMock | None = None,
    service_actor: Actor = _SERVICE_ACTOR,
) -> SandboxWarmPool:
    return SandboxWarmPool(
        backend=backend or AsyncMock(),
        max_pool_size_per_key=max_pool_size_per_key,
        idle_ttl_s=idle_ttl_s,
        audit_store=MagicMock(),
        decision_history_store=(
            decision_history_store
            if decision_history_store is not None
            else _make_decision_history_store()
        ),
        service_actor=service_actor,
    )


# ---------------------------------------------------------------------------
# Spec §11 LOAD-BEARING #1 — replenisher bypasses pool
# ---------------------------------------------------------------------------


class TestReplenisherBypassesPool:
    """Spec §11 line 775 — replenisher MUST call backend.create(...,
    use_warm_pool=False, pack_context=<registered>); without these kwargs
    the replenisher would either consume an existing pool member while
    trying to increment OR loop indefinitely."""

    @pytest.mark.asyncio
    async def test_precreate_calls_backend_create_with_use_warm_pool_false(
        self,
    ) -> None:
        backend = AsyncMock()
        backend.create.return_value = _make_session("warmed", _PACK_CTX_A)
        pool = _make_pool(backend=backend)

        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)

        backend.create.assert_awaited_once()
        kwargs = backend.create.await_args.kwargs
        assert kwargs["use_warm_pool"] is False, (
            "Replenisher MUST bypass warm-pool fast-path or it will "
            "either consume existing members or loop. Spec §11 line 775."
        )
        assert kwargs["pack_context"] == _PACK_CTX_A, (
            "Replenisher MUST pass the registered pack_context so "
            "admission decisions at warming time stay valid at "
            "checkout time. Spec §11 line 774."
        )
        assert kwargs["tenant_id"] == "t-1"

    @pytest.mark.asyncio
    async def test_pool_size_monotonically_increases_under_replenishment(
        self,
    ) -> None:
        """Repeated precreate calls grow the pool; a single replenisher
        sweep that consumed-while-incrementing would NOT show
        monotonic growth."""
        backend = AsyncMock()
        backend.create.side_effect = [_make_session(f"warmed-{i}", _PACK_CTX_A) for i in range(3)]
        pool = _make_pool(backend=backend)

        for _ in range(3):
            await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)

        assert pool.current_size(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A) == 3


# ---------------------------------------------------------------------------
# Spec §11 LOAD-BEARING #2 — pack_context mismatch is pool miss
# ---------------------------------------------------------------------------


class TestCheckoutWithPackContextMismatchIsPoolMiss:
    """Spec §11 line 740 — a session admitted for pack A (artifact X)
    MUST NOT be handed to pack B (artifact Y) even when policy is
    identical, because admission decisions may differ across
    pack_artifact_digests."""

    @pytest.mark.asyncio
    async def test_checkout_with_different_pack_context_returns_none(
        self,
    ) -> None:
        backend = AsyncMock()
        backend.create.return_value = _make_session("warmed-A", _PACK_CTX_A)
        pool = _make_pool(backend=backend)

        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        assert pool.current_size(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A) == 1

        # Checkout for pack B → pool miss
        result = await pool.checkout(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_B)
        assert result is None, (
            "Pack B checkout MUST NOT consume pack A warm member; "
            "spec §11 line 740 uses 5 PackAdmissionContext fields "
            "in the pool key."
        )
        # Pack A's warm member is still in the pool
        assert pool.current_size(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A) == 1


# ---------------------------------------------------------------------------
# Spec §11 LOAD-BEARING #3 — cold-released session deposits to correct key
# ---------------------------------------------------------------------------


class TestColdCreatedSessionReleasesToCorrectPoolKey:
    """Spec §11 line 749 — when a caller cold-creates after a pool miss
    and calls release_or_destroy(session) on exit, the pool MUST derive
    the correct key from session.pack_context (carried on
    SandboxSession per the round-3-FU Protocol amendment) WITHOUT a
    separate pack_context parameter."""

    @pytest.mark.asyncio
    async def test_cold_release_then_matching_checkout_returns_session(
        self,
    ) -> None:
        pool = _make_pool()

        cold_session = _make_session("cold-1", _PACK_CTX_A)
        await pool.release_or_destroy(cold_session)
        assert pool.current_size(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A) == 1

        result = await pool.checkout(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        assert result is cold_session


# ---------------------------------------------------------------------------
# Drain semantics
# ---------------------------------------------------------------------------


class TestDrainSemantics:
    @pytest.mark.asyncio
    async def test_drain_destroys_all_warm_members_and_refuses_subsequent_checkout(
        self,
    ) -> None:
        backend = AsyncMock()
        backend.create.return_value = _make_session("warmed", _PACK_CTX_A)
        pool = _make_pool(backend=backend)
        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)

        await pool.drain()

        # All warm members destroyed
        backend.destroy.assert_awaited()
        # Subsequent checkout fails-closed with the closed-enum reason
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await pool.checkout(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        assert exc.value.reason == "sandbox_warm_pool_drained"

    @pytest.mark.asyncio
    async def test_release_or_destroy_after_drain_destroys_never_deposits(
        self,
    ) -> None:
        """A late `release_or_destroy(session)` arriving AFTER `drain()`
        MUST destroy the session, NEVER deposit it back into the pool.
        Pinning this prevents a resource-leak path where a drained pool
        accumulates sessions that no future checkout can ever consume."""
        backend = AsyncMock()
        pool = _make_pool(backend=backend)

        await pool.drain()
        late_session = _make_session("late", _PACK_CTX_A)
        await pool.release_or_destroy(late_session)

        backend.destroy.assert_awaited_with(late_session)
        assert pool.current_size(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A) == 0

    @pytest.mark.asyncio
    async def test_drain_destroys_members_across_multiple_keys(self) -> None:
        backend = AsyncMock()
        backend.create.side_effect = [
            _make_session("a-1", _PACK_CTX_A),
            _make_session("b-1", _PACK_CTX_B),
        ]
        pool = _make_pool(backend=backend)
        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_B)

        await pool.drain()

        # Both warm sessions destroyed
        assert backend.destroy.await_count == 2


# ---------------------------------------------------------------------------
# Per-key isolation
# ---------------------------------------------------------------------------


class TestPerKeyIsolation:
    @pytest.mark.asyncio
    async def test_two_keys_do_not_cross_feed(self) -> None:
        backend = AsyncMock()
        backend.create.side_effect = [
            _make_session("a-1", _PACK_CTX_A),
            _make_session("b-1", _PACK_CTX_B),
        ]
        pool = _make_pool(backend=backend)
        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_B)

        assert pool.current_size(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A) == 1
        assert pool.current_size(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_B) == 1

        # Checkout A consumes A only
        a = await pool.checkout(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        assert a is not None
        assert a.session_id == "a-1"
        assert pool.current_size(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A) == 0
        assert pool.current_size(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_B) == 1


# ---------------------------------------------------------------------------
# Pool-key derivation — depends on all 5 pack_context admission fields,
# NOT pack_version
# ---------------------------------------------------------------------------


class TestPoolKeyDerivation:
    """Parametric pin that flipping ANY of the 5 admission-relevant
    pack_context fields produces a different pool key (pool miss).
    Flipping pack_version produces the SAME key (per spec §11 line 767
    — human-mutable, intentionally NOT in key)."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "field_name,changed_value",
        [
            ("pack_id", "pack.different"),
            ("pack_artifact_digest", "sha256:" + "9" * 64),
            ("risk_tier", "customer_data_read"),
            ("declares_dynamic_install", True),
            ("profile", "development"),
        ],
    )
    async def test_flipping_any_of_5_admission_fields_changes_pool_key(
        self, field_name: str, changed_value: Any
    ) -> None:
        """If flipping any of the 5 admission fields produces the SAME
        key, a session admitted under one set of admission decisions
        could serve a request requiring different admission decisions —
        the integrity bug class spec §11 line 740 explicitly prevents."""
        backend = AsyncMock()
        backend.create.return_value = _make_session("warmed", _PACK_CTX_A)
        pool = _make_pool(backend=backend)

        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)

        # Build a mutated context with one field changed
        changed_ctx = PackAdmissionContext(
            pack_id=changed_value if field_name == "pack_id" else _PACK_CTX_A.pack_id,
            pack_version=_PACK_CTX_A.pack_version,
            pack_artifact_digest=(
                changed_value
                if field_name == "pack_artifact_digest"
                else _PACK_CTX_A.pack_artifact_digest
            ),
            risk_tier=(changed_value if field_name == "risk_tier" else _PACK_CTX_A.risk_tier),
            declares_dynamic_install=(
                changed_value
                if field_name == "declares_dynamic_install"
                else _PACK_CTX_A.declares_dynamic_install
            ),
            profile=(changed_value if field_name == "profile" else _PACK_CTX_A.profile),
        )

        result = await pool.checkout(_POLICY, tenant_id="t-1", pack_context=changed_ctx)
        assert result is None, (
            f"Flipping pack_context.{field_name} from "
            f"{getattr(_PACK_CTX_A, field_name)!r} to {changed_value!r} "
            f"MUST produce a different pool key (pool miss); got a hit "
            f"which means the admission integrity invariant from "
            f"spec §11 line 740 is broken."
        )
        # Pack A's warmed member is untouched
        assert pool.current_size(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A) == 1

    @pytest.mark.asyncio
    async def test_flipping_pack_version_keeps_same_pool_key(self) -> None:
        """pack_version is human-mutable + intentionally NOT in the
        pool key per spec §11 line 767. Two PackAdmissionContexts
        identical in all 5 admission fields but differing in
        pack_version MUST hit the same pool key."""
        backend = AsyncMock()
        backend.create.return_value = _make_session("warmed", _PACK_CTX_A)
        pool = _make_pool(backend=backend)

        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)

        different_version_ctx = PackAdmissionContext(
            pack_id=_PACK_CTX_A.pack_id,
            pack_version="v999",  # ← only this changes
            pack_artifact_digest=_PACK_CTX_A.pack_artifact_digest,
            risk_tier=_PACK_CTX_A.risk_tier,
            declares_dynamic_install=_PACK_CTX_A.declares_dynamic_install,
            profile=_PACK_CTX_A.profile,
        )

        result = await pool.checkout(
            _POLICY,
            tenant_id="t-1",
            pack_context=different_version_ctx,
        )
        assert result is not None, (
            "pack_version differs but the 5 admission fields are "
            "identical — pool MUST hit per spec §11 line 767."
        )


# ---------------------------------------------------------------------------
# max_pool_size_per_key enforcement
# ---------------------------------------------------------------------------


class TestMaxPoolSizeEnforcement:
    @pytest.mark.asyncio
    async def test_release_into_full_pool_destroys_session(self) -> None:
        """When the pool is at max capacity, release_or_destroy() MUST
        destroy the released session via backend.destroy() rather than
        deposit-then-evict (which would temporarily exceed the cap)."""
        backend = AsyncMock()
        # Pre-fill the pool to capacity via precreate
        backend.create.side_effect = [_make_session(f"warmed-{i}", _PACK_CTX_A) for i in range(2)]
        pool = _make_pool(backend=backend, max_pool_size_per_key=2)

        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        assert pool.current_size(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A) == 2

        # Release a cold-created session into the full pool → destroy
        cold = _make_session("overflow", _PACK_CTX_A)
        await pool.release_or_destroy(cold)

        backend.destroy.assert_awaited_with(cold)
        # Pool stays at the cap
        assert pool.current_size(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A) == 2

    @pytest.mark.asyncio
    async def test_precreate_into_full_pool_is_noop(self) -> None:
        """Replenisher precreate when pool already at cap MUST NOT
        call backend.create() (no point creating a session destined
        for immediate destruction)."""
        backend = AsyncMock()
        backend.create.side_effect = [_make_session(f"warmed-{i}", _PACK_CTX_A) for i in range(2)]
        pool = _make_pool(backend=backend, max_pool_size_per_key=2)

        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        assert backend.create.await_count == 2

        # Third precreate when at cap → no backend.create call
        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        assert backend.create.await_count == 2


# ---------------------------------------------------------------------------
# Audit emission
# ---------------------------------------------------------------------------


class TestAuditEmission:
    """The 3 warm-pool events from spec §12 wire-protocol-public list
    fire at the correct lifecycle moments with the spec-locked payload
    shape. Pool_key is the human-readable warm_pool_key attached to the
    policy (per spec §11 line 771)."""

    @pytest.mark.asyncio
    async def test_precreate_emits_warm_pool_precreated_event(self) -> None:
        backend = AsyncMock()
        backend.create.return_value = _make_session("w-1", _PACK_CTX_A)
        dh_store = AsyncMock()
        # emit_sandbox_event returns (uuid, bytes) per audit.py:74
        import uuid

        dh_store.append_with_precondition.return_value = (uuid.uuid4(), b"\x00" * 32)
        pool = _make_pool(backend=backend, decision_history_store=dh_store)

        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)

        # Exactly one chain row appended on green path
        dh_store.append_with_precondition.assert_awaited_once()
        # Inspect the built record
        record_builder = dh_store.append_with_precondition.await_args.kwargs["record_builder"]
        record = record_builder(None)
        assert record.decision_type == "sandbox.warm_pool.precreated"
        assert record.payload["pool_key"] == "python-interactive"
        assert record.payload["pool_size_after"] == 1
        assert record.iso_controls == ("A.6.2.5",)

    @pytest.mark.asyncio
    async def test_checkout_hit_emits_warm_pool_checked_out_event(self) -> None:
        backend = AsyncMock()
        backend.create.return_value = _make_session("w-1", _PACK_CTX_A)
        dh_store = AsyncMock()
        import uuid

        dh_store.append_with_precondition.return_value = (uuid.uuid4(), b"\x00" * 32)
        pool = _make_pool(backend=backend, decision_history_store=dh_store)

        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        # Reset to isolate the checkout emission
        dh_store.append_with_precondition.reset_mock()

        result = await pool.checkout(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        assert result is not None

        dh_store.append_with_precondition.assert_awaited_once()
        record_builder = dh_store.append_with_precondition.await_args.kwargs["record_builder"]
        record = record_builder(None)
        assert record.decision_type == "sandbox.warm_pool.checked_out"
        assert record.payload["pool_key"] == "python-interactive"
        assert record.payload["pool_size_after"] == 0

    @pytest.mark.asyncio
    async def test_checkout_miss_emits_no_audit_event(self) -> None:
        """A checkout that returns None (no warm member) MUST NOT emit
        a checked_out audit event — otherwise examiners would see
        warm-pool hits that never happened."""
        dh_store = AsyncMock()
        pool = _make_pool(decision_history_store=dh_store)

        result = await pool.checkout(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        assert result is None
        dh_store.append_with_precondition.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_drain_emits_one_warm_pool_drained_event_per_key(
        self,
    ) -> None:
        backend = AsyncMock()
        backend.create.side_effect = [
            _make_session("a-1", _PACK_CTX_A),
            _make_session("a-2", _PACK_CTX_A),
            _make_session("b-1", _PACK_CTX_B),
        ]
        dh_store = AsyncMock()
        import uuid

        dh_store.append_with_precondition.return_value = (uuid.uuid4(), b"\x00" * 32)
        pool = _make_pool(backend=backend, decision_history_store=dh_store)

        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_B)
        dh_store.append_with_precondition.reset_mock()

        await pool.drain()

        # One drained event per non-empty pool key (2 keys)
        assert dh_store.append_with_precondition.await_count == 2
        # Each carries the spec-locked payload shape
        for call_args in dh_store.append_with_precondition.await_args_list:
            record = call_args.kwargs["record_builder"](None)
            assert record.decision_type == "sandbox.warm_pool.drained"
            assert "pool_key" in record.payload
            assert "drained_count" in record.payload
            assert record.payload["drained_count"] >= 1


# ---------------------------------------------------------------------------
# Register API — for the harness-side replenisher orchestration
# ---------------------------------------------------------------------------


class TestRegister:
    @pytest.mark.asyncio
    async def test_register_records_pair_for_replenishment(self) -> None:
        """register() records a (policy, tenant, pack_context) tuple
        so the harness-side background replenisher can iterate
        registered pairs and call precreate() against each. The pool
        introspection helper exposes the registered count."""
        pool = _make_pool()

        await pool.register(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        await pool.register(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_B)

        assert pool.registered_pair_count() == 2

    @pytest.mark.asyncio
    async def test_register_is_idempotent_for_same_triple(self) -> None:
        """Re-registering the same (policy, tenant, pack_context)
        triple MUST NOT double-count — otherwise the replenisher would
        precreate twice per sweep for the same key."""
        pool = _make_pool()

        await pool.register(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        await pool.register(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)

        assert pool.registered_pair_count() == 1


# ---------------------------------------------------------------------------
# R1 P1 reviewer fix #1 — tenant scope (pool key INCLUDES tenant_id)
# ---------------------------------------------------------------------------


class TestPoolIsTenantScoped:
    """R1 P1 reviewer fix — admission decisions, image trust roots,
    per-tenant max-policy caps, and egress allow-lists are all
    tenant-scoped. A warm session admitted under tenant A's trust
    posture MUST NOT serve a request from tenant B even when policy +
    pack_context are byte-identical."""

    @pytest.mark.asyncio
    async def test_checkout_under_different_tenant_id_returns_none(
        self,
    ) -> None:
        backend = AsyncMock()
        backend.create.return_value = _make_session("warmed-A", _PACK_CTX_A)
        pool = _make_pool(backend=backend)

        await pool.precreate(_POLICY, tenant_id="tenant-A", pack_context=_PACK_CTX_A)
        assert pool.current_size(_POLICY, tenant_id="tenant-A", pack_context=_PACK_CTX_A) == 1

        # Same policy + same pack_context, DIFFERENT tenant → pool miss
        result = await pool.checkout(_POLICY, tenant_id="tenant-B", pack_context=_PACK_CTX_A)
        assert result is None, (
            "Cross-tenant checkout MUST be a pool miss — tenant A's "
            "warm session cannot serve tenant B even with byte-identical "
            "policy + pack_context. R1 P1 reviewer fix."
        )
        # Tenant A's warm member is untouched + tenant B sees 0
        assert pool.current_size(_POLICY, tenant_id="tenant-A", pack_context=_PACK_CTX_A) == 1
        assert pool.current_size(_POLICY, tenant_id="tenant-B", pack_context=_PACK_CTX_A) == 0

    @pytest.mark.asyncio
    async def test_register_for_two_tenants_does_not_collapse(self) -> None:
        """Two distinct tenants registering the same policy +
        pack_context MUST produce two distinct registered triples;
        collapsing them would mean only one warm-pool key is fed even
        though both tenants need their own warm-up budget."""
        pool = _make_pool()

        await pool.register(_POLICY, tenant_id="tenant-A", pack_context=_PACK_CTX_A)
        await pool.register(_POLICY, tenant_id="tenant-B", pack_context=_PACK_CTX_A)

        assert pool.registered_pair_count() == 2, (
            "Cross-tenant register MUST NOT collapse two tenants into "
            "one entry. R1 P1 reviewer fix."
        )


# ---------------------------------------------------------------------------
# R1 P1 reviewer fix #2 — drained pool repopulation race
# ---------------------------------------------------------------------------


class TestPrecreateRefusedAfterDrain:
    """R1 P1 reviewer fix #2 — a background replenisher tick firing
    after drain() must NOT repopulate the pool. Without the drained
    check in precreate, the post-drain tick calls backend.create(),
    appends a warm session, and emits warm_pool.precreated; the
    session can never be checked out (checkout refuses) so AgentOS
    leaks a sandbox at shutdown."""

    @pytest.mark.asyncio
    async def test_precreate_after_drain_is_noop_no_backend_create(
        self,
    ) -> None:
        backend = AsyncMock()
        pool = _make_pool(backend=backend)

        await pool.drain()
        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)

        backend.create.assert_not_awaited()
        # Pool stays empty + no audit event emitted (we can't directly
        # observe "no emit" because the dh_store mock doesn't track
        # the pre-precreate baseline; the lack of backend.create call
        # is the strong signal — no session, no emit).
        assert pool.current_size(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A) == 0


# ---------------------------------------------------------------------------
# R1 P2 reviewer fix #3 — idle_ttl_s enforcement at checkout
# ---------------------------------------------------------------------------


class TestIdleTTLEnforcement:
    """R1 P2 + R2 P2 reviewer fixes — idle_ttl_s measures time-IDLE-
    IN-POOL (since deposit), NOT time-since-session-creation. Expired
    entries are destroyed at checkout time (FIFO scan from the head);
    the first non-expired entry is served. All-expired → pool miss.

    Tests use short ``idle_ttl_s=0.05`` (50ms) + ``asyncio.sleep``
    so the wall-clock semantics are exercised end-to-end rather than
    via internal timestamp injection (would risk false-passing on a
    bug where the wrong timestamp field is consulted)."""

    @pytest.mark.asyncio
    async def test_expired_entry_destroyed_at_checkout_pool_miss(
        self,
    ) -> None:
        import asyncio as _asyncio

        backend = AsyncMock()
        pool = _make_pool(backend=backend, idle_ttl_s=0.05)

        expired = _make_session("expired", _PACK_CTX_A)
        await pool.release_or_destroy(expired)
        # Wait past the TTL so the deposit goes stale.
        await _asyncio.sleep(0.1)

        result = await pool.checkout(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        assert result is None
        backend.destroy.assert_awaited_with(expired)
        assert pool.current_size(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A) == 0

    @pytest.mark.asyncio
    async def test_expired_first_then_valid_returns_valid(self) -> None:
        """An expired entry at the head of the FIFO deque is destroyed,
        then the next non-expired entry is served — NOT a pool miss.

        With the R3 P2a fix, the expired entry is destroyed during the
        second release_or_destroy (the pre-capacity eviction sweep),
        NOT during the checkout scan. Either path satisfies the
        intent: stale entries never reach the consumer."""
        import asyncio as _asyncio

        backend = AsyncMock()
        pool = _make_pool(backend=backend, idle_ttl_s=0.05)

        expired = _make_session("expired", _PACK_CTX_A)
        await pool.release_or_destroy(expired)
        # Wait past TTL so the first deposit goes stale.
        await _asyncio.sleep(0.1)
        # Second release sweeps the expired entry BEFORE the capacity
        # check (R3 P2a fix), then deposits valid → pool now has 1.
        valid = _make_session("valid", _PACK_CTX_A)
        await pool.release_or_destroy(valid)
        backend.destroy.assert_awaited_with(expired)
        assert pool.current_size(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A) == 1

        result = await pool.checkout(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        assert result is valid
        assert pool.current_size(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A) == 0

    @pytest.mark.asyncio
    async def test_all_expired_returns_pool_miss_destroys_all(self) -> None:
        import asyncio as _asyncio

        backend = AsyncMock()
        pool = _make_pool(backend=backend, idle_ttl_s=0.05)

        sessions = [_make_session(f"expired-{i}", _PACK_CTX_A) for i in range(3)]
        for s in sessions:
            await pool.release_or_destroy(s)
        await _asyncio.sleep(0.1)
        assert pool.current_size(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A) == 3

        result = await pool.checkout(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        assert result is None
        assert backend.destroy.await_count == 3
        assert pool.current_size(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A) == 0

    @pytest.mark.asyncio
    async def test_valid_entry_under_ttl_is_served_normally(self) -> None:
        """Sanity: a fresh entry well under the TTL is served as a
        normal pool hit (no destroy)."""
        backend = AsyncMock()
        pool = _make_pool(backend=backend, idle_ttl_s=300.0)

        fresh = _make_session("fresh", _PACK_CTX_A)
        await pool.release_or_destroy(fresh)
        result = await pool.checkout(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        assert result is fresh
        backend.destroy.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_long_running_session_restarts_idle_clock_on_release(
        self,
    ) -> None:
        """R2 P2 reviewer fix — the bug class: a session that has been
        ALIVE for a long time (e.g. a long-running tool call took 10
        minutes) is released back to the pool. With the buggy
        time-since-creation TTL, the session would be immediately
        evicted on the next checkout. With the correct idle-since-
        deposit TTL, the freshly-released session has a NEW
        ``deposited_at`` so it serves the next matching checkout."""
        backend = AsyncMock()
        # Plenty of headroom on idle TTL so the fresh deposit is well
        # under it; the test pins that session.created_at being old
        # does NOT trigger eviction.
        pool = _make_pool(backend=backend, idle_ttl_s=300.0)

        # Build a session whose created_at is far in the past
        # (10 minutes ago = 600s old). Under the buggy semantics this
        # would exceed the 300s TTL on next checkout; under the
        # correct semantics deposited_at is "now" so it serves cleanly.
        long_running = _make_session("long-running", _PACK_CTX_A)
        long_running.created_at = datetime.now(UTC).fromtimestamp(
            datetime.now(UTC).timestamp() - 600, tz=UTC
        )

        await pool.release_or_destroy(long_running)
        result = await pool.checkout(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        assert result is long_running, (
            "A long-running session released to the pool MUST be served "
            "on the next checkout — idle-TTL measures time-IDLE-IN-POOL, "
            "NOT time-since-creation. R2 P2 reviewer fix."
        )
        backend.destroy.assert_not_awaited()


# ---------------------------------------------------------------------------
# R2 P1 — service actor threaded to backend.create
# ---------------------------------------------------------------------------


class TestServiceActorThreadedToBackendCreate:
    """R2 P1 reviewer fix — the replenisher path calls
    ``backend.create(..., actor=service_actor, ...)`` with the Actor
    supplied at construction time. The earlier buggy implementation
    passed ``actor=None`` with a ``# type: ignore[arg-type]`` smuggling
    a contract violation past the type system; the production T10
    backend would then crash or create a sandbox without a service
    identity."""

    @pytest.mark.asyncio
    async def test_precreate_passes_service_actor_to_backend_create(
        self,
    ) -> None:
        backend = AsyncMock()
        backend.create.return_value = _make_session("warmed", _PACK_CTX_A)
        custom_actor = Actor(
            subject="custom-replenisher",
            tenant_id="cognic-system",
            scopes=frozenset(),
            actor_type="service",
        )
        pool = _make_pool(backend=backend, service_actor=custom_actor)

        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)

        kwargs = backend.create.await_args.kwargs
        assert kwargs["actor"] is custom_actor, (
            "Replenisher MUST pass the configured service Actor to "
            "backend.create — R2 P1 reviewer fix. None smuggling "
            "would crash production T10 backend or create sandboxes "
            "without a service identity."
        )
        # Defence-in-depth: actor_type is 'service' so backend wiring
        # that branches on actor.actor_type sees the right tier.
        assert kwargs["actor"].actor_type == "service"


# ---------------------------------------------------------------------------
# R2 P2 — registered_pairs() public snapshot iterator
# ---------------------------------------------------------------------------


class TestRegisteredPairsSnapshot:
    """R2 P2 reviewer fix — replaces the write-only register API with
    a proper read seam. T10's background replenisher iterates the
    registered pairs without reaching into ``_registered``."""

    @pytest.mark.asyncio
    async def test_registered_pairs_returns_tenant_scoped_triples(
        self,
    ) -> None:
        pool = _make_pool()

        await pool.register(_POLICY, tenant_id="tenant-A", pack_context=_PACK_CTX_A)
        await pool.register(_POLICY, tenant_id="tenant-B", pack_context=_PACK_CTX_A)
        await pool.register(_POLICY, tenant_id="tenant-A", pack_context=_PACK_CTX_B)

        pairs = pool.registered_pairs()
        assert len(pairs) == 3

        # Each triple is (policy, tenant_id, pack_context) per the
        # registered-API shape; tenant-scoped per R1 P1.
        tenant_pack_pairs = {(tenant_id, pack_ctx.pack_id) for _, tenant_id, pack_ctx in pairs}
        assert tenant_pack_pairs == {
            ("tenant-A", "pack.a"),
            ("tenant-B", "pack.a"),
            ("tenant-A", "pack.b"),
        }

    @pytest.mark.asyncio
    async def test_registered_pairs_is_a_snapshot_not_a_live_view(
        self,
    ) -> None:
        """The snapshot returned by ``registered_pairs()`` MUST NOT
        reflect subsequent register() mutations — otherwise the
        replenisher's iteration loop would observe in-flight
        registrations + potentially process the same pair twice."""
        pool = _make_pool()

        await pool.register(_POLICY, tenant_id="tenant-A", pack_context=_PACK_CTX_A)
        snapshot = pool.registered_pairs()
        assert len(snapshot) == 1

        await pool.register(_POLICY, tenant_id="tenant-B", pack_context=_PACK_CTX_A)
        # Original snapshot unchanged
        assert len(snapshot) == 1
        # Fresh snapshot reflects the new pair
        assert len(pool.registered_pairs()) == 2


# ---------------------------------------------------------------------------
# R3 P2a — expired entries don't block capacity decisions
# ---------------------------------------------------------------------------


class TestExpiredEntriesDoNotBlockCapacity:
    """R3 P2a reviewer fix — precreate + release_or_destroy must
    evict expired entries BEFORE their capacity check, otherwise a
    quiet pool full of stale entries blocks replenishment + a fresh
    returned session gets destroyed while stale entries occupy the
    cap.

    These max=1 regressions are the sharpest form of the bug: at
    max=1, a single stale entry can monopolise the pool until cold-
    miss (precreate path) or destroy a fresh release (release path)."""

    @pytest.mark.asyncio
    async def test_precreate_with_max_one_evicts_expired_then_replenishes(
        self,
    ) -> None:
        """At max=1 with a stale entry occupying the slot: precreate
        must (1) destroy the stale entry, (2) call backend.create()
        to produce a fresh warm session, (3) leave the pool at size
        1 holding the fresh entry. Without R3 P2a the capacity check
        sees 1>=1 and returns early — fresh sandbox never produced."""
        import asyncio as _asyncio

        backend = AsyncMock()
        # First create() seeds the pool; subsequent precreate (post-
        # eviction) calls create() a second time for the replacement.
        backend.create.side_effect = [
            _make_session("stale", _PACK_CTX_A),
            _make_session("fresh", _PACK_CTX_A),
        ]
        pool = _make_pool(backend=backend, max_pool_size_per_key=1, idle_ttl_s=0.05)

        # Seed the pool to capacity, then wait past TTL.
        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        assert pool.current_size(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A) == 1
        await _asyncio.sleep(0.1)

        # Second precreate MUST evict the stale entry + replenish.
        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)

        # The stale entry's session was destroyed during the eviction
        # sweep; backend.create was called a second time for the
        # fresh warm session.
        assert backend.create.await_count == 2, (
            "precreate at cap with stale entry MUST evict + replenish; "
            "without R3 P2a fix the second create call never happens."
        )
        assert backend.destroy.await_count == 1
        assert pool.current_size(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A) == 1

    @pytest.mark.asyncio
    async def test_release_with_max_one_evicts_expired_then_deposits_fresh(
        self,
    ) -> None:
        """At max=1 with a stale entry occupying the slot: a fresh
        release_or_destroy must (1) destroy the stale entry, (2) deposit
        the fresh session, (3) NOT destroy the fresh session under
        capacity pressure. Without R3 P2a the capacity check sees 1>=1
        + destroys the fresh session while stale occupies the cap."""
        import asyncio as _asyncio

        backend = AsyncMock()
        pool = _make_pool(backend=backend, max_pool_size_per_key=1, idle_ttl_s=0.05)

        # Seed pool to capacity with a session that will go stale.
        stale = _make_session("stale", _PACK_CTX_A)
        await pool.release_or_destroy(stale)
        assert pool.current_size(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A) == 1
        await _asyncio.sleep(0.1)

        # Fresh release MUST evict stale + deposit fresh — NOT destroy fresh.
        fresh = _make_session("fresh", _PACK_CTX_A)
        await pool.release_or_destroy(fresh)

        # Stale was destroyed during the eviction sweep; fresh was
        # deposited, NOT destroyed by capacity pressure.
        backend.destroy.assert_awaited_with(stale)
        assert backend.destroy.await_count == 1, (
            "Without R3 P2a fix, fresh release would also be destroyed "
            "under the capacity-before-eviction path."
        )
        assert pool.current_size(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A) == 1
        # Subsequent checkout returns fresh (proves the deposit landed).
        result = await pool.checkout(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        assert result is fresh


# ---------------------------------------------------------------------------
# R3 P2b — warm-pool audit rows carry service-actor identity
# ---------------------------------------------------------------------------


class TestWarmPoolAuditRowsCarryServiceActorIdentity:
    """R3 P2b reviewer fix — warm-pool chain rows MUST attribute system
    actions to the service actor. R2 wired service_actor into
    backend.create() but the pool's OWN audit rows still emitted
    actor_id=""; examiners reading sandbox.warm_pool.* rows had no
    way to identify the actor responsible for the system action."""

    @pytest.mark.asyncio
    async def test_precreate_audit_row_carries_service_actor_subject(
        self,
    ) -> None:
        backend = AsyncMock()
        backend.create.return_value = _make_session("warmed", _PACK_CTX_A)
        custom_actor = Actor(
            subject="custom-replenisher-id",
            tenant_id="cognic-system",
            scopes=frozenset(),
            actor_type="service",
        )
        dh_store = _make_decision_history_store()
        pool = _make_pool(
            backend=backend,
            decision_history_store=dh_store,
            service_actor=custom_actor,
        )

        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)

        record_builder = dh_store.append_with_precondition.await_args.kwargs["record_builder"]
        record = record_builder(None)
        assert record.actor_id == "custom-replenisher-id", (
            "Warm-pool audit rows MUST carry the service actor's subject "
            "as actor_id — R3 P2b reviewer fix. Empty actor_id leaves "
            "chain rows actorless even when the service identity is "
            "available."
        )

    @pytest.mark.asyncio
    async def test_drain_audit_row_carries_service_actor_subject(
        self,
    ) -> None:
        backend = AsyncMock()
        backend.create.return_value = _make_session("warmed", _PACK_CTX_A)
        custom_actor = Actor(
            subject="drain-actor-id",
            tenant_id="cognic-system",
            scopes=frozenset(),
            actor_type="service",
        )
        dh_store = _make_decision_history_store()
        pool = _make_pool(
            backend=backend,
            decision_history_store=dh_store,
            service_actor=custom_actor,
        )
        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        dh_store.append_with_precondition.reset_mock()

        await pool.drain()

        # 1 drained event for the 1 populated key
        assert dh_store.append_with_precondition.await_count == 1
        record_builder = dh_store.append_with_precondition.await_args.kwargs["record_builder"]
        record = record_builder(None)
        assert record.decision_type == "sandbox.warm_pool.drained"
        assert record.actor_id == "drain-actor-id"


# ---------------------------------------------------------------------------
# T13 R6 coverage repair — close 8 missing lines + 8 missing branches on
# warm_pool.py per `tools/check_critical_coverage.py`'s 95% line / 90% branch
# floor (Sprint-8A T12 promotion). Tests target negative/error/race paths
# the existing suite did not exercise — NOT broad coverage padding.
# ---------------------------------------------------------------------------


class TestInitValidation:
    """warm_pool.py:256-259 — `__init__` ValueError gates per spec §11.

    Without these gates a degenerate pool (max=0 → can never deposit;
    idle_ttl=0 → instant-expire every entry) would silently misbehave
    long after construction. Fail-loud at construction time per the
    production-grade rule.
    """

    @pytest.mark.parametrize("bad_size", [0, -1])
    def test_init_raises_on_max_pool_size_per_key_below_one(self, bad_size: int) -> None:
        """warm_pool.py:256-257 — ValueError on max_pool_size_per_key < 1."""
        with pytest.raises(ValueError, match="max_pool_size_per_key must be >= 1"):
            _make_pool(max_pool_size_per_key=bad_size)

    @pytest.mark.parametrize("bad_ttl", [0.0, -1.0, -0.001])
    def test_init_raises_on_idle_ttl_s_zero_or_negative(self, bad_ttl: float) -> None:
        """warm_pool.py:258-259 — ValueError on idle_ttl_s <= 0."""
        with pytest.raises(ValueError, match="idle_ttl_s must be > 0"):
            _make_pool(idle_ttl_s=bad_ttl)


class TestDrainFlippedDuringPerKeyLockWait:
    """warm_pool.py:341-342 + 447-449 — `_drained` re-check inside the
    per-key lock per the R1 P1 race-window fix.

    Race window: a fast-path check at line 329 (precreate) or 437
    (release_or_destroy) sees `_drained=False`; another coroutine flips
    `_drained=True` and starts draining; the original coroutine is
    still waiting on `_lock_for(key)`. Without the in-lock re-check the
    coroutine would proceed to deposit (precreate) or release into a
    drained pool. The re-check (lines 341 + 447) is the load-bearing
    correctness gate — these tests exercise it by holding the per-key
    lock externally, flipping `_drained` while the in-flight call
    blocks on the lock, then releasing.
    """

    @pytest.mark.asyncio
    async def test_precreate_observes_drain_flipped_during_lock_acquisition(
        self,
    ) -> None:
        """warm_pool.py:341-342 — branch [341,342] precreate in-lock re-check."""
        import asyncio

        backend = AsyncMock()
        backend.create.return_value = _make_session("blocked", _PACK_CTX_A)
        pool = _make_pool(backend=backend)
        # Acquire the per-key lock externally to block precreate at line 333.
        from cognic_agentos.sandbox.warm_pool import _derive_pool_key

        pool_key = _derive_pool_key(_POLICY, _PACK_CTX_A, "t-1")
        lock = await pool._lock_for(pool_key)
        await lock.acquire()
        try:
            # Spawn precreate — it will hit the fast-path check at 329
            # (_drained=False), then block at line 333 acquiring the lock.
            precreate_task = asyncio.create_task(
                pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
            )
            # Yield so precreate runs up to the lock wait.
            await asyncio.sleep(0)
            # Flip _drained while precreate is blocked.
            pool._drained = True
        finally:
            # Release the lock; precreate acquires it + hits the
            # in-lock re-check at 341 + returns at 342.
            lock.release()
        await precreate_task
        # backend.create MUST NOT have been called — the in-lock
        # re-check short-circuited before the cold-create at line 354.
        backend.create.assert_not_called()

    @pytest.mark.asyncio
    async def test_release_destroys_when_drain_flipped_during_lock_acquisition(
        self,
    ) -> None:
        """warm_pool.py:447-449 — branch [447,448] release in-lock re-check."""
        import asyncio

        from cognic_agentos.sandbox.warm_pool import _derive_pool_key

        backend = AsyncMock()
        pool = _make_pool(backend=backend)
        pool_key = _derive_pool_key(_POLICY, _PACK_CTX_A, "t-1")
        lock = await pool._lock_for(pool_key)
        await lock.acquire()
        session = _make_session("racing", _PACK_CTX_A)
        try:
            # Spawn release_or_destroy — fast-path at 437 sees
            # _drained=False; blocks at 442 acquiring the lock.
            release_task = asyncio.create_task(pool.release_or_destroy(session))
            await asyncio.sleep(0)
            # Flip _drained while release blocks.
            pool._drained = True
        finally:
            lock.release()
        await release_task
        # In-lock re-check fires: backend.destroy called with the
        # session + return without depositing into the pool.
        backend.destroy.assert_awaited_once_with(session)
        # Pool MUST be empty — the session was destroyed, not deposited.
        assert pool.current_size(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A) == 0


class TestDrainEmptyAndRegisteredPaths:
    """warm_pool.py drain() additional branches.

    * Branch [497,493] — `if pool:` False on a key whose deque is
      empty (natural state after a prior drain).
    * Line 520-521 — `if key in self._registered:` True branch — the
      drained payload's policy + tenant come from the registered triple
      rather than the cold-released else fallback.
    """

    @pytest.mark.asyncio
    async def test_drain_skips_keys_with_empty_deque(self) -> None:
        """warm_pool.py drain branch [497,493] — empty pool skip.

        After the first drain, every key in _pools is an empty deque.
        A second drain iterates the same keys; `if pool:` is False so
        the snapshot stays empty + the audit loop emits zero events.
        """
        backend = AsyncMock()
        backend.create.return_value = _make_session("warm", _PACK_CTX_A)
        dh_store = _make_decision_history_store()
        pool = _make_pool(backend=backend, decision_history_store=dh_store)
        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        await pool.drain()  # First drain — emits one drained event
        dh_store.append_with_precondition.reset_mock()
        # _drained is set so subsequent register fails — but the keys
        # remain in _pools as empty deques. Second drain hits the
        # `if pool:` False branch for every key.
        await pool.drain()
        # Zero events emitted on the second drain — all pools were empty.
        dh_store.append_with_precondition.assert_not_called()

    @pytest.mark.asyncio
    async def test_drain_uses_registered_policy_for_audit_emission(
        self,
    ) -> None:
        """warm_pool.py:520-521 — drain emit uses registered triple's
        policy + tenant when the key IS in _registered.

        Existing tests in TestAuditEmission exercise the cold-released
        path (no register call → else branch fallback at 522-524). This
        test exercises the registered path so both arms of the
        if/else split at 520 are covered.
        """
        backend = AsyncMock()
        backend.create.return_value = _make_session("warm", _PACK_CTX_A)
        dh_store = _make_decision_history_store()
        pool = _make_pool(backend=backend, decision_history_store=dh_store)
        # register BEFORE precreate so the key is in _registered when
        # drain runs the per-key audit emission.
        await pool.register(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        await pool.precreate(_POLICY, tenant_id="t-1", pack_context=_PACK_CTX_A)
        dh_store.append_with_precondition.reset_mock()
        await pool.drain()
        # One drained event — the registered branch fired (policy + tenant
        # came from _registered, not from sessions[0]).
        assert dh_store.append_with_precondition.await_count == 1
        record_builder = dh_store.append_with_precondition.await_args.kwargs["record_builder"]
        record = record_builder(None)
        assert record.decision_type == "sandbox.warm_pool.drained"
        assert record.tenant_id == "t-1"


class TestLockForRace:
    """warm_pool.py:625-630 — `_lock_for` re-check inside `_locks_lock`.

    Race window: two coroutines call `_lock_for(key)` concurrently;
    both fail the fast-path check at 622 (no existing lock); both
    await `_locks_lock`; the first wins + allocates; the second wins
    next + MUST re-check at 628 + return the existing lock at 630
    rather than allocating a second lock. Without this re-check, two
    locks would exist for the same key + the per-key serialisation
    contract would silently break.
    """

    @pytest.mark.asyncio
    async def test_lock_for_returns_existing_when_race_resolves_inside_locks_lock(
        self,
    ) -> None:
        """warm_pool.py:629-630 — branch [629,630] in-lock re-check."""
        import asyncio

        pool = _make_pool()
        key = b"race-key"
        # Hold _locks_lock externally so both _lock_for coroutines
        # block at line 625 awaiting it.
        await pool._locks_lock.acquire()
        try:
            t1 = asyncio.create_task(pool._lock_for(key))
            t2 = asyncio.create_task(pool._lock_for(key))
            # Yield so both reach the await on _locks_lock.
            await asyncio.sleep(0)
            await asyncio.sleep(0)
        finally:
            pool._locks_lock.release()
        lock1 = await t1
        lock2 = await t2
        # Both calls MUST return the SAME lock object — the race
        # resolved correctly via the in-lock re-check.
        assert lock1 is lock2
        # And only one lock exists in the map.
        assert len([k for k in pool._locks if k == key]) == 1
