"""Sprint 7B.4 T4 — UIEventBroker primitive regressions.

protocol/ui_events.py is on the AGENTS.md critical-controls list +
stop-rule surface; these regressions defend:

  - the ContextVar-based event_id capture seam (resolves
    AppendResult.event_id from the typed event projected during
    the awaited DecisionHistoryStore.append — pinned by the
    no-subscribers + projector-missing + task-scoped regressions)
  - the per-subscriber tenant + run_id + family filter
  - the bounded asyncio.Queue + overflow accounting
  - the per-tenant cap + the reap-idle accounting

Fixture pattern mirrors tests/unit/protocol/test_ui_events_audit_mirror.py
(the canonical Sprint-6 emitter-test pattern). Module-local fixtures
(not a shared conftest) keep the T4 surface self-contained.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.protocol.ui_events import (
    AppendResult,
    DecisionAuditEventAppended,
    FrontendActionSubmitted,
    PolicyRBACDenied,
    TenantConnectionCapExceeded,
    UIEventBroker,
    UIEventEmitter,
)

# =============================================================================
# Fixtures — mirror the Sprint-6 emitter-test pattern
# =============================================================================


@pytest.fixture
async def engine(tmp_path: Any) -> AsyncIterator[AsyncEngine]:
    url = f"sqlite+aiosqlite:///{tmp_path / 'broker.db'}"
    eng: AsyncEngine = create_async_engine(url)
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id,
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=datetime.now(UTC),
                )
            )
    yield eng
    await eng.dispose()


@pytest.fixture
def audit_store(engine: AsyncEngine) -> AuditStore:
    return AuditStore(engine)


@pytest.fixture
def dh_store(engine: AsyncEngine) -> DecisionHistoryStore:
    return DecisionHistoryStore(engine)


@pytest.fixture
def settings() -> Settings:
    return Settings()


@pytest.fixture
def emitter(audit_store: AuditStore, dh_store: DecisionHistoryStore) -> UIEventEmitter:
    return UIEventEmitter(audit_store=audit_store, decision_history_store=dh_store)


@pytest.fixture
def broker(
    dh_store: DecisionHistoryStore, settings: Settings, emitter: UIEventEmitter
) -> UIEventBroker:
    """Standard broker: registered as a hook on the emitter so chain
    appends drive the broker fan-out path."""
    b = UIEventBroker(decision_history_store=dh_store, settings=settings)
    b.register_with_emitter(emitter)
    return b


@pytest.fixture
def broker_with_no_subscribers(
    dh_store: DecisionHistoryStore, settings: Settings, emitter: UIEventEmitter
) -> UIEventBroker:
    """Broker with the emitter wired but ZERO subscribers — pins that
    AppendResult.event_id resolution is independent of subscriber state."""
    b = UIEventBroker(decision_history_store=dh_store, settings=settings)
    b.register_with_emitter(emitter)
    return b


@pytest.fixture
def low_cap_settings() -> Settings:
    """Settings with per-tenant cap = 2 for the cap-exceeded regression."""
    return Settings(ui_event_stream_per_tenant_cap=2)


@pytest.fixture
def low_cap_broker(
    dh_store: DecisionHistoryStore,
    low_cap_settings: Settings,
    emitter: UIEventEmitter,
) -> UIEventBroker:
    b = UIEventBroker(decision_history_store=dh_store, settings=low_cap_settings)
    b.register_with_emitter(emitter)
    return b


@pytest.fixture
def small_queue_settings() -> Settings:
    """Settings with per-subscriber queue maxsize = 16 (the floor) for
    the overflow regression."""
    return Settings(ui_event_stream_queue_maxsize=16)


@pytest.fixture
def small_queue_broker(
    dh_store: DecisionHistoryStore,
    small_queue_settings: Settings,
    emitter: UIEventEmitter,
) -> UIEventBroker:
    b = UIEventBroker(decision_history_store=dh_store, settings=small_queue_settings)
    b.register_with_emitter(emitter)
    return b


# =============================================================================
# AppendResult event_id resolution
# =============================================================================


class TestBrokerAppendReturnsEventIdMatchingProjectedEvent:
    """Happy path: every broker append seam returns a full AppendResult
    whose `event_id` matches the typed event projected during the awaited
    DecisionHistoryStore.append. The id is deterministic — derived from
    (chain_id, sequence, ordinal, family.type) via the T3 16-byte cursor
    payload — so route handlers can hand it back as a resume cursor."""

    @pytest.mark.asyncio
    async def test_append_frontend_action_submitted_returns_valid_result(
        self, broker: UIEventBroker
    ) -> None:
        result = await broker.append_frontend_action_submitted(
            request_id="portal-req-aabbcc",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id="cli-1",
            payload_digest="sha256:dead",
            tenant_id="t1",
        )
        assert isinstance(result, AppendResult)
        assert result.record_id is not None
        assert isinstance(result.chain_hash, bytes) and len(result.chain_hash) == 32
        # event_id matches the T3 wire format (`evt_` + 26 base32).
        assert result.event_id.startswith("evt_")
        assert len(result.event_id) == 30

    @pytest.mark.asyncio
    async def test_append_frontend_action_accepted_returns_valid_result(
        self, broker: UIEventBroker
    ) -> None:
        # First submit → captures the submitted event_id for the accept's
        # submitted_event_id payload field.
        submitted = await broker.append_frontend_action_submitted(
            request_id="portal-req-sub-1",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:11",
            tenant_id="t1",
        )
        accepted = await broker.append_frontend_action_accepted(
            request_id="portal-req-acc-1",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            submitted_event_id=submitted.event_id,
            tenant_id="t1",
        )
        assert isinstance(accepted, AppendResult)
        assert accepted.event_id.startswith("evt_") and len(accepted.event_id) == 30
        # Different sequence → different event_id from the submit.
        assert accepted.event_id != submitted.event_id

    @pytest.mark.asyncio
    async def test_append_frontend_action_rejected_returns_valid_result(
        self, broker: UIEventBroker
    ) -> None:
        submitted = await broker.append_frontend_action_submitted(
            request_id="portal-req-sub-2",
            action_class="deny",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:22",
            tenant_id="t1",
        )
        rejected = await broker.append_frontend_action_rejected(
            request_id="portal-req-rej-2",
            action_class="deny",
            actor_subject="u1",
            client_correlation_id=None,
            submitted_event_id=submitted.event_id,
            reason="action_backend_deferred_deny",
            tenant_id="t1",
        )
        assert isinstance(rejected, AppendResult)
        assert rejected.event_id.startswith("evt_")

    @pytest.mark.asyncio
    async def test_emit_rbac_denial_returns_valid_result(self, broker: UIEventBroker) -> None:
        result = await broker.emit_rbac_denial(
            denial_type="scope_not_held",
            actor_subject="u1",
            request_id="portal-req-denial-1",
            http_status=403,
            tenant_id="t1",
            required_scope="ui.action.approve",
        )
        assert isinstance(result, AppendResult)
        assert result.event_id.startswith("evt_") and len(result.event_id) == 30


class TestBrokerAppendReturnsEventIdWithNoSubscribers:
    """Pin that capture is independent of subscriber state — POST /actions
    must always emit submitted/resolution cursors even with zero UIs
    watching. This is the load-bearing invariant for ActionResponse:
    every action POST returns a valid submitted_event_id regardless of
    whether anyone is listening."""

    @pytest.mark.asyncio
    async def test_zero_subscribers_still_returns_valid_event_id(
        self, broker_with_no_subscribers: UIEventBroker
    ) -> None:
        # Sanity: no subscribers registered.
        assert broker_with_no_subscribers._subscribers == []
        result = await broker_with_no_subscribers.append_frontend_action_submitted(
            request_id="portal-req-noop",
            action_class="cancel_run",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:00",
            tenant_id="t1",
        )
        assert result.event_id and result.event_id.startswith("evt_")


class TestBrokerAppendRaisesWhenTypedProjectorMissing:
    """Fail-loud regression: if a future decision_type slips through the
    broker append seam without a corresponding entry in
    _DECISION_HISTORY_TYPED_PROJECTORS, the ContextVar stays unset and
    the broker raises RuntimeError. Production-grade rule — no silent
    None event_id falling through to the route handler."""

    @pytest.mark.asyncio
    async def test_raises_runtime_error_when_projector_unwired(
        self, broker: UIEventBroker, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cognic_agentos.protocol import ui_events

        monkeypatch.setattr(ui_events, "_DECISION_HISTORY_TYPED_PROJECTORS", {})
        with pytest.raises(RuntimeError, match="no typed event projected"):
            await broker.append_frontend_action_submitted(
                request_id="portal-req-z",
                action_class="approve",
                actor_subject="u1",
                client_correlation_id=None,
                payload_digest="sha256:11",
                tenant_id="t1",
            )

    @pytest.mark.asyncio
    async def test_pending_event_id_reset_prevents_stale_reuse(
        self, broker: UIEventBroker, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Threat-model regression: the `_PENDING_TYPED_EVENT_ID.set(None)`
        at the top of `_append` is LOAD-BEARING. Without it, a second
        append in the SAME asyncio task whose decision_type has NO
        projector would silently inherit the first append's event_id —
        returning a wrong cursor (pointing at the previous row) instead
        of raising RuntimeError.

        Pinned by: first append succeeds and sets the ContextVar; then
        monkeypatch the projector table to empty; the second append on
        the SAME task MUST refuse with RuntimeError, NOT return the
        first append's event_id."""
        from cognic_agentos.protocol import ui_events

        # First append: typed projector fires; ContextVar holds the result.
        first = await broker.append_frontend_action_submitted(
            request_id="portal-req-first",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:11",
            tenant_id="t1",
        )
        assert first.event_id.startswith("evt_")

        # Now empty the projector table. The next append's chain row will
        # have no matching projector, so the ContextVar would carry the
        # stale `first.event_id` UNLESS the reset at the top of `_append`
        # fires. The reset converts this scenario into the RuntimeError
        # fail-loud path.
        monkeypatch.setattr(ui_events, "_DECISION_HISTORY_TYPED_PROJECTORS", {})
        with pytest.raises(RuntimeError, match="no typed event projected"):
            await broker.append_frontend_action_accepted(
                request_id="portal-req-second",
                action_class="approve",
                actor_subject="u1",
                client_correlation_id=None,
                submitted_event_id=first.event_id,
                tenant_id="t1",
            )


class TestBrokerAppendIsTaskScoped:
    """ContextVar capture MUST be task-scoped — every append resolves the
    event_id of its OWN typed projection, never a stale value from a
    previous append. The `_append` body's `set(None)` at the top is the
    load-bearing reset: without it, an unmatched decision_type would
    silently return a previous typed event_id instead of raising
    RuntimeError.

    Test pattern note: sqlite-aiosqlite serializes ALL writes against a
    single SQLite database, so `asyncio.gather` of N appends would race
    for sequence=1 and fail with a UNIQUE-constraint violation BEFORE
    proving anything about ContextVar. The sequential pattern below
    exercises N distinct invocations of `_append`, each of which goes
    through the full set(None) → await DH-store → ContextVar.get() round
    trip. A broken ContextVar implementation (e.g. module-global mutable)
    would either return stale event_ids or return None from .get() and
    raise RuntimeError — both fail this regression. The cross-task
    isolation property of ContextVar itself is Python-library contract
    and pinned by CPython's own test suite; we do NOT need to re-prove it.
    """

    @pytest.mark.asyncio
    async def test_sequential_appends_each_resolve_own_typed_event_id(
        self, broker: UIEventBroker
    ) -> None:
        from cognic_agentos.protocol.ui_events import _decode_chain_cursor

        results: list[AppendResult] = []
        for i in range(8):
            r = await broker.append_frontend_action_submitted(
                request_id=f"portal-req-tag{i}",
                action_class="approve",
                actor_subject=f"u_tag{i}",
                client_correlation_id=None,
                payload_digest=f"sha256:tag{i}",
                tenant_id="t1",
            )
            results.append(r)
        ids = [r.event_id for r in results]
        # All 8 event_ids unique — different sequence numbers → different
        # deterministic cursors (T3 cursor invariant).
        assert len(set(ids)) == 8
        # Each cursor decodes to a distinct sequence under the same
        # decision_history chain. The sequences are CONSECUTIVE (1..8)
        # because sqlite serialized the writes.
        sequences = [_decode_chain_cursor(eid).sequence for eid in ids]
        assert sequences == list(range(1, 9))


class TestBrokerCaptureFiltersOutDecisionAuditMirror:
    """ContextVar capture is filtered to `_TYPED_PROJECTION_CLASSES` —
    the always-emitted `decision_audit.event_appended` mirror at ordinal
    1 must NOT overwrite the typed event_id captured at ordinal 0. Pins
    the canonical projection order (typed first, mirror second) +
    ensures the broker resolves the TYPED cursor not the MIRROR cursor."""

    @pytest.mark.asyncio
    async def test_event_id_matches_typed_event_not_mirror(self, broker: UIEventBroker) -> None:
        result = await broker.append_frontend_action_submitted(
            request_id="portal-req-cap-1",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:cap",
            tenant_id="t1",
        )
        # Decode the cursor — the type_hash MUST be the frontend_action.submitted
        # hash, NOT the decision_audit.event_appended hash. If the broker
        # mistakenly captured the mirror event_id, type_hash would be the
        # decision_audit hash and this assertion would fail.
        from cognic_agentos.protocol.ui_events import _decode_chain_cursor

        cursor = _decode_chain_cursor(result.event_id)
        import hashlib

        expected_typed_hash = hashlib.sha256(b"frontend_action.submitted").digest()[:6]
        unexpected_mirror_hash = hashlib.sha256(b"decision_audit.event_appended").digest()[:6]
        assert cursor.type_hash == expected_typed_hash
        assert cursor.type_hash != unexpected_mirror_hash
        # Also: ordinal 0 (typed projector slot), not ordinal 1 (mirror slot).
        assert cursor.ordinal == 0


# =============================================================================
# Subscriber lifecycle — register, cap, overflow, reap
# =============================================================================


class TestRegisterSubscriberAndFanout:
    """Standard subscriber lifecycle — register, observe events via the
    bounded queue, unregister."""

    @pytest.mark.asyncio
    async def test_subscriber_receives_tenant_event(self, broker: UIEventBroker) -> None:
        sub = broker.register_subscriber(tenant_id="t1")
        try:
            await broker.append_frontend_action_submitted(
                request_id="portal-req-fan-1",
                action_class="approve",
                actor_subject="u1",
                client_correlation_id=None,
                payload_digest="sha256:fan",
                tenant_id="t1",
            )
            # Typed event lands in the subscriber's queue; decision_audit
            # mirror lands too (Wave-1 _SSE_WAVE_1_STREAMED_FAMILIES includes
            # both `frontend_action` and `decision_audit`).
            evt1 = await asyncio.wait_for(sub.queue.get(), timeout=0.5)
            evt2 = await asyncio.wait_for(sub.queue.get(), timeout=0.5)
            kinds = {type(evt1).__name__, type(evt2).__name__}
            assert "FrontendActionSubmitted" in kinds
            assert "DecisionAuditEventAppended" in kinds
        finally:
            broker.unregister_subscriber(sub)

    @pytest.mark.asyncio
    async def test_subscriber_skips_other_tenant_events(self, broker: UIEventBroker) -> None:
        sub_t1 = broker.register_subscriber(tenant_id="t1")
        try:
            await broker.append_frontend_action_submitted(
                request_id="portal-req-cross-1",
                action_class="approve",
                actor_subject="u_other",
                client_correlation_id=None,
                payload_digest="sha256:cross",
                tenant_id="t2",  # different tenant
            )
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(sub_t1.queue.get(), timeout=0.15)
        finally:
            broker.unregister_subscriber(sub_t1)


class TestTenantConnectionCapExceeded:
    """The per-tenant cap refuses registration with a closed-enum
    exception type (NOT a silent drop) — Wave-1 SSE deployments
    bound concurrent connections per tenant to protect the broker
    from a single-tenant exhaustion attack."""

    def test_register_beyond_cap_raises(self, low_cap_broker: UIEventBroker) -> None:
        sub_a = low_cap_broker.register_subscriber(tenant_id="t1")
        sub_b = low_cap_broker.register_subscriber(tenant_id="t1")
        try:
            with pytest.raises(TenantConnectionCapExceeded) as exc_info:
                low_cap_broker.register_subscriber(tenant_id="t1")
            # Exception carries the tenant + cap for operator diagnostics.
            assert exc_info.value.tenant_id == "t1"
            assert exc_info.value.cap == 2
        finally:
            low_cap_broker.unregister_subscriber(sub_a)
            low_cap_broker.unregister_subscriber(sub_b)

    def test_other_tenants_unaffected_by_cap(self, low_cap_broker: UIEventBroker) -> None:
        """The cap is per-tenant — tenant t1 hitting the cap MUST NOT
        block tenant t2 from registering."""
        a = low_cap_broker.register_subscriber(tenant_id="t1")
        b = low_cap_broker.register_subscriber(tenant_id="t1")
        try:
            # Tenant t2 still has full budget.
            c = low_cap_broker.register_subscriber(tenant_id="t2")
            low_cap_broker.unregister_subscriber(c)
        finally:
            low_cap_broker.unregister_subscriber(a)
            low_cap_broker.unregister_subscriber(b)

    def test_unregister_frees_slot(self, low_cap_broker: UIEventBroker) -> None:
        """After unregister, a new register on the same tenant succeeds."""
        a = low_cap_broker.register_subscriber(tenant_id="t1")
        b = low_cap_broker.register_subscriber(tenant_id="t1")
        low_cap_broker.unregister_subscriber(a)
        c = low_cap_broker.register_subscriber(tenant_id="t1")
        low_cap_broker.unregister_subscriber(b)
        low_cap_broker.unregister_subscriber(c)


class TestSubscriberOverflowDoesNotSilentlyDrop:
    """Per ADR-020 + the design spec: a full subscriber queue MUST NOT
    silently drop events; the broker increments `overflow_count` so
    operators can detect slow consumers. The queue stays bounded — no
    unbounded memory growth on a hung subscriber."""

    @pytest.mark.asyncio
    async def test_overflow_count_increments_on_queue_full(
        self, small_queue_broker: UIEventBroker
    ) -> None:
        sub = small_queue_broker.register_subscriber(tenant_id="t1")
        try:
            assert sub.overflow_count == 0
            # Fill the queue beyond maxsize=16. Each broker.append emits
            # 2 events (typed + mirror) so 10 appends produce 20 enqueues.
            for i in range(20):
                await small_queue_broker.append_frontend_action_submitted(
                    request_id=f"portal-req-overflow-{i}",
                    action_class="approve",
                    actor_subject="u1",
                    client_correlation_id=None,
                    payload_digest=f"sha256:o{i}",
                    tenant_id="t1",
                )
            # Queue stayed bounded.
            assert sub.queue.qsize() <= 16
            # Overflow accounting fired.
            assert sub.overflow_count > 0
        finally:
            small_queue_broker.unregister_subscriber(sub)


class TestReapIdleClosesStaleSubscribers:
    """`reap_idle(now)` is called by the SSE route's reap task on a
    cadence; subscribers idle past `ui_event_stream_idle_timeout_s`
    are unregistered. Returns the count of reaped subscribers so the
    operator log can surface deployment-wide cleanup activity."""

    @pytest.mark.asyncio
    async def test_idle_subscriber_reaped(self, broker: UIEventBroker) -> None:
        sub = broker.register_subscriber(tenant_id="t1")
        # Force last_activity_at into the past.
        sub.last_activity_at = datetime.now(UTC) - timedelta(seconds=200)
        reaped = broker.reap_idle(datetime.now(UTC))
        assert reaped == 1
        assert sub not in broker._subscribers

    @pytest.mark.asyncio
    async def test_active_subscriber_not_reaped(self, broker: UIEventBroker) -> None:
        sub = broker.register_subscriber(tenant_id="t1")
        try:
            sub.last_activity_at = datetime.now(UTC)
            reaped = broker.reap_idle(datetime.now(UTC))
            assert reaped == 0
            assert sub in broker._subscribers
        finally:
            broker.unregister_subscriber(sub)


# =============================================================================
# emit_rbac_denial — chain row + PolicyRBACDenied projection
# =============================================================================


class TestEmitRBACDenialProjectsPolicyRBACDenied:
    """`emit_rbac_denial` appends `rbac.<denial_type>` chain rows that
    flow through the prefix-matched projector to PolicyRBACDenied.
    Verifies the full broker → DH-store → emitter → typed projection
    → subscriber fan-out path end-to-end."""

    @pytest.mark.asyncio
    async def test_subscriber_receives_policy_rbac_denied(self, broker: UIEventBroker) -> None:
        sub = broker.register_subscriber(tenant_id="t1")
        try:
            await broker.emit_rbac_denial(
                denial_type="scope_not_held",
                actor_subject="u1",
                request_id="portal-req-denial-end-to-end",
                http_status=403,
                tenant_id="t1",
                required_scope="ui.action.approve",
            )
            # Collect events until we see both the typed event + the mirror.
            received: list[Any] = []
            for _ in range(2):
                received.append(await asyncio.wait_for(sub.queue.get(), timeout=0.5))
            kinds = {type(e).__name__ for e in received}
            assert "PolicyRBACDenied" in kinds
            assert "DecisionAuditEventAppended" in kinds
            # Typed event carries the denial_type in its data payload.
            typed = next(e for e in received if isinstance(e, PolicyRBACDenied))
            assert typed.data["denial_type"] == "scope_not_held"
            assert typed.data["required_scope"] == "ui.action.approve"
        finally:
            broker.unregister_subscriber(sub)

    @pytest.mark.asyncio
    async def test_invalid_denial_type_refuses_before_chain_append(
        self, broker: UIEventBroker, dh_store: DecisionHistoryStore
    ) -> None:
        """R1 #2 regression: `emit_rbac_denial` MUST validate `denial_type`
        against the 9-value :data:`RBACDenialType` closed enum BEFORE
        appending a chain row. The type annotation alone is build-time
        only; callers using `Any` (or string literals) can bypass mypy,
        so the runtime guard is the load-bearing seam.

        Threat model: a caller typo like `denial_type='scope_not_helt'`
        would otherwise persist `rbac.scope_not_helt` to the chain (an
        out-of-vocabulary row). The downstream projector would refuse to
        type it (R1 #1 fix), so the row becomes mirror-only — but the
        chain still has a permanent out-of-vocab decision_type that
        examiners can't classify. R1 #2 closes this by refusing at the
        broker seam BEFORE the append fires.

        Pinned: (a) ValueError raised; (b) message names the offending
        value AND the 9-value closed set; (c) NO chain row written
        (verified by checking the DH chain head sequence is unchanged
        across the refusal call).
        """
        from sqlalchemy import select

        from cognic_agentos.core.audit import _chain_heads

        async def _read_dh_sequence() -> int:
            async with dh_store._engine.connect() as conn:
                row = (
                    await conn.execute(
                        select(_chain_heads.c.latest_sequence).where(
                            _chain_heads.c.chain_id == "decision_history"
                        )
                    )
                ).one()
                return int(row[0])

        before_seq = await _read_dh_sequence()

        with pytest.raises(ValueError, match="not in the 9-value RBACDenialType"):
            await broker.emit_rbac_denial(
                denial_type="not_a_real_denial",  # type: ignore[arg-type]
                actor_subject="u1",
                request_id="portal-req-bad-vocab",
                http_status=403,
                tenant_id="t1",
            )

        # NO chain row appended on refusal — sequence head unchanged.
        after_seq = await _read_dh_sequence()
        assert after_seq == before_seq, (
            f"chain sequence changed across refusal: {before_seq} → {after_seq} "
            f"(emit_rbac_denial should have raised BEFORE the append)"
        )

    @pytest.mark.asyncio
    async def test_unauthenticated_denial_with_tenant_none(self, broker: UIEventBroker) -> None:
        """Per P1 #5 (design spec): when actor is unresolved
        (actor_unauthenticated / actor_binder_not_configured), the
        caller passes tenant_id=None. The chain row still writes (audit
        surface preserved); SSE subscribers filter by event.tenant so
        unauth denials never reach any tenant's stream."""
        sub = broker.register_subscriber(tenant_id="t1")
        try:
            result = await broker.emit_rbac_denial(
                denial_type="actor_unauthenticated",
                actor_subject=None,
                request_id="portal-req-unauth-1",
                http_status=403,
                tenant_id=None,
            )
            assert result.event_id.startswith("evt_")
            # Subscriber for t1 must NOT receive the tenant=None event.
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(sub.queue.get(), timeout=0.15)
        finally:
            broker.unregister_subscriber(sub)


# =============================================================================
# Decision-audit mirror still fires (Sprint-6 regression — must stay green)
# =============================================================================


class TestDecisionAuditMirrorStillEmittedAfterT4Refactor:
    """Sprint-6 invariant: every DH append produces a
    decision_audit.event_appended mirror. T4 extends
    `_on_decision_append` with typed dispatch at ordinal 0 — this test
    confirms the mirror at ordinal 1 still fires for both known and
    unknown decision_types."""

    @pytest.mark.asyncio
    async def test_unknown_decision_type_only_emits_mirror(
        self, broker: UIEventBroker, dh_store: DecisionHistoryStore
    ) -> None:
        from cognic_agentos.core.decision_history import DecisionRecord

        sub = broker.register_subscriber(tenant_id="t1")
        try:
            # Append a decision_type with NO typed projector entry.
            await dh_store.append(
                DecisionRecord(
                    decision_type="something.unmapped",
                    request_id="portal-req-mirror-only",
                    tenant_id="t1",
                    payload={"k": "v"},
                )
            )
            # Exactly ONE event reaches the subscriber: the decision_audit
            # mirror. No typed event because no projector matched.
            evt = await asyncio.wait_for(sub.queue.get(), timeout=0.5)
            assert isinstance(evt, DecisionAuditEventAppended)
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(sub.queue.get(), timeout=0.15)
        finally:
            broker.unregister_subscriber(sub)

    @pytest.mark.asyncio
    async def test_known_decision_type_emits_typed_first_then_mirror(
        self, broker: UIEventBroker
    ) -> None:
        sub = broker.register_subscriber(tenant_id="t1")
        try:
            await broker.append_frontend_action_submitted(
                request_id="portal-req-order-1",
                action_class="approve",
                actor_subject="u1",
                client_correlation_id=None,
                payload_digest="sha256:ord",
                tenant_id="t1",
            )
            # Ordinal-canonical order: typed first, mirror second.
            first = await asyncio.wait_for(sub.queue.get(), timeout=0.5)
            second = await asyncio.wait_for(sub.queue.get(), timeout=0.5)
            assert isinstance(first, FrontendActionSubmitted)
            assert isinstance(second, DecisionAuditEventAppended)
        finally:
            broker.unregister_subscriber(sub)
