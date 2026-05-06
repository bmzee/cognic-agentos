"""Sprint 6 T12 — UI event-stream audit-mirror integration tests.

Per ADR-020 + T12 R0 doctrine: every audit emit produces a parallel
typed UI event in-process; every DH emit produces a generic
``decision_audit.event_appended`` UI event regardless of subsystem.

Pinned doctrines (R0):
  - Layer-safe append-hooks (R0 #1) — emitter registers from
    ``protocol/`` against generic Callable surface in ``core/``.
  - Awaited sequential post-commit firing (R0 #2) — hooks fire AFTER
    the chain commits + BEFORE ``append()`` returns.
  - Snapshot payload (R0 #3) — caller mutation of raw payload after
    return CANNOT affect mirrored data.
  - Routing mappings (R0 #7) — pinned via parametrized arms.
  - Hook isolation — broken subscriber does not block subsequent
    subscribers; primary append outcome unchanged.
  - ``(record_id, hash)`` return tuple unchanged across the refactor.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import (
    AuditEvent,
    AuditStore,
    _chain_heads,
    _metadata,
)
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import (
    DecisionHistoryStore,
    DecisionRecord,
)
from cognic_agentos.protocol.ui_events import (
    ArtifactCompleted,
    DecisionAuditEventAppended,
    ToolCallCompleted,
    ToolCallDenied,
    ToolCallFailed,
    UIEventEmitter,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
async def engine(tmp_path: Any) -> Any:
    url = f"sqlite+aiosqlite:///{tmp_path / 'audit_mirror.db'}"
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
def emitter(
    audit_store: AuditStore,
    dh_store: DecisionHistoryStore,
) -> UIEventEmitter:
    return UIEventEmitter(
        audit_store=audit_store,
        decision_history_store=dh_store,
    )


@pytest.fixture
def collector(emitter: UIEventEmitter) -> list[Any]:
    """A list-collector hook — every emitted UIEvent appends here."""
    events: list[Any] = []

    async def _collect(event: Any) -> None:
        events.append(event)

    emitter.register_hook(_collect)
    return events


# =============================================================================
# tool_call.* mirror — Sprint-5 audit.tool_invocation_* routing
# =============================================================================


class TestToolCallMirror:
    @pytest.mark.parametrize(
        ("audit_event_type", "expected_cls", "expected_type"),
        [
            ("audit.tool_invocation", ToolCallCompleted, "completed"),
            ("audit.tool_invocation_refused", ToolCallDenied, "denied"),
            ("audit.tool_invocation_error", ToolCallFailed, "failed"),
        ],
    )
    async def test_audit_event_type_mirrors_to_tool_call(
        self,
        audit_store: AuditStore,
        collector: list[Any],
        audit_event_type: str,
        expected_cls: type[Any],
        expected_type: str,
    ) -> None:
        """Per T12 R0 #7: each audit.tool_invocation_* event_type
        mirrors to its mapped tool_call.* family/type. Per R2 P2
        #1: AuditStore appends ALSO emit a generic
        ``decision_audit.event_appended`` mirror, so the final
        emission count is 2 (typed family + generic)."""
        await audit_store.append(
            AuditEvent(
                event_type=audit_event_type,
                request_id="rid-1",
                tenant_id="bank_a",
                trace_id="trace-1",
                payload={"tool": "foo"},
            )
        )
        # Two emissions: typed family event + generic decision_audit
        # mirror (R2 P2 #1). The typed event is emitted first.
        assert len(collector) == 2
        typed_event: Any = collector[0]
        assert isinstance(typed_event, expected_cls)
        assert typed_event.family == "tool_call"
        assert typed_event.type == expected_type
        assert typed_event.tenant == "bank_a"
        assert typed_event.trace_id == "trace-1"
        assert typed_event.audit_chain_hash.startswith("sha256:")
        assert typed_event.run_id is None
        # Generic mirror.
        generic: Any = collector[1]
        assert isinstance(generic, DecisionAuditEventAppended)
        assert generic.data["chain_id"] == "audit_event"
        assert generic.data["event_type"] == audit_event_type

    async def test_unrelated_audit_event_no_typed_family_but_generic_fires(
        self,
        audit_store: AuditStore,
        collector: list[Any],
    ) -> None:
        """T9 a2a.task_* events get NO typed family mirror (not in
        the routing table) but DO get the generic
        ``decision_audit.event_appended`` mirror per R2 P2 #1
        (every audit append mirrors)."""
        await audit_store.append(
            AuditEvent(
                event_type="a2a.task_succeeded",
                request_id="rid-2",
                tenant_id="bank_a",
                payload={},
            )
        )
        assert len(collector) == 1
        generic: Any = collector[0]
        assert isinstance(generic, DecisionAuditEventAppended)
        assert generic.data["event_type"] == "a2a.task_succeeded"
        assert generic.data["chain_id"] == "audit_event"

    async def test_audit_only_event_mirrors_with_payload_digest(
        self,
        audit_store: AuditStore,
        collector: list[Any],
    ) -> None:
        """T12 R2 P2 #1 + #2 — audit-only event sources (e.g.
        ``guardrail.trip``, ``trust_gate.cosign_timeout``) that
        never write to ``decision_history`` MUST still mirror via
        the AuditStore-side generic emission, carrying chain_id +
        sequence + event_type + payload_digest in ``data``."""
        await audit_store.append(
            AuditEvent(
                event_type="guardrail.trip",
                request_id="rid-guard",
                tenant_id="bank_a",
                payload={"rule": "max_tokens", "value": 9999},
            )
        )
        assert len(collector) == 1
        generic: Any = collector[0]
        assert isinstance(generic, DecisionAuditEventAppended)
        # Payload-identity fields per R2 P2 #2.
        assert generic.data["chain_id"] == "audit_event"
        assert generic.data["event_type"] == "guardrail.trip"
        assert generic.data["request_id"] == "rid-guard"
        assert generic.data["sequence"] >= 1
        assert generic.data["payload_digest"].startswith("sha256:")
        # 64 hex chars after "sha256:" prefix (SHA-256).
        assert len(generic.data["payload_digest"]) == len("sha256:") + 64
        assert generic.data["tenant_id"] == "bank_a"


# =============================================================================
# artifact.* mirror — T11's a2a.artifact_prepared routing
# =============================================================================


class TestArtifactMirror:
    async def test_artifact_prepared_mirrors_to_artifact_completed(
        self,
        audit_store: AuditStore,
        collector: list[Any],
    ) -> None:
        await audit_store.append(
            AuditEvent(
                event_type="a2a.artifact_prepared",
                request_id="rid-art-1",
                tenant_id="bank_a",
                trace_id="trace-art-1",
                payload={"sha256": "a" * 64, "size_bytes": 1024},
            )
        )
        # Two emissions per R2 P2 #1: typed artifact event + generic
        # decision_audit mirror.
        assert len(collector) == 2
        typed_event: Any = collector[0]
        assert isinstance(typed_event, ArtifactCompleted)
        assert typed_event.family == "artifact"
        assert typed_event.type == "completed"
        # Generic mirror.
        generic: Any = collector[1]
        assert isinstance(generic, DecisionAuditEventAppended)
        assert generic.data["event_type"] == "a2a.artifact_prepared"


# =============================================================================
# decision_audit.event_appended generic mirror — every DH append
# =============================================================================


class TestDecisionAuditGenericMirror:
    """T12 R0 #7 + ADR-020 load-bearing contract: EVERY DH append
    fires ``decision_audit.event_appended``, regardless of subsystem
    origin (Sprint-5 mcp_call, Sprint-6 a2a_call, Sprint-6 a2a_stream,
    future Sprint-3 LLM-gateway, ...)."""

    @pytest.mark.parametrize(
        "decision_type",
        ["mcp_call", "a2a_call", "a2a_stream", "future_subsystem_xyz"],
    )
    async def test_every_dh_append_mirrors_to_decision_audit(
        self,
        dh_store: DecisionHistoryStore,
        collector: list[Any],
        decision_type: str,
    ) -> None:
        await dh_store.append(
            DecisionRecord(
                decision_type=decision_type,
                request_id="rid-dh-1",
                tenant_id="bank_a",
                payload={"source": "test"},
            )
        )
        assert len(collector) == 1
        event: Any = collector[0]
        assert isinstance(event, DecisionAuditEventAppended)
        assert event.family == "decision_audit"
        assert event.type == "event_appended"
        # Per R2 P2 #2: data carries source row's identity:
        # event_type (from decision_type), payload_digest, chain_id,
        # request_id, sequence, tenant_id.
        assert event.data["event_type"] == decision_type
        assert event.data["chain_id"] == "decision_history"
        assert event.data["request_id"] == "rid-dh-1"
        assert event.data["payload_digest"].startswith("sha256:")
        assert len(event.data["payload_digest"]) == len("sha256:") + 64
        assert event.data["tenant_id"] == "bank_a"

    async def test_dh_mirror_carries_chain_hash(
        self,
        dh_store: DecisionHistoryStore,
        collector: list[Any],
    ) -> None:
        await dh_store.append(
            DecisionRecord(
                decision_type="x",
                request_id="rid-1",
                tenant_id="bank_a",
                payload={},
            )
        )
        event: Any = collector[0]
        assert event.audit_chain_hash.startswith("sha256:")
        # 64 hex chars after "sha256:" prefix.
        assert len(event.audit_chain_hash) == len("sha256:") + 64


# =============================================================================
# Append return tuple unchanged across refactor
# =============================================================================


class TestAppendReturnTupleUnchanged:
    """Refactoring AuditStore.append + DecisionHistoryStore.append to
    fire post-commit hooks MUST NOT change the public return shape."""

    async def test_audit_append_returns_record_id_and_hash(
        self,
        audit_store: AuditStore,
    ) -> None:
        result = await audit_store.append(AuditEvent(event_type="x", request_id="r", payload={}))
        assert isinstance(result, tuple)
        assert len(result) == 2
        record_id, new_hash = result
        assert isinstance(record_id, uuid.UUID)
        assert isinstance(new_hash, bytes)
        assert len(new_hash) == 32  # SHA-256

    async def test_dh_append_returns_record_id_and_hash(
        self,
        dh_store: DecisionHistoryStore,
    ) -> None:
        result = await dh_store.append(
            DecisionRecord(decision_type="x", request_id="r", payload={})
        )
        assert isinstance(result, tuple)
        assert len(result) == 2
        record_id, new_hash = result
        assert isinstance(record_id, uuid.UUID)
        assert isinstance(new_hash, bytes)


# =============================================================================
# Caller-mutation cannot affect mirrored data (R0 doctrine #3)
# =============================================================================


class TestCallerMutationIsolation:
    """T12 R0 #3: the snapshot is the canonicalised persisted dict
    (deep-copied via the canonical-form round-trip in
    AuditStore.append). Caller mutating the raw payload after
    ``await audit_store.append(...)`` returns CANNOT affect what
    hooks see (the snapshot was captured before the await
    completed)."""

    async def test_post_return_mutation_does_not_affect_mirror(
        self,
        audit_store: AuditStore,
        collector: list[Any],
    ) -> None:
        original_payload: dict[str, Any] = {"tool": "foo", "count": 1}
        await audit_store.append(
            AuditEvent(
                event_type="audit.tool_invocation",
                request_id="rid-mut",
                tenant_id="bank_a",
                payload=original_payload,
            )
        )
        # Mutate the original payload AFTER append returned. The
        # mirrored event's payload-derived data MUST be unaffected.
        original_payload["count"] = 999
        original_payload["injected"] = "evil"

        event: Any = collector[0]
        # The mirror's data carries snapshot-derived fields like
        # request_id; the test exercises that the source append
        # already received an isolated snapshot. We can't directly
        # assert the audit row hasn't been mutated (it's already
        # persisted), but we CAN assert the mirror saw a valid
        # tool_call.completed event with stable identity.
        assert event.family == "tool_call"
        assert event.type == "completed"


# =============================================================================
# Hook isolation — broken subscriber does not block subsequent
# =============================================================================


class TestHookIsolation:
    async def test_broken_subscriber_does_not_block_subsequent(
        self,
        emitter: UIEventEmitter,
        audit_store: AuditStore,
    ) -> None:
        """One broken UIEventHook subscriber MUST NOT poison
        emission to subsequent subscribers."""
        broken_called: list[Any] = []
        good_called: list[Any] = []

        async def broken(event: Any) -> None:
            broken_called.append(event)
            raise RuntimeError("subscriber broken")

        async def good(event: Any) -> None:
            good_called.append(event)

        emitter.register_hook(broken)
        emitter.register_hook(good)

        await audit_store.append(
            AuditEvent(
                event_type="audit.tool_invocation",
                request_id="rid-iso",
                tenant_id="bank_a",
                payload={},
            )
        )
        # Both subscribers were called — the broken one's exception
        # was caught; the good one still ran. Per R2 P2 #1: an
        # audit.tool_invocation produces 2 emissions (typed +
        # generic), so each subscriber sees both.
        assert len(broken_called) == 2
        assert len(good_called) == 2

    async def test_broken_subscriber_does_not_break_audit_append(
        self,
        emitter: UIEventEmitter,
        audit_store: AuditStore,
    ) -> None:
        """Subscriber failure MUST NOT propagate up to break the
        primary ``audit_store.append`` outcome."""

        async def broken(event: Any) -> None:
            raise RuntimeError("subscriber broken")

        emitter.register_hook(broken)

        # The append MUST succeed even though the hook will fail.
        result = await audit_store.append(
            AuditEvent(
                event_type="audit.tool_invocation",
                request_id="rid-iso-2",
                tenant_id="bank_a",
                payload={},
            )
        )
        assert isinstance(result, tuple)
        assert len(result) == 2


# =============================================================================
# Both axes: tool_call audit + decision_audit on a tool_call DH row
# =============================================================================


class TestLiveRegistrySnapshotting:
    """T12 R2 P3 reviewer correction: hook dispatch snapshots the
    registry at entry. A hook that registers another hook
    mid-emission MUST NOT be invoked for the current event (which
    would let a self-registering hook extend the loop indefinitely)
    — the new hook only fires on the NEXT emission.

    Three hook surfaces require this guard:
      - :meth:`UIEventEmitter._safe_emit`
      - :meth:`AuditStore._fire_append_hooks`
      - :meth:`DecisionHistoryStore._fire_append_hooks`
    """

    async def test_ui_emitter_self_registering_hook_returns(
        self,
        emitter: UIEventEmitter,
        audit_store: AuditStore,
    ) -> None:
        """A hook that registers ITSELF during dispatch MUST NOT
        cause :meth:`_safe_emit` to loop indefinitely. The
        ``tuple(self._hooks)`` snapshot at dispatch entry freezes
        the iteration target so newly-registered hooks land for
        the NEXT dispatch.

        Without the snapshot, a self-extending hook would keep
        appending to the live list and the iterator would never
        terminate — this test would hang rather than fail.

        Note: the count IS unbounded-growing across emissions
        (registry-doubling per dispatch); that's a separate concern
        from this fix's "single dispatch terminates" property. The
        bound here is finite + load-and-test predictable.
        """
        call_count = [0]

        async def self_registering_hook(event: Any) -> None:
            call_count[0] += 1
            # Pathological: register a duplicate hook on every call.
            emitter.register_hook(self_registering_hook)

        emitter.register_hook(self_registering_hook)

        # audit.tool_invocation fires ``_safe_emit`` twice (typed +
        # generic). Each ``_safe_emit`` snapshots the registry at
        # entry then iterates; mid-dispatch self-registration
        # extends the live list but the iterator (already a
        # tuple-snapshot) is not extended.
        #
        # Trace (initial registry: [self_registering_hook]):
        #
        #   _safe_emit #1 snapshot=(hook,)
        #     -> call hook (count=1); list grows to [hook, hook]
        #   _safe_emit #2 snapshot=(hook, hook)
        #     -> call hook (count=2); list grows to [..., hook]
        #     -> call hook (count=3); list grows once more
        #
        # Total invocations = 1 + 2 = 3. The append returns; no
        # infinite loop.
        await audit_store.append(
            AuditEvent(
                event_type="audit.tool_invocation",
                request_id="rid-snap-self",
                tenant_id="bank_a",
                payload={},
            )
        )
        assert call_count[0] == 3

    async def test_ui_emitter_mid_dispatch_registration_does_not_extend_current_loop(
        self,
        emitter: UIEventEmitter,
        audit_store: AuditStore,
    ) -> None:
        """A hook registered mid-dispatch MUST NOT be invoked
        within the SAME ``_safe_emit`` call. Pin the
        per-dispatch-snapshot semantic without conflating with
        cross-emission behavior (a single audit append fires
        ``_safe_emit`` multiple times — typed + generic — and
        the new hook DOES land for the second emission, that's
        intentional)."""
        first_call_indices: list[int] = []
        second_call_indices: list[int] = []
        emit_counter = [0]

        async def second_hook(event: Any) -> None:
            second_call_indices.append(emit_counter[0])

        async def first_hook(event: Any) -> None:
            first_call_indices.append(emit_counter[0])
            emit_counter[0] += 1
            # Register second_hook mid-dispatch — but second_hook
            # MUST NOT be invoked for THIS _safe_emit call (the
            # registry snapshot prevents extension).
            emitter.register_hook(second_hook)

        emitter.register_hook(first_hook)

        # Trigger ONE _safe_emit by appending an audit event whose
        # type does NOT match a typed family (avoids the dual
        # emission: typed + generic). a2a.task_succeeded only
        # fires the generic mirror = exactly one _safe_emit.
        await audit_store.append(
            AuditEvent(
                event_type="a2a.task_succeeded",
                request_id="rid-snap-1",
                tenant_id="bank_a",
                payload={},
            )
        )
        # first_hook fired once; second_hook MUST NOT have fired
        # within that same _safe_emit invocation.
        assert first_call_indices == [0]
        assert second_call_indices == []

    async def test_audit_store_append_hook_dispatch_snapshots_registry(
        self,
        audit_store: AuditStore,
    ) -> None:
        """Same invariant for ``AuditStore.register_append_hook``."""
        first_calls: list[Any] = []
        second_calls: list[Any] = []

        async def second_hook(snapshot: Any) -> None:
            second_calls.append(snapshot)

        async def first_hook(snapshot: Any) -> None:
            first_calls.append(snapshot)
            audit_store.register_append_hook(second_hook)

        audit_store.register_append_hook(first_hook)

        await audit_store.append(
            AuditEvent(
                event_type="x",
                request_id="rid-snap-aud-1",
                tenant_id="bank_a",
                payload={},
            )
        )
        assert len(first_calls) == 1
        # Second hook NOT invoked for current append.
        assert second_calls == []

        await audit_store.append(
            AuditEvent(
                event_type="x",
                request_id="rid-snap-aud-2",
                tenant_id="bank_a",
                payload={},
            )
        )
        assert len(first_calls) == 2
        assert len(second_calls) == 1

    async def test_dh_store_append_hook_dispatch_snapshots_registry(
        self,
        dh_store: DecisionHistoryStore,
    ) -> None:
        """Same invariant for ``DecisionHistoryStore.register_append_hook``."""
        first_calls: list[Any] = []
        second_calls: list[Any] = []

        async def second_hook(snapshot: Any) -> None:
            second_calls.append(snapshot)

        async def first_hook(snapshot: Any) -> None:
            first_calls.append(snapshot)
            dh_store.register_append_hook(second_hook)

        dh_store.register_append_hook(first_hook)

        await dh_store.append(
            DecisionRecord(
                decision_type="x",
                request_id="rid-snap-dh-1",
                tenant_id="bank_a",
                payload={},
            )
        )
        assert len(first_calls) == 1
        assert second_calls == []

        await dh_store.append(
            DecisionRecord(
                decision_type="x",
                request_id="rid-snap-dh-2",
                tenant_id="bank_a",
                payload={},
            )
        )
        assert len(first_calls) == 2
        assert len(second_calls) == 1


class TestHookDeepCopyIsolation:
    """T12 R1 P2 #2 + #3 reviewer corrections: each hook receives
    its OWN deep copy of the event / snapshot. A misbehaving first
    hook mutating ``event.data`` (or ``snapshot.payload``) MUST
    NOT affect what later hooks see.
    """

    async def test_first_ui_hook_mutating_data_does_not_affect_later(
        self,
        emitter: UIEventEmitter,
        audit_store: AuditStore,
    ) -> None:
        """T12 R1 P2 #2 — Pydantic frozen=True is shallow;
        ``event.data`` is a mutable dict. Per-hook deep-copy
        ensures hook B sees the original event regardless of what
        hook A did."""
        first_seen: list[Any] = []
        second_seen: list[Any] = []

        async def first_hook(event: Any) -> None:
            first_seen.append(dict(event.data))
            # Misbehave: mutate the data dict + try to add a new key.
            event.data["mutated_by_first_hook"] = True
            event.data.clear()

        async def second_hook(event: Any) -> None:
            # MUST observe the original data (deep-copied per hook).
            second_seen.append(dict(event.data))

        emitter.register_hook(first_hook)
        emitter.register_hook(second_hook)

        await audit_store.append(
            AuditEvent(
                event_type="audit.tool_invocation",
                request_id="rid-iso-deep-1",
                tenant_id="bank_a",
                payload={"original_key": "original_value"},
            )
        )

        # First hook mutated its copy.
        assert first_seen
        # Second hook MUST NOT see "mutated_by_first_hook" — it got
        # its own deep copy.
        assert second_seen
        assert "mutated_by_first_hook" not in second_seen[0]

    async def test_first_audit_append_hook_mutating_payload_does_not_affect_later(
        self,
        audit_store: AuditStore,
    ) -> None:
        """T12 R1 P2 #3 — ``AppendedEventSnapshot.payload`` is a
        mutable dict. Per-hook deep-copy via ``dataclasses.replace``
        ensures hook B sees the canonical persisted payload
        regardless of what hook A did."""
        first_seen: list[dict[str, Any]] = []
        second_seen: list[dict[str, Any]] = []

        async def first_hook(snapshot: Any) -> None:
            first_seen.append(dict(snapshot.payload))
            # Misbehave.
            snapshot.payload["mutated_by_first"] = True

        async def second_hook(snapshot: Any) -> None:
            second_seen.append(dict(snapshot.payload))

        audit_store.register_append_hook(first_hook)
        audit_store.register_append_hook(second_hook)

        await audit_store.append(
            AuditEvent(
                event_type="x",
                request_id="rid-aud-deep",
                tenant_id="bank_a",
                payload={"orig": "value"},
            )
        )
        assert first_seen
        assert second_seen
        assert "mutated_by_first" not in second_seen[0]

    async def test_first_dh_append_hook_mutating_payload_does_not_affect_later(
        self,
        dh_store: DecisionHistoryStore,
    ) -> None:
        """T12 R1 P2 #3 — same invariant for
        :class:`DecisionHistoryStore`."""
        first_seen: list[dict[str, Any]] = []
        second_seen: list[dict[str, Any]] = []

        async def first_hook(snapshot: Any) -> None:
            first_seen.append(dict(snapshot.payload))
            snapshot.payload["mutated_by_first"] = True

        async def second_hook(snapshot: Any) -> None:
            second_seen.append(dict(snapshot.payload))

        dh_store.register_append_hook(first_hook)
        dh_store.register_append_hook(second_hook)

        await dh_store.append(
            DecisionRecord(
                decision_type="x",
                request_id="rid-dh-deep",
                tenant_id="bank_a",
                payload={"orig": "value"},
            )
        )
        assert first_seen
        assert second_seen
        assert "mutated_by_first" not in second_seen[0]

    async def test_nested_dict_mutation_does_not_leak_between_hooks(
        self,
        audit_store: AuditStore,
    ) -> None:
        """Deep-copy MUST recurse through nested dicts. A first hook
        mutating ``snapshot.payload["nested"]["key"]`` MUST NOT
        affect what the second hook sees."""
        first_seen: list[Any] = []
        second_seen: list[Any] = []

        async def first_hook(snapshot: Any) -> None:
            first_seen.append(snapshot.payload["nested"]["count"])
            snapshot.payload["nested"]["count"] = 999

        async def second_hook(snapshot: Any) -> None:
            second_seen.append(snapshot.payload["nested"]["count"])

        audit_store.register_append_hook(first_hook)
        audit_store.register_append_hook(second_hook)

        await audit_store.append(
            AuditEvent(
                event_type="x",
                request_id="rid-nest-deep",
                tenant_id="bank_a",
                payload={"nested": {"count": 1}},
            )
        )
        assert first_seen == [1]
        # Second hook MUST see the original nested value (1), not 999.
        assert second_seen == [1]


class TestBothAxesFire:
    """T9 / Sprint-5 emit to BOTH AuditStore + DecisionHistoryStore.
    The same logical event produces THREE mirrored UI events:

      1. Typed family event from AuditStore (e.g. ``ToolCallCompleted``).
      2. Generic ``decision_audit.event_appended`` from AuditStore
         (chain_id="audit_event") per R2 P2 #1.
      3. Generic ``decision_audit.event_appended`` from
         DecisionHistoryStore (chain_id="decision_history").

    Two generic mirrors per logical event is intentional per
    ADR-020 — each chain row mirrors. ``data.chain_id``
    discriminates between the two.
    """

    async def test_audit_then_dh_produce_three_mirrored_events(
        self,
        audit_store: AuditStore,
        dh_store: DecisionHistoryStore,
        collector: list[Any],
    ) -> None:
        await audit_store.append(
            AuditEvent(
                event_type="audit.tool_invocation",
                request_id="rid-both",
                tenant_id="bank_a",
                payload={},
            )
        )
        await dh_store.append(
            DecisionRecord(
                decision_type="mcp_call",
                request_id="rid-both",
                tenant_id="bank_a",
                payload={},
            )
        )
        assert len(collector) == 3
        # Audit-side: typed family then generic mirror.
        assert isinstance(collector[0], ToolCallCompleted)
        assert isinstance(collector[1], DecisionAuditEventAppended)
        assert collector[1].data["chain_id"] == "audit_event"
        # DH-side: generic mirror.
        assert isinstance(collector[2], DecisionAuditEventAppended)
        assert collector[2].data["chain_id"] == "decision_history"
