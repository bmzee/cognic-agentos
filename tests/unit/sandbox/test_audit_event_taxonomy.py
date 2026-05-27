"""Sprint 8A T4 — sandbox lifecycle event taxonomy + chain-row shape pins.

Verified against real ``core/decision_history.py`` API at session compose
time per ``feedback_verify_code_citations_at_doc_write``:

* ``DecisionRecord`` at ``core/decision_history.py:206-249`` — ``frozen=True,
  slots=True`` with **exactly 10 constructor fields** (3 required +
  7 optional). NO ``session_id`` / ``actor_subject`` / ``previous_hash``
  constructor field — session-scoped values go on ``payload`` per the
  established ``escalation.py:560`` pattern.
* ``AppendedDecisionSnapshot`` at ``core/decision_history.py:252`` is a
  SEPARATE post-commit dataclass carrying ``record_id`` / ``chain_id`` /
  ``sequence`` / ``new_hash`` / ``created_at`` — NOT fields the
  implementor passes to the ``DecisionRecord`` constructor.
* ``append_with_precondition`` at ``core/decision_history.py:409`` —
  precondition is ``async (conn, prev_sequence, prev_hash) -> T``;
  ``record_builder`` is ``sync (captured: T) -> DecisionRecord``.

Drift-detector reminder from spec line 808 + ``feedback_drift_detector_
test_only_no_runtime_import``: ``TestSandboxLifecycleEventVocabHas19Values``
(Sprint 8.5 T1 extended 8 → 12; Sprint 10 T9 extended 12 → 15; class
renamed each time the count bumps) pins the count + the exact strings
as a test-only check (the production module re-uses the
``SandboxLifecycleEvent`` Literal from ``sandbox/protocol.py`` directly
— there is no runtime cross-module copy that needs lockstep
enforcement).
"""

from __future__ import annotations

import typing
import uuid
from datetime import UTC, datetime, timedelta
from typing import cast
from unittest.mock import AsyncMock

import pytest

from cognic_agentos.core.decision_history import DecisionRecord
from cognic_agentos.core.vault import (
    CredentialLease,
    VaultLeaseActorRef,
    VaultLeaseRequest,
)
from cognic_agentos.sandbox import (
    CheckpointId,
    SandboxLifecycleEvent,
    sandbox_lifecycle_checkpoint_purged,
    sandbox_lifecycle_checkpointed,
    sandbox_lifecycle_lease_minted,
    sandbox_lifecycle_lease_revoke_failed,
    sandbox_lifecycle_lease_revoked,
    sandbox_lifecycle_suspended,
    sandbox_lifecycle_woken,
)
from cognic_agentos.sandbox.audit import emit_sandbox_event

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_store_mock() -> AsyncMock:
    """Build an AsyncMock that mimics the
    ``DecisionHistoryStore.append_with_precondition`` return shape per
    ``core/decision_history.py:414``: ``tuple[uuid.UUID, bytes]``."""

    store = AsyncMock()
    store.append_with_precondition.return_value = (uuid.uuid4(), b"\x00" * 32)
    return store


async def _drive_emit_and_capture(
    store: AsyncMock,
) -> DecisionRecord:
    """Drive the precondition closure + record_builder so the test can
    inspect the ``DecisionRecord`` the production emitter would have
    passed to the chain store."""

    call_kwargs = store.append_with_precondition.call_args.kwargs
    captured = await call_kwargs["precondition"](AsyncMock(), 0, b"\x00" * 32)
    # ``call_kwargs["record_builder"]`` is typed Any by the AsyncMock
    # surface; the production emitter declares it as
    # ``Callable[[T], DecisionRecord]`` so the cast reflects ground truth.
    return cast(DecisionRecord, call_kwargs["record_builder"](captured))


# ---------------------------------------------------------------------------
# Plan T4 Step-1 tests — taxonomy + chain-row shape
# ---------------------------------------------------------------------------


class TestEventTaxonomyAndChainRowShape:
    async def test_lifecycle_created_emits_chain_row_with_a6_2_5_iso_tag(
        self,
    ) -> None:
        """Audit emission for ``sandbox.lifecycle.created`` builds a
        ``DecisionRecord`` with ``iso_controls=('ISO42001.A.6.2.5',)`` per
        ADR-006 amendment + ``session_id`` on payload (NOT a top-level
        ``DecisionRecord`` field)."""

        store = _make_store_mock()

        await emit_sandbox_event(
            store,
            event="sandbox.lifecycle.created",
            tenant_id="t-1",
            actor_id="s-1",
            trace_id="trace-1",
            session_id="sess-1",
            payload={"warm_pool_hit": False},
        )

        store.append_with_precondition.assert_awaited_once()
        built = await _drive_emit_and_capture(store)

        assert isinstance(built, DecisionRecord)
        assert built.decision_type == "sandbox.lifecycle.created"
        assert built.iso_controls == ("ISO42001.A.6.2.5",)
        assert built.tenant_id == "t-1"
        assert built.actor_id == "s-1"
        assert built.trace_id == "trace-1"
        # session_id lives on payload, NOT as a top-level DR field
        assert built.payload["session_id"] == "sess-1"
        assert built.payload["warm_pool_hit"] is False
        # request_id auto-minted with sandbox-evt prefix per plan §4
        assert built.request_id.startswith("sandbox-evt-")

    async def test_refused_event_carries_closed_enum_reason_on_payload(
        self,
    ) -> None:
        store = _make_store_mock()

        await emit_sandbox_event(
            store,
            event="sandbox.lifecycle.refused",
            tenant_id="t-1",
            actor_id="s-1",
            trace_id="trace-1",
            session_id="sess-1",
            payload={"reason": "sandbox_credential_adapter_not_configured"},
        )

        built = await _drive_emit_and_capture(store)
        assert built.payload["reason"] == "sandbox_credential_adapter_not_configured"
        assert built.payload["session_id"] == "sess-1"

    async def test_emit_rejects_unknown_event_at_module_boundary(self) -> None:
        with pytest.raises(ValueError, match="not a valid SandboxLifecycleEvent"):
            await emit_sandbox_event(
                _make_store_mock(),
                event="sandbox.lifecycle.bogus",  # type: ignore[arg-type]
                tenant_id="t-1",
                actor_id="s-1",
                trace_id="trace-1",
                session_id="sess-1",
                payload={},
            )


class TestAllLifecycleEventsReachable:
    """Pin that all current ``SandboxLifecycleEvent`` values have working
    emit paths. Count-neutral (parametrizes over the live
    ``typing.get_args(SandboxLifecycleEvent)``) so the test
    automatically covers Sprint-8.5's 4 new events alongside the
    Sprint-8A 8 without manual count maintenance — the count guard
    lives separately at ``TestSandboxLifecycleEventVocabHas19Values``.
    """

    @pytest.mark.parametrize("event", list(typing.get_args(SandboxLifecycleEvent)))
    async def test_each_event_emits_chain_row_without_error(self, event: str) -> None:
        store = _make_store_mock()
        await emit_sandbox_event(
            store,
            event=event,  # type: ignore[arg-type]
            tenant_id="t-1",
            actor_id="s-1",
            trace_id="trace-1",
            session_id="sess-1",
            payload={},
        )
        store.append_with_precondition.assert_awaited_once()


# ---------------------------------------------------------------------------
# Spec §808 drift detector — taxonomy lockstep
# ---------------------------------------------------------------------------


class TestSandboxLifecycleEventVocabHas19Values:
    """Spec line 808 + §979 + Sprint 8.5 §3.3 + Sprint-10 §6.2 +
    Sprint-10.6 §5.1 — pin the 19-value count + the exact strings.

    No ``warm_pool.replenished`` per the user-locked taxonomy at §4.3 —
    replenishment is the *cause*; the *event* is still ``precreated``.

    Sprint 8.5 T1 extended 8 → 12 (4 new events per spec §3.3).
    Sprint 10 T9 extended 12 → 15 (3 new lease lifecycle events per
    Sprint-10 spec §6.2: lease_minted / lease_revoked /
    lease_revoke_failed; emitted from SandboxBackend.create() +
    .destroy() at T10).
    Sprint 10.6 T17 extended 15 → 19 (4 new credential-projection
    lifecycle events per Sprint-10.6 spec §5.1; Literal-only at T17 —
    emit call sites land at the T21 lifecycle integration when that
    task lands later in the sprint).

    Tombstoning is a STORAGE artifact NOT a lifecycle event — destroy()
    reuses the 8A ``sandbox.lifecycle.destroyed`` event with 2 new
    conditional payload keys per spec §5.1.
    """

    _EXPECTED: typing.ClassVar[frozenset[str]] = frozenset(
        {
            # Sprint 8A — 8 values
            "sandbox.lifecycle.created",
            "sandbox.lifecycle.exec_completed",
            "sandbox.lifecycle.destroyed",
            "sandbox.lifecycle.refused",
            "sandbox.policy.violated",
            "sandbox.warm_pool.precreated",
            "sandbox.warm_pool.checked_out",
            "sandbox.warm_pool.drained",
            # Sprint 8.5 T1 — 4 new events per spec §3.3
            "sandbox.lifecycle.checkpointed",
            "sandbox.lifecycle.suspended",
            "sandbox.lifecycle.woken",
            "sandbox.lifecycle.checkpoint_purged",
            # Sprint 10 T9 — 3 new lease lifecycle events per
            # Sprint-10 spec §6.2 (emitted from SandboxBackend.create()
            # + .destroy() at T10).
            "sandbox.lifecycle.lease_minted",
            "sandbox.lifecycle.lease_revoked",
            "sandbox.lifecycle.lease_revoke_failed",
            # Sprint 10.6 T17 — 4 new credential-projection lifecycle
            # events per spec §5.1. Literal-only at T17 — emit call
            # sites land at T21 ``SandboxBackend.create()`` lifecycle
            # integration when that task lands. Payload-shape contracts
            # locked at T21 alongside the typed audit helpers
            # (mirroring the Sprint-10 ``emit_lease_*`` pattern).
            "sandbox.lifecycle.credentials_projected",
            "sandbox.lifecycle.credentials_projection_failed",
            "sandbox.lifecycle.credentials_projection_cleaned_up",
            "sandbox.lifecycle.credentials_projection_cleanup_failed",
        }
    )

    def test_event_count_is_exactly_nineteen(self) -> None:
        assert len(typing.get_args(SandboxLifecycleEvent)) == 19

    def test_event_strings_match_spec_table_exactly(self) -> None:
        actual = frozenset(typing.get_args(SandboxLifecycleEvent))
        assert actual == self._EXPECTED

    def test_no_warm_pool_replenished_value(self) -> None:
        """User-locked at §4.3 + §979 — replenishment is the *cause*,
        the *event* is still ``precreated``. A future regression that
        adds ``warm_pool.replenished`` would split the taxonomy across
        cause/event and break examiner readers."""

        assert "sandbox.warm_pool.replenished" not in typing.get_args(SandboxLifecycleEvent)


# ---------------------------------------------------------------------------
# Plan T4 Step-4 closure — per-event payload-shape contracts (spec §4.3)
# ---------------------------------------------------------------------------


class TestPerEventPayloadShapeContractsPassThrough:
    """Spec §4.3 table — each event's documented payload shape passes
    through the emitter intact onto the built ``DecisionRecord.payload``.

    The emitter MUST NOT mangle / drop / coerce caller-supplied keys
    (it only merges ``session_id`` per the plan's payload-merge rule).
    """

    async def test_lifecycle_created_payload_carries_warm_pool_hit_bool(
        self,
    ) -> None:
        store = _make_store_mock()
        await emit_sandbox_event(
            store,
            event="sandbox.lifecycle.created",
            tenant_id="t-1",
            actor_id="s-1",
            trace_id="trace-1",
            session_id="sess-1",
            payload={"warm_pool_hit": True},
        )
        built = await _drive_emit_and_capture(store)
        assert built.payload["warm_pool_hit"] is True

    async def test_lifecycle_exec_completed_payload_carries_exit_code_int(
        self,
    ) -> None:
        store = _make_store_mock()
        await emit_sandbox_event(
            store,
            event="sandbox.lifecycle.exec_completed",
            tenant_id="t-1",
            actor_id="s-1",
            trace_id="trace-1",
            session_id="sess-1",
            payload={"exit_code": 0, "proxy_log": []},
        )
        built = await _drive_emit_and_capture(store)
        assert built.payload["exit_code"] == 0
        assert built.payload["proxy_log"] == []

    async def test_lifecycle_destroyed_payload_carries_duration_s_float(
        self,
    ) -> None:
        store = _make_store_mock()
        await emit_sandbox_event(
            store,
            event="sandbox.lifecycle.destroyed",
            tenant_id="t-1",
            actor_id="s-1",
            trace_id="trace-1",
            session_id="sess-1",
            payload={"duration_s": 1.25},
        )
        built = await _drive_emit_and_capture(store)
        assert built.payload["duration_s"] == 1.25

    async def test_lifecycle_refused_payload_carries_sandbox_refusal_reason(
        self,
    ) -> None:
        store = _make_store_mock()
        await emit_sandbox_event(
            store,
            event="sandbox.lifecycle.refused",
            tenant_id="t-1",
            actor_id="s-1",
            trace_id="trace-1",
            session_id="sess-1",
            payload={"reason": "sandbox_image_cosign_verification_failed"},
        )
        built = await _drive_emit_and_capture(store)
        assert built.payload["reason"] == "sandbox_image_cosign_verification_failed"

    async def test_policy_violated_payload_carries_sandbox_policy_violation_reason(
        self,
    ) -> None:
        store = _make_store_mock()
        await emit_sandbox_event(
            store,
            event="sandbox.policy.violated",
            tenant_id="t-1",
            actor_id="s-1",
            trace_id="trace-1",
            session_id="sess-1",
            payload={"reason": "memory_cap_exceeded"},
        )
        built = await _drive_emit_and_capture(store)
        assert built.payload["reason"] == "memory_cap_exceeded"

    async def test_warm_pool_precreated_payload_carries_pool_key_and_size(
        self,
    ) -> None:
        store = _make_store_mock()
        await emit_sandbox_event(
            store,
            event="sandbox.warm_pool.precreated",
            tenant_id="t-1",
            actor_id="s-1",
            trace_id="trace-1",
            session_id="sess-1",
            payload={"pool_key": "small-runtime", "pool_size_after": 3},
        )
        built = await _drive_emit_and_capture(store)
        assert built.payload["pool_key"] == "small-runtime"
        assert built.payload["pool_size_after"] == 3

    async def test_warm_pool_checked_out_payload_carries_pool_key_and_size(
        self,
    ) -> None:
        store = _make_store_mock()
        await emit_sandbox_event(
            store,
            event="sandbox.warm_pool.checked_out",
            tenant_id="t-1",
            actor_id="s-1",
            trace_id="trace-1",
            session_id="sess-1",
            payload={"pool_key": "small-runtime", "pool_size_after": 2},
        )
        built = await _drive_emit_and_capture(store)
        assert built.payload["pool_key"] == "small-runtime"
        assert built.payload["pool_size_after"] == 2

    async def test_warm_pool_drained_payload_carries_pool_key_and_drained_count(
        self,
    ) -> None:
        store = _make_store_mock()
        await emit_sandbox_event(
            store,
            event="sandbox.warm_pool.drained",
            tenant_id="t-1",
            actor_id="s-1",
            trace_id="trace-1",
            session_id="sess-1",
            payload={"pool_key": "small-runtime", "drained_count": 3},
        )
        built = await _drive_emit_and_capture(store)
        assert built.payload["pool_key"] == "small-runtime"
        assert built.payload["drained_count"] == 3


# ---------------------------------------------------------------------------
# Plan T4 — return-value pass-through (record_id, new_hash)
# ---------------------------------------------------------------------------


class TestEmitReturnValuePassThrough:
    """``emit_sandbox_event`` MUST return the ``(record_id, new_hash)``
    tuple from the store per plan §899 + ``core/decision_history.py:414``."""

    async def test_returns_store_append_with_precondition_tuple(self) -> None:
        store = AsyncMock()
        expected_id = uuid.uuid4()
        expected_hash = b"\x42" * 32
        store.append_with_precondition.return_value = (expected_id, expected_hash)

        result = await emit_sandbox_event(
            store,
            event="sandbox.lifecycle.created",
            tenant_id="t-1",
            actor_id="s-1",
            trace_id="trace-1",
            session_id="sess-1",
            payload={"warm_pool_hit": False},
        )

        assert result == (expected_id, expected_hash)


# ---------------------------------------------------------------------------
# Sprint 8.5 T2 — payload-shape contracts for the 4 new lifecycle helpers
# (spec §5.1). Each helper bundles the canonical payload-key set per spec
# so backend callers (T6/T7) cannot drift the field names.
# ---------------------------------------------------------------------------


class TestSandboxLifecycleCheckpointedHelper:
    """Pin the spec §5.1 payload-shape contract for the
    ``sandbox.lifecycle.checkpointed`` helper.

    Per spec §5.1: payload keys are
    ``{checkpoint_id, label, created_at (tz-aware ISO string),
    policy_digest}`` + ``session_id`` threaded by ``emit_sandbox_event``.
    """

    async def test_emits_with_correct_event_type_and_payload_keys(self) -> None:
        store = _make_store_mock()

        await sandbox_lifecycle_checkpointed(
            store,
            tenant_id="t-1",
            actor_id="s-1",
            trace_id="trace-1",
            session_id="sess-1",
            checkpoint_id=CheckpointId("a" * 32),
            label="before_payment",
            policy_digest="sha256:" + "0" * 64,
        )
        built = await _drive_emit_and_capture(store)

        assert built.decision_type == "sandbox.lifecycle.checkpointed"
        assert built.iso_controls == ("ISO42001.A.6.2.5",)
        assert built.tenant_id == "t-1"
        # Per spec §5.1 — 5 payload keys (4 helper-supplied + session_id
        # threaded by emit_sandbox_event).
        assert set(built.payload.keys()) == {
            "checkpoint_id",
            "label",
            "created_at",
            "policy_digest",
            "session_id",
        }
        assert built.payload["checkpoint_id"] == "a" * 32
        assert built.payload["label"] == "before_payment"
        assert built.payload["policy_digest"] == "sha256:" + "0" * 64
        assert built.payload["session_id"] == "sess-1"

    async def test_created_at_is_tz_aware_iso_string(self) -> None:
        """``created_at`` generated INSIDE the helper as
        ``datetime.now(UTC).isoformat()`` — enforces tz-awareness
        consistently per ``feedback_evidence_boundary_runtime_validation``
        (BOTH ``tzinfo is not None`` AND ``utcoffset() is not None``).
        """
        from datetime import datetime

        store = _make_store_mock()

        await sandbox_lifecycle_checkpointed(
            store,
            tenant_id="t-1",
            actor_id="s-1",
            trace_id="trace-1",
            session_id="sess-1",
            checkpoint_id=CheckpointId("a" * 32),
            label="checkpoint-tz",
            policy_digest="sha256:" + "0" * 64,
        )
        built = await _drive_emit_and_capture(store)

        parsed = datetime.fromisoformat(built.payload["created_at"])
        assert parsed.tzinfo is not None, (
            "created_at MUST be tz-aware per feedback_evidence_boundary_runtime_validation"
        )
        assert parsed.utcoffset() is not None, (
            "created_at tz-aware check requires BOTH tzinfo + utcoffset()"
        )


class TestSandboxLifecycleSuspendedHelper:
    """Pin the spec §5.1 payload-shape contract for the
    ``sandbox.lifecycle.suspended`` helper.

    ``final_checkpoint_id`` IS the linkage target the wake-time chain
    verifier walks back to per spec §5.2.
    """

    async def test_emits_with_final_checkpoint_id_linkage_key(self) -> None:
        store = _make_store_mock()

        await sandbox_lifecycle_suspended(
            store,
            tenant_id="t-1",
            actor_id="s-1",
            trace_id="trace-1",
            session_id="sess-1",
            final_checkpoint_id=CheckpointId("b" * 32),
        )
        built = await _drive_emit_and_capture(store)

        assert built.decision_type == "sandbox.lifecycle.suspended"
        assert built.iso_controls == ("ISO42001.A.6.2.5",)
        # Per spec §5.1 — 2 payload keys (1 helper-supplied + session_id).
        assert set(built.payload.keys()) == {"final_checkpoint_id", "session_id"}
        assert built.payload["final_checkpoint_id"] == "b" * 32


class TestSandboxLifecycleWokenHelper:
    """Pin the spec §5.1 payload-shape contract for the
    ``sandbox.lifecycle.woken`` helper.

    Per spec §5.2 chain-verifier walks ``decision_history WHERE
    record_id = payload["suspend_event_id"]`` — the helper serialises
    the UUID to string for canonical_bytes round-trip safety; the
    chain-verifier parses back via ``uuid.UUID(value)``.
    """

    async def test_emits_with_restored_from_checkpoint_id_and_suspend_event_id(
        self,
    ) -> None:
        store = _make_store_mock()
        suspend_record_id = uuid.uuid4()

        await sandbox_lifecycle_woken(
            store,
            tenant_id="t-1",
            actor_id="s-1",
            trace_id="trace-1",
            session_id="sess-1",
            restored_from_checkpoint_id=CheckpointId("c" * 32),
            suspend_event_id=suspend_record_id,
        )
        built = await _drive_emit_and_capture(store)

        assert built.decision_type == "sandbox.lifecycle.woken"
        assert built.iso_controls == ("ISO42001.A.6.2.5",)
        # Per spec §5.1 — 3 payload keys (2 helper-supplied + session_id).
        assert set(built.payload.keys()) == {
            "restored_from_checkpoint_id",
            "suspend_event_id",
            "session_id",
        }
        assert built.payload["restored_from_checkpoint_id"] == "c" * 32
        # UUID serialised to string for canonical_bytes round-trip safety
        # (UUID is not in canonical-bytes-allowed type set per Sprint-2
        # doctrine; chain verifier parses back via uuid.UUID(value)).
        assert built.payload["suspend_event_id"] == str(suspend_record_id)
        assert uuid.UUID(built.payload["suspend_event_id"]) == suspend_record_id


class TestSandboxLifecycleCheckpointPurgedHelper:
    """Pin the spec §5.1 payload-shape contract for the
    ``sandbox.lifecycle.checkpoint_purged`` helper.

    ``purge_reason`` is the 4-value closed enum (spec §4.3 P3.r4
    UNCHANGED): ``explicit_destroy`` / ``max_per_session_cap`` /
    ``retention_expired`` / ``tenant_revocation``.
    """

    @pytest.mark.parametrize(
        "purge_reason",
        [
            "explicit_destroy",
            "max_per_session_cap",
            "retention_expired",
            "tenant_revocation",
        ],
    )
    async def test_emits_with_purge_reason_closed_enum(self, purge_reason: str) -> None:
        store = _make_store_mock()

        await sandbox_lifecycle_checkpoint_purged(
            store,
            tenant_id="t-1",
            session_id="sess-1",
            checkpoint_id=CheckpointId("d" * 32),
            purge_reason=purge_reason,  # type: ignore[arg-type]
        )
        built = await _drive_emit_and_capture(store)

        assert built.decision_type == "sandbox.lifecycle.checkpoint_purged"
        assert built.iso_controls == ("ISO42001.A.6.2.5",)
        # Per spec §5.1 — 3 payload keys (2 helper-supplied + session_id).
        assert set(built.payload.keys()) == {
            "checkpoint_id",
            "purge_reason",
            "session_id",
        }
        assert built.payload["checkpoint_id"] == "d" * 32
        assert built.payload["purge_reason"] == purge_reason

    async def test_default_actor_id_is_reaper(self) -> None:
        """Typical caller is the background CheckpointReaper (T4); the
        helper's actor_id default is ``"reaper"`` so reaper-emitted
        purges show a recognisable actor in the chain.
        """
        store = _make_store_mock()

        await sandbox_lifecycle_checkpoint_purged(
            store,
            tenant_id="t-1",
            session_id="sess-1",
            checkpoint_id=CheckpointId("e" * 32),
            purge_reason="retention_expired",
        )
        built = await _drive_emit_and_capture(store)

        assert built.actor_id == "reaper"

    async def test_unknown_purge_reason_raises_fail_loud(self) -> None:
        """Closed-enum validation at the helper boundary per
        ``feedback_evidence_boundary_runtime_validation`` ("unknown
        Literal values fail-loud"). Caller passing an out-of-set value
        gets a structured ValueError BEFORE any chain row is emitted.
        """
        store = _make_store_mock()

        with pytest.raises(ValueError, match="is not a valid PurgeReason"):
            await sandbox_lifecycle_checkpoint_purged(
                store,
                tenant_id="t-1",
                session_id="sess-1",
                checkpoint_id=CheckpointId("f" * 32),
                purge_reason="retention_window_active",  # type: ignore[arg-type]
            )
        # NO chain row was emitted — defence-in-depth assertion.
        store.append_with_precondition.assert_not_awaited()

    async def test_operator_can_override_actor_id(self) -> None:
        """``tenant_revocation`` purges may be driven by an operator
        action (compliance review, regulator-erasure request). Helper
        accepts a caller-supplied ``actor_id`` override.
        """
        store = _make_store_mock()

        await sandbox_lifecycle_checkpoint_purged(
            store,
            tenant_id="t-1",
            session_id="sess-1",
            checkpoint_id=CheckpointId("g" * 32),
            purge_reason="tenant_revocation",
            actor_id="operator:alice@bank.example",
        )
        built = await _drive_emit_and_capture(store)

        assert built.actor_id == "operator:alice@bank.example"


class TestSandboxLifecycleDestroyedPayloadExtension:
    """Pin the Sprint 8.5 P1.r4 destroyed-payload extension (spec §5.1).

    The 8A ``sandbox.lifecycle.destroyed`` event payload is extended
    with 2 NEW OPTIONAL keys when the destroyed session had persisted
    checkpoints: ``retained_until`` (ISO-string) + ``tombstone_object_key``
    (storage-key). Presence of both keys is the wire-public marker that
    retention is in effect.

    No helper is added for destroyed — backends continue to call
    ``emit_sandbox_event`` directly (8A pattern preserved). The
    extension is documented in the audit.py per-event payload contract;
    these tests pin that callers passing the new keys get them on the
    payload + callers omitting them keep the pre-existing 8A shape.
    """

    async def test_destroyed_with_retention_keys_passes_through(self) -> None:
        """Sessions WITH persisted checkpoints emit destroyed WITH
        ``retained_until`` + ``tombstone_object_key`` payload keys.
        """
        store = _make_store_mock()

        await emit_sandbox_event(
            store,
            event="sandbox.lifecycle.destroyed",
            tenant_id="t-1",
            actor_id="s-1",
            trace_id="trace-1",
            session_id="sess-1",
            payload={
                "duration_s": 12.34,
                "retained_until": "2026-05-19T12:00:00+00:00",
                "tombstone_object_key": "t-1/sess-1/_tombstoned.json",
            },
        )
        built = await _drive_emit_and_capture(store)

        assert built.decision_type == "sandbox.lifecycle.destroyed"
        assert built.payload["retained_until"] == "2026-05-19T12:00:00+00:00"
        assert built.payload["tombstone_object_key"] == "t-1/sess-1/_tombstoned.json"
        assert built.payload["duration_s"] == 12.34

    async def test_destroyed_without_retention_keys_preserves_8a_shape(self) -> None:
        """Sessions with NO persisted checkpoints emit destroyed WITHOUT
        the retention keys (pre-existing 8A shape unchanged). Absence is
        the wire-public marker that NO retention is in effect — the
        session was immediately physically destroyed.
        """
        store = _make_store_mock()

        await emit_sandbox_event(
            store,
            event="sandbox.lifecycle.destroyed",
            tenant_id="t-1",
            actor_id="s-1",
            trace_id="trace-1",
            session_id="sess-1",
            payload={"duration_s": 0.5},
        )
        built = await _drive_emit_and_capture(store)

        assert built.decision_type == "sandbox.lifecycle.destroyed"
        assert built.payload == {"duration_s": 0.5, "session_id": "sess-1"}
        # Defence-in-depth: explicit absence assertions so a future
        # regression that always-injects the keys (even when omitted)
        # fails loud.
        assert "retained_until" not in built.payload
        assert "tombstone_object_key" not in built.payload


# ---------------------------------------------------------------------------
# Sprint 8.5 T2 — public-surface re-export regression (mirrors the T1
# TestSandboxPublicSurfaceExports pattern for CheckpointId at
# tests/unit/sandbox/test_policy_shape.py).
#
# Without these pins, a future edit could drop PurgeReason or any of
# the 4 helpers from cognic_agentos.sandbox.__all__ (OR from the root
# package surface entirely) while the helper-payload tests still pass
# — because those tests import via the canonical module path. The
# public-surface pin breaks loudly in CI if any name is dropped or
# diverges from its canonical source.
# ---------------------------------------------------------------------------


class TestSandboxAuditPublicSurfaceExports:
    """Pin the wire-public T2 re-exports from ``cognic_agentos.sandbox.__init__``.

    Mirrors ``TestSandboxPublicSurfaceExports`` for ``CheckpointId``
    (Sprint 8.5 T1) — locks the canonical import path callers
    (T6/T7 backend wake/checkpoint/suspend impls + T3 CheckpointStore
    purge paths) depend on. Without these pins, a future ``__all__``
    edit that drops the helper names or ``PurgeReason`` would silently
    break public-API consumers while internal tests stay green.
    """

    def test_purge_reason_and_helpers_importable_from_package_root(self) -> None:
        """``from cognic_agentos.sandbox import PurgeReason, sandbox_lifecycle_*``
        MUST succeed. The 4 helpers + the ``PurgeReason`` Literal are
        the wire-public T2 surface; T6/T7 + T3 callers depend on the
        package-root import path (NOT the internal
        ``cognic_agentos.sandbox.audit`` module).
        """
        from cognic_agentos import sandbox as sandbox_pkg

        expected_t2_exports = {
            "PurgeReason",
            "sandbox_lifecycle_checkpointed",
            "sandbox_lifecycle_suspended",
            "sandbox_lifecycle_woken",
            "sandbox_lifecycle_checkpoint_purged",
            # Sprint 10 T9 — 3 new lease lifecycle helpers per spec §6.2
            # (`sandbox_lifecycle_lease_minted` / `_revoked` /
            # `_revoke_failed`). Sprint 10 T10 backend create()/destroy()
            # call sites depend on the package-root import path.
            "sandbox_lifecycle_lease_minted",
            "sandbox_lifecycle_lease_revoked",
            "sandbox_lifecycle_lease_revoke_failed",
        }

        # __all__ membership pin — drift in this set breaks the public
        # API contract documented in audit.py's per-event payload-shape
        # docstring.
        all_set = set(sandbox_pkg.__all__)
        missing = expected_t2_exports - all_set
        assert not missing, (
            f"T2 + T9 wire-public names MUST be in cognic_agentos.sandbox.__all__; "
            f"missing: {sorted(missing)}"
        )

        # hasattr pin — catches a refactor that drops a name from
        # __init__.py imports while leaving it in __all__ (broken
        # re-export).
        for name in expected_t2_exports:
            assert hasattr(sandbox_pkg, name), (
                f"{name!r} MUST be importable from cognic_agentos.sandbox "
                f"(Sprint 8.5 T2 + Sprint 10 T9 public-surface re-export)"
            )

    def test_root_reexports_are_canonical_objects(self) -> None:
        """Re-exported objects MUST be the SAME object as the canonical
        declarations in ``cognic_agentos.sandbox.audit``. Protects
        against a future refactor that creates a divergent re-export
        (e.g., a wrapper function with the same name but different
        behaviour, OR a re-defined ``PurgeReason`` Literal with drift).
        """
        from cognic_agentos import sandbox as sandbox_pkg
        from cognic_agentos.sandbox import audit as audit_module

        assert sandbox_pkg.PurgeReason is audit_module.PurgeReason
        assert (
            sandbox_pkg.sandbox_lifecycle_checkpointed
            is audit_module.sandbox_lifecycle_checkpointed
        )
        assert sandbox_pkg.sandbox_lifecycle_suspended is audit_module.sandbox_lifecycle_suspended
        assert sandbox_pkg.sandbox_lifecycle_woken is audit_module.sandbox_lifecycle_woken
        assert (
            sandbox_pkg.sandbox_lifecycle_checkpoint_purged
            is audit_module.sandbox_lifecycle_checkpoint_purged
        )
        # Sprint 10 T9 — 3 new lease lifecycle helpers.
        assert (
            sandbox_pkg.sandbox_lifecycle_lease_minted
            is audit_module.sandbox_lifecycle_lease_minted
        )
        assert (
            sandbox_pkg.sandbox_lifecycle_lease_revoked
            is audit_module.sandbox_lifecycle_lease_revoked
        )
        assert (
            sandbox_pkg.sandbox_lifecycle_lease_revoke_failed
            is audit_module.sandbox_lifecycle_lease_revoke_failed
        )


# ---------------------------------------------------------------------------
# Sprint 10 T9 — 3 new typed helpers for lease lifecycle events per spec §6.2.
#
# Payload-shape contract per spec §6.2:
#   - 10 always-fields on lease_minted + lease_revoked:
#       lease_id, secret_path, scope_label, tenant_id, actor_subject,
#       actor_type, ttl_s, ttl_s_granted, minted_at (tz-aware ISO),
#       expires_at (tz-aware ISO)
#   - lease_revoke_failed adds 2 conditional keys:
#       vault_error (Vault HTTP error string; caller-supplied — the only
#         field not derivable from CredentialLease), auto_expiry_at
#         (== expires_at per spec §6.2 line 624; DERIVED inside the
#         helper from lease.expires_at.isoformat())
#   - `session_id` threaded by emit_sandbox_event = 11 / 13 total keys
#
# Helper input-shape lock — single-source-of-truth derive (per plan
# T9 Step 2 + the round-4 P1 review fixes):
#   - lease: CredentialLease (single positional) — all 10 payload
#     always-fields derived from one frozen dataclass.
#   - DecisionRecord.tenant_id AND DecisionRecord.actor_id are also
#     DERIVED inside the helper from lease.request.tenant_id +
#     lease.request.actor_ref.actor_subject (NOT accepted as separate
#     kwargs). Closes the contradictory-evidence bug class by
#     construction: there is no caller-supplied channel through which
#     a caller could pass chain-metadata tenant/actor disagreeing with
#     the lease-payload tenant/actor.
#   - trace_id + session_id remain caller-supplied (session-scoped +
#     trace-scoped; NOT lease-scoped).
#   - vault_error: str on revoke_failed — the ONLY caller-supplied
#     extra kwarg (carries the Vault HTTP error string the backend
#     captured during the failed revoke). auto_expiry_at is NOT a
#     kwarg — accepting it as a caller string would re-open the
#     silent-lie bug class where a caller could pass an arbitrary
#     string disagreeing with expires_at; the helper derives it
#     from lease.expires_at instead, matching spec §6.2 line 624.
#
# Live signatures (pinned by the per-helper test classes below):
#   sandbox_lifecycle_lease_minted(store, *, lease, trace_id, session_id)
#   sandbox_lifecycle_lease_revoked(store, *, lease, trace_id, session_id)
#   sandbox_lifecycle_lease_revoke_failed(
#       store, *, lease, trace_id, session_id, vault_error,
#   )
#
# Spec §6.2 + AGENTS.md "Wire-protocol contracts": token contents NEVER
# appear on the chain row. Examiners trace by lease_id + secret_path +
# scope_label.
# ---------------------------------------------------------------------------


def _make_sample_lease() -> CredentialLease:
    """Sample CredentialLease with ``request.ttl_s`` (900) != ``ttl_s_granted``
    (600).

    The distinct values pin spec §6.2's load-bearing distinction between
    "what was requested" and "what Vault actually granted" — collapsing
    them in the payload projection would erase the examiner-evidence
    distinction. The token value is a recognisable sentinel so the
    "never on chain row" defence-in-depth assertion can scan all payload
    values for it.
    """
    minted_at = datetime(2026, 5, 24, 10, 0, 0, tzinfo=UTC)
    return CredentialLease(
        lease_id="vault/leases/db/abc123",
        request=VaultLeaseRequest(
            secret_path="database/creds/payments-read",
            ttl_s=900,
            tenant_id="t-1",
            actor_ref=VaultLeaseActorRef(
                actor_subject="user-42",
                actor_type="human",
            ),
            scope_label="payments-read",
        ),
        # CredentialLease.token is dict[str, str] per core/vault.py:169
        # (Vault returns dict-shaped credentials per backend — DB
        # exposes {username, password}; AWS STS exposes
        # {access_key, secret_key, session_token}; PKI exposes
        # {certificate, private_key, ca_chain}). Sentinel placed
        # inside the dict so the defence-in-depth scan below still
        # detects accidental token-leak via str(payload_value).
        token={"password": "vault-token-NEVER-on-chain"},
        minted_at=minted_at,
        ttl_s_granted=600,
        expires_at=minted_at + timedelta(seconds=600),
    )


_EXPECTED_LEASE_PAYLOAD_KEYS: frozenset[str] = frozenset(
    {
        "lease_id",
        "secret_path",
        "scope_label",
        "tenant_id",
        "actor_subject",
        "actor_type",
        "ttl_s",
        "ttl_s_granted",
        "minted_at",
        "expires_at",
        "session_id",  # threaded by emit_sandbox_event
    }
)


class TestSandboxLifecycleLeaseMintedHelper:
    """Pin the spec §6.2 payload-shape contract for the
    ``sandbox.lifecycle.lease_minted`` helper.

    Called from ``SandboxBackend.create()`` (T10) after each successful
    ``mint_lease()`` round-trip per spec §7.1. Payload contract: 10
    always-fields + ``session_id``.
    """

    async def test_emits_with_correct_event_type_and_payload_keys(self) -> None:
        store = _make_store_mock()
        lease = _make_sample_lease()

        await sandbox_lifecycle_lease_minted(
            store,
            lease=lease,
            trace_id="trace-1",
            session_id="sess-1",
        )
        built = await _drive_emit_and_capture(store)

        assert built.decision_type == "sandbox.lifecycle.lease_minted"
        assert built.iso_controls == ("ISO42001.A.6.2.5",)
        # Chain-metadata DERIVED from lease (no caller-supplied
        # tenant_id / actor_id kwargs — the helper signature itself
        # closes the contradictory-evidence bug class).
        assert built.tenant_id == lease.request.tenant_id == "t-1"
        assert built.actor_id == lease.request.actor_ref.actor_subject == "user-42"
        assert built.trace_id == "trace-1"
        # spec §6.2 — exactly 11 payload keys (10 always-fields +
        # session_id threaded by emit_sandbox_event).
        assert set(built.payload.keys()) == _EXPECTED_LEASE_PAYLOAD_KEYS
        # Per-field value pins.
        assert built.payload["lease_id"] == "vault/leases/db/abc123"
        assert built.payload["secret_path"] == "database/creds/payments-read"
        assert built.payload["scope_label"] == "payments-read"
        assert built.payload["tenant_id"] == "t-1"
        assert built.payload["actor_subject"] == "user-42"
        assert built.payload["actor_type"] == "human"
        assert built.payload["session_id"] == "sess-1"

    async def test_request_ttl_and_granted_ttl_surface_distinctly(self) -> None:
        """Spec §6.2 load-bearing: request.ttl_s (900) MUST appear
        distinctly from lease.ttl_s_granted (600).

        Collapsing them in the payload projection would erase the
        examiner-evidence distinction between "what was requested" and
        "what Vault actually granted" — banks need both to audit
        whether Vault is honouring or capping per-secret TTL requests.
        """
        store = _make_store_mock()
        lease = _make_sample_lease()

        await sandbox_lifecycle_lease_minted(
            store,
            lease=lease,
            trace_id="trace-1",
            session_id="sess-1",
        )
        built = await _drive_emit_and_capture(store)

        assert built.payload["ttl_s"] == 900
        assert built.payload["ttl_s_granted"] == 600
        assert built.payload["ttl_s"] != built.payload["ttl_s_granted"]

    async def test_token_contents_never_appear_on_chain_row(self) -> None:
        """Spec §6.2 + AGENTS.md "Wire-protocol contracts": token
        contents MUST NOT appear on the chain row.

        Defence-in-depth: scans ALL payload values for the sentinel
        token string so a future refactor adding a stringified
        ``CredentialLease`` field (e.g. via ``__repr__`` or
        ``dataclasses.asdict``) cannot silently leak the token. Banks
        trace leases by ``lease_id`` + ``secret_path`` + ``scope_label``;
        the bearer token is the actual Vault credential and stays out of
        the audit chain.
        """
        store = _make_store_mock()
        lease = _make_sample_lease()

        await sandbox_lifecycle_lease_minted(
            store,
            lease=lease,
            trace_id="trace-1",
            session_id="sess-1",
        )
        built = await _drive_emit_and_capture(store)

        assert "token" not in built.payload
        for key, value in built.payload.items():
            assert "vault-token-NEVER-on-chain" not in str(value), (
                f"token leak via payload key {key!r}: {value!r}"
            )

    async def test_minted_at_and_expires_at_are_tz_aware_iso_strings(self) -> None:
        """Per ``feedback_evidence_boundary_runtime_validation``: the
        helper serialises ``datetime`` fields to ISO 8601 strings AND
        the strings round-trip back to tz-aware ``datetime`` (both
        ``tzinfo is not None`` AND ``utcoffset() is not None``).

        Naive datetimes silently corrupt examiner timelines across
        timezones; the chain-payload-canonical-bytes layer also rejects
        ``datetime`` directly (Sprint-2 doctrine), so the helper MUST
        serialise.
        """
        store = _make_store_mock()
        lease = _make_sample_lease()

        await sandbox_lifecycle_lease_minted(
            store,
            lease=lease,
            trace_id="trace-1",
            session_id="sess-1",
        )
        built = await _drive_emit_and_capture(store)

        for key in ("minted_at", "expires_at"):
            parsed = datetime.fromisoformat(built.payload[key])
            assert parsed.tzinfo is not None, (
                f"{key} MUST be tz-aware per feedback_evidence_boundary_runtime_validation"
            )
            assert parsed.utcoffset() is not None, (
                f"{key} tz-aware check requires BOTH tzinfo + utcoffset()"
            )


class TestSandboxLifecycleLeaseRevokedHelper:
    """Pin the spec §6.2 payload-shape contract for the
    ``sandbox.lifecycle.lease_revoked`` helper.

    Called from ``SandboxBackend.destroy()`` (T10) per successful
    revoke round-trip per spec §4.3 + §7.2. Same 11-key payload as
    ``lease_minted`` — the destroy path emits the same lease
    projection so examiners can correlate mint + revoke rows by
    ``lease_id``.
    """

    async def test_emits_with_correct_event_type_and_payload_keys(self) -> None:
        store = _make_store_mock()
        lease = _make_sample_lease()

        await sandbox_lifecycle_lease_revoked(
            store,
            lease=lease,
            trace_id="trace-1",
            session_id="sess-1",
        )
        built = await _drive_emit_and_capture(store)

        assert built.decision_type == "sandbox.lifecycle.lease_revoked"
        assert built.iso_controls == ("ISO42001.A.6.2.5",)
        # Chain-metadata DERIVED from lease (same derive as
        # lease_minted — proves per-lease chain rows carry identical
        # tenant/actor evidence end-to-end).
        assert built.tenant_id == lease.request.tenant_id == "t-1"
        assert built.actor_id == lease.request.actor_ref.actor_subject == "user-42"
        # Same 11-key payload as lease_minted.
        assert set(built.payload.keys()) == _EXPECTED_LEASE_PAYLOAD_KEYS
        assert built.payload["lease_id"] == "vault/leases/db/abc123"
        assert built.payload["session_id"] == "sess-1"

    async def test_token_contents_never_appear_on_chain_row(self) -> None:
        store = _make_store_mock()
        lease = _make_sample_lease()

        await sandbox_lifecycle_lease_revoked(
            store,
            lease=lease,
            trace_id="trace-1",
            session_id="sess-1",
        )
        built = await _drive_emit_and_capture(store)

        for key, value in built.payload.items():
            assert "vault-token-NEVER-on-chain" not in str(value), (
                f"token leak via payload key {key!r}: {value!r}"
            )


class TestSandboxLifecycleLeaseRevokeFailedHelper:
    """Pin the spec §6.2 + §7.2 payload-shape contract for the
    ``sandbox.lifecycle.lease_revoke_failed`` helper.

    Called from ``SandboxBackend.destroy()`` (T10) per FAILED revoke
    per spec §7.2 fail-soft policy: single attempt, on failure emit
    + continue destroy() (do NOT raise). Payload adds 2 conditional
    keys to the 11-key base:

    * ``vault_error`` — Vault HTTP error string (caller-supplied; the
      only field not derivable from CredentialLease).
    * ``auto_expiry_at`` — DERIVED from ``lease.expires_at`` per spec
      §6.2 line 624 (NOT caller-supplied; accepting it as a caller
      string would re-open the silent-lie bug class where a caller
      could pass an arbitrary string disagreeing with ``expires_at``).
    """

    async def test_emits_with_correct_event_type_and_payload_keys(self) -> None:
        store = _make_store_mock()
        lease = _make_sample_lease()

        await sandbox_lifecycle_lease_revoke_failed(
            store,
            lease=lease,
            trace_id="trace-1",
            session_id="sess-1",
            vault_error="Vault HTTP 503: service unavailable",
        )
        built = await _drive_emit_and_capture(store)

        assert built.decision_type == "sandbox.lifecycle.lease_revoke_failed"
        assert built.iso_controls == ("ISO42001.A.6.2.5",)
        # Chain-metadata DERIVED from lease (same derive as
        # lease_minted / lease_revoked above).
        assert built.tenant_id == lease.request.tenant_id == "t-1"
        assert built.actor_id == lease.request.actor_ref.actor_subject == "user-42"
        # spec §6.2 — 13 payload keys (11 base + vault_error +
        # auto_expiry_at).
        expected_keys = _EXPECTED_LEASE_PAYLOAD_KEYS | {
            "vault_error",
            "auto_expiry_at",
        }
        assert set(built.payload.keys()) == expected_keys

    async def test_auto_expiry_at_is_derived_from_lease_expires_at(self) -> None:
        """Spec §6.2 line 624: ``auto_expiry_at`` MUST equal
        ``expires_at`` (surfaced separately for the examiner's "this
        lease should auto-expire on its own" claim).

        Pin: the helper DERIVES ``auto_expiry_at`` from
        ``lease.expires_at`` — there is no caller-supplied kwarg
        through which a caller could pass an arbitrary string that
        disagrees with ``expires_at``. This regression closes the
        silent-lie bug class by construction.
        """
        store = _make_store_mock()
        lease = _make_sample_lease()
        expected_derived_auto_expiry = lease.expires_at.isoformat()

        await sandbox_lifecycle_lease_revoke_failed(
            store,
            lease=lease,
            trace_id="trace-1",
            session_id="sess-1",
            vault_error="Vault HTTP 503: service unavailable",
        )
        built = await _drive_emit_and_capture(store)

        # Derive pin: payload value MUST match lease.expires_at
        # serialised — the helper is the single mint site.
        assert built.payload["auto_expiry_at"] == expected_derived_auto_expiry
        # Cross-row consistency: auto_expiry_at MUST equal the
        # payload's own expires_at projection (both derived from the
        # same lease.expires_at; serialisation is byte-identical).
        assert built.payload["auto_expiry_at"] == built.payload["expires_at"]

    async def test_vault_error_carries_forensic_evidence(self) -> None:
        """Per spec §6.2 + §7.2: ``vault_error`` is the Vault HTTP error
        string (forensic evidence for SOC + bank compliance review).
        Only caller-supplied field (cannot be derived from
        ``CredentialLease``).
        """
        store = _make_store_mock()
        lease = _make_sample_lease()

        await sandbox_lifecycle_lease_revoke_failed(
            store,
            lease=lease,
            trace_id="trace-1",
            session_id="sess-1",
            vault_error="Vault HTTP 503: service unavailable",
        )
        built = await _drive_emit_and_capture(store)

        assert built.payload["vault_error"] == "Vault HTTP 503: service unavailable"
        # auto_expiry_at MUST be tz-aware (same evidence-boundary rule
        # as minted_at / expires_at).
        parsed = datetime.fromisoformat(built.payload["auto_expiry_at"])
        assert parsed.tzinfo is not None
        assert parsed.utcoffset() is not None

    async def test_token_contents_never_appear_on_chain_row(self) -> None:
        """Defence-in-depth: even on revoke-failed (where the lease
        is unrevoked + the token is still valid in Vault), the token
        contents MUST NOT appear on the chain row.
        """
        store = _make_store_mock()
        lease = _make_sample_lease()

        await sandbox_lifecycle_lease_revoke_failed(
            store,
            lease=lease,
            trace_id="trace-1",
            session_id="sess-1",
            vault_error="Vault HTTP 503: service unavailable",
        )
        built = await _drive_emit_and_capture(store)

        for key, value in built.payload.items():
            assert "vault-token-NEVER-on-chain" not in str(value), (
                f"token leak via payload key {key!r}: {value!r}"
            )
