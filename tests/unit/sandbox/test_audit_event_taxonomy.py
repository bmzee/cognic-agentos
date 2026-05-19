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
test_only_no_runtime_import``: ``TestSandboxLifecycleEventVocabHas12Values``
(Sprint 8.5 T1 extended from 8 → 12; renamed) pins the count + the
exact strings as a test-only check (the production module re-uses the
``SandboxLifecycleEvent`` Literal from ``sandbox/protocol.py`` directly
— there is no runtime cross-module copy that needs lockstep
enforcement).
"""

from __future__ import annotations

import typing
import uuid
from typing import cast
from unittest.mock import AsyncMock

import pytest

from cognic_agentos.core.decision_history import DecisionRecord
from cognic_agentos.sandbox import SandboxLifecycleEvent
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
        ``DecisionRecord`` with ``iso_controls=('A.6.2.5',)`` per
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
        assert built.iso_controls == ("A.6.2.5",)
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
    lives separately at ``TestSandboxLifecycleEventVocabHas12Values``.
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


class TestSandboxLifecycleEventVocabHas12Values:
    """Spec line 808 + §979 + Sprint 8.5 §3.3 — pin the 12-value count
    + the exact strings.

    No ``warm_pool.replenished`` per the user-locked taxonomy at §4.3 —
    replenishment is the *cause*; the *event* is still ``precreated``.

    Sprint 8.5 T1 extended 8 → 12 (4 new events per spec §3.3).
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
        }
    )

    def test_event_count_is_exactly_twelve(self) -> None:
        assert len(typing.get_args(SandboxLifecycleEvent)) == 12

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
