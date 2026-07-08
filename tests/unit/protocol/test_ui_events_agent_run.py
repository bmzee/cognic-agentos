"""M8 A12 (ADR-027 + ADR-020) — agent.run.* decision-history typed projectors.

A11 emits ``agent.run.started`` / ``agent.run.completed`` / ``agent.run.refused``
/ ``agent.run.failed`` decision rows (plus A10's ``agent.run.dispatch``). A12
wires the five decision_types into ``_DECISION_HISTORY_TYPED_PROJECTORS`` so
replay + SSE surface them as typed ``agent_run`` events.

Pins (mirroring the snapshot-harness pattern of
``test_ui_events_dh_replay_snapshot.py`` + the per-type assertions of
``test_ui_events_typed_projectors.py``):

  - one test per decision_type: family/type slot, ``run_id`` extraction,
    tenant, payload passthrough into ``data``, ``audit_chain_hash`` format,
    chain-derived deterministic ``event_id`` (ordinal 0)
  - refused-vs-failed disambiguation: BOTH map onto the frozen family's
    ``AgentRunFailed`` model (there is no "refused" model — ADR-020
    backward-compat freezes the family vocabulary); the payload's
    ``refusal_reason``/``bound`` vs ``error_class`` keys distinguish them
  - no-new-models pin: the ``agent_run`` family's model set is EXACTLY the 7
    pre-A12 stubs (counted via the module's classes, NOT regex — per
    ``feedback_count_enum_values_via_ast_not_regex``)
  - existing-entries-untouched pin: the 12 pre-A12 table entries still map to
    their pre-A12 projector functions
  - table-count pin: 12 → 17
  - ``_TYPED_PROJECTION_CLASSES``: the 4 wired agent_run classes are members
    (the module contract comment's clause (c)); the 3 still-stub classes
    (Cancelled/Paused/Resumed) stay excluded
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, ClassVar

import pydantic

from cognic_agentos.core.decision_history import AppendedDecisionSnapshot
from cognic_agentos.protocol import ui_events as _ui_events_module
from cognic_agentos.protocol.ui_events import (
    _DECISION_HISTORY_TYPED_PROJECTORS,
    _TYPED_PROJECTION_CLASSES,
    AgentRunCancelled,
    AgentRunCompleted,
    AgentRunFailed,
    AgentRunPaused,
    AgentRunProgress,
    AgentRunResumed,
    AgentRunStarted,
    _chain_derived_event_id,
    _project_typed_decision_history,
)

_RUN_ID = "agent-run-" + "ab" * 16

#: Realistic A11 ``agent.run.started`` payload (digest-only per ADR-027 §f).
_STARTED_PAYLOAD: dict[str, Any] = {
    "run_id": _RUN_ID,
    "agent_id": "schema-advisor",
    "originator_subject": "analyst@bank",
    "question_sha256": "aa" * 32,
    "question_bytes": 42,
    "max_steps": 6,
    "token_budget": 24_000,
    "wall_clock_s": 120.0,
}

#: Realistic A10 ``agent.run.dispatch`` payload (one row per dispatch arm).
_DISPATCH_PAYLOAD: dict[str, Any] = {
    "run_id": _RUN_ID,
    "agent_id": "schema-advisor",
    "originator_subject": "analyst@bank",
    "capability_kind": "tool",
    "capability_ref": "cognic-tool-oracle-schema/describe_table",
    "scope_id": None,
    "step_index": 0,
    "outcome": "ok",
    "refusal_reason": None,
    "args_sha256": "bb" * 32,
    "result_sha256": "cc" * 32,
    "result_bytes": 128,
}

#: Realistic A11 terminal payload base (completed shape).
_COMPLETED_PAYLOAD: dict[str, Any] = {
    "run_id": _RUN_ID,
    "agent_id": "schema-advisor",
    "originator_subject": "analyst@bank",
    "answer_sha256": "dd" * 32,
    "answer_bytes": 256,
    "steps_used": 2,
    "prompt_tokens_total": 900,
    "completion_tokens_total": 300,
}

#: Terminal ``refused`` — the completed shape + refusal_reason + bound.
_REFUSED_PAYLOAD: dict[str, Any] = {
    **_COMPLETED_PAYLOAD,
    "refusal_reason": "agent_max_steps_exceeded",
    "bound": "max_steps",
}

#: Terminal ``failed`` — the completed shape + error_class.
_FAILED_PAYLOAD: dict[str, Any] = {
    **_COMPLETED_PAYLOAD,
    "error_class": "TimeoutError",
}


def _make_snapshot(
    *,
    decision_type: str,
    payload: dict[str, Any],
    sequence: int = 42,
    tenant_id: str = "tenant-a",
) -> AppendedDecisionSnapshot:
    """Snapshot-shaped row (mirrors the dh_replay harness) — the projectors
    are pure over snapshot inputs; no DB I/O."""
    return AppendedDecisionSnapshot(
        record_id=uuid.UUID(int=0),
        chain_id="decision_history",
        sequence=sequence,
        new_hash=b"\xaa" * 32,
        created_at=datetime.now(UTC),
        decision_type=decision_type,
        request_id=f"{_RUN_ID}-terminal",
        payload=payload,
        tenant_id=tenant_id,
        trace_id="trace-x",
    )


def _expected_event_id(*, sequence: int, type_: str) -> str:
    return _chain_derived_event_id(
        chain_id="decision_history",
        sequence=sequence,
        ordinal=0,
        family="agent_run",
        type_=type_,
    )


class TestAgentRunProjectorPerDecisionType:
    """One test per A12-wired decision_type — family/type slot + run_id +
    tenant + data passthrough + audit_chain_hash + deterministic event_id."""

    def test_agent_run_started(self) -> None:
        snap = _make_snapshot(decision_type="agent.run.started", payload=dict(_STARTED_PAYLOAD))
        evt = _project_typed_decision_history(snap)
        assert isinstance(evt, AgentRunStarted)
        assert evt.family == "agent_run"
        assert evt.type == "started"
        assert evt.run_id == _RUN_ID
        assert evt.tenant == "tenant-a"
        assert evt.trace_id == "trace-x"
        assert evt.data == _STARTED_PAYLOAD
        assert evt.audit_chain_hash == "sha256:" + "aa" * 32
        assert evt.event_id == _expected_event_id(sequence=42, type_="started")

    def test_agent_run_started_data_is_a_copy_of_the_payload(self) -> None:
        """``data={**snapshot.payload}`` passthrough — a later mutation of the
        source payload dict never reaches the projected (frozen) event."""
        payload = dict(_STARTED_PAYLOAD)
        snap = _make_snapshot(decision_type="agent.run.started", payload=payload)
        evt = _project_typed_decision_history(snap)
        assert evt is not None
        payload["question_sha256"] = "MUTATED"
        assert evt.data["question_sha256"] == "aa" * 32

    def test_agent_run_dispatch_projects_progress(self) -> None:
        snap = _make_snapshot(
            decision_type="agent.run.dispatch", payload=dict(_DISPATCH_PAYLOAD), sequence=7
        )
        evt = _project_typed_decision_history(snap)
        assert isinstance(evt, AgentRunProgress)
        assert evt.family == "agent_run"
        assert evt.type == "progress"
        assert evt.run_id == _RUN_ID
        assert evt.tenant == "tenant-a"
        assert evt.data == _DISPATCH_PAYLOAD
        assert evt.audit_chain_hash == "sha256:" + "aa" * 32
        assert evt.event_id == _expected_event_id(sequence=7, type_="progress")

    def test_agent_run_completed(self) -> None:
        snap = _make_snapshot(
            decision_type="agent.run.completed", payload=dict(_COMPLETED_PAYLOAD), sequence=9
        )
        evt = _project_typed_decision_history(snap)
        assert isinstance(evt, AgentRunCompleted)
        assert evt.family == "agent_run"
        assert evt.type == "completed"
        assert evt.run_id == _RUN_ID
        assert evt.data == _COMPLETED_PAYLOAD
        assert evt.event_id == _expected_event_id(sequence=9, type_="completed")

    def test_agent_run_refused_projects_onto_failed_model(self) -> None:
        """The frozen family has NO "refused" model — ``agent.run.refused``
        collapses onto :class:`AgentRunFailed` with the payload's
        ``refusal_reason``/``bound`` keys riding ``data`` untouched (inject
        NOTHING — the rows are already digest-only per A10/A11)."""
        snap = _make_snapshot(
            decision_type="agent.run.refused", payload=dict(_REFUSED_PAYLOAD), sequence=11
        )
        evt = _project_typed_decision_history(snap)
        assert isinstance(evt, AgentRunFailed)
        assert evt.family == "agent_run"
        assert evt.type == "failed"
        assert evt.run_id == _RUN_ID
        assert evt.data == _REFUSED_PAYLOAD
        assert evt.event_id == _expected_event_id(sequence=11, type_="failed")

    def test_agent_run_failed(self) -> None:
        snap = _make_snapshot(
            decision_type="agent.run.failed", payload=dict(_FAILED_PAYLOAD), sequence=13
        )
        evt = _project_typed_decision_history(snap)
        assert isinstance(evt, AgentRunFailed)
        assert evt.family == "agent_run"
        assert evt.type == "failed"
        assert evt.run_id == _RUN_ID
        assert evt.data == _FAILED_PAYLOAD
        assert evt.event_id == _expected_event_id(sequence=13, type_="failed")


class TestRefusedVsFailedDisambiguation:
    """Same model class; the distinguishing surface is the payload keyset
    riding ``data`` (refused → refusal_reason + bound; failed → error_class)."""

    def test_refused_and_failed_share_the_model_but_data_keys_distinguish(self) -> None:
        refused = _project_typed_decision_history(
            _make_snapshot(decision_type="agent.run.refused", payload=dict(_REFUSED_PAYLOAD))
        )
        failed = _project_typed_decision_history(
            _make_snapshot(decision_type="agent.run.failed", payload=dict(_FAILED_PAYLOAD))
        )
        assert type(refused) is AgentRunFailed
        assert type(failed) is AgentRunFailed
        # refused carries the bound vocabulary, never an error class.
        assert refused is not None and failed is not None
        assert refused.data["refusal_reason"] == "agent_max_steps_exceeded"
        assert refused.data["bound"] == "max_steps"
        assert "error_class" not in refused.data
        # failed carries the exception CLASS name, never a bound.
        assert failed.data["error_class"] == "TimeoutError"
        assert "bound" not in failed.data
        assert "refusal_reason" not in failed.data

    def test_refused_and_failed_event_ids_collide_only_across_sequences(self) -> None:
        """Both encode ``type_="failed"`` — the SAME sequence yields the SAME
        cursor (deliberate: one chain row emits one typed event; refused and
        failed rows are distinct rows so distinct sequences in practice)."""
        refused = _project_typed_decision_history(
            _make_snapshot(
                decision_type="agent.run.refused", payload=dict(_REFUSED_PAYLOAD), sequence=5
            )
        )
        failed = _project_typed_decision_history(
            _make_snapshot(
                decision_type="agent.run.failed", payload=dict(_FAILED_PAYLOAD), sequence=6
            )
        )
        assert refused is not None and failed is not None
        assert refused.event_id != failed.event_id


class TestRunIdGuard:
    """``run_id`` is extracted via an isinstance-str guard — a malformed
    (non-str) payload value degrades to None, never a type leak."""

    def test_non_str_run_id_projects_none(self) -> None:
        payload = {**_STARTED_PAYLOAD, "run_id": 123}
        evt = _project_typed_decision_history(
            _make_snapshot(decision_type="agent.run.started", payload=payload)
        )
        assert evt is not None
        assert evt.run_id is None

    def test_absent_run_id_projects_none(self) -> None:
        payload = {k: v for k, v in _DISPATCH_PAYLOAD.items() if k != "run_id"}
        evt = _project_typed_decision_history(
            _make_snapshot(decision_type="agent.run.dispatch", payload=payload)
        )
        assert evt is not None
        assert evt.run_id is None


class TestAgentRunFamilyModelSetFrozen:
    """No-new-models pin (ADR-020 backward-compat): the agent_run family's
    model set is EXACTLY the 7 pre-A12 stubs. Counted via the module's
    classes (family Literal default), NOT regex."""

    def test_agent_run_model_set_is_exactly_the_seven_stubs(self) -> None:
        agent_run_models = {
            name
            for name, obj in vars(_ui_events_module).items()
            if isinstance(obj, type)
            and issubclass(obj, pydantic.BaseModel)
            and "family" in obj.model_fields
            and obj.model_fields["family"].default == "agent_run"
        }
        assert agent_run_models == {
            "AgentRunStarted",
            "AgentRunProgress",
            "AgentRunCompleted",
            "AgentRunFailed",
            "AgentRunCancelled",
            "AgentRunPaused",
            "AgentRunResumed",
        }


class TestDispatchTableAfterA12:
    """Table-shape pins: 12 → 17 entries; the 12 pre-A12 entries untouched;
    the 5 new agent.run.* entries map to the A12 projector functions."""

    #: The 12 pre-A12 entries and the projector each mapped to BEFORE A12 —
    #: hand-pinned here so an accidental remap during the A12 edit fails loud.
    _PRE_A12_ENTRIES: ClassVar[dict[str, str]] = {
        "frontend_action.submitted": "_project_frontend_action_submitted",
        "frontend_action.accepted": "_project_frontend_action_accepted",
        "frontend_action.rejected": "_project_frontend_action_rejected",
        "policy.decision_evaluated": "_project_policy_decision_evaluated",
        "subagent.spawn": "_project_subagent_spawned",
        "subagent.return": "_project_subagent_return",
        "memory.read": "_project_memory_recall_completed",
        "memory.forget": "_project_memory_forget",
        "memory.regulator_erasure": "_project_memory_regulator_erasure",
        "memory.redact": "_project_memory_redact",
        "emergency.kill_switch_flipped": "_project_kill_switch_flipped",
        "emergency.kill_switch_reverted": "_project_kill_switch_reverted",
    }

    _A12_ENTRIES: ClassVar[dict[str, str]] = {
        "agent.run.started": "_project_agent_run_started",
        "agent.run.dispatch": "_project_agent_run_dispatch",
        "agent.run.completed": "_project_agent_run_completed",
        "agent.run.refused": "_project_agent_run_refused",
        "agent.run.failed": "_project_agent_run_failed",
    }

    def test_table_count_is_seventeen(self) -> None:
        assert len(_DECISION_HISTORY_TYPED_PROJECTORS) == 17

    def test_pre_a12_entries_untouched(self) -> None:
        for decision_type, projector_name in self._PRE_A12_ENTRIES.items():
            assert decision_type in _DECISION_HISTORY_TYPED_PROJECTORS, (
                f"pre-A12 entry {decision_type!r} dropped from the dispatch table"
            )
            assert _DECISION_HISTORY_TYPED_PROJECTORS[decision_type].__name__ == projector_name, (
                f"pre-A12 entry {decision_type!r} remapped away from {projector_name}"
            )

    def test_a12_entries_present_and_mapped(self) -> None:
        for decision_type, projector_name in self._A12_ENTRIES.items():
            assert decision_type in _DECISION_HISTORY_TYPED_PROJECTORS, (
                f"A12 entry {decision_type!r} missing from the dispatch table"
            )
            assert _DECISION_HISTORY_TYPED_PROJECTORS[decision_type].__name__ == projector_name

    def test_table_keyset_is_exactly_pre_a12_plus_a12(self) -> None:
        assert set(_DECISION_HISTORY_TYPED_PROJECTORS.keys()) == (
            set(self._PRE_A12_ENTRIES) | set(self._A12_ENTRIES)
        )


class TestTypedProjectionClassesMembership:
    """The 4 A12-wired classes join ``_TYPED_PROJECTION_CLASSES`` (the module
    contract's clause (c) — the ContextVar capture filter); the 3 still-stub
    classes stay excluded (no chain row emits them)."""

    def test_wired_agent_run_classes_are_members(self) -> None:
        for cls in (AgentRunStarted, AgentRunProgress, AgentRunCompleted, AgentRunFailed):
            assert cls in _TYPED_PROJECTION_CLASSES, (
                f"{cls.__name__} missing from _TYPED_PROJECTION_CLASSES; the table's "
                "drift comment requires (c) class membership for every wired projector"
            )

    def test_stub_agent_run_classes_stay_excluded(self) -> None:
        for cls in (AgentRunCancelled, AgentRunPaused, AgentRunResumed):
            assert cls not in _TYPED_PROJECTION_CLASSES, (
                f"{cls.__name__} is in _TYPED_PROJECTION_CLASSES but no chain row "
                "projects it — model-only stubs stay excluded until their owning task"
            )
