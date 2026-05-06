"""Sprint 6 T12 — protocol/ui_events.py model contract tests.

Pin the typed Pydantic event-family contracts per ADR-020 §"Event
taxonomy (Wave 1)". The schema is **public** (Sprint-7B SSE
subscribers consume it); pinning each family/type Literal +
``schema_version`` constant + ``event_id`` ULID format guards
against silent drift.

T12 R0 doctrines pinned:
  - Family-level + type-level Literal discrimination (R0 #6).
  - ``event_id`` is ULID-shaped + ``evt_`` prefix (R0 #5).
  - ``run_id: str | None = None`` (R0 #4).
  - SCHEMA_VERSION is "1.0".
"""

from __future__ import annotations

import datetime as dt
import re

import pydantic
import pytest

from cognic_agentos.protocol.ui_events import (
    SCHEMA_VERSION,
    AgentRunStarted,
    ArtifactCompleted,
    DecisionAuditEventAppended,
    ToolCallApproved,
    ToolCallCompleted,
    ToolCallDenied,
    ToolCallFailed,
    _new_event_id,
)

# =============================================================================
# event_id format (ULID-shaped per T12 R0 doctrine #5)
# =============================================================================


class TestEventIdFormat:
    def test_event_id_has_evt_prefix(self) -> None:
        assert _new_event_id().startswith("evt_")

    def test_event_id_is_thirty_chars(self) -> None:
        """``evt_`` (4) + ULID body (26) = 30 chars total."""
        assert len(_new_event_id()) == 30

    def test_event_id_body_is_crockford_base32(self) -> None:
        """ULID Crockford-base32 alphabet: 0-9, A-Z minus I, L, O, U.
        The 26-char body MUST conform; a regression to UUID4 hex
        would let lowercase + ``-`` chars through."""
        body = _new_event_id()[len("evt_") :]
        assert re.match(r"^[0-9A-HJKMNP-TV-Z]{26}$", body), (
            f"event_id body {body!r} does not match Crockford-base32 alphabet "
            f"(ULID regression to UUID4 hex / different scheme)"
        )

    def test_event_ids_are_unique(self) -> None:
        ids = {_new_event_id() for _ in range(100)}
        assert len(ids) == 100

    def test_event_ids_are_time_orderable(self) -> None:
        """ULIDs are time-ordered. Stringify-sort MUST match
        creation order (ULID's timestamp prefix is the leading 10
        chars). Critical for Sprint-7B SSE-resume cursor semantics."""
        first = _new_event_id()
        # Sleep 2ms — ULID timestamp resolution is ms.
        import time as _time

        _time.sleep(0.002)
        second = _new_event_id()
        assert first < second, "ULIDs MUST be time-orderable"


# =============================================================================
# Model shape — family + type Literal discrimination (R0 doctrine #6)
# =============================================================================


@pytest.fixture
def now() -> dt.datetime:
    return dt.datetime(2026, 4, 27, 14, 23, 11, 123_000, tzinfo=dt.UTC)


class TestFamilyTypeLiterals:
    """Per T12 R0 #6: each model carries both ``family: Literal[...]``
    AND ``type: Literal[...]``. Discrimination by ``family`` alone
    AND by ``type`` alone are both insufficient (e.g. ``completed``
    appears in agent_run + tool_call + subagent + artifact)."""

    def test_tool_call_completed_pins_family_and_type(self, now: dt.datetime) -> None:
        e = ToolCallCompleted(ts=now, tenant="bank_a", audit_chain_hash="sha256:x")
        assert e.family == "tool_call"
        assert e.type == "completed"

    def test_artifact_completed_pins_family_and_type(self, now: dt.datetime) -> None:
        e = ArtifactCompleted(ts=now, tenant="bank_a", audit_chain_hash="sha256:x")
        assert e.family == "artifact"
        assert e.type == "completed"

    def test_completed_value_is_shared_across_families(self) -> None:
        """Pin that ``completed`` repeats — discriminating only on
        ``type`` would collide. The two events have the SAME ``type``
        but DIFFERENT ``family``."""
        assert ToolCallCompleted.model_fields["type"].default == "completed"
        assert ArtifactCompleted.model_fields["type"].default == "completed"
        assert (
            ToolCallCompleted.model_fields["family"].default
            != ArtifactCompleted.model_fields["family"].default
        )


# =============================================================================
# Pydantic v2 model_dump / model_validate round-trip
# =============================================================================


class TestModelRoundTrip:
    def test_tool_call_completed_round_trip(self, now: dt.datetime) -> None:
        original = ToolCallCompleted(
            ts=now,
            tenant="bank_a",
            run_id=None,
            trace_id="trace-1",
            audit_chain_hash="sha256:abc",
            data={"tool": "foo", "request_id": "rid-1"},
        )
        serialized = original.model_dump()
        restored = ToolCallCompleted.model_validate(serialized)
        assert restored == original

    def test_decision_audit_event_appended_round_trip(self, now: dt.datetime) -> None:
        original = DecisionAuditEventAppended(
            ts=now,
            tenant="bank_a",
            trace_id="trace-1",
            audit_chain_hash="sha256:def",
            data={"decision_type": "a2a_call", "request_id": "rid-2"},
        )
        restored = DecisionAuditEventAppended.model_validate(original.model_dump())
        assert restored == original


# =============================================================================
# run_id is optional (R0 doctrine #4)
# =============================================================================


class TestRunIdOptional:
    """Per T12 R0 #4: ``run_id: str | None = None`` for Sprint-6.
    No agent-run primitive yet (Sprint-7A introduces it)."""

    def test_run_id_defaults_to_none(self, now: dt.datetime) -> None:
        e = ToolCallCompleted(ts=now, tenant="bank_a", audit_chain_hash="sha256:x")
        assert e.run_id is None

    def test_run_id_accepts_string_when_provided(self, now: dt.datetime) -> None:
        e = ToolCallCompleted(
            ts=now,
            tenant="bank_a",
            audit_chain_hash="sha256:x",
            run_id="run_01HV...",
        )
        assert e.run_id == "run_01HV..."

    def test_run_id_in_serialized_output(self, now: dt.datetime) -> None:
        """When unset, ``run_id`` MUST round-trip as ``null`` (not
        omitted) so SSE consumers see the field."""
        e = ToolCallCompleted(ts=now, tenant="bank_a", audit_chain_hash="sha256:x")
        d = e.model_dump()
        assert "run_id" in d
        assert d["run_id"] is None


# =============================================================================
# Frozen invariant
# =============================================================================


class TestFrozenInvariant:
    def test_event_is_frozen(self, now: dt.datetime) -> None:
        e = ToolCallCompleted(ts=now, tenant="bank_a", audit_chain_hash="sha256:x")
        # Pydantic v2 frozen check — ValidationError on set
        with pytest.raises(pydantic.ValidationError):
            e.tenant = "bank_b"


# =============================================================================
# SCHEMA_VERSION
# =============================================================================


class TestSchemaVersion:
    def test_schema_version_is_one_dot_oh(self) -> None:
        """Pinned at "1.0" per ADR-020. A bump requires a deliberate
        wire-format-migration review."""
        assert SCHEMA_VERSION == "1.0"


# =============================================================================
# All seven tool_call subclasses pin distinct types
# =============================================================================


class TestToolCallFamily:
    def test_all_tool_call_types_distinct(self, now: dt.datetime) -> None:
        approved = ToolCallApproved(ts=now, tenant="t", audit_chain_hash="x")
        denied = ToolCallDenied(ts=now, tenant="t", audit_chain_hash="x")
        completed = ToolCallCompleted(ts=now, tenant="t", audit_chain_hash="x")
        failed = ToolCallFailed(ts=now, tenant="t", audit_chain_hash="x")
        types = {approved.type, denied.type, completed.type, failed.type}
        assert types == {"approved", "denied", "completed", "failed"}
        # All share the same family.
        families = {approved.family, denied.family, completed.family, failed.family}
        assert families == {"tool_call"}


# =============================================================================
# AgentRun schema-only stub still constructs
# =============================================================================


class TestSchemaOnlyStubsConstruct:
    """Schema-only families (no emit hooks in Sprint 6) MUST still
    be constructible — Sprint-7B SSE subscribers see the full
    11-family contract immediately when SSE lands."""

    def test_agent_run_started_constructs(self, now: dt.datetime) -> None:
        e = AgentRunStarted(ts=now, tenant="bank_a", audit_chain_hash="sha256:x")
        assert e.family == "agent_run"
        assert e.type == "started"
