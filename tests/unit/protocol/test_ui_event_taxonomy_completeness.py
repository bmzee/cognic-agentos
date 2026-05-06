"""Sprint 6 T12 — UI event taxonomy + layer-safety drift detectors.

Pin two invariants against silent regression:

  1. **Taxonomy completeness** (T12 R0 doctrine #6 + #8) — the 11
     Wave-1 family literal-set MUST equal the ADR-020 published
     taxonomy + the Sprint-6-WIRED set MUST equal exactly
     ``{"tool_call", "artifact", "decision_audit"}``. Adding a
     family without updating ADR-020 + adding a 4th wired family
     in Sprint 6 are both regressions that MUST trip this test.

  2. **Layer safety** (T12 R0 doctrine #1) — ``core/audit.py`` and
     ``core/decision_history.py`` MUST NOT import any
     ``cognic_agentos.protocol.*`` submodule. The hook surface is
     a generic Callable; the UI emitter implements it from
     ``protocol/`` and registers itself at construction. AST-walk
     regression bans the layering violation.
"""

from __future__ import annotations

import ast
import inspect
from types import ModuleType
from typing import Any

from cognic_agentos.protocol.ui_events import (
    _WAVE_1_FAMILIES,
    _WIRED_IN_SPRINT_6,
)

# =============================================================================
# Wave-1 taxonomy completeness
# =============================================================================


class TestWave1FamilySet:
    """All 11 families per ADR-020 §"Event taxonomy (Wave 1)" MUST
    appear in :data:`_WAVE_1_FAMILIES`. Adding/dropping one trips
    this test before merge."""

    def test_wave1_family_count(self) -> None:
        """ADR-020 §"Event taxonomy (Wave 1)" lists exactly 11
        families."""
        assert len(_WAVE_1_FAMILIES) == 11

    def test_wave1_family_set(self) -> None:
        expected = {
            "agent_run",
            "tool_call",
            "subagent",
            "approval",
            "artifact",
            "interrupt",
            "frontend_action",
            "memory",
            "decision_audit",
            "policy",
            "kill_switch",
        }
        assert expected == _WAVE_1_FAMILIES


# =============================================================================
# Sprint-6 wired-family set
# =============================================================================


class TestWiredFamilySet:
    """T12 R0 doctrine #8 — the wired-in-Sprint-6 set is exactly
    ``{tool_call, artifact, decision_audit}``. Adding a 4th wired
    family in Sprint 6 (rather than the family's owning sprint per
    ADR-020 phase table) is a regression that trips this pin."""

    def test_wired_family_count(self) -> None:
        assert len(_WIRED_IN_SPRINT_6) == 3

    def test_wired_family_set(self) -> None:
        assert frozenset({"tool_call", "artifact", "decision_audit"}) == _WIRED_IN_SPRINT_6

    def test_wired_subset_of_wave1(self) -> None:
        """Every wired family MUST be a Wave-1 family."""
        assert _WIRED_IN_SPRINT_6 <= _WAVE_1_FAMILIES


# =============================================================================
# Layer-safety regression — core/ MUST NOT import protocol/
# =============================================================================


class TestLayerSafety:
    """T12 R0 doctrine #1 — ``core/audit.py`` + ``core/decision_history.py``
    MUST NOT import ``cognic_agentos.protocol.*``. AST-walks the
    source files for any forbidden import; trips before merge.

    Mirrors Sprint-6 T10's no-direct-SDK regression in
    :mod:`tests.unit.protocol.test_a2a_streaming.TestSchemaModuleBoundary`."""

    def test_core_audit_does_not_import_protocol(self) -> None:
        from cognic_agentos.core import audit as audit_mod

        self._assert_no_protocol_import(audit_mod, "core/audit.py")

    def test_core_decision_history_does_not_import_protocol(self) -> None:
        from cognic_agentos.core import decision_history as dh_mod

        self._assert_no_protocol_import(dh_mod, "core/decision_history.py")

    @staticmethod
    def _assert_no_protocol_import(module: ModuleType, label: str) -> None:
        tree = ast.parse(inspect.getsource(module))
        forbidden_prefixes = ("cognic_agentos.protocol",)
        offenders: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if any(alias.name.startswith(p) for p in forbidden_prefixes):
                        offenders.append(f"import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                module_name = node.module or ""
                if any(module_name.startswith(p) for p in forbidden_prefixes):
                    offenders.append(f"from {module_name} import ...")
        assert not offenders, (
            f"{label} imports cognic_agentos.protocol.* (T12 R0 #1 layer violation): {offenders}"
        )


# =============================================================================
# Routing tables align with audit event_type vocabulary
# =============================================================================


class TestRoutingTables:
    """The Sprint-6-wired routing tables MUST be aligned with the
    actual audit event_type vocabulary that Sprint-5 (mcp_host) +
    Sprint-6 (a2a_artifacts) emit. Drift detector against typos."""

    def test_tool_call_routing_keys(self) -> None:
        from cognic_agentos.protocol.ui_events import (
            _TOOL_CALL_AUDIT_ROUTING,
        )

        assert set(_TOOL_CALL_AUDIT_ROUTING.keys()) == {
            "audit.tool_invocation",
            "audit.tool_invocation_refused",
            "audit.tool_invocation_error",
        }

    def test_tool_call_routing_values(self) -> None:
        from cognic_agentos.protocol.ui_events import (
            _TOOL_CALL_AUDIT_ROUTING,
        )

        assert _TOOL_CALL_AUDIT_ROUTING == {
            "audit.tool_invocation": ("tool_call", "completed"),
            "audit.tool_invocation_refused": ("tool_call", "denied"),
            "audit.tool_invocation_error": ("tool_call", "failed"),
        }

    def test_artifact_routing(self) -> None:
        from cognic_agentos.protocol.ui_events import (
            _ARTIFACT_AUDIT_ROUTING,
        )

        assert _ARTIFACT_AUDIT_ROUTING == {
            "a2a.artifact_prepared": ("artifact", "completed"),
        }


# =============================================================================
# T12 R1 P2 #1 — UIEvent discriminated union builds + validates
# =============================================================================


class TestUIEventDiscriminatedUnion:
    """T12 R1 P2 #1 reviewer correction: ``Annotated[Union[...],
    Field(discriminator="family")]`` over a flat union of all 35
    event subclasses fails Pydantic adapter creation because each
    family has multiple event classes (``family`` is NOT unique
    per branch). The fix is a two-level discriminated union:
    per-family inner union on ``type``, top-level union on
    ``family``.

    Public ADR-020 consumers MUST be able to:
      - Build ``TypeAdapter(UIEvent)`` without error.
      - Validate any concrete event class through the adapter.
      - Round-trip serialize → validate.
    """

    def test_type_adapter_builds(self) -> None:
        """Pydantic adapter builds without TypeError. Pre-fix this
        raised ``TypeError: Value 'agent_run' for discriminator
        'family' mapped to multiple choices``."""
        import pydantic

        from cognic_agentos.protocol.ui_events import UIEvent

        adapter: pydantic.TypeAdapter[Any] = pydantic.TypeAdapter(UIEvent)
        # Adapter constructed successfully; smoke-test the schema.
        schema = adapter.json_schema()
        assert isinstance(schema, dict)

    def test_type_adapter_validates_each_family(self) -> None:
        """Round-trip a representative event from each Wave-1
        family through the adapter."""
        import datetime as dt

        import pydantic

        from cognic_agentos.protocol.ui_events import (
            AgentRunStarted,
            ApprovalPending,
            ArtifactCompleted,
            DecisionAuditEventAppended,
            FrontendActionSubmitted,
            InterruptRequestedByAgent,
            KillSwitchFlipped,
            MemoryRecallStarted,
            PolicyDecisionEvaluated,
            SubagentSpawned,
            ToolCallCompleted,
            UIEvent,
        )

        adapter: pydantic.TypeAdapter[Any] = pydantic.TypeAdapter(UIEvent)
        now = dt.datetime.now(dt.UTC)
        family_representatives = [
            AgentRunStarted(ts=now, audit_chain_hash="x"),
            ToolCallCompleted(ts=now, audit_chain_hash="x"),
            SubagentSpawned(ts=now, audit_chain_hash="x"),
            ApprovalPending(ts=now, audit_chain_hash="x"),
            ArtifactCompleted(ts=now, audit_chain_hash="x"),
            InterruptRequestedByAgent(ts=now, audit_chain_hash="x"),
            FrontendActionSubmitted(ts=now, audit_chain_hash="x"),
            MemoryRecallStarted(ts=now, audit_chain_hash="x"),
            DecisionAuditEventAppended(ts=now, audit_chain_hash="x"),
            PolicyDecisionEvaluated(ts=now, audit_chain_hash="x"),
            KillSwitchFlipped(ts=now, audit_chain_hash="x"),
        ]
        for event in family_representatives:
            serialized = event.model_dump()
            restored = adapter.validate_python(serialized)
            assert type(restored) is type(event), (
                f"adapter failed to round-trip {type(event).__name__}: "
                f"got {type(restored).__name__}"
            )
