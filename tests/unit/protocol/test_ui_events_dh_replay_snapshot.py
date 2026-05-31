"""Sprint 7B.4 T10 R1 P1 #1 — pin _DHReplaySnapshot field-shape
compatibility with AppendedDecisionSnapshot.

T10 introduces :class:`cognic_agentos.protocol.ui_events._DHReplaySnapshot`
as a replay-side snapshot built from raw ``_decision_history`` rows in
:func:`portal.api.ui.stream_routes._replay_from_decision_history`. The
projectors :func:`_project_typed_decision_history` +
:func:`_build_decision_audit_for_dh_snapshot` are declared with the
:class:`AppendedDecisionSnapshot` parameter type but the replay path
passes ``_DHReplaySnapshot`` instances via ``cast``. The cast hides
structural drift from mypy — a future projector adding an attribute
access on a field NOT present on ``_DHReplaySnapshot`` would type-check
clean and fail only at runtime during replay (client experience:
broken stream; server-side: ``AttributeError`` inside the SSE
generator).

This module pins the structural contract three ways, each DERIVED
from code (NOT from a hand-maintained constant — per the R1 P1 #1
review, a hand-maintained constant defeats the purpose; the test
must update automatically when the projectors update):

  1. **Field-name subset (static):** every dataclass field of
     ``_DHReplaySnapshot`` MUST exist on ``AppendedDecisionSnapshot``
     (so a ``cast(AppendedDecisionSnapshot, replay_snapshot)`` reads
     the same field as a real append-time snapshot would). Derived
     from ``dataclasses.fields(...)``.

  2. **AST-walk access surface (static, derived from source):** parses
     the actual projector source bodies + collects every
     ``snapshot.<attr>`` access node. Compares against
     ``_DHReplaySnapshot``'s field set. A future projector adding
     ``snapshot.actor_id`` access surfaces here automatically WITHOUT
     a constant update.

  3. **Parametrized runtime smoke (dynamic):** drives every
     ``_DECISION_HISTORY_TYPED_PROJECTORS`` entry + every
     ``_RBAC_DENIAL_TYPE_VALUES`` ``rbac.<suffix>`` route through
     :func:`_project_typed_decision_history` +
     :func:`_build_decision_audit_for_dh_snapshot` with a constructed
     ``_DHReplaySnapshot`` instance — proves no ``AttributeError``
     against the runtime values. Catches helper-indirection cases
     the AST walk would miss (a projector that passes ``snapshot``
     into a helper not in the walked function set).
"""

from __future__ import annotations

import ast
import dataclasses
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from cognic_agentos.core.decision_history import AppendedDecisionSnapshot
from cognic_agentos.protocol import ui_events as _ui_events_module
from cognic_agentos.protocol.ui_events import (
    _RBAC_DENIAL_TYPE_VALUES,
    _build_decision_audit_for_dh_snapshot,
    _DHReplaySnapshot,
    _project_typed_decision_history,
)

# Functions whose bodies are walked for ``snapshot.<attr>`` access.
# Derived from the call chain inside
# :func:`_project_typed_decision_history` +
# :func:`_build_decision_audit_for_dh_snapshot` (every per-type
# projector dispatched by the former, plus the latter). Adding a new
# projector to the dispatch table requires adding the function name
# here too — pinned by the parametrized runtime test below which
# drives the dispatcher (NOT the function set), so a missing entry
# surfaces as a runtime test failure on the new decision_type.
_WALKED_PROJECTORS: frozenset[str] = frozenset(
    {
        "_project_typed_decision_history",
        "_project_frontend_action_submitted",
        "_project_frontend_action_accepted",
        "_project_frontend_action_rejected",
        "_project_policy_decision_evaluated",
        "_project_policy_rbac_denied",
        # Sprint 11b T9 — subagent projectors + the depth-cap scoping helper.
        # recursion_capped is NOT a registry key (it routes via the escalation
        # conditional), so the parametrized replay test does not reach it; the
        # AST walk here is what pins its snapshot-field access to the replay set.
        "_project_subagent_spawned",
        "_project_subagent_return",
        "_is_subagent_depth_cap",
        "_project_subagent_recursion_capped",
        "_build_decision_audit_for_dh_snapshot",
    }
)


def _collect_snapshot_attr_accesses(source: str, function_names: frozenset[str]) -> set[str]:
    """Walk ``source`` as Python AST; return every distinct ``snapshot.<attr>``
    access node found inside the bodies of functions named in ``function_names``.

    The walk handles:

      - ``snapshot.foo`` — direct attribute access (``Attribute`` node
        whose ``value`` is a ``Name`` with ``id=="snapshot"``)
      - rebinding inside the function body (``s = snapshot``) is NOT
        followed — projectors don't currently do this; adding such a
        pattern would require extending this walker
      - ``getattr(snapshot, "foo")`` dynamic access is NOT detected —
        also not currently used; the parametrized runtime smoke
        catches that drift class via ``AttributeError`` at call time
    """
    tree = ast.parse(source)
    accesses: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if node.name not in function_names:
            continue
        for inner in ast.walk(node):
            if (
                isinstance(inner, ast.Attribute)
                and isinstance(inner.value, ast.Name)
                and inner.value.id == "snapshot"
            ):
                accesses.add(inner.attr)
    return accesses


def _build_replay_snapshot(decision_type: str) -> _DHReplaySnapshot:
    """Construct a syntactically-valid ``_DHReplaySnapshot`` instance
    with the requested ``decision_type``. Payload shape is the
    intersection of what the per-type projectors might read; the
    current projectors pass ``payload`` through as ``data`` without
    inspecting keys, so a minimal dict suffices."""
    return _DHReplaySnapshot(
        sequence=1,
        decision_type=decision_type,
        tenant_id="t1",
        trace_id=None,
        request_id="portal-req-1",
        payload={
            "request_id": "portal-req-1",
            "tenant_id": "t1",
            "actor_subject": "u1",
            "decision_type": decision_type,
        },
        new_hash=b"\x00" * 32,
        chain_id="decision_history",
        created_at=datetime.now(UTC),
    )


class TestDHReplaySnapshotShapeMatchesAppendedDecisionSnapshot:
    """Structural compatibility pin between the replay-side snapshot
    and the append-time snapshot the projector signatures declare."""

    def test_replay_snapshot_field_names_are_subset_of_appended_snapshot(self) -> None:
        """Cast-safety: every ``_DHReplaySnapshot`` field MUST exist on
        ``AppendedDecisionSnapshot``. Without this, a
        ``cast(AppendedDecisionSnapshot, replay_snapshot)`` would let a
        replay-side-only field escape into projector code that doesn't
        expect it (drift class: replay vs. live divergence)."""
        replay_fields = {f.name for f in dataclasses.fields(_DHReplaySnapshot)}
        appended_fields = {f.name for f in dataclasses.fields(AppendedDecisionSnapshot)}
        missing = replay_fields - appended_fields
        assert not missing, (
            f"_DHReplaySnapshot fields not present on AppendedDecisionSnapshot: "
            f"{missing}. Replay-side fields that don't exist on the append-time "
            f"snapshot are wire-protocol drift."
        )

    def test_ast_derived_projector_accesses_are_subset_of_replay_snapshot(self) -> None:
        """Walks the ACTUAL projector source bodies (not a constant)
        and collects every ``snapshot.<attr>`` access. Every accessed
        attribute MUST exist on ``_DHReplaySnapshot`` — else the
        replay path ``AttributeError``s.

        This is the load-bearing detector: a future projector adding
        ``snapshot.actor_id`` access fails this test automatically
        WITHOUT updating any constant in this file. (R1 P1 #1 fix:
        replaced the hand-maintained ``_PROJECTOR_FIELD_ACCESS_SURFACE``
        constant with this code-derived check.)"""
        source = Path(_ui_events_module.__file__).read_text()
        actual_accesses = _collect_snapshot_attr_accesses(source, _WALKED_PROJECTORS)
        replay_fields = {f.name for f in dataclasses.fields(_DHReplaySnapshot)}
        missing = actual_accesses - replay_fields
        assert not missing, (
            f"AST walk of {sorted(_WALKED_PROJECTORS)} found snapshot accesses "
            f"NOT present on _DHReplaySnapshot: {missing}. The replay path "
            f"would AttributeError at runtime. Either add these fields to "
            f"_DHReplaySnapshot (+ wire them in _replay_from_decision_history's "
            f"row→snapshot mapping) OR remove the access from the projector."
        )

    def test_ast_walk_found_non_empty_access_set(self) -> None:
        """Sentinel — if the AST walker silently finds zero accesses
        (e.g. the projector function names drifted + ``_WALKED_PROJECTORS``
        no longer matches), the previous test would vacuously pass. This
        test pins ``actual_accesses`` non-empty so the walker
        correctness is independently verified."""
        source = Path(_ui_events_module.__file__).read_text()
        actual_accesses = _collect_snapshot_attr_accesses(source, _WALKED_PROJECTORS)
        assert actual_accesses, (
            f"AST walk found ZERO snapshot.<attr> accesses across "
            f"{sorted(_WALKED_PROJECTORS)}. Either the projector function "
            f"names have drifted (update _WALKED_PROJECTORS) or the walker "
            f"is broken (debug _collect_snapshot_attr_accesses)."
        )


class TestDHReplaySnapshotDrivesEveryDispatchedProjector:
    """Runtime-smoke: drives every entry the dispatcher
    (:func:`_project_typed_decision_history`) routes to, with a
    ``_DHReplaySnapshot`` instance. Verifies no ``AttributeError``
    against the runtime value — catches helper-indirection drift the
    AST walk above misses (e.g. a projector that passes ``snapshot``
    into a helper not in ``_WALKED_PROJECTORS``).

    Parametrized over ``_DECISION_HISTORY_TYPED_PROJECTORS.keys()``
    (DERIVED from the live dict; adding a new entry to the dispatcher
    automatically extends this test's parameter set — no constant
    update needed) PLUS every ``rbac.<suffix>`` route under the
    prefix dispatcher (derived from ``_RBAC_DENIAL_TYPE_VALUES``)."""

    @pytest.mark.parametrize(
        "decision_type",
        sorted(_ui_events_module._DECISION_HISTORY_TYPED_PROJECTORS.keys())
        + sorted(f"rbac.{suffix}" for suffix in _RBAC_DENIAL_TYPE_VALUES),
    )
    def test_typed_projector_consumes_replay_snapshot(self, decision_type: str) -> None:
        snapshot = _build_replay_snapshot(decision_type)
        snapshot_cast = cast(AppendedDecisionSnapshot, snapshot)
        # _project_typed_decision_history dispatches to the matching
        # per-type projector. AttributeError at any access on the
        # replay snapshot bubbles up here.
        typed = _project_typed_decision_history(snapshot_cast)
        # Every routed decision_type MUST produce a typed event (the
        # dispatcher returned non-None for routed types; only unmatched
        # types fall through to None). This assertion also pins the
        # dispatcher's routing behavior — if a future change accidentally
        # drops a routing entry, the test fails informatively.
        assert typed is not None, (
            f"_project_typed_decision_history returned None for "
            f"decision_type={decision_type!r}; either the dispatcher dropped "
            f"the routing or the rbac.<suffix> table drifted from "
            f"_RBAC_DENIAL_TYPE_VALUES."
        )

    @pytest.mark.parametrize(
        "decision_type",
        sorted(_ui_events_module._DECISION_HISTORY_TYPED_PROJECTORS.keys())
        + sorted(f"rbac.{suffix}" for suffix in _RBAC_DENIAL_TYPE_VALUES),
    )
    def test_decision_audit_mirror_consumes_replay_snapshot(self, decision_type: str) -> None:
        """The ordinal-1 decision_audit mirror is built for EVERY
        decision_type (not just typed-routable ones). Drives it
        explicitly with a replay snapshot — catches accesses the
        typed-projector path doesn't exercise."""
        snapshot = _build_replay_snapshot(decision_type)
        snapshot_cast = cast(AppendedDecisionSnapshot, snapshot)
        mirror = _build_decision_audit_for_dh_snapshot(snapshot_cast)
        assert mirror is not None
        assert mirror.family == "decision_audit"
        assert mirror.type == "event_appended"
