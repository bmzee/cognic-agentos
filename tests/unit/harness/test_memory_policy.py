"""Harness Injection T6 — MemoryPolicyRouter (two-bundle dispatch + fail-loud)."""

from __future__ import annotations

from typing import Any

import pytest

from cognic_agentos.harness.memory_policy import MemoryPolicyRouter


class _Decision:
    def __init__(self, tag: str) -> None:
        self.allow = True
        self.tag = tag


class _RecordingEngine:
    """Structural OPAEngine conformer that records the decision points it was
    asked to evaluate (so the test asserts WHICH engine the router delegated to,
    proving the routing, not merely an echoed tag)."""

    def __init__(self, tag: str) -> None:
        self.tag = tag
        self.calls: list[str] = []

    async def evaluate(self, *, decision_point: str, input: dict[str, Any]) -> _Decision:
        self.calls.append(decision_point)
        return _Decision(tag=self.tag)


@pytest.mark.parametrize(
    "decision_point,expected_engine",
    [
        ("data.cognic.memory.long_term.allow", "memory"),
        ("data.cognic.memory.cross_subject.allow", "memory"),
        ("data.cognic.memory.restricted_class_write.allow", "memory"),
        ("data.cognic.memory.recall.purpose_compatible.allow", "purpose_matrix"),
    ],
)
async def test_router_dispatches_decision_point(decision_point: str, expected_engine: str) -> None:
    mem = _RecordingEngine("memory")
    pm = _RecordingEngine("purpose_matrix")
    router = MemoryPolicyRouter(memory_engine=mem, purpose_matrix_engine=pm)  # type: ignore[arg-type]
    await router.evaluate(decision_point=decision_point, input={})
    # Exactly the expected engine saw the call; the other saw nothing.
    if expected_engine == "memory":
        assert mem.calls == [decision_point] and pm.calls == []
    else:
        assert pm.calls == [decision_point] and mem.calls == []


async def test_router_raises_on_unknown_decision_point() -> None:
    from cognic_agentos.harness.memory_policy import MemoryPolicyDecisionPointUnknown

    mem = _RecordingEngine("memory")
    pm = _RecordingEngine("purpose_matrix")
    router = MemoryPolicyRouter(memory_engine=mem, purpose_matrix_engine=pm)  # type: ignore[arg-type]
    with pytest.raises(
        MemoryPolicyDecisionPointUnknown, match="memory_policy_decision_point_unknown"
    ):
        await router.evaluate(decision_point="data.cognic.memory.bogus.allow", input={})
    assert mem.calls == [] and pm.calls == []  # never delegated on the unknown path


def test_router_decision_points_match_gate_constants() -> None:
    """Drift detector (test-only, per feedback_drift_detector_test_only_no_runtime_import).

    The router declares its OWN copy of the four memory decision-point strings; they MUST
    stay byte-identical to ``core/memory/gate.py``'s canonical constants. The router does
    NOT import gate.py at runtime — this test imports both and asserts equality. If gate.py
    ever renames a decision point, the router would silently route it to the fail-loud else
    branch (``MemoryPolicyDecisionPointUnknown``), breaking memory at runtime — this catches
    that rename at test time.
    """
    from cognic_agentos.core.memory import gate
    from cognic_agentos.harness.memory_policy import (
        _MEMORY_DECISION_POINTS,
        _PURPOSE_MATRIX_DECISION_POINT,
    )

    assert ({_PURPOSE_MATRIX_DECISION_POINT} | _MEMORY_DECISION_POINTS) == {
        gate._LONG_TERM_DECISION_POINT,
        gate._CROSS_SUBJECT_DECISION_POINT,
        gate._RESTRICTED_CLASS_WRITE_DECISION_POINT,
        gate._PURPOSE_COMPATIBLE_DECISION_POINT,
    }
    # The purpose-matrix point is the ONLY one routed to the purpose-matrix bundle.
    assert _PURPOSE_MATRIX_DECISION_POINT == gate._PURPOSE_COMPATIBLE_DECISION_POINT
