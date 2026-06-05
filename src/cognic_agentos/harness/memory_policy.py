"""``MemoryPolicyRouter`` — routes memory Rego decision points across the TWO
single-file OPAEngines MemoryGate needs.

``OPAEngine`` is a single-FILE loader (engine.py:204 — ``bundle_path.is_file()``),
but ``MemoryGate`` queries four decision points spanning ``memory.rego`` (long_term /
cross_subject / restricted_class_write) and ``memory_purpose_matrix.rego``
(recall.purpose_compatible). This router presents the exact ``OPAEngine.evaluate(...)``
interface MemoryGate calls and delegates — the per-point fail-closed
(OpaNotInstalledError / RegoEvaluationError) stays in MemoryGate. Harness-owned (NOT
core/memory); ``build_runtime`` passes it as MemoryAPI's ``policy`` with
``# type: ignore[arg-type]`` (MemoryGate types ``policy: OPAEngine``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cognic_agentos.core.policy.engine import Decision, OPAEngine

#: The ONLY decision point served by memory_purpose_matrix.rego (gate.py:93).
_PURPOSE_MATRIX_DECISION_POINT = "data.cognic.memory.recall.purpose_compatible.allow"

#: The decision points served by memory.rego (gate.py:90-92). A test-only drift
#: detector pins this set + _PURPOSE_MATRIX_DECISION_POINT against the gate.py
#: constants (per feedback_drift_detector_test_only_no_runtime_import).
_MEMORY_DECISION_POINTS: frozenset[str] = frozenset(
    {
        "data.cognic.memory.long_term.allow",
        "data.cognic.memory.cross_subject.allow",
        "data.cognic.memory.restricted_class_write.allow",
    }
)


class MemoryPolicyDecisionPointUnknown(ValueError):
    """The router was asked to evaluate a decision point outside the known memory
    set — fail loud (a programming error: the gate queried an unexpected point)
    rather than silently routing it to memory.rego."""


class MemoryPolicyRouter:
    def __init__(self, *, memory_engine: OPAEngine, purpose_matrix_engine: OPAEngine) -> None:
        self._memory = memory_engine
        self._purpose_matrix = purpose_matrix_engine

    async def evaluate(self, *, decision_point: str, input: dict[str, Any]) -> Decision:
        if decision_point == _PURPOSE_MATRIX_DECISION_POINT:
            return await self._purpose_matrix.evaluate(decision_point=decision_point, input=input)
        if decision_point in _MEMORY_DECISION_POINTS:
            return await self._memory.evaluate(decision_point=decision_point, input=input)
        raise MemoryPolicyDecisionPointUnknown(
            f"memory_policy_decision_point_unknown: {decision_point!r}"
        )
