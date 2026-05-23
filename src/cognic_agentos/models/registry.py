"""Model Registry lifecycle state machine — Sprint 9.5 per ADR-013.

Pure-functional, I/O-free, dialect-free — the model-registry mirror of
``packs/lifecycle.py``. CRITICAL CONTROL: 95% line / 90% branch floor,
negative-path tests required; touched under ``core-controls-engineer`` +
``/critical-module-mode``.

``register`` is the genesis (``POST /api/v1/models`` -> ``proposed``) and
is NOT a transition — it is handled by
``models/storage.py:ModelRecordStore.register``. The five non-genesis
transitions are the four forward promotes plus ``retire``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final, Literal, get_args

#: The four model kinds per ADR-013. All four flow through the SAME
#: lifecycle; ``kind`` carries no per-kind transition rule in Wave 1.
ModelKind = Literal["foundation", "fine_tune", "adapter", "embedding"]

#: The six canonical lifecycle states per ADR-013.
ModelLifecycleState = Literal[
    "proposed",
    "eval_passed",
    "tenant_approved",
    "serving",
    "deprecated",
    "retired",
]

#: The five non-genesis transitions. ``register`` (genesis) is deliberately
#: NOT a member — it never reaches :func:`validate_transition`.
ModelTransition = Literal[
    "promote_eval_passed",
    "promote_tenant_approved",
    "promote_serving",
    "promote_deprecated",
    "retire",
]

#: Closed-enum refusal vocabulary — the wire-protocol contract carried in
#: every 409 refusal body. Nine values, pinned (design spec §2.1). A
#: missing reason lands as a reviewed spec amendment first.
ModelLifecycleRefusalReason = Literal[
    "model_transition_invalid_state_pair",
    "model_transition_state_unknown",
    "model_transition_from_terminal_state",
    "model_register_duplicate_id",
    "model_promote_signature_verification_failed",
    "model_promote_signature_refs_changed_during_promote",
    "model_promote_eval_evidence_missing",
    "model_promote_eval_evidence_malformed",
    "model_retire_already_retired",
]

#: The 5 canonical ISO 42001 controls every ``model.lifecycle.*`` chain
#: row is stamped with (design spec §4.2). Inlined local copy of a subset
#: of ``compliance/iso42001/controls.ComplianceControlId``; the test-only
#: drift detector
#: ``test_registry.py::test_iso_controls_subset_of_canonical_registry``
#: pins them against the canonical registry (no runtime cross-import —
#: the architectural arrow is models/ does not import compliance/).
MODEL_LIFECYCLE_ISO_CONTROLS: Final[tuple[str, ...]] = (
    "ISO42001.A.6.2.6",
    "ISO42001.A.7.4",
    "ISO42001.A.8.2",
    "ISO42001.A.8.5",
    "ISO42001.A.10.2",
)

#: Legal ``(from_state, to_state)`` pairs per transition. ``register`` is
#: genesis (not here). ``retire`` accepts every non-terminal state.
_VALID_TRANSITIONS: Final[
    Mapping[ModelTransition, frozenset[tuple[ModelLifecycleState, ModelLifecycleState]]]
] = {
    "promote_eval_passed": frozenset({("proposed", "eval_passed")}),
    "promote_tenant_approved": frozenset({("eval_passed", "tenant_approved")}),
    "promote_serving": frozenset({("tenant_approved", "serving")}),
    "promote_deprecated": frozenset({("serving", "deprecated")}),
    "retire": frozenset(
        {
            ("proposed", "retired"),
            ("eval_passed", "retired"),
            ("tenant_approved", "retired"),
            ("serving", "retired"),
            ("deprecated", "retired"),
        }
    ),
}

_KNOWN_STATES: Final[frozenset[str]] = frozenset(get_args(ModelLifecycleState))
_KNOWN_TRANSITIONS: Final[frozenset[str]] = frozenset(get_args(ModelTransition))
_KNOWN_KINDS: Final[frozenset[str]] = frozenset(get_args(ModelKind))


class ModelLifecycleRefused(Exception):
    """Raised when the model-registry state machine refuses a lifecycle
    action (register / promote / retire). Carries ONLY the closed-enum
    :data:`ModelLifecycleRefusalReason` — no transition field.
    """

    def __init__(self, reason: ModelLifecycleRefusalReason) -> None:
        self.reason = reason
        super().__init__(reason)


def validate_transition(
    *,
    from_state: ModelLifecycleState,
    to_state: ModelLifecycleState,
    transition: ModelTransition,
) -> ModelLifecycleRefusalReason | None:
    """Pure validator for the five non-genesis transitions.

    Returns the closed-enum refusal reason, or ``None`` when the
    transition is legal. Refusal precedence: state vocabulary ->
    re-retire idempotency -> terminal-state guard -> generic legal-pair.
    """
    # 1. State vocabulary (both endpoints).
    if from_state not in _KNOWN_STATES or to_state not in _KNOWN_STATES:
        return "model_transition_state_unknown"
    # 2. Per-transition specific: re-retire idempotency takes precedence
    #    over the generic terminal-state guard.
    if transition == "retire" and from_state == "retired":
        return "model_retire_already_retired"
    # 3. Terminal-state guard — no transition leaves ``retired``.
    if from_state == "retired":
        return "model_transition_from_terminal_state"
    # 4. Generic legal-pair fallthrough.
    if (from_state, to_state) not in _VALID_TRANSITIONS[transition]:
        return "model_transition_invalid_state_pair"
    # 5. Legal.
    return None


# Build-time invariant — _VALID_TRANSITIONS keys exactly match the
# ModelTransition closed-enum vocabulary (mirrors packs/lifecycle.py).
assert set(_VALID_TRANSITIONS.keys()) == _KNOWN_TRANSITIONS, (
    "_VALID_TRANSITIONS keys diverge from get_args(ModelTransition)"
)
for _t, _pairs in _VALID_TRANSITIONS.items():
    assert len(_pairs) > 0, f"_VALID_TRANSITIONS[{_t!r}] is empty"
del _t, _pairs

__all__ = [
    "MODEL_LIFECYCLE_ISO_CONTROLS",
    "ModelKind",
    "ModelLifecycleRefusalReason",
    "ModelLifecycleRefused",
    "ModelLifecycleState",
    "ModelTransition",
    "validate_transition",
]
