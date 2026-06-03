"""Sprint 11.5c T1 — ValidatorReason + _VALIDATOR_REASON_OWNERSHIP vocab seed tests.

Pins the addition of ``learning_surface_violation`` per ADR-019 §52.
Sub-cases (mode mismatch / mode unknown / etc.) ride ``payload.failure_mode``
at runtime; only a single top-level closed-enum reason is added here, per the
ADR-019 single-reason doctrine. The owning validator (``validators/learning_surface.py``)
is a T2+ artifact; the vocab is seeded at T1 so later tasks can land the
validator without touching the closed-enum + ownership map.
"""

import typing

from cognic_agentos.cli import _VALIDATOR_REASON_OWNERSHIP, ValidatorReason


def test_learning_surface_violation_present_in_validator_reason() -> None:
    # ADR-019 §52 names a SINGLE closed-enum reason; sub-cases ride payload.failure_mode.
    assert "learning_surface_violation" in typing.get_args(ValidatorReason)


def test_learning_surface_violation_owned_by_learning_surface_validator() -> None:
    assert (
        _VALIDATOR_REASON_OWNERSHIP["learning_surface_violation"]
        == "validators/learning_surface.py"
    )
