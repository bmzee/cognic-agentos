"""Wave-1 T6 — ``adversarial_pass_rate_floor`` Settings field (CFG-portal-adversarial).

The ADR-011 / ADR-012 §41 gate-3 adversarial corpus pass-rate floor is now an
operator-configurable, **tighten-only** Settings field (was a baked ``0.99`` in
``review_routes.py``). ``ge=0.99`` is the kernel floor — banks may raise the bar
but can never drop below it. A drift test pins the field default to the named
kernel-floor constant the route defaults reference.
"""

import pytest
from pydantic import ValidationError

from cognic_agentos.core.config import Settings


def test_default_is_kernel_floor() -> None:
    assert Settings(runtime_profile="dev").adversarial_pass_rate_floor == 0.99


def test_accepts_tighter_floor() -> None:
    s = Settings(runtime_profile="dev", adversarial_pass_rate_floor=0.999)
    assert s.adversarial_pass_rate_floor == 0.999


def test_rejects_below_kernel_floor() -> None:
    # ge=0.99 — loosening below the kernel floor is a critical-controls weakening.
    with pytest.raises(ValidationError):
        Settings(runtime_profile="dev", adversarial_pass_rate_floor=0.95)


def test_rejects_above_one() -> None:
    # le=1.0 — a pass-rate floor above 1.0 is nonsensical.
    with pytest.raises(ValidationError):
        Settings(runtime_profile="dev", adversarial_pass_rate_floor=1.01)


def test_config_default_matches_review_routes_kernel_floor() -> None:
    """Drift detector (test-only, no runtime cross-import per the doctrine): the
    config field default MUST equal the named kernel-floor constant that the
    ``build_review_routes`` / ``build_packs_router`` defaults reference, so the
    two cannot silently diverge."""
    from cognic_agentos.portal.api.packs.review_routes import (
        _ADVERSARIAL_PASS_RATE_THRESHOLD,
    )

    assert (
        Settings(runtime_profile="dev").adversarial_pass_rate_floor
        == _ADVERSARIAL_PASS_RATE_THRESHOLD
    )
