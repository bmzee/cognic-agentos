from __future__ import annotations

from cognic_agentos.core.approval.engine import _TIER_GRANT_SCOPE, grant_scope_for_risk_tier


def test_helper_returns_scope_for_each_high_tier() -> None:
    for tier, scope in _TIER_GRANT_SCOPE.items():
        assert grant_scope_for_risk_tier(tier) == scope


def test_helper_returns_none_for_auto_and_unknown_tiers() -> None:
    assert grant_scope_for_risk_tier("read_only") is None
    assert grant_scope_for_risk_tier("internal_write") is None
    assert grant_scope_for_risk_tier("does_not_exist") is None


def test_helper_never_returns_observe_scope() -> None:
    # observe grants nothing; it must appear in NO helper return value.
    returned = {grant_scope_for_risk_tier(t) for t in _TIER_GRANT_SCOPE}
    assert "tool.approve.observe" not in returned
    # non-None domain == the 6 _TIER_GRANT_SCOPE keys (drift pin).
    non_none = {
        t
        for t in (*_TIER_GRANT_SCOPE, "read_only", "internal_write", "x")
        if grant_scope_for_risk_tier(t) is not None
    }
    assert non_none == set(_TIER_GRANT_SCOPE)
