"""Sprint 13.6b T5 — QuotaRBACScope closed-enum + namespace disjointness.

A NEW family (`quota.read` only, Wave-1) — quota scopes do NOT live in
``EmergencyRBACScope`` (the 13.6a review-patch-4 split). The override scope
(`quota.override.tokens`) lands with the deferred limit-write surface.
Disjoint from every other family (`quota.*` prefix); widened into the
``Actor.scopes`` + ``RequireScope`` unions (additive).
"""

import typing

from cognic_agentos.portal.rbac.scopes import (
    QUOTA_SCOPES,
    ComplianceRBACScope,
    EmergencyRBACScope,
    MemoryRBACScope,
    ModelRBACScope,
    PackRBACScope,
    QuotaRBACScope,
    UIRBACScope,
)


def test_quota_scope_is_exactly_quota_read():
    assert set(typing.get_args(QuotaRBACScope)) == {"quota.read"}
    assert frozenset({"quota.read"}) == QUOTA_SCOPES


def test_quota_scope_disjoint_from_every_other_family():
    others = set()
    for fam in (
        EmergencyRBACScope,
        MemoryRBACScope,
        PackRBACScope,
        UIRBACScope,
        ModelRBACScope,
        ComplianceRBACScope,
    ):
        others |= set(typing.get_args(fam))
    assert set(typing.get_args(QuotaRBACScope)).isdisjoint(others)


def test_require_scope_constructs_for_quota_read():
    from cognic_agentos.portal.rbac.enforcement import RequireScope

    dep = RequireScope("quota.read")
    assert callable(dep)
