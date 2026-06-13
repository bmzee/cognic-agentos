"""EmergencyRBACScope closed-enum + namespace disjointness.

Sprint 11.5b T1 seeded the single ``emergency.kill.memory_write_freeze``
value; Sprint 13.6 T5 grows the family to 9 (the 7 ADR-018 kill-switch
classes + the seed + ``emergency.read`` for the GET surfaces). Disjointness
from every existing scope family stays pinned (wire-protocol-public: overlap
creates ambiguity in 403 scope_not_held denial bodies). Also pins the 4→7
MemoryRBACScope extension that landed in the same 11.5b T1 commit.
"""

import typing

from cognic_agentos.portal.rbac.scopes import (
    EMERGENCY_SCOPES,
    ComplianceRBACScope,
    EmergencyRBACScope,
    MemoryRBACScope,
    ModelRBACScope,
    PackRBACScope,
    UIRBACScope,
)

_EXPECTED_13_6_EMERGENCY_SCOPES = {
    # The 7 ADR-018 kill-switch classes (the ADR's scope column, §34-42).
    "emergency.kill.pack",
    "emergency.kill.tool",
    "emergency.kill.model",
    "emergency.kill.tenant_packs",
    "emergency.kill.tenant_full",
    "emergency.kill.cloud",
    "emergency.kill.feature",
    # The 11.5b seed class.
    "emergency.kill.memory_write_freeze",
    # Sprint 13.6 — the read scope for GET /kill-switches + GET /audit.
    "emergency.read",
}


def test_emergency_scope_is_exactly_the_nine_13_6_values():
    assert set(typing.get_args(EmergencyRBACScope)) == _EXPECTED_13_6_EMERGENCY_SCOPES
    assert frozenset(_EXPECTED_13_6_EMERGENCY_SCOPES) == EMERGENCY_SCOPES


def test_require_scope_constructs_for_new_emergency_values():
    # The Actor/RequireScope unions already carry EmergencyRBACScope —
    # growth is purely additive; this pins that no widening edit is needed.
    from cognic_agentos.portal.rbac.enforcement import RequireScope

    dep = RequireScope("emergency.kill.model")
    assert callable(dep)


def test_emergency_scope_disjoint_from_every_other_family():
    others = set()
    for fam in (MemoryRBACScope, PackRBACScope, UIRBACScope, ModelRBACScope, ComplianceRBACScope):
        others |= set(typing.get_args(fam))
    assert set(typing.get_args(EmergencyRBACScope)).isdisjoint(others)


def test_memory_scope_now_has_the_4_lifecycle_and_export_values():
    vals = set(typing.get_args(MemoryRBACScope))
    assert {"memory.forget", "memory.redact", "memory.regulator_erasure"} <= vals
    assert "memory.export.read" in vals  # export RBAC landed in 11.5c T1
    assert len(vals) == 8
