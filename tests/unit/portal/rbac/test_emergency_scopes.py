"""Sprint 11.5b T1 — EmergencyRBACScope closed-enum + namespace disjointness.

Pins the single 11.5b emergency scope value and asserts disjointness from
every existing scope family (wire-protocol-public: overlap creates ambiguity
in 403 scope_not_held denial bodies). Also pins the 4→7 MemoryRBACScope
extension that lands in the same T1 commit.
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


def test_emergency_scope_is_exactly_the_one_11_5b_value():
    assert set(typing.get_args(EmergencyRBACScope)) == {"emergency.kill.memory_write_freeze"}
    assert frozenset({"emergency.kill.memory_write_freeze"}) == EMERGENCY_SCOPES


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
