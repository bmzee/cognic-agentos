"""Sprint 11.5a T12 — memory RBAC scope literal stability + namespace disjointness.

Pins the 4 additive 11.5a memory scopes per ADR-019:

- ``MemoryRBACScope`` closed-enum literal carries exactly the 4 read/write
  values (``memory.read`` + the three tier-scoped writes). Any addition,
  rename, or removal is a wire-protocol break visible in this test's diff.
- ``MEMORY_SCOPES`` frozenset stays 1:1 with the Literal.
- ``MemoryRBACScope`` is value-disjoint from every other scope family
  (``PackRBACScope`` / ``UIRBACScope`` / ``ModelRBACScope`` /
  ``ComplianceRBACScope``) by the ``memory.*`` namespace — overlap would
  create a wire-protocol ambiguity where a single 403 ``scope_not_held``
  denial reason could match multiple families.

11.5b extends ``MemoryRBACScope`` with ``memory.forget`` / ``memory.redact``
/ ``memory.export.read`` / ``memory.regulator_erasure``; the 11.5a pin is
locked at the 4 values here.
"""

import typing

import pytest

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope
from cognic_agentos.portal.rbac.scopes import (
    MEMORY_SCOPES,
    ComplianceRBACScope,
    MemoryRBACScope,
    ModelRBACScope,
    PackRBACScope,
    UIRBACScope,
)

#: The exact 4 values 11.5a ships. Drift here is a wire-protocol break.
_EXPECTED_MEMORY_SCOPES = {
    "memory.read",
    "memory.write.scratch",
    "memory.write.task",
    "memory.write.long_term",
}


def test_memory_scopes_exactly_the_4_11_5a_values() -> None:
    """``MemoryRBACScope`` carries exactly the 4 11.5a values, and
    ``MEMORY_SCOPES`` stays 1:1 with the Literal."""
    assert set(typing.get_args(MemoryRBACScope)) == _EXPECTED_MEMORY_SCOPES
    assert frozenset(_EXPECTED_MEMORY_SCOPES) == MEMORY_SCOPES


def test_memory_scopes_disjoint_from_other_families() -> None:
    """``MemoryRBACScope`` MUST be value-disjoint from every other family by
    the ``memory.*`` namespace. Overlap would make a single 403 denial reason
    string ambiguous across surfaces."""
    other_families = (
        PackRBACScope,
        UIRBACScope,
        ModelRBACScope,
        ComplianceRBACScope,
    )
    other_values: set[str] = set()
    for family in other_families:
        other_values |= set(typing.get_args(family))

    memory_values = set(typing.get_args(MemoryRBACScope))
    overlap = memory_values & other_values
    assert overlap == set(), (
        f"MemoryRBACScope MUST be value-disjoint from all other scope families; overlap: {overlap}"
    )
    # Defence-in-depth: every memory value lives in the memory.* namespace.
    for value in memory_values:
        assert value.startswith("memory."), f"memory scope {value!r} does not start with 'memory.'"


class TestActorAcceptsMemoryScopes:
    """``Actor.scopes`` widened additively (Sprint 11.5a T12) to include
    ``MemoryRBACScope`` so a single bank-overlay actor can carry memory scopes
    alongside any other family. WITHOUT the actor.py widening,
    ``Actor(scopes=frozenset({"memory.read"}))`` raises a Pydantic
    ``ValidationError`` — so these tests are what make the new scopes usable."""

    @pytest.mark.parametrize("scope", sorted(_EXPECTED_MEMORY_SCOPES))
    def test_actor_constructs_with_every_memory_scope(self, scope: MemoryRBACScope) -> None:
        actor = Actor(
            subject="kyc-agent",
            tenant_id="tenant-acme",
            scopes=frozenset({scope}),
            actor_type="service",
        )
        assert scope in actor.scopes

    def test_actor_accepts_full_memory_scope_set(self) -> None:
        actor = Actor(
            subject="memory-bot",
            tenant_id="tenant-acme",
            scopes=MEMORY_SCOPES,
            actor_type="service",
        )
        assert actor.scopes == MEMORY_SCOPES

    def test_actor_accepts_mixed_memory_and_other_family(self) -> None:
        # The reason for the widening: one actor carrying memory + another family.
        scopes: frozenset[MemoryRBACScope | PackRBACScope] = frozenset(
            {"memory.read", "pack.audit.read"}
        )
        actor = Actor(
            subject="examiner",
            tenant_id="tenant-acme",
            scopes=scopes,
            actor_type="human",
        )
        assert actor.scopes == scopes

    def test_actor_accepts_pack_scopes_unchanged(self) -> None:
        # Backward-compat: pre-11.5a pack-only actors still construct (additive).
        actor = Actor(
            subject="reviewer",
            tenant_id="tenant-acme",
            scopes=frozenset({"pack.submit"}),
            actor_type="human",
        )
        assert "pack.submit" in actor.scopes


class TestRequireScopeAcceptsMemoryScopes:
    """``RequireScope(scope=...)`` MUST accept ``MemoryRBACScope`` — pinned at
    the runtime level (callable construction) AND the type-union level
    (``typing.get_type_hints`` introspection), so memory endpoints can be
    RBAC-gated with ``RequireScope("memory.read")`` etc."""

    def test_scope_parameter_union_includes_memory_rbac_scope(self) -> None:
        hints = typing.get_type_hints(RequireScope)
        accepted: set[str] = set()
        for member in typing.get_args(hints["scope"]):
            accepted |= set(typing.get_args(member))
        assert accepted >= _EXPECTED_MEMORY_SCOPES

    def test_scope_parameter_union_keeps_other_families(self) -> None:
        # Backward-compat: pre-11.5a families still accepted after the widening.
        hints = typing.get_type_hints(RequireScope)
        accepted: set[str] = set()
        for member in typing.get_args(hints["scope"]):
            accepted |= set(typing.get_args(member))
        assert "pack.submit" in accepted
        assert "ui.tenant_stream" in accepted
        assert "model.register" in accepted

    @pytest.mark.parametrize("scope", sorted(_EXPECTED_MEMORY_SCOPES))
    def test_require_scope_constructs_for_every_memory_scope(self, scope: MemoryRBACScope) -> None:
        dep = RequireScope(scope)
        assert callable(dep)
