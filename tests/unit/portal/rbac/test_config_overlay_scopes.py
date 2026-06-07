"""ADR-023 Task 5 — ConfigOverlayRBACScope family unit tests.

Two values in the ``config.tenant_overlay.*`` namespace, value-disjoint from
every other scope family by namespace separation (no other family is
``config.*``). The Literal is the wire-protocol contract for the 403
``scope_not_held`` denial body on the per-tenant config-overlay endpoints
(Task 6): ``config.tenant_overlay.write`` (PUT/DELETE — human-only mutation)
and ``config.tenant_overlay.read`` (GET — service actors permitted).
"""

from __future__ import annotations

import typing

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.scopes import (
    CONFIG_OVERLAY_SCOPES,
    ComplianceRBACScope,
    ConfigOverlayRBACScope,
    EmergencyRBACScope,
    EvalRBACScope,
    MemoryRBACScope,
    ModelRBACScope,
    PackRBACScope,
    UIRBACScope,
)

_EXPECTED = {"config.tenant_overlay.read", "config.tenant_overlay.write"}


def test_config_overlay_scope_family_has_exactly_two_values() -> None:
    assert set(typing.get_args(ConfigOverlayRBACScope)) == _EXPECTED


def test_config_overlay_scopes_frozenset_is_1to1_with_literal() -> None:
    assert frozenset(_EXPECTED) == CONFIG_OVERLAY_SCOPES
    assert len(CONFIG_OVERLAY_SCOPES) == len(typing.get_args(ConfigOverlayRBACScope)) == 2


def test_actor_accepts_config_overlay_scopes() -> None:
    a = Actor(
        subject="op@bank",
        tenant_id="t1",
        scopes=frozenset({"config.tenant_overlay.read", "config.tenant_overlay.write"}),
        actor_type="human",
    )
    assert "config.tenant_overlay.write" in a.scopes
    assert "config.tenant_overlay.read" in a.scopes


def test_config_overlay_scope_disjoint_from_every_other_family() -> None:
    others: set[str] = set()
    for fam in (
        PackRBACScope,
        UIRBACScope,
        ComplianceRBACScope,
        ModelRBACScope,
        MemoryRBACScope,
        EmergencyRBACScope,
        EvalRBACScope,
    ):
        others |= set(typing.get_args(fam))
    assert _EXPECTED.isdisjoint(others)
    # Namespace separation: every config-overlay scope is config.tenant_overlay.*
    assert all(v.startswith("config.tenant_overlay.") for v in _EXPECTED)
