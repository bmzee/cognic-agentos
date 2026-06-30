"""Sprint 7B.3 T8 — RBAC override-scope vocabulary extension (13th scope).

Pins the ADR-012 §107-110 override scope ``pack.override.approval_gate``:

- ``OVERRIDE_SCOPES`` is a 1-value frozenset, distinct from the 4
  role-group frozensets (author / reviewer / operator / examiner).
- ``pack.override.approval_gate`` is a member of both
  ``PACK_LIFECYCLE_SCOPES`` and the ``PackRBACScope`` Literal.
- ``PackRBACScope`` Literal arity grew 12 → 13 here (the override scope at Sprint
  7B.3 T8); the arity assertion below now pins 14 after M4's ``pack.configure``
  (ADR-026 D4).

The override scope is the wire-protocol contract for the
``pack.override.approval_gate`` RBAC gate on the approve endpoint's
override path (T9). Any rename or removal is a wire-protocol break.
The full 5-way partition invariant (4 role groups + ``OVERRIDE_SCOPES``
== ``PACK_LIFECYCLE_SCOPES``) is pinned in ``test_scopes.py``.
"""

from typing import get_args

from cognic_agentos.portal.rbac.scopes import (
    AUTHOR_SCOPES,
    EXAMINER_SCOPES,
    OPERATOR_SCOPES,
    OVERRIDE_SCOPES,
    PACK_LIFECYCLE_SCOPES,
    REVIEWER_SCOPES,
    PackRBACScope,
)


def test_override_scopes_is_single_value() -> None:
    """ADR-012 §107-110 — exactly one override scope in 7B.3."""
    assert frozenset({"pack.override.approval_gate"}) == OVERRIDE_SCOPES


def test_override_scope_in_pack_lifecycle_scopes() -> None:
    """The override scope is part of the lifecycle scope vocabulary."""
    assert "pack.override.approval_gate" in PACK_LIFECYCLE_SCOPES


def test_override_scope_in_pack_rbac_scope_literal() -> None:
    """``PackRBACScope`` Literal admits the override scope — closed-enum
    membership pin; a rename or removal breaks here."""
    assert "pack.override.approval_gate" in get_args(PackRBACScope)


def test_pack_rbac_scope_literal_arity_is_14() -> None:
    """``PackRBACScope`` Literal arity. The 13th (``pack.override.approval_gate``)
    landed at 7B.3 T8; the 14th (``pack.configure``) lands at M4 (ADR-026 D4)."""
    assert len(get_args(PackRBACScope)) == 14


def test_override_scopes_disjoint_from_role_groups() -> None:
    """``OVERRIDE_SCOPES`` is distinct from all 4 role-group frozensets:
    the override scope is its own group — no author / reviewer /
    operator / examiner role holds it implicitly. A privileged operator
    must be granted ``pack.override.approval_gate`` explicitly."""
    for group in (AUTHOR_SCOPES, REVIEWER_SCOPES, OPERATOR_SCOPES, EXAMINER_SCOPES):
        assert OVERRIDE_SCOPES.isdisjoint(group)
