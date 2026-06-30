"""Sprint 7B.2 T2 + Sprint 11.5c T1 — RBAC scope stability + ADR-012 transition cross-check.

Pins:

- The 14 lifecycle scopes: the 12 from BUILD_PLAN.md §622-625 verbatim, the
  override scope ``pack.override.approval_gate`` from ADR-012 §107-110 (added at
  Sprint 7B.3 T8 alongside the 5-gate composer's override path), and the M4
  ``pack.configure`` operator scope from ADR-026 D4 (the runtime-config configure
  step). (Historical note: the Sprint-7B.1 closeout L119 said "14 scopes" but only
  enumerated 12 — a cite-from-memory typo per Sprint 7B.2 plan self-review Round
  0.5; the genuine count reached 13 at 7B.3 T8 and 14 at M4.)
- Closed-enum literal stability — any addition or rename is a wire-protocol break
  visible in this test's diff. ``PackRBACScope`` is the wire-protocol contract
  carried in every 403 ``scope_not_held`` denial body.
- Role-group frozensets + ``OVERRIDE_SCOPES`` partition ``PACK_LIFECYCLE_SCOPES``
  exactly — no scope appears in two groups, none are missing. The override-scope-
  specific assertions live in ``test_scopes_override_extension.py``.
"""

import typing
from typing import get_args

import pytest

from cognic_agentos.portal.rbac.scopes import (
    AUTHOR_SCOPES,
    EXAMINER_SCOPES,
    MEMORY_SCOPES,
    OPERATOR_SCOPES,
    OVERRIDE_SCOPES,
    PACK_LIFECYCLE_SCOPES,
    REVIEWER_SCOPES,
    MemoryRBACScope,
    PackRBACScope,
)


def test_pack_lifecycle_scopes_frozen_at_14_values() -> None:
    """ADR-012 §39 + §107-110 + ADR-026 — 12 BUILD_PLAN §622-625 lifecycle scopes,
    the Sprint-7B.3-T8 override scope, and the M4 ``pack.configure`` operator scope
    (ADR-026 D4) = 14."""
    assert len(PACK_LIFECYCLE_SCOPES) == 14


def test_pack_lifecycle_scopes_match_build_plan_verbatim() -> None:
    """Every scope in BUILD_PLAN §622-625 plus the ADR-012 §107-110 override
    scope plus the ADR-026 D4 ``pack.configure`` operator scope must appear in
    PACK_LIFECYCLE_SCOPES."""
    expected = frozenset(
        {
            # Author surface (BUILD_PLAN §622)
            "pack.submit",
            "pack.withdraw",
            # Reviewer surface (BUILD_PLAN §623)
            "pack.review.claim",
            "pack.review.approve",
            "pack.review.reject",
            # Operator surface (BUILD_PLAN §624 + ADR-026 D4 — ``pack.configure``,
            # the M4 runtime-config configure step, sits between allow_list +
            # install)
            "pack.allow_list",
            "pack.configure",
            "pack.install",
            "pack.disable",
            "pack.revoke",
            "pack.uninstall",
            # Examiner surface (BUILD_PLAN §625) — also serves the inspection
            # surface per ADR-012 §75 "Inspection — examiner-facing"; basic
            # GET / and GET /{id} require ``pack.audit.read`` (no separate
            # ``pack.read.metadata`` scope — inspection is examiner territory)
            "pack.audit.read",
            "pack.invocation.read",
            # Override surface (ADR-012 §107-110) — Sprint 7B.3 T8; the
            # privileged force-approve gate. Its own group (OVERRIDE_SCOPES),
            # not held implicitly by any of the 4 role groups.
            "pack.override.approval_gate",
        }
    )
    assert expected == PACK_LIFECYCLE_SCOPES


@pytest.mark.parametrize(
    "value",
    [
        "pack.submit",
        "pack.withdraw",
        "pack.review.claim",
        "pack.review.approve",
        "pack.review.reject",
        "pack.allow_list",
        "pack.configure",
        "pack.install",
        "pack.disable",
        "pack.revoke",
        "pack.uninstall",
        "pack.audit.read",
        "pack.invocation.read",
        "pack.override.approval_gate",
    ],
)
def test_pack_rbac_scope_literal_admits_value(value: str) -> None:
    """Closed-enum membership pin — each of the 14 wire-protocol values must
    appear in ``get_args(PackRBACScope)``. Any rename or removal breaks here."""
    assert value in get_args(PackRBACScope)


def test_pack_rbac_scope_literal_size_matches_scope_set() -> None:
    """``PackRBACScope`` literal arity must equal ``PACK_LIFECYCLE_SCOPES`` size —
    decouples ``get_args`` from the frozenset; both must agree."""
    assert len(get_args(PackRBACScope)) == len(PACK_LIFECYCLE_SCOPES)


def test_author_scopes_match_build_plan_author_surface() -> None:
    """BUILD_PLAN §622 — author scopes pinned to 2 values."""
    assert frozenset({"pack.submit", "pack.withdraw"}) == AUTHOR_SCOPES


def test_reviewer_scopes_match_build_plan_reviewer_surface() -> None:
    """BUILD_PLAN §623 — reviewer scopes pinned to 3 values."""
    assert (
        frozenset(
            {
                "pack.review.claim",
                "pack.review.approve",
                "pack.review.reject",
            }
        )
        == REVIEWER_SCOPES
    )


def test_operator_scopes_match_build_plan_operator_surface() -> None:
    """BUILD_PLAN §624 + ADR-026 D4 — operator scopes pinned to 6 values (the M4
    ``pack.configure`` runtime-config configure step joins the operator surface)."""
    assert (
        frozenset(
            {
                "pack.allow_list",
                "pack.configure",
                "pack.install",
                "pack.disable",
                "pack.revoke",
                "pack.uninstall",
            }
        )
        == OPERATOR_SCOPES
    )


def test_examiner_scopes_match_build_plan_examiner_surface() -> None:
    """BUILD_PLAN §625 — examiner scopes pinned to 2 values (also serves
    inspection per ADR-012 §75)."""
    assert (
        frozenset(
            {
                "pack.audit.read",
                "pack.invocation.read",
            }
        )
        == EXAMINER_SCOPES
    )


def test_role_groups_partition_pack_lifecycle_scopes_exactly() -> None:
    """Invariant — the four role-group frozensets plus ``OVERRIDE_SCOPES``
    partition ``PACK_LIFECYCLE_SCOPES`` with no overlap and no gap. This
    catches the refactor failure mode where a new scope is added to
    ``PACK_LIFECYCLE_SCOPES`` but forgotten in its group (or vice versa).
    Sprint 7B.3 T8 extended the partition from 4 groups to 5 with the
    addition of ``OVERRIDE_SCOPES`` (the ADR-012 §107-110 override scope)."""
    union = AUTHOR_SCOPES | REVIEWER_SCOPES | OPERATOR_SCOPES | EXAMINER_SCOPES | OVERRIDE_SCOPES
    assert union == PACK_LIFECYCLE_SCOPES
    # Pairwise disjointness — no scope in two groups.
    groups = [
        AUTHOR_SCOPES,
        REVIEWER_SCOPES,
        OPERATOR_SCOPES,
        EXAMINER_SCOPES,
        OVERRIDE_SCOPES,
    ]
    for i, g1 in enumerate(groups):
        for g2 in groups[i + 1 :]:
            assert g1.isdisjoint(g2), f"Group overlap detected: {g1 & g2}"


# ---------------------------------------------------------------------------
# Sprint 11.5c T1 — memory.export.read scope addition
# ---------------------------------------------------------------------------


def test_memory_scope_has_eight_values_after_11_5c() -> None:
    assert len(typing.get_args(MemoryRBACScope)) == 8
    assert "memory.export.read" in typing.get_args(MemoryRBACScope)


def test_memory_scopes_frozenset_is_1to1_with_literal() -> None:
    assert frozenset(typing.get_args(MemoryRBACScope)) == MEMORY_SCOPES
