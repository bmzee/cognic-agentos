"""Sprint 7B.2 T2 — RBAC scope literal stability + ADR-012 transition-table cross-check.

Pins:

- The 12 scopes from BUILD_PLAN.md §622-625 verbatim. (The Sprint-7B.1 closeout
  L119 says "14 scopes" but enumerates 12 — known cite-from-memory typo in the
  closeout per Sprint 7B.2 plan self-review Round 0.5. BUILD_PLAN §622-625 is the
  source of truth at 12. The override scope ``pack.override.approval_gate`` from
  ADR-012 §107-110 ships with Sprint 7B.3's 5-gate composer — not 7B.2.)
- Closed-enum literal stability — any addition or rename is a wire-protocol break
  visible in this test's diff. ``PackRBACScope`` is the wire-protocol contract
  carried in every 403 ``scope_not_held`` denial body.
- Role-group frozensets partition ``PACK_LIFECYCLE_SCOPES`` exactly — no scope
  appears in two role groups, none are missing.
"""

from typing import get_args

import pytest

from cognic_agentos.portal.rbac.scopes import (
    AUTHOR_SCOPES,
    EXAMINER_SCOPES,
    OPERATOR_SCOPES,
    PACK_LIFECYCLE_SCOPES,
    REVIEWER_SCOPES,
    PackRBACScope,
)


def test_pack_lifecycle_scopes_frozen_at_12_values() -> None:
    """ADR-012 §39 + BUILD_PLAN §622-625 — exactly 12 lifecycle scopes in 7B.2."""
    assert len(PACK_LIFECYCLE_SCOPES) == 12


def test_pack_lifecycle_scopes_match_build_plan_verbatim() -> None:
    """Every scope in BUILD_PLAN §622-625 must appear in PACK_LIFECYCLE_SCOPES."""
    expected = frozenset(
        {
            # Author surface (BUILD_PLAN §622)
            "pack.submit",
            "pack.withdraw",
            # Reviewer surface (BUILD_PLAN §623)
            "pack.review.claim",
            "pack.review.approve",
            "pack.review.reject",
            # Operator surface (BUILD_PLAN §624)
            "pack.allow_list",
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
        "pack.install",
        "pack.disable",
        "pack.revoke",
        "pack.uninstall",
        "pack.audit.read",
        "pack.invocation.read",
    ],
)
def test_pack_rbac_scope_literal_admits_value(value: str) -> None:
    """Closed-enum membership pin — each of the 12 wire-protocol values must
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
    """BUILD_PLAN §624 — operator scopes pinned to 5 values."""
    assert (
        frozenset(
            {
                "pack.allow_list",
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
    """Invariant — the four role-group frozensets partition
    ``PACK_LIFECYCLE_SCOPES`` with no overlap and no gap. This catches the
    refactor failure mode where a new scope is added to ``PACK_LIFECYCLE_SCOPES``
    but forgotten in its role group (or vice versa)."""
    union = AUTHOR_SCOPES | REVIEWER_SCOPES | OPERATOR_SCOPES | EXAMINER_SCOPES
    assert union == PACK_LIFECYCLE_SCOPES
    # Pairwise disjointness — no scope in two role groups.
    groups = [AUTHOR_SCOPES, REVIEWER_SCOPES, OPERATOR_SCOPES, EXAMINER_SCOPES]
    for i, g1 in enumerate(groups):
        for g2 in groups[i + 1 :]:
            assert g1.isdisjoint(g2), f"Role-group overlap detected: {g1 & g2}"
