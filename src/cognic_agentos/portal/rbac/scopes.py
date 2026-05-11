"""Sprint 7B.2 T2 — closed-enum RBAC scope vocabulary for the bank-pack lifecycle.

Per ADR-012 §39 + BUILD_PLAN §622-625 the lifecycle portal API ships with
exactly **12** scopes, partitioned across four role groups:

- Author surface (BUILD_PLAN §622): ``pack.submit``, ``pack.withdraw``
- Reviewer surface (BUILD_PLAN §623): ``pack.review.claim``,
  ``pack.review.approve``, ``pack.review.reject``
- Operator surface (BUILD_PLAN §624): ``pack.allow_list``, ``pack.install``,
  ``pack.disable``, ``pack.revoke``, ``pack.uninstall``
- Examiner / inspection surface (BUILD_PLAN §625 + ADR-012 §75):
  ``pack.audit.read``, ``pack.invocation.read``

:data:`PackRBACScope` is the **wire-protocol contract** — every 403
``scope_not_held`` denial body carries the missing scope as a closed-enum
string. Any addition, rename, or removal is a wire-protocol break and
shows up in :file:`tests/unit/portal/rbac/test_scopes.py`'s diff (the
parametrised literal-pin tests + the role-group partition invariant).

Sprint 7B.3 adds the override scope ``pack.override.approval_gate`` from
ADR-012 §107-110 alongside the 5-gate composer. It is intentionally NOT
present in 7B.2.

The Sprint-7B.1 closeout L119 says "14 scopes" but enumerates 12 — a
known cite-from-memory typo in the closeout per Sprint 7B.2 plan
self-review Round 0.5. BUILD_PLAN §622-625 is the source of truth at 12.
"""

from __future__ import annotations

from typing import Literal

#: Closed-enum literal of the 12 bank-pack lifecycle scopes carried in
#: the 403 ``scope_not_held`` denial body. ANY change here is a
#: wire-protocol break — pinned by the parametrised literal-membership
#: tests in :file:`tests/unit/portal/rbac/test_scopes.py`.
#:
#: Style note: assigned as a plain ``= Literal[...]`` (without
#: ``TypeAlias`` annotation) to match the Sprint-7B.1 repo convention at
#: ``packs/lifecycle.py:111``.
PackRBACScope = Literal[
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
]

#: Set type carried on :class:`~cognic_agentos.portal.rbac.actor.Actor`
#: instances and consumed by :class:`RequireScope`. The frozenset is
#: chosen for membership-test O(1) + immutability (matches the frozen
#: Actor model). The element type is the closed-enum literal so out-of-
#: vocab scope strings are caught by mypy at the call site.
ScopeSet = frozenset[PackRBACScope]

#: All 12 lifecycle scopes as a frozenset — wire-protocol surface for
#: the validator + the role-group partition invariant test. Used by
#: bank-overlay binders to validate the actor's effective scope set
#: against the kernel's closed-enum vocabulary before minting an
#: :class:`Actor` (catches typos in the overlay's scope-claim mapping
#: before they reach the enforcement layer).
PACK_LIFECYCLE_SCOPES: frozenset[PackRBACScope] = frozenset(
    {
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
    }
)

#: BUILD_PLAN §622 — author-surface scopes. T4 endpoints depend on these.
#:
#: ``pack.submit`` admits CREATE / UPDATE / SUBMIT (same-tenant author
#: collaboration policy per plan Round 7 P2 #4); ``pack.withdraw`` admits
#: CANCEL (also covers post-review withdraw).
AUTHOR_SCOPES: frozenset[PackRBACScope] = frozenset(
    {
        "pack.submit",
        "pack.withdraw",
    }
)

#: BUILD_PLAN §623 — reviewer-surface scopes. T5 endpoints depend on these.
REVIEWER_SCOPES: frozenset[PackRBACScope] = frozenset(
    {
        "pack.review.claim",
        "pack.review.approve",
        "pack.review.reject",
    }
)

#: BUILD_PLAN §624 — operator-surface scopes. T6 endpoints depend on these.
#: ``pack.allow_list`` additionally requires :class:`RequireHumanActor`
#: per ADR-012 §"Per-tenant allow-list change is human-only".
OPERATOR_SCOPES: frozenset[PackRBACScope] = frozenset(
    {
        "pack.allow_list",
        "pack.install",
        "pack.disable",
        "pack.revoke",
        "pack.uninstall",
    }
)

#: BUILD_PLAN §625 + ADR-012 §75 — examiner / inspection-surface scopes.
#: T7 endpoints depend on these.
EXAMINER_SCOPES: frozenset[PackRBACScope] = frozenset(
    {
        "pack.audit.read",
        "pack.invocation.read",
    }
)
