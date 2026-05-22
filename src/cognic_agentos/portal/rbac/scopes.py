"""Sprint 7B.2 T2 — closed-enum RBAC scope vocabulary for the bank-pack lifecycle.

Per ADR-012 §39 + BUILD_PLAN §622-625 + ADR-012 §107-110 the lifecycle
portal API ships with **13** scopes, partitioned across five groups:

- Author surface (BUILD_PLAN §622): ``pack.submit``, ``pack.withdraw``
- Reviewer surface (BUILD_PLAN §623): ``pack.review.claim``,
  ``pack.review.approve``, ``pack.review.reject``
- Operator surface (BUILD_PLAN §624): ``pack.allow_list``, ``pack.install``,
  ``pack.disable``, ``pack.revoke``, ``pack.uninstall``
- Examiner / inspection surface (BUILD_PLAN §625 + ADR-012 §75):
  ``pack.audit.read``, ``pack.invocation.read``
- Override surface (ADR-012 §107-110): ``pack.override.approval_gate`` —
  the privileged force-approve gate, added at Sprint 7B.3 T8 alongside
  the 5-gate composer's override path. Its own group
  (:data:`OVERRIDE_SCOPES`), not held implicitly by any of the four
  role groups.

:data:`PackRBACScope` is the **wire-protocol contract** — every 403
``scope_not_held`` denial body carries the missing scope as a closed-enum
string. Any addition, rename, or removal is a wire-protocol break and
shows up in :file:`tests/unit/portal/rbac/test_scopes.py`'s diff (the
parametrised literal-pin tests + the 5-group partition invariant); the
override-scope-specific assertions live in
:file:`tests/unit/portal/rbac/test_scopes_override_extension.py`.

The Sprint-7B.1 closeout L119 says "14 scopes" but enumerated 12 — a
known cite-from-memory typo in the closeout per Sprint 7B.2 plan
self-review Round 0.5. BUILD_PLAN §622-625 + ADR-012 §107-110 are the
source of truth at 13.
"""

from __future__ import annotations

from typing import Literal

#: Closed-enum literal of the 13 bank-pack lifecycle scopes carried in
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
    # Sprint 7B.3 T8 — ADR-012 §107-110 override scope (the 13th).
    "pack.override.approval_gate",
]


#: Sprint 7B.4 T5 — closed-enum literal of the 8 UI event-stream + action
#: scopes added per ADR-020 + the design spec §4.1. Carried in the same
#: 403 ``scope_not_held`` denial body as :data:`PackRBACScope` — ANY
#: change here is a wire-protocol break on the UI denial surface.
#:
#: The 8 values partition into:
#:
#:   - **2 stream-surface scopes** consumed by the T10 SSE GET endpoints
#:     (one for the run-scoped stream, one for the tenant-scoped stream):
#:     ``ui.run_stream``, ``ui.tenant_stream``.
#:   - **6 action-surface scopes** consumed by the T11 POST /actions
#:     endpoint's per-class :class:`RequireUIAction` dependency; one
#:     scope per :data:`~cognic_agentos.portal.api.ui.dto.ActionClass`
#:     value: ``ui.action.{approve,deny,cancel_run,interrupt,resume,
#:     submit_elicitation}``.
#:
#: **Value-disjoint from :data:`PackRBACScope`** by namespace separation
#: (every UI scope is ``ui.*``; no pack scope is). Disjointness +
#: namespace separation are enforced by
#: :file:`tests/unit/portal/rbac/test_actor_scope_widening.py`: overlap
#: would create a wire-protocol ambiguity where a single 403 reason
#: string could match either family, leaving examiners + operator
#: runbooks unable to determine which surface emitted the denial.
#:
#: Style note: plain ``= Literal[...]`` (no ``TypeAlias`` annotation) to
#: match the Sprint-7B.1 + Sprint-7B.2 repo convention at
#: ``packs/lifecycle.py:111`` + :data:`PackRBACScope` above.
UIRBACScope = Literal[
    # 2 SSE stream-surface scopes (T10 GET endpoints).
    "ui.run_stream",
    "ui.tenant_stream",
    # 6 action-surface scopes — one per ActionClass (T11 POST /actions
    # per-class RequireUIAction).
    "ui.action.approve",
    "ui.action.deny",
    "ui.action.cancel_run",
    "ui.action.interrupt",
    "ui.action.resume",
    "ui.action.submit_elicitation",
]


#: #sprint-9 — ISO 42001 compliance evidence scopes (ADR-006). Two atoms:
#: bulk evidence-pack disclosure vs targeted forensic trace lookup.
ComplianceRBACScope = Literal[
    "compliance.evidence_pack.read",
    "compliance.trace.read",
]


#: Examiner-role compliance grant. Bank-overlay examiner binders grant
#: EXAMINER_SCOPES | EXAMINER_COMPLIANCE_SCOPES.
EXAMINER_COMPLIANCE_SCOPES: frozenset[ComplianceRBACScope] = frozenset(
    {
        "compliance.evidence_pack.read",
        "compliance.trace.read",
    }
)


#: Set type carried on :class:`~cognic_agentos.portal.rbac.actor.Actor`
#: instances and consumed by :class:`RequireScope`. The frozenset is
#: chosen for membership-test O(1) + immutability (matches the frozen
#: Actor model). The element type is the closed-enum literal so out-of-
#: vocab scope strings are caught by mypy at the call site.
#:
#: Sprint 7B.4 T5 note: this alias keeps the narrow
#: ``frozenset[PackRBACScope]`` shape for backward compat with existing
#: bank-overlay binders that mint pack-only scope sets. :class:`Actor`
#: itself widens the annotation directly to
#: ``frozenset[PackRBACScope | UIRBACScope]`` (see actor.py) so a single
#: actor can carry mixed-family scopes; this `ScopeSet` alias stays
#: pack-only until a future overlay-API amendment promotes it to the
#: union form.
ScopeSet = frozenset[PackRBACScope]

#: All 13 lifecycle scopes as a frozenset — wire-protocol surface for
#: the validator + the 5-group partition invariant test. Used by
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
        "pack.override.approval_gate",
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

#: ADR-012 §107-110 — override-surface scope group. Sprint 7B.3 T8.
#: A single-value group, intentionally distinct from the four role-group
#: frozensets above: ``pack.override.approval_gate`` is the privileged
#: force-approve gate and is NOT held implicitly by any author /
#: reviewer / operator / examiner role — a bank-overlay binder must
#: grant it explicitly. The 5-way partition
#: ``AUTHOR | REVIEWER | OPERATOR | EXAMINER | OVERRIDE ==
#: PACK_LIFECYCLE_SCOPES`` is pinned by the partition invariant test in
#: :file:`tests/unit/portal/rbac/test_scopes.py`. The T9 approve
#: endpoint's override path gates on this scope; the composer-side
#: :func:`cognic_agentos.packs.approval_gates.evaluate_override_decision`
#: consumes the held/not-held boolean.
OVERRIDE_SCOPES: frozenset[PackRBACScope] = frozenset(
    {
        "pack.override.approval_gate",
    }
)
