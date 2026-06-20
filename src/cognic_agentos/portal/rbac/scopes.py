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


#: Sprint 9.5 B1 — Model Registry RBAC scopes per ADR-013 + spec §6.3.
#: Eight values, covering the 6 portal endpoints planned at B4-B5 (list
#: / detail / audit share ``model.audit.read``; ``POST /promote`` is
#: body-aware, mapping ``target_state`` to ``model.promote.<target_state>``
#: at the route handler):
#:
#:   1. ``model.register``                  ← POST /api/v1/models
#:   2. ``model.promote.eval_passed``       ← POST /…/promote (body-routed)
#:   3. ``model.promote.tenant_approved``   ← POST /…/promote (body-routed)
#:   4. ``model.promote.serving``           ← POST /…/promote (body-routed;
#:                                            + RequireHumanActor)
#:   5. ``model.promote.deprecated``        ← POST /…/promote (body-routed)
#:                                            +1 vs BUILD_PLAN §796-802's
#:                                            7-value enumeration — see
#:                                            spec §8 reconciliation
#:   6. ``model.retire``                    ← POST /api/v1/models/{id}/retire
#:   7. ``model.audit.read``                ← GET /…, GET /{id}, GET /{id}/audit
#:   8. ``model.usage.read``                ← GET /{id}/usage (Block C)
#:
#: **Value-disjoint from :data:`PackRBACScope` / :data:`UIRBACScope` /
#: :data:`ComplianceRBACScope`** by namespace separation (every model
#: scope is ``model.*``; no other family is). Overlap would create a
#: wire-protocol ambiguity where a single 403 denial reason could match
#: multiple scope families. Pinned by
#: :file:`tests/unit/portal/rbac/test_model_scopes.py::TestModelScopesDisjointFromOtherFamilies`.
#:
#: Wire-protocol contract — every 403 ``scope_not_held`` denial body on
#: the model-registry surface carries one of these as
#: ``required_scope``. ANY drift here is a wire-protocol break.
#:
#: Style note: plain ``= Literal[...]`` (no ``TypeAlias`` annotation)
#: to match the Sprint-7B.1 / 7B.2 / 7B.4 / 9 repo convention at
#: ``packs/lifecycle.py:111`` + :data:`PackRBACScope` /
#: :data:`UIRBACScope` / :data:`ComplianceRBACScope` above.
ModelRBACScope = Literal[
    "model.register",
    "model.promote.eval_passed",
    "model.promote.tenant_approved",
    "model.promote.serving",
    "model.promote.deprecated",
    "model.retire",
    "model.audit.read",
    "model.usage.read",
]


#: All 8 model-lifecycle scopes as a frozenset, for bank-overlay binders
#: that mint a model-only actor scope set. MUST stay 1:1 with the
#: :data:`ModelRBACScope` Literal — pinned by
#: :file:`tests/unit/portal/rbac/test_model_scopes.py::TestModelLifecycleScopesFrozenset`.
MODEL_LIFECYCLE_SCOPES: frozenset[ModelRBACScope] = frozenset(
    {
        "model.register",
        "model.promote.eval_passed",
        "model.promote.tenant_approved",
        "model.promote.serving",
        "model.promote.deprecated",
        "model.retire",
        "model.audit.read",
        "model.usage.read",
    }
)


#: Sprint 11.5a — memory RBAC scopes per ADR-019. Grew from 4 (11.5a) to 7
#: (11.5b: + memory.forget / memory.redact / memory.regulator_erasure) to 8
#: (11.5c T1: + memory.export.read — examiner export surface per ADR-019 §52).
#: Value-disjoint from every other family by the memory.* namespace (pinned by
#: tests/unit/portal/rbac/test_memory_scopes.py + test_emergency_scopes.py).
MemoryRBACScope = Literal[
    "memory.read",
    "memory.write.scratch",
    "memory.write.task",
    "memory.write.long_term",
    # Sprint 11.5b T1 — erasure / lifecycle ops
    "memory.forget",
    "memory.redact",
    "memory.regulator_erasure",
    # Sprint 11.5c T1 — examiner export surface per ADR-019 §52
    "memory.export.read",
]


#: All 8 memory scopes as a frozenset (1:1 with MemoryRBACScope) for bank-overlay
#: binders. Pinned by tests/unit/portal/rbac/test_memory_scopes.py +
#: tests/unit/portal/rbac/test_emergency_scopes.py + test_scopes.py.
MEMORY_SCOPES: frozenset[MemoryRBACScope] = frozenset(
    {
        "memory.read",
        "memory.write.scratch",
        "memory.write.task",
        "memory.write.long_term",
        "memory.forget",
        "memory.redact",
        "memory.regulator_erasure",
        # Sprint 11.5c T1
        "memory.export.read",
    }
)


#: Emergency-control RBAC family per ADR-018. Sprint 11.5b T1 seeded the
#: single ``emergency.kill.memory_write_freeze`` value; Sprint 13.6 T5 grew
#: the family to 9 — the 7 ADR-018 kill-switch classes (the ADR table's scope
#: column, §34-42) + the seed + ``emergency.read`` for the GET surfaces
#: (list/audit). Quota scopes live in their OWN ``QuotaRBACScope`` family
#: (13.6 half 2, spec review patch 4) — NOT here. Its own family (NOT folded
#: into MemoryRBACScope) — emergency != memory-data scope. Wire-protocol-
#: public: every 403 ``scope_not_held`` denial on the kill-switch surface
#: carries one of these values. Namespace-disjoint from all other families by
#: the ``emergency.*`` prefix (pinned by
#: ``test_emergency_scopes.py::test_emergency_scope_disjoint_from_every_other_family``).
EmergencyRBACScope = Literal[
    "emergency.kill.pack",
    "emergency.kill.tool",
    "emergency.kill.model",
    "emergency.kill.tenant_packs",
    "emergency.kill.tenant_full",
    "emergency.kill.cloud",
    "emergency.kill.feature",
    "emergency.kill.memory_write_freeze",
    "emergency.read",
]

#: All 9 emergency scopes as a frozenset (1:1 with EmergencyRBACScope).
EMERGENCY_SCOPES: frozenset[EmergencyRBACScope] = frozenset(
    {
        "emergency.kill.pack",
        "emergency.kill.tool",
        "emergency.kill.model",
        "emergency.kill.tenant_packs",
        "emergency.kill.tenant_full",
        "emergency.kill.cloud",
        "emergency.kill.feature",
        "emergency.kill.memory_write_freeze",
        "emergency.read",
    }
)


#: Quota RBAC family per ADR-018 (Sprint 13.6b). Its OWN family — NOT folded
#: into ``EmergencyRBACScope`` (the 13.6a review-patch-4 split: kill switches
#: and quotas are distinct operator surfaces). Wave-1 = ``quota.read`` (the
#: read-only usage surface) ONLY; the operator override scope
#: (``quota.override.tokens``) lands with the deferred limit-write/override
#: surface. Wire-protocol-public; namespace-disjoint by the ``quota.*`` prefix
#: (pinned by ``test_quota_scopes.py``).
QuotaRBACScope = Literal["quota.read"]

#: All 1 quota scope as a frozenset (1:1 with QuotaRBACScope).
QUOTA_SCOPES: frozenset[QuotaRBACScope] = frozenset({"quota.read"})


#: Eval surface scope family (ADR-010 judge slice + Sprint-12 bulk runner +
#: Sprint-13a replay + Sprint-13b adversarial). Service or human actors may
#: run evals, replays, and adversarial runs (NOT a Human-only decision).
EvalRBACScope = Literal[
    "eval.judge.run",
    "eval.bulk.run",
    "eval.runs.read",
    # Sprint 13a T4 — live-replay endpoint scope.
    "eval.replay.run",
    # Sprint 13b T8 — adversarial-run endpoint scope (ADR-011).
    "eval.adversarial.run",
]

#: All eval scopes as a frozenset (1:1 with EvalRBACScope) for bank-overlay binders.
EVAL_SCOPES: frozenset[EvalRBACScope] = frozenset(
    {
        "eval.judge.run",
        "eval.bulk.run",
        "eval.runs.read",
        "eval.replay.run",
        "eval.adversarial.run",
    }
)


#: ADR-014 Sprint-13.5a — runtime tool-approval RBAC family. The 6 grant scopes
#: map 1:1 to the high-risk tiers (the approval engine enforces scope-per-tier);
#: ``tool.approve.observe`` is read-only approval-queue access (examiner) and
#: grants nothing. Value-disjoint from every other family by the
#: ``tool.approve.*`` namespace. Grant actions are ALSO Human-only — enforced at
#: the CORE approval engine AND the 13.5b portal seam (a service-token actor is
#: refused even holding the scope).
ToolApprovalRBACScope = Literal[
    "tool.approve.customer_data",
    "tool.approve.customer_data_write",
    "tool.approve.payment",
    "tool.approve.regulator",
    "tool.approve.cross_tenant",
    "tool.approve.high_risk_custom",
    "tool.approve.observe",
]

#: All 7 tool-approval scopes as a frozenset (1:1 with ToolApprovalRBACScope).
TOOL_APPROVAL_SCOPES: frozenset[ToolApprovalRBACScope] = frozenset(
    {
        "tool.approve.customer_data",
        "tool.approve.customer_data_write",
        "tool.approve.payment",
        "tool.approve.regulator",
        "tool.approve.cross_tenant",
        "tool.approve.high_risk_custom",
        "tool.approve.observe",
    }
)


#: Sprint 14A-A2a (ADR-022) — managed-run RBAC family. 2 run scopes in the
#: ``run.*`` namespace:
#:
#:   - ``run.submit`` ← ``POST /api/v1/runs`` (Sprint 14A-A2a).
#:   - ``run.resume`` ← ``POST /api/v1/runs/{run_id}/resume`` (Sprint 14A-A3b;
#:     the run→session resume route).
#:
#: NOT a Human-only decision (the sandbox approval seam owns the per-tier human
#: checkpoint, so the run routes do NOT also gate on :class:`RequireHumanActor`).
#: Value-disjoint from every other family by the ``run.*`` namespace.
#: Wire-protocol-public — the 403 ``scope_not_held`` body carries it. Pinned by
#: ``tests/unit/portal/rbac/test_run_scopes.py``.
#:
#: Style note: plain ``= Literal[...]`` (no ``TypeAlias`` annotation) per the
#: repo convention at ``packs/lifecycle.py:111`` + the families above.
RunRBACScope = Literal["run.submit", "run.resume"]  # A3b — +run.resume

#: All 2 run scopes as a frozenset (1:1 with :data:`RunRBACScope`) for
#: bank-overlay binders. Pinned by ``tests/unit/portal/rbac/test_run_scopes.py``.
RUN_SCOPES: frozenset[RunRBACScope] = frozenset({"run.submit", "run.resume"})


#: ADR-002 ("Fork D") — MCP tool-invocation RBAC family. 2 scopes in the
#: ``mcp.*`` namespace:
#:
#:   - ``mcp.tool.list`` ← ``GET /api/v1/mcp/servers/{server_id}/tools``.
#:   - ``mcp.tool.invoke`` ← ``POST /api/v1/mcp/servers/{server_id}/tools/call``.
#:
#: Read-only discovery (``list``) is a lower privilege than invocation
#: (``invoke``); a caller may hold ``list`` without ``invoke``. The sandbox/MCP
#: approval seam owns the per-tier human checkpoint, so the MCP routes do NOT
#: also gate on :class:`RequireHumanActor`. Value-disjoint from every other
#: family by the ``mcp.*`` namespace. Wire-protocol-public — the 403
#: ``scope_not_held`` body carries it. Pinned by
#: ``tests/unit/portal/rbac/test_mcp_scopes.py``.
#:
#: Style note: plain ``= Literal[...]`` (no ``TypeAlias``) per the repo
#: convention at ``packs/lifecycle.py:111`` + the families above.
MCPRBACScope = Literal["mcp.tool.list", "mcp.tool.invoke"]

#: All 2 MCP scopes as a frozenset (1:1 with :data:`MCPRBACScope`) for
#: bank-overlay binders. Pinned by ``tests/unit/portal/rbac/test_mcp_scopes.py``.
MCP_SCOPES: frozenset[MCPRBACScope] = frozenset({"mcp.tool.list", "mcp.tool.invoke"})


#: Sub-agent portal-trigger scope (ADR-005, "Fork B" portal seam). Spawning is
#: operational orchestration, not a Human-only decision; a high-risk child still
#: pends for a human downstream at sandbox cold-create admission.
SubAgentRBACScope = Literal["subagent.spawn"]

#: The 1 sub-agent scope as a frozenset (1:1 with :data:`SubAgentRBACScope`).
SUBAGENT_SCOPES: frozenset[SubAgentRBACScope] = frozenset({"subagent.spawn"})


#: ADR-023 (Wave-2) — per-tenant config-overlay RBAC family. Two values in the
#: ``config.tenant_overlay.*`` namespace, consumed by the operator-administered
#: overlay endpoints (`portal/api/config_overlay/routes.py`):
#:
#:   - ``config.tenant_overlay.write`` ← PUT/DELETE (set / clear an overlay).
#:     The mutation surface; ALSO gated by :class:`RequireHumanActor` per the
#:     AGENTS.md "Per-tenant allow-list changes" human-only-decisions rule —
#:     a service-token actor holding the scope is still refused at the dep
#:     chain (overlays are a per-tenant control surface).
#:   - ``config.tenant_overlay.read`` ← GET (list a tenant's overlays). Service
#:     actors permitted — read-only inspection is not a Human-only decision.
#:
#: **Value-disjoint from every other family** by namespace separation (every
#: config-overlay scope is ``config.tenant_overlay.*``; no other family is
#: ``config.*``). Overlap would create a wire-protocol ambiguity where a single
#: 403 ``scope_not_held`` denial reason could match multiple scope families.
#: Pinned by the disjointness test in
#: :file:`tests/unit/portal/rbac/test_config_overlay_scopes.py`.
#:
#: Wire-protocol contract — every 403 ``scope_not_held`` denial body on the
#: config-overlay surface carries one of these as ``required_scope``. ANY drift
#: here is a wire-protocol break.
#:
#: Style note: plain ``= Literal[...]`` (no ``TypeAlias`` annotation) to match
#: the repo convention at ``packs/lifecycle.py:111`` + the families above.
ConfigOverlayRBACScope = Literal[
    "config.tenant_overlay.read",
    "config.tenant_overlay.write",
]

#: All 2 config-overlay scopes as a frozenset (1:1 with ConfigOverlayRBACScope)
#: for bank-overlay binders. Pinned by
#: :file:`tests/unit/portal/rbac/test_config_overlay_scopes.py`.
CONFIG_OVERLAY_SCOPES: frozenset[ConfigOverlayRBACScope] = frozenset(
    {
        "config.tenant_overlay.read",
        "config.tenant_overlay.write",
    }
)


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
