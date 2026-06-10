# ADR-012 — Bank Pack Lifecycle (Portal API + Workflow)

## Status
**APPROVED for implementation** on 2026-04-26.

## Context

ADR-002 establishes MCP as the discovery + invocation protocol. ADR-008 establishes the SDK + CLI for engineers to author packs. PROJECT_PLAN.md §8 ("Bank-Created Pack Enablement Plan") makes clear that **bank-created packs are a product requirement**, not an afterthought — and that the contract is incomplete until banks can manage the **full pack lifecycle through portal APIs**, not just through CLI.

A bank running AgentOS at scale will have:
- Multiple developers authoring packs (CBS adapters, internal-data tools, workflow agents)
- Security/compliance reviewers approving or rejecting packs
- Operators allow-listing approved packs and installing them on tenants
- Auditors inspecting installed-pack provenance + governance evidence
- Incident responders revoking compromised packs

CLI alone cannot satisfy these audiences. They need RBAC-scoped portal APIs with workflow state machines, audit linkage, and evidence inspection.

## Decision

Add a **bank pack lifecycle layer** to AgentOS — portal API endpoints + workflow state machine that drive a pack from `draft` → `submitted` → `under-review` → `approved` (or `rejected`) → `allow-listed` → `installed` → `disabled` → `revoked` → `uninstalled`. Every transition is RBAC-gated, audit-chained, and evidence-bearing.

### Lifecycle states

```
draft ─→ submitted ─→ under_review ─→ approved ─→ allow_listed ─→ installed
                          │              │              │             │
                          │              │              │             ↓
                          ↓              ↓              ↓          disabled
                       rejected      withdrawn      revoked          │
                                                                     ↓
                                                                 uninstalled
```

State transitions (per state, who can trigger, which RBAC scope, what evidence is captured):

| From | To | Triggered by | RBAC scope | Evidence captured |
|---|---|---|---|---|
| draft | submitted | pack author | `pack.submit` | manifest, signed artefact digest, SBOM, conformance-suite report |
| submitted | under_review | reviewer | `pack.review.claim` | reviewer identity, claim time |
| under_review | approved | reviewer | `pack.review.approve` | reviewer comments, reasoning chain, ISO 42001 evidence pointer. **Approval is gated by: (1) cosign signature valid against tenant trust root; (2) ADR-010 evaluation harness pass-rate ≥ tenant quality threshold; (3) ADR-011 adversarial corpus pass-rate ≥ 0.99 with 100% on high-severity categories; (4) OWASP Agentic conformance suite green; (5) tenant RBAC scope `pack.review.approve` held by reviewer. Approval action MUST refuse to proceed if any gate is red — reviewer override requires `pack.override.approval_gate` scope plus categorised override reason.** |
| under_review | rejected | reviewer | `pack.review.reject` | rejection reasons (categorised), reviewer comments |
| submitted/under_review | withdrawn | author | `pack.withdraw` | reason |
| approved | allow_listed | operator | `pack.allow_list` | tenant scope, scope justification |
| allow_listed | installed | operator | `pack.install` | tenant target, install time, AgentOS version |
| installed | disabled | operator | `pack.disable` | reason (e.g. incident, performance) |
| installed/disabled | revoked | operator | `pack.revoke` | revocation reason, blast-radius scope (this tenant / all tenants) |
| disabled/revoked | uninstalled | operator | `pack.uninstall` | uninstall time, retained-history-window |

Historical audit/evidence records are **never deleted** even after `uninstalled`. Revocation revokes future invocations; the pack's past actions remain examiner-auditable.

### Portal API endpoints (Phase 2 — Sprint 7B)

```
# Pack management — author surface
POST   /api/v1/packs/drafts                    create new draft pack record
PUT    /api/v1/packs/drafts/{id}               update draft (manifest, artefact, metadata)
POST   /api/v1/packs/drafts/{id}/submit        submit for review
DELETE /api/v1/packs/drafts/{id}               cancel draft

# Review surface
GET    /api/v1/packs?status=submitted          reviewer queue
POST   /api/v1/packs/{id}/claim                reviewer claims a submission
POST   /api/v1/packs/{id}/approve              approve with reasoning
POST   /api/v1/packs/{id}/reject               reject with categorised reasons
GET    /api/v1/packs/{id}/evidence             SBOM, signature, conformance results, dependency scan

# Operator surface
POST   /api/v1/packs/{id}/allow-list           add to tenant allow-list
POST   /api/v1/packs/{id}/install              install on a tenant
POST   /api/v1/packs/{id}/disable              disable on a tenant
POST   /api/v1/packs/{id}/revoke               revoke (security incident path)
DELETE /api/v1/packs/{id}/install              uninstall (retain history)

# Inspection — examiner-facing
GET    /api/v1/packs                           list packs with current state, version, signature digest
GET    /api/v1/packs/{id}                      pack detail incl. lifecycle history
GET    /api/v1/packs/{id}/audit                hash-chained audit events for this pack
GET    /api/v1/packs/{id}/invocations?from&to  pack invocation history (audit-derived)
```

All endpoints RBAC-gated. All state transitions emit hash-chained audit events tagged with applicable ISO 42001 controls (per ADR-006).

### Approval gate composition (the explicit dependency chain)

The `under_review → approved` transition is the most consequential in the lifecycle. It depends on **five orthogonal gates** all returning green:

```
                          ┌────────────────────────────┐
                          │  approve(pack_id) endpoint │
                          └─────────────┬──────────────┘
                                        │
            ┌────────────┬───────────────┼───────────────┬───────────────┐
            │            │               │               │               │
            ▼            ▼               ▼               ▼               ▼
   ┌─────────────┐ ┌──────────┐ ┌────────────────┐ ┌──────────────┐ ┌──────────┐
   │ cosign      │ │ Tenant   │ │ ADR-010 eval   │ │ ADR-011      │ │ OWASP    │
   │ signature   │ │ allow-   │ │ harness pass   │ │ adversarial  │ │ Agentic  │
   │ verifies    │ │ list     │ │ ≥ threshold    │ │ pass ≥ 0.99  │ │ conform- │
   │ vs trust    │ │ permits  │ │ (per scope)    │ │ + 100% high- │ │ ance     │
   │ root        │ │ this pack│ │                │ │ severity     │ │ green    │
   └─────────────┘ └──────────┘ └────────────────┘ └──────────────┘ └──────────┘
```

If any gate is red, `approve()` returns 412 Precondition Failed with a structured payload listing which gates failed. **No silent partial approval.** No "approve and we'll fix testing later" path.

Override path: a privileged operator with the `pack.override.approval_gate` scope can force-approve a pack despite a red gate. This:
- Requires a categorised reason (`security_exception`, `prerelease_validation`, `legacy_grandfather`, `other`)
- Emits a hash-chained `pack.approval_override` event tagged with ISO control A.6.2.4 (governance overrides)
- Is surfaced as a compliance metric (override count per pack, per reviewer, per tenant) — escalates to MLRO if the override rate exceeds tenant threshold

**Trust onboarding gate** (cosign verify) is the only gate that cannot be overridden — an unsigned or wrong-signed pack is refused absolutely. Overriding cosign would make the entire trust model meaningless.

### Local governance test harness

Before submission, pack authors run their pack through `agentos test-harness <pack>` (extends Sprint 7A CLI). The harness:
- Loads the pack into a fixture-only AgentOS instance
- Runs the pack against fixture-based guardrails, audit chain, decision history, sandbox policy
- Runs OWASP Agentic Top 10 / Agentic Skills conformance checks (tool misuse, goal hijacking, identity abuse, prompt-injected skills, dependency poisoning, secret exfiltration, unsafe filesystem/network access)
- Outputs a conformance report attached to the eventual submission

Banks see a green local report → submit with confidence. Reviewers see the same report → approval is data-driven.

### Trust onboarding flow

Banks bringing their own cosign trust root must:
1. Generate or import a key pair in their Vault
2. Configure the per-tenant trust-root path in AgentOS (`secret/cognic/<tenant>/trust-root`)
3. Test against a known-good Cognic pack to confirm signature chain validates
4. Add their own published-pack public keys to the per-tenant trust list

Trust-root rotation is operator-only with audit. Rotated-out keys remain valid for verifying past evidence (so old audit records still verify).

### Wave 2 vs Wave 1

Wave 1 (this ADR) ships the workflow + APIs + harness. Wave 2 adds:
- Reviewer dashboard UI (lives in portal-ui repo, not here)
- Automated security scans on submission (CVE in deps, secret leakage in code, license check)
- Cross-tenant pack sharing (private marketplace) — beyond bank-internal scope

## Consequences

### Positive
- **Banks are first-class extension authors**, not Cognic-dependent
- **Lifecycle is auditable end-to-end** — examiner can trace any installed pack from draft → install with full reviewer reasoning
- **RBAC-gated workflow** — clear separation between developer / reviewer / operator / examiner roles
- **Evidence-driven approval** — reviewers see SBOM + signature + conformance + dependency scan + sandbox profile in one inspection view
- **Revocation preserves history** — security incident response doesn't destroy audit trail
- **Local harness reduces submission churn** — packs come in already-validated

### Negative
- **Significant scope** — ~3 work-units for the lifecycle API + state machine + harness (Sprint 7B)
- **State-machine surface area** — 11 states × multiple transitions = ~30 distinct API contracts. Strict schema testing required.
- **Cross-tenant complications** — a pack approved on one tenant must be re-approved on another (intentional for security; needs UX consideration in a future Studio sprint)
- **Trust-root rotation playbook** is operator work — Wave 2 needs a runbook

### Neutral
- The lifecycle is **bank-operator-driven**. Cognic-authored packs go through the same workflow when installed on a bank tenant — no privileged path.

## Implementation phases

| Sprint | Work |
|---|---|
| **Sprint 7B** (split from Sprint 7) | Lifecycle state machine + portal API endpoints + RBAC scopes + local governance test harness + OWASP conformance checks |
| **Sprint 13** (existing) | Adversarial testing integrates as a pre-approval gate |
| **Phase 5 / Sprint 21** | Reviewer dashboard UI in `studio-ui/` (only if Phase 5 is built) |

Sprint 7B work-units: ~3.

## References
- PROJECT_PLAN.md §7 Phase 2 (deliverables 213-214 — portal API for pack lifecycle)
- PROJECT_PLAN.md §8 (Bank-Created Pack Enablement Plan)
- ADR-002 (MCP plugin protocol — defines what's being lifecycle-managed)
- ADR-008 (authoring platform — Phase A is SDK/CLI; this ADR is the Phase A complement: lifecycle APIs)
- ADR-011 (adversarial testing — gates approval transition)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/)

## Sprint 13c reconciliation — §41 gate-3 now live (2026-06-10)

The §41 approval gate (3) — "ADR-011 adversarial corpus pass-rate ≥ 0.99 with 100% on high-severity categories" — is **now live-populated** at submit. Per ADR-011's Sprint-13c amendment, the gate is the existing 5-gate composer `packs/approval_gates.compose_approval_gates` (gate-3 = adversarial); there is **no** standalone `evaluation/promotion_gate.py` (BUILD_PLAN §1101 superseded). Sprint 13c adds a submit-time, reference-based producer that resolves a 13b adversarial eval-run and freezes the `payload["adversarial"]` snapshot on the `pack.lifecycle.submitted` chain row, plus a **zero-new-vs-baseline regression** sub-term (reusing Sprint-13a's `compute_replay_diff`). The pass-rate floor stays the operator-configured `Settings.adversarial_pass_rate_floor` (Human-only threshold change). The reviewer override remains **`pack.override.approval_gate`** (§110) — adversarial is an overridable gate; the BUILD_PLAN §1102 `override.adversarial_gate` shorthand is superseded and **no gate-specific override scope** exists. No new RBAC scope, no Alembic migration, no new Settings.
