# ADR-015 — Policy-as-Code (Central Admission & Control DSL)

## Status
**APPROVED for implementation** on 2026-04-26.

## Context

AgentOS already has multiple decision points that today are scattered across hard-coded checks and per-feature config:

- Pack admission (ADR-002 trust gate; ADR-012 lifecycle approval)
- Model routing (ADR-007 cloud-policy enforcer; ADR-013 model-registry promotion)
- Tool approval (ADR-014 runtime tool approval)
- Sandbox egress (ADR-004 egress allow-list)
- Tenant constraints (per-tenant allow-lists, RBAC scopes, sandbox max policy, sub-agent depth caps)

Bank-grade platforms need these decisions **expressed in a single, auditable, version-controlled policy language** — not buried in ad-hoc settings + per-call code. Three reasons:

1. **Auditability.** Examiners ask: "show me the rule that decides which models can be routed for tenant X." That should be a queryable artefact, not a code review.
2. **Governance hygiene.** Bank security teams want to review policy changes as artefacts (Git PR + audit trail), not as scattered config flips.
3. **Policy drift prevention.** Without a central DSL, tenant-specific rules accumulate as exceptions in code; over time, the actual policy disagrees with what was approved.

OPA (Open Policy Agent / Rego) is the industry-standard answer for cloud-native admission control; AWS Cedar and Casbin are alternatives.

## Decision

Adopt **OPA / Rego** as the policy engine for all admission-control decisions. Rego policies are loaded from per-tenant Vault paths at startup; hot-reload supported with audit. Every decision point in AgentOS that today does an inline RBAC/allow-list check **delegates to the OPA policy bundle** instead.

### Decision points covered

| Decision | Inputs | Output |
|---|---|---|
| **Pack admission** | pack manifest, signature digest, tenant allow-list, conformance results | `allow / deny / require_review` |
| **Model routing** | resolved alias, profile, tenant policy, time-of-day, cost-budget remaining | `allow / deny / require_approval` |
| **Tool approval** (per ADR-014) | tool risk tier, requesting agent, session user, current approvals available | `auto_run / require_single_approval / require_4_eyes` |
| **Sandbox egress** | requested host, sandbox profile, tenant egress allow-list | `allow / deny` |
| **Sub-agent spawn** | parent identity, target agent, requested tool allow-list, recursion depth, budget remaining | `allow / deny / cap` |
| **Pack lifecycle transitions** | pack ID, from-state, to-state, actor identity, gate-results | `allow / deny / require_override_with_reason` |

Each decision is a Rego query against a tenant-specific policy bundle. Decisions are **always logged** with the matched rule(s), input snapshot, and outcome — full traceability.

### Policy bundle structure

```
policies/<tenant_id>/
├── packs.rego              # pack admission rules
├── models.rego             # routing + cloud-policy
├── tools.rego              # runtime approval
├── sandbox.rego            # egress + resource caps
├── subagent.rego           # spawn rules
├── lifecycle.rego          # pack lifecycle transitions
└── shared.rego             # common functions, time-window helpers, etc.
```

Cognic ships **default policy bundles** (`policies/_default/`) covering the same decisions with conservative defaults. Tenants override per-bank by editing their bundle in Vault.

### Engine integration

`cognic_agentos.policy.engine.OPAEngine`:
- Loads tenant bundle on startup (cached; ETag-checked every 60s for hot-reload)
- Sync API: `engine.evaluate(decision, input) -> Decision` returns `{allow: bool, rule_matched: str, reasoning: str}`
- All evaluation calls are **audit-logged** with decision name + input fingerprint + output + matched-rule reference
- Policy bundle changes hash-chained into `decision_history` (`policy.bundle_loaded` event)

### Why OPA / Rego (vs alternatives)

| Option | Pro | Con | Verdict |
|---|---|---|---|
| **OPA / Rego** | Industry standard, K8s-native, policy-as-code maturity, multi-language SDKs | Rego has a learning curve | **Chosen.** Widest tooling + audit support. |
| AWS Cedar | Simpler syntax | Newer, less ecosystem | Plugin pack candidate (Wave 2) |
| Casbin | Multi-language, lightweight | Less expressive for complex admission | Out |
| Internal Python DSL | Familiar to team | Reinvents the wheel; auditor unfamiliarity | Out |

Banks running OPA-based ecosystems (Argo, Istio, K8s admission webhooks) already have OPA tooling; we slot into their existing audit path.

### What this is NOT

- **Not a runtime guardrail.** Guardrails block obviously-bad I/O. Policy engine answers admission questions ("should this happen at all").
- **Not a replacement for RBAC vocabulary** (`portal/rbac/`). RBAC declares *what scopes exist*. Policy uses those scopes plus context to decide.
- **Not a config UI.** Policy bundle changes go through Git PR + cosign-signed bundle deployment + Vault commit, not through a portal "edit policy" page.

## Consequences

### Positive
- **Single audit surface for all admission decisions** — examiner asks one question, gets one answer
- **Policy changes are versioned + reviewable** — bank legal/compliance reviews PRs, not slack threads
- **Tenant-specific policy without code branches** — tenant rules live in their bundle, not in `if tenant_id == ...` code
- **Hot-reload + audit** — policy update doesn't require AgentOS restart; every reload is hash-chained
- **Cross-decision invariants enforceable** — "no payment tool can be called by an agent that has external-egress sandbox" is one Rego rule

### Negative
- **Rego learning curve** — bank security teams must learn it. Mitigation: Cognic ships default bundles + Rego cookbook
- **Performance** — policy evaluation on every admission call. Mitigation: bundle caching, decision result caching (with input-fingerprint key), <5ms P99 target
- **Bundle deployment pipeline** — policy bundles need their own CI/CD: lint, test, sign, Vault-deploy. Wave 2 operational work.
- **Decision-point migration** — existing inline checks (Sprint 4 trust gate, Sprint 7B lifecycle, Sprint 14 approval) all become OPA queries. Refactor lands in a dedicated sprint.

### Neutral
- Banks who refuse OPA can ship a Cedar adapter or internal-DSL adapter as a plugin pack (`cognic-policy-cedar`) — same plugin pattern as ADR-009 infrastructure adapters

## Implementation phases

| Sprint | Work |
|---|---|
| **Sprint 4 (seed)** | Minimal `core/policy/engine.py` evaluator (load-from-disk only, no hot-reload) so Sprint 4's supply-chain grade decision and Sprint 11.5's memory enforcement do not block on Sprint 13.5. Ships `policies/_default/supply_chain.rego` only. |
| **Sprint 11.5 (extends bundles)** | Adds `policies/_default/memory.rego` and `memory_purpose_matrix.rego`; both **default-deny** until tenant override. Reuses Sprint 4 evaluator. |
| **Sprint 13.5 (full)** | Extends Sprint 4 evaluator with hot-reload + decision-trail API (`GET /api/v1/policy/decisions/{trace_id}`); adds remaining default bundles (`packs.rego`, `models.rego`, `tools.rego`, `sandbox.rego`, `subagent.rego`, `lifecycle.rego`, `sampling.rego`); refactors Sprint 7B/8/9.5/11 inline checks to delegate. Sprint 4 trust gate and Sprint 11.5 memory enforcement already delegate via the seed — no refactor needed. |
| **Wave 2** | Cedar adapter pack; policy-bundle-CI templates; bank-grade Rego cookbook; cross-tenant policy review workflow |

Sprint 4 absorbs ~0.5 wu for the seed evaluator. Sprint 13.5 work-units total: ~2.5 (combining ADR-014 + ADR-015 + ADR-018 work; all three touch the same decision-point integration).

## Sprint 13.5a amendment (2026-06-10) — `tools.rego` tier→flow decision point landed

Sprint 13.5a lands the first of the "Sprint 13.5 (full)" bundles ahead of the hot-reload + decision-trail work: **`policies/_default/tools.rego`**, the ADR-014 risk-tier→approval-flow classifier. It exposes one **string-returning** decision point, `data.cognic.tools.approval.flow` (`tools.rego:24` `package cognic.tools.approval`), whose closed 3-value enum is `auto_run` / `require_single_approval` / `require_4_eyes` (`tools.rego:46-50`). The 8 ADR-014 risk tiers map to those flows via three disjoint tier sets; the **default is fail-closed `require_4_eyes`** (`tools.rego:44`).

It is consumed by `core/approval/policy.py::ApprovalPolicy.classify` (`policy.py:51`) through the existing **Sprint-4 `OPAEngine`** — but because the seed `OPAEngine` only evaluates boolean decision points, `classify` fetches the string result via a direct subprocess string-fetch that **mirrors `core/scheduler/policy.py::SchedulerPolicy._fetch_refusal_reason`**, including the drift-pinned `_MINIMAL_SUBPROCESS_ENV` parity (`policy.py:32`). Any OPA error OR an out-of-enum value fails closed to `require_4_eyes` (`policy.py:38`). Per the AGENTS.md stop-rule policy-bundle convention, the tier→flow map is **bank-overlay-tightenable**; loosening the kernel defaults requires a coordinated kernel + ADR amendment (same precedent as `sampling.rego` / `supply_chain.rego` / `elicitation.rego` / `sandbox.rego` / `scheduler.rego`). The remaining 13.5 bundles + the hot-reload + decision-trail API remain as scheduled.

## References
- ADR-002 (trust gate becomes a Rego query)
- ADR-004 (sandbox egress becomes a Rego query)
- ADR-005 (sub-agent spawn becomes a Rego query)
- ADR-007 (cloud-policy enforcer becomes a Rego query)
- ADR-012 (pack lifecycle transitions become Rego queries)
- ADR-013 (model promotion gates become Rego queries)
- ADR-014 (runtime tool approval becomes a Rego query)
- [Open Policy Agent — Rego language](https://www.openpolicyagent.org/docs/latest/policy-language/)
