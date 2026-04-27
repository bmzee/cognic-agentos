# ADR-014 — Runtime Tool Approval & Risk Tiers

## Status
**APPROVED for implementation** on 2026-04-26.

## Context

ADR-012 establishes pack-level approval (a tool/skill/agent goes through draft → submitted → approved → installed before it is callable at all). That gate runs **once per pack version**. It does not gate **per-invocation** decisions — and banks need that.

A pack approved for installation may still expose tools that, on a given call, do something bank-grade-risky: move money, query customer PII, modify a CBS record, send an email externally. The bank needs:

- Read-only operations: auto-run, no approval
- Write / customer-data / payment-touching operations: require human approval before execution
- Destructive / regulator-touching / cross-tenant operations: require **4-eyes approval** (two distinct reviewers) with explicit expiry

Without runtime approval, AgentOS is "pack-approved or pack-blocked" — too coarse for bank operational risk. Anthropic's Managed Agents pattern, OpenAI's Agents SDK, and Google ADK all expose runtime approval flows. AgentOS must too.

This is distinct from RBAC (who can call) and from guardrails (block obviously-bad input/output). Runtime approval is **synchronous human-in-the-loop on classified operations**.

## Decision

Add a **Runtime Tool Approval** layer between the harness and the MCP host. Every tool invocation passes through a risk classifier; high-risk tools block on approval before the underlying MCP call.

### Risk tiers

Every tool declares its risk tier in its pack manifest (Sprint 7A SDK validates this at submission; Sprint 7B reviewer sees it on approval; Sprint 5 MCP host enforces at invocation):

| Tier | Examples | Approval flow |
|---|---|---|
| `read_only` | Search circulars, query KB, read public regulation | **Auto-run.** No approval. Audit-logged like any call. |
| `internal_write` | Update internal ticket state, create a draft, log a comment | **Auto-run with audit emphasis.** No approval, but audit event includes `risk_tier=internal_write` flag for periodic review. |
| `customer_data_read` | Read customer profile, account history, KYC record | **Just-in-time approval** by a single approver with `tool.approve.customer_data` scope. Approval expires in N seconds (default 300s) — if the tool isn't called by then, approval is revoked. |
| `customer_data_write` | Modify customer record, update KYC | **Just-in-time approval** + per-call reason code. |
| `payment_action` | Initiate transfer, hold funds, release hold | **4-eyes** (two distinct approvers, both with `tool.approve.payment` scope; the second cannot be the originating user). Approval expires in N seconds (default 60s) — payments are time-sensitive. |
| `regulator_communication` | File a regulatory return, send email to SBP | **4-eyes** + categorised reason + audit-record reference (must reference a `decision_history` row that justifies the action). |
| `cross_tenant` | Any operation that crosses tenant boundary (rare) | **4-eyes** + bank legal sign-off scope. Default-disabled per tenant; operator-enabled with audit. |
| `high_risk_custom` | Pack author declares custom-tier with declared review process | Reviewer-defined approval flow per pack manifest |

### How the harness enforces it

```
agent.execute(input):
    ...
    when tool.invoke(name, args):
        manifest = plugin_registry.require("tool", name)
        tier = manifest.risk_tier
        if tier == "read_only" or tier == "internal_write":
            execute()  # no approval
        else:
            approval_request = approval.create(
                tool=name,
                args=redact_pii(args),
                tier=tier,
                requesting_agent=current_agent,
                requesting_user=session_user,
                expires_in_s=tier_default_expiry(tier)
            )
            await approval.wait(approval_request.id)  # blocks; harness yields
            if approval.granted:
                execute()
            else:
                raise ToolApprovalDenied(reason)
```

### Portal API

```
POST /api/v1/approvals                       # internal: harness creates
GET  /api/v1/approvals?status=pending        # reviewer queue
GET  /api/v1/approvals/{id}                  # detail (tool, args [PII redacted], tier, requester, expiry)
POST /api/v1/approvals/{id}/grant            # RBAC-scoped per tier
POST /api/v1/approvals/{id}/grant-second     # for 4-eyes (different user; checks distinctness)
POST /api/v1/approvals/{id}/deny             # with reason
GET  /api/v1/approvals/history?from&to       # audit trail
```

### RBAC scopes

- `tool.approve.customer_data` — single-approver scope
- `tool.approve.customer_data_write`
- `tool.approve.payment` — 4-eyes scope (must hold to grant; second grant must be different user)
- `tool.approve.regulator`
- `tool.approve.cross_tenant`
- `tool.approve.observe` — read-only into the queue (examiners)

### Audit linkage

Every approval emits hash-chained events into `decision_history`:
- `approval.requested` (with `parent_trace_id` linking to the agent invocation)
- `approval.granted_first` (and `approval.granted_second` for 4-eyes)
- `approval.denied`
- `approval.expired`

Tagged with ISO 42001 controls A.6.2.5 (operational responsibilities), A.7.4 (impact assessment), A.10.2 (transparency).

### What this is NOT

- **Not a substitute for guardrails.** Guardrails block obviously-bad input/output at parse time. Approval gates *legitimately-risky* operations on classified-tool calls.
- **Not a substitute for RBAC.** RBAC says *who can request a tool call*. Approval says *whether a specific call goes through*.
- **Not a substitute for pack approval.** Pack approval (ADR-012) gates *whether a tool is callable at all on this tenant*. Runtime approval gates *whether this specific invocation runs*.

## Consequences

### Positive
- Bank operational risk is granular: same pack, different tier per tool, different approval flow per tier
- 4-eyes for payments / regulator / cross-tenant is what every banking ops control framework demands
- Approval expiry prevents stale-approval risk (an approval granted 6 hours ago shouldn't authorise an action now)
- Audit chain captures the human decision at each tier — examiner can prove who approved what

### Negative
- Latency: approval-required tools wait on humans. UX must surface this clearly (operator queue, mobile-friendly approval).
- Reviewer workload: high-volume customer_data_read approvals can swamp reviewers. Mitigation: per-user **approval delegation** (a reviewer can pre-approve a class of operations for a session, with shorter expiry)
- 4-eyes-scoped users must be available for time-sensitive operations (payments) — operational policy concern
- Pack manifest now requires risk-tier declarations on every tool — pack authors must classify accurately. Reviewer (Sprint 7B) catches misclassification.

### Neutral
- Runtime approval lives inside AgentOS (not a plugin) because every bank deployment needs it; same logic as audit and guardrails

## Implementation phases

| Sprint | Work |
|---|---|
| **Sprint 5 (transitional rule)** | Harness ships **fail-closed** for all tiers above `internal_write` — high-risk tools register but every invocation is refused with `tool_approval_engine_not_available` and audit-logged. This is the only safe state until the approval engine exists. |
| **Sprint 11.5 (transitional rule, memory)** | Same fail-closed pattern for `long_term` memory writes from packs with `risk_tier >= customer_data_write` — refused with `memory_approval_engine_not_available`. See ADR-019 for the full statement. |
| **Sprint 7A** | Pack manifest schema includes `risk_tier` declaration on every tool |
| **Sprint 7B** | Reviewer sees risk-tier declarations + can require remediation before approval |
| **Sprint 13.5 (new)** | Approval engine + portal API + harness integration + RBAC scopes; the Sprint 5 transitional refusal is replaced by the real approval flow. Removal of the transitional rule is itself an audit event (`tool_approval.engine_enabled`) so banks can prove the cutover. |

Sprint 13.5 is a new sub-sprint introduced in Phase 4 alongside the eval/adversarial gates. ~2 work-units.

**Why the transitional rule:** there is no safe way to allow customer-data / payment / regulator tools to invoke without an approval engine. "Just log it and let it run" violates the threat model. The tradeoff is eight calendar weeks (Sprint 5 → Sprint 13.5) where banks cannot use high-risk tools at all. Fix is not "lower the bar"; fix is "ship Sprint 13.5 on schedule."

## References
- ADR-002 (MCP plugin protocol — pack manifests)
- ADR-005 (sub-agent — sub-agent calls also flow through approval)
- ADR-006 (ISO 42001 — control mappings)
- ADR-012 (pack lifecycle — pack approval is the upstream gate)
- [Anthropic — Managed Agents tool approval flows](https://www.anthropic.com/engineering/managed-agents)
- [OpenAI Agents SDK — approval flows](https://openai.github.io/openai-agents-python/)
