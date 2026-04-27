# ADR-018 — Emergency Controls (Kill Switches, Quotas, Token + Spend Budgets)

## Status
**APPROVED for implementation** on 2026-04-26.

## Context

Banks deploying AgentOS will, within the first six months of production, encounter a situation where they need to **stop something immediately**:

- A pack version was approved + installed but is misbehaving in production (silent error, infinite loop, runaway tool call)
- A model is hallucinating in a customer-facing path; pack rollback is too slow (hours), bank needs **seconds**
- An agent is consuming far more tokens / cost than budget; CFO wants the brake pulled
- A specific tool has been disclosed-as-vulnerable in a CVE; bank needs to revoke it on every tenant immediately
- A tenant is being attacked (DDoS via agent invocations); bank needs to throttle that tenant only
- Cloud-LLM provider has an outage; bank needs to fail-fast rather than queue invocations

Pack lifecycle revocation (ADR-012) is the *paperwork-clean* answer — but it goes through reviewer + operator scopes and audit, taking minutes. **Real emergencies need single-button kill switches with bounded propagation latency** (target: < 30 seconds across all running invocations).

Beyond emergency kill switches, banks need **proactive quota controls** to prevent runaway-spend before it becomes an emergency:
- Per-pack token budget per day / per tenant
- Per-tool invocation rate limits
- Per-model spend ceiling (in $)
- Per-tenant aggregate token + spend caps
- Per-agent recursion / sub-agent depth caps (per ADR-005, but enforced as a *quota*)

## Decision

Add an **Emergency Controls** layer with two surfaces: kill switches (immediate stop) and quotas (proactive budgets). Both are RBAC-gated, audit-chained, hash-linked into `decision_history`.

### Kill switches — granular tier

Operators with appropriate scope can flip these in the **emergency control plane** (portal API + CLI + dashboard); flips propagate to all running invocations within 30 seconds. All flips emit `emergency.kill_switch_flipped` audit events.

| Switch | Scope | Effect | Restoration |
|---|---|---|---|
| `pack:<pack_id>` | `emergency.kill.pack` | All invocations of this pack version refuse with `PackKilled` error; in-flight invocations get `OperationAborted` | Operator revert with reason; audit event |
| `tool:<tool_id>` | `emergency.kill.tool` | All invocations of this tool (across all packs that use it) refuse | Same |
| `model:<model_id>` | `emergency.kill.model` | All routing to this model refuses; LiteLLM gateway returns 503; harness can retry to a different tier alias if pack manifest declares fallbacks | Same |
| `tenant:<tenant_id>:packs` | `emergency.kill.tenant_packs` | All pack invocations on this tenant refuse | Same |
| `tenant:<tenant_id>:full` | `emergency.kill.tenant_full` | Tenant blocked entirely; only `/healthz` and `/readyz` reachable | Same |
| `cloud_routing` | `emergency.kill.cloud` | All cloud-routed model calls refuse; falls back to self-hosted only (or fails if no self-hosted alias) | Same |
| `feature:<feature_name>` | `emergency.kill.feature` | Disable a specific platform feature (e.g. sub-agent spawning, stdio-MCP, sandbox creation) per-tenant or globally | Same |

### Propagation guarantees

- **Push-based**: kill-switch state lives in Redis (per ADR-009 bundled — Redis-as-control-plane); every harness execute-loop checks the relevant switches at every tool invocation + LLM call.
- **30-second SLA**: target P99 propagation latency across all running invocations. Long-running sub-agent spawns check kill switches at every yield point (per-tool boundaries).
- **Fail-closed**: if Redis is unreachable, harness assumes the most-recent locally-cached state for ≤60s, then **fails closed** (refuses all invocations on that tenant) until Redis recovers. Unavailability of the control plane must NOT default to permissive.
- **Hash-chained audit**: every kill-switch state change emits a `decision_history` event tagged with ISO 42001 A.6.2.5 (operational responsibilities) + A.9.2 (logging).

### Quotas — proactive budgets

Quotas declared per-tenant in Rego policy (per ADR-015), enforced by the gateway + harness. Each quota has:
- A budget (numeric)
- A window (rolling, calendar-day, calendar-month)
- A soft-threshold action (warn at 80%)
- A hard-threshold action (refuse at 100%)
- An override scope (operator with `quota.override.<class>` scope can extend with audit reason)

| Quota class | Default scope | Example |
|---|---|---|
| `tokens_per_pack_per_day` | per pack × per tenant | `cognic-agent-policyqa: 10M tokens/day on tenant ABC` |
| `tokens_per_tenant_per_day` | per tenant aggregate | `tenant ABC: 100M tokens/day across all packs` |
| `spend_per_model_per_day` | per model × per tenant | `cognic-tier1-cloud-openai: $50/day on tenant ABC` |
| `spend_per_tenant_per_day` | per tenant aggregate | `tenant ABC: $500/day` |
| `invocations_per_tool_per_minute` | per tool × per tenant | `query_customer_balance: 100/min on tenant ABC` (rate limit) |
| `subagent_depth_max` | per tenant | `tenant ABC: max 3 levels deep` (overrides ADR-005 default) |
| `subagent_spawns_per_minute_per_agent` | per agent × per tenant | `rm_copilot: 10 spawns/min` |

Quotas accumulate via the gateway-call ledger (per ADR-007 amendment) + decision_history aggregation; eventually-consistent within 5s. Hard-threshold breaches emit `quota.exhausted` events.

### Portal API

```
# Emergency kill switches
GET  /api/v1/emergency/kill-switches                   # list active
POST /api/v1/emergency/kill-switches                   # create (RBAC scope per kill type)
DELETE /api/v1/emergency/kill-switches/{key}           # revert (with audit reason)

# Quotas
GET  /api/v1/quotas?tenant=...                         # current quotas + usage %
PUT  /api/v1/quotas/{class}/{scope}                    # set limit (Rego-policy-scoped)
GET  /api/v1/quotas/{class}/{scope}/history?from&to    # time-series usage

# Inspection
GET  /api/v1/emergency/audit?from&to                   # audit trail of all switches + quota overrides
```

### Dashboard surface

Operators see a real-time emergency dashboard (separate from the rest of the portal — accessible even when other surfaces are degraded):
- Active kill switches with timestamps + originator
- Per-tenant quota usage gauges
- Recent overrides (≥80% usage approaches showing on a heat map)
- One-click flip with mandatory reason field (categorised: `incident_response`, `cost_control`, `security_disclosure`, `regulator_directive`, `vendor_outage`)

### What this is NOT

- **Not a substitute for guardrails or policy**. Guardrails block obviously-bad I/O. Policy decides admission. Emergency controls **stop legitimately-permitted things in a hurry**.
- **Not a substitute for pack revocation** (ADR-012). Revocation is the durable answer; kill switches are the immediate-response answer. Banks should use a kill switch *while* pack revocation is being reviewed.
- **Not a global cost-management product**. Quotas are per-tenant operational guardrails. Cross-tenant cost reporting is a separate Wave 2/3 concern.

## Consequences

### Positive
- **Bank-grade incident response** — CISO has a "stop button" with documented blast radius and audit trail
- **Regulatory directive responsiveness** — when SBP or another regulator says "stop X immediately," banks have a single API call to do so
- **Cost predictability** — runaway spend is impossible past the configured quota
- **Per-tenant isolation** — one tenant's emergency doesn't affect others
- **Audit completeness** — every flip + every override + every quota breach is examiner-traceable

### Negative
- **Redis-as-control-plane criticality** — Redis becomes a bank-deployment-critical dependency. Mitigation: HA Redis + fail-closed behaviour + `/readyz` reports Redis as critical.
- **Quota tuning** — banks must size quotas based on actual usage; under-sized quotas trigger frequent overrides (eroding the brake's value). Mitigation: dashboard surfaces "quota near-misses" so banks can right-size.
- **Override audit fatigue** — frequent "extend quota" overrides could drown signal in noise. Mitigation: weekly compliance report on override frequency per scope.

### Neutral
- Kill switches + quotas live in AgentOS core (not a plugin). Every bank deployment needs them; same logic as audit and guardrails.

## Implementation phases

| Sprint | Work |
|---|---|
| **Sprint 11.5 (seed)** | Minimal `core/emergency/kill_switches.py` shipping the single `memory.write_freeze` class with full fail-closed Redis semantics. Same Redis schema as Sprint 13.5 (no migration). Memory writes check this before every operation per ADR-019. |
| **Sprint 13.5 (extended)** | Extends the seed with the full class set (`pack`, `tool`, `model`, `tenant_packs`, `tenant_full`, `cloud`, `feature`); adds portal API + RBAC scopes for new classes; quotas + accumulation from gateway-call ledger; harness checks at every invocation point + LLM call boundary; audit chain linkage |
| **Sprint 14 (deployment kit)** | Rego policy templates + dashboard scaffold + per-tenant tunings |
| **Wave 2** | Quota-prediction (forecast when a tenant will hit the daily cap based on current burn rate) + cross-tenant cost reconciliation dashboard |

Sprint 11.5 absorbs ~0.25 wu for the seed (single class, no portal API). Sprint 13.5 absorbs ~1.25 wu for the extension (now ~3 wu total combined with ADR-014, ADR-015, ADR-018). Sprint 14 grows from 2 → 2.5 wu.

## References
- ADR-005 (sub-agent depth caps — emergency-controls layer enforces these as quotas)
- ADR-007 (gateway-call ledger — quota accounting source)
- ADR-009 (Redis bundled — control-plane substrate)
- ADR-012 (pack revocation — durable counterpart)
- ADR-014 (runtime approval — different layer; emergency stops what was approved)
- ADR-015 (Rego policy — quota declarations)
- [Anthropic — Managed Agents incident response patterns](https://www.anthropic.com/engineering/managed-agents)
