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

## Sprint 10.5 amendment (2026-05-27) — `QuotaInterrogator` + `KillSwitchInterrogator` consumer-owned seams (no implementations yet)

Sprint 10.5 (merged via PR #40, squash `6791eec`) landed the **scheduler-side seams** for quota + kill-switch consultation but **NOT the substantive implementations**. Sprint 13.5 still owns the full `core/emergency/quotas.py` + `core/emergency/kill_switches.py` modules per this ADR's §"Implementation phases" (Sprint 11.5 seed + Sprint 13.5 extended).

### Option A doctrine LOCKED — SchedulerPolicy owns Rego ONLY (per ADR-022 §"Sprint 10.5 implementation closeout / 2. Option A doctrine LOCKED")

ADR-022's original wording (read literally) suggested `SchedulerPolicy` could be the single dispatch point that consults BOTH Rego AND `core/emergency/*` (quota + kill_switch). At T9 this was **rejected** because it conflated **ADR-018 (emergency controls — operational real-time emergency surface)** with **ADR-015 (policy-as-code — declarative bundle decision)**. Kill-switch and quota are operational gates, not policy decisions.

**Locked ownership boundary:**
- `SchedulerPolicy` (`core/scheduler/policy.py`) owns **Rego policy ONLY** — the `data.cognic.scheduler.admit.allow` decision point.
- `SchedulerEngine` (`core/scheduler/engine.py`) owns the operational gates — kill_switch + quota + pack_state + queue/caps — invoked in deterministic order BEFORE / AFTER the policy gate per the 5-gate admission pipeline.

### Consumer-owned Protocol seams declared in `core/scheduler/_seams.py`

Per `[[feedback_consumer_owned_protocol_for_unlanded_dep]]` — the Protocols are declared in the scheduler module that needs them; Sprint 13.5's real `core/emergency/*` implementations will structurally conform.

| Protocol | Method signature(s) — keyword-only args throughout | Sprint 13.5 conformer (planned) |
|---|---|---|
| `QuotaInterrogator` | `async def would_admit(*, task_id: uuid.UUID, tenant_id: str, pack_id: str, estimated_tokens: int) -> bool` AND `async def release_reservation(task_id: uuid.UUID) -> None` | `core/emergency/quotas.QuotaEngine` |
| `KillSwitchInterrogator` | `async def is_active(*, tenant_id: str, pack_id: str) -> bool` | `core/emergency/kill_switches.KillSwitchEngine` |

**`QuotaInterrogator` is a two-method API by design.** `would_admit(...)` atomically reserves `estimated_tokens` against tenant + pack budgets keyed by `task_id` on `True` return. `release_reservation(task_id)` releases the reservation on every terminal-state transition (`completed` / `failed` / `cancelled` / `preempted` / `expired`) AND is **idempotent** — calling on an unknown or already-released `task_id` is a no-op (terminal-state code paths may fire multiple times in failure scenarios and must not raise; this contract was locked at Sprint 10.5b T9). The `task_id` handle is what makes pre-execution quota reservation safe: without it the engine couldn't release on terminal-state without a separate accounting structure.

**`KillSwitchInterrogator` uses `is_active(...)` not `is_killed(...)`.** The naming was deliberately chosen at T9 to match the conventional emergency-controls vocabulary ("kill switch is active" reads naturally; "is killed" suggests a past tense). The two-arg keyword-only signature (`tenant_id` + `pack_id`) is the minimum surface that lets Sprint 13.5 layer per-pack + per-tenant + per-feature kill scopes through a single Protocol call.

### Fail-loud sentinels (Wave-1 default)

- `_NullQuotaInterrogator.would_admit(*, task_id, tenant_id, pack_id, estimated_tokens)` raises `NotImplementedError` referencing ADR-018 §"Decision / Quotas — proactive budgets". `release_reservation(task_id)` does the same. Pre-Sprint-13.5 deployments cannot accidentally see a synthetic-allow result.
- `_NullKillSwitchInterrogator.is_active(*, tenant_id, pack_id)` raises `NotImplementedError` referencing ADR-018 §"Decision / Kill switches — granular tier". Pre-Sprint-13.5 deployments cannot accidentally see a synthetic-not-active result.

### Wire-public admission outcomes already in Wave-1 closed-enum

Both refusal paths' outcome values are **already in the Sprint 10.5 `SchedulerAdmissionOutcome` Literal** at `core/scheduler/_types.py:21-31` (per ADR-022 §"Admission outcomes"). The actual wire-public enum values are unprefixed:

- `refused_quota_exhausted` — emitted when the bound `QuotaInterrogator.would_admit()` returns `False`. **Substantive enforcement WAITS for Sprint 13.5.**
- `refused_kill_switch_active` — emitted when the bound `KillSwitchInterrogator.is_active()` returns `True`. **Substantive enforcement WAITS for Sprint 13.5.**

The Wave-1 closed-enum keys are stable: when Sprint 13.5 binds the real conformers, no scheduler wire-protocol change is needed. Bank-overlay consumers can already build error-handling against these closed-enum values today; the codepaths just route through the fail-loud sentinels until Sprint 13.5's DI binder hook lands.

### Substrate independence — AST-pinned

`core/scheduler/*` modules do NOT import from `cognic_agentos.core.emergency.*`. The binding happens at AgentOS app startup (the DI binder wires Sprint 13.5's real `QuotaEngine` + `KillSwitchEngine` into the seam slots on the `SchedulerEngine` constructor). Pinned by AST guard `tests/unit/core/scheduler/test_architecture_no_emergency_import.py` (PEP-328 relative-import resolver + 5 self-tests — drift would be caught at test time).

### Quota-at-submit-time contract upheld (deferred to Sprint 13.5 binding)

Per ADR-022 §"Quota integration — at submit, not post-hoc", quotas become a first-class scheduling input. Sprint 10.5 ships the **seam contract** that makes this possible; Sprint 13.5 will:

1. Implement `core/emergency/quotas.QuotaEngine.would_admit(*, task_id, tenant_id, pack_id, estimated_tokens)` returning a `bool`, reading from the gateway-call ledger (per ADR-007) for accumulated usage + atomically reserving `estimated_tokens` keyed by `task_id` on `True` return.
2. Implement `core/emergency/quotas.QuotaEngine.release_reservation(task_id)` (idempotent) wired to fire on every terminal-state transition from the Sprint 10.5 `SchedulerEngine`.
3. Wire the engine into the AgentOS DI binder via the `QuotaInterrogator` seam slot.
4. Land the `quota.refused_at_queue` chain event family (currently routes through the existing `scheduler.admission_refused` family with `payload.reason="refused_quota_exhausted"`).
5. Wire the kill-switch parallel: `KillSwitchEngine.is_active(*, tenant_id, pack_id)` over the Redis-as-control-plane substrate per this ADR's §"Propagation guarantees".

**No ADR-018 schedule change** — Sprint 13.5 still ships the full kill-switch + quota engine per the existing implementation phases table. Sprint 10.5's amendment is purely about the cross-sprint seam contract.

## References
- ADR-005 (sub-agent depth caps — emergency-controls layer enforces these as quotas)
- ADR-007 (gateway-call ledger — quota accounting source)
- ADR-009 (Redis bundled — control-plane substrate)
- ADR-012 (pack revocation — durable counterpart)
- ADR-014 (runtime approval — different layer; emergency stops what was approved)
- ADR-015 (Rego policy — quota declarations)
- ADR-022 (runtime scheduler — Sprint 10.5 wired `QuotaInterrogator` + `KillSwitchInterrogator` seam Protocols; substantive enforcement WAITS for Sprint 13.5)
- [Anthropic — Managed Agents incident response patterns](https://www.anthropic.com/engineering/managed-agents)
