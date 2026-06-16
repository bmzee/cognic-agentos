# ADR-022 — Runtime Scheduler / Work Queue

## Status
**APPROVED for implementation** — DRAFT 2026-05-16 → APPROVED 2026-05-27. Scheduler-relevant portions implemented in **Sprint 10.5 (10.5a + 10.5b)**, merged to `main` via PR #40 (squash commit `6791eec`). The credential-projection sub-arc originally bundled as 10.5c was split to **Sprint 10.6** at the Z1b VALVE CHECK; see the §"Sprint 10.5 implementation closeout (2026-05-27)" addendum at the foot of this ADR.

## Context

The AgentOS roadmap covers governance, audit, identity, observability, policy, sandbox, memory, and emergency controls — but no first-class runtime resource-control primitive. The pieces that touch scheduling-adjacent concerns (shipped today through Sprint 7B.4, plus those planned for Sprints 8 → 13.5) are scattered and operate **post-hoc**:

- `core/sla.py` (Sprint 2.5) is pure timer math — `classify(now, deadline) -> status`; it never gates, queues, or refuses an invocation.
- `core/emergency/quotas.py` (Sprint 13.5) accumulates token / spend / invocation counts from the gateway-call ledger and refuses the **next** call when limits hit. It cannot refuse a 10-minute background eval-run from saturating an interactive customer-facing call.
- `subagent/policy.py` (Sprint 11) declares "depth, budget, tool-allow-list narrowing" as static config without a runtime substrate that enforces fair budget arithmetic across concurrent children.
- `protocol/mcp_host.py` (Sprint 5) and `protocol/a2a_endpoint.py` (Sprint 6) dispatch calls synchronously; there is no bounded queue or backpressure response when tools / models / sandboxes are saturated.
- `core/approval/engine.py` (Sprint 13.5) gates high-risk tool calls but does not differentiate live-chat from background work; a queued approval blocks both equally.

The result is a system that has all the governance an examiner needs but cannot honestly call itself an **operating system** — an OS without a scheduler is not an OS. Without this primitive, saturation produces arbitrary cascading failure modes:

- A scheduled overnight eval-run can starve interactive customer-facing calls because both share the same unbounded async dispatch.
- A misbehaving pack consuming its full token quota does not just refuse — it consumes all the in-flight semaphores too, blocking unrelated tenants until cleanup.
- Sub-agent spawning cannot enforce a parent's budget narrowing at the child's first `tool_call`; the budget exists only as a static dataclass field that nobody reads at the right moment.
- Banks cannot distinguish "live customer is waiting" from "batch maintenance is running" at the entry point — every call competes with every other call.

Adding a scheduler later is expensive: every entry point would need to be re-routed, every quota check re-located, every sub-agent budget re-plumbed. **The Sprint 11 sub-agent primitive specifically needs the scheduler underneath it** — child-task budget inheritance is a scheduling operation, not a configuration field.

## Decision

Ship `core/scheduler/` as a first-class OS primitive. **Sprint 10.5**, between Vault credential leasing (Sprint 10) and Sub-agent (Sprint 11). Critical-controls from day 1.

### Module layout

```
core/scheduler/__init__.py          # public re-exports
core/scheduler/engine.py            # SchedulerEngine.submit() / cancel() / observe()
core/scheduler/queue.py             # bounded FIFO-per-(tenant, class) + concurrency caps
core/scheduler/policy.py            # admission policy interface; delegates to scheduler.rego
core/scheduler/storage.py           # Postgres-backed task lifecycle via RelationalAdapter
policies/_default/scheduler.rego    # admission policy bundle (new stop-rule)
```

Matches the `core/memory/` / `core/emergency/` / `core/approval/` subpackage pattern. No top-level `scheduler/` — keeping it under `core/` signals that this is a kernel primitive, not a peer subsystem.

### Wave-1 priority model

**Two classes only. FIFO within each class. No weighted fair-share.**

| Class | Use case | Admission-decision SLA | Default queue depth |
|---|---|---|---|
| `interactive` | Live UI session, customer-facing portal call, real-time agent chat | ≤200ms P95 | 32 per (tenant, class) |
| `background` | Eval runs, batch maintenance, scheduled jobs, regulator-erasure sweeper | ≤5s P95 | 256 per (tenant, class) |

Class is declared at `scheduler.submit(task, *, class_)` time and cannot change after admission. The two-class wave-1 model is deliberately narrow — Wave 2 (deferred) adds weighted fair-share, multi-level feedback queues, and arbitrary-N operator-defined classes. **Picking two classes lets the doctrine ship in 3 weeks instead of 12.**

### Admission outcomes — closed enum (wire-protocol contract)

`SchedulerEngine.submit()` returns a `SchedulerAdmissionOutcome` value carrying one of seven closed-enum outcomes. This vocabulary IS the wire-protocol contract for every caller dispatching on submit result. Drift between the Literal and consumer error-handling is caught at module load by a partition-invariant test.

| Outcome (wire-public Literal value) | Meaning | HTTP analog (when surfaced via portal) |
|---|---|---|
| `accepted_immediate` | Concurrency cap had headroom; task moved straight to `running` | 202 Accepted |
| `accepted_queued` | Queue had capacity; task is `pending` | 202 Accepted (+ `task_id`) |
| `refused_queue_full` | Bounded queue full for (tenant, class); response carries `retry_after_s` derived from oldest queued task's age + class-specific SLA | 429 Too Many Requests |
| `refused_quota_exhausted` | `core/emergency/quotas.py` refused at submit time | 429 + `quota_class` |
| `refused_policy_denied` | `scheduler.rego` returned `allow=false`; carries `policy_reason` field | 403 |
| `refused_kill_switch_active` | `core/emergency/kill_switches.py` flipped for the relevant scope (pack / tenant / cloud / feature) | 503 |
| `refused_pack_not_installed` | Pack lifecycle state ≠ `installed` at admission | 409 |

> **Vocabulary note (Sprint 10.5 closeout — see addendum §1):** the DRAFT version of this table proposed the prefixed shape `scheduler_admission_<state>_<reason>` (e.g. `scheduler_admission_refused_queue_full`). During Sprint 10.5 implementation the vocabulary was tightened to the **unprefixed** shape shown above because the Literal type name (`SchedulerAdmissionOutcome`) already carries the `scheduler_admission` context — repeating it inside each value was redundant. The wire-public values landed in `core/scheduler/_types.py:21-31` are the unprefixed forms; this table now reflects the as-built contract.

**Backpressure semantics (user-locked Wave-1):**

1. If queue has capacity and concurrency cap has headroom → `accepted_immediate` (run now).
2. If queue has capacity but concurrency cap is saturated → `accepted_queued` (FIFO wait; **do NOT refuse**).
3. If queue is full for (tenant, class) → `refused_queue_full` with `retry_after_s`.
4. If quota / policy / kill-switch / pack-state denies → refuse immediately with the matching closed-enum reason; audit-emit `scheduler.admission_refused` carrying the reason.

The five refusal outcomes share a single `scheduler.admission_refused` audit event family; `payload.reason` discriminates. The two acceptance outcomes share `scheduler.admission_accepted`; `payload.outcome` discriminates immediate vs queued. **Seven closed-enum values across two event families** — small enough that examiners can hold the matrix in their head.

### Task lifecycle state machine

```
                  ┌────────────────┐
       submit()──▶│    pending     │
                  └────────┬───────┘
                           │ (capacity opens)
                           ▼
                  ┌────────────────┐  cancel() → ┌────────────┐
                  │    running     │────────────▶│ cancelled  │
                  └─┬────────────┬─┘             └────────────┘
                    │            │ (preempted by quota
        completion  │            │  exhaustion of in-flight
                    ▼            │  token budget — Wave-1
              ┌──────────┐       │  only trigger)
              │completed │       ▼
              └──────────┘  ┌────────────┐
                            │ preempted  │
                            └────────────┘

  pending also exits to:  ┌──────────┐    (queue TTL exceeded
                          │ expired  │     without ever running)
                          └──────────┘
```

7 lifecycle states. Each transition emits a chain-linked audit event under the `scheduler.task_*` namespace (`task_started` / `task_completed` / `task_failed` / `task_cancelled` / `task_preempted` / `task_expired`).

**Preemption is Wave-1-narrow.** Only one trigger: the executing task exhausts its in-flight token budget mid-execution. Wave-2 adds priority-inversion preemption + operator-initiated preemption + quota-revocation preemption.

### Concurrency caps

Three cap surfaces, all configurable per tenant + per scope. The numbers below are **Settings defaults shipped for a sane bootable kernel**, NOT wire-protocol contract — tenants tune them via `core/config.py`. Pinning regressions enforce that the *bounded* invariant holds (caps cannot be unbounded / negative / unset), NOT that the specific defaults survive forever.

| Cap | Default (Settings) | Configured at |
|---|---|---|
| Per-tenant total concurrent tasks | 32 (interactive) + 64 (background) | `core/config.py` |
| Per-pack concurrent invocations within a tenant | 8 | Pack manifest (Sprint 7B.x extension) |
| Per-actor concurrent submissions | 4 | RBAC binding (Sprint 7B.2 extension) |

A cap that would be exceeded routes to the FIFO queue (not refusal). A FULL queue THEN routes to `refused_queue_full`. **Concurrency caps and queue capacity are orthogonal** — saturating the first enqueues, saturating both refuses.

### Cooperative cancellation

`SchedulerEngine.cancel(task_id, *, actor)` is the public cancel seam. The running task receives an `asyncio.CancelledError` at the next cooperative await point; the scheduler **does not** kill blocking-IO sections mid-syscall — no Python-thread force-kill, no SIGKILL injection, no thread-pool eviction. The cancellation contract is documented at the harness boundary: pack authors must await at scheduler-aware points (LLM gateway, MCP tool calls, A2A inter-agent calls — all already await-points today).

**Wave-1 escape hatch — boundary-level kill for tasks owning an external sandbox/process.** If a task holds a `SandboxSession` (Sprint 8) or a long-running external process via the resumable-session API (Sprint 8.5), the scheduler MAY request `sandbox.destroy(session_id)` or `session.suspend()` as a boundary-level kill. The Python coroutine still terminates via `asyncio.CancelledError` at its next await — the boundary-level call just ensures the underlying compute is released without waiting for cooperative cooperation from inside the sandbox. This is the only mid-task forced-termination path in Wave-1; everything else is cooperative.

`scheduler.task_cancelled` carries `payload.actor_subject` + `payload.reason` (closed-enum: `actor_cancelled`, `parent_run_cancelled`, `tenant_admin_cancelled`, `quota_exhausted_in_flight`, `sandbox_boundary_killed`).

### Quota integration — at submit, not post-hoc

This is the substantive ADR-018 amendment. Today (pre-10.5): `core/emergency/quotas.py` checks during the gateway call — the LLM has already been billed by the time the quota check fires. Post-10.5: `SchedulerEngine.submit()` consults `quotas.would_admit(tenant, pack, estimated_tokens)` BEFORE enqueueing. Refusal happens at the queue boundary, not at the LLM. Quotas become a first-class scheduling input.

The estimate-vs-actual gap is closed by the existing post-execution reconciliation in `gateway.py`: scheduler reserves an estimate at submit, the gateway records the actual at completion, and the next submit decision uses the reconciled total. Over-reservation never wedges the queue because reservations are released on every terminal state (`completed`, `failed`, `cancelled`, `preempted`, `expired`).

### Policy integration — `scheduler.rego` bundle

New default-ship bundle at `policies/_default/scheduler.rego`. Decision point: `data.cognic.scheduler.admit.allow`. Inputs include `tenant_id`, `pack_id`, `actor_subject`, `class` (interactive/background), `pack_kind`, `pack_risk_tier`, `current_tenant_concurrent_count`, `requested_estimated_tokens`. Default `allow := false` — admission requires explicit allow.

The Wave-1 default bundle allows everything tier-`read_only` + tier-`internal_write` without further gating, requires `interactive` class for tier-`customer_data_read`, and refuses tier-`payment_action` from `background` class. Bank overlays can tighten but not loosen the defaults — the policy bundle joins the wire-protocol-public stop rule list (mirrors `elicitation.rego` / `sampling.rego` / `supply_chain.rego`).

### Audit event taxonomy

| Event | When emitted | ISO 42001 tag |
|---|---|---|
| `scheduler.admission_accepted` | Task admitted (immediate or queued) | `A.6.2.5` |
| `scheduler.admission_refused` | Submit denied; `payload.reason` is the closed-enum | `A.6.2.5` |
| `scheduler.task_started` | `pending` → `running` | `A.6.2.5` |
| `scheduler.task_completed` | `running` → `completed` | `A.6.2.5` |
| `scheduler.task_failed` | `running` → `failed` | `A.6.2.5` |
| `scheduler.task_cancelled` | `running` → `cancelled` | `A.6.2.5` |
| `scheduler.task_preempted` | `running` → `preempted` | `A.6.2.5` |
| `scheduler.task_expired` | `pending` → `expired` (queue TTL exceeded) | `A.6.2.5` |

All events hash-chain into `decision_history`. The `task_id` field is the chain-derived identity that lets the Sprint 9 trace explorer walk the full lifecycle of a single agent invocation across queue → run → completion.

### Sub-agent budget inheritance — the Sprint 11 hook

`SchedulerEngine.submit(submit_input, *, request_id)` accepts a `SubmitInput` frozen dataclass whose `parent_task_id: str | None` field carries the parent task identifier (per `core/scheduler/_types.py:94`). When a sub-agent invokes `tool_call`, the harness constructs a `SubmitInput(..., parent_task_id=<parent>)` and the parent's remaining token budget is snapshotted at child-submit time via the `ParentBudgetResolver` seam; the child's quota reservation is narrowed accordingly. The child cannot exceed `min(child_pack_quota, parent_remaining_budget)`. Parent completion releases the child's residual budget back to the parent's pool.

This is the substantive ADR-005 amendment — sub-agent "budget narrowing" becomes a scheduler operation instead of a static config field that nobody enforces.

### Critical-controls scope

Per AGENTS.md "Critical-controls rule" + "Stop rules":

**Durable coverage gate (Python modules; ≥95% line / ≥90% branch; halt-before-commit per edit):**

- `core/scheduler/engine.py` — public seam orchestrating queue + policy + quotas + audit emission
- `core/scheduler/queue.py` — bounded queue + admission control + concurrency caps
- `core/scheduler/policy.py` — admission-policy interface to the Rego bundle (load-bearing glue; drift between the Python interface and the Rego decision matrix is the most likely future regression class — gate it from day 1)
- `core/scheduler/storage.py` — chain-linked task lifecycle; mirrors `packs/storage.py` precondition-closure pattern

**Stop-rule policy bundle (tracked separately from the Python coverage gate):**

- `policies/_default/scheduler.rego` — wire-protocol-public admission bundle at `data.cognic.scheduler.admit.allow`. Bank overlays **may tighten** the kernel's default-deny posture (add allow-list narrowing, lower per-tenant caps, refuse additional class/tier combinations); **loosening the kernel defaults requires an explicit kernel + ADR amendment** (mirrors the `elicitation.rego` precedent at AGENTS.md "Stop rules").

Four Python modules on the durable coverage gate (63 → 67) + one new AGENTS.md stop-rule entry for the Rego bundle. The coverage gate tracks Python modules; Rego bundles are governed by the stop-rule list, not the coverage tool.

### What this is NOT

- **Not a fair-share or weighted scheduler.** Wave-1 is strict FIFO within class. Wave-2 (deferred) adds weighted fair-share, multi-level feedback queues, arbitrary-N classes.
- **Not a task pool that pre-warms workers.** Tasks execute in the existing asyncio event loop; the scheduler decides when, not how.
- **Not a cross-process work queue.** Single-AgentOS-instance only. Multi-instance fan-out is a separate Wave-2 concern (would require Redis as the shared queue substrate; today's plan is Postgres for durability + in-process semaphores for concurrency caps).
- **Not a replacement for `core/sla.py`.** SLA stays pure timer math; scheduler uses it but does not own it.
- **Not a tool/model router.** Routing decisions still happen in the gateway. Scheduler decides whether to admit; gateway decides where to route once admitted.
- **Not coupled to UI event-stream emission.** The scheduler emits audit events; the UI event broker (Sprint 7B.4) mirrors them onto its typed streams via the existing decision_history → broker projection — no new emission seam.

## Consequences

### Positive
- AgentOS earns the "operating system" claim — there is now a single point where every invocation passes through resource control.
- Saturation produces a closed-enum refusal (`refused_queue_full` with `retry_after_s`) instead of arbitrary cascading failure.
- Live customer-facing calls never starve behind background eval runs.
- Sub-agent budget narrowing becomes a runtime-enforced operation, not a static config field.
- Quota refusal moves from post-LLM-bill to pre-LLM-bill — saves money, surfaces the deny earlier.
- Trace explorer (Sprint 9) gets a clean chain to walk: `submit → admission_accepted → task_started → … → task_completed`.

### Negative
- Every entry point that today calls `mcp_host.call_tool(...)` or `gateway.complete(...)` directly must be re-routed through `scheduler.submit(...)`. ~30 call sites in the codebase post-7B; ~10 in pack-author-visible SDK surface.
- Wave-1's 2-class FIFO will eventually feel constraining; banks will ask for weighted fair-share. Wave-2 must be in the roadmap from day 1 (called out in this ADR's "Implementation phases" + the BUILD_PLAN.md §1142 schedule-risk table).
- Adds 200-500ms tail latency to interactive calls during periods of high background work (FIFO wait when concurrency cap saturates). Mitigated by per-class concurrency caps but not eliminated.
- `core/emergency/quotas.py` integration requires a co-ordinated Sprint 13.5 amendment — quotas become scheduler-evaluable, which changes their API surface.

### Neutral
- The scheduler is in-process for Wave-1. Multi-instance AgentOS deployments share a Postgres-backed task store for durability but enforce concurrency caps per-instance; cross-instance work-stealing is Wave-2.
- The `interactive` vs `background` class is declared by the caller; misuse (calling a 30-minute eval as `interactive`) is a pack-author bug detected by SLA breach events, not a scheduler-level refusal.

## Implementation phases

**Wave 1 (Sprint 10.5):** the surface this ADR specifies. 2-class FIFO, per-tenant + per-pack + per-actor concurrency caps, bounded queues with closed-enum backpressure, cooperative cancellation, quota-exhaustion preemption, `scheduler.rego` default bundle, full audit-event taxonomy, sub-agent budget inheritance hook, Postgres-backed durable task store. 3 wu floor / 4.5 wu ceiling (see BUILD_PLAN.md §1142).

**Wave 2 (deferred; post-Phase-4):** weighted fair-share across tenants, multi-level feedback queues, arbitrary-N operator-defined priority classes, cross-instance work-stealing (Redis-backed shared queue), priority-inversion detection + escalation, operator-initiated preemption, auto-class-promotion on user-attention signal. Sized at ~3 wu when scoped.

**Cross-ADR amendments triggered by this approval:**

- ADR-005 (sub-agent primitive): budget narrowing becomes a scheduler operation; replace the static `policy.budget` field semantics with `SubmitInput(..., parent_task_id=...)` passed to `SchedulerEngine.submit(submit_input, request_id=...)` arithmetic.
- ADR-014 (runtime tool approval): approval gate continues to fire before `scheduler.submit()` — high-risk-tier tools that require approval go through `approval.engine.wait_for_grant()` first, then `scheduler.submit()`. No semantic change; documented sequencing.
- ADR-018 (emergency controls): quota check moves from gateway-call-time to scheduler-submit-time. Kill switches gain a `scheduler.admit_refusal` integration point so a flipped switch immediately drains the queue.
- ADR-020 (UI event-stream contract): Wave-1 does NOT add a new typed event family. Scheduler audit + decision-history rows surface through the existing `decision_audit.event_appended` mirror (already wired in Sprint 6 via the decision_history → broker projection), keeping the Sprint 7B.4 11-family Wave-1 taxonomy stable. A first-class typed `scheduler.*` UI-event family — with per-event-type Pydantic models for `admission_accepted` / `admission_refused` / `task_started` / `task_completed` / `task_failed` / `task_cancelled` / `task_preempted` / `task_expired` — is a Wave-2 concern and will land as a future ADR-020 amendment.

## Sprint 10.5 implementation closeout (2026-05-27)

Sprint 10.5 (10.5a + 10.5b) merged to `main` as squash `6791eec` via PR #40 on 2026-05-27. The full Wave-1 admission + lifecycle + audit surface this ADR specifies is **landed and on the durable critical-controls coverage gate**. Implementation deviates from the original ADR in three substantive places:

### 1. Closed-enum vocabularies + module set (with as-built deviations from §"Module layout" + §"Admission outcomes")

**Wire-protocol-public Literals (10 total — the 5 most-load-bearing for wire contract are below; the 5 remaining values are listed in the next paragraph):**

| Literal | Values | Source |
|---|---|---|
| `SchedulerAdmissionOutcome` | 7 (2 accepted + 5 refused) | `core/scheduler/_types.py:21` |
| `SchedulerRefusalReason` | 5 (refusal subset; `payload.reason` discriminator) | `core/scheduler/_types.py:33` |
| `SchedulerTaskState` | 7 (`pending` / `running` / `completed` / `failed` / `cancelled` / `preempted` / `expired`) | `core/scheduler/_types.py:41` |
| `SchedulerPromotionRefusedReason` | 2 (`caps_saturated` / `not_at_queue_head`) | `core/scheduler/engine.py:125` |
| `SchedulerSubmitInputInvalidField` | 1 (`parent_task_id` — malformed-UUID typed-exception field) | `core/scheduler/engine.py:133` |

**Remaining 5 Literals in `_types.py`** (lower-traffic but still wire-public): `SchedulerPriorityClass` 2-value (`interactive` / `background`) at `:51`; `SchedulerTaskCancelledReason` 4-value at `:53` (the ADR-022 §"Cooperative cancellation" 5th value `quota_exhausted_in_flight` was deliberately split into the separate 1-value `SchedulerTaskPreemptedReason` Literal at `:60` because mid-flight quota exhaustion is semantically a preemption, not a cancellation — `running → preempted` not `running → cancelled` in the state machine); `SchedulerTaskFailedReason` 2-value at `:62`; `ActorType` 2-value at `:67`.

**Vocabulary deviation — unprefixed values landed instead of prefixed:** the DRAFT version of the §"Admission outcomes" table above proposed `scheduler_admission_<state>_<reason>` (e.g. `scheduler_admission_refused_queue_full`). The as-built `SchedulerAdmissionOutcome` Literal at `_types.py:21-31` uses the **unprefixed** shape (`refused_queue_full`, etc.) because the Literal type name (`SchedulerAdmissionOutcome`) already carries the `scheduler_admission` context — repeating it inside each value was redundant. The original table was patched at this closeout to reflect the as-built shape, and the vocabulary-note callout immediately under the table flags the deviation for examiners reading the audit-event payloads.

Module layout matches §"Module layout" — `core/scheduler/{engine,queue,storage,policy}.py` + `policies/_default/scheduler.rego` + `core/scheduler/_seams.py` (consumer-owned Protocol seams + fail-loud sentinels — see §3 below).

### 2. Option A doctrine LOCKED — SchedulerPolicy owns Rego ONLY (plan §1210 literal-dual-consultation interpretation superseded)

ADR-022's "Quota integration — at submit, not post-hoc" + "Policy integration — `scheduler.rego` bundle" sections, read literally, suggested `SchedulerPolicy` could be the single dispatch point that consults BOTH Rego AND `core/emergency/*` (quota + kill_switch). At T9 this was rejected because it conflated **ADR-018 (emergency controls — operational real-time emergency surface)** with **ADR-015 (policy-as-code — declarative bundle decision)**. Kill-switch is an operational gate, not a policy decision.

**Locked ownership boundary:**
- `SchedulerPolicy` owns **Rego policy ONLY** — wraps the `OPAEngine` at the `data.cognic.scheduler.admit.allow` decision point + maps the bundle's 3-value closed-enum `refusal_reason` document onto the wire-public `SchedulerAdmissionOutcome.refused_policy_denied` outcome. Plan §1179 suppression contract: on `allow=true`, `policy_reason` is suppressed to `None` (propagating the bundle's `scheduler_default_deny` document on a green admission row would be audit-misleading). Plan §1181 fail-closed envelope: any OPAEngine error → `PolicyDecision(allow=False, policy_reason="opa_unavailable")`.
- `SchedulerEngine` owns the **operational gates** (pack_state → kill_switch → policy → quota → caps/queue ordering); the wire-public 5-value `SchedulerAdmissionOutcome` taxonomy is dispatched here, NOT in `SchedulerPolicy`.

This makes the policy-vs-operational split explicit at the module boundary. AST guard `tests/unit/core/scheduler/test_architecture_no_emergency_import.py` pins that `core/scheduler/*` modules do NOT import from `cognic_agentos.core.emergency.*`; binding happens at AgentOS app startup via the consumer-owned seam Protocols.

### 3. Substrate-independence seams via consumer-owned Protocols (per `[[feedback_consumer_owned_protocol_for_unlanded_dep]]`)

The ADR §"Quota integration" + §"Sub-agent budget inheritance" sections describe `quotas.would_admit(...)` + `parent_remaining_budget` calls as if those downstream modules already existed. They don't — quota implementations land in Sprint 13.5 + sub-agent in Sprint 11. Sprint 10.5 declares the dependency contracts as **consumer-owned Protocols** in `core/scheduler/_seams.py`:

| Protocol | Owner sprint (real conformer) | Wave-1 default |
|---|---|---|
| `QuotaInterrogator` | Sprint 13.5 | `_NullQuotaInterrogator` raises `NotImplementedError` pointing at ADR-018 |
| `KillSwitchInterrogator` | Sprint 13.5 | `_NullKillSwitchInterrogator` raises `NotImplementedError` pointing at ADR-018 |
| `ParentBudgetResolver` | Sprint 11 | `_NullParentBudgetResolver` raises `NotImplementedError` pointing at ADR-005 |
| `PackStateInterrogator` | Sprint 13.5 (or earlier — Sprint 7B.x lifecycle integration) | `_NullPackStateInterrogator` raises `NotImplementedError` pointing at ADR-012 |
| `SandboxAdapter` | Sprint 11+ (DI binder at startup wraps `sandbox.SandboxBackend`) | Optional kwarg; `mark_running` accepts `sandbox_adapter=None` |

Fail-loud sentinels — NOT silent no-ops — preserve the AGENTS.md production-grade rule: an unbound consumer raises `NotImplementedError` referencing the relevant ADR.

### 4. T11 SandboxAdapter — atomic create+destroy boundary (substrate independence)

Scheduler → sandbox integration uses an **injected `SandboxAdapter` Protocol with an atomic create+destroy pair** declared in `core/scheduler/_seams.py`. Scheduler NEVER imports from `cognic_agentos.sandbox/*`. The atomic create+destroy API makes the "create without destroy → leak on storage-failure-after-create" bug class **unrepresentable at the type level** — replaced an earlier two-callable signature where the two methods could be passed independently.

Upstream `SandboxLifecycleRefused` exceptions translate to scheduler-owned `SandboxCreateRefused` at the binder boundary; the AgentOS app's DI binder wraps the real `sandbox.SandboxBackend` into a structurally-conforming adapter. AST guard `tests/unit/core/scheduler/test_architecture_no_sandbox_import.py` pins the import boundary.

### 5. Sprint 10.5c (workload credential projection) split to Sprint 10.6

The Sprint 10.1 hotfix deferred-Finding-#1 work (the "minted leases on `session.active_leases` never reach the workload" gap) was originally bundled as 10.5c — a 4th block on top of 10.5a (foundation) + 10.5b (policy + integration seams). At the **Z1b VALVE CHECK** the cumulative wall-clock across T1-T11 + Z1a + Z1b crossed the 4.5 wu mitigation budget threshold per BUILD_PLAN.md §1272 ("Realistic range: 3-4.5 wu"; mitigation: split if it overruns Day 3). User decision: split 10.5c **as a whole** (never partial; no Docker-only-with-K8s-later asymmetry) into a new Sprint 10.6 with its own spec + plan-of-record. ADR-004 §25 + ADR-017 amendments triggered by credential-projection live in Sprint 10.6's closeout, NOT this ADR.

Sprint 10.6's pre-execution gate: branch-cut from `main` post-this-closeout. Spec: `docs/superpowers/specs/2026-05-26-sprint-10.6-workload-credential-projection-design.md`. Plan: `docs/superpowers/plans/2026-05-26-sprint-10.6-workload-credential-projection.md`.

### 6. Critical-controls coverage gate growth (§"Critical-controls scope" amended)

The original §"Critical-controls scope" projected "Four Python modules on the durable coverage gate (63 → 67)". The actual base at the time Sprint 10.5 landed was 85 (Sprint 10 had grown the gate to 85 between this ADR's authoring and 10.5 landing). Actual growth: **85 → 89 (+4 modules at 95/90 floor on fresh `--cov-branch` data):** `core/scheduler/engine.py` + `core/scheduler/queue.py` + `core/scheduler/storage.py` + `core/scheduler/policy.py`. `policies/_default/scheduler.rego` joins the stop-rule policy bundle list (tracked separately from Python coverage gate). All 4 modules at or above floor on the promotion commits per `[[feedback_verify_promotion_meets_floor_at_promotion_time]]`: Z1a promoted engine + queue + storage (88/88 PASS); Z1b promoted policy (89/89 PASS); 89/89 PASS at the merge commit.

### 7. Audit-event taxonomy unchanged from §"Audit event taxonomy"

The 8-event `scheduler.*` taxonomy in §"Audit event taxonomy" (admission_accepted / admission_refused / task_started / task_completed / task_failed / task_cancelled / task_preempted / task_expired) ships as specified — all 8 events emitted via `core/scheduler/storage.py`'s `DecisionHistoryStore.append_with_precondition` consumer (Doctrine Lock D mirror; `_LockedTaskSnapshot` 11-field evidence-snapshot threading per the chain-payload-is-evidence-snapshot doctrine). All events tagged with ISO 42001 `A.6.2.5` as specified.

### 8. Cross-ADR amendments triggered by this approval

Each cross-ADR amendment listed in §"Implementation phases / Cross-ADR amendments" landed as a Sprint 10.5 closeout amendment in the target ADR file:
- **ADR-005**: `ParentBudgetResolver` seam Protocol + T10 `effective_submit_input` narrowing
- **ADR-014**: high-risk-tier refusal pre-13.5 mirrored in `scheduler.rego` (defense-in-depth twin to `sandbox.rego`)
- **ADR-018**: seam Protocols only (`QuotaInterrogator` + `KillSwitchInterrogator`); substantive enforcement WAITS for Sprint 13.5
- **ADR-020**: Wave-1 contract upheld — NO new typed UI event family for scheduler

## Sprint 13.5c2 amendment (2026-06-12) — approval seam cutover (`SchedulerEngine.submit` Step 3.5 + `scheduler.rego` CONVERT)

Sprint 13.5c2 makes `SchedulerEngine.submit` the THIRD approval-engine consumer seam (after the 13.5b2 MCP host and the 13.5c1 sandbox admission) and ships the scheduler half of the coordinated Rego CONVERT. Scope honesty: seam-only — NOTHING constructs `SchedulerEngine` / `SchedulerPolicy` in production today (no `harness/` or `portal/api/app.py` reference); the composition-root sprint wires `runtime.approval_engine` (13.5b1) into a constructed scheduler.

1. **Seam contract.** `SchedulerEngine.__init__` gains `approval_engine: ApprovalEngine | None = None` (`engine.py:297`) — a DIRECT `core.approval` dependency, NOT a consumer-owned `_seams.py` Protocol (the dependency landed at 13.5a, so the consumer-owned-Protocol doctrine does not apply). `SubmitInput` gains 3 defaulted fields (`_types.py:112-114`): `approval_request_id` (caller re-submit carrier; parsed UNCONDITIONALLY at the engine boundary via the `parent_task_id` mirror — malformed → typed `SchedulerSubmitInputInvalid(field="approval_request_id")`, `SchedulerSubmitInputInvalidField` 1→2; a VALID id while unwired is INERT), `approval_verified` (ENGINE-OWNED — the engine unconditionally overwrites it via `dataclasses.replace` on every path, `engine.py:508`; caller-supplied `True` is anti-forgery-pinned), and `data_classes` (manifest-derived, envelope-first-class). Step order (`engine.py:478`): parent-budget → pack-state → kill-switch → **Step 3.5 approval consult** → policy → quota → caps/queue; pack-not-installed + kill-switch BEAT approval (zero approval rows; pinned), approval BEATS policy + quota. `SchedulerAdmissionOutcome` 7→12 / `SchedulerRefusalReason` 5→10 (+5 `refused_approval_{pending,denied,expired,binding_mismatch,request_not_found}`); `AdmissionDecision.approval_request_id` (`_types.py:125`) is set ONLY on the pending refusal. Binding (`_consult_approval`, `engine.py:618`): `tool_identity = "scheduler:"+sha256(canonical_bytes({pack_id, pack_kind}))` (`engine.py:231`; name-based — no artifact digest exists at this seam; the artifact-bound identity fires downstream at the 13.5c1 sandbox seam) + an ACTOR-BOUND 6-key `args_digest` (`engine.py:242`: class / pack_risk_tier / requested_estimated_tokens / parent_task_id / actor_subject / actor_type — an actor swap between grant and re-submit MUST mismatch) computed over the ORIGINAL (pre-parent-narrowing) `SubmitInput` so a parent-budget shift between grant and re-submit cannot spuriously mismatch. A grant authorises exactly one submission **shape** (single-use `consume` stays deferred OUT of the c-series; Sprint-14+). For `regulator_communication` the envelope's `required_refs = {"audit_record_ref": <submit request_id>}` — the param every admission chain row is keyed by (nothing minted). `ApprovalEnvelopeInvalid` and any non-binding-mismatch `ApprovalTransitionRefused` from verify propagate RAW (fail-loud, no evidence row).
2. **Supersession.** The §"Cross-ADR amendments" sentence above — "high-risk-tier tools that require approval go through `approval.engine.wait_for_grant()` first, then `scheduler.submit()`" (line 215) — is EXPLICITLY SUPERSEDED. There is no `wait_for_grant` (the blocking shape was rejected at the ADR-014 13.5a amendment); the as-built contract is non-blocking pending → portal-grant → re-submit through the in-engine Step-3.5 consult, with the harness re-submitting on `refused_approval_pending`'s `approval_request_id`.
3. **`scheduler.rego` CONVERT.** The bundle's allow rule gains a second arm — high tier + strict `input.approval_verified == true` (`scheduler.rego:124`; falsy-by-absence fail-closed); the refusal chain's high-risk arm fires ONLY unverified (`:101`). The 3-value refusal vocabulary is UNCHANGED — `scheduler_high_risk_tier_refused_pre_13_5` is KEPT as the engine-absent/unverified reason (renaming is a wire break; drift-pinned). `SchedulerPolicy._build_rego_input` grows 8→9 keys (`policy.py:249`). The engine-absent fallback comes FREE from the bundle: the scheduler's pre-13.5 refusal lived ONLY in Rego (no Python static tier set, unlike sandbox Step 4), so unwired deployments keep the refusal byte-for-byte — the pre-existing allow/deny matrix tests pass unchanged. This section + the bundle edit ARE the "coordinated kernel + ADR amendment" the Sprint-10.5 bank-overlay contract requires; live-OPA pinned at `tests/unit/policies/test_scheduler_rego.py::TestSchedulerRegoApprovalConvert` (incl. class-unknown-beats-verified precedence and no-bypass).
4. **Per-decision evidence DELIVERED** (the 13.5c1 contrast — no deferral; the scheduler owns a chain-row path). `scheduler.admission_refused` payloads gain CONDITIONAL `approval_request_id` + `approval_flow` keys (`storage.py:362`; only-when-known, so every non-approval refusal row stays byte-identical to its pre-c2 shape — keyset-pinned). `scheduler.admission_accepted` payloads gain `approval_verified` (ALWAYS present post-c2, `storage.py:272`) + CONDITIONAL `approval_request_id` when a granted re-submit is accepted (`storage.py:275`) — without it the examiner join accepted → `approval.*` is impossible for non-regulator tiers (the `audit_record_ref` back-link exists only for `regulator_communication`). The one-shot "cutover audit event" promise in the pre-c2 bundle comments is superseded in the bundle itself. NO new chain event types; NO `SchedulerTaskState` change; the ADR-020 Wave-2 typed `scheduler.*` UI-event family deferral stands. Cross-surface e2e at `tests/integration/approval/test_scheduler_seam_e2e.py` (pending → 13.5b1 HTTP grant → re-submit admits + attests + joins).

## Sprint 13.7 amendment (2026-06-13) — scheduler production-constructed at the composition root (`build_runtime`)

Sprint 13.7 closes the longest-standing "built but not live" gap for the scheduler: `SchedulerEngine` is now **production-constructed at the composition root** (`harness/runtime.py::build_runtime`). This supersedes the 13.5c2 scope-honesty sentence above ("NOTHING constructs `SchedulerEngine` / `SchedulerPolicy` in production today (no `harness/` or `portal/api/app.py` reference)") — that statement was true through 13.6b and is now retired for the scheduler.

1. **Construction + seam binding.** Inside `build_runtime`'s cache block, every `SchedulerEngine` seam slot is bound/postured: `storage` = `SchedulerStorage(engine)` over the relational engine; `caps` = `ConcurrencyCaps` from the 4 `scheduler_per_*` Settings; `class_settings` = the 2 `scheduler_queue_depth_*` + the 2 NEW `scheduler_class_sla_*` Settings keyed by `interactive`/`background`; `policy_evaluator` = `SchedulerPolicy(opa_engine=...).evaluate` over a dedicated `OPAEngine.create(bundle_path=settings.scheduler_policy_bundle, ...)`; `quota_interrogator` = the SAME `QuotaEngine` instance the gateway uses (13.6b); `kill_switch_interrogator` = `SchedulerKillSwitchConformer(engine=<the runtime KillSwitchEngine>)` (13.6a); `pack_state_interrogator` = `PackStoreStateInterrogator(store=PackRecordStore(engine))` (the real ADR-012 pack-state probe, 11b); `approval_engine` = the unconditionally-built `runtime.approval_engine` (13.5b1) — production-CONSTRUCTING the 13.5c2 scheduler approval seam (bound into the live engine; its Step-3.5 consult stays DORMANT until the 14A submit→execute caller exercises a submit, so memory 13.5c3 remains the only approval seam a live caller exercises today). The `SchedulerKillSwitchConformer` "DI-bound at the composition-root sprint" + the `QuotaInterrogator` "binding rides the composition-root sprint" DI-binding promises (ADR-018 / AGENTS.md) are HONORED here — though, like approval, the scheduler's kill-switch + quota gates only FIRE once a caller submits (their enforcement is bound at 13.7, exercised at 14A).

2. **Parent-budget = `_Null` sentinel (deferred to 14A).** `parent_budget_resolver` is deliberately OMITTED, so the engine binds its own `_NullParentBudgetResolver` fail-loud sentinel per `[[feedback_consumer_owned_protocol_for_unlanded_dep]]`. A top-level submit (no `parent_task_id`) NEVER consults it; a sub-agent submit (`parent_task_id` set) fails loud with `NotImplementedError` (pinned by `tests/integration/scheduler/test_scheduler_composition_e2e.py::test_composition_subagent_submit_fails_loud`). The real `LocalParentBudgetResolver` + a top-level run→budget snapshot land at **Sprint 14A** alongside the managed-runtime submit→execute path.

3. **Cache-conditional posture.** The scheduler is constructed ONLY when a cache adapter is present (its quota + kill-switch conformers need the Redis control plane). On the gateway-only path (`cache_driver="none"`) `Runtime.scheduler is None` — there is NO silent `_Null`-quota scheduler that would fail on first submit. Pinned by `tests/unit/harness/test_runtime.py` (cache-present identity pins + cache-absent `scheduler is None`).

4. **Exposure, no caller (Fork D).** The constructed engine is exposed on `Runtime.scheduler` and threaded onto `app.state.scheduler` via the FastAPI lifespan (introspection seam, mirroring `app.state.kill_switch_engine` / `quota_engine`; pre-seeded `None`). 13.7 adds NO `create_app` kwarg, NO route, and NO production submit→execute caller — the managed-runtime caller is 14A. A live composition e2e drives `runtime.scheduler.submit(...)` directly over the in-memory adapters, proving admit (real OPA `scheduler.rego`) + quota reserve/release + the real pack-state refusal in one pass.

5. **Scope split (Forks B/C).** 13.7 is **scheduler-only**. Production MCP-host construction (registry-walk → `MCPServerEntry` → `app.state.mcp_host`) is relocated to **Sprint 13.8**; sandbox-approval production wiring is folded into **Sprint 14A** (it is blocked on a Runtime-owned sandbox backend, which 14A constructs). No quality/feature cut — each piece moves to the sprint where its prerequisites exist.

6. **New Settings (3).** `scheduler_policy_bundle` (default `policies/_default/scheduler.rego`), `scheduler_class_sla_interactive_s` (default `0.2`, `gt=0`), `scheduler_class_sla_background_s` (default `5.0`, `gt=0`) — the per-class queue SLAs `BoundedQueue.compute_retry_after_s` uses for retry-after aging. No CC promotion: the scheduler stack is already on the gate; `harness/runtime.py` + `core/config.py` + `portal/api/app.py` stay off-gate (count unchanged at 129).

## Sprint 14A-A amendment (2026-06-13) — managed-run executor: the first exercised scheduler caller (`core/run/executor.py`)

Sprint 14A-A lands the first production-grade EXERCISED managed-run path, closing the 13.7 "constructed but no caller" gap for the scheduler's synchronous-run lane. The new `core/run/executor.py` `ManagedRunExecutor` is the caller: `load+validate pack record → submit → mark_running → backend.create → session.exec → destroy → complete`, emitting value-free `run.*` evidence. Promoted to the durable per-file critical-controls gate (count **129 → 130**, 95/90 floor; verify-at-promotion 100%/100% in-commit).

1. **Fork A — the executor owns the sandbox session directly.** It does NOT use the scheduler's `SandboxAdapter.create()` seam (`core/scheduler/_seams.py`), which returns no session handle. `mark_running` is called WITHOUT `sandbox_adapter` (the T11 sandbox-routing seam stays dormant for the synchronous executor); the executor drives the real `SandboxBackend.create/exec/destroy` (ADR-004) itself.

2. **Admission contract (synchronous-executor narrowing).** The 14A-A executor runs the task inline immediately, so it can only execute a task the scheduler admitted IMMEDIATELY: `accepted_immediate` → run. An `accepted_queued` task (caps saturated, enqueued) has no worker to promote it once caps free up; the executor CANCELS it via `scheduler.cancel(..., reason="actor_cancelled")` — `pending → cancelled` removes it from the FIFO queue, releases the quota reservation, and writes the terminal `scheduler.task_cancelled` transition — then surfaces a refusal (`run_admission_queued_unsupported`). It does NOT call `mark_running` on a queued task (which would raise `SchedulerPromotionRefused` on the saturated caps + leak the task + its reservation). `refused_*` outcomes surface verbatim as `run.refused`. A real wait/worker path that runs queued tasks is deferred (14A-A2+).

3. **Failure semantics.** A non-zero workload `exit_code` is a `completed` run (the run ran; the exit code is the result), NOT a scheduler failure. An infra exception fails the scheduler task: `backend.create` raises → `scheduler.fail` with `TaskFailedPayload(reason="scheduler_task_failed_sandbox_create_refused", sandbox_refusal_reason=…)`; `session.exec` raises → `scheduler_task_failed_workload_runtime_error`. `session.destroy()` is `finally`-guarded (best-effort; a teardown failure is logged and never flips the terminal state).

4. **Value-free `run.*` evidence.** The executor emits `run.completed` / `run.failed` / `run.refused` chain rows via `DecisionHistoryStore.append`; the `run.completed` payload carries `task_id` + `exit_code` + SEPARATE `stdout_sha256` + `stderr_sha256` + the byte counts, never the raw stdout/stderr (which return only to the caller's `RunResult`). The UI `decision_audit` mirror surfaces these automatically (no new UI family). ISO-control mapping for `run.*` is deferred (Human-only; `iso_controls=()`).

5. **Layering — `PackRecordLoader` seam + `LoadedPackRecord` projection.** `core/run` cannot import `packs/storage` (the `core → packs` arrow is forbidden — zero such imports in the repo; the scheduler holds it via `PackStateInterrogator`). The executor owns a `PackRecordLoader` Protocol returning a core-owned `LoadedPackRecord` projection; the conformer `harness.sandbox.PackRecordStoreLoader` (off-gate) does the direct UUID-keyed `PackRecordStore.load(pack_uuid)` + four fail-closed pre-submit checks (exist / tenant / pack_id / `state=="installed"` — executor-side defence in depth). The `Actor` reference is `TYPE_CHECKING`-only (the executor projects the core-owned `TaskActor` for `submit`, passes the full `portal.rbac.Actor` to `backend.create`). AST-fenced at `tests/unit/architecture/test_run_no_sdk_import.py` (no SDK / no runtime portal / no packs import).

6. **Backend construction + wiring — see the ADR-004 Sprint 14A-A amendment.** The DockerSibling backend + the executor are production-constructed in the FastAPI lifespan (SDK-gated on `is_sandbox_available()`, fail-soft) and exposed on `app.state.sandbox_backend` + `app.state.managed_run_executor`. WIRED-DORMANT — no portal route consumes the executor yet. The real `LocalParentBudgetResolver` + a top-level run→budget snapshot (the 13.7 `_Null` deferral) also land at 14A-A2+; 14A-A submits top-level only (no `parent_task_id`).

**Deferred (14A-A2+):** the `POST /api/v1/runs` portal route, backend-level checkpoint→wake, scheduler-driven suspend/resume, sub-agent dispatch, the real parent-budget resolver, multi-backend (K8s), and broad approval/quota/kill-switch exercise. 14A-A proves the executor through its API + the env-gated real-docker e2e (`tests/integration/run/test_managed_run_e2e.py`), not portal reachability.

## Sprint 14A-A2 amendment (2026-06-14) — `POST /api/v1/runs` production caller + executor pending-approval contract

Sprint 14A-A2 lands the `POST /api/v1/runs` portal route — the production caller that LIVE-exercises `ManagedRunExecutor` and, through `scheduler.submit`, the scheduler approval seam (13.5c2). It closes the 14A-A "WIRED-DORMANT" gap for the synchronous-run lane. **No new gate module** (the route + DTO are off-gate; `core/run/executor.py` stays on the gate at 100%/100%); CC count stays **130**.

1. **The route (off-gate).** `portal/api/runs/routes.py::build_run_routes()` is mounted UNCONDITIONALLY at construction (eval-router pattern) under `/api/v1/runs`; the request-time `_require_managed_run_executor` dep returns **503 `sandbox_runtime_unavailable`** when the lifespan did not populate `app.state.managed_run_executor` (SDK absent / `sandbox_runtime_enabled=False` / construction fail-soft). `RequireScope("run.submit")` (the new `RunRBACScope`, on-gate in `portal/rbac/scopes.py` + `actor.py` + `enforcement.py`); NO `RequireHumanActor` (the sandbox approval seam owns the per-tier human checkpoint). `RunSubmitRequest` (frozen, `extra="forbid"`) carries `{pack_id, pack_uuid, pack_version, argv, approval_request_id?}`; `tenant_id` + actor come ONLY from the bound `Actor` (no body fields); `argv` non-empty + bounded. `RunResponse` returns raw stdout/stderr **base64-encoded + byte counts** (bytes are not an accidental wire ambiguity).

2. **Executor pending-approval contract + the F3 status map.** `RunResult.terminal_state` gains `pending_approval` (`RunTerminalState` 3 → 4) + an `approval_request_id: str | None` field. At `backend.create`, the executor catches `SandboxLifecycleRefused` (FUNCTION-LOCAL import — kernel-boot-clean, no module-level sandbox import; pinned by `test_core_run_no_module_level_sandbox_import` + the hvac subprocess probe) and maps per the F3 contract: `sandbox_approval_pending` → cancel the running task + emit value-free `run.pending_approval` + return `pending_approval`/**202**; any OTHER `SandboxLifecycleRefused` (governance/admission refusal) → cancel + `run.refused` + **409**; a generic `create()` exception OR any `exec()` exception → `scheduler.fail` + `run.failed` + **502**. `completed` (incl. non-zero exit) → **200**. Policy/admission refusal is a governance conflict (409), not infrastructure failure (502).

3. **`approval_request_id` threading — see the ADR-004 + ADR-014 Sprint-14A-A2 amendments.** The route threads `body.approval_request_id` → `RunRequest` → `backend.create` → `admit_policy`; this WIRES the 13.5c1 sandbox approval seam for **cold-create only** (the wake path stays deferred).

**Still deferred (14A-A2+):** backend-level checkpoint→wake (+ its approval correlator), scheduler-driven suspend/resume, sub-agent dispatch + the real `LocalParentBudgetResolver` + a top-level run→budget snapshot, multi-backend (K8s production), MCP `call_tool` exercise (a run route alone does not invoke MCP unless the workload calls a tool).

## Sprint 14A-A3a amendment (2026-06-15) — durable run-record substrate (`core/run/storage.py` + `runs` table)

Sprint 14A-A3a is the first slice of the deferred checkpoint→wake / run-persistence arc (split A3a foundation → A3b resolver/resume → A3c wake approval correlator). A3a ships the **durable run-record substrate** a future resume path depends on; success is "a correct substrate proven by tests," NOT "resume works." **Store-only / dormant — it is NOT wired into the executor or the route** (A3b wires it); proven by 14 unit tests + the migration drift suite + an env-gated PG/Oracle row-lock canary.

1. **`RunState` vocabulary (fixed) + transition subset (expand-only doctrine).** The full **9-value** `RunState` Literal is fixed at A3a: `pending` / `running` / `completed` / `failed` / `refused` / `pending_approval` (active) + `suspended` / `woken` / `cancelled` (reserved). `validate_transition` permits only the **6 synchronous pairs** the current run path can prove (`pending→running`, `pending→refused`, `running→{completed,failed,refused,pending_approval}`); the reserved suspend/wake/cancel pairs REFUSE today. **Locked doctrine:** A3b/A3c may only EXPAND the legal-transition matrix — NEVER the stored vocabulary (growing the enum would be a column-vocabulary migration). Pinned by `test_reserved_pairs_refuse_until_expanded`. Stale-read + illegal-pair share one closed-enum reason `run_transition_invalid_state_pair` (mirrors scheduler storage).

2. **Atomic store (Doctrine Lock D).** `RunRecordStore.create_run` (genesis: INSERT `pending` + append `run.lifecycle.pending`) + `.transition` (SELECT … FOR UPDATE tenant-scoped row → `validate_transition` → UPDATE state + optional nullable columns → append `run.lifecycle.<to_state>`) drive `DecisionHistoryStore.append_with_precondition` — chain row + state-cache UPDATE in one transaction; refusal rolls back (no orphan row). Tenant isolation: `load`/`list_for_tenant`/the transition SELECT are tenant-scoped — a cross-tenant `run_id` reads as absent (`None` / `RunNotFound`). `list_for_tenant` paginates by `run_id` keyset cursor (dialect-portable).

3. **`run.lifecycle.<state>` is DISTINCT from the executor's `run.<terminal>` evidence.** The store emits its own `run.lifecycle.*` lifecycle events (value-free run-record snapshot per the chain-payload-is-evidence-snapshot doctrine); the executor's existing direct `run.completed`/`run.failed`/`run.refused`/`run.pending_approval` output-evidence rows are UNTOUCHED. Whether A3b reconciles the two surfaces (fold output evidence into the store, or keep dual lifecycle-vs-output surfaces) is a deliberate A3b decision.

4. **`runs` schema + `checkpoint_id`.** `run_id` UUID PK; `tenant_id` (NOT NULL boundary); pack identity (`pack_id`/`pack_uuid`/`pack_version`); nullable `task_id` (Uuid), `session_id` (String), `checkpoint_id` (**`String(32)`** — the sandbox `CheckpointId = uuid4().hex`, NOT a Uuid column, per ADR-004 §"Resumable-session API"), `approval_request_id` (Uuid — the approval-engine request id); `state`; timestamps. Migration `0011`; drift pinned by `tests/unit/db/test_migration_20260615_0011.py`.

**CC:** `core/run/storage.py` is the ONLY newly on-gate module — count **130 → 131** (the run-lifecycle tenant-isolation + chain-atomicity boundary; 100/100 at promotion). `core/run/_types.py` + the migration stay off-gate (pure types / run-once DDL), mirroring `core/scheduler/`.

**Deferred (A3b/A3c):** the executor wiring (genesis + terminal `runs` rows; `run_id` on `RunResponse`), the run→session resolver, the `POST /api/v1/runs/{run_id}/resume` route, `backend.wake()` dispatch, the suspend/wake transition pairs (A3b), and the `CheckpointMetadata` approval-correlator + wake-path `admit_policy` threading (A3c).

## Sprint 14A-A3b amendment (2026-06-16) — run→session resolver + the suspend/resume lane (`core/run/executor.py` drives the run record; `POST /api/v1/runs/{run_id}/resume`)

Sprint 14A-A3b is the second slice of the checkpoint→wake / run-persistence arc (A3a foundation → **A3b resolver/resume** → A3c wake approval correlator). It wires the A3a substrate into the executor and adds the suspend/resume lane: the synchronous `POST /api/v1/runs` lane stays STABLE; resumption gets its own dedicated route. **No new on-gate module** — the edits land in modules already on the gate (`core/run/executor.py`, `core/run/storage.py`, `portal/rbac/scopes.py`); `core/run/_types.py` + the dto/routes stay off-gate. CC count stays **131**.

1. **The executor now drives the run record (the A3a store-only posture is retired for the executor).** `ManagedRunExecutor.run` mints a `run_id` + a genesis `run.lifecycle.pending` via `RunRecordStore.create_run` and threads a record transition into EVERY terminal path (completed / failed / refused / pending_approval / **suspended**). `RunResult.run_id` is now the first field; the 5 emitters are reshaped to keyword-only `run_id` + nullable `task_id`. This makes `run.lifecycle.*` (the store's lifecycle snapshot) and the executor's direct `run.*` (output evidence — separate stdout/stderr sha256 + byte counts) two DISTINCT chain surfaces, both populated on a managed run (the A3a "whether A3b reconciles the two surfaces" decision resolved to KEEP both — lifecycle vs output are different evidence axes).

2. **The explicit `suspend_after_exec` trigger + the `suspend()`-then-`load_latest` mechanic.** `RunRequest.suspend_after_exec: bool` is the explicit suspend trigger (no implicit suspension; the default run still creates → exec → destroys → completes). `RunTerminalState` gains `suspended`. The suspend path is: `exec → session.suspend() → skip_destroy=True (set IMMEDIATELY, before any further await — once suspend() returns the container is released and the session handle is dead) → checkpoint_store.load_latest(session_id, tenant_id) (read back the metadata the backend wrote at suspend) → transition running→suspended persisting session_id + checkpoint_id → scheduler.complete → emit run.suspended`. The scheduler task COMPLETES at suspend (the run is durable + resumable; the worker slot is freed) — suspension is not a scheduler-lifecycle state.

3. **Conditional teardown — the tombstone-on-destroy rationale.** The executor's `finally` destroys the session ONLY `if session is not None and not skip_destroy`. A suspended session is therefore NEVER torn down by the run path, because `SandboxSession.destroy()` of a session with persisted checkpoints writes a `_tombstoned.json` sentinel (per ADR-004 §"Tombstone semantics") and `wake()` refuses tombstoned sessions fail-closed — destroying a just-suspended session would make its checkpoint permanently unwakable. `skip_destroy` flips True the instant `suspend()` returns so no intervening failure can route into the destroy arm.

4. **The resume route — first EXERCISED run→session resolver + first production `backend.wake()` caller.** `POST /api/v1/runs/{run_id}/resume` (off-gate, `portal/api/runs/routes.py`) is gated by `RequireScope("run.resume")` (the new scope) and calls `executor.resume(*, run_id, actor, argv)`. `resume()` resolves `run_id → session_id` via a tenant-scoped `RunRecordStore.load` (a cross-tenant `run_id` reads as absent → `RunNotFound` → **404**, so a probe cannot enumerate runs across tenants), then `backend.wake(session_id, actor=, tenant_id=)` — the FIRST production caller of `backend.wake()` (ADR-004) — runs a continuation `argv`, and walks the record `suspended → woken → completed` (or `→ refused` / `→ failed`). `RunNotResumable` (the record isn't suspended) → **409 `run_not_suspended`** + `current_state`. The shared `_run_response_from_result` projector returns one consistent body shape (`run_id` + `task_id` + terminal state) across both submit and resume; `suspended → 202`.

5. **resume makes NO scheduler calls (quota-on-resume = forward item).** Because the scheduler task completed at suspend and the worker slot was freed, `resume()` does NOT re-submit, does NOT re-admit through `scheduler.rego`, and does NOT take a quota reservation — `task_id` is always None on the resume `RunResult`. Re-admission / quota-on-resume / the scheduler-mediated resume path is a deliberate forward item (a resumed run that should re-consume budget is not modelled in A3b).

6. **Claim-gated teardown — the resume-side wake/tombstone race fix.** The woken session is destroyed in the resume `finally` ONLY after the atomic `suspended → woken` transition claim commits (`claimed_woken=True`). The claim is the race arbiter: the FIRST resumer to land the `suspended → woken` transition wins; a concurrent loser's `validate_transition` sees a non-`suspended` row, returns the stale-read closed-enum `run_transition_invalid_state_pair`, raises `RunTransitionRefused` → the executor maps it to `RunResumeConflict` (**409 `run_resume_conflict`**) and leaves `claimed_woken=False`. A non-stale DB error during the claim ALSO leaves `claimed_woken=False`. In BOTH cases the session is NOT destroyed — destroying it would tombstone a session the winner is actively executing (concurrent-loser case) or a run that is still `suspended` and resumable (DB-error case). The resume-side claim-gated teardown is the symmetric counterpart to the suspend-side conditional teardown: neither path tombstones a session that another actor may legitimately wake.

7. **Forward item — the leaked orphaned backend resource.** Item 6's claim-failure / concurrent-loser path deliberately does NOT destroy the woken backend container/pod (to avoid tombstoning the session) — so on a lost race the woken compute is a LIVE orphaned resource. This is NOT auto-reclaimed today: the `CheckpointReaper` (`sandbox/reaper.py` → `CheckpointStore.purge_expired()`) purges only object-store checkpoint/tombstone ARTIFACTS after the retention window, NOT live containers/pods. So a resume race leaks a backend resource (a resource leak — NOT data loss, NOT a tombstone, NOT a correctness bug). Orphaned-backend-resource cleanup / reconciliation is a forward item.

8. **The `resume` UI action is unblocked.** The deferred `resume` frontend action (`portal/api/ui/action_routes.py`'s `action_backend_deferred_sandbox_unwired` stub) now has a run→session resolver behind it; surfacing it through the UI action handler is a follow-up, but the run-resume primitive it was waiting on exists.

**On-gate surface (CC).** `core/run/executor.py` (the run-record drive + suspend/resume lane + claim-gated teardown), `core/run/storage.py` (`_STATE_TO_DECISION_TYPE` += `suspended`→`run.lifecycle.suspended`, `woken`→`run.lifecycle.woken`; `cancelled` stays reserved), and `portal/rbac/scopes.py` (`RunRBACScope` += `run.resume`; `RUN_SCOPES` 1→2). `core/run/_types.py` (off-gate) expanded the matrix with `_A3B_VALID_TRANSITIONS` (+6 producible pairs: `running→suspended`, `suspended→{woken,refused,failed}`, `woken→{completed,failed}`) — the 9-value `RunState` vocabulary is UNCHANGED, honoring the A3a "expand-matrix-only, never the vocabulary" locked doctrine. The dto/routes + the e2e are off-gate. CC count stays **131** (no new gate module).

**A3c fence (still pending).** A3b adds NO `CheckpointMetadata` approval fields and NO wake-path `admit_policy` approval threading — the wake-revalidation `admit_policy` calls (`docker_sibling.py`, `kubernetes_pod.py`) remain UNCHANGED (the 14A-A2 amendment's deferred wake correlator stands). A3c is the wake approval correlator slice. See the ADR-004 Sprint-14A-A3b amendment for the sandbox suspend/wake / checkpoint / tombstone angle.

## References

- AGENTS.md "Critical-controls rule" + "Stop rules" — scheduler module-set added at Sprint 10.5 (gate 85 → 89); `policies/_default/scheduler.rego` added to stop-rule policy bundle list
- BUILD_PLAN.md §10.5 — CLOSED on 2026-05-27 (squash `6791eec`)
- ADR-005 — Sub-agent primitive (Sprint 10.5 amendment: `ParentBudgetResolver` seam wired)
- ADR-014 — Runtime tool approval (Sprint 10.5 amendment: high-risk-tier refusal pre-13.5 mirrored)
- ADR-015 — Policy as code (scheduler.rego bundle landed)
- ADR-018 — Emergency controls (Sprint 10.5 amendment: seam Protocols only; Sprint 13.5 binds real conformers)
- ADR-020 — UI event-stream contract (Sprint 10.5 amendment: no new typed UI event family; Wave-2 deferred)
- `core/sla.py` (Sprint 2.5) — timer math primitive consumed by the scheduler
- `core/emergency/quotas.py` (Sprint 13.5) — accumulation surface re-integrated as scheduler input via `QuotaInterrogator` seam
- `subagent/policy.py` (Sprint 11) — budget narrowing semantics reified via `SubmitInput(..., parent_task_id=...)` passed to `SchedulerEngine.submit(submit_input, request_id=...)` + `ParentBudgetResolver` seam
- Sprint 10.5 spec: `docs/superpowers/specs/2026-05-25-sprint-10.5-scheduler-and-credential-projection-design.md`
- Sprint 10.5 plan: `docs/superpowers/plans/2026-05-25-sprint-10.5-scheduler-and-credential-projection.md` (truncated at Z1b with VALVE CHECK deferral footer)
- Sprint 10.5 closeout note: `docs/closeouts/2026-05-27-sprint-10.5-scheduler-primitive.md`
- Sprint 10.6 spec: `docs/superpowers/specs/2026-05-26-sprint-10.6-workload-credential-projection-design.md`
- Sprint 10.6 plan: `docs/superpowers/plans/2026-05-26-sprint-10.6-workload-credential-projection.md`
