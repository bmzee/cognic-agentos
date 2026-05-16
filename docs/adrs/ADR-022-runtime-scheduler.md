# ADR-022 — Runtime Scheduler / Work Queue

## Status
**DRAFT** authored 2026-05-16. Pending review.

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

`SchedulerEngine.submit()` returns a `SchedulerAdmissionOutcome` value carrying one of seven closed-enum reasons. This vocabulary IS the wire-protocol contract for every caller dispatching on submit result. Drift between the Literal and consumer error-handling is caught at module load by a partition-invariant test.

| Outcome | Meaning | HTTP analog (when surfaced via portal) |
|---|---|---|
| `scheduler_admission_accepted_immediate` | Concurrency cap had headroom; task moved straight to `running` | 202 Accepted |
| `scheduler_admission_accepted_queued` | Queue had capacity; task is `pending` | 202 Accepted (+ `task_id`) |
| `scheduler_admission_refused_queue_full` | Bounded queue full for (tenant, class); response carries `retry_after_s` derived from oldest queued task's age + class-specific SLA | 429 Too Many Requests |
| `scheduler_admission_refused_quota_exhausted` | `core/emergency/quotas.py` refused at submit time | 429 + `quota_class` |
| `scheduler_admission_refused_policy_denied` | `scheduler.rego` returned `allow=false`; carries `policy_reason` field | 403 |
| `scheduler_admission_refused_kill_switch_active` | `core/emergency/kill_switches.py` flipped for the relevant scope (pack / tenant / cloud / feature) | 503 |
| `scheduler_admission_refused_pack_not_installed` | Pack lifecycle state ≠ `installed` at admission | 409 |

**Backpressure semantics (user-locked Wave-1):**

1. If queue has capacity and concurrency cap has headroom → `scheduler_admission_accepted_immediate` (run now).
2. If queue has capacity but concurrency cap is saturated → `scheduler_admission_accepted_queued` (FIFO wait; **do NOT refuse**).
3. If queue is full for (tenant, class) → `scheduler_admission_refused_queue_full` with `retry_after_s`.
4. If quota / policy / kill-switch / pack-state denies → refuse immediately with the matching closed-enum reason; audit-emit `scheduler.admission_refused` carrying the reason.

The four refusal paths share a single `scheduler.admission_refused` audit event family; `payload.reason` discriminates. The two acceptance paths share `scheduler.admission_accepted`; `payload.outcome` discriminates immediate vs queued. **Six closed-enum values across two event families** — small enough that examiners can hold the matrix in their head.

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

A cap that would be exceeded routes to the FIFO queue (not refusal). A FULL queue THEN routes to `scheduler_admission_refused_queue_full`. **Concurrency caps and queue capacity are orthogonal** — saturating the first enqueues, saturating both refuses.

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

`SchedulerEngine.submit(task, *, parent_task_id=...)` accepts a parent task identifier. When a sub-agent invokes `tool_call`, the parent's remaining token budget is snapshotted at child-submit time and the child's quota reservation is narrowed accordingly. The child cannot exceed `min(child_pack_quota, parent_remaining_budget)`. Parent completion releases the child's residual budget back to the parent's pool.

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
- Saturation produces a closed-enum refusal (`scheduler_admission_refused_queue_full` with `retry_after_s`) instead of arbitrary cascading failure.
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

- ADR-005 (sub-agent primitive): budget narrowing becomes a scheduler operation; replace the static `policy.budget` field semantics with `scheduler.submit(..., parent_task_id=...)` arithmetic.
- ADR-014 (runtime tool approval): approval gate continues to fire before `scheduler.submit()` — high-risk-tier tools that require approval go through `approval.engine.wait_for_grant()` first, then `scheduler.submit()`. No semantic change; documented sequencing.
- ADR-018 (emergency controls): quota check moves from gateway-call-time to scheduler-submit-time. Kill switches gain a `scheduler.admit_refusal` integration point so a flipped switch immediately drains the queue.
- ADR-020 (UI event-stream contract): Wave-1 does NOT add a new typed event family. Scheduler audit + decision-history rows surface through the existing `decision_audit.event_appended` mirror (already wired in Sprint 6 via the decision_history → broker projection), keeping the Sprint 7B.4 11-family Wave-1 taxonomy stable. A first-class typed `scheduler.*` UI-event family — with per-event-type Pydantic models for `admission_accepted` / `admission_refused` / `task_started` / `task_completed` / `task_failed` / `task_cancelled` / `task_preempted` / `task_expired` — is a Wave-2 concern and will land as a future ADR-020 amendment.

## References

- AGENTS.md "Critical-controls rule" + "Stop rules" — scheduler module-set added at Sprint 10.5
- BUILD_PLAN.md Sprint 10.5 (to be added when this ADR is approved)
- ADR-005 — Sub-agent primitive (amendment trigger)
- ADR-014 — Runtime tool approval (sequencing relationship)
- ADR-015 — Policy as code (scheduler.rego bundle)
- ADR-018 — Emergency controls (quota integration amendment)
- ADR-020 — UI event-stream contract (typed-event projection)
- `core/sla.py` (Sprint 2.5) — timer math primitive consumed by the scheduler
- `core/emergency/quotas.py` (Sprint 13.5) — accumulation surface re-integrated as scheduler input
- `subagent/policy.py` (Sprint 11) — budget narrowing semantics reified via scheduler.submit
