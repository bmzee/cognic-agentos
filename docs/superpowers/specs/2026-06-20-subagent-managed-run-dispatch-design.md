# Live SubAgentSpawner dispatch — first production slice (child-is-a-managed-run)

**Date:** 2026-06-20
**Status:** design locked (brainstorming complete; ready for writing-plans)
**ADRs:** ADR-005 (sub-agent primitive), ADR-022 (runtime scheduler), ADR-004 (sandbox / managed run)

## Motivation

The sub-agent primitive (`subagent/`) has shipped its orchestration, policy, audit, and
budget seams since Sprint 11b, but **no production path exercises it**: `SubAgentSpawner`
is constructed only in tests, nothing calls `spawn_subagent` in production, and `ChildRunner`
is a Protocol with no production implementation. The just-merged parent-budget-resolver seam
(`SchedulerTaskParentBudgetResolver`, CC 132) cleared the **scheduler-side budget authority**
this dispatch path consumes. This slice composes + proves the live dispatch path.

## Locked decisions (from brainstorming)

- **(ii) child-is-a-managed-run.** `ManagedRunExecutor` is the single owner of `scheduler.submit →
  mark_running → sandbox create/exec/destroy → complete/fail`. `spawn.py` does NOT keep its own
  scheduler task on the live path (that would recreate the double-authority problem the budget
  slice just cleared).
- **(A) no production trigger this slice.** Compose `SubAgentSpawner` + the default runner at the
  portal lifespan; prove `spawn_subagent(...)` directly via tests. A production trigger
  (running managed workload → sub-agent) is the natural **next** slice (was option C). A portal
  route (option B) is rejected as the long-term UX.
- **(3) prove plumbing, defer the rich child-context channel.** The default runner supports a
  minimal **argv-backed** execution shape only. `ChildRunContext.prompt` / `granted_tools` remain
  part of the sub-agent abstraction, but the managed-run runner does NOT invent a prompt/tools
  transport yet. **Fail-closed:** the runner refuses a prompt/tools-only child with no argv mapping,
  never silently drops them.
- **(B + thin-C) adapter DTO + identity resolution.** A new runner-specific `ManagedRunChildSpec`
  carries the managed-run execution shape; the public `SubAgentSpawnRequest` stays runner-agnostic.
  The runner resolves **only `pack_uuid`** (the row id) from `pack_id` via the pack store; `pack_version`
  is **caller-provided** on the spec (`PackRecord` has no version column — consistent with the run routes,
  whose `RunRequest.pack_version` is likewise caller-supplied), so callers never hand-thread the UUID.

### Source anchors (verified)
- `ManagedRunExecutor` derives `pack_kind=record.kind` + `pack_risk_tier=record.risk_tier` +
  `data_classes` from the validated `LoadedPackRecord` at `core/run/executor.py:367-378`.
- `RunRequest` currently carries pack identity + `argv` only (`core/run/executor.py:145-162`);
  `LoadedPackRecord` carries `kind` / `risk_tier` / `data_classes` (`:115-131`).
- `SubAgentSpawnRequest` is runner-agnostic (`subagent/_types.py:73-84`).
- The executor's submit hardcodes `class_="interactive"` and uses `_DEFAULT_ESTIMATED_TOKENS`.

## 1. Scope and non-goals

**In scope:** compose the live dispatch path and prove it — the data-model changes, the default
`ManagedRunChildRunner`, the `spawn.py` live-path refactor, the budget-authority collapse, the
portal-lifespan composition, and the tests. The child becomes a first-class governed managed run
(run-record + value-free `run.*` evidence) with the scheduler as the single budget authority.

**Non-goals (explicitly deferred):**
- The prompt/tools → workload **rich channel** (Option 3 — `argv` only this slice). Lands with the
  first real agent pack.
- A **production trigger** (route/tool) — the next slice (option C).
- **High-risk / `pending_approval` children** — no async child-approval loop this slice; a child that
  pends surfaces as a clean `ChildResult(ok=False, …)`. Children are expected at the auto-tier shape.
- **Real token metering** — the managed run meters bytes + exit, not tokens; `tokens_used = 0` is a
  documented honest gap.
- The **sibling/shared-pool depletion ledger** (a refinement on the granted-snapshot ceiling).
- **Child class selection** — the executor hardcodes `class_="interactive"`; child runs are interactive
  this slice (see §3 / §8).

## 2. Data model / API changes

### `core/run/executor.py` (on-gate) — two additive `RunRequest` fields
Both default-`None`, so top-level runs render byte-identical:
- `parent_task_id: str | None = None` — **`str`, not `uuid.UUID`** (revision #1). The scheduler already
  owns malformed-`parent_task_id` validation (`uuid.UUID(...)` → `SchedulerSubmitInputInvalid`). The
  executor threads the string **unchanged** into `SubmitInput.parent_task_id` (which is `str | None`);
  it does NOT parse. This keeps the parse/validation contract single-owned in the scheduler.
- `requested_estimated_tokens: int | None = None` — when set, overrides the executor's
  `_DEFAULT_ESTIMATED_TOKENS` in the `SubmitInput`; `None` preserves the existing top-level behavior.

`run()` threads both into the existing `SubmitInput(...)` build (`:367`). No `pack_kind`/`pack_risk_tier`
inputs are added — the executor keeps deriving them from `LoadedPackRecord`.

### `subagent/_types.py` (subagent/ stop-rule)
- **NEW** `ManagedRunChildSpec` frozen dataclass: `{pack_id: str, pack_version: str, argv: tuple[str, ...]}`.
  **no** `pack_kind`/`pack_risk_tier` (the executor derives them authoritatively from the validated record).
  **`pack_version` IS caller-provided** (P1): `PackRecord` (`packs/storage.py`) has **no version column**, and
  the run routes already source `pack_version` from the caller body — so the runner resolves **only**
  `pack_uuid` (the row id) from `pack_id` via the pack store, and takes `pack_version` from the spec.
- `ChildRunContext` gains fields (the designed growth point — "threading new fields never churns the
  ChildRunner signature"), all **optional with defaults** so each addition is additive — no constructor
  churn, no intermediate red tree:
  - `actor: Actor | None = None` — the portal `Actor`, threaded from `spawn()`'s `actor`. **Optional** so the
    type addition is additive: when this field lands (the `_types` task), `spawn.py` still holds a `TaskActor`
    (it gains the full `Actor` only in the spawn-refactor task), so a *required* `Actor` would type-error the
    in-flight refactor and break that task's green-tree gate. The **managed-run runner fail-closes on
    `actor is None`** (mirroring `managed_run is None`) — every real spawn sets it, and a pack-provided runner
    that doesn't need one is unaffected. The full `Actor` is threaded, **NOT `TaskActor`** (P1): `TaskActor`
    cannot carry `Actor.scopes`. `Actor` is a `TYPE_CHECKING` import in `subagent/_types.py` (the module has
    `from __future__ import annotations`), mirroring the executor's `core/run → portal` arrow — no runtime
    `subagent → portal` import.
  - `parent_task_id: str | None = None` — the budget-inheritance key, threaded from
    `request.parent_task_id` (`str | None`, mirrors the request).
  - `managed_run: ManagedRunChildSpec | None = None` — the runner-specific shape; `None` for
    pack-provided runners → the managed-run runner fail-closes.
- **`ChildRunContext.budget` is renamed to `requested_estimated_tokens`** (revision #2). Once `spawn.py`
  stops calling the scheduler it no longer knows the *effective* (narrowed) budget, so the field now
  reads as the *requested* child tokens (from `request.requested_estimated_tokens`). The scheduler
  remains the only place that computes the effective child budget (`compute_child_budget`).
- `SubAgentSpawnRequest` — **unchanged** (runner-agnostic; A avoided).

### `subagent/spawn.py` (subagent/ stop-rule) — `spawn()` signature
- **New shape:** `spawn(*, request: SubAgentSpawnRequest, managed_run: ManagedRunChildSpec, actor: Actor,
  parent_trace_id: str)`. The managed-run execution shape (`pack_id` + `pack_version` + `argv`) is **bundled
  into the caller-built `ManagedRunChildSpec`** (kept out of the public `SubAgentSpawnRequest`), so the
  separate `pack_id`/`child_argv` params are gone.
- **`actor` is now the full portal `Actor`** (P1; was `TaskActor`): the audit uses `actor.subject`, and the
  full `Actor` threads to `ChildRunContext.actor → RunRequest.actor` (the executor requires `Actor` and
  `TaskActor` cannot carry scopes). The facade `spawn_subagent` mirrors this signature.
- **Drops** `pack_kind`, `pack_risk_tier`, **and `class_`** (revision #3). All three only fed the now-removed
  in-`spawn` `SubmitInput`; the executor derives kind/risk_tier from the record and hardcodes
  `class_="interactive"`, so carrying them on `spawn()` would be a lie. `narrow_tool_allow_list` /
  `check_depth` / `emit_spawn` do not use them. Class selection arrives with the trigger surface (or a
  future `RunRequest.class_`).
- The constructor **drops** the `scheduler` and `parent_budget` dependencies (the live path no longer
  submits).

### `core/scheduler/engine.py` (already on-gate) — zero-effective-budget guard (P1)
The scheduler currently admits a zero-token task (`compute_child_budget` can return `0`; quota
`would_admit(..., estimated_tokens=0)` does not refuse), so retiring the spawn-level `compute_spawn_budget`
(§6) without a guard would admit a zero-budget child. `SchedulerEngine.submit` gains a guard: **after**
parent narrowing and **before** the quota reservation, refuse `effective_tokens <= 0` with the **existing**
`refused_quota_exhausted` outcome — **no new `SchedulerRefusalReason` value**. Covers the no-parent
(`requested_estimated_tokens=0`) and the parent-narrowed-to-zero cases; no quota reservation is made on the
refusal path. Already-on-gate file (no CC count change — the +1 is the new runner, §7).

## 3. Spawn flow refactor (`spawn.py` shrinks substantially)

The live `spawn()` path becomes:
1. `narrow_tool_allow_list(parent, requested)` — privilege subset (unchanged).
2. `check_depth(...)` + `escalation.open(...)` on exceed (unchanged).
3. `emit_spawn(...)` → `R_spawn` (unchanged; `policy_snapshot` now reflects the *requested* tokens —
   the effective/narrowed value lives in the scheduler chain row, not the spawn audit).
4. Build `ChildRunContext(..., actor=actor, requested_estimated_tokens=request.requested_estimated_tokens,
   parent_task_id=request.parent_task_id, managed_run=managed_run)` — the caller-built `managed_run` spec
   and the full `actor` threaded straight through.
5. `child = await child_runner.run(ctx)`.
6. `emit_return(...)` + `emit_budget(...)` from the `ChildResult`.

**Removed:** `_resolve_budget`, the `scheduler.submit → mark_running → complete/preempt/fail/cancel`
block, the `accepted_queued` cancel path, and the `scheduler`/`parent_budget` deps (roughly the current
`spawn.py:126-297`). All scheduler lifecycle now lives in the executor.

## 4. `ManagedRunChildRunner` behavior + `RunResult → ChildResult` mapping

New module `subagent/managed_run_runner.py` (on-gate — see §7). It imports the `RunRequest`/`RunResult`
types from `core/run` and consumes the executor via a **narrow consumer-owned Protocol seam** (the real
`ManagedRunExecutor` structurally conforms — `[[feedback_consumer_owned_protocol_for_unlanded_dep]]`), so
`subagent/` stays decoupled from the executor's construction; the pack store is consumed for thin-C
(mirroring the existing `subagent/conformers.py` → `packs` dependency). `ManagedRunChildRunner(executor, pack_store)`:

`async def run(self, ctx: ChildRunContext) -> ChildResult`:
1. `ctx.managed_run is None` **OR `ctx.actor is None`** → **fail-closed refusal** (the locked nuance + the
   optional-`actor` fail-close). A prompt/tools-only child with no argv mapping — or a child with no portal
   `Actor` to build the `RunRequest` — is refused, never silently dropped. After this guard, mypy narrows
   `ctx.actor` to `Actor` for the `RunRequest{actor=ctx.actor}` build below.
2. **thin-C identity resolution (revision #4):** resolve **only `pack_uuid` (the row id)** — scan installed
   packs for `tenant_id == ctx.tenant_id` AND `pack_id == ctx.managed_run.pack_id` via the pack store
   (mirrors `PackStoreStateInterrogator`'s `list_for_tenant(state="installed")` match). **Exactly one** match
   required: **zero matches AND multiple matches both fail closed** (no caller UUID-threading, no ambiguity).
   `pack_version` is **not** resolved (P1: `PackRecord` has no version column) — it comes from
   `ctx.managed_run.pack_version`.
3. Build `RunRequest{tenant_id=ctx.tenant_id, pack_id=ctx.managed_run.pack_id, pack_uuid=<resolved row id>,
   pack_version=ctx.managed_run.pack_version, argv=ctx.managed_run.argv, actor=ctx.actor,
   parent_task_id=ctx.parent_task_id, requested_estimated_tokens=ctx.requested_estimated_tokens}` →
   `await executor.run(...)`. **`actor` is required at `executor.py:158`** — threaded from `ctx.actor`.
4. Map `RunResult → ChildResult`:
   - `ok = (terminal_state == "completed" and exit_code == 0)`.
   - `terminal_state ∈ {refused, failed}` → `ok=False`.
   - `terminal_state == "pending_approval"` → `ChildResult(ok=False, summary="<high-risk child unsupported
     this slice; needs async resume>")` (no async child-approval loop — a non-goal).
   - `terminal_state == "suspended"` → defensive `ChildResult(ok=False, summary="suspended_child_unsupported")`
     (the runner never sets `suspend_after_exec`, so this is unreachable — but the mapping is explicit so
     **every** current `RunTerminalState` value is handled; pinned by a test over all values — §7).
   - `summary` = compact status (`run_id` + `terminal_state` + `exit_code`); NOT raw stdout (rich output
     deferred per Option 3).
   - `wall_time_used_s` = runner-measured around the `executor.run` call (`time.monotonic` delta).
   - `tokens_used = 0` (the managed run does not meter tokens; real accounting deferred — documented).

## 5. Composition site (portal app lifespan)

`ManagedRunExecutor` is SDK-gated and constructed in the **portal app lifespan**
(`app.state.managed_run_executor`, via `harness/sandbox.py::build_sandbox_backend`), because it needs the
sandbox SDK. The `ManagedRunChildRunner` + the live `SubAgentSpawner` therefore assemble **in the same
lifespan block, after the executor**:
- The lifespan **constructs** `SubAgentAuditEmitter(runtime.decision_history_store)` and
  `EscalationStore(runtime.decision_history_store)` after `build_runtime` — `Runtime` exposes
  `decision_history_store`, not the emitter/escalation themselves.
- The runner is injected in the lifespan; the spawner is exposed on `app.state.subagent_spawner`,
  **WIRED-but-DORMANT** — no route/caller this slice (the A posture, mirroring the 13.7 scheduler and
  13.8 MCP-host postures).
- The off-gate builder lives in `harness/sandbox.py` (mirrors the existing executor/backend builder).

## 6. Budget-authority collapse

The executor's `scheduler.submit(SubmitInput(parent_task_id=<the child's, string>,
requested_estimated_tokens=<ctx.requested_estimated_tokens>))` flows into the scheduler's
`SchedulerTaskParentBudgetResolver` (the just-merged seam) → `compute_child_budget = min(child_quota,
parent_granted)` — **the single narrowing authority**.

- `spawn.py`'s `_resolve_budget` + `compute_spawn_budget` are **retired from the live path**.
- **A zero-effective-budget child is refused by a NEW scheduler guard (P1).** `SchedulerEngine.submit`
  narrowing can yield `effective_tokens == 0` (top-level `requested_estimated_tokens=0`, OR a parent
  narrowed to zero via `compute_child_budget`), and quota `would_admit(..., estimated_tokens=0)` does NOT
  refuse — so retiring `compute_spawn_budget` without a guard would admit a zero-budget child. The engine
  refuses `effective_tokens <= 0` **after** parent narrowing and **before** the quota reservation, with the
  **existing** `refused_quota_exhausted` outcome (no new `SchedulerRefusalReason` value); no quota
  reservation is made on the refusal path (see the `core/scheduler/engine.py` change in §2). An over-budget
  child stays the **existing** quota-gate refusal. Neither raises the `subagent_parent_budget_exhausted` /
  `subagent_child_quota_zero` spawn-refusal anymore.
- `subagent/policy.compute_spawn_budget` + the `SubAgentBudgetExhausted` / `SubAgentChildQuotaZero`
  exceptions leave the live path; **delete only the now-unused helpers/exceptions** if no remaining consumer
  (tests/facade) needs them.
  **LOCKED (wire-public):** the `SubAgentRefusalReason` Literal values `subagent_parent_budget_exhausted` /
  `subagent_child_quota_zero` are **KEPT for compatibility** — this slice does **no** drift-detector or
  vocab pruning. (They are simply no longer raised on the live path; the scheduler's `refused_quota_exhausted`
  now owns the zero/over-budget refusal per §2/§6 above.)

## 7. Tests + CC posture

**CC:**
- `core/run/executor.py` (on-gate) — the `RunRequest` extension + threading is an on-gate edit
  (≥95% line / 90% branch; CC scrutiny).
- `subagent/_types.py` + `subagent/spawn.py` — `subagent/` stop-rule (CC).
- `core/scheduler/engine.py` (already on-gate) — the P1 zero-effective-budget guard (≥95/90; no count change).
- **`ManagedRunChildRunner` is a NEW on-gate module** (CC **132 → 133**) — it is the live-dispatch
  enforcement surface (fail-closed on missing argv; exact tenant-scoped pack resolution; the
  RunResult→ChildResult mapping), not thin-adapter glue. Registered in `tools/check_critical_coverage.py`
  `_CRITICAL_FILES` + `_EXPECTED_ENTRY_COUNT` (132→133) in the closeout, on fresh `--cov-branch` coverage.

**Tests:**
- Unit: the `spawn.py` refactor with a stub runner (narrow + depth + audit, no scheduler calls); the
  `ManagedRunChildRunner` with a stub executor + stub pack store (the mapping **over every current
  `RunTerminalState` value** — `completed`/`failed`/`refused`/`pending_approval`/`suspended`, the last two
  → `ok=False`; fail-closed on `managed_run=None`; zero-match AND multi-match fail-closed; the
  `parent_task_id` string passthrough; the `requested_estimated_tokens` threading); the `RunRequest`
  additive-field defaults.
- Unit: the **scheduler zero-effective-budget guard (P1)** — top-level `requested_estimated_tokens=0` AND
  parent-narrowed-to-zero both refuse with `refused_quota_exhausted` and make **no** quota reservation.
- Env-gated **real-docker e2e** (`COGNIC_RUN_DOCKER_SANDBOX=1`): `spawn_subagent` → `ManagedRunChildRunner`
  → real `ManagedRunExecutor` → real sandbox → budget inheritance proven against a **seeded parent
  scheduler task** (`compute_child_budget` narrows the child to `min(child_quota, parent_granted)`); the
  child's `run.*` evidence + the sub-agent audit return both assert.

**Migration:** none (all changes are dataclasses + composition; no DB schema change).

## 8. Follow-on slices (out of scope here)

1. **Production trigger** (option C) — expose dispatch to a running managed workload (the first real
   sub-agent caller); brings child class selection (`RunRequest.class_`) with it.
2. **Rich child-context channel** — the prompt/tools transport, tied to the first real agent pack
   (argv-convention or a structured executor input).
3. **High-risk child approval** — the async child-approval/resume loop for `pending_approval` children.
4. **Real token metering** — `tokens_used` from quota actuals / a metered run.
5. **Sibling/shared-pool depletion ledger** — live decrement on top of the granted-snapshot ceiling.
