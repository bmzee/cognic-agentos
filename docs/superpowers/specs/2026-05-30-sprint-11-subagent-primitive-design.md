# Sprint 11 — Sub-Agent Primitive (ADR-005) — Design Spec

**Status:** DRAFT — awaiting user review (no implementation started).
**Date:** 2026-05-30.
**Owner subsystem:** runtime / governance kernel (`subagent/` — new stop-rule isolation boundary per AGENTS.md "privilege de-escalation boundary").
**Source of truth:** ADR-005 (APPROVED 2026-04-26 + Sprint-10.5 amendment 2026-05-27); BUILD_PLAN §"Sprint 11 — Sub-agent primitive"; ADR-003 (A2A substrate); ADR-022 (scheduler); ADR-006 (ISO control mapping); ADR-020 (UI event-stream).
**Baseline:** `origin/main @ 58e27d2` (Sprint 10.6 merged, Phase 3 CLOSED). CC coverage gate at **90** modules.

**Goal:** Ship the AgentOS sub-agent primitive per ADR-005 — dynamic orchestrator→worker delegation with isolated context, privilege de-escalation, capped budget + recursion depth, and a cross-agent audit chain — dispatched through the Sprint-10.5 scheduler so child tasks inherit narrowed budgets and queue-time policy decisions.

**Architecture (2 sentences):** `subagent/` is a thin kernel primitive: pure-functional policy (privilege subset + depth cap) and an audit emitter feed a scheduler-mediated, **in-process** Wave-1 dispatch that preserves A2A trace/audit/identity semantics; parent↔child linkage rides entirely in the hash-chained `decision_history` payload, verified by a cross-row linkage verifier modelled on `verify_suspend_wake_linkage`. The sprint splits into **11a** (pure primitive, no external wiring) and **11b** (scheduler/harness/UI integration) at a valve checkpoint.

---

## 0. Source-of-truth reconciliation — **T0 (runs before any implementation)**

ADR-005 is already APPROVED and currently states the Wave-2 shape in two places that the Wave-1 design intentionally narrows. Per `[[feedback_patch_plan_against_doctrine]]`, the docs are reconciled **before** T1 — not at closeout — so the spec never knowingly diverges from an approved ADR.

**T0 lands the following doc edits (no code):**

1. **ADR-005 amendment — Wave-1 dispatch is in-process.** ADR-005 §Decision (`ADR-005:21` "Sub-agents spawn via the A2A endpoint"), §Implementation-phases (`ADR-005:65` "Phase 4.1: A2A-backed `SubAgent.invoke()`"), and the Sprint-10.5 amendment (`ADR-005:86`) describe an A2A-transport dispatch. Wave-1 ships **in-process, scheduler-mediated dispatch preserving A2A trace/audit/identity semantics** (parent_trace→child_trace propagation; identity metadata carried in the audit payload — no AgentCard/JWS verification at in-process spawn in Wave-1); the A2A *endpoint transport* (cross-pod hop) is deferred to **Wave 2**. This is consistent with ADR-005 §Consequences/Neutral, which already names in-process as a mode (`ADR-005:61` "~50–200ms for in-process; more for cross-pod").

2. **ADR-005 amendment — Wave-1 recursion cap is global.** ADR-005 §Recursion-depth (`ADR-005:30` "Per-tenant configurable; default `max_depth = 3`") is narrowed for Wave-1 to a global `Settings.subagent_max_recursion_depth = 3`. Per-tenant / per-agent overrides are deferred to the policy/approval layer (Sprint 13.5). This is explicitly authorized: BUILD_PLAN's human-decision table lists "Sub-agent recursion depth default — global, per-tenant, or per-agent" as a *Before-Sprint-11* human decision (`BUILD_PLAN:1342`), now decided (global).

3. **BUILD_PLAN Sprint-11 wording update.** Update the deliverable list so it reflects the Wave-1 shape:
   - "subagent/spawn.py — A2A-backed `invoke(prompt)`" → "scheduler-mediated `invoke(prompt)` (A2A semantics; A2A transport Wave-2)".
   - Remove **"`core/decision_history.py` extension"** as an implementation target. Parent↔child linkage is **payload-only**; there is no `DecisionRecord` field change, no `core/canonical.py` change, no top-level `decision_history` column, no `schema_version` bump (verified: `DecisionRecord` at `decision_history.py:240-249` carries no parent field, and the payload dict is canonicalised whole at `append`).
   - Add a Sprint-11 row to the schedule-risk table recording the 11a/11b valve (the table currently stops at 10.5, `BUILD_PLAN:1288`).
   - Reword the Sprint-11 **tests + exit criteria** so "Merkle proof over parent + child events" reads as *payload-linkage verification* (the §11 cross-row verifier, modelled on `verify_suspend_wake_linkage`) and "no direct child execution bypasses the scheduler" is the stated exit criterion; remove any implication of a `core/decision_history.py` schema edit.

**T0 is the only ADR-amendment point.** T10 (closeout) reconciles documentation only — no first-time amendments.

---

## 1. Context & current state (verified this session)

- **Greenfield primitive.** No `subagent/` package, no `harness/`, no `base_agent.py`, zero `SubAgent`/`spawn_subagent` references in `src`. The only existing `subagent` artefacts are the UI-event family and the scheduler seam.
- **Scheduler seam is ready.** `core/scheduler/_seams.py` declares the consumer-owned `ParentBudgetResolver` Protocol (`async remaining_budget_for(parent_task_id: uuid.UUID) -> int`) + fail-loud `_NullParentBudgetResolver` sentinel + pure `compute_child_budget(*, parent_remaining_budget, child_pack_quota) -> int`. `SubmitInput.parent_task_id` (`_types.py:94`) + `SchedulerEngine.submit(submit_input, *, request_id)` budget-narrowing path (`engine.py:290`) are wired. Sprint 11 supplies the real `ParentBudgetResolver` conformer.
- **Scheduler is NOT app-wired.** `SchedulerEngine(` is constructed only in `tests/unit/core/scheduler/test_engine.py:198`; `portal/api/app.py` has zero scheduler references. All four interrogator seams + `SandboxAdapter` have only `_Null*` sentinels (each raises `NotImplementedError`).
- **Decision history.** `DecisionHistoryStore.append(record) -> tuple[uuid.UUID, bytes]` (`decision_history.py:361`); single hash-chain (`_CHAIN_ID = "decision_history"`, `:307`); post-commit hook system `register_append_hook` / `AppendedDecisionSnapshot{record_id, chain_id, sequence, new_hash, decision_type, payload, tenant_id, …}` (`:313`, `:252-285`) — the UI emitter already registers here.
- **Cross-row verifier precedent.** `chain_verifier.py:310` `verify_suspend_wake_linkage()` — per-row payload linkage (lookup-by-`record_id` + decision_type assert + tenant-column parity + causal sequence ordering), independent of the hash-walk. The model for `subagent/audit_verifier.py`.
- **UI subagent family.** `ui_events.py:544-561` — 4 schema-only models (`subagent.spawned` / `subagent.completed` / `subagent.failed` / `subagent.recursion_capped`), in `_WAVE_1_FAMILIES` + `_SSE_WAVE_1_STREAMED_FAMILIES`, **no emit hooks wired**.
- **ISO control.** `A.6.2.5` (Operational responsibilities) is implemented in the iso42001 registry and is what the scheduler tags (`SCHEDULER_ISO_CONTROLS = ("A.6.2.5",)`, `_types.py:118`). ADR-005 §ISO maps sub-agent events to "delegation accountability" + "action traceability" → `A.6.2.5`.
- **Consumer seams ready (no edits, called only):** `EscalationStore.open()/transition()` (`escalation.py:467/510`); `SchedulerEngine.preempt(task_id,*,request_id)` (`engine.py:924`, reason `quota_exhausted_in_flight`) + `cancel(…,reason,…)` (`engine.py:895`, incl. `parent_run_cancelled`).
- **Policy is inline this sprint.** `subagent.rego` is **Sprint 13.5** (`BUILD_PLAN:321,1131`); the inline policy refactors to delegate to `policy.engine.evaluate` only at 13.5 (`BUILD_PLAN:1132`). Shipping inline policy in `subagent/policy.py` is doctrine-correct.

---

## 2. Scope & non-goals

**In scope (Sprint 11):**
- `subagent/` primitive: types, pure policy, audit emitter, cross-agent verifier, budget-resolver conformer, scheduler-mediated spawn, `SubAgent` facade.
- Global `Settings.subagent_max_recursion_depth`.
- Minimal harness exposure seam (`spawn_subagent`) — **not** a broad agent runtime.
- UI emit-hook wiring for the existing `subagent` family.
- T0 doc reconciliation + T10 closeout.

**Out of scope / deferred (do-not-touch):**
- `policies/_default/subagent.rego` and the policy-engine delegation refactor → **Sprint 13.5**.
- Real `QuotaInterrogator` / `KillSwitchInterrogator` conformers + `core/emergency/*` → **Sprint 13.5** (memory-freeze seed is 11.5).
- `core/memory/*`, learning-surface, DLP → **Sprint 11.5**.
- A2A *transport* (cross-pod network dispatch) → **Wave 2**.
- Per-tenant / per-agent recursion overrides → Sprint 13.5.
- `core/canonical.py`, any `DecisionRecord` schema/column change, `schema_version` bump → **never** (payload-only by design).
- Editing `core/chain_verifier.py` → avoided (new `subagent/audit_verifier.py` instead) unless explicitly approved.
- Layer C agents / personas / per-agent workflows / agent packs / Studio UI rendering → other repos.

---

## 3. Wave-1 locked decisions

1. **Split 11a / 11b** at a valve checkpoint (11a pure; 11b integration).
2. **`subagent/` public primitive first**; harness exposure is a *minimal* seam in 11b, not a broad `harness/base_agent.py`.
3. **In-process, scheduler-mediated dispatch** preserving A2A trace/audit/identity semantics; A2A transport deferred to Wave 2.
4. **Tool allow-list = `frozenset[str]` of tool IDs**; child's requested set must be a subset of the parent's; provenance is an **explicit spawn input** (not inferred from the MCP host yet).
5. **Global `Settings.subagent_max_recursion_depth = 3`**; per-tenant/per-agent overrides deferred.
6. **Parent↔child linkage is payload-only** — no `DecisionRecord` schema, no `core/canonical.py`, no top-level column.
7. **`ParentBudgetResolver` reads a Sprint-11-local parent-budget snapshot**; do not require Sprint-13.5 quota conformers.
8. **UI emit hooks land in 11b**; the existing `subagent.*` event models are wired, never renamed (ADR-020 backward-compat).

---

## 4. Architecture & components

```
subagent/
  __init__.py          # SubAgent facade + invoke(prompt)  [11a marker → 11b facade]
  _types.py            # closed-enum vocab + frozen dataclasses + ISO tuple   [11a/T1]
  policy.py            # pure: privilege subset + depth cap                    [11a/T2]
  audit.py             # 4 decision_types + parent-chain emit + child genesis  [11a/T3]
  audit_verifier.py    # cross-agent payload-linkage verifier                  [11a/T4]
  budget_resolver.py   # real ParentBudgetResolver over local snapshot         [11b/T5]
  spawn.py             # scheduler-mediated in-process dispatch                [11b/T6]
core/config.py         # + subagent_max_recursion_depth (global)              [11a/T2]
protocol/ui_events.py  # wire emit hooks for existing subagent family         [11b/T9]
harness exposure        # minimal spawn_subagent(...) seam                     [11b/T8]
```

**Layering invariants:**
- `core/scheduler/*` MUST NOT import `subagent/*` (substrate independence; the real `ParentBudgetResolver` is injected via DI, mirroring the AST guard `test_architecture_no_sandbox_import.py`).
- `subagent/audit.py` **consumes** `DecisionHistoryStore.append` and **does not edit** `core/decision_history.py` or `core/canonical.py`.
- `subagent/audit_verifier.py` is a new module, not an edit to `core/chain_verifier.py`.

---

## 5. Data flow — spawn → execute → return

All rows land in the single `decision_history` hash-chain; parent and child are linked **logically by payload**, exactly like suspend/wake. One sub-agent invocation produces:

```
parent: subagent.spawn   (payload: child_request, policy snapshot, parent_trace_id)  ← record_id = R_spawn
child : subagent.start   (payload: parent_record_id=R_spawn, child_trace_id)         ← the child's own genesis record, chained to parent
parent: subagent.return  (payload: parent_record_id=R_spawn, result_summary)
parent: subagent.budget  (payload: parent_record_id=R_spawn, tokens_used, wall_time_used)
+ scheduler rows: scheduler.admission_accepted / scheduler.task_running / scheduler.task_{completed|preempted|…}
```

Lifecycle steps:
1. Parent calls `SubAgent.invoke(prompt, *, requested_tool_allow_list, current_depth, …)`.
2. **Policy gate (pure):** `check_depth` (vs global cap) + `narrow_tool_allow_list` (subset enforcement). On refusal → `SubAgentDepthExceeded` / `SubAgentPrivilegeEscalation`; depth-exceed additionally triggers `EscalationStore.open(level="depth_exceeded", …)` per ADR-005.
3. **Audit:** emit `subagent.spawn` (parent), capture `R_spawn`.
4. **Scheduler submit:** build `SubmitInput(parent_task_id=<parent task id>, requested_estimated_tokens=<child quota>, …)`; `SchedulerEngine.submit(submit_input, request_id=…)`. The engine narrows the budget via the injected `ParentBudgetResolver` + `compute_child_budget`. Refusals surface as the scheduler's closed enum (`refused_*`).
5. **Dispatch (in-process):** run the child worker in its own isolated context (no parent context unless explicitly passed); emit child-genesis `subagent.start` with `payload["parent_record_id"] = R_spawn`.
6. **Budget/preempt:** if the child exceeds budget mid-flight → `SchedulerEngine.preempt(child_task_id, …)` (reason `quota_exhausted_in_flight`); parent is informed via the chain + return value.
7. **Return:** emit `subagent.return` + `subagent.budget`; discard child context (only the result + decision rows persist).
8. **Verification:** `subagent/audit_verifier.py` proves the parent↔child linkage over the produced rows.

---

## 6. Wire vocabularies

**Audit decision_types (new; parent + child chain rows):** `subagent.spawn`, `subagent.start`, `subagent.return`, `subagent.budget` (per ADR-005 §Audit).

**UI event types (existing; wired in 11b, never renamed):** `subagent.spawned`, `subagent.completed`, `subagent.failed`, `subagent.recursion_capped` (`ui_events.py:544-561`).

**Audit → UI mapping (finalised in T9; provisional):**
| audit decision_type | UI event |
|---|---|
| `subagent.spawn` | `subagent.spawned` |
| `subagent.return` (success) | `subagent.completed` |
| `subagent.return` (failure) / scheduler refusal | `subagent.failed` |
| depth-cap refusal | `subagent.recursion_capped` |
| `subagent.start`, `subagent.budget` | (no UI analogue Wave-1; carried in completed/failed payload) |

**Closed-enum refusal vocabulary (`SubAgentRefusalReason`, finalised in T1, provisional ±1):** `subagent_depth_exceeded`, `subagent_privilege_escalation`, `subagent_parent_budget_exhausted` (when narrowed budget = 0). Scheduler admission refusals (`refused_*`) propagate up unchanged.

**ISO control:** `SUBAGENT_ISO_CONTROLS = ("A.6.2.5",)` mirroring `SCHEDULER_ISO_CONTROLS`; tagged on every `subagent.*` chain row.

---

## 7. Privilege de-escalation model

- Parent grants `parent_tool_allow_list: frozenset[str]`; the spawn request carries `requested_tool_allow_list: frozenset[str]`.
- `narrow_tool_allow_list(*, parent, requested) -> frozenset[str]` returns `requested` iff `requested ⊆ parent`, else raises `SubAgentPrivilegeEscalation`. The granted set is `requested` (already proven ⊆), never a widening.
- **Provenance (Wave-1):** both lists are explicit inputs to the spawn seam. The primitive does **not** infer the parent set from the MCP host `list_tools` cache yet (deferred — keeps the primitive substrate-independent and avoids coupling to MCP host scoping before the harness exists).
- Enforcement lives at the `subagent/` boundary (the AGENTS.md privilege-de-escalation isolation boundary). Pure-functional + unit-proven before any dispatch wiring.

---

## 8. Budget model

- `compute_child_budget(*, parent_remaining_budget, child_pack_quota) = min(...)` (existing pure helper in `_seams.py`).
- **Parent-budget snapshot source (Wave-1):** a Sprint-11-local snapshot owned by `subagent/budget_resolver.py` (the real `ParentBudgetResolver` conformer). It does **not** depend on the Sprint-13.5 quota engine; the backing source is swappable later. The conformer is injected into `SchedulerEngine` via DI at construction; never imported by `core/scheduler/*`.
- Budget exhaustion mid-flight is a **scheduler preemption** (`preempt` → `quota_exhausted_in_flight`), not a spawn-time refusal. The parent is informed via the chain + the `invoke` return.

---

## 9. Depth model

- Global `Settings.subagent_max_recursion_depth: int = Field(default=3, ge=1, description=…)` in `core/config.py` (matches the repo Field pattern; `ge=1` because depth 1 = a single sub-agent with no further nesting). `core/` is a stop-rule → halt-before-commit on this edit.
- `check_depth(*, current_depth, max_depth)` raises `SubAgentDepthExceeded` when `current_depth >= max_depth`. ADR-005: a depth-exceed spawn is **escalated to a reviewer** → `EscalationStore.open(level="depth_exceeded", …)`.

---

## 10. Scheduler integration — **C3 made explicit**

"Every child task flows through the scheduler" (the ADR-005 / BUILD_PLAN exit criterion) means **sub-agent spawn calls `SchedulerEngine.submit()`** — no child-execution seam bypasses `core/scheduler`. It does **not** mean Sprint 11 ships full production Quota/KillSwitch conformers.

- `SchedulerEngine.submit()` traverses **pack_state → kill_switch → policy → quota → caps** (`BUILD_PLAN:913`, Option-A ordering). Quota + KillSwitch have only fail-loud `_Null*` sentinels and remain **Sprint 13.5**.
- **Wave-1 posture (no permissive fakes in production):**
  - Sprint 11 ships the **real `ParentBudgetResolver`** conformer (its job).
  - Scheduler `submit()` is exercised **with injected conformers at the test/DI level**. The unit/integration suites inject structural conformers for quota/kill-switch/pack-state to drive the green + refusal paths.
  - If a real conformer is cheap and honest, Sprint 11 may ship a **minimal real `PackStateInterrogator`** over `packs/storage` (`is_installed`). It ships **no** permissive/no-op quota or kill-switch conformer in any production path — those stay fail-loud until Sprint 13.5 injects the real engines.
  - A pre-13.5 production deployment that wants live sub-agent dispatch must inject the conformers at app startup; absent them, the path fails loud (production-grade rule), not silently.
- **The 11b valve must resolve:** whether 11b stays test/DI-runnable only, or ships the minimal real `PackStateInterrogator`. Either way: no permissive production quota/kill-switch fakes.

---

## 11. Cross-agent audit-chain verification (the Wave-1 "Merkle proof")

`subagent/audit_verifier.py` mirrors `verify_suspend_wake_linkage` (`chain_verifier.py:310`) — a per-row cross-row payload-linkage check, independent of the hash-walk (hash integrity is the separate, existing guarantee). For every child-linked `subagent.*` row carrying `payload["parent_record_id"]`:

1. Read `payload["parent_record_id"]` (a `record_id` of an earlier `subagent.spawn` emit).
2. Look up the `decision_history` row WHERE `record_id` = that value.
3. Assert the looked-up row's `decision_type` is `subagent.spawn`.
4. **Tenant-isolation parity** — assert the parent row's `tenant_id` (ROW COLUMN) equals the child row's `tenant_id` (closes the cross-tenant forged-linkage hole, exactly as the suspend/wake invariant #6).
5. **Causal ordering** — assert the parent row's `sequence` precedes the child row's `sequence` (a child linking forward to a later parent is not a genuine spawn).
6. Optional payload-field parity (e.g., `parent_trace_id` ↔ `child_trace_id` consistency).

Returns the first linkage break (first-break semantics), or `is_clean=True`. This is the `test_subagent_audit_chain.py` "Merkle proof over parent + child events verifies" guarantee. A literal Merkle tree is explicitly **not** built in Wave-1.

---

## 12. Stop-rule / critical-control surfaces

| Surface | Action | Stop-rule | Discipline |
|---|---|---|---|
| `subagent/*` (whole tree) | create | Yes — isolation/privilege boundary | every file halt-before-commit; `core-controls-engineer` + `/critical-module-mode`; 95/90 CC floor on substantive modules |
| `core/config.py` | + 1 Settings field (T2) | Yes (`core/`) | halt-before-commit |
| `core/decision_history.py` / `core/canonical.py` / `core/chain_verifier.py` | **consume only** | Yes | no edits by design (payload-only linkage; new verifier module) |
| `protocol/ui_events.py` | wire emit hooks (T9) | Yes (ADR-020 wire-public) | backward-compatible; never rename the 4 models |
| `core/scheduler/*` | consume via DI | Yes (`core/`) | conformer injected, never imported by scheduler (AST guard) |
| `core/escalation.py` | consume only | Yes | call `open()/transition()`; no edit |
| ADR-005 / BUILD_PLAN | T0 amendments | doctrine | recorded before implementation |

---

## 13. Error handling / refusal taxonomy

- **Spawn-time refusals (subagent's own closed enum):** `subagent_depth_exceeded`, `subagent_privilege_escalation`, `subagent_parent_budget_exhausted`. Carried by typed exceptions `SubAgentDepthExceeded` / `SubAgentPrivilegeEscalation` (+ a budget exception). Depth-exceed also opens an escalation.
- **Scheduler refusals:** propagated unchanged (`refused_queue_full` / `refused_quota_exhausted` / `refused_policy_denied` / `refused_kill_switch_active` / `refused_pack_not_installed`).
- **In-flight failures:** budget exhaustion → `preempt` (`quota_exhausted_in_flight`); parent cancellation cascade → `cancel` (`parent_run_cancelled`).
- **Production-grade rule:** unwired seams fail loud (`NotImplementedError`), never silently permit.

---

## 14. Testing strategy

**The 6 ADR-005 / BUILD_PLAN tests** (`tests/unit/subagent/`):
- `test_subagent_spawn.py` — parent spawns child, child returns result, parent context unchanged.
- `test_subagent_privilege.py` — child cannot escalate to a tool the parent lacks.
- `test_subagent_depth.py` — depth-4 beyond `max_depth=3` → `SubAgentDepthExceeded` + escalation.
- `test_subagent_budget.py` — exceeding token budget → scheduler preempts child + parent informed.
- `test_subagent_scheduler_inheritance.py` — child cannot exceed parent remaining budget or bypass scheduler policy by spawning recursively; **no path bypasses `core/scheduler`**.
- `test_subagent_audit_chain.py` — cross-agent linkage verifies; tamper-negative.

**Plus:**
- **Drift detectors (test-only, no runtime cross-import** per `[[feedback_drift_detector_test_only_no_runtime_import]]`**):** subagent closed-enum vocab; audit↔UI vocabulary map; ISO-control tuple; `subagent` family `.well-known` schema snapshot byte-stability.
- **Negative paths (CC):** privilege escalation, depth exceed, budget preempt, recursive bypass attempt, tampered parent/child linkage — each with threat-model-revert verification per `[[feedback_security_regression_hardening]]`.
- **Integration:** spawn→return through a real (test-injected) `SchedulerEngine` with structural conformers; live-DB row-lock paths behind `COGNIC_RUN_*_INTEGRATION` env flags.
- **Coverage gate:** 11a + 11b `subagent/` modules promoted at Z1a/Z1b (90 → N) at the 95/90 floor on **fresh `--cov-branch coverage.json` in the promoting commit** per `[[feedback_verify_promotion_meets_floor_at_promotion_time]]`; `_EXPECTED_ENTRY_COUNT` bumped in lockstep. Gate ladder: mypy/ruff full-tree at halt; full pytest at commit per `[[feedback_gate_ladder_per_microfix]]`.

---

## 15. Task split (11a / 11b)

**T0 — source-of-truth reconciliation (docs only; before T1).** ADR-005 amendments (in-process dispatch; global depth cap) + BUILD_PLAN Sprint-11 wording (drop `decision_history.py` extension; A2A→Wave-2; add schedule-risk row; reword tests/exit-criteria so "Merkle proof" = payload-linkage). Halt.

**11a — core primitive (pure; lands independently):**
- **T1** — `subagent/__init__.py` (package marker) + `subagent/_types.py` (closed-enum `SubAgentRefusalReason`; `SubAgentDepthExceeded`/`SubAgentPrivilegeEscalation`/budget exceptions; frozen spawn-request + policy dataclasses; `SUBAGENT_ISO_CONTROLS`) + drift detectors.
- **T2** — `core/config.py` global depth field (halt) + `subagent/policy.py` (pure privilege subset + depth cap; budget delegates to `compute_child_budget`).
- **T3** — `subagent/audit.py` (4 decision_types + ISO tuple + parent-chain emit via `DecisionHistoryStore.append` + child-genesis `payload["parent_record_id"]` linkage).
- **T4** — `subagent/audit_verifier.py` (cross-agent payload-linkage verifier mirroring `verify_suspend_wake_linkage`).
- **Z1a** — CC-gate promotion of 11a modules (fresh `--cov-branch`) + **valve check** (proceed to 11b or stop).

**11b — integration:**
- **T5** — `subagent/budget_resolver.py` (real `ParentBudgetResolver` over the local snapshot; DI-injected).
- **T6** — `subagent/spawn.py` (in-process scheduler-mediated dispatch; resolves the C3 conformer choice).
- **T7** — `subagent/__init__.py` `SubAgent` facade + `invoke(prompt)`.
- **T8** — minimal harness exposure (`spawn_subagent` seam) — not a broad harness.
- **T9** — `protocol/ui_events.py` emit-hook wiring (via `register_append_hook`) + audit↔UI map; `.well-known` snapshot unchanged.
- **T10** — **closeout reconciliation only** (closeout note; verify ADR-005/BUILD_PLAN already amended at T0; no first-time amendments).
- **Z1b** — CC-gate promotion of 11b modules + full gate ladder.

---

## 16. Open items to resolve at the 11b gate

1. **C3 conformer choice:** 11b stays test/DI-runnable only, **or** ships a minimal real `PackStateInterrogator` over `packs/storage`. No permissive production quota/kill-switch fakes either way.
2. **Harness exposure shape:** the minimal `spawn_subagent` seam — standalone function vs a thin agent-context object — and where it lives (`subagent/` public API vs a first `harness/` module). Decide once the primitive API is stable.
3. **Audit↔UI mapping specifics:** confirm whether `subagent.start` / `subagent.budget` get any UI surface or remain payload-only on `completed`/`failed`.
4. **Scheduler app-wiring scope:** whether 11b wires `SchedulerEngine` into `portal/api/app.py`, or the sub-agent primitive constructs/holds its scheduler for Wave-1 (currently scheduler is test-only constructed).

---

## 17. ADR status & references

- **ADR-005** (APPROVED) — amended at T0 for Wave-1 in-process dispatch + global depth cap (additive; no semantic reversal).
- **ADR-003** (A2A) — transport substrate; cross-pod dispatch deferred to Wave 2.
- **ADR-022** (scheduler) — `ParentBudgetResolver` seam consumed; substrate independence preserved.
- **ADR-006** (ISO mapping) — `A.6.2.5` tags on `subagent.*` rows.
- **ADR-020** (UI events) — existing `subagent` family wired, not renamed.
- **BUILD_PLAN** — Sprint-11 deliverables reworded at T0; schedule-risk row added.

---

*End of draft. No code written. Awaiting review before commit; on approval, the next step is `writing-plans` to produce the task-by-task plan-of-record.*
