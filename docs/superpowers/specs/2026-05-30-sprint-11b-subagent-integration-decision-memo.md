# Sprint 11b — Sub-agent integration: decision memo

**Status:** DECISIONS LOCKED (2026-05-30) — the three deferred decisions, confirmed before 11b code. **No re-litigation of ADR-005 or 11a.**
**Date:** 2026-05-30. **Branch:** `feat/sprint-11b-subagent-integration` (off `main` @ `6d3285e`).
**Inputs:** Sprint 11 spec §16 (deferred decisions); the 11a reviewer residual (budget naming); the 11b inputs recorded in `project_state_2026_05_30.md`.
**Scope:** three decisions, one consequence table, one task delta — that's it.

## Verified facts (drive the table)
- **Scheduler is NOT app-wired.** `portal/api/app.py` has zero scheduler references; `SchedulerEngine` is constructed only in `tests/unit/core/scheduler/test_engine.py`. `submit()` traverses pack_state → kill_switch → policy → quota → caps, with `QuotaInterrogator`/`KillSwitchInterrogator` defaulting to fail-loud `_Null*` sentinels.
- **A real minimal `PackStateInterrogator` is thin + substrate-backed.** `PackRecord.state: PackState` exists and `"installed" ∈ PackState`; the seam (`core/scheduler/_seams.py`) already notes a closure over `packs/storage` is sufficient. So `is_installed(tenant_id, pack_id)` is a thin `packs/storage` read checking `state == "installed"` — real, not stubbed.
- **Budget naming.** `subagent/policy.compute_spawn_budget` raises the parent-centric `SubAgentBudgetExhausted` whenever `granted == 0`, including a `child_pack_quota == 0` case with a non-zero parent.

## Decisions (locked)

### D1 — Scheduler conformer posture: **test/DI-runnable only** (+ ship a real minimal `PackStateInterrogator`)
`QuotaInterrogator` + `KillSwitchInterrogator` stay the fail-loud `_Null*` sentinels; **real implementations remain Sprint 13.5**. No permissive/no-op fakes in any production path. Ship the **real minimal `PackStateInterrogator`** (a thin `packs/storage`-backed closure checking `state == "installed"`), injected via DI. Because the scheduler is not app-wired and Quota/KillSwitch are Null, a production `submit()` **fails loud until 13.5** — so 11b exercises the scheduler-mediated path only under an **injected** `SchedulerEngine` + conformers in tests. **11b is explicitly NOT a deployable production dispatch path; do not app-wire the scheduler runtime in 11b** (that, plus real Quota/KillSwitch, is Sprint 13.5 + a deploy step).

### D2 — Harness exposure: **thin standalone `spawn_subagent(...)` seam first**
The public spawn surface is a module-level `subagent.spawn_subagent(...)` callable plus the `SubAgent` facade's `invoke(prompt)`. **No `harness/base_agent.py` / agent-context object in 11b** — defer it until the code genuinely needs an agent-context object (a thin seam doesn't). `spawn_subagent(...)` takes the explicit spawn inputs + the injected `SchedulerEngine` + audit emitter, and returns the child result + the spawn `record_id`.

### D3 — Budget refusal vocabulary: **split before runtime exposure** *(LOCKED 2026-05-30)*
Once 11b exposes spawn, a zero **child** quota must not surface as "parent exhausted." **Locked: split** — add a distinct closed-enum value `subagent_child_quota_zero` + a `SubAgentChildQuotaZero` exception; `compute_spawn_budget` raises parent-exhausted only when `parent_remaining_budget == 0`, child-quota-zero when `child_pack_quota == 0`. `subagent_parent_budget_exhausted` stays parent-only. (Generalize-with-`cause`-field was the rejected alternative — split gives crisper wire vocab.) This is a **wire-public closed-enum change** to `subagent/_types.SubAgentRefusalReason` (drift-detector-pinned), done **early in 11b, before the spawn seam exposes it.**

## Consequence table

| Decision | Locked choice | Key consequence |
|---|---|---|
| **D1 conformers** | test/DI-only Quota+KillSwitch (Null → 13.5); real minimal `PackStateInterrogator` | **No live production dispatch path** — scheduler not app-wired + Null sentinels fail loud; 11b is test/DI-proven, production end-to-end gated on 13.5 + a separate app-wiring/deploy step |
| **D2 harness** | thin `spawn_subagent(...)` seam; no `harness/` | **API surface = `subagent.spawn_subagent(...)` + `SubAgent(...).invoke(prompt)`** |
| **D3 budget** | split refusal vocab | **Wire vocab += `subagent_child_quota_zero`**; `subagent_parent_budget_exhausted` stays parent-only |

## Task delta vs the 11a plan's 11b outline
- **NEW T4.5 (do first):** D3 budget-vocab split — `subagent/_types.py` (closed-enum + exception) + `compute_spawn_budget` + drift detector. Small; lands before T6 exposes spawn.
- **T5 `subagent/budget_resolver.py`:** unchanged (real `ParentBudgetResolver` over local snapshot) **+ ship the real minimal `PackStateInterrogator`** (D1), DI-injected.
- **T6 `subagent/spawn.py`:** scheduler-mediated dispatch under an **injected** `SchedulerEngine` + conformers (D1, no app-wiring); proves "every child flows through the scheduler" in tests (production end-to-end deferred to 13.5).
- **T7 `SubAgent` facade:** unchanged.
- **T8 harness exposure → thin `spawn_subagent(...)` seam** (D2), not a `harness/` package.
- **T9 `ui_events` emit hooks / T10 closeout / Z1b:** unchanged; T10 records the production-path-deferred-to-13.5 honesty + the D1/D2/D3 locks.

## The three outputs you asked for
1. **Production path 11b exposes:** none live end-to-end — scheduler not app-wired; Quota/KillSwitch Null until 13.5. 11b ships a test/DI-proven primitive; live production dispatch is a 13.5 + deploy concern.
2. **API surface to spawn:** `subagent.spawn_subagent(...)` + `SubAgent(...).invoke(prompt)`; no new `harness/` module.
3. **Wire-public budget vocab going forward:** `subagent_parent_budget_exhausted` (parent == 0) + new `subagent_child_quota_zero` (child == 0).

---
*End of memo. No code. On approval, this feeds a tight 11b plan (writing-plans) over the T4.5 → Z1b delta above.*
