# Sprint 11b — Sub-agent Integration — Pre-Merge Closeout Report

**Date:** 2026-05-31
**Branch:** `feat/sprint-11b-subagent-integration`
**Head at verification:** `8b47e2e`
**Branch distance:** 9 commits ahead of `main` (`6d3285e`)
**State:** READY-FOR-PR / HOLD. Code, full suite, the per-file critical-controls
gate (against fresh `--cov-branch coverage.json`), and ruff/mypy are green. The
Sprint 11b CODE-COMPLETE marker is recorded; the Sprint 11 `CLOSED` marker
remains **merge-time only**.

## Scope

Sprint 11b completes the ADR-005 sub-agent primitive on top of the merged 11a
core (`subagent/_types` + `policy` + `audit` + `audit_verifier`, CC gate 90→94).
11b ships the integration layer:

- the scheduler-mediated in-process spawn orchestrator (`subagent/spawn.py`),
- the real DI conformers (`subagent/conformers.py`),
- the `SubAgent` facade + the thin `spawn_subagent(...)` seam (`subagent/_facade.py`),
- the subagent UI emit hooks (`protocol/ui_events.py`),

as a **test/DI-proven** increment — NOT a live production dispatch path.

Spec/plan/memo for this sub-sprint:

- `docs/superpowers/specs/2026-05-30-sprint-11b-subagent-integration-decision-memo.md`
- `docs/superpowers/plans/2026-05-30-sprint-11b-subagent-integration.md`

## Decisions Locked

| Lock | Decision |
|---|---|
| **D1** | 11b is a primitive-with-test/DI proof, NOT a deployable production dispatch path. The scheduler is **not** app-wired in 11b; the spawn flow is exercised through injected conformers + a fake/real `ChildRunner`. |
| **D2** | The harness surface is a thin module-level `spawn_subagent(...)` seam over `SubAgent.invoke(...)` — **no** `harness/` package, **no** `base_agent.py`. |
| **D3** | The budget refusal vocabulary is split — `subagent_child_quota_zero` (top-level zero pack quota) is distinct from `subagent_parent_budget_exhausted` (narrowed-to-zero against a parent). |
| **A-projector** (T9) | The `recursion_capped` UI event is sourced from the scoped `escalation.opened` row (the T6 depth-refusal evidence — depth refusals refuse BEFORE emitting `subagent.spawn`). The projector mapping is wired + DI-proven; the **production** emission additionally needs escalation rows routed to the `UIEventEmitter`, which is app-wiring deferred (see Production Path Deferred). `core/escalation.py` was NOT touched. |

`ChildRunner` takes a frozen `ChildRunContext` object (not loose kwargs).

## What Shipped

| Module | Task | Role |
|---|---|---|
| `subagent/_types.py` (extended) | T4.5 | +`subagent_child_quota_zero` refusal value + `SubAgentChildQuotaZero` exception (D3). |
| `subagent/policy.py` (extended) | T4.5 | `compute_spawn_budget` splits the zero-quota refusals before delegation. |
| `subagent/conformers.py` (new) | T5 | `LocalParentBudgetResolver` (fail-loud on unknown parent) + `PackStoreStateInterrogator` (matches the LOGICAL `pack_id` via paginated `list_for_tenant(state="installed")` — NOT `store.load`). |
| `subagent/spawn.py` (new) | T6 | `SubAgentSpawner` — threads every spawn through the real `SchedulerEngine` (policy gate → emit_spawn → submit → mark_running → run child → complete/preempt/fail → emit return + budget). Non-leaky on all 5 admission outcomes (refused / queued-cancel / over-budget-preempt / not-ok-fail / ok-complete). |
| `subagent/_facade.py` (new) | T7 + T8 | `SubAgent` facade (reads `Settings.subagent_max_recursion_depth`, delegates to the spawner) + the module-level `spawn_subagent(...)` seam (D2). |
| `protocol/ui_events.py` (extended) | T9 | Subagent emit hooks: `subagent.spawn`→`spawned`; `subagent.return` ok→`completed`/not-ok→`failed`; scoped `escalation.opened`→`recursion_capped`. The 4 UI models are unchanged (`.well-known` byte-stable). |
| `tools/check_critical_coverage.py` + its test | Z1b | CC gate 94→97 (`spawn` + `conformers` + `_facade`). |

## Commits

| Commit | Summary |
|---|---|
| `a093810` | decision memo — D1/D2/D3 |
| `5100c82` | plan-of-record (T4.5→Z1b; ChildRunner takes ChildRunContext) |
| `5806cbe` | T4.5 split budget refusal vocab (child_quota_zero) |
| `14499d0` | T5 real ParentBudgetResolver + PackStateInterrogator conformers + ChildRunner protocol |
| `a4efe67` | T6 scheduler-mediated in-process spawn orchestrator |
| `4c5fb6b` | T7 SubAgent facade |
| `87ba7e6` | T8 thin spawn_subagent seam |
| `0181309` | T9 wire subagent UI emit hooks |
| `8b47e2e` | Z1b promote 11b modules to the CC gate (94→97) |

(T10 closeout commit adds this report + the BUILD_PLAN marker.)

## Verification

All verification below ran at `8b47e2e` (Z1b), unchanged by the docs-only T10:

| Verification | Result |
|---|---|
| `uv run pytest -q` (full suite) | PASS — `8686 passed / 94 skipped / 0 failed` in `644.92s` |
| `uv run pytest -q --cov=cognic_agentos --cov-branch --cov-report=json -m "not postgres and not oracle"` | fresh `coverage.json` for the gate |
| `uv run python tools/check_critical_coverage.py` | PASS — all 97 modules at floor |
| `uv run pytest tests/unit/tools/test_check_critical_coverage.py -q` | PASS — `27 passed` (count 97 + 11b presence test) |
| `uv run ruff check .` | PASS |
| `uv run ruff format --check` (touched files) | PASS |
| `uv run mypy src tests` | PASS — `624 source files` |

Critical-control coverage from the fresh `coverage.json` — the 3 Z1b promotions
(per `feedback_verify_promotion_meets_floor_at_promotion_time`, gate run against
fresh data in the promoting commit):

| Module | Line | Branch | Floor |
|---|---:|---:|---|
| `src/cognic_agentos/subagent/spawn.py` | 100.00% | 100.00% | 95/90 |
| `src/cognic_agentos/subagent/conformers.py` | 100.00% | 100.00% | 95/90 |
| `src/cognic_agentos/subagent/_facade.py` | 100.00% | 100.00% | 95/90 |

`subagent/_types.py` + `subagent/policy.py` stay on-gate from 11a Z1a (extended
by 11b, NOT re-added); `subagent/__init__.py` stays off-gate per Doctrine F.

## Production Path Deferred

11b is test/DI-proven (D1). The live production dispatch path remains deferred,
consistent with the ADR-005 Sprint-11 amendment:

- **Scheduler not app-wired.** No `create_app` wiring binds the `SubAgentSpawner`
  to a running `SchedulerEngine`; the flow runs only under injected conformers.
- **Real `QuotaInterrogator` + `KillSwitchInterrogator` are Sprint 13.5.** Pre-13.5
  production wiring still defaults to fail-loud `_Null*` seam sentinels; 11b tests
  inject conformers/stubs to prove the spawn path without shipping permissive
  production fakes. The real emergency-controls conformers bind via the AgentOS DI
  binder at Sprint 13.5.
- **`recursion_capped` UI emission needs app-wiring.** The projector mapping is
  wired + DI-proven, but `EscalationStore` writes via its own
  `DecisionHistoryStore` instance (`escalation.py:465`) the `UIEventEmitter` does
  not hook, so depth-refusal escalation rows do not reach the emitter until that
  routing is added in app-wiring. `core/escalation.py` was deliberately NOT
  touched in 11b.
- **A2A endpoint transport (cross-pod hop) is Wave 2** per ADR-005.

## ADR Status

**No new ADR amendment.** ADR-005 was already amended at 11a T0 (the
"Sprint 11 amendment (2026-05-30)" section: Wave-1 in-process scheduler-mediated
dispatch + global `Settings.subagent_max_recursion_depth`). 11b ships exactly
within that amended envelope; D1/D2/D3 are implementation-posture locks recorded
in the 11b memo, not ADR contract changes. Verified consistent at T10.

## Remaining Human-Only Steps

- Push the branch.
- Open the PR.
- Merge after review.
- Add the Sprint 11 `CLOSED` marker only at the PR merge, with the merge commit
  hash and final branch-commit count. (Sprint 11 = 11a MERGED + 11b merged.)

No push, PR, merge, or `CLOSED` marker is performed by this closeout report.
