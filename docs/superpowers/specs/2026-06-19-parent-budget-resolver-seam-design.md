# Parent budget resolver seam — Design (ADR-005 / ADR-022)

**Status:** approved 2026-06-19; **revised 2026-06-19 (post-recon)** — see the Revision note. Slice **(a) resolver seam only** — the read primitive + composition wiring. The live sub-agent dispatch caller + the sibling/shared-pool depletion ledger are the *next* slice **(b)**.

> **Revision note (post-recon).** The initial design assumed greenfield. Recon then found a **Sprint-11b** `subagent/conformers.py::LocalParentBudgetResolver` — an in-memory `dict[uuid.UUID, int]` snapshot conformer (caller-pre-populated, fail-loud `KeyError`, OLD signature) — consumed by the **dormant, NOT-production-wired** `subagent/spawn.py::SubAgentSpawner` (`build_runtime` constructs neither; it imports only `PackStoreStateInterrogator` from that module). Two consequences: **(1)** to avoid a name collision, the scheduler-task-backed resolver this slice adds is named **`SchedulerTaskParentBudgetResolver`** (NOT `LocalParentBudgetResolver`); **(2)** the `*, tenant_id` Protocol extension breaks those dormant `subagent/` consumers, so the boundary widens from *no `subagent/` touch* to **minimal `subagent/` compatibility touch only** — a mechanical signature update of dormant code, NO live-dispatch semantics. `subagent/` is a stop-rule area: this touch carries the extra scrutiny + `core-controls-engineer` discipline.

## 1. Goal

Make parent → child token-budget inheritance real by landing a production `SchedulerTaskParentBudgetResolver` (a scheduler-task-backed resolver, distinct from the pre-existing dict-snapshot `subagent/conformers.py::LocalParentBudgetResolver`), wiring it into `build_runtime` to replace the `_NullParentBudgetResolver` fail-loud sentinel that today makes **every** scheduler sub-agent submit (`SubmitInput.parent_task_id` set) raise `NotImplementedError` at `SchedulerEngine.submit()`. This unblocks governed sub-agent budget inheritance (ADR-005) and gives Sprint 15A (workflow orchestration) a live budget primitive to stand on.

**Boundary (revised):** seam + wiring + a **minimal `subagent/` compatibility touch only** — a signature-compat update of the dormant Sprint-11b consumers (`conformers.py` gains an ignored `tenant_id` kwarg keeping dict-snapshot + `KeyError`; `spawn.py::_resolve_budget` passes `request.tenant_id`; subagent tests updated for the signature only). NO live dispatch caller, NO `SubAgentSpawner` production wiring, NO change to subagent dispatch semantics (`compute_spawn_budget` + the spawn refusals untouched), no sibling ledger, no workflow orchestration, no scheduler refusal-vocabulary / Rego change, no migration.

## 2. Context — the seam as-built (recon)

- `core/scheduler/_seams.py` declares the consumer-owned `ParentBudgetResolver` Protocol (`async def remaining_budget_for(self, parent_task_id: uuid.UUID) -> int`) — "pure read-only seam — does NOT mutate the parent task's budget" — plus the `_NullParentBudgetResolver` sentinel whose `remaining_budget_for` raises `NotImplementedError` ("propagates fail-loud (**NOT** a closed-enum refusal)").
- `core/scheduler/engine.py` already wires the consult (Sprint 10.5 T10): when `submit_input.parent_task_id is not None`, it parses the UUID (malformed → the existing closed-enum `SchedulerSubmitInputInvalid(field="parent_task_id")` input-validation refusal), then `parent_remaining = await self._parent_budget.remaining_budget_for(parent_uuid)`, then `effective_tokens = compute_child_budget(parent_remaining_budget=…, child_pack_quota=submit_input.requested_estimated_tokens)`, and threads the narrowed `effective_tokens` through **all 5** admission gates (quota etc.) + every refusal/audit path.
- `compute_child_budget(*, parent_remaining_budget, child_pack_quota) -> int` returns `min(child_pack_quota, parent_remaining_budget)` (both non-negative; pure).
- The budget figure already exists: `scheduler_tasks.requested_estimated_tokens` is persisted per task (`core/scheduler/storage.py`); `runs.task_id` links a managed run to its scheduler task.
- `harness/runtime.py::build_runtime` constructs `SchedulerEngine` with `parent_budget_resolver` **OMITTED** → the `_NullParentBudgetResolver` sentinel (Fork E; deferred to "14A / Sprint 11").
- `SchedulerTaskState` = `{pending, running, completed, failed, cancelled, preempted, expired}` — **non-terminal** = `{pending, running}`; **terminal** = `{completed, failed, cancelled, preempted, expired}`.
- **(Post-recon correction) the Sprint-11b sub-agent spawn path already exists but is DORMANT:** `subagent/conformers.py::LocalParentBudgetResolver` (an in-memory `dict[uuid.UUID, int]` snapshot conformer, fail-loud `KeyError`, NOT `scheduler_tasks`-backed) + `subagent/spawn.py::SubAgentSpawner` (its OWN `_parent_budget` injection, its OWN `compute_spawn_budget`, its OWN `SubAgentChildQuotaZero`/`SubAgentBudgetExhausted` refusals; `_resolve_budget` calls `remaining_budget_for(uuid.UUID(parent_task_id))` on the OLD signature). **Neither is constructed by `build_runtime`** (it imports only `PackStoreStateInterrogator` from `conformers.py`). This slice neither wires nor changes the spawn path's semantics — it only signature-compat-updates those two consumers (+ their tests) for the Protocol extension.

## 3. The locked contract

**Signature (seam extended):**
```python
async def remaining_budget_for(self, parent_task_id: uuid.UUID, *, tenant_id: str) -> int
```
The `*, tenant_id` is **new** (the existing Protocol had no tenant). The engine passes `submit_input.tenant_id`; the resolver tenant-scopes the parent lookup so a parent in another tenant is invisible.

**Semantics — granted-budget snapshot (ceiling inheritance):**
- Returns the parent task's **granted** token budget (`scheduler_tasks.requested_estimated_tokens`), tenant-scoped. It is a **snapshot**, not a live decrementing balance.
- The child's effective budget becomes `min(child_pack_quota, parent_granted)` (existing `compute_child_budget`).
- This is a **ceiling-inheritance read primitive**, not a sibling-spend ledger. "True remaining after sibling fan-out" (depleting a finite shared pool as children draw) is explicitly deferred to slice (b), which is the layer that has *live child reservations* to track.

**Eligible parent:** non-terminal `{pending, running}`.

**Failure modes — fail-loud, typed, engine-propagated (NOT a scheduler refusal):**
- Absent **or** cross-tenant → `ParentTaskBudgetUnavailable("parent_not_found")`. Cross-tenant collapses to `parent_not_found` per the repo's cross-tenant-invisibility doctrine — a valid UUID outside the tenant reads like absence, never leaking that another tenant's task exists, and callers are not taught to distinguish "absent" from "forbidden foreign object".
- Terminal (`{completed, failed, cancelled, preempted, expired}`) → `ParentTaskBudgetUnavailable("parent_terminal")`.
- The engine does **not** catch this — it propagates fail-loud out of `submit()`, preserving the `_NullParentBudgetResolver` doctrine (parent-budget-resolution failures are fail-loud exceptions, not closed-enum scheduler refusals). **No** `scheduler.admission_refused` row, **no** `SchedulerRefusalReason` value, **no** Rego change. A typed exception is honest evidence (vs a misleading `0`, which would look like a legitimate "parent has no budget" and produce confusing downstream refusals); slice (b)'s live caller owns how to surface it.

**Unchanged:** a **malformed** `parent_task_id` (not a UUID string) remains the existing `SchedulerSubmitInputInvalid(field="parent_task_id")` input-validation refusal — that is *input* validation, distinct from a valid-UUID-but-invalid-*reference* resolution failure.

## 4. Components / file plan

| File | Gate | Change |
|---|---|---|
| `core/scheduler/_seams.py` | **off**-gate | Extend the `ParentBudgetResolver` Protocol + the `_NullParentBudgetResolver` sentinel signatures with `*, tenant_id: str`. Add the `ParentTaskBudgetUnavailable(Exception)` typed exception carrying a 2-value `Literal["parent_not_found", "parent_terminal"]` `reason`. (`_seams.py` stays off-gate per its existing doctrine — the substantive enforcement is in the resolver + the engine consumer; closed-enum drift is pinned by a test.) |
| `core/scheduler/storage.py` | **on**-gate (CC stop-rule) | Add a **pure-read** `get_budget_snapshot(task_id: uuid.UUID, *, tenant_id: str) -> _BudgetSnapshot \| None` (a small frozen `_BudgetSnapshot(granted_tokens: int, state: SchedulerTaskState)`). The `WHERE task_id = :id AND tenant_id = :tenant` **is** the cross-tenant boundary → absent **or** cross-tenant both yield `None`. A module-private `_build_*_stmt` shared between the production path and a SQL-shape regression (the `packs/storage.py` shared-builder pattern). **No new column, no migration.** |
| `core/scheduler/budget_resolver.py` | **NEW, on**-gate (CC 131 → 132) | `SchedulerTaskParentBudgetResolver(storage)` — **renamed from `LocalParentBudgetResolver` to avoid the Sprint-11b `subagent/conformers.py` collision**: `remaining_budget_for` calls `storage.get_budget_snapshot(...)` → `None` → raise `ParentTaskBudgetUnavailable("parent_not_found")`; state ∈ terminal set → raise `ParentTaskBudgetUnavailable("parent_terminal")`; else return `snapshot.granted_tokens`. The substantive parent-budget-inheritance authority (tenant-scoped absence + terminal refusal + the inherited ceiling). 95/90 floor; verify-at-promotion on fresh `--cov-branch`. |
| `core/scheduler/engine.py` | **on**-gate | The **one** call-site change: pass `tenant_id=submit_input.tenant_id` into `remaining_budget_for(parent_uuid, tenant_id=…)`. The consult + `compute_child_budget` + the narrowed-`effective_tokens` threading already exist. |
| `subagent/conformers.py` + `subagent/spawn.py` + subagent tests | **`subagent/` stop-rule** | **Minimal compatibility touch — SIGNATURE ONLY.** `conformers.py::LocalParentBudgetResolver.remaining_budget_for(parent_task_id, *, tenant_id)` accepts + **IGNORES** `tenant_id` (keeps the dict-snapshot lookup + `KeyError`); `spawn.py::_resolve_budget(*, parent_task_id, requested, tenant_id)` threads `request.tenant_id` into its `remaining_budget_for` call; subagent tests that construct the conformer / local stubs gain the kwarg. **NO** change to spawn dispatch semantics (`compute_spawn_budget`, the spawn refusals, the un-wired `SubAgentSpawner` all untouched). `core-controls-engineer` discipline (privilege-de-escalation boundary). |
| `harness/runtime.py` | **off**-gate (composition root) | Construct `SchedulerTaskParentBudgetResolver(storage=SchedulerStorage(engine))` and inject it as `parent_budget_resolver=` into the `SchedulerEngine` (the cache-conditional scheduler block), replacing the OMITTED → sentinel. **The scheduler-backed resolver — NOT the Sprint-11b dict-snapshot `subagent/conformers.py::LocalParentBudgetResolver`.** |

**Data/policy split (per the on-gate rationale):** the storage read owns *only* the data fetch + the tenant boundary; the **resolver** owns the policy interpretation — tenant-scoped absence (`parent_not_found`), terminal-state refusal (`parent_terminal`), and the inherited ceiling returned to the scheduler. That budget authority is why `budget_resolver.py` is on-gate even though it is small.

## 5. Flow

**A `parent_task_id` submit:** `engine.submit()` → (existing) `uuid.UUID(parent_task_id)` parse (malformed → `SchedulerSubmitInputInvalid`) → `remaining_budget_for(parent_uuid, tenant_id=submit_input.tenant_id)` → resolver reads the tenant-scoped snapshot → raise (`parent_not_found` / `parent_terminal`) **or** return `granted_tokens` → `compute_child_budget(min(child_pack_quota, granted))` → the narrowed `effective_tokens` flows through the existing 5 admission gates (quota etc.) and every audit/refusal path.

**A parentless submit (`parent_task_id=None`):** untouched — the resolver is never consulted; `effective_tokens = requested_estimated_tokens`. (Proven explicitly unchanged.)

**Resolver raise:** propagates fail-loud out of `submit()`. No `scheduler.admission_refused` row, no state mutation, no quota reservation.

## 6. CC / scope / posture

- **CC 131 → 132** — `core/scheduler/budget_resolver.py` lands on the durable per-file coverage gate (95% line / 90% branch), verified at promotion on fresh `--cov-branch coverage.json`.
- `core/scheduler/storage.py` (already on-gate) gains a pure-read method, held to the same floor.
- `core/scheduler/_seams.py` + `harness/runtime.py` stay off-gate.
- **No migration** (reads the existing `requested_estimated_tokens` column).
- **No** `SchedulerRefusalReason` / `scheduler.rego` change; **no** `scheduler.admission_refused` row for invalid parents; **no** live dispatch caller; **no** `SubAgentSpawner` production wiring; **no** change to spawn dispatch semantics; **no** sibling/shared-pool ledger; **no** workflow orchestration; **no** Option C.
- **`subagent/` IS touched — minimally + signature-only.** The `*, tenant_id` Protocol extension breaks the dormant Sprint-11b consumers, so `conformers.py::LocalParentBudgetResolver` (gains an IGNORED `tenant_id` kwarg) + `spawn.py::_resolve_budget` (threads `request.tenant_id`) + the subagent tests get a mechanical sig-compat update. `subagent/` is a stop-rule isolation boundary — this edit carries `core-controls-engineer` + extra scrutiny but introduces **NO** new dispatch behavior. The CC count change stays **131 → 132** (only the new `budget_resolver.py` is gate-promoted; `conformers.py`/`spawn.py` are already `subagent/` stop-rule, not per-file-coverage-gated).

## 7. Testing

- **Resolver unit** (`budget_resolver.py`, on-gate floor): happy path (returns `granted_tokens`); not-found (absent task → `parent_not_found`); cross-tenant (task in tenant B, resolver called with tenant A → snapshot `None` → `parent_not_found`); **each** terminal state → `parent_terminal`; `pending` + `running` → return budget. Assert the exception type **and** the closed-enum `reason`.
- **Storage-read unit** (`storage.py`): tenant-scoped (cross-tenant → `None`); absent → `None`; present → `_BudgetSnapshot(granted_tokens, state)`. A SQL-shape regression imports the shared `_build_*_stmt` and asserts the compiled `WHERE` carries both `task_id` and `tenant_id` (shared-builder pattern — no vacuous duplicate-`select` proof).
- **Engine integration** (real resolver over in-memory sqlite storage): a `parent_task_id` submit where `parent_granted < child_pack_quota` → child `effective_tokens == parent_granted` (the **ceiling bites** — the "exhaustion / narrowing" proof); `parent_granted ≥ child_pack_quota` → `effective_tokens == child_pack_quota`; a **parentless** submit → `effective_tokens == requested_estimated_tokens` (unchanged); a resolver raise (`parent_not_found` / `parent_terminal`) propagates out of `submit()` fail-loud — assert the type + reason and assert **zero** `scheduler.admission_refused` rows + no state/quota mutation.
- **Composition** (`build_runtime`): the cache-on path wires the real `SchedulerTaskParentBudgetResolver` (not the sentinel) — a `parent_task_id` submit no longer raises `NotImplementedError`; the gateway-only (cache-off) path's scheduler stays `None` (unchanged).
- **Subagent sig-compat (regression-only)**: the existing subagent suites (`test_subagent_spawn.py` / `test_subagent_facade.py` / `test_spawn_subagent_seam.py`) stay green after the `conformers.py` + `spawn.py` sig update — proving the compatibility touch is behavior-neutral (the dict-snapshot resolver still returns its snapshot value / `KeyError`; the spawn budget flow is unchanged). NO new subagent behavior is added or asserted.
- **Drift**: `ParentTaskBudgetUnavailable.reason` 2-value `Literal` pinned by a closed-enum count/value test.

## 8. Out of scope (the next slice (b))

The live sub-agent dispatch caller (wiring the dormant `subagent/spawn.py::SubAgentSpawner` into production through the `subagent/` privilege-de-escalation boundary, ADR-005); **reconciling the two budget designs** (the scheduler-level `compute_child_budget` + `SchedulerTaskParentBudgetResolver` vs the subagent-level `compute_spawn_budget` + the dict-snapshot `LocalParentBudgetResolver` — whether the spawn path should consult the scheduler-backed resolver, and whether a double consult (spawner + scheduler) is intended); the sibling/shared-pool depletion ledger (true running-remaining as children draw against a finite parent pool); and any workflow-orchestration consumer. With the budget seam live + testable after this slice, (b) is "wire the caller on top of a live seam" — the same construct-then-consume rhythm used for the MCP host (13.8 constructed → the 2026-06-19 route consumed).
