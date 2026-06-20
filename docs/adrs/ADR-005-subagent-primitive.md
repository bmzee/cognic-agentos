# ADR-005 — Sub-Agent Primitive (Orchestrator-Worker Spawning)

## Status
**APPROVED for implementation** on 2026-04-26.

## Context

Per Anthropic's Managed Agents pattern: a "lead" agent dynamically spawns specialised "worker" sub-agents — each runs in its own isolated context window, with a tool allow-list narrower than the parent's. The orchestrator stays slim by delegating; the worker context is discarded after returning a result to the parent.

This is **different from** `workflows/`'s composed-flow pattern:
- Composed flow = pre-defined Temporal choreography (deterministic, workflow author owns sequence)
- Sub-agent = dynamic delegation (LLM owns the spawn decision)

Today AgentOS has no sub-agent primitive. Multi-agent flows must be hard-coded as composed Temporal workflows. For real banking use:
- RM Copilot mid-brief realises "STR flag spotted, need AML verification" → cannot dynamically spawn
- PolicyQA realises "this needs Shariah opinion" → cannot dynamically spawn
- Long investigations blow up the parent's context window because there's no way to delegate

## Decision

Add a `subagent/` primitive providing `SubAgent.invoke(prompt)`. Sub-agents spawn via the A2A endpoint (per ADR-003). Each sub-agent gets:

- **Own context window** — no parent context inherited unless explicitly passed
- **Narrowed tool allow-list** — sub-agent's allowed tools ⊆ parent's allowed tools (privilege de-escalation)
- **Capped budget** — max tokens, wall-time, recursion depth (per-tenant max + per-call request)
- **Linked decision-history record** — child decision row references parent's chain hash (audit chain integrity)
- **Discardable context** — after returning, sub-agent context is destroyed; only the result + decision record persist

### Recursion depth
Per-tenant configurable; default `max_depth = 3`. Sub-agent attempting to spawn beyond depth raises `SubAgentDepthExceeded` and is escalated to a reviewer.

### Privilege de-escalation rule
The harness enforces `sub_agent.tool_allow_list ⊆ parent.tool_allow_list`. Sub-agent cannot escalate to a tool the parent didn't have. Configurable per-tenant override (with audit) for cases where a specialist sub-agent needs an additional tool the parent shouldn't.

### Audit
Every spawn → execute → return cycle emits four events on the parent's chain:
- `subagent.spawn(target, policy, parent_trace_id)`
- `subagent.start(child_trace_id)`
- `subagent.return(child_trace_id, result_summary)`
- `subagent.budget(tokens_used, wall_time_used)`

Plus the sub-agent's own decision_history record (chained to the parent).

### ISO 42001 mapping
Sub-agent spawn + return events map to ISO 42001 Annex A controls around **delegation accountability** and **action traceability**. Per ADR-006 each event is tagged with applicable control IDs.

## Consequences

### Positive
- **Dynamic delegation** without context-window blow-up
- **Privilege containment** — sub-agents can't escalate beyond parent
- **Audit chain integrity** — full cross-agent traceability
- **Token budget control** — per-call cap prevents runaway spawning

### Negative
- **Wire-protocol complexity** — A2A spawn + return + audit linkage is non-trivial
- **Test-coverage burden** — every sub-agent spawn path needs negative-path tests (depth, budget, privilege escalation, parent-cancellation)
- **Reasoning cost** — agents that don't currently do delegation will need explicit prompt engineering to use the primitive

### Neutral
- Sub-agent spawn overhead is comparable to a tool call (~50-200ms for in-process; more for cross-pod)
- Composed flows (Temporal) and sub-agents (dynamic A2A) coexist — same audit chain semantics

## Implementation phases
1. **Phase 4.1**: A2A-backed `SubAgent.invoke()` (depends on ADR-003)
2. **Phase 4.2**: Privilege de-escalation enforcement at the harness boundary
3. **Phase 4.3**: Budget + depth caps + escalation on exceed
4. **Phase 4.4**: Audit chain integrity test (Merkle proof over cross-agent events)

## Sprint 10.5 amendment (2026-05-27) — `ParentBudgetResolver` seam wired

Per ADR-022 §"Sub-agent budget inheritance — the Sprint 11 hook", sub-agent "budget narrowing" becomes a **scheduler operation** instead of a static config field. Sprint 10.5 (merged via PR #40, squash `6791eec`) landed the seam half of that contract in `core/scheduler/`; Sprint 11 will bind a real conformer.

**Landed in 10.5 — scheduler-side seam contract:**

- `core/scheduler/_seams.py` declares the **consumer-owned `ParentBudgetResolver` Protocol** per `[[feedback_consumer_owned_protocol_for_unlanded_dep]]`: `async def remaining_budget_for(parent_task_id: uuid.UUID) -> int`. The Protocol is declared in the scheduler module that needs it; Sprint 11 will provide a structurally-conforming implementation that reads from `subagent/` state, NOT inherit from this declaration.
- `core/scheduler/_seams.py::_NullParentBudgetResolver` is the **fail-loud Wave-1 default sentinel** — `remaining_budget_for(...)` raises `NotImplementedError` referencing ADR-005. Pre-Sprint-11 deployments cannot accidentally see a synthetic-zero budget result; the failure mode is `NotImplementedError` propagating up to the caller.
- `core/scheduler/engine.py::SchedulerEngine.submit(submit_input: SubmitInput, *, request_id: str)` is the public seam. The parent task ID is carried as an **optional field on `SubmitInput`** (`SubmitInput.parent_task_id: str | None = None` declared in `core/scheduler/_types.py:94`) — NOT as a `submit()` kwarg. `submit_input` is typed as a frozen dataclass so the parent linkage rides along with every other admission input through one immutable value. When `submit_input.parent_task_id is not None`:
  1. **T10 typed-exception entrypoint**: `submit()` parses the str via `uuid.UUID(...)` wrapped in a try/except that translates `ValueError` to the typed `SchedulerSubmitInputInvalid(field="parent_task_id", reason=str(exc))` exception. The `field` arg is a closed-enum 1-value `SchedulerSubmitInputInvalidField = Literal["parent_task_id"]` declared in `core/scheduler/engine.py:133` — drift-detector pinned.
  2. **Budget narrowing**: `await parent_budget.remaining_budget_for(parent_uuid)` (calls the injected resolver — `_NullParentBudgetResolver` raises by default) → `effective_tokens = compute_child_budget(parent_remaining_budget=..., child_pack_quota=submit_input.requested_estimated_tokens)` — pure-functional `min(...)` helper in `core/scheduler/_seams.py`.
  3. **Narrowing threads all 5 admission gates**: the narrowed `effective_submit_input` (via `dataclasses.replace`) is threaded through pack_state → kill_switch → policy → quota → caps/queue + all 5 emit-admission-refused chain-row sites. This closes the audit/quota-mismatch class where quota saw narrowed values + storage saw original.
- `core/scheduler/storage.py::SchedulerStorage.submit()` persists the parent linkage in `scheduler_tasks.parent_task_id` + threads it onto the `scheduler.admission_accepted` chain row's payload — examiners can walk the parent → child chain via decision_history without joining mutable state.

**Still owned by Sprint 11 (sub-agent primitive) — NOT in 10.5:**

- `subagent/spawn.py` — A2A-backed `invoke(prompt)` flow that constructs a `SubmitInput(..., parent_task_id=<parent task id>)` and calls `SchedulerEngine.submit(submit_input, request_id=...)` before child dispatch (per the BUILD_PLAN §10.5 + §11 contract).
- The real `ParentBudgetResolver` conformer reading the parent's remaining budget snapshot from `subagent/` state.
- Privilege de-escalation enforcement at the harness boundary (§"Privilege de-escalation rule" + §"Implementation phases / Phase 4.2").
- Depth cap enforcement at the spawn seam (§"Recursion depth").

**No semantic change to ADR-005's existing decisions** — Sprint 10.5 is additive: the scheduler is the runtime substrate that Sprint 11's sub-agent primitive will dispatch through. The §"Decision" section's "max tokens, wall-time, recursion depth" budget contract remains the cross-cutting policy declaration; how it's enforced at the runtime is now scheduler-mediated.

## Sprint 11 amendment (2026-05-30) — Wave-1 in-process dispatch + global recursion cap

Sprint 11 implements the sub-agent primitive. Two Wave-1 narrowings of this ADR's existing decisions are recorded here **before implementation** so the code never diverges from an approved ADR. Both are additive — they scope the Wave-1 enforcement; they do not reverse the §"Decision" contracts.

**1. Wave-1 dispatch is in-process, scheduler-mediated.** §"Decision" ("Sub-agents spawn via the A2A endpoint") and §"Implementation phases / Phase 4.1" ("A2A-backed `SubAgent.invoke()`") describe the cross-pod A2A-transport dispatch. **Wave-1 ships in-process, scheduler-mediated dispatch** that preserves A2A trace/audit/identity *semantics* — parent_trace → child_trace propagation and identity metadata carried in the audit payload — but performs **no AgentCard/JWS verification at the in-process spawn boundary**. The A2A *endpoint transport* (the cross-pod network hop) is deferred to **Wave 2**. This is consistent with §"Consequences / Neutral", which already names in-process as a mode ("~50-200ms for in-process; more for cross-pod"). The §"Decision" "spawn via the A2A endpoint" wording remains the Wave-2 cross-pod contract.

**2. Wave-1 recursion cap is global.** §"Recursion depth" ("Per-tenant configurable; default `max_depth = 3`") is narrowed for Wave-1 to a **global** `Settings.subagent_max_recursion_depth = 3`. Per-tenant / per-agent overrides are deferred to the policy/approval layer (Sprint 13.5). This resolves the BUILD_PLAN human-decision ("Sub-agent recursion depth default — global, per-tenant, or per-agent") as **global**.

**Audit-chain linkage is payload-only.** The child↔parent linkage the §"Audit" section records is implemented as a `payload["parent_record_id"]` key on the child decision-history rows, verified by a cross-row linkage verifier modelled on `core/chain_verifier.verify_suspend_wake_linkage`. There is **no** `DecisionRecord` schema change, **no** `core/canonical.py` change, **no** new top-level `decision_history` column, and **no** `schema_version` bump.

## Parent budget resolver seam amendment (2026-06-19) — the real resolver lands; the Sprint-11 sentinel is superseded at `build_runtime`

The `_NullParentBudgetResolver` fail-loud sentinel (the Wave-1 default at `core/scheduler/_seams.py`, §77 above) is now superseded at the scheduler composition root by the real **`core/scheduler/budget_resolver.py::SchedulerTaskParentBudgetResolver`** — a scheduler-task-backed, tenant-scoped granted-budget read primitive. (Named `SchedulerTaskParentBudgetResolver`, NOT `LocalParentBudgetResolver`, to avoid a collision with the pre-existing Sprint-11b dict-snapshot `subagent/conformers.py::LocalParentBudgetResolver`.)

1. **The resolver.** `remaining_budget_for(parent_task_id, *, tenant_id) -> int` reads the parent task's GRANTED budget (`scheduler_tasks.requested_estimated_tokens`, via the new pure-read `SchedulerStorage.get_budget_snapshot`), tenant-scoped. A **ceiling-inheritance** read primitive: the child budget becomes `min(child_pack_quota, parent_granted)` (the existing `compute_child_budget`); it is a snapshot, NOT a live decrementing balance — sibling/shared-pool depletion is the next slice (the live sub-agent dispatch caller).
2. **Fail-loud typed.** Absent or cross-tenant → `ParentTaskBudgetUnavailable("parent_not_found")` (cross-tenant collapses to not-found per the invisibility doctrine); terminal parent → `ParentTaskBudgetUnavailable("parent_terminal")`. The engine does NOT catch it — it propagates fail-loud (preserving the sentinel doctrine; NO `scheduler.admission_refused` row, NO quota reservation, NO task-row insert — pinned by `tests/unit/core/scheduler/test_engine.py`). A malformed `parent_task_id` stays the existing `SchedulerSubmitInputInvalid` input-validation refusal.
3. **The seam Protocol grew `*, tenant_id`.** The `ParentBudgetResolver` Protocol + `_NullParentBudgetResolver` sentinel gained the keyword-only `tenant_id` (the engine's `submit()` call-site now passes `submit_input.tenant_id`). **The pre-existing Sprint-11b sub-agent consumers got a MINIMAL signature-only compat touch** (a `subagent/` stop-rule edit): `subagent/conformers.py::LocalParentBudgetResolver` accepts + IGNORES `tenant_id` (it stays the dict-snapshot conformer + `KeyError`); `subagent/spawn.py::_resolve_budget` threads `request.tenant_id`. **NO** change to sub-agent dispatch semantics (`compute_spawn_budget`, the spawn refusals, the un-wired `SubAgentSpawner` are untouched).
4. **CC + scope.** CC 131 → 132 (`budget_resolver.py` on the durable per-file gate; also registered in the no-emergency/no-sandbox architecture-guard exhaustiveness lists). No migration. **Deferred:** wiring the dormant `subagent/spawn.py::SubAgentSpawner` into production, reconciling the two budget designs (the scheduler-level `compute_child_budget` + `SchedulerTaskParentBudgetResolver` vs the subagent-level `compute_spawn_budget` + the dict-snapshot `LocalParentBudgetResolver`), the sibling/shared-pool ledger.

## Sub-agent portal trigger amendment (2026-06-20) — `POST /api/v1/subagents`, the first LIVE dispatch trigger

The dormant `subagent/spawn.py::SubAgentSpawner` (composed WIRED-but-DORMANT at the portal lifespan when the child-is-a-managed-run dispatch path landed) now has its **first production consumer**: the RBAC-gated portal route **`POST /api/v1/subagents`** (`portal/api/subagents/`, off-gate; the "Fork B" narrow internal seam — the in-workload channel is the deferred "Fork A").

1. **Parent identity — managed-run terms.** The body carries `parent_run_id`; the route resolves it tenant-scoped via `RunRecordStore.load(parent_run_id, tenant_id=actor.tenant_id)` (cross-tenant → `None` → 404 `parent_run_not_found`, invisible), requires `record.task_id is not None` (else 409 `parent_run_not_admitted`), and threads `parent_task_id=str(record.task_id)` into the spawn (budget inheritance). Scheduler IDs stay internal. `parent_trace_id = f"run:{parent_run_id}"` (deterministic, no caller override Wave-1).
2. **RBAC.** New `subagent.spawn` scope (`RequireScope`, service-actor allowed, **no `RequireHumanActor`** — spawning is operational orchestration, not a Human-only decision; a high-risk child still pends for a human DOWNSTREAM at sandbox cold-create admission, mirroring the run route).
3. **Body split.** Caller-supplied {`parent_run_id`, `managed_run{pack_id, pack_version, argv}`, `prompt`, `parent_tool_allow_list`, `requested_tool_allow_list`, `requested_estimated_tokens`}; route-derived {`tenant_id`/`actor`, `current_depth=0` (the portal spawn roots a fresh sub-agent tree — NOT caller-supplied, so the recursion cap cannot be defeated), `parent_task_id`, `parent_trace_id`}.
4. **Tool-list contract (Wave-1 honesty).** Both allow-lists are body-supplied; `narrow_tool_allow_list` enforces `requested ⊆ parent` — in Wave-1 an **audited invariant** (both lists in the `subagent.spawn` policy snapshot), NOT a hard boundary against a caller claiming a wide parent. The hard tool capability boundary is downstream (pack manifest + ADR-014 runtime tool-approval + MCP authz). A later in-workload channel (Fork A) sources `parent_tool_allow_list` from trusted running-agent context, upgrading the check to a real boundary.
5. **Coarse response.** The child runs synchronously; the route returns 200 + `SubAgentSpawnResponse{spawn_record_id, child_result}` (mapping the existing `SubAgentResult`). A `pending_approval`/failed/refused child rides `child_result.ok=false` + summary — **`pending_approval` is a documented Wave-1 non-goal** (a `202`/resume would contradict the `subagent.return … failed` audit row that the runner's flattening produces; the proper child-approval/resume is a later slice that fixes the flattening — enrich the result, widen `ReturnOutcome` to a pending value — first).
6. **CC + scope.** CC stays **133** — the route + DTOs are off-gate (the enforcement — narrow + depth + audit, the spawner, the runner, the scheduler budget gate — is already on-gate); the only on-gate edits are the additive `portal/rbac/*` scope trio (`SubAgentRBACScope` + `Actor.scopes`/`RequireScope` union widenings). No migration. **Deferred:** the in-workload channel (Fork A — a running workload requesting a spawn, needs a sandbox control-plane callback); the `pending_approval` child-approval/resume slice; the two-budget reconciliation; the sibling/shared-pool ledger.

## Sub-agent child approval-retry amendment (2026-06-20) — `pending_approval` made honest + actionable

The portal trigger (above) left a high-risk `pending_approval` child as a documented Wave-1 non-goal: the runner flattened it to `ChildResult(ok=False)`, `subagent.return` recorded `outcome="failed"`, and the UI projected `subagent.failed` — indistinguishable from a real failure, with no way to act. This amendment makes pending **honest** (audit chain + UI event stream) and **actionable** (a `202` + the existing approval surface + an approval retry).

1. **Honest result + audit.** `ManagedRunChildRunner` no longer flattens — `ChildResult` carries `run_id`/`terminal_state`/`approval_request_id` on every branch. `ReturnOutcome` gains `"pending_approval"` (additive); a pending child emits `subagent.return outcome="pending_approval"` (carrying the ids) and **skips `subagent.budget`** (the cold-create pended before the workload ran — zero work). Non-pending `subagent.return` rows stay byte-identical (the new payload keys are conditional).
2. **Honest UI.** A new backward-compatible `SubagentPending` event (ADR-020 — see that amendment); `_project_subagent_return` routes `pending_approval` to it, preserving the conservative `completed`/`failed`/unknown projections.
3. **Actionable — approval retry, NOT resume.** The child pends at cold-create, so it is resolved like the run route's cold-create-pending: the route returns **`202` + `approval_request_id`**; the operator grants via the existing `portal/api/approvals/` surface; a **re-POST `POST /api/v1/subagents`** with the same child spec + the granted `approval_request_id` runs a **new** child run (a new `subagent.spawn` row) that clears admission. Deliberately **not** `ManagedRunExecutor.resume()` (the wake/suspend axis) and **not** same-spawn correlation (deferred — needs spawn-correlation persistence).
4. **The threading.** `approval_request_id` flows portal body (`uuid.UUID`) → `SubAgentSpawnRequest` (`str`) → `ChildRunContext` (`str`, built in `spawn.py`) → the runner parses `str → uuid.UUID` → `RunRequest.approval_request_id`. (The `spawn.py` `request → ChildRunContext` link was an integration gap the operator e2e surfaced + closed — the unit tests structurally missed it: T2 set the context directly, T5 stubbed the spawner.)
5. **CC + scope.** Edits to already-on-gate modules (`subagent/audit.py`/`spawn.py`/`_types.py`/`managed_run_runner.py` + `protocol/ui_events.py`); **no new gate module**, every change backward-compatible-additive, **no migration**. `core-controls-engineer` + `/critical-module-mode`. **Deferred:** a dedicated subagent resume endpoint + same-spawn correlation/finalization; the in-workload channel (Fork A).

## References
- [Anthropic — Sub-agents in Claude Code](https://docs.anthropic.com/en/docs/claude-code/sub-agents)
- [The Architecture of Scale: Anthropic's Sub-Agents — Medium](https://medium.com/@jiten.p.oswal/the-architecture-of-scale-a-deep-dive-into-anthropics-sub-agents-6c4faae1abda)
- ADR-003 (A2A — substrate for sub-agent spawning)
- ADR-004 (sandbox — sub-agents may run in their own sandbox)
- ADR-022 (runtime scheduler — Sprint 10.5 wires the `ParentBudgetResolver` seam)
