# Sub-Agent Child Approval-Retry Semantics — Design Spec

> **Status:** DRAFT — pending user review before writing-plans.
> **Date:** 2026-06-20
> **ADRs:** ADR-005 (sub-agent primitive), ADR-022 (scheduler / managed run), ADR-004 (sandbox cold-create approval), ADR-014 (runtime tool approval), ADR-020 (UI event-stream contract — `protocol/ui_events.py` stop rule).

**Goal:** Make a `pending_approval` child sub-agent **honest in the audit chain + the UI event stream** and **actionable over the wire**, closing the gap the Fork-B portal trigger left as a documented Wave-1 non-goal. Today a child that pends at sandbox cold-create is flattened to `ChildResult(ok=False)`, recorded as `subagent.return outcome="failed"`, and projected to the UI as `subagent.failed` — a high-risk child is indistinguishable from a real failure, and the caller has no way to act on it.

**Architecture — "approval retry", NOT "resume".** The child pends at **cold-create** (the 13.5c1 sandbox approval seam pends *before* the workload runs), so this is resolved exactly like the run route's cold-create-pending: the caller **grants the existing approval** (via the existing `portal/api/approvals/` surface) and **re-POSTs `POST /api/v1/subagents`** with the same child spec + the granted `approval_request_id`. That second call mints a **new** child run (and a new `subagent.spawn` audit row) that clears admission and executes. This is deliberately **not** `ManagedRunExecutor.resume()` (which is the wake/suspend axis) and **not** same-spawn correlation — a true same-spawn resume would require persisting spawn-correlation state and finalizing the earlier pending audit row, which is a bigger persistence problem deferred to a later slice.

---

## Context — what exists (verified on `main` @ `87e211d`)

- **The flattening (the bug).** `ManagedRunChildRunner.run` builds a `RunRequest` (no `approval_request_id` today) → `executor.run` → `RunResult`, then maps `RunResult` → `ChildResult` keeping only `summary`/`tokens_used`/`wall_time_used_s`/`ok`. A `pending_approval` `RunResult` becomes `ChildResult(ok=False, summary="pending_approval_child_unsupported")` — `run_id`, `terminal_state`, `approval_request_id` are dropped.
- **`RunResult` already carries the truth** (`core/run/executor.py:179-196`): `run_id` (minted on EVERY path), `terminal_state: RunTerminalState`, and `approval_request_id` (set **only** when `terminal_state=="pending_approval"` — the sandbox approval correlator).
- **The audit map (`spawn.py:138`):** `outcome: ReturnOutcome = "completed" if child.ok else "failed"` → `emit_return(outcome)` → `emit_budget(...)`. `ReturnOutcome = Literal["completed","failed"]` (`subagent/audit.py:15`). A pending child gets `outcome="failed"` **and** a `subagent.budget` row for work it never did (it pends before the workload runs — zero tokens, zero wall-time).
- **The UI projector (`protocol/ui_events.py:969`, ADR-020 stop rule):** `_project_subagent_return` projects `subagent.return` by `payload['outcome']` — `"completed" → SubagentCompleted`, **everything else (incl. unknown) → `SubagentFailed`** (the conservative default). So a `pending_approval` outcome would relocate the same gap into the event stream unless the projector gains an arm.
- **The run route's cold-create-retry precedent (14A-A2):** cold-create-pending is resolved by **re-POSTing the submit route** with `approval_request_id` (NOT `resume()`, which is `:257` the wake/suspend axis); the executor mints a fresh `run_id` on the retry. `RunRequest.approval_request_id` (`:162`) is the existing input that threads the grant into cold-create.
- **The Fork-B route** (`portal/api/subagents/routes.py`): coarse 200 + `SubAgentSpawnResponse{spawn_record_id, child_result}`; `pending_approval` currently rides `child_result.ok=false`.

---

## Locked design

### Semantics — the approval-retry flow

1. **First spawn** (`POST /api/v1/subagents`, no `approval_request_id`): high-risk child → `executor.run` cold-creates → **pends**. The runner surfaces `terminal_state="pending_approval"` + `run_id` + `approval_request_id`. spawn.py audits `subagent.return outcome="pending_approval"` (no budget row). The route returns **`202`** with the actionable `approval_request_id`.
2. **Grant** (existing `portal/api/approvals/` surface — unchanged): the operator grants the `approval_request_id`.
3. **Retry** (`POST /api/v1/subagents`, **same child spec + the granted `approval_request_id`**): the route threads `approval_request_id` → request → context → `RunRequest.approval_request_id` → `executor.run` cold-creates **with the grant** → executes → `200` with the completed `child_result`. A new `subagent.spawn` row (the accepted Wave-1 "approval retry" cost).

No same-spawn correlation; no finalization of the earlier pending row; the earlier `subagent.return(pending_approval)` stands as the honest record of the first attempt.

### 1. `ChildResult` enrichment (`subagent/_types.py`, on-gate)

Add three fields, all defaulted (`None`) so every existing caller/test is preserved:
- `run_id: str | None = None`
- `terminal_state: str | None = None` (mirrors the executor's `RunTerminalState`; kept as `str | None` to avoid a `subagent → core/run` type import — drift-pinned by a test if needed)
- `approval_request_id: str | None = None`

`SubAgentResult{spawn_record_id, child_result}` is unchanged (it already carries `child_result`).

### 2. `approval_request_id` threading (IN)

`approval_request_id: uuid.UUID | None` (or `str | None`) added to: the portal request DTO (`SubAgentSpawnRequestBody`, off-gate) → `SubAgentSpawnRequest` (on-gate) → `ChildRunContext` (on-gate, additive optional) → the runner threads `context.approval_request_id` into `RunRequest(approval_request_id=...)` (the existing executor input). On the first spawn it is absent; on the retry it is the granted id.

### 3. Runner mapping (`subagent/managed_run_runner.py`, on-gate)

Stop flattening. The `RunResult → ChildResult` map captures `run_id` + `terminal_state` + `approval_request_id` on every branch. The `pending_approval` branch becomes an **honest** result: `ChildResult(ok=False, terminal_state="pending_approval", run_id=result.run_id, approval_request_id=result.approval_request_id, summary="pending_approval_child", tokens_used=0, wall_time_used_s=elapsed)`. `completed`/`failed`/`refused`/`suspended` keep their `ok` mapping + now also carry `run_id`/`terminal_state` (and `approval_request_id` stays `None` off the pending path).

### 4. `ReturnOutcome += "pending_approval"` (`subagent/audit.py`, on-gate, wire-protocol-public)

`ReturnOutcome = Literal["completed", "failed", "pending_approval"]` — additive. The `subagent.return` chain row for a pending child carries `outcome="pending_approval"` **and** `approval_request_id` + child `run_id` in its payload (for UI projection + examiner traceability).

### 5. `spawn.py` audit honesty (on-gate)

The outcome derivation becomes terminal-state-aware (not the binary `ok`): a `pending_approval` child → `emit_return(outcome="pending_approval", … approval_request_id, run_id …)` and **skip `emit_budget`** (no child work happened — the cold-create pended before the workload ran). Completed/failed children keep `emit_return` + `emit_budget`. The audit sequence for a pending child is `spawn → child_genesis → return(pending_approval)` (no `budget`); for a terminal child it stays `spawn → child_genesis → return → budget`.

### 6. UI projector arm (`protocol/ui_events.py`, ADR-020 stop rule, backward-compatible)

- Add a `SubagentPending` event model to the **subagent** family (a new additive `type` in the family's inner discriminated union — backward-compatible per ADR-020; existing `completed`/`failed` consumers are unaffected). It carries the `approval_request_id` + child `run_id` from the payload so a UI can render "awaiting approval" + a deep link.
- `_project_subagent_return` gains a `payload['outcome'] == "pending_approval" → SubagentPending` arm **before** the conservative `SubagentFailed` fallback; its return type widens to `SubagentCompleted | SubagentFailed | SubagentPending`. The "anything unknown → failed" conservative default is preserved (only the *known* `pending_approval` value is re-routed). The `.well-known/cognic-ui-events.json` schema snapshot updates additively.

### 7. Route status (`portal/api/subagents/`, off-gate)

`POST /api/v1/subagents` response map:
- `child_result.terminal_state == "pending_approval"` **and** `approval_request_id` present → **`202`**, body `{spawn_record_id, child_result, approval_request_id}` (the `approval_request_id` lifted top-level for caller convenience, mirroring the run route).
- `completed`/`failed`/`refused`/`suspended` coarse child → **`200`** (unchanged).
- The existing 404/409/403×2/503 gates are unchanged.
- The retry is the **same** route + the new optional `approval_request_id` body field — **no new endpoint, no new RBAC scope** (`subagent.spawn` covers it; the grant uses the existing approvals surface).

### 8. No dedicated subagent resume endpoint

Explicitly out of scope. Same-spawn correlation/finalization, a `POST /api/v1/subagents/{spawn_record_id}/resume`, and reusing the pending child's `run_id` are all deferred — they require spawn-correlation persistence this slice intentionally avoids.

---

## Module structure + CC / stop-rule posture

| File | Change | Gate / boundary |
|---|---|---|
| `subagent/audit.py` | `ReturnOutcome += "pending_approval"` (wire-public additive) | on-gate, `subagent/` stop rule |
| `subagent/spawn.py` | terminal-state-aware outcome + skip-budget-when-pending | on-gate, `subagent/` stop rule |
| `subagent/_types.py` | `ChildResult` +3 fields; `SubAgentSpawnRequest`/`ChildRunContext` + `approval_request_id` | on-gate, `subagent/` stop rule |
| `subagent/managed_run_runner.py` | un-flatten the `RunResult → ChildResult` map; thread `approval_request_id` into `RunRequest` | on-gate, `subagent/` stop rule |
| `protocol/ui_events.py` | `SubagentPending` event + `_project_subagent_return` arm | **on-gate, ADR-020 stop rule (wire-protocol-public, backward-compatible)** |
| `portal/api/subagents/dto.py` | `approval_request_id` request field; `SubAgentSpawnResponse` top-level `approval_request_id` | off-gate |
| `portal/api/subagents/routes.py` | `202` for pending; thread `approval_request_id` | off-gate |
| `.well-known` schema snapshot | additive (the new event type) | test asset |

**This slice lives inside the stop-rule boundaries — `subagent/*` (on-gate) + the ADR-020 `ui_events` wire contract — so it needs `core-controls-engineer` + `/critical-module-mode`.** Every change is **backward-compatible-additive** (a new enum value, a new event type, new defaulted fields). **No new gate module is expected** (edits to already-on-gate modules); the full `--cov-branch` suite + the 95/90 floor must hold for each on-gate module. **No migration** (no schema/DB change — the audit payload is additive). The ADR-020 wire-protocol change must keep the replay-snapshot drift test green (the projector always returns a typed event).

---

## Testing

- **Runner:** the `pending_approval` `RunResult` → an honest `ChildResult` (`terminal_state`/`run_id`/`approval_request_id` surfaced, `ok=False`); the terminal branches carry `run_id`/`terminal_state`; `approval_request_id` threads from `ChildRunContext` into `RunRequest`.
- **Audit (`spawn.py`):** a pending child emits `subagent.return outcome="pending_approval"` (+ `approval_request_id`/`run_id` payload) and **no** `subagent.budget`; a terminal child emits `return` + `budget` as before. Pinned against a real `DecisionHistoryStore` (in-memory sqlite).
- **`ReturnOutcome`:** the closed-enum now has exactly the 3 values; drift-pinned.
- **UI projector:** `subagent.return outcome="pending_approval"` → `SubagentPending` (not `SubagentFailed`); `completed`/`failed`/unknown unchanged; the replay-snapshot drift test + `.well-known` schema snapshot updated additively.
- **Route:** first spawn (high-risk, no approval id) → `202` + actionable `approval_request_id`; retry (same spec + granted id) → `200` completed. Over a stub spawner (the real cold-create→grant→retry seam is exercised by the env-gated sandbox e2e).
- **Whole-project `uv run mypy src tests` + ruff + the full `--cov-branch` suite + the CC gate** (no new module; on-gate modules stay ≥ floor) on fresh coverage in the landing commit.
- **Operator e2e (env-gated, `COGNIC_RUN_DOCKER_SANDBOX=1`):** spawn a high-risk child → `202` + `approval_request_id` → real `grant()` → re-POST with the id → `200` completed; assert the chain carries `subagent.return(pending_approval)` then a fresh `subagent.spawn → return(completed)`.

---

## Non-goals (Wave-1)

- **A dedicated subagent resume endpoint / same-spawn correlation / pending-row finalization** — deferred (needs spawn-correlation persistence).
- **Reusing the pending child's `run_id` on retry** — the retry mints a new child run, like the run route's cold-create re-submit.
- **The in-workload spawn channel (Fork A)** — independent; this slice gives Fork A a child lifecycle that already knows how to pend, grant, and retry without contradicting `subagent.return`.
- **`high_risk` policy changes** — the child's risk tier + the sandbox cold-create approval gate are unchanged; this slice only makes the *pending* outcome honest + actionable.
