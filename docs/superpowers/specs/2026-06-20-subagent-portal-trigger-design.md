# Sub-Agent Portal Trigger — Design Spec

> **Status:** LANDED (2026-06-20) — implemented on `feat/subagent-portal-trigger` (T1-T5); CC stays 133, no migration.
> **Date:** 2026-06-20
> **ADRs:** ADR-005 (sub-agent primitive), ADR-022 (scheduler), ADR-014 (runtime tool approval), ADR-012 §40 (portal RBAC).

**Goal:** Make the WIRED-but-DORMANT `app.state.subagent_spawner` LIVE through its first production consumer — an RBAC-gated portal route `POST /api/v1/subagents` that spawns a child sub-agent (which runs as a governed managed run). This is the "narrow internal seam" (Option B); it is the stepping stone toward the in-workload channel (Option A), which is explicitly out of scope here.

**Architecture:** The route is a thin off-gate consumer of the already-on-gate spawn path (`narrow_tool_allow_list` → `check_depth` → audit → `ManagedRunChildRunner.run` → audit). It mirrors the `portal/api/runs/` pattern exactly: a `build_*_routes()` factory mounted unconditionally, a request-time `_require_*` dependency that returns `503` when the SDK-gated lifespan did not populate the spawner, and an `RequireScope` gate. The spawn runs the child **synchronously** to completion (like the run route) and returns a coarse result.

**Tech stack:** FastAPI (Annotated/Depends), Pydantic v2 DTOs, the existing `SubAgentSpawner` + `ManagedRunChildRunner` + `RunRecordStore`.

---

## Context — what already exists

- **Dormant spawner** (landed 2026-06-20): `portal/api/app.py` lifespan sets `app.state.subagent_spawner = build_subagent_spawner(runtime=…, managed_run_executor=…, engine=…, settings=…)` (SDK-gated; `None` on the off-path). **No production consumer yet** — this slice adds the first.
- **The spawn path** (`subagent/spawn.py` + `subagent/_facade.py`, on-gate): `spawn(*, request: SubAgentSpawnRequest, managed_run: ManagedRunChildSpec, actor: Actor, parent_trace_id: str)` = `narrow_tool_allow_list(parent=request.parent_tool_allow_list, requested=request.requested_tool_allow_list)` → `check_depth(current_depth=request.current_depth, max_depth)` → `emit_spawn` (returns the `spawn_id: uuid.UUID`) → `emit_child_genesis` → `ManagedRunChildRunner.run(ctx)` → `emit_return` + `emit_budget`. **Already returns `SubAgentResult` (`spawn.py:155`), NOT `ChildResult`** — the `emit_spawn` `spawn_id` is captured as `spawn_record_id`.
- **`SubAgentSpawnRequest`** (`subagent/_types.py:76`): `prompt`, `parent_tool_allow_list: frozenset[str]`, `requested_tool_allow_list: frozenset[str]`, `current_depth: int`, `requested_estimated_tokens: int`, `tenant_id: str`, `parent_task_id: str | None`.
- **`ManagedRunChildSpec`** (`subagent/_types.py`): `pack_id: str`, `pack_version: str`, `argv: tuple[str, ...]`.
- **`ChildResult`** (`subagent/_types.py`): `summary: str`, `tokens_used: int`, `wall_time_used_s: float`, `ok: bool`.
- **`SubAgentResult`** (`subagent/_types.py:143`): `spawn_record_id: uuid.UUID`, `child_result: ChildResult` — **already the return type of `spawn()` (`spawn.py:155`) and the facade `spawn_subagent()` (`_facade.py:67,99`)**. The route consumes this directly; the slice adds **NO `subagent/` change**.
- **`RunRecordStore.load(run_id, *, tenant_id) -> RunRecord | None`** (`core/run/storage.py:378`): tenant-scoped; a run owned by another tenant returns `None` (cross-tenant-invisible). `RunRecord.task_id: uuid.UUID | None` (`core/run/_types.py:123`).
- **`narrow_tool_allow_list(*, parent, requested)`** (`subagent/policy.py:19`): returns `requested` iff `requested ⊆ parent`, else raises `SubAgentPrivilegeEscalation(extra_tools=…)`.
- **Precedent — the run route** (`portal/api/runs/routes.py`): `build_run_routes()` factory, `_require_managed_run_executor` → `503 {"reason": "sandbox_runtime_unavailable"}`, `RequireScope("run.submit")`, **no `RequireHumanActor`** (the sandbox cold-create approval seam owns the human checkpoint). `from __future__ import annotations` INTENTIONALLY OMITTED (FastAPI `Annotated[..., Depends(...)]` resolution invariant).
- **`app.py` run-store gap (P2):** the lifespan constructs `RunRecordStore(adapters.relational.engine)` **inline** in the `ManagedRunExecutor(...)` call (`app.py:711`) and does **not** assign `app.state.run_record_store`. This slice lifts it to a named lifespan local + an `app.state` assignment so the route can resolve it at request time (see Module structure).

---

## Locked design decisions

### 1. Approach — Option B (portal seam) first

A running managed workload has **no channel** back to the kernel to request a spawn (the executor runs an opaque `argv` in a network-isolated sandbox). Building that control-plane channel is Option A — a separate, larger slice. Option B proves the dispatch path end-to-end through a real RBAC-gated production surface without the sandbox-channel complexity.

### 2. Parent identity — `parent_run_id`, route-resolved to `task_id`

The public surface speaks **managed-run terms**; scheduler IDs stay internal.

- Body carries `parent_run_id: str` (a UUID).
- Route runs `RunRecordStore.load(parent_run_id, tenant_id=actor.tenant_id)`.
- `None` → **`404 {"reason": "parent_run_not_found"}`** — cross-tenant-invisible (a probe cannot tell "another tenant's run" from "no such run").
- `record.task_id is None` (the parent run was never scheduler-admitted) → **`409 {"reason": "parent_run_not_admitted"}`**.
- Otherwise the route passes `parent_task_id = str(record.task_id)` into the spawn request (budget inheritance).
- `parent_trace_id = f"run:{parent_run_id}"`, **deterministic, no caller override** in Wave-1 (`RunRecord` carries no `trace_id` to thread; a caller-supplied trace label is YAGNI and addable later without breaking the contract).

`parent_run_id` is the **budget** parent; **depth** is a fresh portal-rooted spawn tree (see §4). The two are decoupled by construction.

### 3. RBAC — `subagent.spawn`, service-actor allowed, no human gate

Spawning is operational orchestration, not a Human-only decision (it is not on the AGENTS.md Human-only list). The run route is the exact precedent: `RequireScope` only, **no `RequireHumanActor`**. A high-risk child still pends for a human **downstream** at sandbox cold-create admission (the 14A-A2 approval seam) — not at the spawn call. A human gate here would break service orchestrators or invite fake human identity (a production-grade anti-pattern).

- New closed-enum `SubAgentRBACScope = Literal["subagent.spawn"]` + `SUBAGENT_SCOPES` frozenset in `portal/rbac/scopes.py` (mirrors `PackRBACScope`/`UIRBACScope`/`ModelRBACScope`/…).
- Additive widening of the `Actor.scopes` union (`portal/rbac/actor.py`) and the `RequireScope` param union (`portal/rbac/enforcement.py`); `subagent.*` is namespace-disjoint.
- Pinned by `tests/unit/portal/rbac/test_subagent_scopes.py`.

### 4. Request body — caller-supplied vs route-derived

**Caller-supplied** (the body DTO `SubAgentSpawnRequestBody`):
`parent_run_id`, `managed_run {pack_id, pack_version, argv}`, `prompt`, `parent_tool_allow_list`, `requested_tool_allow_list`, `requested_estimated_tokens`.

**Route-derived** (never caller-supplied):
`tenant_id` + `actor` (from the bound `Actor`), `current_depth = 0`, `parent_task_id` (resolved per §2), `parent_trace_id` (per §2).

- **`current_depth = 0` is route-set, NOT caller-supplied** — a portal-triggered spawn is the root of a fresh sub-agent tree (the child sits at depth 1). A caller who could set `current_depth` would send `0` forever to defeat the recursion cap. `SubAgentDepthExceeded` is therefore **unreachable in Wave-1** (`current_depth=0` with `max_depth ≥ 1`); the depth cap only bites for in-tree (Option A) spawning later. No status row for it.
- Tool lists ride the body as **`list[str]`** (JSON ergonomics; dedupe is natural and ordering is not semantically meaningful) and are converted to **`frozenset[str]`** when building `SubAgentSpawnRequest`.

### 5. Tool-list contract + the Wave-1 honesty note

The body supplies **both** `parent_tool_allow_list` and `requested_tool_allow_list`; the existing `narrow_tool_allow_list` enforces `requested ⊆ parent`, raising `SubAgentPrivilegeEscalation(extra_tools=…)` otherwise. There is no parent-run tool grant stored anywhere (`RunRecord` has no tool field), and `Actor.scopes` are portal/RBAC permissions — a different vocabulary from child tool grants — so deriving the parent set from either is wrong.

> **Honesty note (must appear in the code + the operator doc):** because the caller supplies **both** lists, the `requested ⊆ parent` check is **trivially satisfiable** (a caller can always claim a wide `parent`). In Wave-1 it is therefore an **audited invariant** — both lists land in the `subagent.spawn` policy snapshot, and the child provably cannot exceed the *claimed* parent — **not a hard boundary against a malicious caller.** The hard tool capability boundary is **downstream**: the child runs as a managed run, so its real tool/MCP access is governed by the pack manifest + ADR-014 runtime tool-approval + MCP authz at invocation. **Option A** later replaces the body-supplied `parent_tool_allow_list` with the trusted running-agent context, upgrading the check to a real boundary.

### 6. Response / status — coarse, with `pending_approval` a documented non-goal

`spawn()` runs the child synchronously and the result is **coarse on purpose**. A richer `202 + approval_request_id` is a **coherence bug today**: `ManagedRunChildRunner` flattens a `pending_approval` child to `ChildResult(ok=False, summary="pending_approval_child_unsupported")`, and `spawn.py:138` then emits `subagent.return` as **`failed`** (`ReturnOutcome = Literal["completed", "failed"]`, `audit.py:15` — there is no "pending"). A `202` wire response implying a resumable sub-agent would directly contradict a `…failed` audit row. So:

| Code | Body | Trigger |
|---|---|---|
| `200` | `SubAgentSpawnResponse` (see §7) | green spawn call — `child_result.ok` may be `true` or `false` |
| `404` | `{"reason": "parent_run_not_found"}` | unknown / cross-tenant `parent_run_id` |
| `409` | `{"reason": "parent_run_not_admitted"}` | resolved run, `task_id is None` |
| `403` | `{"reason": "scope_not_held", …}` | `RequireScope("subagent.spawn")` (RBAC) |
| `403` | `{"reason": "subagent_privilege_escalation", "extra_tools": [...]}` | `requested ⊄ parent` — **distinct route-owned 403** |
| `503` | `{"reason": "subagent_spawner_unavailable"}` | dormant runtime — `app.state.subagent_spawner` **or** `app.state.run_record_store` absent (co-populated in one SDK-gated block; one combined dep, one reason) |

A child failure / refusal / pending-unsupported is represented inside a `200` as `child_result.ok=false` + the summary string — consistent with the `subagent.return … failed` audit row. **`pending_approval_child_unsupported` is a documented Wave-1 non-goal** (see Deferred slice).

### 7. The `spawn_record_id` grounding — already on `main`, no `subagent/` change

`SubAgentResult { spawn_record_id: uuid.UUID, child_result: ChildResult }` **already exists** (`subagent/_types.py:143`) and is **already the return type** of `spawn()` (`spawn.py:155` — `return SubAgentResult(spawn_record_id=spawn_id, child_result=child)`, capturing the `emit_spawn` chain-event id) and the facade `spawn_subagent()` (`_facade.py:67,99`). So the slice adds **NO `subagent/` change** — it consumes the existing type:

- The route maps `spawn_record_id = str(result.spawn_record_id)` (the audit-correlatable subagent.spawn chain-event id) and `child_result = {ok, summary, tokens_used, wall_time_used_s}` from `result.child_result`.

**No extra route-level structured log.** The authoritative evidence is the `subagent.spawn` / `child_genesis` / `return` / `budget` audit chain the spawner already emits; a separate route log would be duplicate evidence with no distinct operational purpose.

---

## Module structure

| File | Change | Gate |
|---|---|---|
| `portal/api/subagents/__init__.py` | new — `build_subagent_routes` export | off-gate |
| `portal/api/subagents/dto.py` | new — `SubAgentSpawnRequestBody`, `ManagedRunChildSpecBody`, `SubAgentSpawnResponse`, `ChildResultBody` (Pydantic v2, `extra="forbid"`) | off-gate |
| `portal/api/subagents/routes.py` | new — `build_subagent_routes()` (no factory args, mirrors `build_run_routes`) + **one combined** `_require_subagent_runtime(request)` reading `app.state.subagent_spawner` + `app.state.run_record_store` (503 if either absent — they are co-populated) + `POST /api/v1/subagents`; `from __future__ import annotations` OMITTED | off-gate |
| `portal/rbac/scopes.py` | additive — `SubAgentRBACScope` + `SUBAGENT_SCOPES` | on-gate (additive) |
| `portal/rbac/actor.py` | additive — widen `Actor.scopes` union | on-gate (additive) |
| `portal/rbac/enforcement.py` | additive — widen `RequireScope` param union | on-gate (additive) |
| `portal/api/app.py` | (1) mount `build_subagent_routes` unconditionally; (2) **P2 run-store wiring** — preseed `app.state.run_record_store = None`; lift the inline `RunRecordStore(adapters.relational.engine)` (currently built inside the `ManagedRunExecutor(...)` call at `:711`) to a named lifespan local; pass it to the executor; assign `app.state.run_record_store = run_record_store` in the **same SDK-gated block** as the spawner; clear it (`= None`) on the exception path | off-gate |

**No `subagent/` files are touched** — `SubAgentResult` (§7) already exists on `main`. The route resolves `app.state.subagent_spawner` + `app.state.run_record_store` at request time via the **one combined** `_require_subagent_runtime(request)` dependency; both are co-populated in the same SDK-gated lifespan block, so a single `503 {"reason": "subagent_spawner_unavailable"}` covers either being absent (the dormant-lifespan pattern). The route mounts unconditionally.

---

## CC posture

- **CC stays 133 — no new gate module.** The route + DTOs are off-gate thin glue (same posture as the run + MCP routes); all enforcement (narrow + depth + audit, the spawner, the runner, the scheduler budget gate) is already on-gate.
- **No `subagent/` stop-rule files are touched** — `SubAgentResult` (§7) already exists on `main`, so there is no return-enrichment change. The only on-gate edits are the additive `portal/rbac/*` ones above (additive, namespace-disjoint, pinned by a scopes test). The full `--cov-branch` suite + the 133/133 CC gate must stay green on fresh coverage.
- **No migration.**

---

## Testing

- **Route (stub spawner + stub `RunRecordStore`):** green 200 (`spawn_record_id` + `child_result`); `child_result.ok=false` pass-through (pending/failed child); `parent_run_not_found` 404 (unknown + cross-tenant both → 404); `parent_run_not_admitted` 409 (`task_id is None`); `subagent_privilege_escalation` 403 (with `extra_tools`); `scope_not_held` 403; `subagent_spawner_unavailable` 503 — **both** the spawner-absent and the run-store-absent paths (the one combined dep).
- **RBAC:** `test_subagent_scopes.py` — the Literal + frozenset + union-widening lockstep (namespace-disjoint partition invariant).
- **`spawn_record_id` mapping:** assert the route's `spawn_record_id == str(result.spawn_record_id)` from the stubbed `SubAgentResult` — the existing `subagent/` return type is consumed unchanged (no `subagent/` test churn).
- **P2 app-state wiring:** assert `create_app` lifespan sets `app.state.run_record_store` (non-None on the SDK-available path; cleared to `None` on the exception path), and that the executor still receives the same instance.
- **DTO:** `list[str] → frozenset[str]` conversion (dedupe); `extra="forbid"`; `current_depth` is NOT a body field (route-set).
- **Whole-project `uv run mypy src tests` + ruff + the full `--cov-branch` suite + the 133/133 CC gate** on fresh coverage in the landing commit.

---

## Non-goals (Wave-1)

- **`pending_approval` child** — surfaced as `child_result.ok=false` + `pending_approval_child_unsupported`; **no `202`/resume** (preserves audit coherence; see §6).
- **The in-workload channel (Option A)** — a running workload requesting a spawn; needs a sandbox control-plane callback channel (a separate slice).
- **Depth recursion in B** — `current_depth=0` always; the cap is unreachable here.
- **A hard tool boundary from a trusted parent grant** — the body-supplied `parent_tool_allow_list` is an audited invariant in Wave-1 (§5); the Option-A upgrade sources it from the running-agent context.

---

## Deferred — the "child approval / resume" slice

To make a high-risk pending child actionable (`202 + approval_request_id` + a resume path), a later slice must, **in this order**:

1. **Fix the flattening / audit coherence first:** enrich `ChildResult` (or the existing `SubAgentResult`) to carry the child's `run_id` + real terminal state + `approval_request_id`; widen `ReturnOutcome` to a "pending" value **or** add a dedicated pending audit event, so `subagent.return` no longer records a pending child as `failed`.
2. Preserve `run_id` / `approval_request_id` through the spawn path to the route.
3. Define the resume surface — reuse `POST /api/v1/runs/{run_id}/resume` (the child *is* a managed run) vs a subagent-specific resume — and the RBAC scope for it.

Only after (1) is the `202` wire response coherent with the audit chain.
