# Sprint 14A-A3a — Run-persistence foundation (durable `RunRecord` substrate) — Design

**ADR:** ADR-022 (scheduler/run) + ADR-004 (sandbox/checkpoint). **Status:** design locked, ready for plan.
**Date:** 2026-06-15. **Predecessor:** 14A-A2 (route + sandbox approval threading, MERGED `main @ 3895311`).

## 1. Goal + success criterion

Build a **correct durable run-record substrate** that a future resume path (14A-A3b) can safely depend on. **Success is NOT "resume works"** — it is "we have a tenant-owned, atomically-transitioned, forward-compatible `runs` store proven by tests."

**Store-only / dormant.** A3a ships a new `RunRecordStore` + `runs` table + closed-enum `RunState` machine + atomic chain-row/state-cache transitions, on the critical-controls gate, proven by unit + (env-gated) integration tests. It is **NOT wired into the executor** and has **no production caller** yet (like the 13.7 scheduler substrate before its caller). A3b wires it into the run lifecycle + adds the resolver; A3c adds the wake approval correlator.

## 2. Scope + non-scope (the A3a→A3b→A3c split)

**In scope (A3a):**
- `core/run/_types.py` (NEW, off-gate) — `RunState` closed enum (full forward-compatible vocabulary) + `RunRecord` frozen dataclass + pure-functional `validate_transition` (A3a synchronous subset) + `RunTransitionRefused`.
- `core/run/storage.py` (NEW, **on-gate, CC**) — `RunRecordStore`: `create_run` (genesis) + `transition` + `load` + `list_for_tenant`; the `runs` SQLAlchemy `Table`; `_LockedRunSnapshot`. Atomic chain-row + state-cache via `DecisionHistoryStore.append_with_precondition` (Doctrine Lock D).
- A new Alembic migration (`20260615_0011_runs.py`, off-gate) — the `runs` table DDL.
- Tests: state-machine + closed-enum drift (`_types`), store genesis/transition/read/atomicity/tenant-isolation (`storage`), + env-gated Postgres/Oracle row-lock integration.
- The architecture fence (`tests/unit/architecture/test_run_no_sdk_import.py`) expected-sources set expands to admit the two new `core/run/` modules; the no-SDK / no-runtime-portal / no-packs / no-module-level-sandbox / hvac-clean rules **still apply** to them (the run store imports only `core.decision_history` + SQLAlchemy — no sandbox, no hvac).

**NOT in scope (deferred):**
- **A3b:** executor wiring (genesis + terminal `runs` rows from the run lifecycle), `run_id` on `RunResponse`, the run→session resolver, the dedicated `POST /api/v1/runs/{run_id}/resume` route, `backend.wake(session_id)` dispatch, the executor Fork-A→Fork-B rework (don't-destroy-on-suspend; persist `session_id`), and the suspend/wake transition pairs.
- **A3c:** `CheckpointMetadata` approval fields, wake-path `admit_policy` approval correlator threading, the high-risk re-verify proof.
- A3a touches **NONE** of `core/run/executor.py`, `portal/api/runs/*`, or the sandbox modules.

## 3. The `runs` table (Fork D — confirmed)

| Column | Type | Null | Notes |
|---|---|---|---|
| `run_id` | UUID | PK | the durable run identity (distinct from `task_id`; a future retry may mint a new task under the same run) |
| `tenant_id` | String(128) | NOT NULL | the cross-tenant-invisibility boundary |
| `pack_id` | String(128) | NOT NULL | pack identity (display/scoping) |
| `pack_uuid` | UUID | NOT NULL | trusted pack load key (the executor's `RunRequest.pack_uuid`) |
| `pack_version` | String(128) | NOT NULL | caller-supplied display context |
| `task_id` | UUID | nullable | the scheduler task once submitted; NULL pre-submit / on pre-submit refusal |
| `session_id` | String(128) | nullable | the sandbox session (A3b populates) |
| `checkpoint_id` | String(32) | nullable | the latest checkpoint to restore (A3b/A3c); the sandbox `CheckpointId = NewType("CheckpointId", str)` — a **32-char hex string** (`uuid4().hex`), NOT a `UUID` column (matches `protocol.py:425` / `checkpoint_store.py:284,829`) |
| `approval_request_id` | UUID | nullable | the approval correlator on a pending/approved run (A3c) |
| `state` | String(32) | NOT NULL | a `RunState` value (app-validated against the closed enum; CHECK constraint optional, mirroring `scheduler_tasks`) |
| `created_at` | TIMESTAMP(tz) | NOT NULL | genesis timestamp |
| `updated_at` | TIMESTAMP(tz) | NOT NULL | last state-change timestamp |

Composite index `ix_runs_tenant_state` on `(tenant_id, state)` for the A3b/examiner list seam (mirrors `ix_packs_tenant_state`). `exit_code` / `refusal_reason` / `from_state` / `to_state` are **NOT columns** — they ride the chain row's value-free payload snapshot (§7), keeping the table to structural identity + state.

## 4. `RunState` closed enum (Fork B — full vocab upfront)

Nine values, fixed at A3a (the **stored vocabulary**):

```
pending, running, completed, failed, refused, pending_approval, suspended, woken, cancelled
```

- **Active in A3a** (the synchronous run path the executor will produce at A3b): `pending` (genesis) · `running` · `completed` · `failed` · `refused` · `pending_approval`.
- **Reserved (no A3a transition; A3b/future)**: `suspended`, `woken` (A3b suspend/wake), `cancelled` (a future run-layer mirror of scheduler cancellation — included now per the forward-compat doctrine so the vocabulary never churns).

Pinned by a closed-enum drift detector (`typing.get_args(RunState)` == the 9-value set; count-9 guard) at `tests/unit/core/run/test_run_types.py`.

## 5. Transition table — A3a synchronous subset + reserved pairs

`validate_transition(*, from_state, to_state)` (keyword-only, pure-functional, mirrors `core/scheduler/_types.validate_transition`) permits **only** the pairs A3a can prove:

| from | to | reason |
|---|---|---|
| `pending` | `running` | run admitted + mark_running |
| `pending` | `refused` | pre-running refusal (pack validation, scheduler refusal, queued-unsupported) |
| `running` | `completed` | exec returned (any exit code) |
| `running` | `failed` | infra create/exec exception |
| `running` | `refused` | sandbox governance/admission refusal |
| `running` | `pending_approval` | sandbox approval pending at create |

Everything else (esp. `running → suspended`, `suspended → woken`, `woken → running`, `* → cancelled`) is **NOT** in the A3a legal set → `validate_transition` raises `RunTransitionRefused("run_transition_invalid_state_pair")`. A3a tests assert a sample reserved pair (e.g. `running → suspended`) currently REFUSES.

## 6. The "full enum upfront, transition subset now" doctrine (the spec-time pin)

**Locked invariant:** future slices (A3b/A3c) may **only EXPAND the legal-transition matrix** — they may **NEVER change the stored `RunState` vocabulary**. The 9-value enum is the durable wire/column vocabulary; growing it later would be a column-vocabulary migration. Adding suspend/wake/cancel is purely adding legal *pairs* to `validate_transition` over the already-defined states.

Pinned three ways: (1) the closed-enum drift detector fixes the 9-value `RunState` set; (2) `validate_transition`'s legal-pair set is the A3a subset, with the reserved pairs documented inline as "A3b/A3c expansion"; (3) a test (`test_reserved_pairs_refuse_until_expanded`) asserts the reserved pairs refuse today — so A3b adding them is provably an *expansion*, not a vocabulary change.

## 7. `RunRecordStore` API + atomicity (Doctrine Lock D)

Mirrors `core/scheduler/storage.py` exactly:

- **`create_run(*, run_id, tenant_id, pack_id, pack_uuid, pack_version, task_id=None, request_id) -> AppendResult`** — genesis: INSERT a `state="pending"` `runs` row **and** append a `run.lifecycle.pending` chain row in **one** transaction via `append_with_precondition` (the precondition closure does the INSERT; the record builder mints the `DecisionRecord`).
- **`transition(*, run_id, tenant_id, from_state, to_state, request_id, actor_id, session_id=None, task_id=None, checkpoint_id=None, approval_request_id=None, payload_extras=None) -> AppendResult`** — `SELECT ... FOR UPDATE` the `runs` row (tenant-scoped) → if absent raise `RunNotFound`; if `row.state != from_state` raise `RunTransitionRefused("run_transition_invalid_state_pair")` (the **single** scheduler-consistent reason — stale-read AND illegal-pair share one closed-enum value, mirroring `core/scheduler/storage.py`; `RunTransitionRefused`'s Literal carries exactly this one value) → `validate_transition(from_state, to_state)` (pure-functional) → `UPDATE runs SET state=to_state, updated_at, + any provided nullable columns (session_id/task_id/checkpoint_id/approval_request_id)` under the lock → return the captured `_LockedRunSnapshot`; the record builder mints `run.lifecycle.<to_state>` with the value-free snapshot. The optional column kwargs are additive seams A3b/A3c populate (session_id on suspend, checkpoint_id/approval_request_id on the approval/checkpoint paths); A3a tests exercise them, no production caller.
- **`load(run_id, *, tenant_id) -> RunRecord | None`** — the A3b resolver substrate (`run_id → RunRecord` incl. `session_id`). **Tenant-scoped:** a run owned by another tenant returns `None` (cross-tenant-invisible at the store boundary, mirroring the tenant-isolation doctrine — see §8).
- **`list_for_tenant(tenant_id, *, limit=50, cursor=None, state=None) -> list[RunRecord]`** — tenant-scoped list over `ix_runs_tenant_state` (mirrors `packs.storage.list_for_tenant`); the `tenant_id` WHERE clause IS the boundary.

**Atomicity (Doctrine Lock D):** chain-head `FOR UPDATE` → run-row `FOR UPDATE` → `validate_transition` → state-cache UPDATE → chain row INSERT → chain-head UPDATE, all inside the single `append_with_precondition` `engine.begin()` transaction. Any failure rolls back all three (no orphan row, no orphan chain row). Integration tests pin row-lock serialisation on live Postgres + Oracle (env-gated `COGNIC_RUN_POSTGRES_INTEGRATION=1` / `COGNIC_RUN_ORACLE_INTEGRATION=1`).

## 8. Tenant isolation (cross-tenant read collapse)

`load(run_id, *, tenant_id)` returns `None` for a run owned by another tenant — a probe cannot distinguish "unknown run" from "another tenant's run" (the wire-collapse doctrine `packs`/`models` ship; the portal 404 mapping is A3b's concern, but the store boundary is established here so the substrate is tenant-safe by construction). `list_for_tenant` filters by `tenant_id`. The `transition`'s `SELECT ... FOR UPDATE` is tenant-scoped (a cross-tenant `run_id` reads as absent → `RunNotFound`). `tenant_id` is `NOT NULL` on the table.

## 9. Value-free payload snapshot (chain-payload-is-evidence-snapshot)

The `run.lifecycle.<state>` chain row's payload is the run-record evidence snapshot — `run_id`, `tenant_id`, `pack_id`, `pack_uuid` (str), `pack_version`, `task_id` (str|None), `session_id`, `checkpoint_id` (str|None), `approval_request_id` (str|None), `from_state` (None on genesis), `to_state`, `created_at`/`updated_at` (isoformat) + any `payload_extras`. **Value-free:** no raw stdout/stderr (the executor's separate `run.completed` evidence rows carry the output digests; §10 keeps them distinct). `iso_controls` deferred (`()`) — a Human-only mapping decision, matching the executor's `_RUN_EVIDENCE_ISO_CONTROLS = ()`.

## 10. Chain namespace (Fork C — distinct `run.lifecycle.*`)

The store emits `run.lifecycle.<state>` events (`run.lifecycle.pending` / `…running` / `…completed` / `…failed` / `…refused` / `…pending_approval`; the reserved states' events land when A3b/A3c add their transitions). These are **distinct** from the executor's existing value-free `run.completed` / `run.failed` / `run.refused` / `run.pending_approval` output-evidence rows (emitted directly via `DecisionHistoryStore.append` in `executor.py`). A3a does NOT touch the executor's `_emit_*`; whether A3b reconciles the two surfaces (fold the executor's output evidence into the store transition, or keep dual surfaces — lifecycle-state vs output-evidence) is an explicit **A3b decision**, deliberately left open here.

## 11. CC posture

- **`core/run/storage.py`** — ON the durable per-file critical-controls gate (tenant-isolation + chain-atomicity boundary; mirrors `core/scheduler/storage.py` + `packs/storage.py`). **Count 130 → 131.** Verify-at-promotion ≥ 95/90 on fresh `--cov-branch coverage.json` in the landing commit; CC count pin bumped in BOTH `tools/check_critical_coverage.py` AND `tests/unit/tools/test_check_critical_coverage.py` `_EXPECTED_ENTRY_COUNT`.
- **`core/run/_types.py`** — OFF the gate (pure types + pure-functional `validate_transition`; closed-enum + state-machine drift detectors cover the surface — mirrors `core/scheduler/_types.py`, which is off-gate).
- **The migration** — off-gate (run-once DDL, Doctrine F migration carve-out).
- The architecture-fence update (`test_run_no_sdk_import.py` expected-sources) is a test-only change.

## 12. Module layout

```
src/cognic_agentos/core/run/
  __init__.py        (unchanged)
  executor.py        (unchanged — A3a does NOT touch it)
  _types.py          (NEW, off-gate) RunState + RunRecord + validate_transition + RunTransitionRefused
  storage.py         (NEW, on-gate)  RunRecordStore + runs Table + _LockedRunSnapshot + RunNotFound
src/cognic_agentos/db/migrations/versions/
  20260615_0011_runs.py   (NEW, off-gate)
tests/unit/core/run/
  test_run_types.py       (NEW) enum drift + state machine + reserved-pair refusal + the doctrine pin
  test_run_storage.py     (NEW) genesis / transition / load / list_for_tenant / tenant-isolation / atomicity (in-memory sqlite)
tests/integration/run/
  test_run_storage_rowlock.py  (NEW, env-gated PG/Oracle row-lock serialisation)
tests/unit/architecture/
  test_run_no_sdk_import.py     (MODIFY) expected-sources set += _types.py, storage.py
```

## 13. Test surface

- **`_types`:** `RunState` is exactly the 9 values (drift detector); `validate_transition` permits the 6 A3a pairs (`pending→running`, `pending→refused`, `running→{completed,failed,refused,pending_approval}`); a reserved pair (`running → suspended`) refuses with `run_transition_invalid_state_pair`; the doctrine pin (`test_reserved_pairs_refuse_until_expanded`).
- **`storage`:** `create_run` inserts a `pending` row + one `run.lifecycle.pending` chain row atomically; each A3a transition updates state + emits `run.lifecycle.<to_state>`; `from_state` mismatch → `RunTransitionRefused`; missing run → `RunNotFound`; optional column kwargs (session_id/checkpoint_id/approval_request_id) persist when provided; `load`/`list_for_tenant` are tenant-scoped (cross-tenant → None/empty); the chain payload is the value-free snapshot (no raw output); a refusal rolls back (no orphan row).
- **integration (env-gated):** concurrent transitions serialise on the run-row + chain-head locks (PG + Oracle).
- **architecture fence:** the two new modules carry no SDK / runtime-portal / packs / module-level-sandbox import; the hvac probe stays green.

## 14. Resolved decisions
- **A (scope):** store-only / dormant; A3a does NOT touch `executor.py` / `RunResponse` / the route; A3b wires it.
- **B (vocabulary):** full 9-value `RunState` upfront (`pending`/`running`/`completed`/`failed`/`refused`/`pending_approval`/`suspended`/`woken`/`cancelled`); `validate_transition` permits only the synchronous subset; `cancelled` included as a reserved forward-compat state.
- **C (chain namespace):** distinct `run.lifecycle.<state>` events; the executor's existing `run.<terminal>` evidence rows stay separate; reconciliation is an A3b decision.
- **D (schema):** the §3 table; cross-tenant reads collapse to None; `append_with_precondition` atomicity.
- **Doctrine pin:** future slices only EXPAND the legal-transition matrix, never the stored `RunState` vocabulary (§6).
- **CC:** `core/run/storage.py` on-gate (count 130 → 131); `_types.py` + migration off-gate.
