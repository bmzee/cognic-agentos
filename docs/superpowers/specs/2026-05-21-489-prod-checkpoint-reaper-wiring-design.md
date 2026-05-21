# #489 — Production checkpoint-reaper wiring — design

**Date:** 2026-05-21
**Status:** approved — see implementation plan `docs/superpowers/plans/2026-05-21-489-prod-checkpoint-reaper-wiring.md`
**Subsystem:** sandbox primitive (resumable-session retention) + portal app factory + persistence adapters
**Relevant ADRs:** ADR-004 (sandbox primitive / resumable session API), ADR-009 (pluggable infrastructure adapters), ADR-006 (audit-chain evidence)

---

## 1. Problem statement

Sprint 8.5 landed the resumable-session retention reaper:

- `CheckpointStore.purge_expired()` (`sandbox/checkpoint_store.py`) — the substantive
  retention-floor enforcement point.
- `CheckpointReaper` (`sandbox/reaper.py`) — a single-instance asyncio loop driving
  `purge_expired()` on a schedule.
- An opt-in `create_app(checkpoint_store=...)` seam (Sprint 8.5 T10): when a pre-built
  `CheckpointStore` is injected, the FastAPI lifespan starts a `CheckpointReaper`
  background task and cancels it on shutdown.

The gap: **`create_prod_app()` never constructs a `CheckpointStore`.** It is a thin
wrapper — `create_app(adapter_registry=bundled_registry)` plus MCP/A2A SDK-presence
logging. The `checkpoint_store=` kwarg expects a *pre-built* store, but the store's
dependencies only exist *inside the lifespan*:

- `CheckpointStore.__init__` requires an `ObjectStoreAdapter`, an `AuditStore`, and a
  `DecisionHistoryStore`.
- `AuditStore` and `DecisionHistoryStore` each take a raw SQLAlchemy `AsyncEngine`.
- The object store and the DB engine are built by `build_adapters()` → `open_all()`
  *during* the lifespan — they do not exist when `create_app` is called.

So a pre-built store cannot be passed to `create_app` in production. The retention
reaper therefore never runs in a production deployment: expired checkpoints accumulate
indefinitely.

## 2. Goals

Wire the checkpoint reaper so it runs under `create_prod_app`, by constructing the
`CheckpointStore` *inside the lifespan* from the live adapter pool, gated by an
operator-controlled setting.

## 3. Non-goals (explicitly out of scope)

- **Kubernetes manifests / PersistentVolume / reaper Deployment YAML** — the production
  `local_fs` object-store root needs a persistent path, and the single-instance posture
  implies a designated reaper instance. These deployment artifacts belong to the
  Sprint 14 deployment kit.
- **Cross-instance leader election** — multi-replica reaper coordination is deferred to
  Sprint 10.5 (the scheduler primitive). See §6.
- **Running alembic migrations** — the `decision_history` / `audit_event` tables are an
  existing operational precondition created by `run_migrations` as a separate ops step.
  #489's reaper assumes the schema exists, the same assumption every other DB-touching
  feature already makes.
- The rejected engine-seam alternatives (a dedicated second engine; concrete-adapter
  `isinstance` narrowing) — see §7.

## 4. Design

### §4.1 Setting

Add `sandbox_reaper_enabled: bool = False` to `Settings` (`core/config.py`).

- **Default OFF.** AgentOS's production target is OpenShift / Kubernetes, which runs
  multiple replicas. The Sprint 8.5 reaper is single-instance-by-design: N replicas each
  starting a reaper produce N reapers racing on the same shared object-store backend,
  yielding duplicate `sandbox.lifecycle.checkpoint_purged` audit-chain rows (the
  underlying byte-level deletes stay idempotent and safe; the duplication is an
  examiner-facing audit-noise problem). See `sandbox/reaper.py` module docstring and the
  Sprint 8.5 spec §13.
- Operators set `sandbox_reaper_enabled=true` on **exactly one** instance (or a
  dedicated single-replica reaper Deployment).
- The default-OFF posture carries a silent-no-op risk — an operator who never sets the
  flag gets no reaper. This is mitigated by a loud startup log (§4.3).

### §4.2 Engine seam — `RelationalAdapter.engine`

`AuditStore` and `DecisionHistoryStore` have always taken a raw `AsyncEngine`. The
`RelationalAdapter` protocol (`db/adapters/protocols.py`) currently exposes
`connect / session() / run_migrations / close / health_check` — **no engine accessor**.
Something must bridge adapter → engine; the adapter is the honest owner of the
connection it already holds.

Add a read-only `engine` accessor to the `RelationalAdapter` protocol:

- `PostgresAdapter`, `OracleAdapter`, and the `tests/support` `InMemoryRelationalAdapter`
  each already hold a `self._engine: AsyncEngine`; each exposes it through the new
  accessor. The accessor is a uniform trivial exposure across all three.
- **Lifecycle stays adapter-owned.** `connect()` creates the engine; `close()` disposes
  it. The `engine` accessor is read-only — consumers (the checkpoint stores) **must not
  dispose it**.
- **Pre-connect access fails loud.** Accessed before `connect()` has run (engine is
  `None`), the accessor raises a clear error rather than returning a half-live handle.
  In the production flow the lifespan only reads `engine` after `open_all()`, so the
  raise path is defensive.

This is a protocol change to the Sprint 1C adapters layer. It is small and well-bounded
(exposing existing state through the proper interface), but it touches every relational
adapter implementation and is covered by an explicit conformance test (§4.5).

### §4.3 Lifespan wiring (`portal/api/app.py`)

A module-private helper `_build_checkpoint_store_from_adapters(adapters, settings)`
constructs the production store from the live adapter pool:
`AuditStore(adapters.relational.engine)` + `DecisionHistoryStore(adapters.relational.engine)`
+ `CheckpointStore(object_store=adapters.object_store, audit_store=..., decision_history_store=..., settings=settings)`.

The lifespan decides whether and how to start the reaper, with this **precedence**:

1. **Explicit `create_app(checkpoint_store=...)` injected.** Start the reaper from the
   injected store. The `sandbox_reaper_enabled` setting is irrelevant on this path, and
   **no adapter registry is required** — the injected store is fully self-contained
   (its own engine, audit store, object store). This preserves the Sprint 8.5 T10 test
   seam unchanged, including the `adapter_registry is None` path. This path **never**
   fails startup for adapter reasons, because it never touches the adapter pool.

2. **Else, `sandbox_reaper_enabled=True`.** Build the store from the adapter pool via the
   helper and start the reaper. On this path the production adapters are required:

   - **Fail-loud (guardrail).** If the needed production adapters are unavailable or
     unusable — no adapter registry / pool, `adapters.object_store is None`, or the
     relational `engine` is unavailable — the lifespan raises a fail-loud `RuntimeError`
     at startup whose message names the missing dependency. Startup fails; the reaper is
     **never silently disabled** when an operator explicitly asked for it.
   - The fail-loud condition is scoped to *this* path only. It is not triggered by the
     explicit-injection path (§4.3.1) or the default path (§4.3.3).

3. **Else (default — `sandbox_reaper_enabled=False`, no injection).** No reaper task is
   created. The lifespan emits a loud info-level log:
   *"checkpoint reaper disabled — set `sandbox_reaper_enabled=true` on exactly one
   instance to run the resumable-session retention sweep."* Startup is unaffected.

On the enabled-and-started paths the lifespan emits a loud info log confirming the
reaper started on this instance.

**Ordering invariants:**

- The setting-driven reaper is created only **after `open_all()`** — the adapter pool
  (object store + relational engine) must be live before the store is built
  (guardrail 3).
- The checkpoint reaper task is **cancelled and awaited before `adapters.close_all()`**
  runs, so the shared adapter-owned engine is never disposed under an in-flight sweep.
  This is a small restructure of the current lifespan, where the reaper-cleanup block
  runs *after* `close_all()`. The SSE `reap_task` cleanup moves alongside it into a
  single pre-`close_all()` cleanup block for a comprehensible shutdown sequence.

**`create_prod_app` itself needs no code change.** It already passes
`adapter_registry=bundled_registry`, which enables the adapter pool the lifespan needs;
the setting plus the lifespan path do the rest. (Honesty note: the task is "the reaper
runs under `create_prod_app`," achieved through the setting + lifespan wiring, not
through a `create_prod_app` diff. A startup log line confirming the reaper posture is
the only optional `create_prod_app`-adjacent addition and may be folded into the
lifespan logs of §4.3.)

### §4.4 Operator runbook

A new `docs/operator-runbooks/checkpoint-reaper.md` covering:

- What the reaper does (resumable-session retention-floor enforcement).
- **Enable on exactly one instance.** Multiple enabled instances produce duplicate
  `checkpoint_purged` audit rows until Sprint 10.5 leader election; deletes stay safe.
- The `local_fs` object-store root (`Settings.local_object_store_root`) must be a
  persistent path — in Kubernetes, a PersistentVolume — shared by whatever instance runs
  the reaper.
- Alembic migrations must have run (`decision_history` / `audit_event` tables present).
- How to read the startup log to confirm the reaper posture (started here / disabled).
- The fail-loud behavior: if `sandbox_reaper_enabled=true` and the adapters are
  misconfigured, the process fails to start with a message naming the missing
  dependency — this is intentional.

### §4.5 Testing

- **Protocol conformance.** A test asserting the `engine` accessor on every relational
  adapter implementation — `PostgresAdapter`, `OracleAdapter`, `InMemoryRelationalAdapter`
  — yields the live `AsyncEngine` after `connect()` and fails loud before `connect()`
  (guardrail 1).
- **Lifespan scenarios** (`tests/unit/portal/api/`):
  - disabled (default) → no reaper task created + the loud info log emitted.
  - `sandbox_reaper_enabled=True` + adapters healthy → a reaper task is created and
    running; `app.state` reflects it.
  - `sandbox_reaper_enabled=True` + `object_store` unavailable → startup raises the
    fail-loud `RuntimeError` naming the object store.
  - `sandbox_reaper_enabled=True` + relational engine unavailable → startup raises the
    fail-loud `RuntimeError` naming the engine.
  - `sandbox_reaper_enabled=True` + no adapter registry → startup raises fail-loud.
  - explicit `create_app(checkpoint_store=...)` injection still starts a reaper, with
    no adapter registry, and does **not** fail loud — the T10 seam is intact.
- **Shutdown ordering.** A test pinning that the reaper task is cancelled and awaited
  before `adapters.close_all()` (the shared engine is not disposed under an in-flight
  sweep).

## 5. Acceptance criteria

- **AC1** — `Settings.sandbox_reaper_enabled` exists, defaults `False`.
- **AC2** — `RelationalAdapter` protocol declares a read-only `engine` accessor;
  `PostgresAdapter`, `OracleAdapter`, `InMemoryRelationalAdapter` all implement it;
  conformance test green.
- **AC3** — With `sandbox_reaper_enabled=True` and a healthy bundled adapter pool, a
  `CheckpointReaper` task is constructed in the lifespan from the adapter-pool engine +
  object store and runs; confirmed by a lifespan test.
- **AC4** — With `sandbox_reaper_enabled=True` and the object store or relational engine
  unavailable/unusable, startup raises a fail-loud `RuntimeError` naming the missing
  dependency. No silent disable.
- **AC5** — The explicit `create_app(checkpoint_store=...)` injection path is unchanged:
  starts a reaper, requires no adapter registry, never fails loud for adapter reasons.
- **AC6** — On shutdown, the reaper task is cancelled and awaited before
  `adapters.close_all()`; pinned by a test.
- **AC7** — Default path (`sandbox_reaper_enabled=False`, no injection) creates no reaper
  and emits the loud disabled-posture info log; startup unaffected.
- **AC8** — `docs/operator-runbooks/checkpoint-reaper.md` exists and covers the
  single-instance posture, persistent object-store root, migration precondition, and
  startup-log interpretation.
- **AC9** — Full gate ladder green: `ruff check` + `ruff format --check` +
  `mypy src tests` + full `pytest` suite; the critical-controls coverage gate unaffected
  (no CC module's constructor changes; `sandbox/checkpoint_store.py` and
  `sandbox/reaper.py` are not modified).

## 6. Multi-replica posture and the deferred Sprint 10.5 path

The default-OFF setting is a deliberate honest posture, not a workaround. Until Sprint
10.5 introduces the scheduler primitive (the natural cross-instance coordination point),
AgentOS has no leader election; running one reaper is the only way to keep the audit
chain free of duplicate `checkpoint_purged` rows. #489 makes the single-instance reaper
*possible and operator-controlled* in production; Sprint 10.5 makes multi-instance
*safe*. The operator runbook (§4.4) is explicit about this boundary.

## 7. Rejected alternatives

- **Approach B — dedicated checkpoint engine.** Build a second `AsyncEngine` from
  `Settings.database_url` purely for the checkpoint stores. Rejected: a second
  connection pool to the same database alongside the adapter pool, with its own
  lifecycle to manage — a real duplication smell in a production system. Approach A
  reuses the one pool the rest of production uses.
- **Approach C — concrete-adapter `isinstance` narrowing.** Branch on
  `isinstance(adapters.relational, (PostgresAdapter, OracleAdapter))` and read a
  concrete-class-only engine property. Rejected: `isinstance` branching on concrete
  adapter classes in the lifespan is a code smell and does not generalize — a third
  relational driver means editing the tuple. It carries Approach A's protocol-coupling
  cost without A's clean protocol interface.

## 8. Files touched

**Modified:**

- `src/cognic_agentos/core/config.py` — add `sandbox_reaper_enabled` setting.
- `src/cognic_agentos/db/adapters/protocols.py` — add `engine` to `RelationalAdapter`.
- `src/cognic_agentos/db/adapters/postgres_adapter.py` — `engine` accessor.
- `src/cognic_agentos/db/adapters/oracle_adapter.py` — `engine` accessor.
- `tests/support/adapter_fixtures.py` — `engine` accessor on `InMemoryRelationalAdapter`.
- `src/cognic_agentos/portal/api/app.py` — `_build_checkpoint_store_from_adapters`
  helper; lifespan reaper-construction precedence + fail-loud + shutdown-ordering
  restructure + posture logs.

**Created:**

- `docs/operator-runbooks/checkpoint-reaper.md` — operator runbook.
- Unit tests: relational-adapter `engine` conformance; `portal/api/app.py` lifespan
  scenario + shutdown-ordering tests.

**Not modified (deliberately):** `sandbox/checkpoint_store.py`, `sandbox/reaper.py`,
`core/audit.py`, `core/decision_history.py` — no critical-controls module's contract
changes; #489 is wiring around existing primitives.
