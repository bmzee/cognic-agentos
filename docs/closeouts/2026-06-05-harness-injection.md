# Harness Injection — Closeout (2026-06-05)

**Branch:** `feat/harness-injection` · **Workstream #2** of the deployable-without-code-surgery sequence (Pre-GA Configurability Audit → Wave-1 Deploy-Safety → **Harness Injection**).

**Goal met:** AgentOS now has a canonical OS composition root. `harness/build_runtime(settings, adapters) -> Runtime` constructs the real kernel runtime — the `LLMGateway` (built from live config, activating the Wave-1 T3 `vault://` master-key seam) and the governed-memory `MemoryApiFactory` — from Settings + the live adapter pool, and is wired into the FastAPI lifespan. The `/api/v1/memory` portal surface resolves that factory at request time and fails closed `503` until the lifespan populates it. Redis is now a first-class adapter (no harness-local client).

Source spec: `docs/superpowers/specs/2026-06-05-harness-injection-design.md`.
Plan-of-record: `docs/superpowers/plans/2026-06-05-harness-injection.md`.

## The 13 commits (3 docs + T1–T9 + 1 fence reconciliation)

| Task | Commit | What |
|---|---|---|
| docs | `11a12e1` | design spec — B1-fenced OS composition root |
| docs | `d1d683c` | spec follow-up — two-bundle memory policy router + gateway/memory config surface |
| docs | `f32511b` | plan-of-record + spec alignment (vector decouple, redis import, two-bundle router) |
| T1 | `6d6976a` | `CacheAdapter` protocol + cache registry typing + in-memory fixture |
| T2 | `71076d0` | real `RedisAdapter` cache driver (optional `adapters` extra) |
| T4 | `1f5780f` | cache/gateway/memory Settings + strict-profile cache guards (G9/G10) |
| T3 | `17b8abd` | `Adapters.cache` field + factory wiring + `"none"`-opt-out skip |
| T5 | `247fcea` | `build_runtime` composition root — gateway path |
| T6 | `0269ac0` | two-bundle `MemoryPolicyRouter` + `build_runtime` memory factory |
| fence | `b8719db` | exempt the composition root from the memory-storage fence (T6 reconciliation) |
| T7 | `9c957de` | `/memory` handlers resolve the factory from `app.state` + `503` fail-closed |
| T8 | `ce50283` | wire `build_runtime` into the `create_app` lifespan + construction-time `/memory` gate + `llm_gateway` seam |
| T9 | `daf6f43` | architecture fences (no Layer-C / no local Redis / no 2nd engine / no Bucket-1 default / real kill switch) |
| T10 | (this doc) | Z-gate: full suite + critical-coverage + closeout |

> **Execution order** was header-pinned `T1 → T2 → T4 → T3 → T5 → T6 → T7 → T8 → T9 → T10` (T4 config before T3 factory because `build_adapters` reads `settings.cache_driver`).

## The B1 fence (scope lock)

`Runtime`'s public members are exactly the two Bucket-2 seams — `{llm_gateway, memory_api_factory}` (the spine `audit_store` / `decision_history_store` / `memory_policy` / `_http_client` are exposed but nothing new consumes them this workstream). **Deferred by the fence:** `ParentBudgetResolver`, `VaultCredentialAdapter`, any Bucket-1 bank-overlay default, Bucket-3 (scheduler/quota) construction, the managed-agent substrate, and any `core/memory/` edit.

## Key architectural decisions

- **Two-bundle `MemoryPolicyRouter` (`harness/memory_policy.py`).** `OPAEngine` is a single-FILE loader (`core/policy/engine.py` — `bundle_path.is_file()`), but `MemoryGate` queries four decision points spanning `memory.rego` (long_term / cross_subject / restricted_class_write) and `memory_purpose_matrix.rego` (recall.purpose_compatible). The harness-owned router fronts two `OPAEngine`s, dispatches each point to the right bundle, and raises `MemoryPolicyDecisionPointUnknown` (fail-loud) on any other point. It is passed as `MemoryAPI`'s `policy` with the **single** `# type: ignore[arg-type]` (`runtime.py:156` — the router conforms structurally; `MemoryGate` types `policy: OPAEngine`). A test-only drift detector pins the router's four decision-point constants against `core/memory/gate.py` (no runtime cross-import).
- **Cache as a first-class adapter** (not harness-local). `CacheAdapter` Protocol + `_AsyncKVClient` (`db/adapters/protocols.py`); real `RedisAdapter` behind the `adapters` extra (`db/adapters/redis_adapter.py`); `cache_driver: Literal["none","redis","memory"]` **default `"none"`** (opt-out — pack-only deploys wire no cache); `Adapters.cache` is `None` when `cache_driver="none"`, which is exactly the signal `build_runtime` uses to skip the memory branch (gateway-only).
- **Mount strategy.** `/memory` mounts at **construction time** when a factory is injected (test path) OR `settings.cache_driver != "none"` (prod). `build_runtime` then populates `app.state.memory_api_factory` in the lifespan; the request-time `_require_memory_api_factory` dependency fails closed `503 memory_unavailable` if a request arrives before population. `cache_driver="none"` with no injected factory mounts nothing.
- **Leak-safety ordering.** Inside `build_runtime`, the `httpx.AsyncClient` (the gateway's only owned resource; `LLMGateway` has no close method) is allocated **last** — after every fallible step (preflight YAML, SLA, `vault://` resolve, and the memory branch's `OPAEngine.create` / `ensure_collection`). A raise can never orphan it before `Runtime` (and its `aclose`) exists.
- **Runtime-first shutdown** (user-locked). In the lifespan inner `finally`, `runtime.aclose()` runs **before** `adapters.close_all()` (the runtime's `memory_api_factory` closes over adapter-backed clients), getattr-guarded so a `build_runtime` failure never `AttributeError`s.

## The 8 new Settings (`core/config.py`, T4)

`cache_driver` (Literal, default `"none"`), `redis_url`, `litellm_config_path` (default `infra/litellm/config.yaml`), `llm_sla_total_budget_s` (30.0), `llm_sla_warning_threshold_s` (20.0), `memory_policy_bundle` (`policies/_default/memory.rego`), `memory_purpose_matrix_policy_bundle` (`policies/_default/memory_purpose_matrix.rego`), `memory_vector_recall_enabled` (`False`).

Plus two strict-profile cache guards in `_validate_wave1_deploy_safety_guards` (TM-revert-proven): **G9** `cache_driver_memory_forbidden_in_strict_profile` (ADR-018 cross-instance freeze needs distributed Redis, not in-process memory), **G10** `redis_url_unset_for_redis_cache_driver` (every profile).

## The composition-root fence reconciliation (`b8719db`)

T6 made `harness/runtime.py` the first **production** composition of `MemoryAPI`, so it runtime-imports `core.memory.storage` (`PostgresMemoryAdapter` / `RedisMemoryAdapter`) to name the concrete adapters and inject them into `MemoryAPI`. The Sprint-11.5a `test_memory_layer_c_no_direct_storage` fence (a blanket "no `src/` module except `storage.py` may import `core.memory.storage`") predated any production composition root and flagged it. Resolution (its own honest commit, **not** folded into T7): exempt the composition root — path-pinned, analogous to `storage.py`'s self-exemption — because it *wires* adapters into `MemoryAPI` (which enforces `MemoryGate` on every op) and never calls `put`/`get` itself. The narrowness is enforced by `test_composition_root_is_the_only_runtime_importer` (whole-tree scan asserting the composition root is the SOLE runtime importer; TM-revert-proven).

## Architecture fences (T9, `tests/unit/architecture/test_harness_fences.py`)

The 5 B1 pins over `harness/*.py`: no Layer-C (`cognic_agentos.agents.*`) import; no harness-local Redis client (consumes `adapters.cache.client`); no second SQLAlchemy engine (reuses `adapters.relational.engine`); no Bucket-1 bank-overlay default (`KernelDefault*`); and the behavioural pin that the wired kill switch is a real `RedisMemoryWriteFreezeKillSwitch`, never the `_Null` fail-loud sentinel. A non-vacuous `test_harness_dir_has_expected_sources` guard pins the exact `{__init__, memory_policy, runtime}.py` set.

## TM-revert ledger (load-bearing proofs)

- **http_client leak (T6):** with the client allocated before the memory branch, `test_http_client_not_constructed_when_memory_construction_fails` FAILED (client constructed then orphaned by the raise) → restructured so it's allocated last → passes.
- **kill switch real-not-`_Null` (T9):** `build_runtime` passing `kill_switch=None` made the gate bind `_NullMemoryKillSwitchInterrogator` → the `isinstance` pin FAILED (error named the `_Null` sentinel) → restored.
- **fence narrowness (`b8719db`):** injecting a second `core.memory.storage` runtime importer made `test_composition_root_is_the_only_runtime_importer` FAIL (flagged the extra module) → reverted.
- **G9/G10 cache guards (T4):** each guard neutralized in isolation → its negative test FAILED → restored.

## Gate evidence (Z-gate, fresh `--cov-branch coverage.json`)

- **Full unit suite:** 9645 passed, 96 skipped (the skips are standing env-gated integration/K8s-live tests).
- **Full-tree:** `ruff check .` ✅ · `ruff format --check .` ✅ (748 files) · `mypy src tests` ✅ (732 files).
- **Per-file critical-controls coverage gate: passed — 112/112, count unchanged.** The harness is **off** the per-file gate (Doctrine F — enforcement lives in the already-on-gate wired modules: `core/memory/{api,gate,storage,consent}.py`, `core/dlp/scanner.py`, `core/emergency/kill_switches.py`, `OPAEngine`).
- **On-gate module touched by T7 — verified no regression:** `portal/api/memory/routes.py` is on the gate (`0.95`/`0.90`) and T7 modified it (request-time resolver + `503` path + 4 handler dep injections). The Z-gate confirms it held at **line 100.00% / branch 100.00%**. The single real `# type: ignore` is the documented T6 one.

> **Process note (recorded as a lesson):** the plan's T10 step asserted "routes off-gate", which was **wrong** — `memory/routes.py` is on the gate. T7 ran the full suite at its commit but not `check_critical_coverage.py`, so the on-gate floor was first re-verified here at the Z-gate (and held). A future task that modifies an on-gate CC module should run the critical-coverage gate **at that commit**, and verify a module's gate status against `tools/check_critical_coverage.py::_CRITICAL_FILES` rather than trusting a plan's classification.

## Honesty markers (scope truth)

- **Gateway — primitive-wired, consumption-deferred.** `build_runtime` constructs the real `LLMGateway` from live config (activating the Wave-1 T3 `vault://` master-key resolution) and publishes it on `app.state.llm_gateway`. But **no in-repo path consumes `app.state.llm_gateway` yet** — live gateway *use* lands when an agent / LLM-call path reads it. The seam is real, swappable, and deployable; its consumer is a later workstream.
- **Memory — live portal consumer.** The `/api/v1/memory` endpoints resolve the factory and run the full governed-memory path (gate → DLP → consent → kill-switch → adapter) against the lifespan-built runtime.
- **`vector_index` — opt-in, default OFF** via `memory_vector_recall_enabled`. `/memory` startup is NOT coupled to the vector backend (qdrant) reachability by default; `ensure_collection()` runs only when enabled.
- **Not wired (deferred):** `ParentBudgetResolver`, `VaultCredentialAdapter` (the sandbox credential adapter), any Bucket-1 bank-overlay default, Bucket-3 scheduler/quota construction, and the managed-agent substrate.

## Open follow-ups (recorded, out of Workstream #2 scope)

1. **Gateway consumption.** Add the first in-repo reader of `app.state.llm_gateway` (an agent / LLM-call path), retiring the consumption-deferred marker.
2. **Live-startup integration proof.** The lifespan-population test (`test_lifespan_build_runtime_populates_state`) uses an in-memory adapter pool; a live Postgres + Redis prod-image startup proof of `build_runtime` (mirroring the env-gated integration suites) is deferred.
3. **Deferred B1 seams.** `ParentBudgetResolver` + `VaultCredentialAdapter` remain off the `Runtime` membership until their consumers land.
4. **CC-gate-at-modification (process).** Fold a `check_critical_coverage.py` run into any task that touches a `_CRITICAL_FILES` module, rather than deferring to the Z-gate.

## READY FOR GATE

All 10 tasks (+ the fence reconciliation) complete; full suite + full-tree lint/type + critical-coverage gate (112/112, count unchanged) all green. The branch (spec + plan + T1–T9 + fence + this closeout) is ready to push + open as one Workstream #2 PR on the human's tokens.
