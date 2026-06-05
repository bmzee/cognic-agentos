# Harness Injection — Design Spec (2026-06-05)

> **Status:** Design — approved in brainstorming; pending spec review before plan.
>
> **Workstream:** #2 of the deployable-without-code-surgery sequence
> (Pre-GA Configurability Audit → **Wave-1 Deploy-Safety** → **Harness Injection**).
>
> **Goal:** Give AgentOS a single canonical OS composition root — `harness/` — that
> constructs the real kernel runtime (the `LLMGateway`, and — when `cache_driver != "none"`
> — the governed-memory API factory) from `Settings` + the adapter pool, so a bank running
> `create_prod_app` gets a wired gateway (plus governed memory when enabled) instead of a
> half-constructed app whose gateway is `None`. This activates the Wave-1 T3 gateway
> `vault://` seam.
>
> **Related:**
> - `docs/closeouts/2026-06-04-wave-1-deploy-safety.md` (names this workstream as the
>   home for "live `vault://` resolution for the gateway").
> - ADR-007 provider honesty / `llm/gateway.py` (cloud-policy enforcer, critical control).
> - ADR-019 agent memory governance (`core/memory/` — stop-rule isolation boundary).
> - ADR-018 emergency controls (`core/emergency/kill_switches.py` — the Redis write-freeze
>   kill switch this design wires for real).
> - ADR-009 pluggable infrastructure adapters (the adapter-pool pattern the Redis/cache
>   adapter joins).

---

## 1. Problem

The kernel exposes ~17 dependency-injection seams. Today the production entrypoint
(`create_app` / `create_prod_app` in `portal/api/app.py:249`) uses a strict
"None-default optional kwarg" pattern: the **caller** constructs every collaborator
and passes it in; `create_app` only stores them on `app.state` and conditionally
mounts routers. The single place that constructs real objects from `Settings` is
`build_adapters_async()` (`db/adapters/factory.py`), which returns an `Adapters`
container.

Two consequences:

1. **`LLMGateway` has zero production construction.** It is built only in test files,
   and three of its required deps (`ProfileRateLimiter`, `PreflightResolver`,
   `SLAPolicy`) have no construction site anywhere. The Wave-1 T3 `vault://`
   master-key seam therefore cannot fire in production — it is "seam-only."
2. **There is no `harness/` package** and no `bootstrap`/`container`/`wiring` module.
   The governed-memory API (ADR-019) is similarly DI-tested but never harness-wired.

This workstream builds the missing composition root, fenced tightly.

### 1.1 The three seam buckets (decision record)

| Bucket | Seams | Harness action |
|---|---|---|
| **1 — Bank-overlay (kernel ships fail-loud by design)** | `ActorBinder`, `TrustRootResolver`, `ElicitationAdapter`, sandbox-admission `CredentialAdapter` | **Never wire.** The bank injects these. The harness invents **no defaults**. |
| **2 — Real OS impl exists, no prod wiring** | `LLMGateway` (+ ledger/limiter/preflight/SLA + `vault://` key), governed-memory factory (`MemoryAPI` cluster incl. `RedisMemoryWriteFreezeKillSwitch`), `ParentBudgetResolver`, `VaultCredentialAdapter` | Wirable now — but see B1 membership below. |
| **3 — Real impl does not exist yet** | scheduler `QuotaInterrogator` / `KillSwitchInterrogator` (Sprint 13.5), `PackStateInterrogator`, sandbox `CatalogProtocol` | Stay `_Null` / fail-loud. **No construction.** |

**Scope decision — B1 (canonical, not maximal).** `Runtime`'s **public** members are
exactly the two Bucket-2 seams that have a **live app-owned consumer now**:
`llm_gateway` and `memory_api_factory`. `ParentBudgetResolver` and
`VaultCredentialAdapter` are **deferred** — their only consumers (the scheduler,
the subagent spawner, the sandbox-admission orchestrator) are not constructed in
this workstream, and wiring an impl nothing reads is dead surface that blurs the
Bucket-3 fence.

---

## 2. Goals / Non-goals

### Goals

- A new `harness/` package: **OS runtime wiring only**, never Layer-C agent behavior.
- `async build_runtime(settings, adapters) -> Runtime`, mirroring
  `build_adapters_async → Adapters`.
- `create_prod_app()` is the production path that runs
  `build_adapters_async()` → `open_all()` → `build_runtime()` once and stores the
  result on `app.state`.
- `create_app()` **preserves its DI-friendly factory shape** (still accepts
  pre-constructed collaborators, stays test-friendly). The changes are additive: an
  `llm_gateway: LLMGateway | None = None` kwarg, a construction-time `/memory` mount
  signal, and request-time factory resolution in the memory router (§3.4).
- Promote **Redis/cache to a first-class adapter-pool member** so its
  construction + lifecycle live in `build_adapters_async`, and `build_runtime`
  consumes `adapters.cache` rather than opening its own Redis.

### Non-goals (the hard fence — a worker may not drift past these)

- **No** scheduler / quota / pack-state construction (Bucket 3 stays `_Null`).
- **No** `ParentBudgetResolver` and **no** `VaultCredentialAdapter` wiring.
- **No** invented defaults for Bucket-1 bank-overlay seams.
- **No** lighting-up of the `UIEventBroker` / packs router / UI-elicitation by
  feeding them the runtime spine — that is a later workstream. (`build_runtime`
  *exposes* its spine for that future reuse but **nothing new consumes it here**.)
- **No** managed-agent substrate, session API, tool palette, persona/Hermes memory
  manager, or `harness/base_agent.py`. (The 2026-05-26 local-managed-agents gap
  analysis is Sprint 12+ Track-A/C territory, explicitly out of scope.)
- **No** modification of `core/memory/*` (stop-rule isolation boundary) — the harness
  *imports and injects* memory collaborators; it does not change memory enforcement.
- **No** modification of `llm/gateway.py` or `core/emergency/kill_switches.py` — they
  are **constructed**, not edited.

---

## 3. Architecture

### 3.1 The `harness/` package

```
src/cognic_agentos/harness/
  __init__.py        # re-exports build_runtime, Runtime
  runtime.py         # Runtime container + async build_runtime(settings, adapters)
```

`harness/runtime.py` is the **composition root**. It is the explicit, allowed importer
of the memory-construction modules (`core/memory/storage.py`, `core/memory/consent.py`,
etc.): `core/memory/api.py` deliberately does **not** import `core/memory/storage` at
runtime (the adapter is *injected*) — the harness is the injector. This does **not**
relax the existing architecture-discipline test, which pins the **Layer-C / `api.py`**
boundary, not the composition root.

### 3.2 The `Runtime` container

A frozen dataclass mirroring `Adapters`:

```python
@dataclass(frozen=True, slots=True)
class Runtime:
    # Public Bucket-2 members (B1):
    llm_gateway: LLMGateway
    memory_api_factory: MemoryApiFactory | None   # None when cache/memory not wired

    # Internal spine — build_runtime uses these to construct the gateway + memory
    # factory, and surfaces them on the container so a later workstream can reuse
    # them (broker / packs / UI) without rebuilding. This workstream wires NO new
    # external consumer to the spine.
    audit_store: AuditStore
    decision_history_store: DecisionHistoryStore
    opa_engine: OPAEngine

    async def aclose(self) -> None: ...   # closes the gateway http_client
```

`aclose()` is called by the lifespan on shutdown (alongside `adapters.close_all()`).
The Redis client's lifecycle is owned by the **cache adapter**, not `Runtime`
(see §3.5) — so `Runtime.aclose()` only closes runtime-owned resources (the gateway's
HTTP client).

### 3.3 `build_runtime` — construction graph

**Signature holds at `(settings, adapters)`.** The shared `AsyncEngine` is reachable
via `adapters.relational.engine` (read-only property, valid after `open_all()` —
`db/adapters/postgres_adapter.py:49`, `db/adapters/protocols.py:102`). The lifespan
does **not** construct `AuditStore` / `DecisionHistoryStore` / `OPAEngine` for general
startup today, so `build_runtime` **owns its own spine** with zero double-construction
risk.

`build_runtime` constructs, in order:

1. **Spine** (from the engine + settings):
   - `engine = adapters.relational.engine`
   - `audit_store = AuditStore(engine)`
   - `decision_history_store = DecisionHistoryStore(engine)`
   - `opa_engine = await OPAEngine.create(bundle_path=<settings>, audit_store=…, decision_history_store=…, opa_path=<settings>, eval_timeout_s=<settings>)`
2. **Gateway sub-deps** (settings-derived, trivial):
   - `GatewayCallLedger(engine)`
   - `ProfileRateLimiter(per_profile=settings…, mode=settings…)`
   - `PreflightResolver.from_yaml(<settings litellm config path>)`
   - `SLAPolicy(name=…, total_budget=…, warning_threshold=…)` (settings-derived)
   - `litellm_master_key`: resolved **once at construction** — if `settings.litellm_master_key`
     is a `vault://` URI, resolve via the existing secret-resolution helper
     (`db/adapters/secret_resolution.resolve_secret_field`) and pass the plain value;
     a `vault://` value reaching the gateway constructor unresolved is fail-loud
     (`litellm_master_key_unresolved_vault_uri`, already enforced in `gateway.py`).
   - Guardrail input/output pipelines remain `None` in this workstream (optional;
     real pipelines are a later concern — out of scope, documented).
3. **`LLMGateway(...)`** from settings + the spine + sub-deps.
4. **Memory factory** (only if a usable cache is present — see §3.5/§3.6).

### 3.4 Lifespan placement + `create_app` / `create_prod_app` split

`build_runtime` is `async` and runs **inside the FastAPI lifespan**, on the
adapter-registry path, **after `await adapters.open_all()`** — because gateway
`vault://` resolution and the live engine are async, and `create_prod_app` must stay a
sync `--factory` callable. This mirrors the existing precedent where the checkpoint
reaper is built from live adapters in the lifespan.

- `create_app()` — **preserves its DI-friendly factory shape** (test-friendly; accepts
  pre-constructed collaborators). Additive changes: an
  `llm_gateway: LLMGateway | None = None` kwarg (stored on `app.state.llm_gateway`; never
  used to imply Layer-C behavior exists) + the construction-time `/memory` mount gate
  (mount strategy below).
- `create_prod_app()` — the production path. On the adapter path the lifespan:
  1. `adapters = await build_adapters_async(settings, registry=…)`
  2. `await adapters.open_all()`
  3. `runtime = await build_runtime(settings, adapters)`
  4. `app.state.llm_gateway = runtime.llm_gateway`
  5. `app.state.memory_api_factory = runtime.memory_api_factory` (populates the slot the
     mounted router resolves at request time — see the mount strategy below)
  6. register `runtime.aclose()` for shutdown.

**The `/memory` mount strategy (LOCKED — resolves the construction-time-vs-lifespan-time tension).**

Today `create_app` mounts `/memory` in the **factory body**, gated on the
`memory_api_factory` kwarg being non-None at construction (`portal/api/app.py:920`,
`app.state.memory_router_mounted`), and `build_memory_routes` **captures the factory in a
closure** (`portal/api/memory/routes.py:99,102`). But `build_runtime` produces the factory
**later, in the lifespan** — so a literal reading would leave prod with the factory `None`
at construction → router skipped → **no `/memory` routes**. Locked resolution:

1. **Mount decision = construction-time, from config** (not from the async-built object).
   `create_app` registers `/memory` when memory is configured — the construction-time
   signal is `settings.cache_driver != "none"` (memory's only consumer this workstream is
   the cache; see §3.6) — OR when a `memory_api_factory` kwarg is passed directly (the test
   path). This pins routes / OpenAPI / `app.state.memory_router_mounted` at construction,
   with **no dynamic post-startup route addition**.
2. **Factory = resolved at request time from `app.state.memory_api_factory`** (not
   closure-captured). `build_memory_routes`' handlers read
   `request.app.state.memory_api_factory` — a small change aligning memory with how the
   gateway / broker are already accessed from `app.state`. The slot is seeded at
   construction on the test path (existing `app.py:675`) and **populated by `build_runtime`
   during the lifespan** on the prod path.
3. **Mounted handler, factory still `None` at request time** (a misconfig that did not fail
   loud) → **fail closed: `503 memory_unavailable`**. Defensive; unreachable when wired
   correctly.
4. **Memory not configured** (`cache_driver == "none"`) → router **not registered** — quiet
   in dev, structured warning in strict (partial-config doctrine).

### 3.5 Redis/cache as a first-class adapter (locked: option **a**)

Redis is a shared runtime substrate (memory scratch + write-freeze kill switch today;
scheduler/emergency/throttling later). It becomes a first-class adapter-pool member so
construction + lifecycle are standardized in one place — **not** opened ad hoc by the
harness.

> **Anti-pattern (explicit): no harness-local Redis client.** `build_runtime` must
> consume `adapters.cache` and must **never** call `redis.asyncio.Redis(...)` or
> otherwise open its own Redis. A second adapter construction/lifecycle pattern
> immediately after Wave-1 standardized them is an architectural regression. Pinned
> by an architecture test that scans `harness/` for any `redis` import / client
> construction.

Mirrors every existing adapter convention:

- **Pool field:** add `cache: CacheAdapter | None = None` to the `Adapters` dataclass
  (`db/adapters/factory.py:32`), appended to `_all` in `__post_init__` so
  `open_all()` / `close_all()` manage its lifecycle.
- **Protocol:** new `CacheAdapter` Protocol in `db/adapters/protocols.py` exposing
  `async connect()`, a `client` property (the async redis-like KV client),
  `async close()`, `async health_check()` — the `.client` property mirrors
  `RelationalAdapter.engine`. The client must satisfy the consumers' duck-types
  (`get(key)`, `set(key, value, **kwargs)` with TTL via `ex=` — see
  `core/memory/storage.py` `_AsyncRedisLike` and
  `core/emergency/kill_switches.py` `_AsyncRedisKVLike`).
- **Registry typing:** add `"cache"` to `registry.py`'s `AdapterKind` Literal and
  `"cache": CacheAdapter` to `PROTOCOL_FOR_KIND` — the convenience-typing +
  structural-verification surfaces the other six pool kinds use. (The registry's
  `(kind, driver)` dict itself needs no logic change; the module already documents that
  new kinds may join.)
- **Drivers (`cache_driver: Literal["none", "redis", "memory"]`):**
  - `redis` — the **real** adapter (`db/adapters/redis_adapter.py`), used in **both dev
    and prod** (dev → a local Redis; prod → the cluster). `redis>=5.3` is in the
    **`adapters` extra** (`pyproject.toml:122` — the driver-specific packages the kernel
    image must NOT ship), so the `RedisAdapter` loads via the **optional-adapter path**: it
    self-registers on import (`bundled_registry.register("cache","redis",RedisAdapter)`) and
    is pulled in by `load_bundled_adapters()` only when the `adapters` extra is installed —
    exactly like `QdrantAdapter`. Imports `redis.asyncio` lazily.
  - `memory` — a **test-only** in-memory dict-backed KV fixture registered by the test
    harness (`tests/conftest.py`: `r.register("cache","memory",…)`), mirroring the sibling
    in-memory adapters (`InMemory*Adapter` live in `tests/support/adapter_fixtures.py` and
    are registered **only in test code** — there is no in-memory adapter in
    `src/db/adapters/`). **Not** a real dev driver and **not** a `src/` module;
    `fakeredis` is not a project dep.
  - `none` — **opt-out**: `build_adapters` **skips resolution** and sets
    `adapters.cache = None`. Cache is the only adapter with an opt-out, because — unlike
    relational / vector / secret — it is optional: a pack-only deploy that does not use
    governed memory needs no Redis. This is the explicit state §3.6 references; the
    existing factory always resolves a configured driver, so the skip-branch is new.
- **Args helper:** `_cache_args(settings)` returns `(settings.redis_url,)` for `redis` and
  `()` for `memory`; `none` is handled by the skip-branch, not `_cache_args`.
- **Settings:** new `cache_driver: Literal["none","redis","memory"]` (**default `"none"`**
  — locked; the §3.4 mount strategy makes it load-bearing, and `"none"` preserves today's
  bare-`create_app()` no-`/memory` behavior) + `redis_url: str | None` (default `None`;
  required when `cache_driver="redis"`). Reuse the existing Sprint-11.5 memory TTL settings
  (`memory_scratch_ttl_s`, `memory_kill_switch_cache_ttl_s`).

**Single shared client.** The `RedisAdapter` owns the one async client; `build_runtime`
reads `adapters.cache.client` and injects that **same** client into the
`RedisMemoryAdapter` (scratch tier) and the `RedisMemoryWriteFreezeKillSwitch`. One
client, one lifecycle, one connection pool.

### 3.6 Memory factory construction + mount-gating

`MemoryApiFactory` is `Callable[[MemoryCallerContext], MemoryAPI]` — a closure
`build_runtime` builds, capturing the shared deps and minting a per-request `MemoryAPI`
(subject binding is per `MemoryCallerContext`). The closure captures:

- routing memory adapter: `RoutingMemoryAdapter(redis_adapter=RedisMemoryAdapter(client, scratch_ttl_s), pg_adapter=PostgresMemoryAdapter(engine, dh_store), scratch_ttl_s)`
- `dlp = ChecksumRegexGazetteerScanner()`
- `consent = ConsentValidator(audit=decision_history_store)`
- `policy = opa_engine` (the spine OPA)
- `kill_switch = RedisMemoryWriteFreezeKillSwitch(redis_client=client, cache_ttl_s=settings.memory_kill_switch_cache_ttl_s)`
- `audit = decision_history_store`
- optional `object_store = adapters.object_store`
- optional `vector_index = MemoryVectorIndex(embedder=adapters.embedding, client=adapters.vector, collection=…)`

**Mount-gating (per the §3.4 locked strategy + the partial-config doctrine).** The mount
decision is construction-time (`cache_driver != "none"`); the factory is built in the
lifespan and resolved per request. Cases:

- **`cache_driver="redis"`, reachable** → router registered at construction; `build_runtime`
  builds the factory in the lifespan; `/memory` serves with a **distributed** Redis kill
  switch (local Redis in dev, cluster in prod).
- **`cache_driver="redis"`, unreachable** → `adapters.open_all()` fails loud at startup (a
  configured-but-down backend is a hard error, not a graceful skip). The router was
  registered at construction, but startup aborts before serving.
- **`cache_driver="none"`** → `adapters.cache = None`, `runtime.memory_api_factory = None`,
  router **not registered**: **quiet in dev**, **structured warning in strict**
  (partial-config doctrine).
- **Tests (`cache_driver="memory"`, fixture-registered)** → an in-memory cache backs a real
  single-process `RedisMemoryWriteFreezeKillSwitch`; `/memory` serves. This is the test
  harness, **not** a deploy profile (the in-memory driver is unregistered in `src/` runtime).

> **Never a `_Null` kill switch behind a mounted `/memory`.** When `/memory` serves, its
> kill switch is always a real `RedisMemoryWriteFreezeKillSwitch` over the cache adapter's
> client — never the fail-loud `_Null` sentinel. **Strict profiles** additionally forbid
> `cache_driver="memory"` (§4), so a strict `/memory` is always backed by a *distributed*
> Redis kill switch — an in-memory one cannot propagate the ADR-018 ≤30 s freeze across
> instances.

---

## 4. Error handling / fail-loud posture

- **Gateway `vault://` key:** resolved once at construction; unresolved `vault://`
  reaching the constructor is fail-loud (existing `gateway.py` guard).
- **Bucket-1 seams:** harness invents no defaults; the kernel sentinels stay fail-loud.
- **Bucket-3 seams:** untouched; `_Null` sentinels stay fail-loud on use.
- **Strict-profile cache guard (new, Wave-1-style):** in strict profiles (`{stage, prod}`),
  `cache_driver` must be `redis` (memory enabled) or `none` (memory disabled);
  `cache_driver="memory"` is **forbidden**. The in-memory driver is unregistered in `src/`
  runtime (so it would fail at resolve regardless), but the guard turns that into a
  **legible deploy-safety refusal** and documents the invariant: a strict `/memory` must be
  Redis-backed for ADR-018 cross-instance propagation. Add it to
  `_validate_wave1_deploy_safety_guards()` (`core/config.py`) alongside a
  `redis_url`-required-when-`cache_driver="redis"` check. (Touches `core/config.py` →
  halt-before-commit; final reason-prefixes confirmed at plan time.)

---

## 5. Honesty / scope markers (carried into module docstrings + the closeout)

- **Gateway — "primitive-wired, consumption-deferred."** `build_runtime` constructs the
  gateway and stores it on `app.state.llm_gateway`; its in-repo consumers are the
  future agent-runtime / Layer-C, out of this repo. Same posture as memory in 11.5.
- **Memory — "live portal consumer."** The `/memory` router is the real, in-repo
  consumer of `memory_api_factory`.
- **`ParentBudgetResolver` + `VaultCredentialAdapter` — "not wired yet."** Construct only
  when their owning consumer (scheduler / subagent / sandbox-admission) is constructed.

---

## 6. Testing & critical-controls posture

`harness/runtime.py` is a **wiring seam** — expected **OFF** the per-file coverage gate
(Doctrine F, same precedent as `sandbox/backend_factory.py`: enforcement lives in the
wired critical-control modules — `llm/gateway.py`, the memory gate, `OPAEngine`). But it
is the security-adjacent composition root, so **every commit is halt-before-commit** per
`feedback_strict_review_off_gate`. Final on/off-gate call confirmed at plan time.

The load-bearing pins are **architecture tests**:

1. `harness/` imports nothing from Layer-C / `cognic_agentos.agents.*`.
2. `harness/` contains no `redis` import / Redis client construction (the §3.5 anti-pattern).
3. `build_runtime` constructs no Bucket-1 default.
4. If the `/memory` router mounts, its kill switch is the real Redis impl, never `_Null`.
5. `build_runtime` never opens a second `AsyncEngine` (uses `adapters.relational.engine`).

Plus behavioural tests: `build_runtime` produces a usable gateway from a fixture adapter
pool; the memory factory mints a working `MemoryAPI`; **the `/memory` mount strategy —
router present in the OpenAPI schema when `cache_driver != "none"` and absent when
`"none"`; the handler resolves the factory from `app.state` at request time; `503
memory_unavailable` when a mounted route finds the factory absent**; the strict-profile
`cache_driver="memory"` guard + the `redis_url`-required check fail loud (with TM-revert
proofs per `feedback_security_regression_hardening`).

---

## 7. File-change map (blast radius — deliberately small)

**New:**
- `src/cognic_agentos/harness/__init__.py`
- `src/cognic_agentos/harness/runtime.py` — `Runtime` + `build_runtime`
- `src/cognic_agentos/db/adapters/redis_adapter.py` — `RedisAdapter` (bundled/optional)
- in-memory cache adapter for the **test-only** `memory` driver — an `InMemoryCacheAdapter`
  in `tests/support/adapter_fixtures.py` + registration in `tests/conftest.py`
  (`r.register("cache","memory",…)`), mirroring the sibling in-memory adapters. **Not a
  `src/` module.**
- `tests/unit/harness/…`, `tests/unit/architecture/…` (the 5 arch pins)

**Modified:**
- `db/adapters/factory.py` — `Adapters.cache` field + `_cache_args` + resolve call
- `db/adapters/protocols.py` — `CacheAdapter` Protocol
- `db/adapters/registry.py` — add `"cache"` to the `AdapterKind` Literal + `"cache": P.CacheAdapter`
  to `PROTOCOL_FOR_KIND` (the convenience-typing + structural-verification surfaces; the free
  `(kind, driver)` dict needs no logic change). Unlike Sprint-11.5 "memory" (not a pool kind),
  `cache` is a genuine `Adapters` member, so it joins both — consistent with the other six kinds.
- `db/adapters/__init__.py` — bundled redis registration on the optional path
- `core/config.py` — `cache_driver` (`Literal["none","redis","memory"]`) + `redis_url` +
  the strict-profile cache guard + the `redis_url`-required check *(halt-before-commit)*
- `portal/api/app.py` — lifespan calls `build_runtime` on the adapter path; stores
  `app.state.llm_gateway`; **populates `app.state.memory_api_factory` from the runtime**;
  the `/memory` mount gate becomes construction-time (`cache_driver != "none"` OR a
  `memory_api_factory` kwarg) per §3.4; new `create_app(llm_gateway=…)` kwarg;
  `runtime.aclose()` on shutdown *(halt-before-commit — composition root)*
- `portal/api/memory/routes.py` — `build_memory_routes` handlers resolve the factory from
  `request.app.state.memory_api_factory` at request time (was closure-capture) + fail closed
  `503 memory_unavailable` when absent, per §3.4. Portal surface — the `core/memory/`
  stop-rule boundary is untouched. *(halt-before-commit — governance-adjacent surface)*

**Not touched (asserted):** `core/memory/*` (stop-rule), `llm/gateway.py` (constructed,
not edited), `core/emergency/kill_switches.py` (constructed, not edited), `core/scheduler/*`,
`subagent/*`, `sandbox/*`.

---

## 8. Open items (resolved at plan time, not blocking design)

- Exact reason-prefix wording for the strict-profile cache guard + the
  `redis_url`-required check (confirm against the existing G1–G8 naming).
- `PreflightResolver.from_yaml` requires the LiteLLM config YAML to exist as a deploy
  artifact; confirm the settings path field + the strict-profile behavior when it is
  absent (likely fail-loud, consistent with the deploy-safety posture).
- `redis_url` may want a dev-convenience default (e.g. `redis://localhost:6379/0`) for the
  `redis` driver — plan-time ergonomics only. (The `cache_driver` default itself is
  **locked to `"none"`** in §3.5 — it is load-bearing for the §3.4 mount strategy, so it is
  a design decision, not a plan-time open item.)
- Forward note (not this workstream): when the scheduler/emergency Redis consumers land,
  they reuse `adapters.cache` — no second Redis sourcing.
