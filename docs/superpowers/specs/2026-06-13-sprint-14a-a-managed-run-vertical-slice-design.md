# Sprint 14A-A — Managed Agent Runtime: thinnest vertical slice — Design

**ADR:** ADR-022 (scheduler) + ADR-004 (sandbox) + ADR-005 (sub-agent, future). **Status:** design locked, ready for plan.
**Date:** 2026-06-13. **Predecessors:** 13.7 (scheduler constructed, dormant), 13.8 (MCP host constructed, dormant).

## 1. Goal + scope

First production-grade **exercised** managed-run path: a `submit → scheduler admit → execute one sandbox-backed task → capture result → complete → evidence` loop that makes the dormant 13.7 scheduler *fire* against a real, Runtime-owned sandbox backend. This is the moment AgentOS stops only *constructing* primitives and starts *running* them.

**14A-A is `backend construction + managed-run executor` only**, proven by a programmatic executor-API e2e (no portal route). The valve splits **before** the portal route + the checkpoint→wake proof.

- **14A-A (this spec):** the Runtime-owned sandbox backend construction (lifespan, SDK-gated) + `is_sandbox_available()` + the `core/run` managed-run executor + the lifecycle/failure semantics + value-free evidence + two test tiers (always-run stub-backend orchestration proof + env-gated real-docker proof).
- **14A-A2 (deferred):** `POST /api/v1/runs` (synchronous) + a backend-level checkpoint→wake proof.
- **Explicitly OUT of 14A-A (deferred unless spec grounding proves trivial+required):** MCP `call_tool` exercise, broad approval/quota/kill-switch exercise, scheduler-driven suspend/resume, sub-agent dispatch (`spawn.py`), the real `LocalParentBudgetResolver`, multi-backend, the portal run route.

## 2. Locked forks (brainstorm 2026-06-13)

1. **F1** — the executor is `core/run/executor.py`, **ON the CC gate (count 129→130)** — runtime authority, not glue. **NO Docker/K8s SDK imports in `core/run`**: it depends on the SDK-free `sandbox.protocol`/`sandbox.policy` interfaces (`SandboxBackend`, `SandboxSession`, `SandboxPolicy`, `PackAdmissionContext`, `SandboxExecResult`) + `core.scheduler` + `core.decision_history`; the concrete backend is injected. Pinned by an AST fence.
2. **F2** — add `is_sandbox_available()` + a new `settings.sandbox_runtime_enabled` flag; construct the backend + executor in the FastAPI **lifespan** (builder in `harness/sandbox.py`), **SDK-gated + fail-soft**. `build_runtime` stays SDK-free + untouched. Expose via `app.state.sandbox_backend` + `app.state.managed_run_executor` ONLY (NO `Runtime` slot — see §5).
3. **F3** — `submit → mark_running → backend.create → session.exec → capture → destroy → complete`. **Non-zero workload exit → `complete`** (a run result, not a scheduler failure); **infra/create/exec exception → scheduler `fail`** + `finally`-guarded teardown.
4. **F3-evidence** — value-free chain only: **output digests + exit code, never raw stdout/stderr in the chain**; raw output returns only to the caller/test.
5. **F4** — minimal run request; the workload command is **`argv: list[str]`** (native to `session.exec`) — **NO shell-string concatenation** in the executor. Manifest-driven `SandboxPolicy` is 14A-B.
6. **F5** — route deferred to 14A-A2; 14A-A proves production code through the executor API + e2e.
7. **F6** — deterministic minimal `exec` in a canonical runtime image; always-run stub-backend tests + env-gated real-docker proof.

## 3. Architecture

```
Caller (e2e in 14A-A; POST /runs in 14A-A2)
  └─ ManagedRunExecutor.run(RunRequest)            [core/run/executor.py — CC, SDK-free]
       1. submit(SubmitInput)            -> scheduler admit + scheduler.admission_accepted
          (refused -> RunResult(refused) + run.refused evidence; no sandbox)
       2. mark_running(task_id)          -> scheduler.task_started   (NO sandbox_adapter — Fork A)
       3. backend.create(policy, actor=request.actor, tenant_id=request.tenant_id,
             pack_context=ctx, requires_credentials=())  -> SandboxSession   [injected DockerSibling]
       4. session.exec(argv, timeout_s)  -> SandboxExecResult(stdout, stderr, exit_code)
       5. session.destroy()              (finally-guarded)
       6. complete(task_id)              -> scheduler.task_completed
       7. emit run.completed evidence    -> value-free (exit_code + stdout/stderr sha256 + byte-counts)
       -> RunResult(task_id, terminal_state, exit_code, stdout, stderr)   [raw output to caller only]

  Lifespan (portal/api/app.py) — SDK-gated, fail-soft:
       if is_sandbox_available(settings) and settings.sandbox_runtime_enabled:
           backend, docker_client = build_sandbox_backend(settings=settings, runtime=runtime)  [harness/sandbox.py;
              FUNCTION-LOCAL aiodocker + backend imports keep the module SDK-free; the factory
              get_backend() OWNS the canonical catalog + egress image from settings]
           app.state.sandbox_backend = backend
           app.state.managed_run_executor = ManagedRunExecutor(scheduler=runtime.scheduler,
              sandbox_backend=backend, decision_history_store=runtime.decision_history_store, settings=...)
           (lifespan retains docker_client; closes it on shutdown + on fail-soft)
       else: app.state.sandbox_backend = None; app.state.managed_run_executor = None  (+ warning)
```

Three units, clear boundaries:
- **`core/run/executor.py` (NEW, CC):** the `ManagedRunExecutor` — the run authority. SDK-free (interfaces only). Takes an injected `SandboxBackend` + the `SchedulerEngine` + a `DecisionHistoryStore`.
- **`harness/sandbox.py` (NEW, off-gate composition):** `is_sandbox_available()` + `build_sandbox_backend()`. The *module* is SDK-free-import; the concrete backend + `aiodocker` are imported FUNCTION-LOCALLY inside `build_sandbox_backend` (only reached on the SDK-present path). Mirrors `harness/mcp_host.py`. Returns `(backend, docker_client)` so the lifespan can close the owned client.
- **`portal/api/app.py` (off-gate, MODIFIED):** the SDK-gated lifespan branch + `app.state.sandbox_backend` + `app.state.managed_run_executor` + closing the owned `docker_client` on shutdown.

## 4. The executor (`core/run/executor.py`, CC)

`ManagedRunExecutor(*, scheduler: SchedulerEngine, sandbox_backend: SandboxBackend,
decision_history_store: DecisionHistoryStore, settings: Settings)` with one public async method
`run(request: RunRequest) -> RunResult`.

- **`RunRequest`** (frozen): `tenant_id: str`, `pack_id: str`, `argv: tuple[str, ...]` (NOT a shell
  string — passed verbatim to `session.exec`), `actor: Actor`. Risk tier + resource policy are a
  minimal default for 14A-A (read-only-tier, canonical image, modest cpu/mem/walltime) — manifest-driven
  is 14A-B.
  - **`actor` is `portal.rbac.actor.Actor`** (the authenticated request actor, carrying scopes), because
    `SandboxBackend.create(*, actor: Actor, ...)` requires exactly that type (protocol.py:654). `core/run`
    references it via a **`TYPE_CHECKING`-only import** (mirrors `sandbox.protocol`'s own TYPE_CHECKING
    `Actor` import at protocol.py:560) — the actor object is constructed by the caller (the portal/e2e layer)
    and only *passed through* + read-projected; `core/run` never constructs a portal type at runtime, so the
    `core → portal` arrow holds (no runtime portal import). The executor **projects** the scheduler's core-owned
    `TaskActor(subject=actor.subject, tenant_id=actor.tenant_id, actor_type=actor.actor_type)` for
    `SubmitInput.actor` (the scheduler keeps `TaskActor` to stay portal-free), and passes the full `actor`
    straight to `backend.create`. The executor asserts `request.tenant_id == request.actor.tenant_id`
    (confused-deputy defence) and uses `request.tenant_id` for both `submit` and `create`.
- **`RunResult`** (frozen): `task_id: str | None`, `terminal_state: Literal["completed","failed","refused"]`,
  `exit_code: int | None`, `stdout: bytes`, `stderr: bytes`, `refusal_reason: str | None`. Raw output here is
  for the caller ONLY — never the chain.
- **Lifecycle (F3):** `submit` → on refusal, emit `run.refused` (value-free) + return; on accept,
  `mark_running` → `await backend.create(policy, actor=request.actor, tenant_id=request.tenant_id,
  pack_context=ctx, requires_credentials=())` (the full grounded signature — `actor` + `tenant_id` are
  required keyword args, protocol.py:654-655) → `session.exec(list(argv), timeout_s=...)` → capture →
  `session.destroy()` (in `finally`) → `complete` → emit `run.completed` (value-free) → `RunResult`. The empty
  `requires_credentials=()` means the backend never calls `credential_adapter.mint_lease` (docker_sibling.py:1176)
  — the `VaultCredentialAdapter` is constructed but NOT exercised in 14A-A, and no Vault is contacted.
- **Failure semantics (F3):** a **non-zero `exit_code` is a `completed` run** (the run ran; the exit code is the
  result). An **infra exception** (`backend.create`/`session.exec` raises, e.g. `SandboxPolicyViolated` /
  `SandboxLifecycleRefused` / a transport error) → `scheduler.fail(task_id, payload=...)` + `finally`
  teardown + emit `run.failed` (value-free reason) + `RunResult(terminal_state="failed")`. The session is
  destroyed in a `finally` so it never leaks regardless of which step raised.
- **Evidence (F3-evidence):** the executor emits value-free `run.completed` / `run.failed` / `run.refused`
  chain rows via `DecisionHistoryStore.append`. The `run.completed` payload carries `task_id` + `exit_code` +
  **separate** `stdout_sha256` + `stderr_sha256` (hex digests of each stream INDEPENDENTLY — never a
  `sha256(stdout + stderr)` concatenation, which is ambiguous: `("ab","c")` and `("a","bc")` would collide) +
  the size counts `stdout_bytes` + `stderr_bytes` (`len()` of each stream). **No raw stdout/stderr ever enters
  the chain.** `run.failed` / `run.refused` carry `task_id` + a closed-enum reason instead. The UI
  `decision_audit` mirror surfaces these automatically (NO new UI family). The scheduler
  (`admission_accepted`/`task_started`/`task_completed`) + sandbox-lifecycle
  (`created`/`exec_completed[exit_code]`/`destroyed`) rows complete the evidence trail.
- **No SDK imports + arrow:** `core/run` imports the SDK-free `sandbox.protocol` + `sandbox.policy`
  interfaces + `core.scheduler` + `core.decision_history`. AST fence at
  `tests/unit/architecture/test_run_no_sdk_import.py` pins: (a) **no `aiodocker` / `kubernetes_asyncio`**
  import in `core/run/`; (b) **no RUNTIME `cognic_agentos.portal` import** (the `portal.rbac.Actor` reference
  is TYPE_CHECKING-only — the fence allows it under an `if TYPE_CHECKING:` block, forbids it elsewhere, exactly
  as `sandbox.protocol` is structured). So the `core → portal` arrow holds at runtime.

## 5. The backend construction (F2 — off-gate, SDK-gated, fail-soft)

- **`is_sandbox_available(settings) -> bool`** (NEW, mirror of `is_mcp_available`) — **14A-A is
  DockerSibling-only** (multi-backend deferred): returns `True` **only** when
  `settings.sandbox_backend == "docker_sibling"` AND `aiodocker` is importable. For
  `settings.sandbox_backend == "kubernetes_pod"` it returns `False` (the lifespan logs a structured
  "kubernetes_pod sandbox backend deferred in 14A-A — multi-backend lands later" warning and leaves both
  `app.state` slots `None`). SDK-free itself (try-import only). Real K8s construction stays out of 14A-A with
  multi-backend; the `(backend, docker_client)` return is deliberately Docker-specific.
- **`build_sandbox_backend(*, settings, runtime, checkpoint_store=None) -> (SandboxBackend, docker_client)`** —
  lives in **`harness/sandbox.py`** (NEW, off-gate; mirrors `harness/mcp_host.py`; keyword-only). Steps:
  (1) create the `aiodocker.Docker()` client; (2) mint the Vault transport from settings —
  `vault_transport = VaultTransport(vault_addr=settings.vault_addr, vault_token=settings.vault_token,
  vault_namespace=settings.vault_namespace)` (core/_vault_transport.py:13) — then wrap it as
  `credential_adapter = VaultCredentialAdapter(transport=vault_transport, settings=settings)`
  (sandbox/credentials.py:99); (3) assemble the backend via `backend_factory.get_backend(settings,
  docker_client=<client>, credential_adapter=<that>, rego_engine=await OPAEngine.create(
  bundle_path=sandbox.rego, ...), audit_store=runtime.audit_store,
  decision_history_store=runtime.decision_history_store, checkpoint_store=checkpoint_store, warm_pool=None)`.
- **Why a fresh `VaultTransport` (Option 1, locked):** `adapters.secret` is a `SecretAdapter` (factory.py:48),
  NOT a `VaultTransport` — it lacks the `lease`/`revoke` surface `VaultCredentialAdapter.mint_lease` needs — so
  it cannot be passed as `transport`. The builder mints the transport from `settings` (parallel to how it mints
  the `aiodocker` client). **`VaultTransport` is lazy** (the `hvac.Client` is built on first use,
  _vault_transport.py:34) so construction contacts no Vault; only a real `mint_lease` call would. A later
  credentialed-run sprint (14A-A2+) may revisit sharing one Vault transport across consumers rather than
  minting a second — out of 14A-A scope.
- **`checkpoint_store=None` in 14A-A** — `Runtime` carries no `checkpoint_store` field, and checkpoint/wake is
  deferred to 14A-A2, so 14A-A passes `checkpoint_store=None`. 14A-A2 threads the lifespan-wired store
  (`app.state.checkpoint_store`, Sprint 8.5) when it adds the checkpoint→wake proof.
- **No `image_catalog` / `egress_proxy_image` passed** — `get_backend()` is AUTHORITATIVE for both: it
  overwrites `kwargs["image_catalog"] = CanonicalImageCatalog(...)` (factory:100) and
  `kwargs["egress_proxy_image"] = settings.sandbox_canonical_egress_proxy_image` (factory:125) from the
  `sandbox_canonical_*` settings (a caller-supplied catalog would be silently overwritten — the factory owns
  the canonical-image gate).
- **Function-local SDK imports** — the concrete backend + `aiodocker` are imported FUNCTION-LOCALLY (inside
  `build_sandbox_backend`, only reached on the SDK-present path) so the *module* stays SDK-free-import: the
  kernel image (no `adapters` extra) imports `harness/sandbox.py` without `aiodocker`; only the gated call
  touches the SDK. Mirrors how the 13.8 lifespan imports `build_mcp_host` only on the `is_mcp_available()`
  path.
- **Client ownership + shutdown (F2 — explicit):** the `SandboxBackend` has **no close API** — `DockerSibling`
  stores the injected `self._docker = docker_client` (docker_sibling.py:958) and never closes it; there is no
  `backend.close()`/`aclose()`/`__aexit__`. So the `aiodocker.Docker` client is owned by whoever creates it:
  `build_sandbox_backend` creates it and RETURNS it alongside the backend, and the **lifespan** retains the
  handle and `await docker_client.close()` on shutdown AND on the fail-soft construction-failure path (mirrors
  the 13.8 lifespan-owned `httpx.AsyncClient` close). No client leak on any path.
- **Lifespan wiring:** AFTER `build_runtime`, gated on `is_sandbox_available(settings)` AND the NEW
  **`settings.sandbox_runtime_enabled`** flag (`bool`, conservative default `False`, **added to
  `core/config.py` in T2** — the existing `settings.sandbox_backend` only *names* the backend; this flag
  *enables* the eager construction so a kernel deploy does not open a docker client unbidden). Fail-soft →
  both `app.state.sandbox_backend` and `app.state.managed_run_executor` set to `None`, the owned
  `docker_client` closed if it was created, + a structured warning on any construction failure — missing SDK /
  docker daemon unreachable / **missing-or-invalid `settings.vault_addr`** (the `VaultTransport` ctor raises
  `ValueError` on an empty addr, _vault_transport.py:24, so enabling `sandbox_runtime_enabled` without a Vault
  address fail-softs rather than crashing the app) / any other error (mirrors the 13.8 MCP fail-soft). On the success path the lifespan ALSO constructs `app.state.managed_run_executor =
  ManagedRunExecutor(scheduler=runtime.scheduler, sandbox_backend=backend,
  decision_history_store=runtime.decision_history_store, settings=settings)` — the executor is what a caller
  (the 14A-A2 route; the e2e) drives. Pre-seed BOTH `app.state.sandbox_backend = None` and
  `app.state.managed_run_executor = None`. `build_runtime` stays SDK-free + untouched.
- **No `Runtime.sandbox_backend` slot:** 14A-A exposes the backend + executor via **`app.state.sandbox_backend`
  + `app.state.managed_run_executor` ONLY**. `build_runtime` is untouched (it stays SDK-free and does not learn
  about the sandbox backend); the executor is constructed in the lifespan where the backend + scheduler meet.

## 6. The run request → scheduler + sandbox inputs (F4)

- **`SubmitInput`** (`core/scheduler/_types`): `tenant_id` / `pack_id` (from the request) / `actor` (the
  `TaskActor` the executor **projects** from `request.actor` — `subject` / `tenant_id` / `actor_type`) /
  `class_="interactive"` / `pack_kind` (from the installed pack record) / `pack_risk_tier="read_only"`
  (minimal default for 14A-A) / `requested_estimated_tokens` (a small fixed default).
- **`PackAdmissionContext`** (`sandbox/policy`): `pack_id` / `pack_version` / `pack_artifact_digest` (from
  the installed pack record) / `risk_tier="read_only"` / `declares_dynamic_install=False` /
  **`profile="production"`** (required `Literal["production","development"]` field, policy.py:130 — no
  default; the production profile is what a real bank deploy runs) / `data_classes=()`.
- **`SandboxPolicy`** (`sandbox/policy`): a minimal valid default — `runtime_image=
  settings.sandbox_canonical_runtime_python_image` (the digest-pinned canonical image, config.py:1643 — NOT a
  hardcoded literal), `read_only_root=True`, modest `cpu_cores`/`memory_mb`/`walltime_s`,
  `egress_allow_list=()`, `vault_path=None`, `warm_pool_key=None`.
- **Installed-pack precondition:** the scheduler's `pack_state_interrogator` already refuses
  `refused_pack_not_installed`; the executor surfaces that as `RunResult(terminal_state="refused")`. The
  executor loads the installed pack record (`PackRecordStore`) to fill `pack_kind` / `pack_version` /
  `pack_artifact_digest`. The e2e seeds one installed pack (the 13.7 seed pattern).
- **argv safety:** `request.argv` is a `tuple[str, ...]` passed verbatim as `list(argv)` to
  `session.exec(command: list[str], ...)` — NO `sh -c`/string concatenation in the executor (the command
  is the workload's argv; a pack that wants a shell declares it in its own argv).

## 7. Workload + result capture (F6)

- **Workload:** a deterministic argv (e.g. `["printf", "<marker>"]` or the runtime image's echo) in the
  **canonical** `settings.sandbox_canonical_runtime_python_image` (digest-pinned, real artifact — NOT an OSS
  substitute).
- **Capture:** `SandboxExecResult(stdout, stderr, exit_code)` → `RunResult` (raw stdout/stderr to the caller)
  + the value-free `run.completed` evidence (`exit_code` + `stdout_sha256` + `stderr_sha256` + `stdout_bytes`
  + `stderr_bytes`; never the raw bytes).
- **Test tiers:**
  1. **Always-run orchestration proof (unit/integration):** a stub `SandboxBackend` (a hand-rolled object
     conforming to the SDK-free `SandboxBackend` Protocol) returning a canned `SandboxExecResult` → drives
     the executor's full loop (submit→…→complete + the evidence rows + the failure paths) over a migrated DB.
     No docker. Runs everywhere.
  2. **Env-gated real-docker e2e:** `tests/integration/run/test_managed_run_e2e.py`, gated on
     `COGNIC_RUN_DOCKER_SANDBOX=1` (mirrors the repo's postgres/oracle/vault/k8s env-gating) — constructs the
     real `DockerSiblingSandboxBackend` + the executor, runs the deterministic argv in the canonical image,
     asserts the real `exit_code` + stdout + the chain rows. Fail-loud-when-opted-in, skip-default.

## 8. Failure posture (summary)

| Case | Behavior |
|---|---|
| Scheduler refuses admission (`refused_pack_not_installed` / quota / policy) | `RunResult(refused)` + `run.refused` evidence; NO sandbox created |
| `backend.create` raises (policy violation / lifecycle refusal / transport) | `scheduler.fail` + `run.failed` evidence; no session to tear down (or `finally` no-ops) |
| `session.exec` raises (infra) | `scheduler.fail` + `session.destroy()` in `finally` + `run.failed` evidence |
| `session.exec` returns non-zero `exit_code` | **`scheduler.complete`** + `run.completed` evidence (exit_code is the result); session destroyed in `finally` |
| `session.destroy` raises during teardown | logged best-effort; does NOT flip an already-`completed`/`failed` terminal state |
| Sandbox runtime not constructed at startup (SDK absent / `sandbox_runtime_enabled=False` / docker daemon unreachable / missing-or-invalid `settings.vault_addr` / any construction error) | both `app.state.sandbox_backend` AND `app.state.managed_run_executor` = `None` + structured warning; the owned `docker_client` (if it was created) is closed; runs are unavailable (the caller/e2e skips) |

## 9. CC + gate implications

- **`core/run/executor.py`** — NEW CC stop-rule module, promoted to the durable gate (count **129→130**),
  95/90 floor, verify-at-promotion on fresh `--cov-branch` in the landing commit. SDK-free (AST-fenced).
- **`harness/sandbox.py` (`is_sandbox_available` + `build_sandbox_backend`) + the `app.py` lifespan** —
  off-gate composition (SDK-aware wiring consuming the on-gate executor + the on-gate sandbox backend).
- **`build_runtime`** — untouched + SDK-free.
- Count moves **129→130** (the executor is the one promotion); the CC self-test pin + the gate file both bump.

## 10. Task sketch (for the plan)

- **T1** — `core/run/executor.py`: `RunRequest` (incl. `actor: Actor` via TYPE_CHECKING) / `RunResult` +
  `ManagedRunExecutor.run` (the full lifecycle incl. the `TaskActor` projection + the `actor`/`tenant_id`
  create args + failure semantics + value-free evidence) + the stub-backend always-run orchestration tests
  (refuse / complete / non-zero-exit-still-completes / infra-fail / teardown-finally / actor-projection /
  tenant-mismatch-assert). CC task — own halt + verify-at-promotion + AST fence (no SDK + no runtime portal;
  TYPE_CHECKING `Actor` allowed) + CC-count 129→130 (gate file + self-test).
- **T2** — `harness/sandbox.py`: `is_sandbox_available()` + `build_sandbox_backend()` (function-local SDK
  imports; mints the `VaultTransport` + wraps it in `VaultCredentialAdapter`; passes `checkpoint_store=None`;
  returns `(backend, docker_client)`) + the `settings.sandbox_runtime_enabled` flag (default `False`) in
  `core/config.py` + the SDK-gated lifespan construction of BOTH `app.state.sandbox_backend` AND
  `app.state.managed_run_executor` (NO `Runtime` slot) + closing the owned `docker_client` on shutdown.
  Tests: SDK-absent (both slots `None`, no client leak); `sandbox_runtime_enabled=False` (no construction);
  missing-`vault_addr` fail-soft (both slots `None` + warning); construction-fail-soft (both `None` + client
  closed); both slots pre-seeded `None`.
- **T3** — the env-gated real-docker e2e (`COGNIC_RUN_DOCKER_SANDBOX=1`): real backend + executor + the
  canonical-image deterministic argv; assert exit_code + stdout + the chain rows. **Valve checkpoint here**:
  if T1+T2 already crossed reviewable size, T3 is the natural 14A-A close and the route/checkpoint→wake stay
  14A-A2.
- **T4** — docs: ADR-022/ADR-004 amendment (managed-run executor; the run loop; the SDK-gated backend
  construction; the deferred 14A-A2) + AGENTS.md (`core/run/executor.py` on the gate; the executor authority)
  + capability map (pillar 2 — the first exercised managed-run path; 14A-A DONE; 14A-A2 next).

## 11. Resolved decisions

- Executor in `core/run/executor.py` (CC, SDK-free interfaces only, AST-fenced: no SDK + no runtime portal);
  count 129→130.
- 14A-A is **DockerSibling-only** — `is_sandbox_available` returns `True` only for
  `sandbox_backend == "docker_sibling"` + `aiodocker` importable; `kubernetes_pod` fail-softs (deferred
  warning, both `app.state` slots `None`). Multi-backend (real K8s construction) stays out of 14A-A.
- `backend.create` is called with the full grounded signature `create(policy, *, actor, tenant_id,
  pack_context, requires_credentials=())` (protocol.py:650-659). `RunRequest.actor` is the
  `portal.rbac.Actor` (TYPE_CHECKING-only in `core/run`, runtime pass-through — mirrors `sandbox.protocol`);
  the executor projects the core-owned `TaskActor` for the scheduler `submit` (keeps the scheduler portal-free)
  and asserts `request.tenant_id == request.actor.tenant_id`.
- Builder in `harness/sandbox.py` (off-gate; function-local SDK imports; mirrors `harness/mcp_host.py`);
  backend + executor constructed in the lifespan, SDK-gated via a new `is_sandbox_available()` + the new
  `settings.sandbox_runtime_enabled` flag (conservative default `False`), fail-soft; `build_runtime` untouched
  + SDK-free.
- Exposure via `app.state.sandbox_backend` + `app.state.managed_run_executor` ONLY — NO `Runtime.sandbox_backend`
  slot.
- The backend has no close API; `build_sandbox_backend` returns `(backend, docker_client)` and the lifespan
  closes the owned `docker_client` on shutdown + on fail-soft.
- `get_backend()` is authoritative for `image_catalog` + `egress_proxy_image` (built from `sandbox_canonical_*`
  settings); the builder passes neither.
- Credential adapter = the real `VaultCredentialAdapter(transport=VaultTransport(<from settings>),
  settings=settings)`; the builder mints the `VaultTransport` (Option 1 — `adapters.secret` is a `SecretAdapter`,
  not a `VaultTransport`). The `read_only` no-creds slice passes `requires_credentials=()` → `mint_lease` never
  runs, the lazy `VaultTransport` contacts no Vault. Missing/invalid `settings.vault_addr` while
  `sandbox_runtime_enabled=True` → fail-soft `None` + warning. `checkpoint_store=None` in 14A-A (14A-A2 wires it
  + may revisit sharing one Vault transport).
- Fork A (executor owns the session); scheduler `sandbox_adapter` seam NOT used in 14A-A (stays a documented
  dormant seam).
- Non-zero exit → `complete`; infra exception → `fail`; `finally`-guarded teardown.
- Value-free `run.*` evidence (`exit_code` + separate `stdout_sha256`/`stderr_sha256` + `stdout_bytes`/
  `stderr_bytes`; never `sha256(stdout+stderr)`); raw output to caller only; UI `decision_audit` mirror, no
  new UI family.
- `argv: tuple[str,...]` verbatim to `session.exec`; no shell concatenation; minimal default `SandboxPolicy`
  (`runtime_image=settings.sandbox_canonical_runtime_python_image`) + `PackAdmissionContext(profile="production")`;
  manifest-driven = 14A-B.
- Route + checkpoint→wake = 14A-A2 (valve after T1+T2/backend+executor).
- Two test tiers: always-run stub-backend orchestration + env-gated real-docker proof.
