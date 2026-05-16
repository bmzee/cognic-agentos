# Sprint 8A — Sandbox primitive (core + Docker sibling backend + canonical image catalog) — Design spec

**Status:** DRAFT pending review
**Authored:** 2026-05-16
**Source ADRs:** ADR-004 (Sandbox Primitive — APPROVED) + amendment landing alongside this spec
**Cross-ADR amendments triggered:** ADR-004 (dual-backend Wave-1 reality, naming, immutable-image doctrine), ADR-016 (canonical image catalog joins the cosign-signed artifact set), ADR-006 (sandbox lifecycle events tagged A.6.2.5)
**Sprint sizing:** ~3.5 wu floor / ~4.5 wu ceiling (warm-pool brings core 3 wu + 0.5 wu minimum)
**Related sprints:** **8B** = Kubernetes/OpenShift backend (sibling sprint); **8.5** = resumable session API (checkpoint/suspend/wake); **10** = Vault credential leasing (replaces 8A's fail-loud stub); **10.5** = scheduler (wraps sandbox.submit per ADR-022)
**Brainstorming source:** session of 2026-05-16; 6 doctrinal AskUserQuestion rounds locked the major decisions

---

## 1. Scope summary

**What 8A ships:** the `sandbox/` primitive package + the first of two Wave-1 backends + a canonical signed image catalog + the egress-proxy mechanism + the warm-pool interface and Docker implementation + the credential-leasing seam (fail-loud stub pending Sprint 10) + audit chain integration + the shared backend conformance test suite.

**What 8A does NOT ship** (each item is named so future implementors and reviewers can verify scope):
- `KubernetesPodSandboxBackend` and OpenShift-specific NetworkPolicy / ServiceAccount / SecurityContext — **ships in Sprint 8B**.
- `SandboxSession.checkpoint() / suspend() / wake()` resumable API — **ships in Sprint 8.5**.
- Real Vault credential leasing — **ships in Sprint 10**; 8A ships only the `CredentialAdapter` Protocol + fail-loud `NotImplementedError` stub.
- Scheduler integration — sandbox creation in 8A dispatches synchronously; **Sprint 10.5** wraps `SchedulerEngine.submit()` above the sandbox primitive without breaking 8A's contract.
- Per-tenant backend routing — backend choice is process-wide via env var in 8A; per-tenant routing is **explicitly deferred** to a later sprint (Sprint 14 deployment kit is the candidate home).
- Advanced warm-pool features — autoscaling, predictive warming, cross-node balancing, K8s-specific prewarming (beyond the interface stub), cost optimization beyond max-pool-size + idle-TTL — **all deferred** post-Phase-4 per the locked scope discipline.
- gVisor / Firecracker / Kata / rootless Docker — **Wave-2** per ADR-004 line 28; must conform to the same `SandboxBackend` Protocol.

---

## 2. Doctrinal locks (verbatim from brainstorming)

### 2.1 Wave-1 egress doctrine

> *"Wave 1 egress is HTTP/HTTPS-only through an AgentOS-controlled proxy endpoint. The sandbox gets no direct external network route; all outbound traffic must traverse the proxy, which enforces the per-call hostname allow-list and emits audit evidence. Non-HTTP protocols are out of scope/refused in Wave 1."*

**Doctrinal contract:** the wire-protocol-public doctrine is "no direct external route + proxy-mediated allow-list + audit evidence + non-HTTP refused at the application layer". The specific Wave-1 implementation that satisfies this doctrine is the **dual-container internal-network egress topology locked in §10.1** (sandbox attaches to a per-session Docker bridge with `internal=True` so the kernel has no external gateway; the proxy is a separate dual-homed container reachable via the internal bridge and itself joined to a second non-internal bridge with external gateway; `HTTP_PROXY` / `HTTPS_PROXY` env vars on the sandbox container point at the proxy). Earlier round-1 framing that described "proxy process inside sandbox netns + `--network none`" is rejected as physically impossible (a sandbox with `--network none` has no in-namespace reachable proxy either). Alternative implementable variants (host-side proxy via mounted Unix-domain socket; single-container proxy-as-first-process with `CAP_NET_ADMIN` + iptables) are documented in §10.5 as "rejected for Wave-1 unless plan-of-record review surfaces a concrete blocker on the dual-container pattern".

### 2.2 Vault credential-leasing contract (Sprint 10 stub)

> *"Sprint 8 defines the credential-leasing seam but does not implement Vault leasing. `sandbox/credentials.py` ships `CredentialAdapter` plus `KernelDefaultCredentialAdapter`, whose methods raise `NotImplementedError` pointing to Sprint 10 / ADR-004. If a sandbox policy requires credentials and no real adapter is configured, `sandbox.create()` refuses fail-closed with `sandbox_credential_adapter_not_configured`. Sandboxes that do not request credentials are unaffected."*

### 2.3 Docker backend naming + trust boundary

> *"Wave-1 sandbox isolation is Docker-container isolation managed through the host Docker daemon. AgentOS is inside the trusted control plane. A compromised AgentOS process with Docker socket access is equivalent to host-level Docker control. This is acceptable for Wave-1 reference deployment, not the final bank-grade isolation story."*

> *"Wave 1 implements `DockerSiblingSandboxBackend`: AgentOS talks to the host Docker daemon and launches sibling sandbox containers with pinned image digest, CPU/memory/wall-time limits, read-only mounts, no direct external egress, and proxy-mediated HTTP/HTTPS egress. This is not nested privileged DinD. Stronger backends such as gVisor, Firecracker, Kata, or rootless Docker are Wave 2 and must conform to the same `SandboxBackend` Protocol."*

### 2.4 Immutable runtime image doctrine

> *"Wave 1 sandboxes run immutable, digest-pinned runtime images. AgentOS publishes a small canonical image catalog for common cases. Pack-specific runtime images are allowed only when signed, SBOM-scanned, digest-pinned, and tenant allow-listed. Production sandboxes do not install OS or Python packages at create time; missing dependencies fail closed with a clear refusal."*

### 2.5 Warm-pool scope discipline

> *"Warm-pool is a Wave-1 sandbox capability, introduced with the core SandboxBackend contract in Sprint 8A. Docker sibling backend implements it immediately. Kubernetes/OpenShift backend in 8B must conform to the same warm-pool semantics."*

In-scope for 8A: `sandbox/warm_pool.py` + per-backend `precreate / checkout / release_or_destroy` interface + per-tenant/per-policy pool size + background replenisher + pool-hit fast path + pool-miss cold-create fallback + shutdown drain + audit events. Out-of-scope for 8A: advanced autoscaling, predictive warming, cross-node pool balancing, K8s-specific prewarming beyond interface stub, cost optimization beyond max-pool-size + idle-TTL.

### 2.6 Backend selection

Wave-1 backend selection is process-wide via env var:

```
COGNIC_SANDBOX_BACKEND = docker_sibling | kubernetes_pod
```

Per-tenant backend routing is **explicitly deferred** out of 8A scope. A future sprint (Sprint 14 deployment kit is the candidate home) introduces per-tenant routing without breaking the 8A `SandboxBackend` Protocol.

---

## 3. Module layout

```
src/cognic_agentos/sandbox/
├── __init__.py                  # public re-exports: SandboxBackend, SandboxSession,
│                                #   SandboxPolicy, SandboxRefusalReason,
│                                #   SandboxPolicyViolationReason, SandboxLifecycleEvent
├── protocol.py                  # SandboxBackend Protocol (async); SandboxSession
│                                #   Protocol (async); shared TypedDicts
├── policy.py                    # SandboxPolicy frozen dataclass + PURE
│                                #   validate_policy_shape() — field shape, ranges,
│                                #   RFC-1123 hosts, scheme refusal. NO I/O.
├── admission.py                 # ASYNC admit_policy() — catalog lookup + cosign
│                                #   verify + SBOM check + rego eval + tenant-max
│                                #   enforcement. Wires deps (catalog, rego_engine,
│                                #   audit_store) via constructor injection so both
│                                #   Wave-1 backends share the admission pipeline.
├── credentials.py               # CredentialAdapter Protocol +
│                                #   KernelDefaultCredentialAdapter (NotImplementedError
│                                #   stub pointing at Sprint 10 / ADR-004)
├── audit.py                     # sandbox lifecycle event emitters + chain-row
│                                #   payload builders; ISO 42001 A.6.2.5 tagging
├── warm_pool.py                 # SandboxWarmPool + per-policy-key pool; background
│                                #   replenisher; shutdown drain; emits warm-pool
│                                #   audit events
├── catalog.py                   # CanonicalImageCatalog: 4 image refs (3 runtime +
│                                #   1 egress-proxy sidecar) + cosign + SBOM
│                                #   verification + per-tenant allow-list check
├── proxy.py                     # EgressProxyConfig + egress allow-list rendering
│                                #   into proxy config; runtime emits per-request
│                                #   proxy audit rows
└── backends/
    ├── __init__.py
    └── docker_sibling.py        # DockerSiblingSandboxBackend; mounts host docker.sock;
                                 #   spawns sibling containers; implements
                                 #   SandboxBackend Protocol; warm_pool integration

policies/_default/sandbox.rego   # admission policy bundle (NEW; default-deny;
                                 #   wire-protocol-public via the AGENTS.md stop-rule
                                 #   list ladder when Sprint 8A lands)

tests/unit/sandbox/
├── __init__.py
├── test_policy_shape.py                 # PURE validate_policy_shape() — field shapes,
│                                        #   RFC-1123 hosts, scheme refusal arms; no I/O
├── test_admission_pipeline.py           # ASYNC admit_policy() — catalog miss + cosign
│                                        #   fail + sbom fail + rego deny + tenant-max
│                                        #   + high-risk-tier-pre-13.5 refusal arms;
│                                        #   pin warm-pool replenishment uses
│                                        #   use_warm_pool=False (no recursion)
├── test_credential_adapter_stub.py      # NotImplementedError + closed-enum refusal
├── test_image_catalog.py                # canonical catalog + cosign + SBOM + tenant
├── test_egress_proxy_config.py          # allow-list rendering + non-HTTP refusal
├── test_warm_pool.py                    # precreate / checkout / drain / audit;
│                                        #   no-recursion-through-create pinned
├── test_audit_event_taxonomy.py         # 8-event taxonomy + 15+5 closed-enum pin
├── conftest.py                          # shared backend fixtures + conformance harness
└── backends/
    ├── __init__.py
    ├── test_docker_sibling_lifecycle.py   # create + exec + destroy on real Docker
    ├── test_docker_sibling_egress.py      # allow-listed succeeds; non-allow refused
    ├── test_docker_sibling_resource_caps.py  # cpu / memory / walltime prove-out
    └── test_docker_sibling_image_pin.py   # wrong digest refused

tests/conformance/sandbox/                # SHARED conformance suite — 8B's
├── __init__.py                           #   KubernetesPodSandboxBackend runs the
├── conftest.py                           #   same tests via a backend-parameterized
└── test_backend_conformance.py           #   fixture
```

**Total**: ~10 production modules + 1 Rego bundle + **11 unit-test files** (7 top-level in `tests/unit/sandbox/` + 4 backend-specific in `tests/unit/sandbox/backends/`) + 1 conformance suite in `tests/conformance/sandbox/`. Following the `core/memory/` / `core/scheduler/` subpackage pattern from previous platform primitives.

---

## 4. Closed-enum vocabularies (wire-protocol-public)

### 4.1 `SandboxRefusalReason` — `sandbox.lifecycle.refused.payload.reason`

The 15-value closed-enum for sandbox-creation refusals. Drift between this Literal and consumer error-handling is caught at module load by a partition-invariant test.

| Reason | Trigger |
|---|---|
| `sandbox_credential_adapter_not_configured` | Policy requires credentials; `CredentialAdapter` is the fail-loud default stub (pre-Sprint-10) |
| `sandbox_runtime_deps_unsupported_in_production` | Pack manifest declares dynamic install at create-time + tenant runs production profile |
| `sandbox_high_risk_tier_refused_pre_13_5` | Pack `risk_tier ∈ {customer_data_read, customer_data_write, payment_action, regulator_communication, cross_tenant, high_risk_custom}` (6-value high-risk set, canonical across §6.1 admission + §13 `sandbox.rego`) AND `core/approval` engine not yet wired (pre-Sprint-13.5 transitional refusal; mirrors the Sprint-5 MCP transitional + Sprint-11.5 memory transitional patterns) |
| `sandbox_image_digest_not_in_canonical_catalog` | Pack manifest's `runtime_image` digest is not in AgentOS canonical catalog AND not in tenant allow-list |
| `sandbox_image_cosign_verification_failed` | cosign verify of the image digest failed against tenant trust root |
| `sandbox_image_sbom_check_failed` | SBOM missing or fails tenant SBOM policy (e.g. blocked-licence detected) |
| `sandbox_image_digest_format_invalid` | Image digest is not in `sha256:<64-hex>` format |
| `sandbox_policy_exceeds_tenant_max_cpu` | `SandboxPolicy.cpu_cores` > tenant max (from `policy.yaml`) |
| `sandbox_policy_exceeds_tenant_max_memory` | `SandboxPolicy.memory_mb` > tenant max |
| `sandbox_policy_exceeds_tenant_max_walltime` | `SandboxPolicy.walltime_s` > tenant max |
| `sandbox_policy_egress_host_invalid` | `SandboxPolicy.egress_allow_list` contains malformed host (RFC 1123 violation) |
| `sandbox_policy_egress_protocol_not_http` | `SandboxPolicy.egress_allow_list` declares non-HTTP/HTTPS scheme (Wave-1 refused per §2.1) |
| `sandbox_policy_rego_denied` | `sandbox.rego` at `data.cognic.sandbox.admit.allow` returned `false` |
| `sandbox_backend_unavailable` | Docker daemon unreachable (or K8s API unreachable in 8B) |
| `sandbox_warm_pool_drained` | Checkout from a pool that completed shutdown drain |

### 4.2 `SandboxPolicyViolationReason` — `sandbox.policy.violated.payload.reason`

The 5-value closed-enum for runtime policy violations during `exec`. **Note:** CPU throttling under the `--cpus` cap is NOT a violation by itself — a CPU-bound workload that stays within its budget is expected to be throttled by the kernel scheduler. Workloads needing a hard CPU-seconds budget set `SandboxPolicy.cpu_time_budget_s` (optional; runtime monitor reads `cgroup cpuacct.usage_us` and kills when exceeded).

| Reason | Trigger |
|---|---|
| `cpu_time_budget_exceeded` | `SandboxPolicy.cpu_time_budget_s` set AND cgroup `cpuacct.usage_us` exceeded the budget; container killed. Not fired when budget is unset (the `--cpus` throttle is the only CPU control). |
| `memory_cap_exceeded` | OOM-killer triggered by the cgroup memory cap |
| `walltime_cap_exceeded` | AgentOS-side timer fires; container killed |
| `egress_host_not_allow_listed` | Proxy rejects an outbound request to a non-allow-listed host |
| `egress_protocol_not_http` | Proxy receives HTTP CONNECT to a non-443 port OR a non-HTTP method (e.g. `CONNECT example.com:6379 HTTP/1.1` for Redis, `CONNECT example.com:25 HTTP/1.1` for SMTP). **Proxy-observed only** — raw TCP / UDP / DNS-over-TCP attempts that bypass the proxy entirely are blocked at the network layer (sandbox has no external gateway per §10.1) and are NOT emitted as policy-violation events in Wave 1; see §10.4 for the full proxy-observed vs network-blocked split |

### 4.3 `SandboxLifecycleEvent` — top-level audit event family discriminator

The 8-value closed-enum following the user-locked taxonomy (Sprint 8 brainstorming Q-final):

| Event | When emitted | Discriminator field |
|---|---|---|
| `sandbox.lifecycle.created` | `SandboxSession.create()` succeeds (cold or warm-pool hit) | `payload.warm_pool_hit: bool` |
| `sandbox.lifecycle.exec_completed` | `SandboxSession.exec()` returns (success or non-violation failure) | `payload.exit_code: int` |
| `sandbox.lifecycle.destroyed` | `SandboxSession.destroy()` succeeds | `payload.duration_s: float` |
| `sandbox.lifecycle.refused` | `SandboxSession.create()` fails admission | `payload.reason: SandboxRefusalReason` |
| `sandbox.policy.violated` | Runtime policy cap exceeded; session killed | `payload.reason: SandboxPolicyViolationReason` |
| `sandbox.warm_pool.precreated` | A new pool member becomes ready (covers initial fill AND replenishment) | `payload.pool_key: str` + `payload.pool_size_after: int` |
| `sandbox.warm_pool.checked_out` | A pool member is handed to a `SandboxSession.create()` call | `payload.pool_key: str` + `payload.pool_size_after: int` |
| `sandbox.warm_pool.drained` | Shutdown drain completes for a pool | `payload.pool_key: str` + `payload.drained_count: int` |

All 8 events tagged with ISO 42001 control `A.6.2.5` (operational controls) per ADR-006 + ADR-004 §3.4.

**Per user-locked decision: NO `warm_pool.replenished` event** — replenishment is the *cause* (background replenisher fires), the *event* is still `precreated` (a new pool member is ready). Drift detector pins the 8-value count.

---

## 5. `SandboxBackend` Protocol

```python
class SandboxBackend(Protocol):
    """Backend-abstracted sandbox lifecycle.

    Wave-1 implementations: DockerSiblingSandboxBackend (8A),
    KubernetesPodSandboxBackend (8B). Wave-2: gVisor, Firecracker, Kata,
    rootless Docker. All implementations MUST honor the same lifecycle
    contract and the shared conformance test suite.
    """

    async def create(
        self,
        policy: SandboxPolicy,
        *,
        actor: Actor,
        tenant_id: str,
        pack_context: PackAdmissionContext,
        use_warm_pool: bool = True,
    ) -> SandboxSession:
        """Admit + create a sandbox session.

        Refuses fail-closed with SandboxLifecycleRefused carrying a
        SandboxRefusalReason closed-enum value on any admission failure.

        use_warm_pool: if True (default), AND policy.warm_pool_key is set,
        AND the pool has a matching member, returns a warm session
        (audit-emit warm_pool.checked_out + lifecycle.created with
        warm_pool_hit=True). Else cold-creates (audit-emit
        lifecycle.created with warm_pool_hit=False).

        use_warm_pool=False is the replenishment path: SandboxWarmPool
        .precreate() calls this with use_warm_pool=False so the
        replenisher never consumes an existing pool member (closes the
        precreate↔checkout recursion trap; pinned by
        test_admission_pipeline.py::test_replenisher_bypasses_pool).
        """

    async def exec(
        self,
        session: SandboxSession,
        command: list[str],
        *,
        timeout_s: float | None = None,
    ) -> SandboxExecResult:
        """Execute a command in the session. Returns the exec result.

        Runtime policy-violation kills the session before returning; in
        that case raises SandboxPolicyViolated carrying a closed-enum
        reason.
        """

    async def destroy(self, session: SandboxSession) -> None:
        """Tear down the session. Idempotent.

        For warm-pool members, release_or_destroy() is the public seam;
        destroy() is the unconditional teardown.
        """

    async def health(self) -> SandboxBackendHealth:
        """Backend readiness check. Used by /readyz and at startup.

        Returns SandboxBackendHealth(status, detail) where status is
        Literal["ok", "degraded", "unavailable"].
        """
```

```python
class SandboxSession(Protocol):
    """A live sandbox. Identity persists across exec() calls."""

    session_id: str                       # uuid4 hex; persists into Sprint 8.5 checkpoint store
    policy: SandboxPolicy
    tenant_id: str
    pack_context: PackAdmissionContext   # the PackAdmissionContext under which this
                                          #   session was admitted; carried on the session
                                          #   so warm_pool.release_or_destroy(session) can
                                          #   derive the correct pool key for cold-created
                                          #   sessions (round-3 follow-on P1 reviewer fix);
                                          #   also load-bearing for Sprint 8.5 wake-time
                                          #   re-admission against the same context
    created_at: datetime
    warm_pool_hit: bool                   # True if checked-out from pool; False if cold

    async def exec(self, command: list[str], *, timeout_s: float | None = None) -> SandboxExecResult: ...
    async def destroy(self) -> None: ...
```

**Lifecycle ergonomics:** the `SandboxBackend` Protocol intentionally exposes only the 4 primary lifecycle ops (`create / exec / destroy / health`). A context-manager wrapper ships as a **helper function** in `sandbox/__init__.py` (NOT a Protocol method — keeps the Protocol minimal so backend implementors don't have to re-implement the wrapper):

```python
# sandbox/__init__.py
@asynccontextmanager
async def sandbox_session(
    backend: SandboxBackend,
    policy: SandboxPolicy,
    *,
    actor: Actor,
    tenant_id: str,
    pack_context: PackAdmissionContext,
    use_warm_pool: bool = True,
    warm_pool: SandboxWarmPool | None = None,
) -> AsyncIterator[SandboxSession]:
    """Helper context manager; preserves warm-pool reuse on exit.

    On exit:
    - If use_warm_pool=True AND warm_pool is not None → routes through
      warm_pool.release_or_destroy(session) so a checked-out warm
      member returns to the pool instead of being destroyed (round-2
      P2 reviewer fix: without this, warm-pool members would be
      one-shot under the ergonomic API, defeating the latency target).
    - Else → session.destroy() unconditionally.

    NOT part of the SandboxBackend Protocol (which stays minimal at 4
    primary ops). Backend implementors do not need to provide their own
    session() — this helper works for every Protocol-conforming backend.

    Pinned by:
    - test_helper_releases_to_pool_when_pool_wired (warm-pool route)
    - test_helper_destroys_when_pool_not_wired (fallback route)
    """
    session = await backend.create(
        policy,
        actor=actor,
        tenant_id=tenant_id,
        pack_context=pack_context,
        use_warm_pool=use_warm_pool,
    )
    try:
        yield session
    finally:
        if use_warm_pool and warm_pool is not None:
            await warm_pool.release_or_destroy(session)
        else:
            await session.destroy()

# Caller usage (warm-pool-aware — typical agent harness path):
async with sandbox_session(
    backend, policy,
    actor=actor, tenant_id=tid, pack_context=pack_ctx,
    warm_pool=warm_pool,                              # ← pool wired
) as s:
    result = await s.exec(["python", "-c", "print(1+1)"])
# session returned to pool via release_or_destroy() on context exit

# Caller usage (no pool — e.g. one-off admin tools):
async with sandbox_session(
    backend, policy,
    actor=actor, tenant_id=tid, pack_context=pack_ctx,
    use_warm_pool=False,                              # ← explicit opt-out
) as s:
    result = await s.exec(...)
# session.destroy() fired on context exit
```

Raw `backend.create() / session.destroy()` are available for advanced cases (Sprint 8.5 suspend/wake, warm-pool members held across requests). Both routes hit the same audit trail.

---

## 6. `SandboxPolicy` schema

```python
@dataclass(frozen=True)
class SandboxPolicy:
    # Resource caps (validated against tenant max from policy.yaml + sandbox.rego)
    cpu_cores: float                       # Docker --cpus / K8s resources.limits.cpu;
                                           #   throttling under cap is NOT a violation
    cpu_time_budget_s: float | None = None # Optional CPU-seconds budget; when set,
                                           #   AgentOS reads cgroup cpuacct.usage_us
                                           #   and kills container on exceed →
                                           #   cpu_time_budget_exceeded.
                                           #   Distinct from walltime_s (which is
                                           #   wall-clock; cpu_time_budget_s is
                                           #   accumulated CPU-seconds across cores).
    memory_mb: int                         # hard cap; OOM-killer enforces
    walltime_s: float                      # AgentOS-side timer

    # Image (canonical catalog OR per-pack allow-listed signed image)
    runtime_image: str      # full ref incl digest, e.g. "cognic/sandbox-runtime-python@sha256:..."

    # Egress
    egress_allow_list: tuple[str, ...]  # RFC-1123 hostnames; HTTP/HTTPS scheme implicit (Wave 1)

    # Credentials (Sprint 10 stub in 8A)
    vault_path: str | None  # if set + adapter not real → sandbox_credential_adapter_not_configured

    # Filesystem
    read_only_root: bool = True  # default True; per-tenant override via policy.rego
    writable_mounts: tuple[WritableMount, ...] = ()  # bounded; tenant-cap enforced

    # Warm-pool
    warm_pool_key: str | None = None  # if set, eligible for pool hit on create()
```

### 6.1 Two-stage validation — pure shape, then async admission

The validation pipeline is **deliberately split** across two modules with different I/O characteristics (P1 reviewer correction from spec round 1):

**Stage 1 — `sandbox/policy.py:validate_policy_shape(policy: SandboxPolicy) -> None`** (PURE; no I/O; matches `core/sla.py` + `packs/lifecycle.py` pattern):

1. **Field-shape validation** — pydantic-equivalent per-field constraints (`cpu_cores > 0`, `memory_mb > 0`, `walltime_s > 0`, `cpu_time_budget_s is None or > 0`). Image-reference validation uses the docker-py / oci-spec library's OCI image-reference parser, NOT an inline regex (round-2 reviewer correction: the inline regex `^[a-z0-9-/]+@sha256:[0-9a-f]{64}$` rejected the spec's own canonical refs like `cognic/sandbox-runtime-python:v1.2@sha256:...` because of the `:v1.2` tag colon and refs from registries with dots/ports like `registry.example.com:5000/foo:bar@sha256:...`). The validator asserts: (a) ref parses as a valid OCI image reference; (b) ref carries an `@sha256:<64-hex>` digest suffix; (c) digest portion matches `^sha256:[0-9a-f]{64}$`. Refusals: `sandbox_image_digest_format_invalid` for the image; `sandbox_policy_*` family for resource shape.
2. **Egress allow-list shape** — RFC 1123 hostname validation per entry; non-HTTP/HTTPS schemes refused — refuses with `sandbox_policy_egress_host_invalid` or `sandbox_policy_egress_protocol_not_http`.

Stage 1 is synchronous + side-effect-free + testable without fixtures. Raises `SandboxLifecycleRefused(reason=...)` on the first failure.

**Stage 2 — `sandbox/admission.py:admit_policy(policy, *, tenant_id, actor, pack_context, catalog, credential_adapter, rego_engine, settings) -> None`** (ASYNC; performs I/O; shared across all backends — both Docker-sibling in 8A and K8sPod in 8B will call this same admission seam):

The `pack_context: PackAdmissionContext` parameter carries pack-level fields the admission pipeline needs but that don't belong on the per-call `SandboxPolicy` (pack-level fields are stable across a pack's many sandbox creates; `SandboxPolicy` is per-tool-call operational config). The dataclass lives in `sandbox/admission.py` and is exported via `sandbox/__init__.py`:

```python
@dataclass(frozen=True)
class PackAdmissionContext:
    """Pack-level context for sandbox admission. Built by the harness
    from the pack manifest when a tool call requires a sandbox; passed
    through to admit_policy() so admission has the manifest-level
    fields it needs to make decisions that aren't on SandboxPolicy."""
    pack_id: str
    pack_version: str                # human-readable; used in audit logs + UI; NOT used in pool key
    pack_artifact_digest: str        # cosign-verified pack artifact sha256; the IMMUTABLE
                                     #   identity per ADR-016 trust-gate pinning. Used in
                                     #   pool key + checkout match so a session admitted for
                                     #   one artifact digest cannot be handed to a different
                                     #   digest even if pack_id matches (round-3-third-follow-on
                                     #   P1 reviewer fix: pack_version alone was insufficient
                                     #   because human-mutable in some workflows; artifact
                                     #   digest is the trust-gate-pinned immutable identity).
    risk_tier: RiskTier              # 8-value ADR-014 RiskTier Literal; drives §6.1 step 4
    declares_dynamic_install: bool   # drives §6.1 step 3a (sandbox_runtime_deps_unsupported_in_production)
    profile: Literal["production", "development"]  # only "production" enforces the dynamic-install refusal
```

3. **Credential-adapter check** — if `policy.vault_path` set AND `credential_adapter` is `KernelDefaultCredentialAdapter` → refuse with `sandbox_credential_adapter_not_configured`. No mint attempt.
3a. **Dynamic-install refusal** — if `pack_context.declares_dynamic_install == True` AND `pack_context.profile == "production"` → refuse with `sandbox_runtime_deps_unsupported_in_production`. (Dev-profile dynamic install permitted under the explicit dev path — clearly separated per `feedback_immutable_runtime_images_no_dynamic_install`.)
4. **High-risk-tier transitional refusal** — if `pack_context.risk_tier ∈ {customer_data_read, customer_data_write, payment_action, regulator_communication, cross_tenant, high_risk_custom}` (6-value canonical set; same as §4.1 trigger + §13 `sandbox.rego` defaults) AND `core/approval` engine not yet wired → refuse with `sandbox_high_risk_tier_refused_pre_13_5` (mirrors Sprint 5 MCP + Sprint 11.5 memory transitional patterns; lifts when Sprint 13.5 ships).
5. **Tenant-max check** — compares against `core/config.py` per-tenant max → `sandbox_policy_exceeds_tenant_max_*`. (Reads tenant config; not pure.)
6. **Image catalog check** — `catalog.is_canonical(image_digest)` OR `catalog.is_tenant_allow_listed(image_digest, tenant_id)` → refuse with `sandbox_image_digest_not_in_canonical_catalog`. (Network or filesystem lookup; not pure.)
7. **Cosign verification** — `await catalog.verify_cosign(image_digest, tenant_id)` → refuse with `sandbox_image_cosign_verification_failed`. (cosign subprocess; not pure.)
8. **SBOM check** — `await catalog.verify_sbom_policy(image_digest, tenant_id)` → refuse with `sandbox_image_sbom_check_failed`. (syft / file inspection; not pure.)
9. **Rego admission** — `await rego_engine.evaluate("data.cognic.sandbox.admit.allow", input=policy_input)` → refuse with `sandbox_policy_rego_denied`. (OPA subprocess; not pure.)

Stage 2 raises `SandboxLifecycleRefused(reason=...)` on the first failure. Steps execute in the order listed; later steps are skipped on earlier failure.

**Backend `create()` call site:**

```python
# inside DockerSiblingSandboxBackend.create() — also inside KubernetesPodSandboxBackend.create() in 8B
validate_policy_shape(policy)                      # Stage 1 — synchronous, fail-fast
await self._admission.admit_policy(                # Stage 2 — async, full I/O
    policy,
    tenant_id=tenant_id,
    actor=actor,
    pack_context=pack_context,                     # PackAdmissionContext from harness
)
# admission passed; proceed to backend-specific container/pod creation below
```

Both stages emit `sandbox.lifecycle.refused` with the matching closed-enum reason on failure. The split avoids the architecture-violation reviewer found in round 1 (where the spec described validation as "pure" but the pipeline contained cosign + SBOM + Rego I/O).

---

## 7. `DockerSiblingSandboxBackend`

Single backend in 8A. Located at `sandbox/backends/docker_sibling.py`.

**Constructor:**

```python
class DockerSiblingSandboxBackend:
    def __init__(
        self,
        *,
        docker_client: docker.AsyncDockerClient,  # connects to host docker.sock
        image_catalog: CanonicalImageCatalog,
        credential_adapter: CredentialAdapter,
        rego_engine: OPAEngine,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
        warm_pool: SandboxWarmPool | None = None,
    ): ...
```

**`create()` flow:**

1. `validate_policy_shape(policy)` — synchronous Stage-1 shape check; early refusal on shape failure
2. `await self._admission.admit_policy(policy, tenant_id=tid, actor=actor, pack_context=pack_context)` — async Stage-2 admission (catalog + cosign + SBOM + Rego + credential-adapter + high-risk-tier); early refusal on any admission failure. The `pack_context` arrives via the Protocol's `create(..., pack_context: PackAdmissionContext)` kwarg per §5; admission needs it for the §6.1-step-3a dynamic-install gate AND the §6.1-step-4 high-risk-tier transitional refusal.
3. If `use_warm_pool=True` AND `policy.warm_pool_key` set AND `self._warm_pool.has_match(policy)` → warm-pool checkout path (sub-50ms); emit `warm_pool.checked_out` + `lifecycle.created` with `warm_pool_hit=True`; return checked-out session
4. Else cold-create using the **dual-container internal-network egress topology** (P1 reviewer fix from spec round 1 — replaces the impossible `--network none` + in-netns-proxy combination):
   - **Create an internal Docker network** scoped to this session: `docker.networks.create(name=f"cognic-sb-internal-{session_id}", driver="bridge", internal=True)` — the `internal=True` flag means this bridge has no external gateway; only containers attached to it can talk to each other.
   - **Create a non-internal egress-staging network** scoped to this session: `docker.networks.create(name=f"cognic-sb-egress-{session_id}", driver="bridge")` — used only by the proxy for outbound traffic.
   - **Start the proxy container** (canonical image `cognic/sandbox-egress-proxy:vX@sha256:...`): `docker.containers.run(image=proxy_image, networks=[internal_net, egress_net], env={"ALLOW_LIST": json.dumps(policy.egress_allow_list), "SESSION_ID": session_id}, cap_drop=["ALL"], user="65534:65534")`. The proxy is dual-homed — reachable from the sandbox on the internal network at a known IP (e.g. via container DNS as `egress-proxy`), with external egress via the staging network.
   - **Create the sandbox container** attached ONLY to the internal network: `docker.containers.create(image=policy.runtime_image, network_mode=internal_net_name, cpus=policy.cpu_cores, mem_limit=f"{policy.memory_mb}m", read_only=policy.read_only_root, cap_drop=["ALL"], security_opt=["no-new-privileges:true"], tmpfs={"/tmp": "rw,noexec,nosuid,size=64m"}, user="65534:65534", environment={"HTTP_PROXY": "http://egress-proxy:3128", "HTTPS_PROXY": "http://egress-proxy:3128", "NO_PROXY": "localhost,127.0.0.1"})`.
   - **Doctrine**: the sandbox is on an `internal=True` Docker network — it has no route to any host except the dual-homed proxy. The doctrinal "no direct external route" holds via Docker's network topology, NOT via `--network none`.
   - Start the sandbox container; emit `sandbox.lifecycle.created` with `warm_pool_hit=False`
5. Return `SandboxSession` carrying `(sandbox_container_id, proxy_container_id, internal_network_id, egress_network_id)` — all four tracked so `destroy()` can tear them down cleanly.

**`exec()` flow:**

1. `docker.containers.exec_run(session.sandbox_container_id, command, demux=True)` with AgentOS-side `asyncio.wait_for(timeout=session.policy.walltime_s)`
2. Walltime exceeded → kill container, raise `SandboxPolicyViolated(reason="walltime_cap_exceeded")`
3. OOM (exit code 137 + cgroup oom-killer event) → raise `SandboxPolicyViolated(reason="memory_cap_exceeded")`
4. If `policy.cpu_time_budget_s` is set: a background AsyncIO task polls cgroup `cpuacct.usage_us` at ≥1Hz; when accumulated CPU-seconds exceeds the budget → kill container, raise `SandboxPolicyViolated(reason="cpu_time_budget_exceeded")`. **Throttling under `--cpus` is NOT a violation by itself** — CPU-bound workloads that stay within budget are expected to be throttled; the only CPU control without budget is the `--cpus` kernel-scheduler throttle.
5. Egress violations (`egress_host_not_allow_listed`, `egress_protocol_not_http`) are surfaced by the proxy via shared-volume signal or container-stop; AgentOS reads the proxy refusal record and raises `SandboxPolicyViolated` with the matching reason.
6. Else emit `sandbox.lifecycle.exec_completed` + return `SandboxExecResult(stdout, stderr, exit_code, proxy_log)`. The `proxy_log` carries the per-request hostname/method/decision audit trail rendered into the chain row.

**`destroy()` flow:**

1. `docker.containers.kill(session.sandbox_container_id, signal="SIGKILL")` (idempotent — already-stopped is no-op)
2. `docker.containers.kill(session.proxy_container_id, signal="SIGTERM")` (graceful — gives proxy 5s to flush audit; then SIGKILL)
3. `docker.containers.remove(session.sandbox_container_id, force=True, v=True)` (volumes purged)
4. `docker.containers.remove(session.proxy_container_id, force=True, v=True)`
5. `docker.networks.remove(session.internal_network_id)` + `docker.networks.remove(session.egress_network_id)` (both must be unattached after container removal)
6. Emit `sandbox.lifecycle.destroyed` with `duration_s = now - session.created_at`

**Resource cap enforcement specifics:**

| Cap | Docker flag | K8s equivalent (Sprint 8B) |
|---|---|---|
| CPU | `--cpus=0.5` | `resources.limits.cpu: "500m"` |
| Memory | `--memory=512m` + `--memory-swap=512m` | `resources.limits.memory: "512Mi"` |
| Wall-time | AgentOS-side `asyncio.wait_for()` | same; sidecar timer container |
| Read-only rootfs | `--read-only` | `securityContext.readOnlyRootFilesystem: true` |
| Capability drop | `--cap-drop=ALL` | `securityContext.capabilities.drop: ["ALL"]` |
| No new privileges | `--security-opt=no-new-privileges:true` | `securityContext.allowPrivilegeEscalation: false` |
| Non-root user | `--user 65534:65534` | `securityContext.runAsNonRoot: true` + `runAsUser: 65534` |

---

## 8. `CredentialAdapter` Protocol + `KernelDefaultCredentialAdapter` (Sprint 10 stub)

```python
class CredentialAdapter(Protocol):
    """Extension point for credential leasing. Real implementation
    ships in Sprint 10 as VaultCredentialAdapter per ADR-004 §Credential-scoped."""

    async def mint_lease(
        self,
        *,
        tenant_id: str,
        vault_path: str,
        session_id: str,
        ttl_s: int,
    ) -> CredentialLease: ...

    async def revoke_lease(self, lease: CredentialLease) -> None: ...


class KernelDefaultCredentialAdapter:
    """Fail-loud stub. Pointer-only scaffold per AGENTS.md production-grade rule.

    Pack manifests declaring `vault_path:` in sandbox policy trigger
    sandbox_credential_adapter_not_configured at create() time when this
    stub is wired (the default before a real adapter is configured).

    Sprint 10 replaces this with VaultCredentialAdapter (real Vault leasing).
    """

    async def mint_lease(self, **_: Any) -> CredentialLease:
        raise NotImplementedError(
            "Vault credential leasing not yet implemented; "
            "ships in Sprint 10 per ADR-004 §'Credential-scoped'. "
            "Sandboxes without `vault_path:` in their policy are unaffected."
        )

    async def revoke_lease(self, lease: CredentialLease) -> None:
        raise NotImplementedError(...)  # same message
```

Wiring: `DockerSiblingSandboxBackend.create()` checks `policy.vault_path is None` BEFORE the validation pipeline; if set + adapter is `KernelDefaultCredentialAdapter`, refuse with `sandbox_credential_adapter_not_configured`. No mint attempt; the stub never runs.

---

## 9. Canonical image catalog

**4 Wave-1 images**, owned + cosign-signed by AgentOS via the Sprint-4 supply-chain pipeline. The catalog includes 3 runtime images (per pack-author needs) + 1 egress-proxy sidecar image (used by every sandbox per the §10.1 dual-container topology; promoted to the catalog so the proxy itself is supply-chain-verified before any sandbox launches):

| Image | Role | Base | Extras |
|---|---|---|---|
| `cognic/sandbox-runtime-python:vX.Y@sha256:...` | Pure Python execution (runtime image) | `python:3.13-slim` | `requests`, `httpx` |
| `cognic/sandbox-runtime-shell:vX.Y@sha256:...` | Shell scripts + small CLIs (runtime image) | `debian:13-slim` | `curl`, `jq`, `coreutils` |
| `cognic/sandbox-runtime-data:vX.Y@sha256:...` | Data tooling for SQL / PDF / common formats (runtime image) | `python:3.13-slim` | `postgresql-client`, `poppler-utils`, `python3-pandas` |
| `cognic/sandbox-egress-proxy:vX.Y@sha256:...` | Egress proxy sidecar (per §10.1 dual-container topology — launched alongside every sandbox by `DockerSiblingSandboxBackend.create()`) | `alpine:3.20` | tinyproxy or equivalent HTTP/HTTPS forward proxy + allow-list config loader |

**No egress proxy binary in the runtime images** (round-3 P1 reviewer fix): the proxy lives in its own sidecar container, NOT embedded in each runtime image. The earlier wording was a round-1 artifact from before the dual-container topology was locked.

Each image:
- Built reproducibly via SLSA-L3+ provenance (Sprint 4 pipeline)
- cosign-signed against the AgentOS trust root
- SBOM-attached (syft) + vuln-scanned (grype) on every build
- License-audited (pip-licenses + dpkg-licenses)
- Sigstore bundle persisted 7 years per ADR-016
- Refresh cadence: monthly base-image refresh + on-CVE; tracked in a published cadence policy

**`CanonicalImageCatalog`:**

```python
class CanonicalImageCatalog:
    def is_canonical(self, image_digest: str) -> bool: ...
    def is_tenant_allow_listed(self, image_digest: str, tenant_id: str) -> bool: ...
    async def verify_cosign(self, image_digest: str, tenant_id: str) -> CosignVerifyResult: ...
    async def verify_sbom_policy(self, image_digest: str, tenant_id: str) -> SBOMVerifyResult: ...
```

Pack-declared per-tool image (`[tool.cognic.sandbox] runtime_image = "bank/my-tool@sha256:..."`):
- Tenant policy MUST allow-list the signer key + the image digest
- Same cosign + SBOM verification as catalog images
- Refusal closed-enum same as catalog mismatch (`sandbox_image_*` family)

---

## 10. Egress proxy

The Wave-1 egress proxy is the single enforcement point for the per-call hostname allow-list. Implementation topology corrected post-spec-round-1 P1 reviewer finding (the original "in-netns proxy + `--network none`" combination was physically impossible; sandbox-side network must exist for any proxy to be reachable).

### 10.1 Topology — dual-container internal-network pattern

The proxy runs as a **separate container** spawned alongside each sandbox container; both containers are tied via an `internal=True` Docker bridge network. The sandbox container can ONLY reach the proxy (no external gateway on the internal bridge); the proxy is dual-homed to a second non-internal bridge that has external egress.

```
                  cognic-sb-egress-{session_id}   (Docker bridge, default — has external gateway)
                              │
                  ┌───────────┴───────────┐
                  │  egress-proxy         │
                  │  container            │   (UID 65534, cap-drop ALL)
                  │  HTTP/HTTPS forward   │
                  │  proxy + allow-list   │
                  └───────────┬───────────┘
                              │
                  cognic-sb-internal-{session_id}  (Docker bridge, --internal — NO external gateway)
                              │
                  ┌───────────┴───────────┐
                  │  sandbox container    │   (UID 65534, cap-drop ALL, read-only rootfs,
                  │  user code runs here  │    HTTP_PROXY/HTTPS_PROXY env vars set)
                  └───────────────────────┘
```

The sandbox container's `network_mode` is the internal bridge — Docker does not provision an external gateway on internal networks, so the sandbox kernel has no route to any host except containers on the same internal bridge (the proxy). This is the doctrinal "no direct external route" enforced via Docker network topology, NOT via `--network none`.

### 10.2 Proxy implementation

**Proxy container image:** `cognic/sandbox-egress-proxy:vX.Y@sha256:...` — joins the canonical image catalog (§9) alongside the runtime images; cosign-signed via the Sprint-4 supply-chain pipeline; SBOM/vuln-scanned.

**Proxy software:** lightweight HTTP/HTTPS forward proxy (tinyproxy / squid / a custom Python proxy). Reads the per-call allow-list from env at start (`ALLOW_LIST` JSON-encoded). Listens on port 3128 on both networks. Sandbox HTTP client routes via `HTTP_PROXY=http://egress-proxy:3128` + `HTTPS_PROXY=http://egress-proxy:3128` env vars (set by the backend when creating the sandbox container).

**Per-call allow-list rendering:** lives in `sandbox/proxy.py` (CC-gated per §17 — the substantive egress enforcement decision point):

```python
def render_proxy_config(allow_list: tuple[str, ...]) -> ProxyConfig:
    # PURE — validates each entry as RFC 1123 hostname
    # rejects non-HTTP/HTTPS schemes via the Stage-1 policy shape check
    # renders tinyproxy-format ACL or equivalent
```

### 10.3 Audit emission

Every outbound request through the proxy emits a `ProxyAccessRecord` carrying `host`, `method`, `timestamp`, `policy_id`, `allow_or_refuse`, `refusal_reason` (if refused). On `exec_completed`, the proxy flushes its access log to a shared mount; the backend reads it and renders into the chain row's `payload.proxy_log: list[ProxyAccessRecord]`. Examiners can prove "this session attempted X outbound calls; Y were allowed, Z were refused" from the chain row alone.

### 10.4 Non-HTTP refusal — proxy-observed vs network-blocked

Two distinct enforcement layers, each catching a different attack shape (round-2 P1 reviewer correction — earlier wording conflated them):

**Proxy-observed (surfaces as `sandbox.policy.violated` with `egress_protocol_not_http`):** the proxy refuses HTTP CONNECT to non-443 ports + non-HTTP methods (e.g. `CONNECT example.com:6379 HTTP/1.1` for Redis, `CONNECT example.com:25 HTTP/1.1` for SMTP). These attempts go through the proxy because the sandbox HTTP client constructs them as HTTP CONNECT — the proxy sees them at the application layer, refuses, and emits a `ProxyAccessRecord` with `refusal_reason="non_http_connect_target"`. AgentOS reads the record and emits `sandbox.policy.violated` with `egress_protocol_not_http`. This IS proxy-auditable.

**Network-blocked (NOT a policy violation event):** sandboxed code attempting raw TCP / UDP / DNS-over-TCP / arbitrary protocols WITHOUT going through the proxy (e.g. opening a raw socket to an external IP) will fail at the network layer because the sandbox container is on an `internal=True` Docker bridge with no external gateway. These attempts get TCP RST or `ENETUNREACH` from the kernel; the proxy never sees them; **there is no per-attempt audit record in Wave 1**. The block is intrinsic to the network topology (§10.1), not a runtime check, so there's nothing to log per-attempt. Wave-2 may add network-level telemetry (Docker network drivers, sidecar tcpdump, eBPF) to surface these attempts as `sandbox.policy.violated` events; Wave-1 documents this as "blocked at network layer; not proxy-logged".

**Net effect of the two layers:** the sandbox cannot reach any external endpoint via any protocol; HTTP/HTTPS allow-list violations are individually audited via the proxy; non-HTTP attempts are blocked but counted only in aggregate (per-session — the absence of a successful proxy_log entry for a non-HTTP target is the negative-space evidence). Examiners auditing a session see exactly what HTTP/HTTPS calls were attempted + allowed/refused; for raw-protocol attempts they see no proxy log + a healthy sandbox that returned exit codes consistent with `ENETUNREACH`. Acceptable Wave-1 trade-off; Wave-2 closes the per-attempt audit gap.

### 10.5 Rejected alternatives (NOT acceptable Wave-1 variants — locked)

The dual-container internal-network pattern is the spec-locked Wave-1 implementation. Plan-of-record T-something does NOT have latitude to swap to one of the alternatives below without first surfacing a concrete blocker on the dual-container pattern + a separate doctrinal review pass.

- **Single-container with proxy-as-first-process + iptables-in-container** — REJECTED for Wave 1. Requires `CAP_NET_ADMIN` inside the sandbox, which contradicts the §7 `cap_drop=["ALL"]` posture. The cap is non-negotiable for the bank-grade trust boundary.
- **Host-side proxy + Unix-domain socket mounted into sandbox via `--volume`** — REJECTED for Wave 1. Requires HTTP-over-UDS client support across all sandbox image variants (Python `requests`, `aiohttp`, `httpx` all need custom transport configuration); HTTPS-over-UDS is particularly painful. Workable in principle but pushes implementation complexity into every sandbox image rather than centralising it in a single proxy container. The operational cost outweighs the dual-container overhead.
- **`--network none` with in-netns proxy** — IMPOSSIBLE. A sandbox with `--network none` has no in-namespace reachable proxy either; the round-1 framing of this pattern was the original P1 reviewer finding.

The doctrinal contract — "no direct external route + proxy-mediated allow-list + audit evidence + non-HTTP refused at the application layer" — is satisfied by the dual-container pattern in §10.1. Wave-2 backends (gVisor, Firecracker, Kata, rootless Docker, K8sPod) may use different topologies that satisfy the same doctrinal contract (e.g. K8sPod uses NetworkPolicy + sidecar proxy in 8B); the Wave-1 Docker backend is locked to dual-container internal-network.

---

## 11. Warm-pool (`sandbox/warm_pool.py`)

**Public API** (per-backend; the pool is backend-agnostic via the SandboxBackend Protocol):

```python
class SandboxWarmPool:
    def __init__(
        self,
        *,
        backend: SandboxBackend,
        max_pool_size_per_key: int,  # config-driven; per-tenant override
        idle_ttl_s: float,            # config-driven; per-tenant override
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ): ...

    async def register(
        self,
        policy: SandboxPolicy,
        *,
        tenant_id: str,
        pack_context: PackAdmissionContext,
    ) -> None:
        """Register a (policy, pack_context) pair for ongoing warming.
        The replenisher iterates over registered pairs."""

    async def precreate(
        self,
        policy: SandboxPolicy,
        *,
        tenant_id: str,
        pack_context: PackAdmissionContext,
    ) -> None:
        """Background replenisher entry point. Idempotent. Calls
        backend.create(..., pack_context=pack_context, use_warm_pool=False)
        — the explicit pack_context kwarg is REQUIRED because every
        Protocol-conforming backend.create() needs PackAdmissionContext
        for admission (risk_tier + declares_dynamic_install + profile).
        Round-3 P1 reviewer fix: warm-pool members are admitted with
        the registered pack's PackAdmissionContext, NOT a synthetic
        system-owned context; this preserves admission-decision
        integrity at checkout time."""

    async def checkout(
        self,
        policy_key: str,
        *,
        tenant_id: str,
        pack_context: PackAdmissionContext,
    ) -> SandboxSession | None:
        """Returns a warm session if available AND matching policy
        AND matching pack_context. Match uses the 5 pool-key fields
        from PackAdmissionContext: `pack_id` + `pack_artifact_digest`
        (cosign-verified sha256; the trust-gate-pinned immutable
        identity per ADR-016 — different artifact digest is ALWAYS a
        pool miss, never a checkout) + `risk_tier` +
        `declares_dynamic_install` + `profile`. `pack_version` is
        intentionally NOT in the match (human-mutable; not load-bearing
        for admission integrity per §11 pool-key derivation).
        pack_context mismatch is a pool miss (caller falls through to
        cold-create); this prevents a session admitted for pack A
        (or pack A v1 with one artifact digest) from being handed to
        pack B (or pack A v2 with a different digest) with potentially
        different admission requirements."""

    async def release_or_destroy(self, session: SandboxSession) -> None:
        """Returns session to pool (if pool has room + session healthy) or destroys.

        Pool-key derivation: reads `session.policy` AND `session.pack_context`
        to compute the pool key (matches the per-tuple key derived at register/
        precreate/checkout time). The `pack_context` field on SandboxSession
        is load-bearing here — round-3 follow-on P1 reviewer fix: cold-created
        sessions returned via the sandbox_session() helper carry their
        admission context on the session itself so release_or_destroy() can
        derive the correct key WITHOUT a separate pack_context parameter.
        Pinned by `test_warm_pool.py::test_cold_created_session_releases_to_correct_pool_key`
        (sandbox_session() cold-creates after a deliberate pool miss; on
        exit, release_or_destroy(session) deposits to the pool key matching
        the session's pack_context; subsequent matching checkout returns the
        deposited session)."""

    async def drain(self) -> None:
        """Shutdown: destroy all warm sessions; emit warm_pool.drained."""
```

**Pool key derivation:** `hash(canonical_bytes(policy)) + hash(canonical_bytes(pack_context_admission_fields))` — sessions with identical effective policy AND identical pack-admission-relevant fields are interchangeable. The pack-admission-relevant fields are **5 fields from PackAdmissionContext**: `pack_id` + `pack_artifact_digest` + `risk_tier` + `declares_dynamic_install` + `profile`.

- `pack_artifact_digest` is the cosign-verified pack artifact sha256 per ADR-016 trust-gate pinning — the immutable identity. **Two versions of the same pack (different `pack_version`, different `pack_artifact_digest`) MUST NOT share warm-pool members** because their admission decisions may differ (different supply-chain attestations, different declared sandbox requirements, different code that the cosign-signed digest binds to).
- `pack_id` is included alongside the digest as a defence-in-depth check (two different packs could in theory share an artifact digest under a misconfiguration; the pair lookup catches that).
- `pack_version` is intentionally NOT in the pool key — it is human-mutable in some workflows and `pack_artifact_digest` is the trust-gate-pinned immutable identity (round-3-third-follow-on P1 reviewer fix; `pack_version` stays in audit logs + UI for human readability but is not load-bearing for admission integrity).
- `risk_tier` is included because the same artifact COULD in principle declare different tiers across reinstalls — different tier → different admission decision per §6.1 step 4.
- `declares_dynamic_install` + `profile` are included because they jointly drive §6.1 step 3a admission.

The `SandboxPolicy.warm_pool_key` field is the human-readable name attached to the auto-derived key for audit purposes.

**Background replenisher:** an asyncio task per-tenant that wakes every `replenish_interval_s` (default 30s); for each registered `(policy, pack_context)` pair with `current_pool_size < max_pool_size_per_key`, calls `backend.create(policy, actor=AgentOS_system_actor, tenant_id=tid, pack_context=registered_pack_context, use_warm_pool=False)` to precreate. **Two load-bearing kwargs:**
- **`pack_context=registered_pack_context`** (round-3 P1 reviewer fix): every Protocol-conforming `backend.create()` requires PackAdmissionContext for admission. The replenisher provides the SAME `pack_context` that was passed at `pool.register(policy, tenant_id, pack_context)` time. There is no "system-owned" synthetic pack context — warm-pool members are admitted with the registered pack's real PackAdmissionContext so that admission decisions made at warming time are still valid at checkout time.
- **`use_warm_pool=False`** (round-1 P1 reviewer correction): forces the backend's cold-create path even though the pool may already have a matching member. Without it, the replenisher would re-enter `backend.create()`'s pool-check fast-path and either consume an existing member (decrementing pool size while trying to increment it) OR loop indefinitely.

Pinned by `test_admission_pipeline.py::test_replenisher_bypasses_pool` (asserts that `SandboxWarmPool.precreate()` calls `backend.create(..., pack_context=<registered_context>, use_warm_pool=False)` via mock-spy + asserts pool size monotonically increases under replenishment) AND `test_warm_pool.py::test_checkout_with_pack_context_mismatch_is_pool_miss` (asserts that a checkout with a different `pack_context` than the warmed-with context returns `None` even when a matching-policy member exists).

Emits `sandbox.warm_pool.precreated` per successful precreate (covers both initial fill at startup AND ongoing replenishment per the user-locked taxonomy at §4.3 — replenishment is the *cause*, the *event* is still `precreated`).

**Pool-hit latency target:** <50ms from `checkout()` return to caller (vs cold create's 800-2000ms). The ≤500ms P95 sandbox create exit criterion is achievable only when pool hit rate >70% for the workload — to be verified in Sprint 8A T-something with a pool-hit-rate benchmark.

**Drain semantics:** on AgentOS shutdown, `drain()` destroys all warm sessions in parallel. A pool that has completed drain refuses subsequent checkouts with `sandbox_warm_pool_drained`.

---

## 12. Audit event taxonomy (the 8-event list)

Reproduced here for the spec's wire-protocol-public surface (see §4.3 for the schema):

```
sandbox.lifecycle.created      payload.warm_pool_hit: bool
sandbox.lifecycle.exec_completed   payload.exit_code: int
sandbox.lifecycle.destroyed    payload.duration_s: float
sandbox.lifecycle.refused      payload.reason: SandboxRefusalReason
sandbox.policy.violated        payload.reason: SandboxPolicyViolationReason
sandbox.warm_pool.precreated   payload.pool_key, pool_size_after
sandbox.warm_pool.checked_out  payload.pool_key, pool_size_after
sandbox.warm_pool.drained      payload.pool_key, drained_count
```

Every event:
- Hash-chained into `decision_history` via the Sprint-2 atomic-precondition primitive
- Tagged with ISO 42001 control `A.6.2.5` per ADR-006 / ADR-004 §3.4
- Carries `tenant_id`, `actor_subject`, `trace_id`, `session_id` (where applicable)
- Mirrored onto the UI event stream via the existing `decision_audit.event_appended` family (NO new typed UI-event family in Wave 1; matches the ADR-022 scheduler pattern)

**Drift detector** (test-only, no runtime cross-module imports per `feedback_drift_detector_test_only_no_runtime_import`): `tests/unit/sandbox/test_audit_event_taxonomy.py::TestSandboxLifecycleEventVocabHas8Values` pins the count + the exact strings.

---

## 13. `sandbox.rego` policy bundle

New policy bundle at `policies/_default/sandbox.rego`. Joins the AGENTS.md "Stop rules" list alongside `sampling.rego` / `supply_chain.rego` / `elicitation.rego` / `scheduler.rego` (Sprint 10.5).

**Decision point:** `data.cognic.sandbox.admit.allow`

**Default:** `allow := false` — explicit allow required.

**Wave-1 default rules:**
- Allow if pack `risk_tier` ∈ `{"read_only", "internal_write"}` AND policy is within tenant max AND egress is HTTP-only
- **Refuse unconditionally** if pack `risk_tier` ∈ `{"customer_data_read", "customer_data_write", "payment_action", "regulator_communication", "cross_tenant", "high_risk_custom"}` — these are the 6 tiers that require `core/approval` engine gating per ADR-014. Until Sprint 13.5 ships the approval engine, all sandbox executions at these tiers fail-closed with `sandbox_high_risk_tier_refused_pre_13_5`. This mirrors the Sprint-5 MCP transitional refusal pattern + the Sprint-11.5 memory transitional refusal pattern exactly: the refusal is itself an audit event so banks can prove the cutover moment when Sprint 13.5 module-load lifts the refusal. **No escalation-token bypass path exists pre-13.5** (P2 reviewer correction from spec round 1 — the original wording referenced a "human-approved escalation token" that has no concrete source pre-13.5, which would have left an undefined bypass; explicit fail-closed posture instead).
- Refuse if `policy.vault_path` set AND `CredentialAdapter` is the default stub (this also fires from Stage-2 admission per §6.1 step 3; Rego's check is defence-in-depth)
- Refuse if `policy.runtime_image` not in catalog AND not in tenant allow-list (defence-in-depth with §6.1 step 6)

Bank overlays may **tighten** (add more refusal conditions, lower per-tenant caps, refuse additional class/tier combinations); **loosening the kernel defaults requires an explicit kernel + ADR amendment** (same wire-protocol-public stop-rule precedent as `elicitation.rego` and `scheduler.rego`).

**Cutover audit at Sprint 13.5 module-load:** when `core/approval/engine.py` lands and is wired into the sandbox admission pipeline, the refusal lifts for tiers `{customer_data_read, customer_data_write, payment_action, regulator_communication, cross_tenant, high_risk_custom}` — instead of refusing fail-closed, those tiers route through approval per ADR-014. The cutover itself is an audit event (`sandbox_approval.engine_enabled`) emitted at module-load so banks can prove the moment high-risk sandbox execution became gated.

---

## 14. Cross-ADR amendments triggered by this spec

Lands as a separate `chore(adr)` commit alongside the Sprint 8A spec, NOT inside this spec doc itself.

### ADR-004 amendments

- **§Backend choice (line 27)** — clarify "Wave 1: DinD" reads as the Docker-sibling pattern (host docker.sock; NOT nested privileged daemon); add explicit trust-boundary language per §2.3 of this spec
- **§Backend choice (line 27)** — add Kubernetes/OpenShift pod-backend as a co-Wave-1 backend (not just gVisor/Firecracker deferred to Wave 2); both backends conform to the same `SandboxBackend` Protocol
- **§Decision (line 22)** — add immutable-runtime-image doctrine per §2.4 of this spec; add canonical-image-catalog + per-pack-image escape hatch
- **§Implementation phases** — extend the phase table to reflect the 8A + 8B split

### ADR-016 amendments

- Add the canonical sandbox image catalog to the cosign-signed artifact set; add monthly base-image refresh cadence policy

### ADR-006 amendments

- Add the 8 sandbox lifecycle events + 2 closed-enum vocabularies to the ISO 42001 A.6.2.5 control mapping list

---

## 15. Test taxonomy

### 15.1 Unit tests (`tests/unit/sandbox/`)

| File | Coverage |
|---|---|
| `test_policy_shape.py` + `test_admission_pipeline.py` | All 15 refusal arms across Stage-1 (shape) + Stage-2 (admission); tenant-max-exceed cases; Rego allow + deny; happy-path; dynamic-install refusal under production profile only; high-risk-tier refusal across all 6 canonical tiers |
| `test_credential_adapter_stub.py` | `KernelDefaultCredentialAdapter` raises NotImplementedError pointing at Sprint 10; `sandbox_credential_adapter_not_configured` fires at create() when policy requires creds + stub wired |
| `test_image_catalog.py` | Canonical-catalog membership; tenant-allow-list-membership; cosign verify (mocked subprocess); SBOM verify; digest-format validation |
| `test_egress_proxy_config.py` | RFC 1123 hostname validation; HTTPS-default rendering; non-HTTP-scheme refusal; rendering correctness across allow-list shapes |
| `test_warm_pool.py` | Precreate + checkout + release + drain + replenisher; checkout-from-drained-pool refusal; pool-key derivation determinism; audit emission per event |
| `test_audit_event_taxonomy.py` | 8-event vocabulary pinned; both closed-enum vocabularies pinned; ISO control tag A.6.2.5 on every event |

### 15.2 DockerSibling-specific (`tests/unit/sandbox/backends/`)

| File | Coverage |
|---|---|
| `test_docker_sibling_lifecycle.py` | create + exec + destroy round-trip on REAL Docker (env-gated `COGNIC_RUN_DOCKER_SANDBOX=1`) |
| `test_docker_sibling_egress.py` | Allow-listed host succeeds; non-allow-listed refused; proxy_log entries in chain row |
| `test_docker_sibling_resource_caps.py` | (a) Docker `--cpus` throttle is APPLIED + OBSERVED but does NOT emit `sandbox.policy.violated` (a CPU-bound workload that stays within cap is expected to throttle; round-3 P2 reviewer correction prevents the T-plan from recreating the rejected CPU-throttling-percent heuristic); (b) `cpu_time_budget_exceeded` fires only when `SandboxPolicy.cpu_time_budget_s` is set AND cgroup `cpuacct.usage_us` exceeds the budget; (c) `memory_cap_exceeded` kills via OOM-killer; (d) `walltime_cap_exceeded` fires via AgentOS-side timer; (b)/(c)/(d) emit `sandbox.policy.violated` with the matching closed-enum reason |
| `test_docker_sibling_image_pin.py` | Wrong digest refused; cosign fail refused; SBOM fail refused |

### 15.3 Shared backend conformance suite (`tests/conformance/sandbox/`)

Parameterized over `SandboxBackend` implementations. In 8A only the Docker backend is parameterized; 8B adds the K8s backend to the same fixture.

| Conformance area | Test |
|---|---|
| Lifecycle | create → exec → destroy succeeds on all backends |
| Refusal taxonomy | Every `SandboxRefusalReason` value reachable on every backend |
| Policy violations | Every `SandboxPolicyViolationReason` value reachable on every backend |
| Warm-pool semantics | Precreate / checkout / drain identical across backends |
| Audit completeness | 8-event taxonomy fires on every backend with identical payload shapes |
| Image-pinning | Cosign + SBOM enforced on every backend |
| Egress isolation | Non-allow-listed refused; non-HTTP refused |
| Health | `backend.health()` returns valid SandboxBackendHealth |

---

## 16. Exit criteria

- Sandbox session creates in ≤500ms P95 (measured under workload with warm-pool active; cold-only would be 800-2000ms)
- Every `SandboxRefusalReason` value is reachable in tests (deliberate violation → caught + sandbox killed)
- Egress allow-list provably blocks non-allow-listed hosts (proxy audit log proves the refusal)
- All 7 critical-controls modules at ≥95% line / ≥90% branch coverage (see §17)
- Conformance suite green for DockerSibling backend; framework ready for 8B to parameterize KubernetesPod
- `policies/_default/sandbox.rego` admission + every refusal arm pinned by unit tests
- ADR-004 amendment + ADR-016 amendment + ADR-006 amendment merged alongside Sprint 8A

---

## 17. Critical-controls scope

Per AGENTS.md "Critical-controls rule" + "Stop rules" — the entire `sandbox/` tree is a stop-rule isolation boundary; every edit requires `core-controls-engineer` + `/critical-module-mode`.

**Durable coverage gate (Python modules; ≥95% line / ≥90% branch; halt-before-commit per edit):**

- `sandbox/protocol.py` — `SandboxBackend` + `SandboxSession` Protocols; admission contract
- `sandbox/policy.py` — `SandboxPolicy` + PURE `validate_policy_shape()`; Stage-1 admission glue
- `sandbox/admission.py` — ASYNC `admit_policy()`; Stage-2 admission pipeline (catalog + cosign + SBOM + Rego + credential-adapter + high-risk-tier); the substantive trust-gate-equivalent decision point shared across all backends
- `sandbox/catalog.py` — canonical image catalog + cosign verification + SBOM check + per-tenant allow-list **(promoted in spec round 1 per P1 reviewer finding** — a bug here lets untrusted images run; not "thin wiring")
- `sandbox/proxy.py` — egress proxy config rendering + allow-list enforcement + per-request audit-log shaping **(promoted in spec round 1 per P1 reviewer finding** — the single egress enforcement point; a bug here lets forbidden outbound traffic through; not "thin wiring")
- `sandbox/warm_pool.py` — bounded pool + drain semantics + audit emission + `use_warm_pool=False` replenishment contract; the latency-target enforcement surface
- `sandbox/backends/docker_sibling.py` — `DockerSiblingSandboxBackend`; the actual Wave-1 backend-specific enforcement surface (dual-container topology + cgroup integration)

**Stop-rule policy bundle (tracked separately from the Python coverage gate):**

- `policies/_default/sandbox.rego` — wire-protocol-public admission bundle at `data.cognic.sandbox.admit.allow`; bank overlays may tighten; loosening requires kernel + ADR amendment

Seven Python modules join the durable coverage gate. **Floor arithmetic:** Sprint 8A lands BEFORE Sprint 10.5 in BUILD_PLAN order (Phase 3 sequence: 8 → 8.5 → 9 → 9.5 → 10 → 10.5 → 11). Post-7B.4 floor is **63**; Sprint 8A adds 7 modules → **70**. When Sprint 10.5 subsequently lands its 4 scheduler modules → 74. + one new AGENTS.md stop-rule entry for `policies/_default/sandbox.rego`.

The `sandbox/credentials.py` stub stays OFF the durable gate (stub-only; raises NotImplementedError; replaced by Sprint 10's real `VaultCredentialAdapter` which DOES go on the gate). `sandbox/audit.py` stays OFF the durable gate (thin chain-row-shape converter; the substantive audit-chain invariants are enforced upstream by the on-gate `core/audit.py` + `core/decision_history.py` + `core/canonical.py`; bugs in sandbox/audit.py's event-payload-rendering surface through the 8-event taxonomy unit test + the integration tests of `backends/docker_sibling.py`).

---

## 18. What this spec is NOT

- **Not a sandbox for AgentOS itself** — the sandbox primitive isolates code that RUNS UNDER AgentOS (tools, agents, sub-agents). AgentOS process itself runs in the bank's container infrastructure (Helm chart in Sprint 14).
- **Not a Vault credential leasing implementation** — `sandbox/credentials.py` ships ONLY the Protocol + fail-loud stub; Sprint 10 ships the real adapter.
- **Not Kubernetes/OpenShift backend** — that's Sprint 8B.
- **Not checkpoint/suspend/wake** — that's Sprint 8.5.
- **Not scheduler-integrated** — Sprint 10.5 wraps sandbox creation in `SchedulerEngine.submit()`; 8A's API is designed for forward-compatibility.
- **Not per-tenant backend routing** — Sprint 8A uses process-wide env var; per-tenant routing deferred.
- **Not warm-pool autoscaling / predictive warming / cross-node balancing** — Wave-2 / deferred.
- **Not raw-TCP / DNS / arbitrary-protocol egress** — Wave-1 is HTTP/HTTPS-only; non-HTTP refused.
- **Not dynamic install of OS or Python packages at create-time** — refused in production with `sandbox_runtime_deps_unsupported_in_production`; dev-profile only with clear separation.
- **Not pure DinD (nested privileged daemon)** — `DockerSiblingSandboxBackend` is sibling-on-host-socket.

---

## 19. References

- **ADR-004 Sandbox Primitive** (APPROVED; amendments triggered by this spec) — `docs/adrs/ADR-004-sandbox-primitive.md`
- **ADR-006 ISO 42001 Control Mapping** (amendment: add 8 sandbox events to A.6.2.5) — `docs/adrs/ADR-006-iso42001-control-mapping.md`
- **ADR-016 Supply-Chain Controls** (amendment: add canonical image catalog) — `docs/adrs/ADR-016-supply-chain-controls.md`
- **ADR-022 Runtime Scheduler** (forward-compatibility — Sprint 10.5 wraps sandbox.submit) — `docs/adrs/ADR-022-runtime-scheduler.md`
- **AGENTS.md** — "Stop rules" list + "Critical-controls rule" + "Production-grade implementation rule"
- **BUILD_PLAN.md §694-715** — Sprint 8 deliverables + exit criteria (to be split into 8A + 8B in the same chore commit as this spec)
- **Project memory:**
  - [[project_openshift_deployment_target]] — Wave-1 deploys on OpenShift
  - [[feedback_sandbox_network_isolation_precision]] — proxy must live INSIDE sandbox netns
  - [[feedback_precise_security_terminology]] — DockerSibling, not DinD
  - [[feedback_immutable_runtime_images_no_dynamic_install]] — production runtime images are immutable + digest-pinned
- **Brainstorming session log (2026-05-16):** 6 AskUserQuestion rounds + 2 user-locked refinements documented in [[project_state_2026_05_16]]

---

## 20. Spec self-review (per superpowers brainstorming skill)

**Round 3** — after addressing 7 reviewer findings (5 P1 + 2 P2) from round 2 on top of round 1's 6 fixes.

**Round-2 reviewer findings addressed:**
- **R2 P1 #1 — §2.1 doctrinal lock still described the rejected `--network none` + in-netns proxy** → §2.1 implementation-pattern prose rewritten to point at §10.1's dual-container internal-network topology; explicit "earlier round-1 framing is rejected as physically impossible".
- **R2 P1 #2 — admission has no source for pack risk_tier** → added `PackAdmissionContext` frozen dataclass (in `sandbox/admission.py`, exported via `sandbox/__init__.py`); `pack_id` / `pack_version` / `risk_tier` / `declares_dynamic_install` / `profile` fields; admit_policy signature gains `pack_context: PackAdmissionContext` kwarg; SandboxBackend.create() Protocol gains it too; backend call site at §6 wires it.
- **R2 P1 #3 — high-risk tier set inconsistent (5 vs 6)** → §4.1 trigger + §6.1 step 4 + §13 sandbox.rego now all reference the canonical 6-value set `{customer_data_read, customer_data_write, payment_action, regulator_communication, cross_tenant, high_risk_custom}`; each site explicitly cross-refs the others ("6-value canonical set; same as §X / §Y").
- **R2 P1 #4 — digest regex rejects spec's own image refs** → §6.1 Stage 1 step 1 dropped the inline regex; defers to docker-py / oci-spec OCI image-reference parser; asserts (a) ref parses, (b) `@sha256:<64-hex>` digest suffix present, (c) digest matches sha256 hex.
- **R2 P1 #5 — raw TCP refusal not proxy-auditable** → §10.4 split into proxy-observed (HTTP CONNECT to non-443 → `egress_protocol_not_http` event) vs network-blocked (raw TCP / UDP / DNS → blocked by topology, NOT logged per-attempt in Wave-1; Wave-2 may add network-level telemetry). Documented as the acceptable Wave-1 trade-off + closure path.
- **R2 P2 #1 — context helper defeats warm-pool reuse** → §5 helper now takes `warm_pool: SandboxWarmPool | None = None`; on exit routes through `warm_pool.release_or_destroy(session)` when `use_warm_pool=True` AND `warm_pool is not None`; otherwise destroys unconditionally; pinned by `test_helper_releases_to_pool_when_pool_wired` + `test_helper_destroys_when_pool_not_wired`.
- **R2 P2 #2 — stale counts** → §15 test list "14 refusal arms" → "15 refusal arms across Stage-1 + Stage-2"; §16 exit criteria "4 critical-controls modules" → "7 critical-controls modules"; §10.5 rewritten as "rejected alternatives — locked" per user direction (dual-container is the 8A implementation, no swap latitude at plan time).

**Round 2** — after addressing 6 reviewer findings (3 P1 + 2 P2 + 1 cleanup) from round 1.

- **Placeholder scan:** no "TBD" / "TODO" / "filler" / vague requirements. Every contract + closed-enum value + module is named concretely.
- **Internal consistency:**
  - `SandboxRefusalReason` is **15 values** — §4.1 table + §16 exit criteria + `test_audit_event_taxonomy.py` description in §15 + the partition-invariant test in §15.1.
  - `SandboxPolicyViolationReason` is **5 values** — §4.2 table + §16 exit criteria. `cpu_cap_exceeded` was renamed to `cpu_time_budget_exceeded` to remove the P2 reviewer finding (Docker `--cpus` throttling under cap is NOT a violation by itself; opt-in `SandboxPolicy.cpu_time_budget_s` is the kill condition).
  - `SandboxLifecycleEvent` is **8 events** — §4.3 + §12 + the audit-emission descriptions in §7 + §11. No `warm_pool.replenished` per the user-locked taxonomy.
  - Critical-controls gate count is **7 Python modules + 1 stop-rule** — §17. Floor arithmetic 63 → 70 (Sprint 8A lands BEFORE Sprint 10.5).
- **Scope check:** focused on Sprint 8A only; 8B / 8.5 / 10 / 10.5 explicitly out of scope; cross-ADR amendments listed for separate commits.
- **Implementation-pattern consistency:** §7 create() flow + §10 proxy topology + §11 warm-pool replenishment are all aligned with the dual-container internal-network egress pattern + `use_warm_pool=False` replenishment kwarg + Stage-1 / Stage-2 split admission pipeline. The round-1 contradictions (`--network none` + in-netns proxy; "pure validation" with I/O in the pipeline; precreate recursing through create) are resolved with explicit implementable topologies + concrete module/method splits.

**Round-1 reviewer findings addressed:**
- **P1 #1 — proxy topology not implementable with `--network none`** → §7 + §10 rewrite for dual-container internal-network pattern; sandbox attaches to `internal=True` bridge; proxy dual-homed; doctrinal "no direct external route" preserved without `--network none`.
- **P1 #2 — validation pipeline mixes pure + I/O** → §6 split into `sandbox/policy.py:validate_policy_shape()` (pure) + `sandbox/admission.py:admit_policy()` (async I/O); module layout in §3 adds `sandbox/admission.py`; backend call site in §7 calls both stages explicitly.
- **P1 #3 — proxy + catalog must be on the gate** → §17 promotes both modules to the durable coverage gate (plus admission.py which is the substantive Stage-2 admission decision point); floor arithmetic corrected.
- **P1 #4 — warm-pool precreate recurses through create** → §5 Protocol adds `use_warm_pool: bool = True` kwarg; §11 replenisher calls `backend.create(..., use_warm_pool=False)`; pinned by `test_replenisher_bypasses_pool`.
- **P2 #1 — CPU cap as policy violation** → §4.2 renames `cpu_cap_exceeded` → `cpu_time_budget_exceeded`; §6 SandboxPolicy adds optional `cpu_time_budget_s: float | None = None`; §7 exec flow drops the throttling-percent heuristic; throttling under `--cpus` is NOT a violation.
- **P2 #2 — approval token source undefined pre-13.5** → §4.1 adds `sandbox_high_risk_tier_refused_pre_13_5`; §13 sandbox.rego defaults refuse 6 high-risk tiers unconditionally pre-13.5 (no escalation-token bypass); transitional refusal lifts at Sprint 13.5 module-load with `sandbox_approval.engine_enabled` cutover audit.
- **Cleanup — backend.session() not in the Protocol** → §5 clarifies the context manager is a helper function in `sandbox/__init__.py`, NOT a Protocol method; minimal Protocol stays at 4 ops.

**Round-3 follow-on patches** (6 reviewer findings that surfaced AFTER the initial round-3 self-review — round 2's `PackAdmissionContext` addition + topology rewrites needed to ripple to additional sites I missed):

- **R3 P1 #1 — Docker create flow at §7 still omitted `pack_context` in admit_policy call** → §7 item 2 updated to pass `pack_context=pack_context`; cross-references §5 Protocol kwarg + §6.1-step-3a + §6.1-step-4 to explain why admission needs it.
- **R3 P1 #2 — `SandboxWarmPool.precreate` no source for `pack_context`** → §11 split warm-pool API into `register(policy, tenant_id, pack_context)` + `precreate(policy, tenant_id, pack_context)` + `checkout(policy_key, tenant_id, pack_context)`; the replenisher iterates over registered `(policy, pack_context)` pairs; pool-key includes `pack_id + risk_tier + declares_dynamic_install + profile` so a session admitted for pack A cannot be handed to pack B; pinned by 2 new tests.
- **R3 P1 #3 — canonical catalog count conflict** → §9 updated from 3 → 4 images (adds `cognic/sandbox-egress-proxy:vX.Y@sha256:...` to the catalog); "egress proxy binary" stripped from the 3 runtime images' "Extras" column (was a round-1 artifact before the dual-container sidecar topology was locked).
- **R3 P2 #1 — `egress_protocol_not_http` trigger description still mentioned raw TCP / DNS-over-TCP** → §4.2 trigger narrowed to "proxy-observed only — HTTP CONNECT to non-443 port OR non-HTTP method"; raw TCP / UDP / DNS attempts get the network-blocked path documented in §10.4 and explicitly do NOT emit policy-violation events in Wave-1.
- **R3 P2 #2 — resource-cap test row still claimed CPU cap fires** → §15 `test_docker_sibling_resource_caps.py` row rewritten with explicit 4-case structure: (a) `--cpus` throttle applied but does NOT fire violation; (b) `cpu_time_budget_exceeded` fires only when budget set; (c) memory cap OOM; (d) walltime cap.
- **R3 P3 — self-review footer said "round 2"** → fixed.

**Round-3-second-follow-on patches** (2 reviewer findings that surfaced after the round-3 follow-on — ripples from the round-3-follow-on warm-pool key change):

- **R3-FU P1 — `release_or_destroy(session)` no pack_context for cold-created sessions** → Added `pack_context: PackAdmissionContext` field to `SandboxSession` Protocol; release_or_destroy derives pool key from `session.policy` + `session.pack_context` (no separate parameter); also load-bearing for Sprint 8.5 wake-time re-admission against the same context; pinned by `test_cold_created_session_releases_to_correct_pool_key`.
- **R3-FU P2 — §3 module layout still said catalog has 3 image refs** → fixed to "4 image refs (3 runtime + 1 egress-proxy sidecar)" matching §9.

**Round-3-third-follow-on patches** (2 reviewer findings that surfaced after the second follow-on — ripples from the warm-pool key change to PackAdmissionContext):

- **R3-FU2 P1 — pool key omitted `pack_version` from PackAdmissionContext** → Rather than add `pack_version` (human-mutable in some workflows), added a 6th field `pack_artifact_digest: str` (cosign-verified pack artifact sha256 per ADR-016 trust-gate pinning — the immutable identity). Pool key now uses 5 fields from PackAdmissionContext: `pack_id` + `pack_artifact_digest` + `risk_tier` + `declares_dynamic_install` + `profile`. `pack_version` stays in audit logs + UI for human readability but is NOT load-bearing for admission integrity.
- **R3-FU2 P2 — test-file count stale (said 8, actually 11)** → §3 Total line corrected to "11 unit-test files (7 top-level + 4 backend-specific) + 1 conformance suite".

Ready for user review after round-3 + 3 follow-on passes. All consistency-ripple sites propagated. The spec is internally consistent across §3 module layout + §4 closed-enums + §5 Protocol + §6.1 admission + §7 Docker flow + §9 catalog + §10 proxy + §11 warm-pool (including pool-key derivation from 5 PackAdmissionContext fields) + §13 sandbox.rego + §15 tests + §17 critical-controls.
