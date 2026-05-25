# ADR-004 — Sandbox Primitive (Ephemeral Isolated Execution)

## Status
**APPROVED for implementation** on 2026-04-26.

**Amended on 2026-05-16** (this revision) — substantive amendment shipped alongside the Sprint 8A T1 design spec. Clarifies that "Wave 1 DinD" in the original wording means the **Docker-sibling pattern via host docker.sock**, NOT pure nested Docker-in-Docker with a `--privileged` container; adds Kubernetes/OpenShift Pod backend as a co-Wave-1 backend (not deferred to Wave 2) per the OpenShift production-deployment target surfaced during Sprint 8A brainstorming; adds the immutable-runtime-image doctrine + canonical image catalog + signed per-pack-image escape hatch; extends implementation phases for the 8A/8B sprint split. Trust-boundary language made explicit for the Docker-sibling pattern. Stronger isolation backends (gVisor, Firecracker, Kata, rootless Docker) remain Wave-2 deferred per the original ADR.

## Context

Per Anthropic's Managed Agents pattern (April 2026), the **sandbox** is the "hands" of an agent system — an ephemeral, resource-capped, network-egress-controlled execution environment. Cognic AgentOS today has no sandbox primitive: agents and tools run in the same Python process as the OS. For banking deployment this is unacceptable:

- Agent generates SQL against a CBS → no way to scope credentials to one query
- Agent processes a customer PDF → malicious PDF can attack the host process
- Agent runs ad-hoc Python → no resource cap, no egress filter
- Tool pack compromise → blast radius is the entire AgentOS process

## Decision

Add a `sandbox/` primitive module providing `SandboxSession`. Lifecycle: `create() → exec() → destroy()`. Each session is:

- A separately-named container (e.g. Docker, runc, gVisor, Firecracker — backend abstracted)
- Resource-capped (CPU quota, memory, wall-time; optional `cpu_time_budget_s` per Sprint 8A spec — `--cpus` throttling under cap is NOT a runtime violation by itself, only an exceeded CPU-seconds budget is)
- Egress allow-listed (per-call list of permitted hostnames; **HTTP/HTTPS-only in Wave 1** via an AgentOS-controlled proxy endpoint; non-HTTP protocols refused at the application layer; raw TCP/UDP/DNS attempts blocked at the network layer)
- **Image-pinned from an immutable, cosign-signed runtime image** (per the 2026-05-16 amendment): AgentOS publishes a small **canonical image catalog** (Wave-1: `cognic/sandbox-runtime-python`, `cognic/sandbox-runtime-shell`, `cognic/sandbox-runtime-data`, `cognic/sandbox-egress-proxy` — 4 images). Pack-specific runtime images are allowed only when signed, SBOM-scanned, digest-pinned, and tenant allow-listed. **Production sandboxes do not install OS or Python packages at create time** (dynamic apt-get/pip is refused fail-closed); the binary set is provably what the cosign-signed digest binds to. Banks reject runtime-install patterns at first security audit because evidence-pack export per ADR-006 cannot capture a runtime-installed binary set.
- Credential-scoped (Vault leases minted at create, revoked at destroy — Sprint 10 shipped (2026-05-24) the real `VaultCredentialAdapter` + the `mint_lease` / `revoke_lease` Protocol extension; Sprint 8A originally shipped only the `CredentialAdapter` Protocol + fail-loud `KernelDefaultCredentialAdapter` stub that refuses fail-closed when a policy declares `vault_path:` and no real adapter is wired. Wave-1 `transport.lease()` uses `client.read(path)` per Sprint-10 Round-9 Gap Q — Vault's dominant dynamic-secret endpoints (database/aws/gcp) are GET-only; the original write-with-ttl recipe was broken for 3 of the 4 spec §3.4 target engines + surfaced + closed by Z2's live proof.)
- Audit-logged (every create / exec / destroy emits an event with policy + outcome; Sprint 8A's 8-event taxonomy lands under ISO 42001 A.6.2.5 per ADR-006)

### Backend choice
- **Wave 1 backend #1 — `DockerSiblingSandboxBackend`** (this is what "Wave 1 DinD" in the original wording resolves to per the 2026-05-16 amendment): AgentOS talks to the host Docker daemon via mounted `/var/run/docker.sock` and launches **sibling** sandbox containers (not nested children of a privileged inner daemon). Trust boundary: *"Wave-1 sandbox isolation is Docker-container isolation managed through the host Docker daemon. AgentOS is inside the trusted control plane. A compromised AgentOS process with Docker socket access is equivalent to host-level Docker control. This is acceptable for Wave-1 reference deployment, not the final bank-grade isolation story."* Egress topology: dual-container internal-network pattern (sandbox attaches to a per-session `internal=True` Docker bridge with NO external gateway; the egress proxy is a separate dual-homed sidecar container on both the internal bridge and a non-internal bridge with external gateway; sandbox HTTP client routes via `HTTP_PROXY` env vars). For local dev, CI, Docker Compose deployments, and small Docker-host deployments where the operator accepts the Docker-daemon trust posture.
- **Wave 1 backend #2 — `KubernetesPodSandboxBackend`** (added 2026-05-16 amendment per the OpenShift production-deployment target): for bank production on OpenShift / Kubernetes clusters where Docker-socket access is unavailable or unacceptable. OpenShift-compatible pod SecurityContext (no `--privileged`; matches the restricted-by-default SCC); NetworkPolicy permits only proxy egress; ServiceAccount with minimal RBAC; namespace/tenant routing config. Ships in **Sprint 8B** as the sibling sprint to Sprint 8A.
- **Wave 2** — gVisor / Firecracker / Kata / rootless Docker — stronger isolation when banks demand kernel-level boundary; deferred until banks demand it.
- Backend swappable via a `SandboxBackend` Protocol; AgentOS does not bake any specific backend into the contract. Backend selection is process-wide via `COGNIC_SANDBOX_BACKEND=docker_sibling | kubernetes_pod` env var in Wave 1; per-tenant routing deferred to a later sprint (Sprint 14 deployment kit is the candidate home).

### Per-call policy
Tools and agents request a sandbox by declaring a `SandboxPolicy`. The harness validates the policy against the per-tenant maximum (defined in `policy.yaml`) and refuses requests that exceed limits.

### Audit
Every sandbox lifecycle event is appended to `decision_history` with the same hash chain as agent decisions. Examiners can prove "this code ran inside this sandbox under this policy with these credentials for this duration."

### ISO 42001 mapping
Sandbox lifecycle hooks map to ISO 42001 Annex A controls A.6.2.x (operational controls), A.7.x (impact assessment), and A.8.x (data management). Per ADR-006 each event is tagged with applicable control IDs.

## Consequences

### Positive
- **Bank-grade isolation** for code execution, document processing, external system calls
- **Credential scoping** via Vault leases tied to sandbox lifetime
- **Audit completeness** — every external action is provably bounded
- **Compromise blast-radius** = one sandbox instance, not the OS process

### Negative
- **Operational complexity** — needs a container runtime alongside AgentOS
- **Latency** — sandbox creation adds 100-500ms to tool invocations; mitigated by warm-pool of pre-created sandboxes
- **Resource overhead** — per-call container is heavier than in-process function call; trade-off for safety
- **Backend lock-in risk** — DinD + Kubernetes pod-spawn costs; mitigated by abstract `SandboxBackend` so we can swap

### Neutral
- Some MCP tools may not need a sandbox (read-only metadata queries, etc). The harness flags `requires_sandbox: bool` per tool and only creates sessions when required.

## Implementation phases

Restructured 2026-05-16 amendment for the Sprint 8A/8B split:

1. **Sprint 8A** — `SandboxBackend` Protocol + `SandboxPolicy` + `DockerSiblingSandboxBackend` (NOT pure DinD) + dual-container internal-network egress topology with `cognic/sandbox-egress-proxy` sidecar + canonical 4-image catalog (3 runtime + 1 proxy sidecar) cosign-signed via Sprint-4 supply-chain pipeline + warm-pool (narrow scope: `register/precreate/checkout/release_or_destroy/drain`) + `CredentialAdapter` Protocol with `KernelDefaultCredentialAdapter` fail-loud stub (Vault leasing deferred to Sprint 10 — landed there 2026-05-24) + shared backend conformance suite + ISO 42001 A.6.2.5 audit-event taxonomy (8 events) + `policies/_default/sandbox.rego` admission bundle. ~3.5 wu.
2. **Sprint 8B** — `KubernetesPodSandboxBackend` + OpenShift-compatible pod SecurityContext + NetworkPolicy egress to proxy only + ServiceAccount + minimal RBAC + namespace/tenant routing config + live-cluster conformance tests env-gated. Same conformance suite as 8A; both backends conform to the same `SandboxBackend` Protocol. ~1.5-2 wu.
3. **Sprint 8.5** — **Resumable-session API** — `checkpoint(label) / suspend() / wake(session_id)` per the separate amendment below.
4. **Sprint 9** — ISO 42001 evidence-pack export integration (sandbox events flow through `compliance/iso42001/evidence_pack.py`).
5. **Sprint 10** — Real Vault credential leasing replaced the Sprint 8A fail-loud stub (`KernelDefaultCredentialAdapter` → `VaultCredentialAdapter`). **Landed 2026-05-24.** Closes the sandbox-credentials sub-arc of Phase 3 — but Phase 3 itself is NOT closed because the Sprint 10.5 scheduler primitive (ADR-022) remains. Z1 promoted 4 modules to the critical-controls coverage gate (`core/vault.py` + `core/_vault_transport.py` + `sandbox/credentials.py` + `sandbox/backends/_shared_credentials.py`); Z2 real-Vault two-layer integration proof passes against pre-running Vault + Postgres (env-gated on `COGNIC_RUN_VAULT_INTEGRATION`). Wave-1 `transport.lease()` uses `client.read(path)` per Round-9 Gap Q (Vault's dominant dynamic-secret endpoints are GET-only; the original write-with-ttl recipe was wrong for database/aws/gcp + surfaced + closed by Z2's live proof).
6. **Sprint 10.5** — Scheduler (ADR-022) wraps `sandbox.create()` in `SchedulerEngine.submit()`; sandbox creation becomes a scheduler-admitted operation. 8A's API is designed for forward-compatibility (no breaking change at 10.5 landing).
7. **Sprint 13.5** — `core/approval/engine.py` lands; the Sprint-8A transitional refusal `sandbox_high_risk_tier_refused_pre_13_5` lifts (6-value high-risk-tier set routes through approval per ADR-014 instead of refusing fail-closed). Cutover audit event `sandbox_approval.engine_enabled` emitted at module-load.
8. **Wave 2** — gVisor / Firecracker / Kata / rootless Docker backends; all conform to the same `SandboxBackend` Protocol.

## Resumable-session API (Sprint 8.5)

Basic create/exec/destroy is insufficient for Anthropic-Managed-Agents-style durable sessions. The sandbox primitive exposes:

```python
session = await sandbox.create(policy)
result = await session.exec(command)
checkpoint_id = await session.checkpoint(label="before_payment_action")
await session.suspend()           # container released; state persisted

# Different process / after harness restart:
# Note: session_id alone is NEVER authorization — wake() takes actor +
# tenant_id keyword-only per Q5 lock + the extra
# "session_id-never-authorization" design lock. Cross-tenant attempts
# refuse fail-closed via sandbox_wake_tenant_mismatch.
session = await sandbox.wake(session_id, actor=actor, tenant_id=tenant_id)
result = await session.exec(next_command)
await session.destroy()
```

**Checkpoint storage:** writable workspace tar snapshot (the canonical `/workspace` mount on every sandbox-runtime image) + env metadata + Vault lease references. Stored in `ObjectStoreAdapter` (per ADR-009) with per-tenant retention policy (default 24h; long-running workflow tenants extend via Rego policy per ADR-015 — deferred to a later sprint).

Wave-1 explicitly does **NOT** use CRIU or container-layer commits — `tar` of `/workspace` is the cross-backend wire-public contract (DockerSibling via aiodocker exec; KubernetesPod via kubernetes_asyncio multiplexed-websocket exec). Both backends ship the same workspace-tar mechanism per Sprint 8.5 spec §7. Mid-process state preservation (CRIU, docker commit) is deferred to Wave-2 if banks demand it; would require node-level privileges incompatible with OpenShift restricted SCC.

**Sprint 8.5 design locks** (Q1-Q5 from 2026-05-18 brainstorming + extra session_id-never-authorization lock):

1. **Q1 — workspace-tar mechanism.** Cross-backend wire contract: `tar` of `/workspace`. NOT CRIU; NOT `docker commit`. Both Wave-1 backends ship the same shape.
2. **Q2 — dedicated `sandbox.lifecycle.checkpoint_purged` audit event.** Reaper emits one chain row per purge; NOT folded into `sandbox.lifecycle.destroyed`.
3. **Q3 — wake-time policy revalidation.** `wake()` reruns `admit_policy()` against the LIVE tenant policy / catalog / Rego / settings. Refusal surfaces as `sandbox_wake_policy_revalidation_failed` (wake-time taxonomy is wake-specific; original 8A reason lives in `detail`).
4. **Q4 — fail-loud Vault-lease path NOW; NO `CredentialAdapter` extension in Sprint 8.5.** The existing Sprint-8A `sandbox_credential_adapter_not_configured` admission-time refusal prevents vault-bearing sessions from being created today, so no vault-bearing wake is reachable. Sprint 10 shipped (2026-05-24) the real `VaultCredentialAdapter` + `mint_lease`/`revoke_lease` Protocol extension; the Q4 LOCK's "vault-bearing sessions don't exist" premise was correctly retired by the Sprint-10 T10 Q5 LOCK (`SandboxSession.checkpoint()` + `.suspend()` raise `NotImplementedError` pointing at Sprint 10.x when `active_leases` is non-empty per spec §4.5 — defers leased-session checkpoint/suspend/wake to a follow-up sprint as production-grade fail-loud scaffolding rather than silently dropping leases at suspend).
5. **Q5 — `wake(session_id, *, actor, tenant_id)` Protocol signature.** Identity seam forward-compat for Sprint 10.5 `SchedulerEngine.submit()` wrap per ADR-022.
6. **Extra lock — session_id alone is NEVER authorization.** `wake()` cross-checks caller `tenant_id` kwarg against `metadata.tenant_id` and refuses fail-closed via `sandbox_wake_tenant_mismatch` on mismatch (defence-in-depth past the prefix-keyed lookup).

**Tombstone semantics for `destroy()`** (Sprint 8.5 design call): `destroy()` of a session with persisted checkpoints writes a `<tenant>/<session>/_tombstoned.json` sentinel via `CheckpointStore.tombstone_session()`; checkpoint bytes are retained until the reaper sweep after the per-tenant retention window. Wake() refuses tombstoned sessions fail-closed via the new `sandbox_wake_session_tombstoned` closed-enum reason. Malformed tombstone surfaces as the SAME closed-enum value via the `TombstoneCorruptError` fail-closed path (operator intent "destroyed = MUST NOT wake" survives degradation).

**Audit:** `sandbox.lifecycle.checkpointed` / `sandbox.lifecycle.suspended` / `sandbox.lifecycle.woken` / `sandbox.lifecycle.checkpoint_purged` events hash-chain into `decision_history` per ADR-006 (4 new event types). Chain verifier walks suspend → wake transitions via explicit payload keys (`suspend_event_id` + `restored_from_checkpoint_id`) to prove no state forgery — no `decision_history` schema migration needed.

**What this enables:** long-running multi-step workflows that survive harness restarts; operator pause/resume for compliance review of paused agent state; multi-day agent loops awaiting external input; time-travel debugging.

## Amendment — 2026-05-25 (Sprint 10.1 — post-merge review of PR #38 + plan-review rounds 1 + 2)

External code review of PR #38 (Sprint 10 Vault credential leasing, merged 2026-05-24) surfaced two gaps in the Wave-1 credential leasing layer:

  1. **[P1 security]** `core/vault.lease_credential` accepted any `lease_duration` Vault returned without comparing it to the caller's requested `ttl_s`. A Vault role whose `default_ttl` or `max_ttl` exceeded AgentOS' cap silently minted over-cap leases. The Rego rule-6 cap at `sandbox.rego` only gates the REQUESTED `ttl_s` at admission time (pre-mint), and the docstring at `_vault_transport.py:300-308` documented this gap as "Wave-1 informational" with Wave-2 deferred enforcement.

  2. **[P2 test-honesty]** The Z2 real-Vault proof at `tests/integration/sandbox/test_real_vault_credential_lifecycle.py` called `pytest.importorskip("hvac")` at module load BEFORE the `COGNIC_RUN_VAULT_INTEGRATION` env-gate evaluation, so an opted-in operator with a missing extra saw a silent skip instead of the fail-loud contract promised by spec §10.

A third reviewer-flagged gap (workload credential projection — minted leases land on `session.active_leases` but never reach the sandbox workload as env / file / socket / projected-secret) is **deferred to Sprint 10.5** with explicit shape-decision gate per ADR-022; the projection contract needs deliberate design before implementation lands and Sprint 10.5's scheduler primitive is the natural home for that work.

**Decision (Sprint 10.1 amendment to §25 — landed on `fix/sprint-10.1-credential-leasing-gaps`):** the Wave-1 TTL contract is upgraded from "informational" to **"post-mint enforced + best-effort revoke on refusal":**

- `lease_credential` MUST refuse with the new wire-protocol-public exception class `VaultLeaseGrantExceedsRequest` when `ttl_s_granted > request.ttl_s`.
- AND MUST attempt `transport.revoke(lease_id)` before raising so the dynamic Vault credential does not leak into Vault's role `default_ttl` / `max_ttl` window. Revoke failure does NOT mask the TTL refusal — the exception still raises, carrying `lease_id` + `revoke_outcome ∈ {"revoked", "revoke_failed"}` attributes for audit traceability + chaining the revoke exception via `__cause__`.
- The formatted exception message string MUST include the `lease_id={lease_id!r}` token (not only the attribute) because the sandbox backend raises `SandboxLifecycleRefused(reason, detail=str(exc))` — only the message text reaches the chain payload, so the dangling-lease correlator must live in the formatted string to survive the `revoke_outcome="revoke_failed"` case.

The new exception class is the 5th value of the `core/vault` closed taxonomy (previously 4-value: `VaultUnavailable` / `VaultPathNotFound` / `VaultAuthDenied` / `VaultProtocolError`). The sandbox boundary at `sandbox/backends/_shared_credentials.py` maps the new exception to the new wire-public `SandboxRefusalReason` closed-enum value `sandbox_credential_lease_ttl_grant_exceeds_request` (27th value; previously 26-value). Both backends' (`docker_sibling.py` + `kubernetes_pod.py`) post-mint cleanup except-tuples extend in the SAME commit per Finding B of plan-review round 1 so no intermediate state leaves the new exception escaping uncaught at the backend boundary.

The Rego rule-6 pre-mint cap remains unchanged — together the two layers provide defence-in-depth across the caller-too-high (caught by Rego) and Vault-role-too-loose (caught by the new post-mint kernel check) failure modes.

The Z2 module-load preamble flips to conditional fail-loud per the spec §10 "opt-in means prove it or fail" contract: when `COGNIC_RUN_VAULT_INTEGRATION=1` is set, missing `hvac` / `aiodocker` extras raise `ImportError` at module load (collection error); when the env var is unset, the silent-skip path is preserved for casual local-only `uv run pytest` runs. Pinned by `tests/unit/test_z2_import_fail_loud_contract.py` (subprocess shim that simulates missing extras + asserts ImportError in opted-in mode + asserts `pytest.skip.Exception` in not-opted-in mode).

This amendment does NOT change the kernel-default `max_credential_ttl_s` cap value — no threshold change; Human-only-decisions gate not triggered. The change is purely the addition of an enforcement layer ALONGSIDE the existing Rego layer + the best-effort revoke step that prevents a refused lease from leaking into Vault.

Operators with existing Vault role bootstraps need to rerun their `vault write database/roles/<role>` command with a `default_ttl` that does not exceed the requested `ttl_s` used by their callers (the Z2 bootstrap docstring's `default_ttl="1h"` → `"600"` is the canonical example).

**Implementation:** `fix/sprint-10.1-credential-leasing-gaps` branch (commits `bbeef69` plan → `6dd95d1` T1 core/vault.py enforcement → `ce703fe` T2 sandbox wire surface → `9524c73` T3 Z2 fail-loud + TTL-grant regressions → this docs commit T4); PR opened post-merge per `[[feedback_explicit_authorization_per_action]]`.

## References
- [Anthropic — Managed Agents: Decoupling brain from hands](https://www.anthropic.com/engineering/managed-agents)
- [Local-First Agent Runtime](https://www.huuphan.com/2026/04/local-first-agent-runtime-guide.html)
- [Self-hosted AI sandboxes — Northflank](https://northflank.com/blog/self-hosted-ai-sandboxes)
