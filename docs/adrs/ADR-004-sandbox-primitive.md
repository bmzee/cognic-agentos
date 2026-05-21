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
- Credential-scoped (Vault leases minted at create, revoked at destroy — Sprint 10 ships the real `VaultCredentialAdapter`; Sprint 8A ships only the `CredentialAdapter` Protocol + fail-loud `KernelDefaultCredentialAdapter` stub that refuses fail-closed when a policy declares `vault_path:` and no real adapter is wired)
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

1. **Sprint 8A** — `SandboxBackend` Protocol + `SandboxPolicy` + `DockerSiblingSandboxBackend` (NOT pure DinD) + dual-container internal-network egress topology with `cognic/sandbox-egress-proxy` sidecar + canonical 4-image catalog (3 runtime + 1 proxy sidecar) cosign-signed via Sprint-4 supply-chain pipeline + warm-pool (narrow scope: `register/precreate/checkout/release_or_destroy/drain`) + `CredentialAdapter` Protocol with `KernelDefaultCredentialAdapter` fail-loud stub (Vault leasing deferred to Sprint 10) + shared backend conformance suite + ISO 42001 A.6.2.5 audit-event taxonomy (8 events) + `policies/_default/sandbox.rego` admission bundle. ~3.5 wu.
2. **Sprint 8B** — `KubernetesPodSandboxBackend` + OpenShift-compatible pod SecurityContext + NetworkPolicy egress to proxy only + ServiceAccount + minimal RBAC + namespace/tenant routing config + live-cluster conformance tests env-gated. Same conformance suite as 8A; both backends conform to the same `SandboxBackend` Protocol. ~1.5-2 wu.
3. **Sprint 8.5** — **Resumable-session API** — `checkpoint(label) / suspend() / wake(session_id)` per the separate amendment below.
4. **Sprint 9** — ISO 42001 evidence-pack export integration (sandbox events flow through `compliance/iso42001/evidence_pack.py`).
5. **Sprint 10** — Real Vault credential leasing replaces the Sprint 8A fail-loud stub (`KernelDefaultCredentialAdapter` → `VaultCredentialAdapter`).
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
4. **Q4 — fail-loud Vault-lease path NOW; NO `CredentialAdapter` extension in Sprint 8.5.** The existing Sprint-8A `sandbox_credential_adapter_not_configured` admission-time refusal prevents vault-bearing sessions from being created today, so no vault-bearing wake is reachable. Sprint 10 ships the real `VaultCredentialAdapter` + `mint_lease`/`revoke_lease` Protocol extension.
5. **Q5 — `wake(session_id, *, actor, tenant_id)` Protocol signature.** Identity seam forward-compat for Sprint 10.5 `SchedulerEngine.submit()` wrap per ADR-022.
6. **Extra lock — session_id alone is NEVER authorization.** `wake()` cross-checks caller `tenant_id` kwarg against `metadata.tenant_id` and refuses fail-closed via `sandbox_wake_tenant_mismatch` on mismatch (defence-in-depth past the prefix-keyed lookup).

**Tombstone semantics for `destroy()`** (Sprint 8.5 design call): `destroy()` of a session with persisted checkpoints writes a `<tenant>/<session>/_tombstoned.json` sentinel via `CheckpointStore.tombstone_session()`; checkpoint bytes are retained until the reaper sweep after the per-tenant retention window. Wake() refuses tombstoned sessions fail-closed via the new `sandbox_wake_session_tombstoned` closed-enum reason. Malformed tombstone surfaces as the SAME closed-enum value via the `TombstoneCorruptError` fail-closed path (operator intent "destroyed = MUST NOT wake" survives degradation).

**Audit:** `sandbox.lifecycle.checkpointed` / `sandbox.lifecycle.suspended` / `sandbox.lifecycle.woken` / `sandbox.lifecycle.checkpoint_purged` events hash-chain into `decision_history` per ADR-006 (4 new event types). Chain verifier walks suspend → wake transitions via explicit payload keys (`suspend_event_id` + `restored_from_checkpoint_id`) to prove no state forgery — no `decision_history` schema migration needed.

**What this enables:** long-running multi-step workflows that survive harness restarts; operator pause/resume for compliance review of paused agent state; multi-day agent loops awaiting external input; time-travel debugging.

## References
- [Anthropic — Managed Agents: Decoupling brain from hands](https://www.anthropic.com/engineering/managed-agents)
- [Local-First Agent Runtime](https://www.huuphan.com/2026/04/local-first-agent-runtime-guide.html)
- [Self-hosted AI sandboxes — Northflank](https://northflank.com/blog/self-hosted-ai-sandboxes)
