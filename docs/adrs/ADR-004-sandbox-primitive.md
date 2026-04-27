# ADR-004 — Sandbox Primitive (Ephemeral Isolated Execution)

## Status
**APPROVED for implementation** on 2026-04-26.

## Context

Per Anthropic's Managed Agents pattern (April 2026), the **sandbox** is the "hands" of an agent system — an ephemeral, resource-capped, network-egress-controlled execution environment. Cognic AgentOS today has no sandbox primitive: agents and tools run in the same Python process as the OS. For banking deployment this is unacceptable:

- Agent generates SQL against a CBS → no way to scope credentials to one query
- Agent processes a customer PDF → malicious PDF can attack the host process
- Agent runs ad-hoc Python → no resource cap, no egress filter
- Tool pack compromise → blast radius is the entire AgentOS process

## Decision

Add a `sandbox/` primitive module providing `SandboxSession`. Lifecycle: `create() → exec() → destroy()`. Each session is:

- A separately-named container (e.g. Docker, runc, gVisor, Firecracker — backend abstracted)
- Resource-capped (CPU quota, memory, wall-time)
- Egress allow-listed (per-call list of permitted hostnames)
- Image-pinned (cosign-verified digest of the sandbox runtime image)
- Credential-scoped (Vault leases minted at create, revoked at destroy)
- Audit-logged (every create / exec / destroy emits an event with policy + outcome)

### Backend choice
- **Wave 1**: Docker-in-Docker (DinD) — simplest to operate inside a single bank deployment
- **Wave 2**: gVisor or Firecracker — stronger isolation when banks demand kernel-level boundary
- Backend swappable via a `SandboxBackend` protocol; AgentOS doesn't bake DinD into the contract

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
1. **Phase 3.1**: `SandboxBackend` protocol + DinD reference implementation
2. **Phase 3.2**: warm-pool + lifecycle metrics
3. **Phase 3.3**: per-tenant policy schema + Vault credential leasing
4. **Phase 3.4**: ISO 42001 control tagging on lifecycle events
5. **Phase 3.5**: **Resumable-session API** — `checkpoint(label) / suspend() / wake(session_id)` (added Sprint 8.5)
6. **Phase 4.x**: gVisor / Firecracker backend (Wave 2)

## Resumable-session API (Sprint 8.5)

Basic create/exec/destroy is insufficient for Anthropic-Managed-Agents-style durable sessions. The sandbox primitive exposes:

```python
session = await sandbox.create(policy)
result = await session.exec(command)
checkpoint_id = await session.checkpoint(label="before_payment_action")
await session.suspend()           # container released; state persisted

# Different process / after harness restart:
session = await sandbox.wake(session_id)  # restores from latest checkpoint
result = await session.exec(next_command)
await session.destroy()
```

**Checkpoint storage:** filesystem deltas (overlay-fs snapshots) + env metadata + Vault lease references. Stored in `ObjectStoreAdapter` (per ADR-009) with per-tenant retention policy (default 24h; long-running workflow tenants extend via Rego policy per ADR-015).

**Audit:** `sandbox.checkpoint` and `sandbox.wake` events hash-chain into `decision_history`. Chain verifier walks suspend → wake transitions to prove no state forgery.

**What this enables:** long-running multi-step workflows that survive harness restarts; operator pause/resume for compliance review of paused agent state; multi-day agent loops awaiting external input; time-travel debugging.

## References
- [Anthropic — Managed Agents: Decoupling brain from hands](https://www.anthropic.com/engineering/managed-agents)
- [Local-First Agent Runtime](https://www.huuphan.com/2026/04/local-first-agent-runtime-guide.html)
- [Self-hosted AI sandboxes — Northflank](https://northflank.com/blog/self-hosted-ai-sandboxes)
