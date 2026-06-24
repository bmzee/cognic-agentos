# Cognic AgentOS — Project Status

**Date:** 2026-06-21 · **Branch:** `main` · **Merged PRs at this snapshot:** 92

## How this page stays honest

This is the single status page for "what is built vs what is pending," measured against the **original** [`docs/BUILD_PLAN.md`](BUILD_PLAN.md). Every **Built / Done** claim is anchored to a merged PR number, because PR titles are immutable and tag their sprint + ADR (e.g. `Sprint 14B-Z1a … (ADR-024)`). The "Built" columns therefore **regenerate** from the PR log and cannot silently rot:

```bash
gh pr list --state merged --limit 200 --json number,title,mergedAt \
  --jq 'sort_by(.number) | .[] | "\(.number)\t\(.mergedAt[0:10])\t\(.title)"'
```

Only the **Pending** column is hand-kept. Authoritative sources this page is derived from: [`docs/BUILD_PLAN.md`](BUILD_PLAN.md) (the original phased plan), [`docs/PROJECT_PLAN.md`](PROJECT_PLAN.md) (north-star + workstreams), [`docs/AS_BUILT_CAPABILITY_MAP.md`](AS_BUILT_CAPABILITY_MAP.md) (latest dated as-built record), `docs/closeouts/` (per-sprint closeouts), and `docs/adrs/`. Where this page and a source disagree, the source wins — fix this page.

**Legend:** ✅ Done (merged PR + closeout/AS-BUILT milestone) · 🟡 Partial / amended-scope · ⬜ Not-started · ⏸ Deferred (explicitly out of current scope).
**"Done" means:** PR merged + tests green + on the critical-controls coverage gate where applicable. **It does NOT mean deployed-and-proven-with-a-real-pack** — see the next section.

---

## North-star + the end-to-end reality check

### The 1.0 outcome we are building toward (verbatim, [`PROJECT_PLAN.md`](PROJECT_PLAN.md) §3)

> AgentOS 1.0 is complete only when a bank can:
>
> 1. Deploy a single-tenant AgentOS instance on bank-controlled infrastructure.
> 2. Install, verify, and allow-list signed tool, skill, and agent packs without changing AgentOS code.
> 3. Create new tool, skill, and agent packs through AgentOS-supported developer functionality, then ship them independently of the AgentOS release cycle.
> 4. Run every pack through a governed kernel that enforces guardrails, audit, decision history, citation verification, RBAC, escalation, SLA, cloud policy, and auto-degradation.
> 5. Execute risky or untrusted actions inside an isolated sandbox with bounded credentials, bounded egress, and bounded resources.
> 6. Spawn sub-agents through a controlled A2A boundary with privilege de-escalation, depth caps, budget caps, and complete audit linkage.
> 7. Export examiner-ready evidence packs aligned to ISO 42001, with tamper-evident integrity proofs.
> 8. Operate in a self-hosted-first posture and report any routing drift honestly through the provider-audit surface.

### The blunt reality box

**AgentOS is an OS-only *kernel*.** By [ADR-001](adrs/ADR-001-os-only-platform.md) design, the actual tools, skills, and agents — the "packs" that do bank work — live in **separate repos that do not exist yet**. This repo ships the governance kernel, runtime primitives, protocol layer (MCP host + A2A receiver), persistence/observability adapters, the pack lifecycle/trust machinery, the sandbox + sub-agent primitives, the deployment substrate (Helm), and the compliance evidence layer. It ships **zero** packs, by design — but that means the product is only as real as the first pack that proves the loop.

**Has the full deployable loop — deploy Helm chart → install one trusted signed pack → an agent does one governed task → audit trail — ever been run end-to-end with a *real* pack? No — but the *in-process* half is now proven (see the 2026-06-23 update below); the *deployed* answer remains No until Proof 1b.**

> **Update (2026-06-23) — Proof 1a: the in-process loop is now proven.** The author → sign → install → startup-trust-register → MCP-invoke → audit → evidence loop has run **green end-to-end with a real pack** (`examples/cognic-tool-search/`) against the **real composition root, in-process** — all 6 PASS assertions, real cosign/syft/grype, documented in [`docs/VALIDATION-RESULTS.md`](VALIDATION-RESULTS.md). The proof earned its keep by surfacing **and** fixing two real kernel bugs that hand-built-fixture tests had masked (cosign 3.x signing break → PR #94 @ `201e190`; in-toto Wave-1 layout contract mismatch → PR #95 @ `566b534`), each as its own reviewed critical-controls PR. **What this does NOT yet prove:** the **deployed** loop (Proof 1b — the same signed pack on a kind/Helm instance, boot-time registration) and a **separate pack repo** with independent CI (Proof 2). Honest status: **Proof 1a in-process proven; Proof 1b deploy proof + Proof 2 still pending.**

> **Update (2026-06-24) — PR-1 ADR-002 trust-register-then-defer + the Proof 1b-1 re-frame.** The deployed **Proof 1b-1** run (the deployed trust-registration axis) surfaced that the *old* boot-time registration ran an OAuth/PRM **discovery probe** of the pack's MCP `server_url`, which the prod SSRF guard correctly refused for a loopback URL — a **runtime-endpoint** concern wrongly gating **trust** registration. **PR-1** (ADR-002 "trust-register-then-defer", on `feat/adr-002-discovery-decoupling`) decouples them: registration is **trust-only** (the discovery probe moves to invoke) + a new **`discovery_status`** axis (`unprobed`/`auth_ready`/`refused`/`unreachable`) surfaced on `/system/plugins`. Under this model the deployed Proof 1b-1 trust registration is **`status == "registered"` + `discovery_status == "unprobed"`** (re-framed in [`docs/VALIDATION-RESULTS.md`](VALIDATION-RESULTS.md)). **Honesty boundary unchanged:** this is the *model* outcome — the deployed run reached signature + attestation verification on a cluster (the offline trust-verification portion; it did **not** complete registration), but the PR-1 kernel is not yet baked into a deployed image, so a deployed re-run is the direct confirmation. It does **not** claim endpoint health (`auth_ready` ≠ "healthy") or **deployed task completion** — **Proof 1b-2** (deployed endpoint/invoke) remains forward and needs the **PR-2** operator `server_url` override + per-tenant internal-host allow-list (its own threat-model pass). Honest status: **Proof 1a in-process proven; Proof 1b-1 deployed trust registration re-framed (deployed re-run pending); Proof 1b-2 + Proof 2 still pending.**

What exists today instead (still true for the *deployed* loop; the *in-process* loop is proven per the update above):

- **Component-level e2es against test fixtures**, not real packs: `tests/integration/run/` (managed-run + sandbox), `tests/integration/approval/` (the 4 approval seams), `tests/integration/sandbox/` (Vault/credential projection), all using `tests/fixtures/cognic_test_*` fixture packs or synthetic argv.
- **Chart-deploy smokes that install no pack**: the env-gated `kind` Ready-smoke (14B-Z1a) and the operator-run AKS smoke (14B-Z1b-d-2) prove the kernel image deploys and `/readyz=200` against real backends — but they register no pack and run no agent task.
- **A startup-discovery conformance test** (#92) that boots a shared trust-registered registry against the `importlib.metadata` entry-point seam — but with "no live cosign / no wheel install," and a bare image correctly yields an **empty catalog**.
- **No separate pack *repos* yet** (Proof 2). `cognic-tool-search` **now exists as a real, functional in-tree MCP tool pack** (`examples/cognic-tool-search/` — built into a wheel, signed, installed as if external; this is what Proof 1a exercises in-process), but as a separately-versioned **repo** with independent pack CI it is still forward; `cognic-agent-policyqa` remains plan text. `examples/cognic-*-example-minimal/` are SDK scaffolds. `docs/VALIDATION-RESULTS.md` (the Proof 1a artifact) **now exists** (per the 2026-06-23 update above).

**Bottom line: code built ≠ proven deployable. The *in-process* loop is now demonstrated end-to-end with a real pack (Proof 1a); the *deployed* loop has not been.** The kernel is production-hardened (134 modules on a 95%/90% per-file coverage gate, ~11k tests, live Postgres/Oracle CI lanes, env-gated Vault/Docker/K8s/AKS proofs), but "a bank installs a real signed pack and an agent completes one governed, audited task on a deployed instance" is the **single most important unproven claim** in the whole project. It is BUILD_PLAN Sprint 15, reframed in the as-built map as the still-forward **Sprint 16 — Production-Readiness Validation**.

---

## Status vs the 6 Agent OS primitives (capability matrix)

A cross-check against the conceptual "Agent OS" model (the kernel = the six runtime primitives below; agents + infra live outside it). This axis exists because the BUILD_PLAN/phase view can make a built primitive read as implied-pending — most acutely the **scheduler/orchestrator**, which is fully built and on the critical-controls gate but easy to miss in the phase ledger. Every primitive below **has a built kernel implementation**; the still-forward work is real **packs** + the **deployed** proof (Proof 1b), not the primitives.

| Primitive | Kernel status | Implemented by (merged modules) | Anchored in | Still forward |
|---|---|---|---|---|
| **Scheduler / orchestrator** | ✅ Built | `core/scheduler/` (`engine.py` submit/mark_running/complete/fail/cancel/preempt/reap · `queue.py` bounded-FIFO + concurrency caps · `storage.py` · `policy.py` Rego gate · `budget_resolver.py` parent-budget inheritance); live caller `core/run/executor.py` (managed-run submit→sandbox→complete) | ADR-022 · Sprint 10.5 + 14A | Wave-2 multi-instance distributed counters |
| **Memory** | ✅ Built | `core/memory/` governed API (`api.py` remember/recall/forget/redact/export · `tiers.py` scratch/task/long_term · `consent.py` · `gate.py` default-deny · `reaper.py` retention · `export.py` regulator-erasure) | ADR-019 · Sprint 11.5 | — |
| **Tools** | ✅ Built (in-process proven) | plugin registry + trust gate (`protocol/plugin_registry.py`, `trust_gate.py`, `supply_chain.py`) · MCP host + invocation route (`protocol/mcp_host.py`, `portal/api/mcp/`) · SDK/CLI validation (`cli/validate.py`) · hooks/DLP (`packs/hooks/`) · runtime approval (`core/approval/`) · sandbox (`sandbox/`) | ADR-002/004/005/014/016 | Real tool **packs** as separate repos (Proof 2); **deployed** loop (Proof 1b) |
| **Identity** | ✅ Built | RBAC actor + tenant isolation (`portal/rbac/`) · MCP OAuth/PRM (`protocol/mcp_authz.py`) · A2A auth + agent cards (`protocol/a2a_authz.py`, `a2a_agent_cards.py`) · pack identity validators (`cli/validators/identity.py`) · Vault credential leasing (`core/vault.py`) | ADR-002/003/004 | A2A **outbound** dispatch; Wave-2/3 mTLS + verifiable credentials |
| **Observability** | ✅ Built | hash-chained audit + decision history + verifier (`core/audit.py`, `decision_history.py`, `chain_verifier.py`) · UI event stream (`protocol/ui_events.py`) · OTel (`observability/otel.py`) · gateway tracing (`llm/gateway.py`) · ISO-42001 evidence export (`compliance/iso42001/`) | ADR-006/009/020 · Sprint 1B/2.5/7B.4 | Live Langfuse OTLP **ingestion** (seam done; enablement parked) |
| **Guardrails** | ✅ Built | `core/guardrails.py` · cloud-policy gateway (`llm/gateway.py`) · policy-as-code OPA/Rego (`core/policy/engine.py` + `policies/_default/`) · DLP hooks (`packs/hooks/dlp_integration.py`) · runtime approval (`core/approval/engine.py`) · kill switches + quotas (`core/emergency/kill_switches.py`, `quotas.py`) | ADR-014/015/017/018 | — |

**Read with the blunt-reality box above:** every primitive has a built kernel implementation; the unproven claim is "a bank installs a real signed pack and an agent completes one governed task **on a deployed instance**." Proof 1a proved that loop **in-process** with a real tool pack (exercising Tools + Identity + Observability + Guardrails together); Proof 1b (deploy) + Proof 2 (separate pack repo) remain forward.

---

## Status vs the original BUILD_PLAN (primary axis)

One row per Phase → Sprint. PRs are the immutable "developed" anchor.

### Phase 1 — Foundation (boots, governs, audits; zero plugins)

| Sprint | Intended scope | Status | Delivering PR(s) |
|---|---|---|---|
| 1A | Repo scaffold + FastAPI boot + CI + arch-discipline | ✅ | #3 (Phase-1 closeout; 1A/1B pre-dated PR tracking) |
| 1B | Observability: logging/OTel/Prometheus/readyz | ✅ | #3 |
| 1C | Adapter protocols + Postgres/Qdrant/Vault | ✅ | #1 |
| 1D | Enterprise adapters: Oracle/Dynatrace/OpenAI-compat | ✅ | #2 |
| 2 | Governance primitives: audit + hash-chain + canonical | ✅ | #4 (plan), #6 |
| 2.5 | Operational primitives: SLA/escalation/guardrails | ✅ | #7 (plan), #8 |
| 3 | LLM gateway + provider-honesty | ✅ | #9 (plan), #10 |

### Phase 2 — Protocol layer + SDK + Pack lifecycle + UI event-stream

| Sprint | Intended scope | Status | Delivering PR(s) |
|---|---|---|---|
| 4 | Plugin registry + trust gate + supply-chain + policy seed | ✅ | #12 (plan), #14 |
| 5 | MCP host (Streamable HTTP + STDIO 4-gate + OAuth/PRM) | ✅ | #15 (plan), #16 |
| 6 | A2A endpoint (1.0 spec) + UI event-stream schema | ✅ | #17 (plan), #18 |
| 7A | Authoring SDK + CLI (validate/sign/verify/test-harness) | ✅ | #19 (plan), #20 |
| 7A2 | Hook packs + runtime DLP hook engine | ✅ | #21 |
| 7B | Bank pack lifecycle API + RBAC + OWASP + evidence panels + SSE | ✅ | #22 (7B.1), #23 (7B.2), #24 (7B.3), #25 (7B.4) |

### Phase 3 — Sandbox + Compliance + Model lifecycle + Scheduler (CLOSED at #42)

| Sprint | Intended scope | Status | Delivering PR(s) |
|---|---|---|---|
| 8 | Sandbox primitive: DockerSibling (8A) + K8s pod (8B) | ✅ | #27 (8A), #29 (8B) |
| 8.5 | Resumable session API: checkpoint/suspend/wake + reaper | ✅ | #30, #31, #32, #33 |
| 9 | ISO 42001 control-mapping evidence layer (cosign + Merkle) | ✅ (honest partial control scope — see ADR-006) | #34 |
| 9.5 | Model Registry primitive (a: storage; b: gateway linkage) | ✅ | #35 (9.5a), #36 (9.5b) |
| 10 | Vault credential leasing (+ 10.1 TTL/grant hotfix) | ✅ | #38, #39 (10.1) |
| 10.5 | Runtime scheduler primitive (FIFO/caps/Rego admission) | ✅ | #40, #41 (closeout) |
| 10.6 | Workload credential projection (Docker/K8s) | ✅ | #42 |

### Phase 4 — Sub-agent + Memory + Quality + Policy + Kill switches + Deploy

| Sprint | Intended scope | Status | Delivering PR(s) |
|---|---|---|---|
| 11 | Sub-agent primitive (a: core; b: integration) | ✅ | #43 (11a), #44 (11b) |
| 11.5 | Agent memory governance (a: substrate; b: regulator; c: surfaces) | ✅ | #45, #46, #47 |
| 12 | Evaluation harness (bulk + LLM-judge) | ✅ | #51 (eval-judge slice), #55 |
| 13 | Live replay + adversarial testing + promotion gate | ✅ | #56 (13a), #57 (13b), #58 (13c) |
| 13.5 | Runtime approval + policy-as-code + emergency controls | ✅ | #59–#66 (13.5a–c4), #67/#68 (13.6a/b kill-switch+quota) |
| 13.7 / 13.8 | Composition-root wiring (scheduler, then MCP host) | ✅ | #70 (13.7), #71 (13.8) |
| 14A (inserted) | Managed-run executor + run route + suspend/resume/wake + high-risk | 🟡 Partial — executor/route/approval seams live + high-risk cold-create & wake e2e-proven; resumption UX, orphaned-resource reconciliation, quota-on-resume forward | #72, #73, #74, #75, #76, #77, #78, #79, #86 |
| 14B (was "per-tenant deploy kit") | Deployment substrate: Helm + ingress/TLS + ESO + OTLP + workload-identity + AKS smoke | ✅ (chart packaging complete; the **deployed-instance** "register a pack + smoke" — i.e. Proof 1b — is not yet run with a real pack; Proof 1a proved that loop **in-process**) | #80, #81, #82, #83, #84, #85 |
| 15 | **End-to-end production-readiness validation with REAL extracted packs** (cognic-tool-search + cognic-agent-policyqa → install → governed query → audit/evidence) | 🟡 **Partial — Proof 1a (in-process) DONE**: real in-tree `cognic-tool-search` pack + `VALIDATION-RESULTS.md` exist, full 6-assertion loop green in the real composition root (surfaced + fixed 2 kernel bugs, #94 / #95); Proof 1b (kind/Helm deploy) + Proof 2 (separate pack repo) still forward | #94, #95 + the Proof-1a branch |

**Forward sprints named in the as-built map (not in original numbering, all unstarted):**

| Forward sprint | Intended scope | Status |
|---|---|---|
| 15A | Dynamic Workflow Orchestration kernel (headless DAG/state-machine) | ⬜ Not-started (named, deliberately unscoped) |
| 15B | AgentOS ADK / local developer runtime (Claude-Code-like loop) | 🟡 Partial — authoring CLI/SDK built (#20/#21); local agent-execution runtime missing |
| 16 | Production-readiness validation + runbooks (= the headline end-to-end proof) | ⬜ Not-started |

### Phase 5 — AgentOS Studio (no-code authoring UI)

| Sprint | Intended scope | Status |
|---|---|---|
| 16–21 | Studio API/storage/trust (ADR-021)/UI shell/composition/promotion | ⏸ Deferred (Phase 5; ships only after Phase 4 stabilises + bank demand confirmed) |

**Cross-cutting work that landed off the sprint numbering** (real, merged, supporting): Wave-1 deploy-safety guards (#49), harness-injection composition root (#50), gateway OTel observability (#52), kernel review remediation of 5 defects (#53), per-tenant config overlay / ADR-023 (#54), the sub-agent live dispatch + portal trigger + approval-retry arc (#88, #89, #90), A2A inbound reachability (#91), MCP/A2A startup discovery + trust-registration (#92).

---

## Status vs the 23 ADRs

| ADR | Capability | Status | Key PR(s) |
|---|---|---|---|
| 001 | OS-only platform boundary | ✅ Enforced (arch-import tests in CI) | #14 + foundational |
| 002 | MCP plugin protocol (Streamable HTTP, STDIO restricted, OAuth/PRM) | ✅ host + construction + invocation route + boot discovery | #16, #71, #86, #92 |
| 003 | A2A inter-agent (pinned 1.0) | 🟡 Inbound **receiver-only** live; outbound A2A + aux surfaces deferred | #18, #91, #92 |
| 004 | Sandbox primitive (Docker + K8s + resumable + credentials) | ✅ | #27, #29, #30, #38, #42 |
| 005 | Sub-agent primitive (spawn, de-escalation, budget, depth) | ✅ dispatch live via portal trigger | #43, #44, #88, #89, #90 |
| 006 | ISO 42001 control mapping + evidence export | 🟡 Export machinery + cosign/Merkle proof done; **3 of 8 controls have live evidence hooks, 5 deferred** | #34 |
| 007 | Provider-honesty (runtime-audited routing) | ✅ | #10 |
| 008 | Authoring platform (SDK + CLI now; Studio deferred) | 🟡 Phase A (SDK/CLI) done; Phase B Studio + local ADK runtime pending | #20, #21 |
| 009 | Pluggable infrastructure adapters | ✅ | #1, #2 |
| 010 | Evaluation harness (bulk + judge + replay) | ✅ | #51, #55, #56 |
| 011 | Adversarial testing (red-team gate) | ✅ | #57, #58 |
| 012 | Bank pack lifecycle (portal + 5-gate approval) | ✅ | #22, #23, #24 |
| 013 | Model lifecycle (Registry in OS; Forge = Wave-2 repo) | ✅ Registry; Forge out of scope by design | #35, #36 |
| 014 | Runtime tool approval (risk tiers + 4-eyes) | ✅ engine + 4 consumer seams live | #59–#66 |
| 015 | Policy-as-code (OPA/Rego bundles) | 🟡 Engine + 8 decision-point bundles production-wired; **hot-reload + decision-trail API unscheduled** | #14, #59 |
| 016 | Supply-chain controls (cosign/SLSA/in-toto/SBOM/vuln/license) | 🟡 cosign + SBOM refusal-grade; **SLSA/in-toto/vuln/license ship at `attestation_grade: partial` grace in Wave-1** | #14, #92 |
| 017 | Data-governance contracts (DLP hooks, classes, egress) | ✅ | #21, #23 |
| 018 | Emergency controls (kill switches + quotas) | ✅ arc CLOSED (8-class matrix + token meter) | #67, #68 |
| 019 | Agent memory governance (remember/recall/forget/redact/export) | ✅ production-wired | #45, #46, #47 |
| 020 | UI event-stream contract (typed events + SSE) | ✅ | #18, #25 |
| 021 | Studio trust model | ⏸ Reserved for Phase 5 entry (not implemented) | — |
| 022 | Runtime scheduler primitive | ✅ | #40, #70, #72 |
| 023 | Per-tenant config overlay (tighten-only, fail-closed) | ✅ (Wave-2 scope) | #54 |
| 024 | Deployment substrate (Helm packaging) | ✅ 14B complete | #80–#85 |

---

## Status vs the 6 workstreams ([`PROJECT_PLAN.md`](PROJECT_PLAN.md) §6)

| Workstream | Status | What's left |
|---|---|---|
| **A — Kernel Hardening** (`core/`, `harness/`, `llm/`, `portal/`, adapters; `retrieval/` named but absent) | 🟡 Substantially complete, with named capability gaps | Ongoing hardening; sampling-`OPAEngine` registration; per-tenant pack-visibility re-key; ML guardrails (regex-only today); governed retrieval/citation verification and auto-degradation are build-or-descope decisions. |
| **B — Pack Ecosystem & Bank Extensibility** (registry, MCP host, A2A, SDK/CLI, lifecycle) | 🟡 In-process proven; deploy + separate-repo unproven | **Proof 1a** demonstrated author → sign → install → invoke → audit → evidence with a real in-tree pack **in the real composition root** (`VALIDATION-RESULTS.md`). Still forward: a separate pack **repo** with independent CI (Proof 2), a real pack on a **deployed instance** + revoke (Proof 1b), outbound A2A, per-tenant pack visibility. The **tool-pack slice** of the PROJECT_PLAN §8 success criterion is now demonstrated **in-process**; the full §8 criterion (multiple pack types incl. agent/A2A, a separate pack ecosystem with independent CI, the bank engineering flow) remains pending Proof 1b / Proof 2 + additional pack types. |
| **C — Compliance & Operational Trust** (audit, citation, ISO 42001, provider-honesty) | 🟡 | Hash-chain/provider-honesty ✅; citation verification is named but absent; ISO 42001 export ✅ but only 3/8 controls evidenced; the Phase-3 exit gate (a 7-day evidence bundle from a *live* deployment, independently verified) has been proven in tests, **not** from a real multi-day run. |
| **D — Execution Isolation & Delegation** (`sandbox/`, `subagent/`, A2A spawn) | ✅ Core live | Two-budget reconciliation (`compute_child_budget` vs `compute_spawn_budget`); sibling/shared-pool ledger; in-workload spawn channel (Fork A); orphaned-backend-resource reconciliation on resume. |
| **E — Bank Deployment Kit** (Docker/Helm, Vault/OIDC, runbooks, backup/restore) | 🟡 | Helm chart + AKS/kind smoke + ESO + ingress/TLS + observability + workload-identity all DONE; **missing**: complete operator runbook set, backup/restore/rollback procedures, release/evidence checklist, and the rehearsed "install → register signed pack → smoke → export evidence → rollback-recover" loop. |

---

## Pending work register

This is the operational backlog. "Required before v1 proof" means the item must be done before claiming the full bank-deployable loop has been demonstrated.

| Priority | Pending item | Why it matters | Success condition | Required before v1 proof? |
|---|---|---|---|---|
| P0 | **First real pack**: ✅ `cognic-tool-search` built as a real **in-tree** MCP server pack (validated, signed, full runtime attestations, installed/allow-listed, invoked, audited — **Proof 1a, in-process**). **Forward**: extract it to a separate **repo** with independent pack CI (Proof 2); `cognic-agent-policyqa` A2A agent pack still plan text. | AgentOS is OS-only. Without a real pack, the kernel cannot prove it runs real bank work. | In-tree pack validated/signed/installed/invoked/audited (Proof 1a ✅); separate pack repo + deployed-instance proof still forward. | Partial (1a done) |
| P0 | **End-to-end real-pack proof** | This is the headline gap. Component tests do not prove "bank deploys AgentOS and runs a governed task." | Helm-deploy AgentOS, discover/trust-register the real signed pack, invoke one governed task, verify decision-history chain, approval/audit records, tool evidence, and evidence export. Capture in `docs/VALIDATION-RESULTS.md`. | Yes |
| P0 | **Production-readiness runbooks** | Banks need repeatable operations, not just code. | Backup/restore, migration/rollback, secret rotation, incident response, release checklist, and evidence-export runbooks exist and are rehearsed against the real-pack proof. | Yes |
| P1 | **Runtime resume hardening** | Managed runtime is live, but resume has known forward edges. | Orphaned backend resource reclaim on resume claim-failure; quota/scheduler re-admission on resume; resumption UX; process-restart concurrency counter durability. | Should do before v1 proof |
| P1 | **Real sub-agent/runtime metering and budget fan-out** | Current sub-agent token metering is not a real usage number, and sibling children can over-fan-out a parent ceiling. | Real `tokens_used`; sibling/shared-pool ledger; two-budget reconciliation documented and enforced. | Should do before v1 proof if subagents are in the proof |
| P1 | **Fork A in-workload spawn channel** | Portal trigger exists, but the architecturally honest parent workload -> child spawn path is still absent. | Kernel-controlled sandbox callback or equivalent trusted channel; parent tool list sourced from trusted running-agent context; audited spawn. | No, unless sub-agent delegation is part of v1 proof |
| P1 | **MCP/A2A tenant visibility model** | Startup registry is global `_default`; true per-tenant pack visibility remains deferred. | Registry/consumer model prevents one tenant's registered pack from becoming visible to another tenant. | Depends on v1 tenancy claim |
| P1 | **MCP sampling registration** | Boot uses `opa_engine=None`; non-sampling MCP packs register, sampling-capable packs default-deny. | Boot wires the sampling OPAEngine and proves sampling-capable MCP packs can register only when policy permits. | No, unless first real pack uses sampling |
| P1 | **Outbound/Auxiliary A2A** | A2A is receiver-only. | Outbound A2A, tasks/get, tasks/cancel, streaming, artifacts/capabilities, and host-based tenancy are designed and surfaced. | No, unless first real pack requires A2A beyond inbound `message/send` |
| P1 | **Governed retrieval + citation verification** | Original doctrine names citation verification, but `retrieval/`, `core/citation.py`, and `retrieval/citation_verifier.py` are absent. | Decide build vs descope. If build: retrieval orchestrator + citation verifier + evidence hooks + tests. If descope: update AGENTS/PROJECT_PLAN/AS_BUILT language. | Yes if the v1 proof claims citation-grounded answers |
| P1 | **Auto-degradation** | Original doctrine names `core/auto_degradation.py`, but the module is absent. | Decide build vs descope. If build: SLA/health-triggered degradation policy + audit/evidence. If descope: update doctrine. | Yes if the v1 proof claims graceful auto-degradation |
| P2 | **ISO 42001 remaining evidence hooks** | Evidence export exists, but only part of the control map has live evidence hooks. | Remaining 5/8 controls have live hooks or are explicitly marked not-applicable/deferred with examiner-facing rationale. | Should do before external examiner proof |
| P2 | **Supply-chain full-grade hardening** | Wave-1 still allows partial attestation grade for some checks. | SLSA L3+, in-toto, vuln scan, and license audit move from grace/partial posture to refusal-grade where required. | Not for first loop, yes before stricter bank rollout |
| P2 | **Policy operations** | OPA engine is live, but hot-reload and decision-trail API are unscheduled. | Policy bundle hot-reload, versioning, and operator-visible decision trail exist. | No |
| P2 | **Approval/quota operator controls** | Several operator controls remain follow-ups. | Single-use grant consume; quota override/write routes; spend-class enforcement. | No, unless required by launch governance |
| P2 | **Workflow orchestration kernel (15A)** | No generic workflow engine exists. | ADR + headless DAG/state-machine substrate with scheduler/policy/audit hooks. | No for OS v1 proof unless workflows are claimed |
| P2 | **ADK/local runtime (15B)** | Authoring CLI exists; Claude-Code-like local governed dev loop does not. | Local pack run/simulate/sign/test loop with governance simulation. | No |
| P3 | **AgentOS Studio / no-code authoring UI** | Phase 5 is explicitly deferred. | ADR-021 activation + Studio scope. | No |

---

## Honest caveats

- **What "Done / ✅" means here:** the sprint's PR is merged, its tests are green, and (for critical controls) it rides the 95%-line / 90%-branch per-file coverage gate. It does **not** mean the capability has been exercised on a deployed instance, and it does **not** mean it has been driven by a *real* pack. Many capabilities are `seam-only` or `env-gated live proof` (built + DI/test-proven, or proven only in opt-in operator runs) rather than `production-wired` — see the posture vocabulary in [`AS_BUILT_CAPABILITY_MAP.md`](AS_BUILT_CAPABILITY_MAP.md).
- **The kernel-vs-product gap is the central risk.** This repo is a hardened OS with no packs by design (ADR-001). The OS is far along; the *product* (a bank running governed agent work) is **not yet fully proven**: Proof 1a has now run the **in-process** version — one real signed pack completing one governed task with a verifiable audit chain, in the real composition root (see the 2026-06-23 update above) — but the **deployed-instance** version of that proof (Proof 1b — the same pack on a kind/Helm AgentOS) has not. That deployed demonstration would convert most 🟡 workstreams from "built" to "proven."
- **A few rows are marked 🟡 on genuine judgment calls** (flagged for the reader to resolve): Sprint 9 / **ADR-006** (the layer is done and AC-verified, but only 3/8 controls have live evidence hooks); **ADR-015** (engine + all decision-point bundles live, but hot-reload + decision-trail API never shipped); **ADR-016** (cosign + SBOM are refusal-grade, but SLSA/in-toto/vuln/license ride a Wave-1 grace period); **Sprint 14A** (managed runtime is live but its resumption/quota forward items remain); **Workstream B/C/E** (built but not proven end-to-end). Where a status was ambiguous, this page chose the more conservative mark.
- **Authoritative sources** (read these, not this page, for ground truth): [`docs/BUILD_PLAN.md`](BUILD_PLAN.md) (original plan + per-sprint closeout status blocks), [`docs/AS_BUILT_CAPABILITY_MAP.md`](AS_BUILT_CAPABILITY_MAP.md) (latest as-built map + milestones 6a–6l), `docs/closeouts/` (25 per-sprint closeouts), `docs/adrs/` (23 ADRs). Regenerate the "Built" anchors with the `gh pr list` command at the top of this page.
