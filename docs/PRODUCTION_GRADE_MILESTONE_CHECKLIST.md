# AgentOS Production-Grade Milestone Checklist

**Date:** 2026-06-27  
**Purpose:** keep AgentOS deployable at every milestone, and make "complete" mean production-grade deployment on AKS with the full v1 feature scope proven.

This checklist is the execution ledger for the remaining product proof. `PROJECT_STATUS.md` says what is built vs pending; this file says what has been **production-grade proven**.

## Non-Negotiable Rules

1. **Main is deployable at every checked milestone.** A milestone cannot land on `main` if it leaves AgentOS in a half-built or non-deployable state. Incomplete work must stay behind flags, dormant seams, env-gated jobs, separate branches, or separate repos.
2. **A checkbox requires evidence.** Code existing is not enough. A milestone is checked only when the proof ran, the evidence is recorded, and the docs say exactly what was proven.
3. **Every milestone has a negative or load-bearing proof.** A happy path alone is not enough for production-grade status. The proof must show the governance control matters: refusal, rollback, disabled state, policy denial, missing allow-list, revoked pack, failed trust gate, or equivalent.
4. **AKS is the final bar.** `kind` is acceptable for intermediate proof. Checklist completion requires a production-grade AKS deployment proof with the full v1 scope enabled, installed, governed, observable, recoverable, and documented.
5. **Packs remain outside this repo.** Tool, skill, hook, and agent packs must be separately versioned repos for product-complete status. In-tree examples can prove substrate behavior, but they do not close the pack-ecosystem milestone.

## What "Production-Grade Proven" Means

Every checked milestone should record:

- merged PR or separate-repo release reference
- CI green for the touched repo(s)
- critical-controls coverage gate, if any critical-control module changed
- image build and Helm/kubeconform validation where deployable surfaces changed
- migration apply/rollback posture, where schema changed
- `kind` or AKS proof, depending on the milestone
- negative/load-bearing proof
- evidence link, usually `docs/VALIDATION-RESULTS.md`, a closeout, or an operator-run report
- updated status docs
- remaining risks explicitly named

## Completion Definition

AgentOS v1 is production-grade complete when **all in-scope milestones below are checked** and the final gate proves:

> A bank can deploy AgentOS on AKS, install signed separately-versioned tool, hook, skill, and agent packs, run a governed LLM-agent task using assigned tools/skills/workflows/memory under policy/RBAC/approval/sandbox controls, recover/rollback operationally, and export examiner-ready evidence.

Studio/no-code authoring and Cognic Forge remain outside this v1 completion checklist unless explicitly promoted into scope by a future ADR.

## Checklist

### A. Proven Foundation

- [x] **M0 — Governance kernel deployable baseline.**  
  **Evidence:** phases 1-4 landed; critical-controls coverage gate; live Postgres/Oracle CI; Helm substrate; README/PROJECT_STATUS reconciliation.  
  **Production posture:** kernel can deploy without product packs; still not a full product claim.

- [x] **M1 — In-process governed pack loop, Proof 1a.**  
  **Evidence:** real in-tree `examples/cognic-tool-search` pack validated, signed, installed, invoked, audited, and evidence-recorded in-process; PR #96 lineage and `docs/VALIDATION-RESULTS.md`.  
  **Load-bearing proof:** surfaced and fixed real trust/in-toto issues.  
  **Production posture:** proves the pack loop in-process; not a deployed or separate-repo proof.

- [x] **M2 — Deployed governed tool-invocation loop, Proof 1b-2.**  
  **Evidence:** PR #103; live `kind` proof with private-ClusterIP MCP tool, override + exact-IP allow-list, external-emulated AS, `list_tools`, `call_tool`, `discovery_status=auth_ready`, and audit evidence.  
  **Load-bearing proof:** allow-list removed -> refused status.  
  **Production posture:** proves deployed tool invocation; not yet a deployed LLM-agent loop or separate-repo pack ecosystem.

### B. Pack Ecosystem And Product-Pack Proofs

- [x] **M3 — First separate-repo tool pack, Proof 2.**  
  **Evidence:** `cognic-tool-oracle-schema@v0.1.0` — a separate **public** repo (`bmzee/cognic-tool-oracle-schema`) with independent CI + a signed GitHub Release (wheel + 7 attestations + `cosign.pub`); installed into a deployed `kind` AgentOS by **boot-time trust registration of the DOWNLOADED released artifact** (sha256-verified, not a local rebuild) and exercised through the governed MCP route — `list_tools` + `call_tool(describe_table owner=COGNIC table=EMPLOYEES)` against an in-cluster seeded Oracle XE, at `discovery_status=auth_ready`. Runner `infra/proof-1b-2c/run-proof-1b-2c.sh` (`RUNNER_EXIT=0`); `docs/VALIDATION-RESULTS.md` "M3-E2c / Proof 2 — PASS" section.  
  **Load-bearing proof:** the per-tenant exact-IP allow-list carve-out — removing the `mcp_internal_host_allowlist` row on a cold pod flips the resource leg from permitted (`audit.mcp_allowlist_permitted`, host `10.96.0.51`) to refused (HTTP 502 + `mcp_discovery_url_refused` + `discovery_status=refused`).  
  **Production posture:** proves the first separate-repo tool pack deployed + governed through AgentOS on `kind`, with zero `src/cognic_agentos` kernel changes for the proof loop. NOT the production AKS platform (M15/M24), NOT an LLM-agent loop (M8), and NOT the operator-grade install flow (M4 — the proof still harness-seeds the override/allow-list/OAuth).

- [x] **M4 — Operator-grade pack install flow.**
  **Evidence:** the released signed `cognic-tool-oracle-schema@v0.1.0` pack was installed through the real operator API path on a deployed `kind` AgentOS: author draft -> submit, distinct reviewer claim/approve, operator-human allow-list, operator configure, install materialization, disable/re-install/revoke. Runner `infra/proof-m4/run-proof-m4.sh` (`RUNNER_EXIT=0`); `docs/VALIDATION-RESULTS.md` "M4 — Operator-grade pack install flow — PASS" section.
  **Load-bearing proof:** install is refused when not approved/allow-listed, when runtime config is absent, when the referenced OAuth Vault material is absent, and when signature verification is red; disable retracts the derived MCP carve-outs and flips discovery to `refused`; disabled -> installed re-enable restores `auth_ready` + `call_tool`; revoke retracts again and makes install terminally refused.
  **Production posture:** replaces the M3 direct DB seeding of override/allow-list rows with lifecycle-governed runtime config plus materialization. OAuth remains by-reference and pre-provisioned in Vault for M4, per ADR-026; AKS/operator-pack distribution hardening remains later milestone work.

- [ ] **M5 — Real hook pack proof.**  
  **Goal:** ship a separate `cognic-hook-*` pack and prove it is installed, trusted, ordered, and enforced at runtime.  
  **Production proof:** a live request triggers the hook in deployed AgentOS.  
  **Load-bearing proof:** hook deny/fail-closed or documented fail-open exception behaves exactly as declared.  
  **Evidence required:** hook pack release + AgentOS validation.

- [ ] **M6 — Executable skill service proof.**  
  **Goal:** ship a separate `cognic-skill-*` pack implementing deterministic `Skill.execute()` tool composition.  
  **Production proof:** deployed AgentOS invokes the skill service, it uses only declared tools, and it emits audit/evidence.  
  **Load-bearing proof:** undeclared tool use or missing required tool is refused.  
  **Evidence required:** skill pack release + deployed proof.

- [ ] **M7 — Agent Skills `SKILL.md` hosting, ADR-025.**  
  **Goal:** host/govern the open Agent Skills `SKILL.md` format without replacing it: ingest a `SKILL.md` folder, wrap it in AgentOS governance, and make it assignable to agents.  
  **Production proof:** an agent receives the instruction skill through the governed assignment path and uses it during a deployed task.  
  **Load-bearing proof:** unsigned/untrusted/malformed skill folder is refused; skill content cannot bypass pack governance.  
  **Evidence required:** ADR-025, adapter implementation, proof run, docs.

### C. Agent Loop And Runtime Capability

- [ ] **M8 — First deployed bank LLM-agent loop using tools and skills.**
  **Goal:** a separate bank-use-case `cognic-agent-*` pack acts as a human-role worker, receives assigned tools and skills, reasons over a realistic banking task, invokes those assigned capabilities, records memory/audit, and completes one governed task.
  **Production proof:** run on deployed AgentOS, not only in-process; first on `kind`, then AKS before final gate.  
  **Load-bearing proof:** agent cannot call unassigned tools/skills; policy/RBAC denial is visible and audited.  
  **Evidence required:** agent pack repo, deployed proof, validation results.

- [ ] **M9 — Governed memory used by a real deployed agent.**  
  **Goal:** the deployed agent uses scratch/task/long-term memory under ADR-019 controls.  
  **Production proof:** remember/recall/forget/redact/export are exercised through the agent path where applicable.  
  **Load-bearing proof:** default-deny long-term, restricted-data consent, purpose mismatch, or regulator-erasure refusal/path is demonstrated.  
  **Evidence required:** memory evidence rows + validation report.

- [ ] **M10 — Sub-agent/A2A delegation proof, if claimed for v1.**  
  **Goal:** controlled delegation from one agent to another through AgentOS boundaries.  
  **Production proof:** parent agent delegates a bounded task to a child/sub-agent or A2A receiver with audit linkage.  
  **Load-bearing proof:** privilege escalation, depth cap, or budget cap refusal.  
  **Evidence required:** deployed run + audit linkage.

- [ ] **M11 — Outbound A2A, if claimed for v1.**  
  **Goal:** AgentOS can call external A2A agents, not only receive inbound A2A.  
  **Production proof:** outbound dispatch with signed Agent Card validation and tenant policy.  
  **Load-bearing proof:** signer/tenant/version/card-policy refusal.  
  **Evidence required:** deployed proof and A2A conformance update.

### D. Development Experience

- [ ] **M12 — AgentOS ADK/local runtime.**  
  **Goal:** local Claude-Code/Codex-like developer loop for creating, running, simulating, validating, signing, and installing AgentOS-compatible packs.  
  **Production proof:** a developer creates a tool/skill/agent pack locally, runs it against local AgentOS governance, signs/verifies it, and deploys it to an AgentOS environment.  
  **Load-bearing proof:** invalid manifest, missing attestations, policy refusal, or untrusted pack fails locally before deployment.  
  **Evidence required:** tutorial/run transcript + CI.

- [ ] **M13 — Pack scaffolding templates for tools, hooks, skills, agents.**  
  **Goal:** supported templates for `cognic-tool-*`, `cognic-hook-*`, `cognic-skill-*`, `cognic-agent-*`, and `SKILL.md` hosted instruction skills.  
  **Production proof:** each template produces a pack that passes validate/sign/verify and can be installed in a deployed AgentOS environment.  
  **Load-bearing proof:** generated negative fixtures fail for the intended reasons.  
  **Evidence required:** template tests + one deployed install proof per pack type.

### E. Workflow And Orchestration

- [ ] **M14 — Dynamic workflow orchestration kernel, Sprint 15A.**  
  **Goal:** generic declarative DAG/state-machine workflow engine with scheduler integration, durable state, pause/resume, approvals, retries/compensation, sub-agent steps, and execution history.  
  **Production proof:** a workflow runs on deployed AgentOS and uses governed tool/skill/agent steps.  
  **Load-bearing proof:** branch policy denial, approval pause/resume, retry limit, cancellation, and rollback/compensation behavior.  
  **Evidence required:** ADR/spec, implementation, deployed proof.

### F. Production Operations And Evidence

- [ ] **M15 — AKS deployed pack + agent proof.**  
  **Goal:** move from `kind` proof to AKS for the real pack + agent loop.  
  **Production proof:** AKS deployment with external secrets/workload identity, real chart values, migrations, pack install, governed agent task, audit, and health checks.  
  **Load-bearing proof:** missing secret/pack trust/allow-list/policy denies correctly; rollback path rehearsed.  
  **Evidence required:** AKS operator-run report and validation results.

- [ ] **M16 — Production ops proof: backup/restore, rollback, secret rotation, kill-switch, incident response.**  
  **Goal:** banks can operate, recover, and emergency-control AgentOS, not only deploy it.  
  **Production proof:** restore from backup; rotate secrets; run migrations/rollback posture; disable/revoke a pack; flip a tenant/pack/tool kill switch and prove ≤30s propagation (ADR-018); and recover service.  
  **Load-bearing proof:** restore/rollback failure surfaces fail-loud (not silent data loss); a flipped kill switch actually blocks the gated path (fail-closed).  
  **Evidence required:** runbook transcripts (incl. an incident-response transcript) and updated operator docs.

- [ ] **M17 — Examiner-ready evidence export from live deployment.**  
  **Goal:** export ISO 42001 evidence from a live AKS run, not only unit/e2e tests.  
  **Production proof:** evidence pack exported, integrity verified, and mapped to live run/audit/decision-history rows.  
  **Load-bearing proof:** tampered evidence fails verification.  
  **Evidence required:** exported evidence report and verifier output.

- [ ] **M18 — ISO 42001 remaining evidence-hook closure or explicit scope decision.**  
  **Goal:** either wire remaining live evidence hooks or explicitly mark controls not-applicable/deferred with examiner-facing rationale.  
  **Production proof:** live evidence coverage matches what the product claims.  
  **Load-bearing proof:** missing evidence is detected by checklist/release gate.  
  **Evidence required:** ISO mapping update and examiner-facing note.

- [ ] **M19 — Supply-chain full-grade hardening decision.**  
  **Goal:** decide and implement which SLSA/in-toto/vuln/license checks become refusal-grade for v1.  
  **Production proof:** pack install accepts only the declared attestation grade.  
  **Load-bearing proof:** vulnerable/license-invalid/provenance-invalid pack is refused when policy requires it.  
  **Evidence required:** trust-gate proof and pack CI evidence.

- [ ] **M20 — Per-tenant pack visibility.**  
  **Goal:** one tenant cannot see or invoke another tenant's registered packs.  
  **Production proof:** deployed multi-tenant or simulated multi-tenant proof with separate pack visibility.  
  **Load-bearing proof:** cross-tenant pack lookup collapses/refuses without information leak.  
  **Evidence required:** tenant-isolation proof.

### G. Named Build-Or-Descope Decisions

These items are in the older doctrine or product story. They must be built and proven if claimed for v1, or explicitly descoped in docs/ADRs before final completion.

- [ ] **M21 — Governed retrieval/citation verification: build or descope.**  
  **If built:** prove retrieval/citation verification in deployed agent answers, including citation failure/refusal.  
  **If descoped:** update docs that currently imply citation verification is part of the v1 claim.

- [ ] **M22 — Auto-degradation: build or descope.**  
  **If built:** prove SLA/health-triggered degradation with audit/evidence.  
  **If descoped:** remove or qualify claims that imply graceful auto-degradation exists.

- [ ] **M23 — Studio/no-code UI: keep deferred or promote.**  
  **Default:** out of v1 checklist.  
  **If promoted:** requires its own production-grade AKS proof and trust model ADR-021 activation.

## Final Gate

- [ ] **M24 — AgentOS v1 production-grade AKS completion gate.**  
  **Goal:** all in-scope checklist milestones above are checked, and the final AKS run proves the whole product story.  
  **Required proof:** deploy AgentOS on AKS; install separately-released signed packs; assign tools/skills to a real agent; run a governed agent task using memory/policy/RBAC/approval/sandbox where applicable; export evidence; rehearse disable/revoke/rollback; leave the release branch and `main` deployable.  
  **Completion statement allowed only after:** CI green, AKS proof green, evidence export verified, runbooks rehearsed, status docs updated, and remaining deferred items named explicitly.

## Update Protocol

When a milestone completes:

1. Update this file in the same PR or an immediate docs PR.
2. Link the proof evidence.
3. Move the checkbox only after verification, not at plan/spec time.
4. Update `docs/PROJECT_STATUS.md` if the completion changes the high-level product status.
5. Do not change older evidence to sound cleaner. Add a dated note instead.
