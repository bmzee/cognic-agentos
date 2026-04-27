# Cognic AgentOS — Roadmap

## Status: Pre-code, doctrine in place (2026-04-26)

The clean-slate AgentOS folder holds **20 ADRs** + project plan + canonical architecture + 3 lessons + 2 conformance matrices (MCP, A2A) + this roadmap + sprint-level build plan. No source code yet. Sprint 1A (the bootstrap) begins next.

## Phase 1 — Foundation (Sprints 1A-1D, 2, 3, ~2.5-3 weeks)

- [x] ADR-001 OS-only platform
- [x] ADR-002 MCP plugin protocol (with STDIO threat-model amendment + OAuth/PRM authorization + AGNTCY/OASF identity fields)
- [x] ADR-003 A2A inter-agent (with Wave 1 feature scope: Agent Cards, tasks, streaming, artifacts)
- [x] ADR-004 sandbox primitive (with resumable session API: checkpoint / suspend / wake)
- [x] ADR-005 sub-agent primitive
- [x] ADR-006 ISO 42001 control mapping
- [x] ADR-007 provider-honesty
- [x] ADR-008 authoring platform (SDK + Studio split)
- [x] ADR-009 pluggable infrastructure adapters
- [x] ADR-010 evaluation harness
- [x] ADR-011 adversarial testing
- [x] ADR-012 bank pack lifecycle
- [x] ADR-013 model lifecycle & fine-tuning boundary (Model Registry in OS; Cognic Forge separate Wave 2 repo)
- [x] ADR-014 runtime tool approval (per-tool risk tiers; 4-eyes for payment_action / regulator_communication)
- [x] ADR-015 policy-as-code (OPA/Rego bundles for admission, routing, approval, egress, sub-agent spawn, lifecycle)
- [x] ADR-016 supply-chain controls (cosign + SLSA L3+ + in-toto + SBOM + vuln scan + license audit + 7-year Sigstore retention)
- [x] ADR-017 data governance contracts (pack-manifest data-class declarations + DLP hooks + consent gates)
- [x] ADR-018 emergency controls (kill switches + quotas; ≤30s P99 propagation; fail-closed)
- [x] ADR-019 agent memory governance (governed memory API; three tiers; default-deny long-term; regulator-erasure pathway)
- [x] ADR-020 UI event-stream contract (typed event taxonomy; SSE default; reconnect-safe via decision_history mirror; supports run state, tool calls, sub-agent, approvals, interrupts, artifacts, frontend actions)
- [x] MCP-CONFORMANCE.md (transport / capability / authorization matrix)
- [x] A2A-CONFORMANCE.md (feature / authorization matrix)
- [x] PROJECT_PLAN.md baseline + BUILD_PLAN.md sprint sheet aligned
- [ ] **Sprint 1A**: pyproject + uv.lock + minimal FastAPI + `/healthz` (liveness) + `/version` + Dockerfile + CI + architecture test + git init
- [ ] **Sprint 1B**: observability — JSON logging + request-id + OTel + Prometheus `/metrics` + OpenAPI export + `/readyz` (readiness) + refined no-env-specific-values discipline test
- [ ] **Sprint 1C**: adapter protocols + Postgres + Qdrant + Vault + Ollama + Langfuse-OTel reference adapters + 7-service docker-compose
- [ ] **Sprint 1D**: enterprise bundled adapters — Oracle + Dynatrace + OpenAI-compat embedding (vLLM/SGLang) + opt-in Oracle/vLLM compose overlays
- [ ] **Sprint 2**: `core/` governance primitives (audit, decision_history with hash chain, chain_verifier, schemas, sla, escalation, guardrails, db migrations)
- [ ] **Sprint 3**: LLM gateway + concurrency + cloud-policy enforcer + provider-honesty endpoint

## Phase 2 — Plugin protocol + SDK + Pack Lifecycle + UI Event-Stream (Sprints 4, 5, 6, 7A, 7B, ~3-3.5 weeks)

- [ ] **Sprint 4**: `protocol/plugin_registry.discover()` + `protocol/trust_gate.py` (cosign + per-tenant allow-list) + `protocol/supply_chain.py` (SLSA L3+ + in-toto + SBOM + vuln scan + license audit + Sigstore bundle 7-year retention) per ADR-016
- [ ] **Sprint 5**: `protocol/mcp_host.MCPHost` — **Streamable HTTP first** (production default); STDIO restricted by 4-gate model (signed manifest + command allow-list + sandbox + bounded env); **OAuth/PRM authorization** per ADR-002 amendment + capability validator per `MCP-CONFORMANCE.md`; full negative-path test coverage
- [ ] **Sprint 6**: `protocol/a2a_endpoint.A2AEndpoint.handle()` — inbound + outbound A2A pinned to A2A 1.0 spec; **Agent Cards two-pass validated (upstream A2A 1.0 schema + AgentOS bank-grade profile that requires JWS signatures, securitySchemes, securityRequirements, provider, supportedInterfaces populated), streaming (SSE), artifacts (by reference), capability negotiation, cancellation, version negotiation (`A2A-Version` header; absent-header = 0.3 per spec → rejected)** per `A2A-CONFORMANCE.md`; chain-hashed audit linkage; conformance fixtures (protobuf source + JSON-schema binding both checked); per-tenant pinned-token authorization. **Plus the UI event-stream stub per ADR-020** (`protocol/ui_events.py` typed event-emit hooks at the harness boundary, no SSE endpoint yet — that ships in 7B)
- [ ] **Sprint 7A**: `agentos-sdk` + `agentos-cli` (init / validate / test-harness / sign) per ADR-008 Phase A; validators enforce **AGNTCY/OASF identity (lives in pack manifest, NOT in the AgentCard), MCP/A2A conformance declarations, data-governance contract per ADR-017, risk-tier consistency per ADR-014, supply-chain attestation paths per ADR-016**
- [ ] **Sprint 7B**: Bank pack lifecycle portal API (draft → submit → review → approve → allow-list → install → disable → revoke → uninstall) + RBAC scopes + OWASP agentic conformance gates per ADR-012; **reviewer evidence panels** for data governance, risk tier, supply chain, conformance matrix; **UI event-stream SSE endpoints + frontend-action POST + portable JSON schema at `/.well-known/cognic-ui-events.json` per ADR-020** (reconnect-safe via decision_history catch-up cursor)

## Phase 3 — Sandbox (with Resumable Sessions) + Compliance + Model Lifecycle (Sprints 8, 8.5, 9, 9.5, 10, ~2-2.5 weeks)

- [ ] **Sprint 8**: `sandbox/SandboxBackend` + DinD reference impl + warm-pool + lifecycle metrics
- [ ] **Sprint 8.5**: **Resumable session API** per ADR-004 amendment — `checkpoint(label) / suspend() / wake(session_id)` with overlay-fs snapshots + ObjectStoreAdapter persistence + per-tenant retention + audit-chain integrity across suspend/wake; required before sub-agent work in Sprint 11
- [ ] **Sprint 9**: ISO 42001 control registry populated; governance hooks emit tagged events; `evidence_pack.export()` with Merkle root
- [ ] **Sprint 9.5**: **Model Registry primitive** per ADR-013 — model record storage + portal API + RBAC scopes + ISO 42001 control tags + `decision_history` linkage + provider-honesty extension. Closes the "which fine-tuned model handled which case" gap. Cognic Forge (Wave 2) plugs in via the published API contract.
- [ ] **Sprint 10**: Vault credential leasing; per-tenant sandbox policy schema; per-tenant TTL caps

## Phase 4 — Sub-agent + Memory Governance + Quality Gates + Policy + Kill Switches + Deploy (Sprints 11, 11.5, 12, 13, 13.5, 14, 15, ~3-3.5 weeks)

- [ ] **Sprint 11**: `subagent.SubAgent.invoke()` via A2A; privilege de-escalation; recursion depth + budget caps
- [ ] **Sprint 11.5**: **Agent memory governance** per ADR-019 — `core/memory/` primitive (`MemoryAPI` with `remember/recall/forget/redact/export/list_for_subject`) + Postgres + Redis adapters + per-write data-class + purpose + consent enforcement + `memory.write_freeze` kill switch + ISO 42001 control tags. Inserted before Sprint 12 so eval can exercise memory-aware agents.
- [ ] **Sprint 12**: Evaluation harness — bulk testing + simulated scenarios + storage + CLI (per ADR-010)
- [ ] **Sprint 13**: LLM-judge + live case replay + adversarial testing + promotion gate (per ADR-010 + ADR-011)
- [ ] **Sprint 13.5**: **Runtime tool approval + Policy-as-code + Emergency controls** — `core/approval` (per ADR-014, 4-eyes for payment_action / regulator_communication) + `core/policy` (OPA/Rego engine per ADR-015 with default bundles for 6 decision points) + `core/emergency` (Redis-backed kill switches + quotas per ADR-018; ≤30s P99 propagation; fail-closed)
- [ ] **Sprint 14**: Per-tenant Helm chart + docker-compose deployment kit; bank-overlay template; operator runbook
- [ ] **Sprint 15**: End-to-end POC — extract `cognic-tool-search` + `cognic-agent-policyqa` packs from parent monorepo, install on AgentOS, run them through the full quality + adversarial gate, audit-chain verification

**Phases 1-4 deliver bank-deployable AgentOS with engineer-friendly authoring + full supply-chain attestations + runtime approval + policy engine + emergency kill switches + automated quality + adversarial gates on every pack promotion.**

## Phase 5 — AgentOS Studio (Sprints 16-21, deferred — only if demanded)

Per ADR-008 Phase B. No-code authoring UI for non-engineer users.

- [ ] **Sprint 16**: Studio API + Postgres-backed pack-definition store + compiler
- [ ] **Sprint 17**: Studio trust model (instance-key signing) + ADR-021 (drafted at Phase 5 entry; ADR-014 through ADR-020 are claimed by runtime tool approval / policy / supply chain / data governance / emergency controls / agent memory governance / UI event-stream contract)
- [ ] **Sprint 18**: Studio UI shell + tool authoring view (separate React artefact `studio-ui/`)
- [ ] **Sprint 19**: Skill composition view (drag-drop)
- [ ] **Sprint 20**: Agent authoring view (prompt + tool allow-list + sub-agent permissions)
- [ ] **Sprint 21**: Promotion workflow (dev → stage → prod, 4-eyes RBAC-gated; reuses Sprint 13 promotion-gate machinery)

## Wave 2 (post-1.0)

- [ ] **Cognic Forge** — separate repo + product for fine-tuning workflow per ADR-013 (Axolotl-driven QLoRA/LoRA/full-FT recipes, PII filter, license tracker, signing pipeline, registry-publish hook into AgentOS Sprint 9.5 API). Independent roadmap, ADRs, build plan in `bmzee/cognic-forge`.
- [ ] AGNTCY adoption (identity + observability + group communication on top of MCP+A2A)
- [ ] gVisor / Firecracker sandbox backends
- [ ] AIUC-1 mapping when schema stabilises
- [ ] EU AI Act high-risk control mapping (post-regulation finalisation)
- [ ] Multi-region active-active deployment topology
- [ ] AGNTCY identity for cross-bank federated agent calls

## Wave 3 (later)

- [ ] DPO / RLHF / RLAIF post-training in Cognic Forge
- [ ] Cross-tenant federated training (privacy-preserving)
- [ ] Model-cost reconciliation dashboard (Forge training spend + AgentOS inference spend)

## Out of scope (forever)

- Layer C agents (separate pack repos)
- Portal UI (separate artefact in parent repo)
- Per-agent workflows (ship in agent pack repos)
- Per-bank overlays (ship in bank-overlay repos)
- Anything that tools / skills / agents could ship as a pack themselves
