# Cognic AgentOS

> **Status: pre-code.** This folder holds the doctrine. Source code is built from scratch starting from these documents — no copy-over from prior repos.
>
> **Sprint 1A ready to start.** Build plan in [`docs/BUILD_PLAN.md`](docs/BUILD_PLAN.md). Project plan + execution baseline in [`docs/PROJECT_PLAN.md`](docs/PROJECT_PLAN.md).

The hardened, governance-first agent operating system for regulated banking deployments. Deployed once per bank; tools, skills, and agents install on top as separately-versioned plugin packs. Banks, the Cognic team, and the wider MCP ecosystem can author packs using the bundled SDK + CLI.

## Where to start

Read in this order. Each doc is a north-star reference; we will not write a line of code until we agree on what's here.

### 1. Strategy + product context (carried from the parent Cognic effort)

These define **what we are building and why** — they predate this repo and remain the supreme reference.

- [`docs/source-of-truth/Cognic_Master_Strategy_v5.0.md`](docs/source-of-truth/Cognic_Master_Strategy_v5.0.md) — supreme strategy
- [`docs/source-of-truth/Cognic_Enterprise_Development_Plan_v1.2_updated.md`](docs/source-of-truth/Cognic_Enterprise_Development_Plan_v1.2_updated.md) — enterprise development plan
- [`docs/source-of-truth/Cognic_AgentOps_Implementation_Guide_v5_sync.md`](docs/source-of-truth/Cognic_AgentOps_Implementation_Guide_v5_sync.md) — operational guide
- [`docs/source-of-truth/Cognic_Future_Roadmap.md`](docs/source-of-truth/Cognic_Future_Roadmap.md) — long-term direction
- [`docs/source-of-truth/Cognic_Development_Stack.md`](docs/source-of-truth/Cognic_Development_Stack.md) — tech-stack reference (LLM tier layout, providers)

### 2. Reference architecture (the SOTA target for this repo)

Synthesised from a 2026-04-26 review of Anthropic's Managed Agents pattern, MCP / A2A / AGNTCY adoption status, ISO 42001 maturity, and what JPMorgan / BlackRock / Klarna / Letta / Agno are doing in production.

- [`docs/source-of-truth/ARCHITECTURE.md`](docs/source-of-truth/ARCHITECTURE.md) — **the canonical architecture**. Read first when planning any code.
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — phase-level plan (Phases 1-4 → bank-deployable; Phase 5 Studio is deferred).
- [`docs/BUILD_PLAN.md`](docs/BUILD_PLAN.md) — **sprint-level breakdown**. Read before approving any sprint.
- [`docs/lessons/01-foundations.md`](docs/lessons/01-foundations.md) — three teaching lessons (what we are building / governance kernel / plugin protocol). Skim before reading the architecture.

### 3. Architectural decisions (immutable contracts)

Renumbered fresh from 001 — these capture every load-bearing choice we have committed to. Each ADR references which Cognic-monorepo investigation or industry source justified it.

- [`docs/adrs/ADR-001-os-only-platform.md`](docs/adrs/ADR-001-os-only-platform.md) — AgentOS as OS-only platform; tools/skills/agents are packs
- [`docs/adrs/ADR-002-mcp-plugin-protocol.md`](docs/adrs/ADR-002-mcp-plugin-protocol.md) — MCP for tool/resource discovery + invocation; entry-point + cosign for trust
- [`docs/adrs/ADR-003-a2a-inter-agent.md`](docs/adrs/ADR-003-a2a-inter-agent.md) — A2A for inter-agent communication
- [`docs/adrs/ADR-004-sandbox-primitive.md`](docs/adrs/ADR-004-sandbox-primitive.md) — ephemeral isolated execution ("hands")
- [`docs/adrs/ADR-005-subagent-primitive.md`](docs/adrs/ADR-005-subagent-primitive.md) — orchestrator-worker spawning with isolated context
- [`docs/adrs/ADR-006-iso42001-control-mapping.md`](docs/adrs/ADR-006-iso42001-control-mapping.md) — first-class compliance evidence
- [`docs/adrs/ADR-007-provider-honesty.md`](docs/adrs/ADR-007-provider-honesty.md) — runtime-audited self-hosted posture
- [`docs/adrs/ADR-008-authoring-platform.md`](docs/adrs/ADR-008-authoring-platform.md) — SDK + CLI now (Phase 2), Studio UI deferred (Phase 5)
- [`docs/adrs/ADR-009-pluggable-infrastructure-adapters.md`](docs/adrs/ADR-009-pluggable-infrastructure-adapters.md) — RDBMS / vector DB / secrets / embeddings / observability are protocol-driven; banks pick backends via `*_DRIVER` env vars; Oracle + Postgres + Dynatrace + Langfuse-OTel bundled; Chroma / AWS Secrets Manager etc. install as plugin packs
- [`docs/adrs/ADR-010-evaluation-harness.md`](docs/adrs/ADR-010-evaluation-harness.md) — bulk testing + simulated scenarios + live case replay + LLM-as-judge with explainable verdicts; promotion gate
- [`docs/adrs/ADR-011-adversarial-testing.md`](docs/adrs/ADR-011-adversarial-testing.md) — auto-generated jailbreak / prompt-injection / PII-extraction tests; pre-promotion CI gate
- [`docs/adrs/ADR-012-bank-pack-lifecycle.md`](docs/adrs/ADR-012-bank-pack-lifecycle.md) — portal API + state machine for pack draft/submit/review/approve/allow-list/install/disable/revoke/uninstall; OWASP agentic conformance gates approval
- [`docs/adrs/ADR-013-model-lifecycle.md`](docs/adrs/ADR-013-model-lifecycle.md) — Model Registry primitive in AgentOS + Cognic Forge (Wave 2 separate repo) for fine-tuning workflow; supports Axolotl / HuggingFace PEFT / Unsloth / LLaMA-Factory; nanochat is teaching reference only
- [`docs/adrs/ADR-014-runtime-tool-approval.md`](docs/adrs/ADR-014-runtime-tool-approval.md) — per-tool risk tiers (read_only → payment_action → cross_tenant); single-approval / 4-eyes / categorised-reason gates with expiry
- [`docs/adrs/ADR-015-policy-as-code.md`](docs/adrs/ADR-015-policy-as-code.md) — OPA / Rego bundles for pack admission, model routing, tool approval, sandbox egress, sub-agent spawn, lifecycle transitions
- [`docs/adrs/ADR-016-supply-chain-controls.md`](docs/adrs/ADR-016-supply-chain-controls.md) — cosign + SLSA L3+ provenance + in-toto layout + SBOM + vuln scan + license audit + 7-year Sigstore bundle retention
- [`docs/adrs/ADR-017-data-governance-contracts.md`](docs/adrs/ADR-017-data-governance-contracts.md) — pack manifest declares data classes, purpose, retention, egress allow-list, DLP hooks, consent requirements; trust gate enforces
- [`docs/adrs/ADR-018-emergency-controls.md`](docs/adrs/ADR-018-emergency-controls.md) — kill switches (pack/tool/model/tenant/cloud/feature) + quotas (tokens/spend/invocations/recursion); ≤30s P99 propagation; fail-closed
- [`docs/adrs/ADR-019-agent-memory-governance.md`](docs/adrs/ADR-019-agent-memory-governance.md) — governed memory API (remember/recall/forget/redact/export); three tiers; default-deny long-term; regulator-erasure pathway
- [`docs/adrs/ADR-020-ui-event-stream-contract.md`](docs/adrs/ADR-020-ui-event-stream-contract.md) — UI event-stream contract (AG-UI-equivalent): typed events for run state, tool calls, sub-agent, approvals, interrupts, artifacts, frontend actions; SSE default; reconnect-safe via decision_history mirror
- ADR-021 reserved for Studio trust model (Phase 5, deferred)

Conformance references: [`docs/MCP-CONFORMANCE.md`](docs/MCP-CONFORMANCE.md), [`docs/A2A-CONFORMANCE.md`](docs/A2A-CONFORMANCE.md)

### 4. Working rules (for humans + Claude Code sessions)

- [`AGENTS.md`](AGENTS.md) — operating model, what lives where, critical-controls list, stop rules
- [`CLAUDE.md`](CLAUDE.md) — Claude Code project memory; plugin/OS boundary discipline; the production-grade rule

## What this folder is NOT

- Not the source code yet. There is no `src/` here. All code is built from scratch using these docs as the contract.
- Not the parent Cognic monorepo (`bmzee/cognic`) — that continues hosting the legacy bundled monolith + agents + UI until the plugin migration completes.

## What we will NOT add to this folder

The core principle is the same as the eventual code repo:

- **No agents.** They are separate `cognic-agent-<name>` pack repos.
- **No UI.** Separate artefact.
- **No bank-specific overlays.** Separate bank-overlay repos.
- **No Layer A tools or Layer B skills bundled here.** They ship as MCP server packs.

If a contributor wants to add any of the above, they're working in the wrong folder.

## Build sequence

Sprint-level detail in [`docs/BUILD_PLAN.md`](docs/BUILD_PLAN.md). Phase summary:

| Phase | Sprints | Delivers |
|---|---|---|
| **1 Foundation** | 1A/1B/1C/1D + 2 + 3 | Bootstrap → observability → adapters → enterprise adapters → governance primitives → LLM gateway. |
| **2 Protocol + SDK + Pack Lifecycle** | 4, 5, 6, 7A, 7B | MCP host (Streamable HTTP + OAuth/PRM; STDIO restricted) + A2A endpoint (Agent Cards, streaming, artifacts) + `agentos-cli` SDK with full conformance + governance validation + bank-pack lifecycle portal API with reviewer evidence panels. Trust gate enforces full supply-chain attestation set. |
| **3 Sandbox (with Resumable Sessions) + Compliance + Model Lifecycle** | 8, 8.5, 9, 9.5, 10 | Bank-grade isolation with `checkpoint() / suspend() / wake()`; ISO 42001 evidence-pack export; Model Registry primitive (Forge ships in Wave 2). |
| **4 Sub-agent + Memory Governance + Quality Gates + Policy + Kill Switches + Deploy** | 11, 11.5, 12, 13, 13.5, 14, 15 | Bank-deployable. Sub-agent + governed agent memory (per ADR-019, three tiers, default-deny long-term, regulator-erasure pathway) + eval harness + adversarial testing + runtime tool approval (4-eyes for payments) + OPA/Rego policy engine + Redis-backed kill switches with ≤30s P99 propagation. End-to-end POC with extracted PolicyQA pack. |
| **5 Studio (deferred)** | 16-21 | No-code authoring UI. Only built if explicitly demanded. |

Each sprint ships independently with green tests, an exit-criteria checklist, and a checkpoint summary. Phases 1-4 (~52.5 work-units / 18-22 calendar weeks) deliver the bank-deployable platform. **52.5 wu is the disciplined lower bound across seven sprints already flagged as optimistic (1D, 5, 7A, 7B, 9.5, 11.5, 13.5) — see BUILD_PLAN.md "Schedule-risk acknowledgement" + "Treat 52.5 wu as a disciplined lower bound" for the realistic midpoint (~57 wu / 20-25 calendar) and ceiling (~62.5 wu / 24-29 calendar) ranges. Quote the floor for internal velocity tracking; quote mid or ceiling for any external commitment.** Phase 5 Studio (deferred) adds ~13 work-units / +5-6 calendar weeks if pursued. Cognic Forge (fine-tuning workflow) is a separate Wave 2 product (per ADR-013), not part of the AgentOS calendar.

See [`docs/BUILD_PLAN.md`](docs/BUILD_PLAN.md) for the authoritative sprint sheet — that's the source of truth for work-unit accounting; this README summary is derived from it.
