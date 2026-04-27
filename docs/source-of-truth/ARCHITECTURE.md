# Cognic AgentOS — Canonical Architecture

**Status:** Foundational (revision 1, 2026-04-26)
**Supersedes:** the cognic monorepo's mixed OS+agents+UI layout

Cognic AgentOS is the hardened, governance-first agent operating system that banks deploy once and run forever. Its job is to host **trust-bearing controls** that plugin packs cannot bypass. Tools, skills, and agents install on top as separately-versioned packs.

## 1. Reference architecture

Inspired by Anthropic's Managed Agents pattern (April 2026) — three virtualised primitives + protocol layer + governance kernel + authoring platform (per ADR-008).

```
┌──────────────────────────────────────────────────────────────────┐
│ AgentOS (deployed once per bank, single-tenant)                  │
│                                                                  │
│ Protocol layer (industry standards):                             │
│   • MCP host           — tool / resource discovery + invocation  │
│   • A2A endpoint       — inter-agent communication               │
│   • Plugin registry    — entry-point discovery + cosign verify   │
│                                                                  │
│ Governance kernel (the trust boundary — never plugin):           │
│   • Audit (append-only, hash-chained, Merkle-rooted)             │
│   • Decision history + chain verifier                            │
│   • Guardrails (PII, injection, content policy)                  │
│   • Citation verifier                                            │
│   • RBAC (role × scope vocabulary)                               │
│   • Cloud-policy enforcer                                        │
│   • Auto-degradation                                             │
│   • SLA enforcement                                              │
│   • Escalation lifecycle                                         │
│   • Plugin trust gate (signature + per-tenant allow-list)        │
│                                                                  │
│ Runtime primitives:                                              │
│   • Harness — governed execute loop                              │
│   • LLM gateway — tier alias + concurrency + policy              │
│   • Sandbox — ephemeral isolated execution ("hands")             │
│   • Sub-agent — orchestrator-worker spawning                     │
│   • Temporal worker — long-running workflows                     │
│   • LangGraph composed flows — multi-agent choreography          │
│                                                                  │
│ Persistence: Postgres + Qdrant + S3/MinIO                        │
│ Observability: OpenTelemetry + Langfuse + Prometheus + SIEM      │
│ Channels: email (Wave 1), Slack/Teams (Wave 2)                   │
│ Portal API + Workbench DTOs + RBAC vocabulary                    │
│                                                                  │
│ Compliance evidence:                                             │
│   • ISO 42001 control-mapping registry                           │
│   • AIUC-1 audit-hook conformance                                │
│   • Tamper-evident decision chain (Merkle root)                  │
│   • SBOM + cosign verification per installed pack                │
│                                                                  │
│ Authoring platform (per ADR-008):                                │
│   • SDK + agentos-cli — scaffolding, signing, registration       │
│   • Studio UI (Phase 5, deferred) — no-code pack composition     │
└──────────────────────────────────────────────────────────────────┘
        ▲ MCP / A2A boundary (versioned, signed, allow-listed)
        │
   ┌────┴────────────┬────────────────┬─────────────────┐
   │                 │                │                 │
┌──┴───────┐  ┌──────┴──────┐  ┌──────┴───────┐ ┌──────┴──────┐
│ Tool MCP │  │ Skill MCP   │  │ Agent Pack   │ │ Portal UI   │
│ Servers  │  │ Servers     │  │ (A2A-speak)  │ │ (separate   │
│          │  │             │  │              │ │  artefact)  │
│ Each is  │  │ Each is     │  │ Each is      │ │             │
│ its own: │  │ its own:    │  │ its own:     │ │ Already     │
│ ─ pkg    │  │ ─ pkg       │  │ ─ pkg        │ │ shipped as  │
│ ─ image  │  │ ─ image     │  │ ─ image      │ │ Docker img  │
│ ─ SBOM   │  │ ─ SBOM      │  │ ─ SBOM       │ │             │
│ ─ cosign │  │ ─ cosign    │  │ ─ cosign     │ │             │
│ ─ semver │  │ ─ semver    │  │ ─ semver     │ │             │
└──────────┘  └─────────────┘  │ + per-agent  │ └─────────────┘
                               │   workflow   │
                               │ + per-agent  │
                               │   UI panel   │
                               └──────────────┘
```

## 2. The three deployment artefacts

| Artefact | Cadence | Repo |
|---|---|---|
| `cognic-agentos:1.x` | Slow — kernel changes only | this repo |
| `cognic-tool-<name>:0.x`, `cognic-skill-<name>:0.x`, `cognic-agent-<name>:0.x` | Fast — independent per pack | one repo per pack |
| `cognic-portal-ui:1.x` | Independent | parent cognic repo / future split |

Adding a new agent, tool, or skill **does not require redeploying AgentOS**. The plugin registry discovers the new pack at next AgentOS restart (or hot-reloads it in Wave 2).

## 3. Protocol choices

| Concern | Standard | Why |
|---|---|---|
| Tool / resource discovery + invocation | **MCP** (Model Context Protocol, Anthropic Nov 2024) | 97M+ installs by April 2026, adopted by Anthropic, OpenAI, Google DeepMind, Microsoft, Cloudflare, Salesforce, ServiceNow. De facto standard. |
| Inter-agent communication | **A2A** (Agent2Agent, Google → Linux Foundation, April 2025) | 150+ orgs in production by April 2026, deep integration on Google/Microsoft/AWS clouds. |
| Identity + observability + group communication | **AGNTCY** (Cisco → Linux Foundation) | Combines A2A + MCP + identity. Wave 2 adoption candidate. |
| Compliance framework | **ISO/IEC 42001:2023** + **AIUC-1** | ISO 42001 is the AI Management System gold standard; AIUC-1 is agent-specific auditable framework. |

We adopt these standards rather than invent Cognic-specific protocols. Forward-compatible by construction.

## 4. The "brain vs hands" decoupling (per Anthropic Managed Agents)

Three virtualised primitives — each swappable without disturbing the others:

| Primitive | Cognic target implementation | Sprint that lands it |
|---|---|---|
| **Session** — append-only event log | `core/decision_history` + `core/chain_verifier` (hash-chained — stronger than Anthropic's plain append-only) | Sprint 2 |
| **Harness** — thin loop that calls model + routes tool calls | `harness/base_agent.py` + `core/harness.py` | Sprint 2-3 |
| **Sandbox** — ephemeral isolated execution | `sandbox/` per ADR-004 | Sprint 8 |

Plus orchestrator-worker spawning:

| Primitive | Cognic target implementation | Sprint that lands it |
|---|---|---|
| **Sub-agent** — dynamic spawn, isolated context, allow-list narrow-down | `subagent/` per ADR-005 | Sprint 11 |

> **Repo state today:** pre-code. None of the modules above exist as source yet. The doctrine in `docs/`, ADRs, and BUILD_PLAN.md fully specify the contracts; first source code lands in Sprint 1A.

## 5. Governance is the differentiator

Where Anthropic Managed Agents and Letta and Agno provide the runtime, **Cognic adds the governance superset** banks need:

- Hash-chained, Merkle-rooted decision history (tamper-evident)
- ISO 42001 control mapping per governance hook
- AIUC-1 conformance evidence
- Per-tenant single-tenant deployment (regulatory data residency)
- Bank-side OIDC / SSO integration
- Per-tenant plugin allow-list with cosign signature verification
- Cloud-policy enforcer (`ALLOW_EXTERNAL_LLM` gate enforced at the gateway, not just configured)
- RBAC vocabulary mirroring backend Brick 96 (role × scope, server-enforced)
- Citation verifier (every cited source verified against the indexed KB)
- Auto-degradation (confidence-band-driven workflow downgrade)
- Escalation lifecycle (reviewer hand-off with state machine)

Anthropic's pattern is the architecture; Cognic's value is the governance superset.

## 6. Layering rules

| Boundary | Rule |
|---|---|
| OS → Plugin pack | OS imports nothing pack-specific. Discovery + invocation always via plugin registry. |
| Pack → OS | Pack may freely use any OS-tier API (`cognic_agentos.core.*`, `cognic_agentos.protocol.*`, etc.). |
| Pack → Pack | Only via A2A. No direct Python imports across packs. |
| UI → AgentOS | Only via versioned HTTP API. UI generates `api.ts` from the FastAPI OpenAPI spec; CI fails on drift. |
| Bank overlay → AgentOS | Bank ships their own MCP server packs for CBS adapters; AgentOS discovers them via the registry. |

Enforcement: CI test `tests/unit/architecture/test_no_pack_imports.py` (to be authored — replaces parent repo's `test_os_agent_separation.py`).

## 7. Build sequence (pre-code today; first source lands Sprint 1A)

The authoritative sprint sheet is `docs/BUILD_PLAN.md`. High-level phases:

- **Phase 1 — Foundation** (Sprints 1A → 1B → 1C → 1D → 2 → 3): bootstrap, observability, adapter protocols, enterprise adapters, governance primitives, LLM gateway. ~12 work-units.
- **Phase 2 — Protocol layer + SDK + Pack Lifecycle + UI Event-Stream** (Sprints 4 → 5 → 6 → 7A → 7B): plugin registry + trust gate (cosign + SLSA + supply-chain attestation set) + minimal `core/policy` Rego seed, MCP host (Streamable HTTP first with OAuth/PRM via WWW-Authenticate + step-up + audience validation; STDIO restricted), A2A endpoint (AgentCards validated against upstream A2A 1.0 schema then AgentOS bank-grade profile + JWS signatures + version negotiation + protobuf canonical model), UI event-stream stub + SSE endpoints + frontend-action POST per ADR-020, SDK + CLI with full conformance/governance validators, bank-pack lifecycle portal API with reviewer evidence panels. ~14.5 work-units.
- **Phase 3 — Sandbox + Compliance + Model Lifecycle + Resumable Sessions** (Sprints 8 → 8.5 → 9 → 9.5 → 10): sandbox primitive with session/checkpoint/snapshot API, ISO 42001 control mapping + evidence-pack export, Model Registry primitive, Vault credential leasing. ~10 work-units.
- **Phase 4 — Sub-agent + Memory Governance + Quality Gates + Policy + Kill Switches + Deploy** (Sprints 11 → 11.5 → 12 → 13 → 13.5 → 14 → 15): sub-agent primitive, agent memory governance (per ADR-019), evaluation harness (per ADR-010), adversarial testing (per ADR-011), policy-as-code engine + runtime tool approval + kill switches (ADR-014/015/018), per-tenant deployment kit, end-to-end POC. ~16 work-units.
- **Phase 5 — Studio (deferred)**: only if banks demand non-engineer authoring UI.

All claims of "shipped" or "done" elsewhere in this doc are aspirational targets; nothing has been implemented yet.

## 8. Translation notes for inherited Master Strategy / EDP / AgentOps Guide

These three legacy product docs predate the OS-only doctrine and contain claims that, read literally, would put non-OS code inside this repo. The PROJECT_PLAN.md §2 translation rule resolves them; the most-frequently-cited cases are listed here for clarity.

### 8.1 "AI Governance Agent" (Master Strategy lines 77, 966, 1253, 1403, 1466)

Master Strategy describes an "AI Governance Agent" that monitors agent accuracy, audits tool calls, and enforces authority compliance. **Do not implement this as a Layer C LLM agent inside AgentOS.** The capability splits into two pieces:

| Master Strategy capability | AgentOS-repo placement |
|---|---|
| Automated accuracy monitor + auto-degradation when rolling 7-day accuracy drops below threshold | **Deterministic platform monitor in `core/auto_degradation.py`** (not an agent — no LLM call). Sprint 2. |
| Audit of agent tool-call patterns for prohibited categories | **Deterministic guardrail + audit hook** (`core/guardrails.py` + `core/audit.py`). Sprint 2. |
| Authority-level compliance enforcement (block actions outside authority scope) | **Deterministic RBAC check** in the harness execute loop, fed by the workforce-identity record. Sprint 2-3. |
| Periodic compliance reporting + KPI dashboards (an LLM job that surfaces governance findings) | **Separate `cognic-agent-ai-governance` plugin pack** (Layer C, ships outside this repo per ADR-001/ADR-002). Bank installs if they want LLM-driven governance reporting. |

The trust-bearing controls (degradation, guardrails, RBAC) MUST be deterministic platform code, not an LLM agent — an LLM-bearing component can hallucinate the verdict, degrading the audit chain. The reporting / summarisation / narrative-generation layer can be an agent pack because it consumes already-deterministic governance data and produces human-facing prose.

### 8.2 Vector store default (Master Strategy line 725)

See ADR-009 §"Translation note vs Master Strategy v5.0 §4 line 725" for the Qdrant vs pgvector resolution.

### 8.3 `src/cognic/` source layout (multiple inherited docs)

See the banner at the top of `Cognic_Development_Stack.md`. AgentOS uses `src/cognic_agentos/`; UI is a separate artefact; agents/tools/skills are external plugin packs.

## 9. What this repo deliberately omits

- Layer C agents (separate pack repos)
- UI (separate artefact)
- Per-agent workflows (ship with the agent pack)
- Per-agent eval scorers (ship with the agent pack)
- Bank-specific overlays (ship as bank-overlay repos)

If a contributor wants to add any of the above, they're working in the wrong repo.

---

Source materials:
- [Anthropic — Scaling Managed Agents: Decoupling brain from hands](https://www.anthropic.com/engineering/managed-agents)
- [Model Context Protocol — 2026 roadmap](https://blog.modelcontextprotocol.io/posts/2026-mcp-roadmap/)
- [A2A Protocol — 150+ orgs in production](https://www.prnewswire.com/news-releases/a2a-protocol-surpasses-150-organizations-lands-in-major-cloud-platforms-and-sees-enterprise-production-use-in-first-year-302737641.html)
- [ISO/IEC 42001:2023 — AI Management Systems](https://www.iso.org/standard/42001)
- [Letta — Rearchitecting the Agent Loop](https://www.letta.com/blog/letta-v1-agent)
- [Agno — AgentOS](https://www.agno.com/)
