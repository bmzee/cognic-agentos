# Cognic AgentOS — Foundational Lessons

> Read these in order. Each is a self-contained mental model. Together they teach what AgentOS is, what it does at runtime, and how plugins extend it without touching the kernel.

---

## Lesson 1 — What we are building

### One-line definition

**Cognic AgentOS is the bank's "operating system" for AI agents.** It runs in the bank's own data centre, governs every agent action, and lets the bank install / swap / remove agents the way a phone installs apps — without ever touching the OS itself.

### The mental model

```
┌──────────────────────────────────────────────────┐
│   Cognic AgentOS  (we build this. once. hardened)│
│   = governance kernel + runtime + protocol layer │
└──────────────────────────────────────────────────┘
                 ▲          ▲          ▲
                 │ MCP/A2A  │          │
        ┌────────┘          │          └────────┐
        │                   │                   │
   ┌────┴────┐         ┌────┴────┐         ┌────┴────┐
   │  Tool   │         │  Agent  │         │  Skill  │
   │  pack   │         │  pack   │         │  pack   │
   │ (search)│         │(PolicyQA)│        │  (KYC)  │
   └─────────┘         └─────────┘         └─────────┘
   built by Cognic, banks, or the wider MCP ecosystem
```

### Three layers, three lifetimes

| Layer | Who builds | Who deploys | How often it changes |
|---|---|---|---|
| **AgentOS** (this) | Cognic | Bank installs once | Slow — kernel-level only |
| **Packs** (agents/tools/skills) | Cognic + banks + ecosystem | Bank picks à la carte | Fast — independent versioning |
| **UI portal** | Cognic | Separate artefact | Independent of OS |

### Three jobs AgentOS does for a bank

1. **Governance** — every agent action is audited, RBAC-gated, citation-verified, SLA-tracked, and recorded in a tamper-evident hash chain. Examiners can prove what happened and which regulation it satisfied.
2. **Runtime** — provides the **harness** (the loop every agent runs inside), the **LLM gateway** (cloud-policy enforced), the **sandbox** (isolated execution), and the **sub-agent primitive** (delegation between agents).
3. **Protocol** — speaks **MCP** (industry standard for tools, 97M installs by April 2026) and **A2A** (industry standard for agent-to-agent calls, 150+ orgs in production). Banks can install third-party MCP tools or write their own.

### What makes Cognic different from existing systems

| Comparable system | What it gives | What Cognic adds |
|---|---|---|
| **Anthropic Managed Agents** | Hosted runtime (their cloud) | Bank-self-hosted; ISO 42001 evidence; tamper-evident audit |
| **Letta / Agno** | Runtime + memory model | Bank-grade governance superset; cloud-policy enforcement; per-tenant trust gate |
| **LangGraph** | Multi-agent orchestration | Protocol standards (MCP + A2A) so packs are interoperable |

### What we will NOT build

- **Agents** — Layer C, separate `cognic-agent-<name>` repos
- **UI** — separate artefact
- **Tools / Skills** — separate `cognic-tool-*` / `cognic-skill-*` repos as MCP servers
- **Bank overlays** — themes, OIDC, custom CBS adapters live in bank-overlay repos

### The "why" — in one sentence

We are building the **trust layer** every banking AI deployment needs but no off-the-shelf project provides; everything that *can* be a plugin *should* be a plugin, so the bank's procurement, audit, and operational risk all converge on a small auditable kernel that doesn't change often.

---

## Lesson 2 — The governance kernel (what runs when an agent acts)

This is the heart of AgentOS. Every Layer C agent — whether it's PolicyQA from Cognic or a custom agent the bank wrote — runs inside one fixed loop. The agent author cannot opt out of any step.

### The harness execute loop

```
┌─────────────────────────────────────────────────────────────────┐
│  Agent.execute(input) — every step is audited                   │
│                                                                 │
│  1. guardrail_pre(input)        → block PII, injection, off-topic│
│  2. retrieval.fetch(query)      → hybrid (BM25 + dense + rerank) │
│  3. citation_verifier.verify    → confirm sources are real      │
│  4. gateway.completion(messages)→ LLM call (cloud-policy gated) │
│  5. guardrail_post(output)      → block leak, profanity, harm   │
│  6. citation_verifier.verify    → confirm output cites sources  │
│  7. compliance_checker.score    → regulatory / factual / quality │
│  8. decision_history.append     → hash-chained, Merkle-rooted   │
│  9. auto_degradation.evaluate   → if low confidence → escalate  │
│ 10. escalation.route            → reviewer queue (RBAC-scoped)  │
└─────────────────────────────────────────────────────────────────┘
```

### Why each step exists

| Step | Why it cannot be removed | ISO 42001 control |
|---|---|---|
| `guardrail_pre` | Stops bad input from ever reaching the LLM (cost, attack surface, content policy) | A.6.2.6, A.7.4 |
| `retrieval` | Grounds every answer in real KB; banks demand citations | A.8.2 |
| `citation_verifier` (twice) | Confirms cited sources actually exist; blocks hallucinated citations | A.8.2, A.8.5 |
| `gateway.completion` | Single chokepoint for LLM calls; enforces `ALLOW_EXTERNAL_LLM` policy; tier alias resolution; concurrency cap | A.8.5 |
| `guardrail_post` | Last line of defence before output reaches user | A.6.2.6 |
| `compliance_checker` | Scores output on regulatory / factual / quality dimensions; threshold breach → escalation | A.7.6 |
| `decision_history.append` | Tamper-evident record of every decision; chain-hashed | A.9.2 |
| `auto_degradation` | When confidence drops, downgrade workflow before customer sees a bad answer | A.7.6 |
| `escalation` | Routes to reviewer with RBAC-scoped queue; reviewer hand-off lifecycle | A.6.2.5 |

### The chain hash invariant

Every `decision_history` row references the previous row's hash. The chain verifier walks the chain to prove no row was inserted, deleted, or re-ordered. Examiners can verify the bundle independently of AgentOS — the proof is mathematical, not procedural.

### Where plugins fit

- **Tools** are called *during* step 2 (retrieval) and step 4 (LLM tool calls) — through the MCP host
- **Sub-agents** are spawned *during* step 4 — through the A2A endpoint
- **Sandbox** wraps any tool that runs untrusted code or processes documents
- **Compliance evidence** is emitted *automatically* at every step; agent author writes nothing

The agent's job is the **prompt + the tool choices**. Every governance concern is the kernel's job. This separation is why a bank can install a third-party agent without auditing its governance — the kernel guarantees it.

---

## Lesson 3 — The plugin protocol (how new tools and agents install)

### The four mechanisms

| Mechanism | Role |
|---|---|
| **Python entry points** | Discovery — packs declare themselves in `pyproject.toml` |
| **MCP (Model Context Protocol)** | Invocation — how AgentOS calls a tool inside an installed pack |
| **A2A (Agent2Agent)** | Communication — how an agent calls another agent |
| **Cosign + per-tenant allow-list** | Trust — only signed, allow-listed packs register |

### How a pack is structured

```
cognic-tool-search/                  ← one repo per pack
├── pyproject.toml
│   [project.entry-points."cognic.tools"]
│   search_circulars = "cognic_tool_search:SearchCircularsTool"
├── src/cognic_tool_search/
│   ├── __init__.py
│   └── server.py                    ← MCP server (stdio or HTTP)
├── Dockerfile
└── .github/workflows/release.yml    ← cosign signing in CI
```

### What happens at AgentOS startup

```
1. plugin_registry.discover()
   └─→ importlib.metadata.entry_points(group="cognic.tools")
       └─→ found: cognic-tool-search 0.4.0

2. trust_gate.verify(pack)
   ├─→ cosign verify --key vault://tenant/trust-root
   └─→ allow_list.contains("cognic-tool-search")?  ✓ register

3. mcp_host.connect(pack)
   ├─→ open stdio session to cognic_tool_search.server
   ├─→ list_tools()  → ["search_circulars"]
   └─→ register tool descriptor + JSON schema
```

After startup, the OS knows: "I have one tool called `search_circulars` provided by `cognic-tool-search:0.4.0`, signed digest `sha256:abc...`, on the allow-list of tenant `bank-acme`."

### Worked example: bank adds their own CBS tool

A bank wants their AgentOS to query their core banking system. Cognic doesn't ship a CBS-Acme adapter. Steps:

1. Bank engineer writes `cognic-tool-cbs-acme` repo with an MCP server exposing `query_account_balance(customer_id) -> Balance`
2. CI signs the wheel with the bank's cosign key (key kept in their Vault)
3. Bank's AgentOS instance has the bank's cosign root configured
4. Bank ops adds `cognic-tool-cbs-acme` to the per-tenant allow-list (`secret/cognic/bank-acme/plugin-allowlist`)
5. Bank deploys the wheel into the AgentOS pod (or via a sidecar container)
6. AgentOS restart → `discover()` picks it up → `trust_gate.verify()` passes → tool registers
7. Any agent on this AgentOS can now call `query_account_balance` — every call is audited

**No Cognic involvement. No AgentOS code change. No agent code change.** Bank-side extensibility is the whole point.

### How sub-agent spawning works (A2A flavour of the same pattern)

```
┌─ RM Copilot agent (pack: cognic-agent-rm-copilot) ───────┐
│                                                          │
│  while drafting customer brief, LLM decides:             │
│  "I need an AML check on this customer"                  │
│                                                          │
│  harness.spawn_subagent(                                 │
│    target_agent="aml_investigation",                     │
│    capability="verify_customer",                         │
│    payload={"customer_id": "...", "summary": "..."},     │
│    policy=SubAgentPolicy(                                │
│      max_token_budget=4000,                              │
│      tool_allow_list=["sanction_screen"],   ← narrower   │
│    ),                                                    │
│  )                                                       │
└───────────────────────┬──────────────────────────────────┘
                        │ A2A message
                        ▼
            ┌─────────────────────────────────┐
            │  AgentOS A2A endpoint           │
            │  ├─ resolve target via registry │
            │  ├─ enforce privilege ⊆ parent  │
            │  ├─ open child session          │
            │  ├─ chain-hash to parent        │
            │  └─ dispatch to AML pack        │
            └────────────────┬────────────────┘
                             │
                             ▼
                ┌──────────────────────────┐
                │  AML pack runs in own    │
                │  context window, returns │
                │  result + audit chain    │
                └──────────────────────────┘
```

The parent's context window stays small. The audit chain is complete. The child cannot escalate beyond the parent's privileges.

### Why this design wins

- **Banks extend AgentOS without forking it** — write a pack, register it, done
- **Adding agent #10 doesn't redeploy AgentOS** — independent pack lifecycle
- **Procurement audit is per-pack** — bank legal signs off `cognic-tool-search:0.4.0` once and never looks at the source again until the version bumps
- **Industry interop** — any MCP tool from the wider ecosystem (97M installs) works on Cognic AgentOS unchanged

---

## What you now know

After these three lessons you can answer:

- *What is Cognic AgentOS?* — the trust layer + runtime that lets a bank install AI agents safely
- *What runs when an agent acts?* — a 10-step governed loop the agent author cannot bypass
- *How does a new agent or tool install?* — pack manifest + entry point + cosign + allow-list, then the registry discovers it
- *Why is this different from LangGraph / Letta / Anthropic Managed Agents?* — Cognic adds the bank-grade governance superset; it doesn't replace the runtime patterns, it builds on them

Next reading order when you're ready to plan implementation:

1. [`docs/PROJECT_PLAN.md`](../PROJECT_PLAN.md) — execution baseline (5 workstreams + 5 phases + bank-pack enablement)
2. [`docs/source-of-truth/ARCHITECTURE.md`](../source-of-truth/ARCHITECTURE.md) — the canonical reference architecture
3. [`docs/BUILD_PLAN.md`](../BUILD_PLAN.md) — sprint-level breakdown (authoritative for sprint execution)
4. [`docs/ROADMAP.md`](../ROADMAP.md) — phase-level checklist
5. The 20 ADRs in [`docs/adrs/`](../adrs/) — every load-bearing decision (ADR-001 OS-only; 002 MCP + STDIO threat model + OAuth/PRM (with WWW-Authenticate + step-up + audience validation) + AGNTCY/OASF identity; 003 A2A + Wave 1 feature scope + version negotiation + protobuf canonical model + signed Agent Cards; 004 sandbox + resumable sessions; 005 sub-agent; 006 ISO 42001; 007 provider honesty; 008 authoring platform; 009 pluggable adapters; 010 eval harness; 011 adversarial testing; 012 bank pack lifecycle; 013 model lifecycle + fine-tuning boundary; 014 runtime tool approval; 015 policy-as-code; 016 supply-chain controls; 017 data governance contracts; 018 emergency controls; 019 agent memory governance; 020 UI event-stream contract). Plus [`docs/MCP-CONFORMANCE.md`](../MCP-CONFORMANCE.md) and [`docs/A2A-CONFORMANCE.md`](../A2A-CONFORMANCE.md) for protocol feature matrices.
