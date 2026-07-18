# M6 — Governed Agent Skill proof — design spec
<!-- STATUS: HISTORICAL -->
<!-- OWNER: cognic-agentos maintainers -->
<!-- LAST-VERIFIED: 2026-07-18 -->

**Status:** DESIGN — brainstormed + decisions locked with the maintainer (2026-07-02); pending spec review, then implementation plan.

**Milestone:** merges the checklist's **M6 (executable skill service)** + **M7 (Agent Skills `SKILL.md` hosting, ADR-025)** into one shape — **"Governed Agent Skill proof."** The public product noun becomes **`Skill = SKILL.md package`** (the open agentskills.io standard); the deterministic executable primitive (`sdk/skill.py`) is repositioned as the **governed action substrate** *inside* a skill, not a competing "skill" concept.

**Kernel provenance for the pack:** `cognic-agentos@<tag>` (author/CI-time only; the runtime skill pack carries no kernel runtime dependency, mirroring the tool/hook pack model).

---

## 1. Motivation — the gap the SOTA names, and the gap AgentOS fills

By mid-2026 the Agent Skills (`SKILL.md`) format is the de-facto open standard — Anthropic-originated, adopted by OpenAI Codex, Microsoft's Agent Framework, and 8+ marketplaces (Skills.sh/Vercel, Agensi, SkillsMP indexing 350k+ crawled skills). "Agent Skills are the new npm."

A `SKILL.md` skill is a **folder of instructions for an LLM agent**, not runnable code: a required `SKILL.md` (YAML frontmatter `name` + `description`, then a Markdown instructions body) plus optional `scripts/`, `references/`, `assets/`. When a task matches the `description`, the agent reads the instructions into context (progressive disclosure, ~5k-token body ceiling; references loaded on demand) and, when told to, runs a bundled script and reads back its output.

The standard's security model is **"trust delegated to the client."** Every practitioner guide and the formal threat-model literature converges on the same warning — *treat every skill as an untrusted dependency: audit the `SKILL.md` before installing, run skills in sandboxed environments, rotate any credentials the skill touches* — and names runtime trust, sandbox granularity (per-skill / per-session / per-tier), and **composition risk** as open problems (Skilldex; Towards Secure Agent Skills; AgentTrap; SoK: Agentic Skills; the safedep Agent Skills Threat Model).

**That warning is AgentOS's product.** Every mitigation the ecosystem tells the operator to do by hand, AgentOS already has as a first-class primitive:

| Ecosystem advice (do it yourself) | AgentOS primitive |
|---|---|
| "audit the `SKILL.md` before installing" | cosign-signed packs + SLSA/SBOM/in-toto attestations + trust-register gate (M3–M5) |
| "run skills in a sandboxed environment" | the ADR-004 sandbox (docker-sibling / kubernetes-pod, `--network none` + egress proxy) |
| "rotate any credentials the skill touches" | no ambient credentials; the executor's only egress is a broker that routes through `MCPHost.call_tool` (OAuth / approval / DLP) |
| (nothing) | hash-chain audit at both the instruction and execution layers |

**Differentiator:** the skill stays the portable open `SKILL.md` standard — the same skill an agent uses anywhere — but AgentOS converts *"trust delegated to the client"* into **cryptographically-trusted, sandboxed, tool-scoped, audited execution.** No marketplace offers this. This is the bank-grade "Governed Agent Skill."

---

## 2. Vocabulary — the naming decision (locked)

- **Skill (public noun) = a `SKILL.md` package.** The agentskills.io-standard folder, shipped as a signed `cognic-skill-*` pack. This is what an agent (M8) discovers, is assigned, and reads.
- **Executable action = the governed runtime primitive inside a skill.** The repositioned `sdk/skill.py::Skill.execute()` — deterministic, no-LLM tool composition with a `declared_tools` contract. It is *not* "the skill"; it is *one governed implementation* of a skill's runnable behavior. Public docs stop calling it "executable skill."
- This resolves the collision the maintainer flagged: the industry has exactly one meaning of "skill" (`SKILL.md`), and AgentOS now matches it. The deterministic composer keeps its value (auditable, no LLM variance — ideal for banking) but at its correct layer.

The 6-way pack vocabulary is amended: "instruction skill" and "executable skill service" collapse into a single **skill** kind (`SKILL.md` package with an optional governed action). Workflow (15A engine) and agent packs stay distinct.

---

## 3. Architecture — five components, one enforcement chain

```text
Agent (M8, later) reads SKILL.md
  ↓  decides to invoke the skill's capability
AgentOS skill-invocation endpoint  (portal route; deterministic caller for THIS milestone)
  ↓
Governed executor  — runs the skill's executable action in the ADR-004 sandbox
  │   (no general network, no ambient credentials, isolated filesystem)
  ↓  narrow non-network IPC (Unix domain socket)
Skill-execution broker / tool adapter
  │   enforces declared_tools (runtime, per call — not just admission)
  ↓
MCPHost.call_tool  →  OAuth / approval / DLP / audit  →  governed external MCP tool
```

The five components:

1. **Skill pack** (`cognic-skill-*`, external repo): a cosign-signed wheel bundling the `SKILL.md` folder + the executable action + a manifest declaring `declared_tools` + the standard attestations. §6.
2. **Hosting / ingestion** (kernel; ADR-025): validate the `SKILL.md` shape, trust-register the pack through the existing plugin-registry gate (skills are already the `cognic.skills` registrable kind), make it discoverable/assignable. §7.
3. **Governed executor + broker** (kernel; the core new surface): run the executable action **fully sandboxed**; mediate every tool call through the broker, which enforces `declared_tools` and routes to `MCPHost.call_tool`. §5.
4. **Skill-invocation endpoint** (portal): a governed route that runs a skill's executable action for a tenant/actor. For this milestone the caller is deterministic (a test/proof driver); the LLM agent that reads `SKILL.md` and *decides* to call is **M8**.
5. **Evidence**: hash-chain rows at both layers — instruction (pack trust-registered, `SKILL.md` ingested/assignable) and execution (executor ran sandboxed, each broker-mediated `call_tool` audited, any undeclared attempt refused).

---

## 4. Decisions locked (maintainer, 2026-07-02)

- **D1 — full sandbox from the start.** The executable action runs isolated in the ADR-004 sandbox with **no general network** and **no ambient credentials**. Its only tool access is a narrow AgentOS-mediated channel (the broker) that ultimately calls `MCPHost.call_tool`. Not "in-kernel first, harden later" — signed code is necessary but not sufficient for a bank-grade story.
- **D2 — defer the real LLM agent to M8.** This milestone proves skill **hosting + governed executable action + declared-tool enforcement + dual-layer audit** by invoking the action through a governed endpoint (deterministic, no LLM variance). M8 proves an LLM agent reading `SKILL.md` and deciding to invoke it.
- **D3 — one supply-chain system.** `cognic-skill-*` stays a signed pack/wheel containing `SKILL.md` + optional `references/`/`assets/` + the executable action code + a manifest with `declared_tools` + attestations + cosign signature. No new artifact type; reuse M5's sign/verify/trust-register machinery end to end.

---

## 5. The governed executor + broker (the core new surface)

This is the one genuinely new subsystem; everything else reuses M5 + the sandbox + the MCP route.

### 5.1 Execution model
The executable action is arbitrary **deterministic** Python from a trust-registered `cognic-skill-*` pack. Because signed ≠ safe (the AgentTrap / threat-model concern), it runs in the **ADR-004 sandbox** — the same primitive M5's tools rely on — with:
- `--network none` on the runtime container (per the sandbox network-isolation contract; the egress proxy is a sidecar, so the action has **no general network**),
- no ambient Vault credentials (`create(requires_credentials=())` — the action never holds a secret),
- an isolated, bounded filesystem (immutable runtime image; no host mounts beyond the broker socket).

**The action never loads into the kernel process** (that is the M5 *hook* pattern — in-kernel `EntryPoint.load` — and is exactly what D1 forbids). Instead:
- The skill's code is baked into an **immutable, cosign-verified sandbox runtime image** (per the no-dynamic-install doctrine — the skill pack wheel is pip-installed into a signed skill-runtime image at build, not dynamically at session-create), alongside a small **skill-runner harness**.
- To execute, the kernel opens a sandbox session on that image and `session.exec(...)`'s the skill-runner with the target skill identity. The skill-runner, running **inside** the sandbox, resolves the action via the pack's `cognic.skills` entry-point, constructs it with a broker-backed `ToolRegistry`, runs `execute(...)`, and returns the result to the kernel through the session's normal completion channel.
- The kernel-side hosting layer (§7) still trust-registers the pack for discovery/`SKILL.md` validation, but does **not** import the action; the only place the action's Python runs is inside the sandbox.

### 5.2 The broker — the load-bearing enforcement point
The action's **only** egress is a request/response tool-call RPC to the **skill-execution broker**, over a **Unix domain socket** bind-mounted into the sandbox (filesystem IPC, works under `--network none`; chosen over stdio so the tool-call protocol is cleanly framed and separate from the action's stdout/logs). The socket is a real production transport with proven security invariants (§5.4), realized identically across local/kind and Kubernetes (§5.5) — not a plan-deferred detail.

Narrow protocol (length-framed JSON), one method:
```text
request  → { "tool_ref": "<server_id>/<tool_name>", "arguments": { ... } }
response ← { "ok": true,  "result": { ... } }
         | { "ok": false, "refused": true, "reason": "skill_tool_not_declared" }
         | { "ok": false, "error": "<mapped MCP refusal/transport reason>" }
```

For each request the broker:
1. **Enforces `declared_tools` at runtime** — if `tool_ref` is not in the skill's declared set, refuse with `skill_tool_not_declared` and do **not** call the tool. This is the load-bearing guard: admission-time declaration is validated too (§6), but the broker enforces per-call so a composition-time attempt to reach an undeclared tool fails closed regardless of what the code tries.
2. **Routes to `MCPHost.call_tool`** with the skill's bound tenant/actor, so OAuth / approval / DLP / audit all apply automatically — the executor inherits, and cannot bypass, the full M5 governance.
3. **Returns only the tool result** (or a mapped refusal) — the action never gets a token, a session, or network.

### 5.3 `declared_tools` becomes MCP tool identities
The dormant `sdk/skill.py` `declared_tools` (tool *names* cross-checked against an in-process `ToolRegistry`) is re-pointed to **MCP tool identities** `<server_id>/<tool_name>`, cross-checked at admission against the registered MCP tools and enforced at runtime by the broker. The `ToolRegistry` the SDK `Skill` binds becomes a thin adapter whose `get(...)`/`invoke(...)` are the broker RPC — so pack authors keep writing `self._tools.get(...)` / `await tool.invoke(...)` unchanged, but every call is now sandboxed + broker-mediated.

### 5.4 Transport proof obligations (mandatory — each pinned by a test)
The broker socket is a trust boundary between sandboxed pack code and the governed MCP host; the transport MUST satisfy and **prove** every invariant below. These are load-bearing (threat-model-revert-pinned) unit/integration tests in the implementation plan, and BAR 3 (§8) exercises the isolation end-to-end on the deployed cluster:

1. **Per-invocation socket directory is `0700`** — the directory holding the socket is created mode `0700`, owned by the broker's runtime user.
2. **Socket is not world-accessible** — the socket file itself is not world-readable/writable; only the sandbox's runtime user (the intended client) can connect.
3. **Unguessable session id** — the socket path embeds a cryptographically-random per-invocation session id (not a sequence/pid), so a co-located process cannot predict or pre-create the path.
4. **Unauthorized / unknown client refused** — a connection that does not present the invocation's session token (bound to the same random session id) is refused before any tool-call is processed.
5. **Stale-socket cleanup on success AND failure** — the socket + its `0700` dir are removed on normal completion, on error, on timeout, and on cancellation (finally-guarded); a re-used session id can never bind to a leftover socket.
6. **Broker closes on timeout / cancel** — the broker enforces a per-invocation deadline and closes the socket + tears down the session on timeout or upstream cancellation; a hung action cannot hold the channel open.
7. **Malformed frame refused** — a request that is not a well-formed length-framed JSON object (bad length prefix, truncated, non-JSON, missing `tool_ref`) is refused with a closed-enum reason and does not reach `MCPHost.call_tool`.
8. **Oversized payload refused** — a frame whose declared length exceeds the transport's bounded maximum is refused before allocation (no unbounded read), protecting the broker from a memory-exhaustion frame.
9. **No general network in the sandbox** — the runtime container runs `--network none`; the action has no route to any host except the broker socket (filesystem IPC).
10. **No ambient credentials** — the sandbox session is created with `requires_credentials=()`; the action never holds a Vault lease, an OAuth token, or an MCP session — those live only broker-side.
11. **Undeclared tool request refused before `MCPHost.call_tool`** — a `tool_ref` outside the skill's `declared_tools` is refused with `skill_tool_not_declared` and the downstream `call_tool` is never reached (so no token is minted, no external tool is touched, and the only evidence is the refusal row).

### 5.5 Local/kind vs Kubernetes realization (same invariants both ways)
The transport is the **same Unix-domain-socket contract** everywhere; only the mount mechanism differs, and §5.4's invariants hold identically:

- **Local / kind (the M6 proof target):** the socket lives in a per-invocation `0700` directory bind-mounted into the sandbox runtime container (docker-sibling: host bind-mount; the broker runs kernel-side and serves the socket).
- **Production Kubernetes:** the broker runs as a **same-Pod sidecar** and the socket lives on a **shared `emptyDir` volume** mounted into both the runtime container and the broker sidecar (never a host path, never a network Service). Same `0700` dir, same unguessable session id, same auth, same cleanup, same bounded framing — the security invariants are transport-level, not backend-level, so they carry across unchanged.

---

## 6. The skill pack shape (`cognic-skill-*`, external repo)

A signed wheel (Model Y distribution, mirroring the tool/hook packs), force-including the `SKILL.md` folder:

```
cognic-skill-schema-summary/
  cognic-pack-manifest.toml        # [pack] kind="skill"; [data_governance]; [risk_tier]; [skill].declared_tools; [supply_chain]
  SKILL.md                         # agentskills.io standard: frontmatter name/description + instructions body
  references/  assets/             # optional, standard
  src/cognic_skill_schema_summary/
    __init__.py
    skill.py                       # the executable action: Skill subclass, execute(), declared_tools ClassVar
  pyproject.toml                   # [project.entry-points."cognic.skills"] → the Skill subclass; kernel dev-only pin
  cosign.pub                       # committed trust root (dev-grade proof key)
  attestations/                    # build output (cosign.sig + 6 more), Release assets
```

- The manifest gains a `[skill]` block declaring `declared_tools = ["<server_id>/<tool_name>", ...]`; the CLI skill validator checks the `SKILL.md` frontmatter shape (name regex, description ≤1024) + the `declared_tools` shape + cross-checks the entry-point.
- The `SKILL.md` is the agent-facing standard artifact; the entry-point `cognic.skills` → the executable action is the governed runtime primitive.
- **Only the signed Python executable action runs (M6 constraint).** `SKILL.md`, `references/`, and `assets/` are hosted (validated, trust-registered, served to the instruction layer) but never executed. A bundled `scripts/` directory — the standard's "agent runs the script via bash" affordance — is **not executed** in M6: general governed-script execution (running arbitrary bundled scripts under the same sandbox+broker regime) is a deliberate later feature. M6's single governed executable surface is the `cognic.skills` entry-point action, so the trust story stays "one signed, declared-tool-scoped, sandboxed action per skill."
- Trust-registration, cosign verify, per-pack trust root — all reuse M5 unchanged (skills are already `cognic.skills`; a per-pack trust root at `trust-roots/skill-packs/<pack_id>/cosign.pub` mirrors the M5 hook-pack layout).

---

## 7. Hosting / ingestion (ADR-025)

ADR-025 (previously reserved for `SKILL.md` hosting) is written for the merged milestone: AgentOS **governs** the open `SKILL.md` format without replacing it. At boot the skill pack is discovered (`cognic.skills`), cosign-verified against its per-pack trust root, and admitted; the `SKILL.md` frontmatter is validated (name/description); the skill is recorded as discoverable/assignable (surfaced on `/api/v1/system/plugins`, and an assignment surface for M8's agent). The `SKILL.md` body + references are the instruction layer an M8 agent will later read; this milestone validates + hosts + audits them but does not yet feed them to an LLM.

---

## 8. The deployed proof — `schema-summary`

Reuses the whole M3–M5 substrate: the deployed `cognic-tool-oracle-schema@v0.2.0` MCP tool, the MCP host, the kind topology, the sandbox. One released `cognic-skill-schema-summary` pack proves all bars (M5-style arg-gating — one deployed artifact).

- **SKILL.md** — `name: schema-summary`, `description:` "Summarize an Oracle schema's tables and key columns; use when a user asks for a schema overview." Instructions body = procedural knowledge an M8 agent will read.
- **Executable action** — `execute(owner, mode="normal")`: (1) `list_tables(owner)`, (2) for each table (bounded), `describe_table(owner, table)`, (3) aggregate into a fixed-shape summary `{schema, table_count, tables:[{name, column_count, columns}]}`. Deterministic, no LLM.
- **`declared_tools`** = `{cognic-tool-oracle-schema/list_tables, cognic-tool-oracle-schema/describe_table}`.

Bars (env-gated deployed runner, modeled on `run-proof-m5.sh`):

- **BAR 1 (governed composition works):** invoke `schema-summary(owner=COGNIC)` → the executor runs sandboxed, the broker mediates the declared `list_tables` + `describe_table` calls through `MCPHost.call_tool`, and a fixed-shape summary returns. Evidence: instruction-layer audit (skill trust-registered + hosted) **and** execution-layer audit (executor ran; the two governed `call_tool` rows present).
- **BAR 2 (undeclared tool refused — load-bearing):** invoke `schema-summary(owner=COGNIC, mode="forbidden")` → the action requests a tool **outside** its declared set (e.g. `cognic-tool-oracle-schema/get_constraints`) → the **broker refuses** (`skill_tool_not_declared`), the tool is **not** invoked (no new `audit.tool_invocation` row for it), and the skill fails closed. Proves runtime broker enforcement, not just admission-time declaration.
- **BAR 3 (isolation — sandbox holds; MANDATORY, arg-gated like BAR 2):** invoke `schema-summary(owner=COGNIC, mode="exfil")` → the action attempts a **direct** network call (bypassing the broker, e.g. an outbound HTTP request to an external host) → blocked by `--network none` / the egress proxy; the action gets no ambient credential and no general network, so signed-but-hostile code is contained and the skill fails closed. Isolation is a required part of M6, not optional hardening — it is the concrete proof of the differentiator that "signed ≠ safe" is handled by isolation, not trust. The transport-level invariants behind it (§5.4) are each independently pinned.

On all-pass: `PROOF M6 (ALL BARS) PASS`. On any bar failure: capture + non-zero, never redefine the proof downward.

---

## 9. Scope boundaries

**In scope:** the skill pack shape + CLI validator; ADR-025 hosting/ingestion; the governed executor + broker + non-network IPC + `declared_tools` runtime enforcement; the skill-invocation endpoint (deterministic caller); the `schema-summary` external pack + deployed 3-bar proof; the `declared_tools`→MCP-identity re-point of `sdk/skill.py`.

**Out of scope (explicit):**
- **The LLM agent** reading `SKILL.md` and deciding to invoke — **M8**.
- **`SKILL.md` → executable mapping semantics** (how instructions name which action) beyond a single declared entry-point action — richer skill/script mapping is a follow-up.
- **Marketplace / registry** distribution — packs are GitHub Releases (Model Y), as M3–M5.
- **The 15A workflow engine** — a skill's executable action is a single deterministic composition, not a declarative DAG.

---

## 10. Open risks / follow-ups

- **Executable action wall-clock / resource bounds** — the sandbox already caps CPU/mem/walltime; the broker adds a per-invocation deadline (§5.4 #6) and a per-skill tool-call budget (a per-call-count bound is a follow-up if a skill fans out unboundedly).
- **General governed-script execution** — running arbitrary bundled `scripts/` under the same sandbox+broker regime is deliberately out of M6 (§6); it is the natural next governed-skill feature once the single-action transport is proven.
- **Critical-controls surface:** the broker is a new trust boundary (it decides which tool calls a sandboxed pack may make) → it belongs on the CC coverage gate with `declared_tools` enforcement as a threat-model-revert-pinned, load-bearing guard, and `protocol/mcp_authz.py` must stay byte-identical (the M5 discipline).
- Two M3-E2b kernel follow-ups + the M5 py.typed gap remain independent.

---

## 11. References

- [Specification — Agent Skills (agentskills.io)](https://agentskills.io/specification) · [Agent Skills Overview](https://agentskills.io/home)
- [Equipping agents for the real world with Agent Skills (Anthropic)](https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills) · [anthropics/skills](https://github.com/anthropics/skills)
- [Agent Skills Threat Model (safedep.io)](https://safedep.io/agent-skills-threat-model/) · [How to sandbox AI agents in 2026 (Northflank)](https://northflank.com/blog/how-to-sandbox-ai-agents)
- Skilldex (arXiv 2604.16911) · Towards Secure Agent Skills (arXiv 2604.02837) · AgentTrap (arXiv 2605.13940) · SoK: Agentic Skills (arXiv 2602.20867)
- Internal: ADR-001 (three-pool), ADR-002 (MCP plugin protocol + hooks amendment), ADR-004 (sandbox), ADR-008 (authoring), ADR-025 (Agent Skills hosting — to be written), `sdk/skill.py`, the M5 hook-pack proof (`docs/superpowers/specs/2026-07-01-m5-hook-pack-proof-design.md`).
