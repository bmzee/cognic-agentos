# ADR-025 — Governed Agent Skills

## Status
**APPROVED** on 2026-07-02 (design decisions locked with the maintainer; this ADR number was previously reserved for `SKILL.md` hosting and is written for the merged milestone). It lands as milestone **M6 — "Governed Agent Skill proof"**, which merges checklist milestones **M6 + M7** into one shape (see §"M6 + M7 merge"). Source design spec: `docs/superpowers/specs/2026-07-02-m6-governed-agent-skill-design.md`; implementation on branch `feat/m6-governed-agent-skill`.

## Context

By mid-2026 the Agent Skills (`SKILL.md`) format is the de-facto open standard — Anthropic-originated, adopted by OpenAI Codex, Microsoft's Agent Framework, and 8+ marketplaces. "Agent Skills are the new npm."

A `SKILL.md` skill is a **folder of instructions for an LLM agent**, not runnable code: a required `SKILL.md` (YAML frontmatter `name` + `description`, then a Markdown instructions body) plus optional `scripts/`, `references/`, `assets/`. When a task matches the `description`, the agent reads the instructions into context (progressive disclosure) and, when told to, runs a bundled script and reads back its output.

The standard's security model is **"trust delegated to the client."** Every practitioner guide and the formal threat-model literature converge on the same warning — *treat every skill as an untrusted dependency: audit the `SKILL.md` before installing, run skills in sandboxed environments, rotate any credentials the skill touches* — and name runtime trust, sandbox granularity, and **composition risk** as open problems (Skilldex; Towards Secure Agent Skills; AgentTrap; SoK: Agentic Skills; the safedep Agent Skills Threat Model).

That warning is AgentOS's product. Every mitigation the ecosystem tells the operator to do by hand, AgentOS already has as a first-class primitive:

| Ecosystem advice (do it yourself) | AgentOS primitive |
|---|---|
| "audit the `SKILL.md` before installing" | cosign-signed packs + SLSA/SBOM/in-toto attestations + trust-register gate (M3–M5) |
| "run skills in a sandboxed environment" | the ADR-004 sandbox (docker-sibling / kubernetes-pod, `--network none` + egress proxy) |
| "rotate any credentials the skill touches" | no ambient credentials; the sandboxed action's only egress is a broker that routes through `MCPHost.call_tool` (OAuth / approval / DLP) |
| (nothing) | hash-chain audit at both the instruction and execution layers |

Two things blocked AgentOS from claiming this space before this decision:

1. **A naming collision.** This repo's pre-existing deterministic composer at `sdk/skill.py` (`Skill.execute()` — no-LLM tool composition with a `declared_tools` contract) used "skill" for a concept that is NOT what the industry means by the word. The industry has exactly one meaning of "skill" (`SKILL.md`).
2. **A split milestone.** The production-grade checklist carried M6 ("executable skill service") and M7 ("Agent Skills `SKILL.md` hosting, ADR-025") as separate milestones, cementing a split pack vocabulary ("instruction skill" vs "executable skill service") that mirrored the collision instead of resolving it.

## Decision

### Vocabulary — `Skill` = a `SKILL.md` package (the public noun)

- **Skill (public noun) = a `SKILL.md` package.** The full agentskills.io-standard folder — a required `SKILL.md` entrypoint (YAML frontmatter `name` + `description`, a Markdown instructions body) plus optional `references/`, `assets/`, `scripts/`, and supporting files — shipped as a signed `cognic-skill-*` pack, the whole folder riding the wheel as signed package data. `SKILL.md` is the entrypoint, not the whole artifact. This is what an agent (M8) discovers, is assigned, and reads. Bundled `scripts/` are package data only — never ambiently executable; v1's single governed execution surface remains the declared action (see §"Security model"; corrected 2026-07-09, see §"Amendment — skill directory-format accuracy").
- **Executable action = the governed runtime primitive inside a skill.** The repositioned `sdk/skill.py` composer (`Skill.execute()`) — deterministic, no-LLM tool composition with a `declared_tools` contract. It is *not* "the skill"; it is *one governed implementation* of a skill's runnable behavior — a **substrate**, not a competing "skill" noun. Public docs stop calling it "executable skill."
- This resolves the collision: the industry has exactly one meaning of "skill," and AgentOS now matches it. The deterministic composer keeps its value (auditable, no LLM variance — ideal for banking) at its correct layer.

### One `skill` pack kind — the instruction/executable split collapses

The earlier pack-vocabulary split — "instruction skill" + "executable skill service" — **collapses into a single `skill` kind**: a `SKILL.md` package with an optional governed action. The **live** pack kinds are **tool, skill, agent, hook** (`PackKind` at `packs/lifecycle.py:111`); **`workflow` is reserved**, not yet a `PackKind` value — it lands, if ever, with the Sprint-15A engine under ADR-029/M14 (amended 2026-07-09; see §"Amendment — workflow-kind accuracy"). Workflow and agent packs stay distinct from skills.

No new entry-point group is needed: skills are already the `cognic.skills` registrable kind in the plugin registry (per ADR-002's entry-point discovery; the ADR-002 hooks amendment added `cognic.hooks` as the fourth group). The pack manifest gains a `[skill]` block declaring `declared_tools = ["<server_id>/<tool_name>", ...]`; the CLI skill validator checks the `SKILL.md` frontmatter shape (name regex, description ≤1024) + the `declared_tools` shape + cross-checks the entry-point.

### M6 + M7 merge — one "Governed Agent Skill proof" milestone

Checklist milestones **M6 (executable skill service)** and **M7 (Agent Skills `SKILL.md` hosting, ADR-025)** are **merged into one** "Governed Agent Skill proof" milestone. The two halves were always one product decision: hosting the open format without governing its execution is a marketplace; governing execution without hosting the open format is a proprietary runtime. The merged milestone ships both as one shape.

**Differentiator: AgentOS *governs* the open skill format rather than replacing it.** The skill stays the portable open `SKILL.md` standard — the same skill an agent uses anywhere. The open ecosystem's security posture is "trust delegated to the client"; AgentOS converts that into **cryptographically-signed packs** (cosign + SLSA/SBOM/in-toto attestations + the trust-register gate), **ADR-004 sandbox isolation**, **per-call `declared_tools` scoping**, **`MCPHost.call_tool` governance** (OAuth / approval / DLP / audit), and **hash-chained audit** at both the instruction and execution layers. No marketplace offers this. This is the bank-grade "Governed Agent Skill."

Three decisions were locked with the maintainer (2026-07-02):

- **D1 — full sandbox from the start.** The executable action runs isolated in the ADR-004 sandbox with **no general network** and **no ambient credentials**. Its only tool access is a narrow AgentOS-mediated channel (the broker) that ultimately calls `MCPHost.call_tool`. Not "in-kernel first, harden later" — signed code is necessary but not sufficient for a bank-grade story.
- **D2 — defer the real LLM agent to M8.** This milestone proves skill **hosting + governed executable action + declared-tool enforcement + dual-layer audit** by invoking the action through a governed endpoint (deterministic, no LLM variance). M8 proves an LLM agent reading `SKILL.md` and deciding to invoke it.
- **D3 — one supply-chain system.** `cognic-skill-*` stays a signed pack/wheel containing `SKILL.md` + optional `references/`/`assets/`/`scripts/` and supporting files (all signed package data; `scripts/` carry **no execution affordance** — governed execution still requires the declared, sandboxed action boundary) + the executable action code + a manifest with `declared_tools` + attestations + cosign signature. No new artifact type; reuse M5's sign/verify/trust-register machinery end to end, including a per-pack trust root at `trust-roots/skill-packs/<pack_id>/cosign.pub` mirroring the M5 hook-pack layout.

### Security model — full sandbox, broker-only egress

One enforcement chain:

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

- **The action never loads into the kernel process.** That is the M5 *hook* pattern (in-kernel `EntryPoint.load`) and exactly what D1 forbids for skills. The skill's code is baked into an **immutable, cosign-verified sandbox runtime image** (per the no-dynamic-install doctrine — the skill pack wheel is pip-installed into a signed skill-runtime image at build, not dynamically at session-create), alongside a generic in-repo **skill-runner** harness. To execute, the kernel opens a sandbox session on that image and `session.exec(...)`'s the skill-runner with the target skill identity; the skill-runner, running *inside* the sandbox, resolves the action via the pack's `cognic.skills` entry-point, constructs it with a broker-backed `ToolRegistry`, runs `execute(...)`, and returns the result through the session's normal completion channel. The kernel-side hosting layer trust-registers the pack for discovery/`SKILL.md` validation but does **not** import the action.
- **Sandbox posture (ADR-004):** `--network none` on the runtime container (the egress proxy is a sidecar, so the action has **no general network**); no ambient Vault credentials (`create(requires_credentials=())` — the action never holds a secret); an isolated, bounded filesystem (immutable runtime image; no host mounts beyond the broker socket).
- **The broker is the load-bearing enforcement point.** The action's **only** egress is a request/response tool-call RPC over a **Unix domain socket** in a per-invocation `0700` directory, mounted into the sandbox (filesystem IPC, works under `--network none`), to the kernel-side **skill-execution broker**. Narrow length-framed JSON protocol, one method:

  ```text
  request  → { "tool_ref": "<server_id>/<tool_name>", "arguments": { ... } }
  response ← { "ok": true,  "result": { ... } }
           | { "ok": false, "refused": true, "reason": "skill_tool_not_declared" }
           | { "ok": false, "error": "<mapped MCP refusal/transport reason>" }
  ```

  For each request the broker: (1) **enforces `declared_tools` at runtime, per call** — a `tool_ref` outside the skill's declared set is refused with `skill_tool_not_declared` and the tool is **not** called (admission-time declaration is validated too, but the broker enforces per-call so a composition-time attempt to reach an undeclared tool fails closed regardless of what the code tries); (2) **routes to `MCPHost.call_tool`** with the skill's bound tenant/actor, so OAuth / approval / DLP / audit all apply automatically — the executor inherits, and cannot bypass, the full M5 governance; (3) **returns only the tool result** (or a mapped refusal) — the action never gets a token, a session, or network.
- **Result projection (2026-07-04 amendment — M6 run-16 finding #17).** The wire arm's `result` is the **tool-level JSON object** — the tool handler's own dict, the same value the SDK `ToolRegistry` convention hands an action in-process (`await tool.invoke(**kwargs) -> dict`) — never a raw mcp SDK object: the broker frames responses with stdlib `json.dumps`, and an mcp `CallToolResult` is a pydantic model (not JSON-able), so an unprojected result kills every real governed call in-band at the broker's result-frame arm. The `MCPHost.call_tool` conformer (`harness/skill_host._MCPHostCallProxy`) owns the projection, in order: (1) `isError` true → raise (fail-closed — a tool-level error must not masquerade as a success result the action's defensive extractors would quietly reduce to an empty summary; the local `MCPToolResultError`'s message never carries the tool's content text, and its short `reason` marker `mcp_tool_result_is_error` surfaces on the broker's downstream-failure WARNING); (2) `structuredContent` dict → return it (the authoritative, schema'd realization); (3) exactly one text content block whose text parses to a JSON **object** → return that dict — the FastMCP bare-`-> dict` realization: mcp 1.27.0 generates **no** output schema for a bare `dict` annotation, so the handler dict rides only as JSON text in the single `TextContent` block (the live oracle-pack v0.2.0 case run 16 failed on); (4) otherwise the JSON-mode model dump (`by_alias`, `exclude_none`) — an honest, still-frameable envelope; (5) plain non-model payloads pass through unchanged. The broker side gained the matching diagnosability WARNING `skill.broker.tool_result_not_frameable` (finding #17b) on the result-frame arm — the one dark arm left after finding #16 instrumented the downstream-exception arm; its bounded detail is value-free by construction (`FrameTooLarge` byte counts / `json.dumps` type-name-only messages), and the socket wire arms are unchanged. Both broker WARNINGs carry the per-call correlator as **`tool_request_id`** (== the downstream audit row's `request_id`), NOT `request_id` — the observability `_ContextFilter` on the production root handler owns `record.request_id`/`trace_id`/`span_id` and stamps the ambient portal context over same-named `extra` keys (finding #17c, pinned by a deterministic filter-installed regression); the distinct key rides alongside the ambient portal request id instead of being clobbered by it.
- **`declared_tools` becomes MCP tool identities.** The dormant `sdk/skill.py` `declared_tools` (tool *names* cross-checked against an in-process `ToolRegistry`) is re-pointed to MCP tool identities `<server_id>/<tool_name>`, cross-checked at admission against the registered MCP tools and enforced at runtime by the broker. The `ToolRegistry` the SDK `Skill` binds becomes a thin adapter whose `get(...)`/`invoke(...)` are the broker RPC — pack authors keep writing `self._tools.get(...)` / `await tool.invoke(...)` unchanged, but every call is now sandboxed + broker-mediated.
- **Hosted, not executed.** `SKILL.md`, `references/`, and `assets/` are validated, trust-registered, hosted, and served to the instruction layer — **never executed**. Arbitrary bundled **`scripts/` execution** (the standard's "agent runs the script via bash" affordance) is **explicitly deferred / out of scope for this milestone**: M6's single governed executable surface is the signed `cognic.skills` Python action, so the trust story stays "one signed, declared-tool-scoped, sandboxed action per skill." General governed-script execution is the natural next governed-skill feature once the single-action transport is proven.
- **Deterministic caller now; the LLM agent is M8.** The LLM agent that *reads* `SKILL.md` and decides to invoke is deferred to a later milestone (M8); this milestone proves the hosting + governed action + declared-tool enforcement **deterministically** through a governed invocation endpoint.

### The eleven transport invariants (verbatim from the design spec §5.4)

The broker socket is a trust boundary between sandboxed pack code and the governed MCP host; the transport MUST satisfy and **prove** every invariant below. The eleven invariants are copied **verbatim** from the design spec §5.4 and are normative for every realization of the transport. Each MUST be pinned by a load-bearing (threat-model-revert-proven) unit/integration test, and the deployed proof's isolation bar exercises the isolation end-to-end on the deployed cluster:

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

### Same invariants on both backends

The transport is the **same Unix-domain-socket contract** everywhere; only the mount mechanism differs, and the invariants above hold identically:

- **Local / kind (the M6 proof target):** the socket lives in a per-invocation `0700` directory bind-mounted into the sandbox runtime container (docker-sibling: host bind-mount; the broker runs kernel-side and serves the socket).
- **Production Kubernetes:** the broker runs as a **same-Pod sidecar** and the socket lives on a **shared `emptyDir` volume** mounted into both the runtime container and the broker sidecar (never a host path, never a network Service). Same `0700` dir, same unguessable session id, same auth, same cleanup, same bounded framing — the security invariants are transport-level, not backend-level, so they carry across unchanged.

### Hosting / ingestion

At boot the skill pack is discovered (`cognic.skills`), cosign-verified against its per-pack trust root, and admitted through the existing plugin-registry trust gate; the `SKILL.md` frontmatter is validated (name/description); the skill is recorded as discoverable/assignable (surfaced on `/api/v1/system/plugins`, and an assignment surface for M8's agent). The `SKILL.md` body + references are the instruction layer an M8 agent will later read; this milestone validates + hosts + audits them but does not yet feed them to an LLM.

### Proof obligations

One released, cosign-signed external pack proves the milestone on a deployed `kind` AgentOS, on three bars: **BAR 1** (governed composition — the sandboxed action composes its declared tools through the broker and `MCPHost.call_tool`, with dual-layer audit evidence), **BAR 2** (undeclared tool refused — the broker refuses `skill_tool_not_declared` at runtime and the tool is never invoked), and **BAR 3** (isolation — a direct network attempt from the action is blocked; signed-but-hostile code is contained and fails closed). **BAR 3 is mandatory**, not optional hardening — it is the concrete proof that "signed ≠ safe" is handled by isolation, not trust. On any bar failure: capture + non-zero, never redefine the proof downward.

### Critical-controls scope

The broker is a **new trust boundary** — it decides which tool calls a sandboxed pack may make. Per AGENTS.md "Critical-controls rule": the skill-execution broker and the governed executor land on the durable per-file critical-controls coverage gate (95% line / 90% branch), with `declared_tools` enforcement as a threat-model-revert-pinned, load-bearing guard. `protocol/mcp_authz.py` MUST stay byte-identical (the M5 discipline). The sandbox and sub-agent enforcement boundaries remain stop-rule surfaces per ADR-004 and AGENTS.md.

## Consequences

### Positive
- AgentOS matches the industry's single meaning of "skill": the portable open `SKILL.md` standard is first-class, and the same skill an agent uses anywhere becomes a cryptographically-trusted, sandboxed, tool-scoped, audited "Governed Agent Skill" here — a differentiator no marketplace offers.
- "Signed ≠ safe" is handled by isolation, not trust: a hostile-but-signed action is contained (no general network, no ambient credentials, no undeclared tools) and fails closed, with the refusal as chain evidence.
- The deterministic composer keeps its value (auditable, no LLM variance) at its correct layer — a governed substrate inside a skill instead of a competing noun.
- Dual-layer evidence: hash-chain rows at both the instruction layer (pack trust-registered, `SKILL.md` ingested/assignable) and the execution layer (executor ran sandboxed, each broker-mediated `call_tool` audited, any undeclared attempt refused).
- One supply-chain system: no new artifact type; the M5 sign/verify/trust-register machinery carries unchanged.

### Negative
- The full-sandbox posture (D1) makes skill execution heavier than in-kernel dispatch — a sandbox session + a per-invocation socket broker per run. This is the accepted cost of a bank-grade story; the sandbox's existing CPU/mem/walltime caps and the broker's per-invocation deadline bound it.
- Only the single declared `cognic.skills` entry-point action is runnable in M6. Skills whose value lives in bundled `scripts/` are hosted but their scripts do not run until general governed-script execution lands as a later feature.
- Until M8 there is no LLM consumer of the hosted instruction layer — `SKILL.md` bodies are validated + hosted + audited but unread by an agent.

### Neutral
- The pack-vocabulary collapse is a naming/doctrine change; the registrable entry-point groups are unchanged (skills were already `cognic.skills`).
- The broker transport contract is identical across sandbox backends; only the socket mount mechanism differs (docker-sibling bind-mount vs same-Pod `emptyDir`).
- A per-skill tool-call budget (a per-call-count bound if a skill fans out unboundedly) is a follow-up; the per-invocation deadline and the sandbox resource caps bound M6.

## Out of scope

- **The LLM agent** reading `SKILL.md` and deciding to invoke — **M8**.
- **`SKILL.md` → executable mapping semantics** (how instructions name which action) beyond a single declared entry-point action — richer skill/script mapping is a follow-up.
- **General governed-script execution** — running arbitrary bundled `scripts/` under the same sandbox+broker regime is deliberately deferred (see §"Security model").
- **Marketplace / registry** distribution — packs are GitHub Releases (Model Y), as M3–M5.
- **The 15A workflow engine** — a skill's executable action is a single deterministic composition, not a declarative DAG.

## M8 amendment (2026-07-05) — instruction-only skill-pack mode joins the skill doctrine

ADR-027 (governed agent loop, M8) extends the single `skill` pack kind with a first-class **instruction-only mode**: `[skill].mode = "instruction"` (absent → `"executable"`; every existing pack is unchanged). An instruction skill is a valid hosted `SKILL.md` with NO entry point, NO runtime image, and NO executable `declared_tools` — hosted / assignable / readable, **never executable** (`SkillExecutor.invoke` refuses an instruction record fail-closed; it can never reach the sandbox). This is a MODE of the one `skill` kind, not a new kind — the §"One `skill` pack kind" collapse stands. The M8 loop is the LLM consumer this ADR anticipated ("Until M8 there is no LLM consumer of the hosted instruction layer"): agents read *granted* skills' bodies via the kernel `read_skill` built-in, gated by ADR-027's assignment sub-gate. The optional `[skill].referenced_tools` list is **non-authoritative reviewer evidence** only — authority comes solely from agent assignment + dispatch.

## Amendment — skill directory-format accuracy (2026-07-09)

The Decision-level vocabulary bullet (§"Vocabulary") and D3 (§"one supply-chain system") originally named only `references/` + `assets/` — narrower than this ADR's own Context (which names `scripts/` in the format description) and §"Security model" (which records the hosted-not-executed boundary and the explicit `scripts/`-execution deferral). Readers citing the Decision line alone kept reproducing the narrowed format. Both bullets are corrected **in place** to the full agentskills.io folder shape: a required `SKILL.md` entrypoint plus optional `references/`, `assets/`, `scripts/`, and supporting files — signed package data end to end.

**No behavior or scope change.** Only `SKILL.md` is parsed (`protocol/skill_manifest.py`); `references/`/`assets/`/`scripts/` ride the wheel unparsed; `scripts/` never execute in v1, and the §"Security model" deferral of general governed-script execution stands unchanged — when it lands it lands as a governed, sandboxed, declared boundary, never ambient execution. Companions: the ADR-008 amendment "harness/ADK as the pack-authoring workbench" (2026-07-09) + the `docs/source-of-truth/VOCABULARY.md` skill-row fix.

## Amendment — workflow-kind accuracy (2026-07-09)

The §"One `skill` pack kind" paragraph originally listed the pack kinds in the present tense as "**tool, skill, workflow, agent, hook**." That was inaccurate: `workflow` has never been a `PackKind` value. The live vocabulary is the four-value `PackKind = Literal["tool", "skill", "agent", "hook"]` (`packs/lifecycle.py:111`), matching the four entry-point groups (`protocol/plugin_registry.py:89-92`).

`workflow` is **reserved** for the Sprint-15A orchestration engine under ADR-029/M14. Nothing else in this ADR changes: the single-`skill`-kind collapse, the "skill = `SKILL.md` package" public noun, and "executable action = a substrate inside a skill, not a competing noun" all stand. The canonical glossary derived from this ADR is `docs/source-of-truth/VOCABULARY.md`.

## References

- [Specification — Agent Skills (agentskills.io)](https://agentskills.io/specification) · [Agent Skills Overview](https://agentskills.io/home)
- [Equipping agents for the real world with Agent Skills (Anthropic)](https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills) · [anthropics/skills](https://github.com/anthropics/skills)
- [Agent Skills Threat Model (safedep.io)](https://safedep.io/agent-skills-threat-model/)
- Skilldex (arXiv 2604.16911) · Towards Secure Agent Skills (arXiv 2604.02837) · AgentTrap (arXiv 2605.13940) · SoK: Agentic Skills (arXiv 2602.20867)
- ADR-001 (OS-only platform / three-pool rule — packs live outside the kernel repo)
- ADR-002 (MCP plugin protocol — entry-point pack kinds incl. `cognic.skills`; the hooks pack kind amendment; `MCPHost.call_tool` governance)
- ADR-004 (sandbox primitive — the isolation substrate the executable action runs in)
- ADR-008 (authoring platform — SDK + CLI; the skill scaffold + validators)
- ADR-017 (data-governance contracts — the DLP hooks applied on the `MCPHost.call_tool` path)
- Design spec: `docs/superpowers/specs/2026-07-02-m6-governed-agent-skill-design.md` · the M5 hook-pack proof (`docs/superpowers/specs/2026-07-01-m5-hook-pack-proof-design.md`) · `sdk/skill.py`
