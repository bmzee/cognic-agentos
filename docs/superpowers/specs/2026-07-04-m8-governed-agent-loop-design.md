# M8 — Governed Agent Loop: the bank data-analyst agent (design)

- **Date:** 2026-07-04
- **Status:** APPROVED (maintainer-reviewed design; Parts 1+2 approved with corrections, all folded in)
- **Milestone:** M8 — "First deployed bank LLM-agent loop using tools and skills" (`docs/PRODUCTION_GRADE_MILESTONE_CHECKLIST.md`), scoped against the proven M5 (hooks on `call_tool`), M6 (governed executable skills + broker), M7 (hosted `SKILL.md` instruction layer) substrate.
- **New ADR:** **ADR-027 — governed agent loop** (ADR-026 is taken by M4 operator runtime-config).
- **Prior art anchors:** platform-owned loop + declarative agent manifests (M365 Copilot declarative agents — "no code path for the LLM"); agent-gateway/OPA-per-tool-call enterprise pattern; OAuth OBO/RFC-8693 dual-identity direction; semantic-layer/governed-view text-to-SQL hardening; DB-native identity propagation.

## 1. What M8 ships

The **AgentOS agent runtime** — a kernel-owned, declarative-agent reasoning loop with a single governed dispatch chokepoint — plus its first production inhabitant: **`cognic-agent-bank-analyst`**, a signature NLP analytical worker. A user asks a natural-language question over the bank's Oracle data ("top 10 customers by deposit balance this quarter"); the agent selects among its *assigned* per-domain instruction skills, follows their guidance to author SQL over *governed views*, executes it through one governed read-only query tool under the *user's* data entitlements, and answers — single-shot, fully evidenced, on a cloud model routed through the governed gateway.

**Locked requirement decisions (maintainer):**
1. Use case: NLP analytical agent; domain knowledge lives in per-domain instruction skills; the agent stays generic.
2. Data access: ONE governed `run_readonly_query` tool (not per-domain parameterized tools).
3. Entitlements: **many-to-many** built now (multi-scope users AND shared scopes); administration stays seed/config-driven in M8 (portal CRUD is a follow-up; per-tenant entitlement changes are Human-only-decision-adjacent).
4. Model: **cloud model for the proof** (operator-supplied env-gated key); bank model choice stays pure configuration (tier aliases → litellm router; on-prem qwen/Kimi/vLLM or cloud Claude/OpenAI). Model sits outside the AgentOS boundary; the governance around calling it sits inside.
5. Memory: **task-tier, digest-only run metadata only** — the agent records what it did via the production-wired MemoryAPI under its `agent_id`. Long-term remember/recall/forget/redact for agents is **M9**, not M8.
6. Invocation: **single-shot** Q&A; a conversation harness above the agent is a later milestone and will wrap exactly this loop.
7. Approach: **Approach 1 — declarative agent pack + kernel-owned loop** (industry-validated; Approaches 2 "sandboxed custom-engine agent" and 3 "loop in pack code" recorded as rejected for M8).

## 2. Architecture

```
User (Actor: analyst.amir) ── POST /api/v1/agents/{agent_id}/ask {question}
        │  (RBAC scope agent.ask; single-shot)
        ▼
core/agent/loop.py  (CC — frames + interprets the UNTRUSTED LLM)
   prompt = persona + assigned-skill names/descriptions (progressive disclosure)
   iterate ≤ max_steps:
        ├── llm/gateway.completion(tier, messages, tools=[GatewayToolSpec…])
        │      (cloud-policy · kill-switches · quotas · guardrails · honesty ledger
        │       · Langfuse trace with agent_workforce_id)
        ▼
core/agent/dispatch.py  (CC — THE agent-gateway chokepoint; ALL authority decisions)
   gate 1  assignment: capability ∈ granted set        else agent_capability_not_assigned
   gate 2  entitlement: scope_id ∈ user's entitled set else agent_scope_not_entitled
   gate 3  policy: agents.rego decision point + ADR-014 risk tier
   stamp   kernel-minted SIGNED query-context token (never LLM-authored)
        │
        ├── built-ins: read_skill(skill_id) · remember(note)
        └── MCP tools: MCPHost.call_tool (M5 dlp hooks intact)
                └── cognic-tool-oracle-schema v0.3.0 run_readonly_query
                       verify context token → parse SQL (sqlglot) →
                       every referenced object ⊆ stamped allow-set →
                       SELECT-only + row/time bounds →
                       execute via Oracle PROXY AUTH as the user's DB identity
                       (grants on governed views = the engine-level backstop)
```

- **The loop is CRITICAL CONTROLS.** Authority decisions live in dispatch, but the loop is CC because it *frames and interprets the untrusted LLM*: prompt assembly, tool-call parsing, max-step and token bounds, final-answer handling, and evidence correlation are all security-relevant even though they grant nothing.
- **The dispatcher owns every authority decision** and is the only path from an LLM utterance to an action. Built-ins and MCP tools dispatch identically.
- **The LLM is untrusted input end to end**: it selects *within* granted/entitled sets; it can never author the sets, the stamped context, or the identities.

## 3. Components

### 3.1 Kernel — new (`core/agent/`, CC; `core/entitlements/`, CC)

- **`core/agent/loop.py`** — the reasoning loop as drawn above. Bounds: `max_steps` (settings, default small), per-run token budget, per-run wall clock. Terminal states: `completed` / `refused` / `failed` (closed vocab). No pack code executes — the loop consumes the agent *record* (manifest-derived) only.
- **`core/agent/dispatch.py`** — gates 1–3 + stamping + evidence emission per dispatch. Closed-enum refusal vocabulary (initial): `agent_capability_not_assigned`, `agent_scope_not_entitled`, `agent_sql_object_out_of_scope` (tool-side, mirrored), `agent_max_steps_exceeded`, `agent_tool_dispatch_failed`. Every refusal = one audited decision row; the agent then answers the user gracefully (proper messaging is a requirement, not a nicety).
- **`core/agent/assignments.py`** — the granted-capability store: `agent_id → {skill_ids, tool_refs}`, seed/config-loaded in M8. **Ingestion invariant (Part-2 review correction #2): a grant outside the pack's *requested* set is refused at load** (`agent_grant_not_requested`) — operator/config drift cannot grant a capability the persona never requested. Dispatch enforces the granted set only; prompt assembly *shapes* to it (defense in depth: shaping + hard gate).
- **`core/entitlements/store.py`** + migration — **data-scope grain (Part-1 review correction #5):**
  - `data_scopes(scope_id → {schema, governed view objects…, proxy_db_identity})` — a named scope IS a curated set of governed view objects (the lightweight semantic layer), not a bare schema.
  - `entitlements(subject ↔ scope_id)` — many-to-many, queryable both directions.
  - M8 seed: `analyst.amir → {retail_analytics, financials}`, `analyst.sara → {cards_analytics}`, plus `retail_analytics` granted to a second user (both m:n directions proven live).

### 3.2 Kernel — extensions

- **`llm/gateway.py` (a stop-rule module — cloud-policy enforcement per AGENTS.md):** additive tool-calling. **AgentOS owns the normalized wire contract (Part-1 review correction #3):** new typed `GatewayToolSpec` (name, description, JSON-schema params) and `GatewayToolCall` (id, name, arguments) frozen types; `completion(..., tools=list[GatewayToolSpec]) → GatewayResponse(content | tool_calls: list[GatewayToolCall])`. litellm is the implementation aid, not the contract: **provider-normalization drift tests** pin the mapping for the supported provider families (openai-format, anthropic-format, ollama) so a provider/library bump cannot silently change the wire our loop parses. All existing gateway governance is untouched and becomes live-exercised.
- **`harness/skill_host.py` + `cli/validators/*` — instruction-only skills as a first-class skill-pack mode (Part-1 review correction #4; the plugin kind remains `skills`).** Today's loader requires exactly one `cognic.skills` entry point and non-empty executable `declared_tools`; M8 adds the hosted **instruction skill**: valid `SKILL.md` (same frontmatter validation), manifest marked instruction-only (no entry point, no runtime image, no executable `declared_tools`), hosted/assignable/readable, never executable. Manifest may carry an **optional, non-authoritative `referenced_tools` list (Part-2 review correction #4)** — validator cross-checks the references against registered tools for reviewer evidence; **authority still comes only from agent assignment + dispatch**.
- **`harness/registry_boot.py`:** per-pack trust root for agent packs (`agent-packs/<pack_id>/cosign.pub`), mirroring hooks/skills.
- **`protocol/ui_events.py`:** the `agent_run` family (schema-only today) gets emitters + decision-history projectors.
- **`portal/api/agents/`:** `POST /api/v1/agents/{agent_id}/ask` (new `agent.ask` RBAC scope) → `{answer, run_id, terminal_state, evidence refs}`. Single-shot.
- **`policies/_default/agents.rego`:** the dispatch decision point (ADR-015 continuity; wire-protocol-public stop-rule treatment like every `_default` bundle).

### 3.3 The kernel-stamped query context (Part-2 review correction #3 — the trust seam)

The LLM-visible tool schema for `run_readonly_query` is **exactly** `{scope_id, sql, max_rows?}` — it must never include the allow-set, proxy identity, or any entitlement fact. After gates pass, the dispatcher injects an **opaque, signed, nonce-bound AgentOS query-context token** into the MCP call (a non-LLM-visible argument): payload carries the resolved scope binding (object allow-set or a scope-binding reference), the proxy DB identity, the dual identity (`sub` = user, `act` = agent), expiry + nonce (anti-replay). The v0.3.0 tool **verifies the token** (signature against the AgentOS query-context public key distributed in deployment config; nonce/expiry) before honoring any stamped fact. Consequences: a **direct MCP caller cannot spoof "server-stamped" fields** — `run_readonly_query` without a valid kernel-minted context refuses (`query_context_missing_or_invalid`), making the tool agent-path-only by construction (operator paths would mint their own tokens later, out of M8). Key material: asymmetric (kernel signs, tool verifies with the public key); proof seeds the keypair alongside the cosign material.

### 3.4 External packs (Part B — separate repos, released + signed like every pack)

- **`cognic-agent-bank-analyst`** — the declarative agent pack. Manifest `[agent]` block: persona/instructions content reference (`AGENT.md`-style, validated like `SKILL.md`), **requested** skills + tools, risk tier, identity/AgentCard as today. **Zero executable *loop* code (Part-2 review correction #1 — rephrased from "zero Python"):** the pack keeps a **minimal inert `cognic.agents` entry point solely as the registry/verify marker** — it rides the entire existing trust pipeline (discovery, wheel integrity, load probe, cosign) with **no modification to the CC registry/trust-gate modules** — and is **never used by the loop**. The marker object MUST be **side-effect-free on import/load** (module body + object construction perform no I/O, no network, no filesystem, no global mutation), and the pack's tests pin this as far as the isolated load-probe can prove, which consumes only the manifest-derived record + assignment store. First-class declarative discovery without `EntryPoint.load` is documented in ADR-027 as the eventual evolution, deliberately not built in M8.
- **`cognic-skill-customer-data`**, **`cognic-skill-financial-data`** (granted) and **`cognic-skill-atm-recon`** (released + hosted, **not granted** — the standing negative): instruction-only skill packs per §3.2. `SKILL.md` teaches: the domain's governed views, join/filter guidance, worked SQL examples, caveats + the scope_id to use.
- **`cognic-tool-oracle-schema` v0.3.0** — adds `run_readonly_query` per §3.3: token verify → **sqlglot parse** (pack-side dependency; kernel stays parser-free) → referenced-objects ⊆ allow-set → SELECT-only (statement-type; no DML/DDL/PL-SQL) → row/time bounds → execute via **Oracle proxy authentication** (connect as app identity, activate the user's DB identity; that identity's grants cover exactly the governed views). Existing metadata tools unchanged; M5 hooks keep arg-gating.

## 4. Evidence & governance contract

Per ask: `agent.run.*` decision rows + `agent_run.*` UI events (started / per-dispatch / terminal) — **digest-only** (question, answer, SQL land as sha256 + byte counts on the chain; plaintext only in the HTTP response to the asking user); **dual identity on every row** (`originator_subject` + `agent_id` — the OBO `sub`/`act` essence; RFC 8693 token-exchange alignment documented as Wave-2 in ADR-027); downstream `audit.tool_invocation` rows as today; provider-honesty ledger row for the external route; Langfuse trace with `agent_workforce_id` (first real caller); task-tier MemoryAPI writes (digest-only run metadata: interpreted question digest, chosen skill, scope, terminal state); every denial closed-enum + audited. Gateway input/output guardrails stay on the completion path; loop bounded by max-steps + token budget + wall clock.

## 5. The bars (deployed proof, all mandatory)

- **BAR 1 — governed loop end-to-end:** entitled user asks a customer question → `read_skill(customer-data)` → `run_readonly_query(retail_analytics, …)` → answer contains the seeded expected rows. Asserted on evidence + result data (never prose): assignment-gate rows, stamped-context dispatch, dual identity, honesty-ledger external row, Langfuse `agent_workforce_id`, memory write, `agent_run` terminal `completed`.
- **BAR 2 — unassigned capability refused (forced probe):** the user explicitly instructs "use the atm-recon skill" → dispatch `agent_capability_not_assigned` audited; graceful answer. (Absence from the prompt is not proof; the probe forces the gate.)
- **BAR 3 — unentitled scope refused with proper messaging:** `analyst.amir` (no `cards_analytics`) asks a cards question → `agent_scope_not_entitled` audited + clean "not available in your data scope" answer; the same question from `analyst.sara` succeeds. Many-to-many demonstrated both directions (amir multi-scope; retail shared by two users).
- **BAR 4 — SQL escape fails closed (main path):** injected steering toward a raw table / cross-scope object → tool-side `agent_sql_object_out_of_scope` (parsed-object refusal); a DML attempt → SELECT-only refusal. Audited; no stack traces to the user. **The parser is never weakened for testing (Part-2 review correction #5).**
- **BAR 4b — DB backstop proven separately (Part-2 review correction #5):** a direct DB probe under the user's proxy identity shows a governed view succeeds and a raw table / cross-scope object fails at the engine (ORA-denied). Proves the backstop without touching the main path.
- **BAR 5 — provider governance live (Part-2 review correction #7, exact proof):** one real chat completion through the governed gateway with: the cloud-policy allow decision, the honesty-ledger `external=true` row, and the Langfuse trace carrying `agent_workforce_id`. The model-alias swap is **documented as config** (one values-file diff shown in the runbook); M8 does **not** depend on a second live provider.

## 6. Deployed proof shape (Part C)

`infra/proof-m8/` modeled on proof-m6: kind cluster + backends; oracle pack v0.3.0 through the full M4 operator lifecycle; agent + 3 skill packs trust-registered at boot (agent per-pack trust root); **seeded Oracle**: RETAIL/CARDS/FIN schemas, base tables + governed views + demo rows, proxy users + view grants; seeded data-scopes/entitlements/assignments; query-context keypair seeded; cloud key **operator-supplied env-gated** (`COGNIC_RUN_PROOF_M8=1` + provider key env; never committed; CI never runs it). Bars scripted with evidence-based assertions; diagnostics capture per the proof-m6 hardening (describe + sandbox/decision-row captures).

## 7. Phasing

- **Part A (kernel):** ADR-027 → gateway typed tool contract + provider drift tests → entitlement + assignment stores (+ migrations, ingestion invariant) → dispatcher (CC) → loop (CC) → query-context token mint/verify contract → instruction-skill hosting + validators (+ `referenced_tools`) → built-ins (`read_skill`, `remember`) → agent trust root → `agent_run` evidence family → portal ask route + `agent.ask` scope → `agents.rego`. Full CC gate discipline throughout; `protocol/mcp_authz.py` byte-identical standing rule.
- **Part B (external):** oracle v0.3.0; three instruction-skill packs; the agent pack. Released/signed; digests pinned for the proof.
- **Part C (proof):** seeds + runner + bars on live kind (operator-run, env-gated).
- **Part D:** `docs/VALIDATION-RESULTS.md` M8 entry → checklist flip → PR. (M8 checklist "records memory/audit" is satisfied by task-tier digest-only writes; if review deems the line to imply more, amend it M7-style rather than overclaim.)

## 8. Explicitly deferred (recorded in ADR-027)

Conversation harness above the single-shot route · long-term agent memory (remember/recall/forget/redact — **M9**) + Wave-1.5 prompt-injection of memory · entitlement/assignment portal administration (Human-only-decision-adjacent) · pure-declarative agent discovery without the inert marker · sandboxed custom-engine agents (Approach 2) · A2A cross-agent workflows · ADR-010/011 eval + adversarial integration for agent targets (M8 creates the targets; wiring is a follow-up) · RFC 8693 token-exchange OBO (Wave-2 alignment documented).

## 9. Open items for the implementation plan

- Exact `GatewayToolSpec`/`GatewayToolCall` field shapes + the three provider-normalization fixtures.
- Query-context token format (claims, signature alg, nonce store) + key rotation posture.
- `agents.rego` input document shape (mirrors the sandbox/scheduler bundle discipline).
- The agent record projection (manifest → kernel record) + validator refusal vocabulary.
- Migration numbering + seeds' home (kernel migration vs proof-side seed split: stores are kernel migrations; scope/entitlement/assignment *rows* are proof-side seed).
- sqlglot pin + Oracle-dialect parse coverage in the tool pack.
