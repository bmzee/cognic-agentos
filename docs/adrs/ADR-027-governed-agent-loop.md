# ADR-027 — Governed Agent Loop

## Status
**APPROVED** on 2026-07-05 (maintainer-reviewed design; Parts 1+2 approved with corrections folded in). It lands as milestone **M8 — "First deployed bank LLM-agent loop using tools and skills"** (`docs/PRODUCTION_GRADE_MILESTONE_CHECKLIST.md`), on the substrate proven by M5 (hooks on `MCPHost.call_tool`), M6 (governed executable skills + broker), and M7 (hosted `SKILL.md` instruction layer) per ADR-025. Source design spec: `docs/superpowers/specs/2026-07-04-m8-governed-agent-loop-design.md`; implementation plan: `docs/superpowers/plans/2026-07-05-m8-governed-agent-loop.md`; implementation on branch `feat/m8-governed-agent-loop`. (ADR-026 is taken by the M4 operator pack-install runtime-config decision.)

## Context

Through M7 AgentOS governs every layer an LLM agent needs — signed packs, sandboxed execution, broker-mediated `MCPHost.call_tool` with hooks/approval/DLP, hosted `SKILL.md` instruction skills — but no LLM agent exists. ADR-025 recorded the gap explicitly: "Until M8 there is no LLM consumer of the hosted instruction layer." The kernel has an agent-shaped hole: the `cognic.agents` entry-point group is already registered in `protocol/plugin_registry.py` (`"agents": "cognic.agents"`), the `agent_run` UI-event family is schema-only, and `llm/gateway.py` carries an `agent_workforce_id` parameter no agent has ever threaded.

The industry converged on the pattern that fills it safely. Microsoft 365 Copilot's declarative agents give the LLM **no code path** — the platform owns the loop, the pack declares persona + capabilities. Enterprise agent-gateway deployments put an OPA-style policy decision on **every** tool call. OAuth token-exchange (RFC 8693) carries the dual identity — the user the agent acts *for* (`sub`) and the agent that acts (`act`) — end to end. Text-to-SQL hardening converged on governed views (a curated semantic layer) plus engine-level grants, never trust in the model's SQL. M8 ships all four as one kernel decision, with its first production inhabitant: **`cognic-agent-bank-analyst`**, an NLP analytical worker answering natural-language questions over the bank's Oracle governed views under the *asking user's* data entitlements — single-shot, fully evidenced, on a cloud model routed through the governed gateway.

Three build approaches were weighed at design time. **Approach 1 — declarative agent pack + kernel-owned loop** was chosen (industry-validated; the LLM never executes pack code). Approach 2 (sandboxed custom-engine agents — the pack ships its own loop, run in the ADR-004 sandbox) and Approach 3 (loop in pack code, in-kernel) were **rejected for M8**; Approach 2 is recorded as a deferral, not a dead end.

```
User (Actor) ── POST /api/v1/agents/{agent_id}/ask {question}   (RBAC agent.ask)
      ▼
core/agent/loop.py      (CC — frames + interprets the UNTRUSTED LLM)
      │  llm/gateway.completion(tier, messages, tools=…)
      │  (cloud-policy · kill-switches · quotas · guardrails · honesty ledger
      │   · Langfuse trace with agent_workforce_id)
      ▼
core/agent/dispatch.py  (CC — THE chokepoint; ALL authority decisions)
      │  gate 1 assignment → gate 2 entitlement → gate 3 agents.rego
      │  stamp: kernel-minted SIGNED query-context token (never LLM-authored)
      ├── built-ins: read_skill(skill_id) · remember(note)
      └── MCP tools: MCPHost.call_tool (M5 hooks + ADR-014 approval intact)
             └── run_readonly_query: verify token → sqlglot parse →
                 objects ⊆ stamped allow-set → SELECT-only + bounds →
                 Oracle PROXY AUTH as the user's DB identity (engine backstop)
```

## Decision

### Declarative agents — the pack declares; the kernel owns the loop

An **agent pack is declarative**: it carries the persona (`AGENT.md`, validated like `SKILL.md`) and the **requested** capabilities (`requested_skills` + `requested_tools`, plus risk tier and the agent-mandatory identity/AgentCard fields), and **zero executable loop code**. The kernel owns the reasoning loop and consumes only the manifest-derived agent *record* — no pack code executes on the agent path.

The pack keeps a **minimal inert `cognic.agents` entry-point marker solely as the registry/verify vehicle**: it rides the entire existing trust pipeline — discovery, wheel integrity, the isolated load probe, cosign verification — with no modification to the critical-controls registry/trust-gate modules, and is **never used by the loop**. The marker MUST be **side-effect-free on import/load**: the module body and the marker object's construction perform no I/O, no network, no filesystem access, and no global mutation. The pack's own import-probe tests and the `agentos verify` Step-11 isolated load probe pin this as far as an isolated load can prove.

**Pure-declarative discovery without `EntryPoint.load` is the eventual evolution** — a registry path that admits an agent pack on manifest + signature alone, with no importable marker at all. It is recorded here deliberately and deliberately **not built in M8**: the inert marker keeps M8 on the proven trust pipeline with zero trust-gate changes.

Manifest `requested_skills` / `requested_tools` are **requests, not grants**. Grants live kernel-side in the assignment store, and the ingestion invariant below (`agent_grant_not_requested`) refuses any grant outside the requested set — operator/config drift can never grant a capability the persona never asked for.

### The loop / dispatch split — framing is critical controls; authority lives only in dispatch

**The loop (`core/agent/loop.py`) is CRITICAL CONTROLS even though it grants nothing.** Authority decisions live in the dispatcher, but the loop *frames and interprets the untrusted LLM*: prompt assembly (persona + granted skills' names/descriptions — progressive disclosure), tool-call parsing off the gateway's typed contract, the max-step / per-run token-budget / wall-clock bounds, final-answer handling, and evidence correlation are all security-relevant surfaces. A bug in framing is a bug in what the model can see or smuggle; the loop rides the same durable coverage gate as the dispatcher.

**The dispatcher (`core/agent/dispatch.py`) owns EVERY authority decision** and is the **only path from an LLM utterance to an action** — built-ins and MCP tools dispatch identically. Its gates, in order:

1. **Assignment gate** — the resolved capability (skill / tool / builtin) must be in the agent's *granted* set. The generic `read_skill` built-in carries a **`skill_id` sub-gate**: the LLM-authored `skill_id` argument is itself a capability selection and must clear the same granted set before any skill body is read — without it, `read_skill("<unassigned>")` would read an unassigned skill's instructions.
2. **Entitlement gate** — for scope-carrying calls, the `scope_id` must be in the *asking user's* entitled set and must resolve to a known data scope.
3. **Policy gate** — the `agents.rego` decision point (below), with ADR-014 risk-tier continuity on the downstream `MCPHost.call_tool` path.
4. **Query-context stamping** — the kernel-minted signed token (below), injected only after gates pass.

Prompt assembly *shapes* to the granted set (an unassigned capability never appears in the prompt or the tool specs); dispatch *enforces* it — defense in depth, and the deployed proof's forced probe demonstrates the hard gate holds even when the prompt shaping is talked around.

**The LLM is untrusted input end to end.** It selects *within* granted/entitled sets; it can never author the sets, the stamped context, or the identities. Nothing the model emits is executed, queried, or trusted except through the dispatcher's gates.

### The query-context trust seam

The LLM-visible tool schema for `run_readonly_query` is **exactly** `{scope_id, sql, max_rows?}` — it never includes the object allow-set, the proxy DB identity, or any entitlement fact. After the gates pass, the dispatcher injects an **opaque, signed AgentOS query-context token** into the MCP call as a **non-LLM-visible argument**. The tool **verifies the token before honoring any stamped fact**. A direct MCP caller without a valid kernel-minted context is refused with `query_context_missing_or_invalid` — the tool is **agent-path-only by construction** (operator paths would mint their own tokens later, out of M8).

**Token format (locked at plan review):** a **joserfc RS256 compact JWS with attached payload** — the same signing stack as the AgentCard JWS in `cli/sign.py`. Claims:

| Claim | Content |
|---|---|
| `iss` | `cognic-agentos` |
| `aud` | the tool ref (e.g. `cognic-tool-oracle-schema/run_readonly_query`) |
| `sub` | the originating user — who the agent acts *for* |
| `act` | the `agent_id` — who acts (the RFC 8693 dual-identity essence) |
| `tenant_id` | tenant binding |
| `scope_id` | the resolved data scope |
| `objects` | the governed-view allow-set the tool enforces `⊆` against |
| `proxy_db_identity` | the Oracle proxy identity the tool activates |
| `args_sha256` | sha256 over the exact LLM-authored arguments — binds the token to this call's `{scope_id, sql, max_rows}` |
| `jti` | crypto-random token id (anti-replay) |
| `iat` / `exp` | issue + expiry; **120 s default expiry**, Settings-tunable |

**Replay posture:** short expiry + `args_sha256` binding (a replayed token cannot carry different SQL) + a **tool-side in-memory TTL'd `jti` seen-set**. A kernel-side Redis-backed shared nonce store is recorded as **Wave-2 hardening — deliberately not built in M8**, preserving the cache-adapter-optional invariant (the kernel must not grow a hard Redis dependency for the agent path).

**Key rotation:** the tool verifies against a public-key **SET** (`{current, previous}`); the kernel signs with `current` — a two-key rotation window, so keys rotate without a coordinated flag-day. The kernel private key is configured via `Settings.agent_query_context_signing_key_path` (a filesystem path or a `vault://` URI); the verification public keys are distributed in deployment config alongside the cosign material.

### Data-scope entitlements — governed-view-set grain

Entitlements are granted at **data-scope grain**, and a named scope IS a **curated set of governed view objects** — the lightweight semantic layer — **plus a proxy DB identity**. Not a bare schema: the scope's object list is exactly the allow-set stamped into the query-context token and enforced by the tool's parse gate.

**Many-to-many subject ↔ scope is built in M8** (multi-scope users AND shared scopes; the deployed proof exercises both directions). **Administration is seed-driven in M8**: scope, entitlement, and assignment rows are deployment seeds. Portal CRUD administration is **deferred and Human-only-decision-adjacent** — per-tenant entitlement changes align with the AGENTS.md "Per-tenant allow-list changes" Human-only-decisions doctrine, so the eventual portal surface must carry the same human-actor gating discipline as the pack allow-list endpoint.

**The Oracle proxy-authentication grants on governed views are the engine-level backstop.** The user's proxy DB identity holds SELECT grants on exactly its governed views; even a hypothetical parser escape hits ORA-denied at the engine. The backstop is **proven by a separate direct DB probe** (a governed view succeeds; a raw table / cross-scope object fails at the engine) — **never by weakening the parser** on the main path.

### Closed dispatch refusal vocabulary (wire-protocol-public)

The dispatch refusal vocabulary is a closed 7-value set. It IS the wire-protocol contract for every consumer reading `agent.run.*` evidence rows, the ask-route response's `refusal_reason`, and the deployed proof's bar assertions — drift is a wire-protocol regression.

| Value | Emitted by | Trigger |
|---|---|---|
| `agent_capability_not_assigned` | dispatch gate 1 | capability (skill / tool / hallucinated name / `read_skill`'s LLM-authored `skill_id`) outside the granted set |
| `agent_scope_not_entitled` | dispatch gate 2 | `scope_id` outside the asking user's entitled set, or unresolvable |
| `agent_sql_object_out_of_scope` | **tool-side, mirrored** in the kernel vocabulary | a parsed SQL object outside the token's `objects` allow-set (the tool emits it; the kernel vocabulary carries the same value so evidence reads uniformly) |
| `agent_max_steps_exceeded` | loop (run-level terminal) | max-steps / token-budget / wall-clock run bounds (one reason family; the payload names the bound) |
| `agent_tool_dispatch_failed` | dispatch execute arm | tool/backend exception surfaced safely (safe detail + digest, never a stack trace) |
| `agent_policy_denied` | dispatch gate 3 | `agents.rego` deny — **a spec-delta addition**: the spec's initial list carried no value for a Rego deny; the vocabulary gains it so a policy deny is distinguishable from an assignment/entitlement refusal |
| `agent_grant_not_requested` | assignment-store **load**, not dispatch | the ingestion invariant: an `agent_assignments` grant outside the pack's *requested* set is refused fail-closed at load — no partial grant set is ever returned |

**The `agents.rego` bundle** (`policies/_default/agents.rego`) is the dispatch decision point: **bool-only** `data.cognic.agents.dispatch.allow`, `default allow := false`. The allow rule re-checks `input.assignment_verified == true` AND `input.entitlement_verified == true` **strict** — the `sandbox.rego` defense-in-depth precedent: the Python gates compute those booleans, and a hypothetical Python-gate bypass (refactor, direct OPA eval, fresh dispatch path) still refuses in pure Rego. Consumed by `core/agent/policy.py` mirroring `core/scheduler/policy.py` over the Sprint-4 `OPAEngine`; any OPA failure is fail-closed. The bundle gets the **wire-protocol-public stop-rule treatment like every `policies/_default` bundle** (the `sampling.rego` / `supply_chain.rego` / `elicitation.rego` / `sandbox.rego` / `scheduler.rego` / `tools.rego` precedent): bank overlays may tighten; loosening the kernel default-deny requires a coordinated kernel + ADR amendment.

### Evidence contract

- **Dual identity on every row.** Every `agent.run.*` decision row carries `originator_subject` (the asking user) + `agent_id` (the acting agent) — the OBO `sub`/`act` essence, chain-persisted so an examiner can always answer "who asked" and "what acted" from one row.
- **Digest-only chain payloads.** The question, the answer, and every SQL statement land on the chain as sha256 digests + byte counts — never plaintext. Plaintext exists only in the HTTP response to the asking user.
- **Downstream evidence unchanged.** `audit.tool_invocation` rows from `MCPHost.call_tool` (M5 hooks, ADR-014 approval, DLP) are untouched — the agent path adds rows, it never alters existing families.
- **Provider honesty + tracing live.** The external completion produces the provider-honesty ledger row, and the Langfuse trace carries `agent_workforce_id` — the **first real caller** of the gateway seam that has awaited an agent since the gateway landed (per the AGENTS.md rule: every LLM call traces with `agent_workforce_id` when an agent is involved).
- **Task-tier, digest-only memory.** The loop records run metadata (interpreted-question digest, chosen skill ids, scope ids, terminal state) through the governed `MemoryAPI` under the agent's identity. **Long-term agent memory is M9**, and the boundary is structural, not conventional: the loop constructs its `MemoryCallerContext` with `long_term_writes_allowed=False`, so a long-term write from the agent path is refused by the existing ADR-019 per-write gate regardless of any declaration.

### Critical-controls scope

Per AGENTS.md "Critical-controls rule": `core/agent/loop.py`, `core/agent/dispatch.py`, `core/agent/assignments.py`, `core/agent/policy.py`, `core/agent/query_context.py`, and `core/entitlements/store.py` land on the durable per-file coverage gate (95% line / 90% branch; gate 143 → 149 per the plan). `llm/gateway.py` and `protocol/ui_events.py` are already on the gate; their M8 edits ride the existing floor. `policies/_default/agents.rego` joins the stop-rule policy-bundle list. `protocol/mcp_authz.py` MUST stay byte-identical (the standing M5/M6 discipline). Security-relevant tests are threat-model-revert-proven load-bearing.

## Consequences

### Positive
- AgentOS gains its first production LLM agent with **every** governance surface live on one path: cosign-signed declarative pack, kernel loop, per-dispatch policy, signed query context, governed views + engine backstop, dual-identity digest-only evidence, honesty ledger, Langfuse attribution, governed memory.
- The LLM has no code path and no authority: a compromised or manipulated model can only select within granted/entitled sets, and every selection is gated + audited.
- Text-to-SQL is defense-in-depth by construction: prompt shaping → assignment/entitlement gates → signed allow-set → tool-side parse gate → Oracle proxy-auth engine grants. No single layer is trusted alone.
- The hosted `SKILL.md` instruction layer (ADR-025) gets its intended consumer; instruction skills become the domain semantic layer that keeps the agent generic.
- The gateway's dormant governance seams (`agent_workforce_id`, honesty ledger on an agent path) become live-exercised instead of schema-only.

### Negative
- Single-shot only: no conversation continuity in M8 — a follow-up question re-enters the loop cold. The conversation harness will wrap exactly this loop.
- Seed-driven entitlement administration is operator-unfriendly at scale; the portal CRUD deferral is deliberate (Human-only-decision-adjacent) but real.
- The kernel-owned loop means banks cannot ship custom reasoning engines in M8 — Approach 2 (sandboxed custom-engine agents) is deferred, not enabled.
- Per-dispatch gating (three gates + a token mint + a Rego eval per tool call) adds latency to every agent action; bounded by the loop's max-steps and acceptable for single-shot analytical work.

### Neutral
- Model choice stays configuration outside the AgentOS boundary (tier aliases through the governed gateway; a cloud model for the proof; on-prem swaps are a values-file diff). The governance around calling the model is the kernel's; the model is not.
- The tool-side `jti` seen-set is per-process — acceptable under the 120 s expiry + `args_sha256` binding; the shared nonce store is recorded Wave-2 hardening.
- The inert marker keeps agent packs on the same 5-kind pack vocabulary (tool / skill / workflow / agent / hook) with zero trust-gate changes; pure-declarative discovery can retire the marker later without a wire break.

## Explicitly deferred (recorded)

1. **Conversation harness** above the single-shot ask route — a later milestone wraps exactly this loop.
2. **Long-term agent memory** (remember / recall / forget / redact for agents) — **M9**; plus the Wave-1.5 prompt-injection-of-memory hardening. M8's task-tier digest-only writes are the full memory surface, structurally enforced by `long_term_writes_allowed=False`.
3. **Entitlement / assignment portal administration** — Human-only-decision-adjacent (AGENTS.md "Per-tenant allow-list changes" alignment); M8 stays seed-driven.
4. **Pure-declarative agent discovery** without the inert `cognic.agents` marker (no `EntryPoint.load` at all) — the eventual evolution of §"Declarative agents".
5. **Sandboxed custom-engine agents** (spec Approach 2) — rejected for M8; a pack-supplied loop under ADR-004 isolation remains a possible later shape.
6. **A2A cross-agent workflows** (ADR-003) — the M8 agent neither exposes nor consumes A2A tasks.
7. **ADR-010 / ADR-011 eval + adversarial integration for agent targets** — M8 creates the targets (a real loop, dispatch gates, refusal vocabulary); wiring the harnesses to them is a follow-up.
8. **RFC 8693 token-exchange OBO** — Wave-2 alignment. M8 carries the dual-identity essence (`sub` / `act`) in the kernel-minted query context; a standards-track token-exchange flow with an external AS is deferred.
9. **Instruction-skill `referenced_tools`** stays **non-authoritative reviewer evidence** — validator-cross-checked for the review panel, never an authority source; authority remains agent assignment + dispatch only.
10. **Sub-agent spawn from the loop** (ADR-005) — the M8 dispatch capability vocabulary (`skill` / `tool` / `builtin`) deliberately carries no spawn kind; wiring the dispatcher to the sub-agent spawn seam is a follow-up (recorded in the ADR-005 M8 amendment).
11. **Kernel-side shared nonce store** (Redis-backed `jti` replay cache) — Wave-2 hardening per §"The query-context trust seam"; the cache-adapter-optional invariant holds in M8.

## Instruction packs are content packs — manifest-walk boot discovery (amendment, 2026-07-06)

Instruction-only skill packs (`[pack] kind="skill"` + `[skill] mode="instruction"`, the A7 mode) are **content packs**: SKILL.md + the signed manifest as package data, with **no executable marker of any kind — none exists and none is permitted** (the A7 validator refuses a `cognic.skills` entry point on an instruction manifest; the runtime loader warn-skips one). Boot discovery therefore rides the **manifest-walk arm** added to `PluginRegistry.discover()` by the ADR-002 "Instruction-skill manifest-walk discovery" amendment (2026-07-06): zero-cognic-entry-point distributions whose signed manifest declares instruction-skill are discovered as `DiscoveredPack(entry_point=None)`, trust-registered through the SAME cosign + allow-list + supply-chain pipeline, reach `iter_registered_pack_candidates()`, and are hosted by the skill host; `load()` refuses them with `ManifestOnlyPackNotLoadable`. This is DISTINCT from deferred item 4 above — **agent** packs keep the inert `cognic.agents` marker in M8; only no-executable instruction skills are manifest-walk-discovered. Sign/verify support the same shape (finding #3, 2026-07-06): the wheel-integrity instruction arm derives kind `"skill"` from the exactly-one in-wheel manifest so `agentos sign --bundle` + `agentos verify` accept zero-entry-point instruction wheels (no AgentCard JWS; verify Step 11 runs a real module-import probe) — per the ADR-002 "Sign/verify wheel-integrity instruction arm" paragraph. AGENT packs sign/verify with the SEPARATE AgentCard-JWS custody landed at finding #4 (2026-07-06): an RSA JWS identity distinct from the cosign key, the tracked pack-root `agent-card.pub` trust root, and `joserfc` in the kernel's base dependencies (which also fixes the runtime `core/agent/query_context.py` RS256 packaging) — per the ADR-016 "AgentCard JWS custody split" amendment.

## References

- Design spec: `docs/superpowers/specs/2026-07-04-m8-governed-agent-loop-design.md` · Implementation plan: `docs/superpowers/plans/2026-07-05-m8-governed-agent-loop.md`
- ADR-002 (MCP plugin protocol — entry-point pack kinds incl. the `cognic.agents` group; `MCPHost.call_tool` governance)
- ADR-003 (A2A inter-agent — deferred cross-agent workflows)
- ADR-004 (sandbox primitive — the isolation substrate behind the rejected-for-M8 Approach 2 and the M6 skill broker)
- ADR-005 (sub-agent primitive — spawn integration from the loop deferred; see its M8 amendment)
- ADR-008 (authoring platform — the `[agent]` block validators + `AGENT.md` contract)
- ADR-010 / ADR-011 (evaluation + adversarial harnesses — agent-target integration deferred)
- ADR-014 (runtime tool approval — risk-tier continuity on agent-invoked tools; see its M8 amendment)
- ADR-015 (policy-as-code — `agents.rego` joins the default bundle family; see its M8 amendment)
- ADR-016 (supply-chain controls — the inert marker rides the existing sign/verify pipeline)
- ADR-017 (data-governance contracts — DLP hooks on the `call_tool` path unchanged)
- ADR-019 (agent memory governance — task-tier digest-only writes; long-term = M9; see its M8 amendment)
- ADR-020 (UI event-stream contract — the `agent_run` family gains emitters/projectors, additive)
- ADR-022 (runtime scheduler — the `core/scheduler/policy.py` pattern `core/agent/policy.py` mirrors)
- ADR-025 (governed agent skills — the hosted instruction layer this loop reads; instruction-only skill mode; see its M8 amendment)
- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) (the `act` claim / delegation semantics the query context mirrors)
- Prior-art anchors (per the design spec): Microsoft 365 Copilot declarative agents ("no code path for the LLM"); the agent-gateway / OPA-per-tool-call enterprise pattern; semantic-layer / governed-view text-to-SQL hardening; DB-native identity propagation (Oracle proxy authentication)
