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

- [x] **M5 — Real hook pack proof.**  
  **Goal:** ship a separate `cognic-hook-*` pack and prove it is installed, trusted, ordered, and enforced at runtime.  
  **Production proof:** a live request triggers the hook in deployed AgentOS.  
  **Load-bearing proof:** hook deny/fail-closed or documented fail-open exception behaves exactly as declared.  
  **Evidence:** the released signed `cognic-hook-schema-guard@v0.1.0` hook pack was trust-registered + `HookRegistry`-admitted at boot in a deployed `kind` AgentOS (discovered as the `cognic.hooks` pack kind, cosign-verified against its per-pack trust root), and its two arg-gated `dlp_pre` hooks enforced the MCP `call_tool` path against the operator-installed `cognic-tool-oracle-schema@v0.2.0` tool: permitted arg -> tool executes (200 + `FULL_NAME`); `__FORBIDDEN__` -> `403 dlp_pre_refused` (`policy_reason=forbidden_schema_arg`) refused before any tool execution, digest-only evidence; `__EXPLODE__` -> `409 dlp_pre_failed` fail-closed. Runner `infra/proof-m5/run-proof-m5.sh` (`runner_exit=0`, `PROOF M5 (ALL BARS) PASS`); `docs/VALIDATION-RESULTS.md` "M5 — Real hook pack proof — PASS" section.  
  **Production posture:** unlike M3/M4 (zero-kernel-change proofs), M5 required wiring the dormant Sprint-7A2 hook subsystem onto `MCPHost.call_tool` and making hook packs first-class in the runtime registry (the `cognic.hooks` pack kind + per-pack boot trust root, ADR-002 hooks amendment) — all under the critical-controls gate with `protocol/mcp_authz.py` byte-identical throughout. The hook pack is trust-register + registry-admit only; an operator enable/disable lifecycle for hook packs (M4-style) is a documented follow-up (spec §8), not an M5 requirement.

- [x] **M6 — Executable skill service proof.**

  **Goal:** ship a separate `cognic-skill-*` pack implementing deterministic `Skill.execute()` tool composition.

  **Production proof:** deployed AgentOS invokes the skill service, it uses only declared tools, and it emits audit/evidence.

  **Load-bearing proof:** undeclared tool use or missing required tool is refused.

  **Evidence:** the released signed `cognic-skill-schema-summary@v0.1.0` pack's deterministic `Skill.execute()` action ran FULLY SANDBOXED (`--network none`, `requires_credentials=()`) in a deployed `kind` AgentOS, composing the operator-installed `cognic-tool-oracle-schema@v0.2.0` MCP tools exclusively through the per-invocation `0700` Unix-socket broker: BAR 1 — 200 + fixed summary + dual-layer evidence (`audit.tool_invocation` ok rows per governed call; digest-only `skill.invoked` completed row); BAR 2 — a REAL undeclared tool (`get_constraints`) → `403 skill_tool_not_declared` refused at the broker BEFORE `MCPHost.call_tool`, tool count unchanged; BAR 3 (mandatory isolation) — direct outbound egress from the action blocked fail-closed (`502 skill_runtime_error`, no success marker). The SDK also cross-checks declared tools at construction (`SkillUnregisteredToolError`, unit-pinned). Runner `infra/proof-m6/run-proof-m6.sh` — runs 21 + 22 both `runner_exit=0`, **`PROOF M6 (ALL BARS) PASS`** (run 22 = ratification against the final kernel state); `docs/VALIDATION-RESULTS.md` "M6 — Governed agent skill proof (M6+M7) — PASS".

  **Production posture:** M6 required kernel changes — the skill-execution broker + governed executor (new CC trust boundary, `core/skill/`, the eleven §5.4 transport invariants TM-revert-pinned) plus five live-proof-driven CC slices (`3e942b2` license carve-out at the sidecar sites; `ab67a29` `writable_mounts` real enforcement, K8s fail-closed; `36e8798` + `2f36bfb` broker diagnosability + MCP result projection; `dc5dba5` sandbox HEALTHCHECK suppression) — all under the critical-controls gate (143 files) with `protocol/mcp_authz.py` byte-identical throughout.

- [x] **M7 — Agent Skills `SKILL.md` hosting, ADR-025.**

  **Goal:** host/govern the open Agent Skills `SKILL.md` format without replacing it: ingest a `SKILL.md` folder, wrap it in AgentOS governance, and make it assignable to agents.

  **Production proof:** deployed AgentOS trust-registers the released `SKILL.md` pack, validates/hosts the `SKILL.md` layer, surfaces it as hosted/assignable metadata, and proves the governed executable action path. LLM-agent consumption of the hosted instruction layer is M8. *(Amended at the ADR-025 M6+M7 merge — the pre-merge line, "an agent receives the instruction skill through the governed assignment path and uses it during a deployed task", is the M8 production proof.)*

  **Load-bearing proof:** unsigned/untrusted/malformed skill folder is refused; skill content cannot bypass pack governance.

  **Evidence:** merged with M6 per ADR-025 (one milestone: "Governed Agent Skill proof"). The `SKILL.md` package standard is hosted, not replaced: the released pack's `SKILL.md` frontmatter is validated at boot, `[skill].declared_tools` is cross-checked against registered MCP servers, and the skill surfaces as discoverable/assignable on `/api/v1/system/plugins` `hosted_skills` (asserted at both boots of runs 21+22). Governance cannot be bypassed: the pack rides the SAME per-pack cosign boot trust gate proven live at M5 (unsigned/untrusted → refused at registration); a malformed `SKILL.md` warn-skips → not hosted → invoke 404s (unit-pinned at `tests/unit/harness/test_skill_host.py`); the executable surface is governed end-to-end (M6 bars). LLM-agent consumption of the hosted instruction layer is **M8** per the amended production proof above; arbitrary bundled `scripts/` execution is out of scope (the single governed executable surface is the signed `cognic.skills` Python action).

### C. Agent Loop And Runtime Capability

- [x] **M8 — First deployed bank LLM-agent loop using tools and skills.**
  **Goal:** a separate bank-use-case `cognic-agent-*` pack acts as a human-role worker, receives assigned tools and skills, reasons over a realistic banking task, invokes those assigned capabilities, records memory/audit, and completes one governed task.
  **Production proof:** run on deployed AgentOS, not only in-process; first on `kind`, then AKS before final gate.  
  **Load-bearing proof:** agent cannot call unassigned tools/skills; policy/RBAC denial is visible and audited.  
  **Evidence required:** agent pack repo, deployed proof, validation results.

  **Evidence (2026-07-08 — PASS, run 16 on `kind`):** the released `cognic-agent-bank-analyst@v0.1.0` (persona + *requested* capability sets, inert marker — no agent code) ran the kernel-owned single-shot loop against a REAL cloud model (LiteLLM → OpenAI `gpt-4o`), read a hosted `SKILL.md` skill, authored read-only SQL over its governed views, invoked the operator-installed `cognic-tool-oracle-schema@v0.3.0` tool under a kernel-signed query-context, and completed the task. **Load-bearing proof holds:** an unassigned skill (`read_skill(atm-recon)` → `agent_capability_not_assigned`, BAR 2) and an unentitled scope (`agent_scope_not_entitled`, BAR 3) are refused at the kernel chokepoint and **audited**. Scope note: "records memory/audit" = a **task-tier memory-digest write** (BAR 1's `memory.write` chain row) + the digest-only dispatch/audit chain; richer scratch/task/long-term memory governance is **M9**. BAR 4's SQL guards (`agent_sql_object_out_of_scope` / `sql_not_select_only`) are proven as **tool-layer defense-in-depth via deterministic minted-token probes**, not as agent-authored SQL escape. Five kernel critical-controls slices landed under the gate (149 files; `protocol/mcp_authz.py` byte-identical throughout). Full detail + honesty boundary: `docs/VALIDATION-RESULTS.md` — "M8 — Governed agent loop (ADR-027) — PASS".

**M8.5 — Production conversational analytical agent program (ADR-028).** Six ordered milestones that carry AgentOS from the M8 single-shot loop to a pilot-ready conversational product. Design rationale + the named prerequisites HP-1…HP-3 live in `docs/superpowers/specs/2026-07-08-adr-028-conversational-sessions-design.md` §0; **this checklist owns the checkboxes and the evidence.** `M8.5-A` is a hard gate before any harness/agent/AKS spend; `M8.5-F` is a hard gate before any bank pilot.

- [x] **M8.5-A — Conversation substrate (hard gate).**

  **Goal:** the kernel-owned conversation primitive — `conversations` + `conversation_turns` store, bounded-replay context assembly, and a turn loop wrapping the M8 `AgentLoop`. No harness, no new bank agent.

  **Production proof:** BARs 1–3 on `kind`, reusing the M8 agent + oracle packs; the only new surface under test is `/api/v1/conversations`.

  **Load-bearing proof:** BAR 2 — the API accepts no client-supplied history in any form; a crafted payload is refused by schema (`extra="forbid"`). BAR 3 — an entitlement removed *between* turns causes the next turn's affected dispatch to refuse `agent_scope_not_entitled`, audited: proof the envelope is re-evaluated per turn and never cached.

  **Evidence required:** `kind` proof log + the three-hop chain join (`conversation → agent_run → dispatch`).

  **Gate:** nothing downstream starts until this passes.

  **Evidence (2026-07-10 — PASS, run 6 on `kind`):** `PROOF M8.5 SLICE (BARS 1-3) PASS`, exit 0, against kernel anchor `main @ 235daede` (PR #126: store + migration 0015 + fenced turn claim + turn loop + portal surface) with proof revision `caab00bd`. BAR 1: two governed turns as `analyst.amir`; the turn-2 run's `prior_context_sha256` was **independently recomputed** from the `conversation_turns` plaintext and matched the chain row (`prior_context_turns=2`); the chain join resolved as two lineages — context (`seq=2 → run → started/completed`; turn-2 dispatch count deliberately unconstrained per the run-5 ruling — run 6 neither constrains nor retains it) and dispatch (`seq=1 → run → ≥1 ok retail run_readonly_query dispatch`); question/answer digests on both digest-only `turn_completed` rows equalled SHA-256 of the stored plaintext. BAR 2: FIVE forged history fields each 422 `extra_forbidden` naming the field + the zero-loop pin. BAR 3: exactly-one entitlement proven → deleted mid-conversation (readback 0) → a FRESH financials question refused `agent_scope_not_entitled` with **zero** ok financials dispatches → restored (readback 1). Four governed model-driven turns; exact completion-call/token totals not retained (cluster torn down by the trap). Log SHA-256 `9c6f17b3…f533f9` (operator-held). Full detail, run ledger (five entries: four pre-pass events plus PASS; every code finding fixed + committed under review), and honesty boundary (BARs 4–7 NOT run — this is the vertical-slice gate, not pilot-ready): `docs/VALIDATION-RESULTS.md` — "M8.5-A — Conversation substrate (ADR-028 vertical slice) — PASS" + `infra/proof-m85/README.md`.

- [x] **M8.5-B — Harness enablement APIs.**

  **Goal:** HP-1 — the transcript + `conversation → agent_run → dispatch` chain-join read API the evidence viewer renders. HP-2 (bank-overlay `ActorBinder`/SSO) is an **external overlay dependency**, tracked outside this checkbox: AgentOS ships `KernelDefaultActorBinder` fail-loud by design and bank OIDC is bank-overlay work. HP-3 (entitlement/data-scope admin API) is **out of v1** — the first agent's entitlements are operator-seeded via SQL / CLI / deployment overlay, as the M8 proof did.

  **Production proof:** the read API serves a real conversation's transcript and chain join from a deployed kernel.

  **Load-bearing proof:** cross-tenant and cross-actor reads collapse to a 404 byte-identical to a genuine not-found.

  **Evidence required:** API contract tests + a deployed read against the M8.5-A conversation.

  **Boundary:** HP-1 is the *read API*; `conversation.export` (M8.5-F) is the examiner *packaging* on top of it, and is what M17 consumes. Do not build them twice.

  **Evidence (2026-07-11 — PASS, run 7 on `kind`):** `PROOF M8.5-B (READ APIS) PASS`, exit 0, kernel anchor = proof revision = `8e77ca16` (the image label verified live via `docker inspect`; both cleanliness guards passed; migrate to rev 0016 with the live schema readback). The M8.5-A BARs 1–3 re-executed and re-passed in the same run; the ten deterministic READ steps (zero model calls) then served THAT record: list + `limit=1` cursor walk + three hostile-cursor 422s; transcript plaintext (non-null, `erased_at` null) with frozen-watermark pagination; the four-block turn-chain join with true-64-hex digests, started↔turn and terminal↔turn digest coupling, args AND result dispatch digests, and the turn-2 dispatch count unconstrained (observed 2 — re-verification; run 5 had observed 0 — context reuse); the **load-bearing proof live**: six-way byte-identical 404 collapse (unknown-id / cross-actor sara / cross-tenant zara × transcript + chain) with owner-visible `turn_not_found` distinct; empty lists for both foreign readers; access trails with identifiers + outcome and zero transcript plaintext. API contract tests: 51 read-model + 45 route pins + the 27-test migration suite + 81 structural pins; `core/conversation/read_model.py` on the 152-file CC gate at 100/100. Log SHA-256 `fb9e6536…d18a1` (743 lines, operator-held). Full detail + run ledger + honesty boundary (HP-1 only; BARs 4–7 NOT run): `docs/VALIDATION-RESULTS.md` — "M8.5-B — Harness enablement APIs (ADR-028 HP-1) — PASS" + `infra/proof-m85/README.md`.

- [x] **M8.5-C — Basic bank harness.**

  **Goal:** a separate web artifact with **exactly three screens — chat, approvals, evidence.** A browser + same-origin BFF with no independent authorization or governance authority; zero authoritative domain/governance state (transient session/token state only); security-sensitive for the OIDC flow, session/token custody, CSRF protection, and request forwarding, but non-authoritative for identity and authorization. Chat is request/response; live progress arrives with the projectors at M8.5-F.

  **Production proof:** a human converses with the deployed M8 agent through the harness; the approvals inbox drives the existing ADR-014 surface; the evidence viewer renders HP-1's chain join.

  **Load-bearing proof:** the harness cannot bypass governance — a refused dispatch surfaces as a governed refusal in both the UI and the chain; no pack-builder and no data-scope admin surface exists (attaching packs, configuring data scopes, and pack-lifecycle approval are an **operator governance console**, a separate later artifact).

  **Evidence required:** harness repo + deployed transcript + chain correlation.

  **Recon locks (ruled 2026-07-11; full text: ADR-028 spec §0.2 HP-4/HP-5 + §0.4):** repo = `cognic-harness` (the external product, distinct from the kernel-internal `src/cognic_agentos/harness/`). **Architecture:** browser + same-origin **BFF** with no independent authorization or governance authority — HttpOnly/Secure/SameSite session cookies browser-side; OAuth tokens BFF-side only (never browser JS/storage); the BFF is a confidential OIDC client (Authorization Code + PKCE S256; RFC 9700 baseline — full FAPI 2.0 is the bank-deployment target, spec §0.4 profile ladder); on every AgentOS call it presents a user-bound AgentOS-audience token (or standards-based exchanged derivative) that AgentOS validates itself — no actor headers, no shared-secret impersonation, proof-only binders absent from production bundles; it may implement OIDC mechanics but never derives authorization/tenant/scopes — `ActorBinder` binds identity, AgentOS is the sole authorization/governance authority; the BFF calls AgentOS server-to-server (no CORS cookies; a cross-origin bearer SPA is a bank-overlay exception needing its own threat model + DPoP). **Custody:** the harness never accepts/stores/displays/forwards DB passwords, wallets, connection strings, Vault tokens, or user-entered schema credentials — no DB client, credential form, data-scope admin, or secret handling in M8.5-C (credential brokerage is designed at M8.5-D, live-proven at M8.5-E; AgentOS stores only non-secret governance metadata). **HP-4 blocks this milestone's live proof** — paginated approval queue + actor-bound MCP grant replay are kernel work scheduled inside M8.5-C (actor-bound = the grant is usable only by the original requesting subject; the approver remains a distinct human for 4-eyes). **HP-5** (typed conversation `pending_approval` + kernel-owned resume) blocks M8.5-D/E high-risk chat claims, not this milestone. Approvals live proof rides a separately released high-risk MCP tool pack through the direct MCP call surface (202 → grant/deny incl. distinct-actor 4-eyes → exact re-call), never claimed as chat-originated — **an entitled read-only NL query does not require human approval** (assignment + entitlement + policy suffice; the high-risk pack exists solely to prove the approvals screen and is not a requirement of the first read-only analytical agent). Proof adjustments: 403 (not empty inbox) without `tool.approve.observe`; cross-tenant observer sees its own empty queue; correlation by exact ID/digest/sequence/refusal fields; the manipulated-UI test; structural pins incl. no proof-header code in the production bundle.

  **Evidence (2026-07-14 — PASS, run 20 on `kind`):** `PROOF M8.5-C (BARS A-F) PASS`, exit 0, against clean AgentOS anchor/proof revision `926b1188` and clean, separately built + signed Cognic Harness revision `4dc64cc`. Bar A passed all ten session cases plus CSRF/XSS against two BFF replicas and TLS Redis. Bar B proved real Keycloak identity and the token-refusal negative space. Bar C rendered a governed chat turn and a mid-conversation `agent_scope_not_entitled` refusal with zero ok financials dispatches. **Load-bearing Bar D:** the independent probe ledger stayed 0 for pending, deny, and incomplete four-eyes; a distinct second human completed approval and the exact re-call moved it to exactly 1; Sara's replay refused `tool_approval_originator_mismatch` and the ledger stayed 1; the real 51-request `Link` walk had exact set/order/no-duplicate coverage, a non-observer rendered 403, and the foreign observer saw only its own empty queue. Bar E re-hashed the two rendered transcript turns to the kernel chain digests and run IDs, PSQL-verified; Bar F found exactly three screens, zero DB modules, no actor-header path or Jinja autoescape bypass, with CSP + `no-store`. Three model-driven governed turns; exact completion-call/token totals were not retained. Log SHA-256 `233787cf…ecf593` (926 lines, operator-held). Full evidence, 20-attempt ledger, and mandatory honesty boundary: `docs/VALIDATION-RESULTS.md` — "M8.5-C — Basic bank harness (ADR-028) — PASS" + `infra/proof-m85c/README.md`. **Not pilot-ready:** HP-5, erasure, safety/escalation hooks, data brokerage, the bank FAPI/equivalent posture, and single-use consumption for real high-risk actions remain later gates.

- [ ] **M8.5-D — First bank NL-query analytical agent.**

  **Goal:** a real bank-facing `cognic-agent-*` pack, the required `cognic-tool-*` packs, and full agentskills.io `cognic-skill-*` packs.

  **Production proof:** the agent is installed through the M4 operator flow with operator-seeded entitlements, and answers analytical questions over real bank views.

  **Load-bearing proof:** the golden eval set is **release-gating** (pass-rate gates the pack release) and doubles as the SR 11-7 documented-validation artifact; an unassigned capability and an unentitled data scope are refused and audited.

  **Evidence required:** agent + tool + skill pack repos, eval report, deployed proof.

  **D2 governed-write substrate (implemented 2026-07-17; A-minus live-proven 2026-07-18):** the kernel now carries HP-5 end to end: bank-owned per-tool approver assignments and N-way maker-checker decisions; originator exclusion at every grant index; exact canonical-argument replay custody with erasure; atomic single-use consumption; action entitlements independent of data-scope entitlements; a typed `pending_approval` conversation terminal; final-grant auto-execution with the reserved 12-claim action-context token; replay-excluded, budget-neutral system turns; queue progress; and live/replay approval UI events. Four authority modules joined the durable critical-controls gate (152→156). The kernel-only D2 e2e pins 1/3 and 2/3 progress, exact replay bytes, token claims, consume-once, stored-result retry, and live/replayed `grant_recorded` + `executed` events. The deployed A-minus Bar G then proved one bank-owned 3-person assignment row, a direct Postgres witness of `require_assigned|3|0`, deployed detail-wire progress 1/3→2/3→3/3, exact-chain decision order, first-recall execution exactly once, second-recall `tool_approval_consumed`, and originator exclusion at decision indices 0 and 1. Bars A-F re-passed on the same clean anchor `c2f418a7`; operator-held 939-line log SHA-256 `5ae3f83e…dc114`. This does **not** close M8.5-D: per-tool risk-tier overrides, pack-side token verification/idempotency persistence, scheduler-lane delivery, D5's conversation-correlated external-action/system-turn proof, and the released bank-agent proof remain forward gates.

  **Data-access ownership (ruled 2026-07-11; ADR-028 spec §0.4):** M8.5-D owns the dedicated data-access identity + credential-brokerage **design** — connection-profile + CredentialBroker ownership decided after source recon; the query-context token treated per the ruled framing — a private AgentOS JWS profile, not claimed to be an RFC 9068 OAuth access token; M8.5-D evaluates RFC 8693 for issuance/exchange, RFC 9068 only if OAuth access-token semantics are adopted, and RFC 9396 for fine-grained authorization details, with retaining + explicitly versioning the private profile permitted (IETF Transaction Tokens stay draft, tracked non-binding); the workload-identity profile (SPIFFE X.509-SVID/mTLS or bank-cloud equivalent); the Oracle adapter implemented **without credentials in AgentOS or the pack manifest** (Oracle target profile: workload identity → Vault/PAM lease or rotated proxy credential → Oracle proxy session → governed views + VPD + DB audit).

- [ ] **M8.5-E — Full-stack `kind` proof.**

  **Goal:** harness + the first bank agent + its released packs + evidence, end to end.

  **Production proof:** a user completes a multi-turn analytical task through the harness, with turn N depending on turn N−1's answer; the evidence viewer resolves the conversation → run → dispatch join.

  **Load-bearing proof:** at least one governed refusal (unassigned capability or unentitled scope) is visible to the user *and* present in the chain.

  **Evidence required:** `kind` run log + evidence export.

  **Data-access live proof (ruled 2026-07-11; ADR-028 spec §0.4):** the M8.5-E proof must include the full brokered chain — entitlement → short-lived query authorization → workload-authenticated credential retrieval → Oracle proxy session → DB-native enforcement. Evidence records credential lease/reference identifiers and the DB session/proxy identity, **never credential material**; the proof demonstrates rotation/revocation or lease expiry plus zero secret leakage to logs, transcript, model context, or evidence.

  **Honesty boundary (mandatory in the proof README):** this proof runs **without the content-safety hook phases and without the erasure pathway** — both land at M8.5-F. It is an **internal product proof**. It **must not** be presented to a bank as pilot-ready.

- [ ] **M8.5-F — Conversational governance completion (pilot gate).**

  **Goal:** the erasure pathway (`conversation.export` / `conversation.redact` scopes, tombstones, the expiry reaper); the kernel-owned `conversation_input` / `conversation_output` hook phases plus a real `cognic-hook-*` content-safety pack; the `escalate_to_human` built-in with `conversation.escalated` and the closed 2-value `blocking` / `advisory` classes; ADR-020 conversation typed projectors + SSE; the `[conversation]` agent-manifest block with tenant tighten-only ceilings.

  **Production proof:** BARs 4–7 on `kind`.

  **Load-bearing proof:** BAR 4 — bounds exhaustion and the terminal-state `conversation_not_active` refusal fire with **zero `AgentLoop` invocation**. BAR 5 — after redact, plaintext is gone, tombstones remain, and the chain is intact and proves the erasure itself. BAR 6 — hostile input is refused fail-closed by the hook pack, and `escalate_to_human` produces an approval-surface request plus an audited block/resume. BAR 7 — an SSE drop and `Last-Event-ID` reconnect replays without gap or duplication.

  **Adversarial:** the ADR-011 red-team is aimed at the **conversational** surface here — multi-turn injection and history-reference manipulation are new attack scope versus M8's single-shot. The live/pilot red-team proof carries into M15/M16.

  **Evidence required:** BAR 4–7 logs + red-team report + erasure evidence rows.

  **Gate:** **no bank pilot before this passes.**

After M8.5-F, pilot readiness lands at **M15** (AKS deployed pack + agent proof) + **M16** (production ops) + **M17** (examiner-ready evidence export), with **M24** the final v1 AKS completion gate. **M9** (memory), **M12/M13** (ADK; **M23** if the no-code Studio is promoted, activating ADR-021), and **M14/ADR-029** (dynamic workflows) are demand-driven and are **not blockers** for the first NL-query agent — ADR-028's transcript erasure adopts ADR-019's verbs without requiring the M9 memory subsystem.

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
